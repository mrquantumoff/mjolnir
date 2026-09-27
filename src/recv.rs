//! The receiver: accept one authenticated sender, admit its data
//! connections round by round, and write chunks into part files.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, Scope};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Serialize;

use crate::bitset::{AtomicBitset, PartState};
use crate::crypto::{Cipher, CipherState, SessionKeys, TAG_LEN, handshake_responder};
use crate::keys::{PrivateKey, PublicKey, require_nonempty};
use crate::manifest::{FileEntry, Manifest, chunk_count, chunk_span};
use crate::net::{self, SharedTx, Sockets, send_ctrl, tell_peer_about, unexpected};
use crate::posio::write_all_at;
use crate::progress::{ActiveConnection, Cancelled, Phase, Progress, Stop};
use crate::wire::{
    self, ADMITTED, CHALLENGE_LEN, ConnKind, ControlRx, FrameHeader, HEADER_LEN, HELLO_LEN, Msg,
    REJECTED, Role, check_hello, open_frame,
};

#[derive(Clone, Debug, Serialize)]
pub struct RecvConfig {
    pub listen: SocketAddr,
    #[serde(skip_serializing)]
    pub key: PrivateKey,
    /// Sender public keys allowed to connect.
    pub authorized: Vec<PublicKey>,
    pub out_dir: PathBuf,
    /// Overwrite existing target files.
    pub force: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecvReport {
    pub peer: PublicKey,
    pub files: usize,
    /// Plaintext bytes of chunks that became present this session.
    pub bytes_received: u64,
    pub chunks_received: u64,
    pub rounds: u32,
    pub elapsed: Duration,
}

pub fn recv(cfg: RecvConfig, progress: Arc<Progress>) -> Result<RecvReport> {
    Receiver::bind(cfg)?.run(progress)
}

/// A bound, not yet running receiver. Serves exactly one transfer.
pub struct Receiver {
    listener: TcpListener,
    cfg: RecvConfig,
}

const CHECKPOINT_EVERY: Duration = Duration::from_secs(2);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const DATA_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a data connection may wait for its round's `RoundStart`.
const ROUND_START_WAIT: Duration = Duration::from_secs(10);
const ACCEPT_POLL: Duration = Duration::from_millis(5);

impl Receiver {
    pub fn bind(cfg: RecvConfig) -> Result<Self> {
        require_nonempty(&cfg.authorized)?;
        let listener = TcpListener::bind(cfg.listen)
            .with_context(|| format!("listening on {}", cfg.listen))?;
        listener.set_nonblocking(true)?;
        Ok(Receiver { listener, cfg })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("bound listener has an address")
    }

    pub fn public_key(&self) -> PublicKey {
        self.cfg.key.public_key()
    }

    /// Blocks until the transfer finishes, fails, or is cancelled.
    pub fn run(self, progress: Arc<Progress>) -> Result<RecvReport> {
        progress.conclude(self.run_inner(&progress))
    }

    /// Serves sessions until one completes. A failed handshake or a failed
    /// session is logged and the receiver waits for the next sender; only a
    /// finished transfer or a local cancel returns.
    fn run_inner(&self, progress: &Progress) -> Result<RecvReport> {
        loop {
            progress.set_phase(Phase::Connecting);
            let control = accept_control(&self.listener, progress)?;
            match self.session(control, progress) {
                Ok(report) => return Ok(report),
                Err(e) if progress.is_cancelled() => return Err(e),
                Err(e) => eprintln!("gorynych: {e:#}; waiting for the next sender"),
            }
        }
    }

    fn session(&self, mut control: TcpStream, progress: &Progress) -> Result<RecvReport> {
        let start = Instant::now();
        progress.set_phase(Phase::Handshaking);
        progress.reset_counts();
        let tx: SharedTx = Mutex::new(None);
        let sockets = Sockets::default();
        let stop = Stop::default();
        let watched = control.try_clone()?;
        thread::scope(|s| {
            s.spawn(|| net::watch_cancel(progress, &stop, &watched, &tx, &sockets));
            let result = (|| {
                control.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
                let (keys, peer) =
                    handshake_responder(&mut control, &self.cfg.key, &self.cfg.authorized)
                        .context("handshake failed")?;
                control.set_read_timeout(None)?;
                let (ctl_tx, mut rx) = wire::control_channel(control, &keys, Role::Receiver)?;
                *tx.lock().unwrap() = Some(ctl_tx);
                let (totals, rounds) = self
                    .receive(keys, &mut rx, &tx, &sockets, progress)
                    .with_context(|| format!("session with {peer} failed"))?;
                Ok(RecvReport {
                    peer,
                    files: totals.files,
                    bytes_received: totals.bytes,
                    chunks_received: totals.chunks,
                    rounds,
                    elapsed: start.elapsed(),
                })
            })();
            if let Err(e) = &result {
                tell_peer_about(e, progress, &tx);
            }
            stop.stop();
            result
        })
    }

    /// Everything after the handshake: offer, rounds, finalize.
    fn receive(
        &self,
        keys: SessionKeys,
        rx: &mut ControlRx,
        tx: &SharedTx,
        sockets: &Sockets,
        progress: &Progress,
    ) -> Result<(Totals, u32)> {
        let (manifest, cipher) = match rx.recv()? {
            Msg::Offer {
                chunk_size,
                cipher,
                files,
            } => (
                Manifest::from_offer(chunk_size, files).context("rejected the offer")?,
                cipher,
            ),
            other => return Err(unexpected(other, "Offer")),
        };
        let targets = prepare_targets(&self.cfg.out_dir, &manifest, self.cfg.force)?;
        let (mut chunks, mut bytes) = (0, 0);
        for t in &targets {
            for k in (0..t.have.len()).filter(|&k| !t.have.get(k)) {
                chunks += 1;
                bytes += u64::from(chunk_span(t.entry.size, manifest.chunk_size, k).1);
            }
        }
        progress.set_totals(chunks, bytes);
        send_ctrl(tx, &have_msg(&targets))?;

        let session = Session {
            keys,
            cipher,
            manifest,
            targets,
            sync: RoundSync::default(),
            sockets,
            progress,
            fatal: Mutex::new(None),
            checkpoint_lock: Mutex::new(()),
        };
        let done = AtomicBool::new(false);
        let checkpoints = Stop::default();
        let rounds = thread::scope(|s| {
            s.spawn(|| accept_data(s, &self.listener, &session, &done));
            s.spawn(|| {
                while !checkpoints.wait(CHECKPOINT_EVERY) {
                    if let Err(e) = session.checkpoint() {
                        eprintln!("gorynych: checkpoint failed: {e:#}");
                    }
                }
            });
            let result = session.rounds(rx, tx);
            done.store(true, Relaxed);
            checkpoints.stop();
            sockets.shutdown_all();
            if result.is_err()
                && let Err(e) = session.checkpoint()
            {
                eprintln!("gorynych: checkpoint failed: {e:#}");
            }
            result
        })?;
        let totals = Totals {
            files: session.targets.len(),
            chunks: progress.chunks_done.load(Relaxed),
            bytes: progress.bytes_done.load(Relaxed),
        };
        Ok((totals, rounds))
    }
}

struct Totals {
    files: usize,
    chunks: u64,
    bytes: u64,
}

/// Waits for the first gorynych control connection, skipping strays.
fn accept_control(listener: &TcpListener, progress: &Progress) -> Result<TcpStream> {
    loop {
        if progress.is_cancelled() {
            return Err(Cancelled::Local.into());
        }
        let (mut stream, from) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL * 4);
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        match wire::read_preamble(&mut stream) {
            Ok(ConnKind::Control) => return Ok(stream),
            Ok(ConnKind::Data) => {
                eprintln!("gorynych: ignoring data connection from {from} before the handshake")
            }
            Err(e) => eprintln!("gorynych: ignoring connection from {from}: {e:#}"),
        }
    }
}

/// One output file.
struct Target {
    entry: FileEntry,
    final_path: PathBuf,
    part_path: PathBuf,
    state_path: PathBuf,
    file: File,
    have: AtomicBitset,
    /// Set after a chunk lands; cleared by the checkpoint that covers it.
    dirty: AtomicBool,
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Opens every part file, resuming from its state file when the state
/// matches the offer, and starting from scratch otherwise.
fn prepare_targets(out: &Path, m: &Manifest, force: bool) -> Result<Vec<Target>> {
    let mut targets = Vec::with_capacity(m.files.len());
    for entry in &m.files {
        let final_path = entry.path.under(out);
        if !force && fs::symlink_metadata(&final_path).is_ok() {
            bail!(
                "{} already exists (use --force to overwrite)",
                final_path.display()
            );
        }
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let part_path = with_suffix(&final_path, ".gorynych-part");
        let state_path = with_suffix(&final_path, ".gorynych-state");
        let count = chunk_count(entry.size, m.chunk_size);
        let resumed = part_path
            .exists()
            .then(|| PartState::load(&state_path).ok())
            .flatten()
            .filter(|s| {
                s.size == entry.size
                    && s.mtime == entry.mtime
                    && s.chunk_size == m.chunk_size.get()
                    && s.bitmap.len() as u64 == count.div_ceil(8)
            });
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(resumed.is_none())
            .open(&part_path)
            .with_context(|| format!("opening {}", part_path.display()))?;
        file.set_len(entry.size)?;
        let have = match &resumed {
            Some(state) => AtomicBitset::from_bytes(count, &state.bitmap),
            None => {
                remove_if_exists(&state_path)?;
                AtomicBitset::new(count)
            }
        };
        targets.push(Target {
            entry: entry.clone(),
            final_path,
            part_path,
            state_path,
            file,
            have,
            dirty: AtomicBool::new(false),
        });
    }
    Ok(targets)
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn have_msg(targets: &[Target]) -> Msg {
    Msg::Have {
        bitmaps: targets.iter().map(|t| t.have.to_bytes()).collect(),
    }
}

struct Session<'a> {
    keys: SessionKeys,
    cipher: Cipher,
    manifest: Manifest,
    targets: Vec<Target>,
    sync: RoundSync,
    sockets: &'a Sockets,
    progress: &'a Progress,
    /// A local write failure; ends the transfer at the end of the round.
    fatal: Mutex<Option<String>>,
    /// Serializes checkpoints so only one thread writes state files.
    checkpoint_lock: Mutex<()>,
}

impl Session<'_> {
    /// Drives the control channel until `Finished`. Returns the round count.
    fn rounds(&self, rx: &mut ControlRx, tx: &SharedTx) -> Result<u32> {
        loop {
            match rx.recv()? {
                Msg::RoundStart { round } => {
                    self.sync.start(round)?;
                    self.progress.set_phase(Phase::Transferring);
                }
                Msg::RoundEnd { round, connections } => {
                    self.sync.end(round, connections, self.progress)?;
                    if let Some(message) = self.fatal.lock().unwrap().take() {
                        bail!(message);
                    }
                    self.checkpoint()?;
                    if self.targets.iter().all(|t| t.have.is_full()) {
                        self.progress.set_phase(Phase::Finishing);
                        self.finalize()?;
                        send_ctrl(tx, &Msg::Finished)?;
                        return Ok(round + 1);
                    }
                    send_ctrl(tx, &have_msg(&self.targets))?;
                }
                other => return Err(unexpected(other, "RoundStart or RoundEnd")),
            }
        }
    }

    /// Snapshot bitmap, sync data, then atomically replace the state file,
    /// so a state file never claims a chunk whose bytes are not on disk.
    fn checkpoint(&self) -> Result<()> {
        let _only_writer = self.checkpoint_lock.lock().unwrap();
        for t in &self.targets {
            if !t.dirty.swap(false, Relaxed) {
                continue;
            }
            let saved = (|| {
                let bitmap = t.have.to_bytes();
                t.file.sync_data()?;
                PartState {
                    size: t.entry.size,
                    mtime: t.entry.mtime,
                    chunk_size: self.manifest.chunk_size.get(),
                    bitmap,
                }
                .save(&t.state_path)
            })();
            if saved.is_err() {
                t.dirty.store(true, Relaxed);
            }
            saved.with_context(|| format!("checkpointing {}", t.part_path.display()))?;
        }
        Ok(())
    }

    fn finalize(&self) -> Result<()> {
        for t in &self.targets {
            t.file
                .sync_all()
                .with_context(|| format!("syncing {}", t.part_path.display()))?;
        }
        for t in &self.targets {
            fs::rename(&t.part_path, &t.final_path)
                .with_context(|| format!("renaming into {}", t.final_path.display()))?;
            remove_if_exists(&t.state_path)?;
        }
        Ok(())
    }
}

/// Accepts data connections until `done`, one thread each.
fn accept_data<'s, 'e>(
    s: &'s Scope<'s, 'e>,
    listener: &'e TcpListener,
    session: &'e Session<'e>,
    done: &'e AtomicBool,
) {
    while !done.load(Relaxed) && !session.progress.is_cancelled() {
        match listener.accept() {
            Ok((stream, from)) => {
                s.spawn(move || {
                    if let Err(e) = serve_data(session, stream)
                        && !done.load(Relaxed)
                        && !session.progress.is_cancelled()
                    {
                        eprintln!("gorynych: data connection from {from}: {e:#}");
                    }
                });
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(e) => {
                eprintln!("gorynych: accept failed: {e}");
                thread::sleep(ACCEPT_POLL);
            }
        }
    }
}

fn serve_data(session: &Session, mut stream: TcpStream) -> Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(DATA_IDLE_TIMEOUT))?;
    session.sockets.add(&stream);
    ensure!(
        wire::read_preamble(&mut stream)? == ConnKind::Data,
        "control preamble on a data connection"
    );
    let mut challenge = [0u8; CHALLENGE_LEN];
    getrandom::fill(&mut challenge).map_err(|e| anyhow!("OS random number generator: {e}"))?;
    stream.write_all(&challenge)?;
    let mut hello = [0u8; HELLO_LEN];
    stream.read_exact(&mut hello)?;
    let admitted = check_hello(&session.keys, &challenge, &hello)
        .filter(|&(round, conn)| session.sync.admit(round, conn, session.progress));
    let Some((round, conn)) = admitted else {
        stream.write_all(&[REJECTED])?;
        bail!("rejected data connection hello");
    };
    let _closed = ClosedGuard { session, round };
    let _active = ActiveConnection::new(session.progress);
    stream.write_all(&[ADMITTED])?;
    receive_frames(session, &stream, round, conn)
}

/// Counts an admitted connection as closed for its round when dropped.
struct ClosedGuard<'a> {
    session: &'a Session<'a>,
    round: u32,
}

impl Drop for ClosedGuard<'_> {
    fn drop(&mut self) {
        self.session.sync.closed(self.round);
    }
}

fn receive_frames(session: &Session, stream: &TcpStream, round: u32, conn: u32) -> Result<()> {
    let m = &session.manifest;
    let sid = &session.keys.session_id;
    let mut cipher = CipherState::new(session.cipher, &session.keys.data_key(round, conn));
    let mut reader = BufReader::with_capacity(256 << 10, stream);
    let mut body = vec![0u8; m.chunk_size.get() as usize + TAG_LEN];
    loop {
        let mut raw = [0u8; HEADER_LEN];
        reader
            .read_exact(&mut raw)
            .context("connection ended without the end marker")?;
        let h = FrameHeader::decode(&raw);
        if h.is_end() {
            ensure!(h == FrameHeader::end(), "malformed end marker");
            let tag = &mut body[..TAG_LEN];
            reader.read_exact(tag)?;
            return open_frame(&mut cipher, sid, &raw, tag).context("end marker");
        }
        let target = session
            .targets
            .get(h.file_id as usize)
            .with_context(|| format!("file_id {} out of range", h.file_id))?;
        ensure!(
            h.chunk_index < target.have.len(),
            "chunk {} out of range for file {}",
            h.chunk_index,
            h.file_id
        );
        let (offset, len) = chunk_span(target.entry.size, m.chunk_size, h.chunk_index);
        ensure!(
            h.ct_len as usize == len as usize + TAG_LEN,
            "ct_len {} does not match chunk length {len}",
            h.ct_len
        );
        let frame = &mut body[..h.ct_len as usize];
        reader.read_exact(frame)?;
        open_frame(&mut cipher, sid, &raw, frame)
            .with_context(|| format!("chunk {} of file {}", h.chunk_index, h.file_id))?;
        if let Err(e) = write_all_at(&target.file, &frame[..len as usize], offset) {
            let message = format!("writing {}: {e}", target.part_path.display());
            *session.fatal.lock().unwrap() = Some(message.clone());
            bail!(message);
        }
        if target.have.set(h.chunk_index) {
            session.progress.add_chunk(u64::from(len));
        }
        target.dirty.store(true, Relaxed);
    }
}

/// Round bookkeeping shared by the control thread and data threads.
#[derive(Default)]
struct RoundSync {
    state: Mutex<RoundState>,
    cv: Condvar,
}

enum RoundState {
    /// Waiting for `RoundStart { round: next }`.
    Between { next: u32 },
    Open {
        round: u32,
        admitted: HashSet<u32>,
        closed: u32,
    },
}

impl Default for RoundState {
    fn default() -> Self {
        RoundState::Between { next: 0 }
    }
}

impl RoundSync {
    fn start(&self, round: u32) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        match *state {
            RoundState::Between { next } if next == round => {}
            _ => bail!("protocol error: unexpected RoundStart {{ round: {round} }}"),
        }
        *state = RoundState::Open {
            round,
            admitted: HashSet::new(),
            closed: 0,
        };
        self.cv.notify_all();
        Ok(())
    }

    /// Admits `(round, conn)` once. A connection may beat its `RoundStart`
    /// to the receiver, so it waits a little for the round to open.
    fn admit(&self, round: u32, conn: u32, progress: &Progress) -> bool {
        let deadline = Instant::now() + ROUND_START_WAIT;
        let mut state = self.state.lock().unwrap();
        loop {
            match &mut *state {
                RoundState::Open {
                    round: open,
                    admitted,
                    ..
                } if *open == round => return admitted.insert(conn),
                RoundState::Between { next } if *next == round => {}
                _ => return false,
            }
            let now = Instant::now();
            if now >= deadline || progress.is_cancelled() {
                return false;
            }
            let wait = (deadline - now).min(Duration::from_millis(100));
            state = self.cv.wait_timeout(state, wait).unwrap().0;
        }
    }

    fn closed(&self, round: u32) {
        let mut state = self.state.lock().unwrap();
        if let RoundState::Open {
            round: open,
            closed,
            ..
        } = &mut *state
            && *open == round
        {
            *closed += 1;
            self.cv.notify_all();
        }
    }

    /// Waits for `connections` admitted connections of `round` to close,
    /// then closes the round to further connections.
    fn end(&self, round: u32, connections: u32, progress: &Progress) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        loop {
            match &*state {
                RoundState::Open {
                    round: open,
                    closed,
                    ..
                } if *open == round => {
                    if *closed >= connections {
                        break;
                    }
                }
                _ => bail!("protocol error: RoundEnd for round {round} which is not open"),
            }
            if progress.is_cancelled() {
                return Err(Cancelled::Local.into());
            }
            state = self
                .cv
                .wait_timeout(state, Duration::from_millis(100))
                .unwrap()
                .0;
        }
        *state = RoundState::Between { next: round + 1 };
        Ok(())
    }
}
