//! The receiver: accept one authenticated sender, admit its data
//! connections round by round, write chunks into part files, and verify
//! them on disk before finishing.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, Scope};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Serialize;

use crate::bitset::{AtomicBitset, PartState};
use crate::crypto::{Cipher, CipherState, SessionKeys, TAG_LEN, handshake_responder};
use crate::keys::{PrivateKey, PublicKey, require_nonempty};
use crate::manifest::{ChunkSize, FileEntry, Manifest, chunk_count, chunk_span};
use crate::net::{self, Io, tell_peer_about, unexpected};
use crate::posio::{read_exact_at, write_all_at};
use crate::progress::{ActiveConnection, Cancelled, Phase, Progress, Stop};
use crate::wire::{
    self, ADMITTED, CHALLENGE_LEN, ConnKind, ControlRx, ControlTx, FrameHeader, HEADER_LEN,
    HELLO_LEN, Msg, REJECTED, Role, check_hello, open_frame,
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
    /// Read every chunk back and check its digest before finishing.
    pub verify: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecvReport {
    pub peer: PublicKey,
    pub files: usize,
    /// Plaintext bytes of chunks that became present this session.
    pub bytes_received: u64,
    pub chunks_received: u64,
    /// Authenticated frames dropped because their chunk was already claimed.
    pub duplicate_chunks: u64,
    /// Chunks whose bytes on disk failed verification and were fetched again.
    pub repaired_chunks: u64,
    /// Whether every chunk was read back and matched its digest.
    pub verified: bool,
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
/// Preamble plus Noise message 1 must arrive within this, however slowly
/// the bytes trickle in.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// Handshakes in progress at once; more connections are dropped at accept.
const MAX_PENDING_HANDSHAKES: usize = 32;
/// Data connections not yet admitted at once; more are dropped at accept.
const MAX_PENDING_DATA: usize = 64;
const DATA_IDLE: Duration = Duration::from_secs(60);
/// How long a data connection may wait for its round's `RoundStart`.
const ROUND_START_WAIT: Duration = Duration::from_secs(10);
/// After `RoundEnd`, how long to wait for the round's connections to close
/// before closing the round anyway.
const ROUND_CLOSE_WAIT: Duration = Duration::from_secs(30);
const ACCEPT_POLL: Duration = Duration::from_millis(5);
/// Verification failures of one chunk tolerated in a session.
const MAX_VERIFY_FAILURES: u8 = 3;
/// Bytes of BLAKE3 kept per chunk in the sums file.
const DIGEST_LEN: usize = 16;
const MAX_VERIFY_THREADS: usize = 16;

/// A control connection that finished the handshake.
struct Handshaken {
    stream: TcpStream,
    keys: SessionKeys,
    peer: PublicKey,
}

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

    /// Serves sessions until one completes. Handshakes run on their own
    /// threads, so a slow or hostile peer cannot hold up a real sender. A
    /// failed handshake or a failed session is logged and the receiver
    /// waits for the next sender; only a finished transfer or a local
    /// cancel returns.
    fn run_inner(&self, progress: &Arc<Progress>) -> Result<RecvReport> {
        let (done_tx, done_rx) = mpsc::channel::<Handshaken>();
        let pending = Arc::new(AtomicUsize::new(0));
        let authorized = Arc::new(self.cfg.authorized.clone());
        loop {
            if progress.is_cancelled() {
                return Err(Cancelled::Local.into());
            }
            match self.listener.accept() {
                Ok((stream, from)) => {
                    if pending.load(Relaxed) >= MAX_PENDING_HANDSHAKES {
                        continue;
                    }
                    pending.fetch_add(1, Relaxed);
                    let (key, authorized, progress) =
                        (self.cfg.key.clone(), authorized.clone(), progress.clone());
                    let (done_tx, pending) = (done_tx.clone(), pending.clone());
                    thread::spawn(move || {
                        match handshake(stream, &key, &authorized, &progress) {
                            Ok(Some(h)) => {
                                let _ = done_tx.send(h);
                            }
                            Ok(None) => {}
                            Err(e) if progress.is_cancelled() => drop(e),
                            Err(e) => eprintln!("mjolnir: handshake with {from} failed: {e:#}"),
                        }
                        pending.fetch_sub(1, Relaxed);
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => eprintln!("mjolnir: accept failed: {e}"),
            }
            let h = match done_rx.recv_timeout(ACCEPT_POLL) {
                Ok(h) => h,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => unreachable!("run_inner holds a sender"),
            };
            let peer = h.peer;
            match self.session(h, progress) {
                Ok(report) => return Ok(report),
                Err(e) if progress.is_cancelled() => return Err(e),
                Err(e) => {
                    eprintln!(
                        "mjolnir: session with {peer} failed: {e:#}; waiting for the next sender"
                    )
                }
            }
            progress.set_phase(Phase::Connecting);
        }
    }

    fn session(&self, h: Handshaken, progress: &Progress) -> Result<RecvReport> {
        let start = Instant::now();
        progress.reset_counts();
        progress.set_phase(Phase::Handshaking);
        let cancelled = || progress.is_cancelled();
        let control = Io::new(h.stream, &cancelled);
        let (mut tx, mut rx) =
            wire::control_channel(control.try_clone()?, control, &h.keys, Role::Receiver);
        let result = self.receive(h.keys, &mut rx, &mut tx, progress);
        if let Err(e) = &result {
            tell_peer_about(e, progress, Some(&mut tx));
        }
        let o = result?;
        Ok(RecvReport {
            peer: h.peer,
            files: o.files,
            bytes_received: o.stats.bytes.load(Relaxed),
            chunks_received: o.stats.chunks.load(Relaxed),
            duplicate_chunks: o.stats.duplicates.load(Relaxed),
            repaired_chunks: o.stats.repaired.load(Relaxed),
            verified: o.verified,
            rounds: o.rounds,
            elapsed: start.elapsed(),
        })
    }

    /// Everything after the handshake: offer, rounds, verification, finalize.
    fn receive(
        &self,
        keys: SessionKeys,
        rx: &mut Rx,
        tx: &mut Tx,
        progress: &Progress,
    ) -> Result<Outcome> {
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
        set_missing_totals(progress, &targets, manifest.chunk_size);
        tx.send(&have_msg(&targets))?;
        progress.set_phase(Phase::Transferring);

        let session = Session {
            keys,
            cipher,
            manifest,
            targets,
            verify: self.cfg.verify,
            sync: RoundSync::default(),
            progress,
            stats: Stats::default(),
            fatal: Mutex::new(None),
            checkpoint_lock: Mutex::new(()),
            pending_data: AtomicUsize::new(0),
            verify_failures: Mutex::new(HashMap::new()),
        };
        let checkpoints = Stop::default();
        let rounds = thread::scope(|s| {
            s.spawn(|| accept_data(s, &self.listener, &session));
            s.spawn(|| {
                while !checkpoints.wait(CHECKPOINT_EVERY) {
                    if let Err(e) = session.checkpoint() {
                        eprintln!("mjolnir: checkpoint failed: {e:#}");
                    }
                }
            });
            let result = session.rounds(rx, tx);
            checkpoints.stop();
            session.sync.shut();
            result
        });
        if rounds.is_err()
            && let Err(e) = session.checkpoint()
        {
            eprintln!("mjolnir: checkpoint failed: {e:#}");
        }
        let rounds = rounds?;
        Ok(Outcome {
            files: session.targets.len(),
            stats: session.stats,
            verified: session.verify,
            rounds,
        })
    }
}

type Tx<'a> = ControlTx<Io<'a>>;
type Rx<'a> = ControlRx<Io<'a>>;

/// Counters for one session's report.
#[derive(Default)]
struct Stats {
    chunks: AtomicU64,
    bytes: AtomicU64,
    duplicates: AtomicU64,
    repaired: AtomicU64,
}

struct Outcome {
    files: usize,
    stats: Stats,
    verified: bool,
    rounds: u32,
}

/// Reads the preamble and runs the Noise handshake, all within
/// `HANDSHAKE_DEADLINE`. `Ok(None)` is a stray data connection.
fn handshake(
    stream: TcpStream,
    key: &PrivateKey,
    authorized: &[PublicKey],
    progress: &Progress,
) -> Result<Option<Handshaken>> {
    net::prepare(&stream)?;
    let cancelled = || progress.is_cancelled();
    let mut io = Io::new(stream, &cancelled).deadline(HANDSHAKE_DEADLINE);
    match wire::read_preamble(&mut io)? {
        ConnKind::Control => {}
        ConnKind::Data => return Ok(None),
    }
    let (keys, peer) = handshake_responder(&mut io, key, authorized)?;
    Ok(Some(Handshaken {
        stream: io.into_stream(),
        keys,
        peer,
    }))
}

/// One output file and its side files.
struct Target {
    entry: FileEntry,
    chunk_size: ChunkSize,
    final_path: PathBuf,
    part_path: PathBuf,
    sums_path: PathBuf,
    state_path: PathBuf,
    part: File,
    /// `DIGEST_LEN` bytes of BLAKE3 per chunk, at `index * DIGEST_LEN`.
    sums: File,
    /// Chunks whose bytes and digest are written. Checkpointed.
    present: AtomicBitset,
    /// Chunks some thread has taken on writing. In memory only; a superset
    /// of `present`.
    claimed: AtomicBitset,
    /// Set after a chunk lands; cleared by the checkpoint that covers it.
    dirty: AtomicBool,
}

/// What became of one authenticated chunk.
#[derive(Debug, PartialEq, Eq)]
enum Landed {
    Written,
    Duplicate,
}

fn digest(plaintext: &[u8]) -> [u8; DIGEST_LEN] {
    blake3::hash(plaintext).as_bytes()[..DIGEST_LEN]
        .try_into()
        .unwrap()
}

impl Target {
    fn span(&self, index: u64) -> (u64, u32) {
        chunk_span(self.entry.size, self.chunk_size, index)
    }

    /// Writes an authenticated chunk exactly once: claim, write bytes,
    /// write digest, then mark present. A failed write releases the claim.
    fn land(&self, index: u64, plaintext: &[u8]) -> io::Result<Landed> {
        if !self.claimed.set(index) {
            return Ok(Landed::Duplicate);
        }
        let written = write_all_at(&self.part, plaintext, self.span(index).0)
            .and_then(|()| write_all_at(&self.sums, &digest(plaintext), index * DIGEST_LEN as u64));
        if let Err(e) = written {
            self.claimed.clear(index);
            return Err(e);
        }
        self.present.set(index);
        self.dirty.store(true, Relaxed);
        Ok(Landed::Written)
    }

    /// Reads chunk `index` back and compares it with its stored digest.
    fn check(&self, index: u64, buf: &mut [u8]) -> io::Result<bool> {
        let (offset, len) = self.span(index);
        let data = &mut buf[..len as usize];
        read_exact_at(&self.part, data, offset)?;
        let mut stored = [0u8; DIGEST_LEN];
        read_exact_at(&self.sums, &mut stored, index * DIGEST_LEN as u64)?;
        Ok(digest(data) == stored)
    }

    /// Makes a chunk missing again after it failed verification.
    fn reject(&self, index: u64) {
        self.present.clear(index);
        self.claimed.clear(index);
        self.dirty.store(true, Relaxed);
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Opens every part and sums file, resuming from the state file when the
/// part, sums, and state all exist and the state matches the offer, and
/// starting the file from scratch otherwise.
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
        let part_path = with_suffix(&final_path, ".mjolnir-part");
        let sums_path = with_suffix(&final_path, ".mjolnir-sums");
        let state_path = with_suffix(&final_path, ".mjolnir-state");
        let count = chunk_count(entry.size, m.chunk_size);
        let resumed = (part_path.exists() && sums_path.exists())
            .then(|| PartState::load(&state_path).ok())
            .flatten()
            .filter(|s| {
                s.size == entry.size
                    && s.mtime == entry.mtime
                    && s.chunk_size == m.chunk_size.get()
                    && s.bitmap.len() as u64 == count.div_ceil(8)
            });
        // A stale state file goes before the part file is truncated, so no
        // crash can leave a matching state next to zeroed data.
        if resumed.is_none() {
            remove_if_exists(&state_path)?;
        }
        let open = |path: &Path, len: u64| -> Result<File> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(resumed.is_none())
                .open(path)
                .with_context(|| format!("opening {}", path.display()))?;
            file.set_len(len)?;
            Ok(file)
        };
        let part = open(&part_path, entry.size)?;
        let sums = open(&sums_path, count * DIGEST_LEN as u64)?;
        let present = match &resumed {
            Some(state) => AtomicBitset::from_bytes(count, &state.bitmap),
            None => AtomicBitset::new(count),
        };
        let claimed = AtomicBitset::from_bytes(count, &present.to_bytes());
        targets.push(Target {
            entry: entry.clone(),
            chunk_size: m.chunk_size,
            final_path,
            part_path,
            sums_path,
            state_path,
            part,
            sums,
            present,
            claimed,
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
        bitmaps: targets.iter().map(|t| t.present.to_bytes()).collect(),
    }
}

/// Points the progress totals at the chunks still missing.
fn set_missing_totals(progress: &Progress, targets: &[Target], chunk_size: ChunkSize) {
    let (mut chunks, mut bytes) = (0, 0);
    for t in targets {
        for k in (0..t.present.len()).filter(|&k| !t.present.get(k)) {
            chunks += 1;
            bytes += u64::from(chunk_span(t.entry.size, chunk_size, k).1);
        }
    }
    progress.reset_counts();
    progress.set_totals(chunks, bytes);
}

struct Session<'a> {
    keys: SessionKeys,
    cipher: Cipher,
    manifest: Manifest,
    targets: Vec<Target>,
    verify: bool,
    sync: RoundSync,
    progress: &'a Progress,
    stats: Stats,
    /// A local write failure; ends the transfer at the end of the round.
    fatal: Mutex<Option<String>>,
    /// Serializes checkpoints so only one thread writes state files.
    checkpoint_lock: Mutex<()>,
    /// Data connections accepted but not yet admitted or rejected.
    pending_data: AtomicUsize,
    /// Verification failures per `(file, chunk)` this session.
    verify_failures: Mutex<HashMap<(u32, u64), u8>>,
}

impl Session<'_> {
    /// Drives the control channel until `Finished`. Returns the round count.
    fn rounds(&self, rx: &mut Rx, tx: &mut Tx) -> Result<u32> {
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
                    if self.targets.iter().all(|t| t.present.is_full()) {
                        if self.verify {
                            self.progress.set_phase(Phase::Verifying);
                            self.verify_all()?;
                        }
                        if self.targets.iter().all(|t| t.present.is_full()) {
                            self.progress.set_phase(Phase::Finishing);
                            self.finalize()?;
                            tx.send(&Msg::Finished {
                                verified: self.verify,
                            })?;
                            return Ok(round + 1);
                        }
                        self.checkpoint()?;
                        set_missing_totals(self.progress, &self.targets, self.manifest.chunk_size);
                    }
                    tx.send(&have_msg(&self.targets))?;
                }
                other => return Err(unexpected(other, "RoundStart or RoundEnd")),
            }
        }
    }

    /// Handles one authenticated chunk from any connection.
    fn land(&self, target: &Target, index: u64, plaintext: &[u8]) -> Result<()> {
        match target.land(index, plaintext) {
            Ok(Landed::Written) => {
                let len = plaintext.len() as u64;
                self.stats.chunks.fetch_add(1, Relaxed);
                self.stats.bytes.fetch_add(len, Relaxed);
                self.progress.add_chunk(len);
                Ok(())
            }
            Ok(Landed::Duplicate) => {
                self.stats.duplicates.fetch_add(1, Relaxed);
                Ok(())
            }
            Err(e) => {
                let message = format!("writing {}: {e}", target.part_path.display());
                *self.fatal.lock().unwrap() = Some(message.clone());
                bail!(message)
            }
        }
    }

    /// Syncs, then reads every chunk back on a small thread pool and
    /// compares it with its digest. Mismatches become missing again.
    fn verify_all(&self) -> Result<()> {
        for t in &self.targets {
            t.part.sync_data()?;
            t.sums.sync_data()?;
        }
        let total_bytes: u64 = self.targets.iter().map(|t| t.entry.size).sum();
        let total_chunks: u64 = self.targets.iter().map(|t| t.present.len()).sum();
        self.progress.reset_counts();
        self.progress.set_totals(total_chunks, total_bytes);
        // `starts[j]` is the global number of file j's first chunk.
        let starts: Vec<u64> = self
            .targets
            .iter()
            .scan(0, |next, t| {
                let first = *next;
                *next += t.present.len();
                Some(first)
            })
            .collect();
        let cursor = AtomicU64::new(0);
        let threads = thread::available_parallelism()
            .map_or(4, |n| n.get())
            .min(MAX_VERIFY_THREADS);
        let failure = Mutex::new(None);
        thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| {
                    let mut buf = vec![0u8; self.manifest.chunk_size.get() as usize];
                    while let n = cursor.fetch_add(1, Relaxed)
                        && n < total_chunks
                        && !self.progress.is_cancelled()
                    {
                        let file = starts.partition_point(|&first| first <= n) - 1;
                        let (t, index) = (&self.targets[file], n - starts[file]);
                        if let Err(e) = self.verify_chunk(file as u32, t, index, &mut buf) {
                            *failure.lock().unwrap() = Some(e);
                            return;
                        }
                    }
                });
            }
        });
        if self.progress.is_cancelled() {
            return Err(Cancelled::Local.into());
        }
        match failure.into_inner().unwrap() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn verify_chunk(&self, file: u32, t: &Target, index: u64, buf: &mut [u8]) -> Result<()> {
        let ok = t
            .check(index, buf)
            .with_context(|| format!("reading back {}", t.part_path.display()))?;
        self.progress.add_chunk(u64::from(t.span(index).1));
        if ok {
            return Ok(());
        }
        t.reject(index);
        self.stats.repaired.fetch_add(1, Relaxed);
        let mut failures = self.verify_failures.lock().unwrap();
        let count = failures.entry((file, index)).or_default();
        *count += 1;
        ensure!(
            *count < MAX_VERIFY_FAILURES,
            "chunk {index} of {} keeps failing verification",
            t.entry.path.as_str()
        );
        Ok(())
    }

    /// Snapshot `present`, sync the part and sums files, then atomically
    /// replace the state file, so a state file never claims a chunk whose
    /// bytes or digest are not on disk.
    fn checkpoint(&self) -> Result<()> {
        let _only_writer = self.checkpoint_lock.lock().unwrap();
        for t in &self.targets {
            if !t.dirty.swap(false, Relaxed) {
                continue;
            }
            let saved = (|| {
                let bitmap = t.present.to_bytes();
                t.part.sync_data()?;
                t.sums.sync_data()?;
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
            t.part
                .sync_all()
                .with_context(|| format!("syncing {}", t.part_path.display()))?;
        }
        for t in &self.targets {
            fs::rename(&t.part_path, &t.final_path)
                .with_context(|| format!("renaming into {}", t.final_path.display()))?;
            remove_if_exists(&t.state_path)?;
            remove_if_exists(&t.sums_path)?;
        }
        Ok(())
    }
}

/// Accepts data connections until the session ends, one thread each.
fn accept_data<'s, 'e>(s: &'s Scope<'s, 'e>, listener: &'e TcpListener, session: &'e Session<'e>) {
    while !session.sync.is_shut() && !session.progress.is_cancelled() {
        match listener.accept() {
            Ok((stream, from)) => {
                if session.pending_data.load(Relaxed) >= MAX_PENDING_DATA {
                    continue;
                }
                session.pending_data.fetch_add(1, Relaxed);
                s.spawn(move || {
                    if let Err(e) = serve_data(session, stream)
                        && !session.sync.is_shut()
                        && !session.progress.is_cancelled()
                    {
                        eprintln!("mjolnir: data connection from {from}: {e:#}");
                    }
                });
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(e) => {
                eprintln!("mjolnir: accept failed: {e}");
                thread::sleep(ACCEPT_POLL);
            }
        }
    }
}

/// Decrements `pending_data` when dropped.
struct PendingGuard<'a>(&'a AtomicUsize);

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

fn serve_data(session: &Session, stream: TcpStream) -> Result<()> {
    let pending = PendingGuard(&session.pending_data);
    net::prepare(&stream)?;
    let ended = || session.sync.is_shut() || session.progress.is_cancelled();
    let mut hello_io = Io::new(stream, &ended).deadline(HANDSHAKE_DEADLINE);
    ensure!(
        wire::read_preamble(&mut hello_io)? == ConnKind::Data,
        "a second control connection during a session"
    );
    let mut challenge = [0u8; CHALLENGE_LEN];
    getrandom::fill(&mut challenge).map_err(|e| anyhow!("OS random number generator: {e}"))?;
    hello_io.write_all(&challenge)?;
    let mut hello = [0u8; HELLO_LEN];
    hello_io.read_exact(&mut hello)?;
    let admitted = check_hello(&session.keys, &challenge, &hello)
        .filter(|&(round, conn)| session.sync.admit(round, conn, session.progress));
    let Some((round, conn)) = admitted else {
        hello_io.write_all(&[REJECTED])?;
        bail!("rejected data connection hello");
    };
    let _closed = ClosedGuard { session, round };
    let _active = ActiveConnection::new(session.progress);
    hello_io.write_all(&[ADMITTED])?;
    drop(pending);
    let round_over = || ended() || session.sync.is_closed(round);
    let io = Io::new(hello_io.into_stream(), &round_over).idle(DATA_IDLE);
    receive_frames(session, io, round, conn)
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

fn receive_frames(session: &Session, io: Io, round: u32, conn: u32) -> Result<()> {
    let m = &session.manifest;
    let sid = &session.keys.session_id;
    let mut cipher = CipherState::new(session.cipher, &session.keys.data_key(round, conn));
    let mut reader = BufReader::with_capacity(256 << 10, io);
    let mut body = vec![0u8; m.chunk_size.get() as usize + TAG_LEN];
    loop {
        let mut raw = [0u8; HEADER_LEN];
        reader
            .read_exact(&mut raw)
            .context("connection ended without the end marker")?;
        if session.sync.is_closed(round) {
            bail!("round {round} closed; dropping its late frames");
        }
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
            h.chunk_index < target.present.len(),
            "chunk {} out of range for file {}",
            h.chunk_index,
            h.file_id
        );
        let len = target.span(h.chunk_index).1;
        ensure!(
            h.ct_len as usize == len as usize + TAG_LEN,
            "ct_len {} does not match chunk length {len}",
            h.ct_len
        );
        let frame = &mut body[..h.ct_len as usize];
        reader.read_exact(frame)?;
        open_frame(&mut cipher, sid, &raw, frame)
            .with_context(|| format!("chunk {} of file {}", h.chunk_index, h.file_id))?;
        session.land(target, h.chunk_index, &frame[..len as usize])?;
    }
}

/// Round bookkeeping shared by the control thread and data threads.
#[derive(Default)]
struct RoundSync {
    state: Mutex<RoundState>,
    cv: Condvar,
    /// Rounds below this are closed. Read lock-free on every frame.
    closed_below: AtomicU32,
}

enum RoundState {
    /// Waiting for `RoundStart { round: next }`.
    Between { next: u32 },
    Open {
        round: u32,
        admitted: HashSet<u32>,
        closed: u32,
    },
    /// The session is over; nothing more is admitted.
    Shut,
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

    fn is_closed(&self, round: u32) -> bool {
        round < self.closed_below.load(Relaxed)
    }

    fn is_shut(&self) -> bool {
        self.closed_below.load(Relaxed) == u32::MAX
    }

    /// Waits up to `ROUND_CLOSE_WAIT` for `connections` admitted
    /// connections of `round` to close, then closes the round: connections
    /// still open drop their buffered frames and hang up.
    fn end(&self, round: u32, connections: u32, progress: &Progress) -> Result<()> {
        let deadline = Instant::now() + ROUND_CLOSE_WAIT;
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
            if Instant::now() >= deadline {
                eprintln!(
                    "mjolnir: round {round}: closing with connections still open after {ROUND_CLOSE_WAIT:?}"
                );
                break;
            }
            state = self
                .cv
                .wait_timeout(state, Duration::from_millis(100))
                .unwrap()
                .0;
        }
        *state = RoundState::Between { next: round + 1 };
        self.closed_below.store(round + 1, Relaxed);
        Ok(())
    }

    /// Ends the session: releases connections waiting in `admit` and stops
    /// every data connection.
    fn shut(&self) {
        *self.state.lock().unwrap() = RoundState::Shut;
        self.closed_below.store(u32::MAX, Relaxed);
        self.cv.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{MIN_CHUNK_SIZE, RelPath};

    fn target_in(dir: &Path, size: u64) -> Target {
        let m = Manifest::new(
            ChunkSize::new(MIN_CHUNK_SIZE).unwrap(),
            vec![FileEntry {
                path: RelPath::parse("f").unwrap(),
                size,
                mtime: 1,
            }],
        )
        .unwrap();
        prepare_targets(dir, &m, false).unwrap().pop().unwrap()
    }

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mjolnir-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_duplicate_chunk_is_dropped_without_writing() {
        let dir = tempdir("dup");
        let t = target_in(&dir, 3 * u64::from(MIN_CHUNK_SIZE));
        let chunk = vec![7u8; MIN_CHUNK_SIZE as usize];
        assert_eq!(t.land(1, &chunk).unwrap(), Landed::Written);
        assert!(t.present.get(1) && t.claimed.get(1));

        let marker = vec![0xAAu8; MIN_CHUNK_SIZE as usize];
        write_all_at(&t.part, &marker, u64::from(MIN_CHUNK_SIZE)).unwrap();
        assert_eq!(t.land(1, &chunk).unwrap(), Landed::Duplicate);
        let mut on_disk = vec![0u8; MIN_CHUNK_SIZE as usize];
        read_exact_at(&t.part, &mut on_disk, u64::from(MIN_CHUNK_SIZE)).unwrap();
        assert_eq!(on_disk, marker, "the duplicate must not touch the file");
        drop(t);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn check_detects_corruption_and_reject_makes_the_chunk_missing() {
        let dir = tempdir("check");
        let t = target_in(&dir, 2 * u64::from(MIN_CHUNK_SIZE) - 5);
        let mut buf = vec![0u8; MIN_CHUNK_SIZE as usize];
        t.land(0, &vec![1u8; MIN_CHUNK_SIZE as usize]).unwrap();
        t.land(1, &vec![2u8; MIN_CHUNK_SIZE as usize - 5]).unwrap();
        assert!(t.check(0, &mut buf).unwrap());
        assert!(t.check(1, &mut buf).unwrap());
        write_all_at(&t.part, &[9u8], 3).unwrap();
        assert!(!t.check(0, &mut buf).unwrap());
        t.reject(0);
        assert!(!t.present.get(0) && !t.claimed.get(0));
        assert_eq!(
            t.land(0, &vec![1u8; MIN_CHUNK_SIZE as usize]).unwrap(),
            Landed::Written
        );
        assert!(t.check(0, &mut buf).unwrap());
        drop(t);
        fs::remove_dir_all(dir).unwrap();
    }
}
