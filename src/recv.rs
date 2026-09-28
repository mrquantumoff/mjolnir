//! The receiver: accept one authenticated sender, admit its data
//! connections round by round, write chunks into part files, and verify
//! them on disk before finishing.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, Scope};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Serialize;

use crate::bitset::{AtomicBitset, PartState};
use crate::crypto::{
    Cipher, CipherState, DIGEST_LEN, FileHasher, FrameKey, SessionKeys, TAG_LEN, chunk_digest,
    handshake_responder,
};
use crate::filemap::{self, ApplyPolicy, FileMap};
use crate::keys::{PrivateKey, PublicKey, require_nonempty};
use crate::manifest::{ChunkSize, FileEntry, Manifest, chunk_count, chunk_span};
use crate::net::{self, Io, tell_peer_about, unexpected};
use crate::pool::{Buffers, Gate, InFlight, Permit, Permits, Pool, buffer_count, resolve_threads};
use crate::posio::{read_exact_at, write_all_at};
use crate::printable;
use crate::progress::{ActiveConnection, Cancelled, Phase, PhaseTimes, Progress, Stop};
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
    /// Workers that open, write, and verify chunks; 0 means one per core.
    pub threads: usize,
    /// How far to trust the sender's file map.
    pub apply: ApplyPolicy,
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
    /// Whether the sender's re-read digests were compared (`send --hash`).
    pub hashed: bool,
    /// Chunks the hash check found different and fetched again.
    pub hash_repaired_chunks: u64,
    /// `(path, file_hash)` per file.
    pub file_hashes: Vec<(String, String)>,
    /// File map entries that could not be applied.
    pub warnings: Vec<String>,
    /// Always empty on the receiver; the sender lists what it skipped.
    pub skipped: Vec<String>,
    pub rounds: u32,
    /// For this session; `connect` is its handshake.
    pub phase_times: PhaseTimes,
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
/// After the handshake, the sender's Offer must arrive within this; until
/// it does, the connection holds only a handshake thread, not the session.
const OFFER_DEADLINE: Duration = Duration::from_secs(10);
/// Handshakes in progress at once; more connections are dropped at accept.
const MAX_PENDING_HANDSHAKES: usize = 256;
/// Stack for a handshake thread; the handshake keeps its buffers on the heap.
const HANDSHAKE_STACK: usize = 256 << 10;
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
const MAX_VERIFY_THREADS: usize = 16;
/// Connections the buffer pool is sized for; more still work, sharing it.
const EXPECTED_CONNECTIONS: usize = 16;

/// A control connection that finished the handshake.
/// A control connection whose sender finished the handshake and whose
/// Offer decrypted, so the sender is live: only these take the session.
struct Handshaken {
    stream: TcpStream,
    keys: SessionKeys,
    peer: PublicKey,
    offer: Msg,
    /// The control stream's receive state after the Offer.
    rx_cipher: CipherState,
}

impl Receiver {
    pub fn bind(cfg: RecvConfig) -> Result<Self> {
        require_nonempty(&cfg.authorized)?;
        crate::pool::check_threads(cfg.threads)?;
        let listener =
            net::listen(cfg.listen).with_context(|| format!("listening on {}", cfg.listen))?;
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
        let permits = Permits::new(MAX_PENDING_HANDSHAKES);
        let authorized = Arc::new(self.cfg.authorized.clone());
        loop {
            if progress.is_cancelled() {
                return Err(Cancelled::Local.into());
            }
            // After a connection, more may be queued: take them before
            // sleeping, or a burst drains one per poll and fills the backlog.
            let wait = match self.listener.accept() {
                Ok((stream, from)) => {
                    // Over the limit, the socket is closed right here.
                    let Some(permit) = permits.try_acquire() else {
                        drop(stream);
                        continue;
                    };
                    let (key, authorized, progress) =
                        (self.cfg.key.clone(), authorized.clone(), progress.clone());
                    let done_tx = done_tx.clone();
                    let spawned = thread::Builder::new()
                        .name("mjolnir-handshake".into())
                        .stack_size(HANDSHAKE_STACK)
                        .spawn(move || {
                            let _permit = permit;
                            match handshake(stream, &key, &authorized, &progress) {
                                Ok(Some(h)) => {
                                    let _ = done_tx.send(h);
                                }
                                Ok(None) => {}
                                Err(e) if progress.is_cancelled() => drop(e),
                                Err(e) => {
                                    eprintln!("mjolnir: handshake with {from} failed: {e:#}")
                                }
                            }
                        });
                    if let Err(e) = spawned {
                        eprintln!("mjolnir: cannot start a handshake thread: {e}");
                    }
                    Duration::ZERO
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => ACCEPT_POLL,
                Err(e) => {
                    eprintln!("mjolnir: accept failed: {e}");
                    ACCEPT_POLL
                }
            };
            let h = match done_rx.recv_timeout(wait) {
                Ok(h) => h,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => unreachable!("run_inner holds a sender"),
            };
            let peer = h.peer;
            match self.session(h, progress) {
                Ok(report) => return Ok(report),
                Err(e) if progress.is_cancelled() => return Err(e),
                Err(e) => {
                    let e = printable::escape(&format!("{e:#}")).into_owned();
                    eprintln!(
                        "mjolnir: session with {peer} failed: {e}; waiting for the next sender"
                    )
                }
            }
            progress.set_phase(Phase::Connecting);
        }
    }

    fn session(&self, h: Handshaken, progress: &Progress) -> Result<RecvReport> {
        let start = Instant::now();
        progress.reset_counts();
        progress.reset_phase_times();
        progress.set_phase(Phase::Handshaking);
        let cancelled = || progress.is_cancelled();
        let control = Io::new(h.stream, &cancelled);
        let (mut tx, _) = wire::control_channel(
            std::io::empty(),
            control.try_clone()?,
            &h.keys,
            Role::Receiver,
        );
        let mut rx = ControlRx::resume(control, h.rx_cipher);
        let result = self.receive(h.keys, h.offer, &mut rx, &mut tx, progress);
        if let Err(e) = &result {
            tell_peer_about(e, progress, Some(&mut tx), Some(&self.cfg.out_dir));
            net::linger(rx.into_inner().into_stream());
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
            hashed: o.finish.hashed,
            hash_repaired_chunks: o.stats.hash_repaired.load(Relaxed),
            file_hashes: o.finish.file_hashes,
            warnings: o.finish.warnings,
            skipped: Vec::new(),
            rounds: o.finish.rounds,
            phase_times: progress.phase_summary(),
            elapsed: start.elapsed(),
        })
    }

    /// Everything after the handshake: offer, rounds, verification, finalize.
    fn receive(
        &self,
        keys: SessionKeys,
        offer: Msg,
        rx: &mut Rx,
        tx: &mut Tx,
        progress: &Progress,
    ) -> Result<Outcome> {
        let (manifest, cipher) = match offer {
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

        let pool = Pool::new(resolve_threads(self.cfg.threads));
        let buf_len = manifest.chunk_size.get() as usize + TAG_LEN;
        let buffers = Buffers::new(
            buffer_count(pool.threads(), EXPECTED_CONNECTIONS, buf_len),
            buf_len,
        );
        let starts = targets
            .iter()
            .scan(0, |next, t| {
                let first = *next;
                *next += t.present.len();
                Some(first)
            })
            .collect();
        let session = Session {
            keys,
            cipher,
            manifest,
            targets,
            verify: self.cfg.verify,
            out_dir: &self.cfg.out_dir,
            policy: self.cfg.apply,
            sync: RoundSync::default(),
            progress,
            stats: Stats::default(),
            fatal: Mutex::new(None),
            checkpoint_lock: Mutex::new(()),
            pending_data: Permits::new(MAX_PENDING_DATA),
            verify_failures: Mutex::new(HashMap::new()),
            pool: &pool,
            buffers: &buffers,
            in_flight: InFlight::default(),
            verify_run: VerifyRun {
                starts,
                cursor: AtomicU64::new(0),
                failure: Mutex::new(None),
            },
        };
        let checkpoints = Stop::default();
        let rounds = thread::scope(|s| {
            for _ in 0..pool.threads() {
                spawn_named(s, "mjolnir-worker", || pool.work(|job| session.run(job)));
            }
            spawn_named(s, "mjolnir-accept", || {
                accept_data(s, &self.listener, &session)
            });
            spawn_named(s, "mjolnir-ckpt", || {
                while !checkpoints.wait(CHECKPOINT_EVERY) {
                    if let Err(e) = session.checkpoint() {
                        eprintln!(
                            "mjolnir: checkpoint failed: {}",
                            printable::escape(&format!("{e:#}"))
                        );
                    }
                }
            });
            let result = session.rounds(rx, tx);
            checkpoints.stop();
            session.sync.shut();
            pool.close();
            result
        });
        // Data connections still queued in the listener would wait out
        // their hello deadline; hang up on them now.
        while self.listener.accept().is_ok() {}
        if rounds.is_err()
            && let Err(e) = session.checkpoint()
        {
            eprintln!(
                "mjolnir: checkpoint failed: {}",
                printable::escape(&format!("{e:#}"))
            );
        }
        let finish = rounds?;
        Ok(Outcome {
            files: session.targets.len(),
            stats: session.stats,
            verified: session.verify,
            finish,
        })
    }
}

type Tx<'a> = ControlTx<Io<'a>>;
type Rx<'a> = ControlRx<Io<'a>>;

/// A scoped thread with a name, so profilers can tell the roles apart.
fn spawn_named<'s, F>(s: &'s Scope<'s, '_>, name: &str, f: F)
where
    F: FnOnce() + Send + 's,
{
    thread::Builder::new()
        .name(name.into())
        .spawn_scoped(s, f)
        .expect("spawning a session thread");
}

/// Counters for one session's report.
#[derive(Default)]
struct Stats {
    chunks: AtomicU64,
    bytes: AtomicU64,
    duplicates: AtomicU64,
    repaired: AtomicU64,
    hash_repaired: AtomicU64,
}

struct Outcome {
    files: usize,
    stats: Stats,
    verified: bool,
    finish: Finish,
}

/// What the final round decided.
struct Finish {
    rounds: u32,
    hashed: bool,
    file_hashes: Vec<(String, String)>,
    warnings: Vec<String>,
}

/// The sender's `Finalize`, kept while a hash repair round runs.
struct Finalized {
    hash: bool,
    map: FileMap,
    /// The sender's digests for the chunks the hash check sent back.
    expected: HashMap<(u32, u64), [u8; DIGEST_LEN]>,
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
    // Message 1 can be replayed, so the handshake alone proves nothing
    // about liveness; the Offer does, because only the real sender can
    // seal it. Reading it here keeps unconfirmed peers out of the session.
    let reader = Io::new(io.into_stream(), &cancelled).deadline(OFFER_DEADLINE);
    let (_, mut rx) = wire::control_channel(reader, std::io::sink(), &keys, Role::Receiver);
    let offer = rx.recv().context("waiting for the Offer")?;
    ensure!(
        matches!(offer, Msg::Offer { .. }),
        "expected Offer, got {offer:?}"
    );
    let (reader, rx_cipher) = rx.into_parts()?;
    Ok(Some(Handshaken {
        stream: reader.into_stream(),
        keys,
        peer,
        offer,
        rx_cipher,
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
    /// One worker writes this file at a time. Concurrent positional writes
    /// into one file serialize on the inode lock anyway, and on Linux the
    /// waiters spin: 32 workers burned about 15 cores writing 830 MiB/s
    /// into one ext4 file where a single writer used 0.3 cores for
    /// 1.2 GiB/s. A 1 MiB copy into the page cache takes about 200 us, so
    /// the pool keeps opening frames while one worker writes. The
    /// `MJOLNIR_WRITERS_PER_FILE` knob widens the gate for measurements.
    writers: Gate,
}

/// What became of one authenticated chunk.
#[derive(Debug, PartialEq, Eq)]
enum Landed {
    Written,
    Duplicate,
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
        // Hash outside the gate, so only the writes serialize per file.
        let digest = chunk_digest(plaintext);
        let slot = self.writers.enter();
        let data = if crate::benchmode::get().discard {
            Ok(())
        } else {
            write_all_at(&self.part, plaintext, self.span(index).0)
        };
        let written =
            data.and_then(|()| write_all_at(&self.sums, &digest, index * DIGEST_LEN as u64));
        drop(slot);
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
        Ok(chunk_digest(data) == stored)
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
        let final_path = entry.path.to_local_path(out);
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
            writers: Gate::new(crate::benchmode::get().writers_per_file),
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
    out_dir: &'a Path,
    policy: ApplyPolicy,
    sync: RoundSync,
    progress: &'a Progress,
    stats: Stats,
    /// A local write failure; ends the transfer at the end of the round.
    fatal: Mutex<Option<String>>,
    /// Serializes checkpoints so only one thread writes state files.
    checkpoint_lock: Mutex<()>,
    /// Data connections accepted but not yet admitted or rejected.
    pending_data: Arc<Permits>,
    /// Verification failures per `(file, chunk)` this session.
    verify_failures: Mutex<HashMap<(u32, u64), u8>>,
    pool: &'a Pool<RecvJob>,
    buffers: &'a Buffers,
    /// Frames handed to the pool and not yet landed, plus verify jobs.
    in_flight: InFlight,
    verify_run: VerifyRun,
}

/// Work for the pool.
enum RecvJob {
    /// Open frame `k` of `conn`, then land its chunk. `buf` holds the body.
    Frame {
        conn: Arc<RecvConn>,
        k: u64,
        header: [u8; HEADER_LEN],
        buf: Vec<u8>,
    },
    /// Read chunks back from `verify_run.cursor` until none are left.
    Verify,
}

/// A data connection as the pool sees it.
struct RecvConn {
    key: FrameKey,
    /// Set when one of its frames fails to open; its reader then stops.
    dead: AtomicBool,
}

/// Shared state of one verification pass.
struct VerifyRun {
    /// `starts[j]` is the global number of file j's first chunk.
    starts: Vec<u64>,
    cursor: AtomicU64,
    failure: Mutex<Option<anyhow::Error>>,
}

impl Session<'_> {
    /// Drives the control channel until `Finished`.
    fn rounds(&self, rx: &mut Rx, tx: &mut Tx) -> Result<Finish> {
        let mut finalized: Option<Finalized> = None;
        loop {
            let (round, connections) = match rx.recv()? {
                Msg::RoundStart { round } => {
                    self.sync.start(round)?;
                    self.progress.set_phase(Phase::Transferring);
                    continue;
                }
                Msg::RoundEnd { round, connections } => (round, connections),
                other => return Err(unexpected(other, "RoundStart or RoundEnd")),
            };
            self.sync.end(round, connections, self.progress)?;
            self.in_flight.wait_idle();
            if let Some(message) = self.fatal.lock().unwrap().take() {
                bail!(message);
            }
            self.checkpoint()?;
            if self.all_present() && self.verify {
                self.progress.set_phase(Phase::Verifying);
                tx.send(&Msg::Verifying)?;
                self.verify_all()?;
            }
            if self.all_present() {
                match &finalized {
                    None => {
                        tx.send(&Msg::Delivered)?;
                        self.progress.set_phase(Phase::Finishing);
                        finalized = Some(self.await_finalize(rx)?);
                    }
                    Some(done) => self.check_repairs(done)?,
                }
            }
            if self.all_present() {
                let done = finalized.expect("finalized before every chunk is present");
                self.progress.set_phase(Phase::Finishing);
                let file_hashes = self.file_hashes()?;
                self.finalize()?;
                let warnings = filemap::apply(&done.map, self.out_dir, self.policy);
                for w in &warnings {
                    eprintln!("mjolnir: {}", printable::escape(w));
                }
                tx.send(&Msg::Finished {
                    verified: self.verify,
                    hashed: done.hash,
                    warnings: warnings.clone(),
                })?;
                return Ok(Finish {
                    rounds: round + 1,
                    hashed: done.hash,
                    file_hashes,
                    warnings,
                });
            }
            self.checkpoint()?;
            set_missing_totals(self.progress, &self.targets, self.manifest.chunk_size);
            tx.send(&have_msg(&self.targets))?;
        }
    }

    fn all_present(&self) -> bool {
        self.targets.iter().all(|t| t.present.is_full())
    }

    /// After `Delivered`: reads the sender's `Digests` (if any) and its
    /// `Finalize`. Chunks whose stored digest differs from the sender's
    /// become missing and are remembered for the repair round.
    fn await_finalize(&self, rx: &mut Rx) -> Result<Finalized> {
        let mut expected = HashMap::new();
        loop {
            match rx.recv()? {
                Msg::Digests {
                    file,
                    first,
                    digests,
                } => {
                    self.progress.set_phase(Phase::Hashing);
                    self.compare_digests(file, first, &digests, &mut expected)?;
                }
                Msg::Finalize { hash, map } => {
                    let offer: Vec<_> =
                        self.manifest.files.iter().map(|f| f.path.clone()).collect();
                    map.check(&offer).context("rejected the file map")?;
                    return Ok(Finalized {
                        hash,
                        map,
                        expected,
                    });
                }
                other => return Err(unexpected(other, "Digests or Finalize")),
            }
        }
    }

    fn compare_digests(
        &self,
        file: u32,
        first: u64,
        digests: &[u8],
        expected: &mut HashMap<(u32, u64), [u8; DIGEST_LEN]>,
    ) -> Result<()> {
        let t = self
            .targets
            .get(file as usize)
            .with_context(|| format!("Digests for file {file}, which is not in the offer"))?;
        ensure!(
            digests.len().is_multiple_of(DIGEST_LEN),
            "Digests length is not a multiple of {DIGEST_LEN}"
        );
        let n = (digests.len() / DIGEST_LEN) as u64;
        ensure!(
            first
                .checked_add(n)
                .is_some_and(|end| end <= t.present.len()),
            "Digests for chunks past the end of {}",
            t.entry.path.display()
        );
        let mut ours = vec![0u8; digests.len()];
        read_exact_at(&t.sums, &mut ours, first * DIGEST_LEN as u64)?;
        let (theirs, _) = digests.as_chunks::<DIGEST_LEN>();
        let (mine, _) = ours.as_chunks::<DIGEST_LEN>();
        for (i, (theirs, mine)) in theirs.iter().zip(mine).enumerate() {
            if theirs != mine {
                let index = first + i as u64;
                t.reject(index);
                self.stats.hash_repaired.fetch_add(1, Relaxed);
                expected.insert((file, index), *theirs);
            }
        }
        Ok(())
    }

    /// After a hash repair round: every refetched chunk must now match the
    /// digest the sender reported.
    fn check_repairs(&self, done: &Finalized) -> Result<()> {
        for (&(file, index), want) in &done.expected {
            let t = &self.targets[file as usize];
            let mut stored = [0u8; DIGEST_LEN];
            read_exact_at(&t.sums, &mut stored, index * DIGEST_LEN as u64)?;
            ensure!(
                stored == *want,
                "{} changed during transfer",
                t.entry.path.display()
            );
        }
        Ok(())
    }

    /// `(path, BLAKE3(chunk_size u32 | chunk digests))` for every file, from
    /// the sums files.
    fn file_hashes(&self) -> Result<Vec<(String, String)>> {
        let chunk_size = self.manifest.chunk_size.get();
        self.targets
            .iter()
            .map(|t| {
                let mut digests = vec![0u8; t.present.len() as usize * DIGEST_LEN];
                read_exact_at(&t.sums, &mut digests, 0)?;
                let mut hasher = FileHasher::new(chunk_size);
                hasher.update(&digests);
                Ok((t.entry.path.display(), hasher.hex()))
            })
            .collect()
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

    /// Syncs, then reads every chunk back on the worker pool (at most
    /// `MAX_VERIFY_THREADS` at once) and compares each with its digest.
    /// Mismatches become missing again.
    fn verify_all(&self) -> Result<()> {
        for t in &self.targets {
            t.part.sync_data()?;
            t.sums.sync_data()?;
        }
        let total_bytes: u64 = self.targets.iter().map(|t| t.entry.size).sum();
        let total_chunks: u64 = self.targets.iter().map(|t| t.present.len()).sum();
        self.progress.reset_counts();
        self.progress.set_totals(total_chunks, total_bytes);
        let run = &self.verify_run;
        run.cursor.store(0, Relaxed);
        for _ in 0..self.pool.threads().min(MAX_VERIFY_THREADS) {
            self.in_flight.add();
            self.pool.submit(RecvJob::Verify);
        }
        self.in_flight.wait_idle();
        if self.progress.is_cancelled() {
            return Err(Cancelled::Local.into());
        }
        match run.failure.lock().unwrap().take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// One pool worker's share of a verification pass.
    fn verify_some(&self) {
        let run = &self.verify_run;
        let total = self.targets.iter().map(|t| t.present.len()).sum();
        let mut buf = vec![0u8; self.manifest.chunk_size.get() as usize];
        while let n = run.cursor.fetch_add(1, Relaxed)
            && n < total
            && !self.progress.is_cancelled()
        {
            let file = run.starts.partition_point(|&first| first <= n) - 1;
            let (t, index) = (&self.targets[file], n - run.starts[file]);
            if let Err(e) = self.verify_chunk(file as u32, t, index, &mut buf) {
                *run.failure.lock().unwrap() = Some(e);
                return;
            }
        }
    }

    /// Runs one pool job.
    fn run(&self, job: RecvJob) {
        match job {
            RecvJob::Frame {
                conn,
                k,
                header,
                mut buf,
            } => {
                let h = FrameHeader::decode(&header);
                let target = &self.targets[h.file_id as usize];
                let body = &mut buf[..h.ct_len as usize];
                let sid = &self.keys.session_id;
                if open_frame(&conn.key, k, sid, &header, body).is_ok() {
                    let len = body.len() - TAG_LEN;
                    // A failed write is recorded in `fatal` for the round.
                    let _ = self.land(target, h.chunk_index, &body[..len]);
                } else if !conn.dead.swap(true, Relaxed) {
                    eprintln!(
                        "mjolnir: frame {k} (chunk {} of file {}) failed to authenticate; \
                         dropping its connection",
                        h.chunk_index, h.file_id
                    );
                }
                self.buffers.give(buf);
            }
            RecvJob::Verify => self.verify_some(),
        }
        self.in_flight.done();
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
            t.entry.path.display()
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
                // Over the limit, the socket is closed right here.
                let Some(permit) = session.pending_data.try_acquire() else {
                    drop(stream);
                    continue;
                };
                spawn_named(s, "mjolnir-data", move || {
                    if let Err(e) = serve_data(session, stream, permit)
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

/// `pending` is this connection's slot among the unadmitted ones; it is
/// released once the connection is admitted.
fn serve_data(session: &Session, stream: TcpStream, pending: Permit) -> Result<()> {
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
    let conn = Arc::new(RecvConn {
        key: FrameKey::new(session.cipher, &session.keys.data_key(round, conn)),
        dead: AtomicBool::new(false),
    });
    let stop = || ended() || session.sync.is_closed(round) || conn.dead.load(Relaxed);
    let io = Io::new(hello_io.into_stream(), &stop).idle(DATA_IDLE);
    receive_frames(session, io, round, &conn, &stop)
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

/// The connection's reader: does I/O only. It checks each header, reads
/// the body into a pooled buffer, numbers the frame, and hands it to the
/// pool, which opens and lands it.
fn receive_frames(
    session: &Session,
    io: Io,
    round: u32,
    conn: &Arc<RecvConn>,
    stop: &dyn Fn() -> bool,
) -> Result<()> {
    let sid = &session.keys.session_id;
    let mut reader = BufReader::with_capacity(256 << 10, io);
    for k in 0u64.. {
        let mut header = [0u8; HEADER_LEN];
        reader
            .read_exact(&mut header)
            .context("connection ended without the end marker")?;
        if session.sync.is_closed(round) {
            bail!("round {round} closed; dropping its late frames");
        }
        ensure!(!conn.dead.load(Relaxed), "a frame failed to authenticate");
        let h = FrameHeader::decode(&header);
        if h.is_end() {
            ensure!(h == FrameHeader::end(), "malformed end marker");
            let mut tag = [0u8; TAG_LEN];
            reader.read_exact(&mut tag)?;
            return open_frame(&conn.key, k, sid, &header, &mut tag).context("end marker");
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
        let Some(mut buf) = session.buffers.take(stop) else {
            bail!("connection stopped");
        };
        if let Err(e) = reader.read_exact(&mut buf[..h.ct_len as usize]) {
            session.buffers.give(buf);
            return Err(e.into());
        }
        session.in_flight.add();
        session.pool.submit(RecvJob::Frame {
            conn: conn.clone(),
            k,
            header,
            buf,
        });
    }
    unreachable!("u64 frame numbers exhausted")
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
        if progress.is_cancelled() {
            return Err(Cancelled::Local.into());
        }
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
    use crate::manifest::MIN_CHUNK_SIZE;
    use crate::names::WirePath;

    fn target_in(dir: &Path, size: u64) -> Target {
        let m = Manifest::new(
            ChunkSize::new(MIN_CHUNK_SIZE).unwrap(),
            vec![FileEntry {
                path: WirePath::parse([b"f".to_vec()]).unwrap(),
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
