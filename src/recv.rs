//! The receiver: accept one authenticated sender, admit its data
//! connections round by round, write chunks into part files, and verify
//! them on disk before finishing.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
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
use crate::filemap::{self, ApplyPolicy, EntryKind, FileMap};
use crate::fsops;
use crate::keys::{PrivateKey, PublicKey, require_nonempty};
use crate::manifest::{ChunkSize, FileEntry, Manifest, chunk_count, chunk_span};
use crate::net::{self, Io, tell_peer_about, unexpected};
use crate::pool::{Buffers, Gate, InFlight, Permit, Permits, Pool, buffer_count, resolve_threads};
use crate::posio::{read_exact_at, write_all_at};
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
    /// Resumed chunks whose digest no longer matched the sender's fresh
    /// read of the source, and were fetched again.
    pub stale_chunks: u64,
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
/// After the handshake, the sender's `Confirm` must arrive within this;
/// until it does, the connection holds only a handshake thread and a
/// `CONFIRM_LEN`-byte buffer, not the session.
const CONFIRM_DEADLINE: Duration = Duration::from_secs(10);
/// Once a connection holds the session, its `Offer` must arrive within this.
const OFFER_DEADLINE: Duration = Duration::from_secs(10);
/// Handshakes in progress at once; more connections are dropped at accept.
/// Each buffers at most `CONFIRM_LEN` bytes before its peer proves it is
/// live, so unconfirmed peers hold under 8 KiB of control buffers in all.
const MAX_PENDING_HANDSHAKES: usize = 256;
/// Stack for a handshake thread; the handshake keeps its buffers on the heap.
const HANDSHAKE_STACK: usize = 256 << 10;
/// Data connections not yet admitted at once; more are dropped at accept.
const MAX_PENDING_DATA: usize = 64;
/// Admitted data connections open at once, and admissions per round. Each
/// holds a thread and a 256 KiB reader buffer; the sender's `--connections`
/// stops at the same number.
pub const MAX_DATA_CONNECTIONS: usize = 256;
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

/// A control connection whose sender finished the handshake and whose
/// `Confirm` decrypted, so the sender is live: only these take the session.
struct Handshaken {
    stream: TcpStream,
    keys: SessionKeys,
    peer: PublicKey,
    /// The control stream's receive state after `Confirm`.
    rx_cipher: CipherState,
}

impl Receiver {
    pub fn bind(cfg: RecvConfig) -> Result<Self> {
        require_nonempty(&cfg.authorized)?;
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
        // The Offer may be large; only a confirmed sender gets this far,
        // and it still has to deliver it within the deadline.
        let mut offer_rx =
            ControlRx::resume(control.try_clone()?.deadline(OFFER_DEADLINE), h.rx_cipher);
        let offer = offer_rx.recv().context("waiting for the Offer");
        let (offer, rx_cipher) = match offer.and_then(|o| Ok((o, offer_rx.into_parts()?.1))) {
            Ok(got) => got,
            Err(e) => {
                net::linger(control.into_stream());
                return Err(e);
            }
        };
        let mut rx = ControlRx::resume(control, rx_cipher);
        let result = self.receive(h.keys, h.peer, offer, &mut rx, &mut tx, progress);
        if let Err(e) = &result {
            tell_peer_about(e, progress, Some(&mut tx));
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
            stale_chunks: o.stats.stale.load(Relaxed),
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
        peer: PublicKey,
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
                dirs,
            } => (
                Manifest::from_offer(chunk_size, files, dirs).context("rejected the offer")?,
                cipher,
            ),
            other => return Err(unexpected(other, "Offer")),
        };
        let (store, targets) =
            prepare_targets(&self.cfg.out_dir, &manifest, &peer, self.cfg.force)?;
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
            store,
            verify: self.cfg.verify,
            out_dir: &self.cfg.out_dir,
            policy: self.cfg.apply,
            sync: RoundSync::default(),
            progress,
            stats: Stats::default(),
            fatal: Mutex::new(None),
            checkpoint_lock: Mutex::new(()),
            pending_data: Permits::new(MAX_PENDING_DATA),
            active_data: Permits::new(MAX_DATA_CONNECTIONS),
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
        set_missing_totals(progress, &session.targets, session.manifest.chunk_size);
        tx.send(&have_msg(&session.targets))?;
        if session.targets.iter().any(|t| t.present.count_ones() > 0) {
            progress.set_phase(Phase::Hashing);
            session.check_resume(rx)?;
            session.checkpoint()?;
            set_missing_totals(progress, &session.targets, session.manifest.chunk_size);
            tx.send(&have_msg(&session.targets))?;
        }
        progress.set_phase(Phase::Transferring);
        let checkpoints = Stop::default();
        let rounds = thread::scope(|s| {
            let spawned = (|| {
                for _ in 0..pool.threads() {
                    spawn_named(s, "mjolnir-worker", || pool.work(|job| session.run(job)))?;
                }
                spawn_named(s, "mjolnir-accept", || {
                    accept_data(s, &self.listener, &session)
                })?;
                spawn_named(s, "mjolnir-ckpt", || {
                    while !checkpoints.wait(CHECKPOINT_EVERY) {
                        if let Err(e) = session.checkpoint() {
                            eprintln!("mjolnir: checkpoint failed: {e:#}");
                        }
                    }
                })
            })();
            let result = match spawned {
                Ok(()) => session.rounds(rx, tx),
                Err(e) => Err(anyhow!(e).context("starting the session's threads")),
            };
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
            eprintln!("mjolnir: checkpoint failed: {e:#}");
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
fn spawn_named<'s, F>(s: &'s Scope<'s, '_>, name: &str, f: F) -> io::Result<()>
where
    F: FnOnce() + Send + 's,
{
    thread::Builder::new()
        .name(name.into())
        .spawn_scoped(s, f)
        .map(drop)
}

/// Counters for one session's report.
#[derive(Default)]
struct Stats {
    chunks: AtomicU64,
    bytes: AtomicU64,
    duplicates: AtomicU64,
    repaired: AtomicU64,
    hash_repaired: AtomicU64,
    stale: AtomicU64,
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
    // about liveness; the fixed-size Confirm does, because only the real
    // sender can seal it. Reading it here keeps unconfirmed peers out of
    // the session while buffering nothing they can size.
    let reader = Io::new(io.into_stream(), &cancelled).deadline(CONFIRM_DEADLINE);
    let (_, mut rx) = wire::control_channel(reader, std::io::sink(), &keys, Role::Receiver);
    rx.recv_confirm().context("waiting for Confirm")?;
    let (reader, rx_cipher) = rx.into_parts()?;
    Ok(Some(Handshaken {
        stream: reader.into_stream(),
        keys,
        peer,
        rx_cipher,
    }))
}

/// Open handles kept at once by the receiver's handle cache; a transfer
/// of more files than this reopens them as its work moves along.
const MAX_OPEN_TARGETS: usize = 256;
/// How long the receiver waits for the sender's `Ack` of `Finished`
/// before keeping its journal for a retry.
const ACK_WAIT: Duration = Duration::from_secs(5);
/// The private directory under the output directory that holds every
/// transfer's staging files, keyed by transfer identity.
pub const STAGING_DIR: &str = ".mjolnir-staging";

/// One output file: its staging files, its bitmaps, and its commit state.
struct Target {
    file_id: u32,
    entry: FileEntry,
    chunk_size: ChunkSize,
    final_path: PathBuf,
    /// Where the bytes live: the staging part file until the file is
    /// committed, the final path afterwards.
    payload: Mutex<PathBuf>,
    part_path: PathBuf,
    /// `DIGEST_LEN` bytes of BLAKE3 per chunk, at `index * DIGEST_LEN`.
    sums_path: PathBuf,
    state_path: PathBuf,
    /// Renamed into place; the journal treats the file as published.
    committed: AtomicBool,
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

/// A target's payload and sums handles, shared by whoever has them open.
struct Open {
    part: File,
    sums: File,
}

/// At most `MAX_OPEN_TARGETS` targets open at once, least recently used
/// closed first, so a tree of many files never exhausts descriptors.
struct Handles {
    cap: usize,
    state: Mutex<HandleState>,
}

struct HandleState {
    open: HashMap<u32, (Arc<Open>, u64)>,
    tick: u64,
}

impl Handles {
    fn new(cap: usize) -> Self {
        Handles {
            cap,
            state: Mutex::new(HandleState {
                open: HashMap::new(),
                tick: 0,
            }),
        }
    }

    fn get(&self, t: &Target) -> io::Result<Arc<Open>> {
        let mut s = self.state.lock().unwrap();
        s.tick += 1;
        let tick = s.tick;
        if let Some((open, used)) = s.open.get_mut(&t.file_id) {
            *used = tick;
            return Ok(open.clone());
        }
        let part = fsops::open_private(&t.payload.lock().unwrap(), false)?;
        let sums = fsops::open_private(&t.sums_path, false)?;
        let open = Arc::new(Open { part, sums });
        if s.open.len() >= self.cap
            && let Some(&oldest) = s
                .open
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(k, _)| k)
        {
            s.open.remove(&oldest);
        }
        s.open.insert(t.file_id, (open.clone(), tick));
        Ok(open)
    }

    /// Drops the cached handles of a target whose payload moved.
    fn forget(&self, file_id: u32) {
        self.state.lock().unwrap().open.remove(&file_id);
    }

    /// Drops every cached handle, so the staging directory can be moved.
    fn clear(&self) {
        self.state.lock().unwrap().open.clear();
    }
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
    fn land(&self, files: &Open, index: u64, plaintext: &[u8]) -> io::Result<Landed> {
        if !self.claimed.set(index) {
            return Ok(Landed::Duplicate);
        }
        // Hash outside the gate, so only the writes serialize per file.
        let digest = chunk_digest(plaintext);
        let slot = self.writers.enter();
        let data = if crate::benchmode::get().discard {
            Ok(())
        } else {
            write_all_at(&files.part, plaintext, self.span(index).0)
        };
        let written =
            data.and_then(|()| write_all_at(&files.sums, &digest, index * DIGEST_LEN as u64));
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
    fn check(&self, files: &Open, index: u64, buf: &mut [u8]) -> io::Result<bool> {
        let (offset, len) = self.span(index);
        let data = &mut buf[..len as usize];
        read_exact_at(&files.part, data, offset)?;
        let mut stored = [0u8; DIGEST_LEN];
        read_exact_at(&files.sums, &mut stored, index * DIGEST_LEN as u64)?;
        Ok(chunk_digest(data) == stored)
    }

    /// Makes a chunk missing again after it failed verification.
    fn reject(&self, index: u64) {
        self.present.clear(index);
        self.claimed.clear(index);
        self.dirty.store(true, Relaxed);
    }
}

/// The receiver's staging area for one transfer: `<out>/.mjolnir-staging`
/// is owner-only and holds a lock file, so one session runs per output
/// directory, and one directory per transfer identity holds every file's
/// `<id>.part`, `<id>.sums`, and `<id>.state`. That directory is the
/// finalization journal: it exists from the first chunk until the sender
/// acknowledges `Finished`, and a file whose part is gone from it while
/// the directory remains was renamed into place.
struct Store {
    stage: PathBuf,
    _lock: File,
    #[cfg_attr(windows, allow(dead_code))]
    umask: u32,
    force: bool,
    handles: Handles,
}

fn hex16(id: &[u8; 32]) -> String {
    id[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Where a transfer of `m` from `peer` into `out` keeps its staging files.
pub fn staging_dir(out: &Path, m: &Manifest, peer: &PublicKey) -> PathBuf {
    crate::names::local_dir(out)
        .join(STAGING_DIR)
        .join(hex16(&m.identity(peer)))
}

/// Fault injection for the crash tests, scoped to one output directory so
/// tests in one process do not disturb each other.
#[doc(hidden)]
pub mod testing {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Fault {
        /// Fail finalization right after the first file is renamed into
        /// place, leaving the rest staged.
        FailAfterFirstPublish,
        /// Behave as if `Finished` never reached the sender: keep the
        /// journal instead of waiting for `Ack`.
        LoseFinished,
    }

    static FAULTS: Mutex<Vec<(PathBuf, Fault)>> = Mutex::new(Vec::new());

    pub fn inject(out_dir: &Path, fault: Fault) {
        FAULTS.lock().unwrap().push((out_dir.to_path_buf(), fault));
    }

    pub(crate) fn take(out_dir: &Path, fault: Fault) -> bool {
        let mut faults = FAULTS.lock().unwrap();
        match faults.iter().position(|(d, f)| d == out_dir && *f == fault) {
            Some(i) => {
                faults.remove(i);
                true
            }
            None => false,
        }
    }
}

/// Prepares every target: takes the output directory's lock, creates the
/// transfer's staging directory and every directory the offer lists,
/// resumes part files whose state is valid, treats files that an
/// interrupted finalization already renamed into place as committed, and
/// starts everything else from scratch.
fn prepare_targets(
    out: &Path,
    m: &Manifest,
    peer: &PublicKey,
    force: bool,
) -> Result<(Store, Vec<Target>)> {
    let out = crate::names::local_dir(out);
    let root = out.join(STAGING_DIR);
    fsops::create_private_dir(&root).with_context(|| format!("creating {}", root.display()))?;
    let lock = fsops::open_private(&root.join("lock"), true)?;
    ensure!(
        fsops::try_lock_exclusive(&lock)?,
        "another receiver is using {}",
        out.display()
    );
    let stage = staging_dir(&out, m, peer);
    let done = stage.with_extension("done");
    if done.is_dir() && !stage.is_dir() {
        fsops::rename_durable(&done, &stage, false)?;
    }
    let journal = stage.is_dir();
    fsops::create_private_dir(&stage)?;
    for dir in &m.dirs {
        let local = dir.to_local_path(&out);
        fs::create_dir_all(&local).with_context(|| format!("creating {}", local.display()))?;
    }
    let store = Store {
        stage: stage.clone(),
        _lock: lock,
        #[cfg(unix)]
        umask: fsops::umask(),
        #[cfg(windows)]
        umask: 0,
        force,
        handles: Handles::new(MAX_OPEN_TARGETS),
    };
    let mut targets = Vec::with_capacity(m.files.len());
    let mut regenerate = Vec::new();
    for (j, entry) in m.files.iter().enumerate() {
        let file_id = j as u32;
        let final_path = entry.path.to_local_path(&out);
        let part_path = stage.join(format!("{j}.part"));
        let sums_path = stage.join(format!("{j}.sums"));
        let state_path = stage.join(format!("{j}.state"));
        let count = chunk_count(entry.size, m.chunk_size);
        let part_exists = part_path.is_file();
        let published = journal
            && !part_exists
            && fs::metadata(&final_path).is_ok_and(|md| md.is_file() && md.len() == entry.size);
        let (present, payload) = if published {
            let sums = fsops::open_private(&sums_path, true)?;
            if sums.metadata()?.len() != count * DIGEST_LEN as u64 {
                sums.set_len(count * DIGEST_LEN as u64)?;
                regenerate.push(file_id);
            }
            let present = AtomicBitset::new(count);
            for k in 0..count {
                present.set(k);
            }
            (present, final_path.clone())
        } else {
            if !force && fs::symlink_metadata(&final_path).is_ok() {
                bail!(
                    "{} already exists (use --force to overwrite)",
                    final_path.display()
                );
            }
            if let Some(parent) = final_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let resumed = (part_exists && sums_path.is_file())
                .then(|| PartState::load(&state_path).ok())
                .flatten()
                .filter(|s| {
                    s.size == entry.size
                        && s.mtime == entry.mtime
                        && s.chunk_size == m.chunk_size.get()
                        && s.bitmap.len() as u64 == count.div_ceil(8)
                });
            // A stale state file goes before the part file is truncated,
            // so no crash can leave a matching state next to zeroed data.
            if resumed.is_none() {
                fsops::remove_durable(&state_path)?;
            }
            let open = |path: &Path, len: u64| -> Result<()> {
                let file = fsops::open_private(path, true)
                    .with_context(|| format!("opening {}", path.display()))?;
                if resumed.is_none() {
                    file.set_len(0)?;
                }
                file.set_len(len)?;
                Ok(())
            };
            open(&part_path, entry.size)?;
            open(&sums_path, count * DIGEST_LEN as u64)?;
            let present = match &resumed {
                Some(state) => AtomicBitset::from_bytes(count, &state.bitmap),
                None => AtomicBitset::new(count),
            };
            (present, part_path.clone())
        };
        let claimed = AtomicBitset::from_bytes(count, &present.to_bytes());
        targets.push(Target {
            file_id,
            entry: entry.clone(),
            chunk_size: m.chunk_size,
            final_path,
            payload: Mutex::new(payload),
            part_path,
            sums_path,
            state_path,
            committed: AtomicBool::new(published),
            present,
            claimed,
            dirty: AtomicBool::new(false),
            writers: Gate::new(crate::benchmode::get().writers_per_file),
        });
    }
    for file_id in regenerate {
        let t = &targets[file_id as usize];
        let files = store.handles.get(t)?;
        let mut buf = vec![0u8; m.chunk_size.get() as usize];
        for k in 0..t.present.len() {
            let (offset, len) = t.span(k);
            read_exact_at(&files.part, &mut buf[..len as usize], offset)
                .with_context(|| format!("reading back {}", t.final_path.display()))?;
            let digest = chunk_digest(&buf[..len as usize]);
            write_all_at(&files.sums, &digest, k * DIGEST_LEN as u64)?;
        }
        files.sums.sync_data()?;
    }
    Ok((store, targets))
}

impl Store {
    /// After the sender acknowledged `Finished`: the journal is renamed
    /// aside, so a crash mid-removal still reads as complete, then removed.
    fn cleanup(&self) -> Result<()> {
        self.handles.clear();
        let done = self.stage.with_extension("done");
        fsops::rename_durable(&self.stage, &done, false)?;
        fsops::remove_tree_durable(&done)?;
        Ok(())
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
    store: Store,
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
    /// Admitted data connections; a permit is held until the connection
    /// closes, so a peer cannot open more than `MAX_DATA_CONNECTIONS`.
    active_data: Arc<Permits>,
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
                self.finalize(&done.map)?;
                let warnings = filemap::apply(&done.map, self.out_dir, self.policy);
                for w in &warnings {
                    eprintln!("mjolnir: {w}");
                }
                tx.send(&Msg::Finished {
                    verified: self.verify,
                    hashed: done.hash,
                    warnings: warnings.clone(),
                })?;
                // Only an acknowledged Finished lets the journal go; a
                // sender that never saw it can run again and replay.
                rx.inner_mut().set_deadline(ACK_WAIT);
                let acked = !testing::take(self.out_dir, testing::Fault::LoseFinished)
                    && matches!(rx.recv(), Ok(Msg::Ack));
                // The transfer is complete either way; what remains is
                // housekeeping, so its failures are reported, not fatal.
                match acked {
                    true => {
                        if let Err(e) = self.store.cleanup() {
                            eprintln!(
                                "mjolnir: could not remove {}: {e:#}",
                                self.store.stage.display()
                            );
                        }
                    }
                    false => eprintln!(
                        "mjolnir: the sender did not acknowledge Finished; keeping {} for a retry",
                        self.store.stage.display()
                    ),
                }
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

    /// Before round 0 of a resumed transfer: the sender re-reads every
    /// chunk the `Have` reported present and sends its digests. A chunk
    /// whose stored digest differs is stale (the source changed behind
    /// its size and mtime, or an earlier session left other bytes) and
    /// becomes missing again.
    fn check_resume(&self, rx: &mut Rx) -> Result<()> {
        loop {
            match rx.recv()? {
                Msg::Digests {
                    file,
                    first,
                    digests,
                } => self.compare_digests(file, first, &digests, |_, _, _| {
                    self.stats.stale.fetch_add(1, Relaxed);
                })?,
                Msg::Resume => return Ok(()),
                other => return Err(unexpected(other, "Digests or Resume")),
            }
        }
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
                    self.compare_digests(file, first, &digests, |file, index, theirs| {
                        self.stats.hash_repaired.fetch_add(1, Relaxed);
                        expected.insert((file, index), theirs);
                    })?;
                }
                Msg::Finalize { hash, map } => {
                    map.check(&self.manifest).context("rejected the file map")?;
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

    /// Compares the sender's digests for chunks `first..` of `file` with
    /// the stored ones. A mismatched chunk becomes missing and is reported
    /// to `mismatch` with the sender's digest.
    fn compare_digests(
        &self,
        file: u32,
        first: u64,
        digests: &[u8],
        mut mismatch: impl FnMut(u32, u64, [u8; DIGEST_LEN]),
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
        let files = self.store.handles.get(t)?;
        let mut ours = vec![0u8; digests.len()];
        read_exact_at(&files.sums, &mut ours, first * DIGEST_LEN as u64)?;
        let (theirs, _) = digests.as_chunks::<DIGEST_LEN>();
        let (mine, _) = ours.as_chunks::<DIGEST_LEN>();
        for (i, (theirs, mine)) in theirs.iter().zip(mine).enumerate() {
            if theirs != mine {
                let index = first + i as u64;
                t.reject(index);
                mismatch(file, index, *theirs);
            }
        }
        Ok(())
    }

    /// After a hash repair round: every refetched chunk must now match the
    /// digest the sender reported.
    fn check_repairs(&self, done: &Finalized) -> Result<()> {
        for (&(file, index), want) in &done.expected {
            let t = &self.targets[file as usize];
            let files = self.store.handles.get(t)?;
            let mut stored = [0u8; DIGEST_LEN];
            read_exact_at(&files.sums, &mut stored, index * DIGEST_LEN as u64)?;
            ensure!(
                stored == *want,
                "{} changed during transfer",
                t.entry.path.display()
            );
        }
        Ok(())
    }

    /// `(path, BLAKE3(chunk_size u32 | chunk digests))` for every file,
    /// streamed from the sums files in fixed-size steps, so a file of any
    /// chunk count hashes in bounded memory.
    fn file_hashes(&self) -> Result<Vec<(String, String)>> {
        const STEP: u64 = 1 << 20;
        let chunk_size = self.manifest.chunk_size.get();
        let mut buf = vec![0u8; STEP as usize];
        self.targets
            .iter()
            .map(|t| {
                let files = self.store.handles.get(t)?;
                let mut hasher = FileHasher::new(chunk_size);
                let total = t.present.len() * DIGEST_LEN as u64;
                let mut offset = 0;
                while offset < total {
                    let n = (total - offset).min(STEP) as usize;
                    read_exact_at(&files.sums, &mut buf[..n], offset)?;
                    hasher.update(&buf[..n]);
                    offset += n as u64;
                }
                Ok((t.entry.path.display(), hasher.hex()))
            })
            .collect()
    }

    /// Handles one authenticated chunk from any connection.
    fn land(&self, target: &Target, index: u64, plaintext: &[u8]) -> Result<()> {
        let landed = self
            .store
            .handles
            .get(target)
            .and_then(|files| target.land(&files, index, plaintext));
        match landed {
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
            let files = self.store.handles.get(t)?;
            files.part.sync_data()?;
            files.sums.sync_data()?;
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
        let ok = self
            .store
            .handles
            .get(t)
            .and_then(|files| t.check(&files, index, buf))
            .with_context(|| format!("reading back {}", t.payload.lock().unwrap().display()))?;
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
                let files = self.store.handles.get(t)?;
                files.part.sync_data()?;
                files.sums.sync_data()?;
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

    /// Publishes every file not yet committed: sync it, give it its final
    /// mode while it is still private, rename it into place durably (and
    /// without replacing anything unless `--force`), and drop its state.
    /// Sums stay until the sender acknowledges `Finished`, so a replayed
    /// finalization can still verify. Each file's commit is one rename,
    /// so a crash leaves every file either staged or published.
    fn finalize(&self, map: &FileMap) -> Result<()> {
        let _no_checkpoint = self.checkpoint_lock.lock().unwrap();
        let modes: HashMap<u32, Option<u32>> = map
            .entries
            .iter()
            .filter_map(|e| match e.kind {
                EntryKind::File { file_id } => Some((file_id, e.mode)),
                EntryKind::Dir => None,
            })
            .collect();
        for t in &self.targets {
            if t.committed.load(Relaxed) {
                continue;
            }
            let files = self.store.handles.get(t)?;
            files
                .part
                .sync_all()
                .with_context(|| format!("syncing {}", t.part_path.display()))?;
            let mode = modes.get(&t.file_id).copied().flatten();
            self.set_final_mode(&files.part, mode)?;
            drop(files);
            self.store.handles.forget(t.file_id);
            fsops::rename_durable(&t.part_path, &t.final_path, self.store.force)
                .with_context(|| format!("renaming into {}", t.final_path.display()))?;
            fsops::inherit_parent_acl(&t.final_path)?;
            *t.payload.lock().unwrap() = t.final_path.clone();
            t.committed.store(true, Relaxed);
            fsops::remove_durable(&t.state_path)?;
            if testing::take(self.out_dir, testing::Fault::FailAfterFirstPublish) {
                bail!(
                    "injected failure after publishing {}",
                    t.final_path.display()
                );
            }
        }
        Ok(())
    }

    /// The mode a file is published with: the map's, under the special-bit
    /// policy, or what `creat` would give under the current umask.
    #[cfg(unix)]
    fn set_final_mode(&self, file: &File, mode: Option<u32>) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let keep = if self.policy.allow_special_bits {
            0o7777
        } else {
            0o777
        };
        let mode = match mode {
            Some(m) => m & keep,
            None => 0o666 & !self.store.umask,
        };
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    /// Windows has no mode; the file map's read-only bit is applied by
    /// `filemap::apply` through the published path.
    #[cfg(windows)]
    fn set_final_mode(&self, _: &File, _: Option<u32>) -> Result<()> {
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
                let spawned = spawn_named(s, "mjolnir-data", move || {
                    if let Err(e) = serve_data(session, stream, permit)
                        && !session.sync.is_shut()
                        && !session.progress.is_cancelled()
                    {
                        eprintln!("mjolnir: data connection from {from}: {e:#}");
                    }
                });
                if let Err(e) = spawned {
                    eprintln!(
                        "mjolnir: cannot start a thread for the data connection from {from}: {e}"
                    );
                }
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
    // The active permit is taken before admission, so a rejected hello
    // never counts, and it is held until this function returns.
    let active = session.active_data.try_acquire();
    let admitted = check_hello(&session.keys, &challenge, &hello)
        .filter(|_| active.is_some())
        .and_then(|(round, conn)| {
            let socket = hello_io.try_clone().ok()?.into_stream();
            session
                .sync
                .admit(round, conn, socket, session.progress)
                .map(|reader| (round, conn, reader))
        });
    let Some((round, conn, _reader)) = admitted else {
        hello_io.write_all(&[REJECTED])?;
        bail!("rejected data connection hello");
    };
    let _closed = ClosedGuard { session, round };
    let _shown = ActiveConnection::new(session.progress);
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

/// Marks a round's reader thread as alive: while any exists, the round
/// cannot close, because the reader might still hand the pool a frame.
struct ReaderGuard<'a> {
    sync: &'a RoundSync,
    round: u32,
}

impl Drop for ReaderGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.sync.state.lock().unwrap();
        if let RoundState::Open { round, readers, .. } = &mut *state
            && *round == self.round
        {
            *readers -= 1;
            self.sync.cv.notify_all();
        }
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
        /// Reader threads of this round still running.
        readers: usize,
        /// The admitted sockets, so closing the round can shut them down.
        sockets: Vec<TcpStream>,
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
            readers: 0,
            sockets: Vec::new(),
        };
        self.cv.notify_all();
        Ok(())
    }

    /// Admits `(round, conn)` once, up to `MAX_DATA_CONNECTIONS` per round,
    /// and registers its reader. A connection may beat its `RoundStart` to
    /// the receiver, so it waits a little for the round to open.
    fn admit(
        &self,
        round: u32,
        conn: u32,
        socket: TcpStream,
        progress: &Progress,
    ) -> Option<ReaderGuard<'_>> {
        let deadline = Instant::now() + ROUND_START_WAIT;
        let mut state = self.state.lock().unwrap();
        loop {
            match &mut *state {
                RoundState::Open {
                    round: open,
                    admitted,
                    readers,
                    sockets,
                    ..
                } if *open == round => {
                    if admitted.len() >= MAX_DATA_CONNECTIONS || !admitted.insert(conn) {
                        return None;
                    }
                    *readers += 1;
                    sockets.push(socket);
                    return Some(ReaderGuard { sync: self, round });
                }
                RoundState::Between { next } if *next == round => {}
                _ => return None,
            }
            let now = Instant::now();
            if now >= deadline || progress.is_cancelled() {
                return None;
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
    /// connections of `round` to close, then closes the round: it shuts
    /// down every socket the round admitted and waits for every reader
    /// thread to exit. Only then can nothing more be submitted for the
    /// round, so the caller's `wait_idle` is a real barrier.
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
        self.closed_below.store(round + 1, Relaxed);
        if let RoundState::Open { sockets, .. } = &mut *state {
            for socket in sockets.drain(..) {
                let _ = socket.shutdown(Shutdown::Both);
            }
        }
        while let RoundState::Open { readers, .. } = &*state
            && *readers > 0
        {
            state = self.cv.wait(state).unwrap();
        }
        *state = RoundState::Between { next: round + 1 };
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

    fn target_in(dir: &Path, size: u64) -> (Store, Target) {
        let m = Manifest::new(
            ChunkSize::new(MIN_CHUNK_SIZE).unwrap(),
            vec![FileEntry {
                path: WirePath::parse([b"f".to_vec()]).unwrap(),
                size,
                mtime: 1,
            }],
            Vec::new(),
        )
        .unwrap();
        let peer = PrivateKey::generate().public_key();
        let (store, mut targets) = prepare_targets(dir, &m, &peer, false).unwrap();
        (store, targets.pop().unwrap())
    }

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mjolnir-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A reader that is still alive when `RoundEnd` arrives could hand the
    /// pool a frame after the round's completeness has been judged. Closing
    /// the round must shut its socket and wait for it to exit first.
    #[test]
    fn closing_a_round_shuts_its_sockets_and_waits_for_its_readers() {
        let sync = RoundSync::default();
        let progress = Progress::default();
        sync.start(0).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (ours, _) = listener.accept().unwrap();
        let reader = sync
            .admit(0, 0, ours, &progress)
            .expect("the open round admits its first connection");
        let ended = AtomicBool::new(false);
        thread::scope(|s| {
            s.spawn(|| {
                sync.end(0, 0, &progress).unwrap();
                ended.store(true, Relaxed);
            });
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            assert_eq!(
                peer.read(&mut [0u8; 1]).unwrap(),
                0,
                "closing the round shuts the admitted socket"
            );
            assert!(sync.is_closed(0));
            thread::sleep(Duration::from_millis(200));
            assert!(!ended.load(Relaxed), "the round closed with a reader alive");
            drop(reader);
        });
        assert!(ended.load(Relaxed));
        assert!(
            sync.admit(0, 1, peer, &progress).is_none(),
            "closed rounds admit nothing"
        );
    }

    #[test]
    fn a_round_admits_at_most_the_connection_cap() {
        let sync = RoundSync::default();
        let progress = Progress::default();
        sync.start(0).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = || {
            let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            listener.accept().unwrap().0
        };
        let held: Vec<_> = (0..MAX_DATA_CONNECTIONS as u32)
            .map(|conn| {
                sync.admit(0, conn, socket(), &progress)
                    .expect("under the cap")
            })
            .collect();
        assert!(sync.admit(0, u32::MAX, socket(), &progress).is_none());
        drop(held);
    }

    #[test]
    fn a_duplicate_chunk_is_dropped_without_writing() {
        let dir = tempdir("dup");
        let (store, t) = target_in(&dir, 3 * u64::from(MIN_CHUNK_SIZE));
        let files = store.handles.get(&t).unwrap();
        let chunk = vec![7u8; MIN_CHUNK_SIZE as usize];
        assert_eq!(t.land(&files, 1, &chunk).unwrap(), Landed::Written);
        assert!(t.present.get(1) && t.claimed.get(1));

        let marker = vec![0xAAu8; MIN_CHUNK_SIZE as usize];
        write_all_at(&files.part, &marker, u64::from(MIN_CHUNK_SIZE)).unwrap();
        assert_eq!(t.land(&files, 1, &chunk).unwrap(), Landed::Duplicate);
        let mut on_disk = vec![0u8; MIN_CHUNK_SIZE as usize];
        read_exact_at(&files.part, &mut on_disk, u64::from(MIN_CHUNK_SIZE)).unwrap();
        assert_eq!(on_disk, marker, "the duplicate must not touch the file");
        drop((files, t, store));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn check_detects_corruption_and_reject_makes_the_chunk_missing() {
        let dir = tempdir("check");
        let (store, t) = target_in(&dir, 2 * u64::from(MIN_CHUNK_SIZE) - 5);
        let files = store.handles.get(&t).unwrap();
        let mut buf = vec![0u8; MIN_CHUNK_SIZE as usize];
        t.land(&files, 0, &vec![1u8; MIN_CHUNK_SIZE as usize])
            .unwrap();
        t.land(&files, 1, &vec![2u8; MIN_CHUNK_SIZE as usize - 5])
            .unwrap();
        assert!(t.check(&files, 0, &mut buf).unwrap());
        assert!(t.check(&files, 1, &mut buf).unwrap());
        write_all_at(&files.part, &[9u8], 3).unwrap();
        assert!(!t.check(&files, 0, &mut buf).unwrap());
        t.reject(0);
        assert!(!t.present.get(0) && !t.claimed.get(0));
        assert_eq!(
            t.land(&files, 0, &vec![1u8; MIN_CHUNK_SIZE as usize])
                .unwrap(),
            Landed::Written
        );
        assert!(t.check(&files, 0, &mut buf).unwrap());
        drop((files, t, store));
        fs::remove_dir_all(dir).unwrap();
    }

    /// The handle cache keeps at most its capacity open and reopens what it
    /// evicted, so a transfer of more files than descriptors still works.
    #[test]
    fn handles_are_bounded_and_reopened() {
        let dir = tempdir("handles");
        let files: Vec<FileEntry> = (0..10)
            .map(|j| FileEntry {
                path: WirePath::parse([format!("f{j}").into_bytes()]).unwrap(),
                size: u64::from(MIN_CHUNK_SIZE),
                mtime: 1,
            })
            .collect();
        let m = Manifest::new(ChunkSize::new(MIN_CHUNK_SIZE).unwrap(), files, Vec::new()).unwrap();
        let peer = PrivateKey::generate().public_key();
        let (mut store, targets) = prepare_targets(&dir, &m, &peer, false).unwrap();
        store.handles = Handles::new(3);
        let chunk = vec![5u8; MIN_CHUNK_SIZE as usize];
        for t in &targets {
            let files = store.handles.get(t).unwrap();
            assert_eq!(t.land(&files, 0, &chunk).unwrap(), Landed::Written);
            assert!(store.handles.state.lock().unwrap().open.len() <= 3);
        }
        let mut buf = vec![0u8; MIN_CHUNK_SIZE as usize];
        for t in &targets {
            let files = store.handles.get(t).unwrap();
            assert!(t.check(&files, 0, &mut buf).unwrap(), "{}", t.file_id);
        }
        drop((targets, store));
        fs::remove_dir_all(dir).unwrap();
    }
}
