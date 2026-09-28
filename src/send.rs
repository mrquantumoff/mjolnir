//! The sender: walk the inputs, authenticate, and stream missing chunks over
//! parallel data connections, round by round.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Serialize;

use crate::bitset::AtomicBitset;
use crate::crypto::{
    Cipher, DIGEST_LEN, FileHasher, FrameKey, SessionKeys, TAG_LEN, chunk_digest,
    handshake_initiator,
};
use crate::filemap::{self, EntryKind, FileMap, Preserve};
use crate::keys::{PrivateKey, PublicKey};
use crate::manifest::{ChunkId, ChunkSize, FileEntry, Manifest, chunk_count, chunk_span, mtime_of};
use crate::net::{self, Io, tell_peer_about, unexpected};
use crate::pool::{Buffers, InFlight, Pool, buffer_count, check_threads, resolve_threads};
use crate::posio::read_exact_at;
use crate::progress::{ActiveConnection, Cancelled, Phase, PhaseTimes, Progress};
use crate::recv::MAX_DATA_CONNECTIONS;
use crate::schedule::Scheduler;
use crate::wire::{
    self, ADMITTED, CHALLENGE_LEN, ConnKind, ControlRx, ControlTx, DIGESTS_PER_MSG, FrameHeader,
    HEADER_LEN, Msg, Role, chunk_header, encode_hello, seal_frame,
};

#[derive(Clone, Debug, Serialize)]
pub struct SendConfig {
    /// `HOST:PORT` of the receiver.
    pub addr: String,
    #[serde(skip_serializing)]
    pub key: PrivateKey,
    /// The receiver's pinned public key.
    pub peer: PublicKey,
    pub connections: usize,
    pub chunk_size: u32,
    pub cipher: Cipher,
    /// Workers that read and seal chunks; 0 means one per CPU core.
    pub threads: usize,
    /// Files or directories; a directory is sent recursively under its name.
    pub paths: Vec<PathBuf>,
    /// Re-read every file after delivery and have the receiver compare
    /// chunk digests (`send --hash`).
    pub hash: bool,
    /// Metadata to put in the file map (`send --preserve`).
    pub preserve: Preserve,
}

#[derive(Clone, Debug, Serialize)]
pub struct SendReport {
    pub files: usize,
    /// Plaintext bytes of the chunks sent this session.
    pub bytes_sent: u64,
    pub chunks_sent: u64,
    /// Chunks sent again in a later round of this session.
    pub chunks_resent: u64,
    pub rounds: u32,
    /// Whether the receiver read every chunk back and matched its digest.
    pub verified: bool,
    /// Whether the receiver compared this side's re-read digests.
    pub hashed: bool,
    /// Chunks the hash check sent back for a repair round.
    pub hash_repaired_chunks: u64,
    /// `(path, file_hash)` per file, when `hash` is on.
    pub file_hashes: Vec<(String, String)>,
    /// Metadata the receiver could not apply, and skipped sources.
    pub warnings: Vec<String>,
    /// Symbolic links and special files that were not sent.
    pub skipped: Vec<String>,
    pub phase_times: PhaseTimes,
    pub elapsed: Duration,
}

/// Rounds without progress tolerated before giving up.
const MAX_FAILED_ROUNDS: u32 = 3;
/// Handshakes and data connection hellos must finish within this.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);
/// A data connection whose socket accepts no byte for this long is dropped.
const DATA_IDLE: Duration = Duration::from_secs(60);
/// Frames per connection being read and sealed ahead of the socket.
const DEPTH: usize = 4;

pub fn send(cfg: SendConfig, progress: std::sync::Arc<Progress>) -> Result<SendReport> {
    progress.conclude(run(&cfg, &progress))
}

struct Ctx<'a> {
    addrs: &'a [SocketAddr],
    keys: &'a SessionKeys,
    cipher: Cipher,
    manifest: &'a Manifest,
    files: &'a Sources,
    /// Every file's bytes, when `MJOLNIR_BENCH=memory-source`.
    memory: &'a [Vec<u8>],
    paths: &'a [PathBuf],
    progress: &'a Progress,
    chunks_sent: AtomicU64,
    bytes_sent: AtomicU64,
    chunks_resent: AtomicU64,
    /// Per file, the chunks sent at least once this session.
    sent: Vec<AtomicBitset>,
    /// A local read failure; fatal for the transfer, unlike network errors.
    fatal: Mutex<Option<anyhow::Error>>,
    pool: &'a Pool<SendJob>,
    buffers: &'a Buffers,
    in_flight: InFlight,
    hashing: HashRun,
}

/// Open source files kept at once; a larger tree reopens files as the
/// schedule moves through them, so descriptors are never exhausted.
const MAX_OPEN_SOURCES: usize = 256;

/// The source files, opened on demand and closed least recently used
/// first. A reopened file must still have the size and mtime it was
/// offered with.
struct Sources {
    paths: Vec<PathBuf>,
    entries: Vec<FileEntry>,
    state: Mutex<SourceState>,
}

struct SourceState {
    open: HashMap<u32, (Arc<File>, u64)>,
    tick: u64,
}

impl Sources {
    fn new(paths: Vec<PathBuf>, entries: Vec<FileEntry>) -> Self {
        Sources {
            paths,
            entries,
            state: Mutex::new(SourceState {
                open: HashMap::new(),
                tick: 0,
            }),
        }
    }

    fn get(&self, file: u32) -> Result<Arc<File>> {
        let mut s = self.state.lock().unwrap();
        s.tick += 1;
        let tick = s.tick;
        if let Some((f, used)) = s.open.get_mut(&file) {
            *used = tick;
            return Ok(f.clone());
        }
        let path = &self.paths[file as usize];
        let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let meta = f.metadata()?;
        let entry = &self.entries[file as usize];
        ensure!(
            meta.len() == entry.size && mtime_of(&meta) == entry.mtime,
            "source file changed during transfer: {}",
            path.display()
        );
        let f = Arc::new(f);
        if s.open.len() >= MAX_OPEN_SOURCES
            && let Some(&oldest) = s
                .open
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(k, _)| k)
        {
            s.open.remove(&oldest);
        }
        s.open.insert(file, (f.clone(), tick));
        Ok(f)
    }
}

/// Work for the pool.
enum SendJob {
    Seal(SealJob),
    /// Digest chunks of the current `HashRun` window until none are left.
    Hash,
}

/// One window of the `--hash` re-read: chunks `first..first + count` of
/// `file`, digests written to `out` at `(index - first) * DIGEST_LEN`.
#[derive(Default)]
struct HashRun {
    window: Mutex<(u32, u64, u64)>,
    cursor: AtomicU64,
    out: Mutex<Vec<u8>>,
    error: Mutex<Option<anyhow::Error>>,
}

/// "Read `chunk` and seal it as frame `k` of `conn`", run on the pool.
struct SealJob {
    conn: Arc<SendConn>,
    k: u64,
    chunk: ChunkId,
    buf: Vec<u8>,
}

/// One data connection's key and its ring of `DEPTH` result slots; frame
/// `k` lands in slot `k % DEPTH`.
struct SendConn {
    key: FrameKey,
    slots: [Slot; DEPTH],
}

/// A sealed frame (its buffer and length) handed from a worker to the
/// connection's writer.
#[derive(Default)]
struct Slot {
    sealed: Mutex<Option<(Vec<u8>, Result<usize>)>>,
    cv: Condvar,
}

impl Slot {
    fn put(&self, buf: Vec<u8>, frame_len: Result<usize>) {
        *self.sealed.lock().unwrap() = Some((buf, frame_len));
        self.cv.notify_one();
    }

    fn take(&self) -> (Vec<u8>, Result<usize>) {
        let mut sealed = self.sealed.lock().unwrap();
        loop {
            if let Some(done) = sealed.take() {
                return done;
            }
            sealed = self.cv.wait(sealed).unwrap();
        }
    }
}

type Tx<'a> = ControlTx<Io<'a>>;
type Rx<'a> = ControlRx<Io<'a>>;

fn run(cfg: &SendConfig, progress: &Progress) -> Result<SendReport> {
    let start = Instant::now();
    progress.set_phase(Phase::Connecting);
    ensure!(
        (1..=MAX_DATA_CONNECTIONS).contains(&cfg.connections),
        "connections must be between 1 and {MAX_DATA_CONNECTIONS}"
    );
    check_threads(cfg.threads)?;
    let chunk_size = ChunkSize::new(cfg.chunk_size)?;
    let captured = filemap::capture(&cfg.paths, cfg.preserve)?;
    let paths: Vec<PathBuf> = captured.files.iter().map(|f| f.source.clone()).collect();
    let memory: Vec<Vec<u8>> = if crate::benchmode::get().memory_source {
        paths.iter().map(fs::read).collect::<std::io::Result<_>>()?
    } else {
        Vec::new()
    };
    let entries = captured
        .files
        .iter()
        .map(|f| FileEntry {
            path: f.path.clone(),
            size: f.size,
            mtime: f.mtime,
        })
        .collect();
    let dirs = captured
        .map
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::Dir)
        .map(|e| e.path.clone())
        .collect();
    let manifest = Manifest::new(chunk_size, entries, dirs)?;
    let files = Sources::new(paths.clone(), manifest.files.clone());
    let skipped: Vec<String> = captured
        .skipped
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    for p in &skipped {
        eprintln!(
            "mjolnir: skipping {}: not a regular file or directory",
            crate::printable::escape(p)
        );
    }

    let addrs = net::resolve(&cfg.addr)?;
    let cancelled = || progress.is_cancelled();
    let (control, keys) = open_control(cfg, &addrs, progress, &cancelled)?;
    let (mut tx, mut rx) =
        wire::control_channel(control.try_clone()?, control, &keys, Role::Sender);
    let pool = Pool::new(resolve_threads(cfg.threads));
    let buf_len = HEADER_LEN + chunk_size.get() as usize + TAG_LEN;
    // Each connection holds at most DEPTH frames between sealing and the
    // socket, so more buffers than that only wait; the hash passes keep a
    // few workers reading even on one connection.
    let useful = (cfg.connections * DEPTH).max(pool.threads().min(8));
    let buffers = Buffers::new(
        buffer_count(pool.threads(), cfg.connections, buf_len, useful),
        buf_len,
    );
    let ctx = Ctx {
        addrs: &addrs,
        keys: &keys,
        cipher: cfg.cipher,
        manifest: &manifest,
        files: &files,
        memory: &memory,
        paths: &paths,
        progress,
        chunks_sent: AtomicU64::new(0),
        bytes_sent: AtomicU64::new(0),
        chunks_resent: AtomicU64::new(0),
        sent: (0..manifest.files.len() as u32)
            .map(|j| AtomicBitset::new(manifest.chunk_count(j)))
            .collect(),
        fatal: Mutex::new(None),
        pool: &pool,
        buffers: &buffers,
        in_flight: InFlight::default(),
        hashing: HashRun::default(),
    };
    let result = thread::scope(|s| {
        for _ in 0..pool.threads() {
            s.spawn(|| pool.work(|job| run_job(&ctx, job)));
        }
        let result = transfer(&ctx, cfg, &captured.map, &mut tx, &mut rx);
        pool.close();
        result
    });
    if let Err(e) = &result {
        tell_peer_about(e, progress, Some(&mut tx), None);
        net::linger(rx.into_inner().into_stream());
    }
    let done = result?;
    let mut warnings = done.warnings;
    warnings.extend(skipped.iter().map(|p| format!("skipped {p}")));
    Ok(SendReport {
        files: manifest.files.len(),
        bytes_sent: ctx.bytes_sent.load(Relaxed),
        chunks_sent: ctx.chunks_sent.load(Relaxed),
        chunks_resent: ctx.chunks_resent.load(Relaxed),
        rounds: done.rounds,
        verified: done.verified,
        hashed: done.hashed,
        hash_repaired_chunks: done.hash_repaired,
        file_hashes: done.file_hashes,
        warnings,
        skipped,
        phase_times: progress.phase_summary(),
        elapsed: start.elapsed(),
    })
}

/// Delays before the second and third attempt when the receiver hangs up
/// during the handshake, which it does while another sender's session is
/// active.
const HANDSHAKE_RETRIES: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(3)];

/// Connects the control connection and runs the handshake, retrying when
/// the receiver closes it before answering.
fn open_control<'a>(
    cfg: &SendConfig,
    addrs: &[SocketAddr],
    progress: &Progress,
    cancelled: &'a (dyn Fn() -> bool + Sync),
) -> Result<(Io<'a>, SessionKeys)> {
    let mut delays = HANDSHAKE_RETRIES.iter();
    loop {
        progress.set_phase(Phase::Connecting);
        let mut control = Io::new(net::connect(addrs, progress)?, cancelled);
        wire::write_preamble(&mut control, ConnKind::Control)?;
        progress.set_phase(Phase::Handshaking);
        let mut handshake = control.try_clone()?.deadline(HANDSHAKE_DEADLINE);
        match handshake_initiator(&mut handshake, &cfg.key, &cfg.peer) {
            Ok(keys) => return Ok((control, keys)),
            Err(e) if e.to_string() == crate::crypto::REJECTED => match delays.next() {
                Some(&delay) => {
                    let until = Instant::now() + delay;
                    while Instant::now() < until {
                        if progress.is_cancelled() {
                            return Err(Cancelled::Local.into());
                        }
                        thread::sleep(Duration::from_millis(50));
                    }
                }
                None => return Err(e),
            },
            Err(e) => return Err(e),
        }
    }
}

/// How the session ended, as the receiver's `Finished` and our own
/// bookkeeping tell it.
struct Done {
    rounds: u32,
    verified: bool,
    hashed: bool,
    hash_repaired: u64,
    file_hashes: Vec<(String, String)>,
    warnings: Vec<String>,
}

/// Runs rounds until the receiver reports `Finished`, finalizing (with the
/// hash check when asked) once the receiver reports `Delivered`.
fn transfer(ctx: &Ctx, cfg: &SendConfig, map: &FileMap, tx: &mut Tx, rx: &mut Rx) -> Result<Done> {
    let m = ctx.manifest;
    let connections = cfg.connections;
    let mut finalized = false;
    let mut file_hashes = Vec::new();
    let mut hash_repaired = 0;
    tx.send(&Msg::Confirm)?;
    tx.send(&Msg::Offer {
        chunk_size: m.chunk_size.get(),
        cipher: ctx.cipher,
        files: m.to_offer(),
        dirs: m.offer_dirs(),
    })?;
    let mut have = match rx.recv()? {
        Msg::Have { bitmaps } => parse_have(m, &bitmaps)?,
        other => return Err(unexpected(other, "Have")),
    };
    if have.iter().any(|b| b.count_ones() > 0) {
        send_resume_digests(ctx, tx, &have)?;
        tx.send(&Msg::Resume)?;
        have = match rx.recv()? {
            Msg::Have { bitmaps } => parse_have(m, &bitmaps)?,
            other => return Err(unexpected(other, "Have")),
        };
    }
    let (chunks, bytes) = missing_totals(m, &have);
    ctx.progress.set_totals(chunks, bytes);
    ctx.progress.set_phase(Phase::Transferring);

    let mut failed_rounds = 0;
    for round in 0u32.. {
        let (to_send, _) = missing_totals(m, &have);
        let sched = Scheduler::new(&have);
        tx.send(&Msg::RoundStart { round })?;
        let wanted = usize::try_from(to_send).map_or(connections, |n| connections.min(n));
        let admitted = run_round(ctx, round, wanted, &sched);
        if ctx.progress.is_cancelled() {
            return Err(Cancelled::Local.into());
        }
        if let Some(e) = ctx.fatal.lock().unwrap().take() {
            return Err(e);
        }
        check_unchanged(ctx)?;
        let sent = tx.send(&Msg::RoundEnd {
            round,
            connections: admitted,
        });
        // The round, and so the transfer phase, lasts until the receiver has
        // absorbed the data and answers. Read even if the send failed: the
        // peer may have said why it left.
        let mut reply = reply(ctx, rx).map_err(|e| sent.err().unwrap_or(e))?;
        if matches!(reply, Msg::Delivered) && !finalized {
            finalized = true;
            if cfg.hash {
                file_hashes = send_digests(ctx, tx)?;
            }
            ctx.progress.set_phase(Phase::Finishing);
            tx.send(&Msg::Finalize {
                hash: cfg.hash,
                map: map.clone(),
            })?;
            reply = self::reply(ctx, rx)?;
            if let Msg::Have { bitmaps } = &reply {
                hash_repaired = missing_count(&parse_have(m, bitmaps)?);
            }
        }
        match reply {
            Msg::Finished {
                verified,
                hashed,
                warnings,
            } => {
                // Best effort: the receiver keeps its journal without it.
                let _ = tx.send(&Msg::Ack);
                return Ok(Done {
                    rounds: round + 1,
                    verified,
                    hashed,
                    hash_repaired,
                    file_hashes,
                    warnings,
                });
            }
            Msg::Have { bitmaps } => {
                let after = parse_have(m, &bitmaps)?;
                // Progress means some chunk this round carried is now
                // held. Chunks the receiver's verification sent back to
                // missing do not count against the round.
                let landed = after
                    .iter()
                    .zip(&have)
                    .any(|(now, then)| now.gained_over(then));
                have = after;
                if to_send > 0 && !landed {
                    failed_rounds += 1;
                    if failed_rounds == MAX_FAILED_ROUNDS {
                        bail!("{MAX_FAILED_ROUNDS} rounds in a row made no progress");
                    }
                } else {
                    failed_rounds = 0;
                }
            }
            other => return Err(unexpected(other, "Have, Delivered, or Finished")),
        }
        ctx.progress.set_phase(Phase::Transferring);
    }
    unreachable!("u32 rounds exhausted")
}

/// The receiver's next answer, following its `Verifying` notices so the
/// phase shows what the receiver is doing.
fn reply(ctx: &Ctx, rx: &mut Rx) -> Result<Msg> {
    loop {
        match rx.recv()? {
            Msg::Verifying => ctx.progress.set_phase(Phase::Verifying),
            Msg::Delivered => {
                ctx.progress.set_phase(Phase::Finishing);
                return Ok(Msg::Delivered);
            }
            other => return Ok(other),
        }
    }
}

/// Opens `connections` data connections that drain `sched` together.
/// Returns how many the receiver admitted.
fn run_round(ctx: &Ctx, round: u32, connections: usize, sched: &Scheduler) -> u32 {
    let admitted = AtomicU32::new(0);
    thread::scope(|s| {
        for conn in 0..connections as u32 {
            let admitted = &admitted;
            s.spawn(move || {
                if let Err(e) = data_connection(ctx, round, conn, sched, admitted)
                    && !ctx.progress.is_cancelled()
                {
                    eprintln!("mjolnir: data connection {conn} of round {round}: {e:#}");
                }
            });
        }
    });
    admitted.into_inner()
}

fn data_connection(
    ctx: &Ctx,
    round: u32,
    conn: u32,
    sched: &Scheduler,
    admitted: &AtomicU32,
) -> Result<()> {
    let cancelled = || ctx.progress.is_cancelled();
    let stream = net::connect(ctx.addrs, ctx.progress)?;
    let mut hello = Io::new(stream, &cancelled).deadline(HANDSHAKE_DEADLINE);
    wire::write_preamble(&mut hello, ConnKind::Data)?;
    let mut challenge = [0u8; CHALLENGE_LEN];
    hello.read_exact(&mut challenge)?;
    hello.write_all(&encode_hello(ctx.keys, &challenge, round, conn))?;
    let mut verdict = [0u8];
    hello.read_exact(&mut verdict)?;
    ensure!(verdict[0] == ADMITTED, "receiver rejected the connection");
    admitted.fetch_add(1, Relaxed);
    let _active = ActiveConnection::new(ctx.progress);
    let mut stream = Io::new(hello.into_stream(), &cancelled).idle(DATA_IDLE);
    let id = conn;
    let conn = Arc::new(SendConn {
        key: FrameKey::new(ctx.cipher, &ctx.keys.data_key(round, id)),
        slots: Default::default(),
    });
    let result = stream_frames(ctx, &conn, &mut stream, || sched.claim(id));
    // Whatever this connection still owned goes to the others.
    sched.release(id);
    stream.into_stream().shutdown(Shutdown::Write)?;
    result
}

/// Keeps up to `DEPTH` frames of this connection sealing on the pool while
/// earlier ones go out, and writes them strictly in frame order. `claim`
/// names the next chunk to send, until it returns `None`.
fn stream_frames(
    ctx: &Ctx,
    conn: &Arc<SendConn>,
    stream: &mut Io,
    mut claim: impl FnMut() -> Option<ChunkId>,
) -> Result<()> {
    // Frames `written..submitted` are sealing or sealed but not yet sent;
    // frame k carries `chunks[k % DEPTH]`.
    let (mut written, mut submitted) = (0u64, 0u64);
    let mut chunks = [ChunkId { file: 0, index: 0 }; DEPTH];
    let result = (|| {
        let mut exhausted = false;
        loop {
            while !exhausted && submitted - written < DEPTH as u64 {
                // Block for a buffer only with nothing in flight; otherwise
                // a writer holding sealed frames could starve the others.
                let buf = if submitted == written {
                    let stop = || ctx.progress.is_cancelled();
                    match ctx.buffers.take(&stop) {
                        Some(buf) => buf,
                        None => return Err(Cancelled::Local.into()),
                    }
                } else {
                    match ctx.buffers.try_take() {
                        Some(buf) => buf,
                        None => break,
                    }
                };
                let Some(chunk) = claim() else {
                    ctx.buffers.give(buf);
                    exhausted = true;
                    break;
                };
                chunks[submitted as usize % DEPTH] = chunk;
                ctx.pool.submit(SendJob::Seal(SealJob {
                    conn: conn.clone(),
                    k: submitted,
                    chunk,
                    buf,
                }));
                submitted += 1;
            }
            if written == submitted {
                break;
            }
            let slot = written as usize % DEPTH;
            let (buf, frame_len) = conn.slots[slot].take();
            written += 1;
            let sent = frame_len.and_then(|n| Ok(stream.write_all(&buf[..n])?));
            ctx.buffers.give(buf);
            sent?;
            let chunk = chunks[slot];
            let len = u64::from(ctx.manifest.chunk_len(chunk));
            ctx.chunks_sent.fetch_add(1, Relaxed);
            ctx.bytes_sent.fetch_add(len, Relaxed);
            // Progress counts each chunk once, so it never passes its total.
            if ctx.sent[chunk.file as usize].set(chunk.index) {
                ctx.progress.add_chunk(len);
            } else {
                ctx.chunks_resent.fetch_add(1, Relaxed);
            }
            if ctx.progress.is_cancelled() {
                return Err(Cancelled::Local.into());
            }
        }
        let mut end = [0u8; HEADER_LEN + TAG_LEN];
        let sid = &ctx.keys.session_id;
        seal_frame(&conn.key, submitted, sid, FrameHeader::end(), &mut end)?;
        stream.write_all(&end)?;
        Ok(())
    })();
    // Frames still sealing hold pool buffers; collect them before leaving.
    while written < submitted {
        let (buf, _) = conn.slots[written as usize % DEPTH].take();
        ctx.buffers.give(buf);
        written += 1;
    }
    result
}

fn run_job(ctx: &Ctx, job: SendJob) {
    match job {
        SendJob::Seal(job) => seal(ctx, job),
        SendJob::Hash => {
            hash_some(ctx);
            ctx.in_flight.done();
        }
    }
}

/// Re-reads every file on the pool and streams its chunk digests in
/// `Digests` messages of at most `DIGESTS_PER_MSG`. Returns each file's
/// `file_hash`.
fn send_digests(ctx: &Ctx, tx: &mut Tx) -> Result<Vec<(String, String)>> {
    let m = ctx.manifest;
    ctx.progress.set_phase(Phase::Hashing);
    ctx.progress.reset_counts();
    let total_chunks = (0..m.files.len() as u32).map(|j| m.chunk_count(j)).sum();
    ctx.progress
        .set_totals(total_chunks, m.files.iter().map(|f| f.size).sum());
    let mut hashes = Vec::with_capacity(m.files.len());
    for (j, f) in m.files.iter().enumerate() {
        let count = chunk_count(f.size, m.chunk_size);
        let mut hasher = FileHasher::new(m.chunk_size.get());
        for first in (0..count).step_by(DIGESTS_PER_MSG) {
            let n = (count - first).min(DIGESTS_PER_MSG as u64);
            let digests = hash_window(ctx, j as u32, first, n)?;
            hasher.update(&digests);
            tx.send(&Msg::Digests {
                file: j as u32,
                first,
                digests,
            })?;
        }
        hashes.push((f.path.display(), hasher.hex()));
    }
    check_unchanged(ctx)?;
    Ok(hashes)
}

/// Before round 0 of a resume: re-reads every chunk the receiver holds
/// and sends its digest, so the receiver can drop chunks that no longer
/// match the source, whatever left them there.
fn send_resume_digests(ctx: &Ctx, tx: &mut Tx, have: &[AtomicBitset]) -> Result<()> {
    let m = ctx.manifest;
    ctx.progress.set_phase(Phase::Hashing);
    ctx.progress.reset_counts();
    let held: Vec<(u32, u64, u64)> = have
        .iter()
        .enumerate()
        .flat_map(|(j, bits)| present_runs(bits).map(move |(first, n)| (j as u32, first, n)))
        .collect();
    let chunks: u64 = held.iter().map(|&(_, _, n)| n).sum();
    let bytes: u64 = held
        .iter()
        .map(|&(j, first, n)| {
            (first..first + n)
                .map(|k| u64::from(m.chunk_len(ChunkId { file: j, index: k })))
                .sum::<u64>()
        })
        .sum();
    ctx.progress.set_totals(chunks, bytes);
    for (file, first, n) in held {
        for start in (first..first + n).step_by(DIGESTS_PER_MSG) {
            let len = (first + n - start).min(DIGESTS_PER_MSG as u64);
            let digests = hash_window(ctx, file, start, len)?;
            tx.send(&Msg::Digests {
                file,
                first: start,
                digests,
            })?;
        }
    }
    Ok(())
}

/// Maximal runs of set bits as `(first, count)`.
fn present_runs(bits: &AtomicBitset) -> impl Iterator<Item = (u64, u64)> + '_ {
    let mut k = 0;
    std::iter::from_fn(move || {
        while k < bits.len() && !bits.get(k) {
            k += 1;
        }
        if k >= bits.len() {
            return None;
        }
        let first = k;
        while k < bits.len() && bits.get(k) {
            k += 1;
        }
        Some((first, k - first))
    })
}

/// Digests chunks `first..first + n` of `file` on the pool.
fn hash_window(ctx: &Ctx, file: u32, first: u64, n: u64) -> Result<Vec<u8>> {
    let run = &ctx.hashing;
    *run.window.lock().unwrap() = (file, first, n);
    *run.out.lock().unwrap() = vec![0u8; n as usize * DIGEST_LEN];
    run.cursor.store(0, Relaxed);
    let jobs = usize::try_from(n).map_or(ctx.pool.threads(), |n| ctx.pool.threads().min(n));
    for _ in 0..jobs {
        ctx.in_flight.add();
        ctx.pool.submit(SendJob::Hash);
    }
    ctx.in_flight.wait_idle();
    if ctx.progress.is_cancelled() {
        return Err(Cancelled::Local.into());
    }
    if let Some(e) = run.error.lock().unwrap().take() {
        return Err(e);
    }
    Ok(std::mem::take(&mut *run.out.lock().unwrap()))
}

/// One pool worker's share of a `HashRun` window.
fn hash_some(ctx: &Ctx) {
    let run = &ctx.hashing;
    let (file, first, n) = *run.window.lock().unwrap();
    let entry = &ctx.manifest.files[file as usize];
    let stop = || ctx.progress.is_cancelled();
    // A pooled frame buffer is idle between rounds and large enough.
    let Some(mut buf) = ctx.buffers.take(&stop) else {
        return;
    };
    let mut done = Vec::new();
    let source = match ctx.files.get(file) {
        Ok(f) => f,
        Err(e) => {
            *run.error.lock().unwrap() = Some(e);
            ctx.buffers.give(buf);
            return;
        }
    };
    while let i = run.cursor.fetch_add(1, Relaxed)
        && i < n
        && !ctx.progress.is_cancelled()
    {
        let (offset, len) = chunk_span(entry.size, ctx.manifest.chunk_size, first + i);
        let data = &mut buf[..len as usize];
        if let Err(e) = read_exact_at(&source, data, offset) {
            let e = anyhow!(e).context(format!("re-reading {}", entry.path.display()));
            *run.error.lock().unwrap() = Some(e);
            ctx.buffers.give(buf);
            return;
        }
        done.push((i, chunk_digest(data)));
        ctx.progress.add_chunk(u64::from(len));
    }
    ctx.buffers.give(buf);
    let mut out = run.out.lock().unwrap();
    for (i, digest) in done {
        out[i as usize * DIGEST_LEN..][..DIGEST_LEN].copy_from_slice(&digest);
    }
}

/// Pool worker: reads a chunk and seals it as its connection's frame `k`.
fn seal(ctx: &Ctx, job: SealJob) {
    let SealJob {
        conn,
        k,
        chunk,
        mut buf,
    } = job;
    let size = ctx.manifest.files[chunk.file as usize].size;
    let (offset, len) = chunk_span(size, ctx.manifest.chunk_size, chunk.index);
    let frame_len = HEADER_LEN + len as usize + TAG_LEN;
    let frame = &mut buf[..frame_len];
    let plain = &mut frame[HEADER_LEN..HEADER_LEN + len as usize];
    let read = match ctx.memory.get(chunk.file as usize) {
        Some(bytes) => {
            plain.copy_from_slice(&bytes[offset as usize..][..len as usize]);
            Ok(())
        }
        None => ctx
            .files
            .get(chunk.file)
            .and_then(|f| Ok(read_exact_at(&f, plain, offset)?)),
    };
    let sealed = read
        .map_err(|e| {
            let path = ctx.manifest.files[chunk.file as usize].path.display();
            let e = e.context(format!("reading {path} at offset {offset}"));
            *ctx.fatal.lock().unwrap() = Some(anyhow!("{e:#}"));
            e
        })
        .and_then(|()| {
            let sid = &ctx.keys.session_id;
            seal_frame(&conn.key, k, sid, chunk_header(chunk, len), frame)
        });
    conn.slots[k as usize % DEPTH].put(buf, sealed.map(|()| frame_len));
}

/// Fails if any source's size or mtime differs from the offer. The error
/// goes to the receiver too, so it names the file by its transfer path,
/// not by where it lives on this host.
fn check_unchanged(ctx: &Ctx) -> Result<()> {
    for (entry, path) in ctx.manifest.files.iter().zip(ctx.paths) {
        let changed = match fs::metadata(path) {
            Ok(meta) => meta.len() != entry.size || mtime_of(&meta) != entry.mtime,
            Err(_) => true,
        };
        ensure!(
            !changed,
            "source file changed during transfer: {}",
            entry.path.display()
        );
    }
    Ok(())
}

fn parse_have(m: &Manifest, bitmaps: &[Vec<u8>]) -> Result<Vec<AtomicBitset>> {
    ensure!(
        bitmaps.len() == m.files.len(),
        "Have lists {} files, the offer has {}",
        bitmaps.len(),
        m.files.len()
    );
    (0..m.files.len())
        .map(|j| {
            let count = m.chunk_count(j as u32);
            let bytes = &bitmaps[j];
            ensure!(
                bytes.len() as u64 == count.div_ceil(8),
                "Have bitmap for file {j} has the wrong length"
            );
            Ok(AtomicBitset::from_bytes(count, bytes))
        })
        .collect()
}

/// `(chunks, bytes)` still to send, counted from the bitmap words: every
/// missing chunk is a full chunk except a missing last chunk of a file.
fn missing_totals(m: &Manifest, have: &[AtomicBitset]) -> (u64, u64) {
    let cs = u64::from(m.chunk_size.get());
    let (mut chunks, mut bytes) = (0, 0);
    for (j, bits) in have.iter().enumerate() {
        let missing = bits.count_zeros();
        chunks += missing;
        bytes += missing * cs;
        let last = bits.len().wrapping_sub(1);
        if missing > 0 && !bits.get(last) {
            bytes -= cs
                - u64::from(m.chunk_len(ChunkId {
                    file: j as u32,
                    index: last,
                }));
        }
    }
    (chunks, bytes)
}

fn missing_count(have: &[AtomicBitset]) -> u64 {
    have.iter().map(AtomicBitset::count_zeros).sum()
}
