//! The sender: walk the inputs, authenticate, and stream missing chunks over
//! parallel data connections, round by round.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Serialize;
use walkdir::WalkDir;

use crate::bitset::AtomicBitset;
use crate::crypto::{Cipher, FrameKey, SessionKeys, TAG_LEN, handshake_initiator};
use crate::keys::{PrivateKey, PublicKey};
use crate::manifest::{ChunkId, ChunkSize, FileEntry, Manifest, RelPath, chunk_span, mtime_of};
use crate::net::{self, Io, tell_peer_about, unexpected};
use crate::pool::{Buffers, Pool, buffer_count, resolve_threads};
use crate::posio::read_exact_at;
use crate::progress::{ActiveConnection, Cancelled, Phase, Progress};
use crate::wire::{
    self, ADMITTED, CHALLENGE_LEN, ConnKind, ControlRx, ControlTx, FrameHeader, HEADER_LEN, Msg,
    Role, chunk_header, encode_hello, seal_frame,
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

/// A local file and where it goes in the manifest.
struct Source {
    entry: FileEntry,
    path: PathBuf,
}

struct Ctx<'a> {
    addrs: &'a [SocketAddr],
    keys: &'a SessionKeys,
    cipher: Cipher,
    manifest: &'a Manifest,
    files: &'a [File],
    paths: &'a [PathBuf],
    progress: &'a Progress,
    chunks_sent: AtomicU64,
    bytes_sent: AtomicU64,
    chunks_resent: AtomicU64,
    /// Per file, the chunks sent at least once this session.
    sent: Vec<AtomicBitset>,
    /// A local read failure; fatal for the transfer, unlike network errors.
    fatal: Mutex<Option<anyhow::Error>>,
    pool: &'a Pool<SealJob>,
    buffers: &'a Buffers,
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
        (1..=1024).contains(&cfg.connections),
        "connections must be between 1 and 1024"
    );
    let chunk_size = ChunkSize::new(cfg.chunk_size)?;
    let sources = collect_sources(&cfg.paths)?;
    let files = sources
        .iter()
        .map(|s| File::open(&s.path).with_context(|| format!("opening {}", s.path.display())))
        .collect::<Result<Vec<_>>>()?;
    let (entries, paths): (Vec<_>, Vec<_>) = sources.into_iter().map(|s| (s.entry, s.path)).unzip();
    let manifest = Manifest::new(chunk_size, entries)?;

    let addrs = net::resolve(&cfg.addr)?;
    let cancelled = || progress.is_cancelled();
    let mut control = Io::new(net::connect(&addrs, progress)?, &cancelled);
    wire::write_preamble(&mut control, ConnKind::Control)?;
    progress.set_phase(Phase::Handshaking);
    let mut handshake = control.try_clone()?.deadline(HANDSHAKE_DEADLINE);
    let keys = handshake_initiator(&mut handshake, &cfg.key, &cfg.peer)?;
    let (mut tx, mut rx) =
        wire::control_channel(control.try_clone()?, control, &keys, Role::Sender);
    let pool = Pool::new(resolve_threads(cfg.threads));
    let buf_len = HEADER_LEN + chunk_size.get() as usize + TAG_LEN;
    let buffers = Buffers::new(
        buffer_count(pool.threads(), cfg.connections, buf_len),
        buf_len,
    );
    let ctx = Ctx {
        addrs: &addrs,
        keys: &keys,
        cipher: cfg.cipher,
        manifest: &manifest,
        files: &files,
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
    };
    let result = thread::scope(|s| {
        for _ in 0..pool.threads() {
            s.spawn(|| pool.work(|job| seal(&ctx, job)));
        }
        let result = transfer(&ctx, cfg.connections, &mut tx, &mut rx);
        pool.close();
        result
    });
    if let Err(e) = &result {
        tell_peer_about(e, progress, Some(&mut tx));
        net::linger(rx.into_inner().into_stream());
    }
    let (rounds, verified) = result?;
    Ok(SendReport {
        files: manifest.files.len(),
        bytes_sent: ctx.bytes_sent.load(Relaxed),
        chunks_sent: ctx.chunks_sent.load(Relaxed),
        chunks_resent: ctx.chunks_resent.load(Relaxed),
        rounds,
        verified,
        elapsed: start.elapsed(),
    })
}

/// Runs rounds until the receiver reports `Finished`. Returns the round
/// count and whether the receiver verified the files.
fn transfer(ctx: &Ctx, connections: usize, tx: &mut Tx, rx: &mut Rx) -> Result<(u32, bool)> {
    let m = ctx.manifest;
    tx.send(&Msg::Offer {
        chunk_size: m.chunk_size.get(),
        cipher: ctx.cipher,
        files: m.to_offer(),
    })?;
    let mut have = match rx.recv()? {
        Msg::Have { bitmaps } => parse_have(m, &bitmaps)?,
        other => return Err(unexpected(other, "Have")),
    };
    let queue = missing(&have);
    let bytes: u64 = queue.iter().map(|&c| u64::from(m.chunk_len(c))).sum();
    ctx.progress.set_totals(queue.len() as u64, bytes);
    ctx.progress.set_phase(Phase::Transferring);

    let mut failed_rounds = 0;
    for round in 0u32.. {
        let queue = missing(&have);
        tx.send(&Msg::RoundStart { round })?;
        let admitted = run_round(ctx, round, connections, &queue);
        if ctx.progress.is_cancelled() {
            return Err(Cancelled::Local.into());
        }
        if let Some(e) = ctx.fatal.lock().unwrap().take() {
            return Err(e);
        }
        check_unchanged(ctx)?;
        ctx.progress.set_phase(Phase::Finishing);
        let sent = tx.send(&Msg::RoundEnd {
            round,
            connections: admitted,
        });
        // Read even if the send failed: the peer may have said why it left.
        let reply = rx.recv().map_err(|e| sent.err().unwrap_or(e))?;
        match reply {
            Msg::Finished { verified } => return Ok((round + 1, verified)),
            Msg::Have { bitmaps } => have = parse_have(m, &bitmaps)?,
            other => return Err(unexpected(other, "Have or Finished")),
        }
        ctx.progress.set_phase(Phase::Transferring);
        // Progress means some chunk this round carried is now held. Chunks
        // the receiver's verification sent back to missing do not count
        // against the round.
        let landed = queue.iter().any(|c| have[c.file as usize].get(c.index));
        if !queue.is_empty() && !landed {
            failed_rounds += 1;
            if failed_rounds == MAX_FAILED_ROUNDS {
                bail!("{MAX_FAILED_ROUNDS} rounds in a row made no progress");
            }
        } else {
            failed_rounds = 0;
        }
    }
    unreachable!("u32 rounds exhausted")
}

/// Opens up to `connections` data connections that drain `queue` together.
/// Returns how many the receiver admitted.
fn run_round(ctx: &Ctx, round: u32, connections: usize, queue: &[ChunkId]) -> u32 {
    let cursor = AtomicUsize::new(0);
    let admitted = AtomicU32::new(0);
    thread::scope(|s| {
        for conn in 0..connections.min(queue.len()) as u32 {
            let (cursor, admitted) = (&cursor, &admitted);
            s.spawn(move || {
                if let Err(e) = data_connection(ctx, round, conn, queue, cursor, admitted)
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
    queue: &[ChunkId],
    cursor: &AtomicUsize,
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
    let conn = Arc::new(SendConn {
        key: FrameKey::new(ctx.cipher, &ctx.keys.data_key(round, conn)),
        slots: Default::default(),
    });
    let result = stream_frames(ctx, &conn, &mut stream, queue, cursor);
    stream.into_stream().shutdown(Shutdown::Write)?;
    result
}

/// Keeps up to `DEPTH` frames of this connection sealing on the pool while
/// earlier ones go out, and writes them strictly in frame order.
fn stream_frames(
    ctx: &Ctx,
    conn: &Arc<SendConn>,
    stream: &mut Io,
    queue: &[ChunkId],
    cursor: &AtomicUsize,
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
                let Some(&chunk) = queue.get(cursor.fetch_add(1, Relaxed)) else {
                    ctx.buffers.give(buf);
                    exhausted = true;
                    break;
                };
                chunks[submitted as usize % DEPTH] = chunk;
                ctx.pool.submit(SealJob {
                    conn: conn.clone(),
                    k: submitted,
                    chunk,
                    buf,
                });
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
            if !ctx.sent[chunk.file as usize].set(chunk.index) {
                ctx.chunks_resent.fetch_add(1, Relaxed);
            }
            ctx.bytes_sent.fetch_add(len, Relaxed);
            ctx.progress.add_chunk(len);
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
    let sealed = read_exact_at(&ctx.files[chunk.file as usize], plain, offset)
        .map_err(|e| {
            let path = ctx.manifest.files[chunk.file as usize].path.as_str();
            let e = anyhow!(e).context(format!("reading {path} at offset {offset}"));
            *ctx.fatal.lock().unwrap() = Some(anyhow!("{e:#}"));
            e
        })
        .and_then(|()| {
            let sid = &ctx.keys.session_id;
            seal_frame(&conn.key, k, sid, chunk_header(chunk, len), frame)
        });
    conn.slots[k as usize % DEPTH].put(buf, sealed.map(|()| frame_len));
}

/// Fails if any source's size or mtime differs from the offer.
fn check_unchanged(ctx: &Ctx) -> Result<()> {
    for (entry, path) in ctx.manifest.files.iter().zip(ctx.paths) {
        let changed = match fs::metadata(path) {
            Ok(meta) => meta.len() != entry.size || mtime_of(&meta) != entry.mtime,
            Err(_) => true,
        };
        ensure!(
            !changed,
            "source file changed during transfer: {}",
            path.display()
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

/// The work queue: every absent chunk in file order, so reads stay nearly
/// sequential while connections claim from the front.
fn missing(have: &[AtomicBitset]) -> Vec<ChunkId> {
    let mut queue = Vec::new();
    for (file, bits) in have.iter().enumerate() {
        for index in 0..bits.len() {
            if !bits.get(index) {
                queue.push(ChunkId {
                    file: file as u32,
                    index,
                });
            }
        }
    }
    queue
}

/// Walks the inputs. A file is named by its file name; a directory's files
/// are named `<dir name>/<path inside it>`.
fn collect_sources(paths: &[PathBuf]) -> Result<Vec<Source>> {
    ensure!(!paths.is_empty(), "nothing to send");
    let mut out = Vec::new();
    for root in paths {
        let meta = fs::metadata(root).with_context(|| format!("reading {}", root.display()))?;
        let canonical = root.canonicalize()?;
        let base = canonical
            .file_name()
            .map(|n| utf8(Path::new(n)))
            .transpose()?;
        if meta.is_file() {
            let name = base.with_context(|| format!("{} has no file name", root.display()))?;
            out.push(source(&name, root.clone(), &meta)?);
            continue;
        }
        for entry in WalkDir::new(root).sort_by_file_name() {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            let inner = utf8(entry.path().strip_prefix(root)?)?;
            let name = match &base {
                Some(base) => format!("{base}/{inner}"),
                None => inner,
            };
            out.push(source(&name, entry.path().to_owned(), &entry.metadata()?)?);
        }
    }
    Ok(out)
}

fn source(name: &str, path: PathBuf, meta: &fs::Metadata) -> Result<Source> {
    Ok(Source {
        entry: FileEntry {
            path: RelPath::parse(name)
                .with_context(|| format!("cannot send {}", path.display()))?,
            size: meta.len(),
            mtime: mtime_of(meta),
        },
        path,
    })
}

/// A relative path as `/`-separated UTF-8.
fn utf8(p: &Path) -> Result<String> {
    let parts = p
        .components()
        .map(|c| {
            c.as_os_str()
                .to_str()
                .with_context(|| format!("{} is not valid UTF-8", p.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(parts.join("/"))
}
