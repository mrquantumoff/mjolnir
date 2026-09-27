//! The sender: walk the inputs, authenticate, and stream missing chunks over
//! parallel data connections, round by round.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Serialize;
use walkdir::WalkDir;

use crate::bitset::AtomicBitset;
use crate::crypto::{Cipher, CipherState, SessionKeys, TAG_LEN, handshake_initiator};
use crate::keys::{PrivateKey, PublicKey};
use crate::manifest::{ChunkId, ChunkSize, FileEntry, Manifest, RelPath, chunk_span, mtime_of};
use crate::net::{self, SharedTx, Sockets, send_ctrl, tell_peer_about, unexpected};
use crate::posio::read_exact_at;
use crate::progress::{ActiveConnection, Cancelled, Phase, Progress, Stop};
use crate::wire::{
    self, ADMITTED, CHALLENGE_LEN, ConnKind, ControlRx, FrameHeader, HEADER_LEN, Msg, Role,
    chunk_header, encode_hello, seal_frame,
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
    /// Files or directories; a directory is sent recursively under its name.
    pub paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SendReport {
    pub files: usize,
    /// Plaintext bytes of the chunks sent this session.
    pub bytes_sent: u64,
    pub chunks_sent: u64,
    pub rounds: u32,
    pub elapsed: Duration,
}

/// Rounds without progress tolerated before giving up.
const MAX_FAILED_ROUNDS: u32 = 3;

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
    sockets: &'a Sockets,
    progress: &'a Progress,
    chunks_sent: AtomicU64,
    bytes_sent: AtomicU64,
    /// A local read failure; fatal for the transfer, unlike network errors.
    fatal: Mutex<Option<anyhow::Error>>,
}

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
    check_bitmaps_fit(&manifest)?;

    let addrs = net::resolve(&cfg.addr)?;
    let mut control = net::connect(&addrs)?;
    wire::write_preamble(&mut control, ConnKind::Control)?;

    let tx: SharedTx = Mutex::new(None);
    let sockets = Sockets::default();
    let stop = Stop::default();
    let watched = control.try_clone()?;
    thread::scope(|s| {
        s.spawn(|| net::watch_cancel(progress, &stop, &watched, &tx, &sockets));
        let result = (|| {
            progress.set_phase(Phase::Handshaking);
            let keys = handshake_initiator(&mut control, &cfg.key, &cfg.peer)?;
            let (ctx_tx, mut rx) = wire::control_channel(control, &keys, Role::Sender)?;
            *tx.lock().unwrap() = Some(ctx_tx);
            let ctx = Ctx {
                addrs: &addrs,
                keys: &keys,
                cipher: cfg.cipher,
                manifest: &manifest,
                files: &files,
                paths: &paths,
                sockets: &sockets,
                progress,
                chunks_sent: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
                fatal: Mutex::new(None),
            };
            let rounds = transfer(&ctx, cfg.connections, &tx, &mut rx)?;
            Ok(SendReport {
                files: manifest.files.len(),
                bytes_sent: ctx.bytes_sent.load(Relaxed),
                chunks_sent: ctx.chunks_sent.load(Relaxed),
                rounds,
                elapsed: start.elapsed(),
            })
        })();
        if let Err(e) = &result {
            tell_peer_about(e, progress, &tx);
        }
        stop.stop();
        sockets.shutdown_all();
        result
    })
}

/// Runs rounds until the receiver reports `Finished`. Returns the round count.
fn transfer(ctx: &Ctx, connections: usize, tx: &SharedTx, rx: &mut ControlRx) -> Result<u32> {
    let m = ctx.manifest;
    send_ctrl(
        tx,
        &Msg::Offer {
            chunk_size: m.chunk_size.get(),
            cipher: ctx.cipher,
            files: m.to_offer(),
        },
    )?;
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
        send_ctrl(tx, &Msg::RoundStart { round })?;
        let admitted = run_round(ctx, round, connections, &queue);
        if ctx.progress.is_cancelled() {
            return Err(Cancelled::Local.into());
        }
        if let Some(e) = ctx.fatal.lock().unwrap().take() {
            return Err(e);
        }
        check_unchanged(ctx)?;
        ctx.progress.set_phase(Phase::Finishing);
        let sent = send_ctrl(
            tx,
            &Msg::RoundEnd {
                round,
                connections: admitted,
            },
        );
        // Read even if the send failed: the peer may have said why it left.
        let reply = rx.recv().map_err(|e| sent.err().unwrap_or(e))?;
        match reply {
            Msg::Finished => return Ok(round + 1),
            Msg::Have { bitmaps } => have = parse_have(m, &bitmaps)?,
            other => return Err(unexpected(other, "Have or Finished")),
        }
        ctx.progress.set_phase(Phase::Transferring);
        if missing_count(&have) >= queue.len() as u64 {
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
                    eprintln!("gorynych: data connection {conn} of round {round}: {e:#}");
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
    let mut stream: TcpStream = net::connect(ctx.addrs)?;
    ctx.sockets.add(&stream);
    wire::write_preamble(&mut stream, ConnKind::Data)?;
    let mut challenge = [0u8; CHALLENGE_LEN];
    stream.read_exact(&mut challenge)?;
    stream.write_all(&encode_hello(ctx.keys, &challenge, round, conn))?;
    let mut verdict = [0u8];
    stream.read_exact(&mut verdict)?;
    ensure!(verdict[0] == ADMITTED, "receiver rejected the connection");
    admitted.fetch_add(1, Relaxed);
    let _active = ActiveConnection::new(ctx.progress);

    let sid = &ctx.keys.session_id;
    let mut cipher = CipherState::new(ctx.cipher, &ctx.keys.data_key(round, conn));
    let chunk_size = ctx.manifest.chunk_size;
    let mut buf = vec![0u8; HEADER_LEN + chunk_size.get() as usize + TAG_LEN];
    loop {
        if ctx.progress.is_cancelled() {
            return Err(Cancelled::Local.into());
        }
        let Some(&chunk) = queue.get(cursor.fetch_add(1, Relaxed)) else {
            break;
        };
        let size = ctx.manifest.files[chunk.file as usize].size;
        let (offset, len) = chunk_span(size, chunk_size, chunk.index);
        let frame = &mut buf[..HEADER_LEN + len as usize + TAG_LEN];
        let plain = &mut frame[HEADER_LEN..HEADER_LEN + len as usize];
        if let Err(e) = read_exact_at(&ctx.files[chunk.file as usize], plain, offset) {
            let path = ctx.manifest.files[chunk.file as usize].path.as_str();
            let e = anyhow!(e).context(format!("reading {path} at offset {offset}"));
            *ctx.fatal.lock().unwrap() = Some(anyhow!("{e:#}"));
            return Err(e);
        }
        seal_frame(&mut cipher, sid, chunk_header(chunk, len), frame)?;
        stream.write_all(frame)?;
        ctx.chunks_sent.fetch_add(1, Relaxed);
        ctx.bytes_sent.fetch_add(u64::from(len), Relaxed);
        ctx.progress.add_chunk(u64::from(len));
    }
    let end = &mut buf[..HEADER_LEN + TAG_LEN];
    seal_frame(&mut cipher, sid, FrameHeader::end(), end)?;
    stream.write_all(end)?;
    stream.shutdown(Shutdown::Write)?;
    Ok(())
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

fn missing_count(have: &[AtomicBitset]) -> u64 {
    have.iter().map(|b| b.len() - b.count_ones()).sum()
}

/// Refuses manifests whose `Have` reply would not fit in one control message.
fn check_bitmaps_fit(m: &Manifest) -> Result<()> {
    let bytes: u64 = (0..m.files.len() as u32)
        .map(|j| m.chunk_count(j).div_ceil(8) + 10)
        .sum();
    ensure!(
        bytes + 1024 <= wire::MAX_CONTROL_LEN as u64,
        "too many chunks for one transfer; use a larger --chunk-size"
    );
    Ok(())
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
