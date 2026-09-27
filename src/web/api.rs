//! JSON API: request parsing and validation at the boundary, handlers, and
//! the response DTOs.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tiny_http::Method;

use super::fs;
use super::jobs::{FileHash, Job, JobId, JobState, Jobs, Outcome, RemoveError, Report};
use crate::filemap::{ApplyPolicy, Preserve};
use crate::keys::{PrivateKey, PublicKey};
use crate::manifest::{MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use crate::{Cipher, Phase, Receiver, RecvConfig, RecvReport, SendConfig, SendReport};

const MAX_CONNECTIONS: usize = 64;
const MAX_THREADS: usize = 256;

pub struct App {
    key: PrivateKey,
    key_path: PathBuf,
    jobs: Arc<Jobs>,
}

impl App {
    pub fn new(key: PrivateKey, key_path: PathBuf) -> Self {
        let key_path = std::path::absolute(&key_path).unwrap_or(key_path);
        App {
            key,
            key_path,
            jobs: Arc::default(),
        }
    }
}

pub enum Reply {
    Asset {
        mime: &'static str,
        body: &'static str,
    },
    Json(Value),
    NoContent,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub field: Option<&'static str>,
    pub message: String,
}

impl ApiError {
    pub fn new(status: u16, field: Option<&'static str>, message: impl Into<String>) -> Self {
        ApiError {
            status,
            field,
            message: message.into(),
        }
    }

    fn field(field: &'static str, message: impl Into<String>) -> Self {
        Self::new(400, Some(field), message)
    }

    pub fn not_found() -> Self {
        Self::new(404, None, "not found")
    }

    pub fn body(&self) -> Value {
        json!({ "error": self.message, "field": self.field })
    }
}

/// What a job was started with, as shown to the UI. Never holds the private key.
#[derive(Clone, Serialize)]
#[serde(tag = "kind", content = "spec", rename_all = "snake_case")]
pub enum JobSpec {
    Send {
        addr: String,
        peer: String,
        paths: Vec<PathBuf>,
        connections: usize,
        chunk_size: u32,
        cipher: Cipher,
        threads: usize,
        hash: bool,
        preserve: Preserve,
    },
    Receive {
        listen: SocketAddr,
        #[serde(skip)]
        bound_addr: SocketAddr,
        authorized: Vec<String>,
        out_dir: PathBuf,
        force: bool,
        verify: bool,
        threads: usize,
        apply: ApplyPolicy,
    },
}

fn file_hashes(pairs: Vec<(String, String)>) -> Vec<FileHash> {
    pairs
        .into_iter()
        .map(|(path, hash)| FileHash { path, hash })
        .collect()
}

impl From<SendReport> for Report {
    fn from(r: SendReport) -> Report {
        Report {
            files: r.files as u64,
            bytes: r.bytes_sent,
            elapsed_ms: r.elapsed.as_millis() as u64,
            verified: r.verified,
            hashed: r.hashed,
            chunks_resent: r.chunks_resent,
            repaired_chunks: 0,
            hash_repaired_chunks: r.hash_repaired_chunks,
            duplicate_chunks: 0,
            file_hashes: file_hashes(r.file_hashes),
            warnings: r.warnings,
            skipped: r.skipped,
        }
    }
}

impl From<RecvReport> for Report {
    fn from(r: RecvReport) -> Report {
        Report {
            files: r.files as u64,
            bytes: r.bytes_received,
            elapsed_ms: r.elapsed.as_millis() as u64,
            verified: r.verified,
            hashed: r.hashed,
            chunks_resent: 0,
            repaired_chunks: r.repaired_chunks,
            hash_repaired_chunks: r.hash_repaired_chunks,
            duplicate_chunks: r.duplicate_chunks,
            file_hashes: file_hashes(r.file_hashes),
            warnings: r.warnings,
            skipped: r.skipped,
        }
    }
}

pub fn route(
    app: &App,
    method: &Method,
    path: &str,
    query: &[(String, String)],
    body: Value,
) -> Result<Reply, ApiError> {
    let segments: Vec<&str> = path.trim_start_matches("/api/").split('/').collect();
    match (method, segments.as_slice()) {
        (Method::Get, ["identity"]) => Ok(Reply::Json(json!({
            "public_key": app.key.public_key().to_string(),
            "key_path": app.key_path,
        }))),
        (Method::Get, ["transfers"]) => Ok(Reply::Json(json!({
            "transfers": app.jobs.map_newest_first(view),
        }))),
        (Method::Post, ["send"]) => start_send(app, parse(body)?),
        (Method::Post, ["receive"]) => start_receive(app, parse(body)?),
        (Method::Post, ["transfers", id, "cancel"]) => {
            let id = job_id(id)?;
            if !app.jobs.cancel(id) {
                return Err(ApiError::not_found());
            }
            transfer(app, id)
        }
        (Method::Delete, ["transfers", id]) => match app.jobs.remove(job_id(id)?) {
            Ok(()) => Ok(Reply::NoContent),
            Err(RemoveError::NotFound) => Err(ApiError::not_found()),
            Err(RemoveError::Running) => Err(ApiError::new(
                409,
                None,
                "the transfer is still running; cancel it first",
            )),
        },
        (Method::Get, ["fs"]) => {
            let dir = query
                .iter()
                .find(|(k, v)| k == "path" && !v.is_empty())
                .map(|(_, v)| Path::new(v));
            fs::list(dir)
                .map(|listing| Reply::Json(json!(listing)))
                .map_err(|e| ApiError::field("path", e.to_string()))
        }
        (_, ["identity" | "transfers" | "send" | "receive" | "fs"])
        | (_, ["transfers", _] | ["transfers", _, "cancel"]) => {
            Err(ApiError::new(405, None, "method not allowed"))
        }
        _ => Err(ApiError::not_found()),
    }
}

fn parse<T: for<'de> Deserialize<'de>>(body: Value) -> Result<T, ApiError> {
    serde_json::from_value(body)
        .map_err(|e| ApiError::new(400, None, format!("invalid request: {e}")))
}

fn job_id(s: &str) -> Result<JobId, ApiError> {
    s.parse().map_err(|_| ApiError::not_found())
}

fn transfer(app: &App, id: JobId) -> Result<Reply, ApiError> {
    app.jobs
        .with(id, |job| Reply::Json(json!(view(job))))
        .ok_or_else(ApiError::not_found)
}

#[derive(Deserialize)]
struct SendRequest {
    addr: String,
    peer: String,
    paths: Vec<String>,
    #[serde(default = "default_connections")]
    connections: usize,
    #[serde(default = "default_chunk")]
    chunk_size: u32,
    #[serde(default)]
    cipher: Cipher,
    #[serde(default)]
    threads: usize,
    #[serde(default)]
    hash: bool,
    #[serde(default)]
    preserve: Preserve,
}

fn default_connections() -> usize {
    8
}
fn default_chunk() -> u32 {
    1024 * 1024
}

#[derive(Deserialize)]
struct ReceiveRequest {
    listen: String,
    authorized: Vec<String>,
    out_dir: String,
    #[serde(default)]
    force: bool,
    #[serde(default = "default_verify")]
    verify: bool,
    #[serde(default)]
    threads: usize,
    #[serde(default)]
    apply: ApplyPolicy,
}

fn default_verify() -> bool {
    true
}

/// 0 means one worker per CPU core.
fn check_threads(threads: usize) -> Result<usize, ApiError> {
    if threads > MAX_THREADS {
        return Err(ApiError::field(
            "threads",
            format!("must be between 0 (auto) and {MAX_THREADS}"),
        ));
    }
    Ok(threads)
}

fn parse_key(field: &'static str, text: &str) -> Result<PublicKey, ApiError> {
    text.trim()
        .parse()
        .map_err(|e| ApiError::field(field, format!("not a valid public key ({e:#})")))
}

fn start_send(app: &App, req: SendRequest) -> Result<Reply, ApiError> {
    let addr = req.addr.trim().to_string();
    let well_formed = addr
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0));
    if !well_formed {
        return Err(ApiError::field(
            "addr",
            "expected host:port, like 192.168.1.20:7777",
        ));
    }
    let peer = parse_key("peer", &req.peer)?;
    if req.paths.is_empty() {
        return Err(ApiError::field(
            "paths",
            "choose at least one file or folder",
        ));
    }
    let paths: Vec<PathBuf> = req.paths.iter().map(PathBuf::from).collect();
    if let Some(missing) = paths.iter().find(|p| !p.exists()) {
        let hint = if missing.to_string_lossy().contains('\u{FFFD}') {
            "; its name is not valid Unicode, so select its parent folder instead"
        } else {
            ""
        };
        return Err(ApiError::field(
            "paths",
            format!("{} does not exist{hint}", missing.display()),
        ));
    }
    if !(1..=MAX_CONNECTIONS).contains(&req.connections) {
        return Err(ApiError::field(
            "connections",
            format!("must be between 1 and {MAX_CONNECTIONS}"),
        ));
    }
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&req.chunk_size) {
        return Err(ApiError::field(
            "chunk_size",
            "must be between 4 KiB and 64 MiB",
        ));
    }
    let threads = check_threads(req.threads)?;

    let spec = JobSpec::Send {
        addr: addr.clone(),
        peer: peer.to_string(),
        paths: paths.clone(),
        connections: req.connections,
        chunk_size: req.chunk_size,
        cipher: req.cipher,
        threads,
        hash: req.hash,
        preserve: req.preserve,
    };
    let cfg = SendConfig {
        addr,
        key: app.key.clone(),
        peer,
        connections: req.connections,
        chunk_size: req.chunk_size,
        cipher: req.cipher,
        threads,
        paths,
        hash: req.hash,
        preserve: req.preserve,
    };
    let id = app.jobs.spawn(spec, move |progress| {
        crate::send(cfg, progress).map(Report::from)
    });
    transfer(app, id)
}

fn start_receive(app: &App, req: ReceiveRequest) -> Result<Reply, ApiError> {
    let listen: SocketAddr = req
        .listen
        .trim()
        .parse()
        .map_err(|_| ApiError::field("listen", "expected ip:port, like 0.0.0.0:7777"))?;
    let authorized = req
        .authorized
        .iter()
        .filter(|k| !k.trim().is_empty())
        .map(|k| parse_key("authorized", k))
        .collect::<Result<Vec<_>, _>>()?;
    if authorized.is_empty() {
        return Err(ApiError::field(
            "authorized",
            "authorize at least one sender key",
        ));
    }
    let out_dir = PathBuf::from(req.out_dir.trim());
    if req.out_dir.trim().is_empty() || !out_dir.is_dir() {
        return Err(ApiError::field("out_dir", "choose an existing folder"));
    }
    let threads = check_threads(req.threads)?;

    let receiver = Receiver::bind(RecvConfig {
        listen,
        key: app.key.clone(),
        authorized: authorized.clone(),
        out_dir: out_dir.clone(),
        force: req.force,
        verify: req.verify,
        threads,
        apply: req.apply,
    })
    .map_err(|e| ApiError::field("listen", format!("{e:#}")))?;
    let bound_addr = receiver.local_addr();

    let spec = JobSpec::Receive {
        listen,
        bound_addr,
        authorized: authorized.iter().map(ToString::to_string).collect(),
        out_dir,
        force: req.force,
        verify: req.verify,
        threads,
        apply: req.apply,
    };
    let id = app.jobs.spawn(spec, move |progress| {
        receiver.run(progress).map(Report::from)
    });
    transfer(app, id)
}

#[derive(Serialize)]
struct TransferView<'a> {
    id: JobId,
    #[serde(flatten)]
    spec: &'a JobSpec,
    created_at_ms: u64,
    state: &'static str,
    error: Option<&'a str>,
    report: Option<&'a Report>,
    bound_addr: Option<SocketAddr>,
    progress: ProgressView,
    elapsed_ms: u64,
}

#[derive(Serialize)]
struct ProgressView {
    phase: &'static str,
    bytes_done: u64,
    bytes_total: u64,
    chunks_done: u64,
    chunks_total: u64,
    active_connections: u64,
}

fn view(job: &Job) -> Value {
    let (state, error, report) = match &job.state {
        JobState::Running => ("running", None, None),
        JobState::Ended { outcome, .. } => match outcome {
            Outcome::Done(r) => ("done", None, Some(r)),
            Outcome::Failed(e) => ("failed", Some(e.as_str()), None),
            Outcome::Cancelled => ("cancelled", None, None),
        },
    };
    let bound_addr = match job.spec {
        JobSpec::Receive { bound_addr, .. } => Some(bound_addr),
        JobSpec::Send { .. } => None,
    };
    let s = job.progress.snapshot();
    json!(TransferView {
        id: job.id,
        spec: &job.spec,
        created_at_ms: job
            .created_at
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64),
        state,
        error,
        report,
        bound_addr,
        progress: ProgressView {
            phase: phase_name(s.phase),
            bytes_done: s.bytes_done,
            bytes_total: s.bytes_total,
            chunks_done: s.chunks_done,
            chunks_total: s.chunks_total,
            active_connections: s.active_connections,
        },
        elapsed_ms: job.elapsed_ms(),
    })
}

fn phase_name(p: Phase) -> &'static str {
    match p {
        Phase::Connecting => "connecting",
        Phase::Handshaking => "handshaking",
        Phase::Transferring => "transferring",
        Phase::Verifying => "verifying",
        Phase::Hashing => "hashing",
        Phase::Finishing => "finishing",
        Phase::Done => "done",
        Phase::Failed => "failed",
    }
}
