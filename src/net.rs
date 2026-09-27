//! Socket plumbing shared by both roles: connecting, the registry of data
//! sockets, and the cancel watchdog.

use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};

use crate::progress::{Cancelled, Progress, Stop};
use crate::wire::{ControlTx, Msg};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn resolve(addr: &str) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<_> = addr
        .to_socket_addrs()
        .with_context(|| format!("resolving {addr}"))?
        .collect();
    anyhow::ensure!(!addrs.is_empty(), "{addr} resolved to no addresses");
    Ok(addrs)
}

pub(crate) fn connect(addrs: &[SocketAddr]) -> Result<TcpStream> {
    let mut last = None;
    for addr in addrs {
        match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                s.set_nodelay(true)?;
                return Ok(s);
            }
            Err(e) => last = Some(anyhow!(e).context(format!("connecting to {addr}"))),
        }
    }
    Err(last.expect("addrs is non-empty"))
}

/// Clones of every data socket, so a cancel or the end of a transfer can
/// unblock threads stuck in `read` or `write` by shutting the sockets down.
#[derive(Default)]
pub(crate) struct Sockets(Mutex<SocketsInner>);

#[derive(Default)]
struct SocketsInner {
    closed: bool,
    streams: Vec<TcpStream>,
}

impl Sockets {
    /// Registers a socket; once `shutdown_all` has run, shuts it immediately.
    pub(crate) fn add(&self, stream: &TcpStream) {
        let mut inner = self.0.lock().unwrap();
        if inner.closed {
            let _ = stream.shutdown(Shutdown::Both);
        } else if let Ok(clone) = stream.try_clone() {
            inner.streams.push(clone);
        }
    }

    pub(crate) fn shutdown_all(&self) {
        let mut inner = self.0.lock().unwrap();
        inner.closed = true;
        for s in inner.streams.drain(..) {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

/// The control channel's sending half, available once the handshake is done.
pub(crate) type SharedTx = Mutex<Option<ControlTx>>;

pub(crate) fn send_ctrl(tx: &SharedTx, msg: &Msg) -> Result<()> {
    tx.lock()
        .unwrap()
        .as_mut()
        .expect("control channel is set up after the handshake")
        .send(msg)
}

/// Polls `progress.cancel` until `stop`. On cancel it tells the peer (if the
/// control channel is free within 100 ms) and shuts every socket down, which
/// makes each blocked thread of the transfer return an error.
pub(crate) fn watch_cancel(
    progress: &Progress,
    stop: &Stop,
    control: &TcpStream,
    tx: &SharedTx,
    sockets: &Sockets,
) {
    while !stop.wait(Duration::from_millis(50)) {
        if !progress.is_cancelled() {
            continue;
        }
        let deadline = Instant::now() + Duration::from_millis(100);
        while Instant::now() < deadline {
            if let Ok(mut guard) = tx.try_lock() {
                if let Some(tx) = guard.as_mut() {
                    let _ = tx.send(&Msg::Cancel);
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = control.shutdown(Shutdown::Both);
        sockets.shutdown_all();
        return;
    }
}

/// Best effort: tell the peer why this side is leaving, `Cancel` for a local
/// cancel and `Error` for a local failure. Errors the peer caused are not
/// echoed back.
pub(crate) fn tell_peer_about(e: &anyhow::Error, progress: &Progress, tx: &SharedTx) {
    let msg = if progress.is_cancelled() {
        Msg::Cancel
    } else if e.is::<Cancelled>() || e.is::<PeerError>() {
        return;
    } else {
        Msg::Error {
            message: format!("{e:#}"),
        }
    };
    if let Ok(mut guard) = tx.try_lock()
        && let Some(tx) = guard.as_mut()
    {
        let _ = tx.send(&msg);
    }
}

/// An `Error` message the peer sent; not echoed back.
#[derive(Debug)]
pub(crate) struct PeerError(pub String);

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer reported an error: {}", self.0)
    }
}

impl std::error::Error for PeerError {}

/// Maps the peer's terminal messages to errors.
pub(crate) fn unexpected(msg: Msg, waiting_for: &str) -> anyhow::Error {
    match msg {
        Msg::Error { message } => PeerError(message).into(),
        Msg::Cancel => Cancelled::Peer.into(),
        other => anyhow!("protocol error: expected {waiting_for}, got {other:?}"),
    }
}
