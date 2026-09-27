//! Socket plumbing shared by both roles: socket setup, interruptible
//! blocking I/O, connecting, and telling the peer why a session ends.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use socket2::{SockRef, TcpKeepalive};

use crate::progress::{Cancelled, Progress};
use crate::wire::{ControlTx, Msg};

/// OS-level socket timeout. Blocked reads and writes wake this often to
/// check whether they should stop; nothing else depends on its value.
pub(crate) const POLL: Duration = Duration::from_millis(100);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Configures an accepted or connected socket: blocking with `POLL`
/// timeouts, no Nagle delay, and TCP keepalive so a vanished peer is
/// noticed even on an idle control connection.
pub(crate) fn prepare(stream: &TcpStream) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(POLL))?;
    stream.set_write_timeout(Some(POLL))?;
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(5));
    SockRef::from(stream).set_tcp_keepalive(&keepalive)
}

/// Why an [`Io`] gave up early.
#[derive(Debug)]
pub(crate) struct Stopped;

impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connection stopped")
    }
}

impl std::error::Error for Stopped {}

/// Blocking reads and writes on a `prepare`d socket. Each call retries
/// across the `POLL` timeouts, so no partial progress is lost, until it
/// finishes, `stop` returns true, the deadline passes, or no byte moves for
/// `idle`. The checks run only on timeouts, which keeps the hot path clean,
/// and they work on Windows, where `shutdown` from another thread does not
/// wake a blocked `recv`.
pub(crate) struct Io<'a> {
    stream: TcpStream,
    stop: &'a (dyn Fn() -> bool + Sync),
    deadline: Option<Instant>,
    idle: Option<Duration>,
}

impl<'a> Io<'a> {
    pub(crate) fn new(stream: TcpStream, stop: &'a (dyn Fn() -> bool + Sync)) -> Self {
        Io {
            stream,
            stop,
            deadline: None,
            idle: None,
        }
    }

    /// Fails every operation once `after` has passed from now.
    pub(crate) fn deadline(mut self, after: Duration) -> Self {
        self.deadline = Some(Instant::now() + after);
        self
    }

    /// Fails an operation that moves no byte for `limit`.
    pub(crate) fn idle(mut self, limit: Duration) -> Self {
        self.idle = Some(limit);
        self
    }

    pub(crate) fn try_clone(&self) -> io::Result<Io<'a>> {
        Ok(Io {
            stream: self.stream.try_clone()?,
            ..*self
        })
    }

    pub(crate) fn into_stream(self) -> TcpStream {
        self.stream
    }

    fn retry<T>(&mut self, mut op: impl FnMut(&mut TcpStream) -> io::Result<T>) -> io::Result<T> {
        let started = Instant::now();
        loop {
            match op(&mut self.stream) {
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                other => return other,
            }
            if (self.stop)() {
                return Err(io::Error::other(Stopped));
            }
            let now = Instant::now();
            if self.deadline.is_some_and(|d| now >= d) {
                return Err(io::Error::new(ErrorKind::TimedOut, "deadline passed"));
            }
            if self.idle.is_some_and(|limit| now - started >= limit) {
                return Err(io::Error::new(ErrorKind::TimedOut, "peer went silent"));
            }
        }
    }
}

impl Read for Io<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.retry(|s| s.read(buf))
    }
}

impl Write for Io<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.retry(|s| s.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn resolve(addr: &str) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<_> = addr
        .to_socket_addrs()
        .with_context(|| format!("resolving {addr}"))?
        .collect();
    anyhow::ensure!(!addrs.is_empty(), "{addr} resolved to no addresses");
    Ok(addrs)
}

pub(crate) fn connect(addrs: &[SocketAddr], progress: &Progress) -> Result<TcpStream> {
    let mut last = None;
    for addr in addrs {
        if progress.is_cancelled() {
            return Err(Cancelled::Local.into());
        }
        match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                prepare(&s)?;
                return Ok(s);
            }
            Err(e) => last = Some(anyhow!(e).context(format!("connecting to {addr}"))),
        }
    }
    Err(last.expect("addrs is non-empty"))
}

/// Best effort: tell the peer why this side is leaving, `Cancel` for a local
/// cancel and `Error` for a local failure. Errors the peer caused are not
/// echoed back.
pub(crate) fn tell_peer_about<W: Write>(
    e: &anyhow::Error,
    progress: &Progress,
    tx: Option<&mut ControlTx<W>>,
) {
    let msg = if progress.is_cancelled() {
        Msg::Cancel
    } else if e.is::<Cancelled>() || e.is::<PeerError>() {
        return;
    } else {
        Msg::Error {
            message: format!("{e:#}"),
        }
    };
    if let Some(tx) = tx {
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
