//! Socket plumbing shared by both roles: socket setup, interruptible
//! blocking I/O, connecting, and telling the peer why a session ends.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use socket2::{SockRef, TcpKeepalive};

use crate::progress::{Cancelled, Progress};
use crate::wire::{ControlTx, Msg};

/// OS-level read timeout. Blocked reads wake this often to check whether
/// they should stop; nothing else depends on its value.
pub(crate) const POLL: Duration = Duration::from_millis(100);
/// OS-level write timeout, after which the connection is given up. A write
/// that times out is never retried: on Windows a send that hits
/// `SO_SNDTIMEO` may already have queued part of its buffer while reporting
/// failure, so a retry would put duplicate bytes on the stream.
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Configures an accepted or connected socket: blocking with a `POLL` read
/// timeout and a `WRITE_TIMEOUT` write timeout, no Nagle delay, and TCP
/// keepalive so a vanished peer is noticed even on an idle control
/// connection.
pub(crate) fn prepare(stream: &TcpStream) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(POLL))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
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

/// Blocking reads and writes on a `prepare`d socket. A read retries across
/// the `POLL` timeouts, so no partial progress is lost, until it finishes,
/// `stop` returns true, the deadline passes, or no byte moves for `idle`.
/// The checks run only on timeouts, which keeps the hot path clean, and
/// they work on Windows, where `shutdown` from another thread does not wake
/// a blocked `recv`. A write blocks until the peer takes the bytes or
/// `WRITE_TIMEOUT` passes, which fails the connection; callers check `stop`
/// between writes.
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

    fn read_retrying(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let started = Instant::now();
        loop {
            match self.stream.read(buf) {
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
        self.read_retrying(buf)
    }
}

impl Write for Io<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            match self.stream.write(buf) {
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "peer stopped reading; giving up the connection",
                    ));
                }
                other => return other,
            }
        }
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

/// Closes a control connection after a goodbye without resetting it. Our
/// half is shut, then whatever the peer still sends (say, a `RoundEnd` in
/// flight) is read and dropped for up to a second. Closing a socket with
/// unread bytes sends a reset, and on Windows a reset makes the peer
/// discard our goodbye before it reads it.
pub(crate) fn linger(mut stream: TcpStream) {
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut scratch = [0u8; 4096];
    while Instant::now() < deadline {
        match stream.read(&mut scratch) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// A reader that pauses for longer than `POLL` makes the writer block.
    /// Every byte must still arrive exactly once and in order.
    #[test]
    fn writes_blocked_by_a_stalled_reader_arrive_exactly_once() {
        let total = 48usize << 20;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 1 << 20];
            let (mut pos, mut bad, mut reads) = (0usize, 0usize, 0u32);
            loop {
                let n = s.read(&mut buf).unwrap();
                if n == 0 {
                    return (pos, bad);
                }
                bad += buf[..n]
                    .iter()
                    .enumerate()
                    .filter(|&(i, &b)| b != ((pos + i) % 251) as u8)
                    .count();
                pos += n;
                reads += 1;
                if reads % 16 == 0 {
                    thread::sleep(Duration::from_millis(250));
                }
            }
        });
        let stream = TcpStream::connect(addr).unwrap();
        prepare(&stream).unwrap();
        let never = || false;
        let mut io = Io::new(stream, &never);
        let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        for part in data.chunks(256 << 10) {
            io.write_all(part).unwrap();
        }
        drop(io);
        assert_eq!(reader.join().unwrap(), (total, 0));
    }
}
