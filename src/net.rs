//! Socket plumbing shared by both roles: socket setup, interruptible
//! blocking I/O, connecting, and telling the peer why a session ends.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use socket2::{SockRef, TcpKeepalive};

use crate::progress::{Cancelled, Progress};
use crate::wire::{ControlTx, Msg};

/// How long a blocked read or write sleeps in `poll` before it checks
/// whether it should stop; nothing else depends on its value.
pub(crate) const POLL: Duration = Duration::from_millis(100);
/// A write that moves no byte for this long fails the connection, whatever
/// its idle limit.
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Configures an accepted or connected socket: non-blocking (see [`Io`]),
/// no Nagle delay, and TCP keepalive so a vanished peer is noticed even on
/// an idle control connection.
pub(crate) fn prepare(stream: &TcpStream) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    stream.set_nodelay(true)?;
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(5));
    SockRef::from(stream).set_tcp_keepalive(&keepalive)
}

/// Waits up to `timeout` for `stream` to become readable (or writable).
/// Errors and hang-ups count as ready; the next read or write reports them.
#[cfg(unix)]
fn wait_ready(stream: &TcpStream, write: bool, timeout: Duration) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut fd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: if write { libc::POLLOUT } else { libc::POLLIN },
        revents: 0,
    };
    match unsafe { libc::poll(&mut fd, 1, timeout.as_millis() as libc::c_int) } {
        -1 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

#[cfg(windows)]
fn wait_ready(stream: &TcpStream, write: bool, timeout: Duration) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        POLLRDNORM, POLLWRNORM, SOCKET, SOCKET_ERROR, WSAPOLLFD, WSAPoll,
    };
    let mut fd = WSAPOLLFD {
        fd: stream.as_raw_socket() as SOCKET,
        events: if write { POLLWRNORM } else { POLLRDNORM },
        revents: 0,
    };
    match unsafe { WSAPoll(&mut fd, 1, timeout.as_millis() as i32) } {
        SOCKET_ERROR => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
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

/// Blocking-style reads and writes on a `prepare`d, non-blocking socket.
/// Each call waits in `poll` for `POLL` at a time until it moves bytes,
/// `stop` returns true, the deadline passes, or no byte moves for `idle`
/// (`WRITE_TIMEOUT` at most for a write). A non-blocking send reports
/// exactly how much it queued, so nothing is lost or duplicated. Blocking
/// sockets would not do: on Windows `shutdown` from another thread wakes
/// neither a blocked `recv` nor a blocked `send`, and a send that hits
/// `SO_SNDTIMEO` may have queued part of its buffer while reporting failure.
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

    fn wait<T>(
        &mut self,
        write: bool,
        mut op: impl FnMut(&mut TcpStream) -> io::Result<T>,
    ) -> io::Result<T> {
        let started = Instant::now();
        let idle = match (self.idle, write) {
            (Some(limit), true) => Some(limit.min(WRITE_TIMEOUT)),
            (None, true) => Some(WRITE_TIMEOUT),
            (limit, false) => limit,
        };
        loop {
            match op(&mut self.stream) {
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
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
            if idle.is_some_and(|limit| now - started >= limit) {
                return Err(io::Error::new(ErrorKind::TimedOut, "peer went silent"));
            }
            wait_ready(&self.stream, write, POLL)?;
        }
    }
}

impl Read for Io<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.wait(false, |s| s.read(buf))
    }
}

impl Write for Io<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.wait(true, |s| s.write(buf))
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
/// flight, or a whole round that raced our goodbye) is read and dropped
/// for up to five seconds. Closing a socket with
/// unread bytes sends a reset, and on Windows a reset makes the peer
/// discard our goodbye before it reads it. Runs on its own thread, so the
/// caller returns at once.
pub(crate) fn linger(mut stream: TcpStream) {
    let _ = stream.shutdown(std::net::Shutdown::Write);
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut scratch = [0u8; 4096];
        while Instant::now() < deadline {
            match stream.read(&mut scratch) {
                Ok(0) => return,
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if wait_ready(&stream, false, POLL).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
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
