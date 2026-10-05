//! The tunnel client: holds the session, listens for `-L` forwards, asks
//! the server to listen for `-R` ones, and opens every stream's
//! connections.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::proto::{self, ADMITTED, CHALLENGE_LEN, CtrlRx, CtrlTx, PROLOGUE, TunnelMsg};
use super::pump::{BUFFER_BUDGET, Budget, ResetGuard, StreamCrypto, Traffic, pump, pump_tcp};
use super::spec::{ForwardSpec, HostPort};
use super::{
    CONNECT_TIMEOUT, GATHER_WAIT, HANDSHAKE_DEADLINE, MAX_CONNS, SERVER_STREAM, connect_any,
    connect_target, connections, human,
};
use crate::crypto::{Cipher, Initiator, NOISE_MSG_MAX, REJECTED, SessionKeys};
use crate::keys::{PrivateKey, PublicKey};
use crate::printable::escape;
use crate::wire::ConnKind;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// `HOST:PORT` of the tunnel server.
    pub addr: String,
    pub key: PrivateKey,
    /// The server's pinned public key.
    pub peer: PublicKey,
    pub cipher: Cipher,
    /// Connections per stream: 1 forwards like ssh, more stripe each stream.
    pub conns: u32,
    /// `-L`: listen here, connect from the server.
    pub local: Vec<ForwardSpec>,
    /// `-R`: listen on the server, connect from here.
    pub remote: Vec<ForwardSpec>,
    /// Log every stream, not only failures.
    pub verbose: bool,
}

/// How long a stream connection waits for the server to admit it: the
/// server first connects to the target and gathers the stream's other
/// connections.
const ADMIT_WAIT: std::time::Duration = CONNECT_TIMEOUT.saturating_add(GATHER_WAIT);
/// `-L` streams starting or running at once. A `-L` listener accepts only
/// while one of these is free, so a flood of connections waits in the
/// kernel's backlog instead of each getting tasks and sockets here.
const MAX_LOCAL_STREAMS: usize = 256;
/// Control messages queued for the server at once.
const CTRL_QUEUE: usize = 64;

/// An established session with its forwards set up. [`TunnelClient::run`]
/// serves them until the session ends.
pub struct TunnelClient {
    session: Session,
    local: LocalForwards,
    cfg: ClientConfig,
}

/// How long [`TunnelClient::run_reconnecting`] waits before each attempt.
#[derive(Clone, Copy, Debug)]
pub struct Backoff {
    /// The first wait. Each failed attempt doubles it.
    pub initial: Duration,
    /// The longest wait.
    pub max: Duration,
    /// A session that stays up this long starts the waits over.
    pub stable: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
            stable: Duration::from_secs(60),
        }
    }
}

/// The waits of one reconnecting client, in order.
struct Waits {
    backoff: Backoff,
    next: Duration,
}

impl Waits {
    fn new(backoff: Backoff) -> Self {
        Waits {
            backoff,
            next: backoff.initial,
        }
    }

    /// The wait after a session that was up for `lasted`.
    fn after_session(&mut self, lasted: Duration) -> Duration {
        if lasted >= self.backoff.stable {
            self.next = self.backoff.initial;
        }
        self.take()
    }

    /// The wait after a failed attempt.
    fn take(&mut self) -> Duration {
        let wait = self.next;
        self.next = wait.saturating_mul(2).min(self.backoff.max);
        wait
    }
}

/// One authenticated session, with every `-R` listener set up on the
/// server.
struct Session {
    shared: Arc<Shared>,
    rx: CtrlRx<BufReader<OwnedReadHalf>>,
    writer: tokio::task::JoinHandle<Result<()>>,
    /// `-R` targets by listener id.
    remote: HashMap<u32, HostPort>,
    remote_addrs: Vec<String>,
    /// Control messages that arrived during setup, handled first by `run`.
    early: Vec<TunnelMsg>,
}

/// An accepted `-L` connection, its target, and the stream permit it holds.
type Accepted = (TcpStream, SocketAddr, HostPort, OwnedSemaphorePermit);

/// The `-L` listeners, each accepting on a task of its own into one queue
/// that the session takes connections from.
struct LocalForwards {
    addrs: Vec<SocketAddr>,
    accepted: mpsc::Receiver<Accepted>,
    acceptors: JoinSet<()>,
}

struct Shared {
    addrs: Vec<SocketAddr>,
    keys: SessionKeys,
    route: [u8; 16],
    cipher: Cipher,
    conns: u32,
    verbose: bool,
    /// Out-of-order stream bytes held across every stream.
    budget: Budget,
    /// The last stream id used. Held while an `Open` is queued, so `Open`s
    /// go out in id order, which the server checks.
    next_stream: Mutex<u32>,
    /// Bounded: a stream waits for room rather than piling requests up.
    ctrl: mpsc::Sender<TunnelMsg>,
}

impl TunnelClient {
    /// Connects, authenticates, asks the server for every `-R` listener,
    /// and binds every `-L` listener. Fails if any forward cannot be set up.
    pub async fn connect(cfg: ClientConfig) -> Result<Self> {
        ensure!(
            (1..=MAX_CONNS).contains(&cfg.conns),
            "connections must be between 1 and {MAX_CONNS}"
        );
        cfg.cipher.ensure_supported()?;
        let session = Session::establish(&cfg).await?;
        let local = LocalForwards::bind(&cfg.local, cfg.verbose).await?;
        Ok(TunnelClient {
            session,
            local,
            cfg,
        })
    }

    /// Where each `-L` forward listens, in the order given.
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.local.addrs.clone()
    }

    /// Where the server listens for each `-R` forward, in the order given.
    pub fn remote_addrs(&self) -> &[String] {
        &self.session.remote_addrs
    }

    /// Serves the forwards until the session ends, which is always an
    /// error from this side's point of view.
    pub async fn run(self) -> Result<()> {
        self.run_with(std::future::pending()).await
    }

    /// Like [`TunnelClient::run`], but returns `Ok` once `stop` completes,
    /// after resetting the connections its streams carried.
    pub async fn run_until(self, stop: impl Future<Output = ()>) -> Result<()> {
        self.run_with(async {
            stop.await;
            Ok(())
        })
        .await
    }

    /// Like [`TunnelClient::run_until`], but when the session ends, waits
    /// as `backoff` says and sets up a new one, until `stop` completes.
    /// Every `-R` listener is asked for again on each new session. The `-L`
    /// listeners stay bound throughout, and reset what they accept while
    /// no session is up.
    pub async fn run_reconnecting(self, backoff: Backoff, stop: impl Future<Output = ()>) {
        let TunnelClient {
            mut session,
            mut local,
            cfg,
        } = self;
        tokio::pin!(stop);
        let mut waits = Waits::new(backoff);
        'serving: loop {
            let up = Instant::now();
            let ended = session
                .run_with(&mut local.accepted, async {
                    stop.as_mut().await;
                    Ok(())
                })
                .await;
            let Err(e) = ended else { break };
            let mut wait = waits.after_session(up.elapsed());
            eprintln!("mjolnir: session ended: {e:#}; reconnecting in {wait:?}");
            session = loop {
                let attempt = async {
                    tokio::time::sleep(wait).await;
                    Session::establish(&cfg).await
                };
                match local.refusing_while(attempt, stop.as_mut()).await {
                    None => break 'serving,
                    Some(Ok(session)) => break session,
                    Some(Err(e)) => {
                        wait = waits.take();
                        eprintln!("mjolnir: reconnecting failed: {e:#}; retrying in {wait:?}");
                    }
                }
            };
            eprintln!("mjolnir: tunnel up again");
        }
        local.acceptors.shutdown().await;
    }

    /// Carries one stream to `target` over stdin and stdout, as `ssh -W`
    /// does, and returns when it ends. Stdout is closed when the target's
    /// end arrives, so whatever reads it sees that end without waiting for
    /// stdin to finish too.
    pub async fn stdio(self, target: HostPort) -> Result<Traffic> {
        self.carry(target, tokio::io::stdin(), StdoutPipe::new())
            .await
    }

    /// Carries one stream to `target` between `input` and `output`, and
    /// returns when it ends: once both directions have ended and the server
    /// has written everything sent to its side.
    pub async fn carry<R, W>(self, target: HostPort, input: R, output: W) -> Result<Traffic>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let shared = self.session.shared.clone();
        let stream = async move {
            let (id, crypto, conns) = shared.open(&target).await?;
            pump(input, output, conns, crypto, shared.budget.clone())
                .await
                .with_context(|| format!("stream {id} to {target}"))
        };
        self.run_with(stream).await
    }

    /// Runs the session alongside `work`, returning when either ends.
    async fn run_with<T>(self, work: impl Future<Output = Result<T>>) -> Result<T> {
        let TunnelClient {
            session, mut local, ..
        } = self;
        let result = session.run_with(&mut local.accepted, work).await;
        local.acceptors.shutdown().await;
        result
    }
}

impl LocalForwards {
    async fn bind(specs: &[ForwardSpec], verbose: bool) -> Result<Self> {
        let permits = Arc::new(Semaphore::new(MAX_LOCAL_STREAMS));
        let (accepted_tx, accepted) = mpsc::channel(16);
        let mut addrs = Vec::new();
        let mut acceptors = JoinSet::new();
        for spec in specs {
            let listener = TcpListener::bind((spec.listen.host.as_str(), spec.listen.port))
                .await
                .with_context(|| format!("listening for -L {spec}"))?;
            let addr = listener.local_addr()?;
            if verbose {
                eprintln!("mjolnir: forwarding {addr} -> server -> {}", spec.target);
            }
            addrs.push(addr);
            acceptors.spawn(accept_local(
                listener,
                spec.target.clone(),
                permits.clone(),
                accepted_tx.clone(),
            ));
        }
        Ok(LocalForwards {
            addrs,
            accepted,
            acceptors,
        })
    }

    /// Runs `work`, resetting every connection accepted meanwhile, as a
    /// broken stream would. `None` if `stop` completes first.
    async fn refusing_while<T>(
        &mut self,
        work: impl Future<Output = T>,
        stop: impl Future<Output = ()>,
    ) -> Option<T> {
        tokio::pin!(work, stop);
        loop {
            tokio::select! {
                () = &mut stop => return None,
                done = &mut work => return Some(done),
                Some((socket, ..)) = self.accepted.recv() => drop(ResetGuard::new(&socket)),
            }
        }
    }
}

impl Session {
    /// Connects, authenticates, and asks the server for every `-R`
    /// listener. Fails if any of them cannot be set up.
    async fn establish(cfg: &ClientConfig) -> Result<Self> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&cfg.addr)
            .await
            .with_context(|| format!("resolving {}", cfg.addr))?
            .collect();
        ensure!(!addrs.is_empty(), "{} resolved to no addresses", cfg.addr);
        let mut stream = connect_any(&addrs).await?;
        let handshake = async {
            stream
                .write_all(&ConnKind::TunnelControl.preamble())
                .await?;
            let (hs, msg1) = Initiator::start(&cfg.key, &cfg.peer, PROLOGUE)?;
            proto::write_noise(&mut stream, &msg1).await?;
            let msg2 = proto::read_noise(&mut stream, NOISE_MSG_MAX)
                .await
                .map_err(|_| anyhow!(REJECTED.replace("receiver", "server")))?;
            hs.finish(&msg2)
        };
        let keys = timeout(HANDSHAKE_DEADLINE, handshake)
            .await
            .map_err(|_| anyhow!("the server did not answer the handshake"))??;
        let (r, w) = stream.into_split();
        let (mut tx, mut rx) = proto::control(BufReader::new(r), w, &keys, true);
        tx.send(&TunnelMsg::Hello { cipher: cfg.cipher }).await?;
        match timeout(HANDSHAKE_DEADLINE, rx.recv()).await {
            Ok(Ok(Some(TunnelMsg::Welcome { max_conns }))) => ensure!(
                cfg.conns <= max_conns,
                "the server allows at most {max_conns} connections per stream"
            ),
            Ok(Ok(Some(TunnelMsg::Error { message }))) => bail!("the server said: {message}"),
            Ok(Ok(other)) => bail!("expected Welcome, got {other:?}"),
            Ok(Err(e)) => return Err(e),
            Err(_) => bail!("the server did not welcome the session"),
        }

        let mut remote = HashMap::new();
        let mut remote_addrs = Vec::new();
        let mut early = Vec::new();
        for (id, spec) in cfg.remote.iter().enumerate() {
            let id = id as u32;
            tx.send(&TunnelMsg::Listen {
                id,
                host: spec.listen.host.clone(),
                port: spec.listen.port,
                conns: cfg.conns,
            })
            .await?;
            // A listener set up earlier may already have a connection.
            let reply = loop {
                let msg = timeout(HANDSHAKE_DEADLINE, rx.recv())
                    .await
                    .map_err(|_| anyhow!("the server did not answer -R {spec}"))??;
                match msg {
                    Some(msg @ TunnelMsg::Incoming { .. }) => early.push(msg),
                    other => break other,
                }
            };
            match reply {
                Some(TunnelMsg::Listening { id: got, addr }) if got == id => {
                    if cfg.verbose {
                        eprintln!("mjolnir: forwarding server {addr} -> {}", spec.target);
                    }
                    remote_addrs.push(addr);
                }
                Some(TunnelMsg::ListenFailed { id: got, message }) if got == id => {
                    bail!("the server cannot listen for -R {spec}: {message}")
                }
                Some(TunnelMsg::Error { message }) => bail!("the server said: {message}"),
                other => bail!("expected Listening, got {other:?}"),
            }
            remote.insert(id, spec.target.clone());
        }

        let (ctrl, ctrl_rx) = mpsc::channel(CTRL_QUEUE);
        let writer = tokio::spawn(write_control(tx, ctrl_rx));
        Ok(Session {
            shared: Arc::new(Shared {
                addrs,
                route: proto::route(&keys),
                keys,
                cipher: cfg.cipher,
                conns: cfg.conns,
                verbose: cfg.verbose,
                budget: Budget::new(BUFFER_BUDGET),
                next_stream: Mutex::new(0),
                ctrl,
            }),
            rx,
            writer,
            remote,
            remote_addrs,
            early,
        })
    }

    /// Runs the session alongside `work`, carrying the `-L` connections
    /// taken from `accepted`, and returns when either ends.
    async fn run_with<T>(
        self,
        accepted: &mut mpsc::Receiver<Accepted>,
        work: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let Session {
            shared,
            mut rx,
            mut writer,
            remote,
            early,
            ..
        } = self;
        // Every stream task lives here, so ending the session can cancel
        // them all, and their guards reset the applications' connections,
        // before the process exits.
        let mut tasks = JoinSet::new();
        let mut last_incoming = None;
        // Reading is not cancellation safe, so it has a task of its own.
        let (in_tx, mut in_rx) = mpsc::channel(16 + early.len());
        for msg in early {
            let _ = in_tx.try_send(Ok(Some(msg)));
        }
        let reader = tokio::spawn(async move {
            loop {
                let msg = rx.recv().await;
                let last = !matches!(msg, Ok(Some(_)));
                if in_tx.send(msg).await.is_err() || last {
                    return;
                }
            }
        });
        tokio::pin!(work);
        let result = loop {
            tokio::select! {
                done = &mut work => break done,
                msg = in_rx.recv() => {
                    let msg = match msg {
                        Some(Ok(Some(msg))) => msg,
                        Some(Ok(None)) => break Err(anyhow!("the server closed the session")),
                        Some(Err(e)) => break Err(e),
                        None => break Err(anyhow!("control reader stopped")),
                    };
                    match msg {
                        TunnelMsg::Incoming { listener, stream, from } => {
                            let Some(target) = remote.get(&listener).cloned() else {
                                break Err(anyhow!("protocol error: unknown listener {listener}"));
                            };
                            if let Err(e) = check_incoming(&mut last_incoming, stream) {
                                break Err(e);
                            }
                            tasks.spawn(serve_incoming(shared.clone(), stream, from, target));
                        }
                        TunnelMsg::Close { stream, message } => {
                            eprintln!("mjolnir: stream {stream}: the server said: {}", escape(&message));
                        }
                        TunnelMsg::Error { message } => {
                            break Err(anyhow!("the server reported an error: {}", escape(&message)));
                        }
                        other => break Err(anyhow!("protocol error: unexpected {other:?}")),
                    }
                }
                done = &mut writer => {
                    break Err(match done {
                        Ok(Ok(())) => anyhow!("control writer stopped"),
                        Ok(Err(e)) => e.context("writing the control connection"),
                        Err(e) => anyhow!("control writer failed: {e}"),
                    });
                }
                Some((socket, from, target, permit)) = accepted.recv() => {
                    tasks.spawn(serve_local(shared.clone(), socket, from, target, permit));
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        };
        reader.abort();
        writer.abort();
        tasks.shutdown().await;
        result
    }
}

async fn write_control(
    mut tx: CtrlTx<OwnedWriteHalf>,
    mut rx: mpsc::Receiver<TunnelMsg>,
) -> Result<()> {
    while let Some(msg) = rx.recv().await {
        tx.send(&msg).await?;
    }
    Ok(())
}

/// Server stream ids have the top bit set and only grow, so one that does
/// not is a server reusing an id, whose keys and nonces were used before.
fn check_incoming(last: &mut Option<u32>, stream: u32) -> Result<()> {
    ensure!(
        stream & SERVER_STREAM != 0 && last.is_none_or(|last| stream > last),
        "protocol error: the server reused stream id {stream}"
    );
    *last = Some(stream);
    Ok(())
}

/// Stdout as a stream's output: its shutdown closes the underlying file
/// descriptor or handle, since tokio's own only flushes. Whatever reads
/// the other end of the pipe then sees the end of the stream at once.
struct StdoutPipe(tokio::io::Stdout);

impl StdoutPipe {
    fn new() -> Self {
        StdoutPipe(tokio::io::stdout())
    }
}

impl AsyncWrite for StdoutPipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        // The flush behind tokio's shutdown waits for its blocking write
        // to finish, so nothing is in flight when the descriptor closes.
        std::task::ready!(Pin::new(&mut self.0).poll_shutdown(cx))?;
        close_stdout();
        Poll::Ready(Ok(()))
    }
}

/// Closes this process's stdout. Later writes to it by the standard
/// library are ignored rather than failing.
#[cfg(unix)]
fn close_stdout() {
    use std::os::fd::AsRawFd;
    unsafe { libc::close(std::io::stdout().as_raw_fd()) };
}

#[cfg(windows)]
fn close_stdout() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::CloseHandle;
    unsafe { CloseHandle(std::io::stdout().as_raw_handle()) };
}

impl Shared {
    /// Opens a `-L` stream to `target`: queues its `Open`, then opens its
    /// connections and waits for the server to admit them.
    async fn open(
        self: &Arc<Self>,
        target: &HostPort,
    ) -> Result<(u32, StreamCrypto, Vec<TcpStream>)> {
        let id = {
            let mut next = self.next_stream.lock().await;
            ensure!(*next < SERVER_STREAM - 1, "stream ids exhausted");
            *next += 1;
            self.ctrl
                .send(TunnelMsg::Open {
                    stream: *next,
                    host: target.host.clone(),
                    port: target.port,
                    conns: self.conns,
                })
                .await
                .map_err(|_| anyhow!("the session has ended"))?;
            *next
        };
        let conns = self.open_conns(id).await?;
        Ok((id, self.crypto(id), conns))
    }

    fn crypto(&self, stream: u32) -> StreamCrypto {
        StreamCrypto::new(&self.keys, self.cipher, stream, self.conns, true)
    }

    /// Opens all of a stream's connections at once. Fails if any fails.
    async fn open_conns(self: &Arc<Self>, stream: u32) -> Result<Vec<TcpStream>> {
        let mut set = JoinSet::new();
        for conn in 0..self.conns {
            let shared = self.clone();
            set.spawn(async move {
                let s = open_conn(&shared.addrs, &shared.keys, &shared.route, stream, conn).await;
                (conn, s)
            });
        }
        let mut conns: Vec<Option<TcpStream>> = (0..self.conns).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            let (i, s) = joined.map_err(|e| anyhow!("connection task failed: {e}"))?;
            conns[i as usize] = Some(s?);
        }
        Ok(conns.into_iter().map(Option::unwrap).collect())
    }

    async fn fail(&self, stream: u32, what: &str, e: &anyhow::Error) {
        eprintln!("mjolnir: stream {stream} ({what}) failed: {e:#}");
        let _ = self
            .ctrl
            .send(TunnelMsg::Close {
                stream,
                message: format!("{e:#}"),
            })
            .await;
    }

    fn report(&self, stream: u32, what: &str, result: Result<Traffic>) {
        match result {
            Ok(t) if self.verbose => eprintln!(
                "mjolnir: stream {stream} ({what}) closed, {} sent, {} received",
                human(t.sent),
                human(t.received)
            ),
            Ok(_) => {}
            Err(e) => eprintln!("mjolnir: stream {stream} ({what}) aborted: {e:#}"),
        }
    }
}

/// Connects one stream connection and waits for the server to admit it.
async fn open_conn(
    addrs: &[SocketAddr],
    keys: &SessionKeys,
    route: &[u8; 16],
    stream: u32,
    conn: u32,
) -> Result<TcpStream> {
    let mut s = connect_any(addrs).await?;
    let hello = async {
        s.write_all(&ConnKind::TunnelData.preamble()).await?;
        let mut challenge = [0u8; CHALLENGE_LEN];
        s.read_exact(&mut challenge).await?;
        s.write_all(&proto::encode_hello(keys, route, &challenge, stream, conn))
            .await?;
        anyhow::Ok(())
    };
    timeout(HANDSHAKE_DEADLINE, hello)
        .await
        .map_err(|_| anyhow!("the server did not answer a stream connection"))??;
    let verdict = timeout(ADMIT_WAIT, s.read_u8())
        .await
        .map_err(|_| anyhow!("the server did not admit the stream in time"))?;
    match verdict {
        Ok(ADMITTED) => Ok(s),
        _ => bail!("the server refused the stream"),
    }
}

/// Accepts `-L` connections, each with a stream permit taken first, and
/// hands them to the session loop, which owns every stream task.
async fn accept_local(
    listener: TcpListener,
    target: HostPort,
    permits: Arc<Semaphore>,
    accepted: mpsc::Sender<Accepted>,
) {
    loop {
        let Ok(permit) = permits.clone().acquire_owned().await else {
            return;
        };
        match listener.accept().await {
            Ok((socket, from)) => {
                if accepted
                    .send((socket, from, target.clone(), permit))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(e) => {
                eprintln!("mjolnir: accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

/// Carries an accepted `-L` connection to `target` from the server,
/// holding its stream permit throughout.
async fn serve_local(
    shared: Arc<Shared>,
    socket: TcpStream,
    from: SocketAddr,
    target: HostPort,
    _permit: OwnedSemaphorePermit,
) {
    // Resets the application's connection if setup fails or is cancelled.
    let guard = ResetGuard::new(&socket);
    let what = format!("{from} -> {target}");
    match shared.open(&target).await {
        Ok((id, crypto, conns)) => {
            if shared.verbose {
                eprintln!(
                    "mjolnir: stream {id} ({what}) open, {}",
                    connections(shared.conns)
                );
            }
            let result = pump_tcp(socket, guard, conns, crypto, shared.budget.clone()).await;
            shared.report(id, &what, result);
        }
        Err(e) => eprintln!("mjolnir: stream ({what}) failed: {e:#}"),
    }
}

/// Carries a stream the server accepted on a `-R` listener to `target`.
async fn serve_incoming(shared: Arc<Shared>, stream: u32, from: String, target: HostPort) {
    let what = format!("{} -> {target}", escape(&from));
    let (local, conns) = tokio::join!(connect_target(&target), shared.open_conns(stream));
    // The target is reset, never left with a clean empty end, if the
    // stream's connections failed.
    let setup = local.and_then(|local| {
        let guard = ResetGuard::new(&local);
        conns.map(|conns| (local, guard, conns))
    });
    match setup {
        Ok((local, guard, conns)) => {
            if shared.verbose {
                eprintln!(
                    "mjolnir: stream {stream} ({what}) open, {}",
                    connections(shared.conns)
                );
            }
            let result = pump_tcp(
                local,
                guard,
                conns,
                shared.crypto(stream),
                shared.budget.clone(),
            )
            .await;
            shared.report(stream, &what, result);
        }
        Err(e) => shared.fail(stream, &what, &e).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_double_up_to_the_max_and_start_over_after_a_stable_session() {
        let s = Duration::from_secs;
        let mut waits = Waits::new(Backoff::default());
        assert_eq!(waits.after_session(s(5)), s(1));
        let failed: Vec<_> = (0..7).map(|_| waits.take()).collect();
        assert_eq!(failed, [2, 4, 8, 16, 32, 60, 60].map(s));
        assert_eq!(waits.after_session(s(59)), s(60), "a short session");
        assert_eq!(waits.after_session(s(60)), s(1), "a stable session");
        assert_eq!(waits.take(), s(2));
    }

    #[test]
    fn server_stream_ids_must_have_the_top_bit_and_grow() {
        let mut last = None;
        assert!(check_incoming(&mut last, 1).is_err(), "a client-side id");
        assert!(check_incoming(&mut last, SERVER_STREAM).is_ok());
        assert!(check_incoming(&mut last, SERVER_STREAM | 5).is_ok());
        assert!(
            check_incoming(&mut last, SERVER_STREAM | 5).is_err(),
            "reused"
        );
        assert!(
            check_incoming(&mut last, SERVER_STREAM | 2).is_err(),
            "gone back"
        );
        assert!(check_incoming(&mut last, SERVER_STREAM | 6).is_ok());
    }

    /// The listener accepts only while a permit is free, so connections
    /// beyond the limit wait in the backlog without a task or a socket
    /// on this side.
    #[tokio::test]
    async fn local_streams_are_accepted_only_with_a_permit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let permits = Arc::new(Semaphore::new(2));
        let (tx, mut rx) = mpsc::channel(16);
        let target = HostPort {
            host: "x".into(),
            port: 1,
        };
        tokio::spawn(accept_local(listener, target, permits, tx));
        let _apps: Vec<_> = futures_connect(addr, 3).await;
        let first = timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let second = timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            timeout(Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "a third stream was accepted without a permit"
        );
        drop(first.3);
        drop(second.3);
        let third = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a freed permit lets the next one in")
            .unwrap();
        drop(third);
    }

    async fn futures_connect(addr: SocketAddr, n: usize) -> Vec<TcpStream> {
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(TcpStream::connect(addr).await.unwrap());
        }
        out
    }
}
