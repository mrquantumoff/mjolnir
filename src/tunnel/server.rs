//! The tunnel server: authenticates clients, connects `-L` streams to their
//! targets when the client's key permits it, listens for `-R` forwards, and
//! gathers each stream's connections.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};

use super::proto::{self, ADMITTED, CHALLENGE_LEN, CtrlRx, CtrlTx, HELLO_LEN, PROLOGUE, TunnelMsg};
use super::pump::{StreamCrypto, pump_tcp};
use super::spec::{HostPort, Permits, Policy};
use super::{
    GATHER_WAIT, HANDSHAKE_DEADLINE, HELLO_DEADLINE, MAX_CONNS, SERVER_STREAM, connect_target,
    connections, human, prepare,
};
use crate::crypto::{self, Cipher, NOISE_MSG1_MAX, SessionKeys};
use crate::keys::{PrivateKey, PublicKey};
use crate::wire::ConnKind;

pub struct ServerConfig {
    pub listen: SocketAddr,
    pub key: PrivateKey,
    /// Authorized client keys and what each may do.
    pub policy: Policy,
    /// Log every stream, not only sessions and failures.
    pub verbose: bool,
}

/// Connections not yet authenticated at once; more are closed at accept.
const MAX_PENDING: usize = 256;
/// Streams one session may have at once, counting ones still starting.
const MAX_STREAMS: usize = 256;
/// `-R` listeners one session may hold.
const MAX_LISTENERS: usize = 64;

/// A bound tunnel server. [`TunnelServer::run`] serves until dropped.
pub struct TunnelServer {
    listener: TcpListener,
    shared: Arc<Shared>,
}

struct Shared {
    key: PrivateKey,
    policy: Policy,
    verbose: bool,
    /// Live sessions by route, for stream connections to find theirs.
    sessions: Mutex<HashMap<[u8; 16], Arc<Session>>>,
    pending: Arc<Semaphore>,
    /// Becomes true when the server stops.
    stop: watch::Sender<bool>,
}

impl TunnelServer {
    pub async fn bind(cfg: ServerConfig) -> Result<Self> {
        ensure!(
            !cfg.policy.keys().is_empty(),
            "no authorized client keys: pass --authorized FILE or --allow KEY"
        );
        let listener = TcpListener::bind(cfg.listen)
            .await
            .with_context(|| format!("listening on {}", cfg.listen))?;
        Ok(TunnelServer {
            listener,
            shared: Arc::new(Shared {
                key: cfg.key,
                policy: cfg.policy,
                verbose: cfg.verbose,
                sessions: Mutex::new(HashMap::new()),
                pending: Arc::new(Semaphore::new(MAX_PENDING)),
                stop: watch::Sender::new(false),
            }),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("bound listener has an address")
    }

    pub fn public_key(&self) -> PublicKey {
        self.shared.key.public_key()
    }

    /// Accepts connections until dropped. Each runs on its own task, so a
    /// slow or hostile peer holds up nobody else, and a failure is logged
    /// and dropped. Dropping the future ends every session.
    pub async fn run(self) -> Result<()> {
        self.run_until(std::future::pending()).await
    }

    /// Like [`TunnelServer::run`], until `stop` completes. Then every session
    /// ends and resets the connections its streams carried, and this waits
    /// (up to 5 seconds) for that to finish.
    pub async fn run_until(self, stop: impl Future<Output = ()>) -> Result<()> {
        let _stop = StopOnDrop(self.shared.stop.clone());
        // Every connection task holds a clone; `recv` ends when all are gone.
        let (alive, mut all_gone) = mpsc::channel::<()>(1);
        tokio::pin!(stop);
        loop {
            let (stream, from) = tokio::select! {
                () = &mut stop => break,
                accepted = self.listener.accept() => match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        eprintln!("mjolnir: accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
            };
            // Over the limit, the socket is closed right here.
            let Ok(permit) = self.shared.pending.clone().try_acquire_owned() else {
                continue;
            };
            let (shared, alive) = (self.shared.clone(), alive.clone());
            tokio::spawn(async move {
                if let Err(e) = serve(&shared, stream, from, permit).await {
                    eprintln!("mjolnir: tunnel connection from {from}: {e:#}");
                }
                drop(alive);
            });
        }
        self.shared.stop.send_replace(true);
        drop(alive);
        let _ = timeout(Duration::from_secs(5), all_gone.recv()).await;
        Ok(())
    }
}

/// Tells every session to end when dropped.
struct StopOnDrop(watch::Sender<bool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

async fn serve(
    shared: &Arc<Shared>,
    mut stream: TcpStream,
    from: SocketAddr,
    permit: OwnedSemaphorePermit,
) -> Result<()> {
    prepare(&stream);
    let mut preamble = [0u8; 6];
    timeout(HANDSHAKE_DEADLINE, stream.read_exact(&mut preamble))
        .await
        .map_err(|_| anyhow!("no preamble within {HANDSHAKE_DEADLINE:?}"))??;
    match ConnKind::from_preamble(&preamble)? {
        ConnKind::TunnelControl => control(shared, stream, from, permit).await,
        ConnKind::TunnelData => stream_conn(shared, stream, permit).await,
        ConnKind::Control | ConnKind::Data => {
            bail!("a file sender connected, but this port runs `mjolnir tunnel-server`")
        }
    }
}

/// Runs the handshake, waits for the client's `Hello`, and serves the
/// session until its control connection ends.
async fn control(
    shared: &Arc<Shared>,
    mut stream: TcpStream,
    from: SocketAddr,
    permit: OwnedSemaphorePermit,
) -> Result<()> {
    let handshake = async {
        let msg1 = proto::read_noise(&mut stream, NOISE_MSG1_MAX)
            .await
            .context("reading Noise message 1")?;
        let (msg2, keys, peer) =
            crypto::respond(&msg1, &shared.key, shared.policy.keys(), PROLOGUE)?;
        proto::write_noise(&mut stream, &msg2).await?;
        anyhow::Ok((keys, peer))
    };
    let (keys, peer) = timeout(HANDSHAKE_DEADLINE, handshake)
        .await
        .map_err(|_| anyhow!("handshake did not finish within {HANDSHAKE_DEADLINE:?}"))??;
    let (r, w) = stream.into_split();
    let (mut tx, mut rx) = proto::control(BufReader::new(r), w, &keys, false);
    // Message 1 can be replayed; only the live client can seal `Hello`.
    let cipher = match timeout(HELLO_DEADLINE, rx.recv()).await {
        Ok(Ok(Some(TunnelMsg::Hello { cipher }))) => cipher,
        Ok(Ok(None)) => bail!("closed before Hello"),
        Ok(Ok(other)) => bail!("expected Hello, got {other:?}"),
        Ok(Err(e)) => return Err(e.context("waiting for Hello")),
        Err(_) => bail!("no Hello within {HELLO_DEADLINE:?}"),
    };
    tx.send(&TunnelMsg::Welcome {
        max_conns: MAX_CONNS,
    })
    .await?;
    drop(permit);

    let (ctrl, ctrl_rx) = mpsc::unbounded_channel();
    let route = proto::route(&keys);
    let session = Arc::new(Session {
        keys,
        cipher,
        peer,
        permits: shared.policy.for_key(&peer).clone(),
        verbose: shared.verbose,
        ctrl,
        slots: Mutex::new(Slots::default()),
        registered: Notify::new(),
        streams: AtomicUsize::new(0),
        next_server_stream: AtomicU32::new(0),
    });
    shared
        .sessions
        .lock()
        .unwrap()
        .insert(route, session.clone());
    eprintln!("mjolnir: tunnel session from {from} (key {peer})");
    let result = session.run(tx, rx, ctrl_rx, shared.stop.subscribe()).await;
    shared.sessions.lock().unwrap().remove(&route);
    match result {
        Ok(()) => eprintln!("mjolnir: tunnel session from {from} closed"),
        Err(e) => eprintln!("mjolnir: tunnel session from {from} ended: {e:#}"),
    }
    Ok(())
}

/// A stream connection: answer the challenge, find the session by route,
/// check the MAC, and hand the socket to its stream.
async fn stream_conn(
    shared: &Arc<Shared>,
    mut stream: TcpStream,
    permit: OwnedSemaphorePermit,
) -> Result<()> {
    let mut challenge = [0u8; CHALLENGE_LEN];
    getrandom::fill(&mut challenge).map_err(|e| anyhow!("OS random number generator: {e}"))?;
    let mut hello = [0u8; HELLO_LEN];
    let exchange = async {
        stream.write_all(&challenge).await?;
        stream.read_exact(&mut hello).await?;
        anyhow::Ok(())
    };
    timeout(HANDSHAKE_DEADLINE, exchange)
        .await
        .map_err(|_| anyhow!("no stream hello within {HANDSHAKE_DEADLINE:?}"))??;
    let (route, id, conn, mac) = proto::decode_hello(&hello);
    let session = shared
        .sessions
        .lock()
        .unwrap()
        .get(&route)
        .cloned()
        .context("stream connection for an unknown session")?;
    ensure!(
        proto::check_hello(&session.keys, &challenge, id, conn, &mac),
        "stream connection hello failed to authenticate"
    );
    session.attach(id, conn, stream).await?;
    drop(permit);
    Ok(())
}

struct Session {
    keys: SessionKeys,
    cipher: Cipher,
    peer: PublicKey,
    permits: Permits,
    verbose: bool,
    /// Messages for the control writer task.
    ctrl: mpsc::UnboundedSender<TunnelMsg>,
    slots: Mutex<Slots>,
    /// Signalled whenever a stream registers.
    registered: Notify,
    /// Streams starting or running.
    streams: AtomicUsize,
    next_server_stream: AtomicU32,
}

/// Streams waiting for their connections.
#[derive(Default)]
struct Slots {
    map: HashMap<u32, Slot>,
    /// The highest client stream id opened so far; client ids only grow.
    highest_client: u32,
}

struct Slot {
    conns: Vec<Option<TcpStream>>,
    have: usize,
    ready: oneshot::Sender<Vec<TcpStream>>,
}

/// Counts a stream as running until dropped.
struct StreamGuard(Arc<Session>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.streams.fetch_sub(1, Relaxed);
    }
}

impl Session {
    async fn run(
        self: &Arc<Self>,
        mut tx: CtrlTx<OwnedWriteHalf>,
        mut rx: CtrlRx<BufReader<OwnedReadHalf>>,
        mut ctrl_rx: mpsc::UnboundedReceiver<TunnelMsg>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut tasks = JoinSet::new();
        // The writer stops after sending an `Error`, so the session can
        // wait for it to go out.
        let mut writer = tokio::spawn(async move {
            while let Some(msg) = ctrl_rx.recv().await {
                let last = matches!(msg, TunnelMsg::Error { .. });
                tx.send(&msg).await?;
                if last {
                    break;
                }
            }
            anyhow::Ok(())
        });
        // Reading is not cancellation safe, so it has a task of its own.
        let (in_tx, mut in_rx) = mpsc::channel(16);
        let reader = tokio::spawn(async move {
            loop {
                let msg = rx.recv().await;
                let last = !matches!(msg, Ok(Some(_)));
                if in_tx.send(msg).await.is_err() || last {
                    return;
                }
            }
        });
        let mut listeners = HashSet::new();
        let result = loop {
            tokio::select! {
                // The guard `wait_for` returns is not `Send`; drop it here.
                () = async { drop(stop.wait_for(|&stopped| stopped).await) } => {
                    break Err(anyhow!("the server is stopping"));
                }
                msg = in_rx.recv() => {
                    let msg = match msg {
                        Some(Ok(Some(msg))) => msg,
                        Some(Ok(None)) => break Ok(()),
                        Some(Err(e)) => break Err(e),
                        None => break Err(anyhow!("control reader stopped")),
                    };
                    if let Err(e) = self.handle(msg, &mut tasks, &mut listeners).await {
                        let _ = self.ctrl.send(TunnelMsg::Error { message: format!("{e:#}") });
                        let _ = timeout(Duration::from_secs(1), &mut writer).await;
                        break Err(e);
                    }
                }
                done = &mut writer => {
                    break match done {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(e)) => Err(e.context("writing the control connection")),
                        Err(e) => Err(anyhow!("control writer failed: {e}")),
                    };
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        };
        reader.abort();
        writer.abort();
        tasks.shutdown().await;
        result
    }

    /// Handles one control message.
    async fn handle(
        self: &Arc<Self>,
        msg: TunnelMsg,
        tasks: &mut JoinSet<()>,
        listeners: &mut HashSet<u32>,
    ) -> Result<()> {
        match msg {
            TunnelMsg::Open {
                stream,
                host,
                port,
                conns,
            } => {
                let target = HostPort { host, port };
                let allowed = self.may_start(conns).and_then(|()| {
                    if self.permits.may_open(&target) {
                        Ok(())
                    } else {
                        Err(format!("{target} is not permitted for this key"))
                    }
                });
                // Raising the watermark and making the slot happen under one
                // lock, or a connection could see the one without the other.
                let registered = {
                    let mut slots = self.slots.lock().unwrap();
                    ensure!(
                        stream & SERVER_STREAM == 0 && stream > slots.highest_client,
                        "protocol error: stream {stream} is out of order"
                    );
                    slots.highest_client = stream;
                    allowed.map(|()| self.register(&mut slots, stream, conns))
                };
                let (guard, ready) = match registered {
                    Ok(registered) => registered,
                    Err(why) => {
                        eprintln!("mjolnir: stream {stream} from {}: {why}", self.peer);
                        self.close(stream, why);
                        return Ok(());
                    }
                };
                self.registered.notify_waiters();
                let session = self.clone();
                tasks.spawn(async move {
                    session
                        .open_stream(guard, stream, target, conns, ready)
                        .await
                });
            }
            TunnelMsg::Listen {
                id,
                host,
                port,
                conns,
            } => {
                let bind = HostPort { host, port };
                let checked = if listeners.contains(&id) {
                    Err(format!("listener {id} already exists"))
                } else if listeners.len() >= MAX_LISTENERS {
                    Err(format!("at most {MAX_LISTENERS} listeners per session"))
                } else if conns == 0 || conns > MAX_CONNS {
                    Err(format!(
                        "asks for {conns} connections; the server allows 1 to {MAX_CONNS}"
                    ))
                } else if !self.permits.may_listen(&bind) {
                    Err(format!("listening on {bind} is not permitted for this key"))
                } else {
                    TcpListener::bind((bind.host.as_str(), bind.port))
                        .await
                        .map_err(|e| format!("listening on {bind}: {e}"))
                };
                match checked {
                    Ok(listener) => {
                        let addr = listener.local_addr()?;
                        eprintln!("mjolnir: {} listens on {addr}", self.peer);
                        listeners.insert(id);
                        let _ = self.ctrl.send(TunnelMsg::Listening {
                            id,
                            addr: addr.to_string(),
                        });
                        let session = self.clone();
                        tasks.spawn(async move { session.listen(id, listener, conns).await });
                    }
                    Err(message) => {
                        eprintln!("mjolnir: listener from {}: {message}", self.peer);
                        let _ = self.ctrl.send(TunnelMsg::ListenFailed { id, message });
                    }
                }
            }
            TunnelMsg::Close { stream, message } => {
                if self.verbose {
                    eprintln!("mjolnir: stream {stream}: the client gave up: {message}");
                }
                // Dropping the slot tells the stream's task to stop.
                self.slots.lock().unwrap().map.remove(&stream);
            }
            TunnelMsg::Error { message } => bail!("the client reported an error: {message}"),
            other => bail!("protocol error: unexpected {other:?}"),
        }
        Ok(())
    }

    fn may_start(&self, conns: u32) -> Result<(), String> {
        if conns == 0 || conns > MAX_CONNS {
            return Err(format!(
                "asks for {conns} connections; the server allows 1 to {MAX_CONNS}"
            ));
        }
        if self.streams.load(Relaxed) >= MAX_STREAMS {
            return Err(format!("at most {MAX_STREAMS} streams per session"));
        }
        Ok(())
    }

    fn close(&self, stream: u32, message: String) {
        let _ = self.ctrl.send(TunnelMsg::Close { stream, message });
    }

    /// Makes a slot for `stream`'s connections. The caller then wakes any
    /// connections that arrived before the slot, with `registered`.
    fn register(
        self: &Arc<Self>,
        slots: &mut Slots,
        stream: u32,
        conns: u32,
    ) -> (StreamGuard, oneshot::Receiver<Vec<TcpStream>>) {
        self.streams.fetch_add(1, Relaxed);
        let (ready, rx) = oneshot::channel();
        slots.map.insert(
            stream,
            Slot {
                conns: (0..conns).map(|_| None).collect(),
                have: 0,
                ready,
            },
        );
        (StreamGuard(self.clone()), rx)
    }

    /// Adds a connection to its stream's slot; the last one completes the
    /// slot. A connection may beat its stream's `Open` here, so an unknown
    /// client stream id above the highest seen waits for it.
    async fn attach(&self, stream: u32, conn: u32, socket: TcpStream) -> Result<()> {
        let deadline = Instant::now() + GATHER_WAIT;
        let mut socket = Some(socket);
        loop {
            let registered = self.registered.notified();
            tokio::pin!(registered);
            registered.as_mut().enable();
            {
                let mut slots = self.slots.lock().unwrap();
                if let Some(slot) = slots.map.get_mut(&stream) {
                    let i = conn as usize;
                    ensure!(
                        i < slot.conns.len() && slot.conns[i].is_none(),
                        "stream {stream} got an unexpected connection {conn}"
                    );
                    slot.conns[i] = socket.take();
                    slot.have += 1;
                    if slot.have == slot.conns.len() {
                        let slot = slots.map.remove(&stream).unwrap();
                        let conns = slot.conns.into_iter().map(Option::unwrap).collect();
                        // A stream that gave up drops the connections.
                        let _ = slot.ready.send(conns);
                    }
                    return Ok(());
                }
                ensure!(
                    stream & SERVER_STREAM == 0 && stream > slots.highest_client,
                    "stream {stream} is closed or unknown"
                );
            }
            timeout_at(deadline, registered)
                .await
                .map_err(|_| anyhow!("stream {stream} was never opened"))?;
        }
    }

    /// Waits for a stream's connections, admits them, and pumps.
    async fn start(
        &self,
        stream: u32,
        local: TcpStream,
        ready: oneshot::Receiver<Vec<TcpStream>>,
        conns: u32,
        what: &str,
    ) {
        let mut sockets = match timeout(GATHER_WAIT, ready).await {
            Ok(Ok(sockets)) => sockets,
            // The client sent `Close`, or the session ended.
            Ok(Err(_)) => return,
            Err(_) => {
                self.slots.lock().unwrap().map.remove(&stream);
                let why = format!("its {} did not arrive", connections(conns));
                eprintln!("mjolnir: stream {stream} ({what}): {why}");
                self.close(stream, why);
                return;
            }
        };
        for s in &mut sockets {
            if let Err(e) = s.write_u8(ADMITTED).await {
                eprintln!("mjolnir: stream {stream} ({what}): {e}");
                return;
            }
        }
        if self.verbose {
            eprintln!(
                "mjolnir: stream {stream} ({what}) open, {}",
                connections(conns)
            );
        }
        let crypto = StreamCrypto::new(&self.keys, self.cipher, stream, conns, false);
        match pump_tcp(local, sockets, crypto).await {
            Ok(t) if self.verbose => eprintln!(
                "mjolnir: stream {stream} ({what}) closed, {} to the client, {} from it",
                human(t.sent),
                human(t.received)
            ),
            Ok(_) => {}
            Err(e) => eprintln!("mjolnir: stream {stream} ({what}) aborted: {e:#}"),
        }
    }

    /// A `-L` stream: connect to the target while the connections arrive.
    async fn open_stream(
        self: Arc<Self>,
        _guard: StreamGuard,
        stream: u32,
        target: HostPort,
        conns: u32,
        ready: oneshot::Receiver<Vec<TcpStream>>,
    ) {
        let what = format!("{} -> {target}", self.peer);
        let local = match connect_target(&target).await {
            Ok(s) => s,
            Err(e) => {
                self.slots.lock().unwrap().map.remove(&stream);
                let why = format!("{e:#}");
                eprintln!("mjolnir: stream {stream} ({what}): {why}");
                self.close(stream, why);
                return;
            }
        };
        self.start(stream, local, ready, conns, &what).await;
    }

    /// A `-R` listener: every accepted connection becomes a server stream.
    async fn listen(self: Arc<Self>, id: u32, listener: TcpListener, conns: u32) {
        let mut streams = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (socket, from) = match accepted {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!("mjolnir: listener {id}: accept failed: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    if let Err(why) = self.may_start(conns) {
                        eprintln!("mjolnir: listener {id}: dropping {from}: {why}");
                        continue;
                    }
                    prepare(&socket);
                    let n = self.next_server_stream.fetch_add(1, Relaxed);
                    let stream = SERVER_STREAM | (n & !SERVER_STREAM);
                    // Server streams are made before the client hears of
                    // them, so no connection ever waits for one.
                    let (guard, ready) = self.register(&mut self.slots.lock().unwrap(), stream, conns);
                    let _ = self.ctrl.send(TunnelMsg::Incoming {
                        listener: id,
                        stream,
                        from: from.to_string(),
                    });
                    let session = self.clone();
                    let what = format!("{from} -> {}", self.peer);
                    streams.spawn(async move {
                        let _guard = guard;
                        session.start(stream, socket, ready, conns, &what).await;
                    });
                }
                Some(_) = streams.join_next(), if !streams.is_empty() => {}
            }
        }
    }
}
