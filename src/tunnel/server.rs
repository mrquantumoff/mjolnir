//! The tunnel server: authenticates clients, connects `-L` streams to their
//! targets when the client's key permits it, listens for `-R` forwards, and
//! gathers each stream's connections.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
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
use super::pump::{BUFFER_BUDGET, Budget, ResetGuard, StreamCrypto, pump_tcp};
use super::spec::{HostPort, Permits, Policy};
use super::{
    GATHER_WAIT, HANDSHAKE_DEADLINE, MAX_CONNS, SERVER_STREAM, connect_target, connections, human,
    prepare,
};
use crate::crypto::{self, Cipher, NOISE_MSG1_MAX, SessionKeys};
use crate::keys::{PrivateKey, PublicKey};
use crate::printable::{escape, truncate};
use crate::wire::ConnKind;

pub struct ServerConfig {
    pub listen: SocketAddr,
    pub key: PrivateKey,
    /// Authorized client keys and what each may do.
    pub policy: Policy,
    /// Log every stream, not only sessions and failures.
    pub verbose: bool,
}

/// Connections in their handshake at once. One more evicts one of them.
const MAX_PENDING: usize = 256;
/// Sessions the server holds at once, counting ones whose control
/// connection has closed while their streams finish.
const MAX_SESSIONS: usize = 256;
/// Sessions one client key may hold at once.
const MAX_SESSIONS_PER_KEY: usize = 8;
/// Streams one session may have at once, counting ones still starting.
const MAX_STREAMS: usize = 256;
/// Stream connections one session may have at once, over all its streams:
/// what bounds a session's sockets and buffers when streams are striped.
const MAX_SESSION_CONNS: usize = 512;
/// `-R` listeners one session may hold.
const MAX_LISTENERS: usize = 64;
/// Control messages queued for a client at once. A client that stops
/// reading its control connection is not read either once this fills.
const CTRL_QUEUE: usize = 64;
/// How long one control message may take to write before the client
/// counts as not reading, which ends the session.
pub(crate) const CTRL_STALL: Duration = Duration::from_secs(10);
/// The control connection's kernel send buffer. Small on purpose, so the
/// writer blocks (and `CTRL_STALL` fires) when the client stops reading,
/// rather than the kernel swallowing the whole backlog.
const CTRL_SEND_BUF: usize = 16 << 10;
/// Longest host name in `Open` and `Listen`, the DNS limit.
pub(crate) const MAX_HOST_LEN: usize = 255;

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
    pending: Mutex<Pending>,
    /// Out-of-order stream bytes held across every session.
    budget: Budget,
    /// Places for sessions, held until a session and its streams are gone.
    session_places: Arc<Semaphore>,
    /// Live sessions per client key.
    sessions_per_key: Mutex<HashMap<PublicKey, usize>>,
    /// Becomes true when the server stops.
    stop: watch::Sender<bool>,
}

/// A session's place among the server's and its key's sessions; dropping
/// it frees both.
struct SessionPlace {
    _server: OwnedSemaphorePermit,
    shared: Arc<Shared>,
    key: PublicKey,
}

impl Drop for SessionPlace {
    fn drop(&mut self) {
        let mut per_key = self.shared.sessions_per_key.lock().unwrap();
        if let Some(n) = per_key.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                per_key.remove(&self.key);
            }
        }
    }
}

impl Shared {
    /// Takes a place for a session of `key`, or says why there is none.
    fn place_session(self: &Arc<Self>, key: PublicKey) -> Result<SessionPlace, &'static str> {
        let server = self
            .session_places
            .clone()
            .try_acquire_owned()
            .map_err(|_| "the server has as many sessions as it allows")?;
        let mut per_key = self.sessions_per_key.lock().unwrap();
        let mine = per_key.entry(key).or_insert(0);
        if *mine >= MAX_SESSIONS_PER_KEY {
            return Err("this key has as many sessions as the server allows");
        }
        *mine += 1;
        Ok(SessionPlace {
            _server: server,
            shared: self.clone(),
            key,
        })
    }
}

/// Connections in their handshake, oldest first. A full pool evicts a
/// connection rather than refusing the newest, so idle connections cannot
/// lock out a live client. The victim is the oldest connection of the
/// address holding the most of them: one source cannot push everyone
/// else's handshakes out, and a burst from one client is never refused
/// while the pool has room.
#[derive(Default)]
struct Pending {
    by_age: BTreeMap<u64, (IpAddr, Arc<Notify>)>,
    per_ip: HashMap<IpAddr, usize>,
    next: u64,
}

/// A connection's place in [`Pending`]; dropping it frees the place.
struct PendingSlot {
    shared: Arc<Shared>,
    id: u64,
    ip: IpAddr,
    /// Signalled when the pool evicts this connection.
    evicted: Arc<Notify>,
}

impl Pending {
    /// Takes a place for a connection from `ip`, evicting one first when
    /// the pool is full.
    fn admit(&mut self, ip: IpAddr) -> (u64, Arc<Notify>) {
        *self.per_ip.entry(ip).or_insert(0) += 1;
        if self.by_age.len() >= MAX_PENDING {
            self.evict();
        }
        let id = self.next;
        self.next += 1;
        let evicted = Arc::new(Notify::new());
        self.by_age.insert(id, (ip, evicted.clone()));
        (id, evicted)
    }

    /// Closes the oldest connection among those of the addresses with the
    /// most.
    fn evict(&mut self) {
        let most = self.per_ip.values().copied().max().unwrap_or(0);
        let &id = self
            .by_age
            .iter()
            .find(|(_, (ip, _))| self.per_ip[ip] == most)
            .map(|(id, _)| id)
            .expect("a full pool has a connection from a heaviest address");
        let (ip, evicted) = self.by_age.remove(&id).expect("just found");
        evicted.notify_one();
        self.forget(ip);
    }

    /// Frees a place; a no-op for one the pool already evicted.
    fn release(&mut self, id: u64, ip: IpAddr) {
        if self.by_age.remove(&id).is_some() {
            self.forget(ip);
        }
    }

    fn forget(&mut self, ip: IpAddr) {
        if let Some(n) = self.per_ip.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                self.per_ip.remove(&ip);
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_age.len()
    }
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        self.shared
            .pending
            .lock()
            .unwrap()
            .release(self.id, self.ip);
    }
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
                pending: Mutex::new(Pending::default()),
                budget: Budget::new(BUFFER_BUDGET),
                session_places: Arc::new(Semaphore::new(MAX_SESSIONS)),
                sessions_per_key: Mutex::new(HashMap::new()),
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
            let (id, evicted) = self.shared.pending.lock().unwrap().admit(from.ip());
            let slot = PendingSlot {
                shared: self.shared.clone(),
                id,
                ip: from.ip(),
                evicted,
            };
            let (shared, alive) = (self.shared.clone(), alive.clone());
            tokio::spawn(async move {
                if let Err(e) = serve(&shared, stream, from, slot).await {
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

/// What a connection turned out to be once it authenticated.
enum Admitted {
    Control {
        keys: SessionKeys,
        peer: PublicKey,
        cipher: Cipher,
        rx: CtrlRx<()>,
    },
    Stream {
        session: Arc<Session>,
        stream: u32,
        conn: u32,
    },
}

/// Runs a connection's handshake within `HANDSHAKE_DEADLINE` of its accept,
/// holding its pending place only until it has authenticated, then serves
/// it.
async fn serve(
    shared: &Arc<Shared>,
    mut stream: TcpStream,
    from: SocketAddr,
    slot: PendingSlot,
) -> Result<()> {
    prepare(&stream);
    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    let evicted = slot.evicted.clone();
    let admitted = tokio::select! {
        r = timeout_at(deadline, admit(shared, &mut stream)) => {
            r.map_err(|_| anyhow!("no handshake within {HANDSHAKE_DEADLINE:?}"))??
        }
        () = evicted.notified() => bail!("closed to make room for a newer connection"),
    };
    drop(slot);
    match admitted {
        Admitted::Control {
            keys,
            peer,
            cipher,
            rx,
        } => control(shared, stream, from, keys, peer, cipher, rx).await,
        Admitted::Stream {
            session,
            stream: id,
            conn,
        } => session.attach(id, conn, stream).await,
    }
}

/// The preamble and then, by kind, the Noise handshake and the `Hello`, or
/// the stream challenge and its MAC. Nothing here buffers more than a
/// fixed few bytes for a peer that has not proven itself.
async fn admit(shared: &Arc<Shared>, stream: &mut TcpStream) -> Result<Admitted> {
    let mut preamble = [0u8; 6];
    stream.read_exact(&mut preamble).await?;
    match ConnKind::from_preamble(&preamble)? {
        ConnKind::TunnelControl => {
            let msg1 = proto::read_noise(stream, NOISE_MSG1_MAX)
                .await
                .context("reading Noise message 1")?;
            let (msg2, keys, peer) =
                crypto::respond(&msg1, &shared.key, shared.policy.keys(), PROLOGUE)?;
            proto::write_noise(stream, &msg2).await?;
            // Message 1 can be replayed; only the live client can seal
            // `Hello`, which is read unbuffered and at its fixed length.
            let mut rx = CtrlRx::new(&mut *stream, &keys, false);
            let cipher = rx.recv_hello().await?;
            let rx = rx.with_reader(|_| ());
            Ok(Admitted::Control {
                keys,
                peer,
                cipher,
                rx,
            })
        }
        ConnKind::TunnelData => {
            let mut challenge = [0u8; CHALLENGE_LEN];
            getrandom::fill(&mut challenge)
                .map_err(|e| anyhow!("OS random number generator: {e}"))?;
            stream.write_all(&challenge).await?;
            let mut hello = [0u8; HELLO_LEN];
            stream.read_exact(&mut hello).await?;
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
            Ok(Admitted::Stream {
                session,
                stream: id,
                conn,
            })
        }
        ConnKind::Control | ConnKind::Data => {
            bail!("a file sender connected, but this port runs `mjolnir tunnel-server`")
        }
    }
}

/// Registers the session, answers `Welcome`, and serves the session until
/// its control connection ends.
async fn control(
    shared: &Arc<Shared>,
    stream: TcpStream,
    from: SocketAddr,
    keys: SessionKeys,
    peer: PublicKey,
    cipher: Cipher,
    rx: CtrlRx<()>,
) -> Result<()> {
    // A small send buffer for control replies, so a client that stops
    // reading fills it within a few hundred messages and the writer's own
    // `CTRL_STALL` timeout fires; without it the kernel would buffer the
    // whole bounded backlog and the writer would never block. Control
    // messages are tiny and read promptly, so this never limits a live
    // client.
    let _ = socket2::SockRef::from(&stream).set_send_buffer_size(CTRL_SEND_BUF);
    let (r, w) = stream.into_split();
    let mut tx = CtrlTx::new(w, &keys, false);
    let rx = rx.with_reader(|()| BufReader::new(r));
    let place = match shared.place_session(peer) {
        Ok(place) => place,
        Err(why) => {
            tx.send(&TunnelMsg::Error {
                message: why.into(),
            })
            .await?;
            bail!("session from {from} (key {peer}) refused: {why}");
        }
    };
    let (ctrl, ctrl_rx) = mpsc::channel(CTRL_QUEUE);
    let route = proto::route(&keys);
    let session = Arc::new(Session {
        _place: place,
        keys,
        cipher,
        peer,
        permits: shared.policy.for_key(&peer).clone(),
        verbose: shared.verbose,
        budget: shared.budget.clone(),
        ctrl,
        slots: Mutex::new(Slots::default()),
        closing: watch::Sender::new(false),
        registered: Notify::new(),
        streams: AtomicUsize::new(0),
        conns_in_use: AtomicUsize::new(0),
        waiting: AtomicUsize::new(0),
        next_server_stream: AtomicU32::new(0),
    });
    // Registered before `Welcome` goes out, so a stream connection the
    // client opens on seeing it always finds the session.
    shared
        .sessions
        .lock()
        .unwrap()
        .insert(route, session.clone());
    eprintln!("mjolnir: tunnel session from {from} (key {peer})");
    let result = async {
        tx.send(&TunnelMsg::Welcome {
            max_conns: MAX_CONNS,
        })
        .await?;
        session.run(tx, rx, ctrl_rx, shared.stop.subscribe()).await
    }
    .await;
    shared.sessions.lock().unwrap().remove(&route);
    match result {
        Ok(()) => eprintln!("mjolnir: tunnel session from {from} closed"),
        Err(e) => eprintln!("mjolnir: tunnel session from {from} ended: {e:#}"),
    }
    Ok(())
}

struct Session {
    /// Held as long as the session or any of its streams lives.
    _place: SessionPlace,
    keys: SessionKeys,
    cipher: Cipher,
    peer: PublicKey,
    permits: Permits,
    verbose: bool,
    budget: Budget,
    /// Messages for the control writer task. Bounded: senders wait when
    /// the client does not read, so nothing piles up on its behalf.
    ctrl: mpsc::Sender<TunnelMsg>,
    slots: Mutex<Slots>,
    /// Becomes true when the control connection closed cleanly.
    closing: watch::Sender<bool>,
    /// Signalled whenever a stream registers.
    registered: Notify,
    /// Streams starting or running.
    streams: AtomicUsize,
    /// Stream connections those streams asked for.
    conns_in_use: AtomicUsize,
    /// Stream connections waiting in `attach` for their `Open`.
    waiting: AtomicUsize,
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

/// Counts a stream and its connections as in use until dropped.
struct StreamGuard {
    session: Arc<Session>,
    conns: usize,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.session.streams.fetch_sub(1, Relaxed);
        self.session.conns_in_use.fetch_sub(self.conns, Relaxed);
    }
}

/// Counts a connection as waiting for its `Open` until dropped.
struct Waiting<'a>(&'a Session);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Relaxed);
    }
}

impl Session {
    async fn run(
        self: &Arc<Self>,
        mut tx: CtrlTx<OwnedWriteHalf>,
        mut rx: CtrlRx<BufReader<OwnedReadHalf>>,
        mut ctrl_rx: mpsc::Receiver<TunnelMsg>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut tasks = JoinSet::new();
        // The writer stops after sending an `Error`, so the session can
        // wait for it to go out.
        let mut writer = tokio::spawn(async move {
            while let Some(msg) = ctrl_rx.recv().await {
                let last = matches!(msg, TunnelMsg::Error { .. });
                timeout(CTRL_STALL, tx.send(&msg))
                    .await
                    .map_err(|_| anyhow!("the client stopped reading its control connection"))??;
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
                        // A clean close: no new streams, but the running
                        // ones finish on their own terms, so nothing the
                        // client sent before closing is thrown away.
                        Some(Ok(None)) => {
                            self.closing.send_replace(true);
                            while tasks.join_next().await.is_some() {}
                            break Ok(());
                        }
                        Some(Err(e)) => break Err(e),
                        None => break Err(anyhow!("control reader stopped")),
                    };
                    if let Err(e) = self.handle(msg, &mut tasks, &mut listeners).await {
                        let error = TunnelMsg::Error { message: format!("{e:#}") };
                        let _ = timeout(Duration::from_secs(1), self.ctrl.send(error)).await;
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
                let target = host_port(host, port)?;
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
                // Connections that arrived first learn either way: a slot
                // to join, or a watermark past their stream.
                self.registered.notify_waiters();
                let (guard, ready) = match registered {
                    Ok(registered) => registered,
                    Err(why) => {
                        eprintln!(
                            "mjolnir: stream {stream} from {}: {}",
                            self.peer,
                            shown(&why)
                        );
                        self.close(stream, why).await?;
                        return Ok(());
                    }
                };
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
                let bind = host_port(host, port)?;
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
                    bind_listener(&bind)
                        .await
                        .map_err(|e| format!("listening on {bind}: {e:#}"))
                };
                match checked {
                    Ok(listener) => {
                        let addr = listener.local_addr()?;
                        eprintln!("mjolnir: {} listens on {addr}", self.peer);
                        listeners.insert(id);
                        self.send(TunnelMsg::Listening {
                            id,
                            addr: addr.to_string(),
                        })
                        .await?;
                        let session = self.clone();
                        tasks.spawn(async move { session.listen(id, listener, conns).await });
                    }
                    Err(message) => {
                        eprintln!("mjolnir: listener from {}: {}", self.peer, shown(&message));
                        self.send(TunnelMsg::ListenFailed { id, message }).await?;
                    }
                }
            }
            TunnelMsg::Close { stream, message } => {
                if self.verbose {
                    eprintln!(
                        "mjolnir: stream {stream}: the client gave up: {}",
                        shown(&message)
                    );
                }
                // Dropping the slot tells the stream's task to stop.
                self.slots.lock().unwrap().map.remove(&stream);
            }
            TunnelMsg::Error { message } => {
                bail!("the client reported an error: {}", shown(&message))
            }
            other => bail!("protocol error: unexpected {other:?}"),
        }
        Ok(())
    }

    /// Queues a control message, waiting up to `CTRL_STALL` for room. A
    /// queue that stays full that long means the client is not reading its
    /// replies, so the whole backlog cannot drain however large the socket
    /// buffers are; that ends the session. A session already gone drops the
    /// message.
    async fn send(&self, msg: TunnelMsg) -> Result<()> {
        match self.ctrl.send_timeout(msg, CTRL_STALL).await {
            Ok(()) => Ok(()),
            Err(mpsc::error::SendTimeoutError::Closed(_)) => Ok(()),
            Err(mpsc::error::SendTimeoutError::Timeout(_)) => {
                bail!("the client stopped reading its control connection")
            }
        }
    }

    /// Whether a stream of `conns` connections fits the session's limits.
    /// Checked, not reserved: `register` under the slots lock counts it.
    fn may_start(&self, conns: u32) -> Result<(), String> {
        if conns == 0 || conns > MAX_CONNS {
            return Err(format!(
                "asks for {conns} connections; the server allows 1 to {MAX_CONNS}"
            ));
        }
        if self.streams.load(Relaxed) >= MAX_STREAMS {
            return Err(format!("at most {MAX_STREAMS} streams per session"));
        }
        if self.conns_in_use.load(Relaxed) + conns as usize > MAX_SESSION_CONNS {
            return Err(format!(
                "at most {MAX_SESSION_CONNS} stream connections per session, over all its streams"
            ));
        }
        Ok(())
    }

    async fn close(&self, stream: u32, message: String) -> Result<()> {
        self.send(TunnelMsg::Close { stream, message }).await
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
        self.conns_in_use.fetch_add(conns as usize, Relaxed);
        let (ready, rx) = oneshot::channel();
        slots.map.insert(
            stream,
            Slot {
                conns: (0..conns).map(|_| None).collect(),
                have: 0,
                ready,
            },
        );
        (
            StreamGuard {
                session: self.clone(),
                conns: conns as usize,
            },
            rx,
        )
    }

    /// Adds a connection to its stream's slot; the last one completes the
    /// slot. A connection may beat its stream's `Open` here, so an unknown
    /// client stream id above the highest seen waits for it, within the
    /// session's connection limit.
    async fn attach(&self, stream: u32, conn: u32, socket: TcpStream) -> Result<()> {
        let deadline = Instant::now() + GATHER_WAIT;
        let mut socket = Some(socket);
        let _waiting = Waiting(self);
        ensure!(
            self.waiting.fetch_add(1, Relaxed) < MAX_SESSION_CONNS,
            "stream {stream}: too many connections are waiting for their Open"
        );
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

    /// Waits for a stream's connections, admits them, and pumps. `guard`
    /// resets `local` on any way out but a clean end, so an application
    /// whose stream never started sees a failure, not an empty reply.
    async fn start(
        &self,
        stream: u32,
        local: TcpStream,
        guard: ResetGuard,
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
                let _ = self.close(stream, why).await;
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
        match pump_tcp(local, guard, sockets, crypto, self.budget.clone()).await {
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
                let _ = self.close(stream, why).await;
                return;
            }
        };
        let guard = ResetGuard::new(&local);
        self.start(stream, local, guard, ready, conns, &what).await;
    }

    /// A `-R` listener: every accepted connection becomes a server stream.
    /// When the session closes cleanly the listener goes away and its
    /// streams drain.
    async fn listen(self: Arc<Self>, id: u32, listener: TcpListener, conns: u32) {
        let mut streams = JoinSet::new();
        let mut closing = self.closing.subscribe();
        loop {
            tokio::select! {
                () = async { drop(closing.wait_for(|&closing| closing).await) } => {
                    drop(listener);
                    while streams.join_next().await.is_some() {}
                    return;
                }
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
                    let guard = ResetGuard::new(&socket);
                    let Some(stream) = next_server_stream(&self.next_server_stream) else {
                        eprintln!("mjolnir: listener {id}: dropping {from}: this session has used every stream id; reconnect to start a new session");
                        continue;
                    };
                    // Server streams are made before the client hears of
                    // them, so no connection ever waits for one.
                    let (counted, ready) = self.register(&mut self.slots.lock().unwrap(), stream, conns);
                    let _ = self
                        .send(TunnelMsg::Incoming {
                            listener: id,
                            stream,
                            from: from.to_string(),
                        })
                        .await;
                    let session = self.clone();
                    let what = format!("{from} -> {}", self.peer);
                    streams.spawn(async move {
                        let _counted = counted;
                        session.start(stream, socket, guard, ready, conns, &what).await;
                    });
                }
                Some(_) = streams.join_next(), if !streams.is_empty() => {}
            }
        }
    }
}

/// Binds a `-R` listener on `bind`, trying each address it resolves to.
/// The socket is exclusive on Windows: without `SO_EXCLUSIVEADDRUSE`,
/// binding `127.0.0.1:P` succeeds there while another service listens on
/// `0.0.0.0:P`, and loopback connections meant for that service go to
/// the tunnel instead. Linux refuses such a bind on its own; the option
/// makes Windows do the same.
async fn bind_listener(bind: &HostPort) -> Result<TcpListener> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((bind.host.as_str(), bind.port))
        .await
        .with_context(|| format!("resolving {bind}"))?
        .collect();
    ensure!(!addrs.is_empty(), "{bind} resolved to no addresses");
    let mut last = None;
    for addr in addrs {
        match bind_exclusive(addr) {
            Ok(listener) => return Ok(listener),
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("at least one address was tried").into())
}

fn bind_exclusive(addr: SocketAddr) -> std::io::Result<TcpListener> {
    // Windows lets a specific address be bound over another socket's
    // wildcard bind of the same port, whatever options the new socket
    // sets. What it does refuse is an exclusive bind of the wildcard while
    // any socket holds the port, so that is tried first, as a probe.
    #[cfg(windows)]
    if !addr.ip().is_unspecified() {
        let wildcard = SocketAddr::new(
            match addr {
                SocketAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
                SocketAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
            },
            addr.port(),
        );
        exclusive_socket(wildcard)?.bind(&wildcard.into())?;
    }
    let socket = exclusive_socket(addr)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// A socket for `addr` that no later bind may share: `SO_EXCLUSIVEADDRUSE`
/// on Windows. Elsewhere `SO_REUSEADDR` only lets the port be taken again
/// right after a session ends, while its last connections are in
/// TIME_WAIT; a listening socket still cannot be shadowed.
fn exclusive_socket(addr: SocketAddr) -> std::io::Result<socket2::Socket> {
    use socket2::{Domain, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            SO_EXCLUSIVEADDRUSE, SOL_SOCKET, setsockopt,
        };
        let on: i32 = 1;
        let rc = unsafe {
            setsockopt(
                socket.as_raw_socket() as usize,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&on as *const i32).cast(),
                std::mem::size_of::<i32>() as i32,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    Ok(socket)
}

/// The next `-R` stream id: the top bit set, then a counter. Once the
/// counter runs out the session must end, since an id used again would
/// reuse its keys and nonces.
fn next_server_stream(counter: &AtomicU32) -> Option<u32> {
    counter
        .fetch_update(Relaxed, Relaxed, |n| (n < SERVER_STREAM).then_some(n + 1))
        .ok()
        .map(|n| SERVER_STREAM | n)
}

/// A host and port from the client, with the host held to the DNS limit;
/// over it is a protocol error rather than something to echo back.
fn host_port(host: String, port: u16) -> Result<HostPort> {
    ensure!(
        host.len() <= MAX_HOST_LEN,
        "protocol error: a host name of {} bytes is over the {MAX_HOST_LEN}-byte limit",
        host.len()
    );
    Ok(HostPort { host, port })
}

/// Peer-supplied text as it may be logged: escaped and cut short.
fn shown(text: &str) -> String {
    escape(&truncate(text, 300)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    /// Another service listens on every interface; a -R listener asking
    /// for the same port on loopback must be refused, or it would take
    /// that service's loopback traffic. Linux refuses this on its own;
    /// Windows needs the exclusive option. macOS allows the bind with
    /// SO_REUSEADDR, so the check is not made there.
    #[cfg(any(windows, target_os = "linux"))]
    #[tokio::test]
    async fn a_reverse_listener_cannot_shadow_a_wildcard_listener() {
        let wild = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = wild.local_addr().unwrap().port();
        let specific = HostPort {
            host: "127.0.0.1".into(),
            port,
        };
        let err = match bind_listener(&specific).await {
            Ok(_) => panic!("bound 127.0.0.1:{port} over a listener on 0.0.0.0:{port}"),
            Err(e) => e,
        };
        assert!(!format!("{err:#}").contains("resolving"), "{err:#}");
        drop(wild);
        bind_listener(&specific)
            .await
            .expect("the port is free once the other listener is gone");
        // The other way round as well: a wildcard request over a service
        // on loopback.
        let loopback = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = loopback.local_addr().unwrap().port();
        let wildcard = HostPort {
            host: "0.0.0.0".into(),
            port,
        };
        assert!(
            bind_listener(&wildcard).await.is_err(),
            "bound 0.0.0.0:{port} over a listener on 127.0.0.1:{port}"
        );
    }

    #[test]
    fn server_stream_ids_stop_before_they_could_repeat() {
        let counter = AtomicU32::new(SERVER_STREAM - 2);
        assert_eq!(next_server_stream(&counter), Some(u32::MAX - 1));
        assert_eq!(next_server_stream(&counter), Some(u32::MAX));
        assert_eq!(next_server_stream(&counter), None);
        assert_eq!(next_server_stream(&counter), None);
        let fresh = AtomicU32::new(0);
        assert_eq!(next_server_stream(&fresh), Some(SERVER_STREAM));
        assert_eq!(next_server_stream(&fresh), Some(SERVER_STREAM | 1));
    }

    fn told(evicted: &Notify) -> bool {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            timeout(Duration::from_millis(100), evicted.notified())
                .await
                .is_ok()
        })
    }

    #[test]
    fn a_full_pool_evicts_the_oldest_of_the_heaviest_address() {
        let ip = |n: u8| IpAddr::from([10, 0, 0, n]);
        let mut pool = Pending::default();
        // One address floods; two others each hold one older connection.
        let (victim_id, victim) = pool.admit(ip(1));
        let (_, bystander) = pool.admit(ip(2));
        let mut flood = Vec::new();
        for _ in 2..MAX_PENDING {
            flood.push(pool.admit(ip(9)));
        }
        assert_eq!(pool.len(), MAX_PENDING);
        // Full: a newcomer from a third address evicts the flooder's oldest,
        // not the oldest connection overall.
        let (_, newcomer) = pool.admit(ip(3));
        assert_eq!(pool.len(), MAX_PENDING);
        assert!(told(&flood[0].1), "the flooder's oldest goes first");
        assert!(!told(&victim) && !told(&bystander) && !told(&newcomer));
        // The flooder's own newcomer evicts the flooder again.
        pool.admit(ip(9));
        assert!(told(&flood[1].1));
        // Releasing an evicted slot is a no-op; releasing a live one frees it.
        pool.release(flood[0].0, ip(9));
        assert_eq!(pool.len(), MAX_PENDING);
        pool.release(victim_id, ip(1));
        assert_eq!(pool.len(), MAX_PENDING - 1);
        assert!(!pool.per_ip.contains_key(&ip(1)));
    }

    #[test]
    fn a_full_pool_of_equals_evicts_the_oldest() {
        let ip = |n: u16| IpAddr::from([10, 0, (n >> 8) as u8, n as u8]);
        let mut pool = Pending::default();
        let slots: Vec<_> = (0..MAX_PENDING as u16).map(|n| pool.admit(ip(n))).collect();
        pool.admit(ip(999));
        assert!(told(&slots[0].1));
        assert!(!told(&slots[1].1));
    }
}
