//! The tunnel client: holds the session, listens for `-L` forwards, asks
//! the server to listen for `-R` ones, and opens every stream's
//! connections.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail, ensure};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::proto::{self, ADMITTED, CHALLENGE_LEN, CtrlRx, CtrlTx, PROLOGUE, TunnelMsg};
use super::pump::{BUFFER_BUDGET, Budget, ResetGuard, StreamCrypto, Traffic, pump, pump_tcp};
use super::spec::{ForwardSpec, HostPort};
use super::{
    CONNECT_TIMEOUT, GATHER_WAIT, HANDSHAKE_DEADLINE, MAX_CONNS, connect_any, connect_target,
    connections, human,
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

/// An established session with its forwards set up. [`TunnelClient::run`]
/// serves them until the session ends.
pub struct TunnelClient {
    shared: Arc<Shared>,
    rx: CtrlRx<BufReader<OwnedReadHalf>>,
    writer: tokio::task::JoinHandle<Result<()>>,
    local: Vec<(TcpListener, HostPort)>,
    /// `-R` targets by listener id.
    remote: HashMap<u32, HostPort>,
    remote_addrs: Vec<String>,
    /// Control messages that arrived during setup, handled first by `run`.
    early: Vec<TunnelMsg>,
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
    ctrl: mpsc::UnboundedSender<TunnelMsg>,
}

impl TunnelClient {
    /// Connects, authenticates, asks the server for every `-R` listener,
    /// and binds every `-L` listener. Fails if any forward cannot be set up.
    pub async fn connect(cfg: ClientConfig) -> Result<Self> {
        ensure!(
            (1..=MAX_CONNS).contains(&cfg.conns),
            "connections must be between 1 and {MAX_CONNS}"
        );
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

        let mut local = Vec::new();
        for spec in &cfg.local {
            let listener = TcpListener::bind((spec.listen.host.as_str(), spec.listen.port))
                .await
                .with_context(|| format!("listening for -L {spec}"))?;
            if cfg.verbose {
                eprintln!(
                    "mjolnir: forwarding {} -> server -> {}",
                    listener.local_addr()?,
                    spec.target
                );
            }
            local.push((listener, spec.target.clone()));
        }

        let (ctrl, ctrl_rx) = mpsc::unbounded_channel();
        let writer = tokio::spawn(write_control(tx, ctrl_rx));
        Ok(TunnelClient {
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
            local,
            remote,
            remote_addrs,
            early,
        })
    }

    /// Where each `-L` forward listens, in the order given.
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.local
            .iter()
            .map(|(l, _)| l.local_addr().expect("bound listener has an address"))
            .collect()
    }

    /// Where the server listens for each `-R` forward, in the order given.
    pub fn remote_addrs(&self) -> &[String] {
        &self.remote_addrs
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

    /// Carries one stream to `target` over stdin and stdout, as `ssh -W`
    /// does, and returns when it ends.
    pub async fn stdio(self, target: HostPort) -> Result<Traffic> {
        let shared = self.shared.clone();
        let stream = async move {
            let (id, crypto, conns) = shared.open(&target).await?;
            pump(
                tokio::io::stdin(),
                tokio::io::stdout(),
                conns,
                crypto,
                shared.budget.clone(),
            )
            .await
            .with_context(|| format!("stream {id} to {target}"))
        };
        self.run_with(stream).await
    }

    /// Runs the session alongside `work`, returning when either ends.
    async fn run_with<T>(self, work: impl Future<Output = Result<T>>) -> Result<T> {
        let TunnelClient {
            shared,
            mut rx,
            mut writer,
            local,
            remote,
            early,
            ..
        } = self;
        // Every stream task lives here, so ending the session can cancel
        // them all, and their guards reset the applications' connections,
        // before the process exits.
        let mut tasks = JoinSet::new();
        let (accepted_tx, mut accepted) = mpsc::channel(16);
        for (listener, target) in local {
            tasks.spawn(accept_local(listener, target, accepted_tx.clone()));
        }
        drop(accepted_tx);
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
                            tasks.spawn(serve_incoming(shared.clone(), stream, from, target));
                        }
                        TunnelMsg::Close { stream, message } => {
                            eprintln!("mjolnir: stream {stream}: the server said: {message}");
                        }
                        TunnelMsg::Error { message } => {
                            break Err(anyhow!("the server reported an error: {message}"));
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
                Some((socket, from, target)) = accepted.recv() => {
                    tasks.spawn(serve_local(shared.clone(), socket, from, target));
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
    mut rx: mpsc::UnboundedReceiver<TunnelMsg>,
) -> Result<()> {
    while let Some(msg) = rx.recv().await {
        tx.send(&msg).await?;
    }
    Ok(())
}

impl Shared {
    /// Opens a `-L` stream to `target`: queues its `Open`, then opens its
    /// connections and waits for the server to admit them.
    async fn open(
        self: &Arc<Self>,
        target: &HostPort,
    ) -> Result<(u32, StreamCrypto, Vec<TcpStream>)> {
        let id = {
            let mut next = self.next_stream.lock().unwrap();
            ensure!(*next < super::SERVER_STREAM - 1, "stream ids exhausted");
            *next += 1;
            self.ctrl
                .send(TunnelMsg::Open {
                    stream: *next,
                    host: target.host.clone(),
                    port: target.port,
                    conns: self.conns,
                })
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

    fn fail(&self, stream: u32, what: &str, e: &anyhow::Error) {
        eprintln!("mjolnir: stream {stream} ({what}) failed: {e:#}");
        let _ = self.ctrl.send(TunnelMsg::Close {
            stream,
            message: format!("{e:#}"),
        });
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

/// Accepts `-L` connections and hands them to the session loop, which
/// owns every stream task.
async fn accept_local(
    listener: TcpListener,
    target: HostPort,
    accepted: mpsc::Sender<(TcpStream, SocketAddr, HostPort)>,
) {
    loop {
        match listener.accept().await {
            Ok((socket, from)) => {
                if accepted.send((socket, from, target.clone())).await.is_err() {
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

/// Carries an accepted `-L` connection to `target` from the server.
async fn serve_local(shared: Arc<Shared>, socket: TcpStream, from: SocketAddr, target: HostPort) {
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
        Err(e) => shared.fail(stream, &what, &e),
    }
}
