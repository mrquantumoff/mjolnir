//! Protocol-level tests that drive the server with hand-made clients: the
//! handshake pool, replayed handshakes, and peers that break the rules.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

use super::proto::{self, CHALLENGE_LEN, CtrlRx, CtrlTx, PROLOGUE, TunnelMsg};
use super::pump::{BUFFER_BUDGET, Budget, StreamCrypto, pump};
use super::{ClientConfig, Permits, Policy, ServerConfig, TunnelClient, TunnelServer};
use crate::crypto::{Cipher, Initiator, NOISE_MSG_MAX, SessionKeys};
use crate::keys::{AuthorizedKey, PrivateKey, PublicKey};
use crate::wire::ConnKind;

const LIMIT: Duration = Duration::from_secs(30);
/// The server's pool of connections in their handshake.
const MAX_PENDING: usize = 256;
/// How long the server lets one control write stall before it gives up
/// on the client.
const CTRL_STALL: Duration = Duration::from_secs(10);
/// The longest host name the server takes in a request.
const MAX_HOST_LEN: usize = 255;

struct Srv {
    addr: SocketAddr,
    pubkey: PublicKey,
    client: PrivateKey,
}

async fn start_server(open: &[&str], listen: &[&str]) -> Srv {
    let (srv, mut keys) = start_server_with_keys(1, open, listen).await;
    Srv {
        client: keys.remove(0),
        ..srv
    }
}

/// A server that authorizes `n` fresh keys; `Srv::client` is the first.
async fn start_server_with_keys(
    n: usize,
    open: &[&str],
    listen: &[&str],
) -> (Srv, Vec<PrivateKey>) {
    let keys: Vec<PrivateKey> = (0..n).map(|_| PrivateKey::generate()).collect();
    let entries: Vec<AuthorizedKey> = keys
        .iter()
        .map(|k| AuthorizedKey {
            key: k.public_key(),
            options: vec![],
        })
        .collect();
    let policy = Policy::new(
        &entries,
        Permits {
            open: open.iter().map(|p| p.parse().unwrap()).collect(),
            listen: listen.iter().map(|p| p.parse().unwrap()).collect(),
        },
    )
    .unwrap();
    let server = TunnelServer::bind(ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        key: PrivateKey::generate(),
        policy,
        verbose: false,
    })
    .await
    .unwrap();
    let (addr, pubkey) = (server.local_addr(), server.public_key());
    tokio::spawn(server.run());
    let srv = Srv {
        addr,
        pubkey,
        client: keys[0].clone(),
    };
    (srv, keys)
}

fn cfg(s: &Srv, conns: u32, local: &[String]) -> ClientConfig {
    ClientConfig {
        addr: s.addr.to_string(),
        key: s.client.clone(),
        peer: s.pubkey,
        cipher: Cipher::Aes256Gcm,
        conns,
        local: local.iter().map(|x| x.parse().unwrap()).collect(),
        remote: vec![],
        verbose: false,
    }
}

/// The Noise handshake on a fresh connection, up to but not including
/// `Hello`.
async fn raw_handshake(s: &Srv) -> (TcpStream, SessionKeys) {
    let mut t = TcpStream::connect(s.addr).await.unwrap();
    t.write_all(&ConnKind::TunnelControl.preamble())
        .await
        .unwrap();
    let (hs, m1) = Initiator::start(&s.client, &s.pubkey, PROLOGUE).unwrap();
    proto::write_noise(&mut t, &m1).await.unwrap();
    let m2 = proto::read_noise(&mut t, NOISE_MSG_MAX).await.unwrap();
    (t, hs.finish(&m2).unwrap())
}

type Tx = CtrlTx<OwnedWriteHalf>;
type Rx = CtrlRx<BufReader<OwnedReadHalf>>;

/// A hand-driven, fully authenticated client session.
async fn raw_session(s: &Srv) -> (Tx, Rx, SessionKeys) {
    let (t, keys) = raw_handshake(s).await;
    let (r, w) = t.into_split();
    let (mut tx, mut rx) = proto::control(BufReader::new(r), w, &keys, true);
    tx.send(&TunnelMsg::Hello {
        cipher: Cipher::Aes256Gcm,
    })
    .await
    .unwrap();
    match rx.recv().await.unwrap() {
        Some(TunnelMsg::Welcome { .. }) => {}
        other => panic!("{other:?}"),
    }
    (tx, rx, keys)
}

/// Opens a stream connection and sends its (valid) hello.
async fn raw_stream_conn(
    addr: SocketAddr,
    keys: &SessionKeys,
    stream: u32,
    conn: u32,
) -> TcpStream {
    let mut t = TcpStream::connect(addr).await.unwrap();
    t.write_all(&ConnKind::TunnelData.preamble()).await.unwrap();
    let mut ch = [0u8; CHALLENGE_LEN];
    t.read_exact(&mut ch).await.unwrap();
    t.write_all(&proto::encode_hello(
        keys,
        &proto::route(keys),
        &ch,
        stream,
        conn,
    ))
    .await
    .unwrap();
    t
}

fn open(stream: u32, host: &str) -> TunnelMsg {
    TunnelMsg::Open {
        stream,
        host: host.into(),
        port: 1,
        conns: 1,
    }
}

trait WithPort {
    fn clone_with_port(&self, port: u16) -> TunnelMsg;
}

impl WithPort for TunnelMsg {
    fn clone_with_port(&self, port: u16) -> TunnelMsg {
        match self {
            TunnelMsg::Open {
                stream,
                host,
                conns,
                ..
            } => TunnelMsg::Open {
                stream: *stream,
                host: host.clone(),
                port,
                conns: *conns,
            },
            other => panic!("not an Open: {other:?}"),
        }
    }
}

async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    a
}

async fn round_trip(addr: SocketAddr, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(addr).await?;
    let (mut r, mut w) = s.split();
    let write = async {
        w.write_all(data).await?;
        w.shutdown().await
    };
    let read = async {
        let mut got = Vec::new();
        r.read_to_end(&mut got).await?;
        Ok(got)
    };
    let (a, b) = tokio::join!(write, read);
    a?;
    b
}

/// How long until the peer closes or resets `s`, reading and discarding.
async fn until_closed(mut s: TcpStream, t0: Instant) -> Duration {
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => return t0.elapsed(),
            Ok(_) => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_connections_do_not_lock_out_sessions_or_streams() {
    let echo = echo_server().await;
    let srv = start_server(&["127.0.0.1:*"], &[]).await;
    let spec = format!("127.0.0.1:0:127.0.0.1:{}", echo.port());
    let client = TunnelClient::connect(cfg(&srv, 1, std::slice::from_ref(&spec)))
        .await
        .unwrap();
    let local = client.local_addrs()[0];
    tokio::spawn(client.run());
    assert_eq!(round_trip(local, b"ping").await.unwrap(), b"ping");

    let mut idle = Vec::new();
    for _ in 0..MAX_PENDING {
        idle.push(TcpStream::connect(srv.addr).await.unwrap());
    }
    sleep(Duration::from_millis(300)).await;
    let got = timeout(LIMIT, round_trip(local, b"ping"))
        .await
        .expect("a stream on an established session must not wait for idle sockets")
        .expect("idle sockets must not break a stream");
    assert_eq!(got, b"ping");
    let fresh = timeout(LIMIT, TunnelClient::connect(cfg(&srv, 1, &[])))
        .await
        .expect("a new session must not wait for idle sockets");
    fresh.expect("idle sockets must not refuse a new session");
    drop(idle);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_handshake_has_one_deadline_from_accept() {
    let srv = start_server(&[], &[]).await;
    let t0 = Instant::now();
    let mut t = TcpStream::connect(srv.addr).await.unwrap();
    // A preamble sent late does not buy another full deadline.
    sleep(Duration::from_secs(8)).await;
    t.write_all(&ConnKind::TunnelControl.preamble())
        .await
        .unwrap();
    let closed = timeout(Duration::from_secs(20), until_closed(t, t0))
        .await
        .expect("the server closes an unfinished handshake");
    assert!(
        closed < Duration::from_secs(13),
        "closed only after {closed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_message_1_gets_no_buffer_past_hello() {
    let srv = start_server(&[], &[]).await;
    // Whoever replays message 1 gets message 2 back but cannot seal a
    // Hello; claiming a long one must not make the server wait for it.
    let (mut t, _keys) = raw_handshake(&srv).await;
    let t0 = Instant::now();
    t.write_all(&(64u32 << 10).to_be_bytes()).await.unwrap();
    t.write_all(&[0u8; 100]).await.unwrap();
    let closed = timeout(Duration::from_secs(20), until_closed(t, t0))
        .await
        .expect("the server closes the connection");
    assert!(
        closed < Duration::from_secs(3),
        "the server waited {closed:?} for a body it should never read"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_open_wakes_connections_that_arrived_first() {
    let srv = start_server(&[], &[]).await;
    let (mut tx, mut rx, keys) = raw_session(&srv).await;
    let early = raw_stream_conn(srv.addr, &keys, 1, 0).await;
    sleep(Duration::from_millis(200)).await;
    let t0 = Instant::now();
    tx.send(&open(1, "not-permitted")).await.unwrap();
    assert!(matches!(
        rx.recv().await.unwrap(),
        Some(TunnelMsg::Close { stream: 1, .. })
    ));
    let closed = timeout(LIMIT, until_closed(early, t0)).await.unwrap();
    assert!(
        closed < Duration::from_secs(3),
        "the early connection waited {closed:?} for a stream that was refused at once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_over_the_dns_limit_is_a_protocol_error() {
    let srv = start_server(&["*"], &[]).await;
    let (mut tx, mut rx, _keys) = raw_session(&srv).await;
    tx.send(&open(1, &"a".repeat(MAX_HOST_LEN + 1)))
        .await
        .unwrap();
    match timeout(LIMIT, rx.recv()).await.unwrap() {
        Ok(Some(TunnelMsg::Error { message })) => assert!(message.contains("host"), "{message}"),
        Ok(None) | Err(_) => {}
        other => panic!("expected the session to end, got {other:?}"),
    }
    assert!(
        timeout(LIMIT, rx.recv())
            .await
            .unwrap()
            .ok()
            .flatten()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sessions_per_key_are_limited() {
    let srv = start_server(&[], &[]).await;
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(TunnelClient::connect(cfg(&srv, 1, &[])).await.unwrap());
    }
    let err = match TunnelClient::connect(cfg(&srv, 1, &[])).await {
        Ok(_) => panic!("a ninth session for one key was accepted"),
        Err(e) => e,
    };
    assert!(format!("{err:#}").contains("as many sessions"), "{err:#}");
    // A session's place is freed once it and its streams are gone.
    drop(held.pop());
    sleep(Duration::from_millis(300)).await;
    TunnelClient::connect(cfg(&srv, 1, &[]))
        .await
        .expect("the freed place is taken again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sessions_in_total_are_limited() {
    let (srv, keys) = start_server_with_keys(33, &[], &[]).await;
    let mut held = Vec::new();
    let mut refused = None;
    'outer: for key in &keys {
        for _ in 0..8 {
            let mut c = cfg(&srv, 1, &[]);
            c.key = key.clone();
            match TunnelClient::connect(c).await {
                Ok(client) => held.push(client),
                Err(e) => {
                    refused = Some(e);
                    break 'outer;
                }
            }
        }
    }
    let err = refused.expect("264 sessions over 33 keys must not all be accepted");
    assert_eq!(held.len(), 256, "{err:#}");
    assert!(format!("{err:#}").contains("as many sessions"), "{err:#}");
}

/// A session's streams share one connection budget: with 32 connections
/// per stream, the seventeenth stream is refused at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_per_session_are_budgeted() {
    let echo = echo_server().await;
    let srv = start_server(&["127.0.0.1:*"], &[]).await;
    let (mut tx, mut rx, _keys) = raw_session(&srv).await;
    for stream in 1..=17 {
        tx.send(&TunnelMsg::Open {
            stream,
            host: "127.0.0.1".into(),
            port: echo.port(),
            conns: 32,
        })
        .await
        .unwrap();
    }
    match timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap()
    {
        Some(TunnelMsg::Close {
            stream: 17,
            message,
        }) => {
            assert!(message.contains("512"), "{message}");
        }
        other => panic!("expected the seventeenth stream refused, got {other:?}"),
    }
}

/// A stream keeps running after its control connection closed cleanly:
/// the server stops taking new streams but lets this one finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_control_close_lets_running_streams_finish() {
    let echo = echo_server().await;
    let srv = start_server(&["127.0.0.1:*"], &[]).await;
    let (mut tx, rx, keys) = raw_session(&srv).await;
    tx.send(&open(1, "127.0.0.1").clone_with_port(echo.port()))
        .await
        .unwrap();
    let mut conn = raw_stream_conn(srv.addr, &keys, 1, 0).await;
    assert_eq!(conn.read_u8().await.unwrap(), proto::ADMITTED);
    let (mut app, pump_end) = tokio::io::duplex(1 << 16);
    let (r, w) = tokio::io::split(pump_end);
    let crypto = StreamCrypto::new(&keys, Cipher::Aes256Gcm, 1, 1, true);
    let pumping = tokio::spawn(pump(r, w, vec![conn], crypto, Budget::new(BUFFER_BUDGET)));
    app.write_all(b"before").await.unwrap();
    let mut buf = [0u8; 6];
    app.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"before");
    // The control connection closes cleanly with the stream still open.
    drop((tx, rx));
    sleep(Duration::from_millis(300)).await;
    app.write_all(b"after").await.unwrap();
    let mut buf = [0u8; 5];
    timeout(LIMIT, app.read_exact(&mut buf))
        .await
        .unwrap()
        .expect("the stream was cut off by the clean close");
    assert_eq!(&buf, b"after");
    app.shutdown().await.unwrap();
    let mut rest = Vec::new();
    app.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    timeout(LIMIT, pumping).await.unwrap().unwrap().unwrap();
}

/// A client that sends requests but never reads the replies: the server
/// must stop reading it and, after a while, drop it, rather than queue
/// replies without bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_stops_reading_is_disconnected() {
    let srv = start_server(&[], &[]).await;
    let (t, keys) = raw_handshake(&srv).await;
    // Small socket buffers so the stall shows after a few hundred replies
    // instead of a few thousand.
    let sock = socket2::SockRef::from(&t);
    sock.set_recv_buffer_size(4096).unwrap();
    sock.set_send_buffer_size(4096).unwrap();
    let (r, w) = t.into_split();
    let (mut tx, mut rx) = proto::control(BufReader::new(r), w, &keys, true);
    tx.send(&TunnelMsg::Hello {
        cipher: Cipher::Aes256Gcm,
    })
    .await
    .unwrap();
    assert!(matches!(
        rx.recv().await.unwrap(),
        Some(TunnelMsg::Welcome { .. })
    ));
    let host = "h".repeat(MAX_HOST_LEN);
    let t0 = Instant::now();
    let mut sent = 0u32;
    let outcome = timeout(CTRL_STALL * 3, async {
        loop {
            sent += 1;
            if tx.send(&open(sent, &host)).await.is_err() {
                return t0.elapsed();
            }
        }
    })
    .await;
    let cut_off = outcome.expect("the server never stopped taking requests it could not answer");
    assert!(
        cut_off < CTRL_STALL * 2,
        "cut off only after {cut_off:?} and {sent} requests"
    );
}
