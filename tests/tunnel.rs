//! End-to-end tunnels over loopback: `-L` and `-R` forwards with one and
//! several connections per stream, permits, and aborts.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;

use mjolnir::keys::{AuthorizedKey, KeyOption};
use mjolnir::tunnel::{
    ClientConfig, ForwardSpec, Permits, Policy, ServerConfig, TunnelClient, TunnelServer,
};
use mjolnir::{Cipher, PrivateKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(30);

/// A target that echoes each connection's bytes back as they arrive and
/// half-closes when its input ends.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                tokio::io::copy(&mut r, &mut w).await.unwrap();
                w.shutdown().await.unwrap();
            });
        }
    });
    addr
}

struct Setup {
    client_key: PrivateKey,
    server: SocketAddr,
    server_key: mjolnir::PublicKey,
    _server: JoinHandle<()>,
}

async fn server(
    permits: Permits,
    entries: impl FnOnce(&PrivateKey) -> Vec<AuthorizedKey>,
) -> Setup {
    let client_key = PrivateKey::generate();
    let policy = Policy::new(&entries(&client_key), permits).unwrap();
    let server = TunnelServer::bind(ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        key: PrivateKey::generate(),
        policy,
        verbose: true,
    })
    .await
    .unwrap();
    let (addr, key) = (server.local_addr(), server.public_key());
    let handle = tokio::spawn(async move {
        server.run().await.unwrap();
    });
    Setup {
        client_key,
        server: addr,
        server_key: key,
        _server: handle,
    }
}

fn plain(key: &PrivateKey) -> Vec<AuthorizedKey> {
    vec![AuthorizedKey {
        key: key.public_key(),
        options: vec![],
    }]
}

fn permits(open: &[&str], listen: &[&str]) -> Permits {
    Permits {
        open: open.iter().map(|p| p.parse().unwrap()).collect(),
        listen: listen.iter().map(|p| p.parse().unwrap()).collect(),
    }
}

fn client_cfg(setup: &Setup, conns: u32, local: &[String], remote: &[String]) -> ClientConfig {
    ClientConfig {
        addr: setup.server.to_string(),
        key: setup.client_key.clone(),
        peer: setup.server_key,
        cipher: Cipher::Aes256Gcm,
        conns,
        local: local.iter().map(|s| s.parse().unwrap()).collect(),
        remote: remote.iter().map(|s| s.parse().unwrap()).collect(),
        verbose: true,
    }
}

/// Sends `data`, half-closes, and returns everything read back.
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
    let (written, got) = tokio::join!(write, read);
    written?;
    got
}

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2654435761) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_forward_carries_streams_with_one_and_many_connections() {
    let echo = echo_server().await;
    let setup = server(
        permits(&[&format!("127.0.0.1:{}", echo.port())], &[]),
        plain,
    )
    .await;
    for conns in [1, 4] {
        let spec = format!("127.0.0.1:0:127.0.0.1:{}", echo.port());
        let client = TunnelClient::connect(client_cfg(&setup, conns, &[spec], &[]))
            .await
            .unwrap();
        let local = client.local_addrs()[0];
        let run = tokio::spawn(client.run());
        let data = pattern(12 << 20, conns);
        let got = timeout(LIMIT, round_trip(local, &data))
            .await
            .unwrap()
            .unwrap();
        assert!(got == data, "{conns} connections: echo differs");
        // Small interactive exchanges on a second stream.
        let mut s = TcpStream::connect(local).await.unwrap();
        for i in 0..20u8 {
            s.write_all(&[i; 3]).await.unwrap();
            let mut back = [0u8; 3];
            timeout(LIMIT, s.read_exact(&mut back))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(back, [i; 3]);
        }
        run.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_striped_streams() {
    let echo = echo_server().await;
    let setup = server(permits(&["127.0.0.1:*"], &[]), plain).await;
    let spec = format!("0:127.0.0.1:{}", echo.port());
    let client = TunnelClient::connect(client_cfg(&setup, 3, &[spec], &[]))
        .await
        .unwrap();
    let local = client.local_addrs()[0];
    let run = tokio::spawn(client.run());
    let streams: Vec<_> = (0..16)
        .map(|i| {
            tokio::spawn(async move {
                let data = pattern((256 << 10) + i * 1000, i as u32);
                let got = round_trip(local, &data).await.unwrap();
                assert!(got == data, "stream {i} differs");
            })
        })
        .collect();
    for s in streams {
        timeout(LIMIT, s).await.unwrap().unwrap();
    }
    run.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_forward_listens_on_the_server() {
    let echo = echo_server().await;
    let setup = server(permits(&[], &["127.0.0.1:*"]), plain).await;
    for conns in [1, 5] {
        let spec = format!("127.0.0.1:0:127.0.0.1:{}", echo.port());
        let client = TunnelClient::connect(client_cfg(&setup, conns, &[], &[spec]))
            .await
            .unwrap();
        let remote: SocketAddr = client.remote_addrs()[0].parse().unwrap();
        let run = tokio::spawn(client.run());
        let data = pattern(6 << 20, 7 + conns);
        let got = timeout(LIMIT, round_trip(remote, &data))
            .await
            .unwrap()
            .unwrap();
        assert!(got == data, "{conns} connections: echo differs");
        run.abort();
        // The listener goes away with the session.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(TcpStream::connect(remote).await.is_err());
    }
}

/// A connection that is refused must look like a failure to the app: reset
/// or closed, never a hang.
async fn expect_refused(local: SocketAddr) {
    // The reset can come before `connect` returns.
    let mut s = match TcpStream::connect(local).await {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::ConnectionReset => return,
        Err(e) => panic!("connecting to the forward: {e}"),
    };
    let _ = s.write_all(b"hello").await;
    let mut buf = [0u8; 16];
    match timeout(LIMIT, s.read(&mut buf)).await.unwrap() {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("read {n} bytes through a refused stream"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn targets_and_listeners_need_a_permit() {
    let echo = echo_server().await;
    let setup = server(permits(&["example.invalid:1"], &["127.0.0.1:1"]), plain).await;
    let spec = format!("127.0.0.1:0:127.0.0.1:{}", echo.port());
    let client = TunnelClient::connect(client_cfg(&setup, 2, std::slice::from_ref(&spec), &[]))
        .await
        .unwrap();
    let local = client.local_addrs()[0];
    let run = tokio::spawn(client.run());
    expect_refused(local).await;
    run.abort();
    let err = TunnelClient::connect(client_cfg(&setup, 1, &[], &[spec]))
        .await
        .err()
        .expect("an unpermitted -R must fail");
    assert!(format!("{err:#}").contains("not permitted"), "{err:#}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_key_options_replace_the_server_defaults() {
    let echo = echo_server().await;
    let allowed = format!("127.0.0.1:{}", echo.port());
    // The default would allow everything; the key's own option allows only
    // listening, so opening the echo target is refused.
    let setup = server(permits(&["*"], &["*"]), |k| {
        vec![AuthorizedKey {
            key: k.public_key(),
            options: vec![KeyOption::PermitListen("127.0.0.1:*".into())],
        }]
    })
    .await;
    let spec = format!("127.0.0.1:0:{allowed}");
    let client = TunnelClient::connect(client_cfg(
        &setup,
        1,
        std::slice::from_ref(&spec),
        std::slice::from_ref(&spec),
    ))
    .await
    .unwrap();
    let local = client.local_addrs()[0];
    let remote: SocketAddr = client.remote_addrs()[0].parse().unwrap();
    let run = tokio::spawn(client.run());
    expect_refused(local).await;
    let got = timeout(LIMIT, round_trip(remote, b"ok"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"ok");
    run.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthorized_and_mispinned_clients_are_rejected() {
    let setup = server(permits(&["*"], &[]), |_| {
        vec![AuthorizedKey {
            key: PrivateKey::generate().public_key(),
            options: vec![],
        }]
    })
    .await;
    let err = TunnelClient::connect(client_cfg(&setup, 1, &[], &[]))
        .await
        .err()
        .unwrap();
    assert!(
        format!("{err:#}").contains("rejected the handshake"),
        "{err:#}"
    );
    let mut cfg = client_cfg(&setup, 1, &[], &[]);
    cfg.peer = PrivateKey::generate().public_key();
    let err = TunnelClient::connect(cfg).await.err().unwrap();
    assert!(
        format!("{err:#}").contains("rejected the handshake"),
        "{err:#}"
    );
}

/// A target that sends `n` bytes and then resets its connection.
async fn resetting_server(n: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                s.write_all(&pattern(n, 3)).await.unwrap();
                tokio::time::sleep(Duration::from_millis(300)).await;
                socket2::SockRef::from(&s)
                    .set_linger(Some(Duration::ZERO))
                    .unwrap();
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reset_target_resets_the_local_connection_instead_of_ending_it() {
    let target = resetting_server(1 << 20).await;
    let setup = server(permits(&["127.0.0.1:*"], &[]), plain).await;
    for conns in [1, 3] {
        let spec = format!("127.0.0.1:0:127.0.0.1:{}", target.port());
        let client = TunnelClient::connect(client_cfg(&setup, conns, &[spec], &[]))
            .await
            .unwrap();
        let local = client.local_addrs()[0];
        let run = tokio::spawn(client.run());
        let mut s = TcpStream::connect(local).await.unwrap();
        let mut got = Vec::new();
        let err = timeout(LIMIT, s.read_to_end(&mut got))
            .await
            .unwrap()
            .expect_err("a cut-off stream must not end cleanly");
        assert_eq!(
            err.kind(),
            ErrorKind::ConnectionReset,
            "{conns} connections"
        );
        assert!(got.len() <= 1 << 20);
        run.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn half_close_reaches_the_target_and_the_reply_comes_back() {
    // Reads everything, then answers with its length.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut all = Vec::new();
        s.read_to_end(&mut all).await.unwrap();
        s.write_all(all.len().to_string().as_bytes()).await.unwrap();
    });
    let setup = server(permits(&[], &["127.0.0.1:*"]), plain).await;
    let spec = format!("127.0.0.1:0:127.0.0.1:{}", target.port());
    let client = TunnelClient::connect(client_cfg(&setup, 2, &[], &[spec]))
        .await
        .unwrap();
    let remote: SocketAddr = client.remote_addrs()[0].parse().unwrap();
    let run = tokio::spawn(client.run());
    let got = timeout(LIMIT, round_trip(remote, &pattern(300_001, 1)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"300001");
    run.abort();
}

#[test]
fn forward_specs_parse_like_ssh() {
    let spec: ForwardSpec = "2222:host:22".parse().unwrap();
    assert_eq!(spec.to_string(), "127.0.0.1:2222 -> host:22");
}

/// A target that greets each connection and then keeps it open, silent.
async fn holding_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"hi").await.unwrap();
            held.push(s);
        }
    });
    addr
}

/// Reads the greeting, then expects a reset once `end` has run.
async fn expect_reset_after(mut s: TcpStream, end: impl std::future::Future<Output = ()>) {
    let mut hi = [0u8; 2];
    timeout(LIMIT, s.read_exact(&mut hi))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&hi, b"hi");
    end.await;
    let mut rest = Vec::new();
    let err = timeout(LIMIT, s.read_to_end(&mut rest))
        .await
        .unwrap()
        .expect_err("a stream cut off with its session must not end cleanly");
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopping_or_losing_the_client_resets_its_streams() {
    let target = holding_server().await;
    let setup = server(permits(&["127.0.0.1:*"], &[]), plain).await;
    let spec = format!("127.0.0.1:0:127.0.0.1:{}", target.port());
    for conns in [1, 2] {
        // A clean stop through `run_until`.
        let client =
            TunnelClient::connect(client_cfg(&setup, conns, std::slice::from_ref(&spec), &[]))
                .await
                .unwrap();
        let local = client.local_addrs()[0];
        let stop = std::sync::Arc::new(tokio::sync::Notify::new());
        let run = tokio::spawn({
            let stop = stop.clone();
            client.run_until(async move { stop.notified().await })
        });
        let s = TcpStream::connect(local).await.unwrap();
        expect_reset_after(s, async {
            stop.notify_one();
            run.await.unwrap().unwrap();
        })
        .await;
        // The run task simply dropped.
        let client =
            TunnelClient::connect(client_cfg(&setup, conns, std::slice::from_ref(&spec), &[]))
                .await
                .unwrap();
        let local = client.local_addrs()[0];
        let run = tokio::spawn(client.run());
        let s = TcpStream::connect(local).await.unwrap();
        expect_reset_after(s, async { run.abort() }).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopping_the_server_resets_its_streams() {
    let target = holding_server().await;
    let client_key = PrivateKey::generate();
    let server = TunnelServer::bind(ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        key: PrivateKey::generate(),
        policy: Policy::new(&plain(&client_key), permits(&[], &["127.0.0.1:*"])).unwrap(),
        verbose: true,
    })
    .await
    .unwrap();
    let cfg = ClientConfig {
        addr: server.local_addr().to_string(),
        key: client_key,
        peer: server.public_key(),
        cipher: Cipher::ChaCha20Poly1305,
        conns: 2,
        local: vec![],
        remote: vec![
            format!("127.0.0.1:0:127.0.0.1:{}", target.port())
                .parse()
                .unwrap(),
        ],
        verbose: true,
    };
    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let serving = tokio::spawn({
        let stop = stop.clone();
        server.run_until(async move { stop.notified().await })
    });
    let client = TunnelClient::connect(cfg).await.unwrap();
    let remote: SocketAddr = client.remote_addrs()[0].parse().unwrap();
    let run = tokio::spawn(client.run());
    let s = TcpStream::connect(remote).await.unwrap();
    expect_reset_after(s, async {
        stop.notify_one();
        timeout(LIMIT, serving).await.unwrap().unwrap().unwrap();
    })
    .await;
    // The client notices that its session is gone.
    let ended = timeout(LIMIT, run).await.unwrap().unwrap();
    assert!(ended.is_err());
}

/// A target with nothing to say: it half-closes at once, then reads
/// slowly, and reports how many bytes it got and how its input ended.
async fn slow_half_closing_target() -> (
    SocketAddr,
    tokio::sync::mpsc::Receiver<Result<usize, String>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (report, reports) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let report = report.clone();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                w.shutdown().await.unwrap();
                let mut buf = vec![0u8; 64 << 10];
                let mut n = 0;
                let outcome = loop {
                    match r.read(&mut buf).await {
                        Ok(0) => break Ok(n),
                        Ok(k) => n += k,
                        Err(e) => break Err(format!("{e} after {n} bytes")),
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                };
                let _ = report.send(outcome).await;
            });
        }
    });
    (addr, reports)
}

/// An upload as `-W` does it, to a target that answers nothing and reads
/// slowly: when the client reports success, the target has every byte,
/// and closing the session afterwards does not cut the stream off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stdio_upload_is_delivered_in_full_before_the_client_reports_success() {
    let (target, mut reports) = slow_half_closing_target().await;
    let setup = server(permits(&["127.0.0.1:*"], &[]), plain).await;
    for conns in [1, 4] {
        let client = TunnelClient::connect(client_cfg(&setup, conns, &[], &[]))
            .await
            .unwrap();
        let (mut app, pump_end) = tokio::io::duplex(1 << 16);
        let (r, w) = tokio::io::split(pump_end);
        let target_hp = format!("127.0.0.1:{}", target.port()).parse().unwrap();
        let carried = tokio::spawn(client.carry(target_hp, r, w));
        let data = pattern(8 << 20, conns);
        app.write_all(&data).await.unwrap();
        app.shutdown().await.unwrap();
        let mut back = Vec::new();
        app.read_to_end(&mut back).await.unwrap();
        assert!(back.is_empty());
        let traffic = timeout(LIMIT, carried).await.unwrap().unwrap().unwrap();
        assert_eq!(traffic.sent, data.len() as u64, "{conns} connections");
        // The session is over; the target must still end up with all of it.
        let got = timeout(LIMIT, reports.recv()).await.unwrap().unwrap();
        assert_eq!(got, Ok(data.len()), "{conns} connections");
    }
}

/// `mjolnir tunnel -W` as a subprocess, with its stdin held open: when the
/// target ends, the reader of its stdout must see the end at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_closes_stdout_when_the_target_ends() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"hello\n").await.unwrap();
        }
    });
    let setup = server(permits(&["127.0.0.1:*"], &[]), plain).await;
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("client.key");
    setup.client_key.save(&key_path).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mjolnir"))
        .arg("tunnel")
        .arg(setup.server.to_string())
        .arg("--key")
        .arg(&key_path)
        .arg("--peer")
        .arg(setup.server_key.to_string())
        .arg("-W")
        .arg(format!("127.0.0.1:{}", target.port()))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let output = tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut stdout, &mut out).map(|_| out)
    });
    let out = timeout(Duration::from_secs(10), output)
        .await
        .expect("stdout must end when the target ends, not when stdin does")
        .unwrap()
        .unwrap();
    assert_eq!(out, b"hello\n");
    drop(stdin);
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success(), "{status}");
}
