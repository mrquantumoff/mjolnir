//! Tunnels: TCP port forwarding over mjolnir's authenticated sessions.
//!
//! A client ([`TunnelClient`]) holds one control connection to a server
//! ([`TunnelServer`]), authenticated with the same Noise IK handshake and
//! pinned keys as a file transfer. Every forwarded TCP connection becomes a
//! *stream* carried by its own K connections to the server: K = 1 is plain
//! `ssh -L`/`ssh -R` style forwarding, and K > 1 stripes one stream across
//! K connections, frame by frame, for long fat or per-connection throttled
//! links. The client always opens the connections, so only the server
//! needs to be reachable. The protocol is specified in `docs/TUNNEL.md`.
//!
//! Everything here runs on tokio; the CLI starts a runtime for the tunnel
//! commands only.

mod client;
mod proto;
mod pump;
mod server;
mod spec;

pub use client::{ClientConfig, TunnelClient};
pub use pump::Traffic;
pub use server::{ServerConfig, TunnelServer};
pub use spec::{DEFAULT_BIND, ForwardSpec, HostPort, Pattern, Permits, Policy};

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

/// The default port of `mjolnir tunnel-server`.
pub const DEFAULT_PORT: u16 = 7778;
/// Most connections one stream may use.
pub const MAX_CONNS: u32 = 32;
/// Stream ids the server picks (for `-R`) have this bit set; the client's
/// do not.
const SERVER_STREAM: u32 = 1 << 31;
/// Preamble plus Noise message 1, and a stream hello, must arrive within
/// this.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// After the handshake, the client's `Hello` must arrive within this.
const HELLO_DEADLINE: Duration = Duration::from_secs(10);
/// Connecting to a server, a forward target, or a `-R` destination.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a new stream waits for all of its connections.
const GATHER_WAIT: Duration = Duration::from_secs(15);

/// No Nagle delay (tunnels carry interactive traffic), and TCP keepalive so
/// a vanished peer is noticed even on an idle stream.
fn prepare(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(5));
    let _ = SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

/// Connects to the first of `addrs` that answers.
async fn connect_any(addrs: &[SocketAddr]) -> Result<TcpStream> {
    let mut last = anyhow!("no addresses to connect to");
    for addr in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                prepare(&s);
                return Ok(s);
            }
            Ok(Err(e)) => last = anyhow!(e).context(format!("connecting to {addr}")),
            Err(_) => last = anyhow!("connecting to {addr} timed out"),
        }
    }
    Err(last)
}

/// Connects to a forward's target by name, resolving it here.
async fn connect_target(target: &HostPort) -> Result<TcpStream> {
    let s = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    .map_err(|_| anyhow!("connecting to {target} timed out"))?
    .with_context(|| format!("connecting to {target}"))?;
    prepare(&s);
    Ok(s)
}

/// Short form of a byte count for log lines.
fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

fn connections(k: u32) -> String {
    if k == 1 {
        "1 connection".into()
    } else {
        format!("{k} connections")
    }
}
