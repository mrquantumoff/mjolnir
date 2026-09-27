//! Local web control plane for managing transfers, served by `mjolnir serve`.
//! See docs/WEB.md for the security model and the API.

mod api;
mod fs;
mod http;
mod jobs;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, anyhow};

use crate::keys::PrivateKey;

const WORKERS: usize = 4;

pub struct ServeConfig {
    pub listen: SocketAddr,
    pub key: PrivateKey,
    pub key_path: PathBuf,
    pub open_browser: bool,
}

pub struct WebServer {
    server: tiny_http::Server,
    guard: http::Guard,
    app: api::App,
    addr: SocketAddr,
    token: String,
}

impl WebServer {
    pub fn bind(cfg: ServeConfig) -> Result<WebServer> {
        let server = tiny_http::Server::http(cfg.listen)
            .map_err(|e| anyhow!("binding the web UI to {}: {e}", cfg.listen))?;
        let addr = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| anyhow!("web UI is not bound to an IP address"))?;
        let token = new_token();
        Ok(WebServer {
            server,
            guard: http::Guard::new(token.clone(), addr),
            app: api::App::new(cfg.key, cfg.key_path),
            addr,
            token,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// The URL to open, with the access token in the fragment so it never
    /// reaches the server's request line or a Referer header.
    pub fn url(&self) -> String {
        let host = match self.addr {
            SocketAddr::V4(a) if a.ip().is_unspecified() => format!("127.0.0.1:{}", a.port()),
            SocketAddr::V6(a) if a.ip().is_unspecified() => format!("[::1]:{}", a.port()),
            a => a.to_string(),
        };
        format!("http://{host}/#token={}", self.token)
    }

    /// Serves requests on a few worker threads until the process exits.
    pub fn run(self) -> Result<()> {
        let shared = Arc::new(self);
        let workers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let s = Arc::clone(&shared);
                std::thread::spawn(move || {
                    while let Ok(req) = s.server.recv() {
                        http::handle(&s.guard, &s.app, req);
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().map_err(|_| anyhow!("web worker panicked"))?;
        }
        Ok(())
    }
}

pub fn serve(cfg: ServeConfig) -> Result<()> {
    let open_browser = cfg.open_browser;
    let server = WebServer::bind(cfg)?;
    let addr = server.local_addr();
    if !addr.ip().is_loopback() {
        eprintln!(
            "WARNING: the web UI is listening on {addr}, which is reachable from other hosts.\n\
             WARNING: anyone with the access token can read any file this user can and send it anywhere."
        );
    }
    let url = server.url();
    println!("mjolnir web UI: {url}");
    if open_browser && let Err(e) = open_in_browser(&url) {
        eprintln!("could not open a browser ({e}); open the URL above yourself");
    }
    server.run()
}

fn new_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS random number generator failed");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn open_in_browser(url: &str) -> std::io::Result<()> {
    let mut cmd = if cfg!(windows) {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else {
        std::process::Command::new("xdg-open")
    };
    cmd.arg(url).spawn().map(drop)
}
