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

    pub fn url(&self) -> String {
        browser_url(self.addr, &self.token)
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
    println!("Mjolnir web UI: {url}");
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

/// The URL to open, with the access token in the fragment so it never
/// reaches the server's request line or a Referer header. An unspecified bind
/// address is opened through loopback.
fn browser_url(addr: SocketAddr, token: &str) -> String {
    let host = match addr {
        SocketAddr::V4(a) if a.ip().is_unspecified() => format!("127.0.0.1:{}", a.port()),
        SocketAddr::V6(a) if a.ip().is_unspecified() => format!("[::1]:{}", a.port()),
        a => a.to_string(),
    };
    format!("http://{host}/#token={token}")
}

/// NUL-terminated UTF-16, as Win32 wide-string parameters expect.
#[cfg(any(windows, test))]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Hands the URL to the shell's default handler directly, so no command
/// interpreter ever parses it.
#[cfg(windows)]
fn open_in_browser(url: &str) -> std::io::Result<()> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let (verb, file) = (wide("open"), wide(url));
    // SAFETY: both strings are NUL-terminated and outlive the call; the null
    // window, parameters, and directory pointers are documented as optional.
    let code = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // Values of 32 or less are error codes, per the ShellExecute docs.
    if code as usize > 32 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "ShellExecuteW failed with code {}",
            code as usize
        )))
    }
}

#[cfg(not(windows))]
fn open_in_browser(url: &str) -> std::io::Result<()> {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener)
        .arg(url)
        .spawn()
        .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn url_keeps_the_token_in_the_fragment() {
        let url = browser_url("127.0.0.1:7878".parse().unwrap(), TOKEN);
        assert_eq!(url, format!("http://127.0.0.1:7878/#token={TOKEN}"));
        let (_, fragment) = url.split_once('#').unwrap();
        assert_eq!(fragment, format!("token={TOKEN}"));
    }

    #[test]
    fn unspecified_binds_open_through_loopback() {
        for (bound, expected) in [
            ("0.0.0.0:7878", "http://127.0.0.1:7878/"),
            ("[::]:7878", "http://[::1]:7878/"),
            ("[::1]:9000", "http://[::1]:9000/"),
            ("192.168.1.20:7878", "http://192.168.1.20:7878/"),
        ] {
            let url = browser_url(bound.parse().unwrap(), TOKEN);
            assert_eq!(url, format!("{expected}#token={TOKEN}"), "{bound}");
        }
    }

    #[test]
    fn wide_string_round_trips_the_url_exactly() {
        let url = browser_url("127.0.0.1:7878".parse().unwrap(), TOKEN);
        let encoded = wide(&url);
        assert_eq!(encoded.last(), Some(&0));
        let decoded = String::from_utf16(&encoded[..encoded.len() - 1]).unwrap();
        assert_eq!(decoded, url);
    }

    #[test]
    fn new_tokens_are_128_bit_hex() {
        let token = new_token();
        assert_eq!(token.len(), 32);
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(token, new_token());
    }
}
