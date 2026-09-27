//! Request admission (token, Host, Origin, body limits), static assets, and
//! response headers. Everything that reaches `api::route` has passed `admit`.

use std::io::Read;
use std::net::{IpAddr, SocketAddr};

use serde_json::Value;
use tiny_http::{Header, Method, Request, Response};

use super::api::{self, ApiError, App, Reply};

pub const MAX_BODY: usize = 1024 * 1024;

const CSP: &str = "default-src 'self'; connect-src 'self'; img-src 'self' data:; \
    style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'; \
    frame-ancestors 'none'";

const ASSETS: &[(&str, &str, &str)] = &[
    (
        "/",
        "text/html; charset=utf-8",
        include_str!("assets/index.html"),
    ),
    (
        "/app.js",
        "text/javascript; charset=utf-8",
        include_str!("assets/app.js"),
    ),
    (
        "/app.css",
        "text/css; charset=utf-8",
        include_str!("assets/app.css"),
    ),
];

/// Who may talk to the server: the per-run token, and the Host values that
/// name this server (anything else is a DNS-rebinding attempt).
pub struct Guard {
    token: String,
    bound: SocketAddr,
}

impl Guard {
    pub fn new(token: String, bound: SocketAddr) -> Self {
        Guard { token, bound }
    }

    fn host_allowed(&self, host: &str) -> bool {
        let Some((name, port)) = host.rsplit_once(':') else {
            return false;
        };
        if port.parse::<u16>().ok() != Some(self.bound.port()) {
            return false;
        }
        if name == "localhost" {
            return true;
        }
        let literal = name
            .strip_prefix('[')
            .and_then(|n| n.strip_suffix(']'))
            .unwrap_or(name);
        let Ok(ip) = literal.parse::<IpAddr>() else {
            return false;
        };
        // Only IP literals get this far, and a DNS-rebinding page can never put
        // one of those in Host, so any address of this machine is safe when
        // bound to the unspecified address.
        ip.is_loopback() || ip == self.bound.ip() || self.bound.ip().is_unspecified()
    }

    fn token_ok(&self, header: Option<&str>) -> bool {
        header
            .and_then(|h| h.strip_prefix("Bearer "))
            .is_some_and(|t| constant_time_eq(t.trim().as_bytes(), self.token.as_bytes()))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn header<'r>(req: &'r Request, name: &'static str) -> Option<&'r str> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

pub fn handle(guard: &Guard, app: &App, mut req: Request) {
    let reply = admit_and_route(guard, app, &mut req);
    let _ = req.respond(render(reply));
}

fn admit_and_route(guard: &Guard, app: &App, req: &mut Request) -> Result<Reply, ApiError> {
    let host = header(req, "Host").unwrap_or("");
    if !guard.host_allowed(host) {
        return Err(ApiError::new(403, None, "unrecognized Host header"));
    }
    let (path, query) = split_url(req.url());
    let method = req.method().clone();

    if !path.starts_with("/api/") {
        return match (&method, ASSETS.iter().find(|(p, _, _)| *p == path)) {
            (Method::Get | Method::Head, Some(&(_, mime, body))) => Ok(Reply::Asset { mime, body }),
            _ => Err(ApiError::not_found()),
        };
    }

    if !guard.token_ok(header(req, "Authorization")) {
        return Err(ApiError::new(401, None, "missing or wrong access token"));
    }

    let body = if method == Method::Get {
        Value::Null
    } else {
        let json = header(req, "Content-Type")
            .is_some_and(|ct| ct.split(';').next().unwrap_or("").trim() == "application/json");
        if !json {
            return Err(ApiError::new(
                403,
                None,
                "Content-Type must be application/json",
            ));
        }
        if header(req, "Origin").is_some_and(|o| o != format!("http://{host}")) {
            return Err(ApiError::new(403, None, "cross-origin request rejected"));
        }
        read_json(req)?
    };

    api::route(app, &method, &path, &query, body)
}

fn read_json(req: &mut Request) -> Result<Value, ApiError> {
    if req.body_length().is_some_and(|n| n > MAX_BODY) {
        return Err(too_large());
    }
    let mut buf = Vec::new();
    req.as_reader()
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| ApiError::new(400, None, format!("reading body: {e}")))?;
    if buf.len() > MAX_BODY {
        return Err(too_large());
    }
    if buf.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&buf).map_err(|e| ApiError::new(400, None, format!("invalid JSON: {e}")))
}

fn too_large() -> ApiError {
    ApiError::new(413, None, "request body exceeds 1 MiB")
}

fn split_url(url: &str) -> (String, Vec<(String, String)>) {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let pairs = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect();
    (percent_decode(path), pairs)
}

fn percent_decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        (b as char).to_digit(16).map(|d| d as u8)
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = (bytes[i] == b'%')
            .then(|| Some(hex(*bytes.get(i + 1)?)? << 4 | hex(*bytes.get(i + 2)?)?))
            .flatten();
        match escaped {
            Some(b) => {
                out.push(b);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn render(reply: Result<Reply, ApiError>) -> Response<std::io::Cursor<Vec<u8>>> {
    let (status, mime, body, is_html) = match reply {
        Ok(Reply::Asset { mime, body }) => (
            200,
            mime,
            body.as_bytes().to_vec(),
            mime.starts_with("text/html"),
        ),
        Ok(Reply::Json(value)) => (
            200,
            "application/json",
            value.to_string().into_bytes(),
            false,
        ),
        Ok(Reply::NoContent) => (204, "application/json", Vec::new(), false),
        Err(e) => (
            e.status,
            "application/json",
            e.body().to_string().into_bytes(),
            false,
        ),
    };
    let mut resp = Response::from_data(body)
        .with_status_code(status)
        .with_header(h("Content-Type", mime))
        .with_header(h("X-Content-Type-Options", "nosniff"))
        .with_header(h("Referrer-Policy", "no-referrer"))
        .with_header(h("Cache-Control", "no-store"));
    if is_html {
        resp = resp
            .with_header(h("Content-Security-Policy", CSP))
            .with_header(h("X-Frame-Options", "DENY"));
    }
    resp
}

fn h(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(bound: &str) -> Guard {
        Guard::new("t".into(), bound.parse().unwrap())
    }

    #[test]
    fn loopback_hosts_are_allowed() {
        let g = guard("127.0.0.1:7878");
        for host in ["127.0.0.1:7878", "localhost:7878", "[::1]:7878"] {
            assert!(g.host_allowed(host), "{host}");
        }
    }

    #[test]
    fn foreign_hosts_and_ports_are_rejected() {
        let g = guard("127.0.0.1:7878");
        for host in [
            "evil.com:7878",
            "127.0.0.1:80",
            "127.0.0.1",
            "",
            "10.0.0.5:7878",
        ] {
            assert!(!g.host_allowed(host), "{host}");
        }
    }

    #[test]
    fn explicit_listen_ip_is_allowed() {
        let g = guard("10.0.0.5:7878");
        assert!(g.host_allowed("10.0.0.5:7878"));
        assert!(!g.host_allowed("10.0.0.6:7878"));
        assert!(!g.host_allowed("gorynych.lan:7878"));
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("C%3A%5CUsers%5Cx"), "C:\\Users\\x");
        assert_eq!(percent_decode("a+b%2"), "a+b%2");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
        assert_eq!(percent_decode("%E2%9C%93"), "\u{2713}");
    }
}
