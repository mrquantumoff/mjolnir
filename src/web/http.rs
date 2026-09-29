//! A strict HTTP/1.1 server for the API, and request admission (token,
//! Host, Origin, body limits), static assets, and response headers.
//! Everything that reaches `api::route` has passed `admit`.
//!
//! The server is hand-rolled on `std` so that every limit is enforced at
//! the transport: the request head is capped at `MAX_HEAD` bytes, a body is
//! read only after the request is admitted and only up to `MAX_BODY`, each
//! phase has an absolute deadline, and a rejected request is answered and
//! closed without draining the body its `Content-Length` announced. One
//! request per connection: every response carries `Connection: close`.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::api::{self, ApiError, App, Reply};

pub const MAX_BODY: usize = 1024 * 1024;
/// Request line plus headers, CRLFs included.
const MAX_HEAD: usize = 16 * 1024;
/// The whole head must arrive within this, however slowly it trickles.
const HEAD_DEADLINE: Duration = Duration::from_secs(10);
/// An admitted body must arrive within this.
const BODY_DEADLINE: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// After the response, unread request bytes are discarded for at most this
/// long and this many bytes, so a client still sending its body sees the
/// response instead of a reset.
const LINGER: Duration = Duration::from_millis(500);
const LINGER_BYTES: usize = 2 * MAX_BODY;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Delete,
    Other,
}

impl Method {
    fn parse(s: &str) -> Method {
        match s {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "DELETE" => Method::Delete,
            _ => Method::Other,
        }
    }
}

/// A parsed request head. The body is read later, by [`Request::body`],
/// and only when the request has been admitted.
struct Request {
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
    /// Bytes read past the head, the start of the body.
    buffered: Vec<u8>,
    /// `Content-Length`, already checked to be a number.
    content_length: u64,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Why a request could not be read; each maps to a status.
enum ReadError {
    Io(io::Error),
    Malformed(&'static str),
    HeadTooLarge,
    BodyTooLarge,
}

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

/// Serves one request on `stream`, then closes it.
pub fn serve(guard: &Guard, app: &App, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let started = Instant::now();
    // `drain` is whether the client may still be sending: a body we did not
    // read, or the rest of a head we refused. Closing with unread input makes
    // TCP send a reset, and on macOS the reset can arrive before the client
    // has read the reply, so the reply is lost.
    let (reply, drain, head_only) = match read_head(&mut stream, started + HEAD_DEADLINE) {
        Ok(mut req) => {
            let reply = admit_and_route(guard, app, &mut stream, &mut req);
            let unread = req.content_length.saturating_sub(req.buffered.len() as u64);
            (reply, unread > 0, req.method == Method::Head)
        }
        Err(e) => (Err(status_of(e)), true, false),
    };
    let (head, body) = render(reply);
    let written = stream.write_all(&head).and_then(|()| {
        if head_only {
            Ok(())
        } else {
            stream.write_all(&body)
        }
    });
    if written.is_err() {
        return;
    }
    let _ = stream.shutdown(Shutdown::Write);
    if drain {
        linger(&mut stream);
    }
}

fn status_of(e: ReadError) -> ApiError {
    match e {
        ReadError::Io(e) => ApiError::new(400, None, format!("reading the request: {e}")),
        ReadError::Malformed(what) => {
            ApiError::new(400, None, format!("malformed request: {what}"))
        }
        ReadError::HeadTooLarge => ApiError::new(431, None, "request head exceeds 16 KiB"),
        ReadError::BodyTooLarge => too_large(),
    }
}

/// Reads and discards what the client is still sending, briefly and up to
/// `LINGER_BYTES`, then drops the socket.
fn linger(stream: &mut TcpStream) {
    let deadline = Instant::now() + LINGER;
    let mut scratch = [0u8; 8192];
    let mut total = 0;
    while total < LINGER_BYTES {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return;
        };
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            return;
        }
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => return,
            Ok(n) => total += n,
        }
    }
}

/// Reads until the blank line that ends the head, never past `MAX_HEAD`
/// bytes and never past `deadline`.
fn read_head(stream: &mut TcpStream, deadline: Instant) -> Result<Request, ReadError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(end) = find_head_end(&buf) {
            break end;
        }
        // One byte past the limit is read, so a head of exactly MAX_HEAD
        // bytes is still accepted, and anything longer is refused.
        let want = chunk.len().min(MAX_HEAD + 1 - buf.len());
        if want == 0 {
            return Err(ReadError::HeadTooLarge);
        }
        let n = read_before(stream, &mut chunk[..want], deadline)?;
        if n == 0 {
            return Err(ReadError::Malformed(
                "connection closed before the head ended",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let rest = buf.split_off(end + 4);
    buf.truncate(end);
    let head = std::str::from_utf8(&buf).map_err(|_| ReadError::Malformed("non-ASCII head"))?;
    if !head.is_ascii() {
        return Err(ReadError::Malformed("non-ASCII head"));
    }
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (Some(method), Some(url), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ReadError::Malformed("request line"));
    };
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(ReadError::Malformed("HTTP version"));
    }
    if !url.starts_with('/') || url.contains(|c: char| c.is_ascii_control() || c == ' ') {
        return Err(ReadError::Malformed("request target"));
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.contains('\r') || line.contains('\n') {
            return Err(ReadError::Malformed("bare CR in a header line"));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ReadError::Malformed("header line"));
        };
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(ReadError::Malformed("header name"));
        }
        headers.push((name.to_string(), value.trim().to_string()));
    }
    let content_length = content_length(&headers)?.unwrap_or_default();
    if headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("Transfer-Encoding"))
    {
        return Err(ReadError::Malformed("Transfer-Encoding is not supported"));
    }
    Ok(Request {
        method: Method::parse(method),
        url: url.to_string(),
        headers,
        buffered: rest,
        content_length,
    })
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// One `Content-Length`, a plain decimal; two that disagree, or one that
/// is not a number, are request smuggling shapes and are rejected.
fn content_length(headers: &[(String, String)]) -> Result<Option<u64>, ReadError> {
    let mut found = None;
    for (_, value) in headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("Content-Length"))
    {
        let n = value
            .parse::<u64>()
            .ok()
            .filter(|_| value.bytes().all(|b| b.is_ascii_digit()))
            .ok_or(ReadError::Malformed("Content-Length"))?;
        if found.is_some_and(|f| f != n) {
            return Err(ReadError::Malformed("conflicting Content-Length"));
        }
        found = Some(n);
    }
    Ok(found)
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// One read that gives up at `deadline`.
fn read_before(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<usize, ReadError> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| ReadError::Io(io::Error::new(ErrorKind::TimedOut, "deadline passed")))?;
    stream.set_read_timeout(Some(left)).map_err(ReadError::Io)?;
    loop {
        match stream.read(buf) {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(ReadError::Io(io::Error::new(
                    ErrorKind::TimedOut,
                    "deadline passed",
                )));
            }
            other => return other.map_err(ReadError::Io),
        }
    }
}

/// Reads the admitted body: exactly `Content-Length` bytes, at most
/// `MAX_BODY`, within `BODY_DEADLINE`. Nothing is read for a body over the
/// limit.
fn read_body(stream: &mut TcpStream, req: &mut Request) -> Result<Vec<u8>, ReadError> {
    if req.content_length > MAX_BODY as u64 {
        return Err(ReadError::BodyTooLarge);
    }
    let len = req.content_length as usize;
    let mut body = std::mem::take(&mut req.buffered);
    if body.len() > len {
        return Err(ReadError::Malformed("bytes past the body"));
    }
    let deadline = Instant::now() + BODY_DEADLINE;
    let mut chunk = [0u8; 8192];
    while body.len() < len {
        let want = (len - body.len()).min(chunk.len());
        let n = read_before(stream, &mut chunk[..want], deadline)?;
        if n == 0 {
            return Err(ReadError::Malformed("connection closed mid-body"));
        }
        body.extend_from_slice(&chunk[..n]);
    }
    // The body has been consumed; `serve` must not linger on it.
    req.content_length = 0;
    Ok(body)
}

fn admit_and_route(
    guard: &Guard,
    app: &App,
    stream: &mut TcpStream,
    req: &mut Request,
) -> Result<Reply, ApiError> {
    let host = req.header("Host").unwrap_or("").to_string();
    if !guard.host_allowed(&host) {
        return Err(ApiError::new(403, None, "unrecognized Host header"));
    }
    let (path, query) = split_url(&req.url);
    let method = req.method;

    if !path.starts_with("/api/") {
        return match (method, ASSETS.iter().find(|(p, _, _)| *p == path)) {
            (Method::Get | Method::Head, Some(&(_, mime, body))) => Ok(Reply::Asset { mime, body }),
            _ => Err(ApiError::not_found()),
        };
    }

    if !guard.token_ok(req.header("Authorization")) {
        return Err(ApiError::new(401, None, "missing or wrong access token"));
    }

    let body = if method == Method::Get {
        Value::Null
    } else {
        let json = req
            .header("Content-Type")
            .is_some_and(|ct| ct.split(';').next().unwrap_or("").trim() == "application/json");
        if !json {
            return Err(ApiError::new(
                403,
                None,
                "Content-Type must be application/json",
            ));
        }
        if req
            .header("Origin")
            .is_some_and(|o| o != format!("http://{host}"))
        {
            return Err(ApiError::new(403, None, "cross-origin request rejected"));
        }
        let bytes = read_body(stream, req).map_err(status_of)?;
        parse_json(&bytes)?
    };

    api::route(app, method, &path, &query, body)
}

fn parse_json(buf: &[u8]) -> Result<Value, ApiError> {
    if buf.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(buf).map_err(|e| ApiError::new(400, None, format!("invalid JSON: {e}")))
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

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    }
}

/// The response as `(head, body)` bytes; the head names the body's length.
fn render(reply: Result<Reply, ApiError>) -> (Vec<u8>, Vec<u8>) {
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
    let mut out = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\n\
         Connection: close\r\nX-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\nCache-Control: no-store\r\n",
        reason(status),
        body.len()
    )
    .into_bytes();
    if is_html {
        out.extend_from_slice(
            format!("Content-Security-Policy: {CSP}\r\nX-Frame-Options: DENY\r\n").as_bytes(),
        );
    }
    out.extend_from_slice(b"\r\n");
    (out, body)
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
        assert!(!g.host_allowed("mjolnir.lan:7878"));
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("C%3A%5CUsers%5Cx"), "C:\\Users\\x");
        assert_eq!(percent_decode("a+b%2"), "a+b%2");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
        assert_eq!(percent_decode("%E2%9C%93"), "\u{2713}");
    }

    #[test]
    fn content_length_must_be_one_plain_number() {
        let h = |values: &[&str]| -> Vec<(String, String)> {
            values
                .iter()
                .map(|v| ("Content-Length".to_string(), v.to_string()))
                .collect()
        };
        assert_eq!(content_length(&h(&["12"])).ok().flatten(), Some(12));
        assert_eq!(content_length(&h(&["12", "12"])).ok().flatten(), Some(12));
        assert_eq!(content_length(&h(&[])).ok().flatten(), None);
        for bad in [&["12", "13"][..], &["+12"], &["0x10"], &["-1"], &[""]] {
            assert!(content_length(&h(bad)).is_err(), "{bad:?}");
        }
    }
}
