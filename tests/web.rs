use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use mjolnir::keys::PrivateKey;
use mjolnir::web::{ServeConfig, WebServer};
use serde_json::{Value, json};

struct Ui {
    addr: SocketAddr,
    token: String,
    public_key: String,
}

fn start() -> Ui {
    let key = PrivateKey::generate();
    let public_key = key.public_key().to_string();
    let server = WebServer::bind(ServeConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        key,
        key_path: "test-key".into(),
        open_browser: false,
    })
    .unwrap();
    let ui = Ui {
        addr: server.local_addr(),
        token: server.token().to_string(),
        public_key,
    };
    std::thread::spawn(move || server.run());
    ui
}

struct Response {
    status: u16,
    head: String,
    body: Value,
}

/// A minimal HTTP/1.1 client; `headers` replaces the defaults it names.
fn raw(ui: &Ui, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
    let mut defaults = vec![
        ("Host".to_string(), ui.addr.to_string()),
        ("Authorization".to_string(), format!("Bearer {}", ui.token)),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    for (name, value) in headers {
        defaults.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        if !value.is_empty() {
            defaults.push((name.to_string(), value.to_string()));
        }
    }
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (n, v) in defaults {
        req.push_str(&format!("{n}: {v}\r\n"));
    }
    req.push_str("\r\n");

    let mut stream = TcpStream::connect(ui.addr).unwrap();
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let body = if body.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body).unwrap_or(Value::String(body.to_string()))
    };
    Response {
        status,
        head: head.to_string(),
        body,
    }
}

fn encode(text: &str) -> String {
    text.bytes().map(|b| format!("%{b:02X}")).collect()
}

fn get(ui: &Ui, path: &str) -> Response {
    raw(ui, "GET", path, &[], b"")
}

fn post(ui: &Ui, path: &str, body: Value) -> Response {
    raw(ui, "POST", path, &[], body.to_string().as_bytes())
}

fn transfer(ui: &Ui, id: u64) -> Value {
    get(ui, "/api/transfers").body["transfers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("transfer {id} is gone"))
}

fn wait_until_ended(ui: &Ui, id: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let t = transfer(ui, id);
        if t["state"] != "running" {
            return t;
        }
        assert!(
            Instant::now() < deadline,
            "transfer {id} did not finish: {t}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn start_receiver(ui: &Ui, out_dir: &Path) -> (u64, String) {
    let r = post(
        ui,
        "/api/receive",
        json!({
            "listen": "127.0.0.1:0",
            "authorized": [ui.public_key],
            "out_dir": out_dir,
            "force": false,
        }),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let bound = r.body["bound_addr"].as_str().unwrap().to_string();
    assert_ne!(bound, "127.0.0.1:0");
    (r.body["id"].as_u64().unwrap(), bound)
}

#[test]
fn missing_token_is_401() {
    let ui = start();
    let r = raw(&ui, "GET", "/api/identity", &[("Authorization", "")], b"");
    assert_eq!(r.status, 401);
}

#[test]
fn wrong_token_is_401() {
    let ui = start();
    let wrong = format!("Bearer {}", "0".repeat(32));
    let r = raw(
        &ui,
        "GET",
        "/api/transfers",
        &[("Authorization", &wrong)],
        b"",
    );
    assert_eq!(r.status, 401);
}

#[test]
fn identity_returns_the_public_key() {
    let ui = start();
    let r = get(&ui, "/api/identity");
    assert_eq!(r.status, 200);
    assert_eq!(r.body["public_key"], ui.public_key);
    assert!(r.body["key_path"].as_str().unwrap().ends_with("test-key"));
}

#[test]
fn foreign_host_is_403_even_with_the_token() {
    let ui = start();
    let host = format!("attacker.example:{}", ui.addr.port());
    for path in ["/api/identity", "/"] {
        let r = raw(&ui, "GET", path, &[("Host", &host)], b"");
        assert_eq!(r.status, 403, "{path}");
    }
}

#[test]
fn cross_origin_post_is_403() {
    let ui = start();
    let body = json!({ "listen": "127.0.0.1:0", "authorized": [], "out_dir": "." }).to_string();
    let r = raw(
        &ui,
        "POST",
        "/api/receive",
        &[("Origin", "http://attacker.example")],
        body.as_bytes(),
    );
    assert_eq!(r.status, 403);
}

#[test]
fn non_json_post_is_403() {
    let ui = start();
    let r = raw(
        &ui,
        "POST",
        "/api/send",
        &[("Content-Type", "text/plain")],
        b"{}",
    );
    assert_eq!(r.status, 403);
}

#[test]
fn oversized_body_is_413() {
    let ui = start();
    let body = vec![b' '; 1024 * 1024 + 1];
    let r = raw(&ui, "POST", "/api/send", &[], &body);
    assert_eq!(r.status, 413);
}

#[test]
fn bad_peer_key_in_send_is_400_on_that_field() {
    let ui = start();
    let dir = tempfile::tempdir().unwrap();
    let r = post(
        &ui,
        "/api/send",
        json!({ "addr": "127.0.0.1:9", "peer": "not-a-key", "paths": [dir.path()] }),
    );
    assert_eq!(r.status, 400);
    assert_eq!(r.body["field"], "peer");
}

#[test]
fn out_of_range_send_options_are_400() {
    let ui = start();
    let dir = tempfile::tempdir().unwrap();
    for (field, value) in [
        ("connections", json!(0)),
        ("connections", json!(65)),
        ("chunk_size", json!(1024)),
        ("threads", json!(257)),
    ] {
        let mut body =
            json!({ "addr": "127.0.0.1:9", "peer": ui.public_key, "paths": [dir.path()] });
        body[field] = value;
        let r = post(&ui, "/api/send", body);
        assert_eq!(r.status, 400);
        assert_eq!(r.body["field"], field);
    }
}

#[test]
fn send_can_turn_off_following_links() {
    let ui = start();
    let dir = tempfile::tempdir().unwrap();
    let r = post(
        &ui,
        "/api/send",
        json!({ "addr": "127.0.0.1:9", "peer": ui.public_key, "paths": [dir.path()], "follow_symlinks": false }),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["spec"]["follow_symlinks"], false);
}

#[test]
fn malformed_preserve_is_400() {
    let ui = start();
    let dir = tempfile::tempdir().unwrap();
    let r = post(
        &ui,
        "/api/send",
        json!({ "addr": "127.0.0.1:9", "peer": ui.public_key, "paths": [dir.path()], "preserve": "yes" }),
    );
    assert_eq!(r.status, 400, "{}", r.body);
}

#[test]
fn receiver_apply_policy_defaults_off_and_is_echoed() {
    let ui = start();
    let out = tempfile::tempdir().unwrap();
    let (id, _) = start_receiver(&ui, out.path());
    assert_eq!(
        transfer(&ui, id)["spec"]["apply"],
        json!({ "allow_special_bits": false, "allow_owner": false })
    );
    let r = post(
        &ui,
        "/api/receive",
        json!({
            "listen": "127.0.0.1:0",
            "authorized": [ui.public_key],
            "out_dir": out.path(),
            "apply": { "allow_special_bits": true, "allow_owner": false },
        }),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["spec"]["apply"]["allow_special_bits"], true);
    for id in [id, r.body["id"].as_u64().unwrap()] {
        post(&ui, &format!("/api/transfers/{id}/cancel"), json!({}));
    }
}

#[test]
fn receiver_on_a_busy_port_is_400() {
    let ui = start();
    let dir = tempfile::tempdir().unwrap();
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let r = post(
        &ui,
        "/api/receive",
        json!({ "listen": busy.local_addr().unwrap(), "authorized": [ui.public_key], "out_dir": dir.path() }),
    );
    assert_eq!(r.status, 400);
    assert_eq!(r.body["field"], "listen");
}

#[test]
fn index_is_served_with_security_headers() {
    let ui = start();
    let r = raw(&ui, "GET", "/", &[("Authorization", "")], b"");
    assert_eq!(r.status, 200);
    let head = r.head.to_ascii_lowercase();
    assert!(
        head.contains("content-security-policy: default-src 'self'"),
        "{head}"
    );
    assert!(head.contains("x-content-type-options: nosniff"));
    assert!(head.contains("referrer-policy: no-referrer"));
    assert!(!head.contains("access-control-allow-origin"));
}

#[test]
fn fs_lists_a_directory_dirs_first() {
    let ui = start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
    std::fs::create_dir(dir.path().join("zdir")).unwrap();
    let path = dir.path().to_str().unwrap();
    let encoded = encode(path);
    let r = get(&ui, &format!("/api/fs?path={encoded}"));
    assert_eq!(r.status, 200, "{}", r.body);
    let entries = r.body["entries"].as_array().unwrap();
    let summary: Vec<_> = entries
        .iter()
        .map(|e| {
            (
                e["name"].as_str().unwrap(),
                e["is_dir"].as_bool().unwrap(),
                e["size"].clone(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![("zdir", true, Value::Null), ("a.txt", false, json!(5))]
    );
    assert!(r.body["parent"].is_string());
    assert!(!r.body["roots"].as_array().unwrap().is_empty());

    let missing = get(&ui, &format!("/api/fs?path={encoded}%2Fnope"));
    assert_eq!(missing.status, 400);
}

#[test]
fn send_a_directory_end_to_end() {
    let ui = start();
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let root = src.path().join("payload");
    std::fs::create_dir_all(root.join("nested/deeper")).unwrap();
    let files: Vec<(&str, Vec<u8>)> = vec![
        (
            "a.bin",
            (0..3_000_000u32).map(|i| (i * 7 % 251) as u8).collect(),
        ),
        ("nested/b.txt", b"hello from mjolnir\n".to_vec()),
        (
            "nested/deeper/c.bin",
            (0..70_000u32).map(|i| (i % 13) as u8).collect(),
        ),
        ("empty", Vec::new()),
    ];
    for (rel, data) in &files {
        std::fs::write(root.join(rel), data).unwrap();
    }

    let (recv_id, bound) = start_receiver(&ui, out.path());
    let r = post(
        &ui,
        "/api/send",
        json!({
            "addr": bound,
            "peer": ui.public_key,
            "paths": [root],
            "connections": 4,
            "chunk_size": 64 * 1024,
            "cipher": "ChaCha20Poly1305",
            "threads": 2,
            "hash": true,
            "preserve": { "perms": true, "times": true, "owner": false },
        }),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["kind"], "send");
    assert_eq!(r.body["spec"]["threads"], 2);
    assert_eq!(r.body["spec"]["preserve"]["times"], true);
    assert_eq!(r.body["spec"]["follow_symlinks"], true, "on by default");
    let send_id = r.body["id"].as_u64().unwrap();

    let sent = wait_until_ended(&ui, send_id);
    assert_eq!(sent["state"], "done", "{sent}");
    let received = wait_until_ended(&ui, recv_id);
    assert_eq!(received["state"], "done", "{received}");
    assert_eq!(received["report"]["files"], files.len());
    assert_eq!(received["report"]["verified"], true);
    assert_eq!(received["report"]["hashed"], true);
    assert_eq!(sent["report"]["hashed"], true);
    for side in [&sent, &received] {
        let times = &side["report"]["phase_times"];
        assert!(times["transfer_ms"].as_f64().unwrap() > 0.0, "{times}");
        for key in ["connect_ms", "verify_ms", "hash_ms", "finalize_ms"] {
            assert!(times[key].as_f64().is_some(), "{key} missing: {times}");
        }
    }
    let hashes = sent["report"]["file_hashes"].as_array().unwrap();
    assert_eq!(hashes.len(), files.len(), "{}", sent["report"]);
    assert!(
        hashes
            .iter()
            .all(|h| h["path"].is_string() && h["hash"].is_string())
    );
    assert_eq!(
        received["report"]["warnings"],
        json!([]),
        "{}",
        received["report"]
    );
    assert_eq!(received["report"]["duplicate_chunks"], 0);
    let total: usize = files.iter().map(|(_, d)| d.len()).sum();
    assert_eq!(sent["progress"]["bytes_done"], total);

    for (rel, data) in &files {
        let got = std::fs::read(out.path().join("payload").join(rel)).unwrap();
        assert!(got == *data, "{rel} differs");
    }

    let list = get(&ui, "/api/transfers").body;
    let ids: Vec<_> = list["transfers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].clone())
        .collect();
    assert_eq!(ids, vec![json!(send_id), json!(recv_id)], "newest first");

    let del = raw(
        &ui,
        "DELETE",
        &format!("/api/transfers/{send_id}"),
        &[],
        b"",
    );
    assert_eq!(del.status, 204);
    assert_eq!(
        get(&ui, "/api/transfers").body["transfers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn cancel_a_running_send() {
    let ui = start();
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let big = src.path().join("big.bin");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(2 << 30)
        .unwrap();

    let (recv_id, bound) = start_receiver(&ui, out.path());
    let r = post(
        &ui,
        "/api/send",
        json!({ "addr": bound, "peer": ui.public_key, "paths": [big], "connections": 1, "chunk_size": 4096 }),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let id = r.body["id"].as_u64().unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    while transfer(&ui, id)["progress"]["bytes_done"]
        .as_u64()
        .unwrap()
        == 0
    {
        assert!(Instant::now() < deadline, "send never started moving bytes");
        std::thread::sleep(Duration::from_millis(10));
    }

    let del = raw(&ui, "DELETE", &format!("/api/transfers/{id}"), &[], b"");
    assert_eq!(del.status, 409);

    let c = post(&ui, &format!("/api/transfers/{id}/cancel"), json!({}));
    assert_eq!(c.status, 200);
    let ended = wait_until_ended(&ui, id);
    assert_eq!(ended["state"], "cancelled", "{ended}");
    assert!(ended["progress"]["bytes_done"].as_u64().unwrap() < 2 << 30);

    let c = post(&ui, &format!("/api/transfers/{recv_id}/cancel"), json!({}));
    assert_eq!(c.status, 200);
    let receiver = wait_until_ended(&ui, recv_id);
    assert_eq!(receiver["state"], "cancelled", "{receiver}");

    let del = raw(&ui, "DELETE", &format!("/api/transfers/{id}"), &[], b"");
    assert_eq!(del.status, 204);
}

#[test]
fn cancel_an_idle_receiver() {
    let ui = start();
    let out = tempfile::tempdir().unwrap();
    let (id, _) = start_receiver(&ui, out.path());
    let c = post(&ui, &format!("/api/transfers/{id}/cancel"), json!({}));
    assert_eq!(c.status, 200);
    assert_eq!(wait_until_ended(&ui, id)["state"], "cancelled");
}

#[cfg(unix)]
fn non_unicode_name() -> std::ffi::OsString {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::OsStr::from_bytes(b"caf\xe9.bin").to_owned()
}

#[cfg(windows)]
fn non_unicode_name() -> std::ffi::OsString {
    use std::os::windows::ffi::OsStringExt;
    let mut wide: Vec<u16> = "caf".encode_utf16().collect();
    wide.push(0xD800);
    wide.extend(".bin".encode_utf16());
    std::ffi::OsString::from_wide(&wide)
}

#[test]
fn non_unicode_names_are_listed_but_must_be_sent_via_their_parent() {
    let ui = start();
    let dir = tempfile::tempdir().unwrap();
    let raw = dir.path().join(non_unicode_name());
    if std::fs::write(&raw, b"x").is_err() {
        eprintln!("this filesystem rejects non-UTF-8 names; skipping");
        return;
    }
    let listing = get(
        &ui,
        &format!("/api/fs?path={}", encode(dir.path().to_str().unwrap())),
    );
    assert_eq!(listing.status, 200, "{}", listing.body);
    let entry = &listing.body["entries"][0];
    assert_eq!(entry["name"], "caf\u{FFFD}.bin");
    assert!(entry["path"].is_null(), "{entry}");

    let lossy = dir.path().join("caf\u{FFFD}.bin");
    let r = post(
        &ui,
        "/api/send",
        json!({ "addr": "127.0.0.1:9", "peer": ui.public_key, "paths": [lossy] }),
    );
    assert_eq!(r.status, 400);
    assert_eq!(r.body["field"], "paths");
    let message = r.body["error"].as_str().unwrap();
    assert!(message.contains("parent folder"), "{message}");
}
