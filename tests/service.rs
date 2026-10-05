//! Installs, runs, and removes a real Windows service. That needs an
//! elevated process, which GitHub's Windows runners are; anywhere else the
//! test says it was skipped and passes.
#![cfg(windows)]

use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use mjolnir::{Cipher, PrivateKey, Progress, SendConfig};

const BIN: &str = env!("CARGO_BIN_EXE_mjolnir");

fn mjolnir(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0;
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Removes the service however the test ends.
struct Uninstall<'a>(&'a str);

impl Drop for Uninstall<'_> {
    fn drop(&mut self) {
        let _ = Command::new(BIN)
            .args(["service", "uninstall", self.0])
            .output();
    }
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn recv_runs_as_a_service() {
    if !elevated() {
        eprintln!("skipped: installing a service needs an elevated process");
        return;
    }
    // Spaces in every path the service command line carries.
    let dir = tempfile::Builder::new()
        .prefix("mjolnir service ")
        .tempdir()
        .unwrap();
    let dir = dir.path();
    let name = format!("test-{}", std::process::id());
    let service = format!("mjolnir-{name}");
    let out = mjolnir(dir, &["keygen", "--out", "recv.key"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let receiver_key = text(&out.stdout).trim().to_owned();
    let sender = PrivateKey::generate();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let listen = format!("127.0.0.1:{port}");
    let allow = sender.public_key().to_string();
    let install = || {
        mjolnir(
            dir,
            &[
                "service",
                "install",
                &name,
                "--manual",
                "--log",
                r"log dir\service.log",
                "--",
                "recv",
                "--keep-listening",
                "--key",
                "recv.key",
                "--allow",
                &allow,
                "--listen",
                &listen,
                "--out",
                "in coming",
            ],
        )
    };

    let out = install();
    let refusal = text(&out.stderr);
    assert!(
        !out.status.success() && refusal.contains("LocalSystem"),
        "{refusal}"
    );
    let user = refusal
        .split("/remove \"*")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("no fix in {refusal}"));
    let status = Command::new("icacls")
        .arg(dir.join("recv.key"))
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "/remove"])
        .arg(format!("*{user}"))
        .output()
        .unwrap()
        .status;
    assert!(status.success());

    let out = install();
    let _uninstall = Uninstall(&name);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = mjolnir(dir, &["service", "start", &name]);
    assert!(out.status.success(), "{}", text(&out.stderr));

    let log = dir.join(r"log dir\service.log");
    let read_log = || fs::read_to_string(&log).unwrap_or_default();
    wait_for("the listening line", || {
        read_log().contains(&format!("listening on {listen}"))
    });
    let out = mjolnir(dir, &["service", "status", &name]);
    let status = text(&out.stdout);
    for line in [
        format!("{service}: running, PID "),
        format!(
            "command: mjolnir recv --keep-listening --key recv.key --allow {allow} \
             --listen {listen} --out \"in coming\""
        ),
        format!("directory: {}", dir.display()),
        format!("log: {}", log.display()),
    ] {
        assert!(status.contains(&line), "{line:?} not in\n{status}");
    }

    fs::write(dir.join("hello.txt"), b"hello, service").unwrap();
    mjolnir::send(
        SendConfig {
            addr: listen.clone(),
            key: sender,
            peer: receiver_key.parse().unwrap(),
            connections: 2,
            chunk_size: 64 << 10,
            cipher: Cipher::Aes256Gcm,
            threads: 1,
            paths: vec![dir.join("hello.txt")],
            hash: false,
            preserve: Default::default(),
            follow_symlinks: true,
        },
        Arc::new(Progress::default()),
    )
    .unwrap();
    assert_eq!(
        fs::read(dir.join(r"in coming\hello.txt")).unwrap(),
        b"hello, service"
    );
    wait_for("the summary", || read_log().contains("received 14 bytes"));

    let out = mjolnir(dir, &["service", "stop", &name]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let log = read_log();
    for line in [
        format!("service {service} starting in {}", dir.display()),
        format!("listening on {listen}"),
        "received 14 bytes".to_owned(),
        "service stop requested, closing".to_owned(),
        "service stopped".to_owned(),
    ] {
        assert!(log.contains(&line), "{line:?} not in\n{log}");
    }
    for line in log.lines() {
        let stamp = line.split(' ').next().unwrap();
        assert!(stamp.len() == 20 && stamp.ends_with('Z'), "{line}");
    }
    let out = mjolnir(dir, &["service", "status", &name]);
    assert!(text(&out.stdout).contains(&format!("{service}: stopped")));

    let out = mjolnir(dir, &["service", "uninstall", &name]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = mjolnir(dir, &["service", "status", &name]);
    assert!(text(&out.stderr).contains("there is no service"));
}
