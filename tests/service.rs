//! Installs, runs, and removes a real Windows service. That needs an
//! elevated process, which GitHub's Windows runners are; anywhere else the
//! test says it was skipped and passes.
#![cfg(windows)]

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use mjolnir::{Cipher, PrivateKey, Progress, SendConfig};

const BIN: &str = env!("CARGO_BIN_EXE_mjolnir");

fn mjolnir(exe: &Path, dir: &Path, args: &[&str]) -> Output {
    Command::new(exe)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn icacls(path: &Path, args: &[&str]) {
    let status = Command::new("icacls")
        .arg(path)
        .args(args)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "icacls {path:?} {args:?}");
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

/// Removes the service and the test's folder however the test ends. The
/// receiver's staging folder is SYSTEM's alone, so ownership is taken
/// back first.
struct Cleanup<'a> {
    name: &'a str,
    base: &'a Path,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        let _ = Command::new(BIN)
            .args(["service", "uninstall", self.name])
            .output();
        let quiet = |cmd: &mut Command| cmd.stdout(Stdio::null()).stderr(Stdio::null()).status();
        let _ = quiet(
            Command::new("takeown")
                .arg("/F")
                .arg(self.base)
                .args(["/R", "/A", "/D", "Y"]),
        );
        let _ = quiet(Command::new("icacls").arg(self.base).args([
            "/grant",
            "*S-1-5-32-544:(OI)(CI)F",
            "/T",
            "/C",
            "/Q",
        ]));
        // The service's process may still be exiting and holding its binary.
        for _ in 0..50 {
            if fs::remove_dir_all(self.base).is_ok() || !self.base.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
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
    // Under ProgramData so that only administrators can change it once
    // `keygen --system` creates it, with spaces in every path the service
    // command line carries.
    let base = PathBuf::from(std::env::var_os("ProgramData").unwrap())
        .join(format!("mjolnir test {}", std::process::id()));
    let name = format!("test-{}", std::process::id());
    let _cleanup = Cleanup {
        name: &name,
        base: &base,
    };
    let service = format!("mjolnir-{name}");
    let bin = Path::new(BIN);
    let here = std::env::temp_dir();

    let out = mjolnir(
        bin,
        &here,
        &[
            "keygen",
            "--system",
            "--out",
            base.join("recv.key").to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let receiver_key = text(&out.stdout).trim().to_owned();
    let out = mjolnir(bin, &base, &["pubkey", "--key", "recv.key"]);
    assert_eq!(
        text(&out.stdout).trim(),
        receiver_key,
        "{}",
        text(&out.stderr)
    );
    // Copied rather than run from target, which other accounts may change.
    let exe = base.join(r"bin\mjolnir.exe");
    fs::create_dir(base.join("bin")).unwrap();
    fs::copy(BIN, &exe).unwrap();

    let sender = PrivateKey::generate();
    fs::write(
        base.join("senders.txt"),
        format!("{}\n", sender.public_key()),
    )
    .unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let listen = format!("127.0.0.1:{port}");
    let install = |exe: &Path, key: &str| {
        mjolnir(
            exe,
            &base,
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
                key,
                "--authorized",
                "senders.txt",
                "--listen",
                &listen,
                "--out",
                "in coming",
            ],
        )
    };
    let refused = |out: Output, says: &[&str]| {
        let err = text(&out.stderr);
        assert!(!out.status.success(), "installed: {}", text(&out.stdout));
        for s in says {
            assert!(err.contains(s), "{s:?} not in {err}");
        }
    };

    let loose = base.join(r"loose\mjolnir.exe");
    fs::create_dir(base.join("loose")).unwrap();
    icacls(&base.join("loose"), &["/grant", "*S-1-1-0:(OI)(CI)M"]);
    fs::copy(BIN, &loose).unwrap();
    refused(
        install(&loose, "recv.key"),
        &["Program Files", "install.ps1", "S-1-1-0"],
    );

    let out = mjolnir(bin, &base, &["keygen", "--out", "user.key"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    refused(
        install(&exe, "user.key"),
        &["LocalSystem", "keygen --system", "icacls"],
    );

    icacls(&base.join("senders.txt"), &["/grant", "*S-1-1-0:W"]);
    refused(
        install(&exe, "recv.key"),
        &["authorized keys file", "S-1-1-0"],
    );
    icacls(&base.join("senders.txt"), &["/remove:g", "*S-1-1-0"]);

    let out = install(&exe, "recv.key");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = mjolnir(&exe, &base, &["service", "start", &name]);
    assert!(out.status.success(), "{}", text(&out.stderr));

    let log = base.join(r"log dir\service.log");
    let read_log = || fs::read_to_string(&log).unwrap_or_default();
    wait_for("the listening line", || {
        read_log().contains(&format!("listening on {listen}"))
    });
    let out = mjolnir(&exe, &base, &["service", "status", &name]);
    let status = text(&out.stdout);
    for line in [
        format!("{service}: running, PID "),
        format!(
            "command: mjolnir recv --keep-listening --key recv.key --authorized senders.txt \
             --listen {listen} --out \"in coming\""
        ),
        format!("directory: {}", base.display()),
        format!("log: {}", log.display()),
    ] {
        assert!(status.contains(&line), "{line:?} not in\n{status}");
    }

    fs::write(base.join("hello.txt"), b"hello, service").unwrap();
    mjolnir::send(
        SendConfig {
            addr: listen.clone(),
            key: sender,
            peer: receiver_key.parse().unwrap(),
            connections: 2,
            chunk_size: 64 << 10,
            cipher: Cipher::default(),
            threads: 1,
            paths: vec![base.join("hello.txt")],
            hash: false,
            preserve: Default::default(),
            follow_symlinks: true,
        },
        Arc::new(Progress::default()),
    )
    .unwrap();
    assert_eq!(
        fs::read(base.join(r"in coming\hello.txt")).unwrap(),
        b"hello, service"
    );
    wait_for("the summary", || read_log().contains("received 14 bytes"));

    let out = mjolnir(&exe, &base, &["service", "stop", &name]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let log = read_log();
    for line in [
        format!("service {service} starting in {}", base.display()),
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
    let out = mjolnir(&exe, &base, &["service", "status", &name]);
    assert!(text(&out.stdout).contains(&format!("{service}: stopped")));

    let out = mjolnir(&exe, &base, &["service", "uninstall", &name]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = mjolnir(&exe, &base, &["service", "status", &name]);
    assert!(text(&out.stderr).contains("there is no service"));
}
