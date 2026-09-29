//! Runs a copy of the built binary's `update` against a local server laid
//! out like GitHub's release URLs.
#![cfg(feature = "self-update")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use mjolnir::update::ASSET;
use sha2::{Digest, Sha256};

const BIN: &str = if cfg!(windows) {
    "mjolnir.exe"
} else {
    "mjolnir"
};

/// Serves `tag` as the latest release with `archive` as this platform's
/// asset and `sums` as its SHA256SUMS; returns the releases base URL.
fn serve(tag: &str, archive: Vec<u8>, sums: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/releases", listener.local_addr().unwrap());
    let latest = format!("{base}/tag/{tag}");
    let asset_path = format!("/releases/download/{tag}/{}", ASSET.unwrap_or_default());
    let sums_path = format!("/releases/download/{tag}/SHA256SUMS");
    let tag_path = format!("/releases/tag/{tag}");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
            }
            let mut parts = request.split_whitespace();
            let (method, path) = (parts.next().unwrap(), parts.next().unwrap());
            let (status, extra, body): (&str, String, &[u8]) = match path {
                "/releases/latest" => ("302 Found", format!("Location: {latest}\r\n"), b""),
                p if p == tag_path => ("200 OK", String::new(), b""),
                p if p == asset_path => ("200 OK", String::new(), &archive),
                p if p == sums_path => ("200 OK", String::new(), sums.as_bytes()),
                _ => ("404 Not Found", String::new(), b""),
            };
            let head = format!(
                "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            if method != "HEAD" {
                stream.write_all(body).unwrap();
            }
        }
    });
    base
}

fn tar() -> PathBuf {
    if cfg!(windows) {
        Path::new(&std::env::var_os("SystemRoot").unwrap()).join(r"System32\tar.exe")
    } else {
        "tar".into()
    }
}

/// An install directory holding a copy of the built binary, and a release
/// archive holding another copy. The copies are identical, since altering
/// a signed macOS binary stops it from running, so the tests tell them apart
/// by file identity instead.
struct Fixture {
    _dir: tempfile::TempDir,
    installed: PathBuf,
    archive: Vec<u8>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let installed = dir.path().join("install").join(BIN);
    std::fs::create_dir(installed.parent().unwrap()).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_mjolnir"), &installed).unwrap();

    let staging = dir.path().join("staging");
    std::fs::create_dir(&staging).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_mjolnir"), staging.join(BIN)).unwrap();
    let archive_path = dir.path().join(ASSET.unwrap());
    let flags = if cfg!(windows) { "-a -cf" } else { "-czf" };
    let status = Command::new(tar())
        .args(flags.split(' '))
        .arg(&archive_path)
        .arg("-C")
        .arg(&staging)
        .arg(BIN)
        .status()
        .unwrap();
    assert!(status.success(), "tar failed");
    let archive = std::fs::read(&archive_path).unwrap();
    Fixture {
        _dir: dir,
        installed,
        archive,
    }
}

fn sums_for(archive: &[u8]) -> String {
    let hash: String = Sha256::digest(archive)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{hash}  {}\n", ASSET.unwrap())
}

fn update(bin: &Path, base: &str, args: &[&str]) -> Output {
    Command::new(bin)
        .arg("update")
        .args(args)
        .env("MJOLNIR_RELEASES_URL", base)
        .output()
        .unwrap()
}

/// Changes when the file at `path` is replaced.
#[cfg(unix)]
fn file_id(path: &Path) -> u64 {
    std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(path).unwrap())
}

/// Not observable here; the `.old` file shows the swap on Windows instead.
#[cfg(windows)]
fn file_id(_: &Path) -> u64 {
    0
}

fn others_in_install_dir(installed: &Path) -> Vec<std::ffi::OsString> {
    std::fs::read_dir(installed.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|name| name != BIN)
        .collect()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn update_installs_a_newer_release() {
    if ASSET.is_none() {
        return;
    }
    let f = fixture();
    let base = serve("v99.0.0", f.archive.clone(), sums_for(&f.archive));
    let before = file_id(&f.installed);

    let out = update(&f.installed, &base, &["--check"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("v99.0.0 is available"),
        "{}",
        text(&out)
    );
    assert_eq!(file_id(&f.installed), before);
    assert!(others_in_install_dir(&f.installed).is_empty());

    let out = update(&f.installed, &base, &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("installed mjolnir "), "{}", text(&out));
    let leftovers = others_in_install_dir(&f.installed);
    if cfg!(windows) {
        assert_eq!(leftovers, ["mjolnir.exe.old"]);
        let out = Command::new(&f.installed)
            .arg("--version")
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(
            !f.installed.with_extension("exe.old").exists(),
            "the next run removes the old binary"
        );
    } else {
        assert_ne!(file_id(&f.installed), before, "the binary was replaced");
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
}

#[test]
fn update_refuses_an_archive_that_fails_its_checksum() {
    if ASSET.is_none() {
        return;
    }
    let f = fixture();
    let before = file_id(&f.installed);
    let base = serve("v99.0.0", f.archive.clone(), sums_for(b"something else"));
    let out = update(&f.installed, &base, &[]);
    assert!(!out.status.success());
    assert!(text(&out).contains("checksum mismatch"), "{}", text(&out));
    assert_eq!(file_id(&f.installed), before);
    assert!(others_in_install_dir(&f.installed).is_empty());
}

#[test]
fn update_leaves_the_current_version_alone() {
    let dir = tempfile::tempdir().unwrap();
    let installed = dir.path().join(BIN);
    std::fs::copy(env!("CARGO_BIN_EXE_mjolnir"), &installed).unwrap();
    let before = std::fs::read(&installed).unwrap();
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let base = serve(&tag, Vec::new(), String::new());
    let out = update(&installed, &base, &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("is up to date"), "{}", text(&out));
    assert_eq!(std::fs::read(&installed).unwrap(), before);
}
