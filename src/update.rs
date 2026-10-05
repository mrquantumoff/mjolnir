//! `mjolnir update`: replace the running binary with the latest release.
//!
//! The latest tag comes from the redirect GitHub serves for
//! `releases/latest`, and the archive, `SHA256SUMS`, and `SHA256SUMS.sig`
//! from the public download URLs, so no API call, login, or token is
//! involved. `SHA256SUMS` must carry a valid signature by [`RELEASE_KEY`],
//! the archive must match its `SHA256SUMS` line, and the new binary must run
//! `--version`, before it takes the old one's place.
//!
//! Downloads go through the system's curl and unpacking through its tar.
//! Windows 10 and later ship both in System32.
//!
//! Built only with the `self-update` feature (on by default). Packagers
//! turn it off so the package manager stays in charge of the binary.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

/// Where releases are published. `MJOLNIR_RELEASES_URL` overrides it, for a
/// fork or a mirror with the same layout.
pub const RELEASES_URL: &str = "https://github.com/mrquantumoff/mjolnir/releases";

/// The ECDSA P-256 key that signs `SHA256SUMS` in every release, as base64
/// of its SubjectPublicKeyInfo DER. The install scripts carry the same
/// string. `MJOLNIR_RELEASE_KEY` overrides it, but only together with
/// `MJOLNIR_RELEASES_URL`, for a fork that signs its own releases.
pub const RELEASE_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfCWNtshHxuxy4XyVXfa/O62yS79tJXqzlChtlVlBGHkHoF470qqwhXnhR/tVxC2a6H/M7miFldxmAlr8R/G1BA==";

/// This platform's release archive, if releases include one.
pub const ASSET: Option<&str> = if cfg!(all(
    target_os = "linux",
    target_env = "gnu",
    target_arch = "x86_64"
)) {
    Some("mjolnir-x86_64-unknown-linux-gnu.tar.gz")
} else if cfg!(all(
    target_os = "linux",
    target_env = "gnu",
    target_arch = "aarch64"
)) {
    Some("mjolnir-aarch64-unknown-linux-gnu.tar.gz")
} else if cfg!(all(windows, target_env = "msvc", target_arch = "x86_64")) {
    Some("mjolnir-x86_64-pc-windows-msvc.zip")
} else if cfg!(all(windows, target_env = "msvc", target_arch = "aarch64")) {
    Some("mjolnir-aarch64-pc-windows-msvc.zip")
} else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
    Some("mjolnir-aarch64-apple-darwin.tar.gz")
} else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
    Some("mjolnir-x86_64-apple-darwin.tar.gz")
} else {
    None
};

const BIN: &str = if cfg!(windows) {
    "mjolnir.exe"
} else {
    "mjolnir"
};

pub enum Outcome {
    UpToDate { latest: String },
    Available { latest: String },
    Updated { version: String, path: PathBuf },
}

/// Checks `releases` for a newer version and, unless `check_only`, installs
/// it over the running executable. `key` takes the form of [`RELEASE_KEY`].
pub fn update(releases: &str, key: &str, check_only: bool) -> Result<Outcome> {
    let releases = releases.trim_end_matches('/');
    let key = parse_key(key).context("cannot read the release key")?;
    let latest = latest_tag(releases)?;
    if parse_version(&latest)? <= parse_version(env!("CARGO_PKG_VERSION"))? {
        return Ok(Outcome::UpToDate { latest });
    }
    if check_only {
        return Ok(Outcome::Available { latest });
    }
    let asset = ASSET.ok_or_else(|| {
        anyhow!("releases include no build for this platform; build {latest} from source")
    })?;
    let mut exe = std::env::current_exe().context("cannot locate the running executable")?;
    // macOS may report the path it was started by, which can be a symlink;
    // the rename must replace the file it points to, not the link.
    if cfg!(unix) {
        exe = fs::canonicalize(&exe)?;
    }

    let tmp = TempDir::new()?;
    let download = |name: &str| -> Result<PathBuf> {
        let path = tmp.0.join(name);
        let url = format!("{releases}/download/{latest}/{name}");
        curl(
            releases,
            &[
                OsStr::new("-L"),
                OsStr::new("-o"),
                path.as_os_str(),
                OsStr::new(&url),
            ],
        )
        .with_context(|| format!("cannot download {url}"))?;
        Ok(path)
    };
    let sums = fs::read(download("SHA256SUMS")?)?;
    let signature = fs::read(download("SHA256SUMS.sig")?)?;
    check_signature(&key, &sums, &signature)?;
    let sums = String::from_utf8(sums).context("SHA256SUMS is not text")?;
    let archive = download(asset)?;
    verify(&archive, asset, &sums)?;
    run(Command::new(system_tool("tar"))
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(&tmp.0)
        .arg(BIN))
    .with_context(|| format!("cannot unpack {asset}"))?;
    let version = replace(&exe, &tmp.0.join(BIN))?;
    Ok(Outcome::Updated { version, path: exe })
}

/// Reads the tag out of the redirect from `releases/latest`, which points at
/// `releases/tag/<tag>` once a release exists.
fn latest_tag(releases: &str) -> Result<String> {
    let url = format!("{releases}/latest");
    let out = curl(releases, &["-I", "-w", "\n%{redirect_url}", url.as_str()])
        .with_context(|| format!("cannot reach {url}"))?;
    let text = String::from_utf8_lossy(&out);
    text.lines()
        .last()
        .and_then(|location| location.rsplit_once("/tag/"))
        .map(|(_, tag)| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .ok_or_else(|| anyhow!("{releases} has no published release"))
}

fn parse_version(text: &str) -> Result<[u64; 3]> {
    let parts: Vec<u64> = text
        .strip_prefix('v')
        .unwrap_or(text)
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| anyhow!("cannot read version {text:?}"))?;
    parts
        .try_into()
        .map_err(|_| anyhow!("version {text:?} is not MAJOR.MINOR.PATCH"))
}

fn parse_key(text: &str) -> Result<VerifyingKey> {
    let der = B64.decode(text.trim())?;
    VerifyingKey::from_public_key_der(&der).map_err(|e| anyhow!("not a P-256 public key: {e}"))
}

/// `signature` is DER, as `openssl dgst -sha256 -sign` writes it.
fn check_signature(key: &VerifyingKey, sums: &[u8], signature: &[u8]) -> Result<()> {
    let valid = Signature::from_der(signature).is_ok_and(|sig| key.verify(sums, &sig).is_ok());
    ensure!(
        valid,
        "SHA256SUMS does not match its signature SHA256SUMS.sig"
    );
    Ok(())
}

fn verify(archive: &Path, asset: &str, sums: &str) -> Result<()> {
    let expected = sums
        .lines()
        .find_map(|line| {
            let (hash, name) = line.split_once(char::is_whitespace)?;
            (name.trim_start().trim_start_matches('*') == asset).then(|| hash.to_ascii_lowercase())
        })
        .ok_or_else(|| anyhow!("SHA256SUMS does not list {asset}"))?;
    let mut hasher = Sha256::new();
    io::copy(&mut File::open(archive)?, &mut hasher)?;
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    ensure!(actual == expected, "checksum mismatch for {asset}");
    Ok(())
}

/// Stages `new` beside `exe`, checks that it runs, and swaps it in. Staging
/// in the install directory keeps the final rename on one file system, and
/// runs the check from there rather than from a temp directory that may be
/// mounted noexec.
fn replace(exe: &Path, new: &Path) -> Result<String> {
    let staged = sibling(exe, ".new");
    fs::copy(new, &staged).with_context(|| format!("cannot write {}", staged.display()))?;
    let result = run(Command::new(&staged).arg("--version"))
        .context("the downloaded binary does not run on this host")
        .and_then(|out| {
            let version = String::from_utf8_lossy(&out).trim().to_string();
            ensure!(
                version.starts_with("mjolnir "),
                "the downloaded binary is not mjolnir"
            );
            swap(exe, &staged).with_context(|| format!("cannot replace {}", exe.display()))?;
            Ok(version)
        });
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

#[cfg(unix)]
fn swap(exe: &Path, staged: &Path) -> io::Result<()> {
    fs::rename(staged, exe)
}

/// Windows will not overwrite or delete a running executable but will rename
/// it, so the old binary moves aside to `<exe>.old` and
/// [`remove_leftover`] deletes it on a later run.
#[cfg(windows)]
fn swap(exe: &Path, staged: &Path) -> io::Result<()> {
    let old = sibling(exe, ".old");
    fs::rename(exe, &old)?;
    fs::rename(staged, exe).inspect_err(|_| {
        let _ = fs::rename(&old, exe);
    })
}

/// Deletes the binary a previous update moved aside, if nothing still runs
/// it.
#[cfg(windows)]
pub fn remove_leftover() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = fs::remove_file(sibling(&exe, ".old"));
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

fn curl<S: AsRef<OsStr>>(releases: &str, args: &[S]) -> Result<Vec<u8>> {
    // Never follow a redirect from HTTPS down to plain HTTP.
    let protocols = if releases.starts_with("https://") {
        "=https"
    } else {
        "=http,https"
    };
    run(Command::new(system_tool("curl"))
        .args(["-fsS", "--retry", "2", "--proto-redir", protocols])
        .args(args))
}

/// Runs `cmd` and returns its stdout, or its stderr as the error.
fn run(cmd: &mut Command) -> Result<Vec<u8>> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let out = cmd
        .output()
        .with_context(|| format!("cannot run {program}"))?;
    ensure!(
        out.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(out.stdout)
}

/// On Windows, the copies in System32: its bsdtar reads zip archives, and
/// the GNU tar that Git for Windows puts on PATH does not.
fn system_tool(name: &str) -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        Path::new(&root)
            .join("System32")
            .join(format!("{name}.exe"))
    } else {
        name.into()
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let path =
            std::env::temp_dir().join(format!("mjolnir-update-{}-{nanos}", std::process::id()));
        fs::create_dir(&path).with_context(|| format!("cannot create {}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_scripts_carry_the_release_key() {
        parse_key(RELEASE_KEY).unwrap();
        for (name, script) in [
            ("install.sh", include_str!("../scripts/install.sh")),
            ("install.ps1", include_str!("../scripts/install.ps1")),
        ] {
            assert!(script.contains(RELEASE_KEY), "{name} has another key");
        }
    }
}
