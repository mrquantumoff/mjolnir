//! Static X25519 identities: key newtypes, key files, and authorized-keys lists.

use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use curve25519_dalek::montgomery::MontgomeryPoint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

mod private_file;

/// A key file is one line of base64; anything past this is not a key.
const KEY_FILE_MAX: usize = 1024;

/// An X25519 public key. Text form is standard base64 of the 32 raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

/// An X25519 private key. `Debug` never prints the bytes, and each copy
/// zeroes them when dropped.
#[derive(Clone)]
pub struct PrivateKey([u8; 32]);

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Decodes into buffers that are zeroed afterwards, since the text may be
/// a private key.
fn decode_key(text: &str) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(
        B64.decode(text.trim())
            .map_err(|e| anyhow!("invalid base64 key: {e}"))?,
    );
    if bytes.len() != 32 {
        bail!("key must be 32 bytes, got {}", bytes.len());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

impl FromStr for PublicKey {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        decode_key(s).map(|k| PublicKey(*k))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&B64.encode(self.0))
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey(public = {})", self.public_key())
    }
}

impl PrivateKey {
    pub fn generate() -> Self {
        let mut key = PrivateKey([0u8; 32]);
        getrandom::fill(&mut key.0).expect("OS random number generator failed");
        key
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(MontgomeryPoint::mul_base_clamped(self.0).to_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses the key-file text form (base64, surrounding whitespace ignored).
    pub fn from_base64(text: &str) -> Result<Self> {
        decode_key(text).map(|k| PrivateKey(*k))
    }

    /// Reads a key file, refusing one that other accounts can read or
    /// change: mode bits beyond 0600 on Unix, or an access list that grants
    /// anyone but this user, SYSTEM, and Administrators on Windows.
    pub fn load(path: &Path) -> Result<Self> {
        let reading = || format!("reading private key {}", path.display());
        let file = File::open(path).with_context(reading)?;
        private_file::check(&file, path)?;
        // Sized up front so reading never reallocates and leaves a copy behind.
        let mut text = Zeroizing::new(String::with_capacity(KEY_FILE_MAX + 1));
        file.take(KEY_FILE_MAX as u64)
            .read_to_string(&mut text)
            .with_context(reading)?;
        Self::from_base64(&text).with_context(|| format!("parsing private key {}", path.display()))
    }

    /// Fails unless [`PrivateKey::load`] would accept the key file at `path`
    /// in a process running as LocalSystem, as a Windows service does.
    #[cfg(windows)]
    pub fn check_for_local_system(path: &Path) -> Result<()> {
        let file =
            File::open(path).with_context(|| format!("reading private key {}", path.display()))?;
        private_file::check_for_local_system(&file, path)
    }

    /// Writes the key as base64 plus a newline. Refuses to overwrite an
    /// existing file. Only this user can open it: mode 0600 on Unix, and on
    /// Windows a DACL that inherits nothing and grants only this user,
    /// SYSTEM, and Administrators.
    pub fn save(&self, path: &Path) -> Result<()> {
        let file = private_file::create(path)
            .with_context(|| format!("creating key file {}", path.display()))?;
        self.write_to(file)
    }

    /// Like [`PrivateKey::save`], but for a Windows service running as
    /// SYSTEM: the file is owned by Administrators and only SYSTEM and
    /// Administrators can use it. A missing folder for it is created with
    /// an access list only they can change. Needs an elevated process.
    #[cfg(windows)]
    pub fn save_for_system(&self, path: &Path) -> Result<()> {
        // Setting Administrators as the owner is what fails unelevated.
        let elevated = |e: std::io::Error| match e.raw_os_error() {
            Some(1307) => {
                anyhow!("`keygen --system` needs an elevated terminal (Run as administrator)")
            }
            _ => e.into(),
        };
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
            && !dir.exists()
        {
            crate::winacl::create_protected_dir(dir)
                .map_err(elevated)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        let file = private_file::create_for_system(path)
            .map_err(elevated)
            .with_context(|| format!("creating key file {}", path.display()))?;
        self.write_to(file)
    }

    fn write_to(&self, mut file: File) -> Result<()> {
        let text = Zeroizing::new(B64.encode(self.0.as_slice()));
        writeln!(file, "{}", text.as_str())?;
        file.sync_all()?;
        Ok(())
    }

    /// Loads `<config dir>/mjolnir/mjolnir.key`, generating it first if it
    /// does not exist. Returns the key and its path.
    pub fn load_or_create_default() -> Result<(Self, PathBuf)> {
        let path = default_key_path()?;
        if !path.exists() {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
            PrivateKey::generate().save(&path)?;
        }
        Ok((PrivateKey::load(&path)?, path))
    }
}

/// `<config dir>/mjolnir/mjolnir.key`, where the config dir is
/// `%APPDATA%` on Windows, `~/Library/Application Support` on macOS, and
/// `$XDG_CONFIG_HOME` or `~/.config` elsewhere.
pub fn default_key_path() -> Result<PathBuf> {
    let env = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let home = || env("HOME").context("HOME is not set");
    let config = if cfg!(windows) {
        env("APPDATA").context("APPDATA is not set")?
    } else if cfg!(target_os = "macos") {
        home()?.join("Library/Application Support")
    } else {
        match env("XDG_CONFIG_HOME") {
            Some(dir) => dir,
            None => home()?.join(".config"),
        }
    };
    Ok(config.join("mjolnir").join("mjolnir.key"))
}

/// One line of an authorized-keys file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedKey {
    pub key: PublicKey,
    /// Options written before the key, in order. A line without options
    /// grants everything; a line with options grants only what they name.
    pub options: Vec<KeyOption>,
}

/// An option on an authorized-keys line, as in SSH's `authorized_keys`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyOption {
    /// `permitopen="HOST:PORT"`: the tunnel server lets this key reach
    /// matching targets with `-L` and `-W`.
    PermitOpen(String),
    /// `permitlisten="HOST:PORT"`: the tunnel server lets this key listen
    /// on matching addresses with `-R`.
    PermitListen(String),
    /// `transfer`: `mjolnir recv` accepts files from this key. A line with
    /// tunnel options and without this one is a tunnel-only key.
    Transfer,
}

/// Option names an authorized-keys line may carry.
pub const KEY_OPTIONS: &[&str] = &["permitopen", "permitlisten", "transfer"];

impl AuthorizedKey {
    /// Whether `mjolnir recv` may take files from this key: a line without
    /// options, or one that says `transfer`.
    pub fn grants_transfer(&self) -> bool {
        self.options.is_empty() || self.options.contains(&KeyOption::Transfer)
    }
}

/// Parses an authorized-keys file: one `[options] <base64 key> [comment]`
/// per line; blank lines and lines starting with `#` are ignored. Options
/// are `name=value` pairs joined by commas, with no spaces unless the value
/// is in double quotes, as in SSH's `authorized_keys`.
pub fn parse_authorized_entries(text: &str) -> Result<Vec<AuthorizedKey>> {
    let mut keys = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let entry = parse_entry(line).with_context(|| format!("authorized keys line {}", n + 1))?;
        keys.push(entry);
    }
    Ok(keys)
}

fn parse_entry(line: &str) -> Result<AuthorizedKey> {
    let first = line.split_whitespace().next().unwrap_or_default();
    if !looks_like_options(first) {
        return Ok(AuthorizedKey {
            key: first.parse()?,
            options: Vec::new(),
        });
    }
    // Options run up to the first space outside double quotes.
    let mut options = Vec::new();
    let (mut name, mut value) = (String::new(), None::<String>);
    let mut quoted = false;
    let mut rest = "";
    let mut finish = |name: &mut String, value: &mut Option<String>| -> Result<()> {
        let needs_value = |value: &mut Option<String>| {
            value
                .take()
                .ok_or_else(|| anyhow!("option {name:?} needs a value, as in {name}=\"...\""))
        };
        let option = match name.as_str() {
            "permitopen" => KeyOption::PermitOpen(needs_value(value)?),
            "permitlisten" => KeyOption::PermitListen(needs_value(value)?),
            "transfer" => {
                ensure!(value.take().is_none(), "option \"transfer\" takes no value");
                KeyOption::Transfer
            }
            _ => bail!(
                "unknown option {name:?} (known: {})",
                KEY_OPTIONS.join(", ")
            ),
        };
        name.clear();
        options.push(option);
        Ok(())
    };
    for (i, c) in line.char_indices() {
        match (c, quoted, value.is_some()) {
            ('"', _, true) => quoted = !quoted,
            (c, false, _) if c.is_whitespace() => {
                rest = &line[i..];
                break;
            }
            (',', false, _) => finish(&mut name, &mut value)?,
            ('=', false, false) => value = Some(String::new()),
            (c, _, true) => value.as_mut().unwrap().push(c),
            (c, false, false) => name.push(c.to_ascii_lowercase()),
            (_, true, false) => unreachable!("quotes open only inside a value"),
        }
    }
    ensure!(!quoted, "unterminated quote in the options");
    finish(&mut name, &mut value)?;
    let token = rest
        .split_whitespace()
        .next()
        .context("no key after the options")?;
    Ok(AuthorizedKey {
        key: token.parse()?,
        options,
    })
}

/// Whether a line's first token is options rather than a key: `name=` with
/// something other than base64 padding after the `=`, or a bare option name.
fn looks_like_options(token: &str) -> bool {
    match token.split_once('=') {
        Some((name, value)) => {
            !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphabetic())
                && !value.chars().all(|c| c == '=')
        }
        None => KEY_OPTIONS.contains(&token.to_ascii_lowercase().as_str()),
    }
}

/// Parses an authorized-keys file and keeps the keys that may send files:
/// tunnel-only lines are left out. See [`AuthorizedKey::grants_transfer`].
pub fn parse_authorized_keys(text: &str) -> Result<Vec<PublicKey>> {
    Ok(transfer_keys(&parse_authorized_entries(text)?))
}

/// Reads and parses an authorized-keys file, keeping the keys that may
/// send files.
pub fn load_authorized_keys(path: &Path) -> Result<Vec<PublicKey>> {
    Ok(transfer_keys(&load_authorized_entries(path)?))
}

/// The keys among `entries` that may send files.
pub fn transfer_keys(entries: &[AuthorizedKey]) -> Vec<PublicKey> {
    entries
        .iter()
        .filter(|e| e.grants_transfer())
        .map(|e| e.key)
        .collect()
}

/// Reads and parses an authorized-keys file, options included.
pub fn load_authorized_entries(path: &Path) -> Result<Vec<AuthorizedKey>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading authorized keys {}", path.display()))?;
    parse_authorized_entries(&text).with_context(|| format!("in {}", path.display()))
}

pub(crate) fn require_nonempty(keys: &[PublicKey]) -> Result<()> {
    if keys.is_empty() {
        bail!("no authorized sender keys: pass --authorized FILE or --allow KEY");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_roundtrips_through_base64() {
        let key = PrivateKey::generate().public_key();
        let text = key.to_string();
        assert_eq!(text.len(), 44);
        assert_eq!(text.parse::<PublicKey>().unwrap(), key);
    }

    #[test]
    fn public_key_matches_x25519_rfc7748_vector() {
        let sk = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let pk = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(PrivateKey(sk).public_key(), PublicKey(pk));
    }

    #[test]
    fn private_key_debug_hides_bytes() {
        let key = PrivateKey::from_base64(&B64.encode([7u8; 32])).unwrap();
        let shown = format!("{key:?}");
        assert!(!shown.contains(&B64.encode([7u8; 32])));
        assert!(shown.contains(&key.public_key().to_string()));
    }

    #[test]
    fn authorized_keys_parsing() {
        let a = PrivateKey::generate().public_key();
        let b = PrivateKey::generate().public_key();
        let text = format!("# team keys\n\n{a} laptop of alice\n   \n  # indented comment\n{b}\n");
        assert_eq!(parse_authorized_keys(&text).unwrap(), vec![a, b]);
    }

    #[test]
    fn authorized_keys_bad_base64_names_the_line() {
        let a = PrivateKey::generate().public_key();
        let text = format!("{a}\n# fine\nnot-base64!!\n");
        let err = format!("{:#}", parse_authorized_keys(&text).unwrap_err());
        assert!(err.contains("line 3"), "{err}");
    }

    #[test]
    fn authorized_keys_wrong_length_rejected() {
        let short = B64.encode([1u8; 16]);
        let err = format!("{:#}", parse_authorized_keys(&short).unwrap_err());
        assert!(err.contains("line 1") && err.contains("32 bytes"), "{err}");
    }

    #[test]
    fn private_key_is_zeroed_on_drop() {
        let mut slot = std::mem::MaybeUninit::new(PrivateKey::generate());
        assert_ne!(unsafe { slot.assume_init_ref() }.0, [0u8; 32]);
        unsafe { slot.assume_init_drop() };
        let left: [u8; 32] = unsafe { std::ptr::read(slot.as_ptr().cast()) };
        assert_eq!(left, [0u8; 32]);
    }

    #[test]
    fn saved_key_loads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.key");
        let key = PrivateKey::generate();
        key.save(&path).unwrap();
        assert_eq!(PrivateKey::load(&path).unwrap().0, key.0);
        assert!(key.save(&path).is_err(), "save must not overwrite");
    }

    #[cfg(unix)]
    #[test]
    fn key_readable_by_others_is_refused_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.key");
        PrivateKey::generate().save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = format!("{:#}", PrivateKey::load(&path).unwrap_err());
        assert!(err.contains("chmod 600"), "{err}");
    }

    /// A directory that grants Everyone read access to what is created in
    /// it: `save` must not inherit that, and a key written without `save`
    /// must be refused.
    #[cfg(windows)]
    #[test]
    fn key_readable_by_others_is_refused_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("icacls")
            .arg(dir.path())
            .args(["/grant", "*S-1-1-0:(OI)(CI)R"])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());

        let saved = dir.path().join("saved.key");
        PrivateKey::generate().save(&saved).unwrap();
        PrivateKey::load(&saved).unwrap();

        let plain = dir.path().join("plain.key");
        std::fs::write(&plain, B64.encode([7u8; 32])).unwrap();
        let err = format!("{:#}", PrivateKey::load(&plain).unwrap_err());
        assert!(err.contains("S-1-1-0") && err.contains("icacls"), "{err}");
    }

    /// Elevated, the key loads both here and as LocalSystem; otherwise
    /// setting its owner fails and says why.
    #[cfg(windows)]
    #[test]
    fn key_for_system_is_usable_by_system_and_administrators() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(r"new dir\k.key");
        let key = PrivateKey::generate();
        match key.save_for_system(&path) {
            Ok(()) => {
                PrivateKey::check_for_local_system(&path).unwrap();
                assert_eq!(PrivateKey::load(&path).unwrap().0, key.0);
            }
            Err(e) => {
                let err = format!("{e:#}");
                assert!(err.contains("elevated terminal"), "{err}");
            }
        }
    }

    /// A key `save` wrote grants this user, which LocalSystem must refuse,
    /// and the fix keeps SYSTEM while removing the user.
    #[cfg(windows)]
    #[test]
    fn saved_key_is_refused_for_local_system() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.key");
        PrivateKey::generate().save(&path).unwrap();
        let err = format!(
            "{:#}",
            PrivateKey::check_for_local_system(&path).unwrap_err()
        );
        assert!(
            err.contains("/grant:r \"*S-1-5-18:F\" /remove \"*S-1-5-"),
            "{err}"
        );
    }

    #[test]
    fn authorized_key_options() {
        let a = PrivateKey::generate().public_key();
        let b = PrivateKey::generate().public_key();
        let text = format!(
            "permitopen=\"db:5432\",PermitOpen=\"[::1]:22\",permitlisten=\"127.0.0.1:8080\" {a} backup\n\
             permitopen=\"a b:1\" {b}\n{b} plain\n"
        );
        let entries = parse_authorized_entries(&text).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].key, a);
        assert_eq!(
            entries[0].options,
            vec![
                KeyOption::PermitOpen("db:5432".into()),
                KeyOption::PermitOpen("[::1]:22".into()),
                KeyOption::PermitListen("127.0.0.1:8080".into()),
            ]
        );
        assert_eq!(
            entries[1].options,
            vec![KeyOption::PermitOpen("a b:1".into())]
        );
        assert!(entries[2].options.is_empty());
    }

    /// A shared file: a key restricted to tunnels must not become a file
    /// sender, while a plain line and a `transfer` line still do.
    #[test]
    fn tunnel_only_keys_do_not_send_files() {
        let (a, b, c, d) = (
            PrivateKey::generate().public_key(),
            PrivateKey::generate().public_key(),
            PrivateKey::generate().public_key(),
            PrivateKey::generate().public_key(),
        );
        let text = format!(
            "permitopen=\"db:5432\" {a} tunnel only\n{b} plain\n\
             permitlisten=\"127.0.0.1:8080\",transfer {c} both\nTransfer {d}\n"
        );
        let entries = parse_authorized_entries(&text).unwrap();
        assert!(!entries[0].grants_transfer());
        assert!(entries[1].grants_transfer());
        assert!(entries[2].grants_transfer());
        assert_eq!(entries[3].options, vec![KeyOption::Transfer]);
        assert_eq!(parse_authorized_keys(&text).unwrap(), vec![b, c, d]);
        let err = format!(
            "{:#}",
            parse_authorized_keys(&format!("transfer=\"yes\" {a}")).unwrap_err()
        );
        assert!(err.contains("takes no value"), "{err}");
    }

    #[test]
    fn authorized_key_bad_options_are_named() {
        let a = PrivateKey::generate().public_key();
        for (line, want) in [
            (format!("permitopn=\"x:1\" {a}"), "unknown option"),
            (format!("permitopen {a}"), "needs a value"),
            (format!("permitopen=\"x:1 {a}"), "unterminated"),
            ("permitopen=x:1".to_string(), "no key"),
        ] {
            let err = format!("{:#}", parse_authorized_keys(&line).unwrap_err());
            assert!(
                err.contains(want) && err.contains("line 1"),
                "{line}: {err}"
            );
        }
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
