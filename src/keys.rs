//! Static X25519 identities: key newtypes, key files, and authorized-keys lists.

use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
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

    /// Writes the key as base64 plus a newline. Refuses to overwrite an
    /// existing file. Only this user can open it: mode 0600 on Unix, and on
    /// Windows a DACL that inherits nothing and grants only this user,
    /// SYSTEM, and Administrators.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut file = private_file::create(path)
            .with_context(|| format!("creating key file {}", path.display()))?;
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

/// Parses an authorized-keys file: one `<base64 key> [comment]` per line;
/// blank lines and lines starting with `#` are ignored.
pub fn parse_authorized_keys(text: &str) -> Result<Vec<PublicKey>> {
    let mut keys = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let token = line.split_whitespace().next().unwrap_or_default();
        let key = token
            .parse()
            .with_context(|| format!("authorized keys line {}", n + 1))?;
        keys.push(key);
    }
    Ok(keys)
}

/// Reads and parses an authorized-keys file.
pub fn load_authorized_keys(path: &Path) -> Result<Vec<PublicKey>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading authorized keys {}", path.display()))?;
    parse_authorized_keys(&text).with_context(|| format!("in {}", path.display()))
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

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
