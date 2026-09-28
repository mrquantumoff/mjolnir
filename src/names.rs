//! Wire file names: raw-byte path components, their validation, and the
//! reversible mapping to each platform's local names. See "File names" in
//! `docs/PROTOCOL.md`.

use std::ffi::OsStr;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;

pub const MAX_COMPONENTS: usize = 256;
/// Limit on the `/`-joined length of a path.
pub const MAX_PATH_BYTES: usize = 4096;

/// Suffixes of the receiver's side files. No component may end in one after
/// folding (see [`WirePath::fold_key`]), since a case-insensitive file
/// system would take such a name for the side file.
pub const RESERVED_SUFFIXES: [&str; 7] = [
    ".mjolnir-part",
    ".mjolnir-state",
    ".mjolnir-state.tmp",
    ".mjolnir-sums",
    ".mjolnir-journal",
    ".mjolnir-journal.tmp",
    ".mjolnir-staging",
];

/// Byte `b` is escaped as `U+F000 + b`.
const ESCAPE_BASE: u32 = 0xF000;

/// One path component as it travels on the wire. Only constructible through
/// [`WireName::new`], so it is never empty, `.`, `..`, or reserved, and never
/// contains NUL or `/`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WireName(Vec<u8>);

/// A validated relative path of [`WireName`]s. Only constructible through
/// [`WirePath::parse`] or [`WirePath::from_os_path`]; deserializing parses.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WirePath(Vec<WireName>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Unix,
    MacOs,
    Windows,
}

impl Platform {
    #[cfg(target_os = "macos")]
    pub const CURRENT: Platform = Platform::MacOs;
    #[cfg(windows)]
    pub const CURRENT: Platform = Platform::Windows;
    #[cfg(all(unix, not(target_os = "macos")))]
    pub const CURRENT: Platform = Platform::Unix;
}

/// A component as a platform's file system stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalName {
    Unix(Vec<u8>),
    /// Always valid UTF-8 when produced by [`encode_local`].
    MacOs(Vec<u8>),
    /// UTF-16, possibly with unpaired surrogates.
    Windows(Vec<u16>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameReason {
    EmptyPath,
    TooManyComponents(usize),
    TooLong(usize),
    /// A local path component that is not a plain name (root, drive, `..`).
    NotRelative,
    Empty,
    Dot,
    DotDot,
    Nul,
    Slash,
    ReservedSuffix(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameError {
    /// Index and lossy text of the failing component, or `None` when the
    /// path as a whole is at fault.
    pub component: Option<(usize, String)>,
    pub reason: NameReason,
}

impl fmt::Display for NameReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameReason::EmptyPath => write!(f, "empty path"),
            NameReason::TooManyComponents(n) => {
                write!(f, "{n} components, more than {MAX_COMPONENTS}")
            }
            NameReason::TooLong(n) => write!(f, "{n} bytes, longer than {MAX_PATH_BYTES}"),
            NameReason::NotRelative => write!(f, "not a relative name"),
            NameReason::Empty => write!(f, "empty component"),
            NameReason::Dot => write!(f, "\".\" component"),
            NameReason::DotDot => write!(f, "\"..\" component"),
            NameReason::Nul => write!(f, "contains NUL"),
            NameReason::Slash => write!(f, "contains '/'"),
            NameReason::ReservedSuffix(s) => {
                write!(
                    f,
                    "ends in {s:?}, which the receiver uses for its own files"
                )
            }
        }
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.component {
            Some((index, name)) => write!(f, "path component {index} ({name:?}): {}", self.reason),
            None => write!(f, "path: {}", self.reason),
        }
    }
}

impl std::error::Error for NameError {}

impl WireName {
    pub fn new(bytes: Vec<u8>) -> Result<WireName, NameReason> {
        check_component(&bytes)?;
        Ok(WireName(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn check_component(c: &[u8]) -> Result<(), NameReason> {
    match c {
        [] => return Err(NameReason::Empty),
        b"." => return Err(NameReason::Dot),
        b".." => return Err(NameReason::DotDot),
        _ => {}
    }
    if c.contains(&0) {
        return Err(NameReason::Nul);
    }
    if c.contains(&b'/') {
        return Err(NameReason::Slash);
    }
    let folded = fold_name(c);
    match RESERVED_SUFFIXES.iter().find(|s| folded.ends_with(*s)) {
        Some(s) => Err(NameReason::ReservedSuffix(s)),
        None => Ok(()),
    }
}

impl WirePath {
    /// The boundary check every received path goes through.
    pub fn parse<I, B>(components: I) -> Result<WirePath, NameError>
    where
        I: IntoIterator<Item = B>,
        B: Into<Vec<u8>>,
    {
        let raw: Vec<Vec<u8>> = components.into_iter().map(Into::into).collect();
        let whole = |reason| NameError {
            component: None,
            reason,
        };
        if raw.is_empty() {
            return Err(whole(NameReason::EmptyPath));
        }
        if raw.len() > MAX_COMPONENTS {
            return Err(whole(NameReason::TooManyComponents(raw.len())));
        }
        let total = raw.iter().map(Vec::len).sum::<usize>() + raw.len() - 1;
        if total > MAX_PATH_BYTES {
            return Err(whole(NameReason::TooLong(total)));
        }
        let names = raw
            .into_iter()
            .enumerate()
            .map(|(index, bytes)| {
                check_component(&bytes).map_err(|reason| NameError {
                    component: Some((index, String::from_utf8_lossy(&bytes).into_owned())),
                    reason,
                })?;
                Ok(WireName(bytes))
            })
            .collect::<Result<_, _>>()?;
        Ok(WirePath(names))
    }

    pub fn components(&self) -> &[WireName] {
        &self.0
    }

    /// The first `len` components, `1 <= len <= components().len()`.
    pub fn prefix(&self, len: usize) -> WirePath {
        WirePath(self.0[..len].to_vec())
    }

    /// Lossy text for terminals, logs, and the web UI.
    pub fn display(&self) -> String {
        let parts: Vec<_> = self
            .0
            .iter()
            .map(|n| String::from_utf8_lossy(&n.0))
            .collect();
        parts.join("/")
    }

    /// Key for the case-insensitive duplicate check. It NFC-normalizes the
    /// macOS mapping and folds it one character at a time (see
    /// [`fold_char`]) on every platform, so an offer is valid or invalid
    /// everywhere alike: names that collide on Windows or macOS always share
    /// a key. APFS treats the NFC and NFD spellings of a name as one file,
    /// hence the normalization.
    pub fn fold_key(&self) -> String {
        let parts: Vec<_> = self.0.iter().map(|n| fold_name(&n.0)).collect();
        parts.join("/")
    }

    /// Names a sender-side path relative to the transfer root.
    pub fn from_os_path(root_relative: &Path) -> Result<WirePath, NameError> {
        let mut parts = Vec::new();
        for (index, c) in root_relative.components().enumerate() {
            match c {
                Component::Normal(name) => parts.push(os_to_wire(name)),
                other => {
                    return Err(NameError {
                        component: Some((index, other.as_os_str().to_string_lossy().into())),
                        reason: NameReason::NotRelative,
                    });
                }
            }
        }
        WirePath::parse(parts)
    }

    /// The receiver-side path under `base`. On Windows the result is a `\\?\`
    /// verbatim path whenever `base` resolves to a drive or UNC path.
    pub fn to_local_path(&self, base: &Path) -> PathBuf {
        let mut path = local_base(base);
        path.extend(self.0.iter().map(wire_to_os));
        path
    }
}

fn fold_name(bytes: &[u8]) -> String {
    use unicode_normalization::UnicodeNormalization;
    String::from_utf8_lossy(&encode_utf8_escaped(bytes))
        .nfc()
        .map(fold_char)
        .collect()
}

/// The character's uppercase, then that one's lowercase, each step skipped
/// when it would expand to several characters. NTFS compares
/// names through a per-character upcase table, so `str::to_lowercase`,
/// which lowers a word-final capital sigma to final `ς` and any other to
/// `σ`, would let `AΣ` and `aσ` through as two names for one file.
fn fold_char(c: char) -> char {
    let upper = single(c.to_uppercase()).unwrap_or(c);
    single(upper.to_lowercase()).unwrap_or(upper)
}

fn single(mut chars: impl Iterator<Item = char>) -> Option<char> {
    let first = chars.next()?;
    chars.next().is_none().then_some(first)
}

/// Maps wire bytes to what `platform`'s file system can store.
pub fn encode_local(name: &WireName, platform: Platform) -> LocalName {
    match platform {
        Platform::Unix => LocalName::Unix(name.0.clone()),
        Platform::MacOs => LocalName::MacOs(encode_utf8_escaped(&name.0)),
        Platform::Windows => LocalName::Windows(encode_windows(&name.0)),
    }
}

/// Maps a local name back to wire bytes. The result is not validated; a
/// local name can decode to something no wire path may contain (for
/// example `U+F02F` on Windows decodes to `/`).
pub fn decode_local(local: &LocalName) -> Vec<u8> {
    match local {
        LocalName::Unix(bytes) => bytes.clone(),
        LocalName::MacOs(bytes) => decode_utf8_escaped(bytes),
        LocalName::Windows(wide) => decode_windows(wide),
    }
}

/// A decoded piece of a wire name, before the platform's escaping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unit {
    Char(char),
    /// An unpaired UTF-16 surrogate, from WTF-8 on the wire.
    Surrogate(u16),
    Escape(u8),
}

fn escape_code(b: u8) -> u32 {
    ESCAPE_BASE + u32::from(b)
}

/// The code points a sender turns back into bytes.
fn unescape(c: u32) -> Option<u8> {
    let b = c.checked_sub(ESCAPE_BASE)?;
    (1..=0xFF).contains(&b).then_some(b as u8)
}

/// Splits `bytes` into code points and stray bytes. With `surrogates`, a
/// three-byte encoding of a surrogate (WTF-8) is a code point too.
fn scan(bytes: &[u8], surrogates: bool) -> Vec<Unit> {
    let mut units = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match decode_one(&bytes[i..], surrogates) {
            Some((unit, len)) => {
                units.push(unit);
                i += len;
            }
            None => {
                units.push(Unit::Escape(bytes[i]));
                i += 1;
            }
        }
    }
    units
}

fn decode_one(b: &[u8], surrogates: bool) -> Option<(Unit, usize)> {
    let lead = *b.first()?;
    let (len, min, init) = match lead {
        0x00..=0x7F => return Some((Unit::Char(char::from(lead)), 1)),
        0xC2..=0xDF => (2, 0x80, u32::from(lead & 0x1F)),
        0xE0..=0xEF => (3, 0x800, u32::from(lead & 0x0F)),
        0xF0..=0xF4 => (4, 0x1_0000, u32::from(lead & 0x07)),
        _ => return None,
    };
    let tail = b.get(1..len)?;
    let mut cp = init;
    for &t in tail {
        if t & 0xC0 != 0x80 {
            return None;
        }
        cp = (cp << 6) | u32::from(t & 0x3F);
    }
    if cp < min {
        return None;
    }
    match char::from_u32(cp) {
        Some(c) => Some((Unit::Char(c), len)),
        None if surrogates && (0xD800..=0xDFFF).contains(&cp) => {
            Some((Unit::Surrogate(cp as u16), len))
        }
        None => None,
    }
}

fn is_lead(u: u16) -> bool {
    (0xD800..=0xDBFF).contains(&u)
}

fn is_trail(u: u16) -> bool {
    (0xDC00..=0xDFFF).contains(&u)
}

/// A lead surrogate right before a trail surrogate would pair up in UTF-16
/// and come back as one four-byte code point, so its bytes are escaped.
fn unpair_surrogates(units: Vec<Unit>) -> Vec<Unit> {
    let mut out = Vec::with_capacity(units.len());
    for (i, &unit) in units.iter().enumerate() {
        match (unit, units.get(i + 1)) {
            (Unit::Surrogate(lead), Some(&Unit::Surrogate(trail)))
                if is_lead(lead) && is_trail(trail) =>
            {
                out.extend(wtf8(u32::from(lead)).into_iter().map(Unit::Escape));
            }
            _ => out.push(unit),
        }
    }
    out
}

/// A literal escape code point would read back as the byte it stands for,
/// so it is escaped byte by byte to keep the mapping one-to-one.
fn escape_literal_escapes(units: Vec<Unit>) -> Vec<Unit> {
    let mut out = Vec::with_capacity(units.len());
    for unit in units {
        match unit {
            Unit::Char(c) if unescape(u32::from(c)).is_some() => {
                let mut buf = [0; 4];
                out.extend(c.encode_utf8(&mut buf).bytes().map(Unit::Escape));
            }
            _ => out.push(unit),
        }
    }
    out
}

/// Encodes a code point as (generalized) UTF-8, surrogates included.
fn wtf8(cp: u32) -> Vec<u8> {
    match cp {
        0..=0x7F => vec![cp as u8],
        0x80..=0x7FF => vec![0xC0 | (cp >> 6) as u8, 0x80 | (cp & 0x3F) as u8],
        0x800..=0xFFFF => vec![
            0xE0 | (cp >> 12) as u8,
            0x80 | ((cp >> 6) & 0x3F) as u8,
            0x80 | (cp & 0x3F) as u8,
        ],
        _ => vec![
            0xF0 | (cp >> 18) as u8,
            0x80 | ((cp >> 12) & 0x3F) as u8,
            0x80 | ((cp >> 6) & 0x3F) as u8,
            0x80 | (cp & 0x3F) as u8,
        ],
    }
}

/// The macOS mapping: valid UTF-8 stays, every other byte is escaped.
fn encode_utf8_escaped(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for unit in escape_literal_escapes(scan(bytes, false)) {
        let cp = match unit {
            Unit::Char(c) => u32::from(c),
            Unit::Escape(b) => escape_code(b),
            Unit::Surrogate(_) => unreachable!("scanned without surrogates"),
        };
        out.extend(wtf8(cp));
    }
    out
}

fn decode_utf8_escaped(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            match unescape(u32::from(c)) {
                Some(b) => out.push(b),
                None => out.extend(wtf8(u32::from(c))),
            }
        }
        out.extend_from_slice(chunk.invalid());
    }
    out
}

const WINDOWS_RESERVED: [char; 8] = ['\\', ':', '*', '?', '"', '<', '>', '|'];

fn windows_escapes(c: char) -> bool {
    WINDOWS_RESERVED.contains(&c) || ('\u{1}'..='\u{1F}').contains(&c)
}

/// Whether a name's stem (the text before the first `.`, trailing spaces
/// dropped) makes Win32 open a device instead of a file.
fn is_device_stem(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let mut chars = upper.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    let digit = chars.next();
    (prefix == "COM" || prefix == "LPT")
        && chars.next().is_none()
        && matches!(digit, Some('1'..='9' | '\u{B9}' | '\u{B2}' | '\u{B3}'))
}

fn windows_stem(name: &str) -> &str {
    name.split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
}

fn windows_units(bytes: &[u8]) -> Vec<Unit> {
    let mut units = escape_literal_escapes(unpair_surrogates(scan(bytes, true)));
    for unit in &mut units {
        if let Unit::Char(c) = *unit
            && windows_escapes(c)
        {
            *unit = Unit::Escape(c as u8);
        }
    }
    let plain: String = units
        .iter()
        .map_while(|u| match u {
            Unit::Char(c) => Some(*c),
            _ => None,
        })
        .collect();
    let stem_is_plain = plain.contains('.') || plain.chars().count() == units.len();
    if stem_is_plain
        && is_device_stem(windows_stem(&plain))
        && let Some(Unit::Char(first)) = units.first().copied()
    {
        units[0] = Unit::Escape(first as u8);
    }
    if let Some(Unit::Char(last @ ('.' | ' '))) = units.last().copied() {
        *units.last_mut().unwrap() = Unit::Escape(last as u8);
    }
    units
}

/// The Windows mapping: a WTF-8 decoder plus the escapes.
fn encode_windows(bytes: &[u8]) -> Vec<u16> {
    let mut out = Vec::with_capacity(bytes.len());
    for unit in windows_units(bytes) {
        match unit {
            Unit::Char(c) => {
                let mut buf = [0; 2];
                out.extend_from_slice(c.encode_utf16(&mut buf));
            }
            Unit::Surrogate(s) => out.push(s),
            Unit::Escape(b) => out.push(escape_code(b) as u16),
        }
    }
    out
}

/// The Windows sender's reading: a WTF-8 encoder that turns escapes back
/// into bytes.
fn decode_windows(wide: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(wide.len());
    for r in char::decode_utf16(wide.iter().copied()) {
        match r {
            Ok(c) => match unescape(u32::from(c)) {
                Some(b) => out.push(b),
                None => out.extend(wtf8(u32::from(c))),
            },
            Err(e) => out.extend(wtf8(u32::from(e.unpaired_surrogate()))),
        }
    }
    out
}

#[cfg(unix)]
fn os_to_wire(name: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = name.as_bytes().to_vec();
    decode_local(&match Platform::CURRENT {
        Platform::MacOs => LocalName::MacOs(bytes),
        _ => LocalName::Unix(bytes),
    })
}

#[cfg(unix)]
fn wire_to_os(name: &WireName) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    let bytes = match Platform::CURRENT {
        Platform::MacOs => encode_utf8_escaped(&name.0),
        _ => name.0.clone(),
    };
    std::ffi::OsString::from_vec(bytes)
}

#[cfg(unix)]
fn local_base(base: &Path) -> PathBuf {
    base.to_path_buf()
}

#[cfg(windows)]
fn os_to_wire(name: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    decode_windows(&name.encode_wide().collect::<Vec<_>>())
}

#[cfg(windows)]
fn wire_to_os(name: &WireName) -> std::ffi::OsString {
    use std::os::windows::ffi::OsStringExt;
    std::ffi::OsString::from_wide(&encode_windows(&name.0))
}

#[cfg(windows)]
fn local_base(base: &Path) -> PathBuf {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::Prefix;
    let abs = std::path::absolute(base).unwrap_or_else(|_| base.to_path_buf());
    let wide: Vec<u16> = abs.as_os_str().encode_wide().collect();
    let (verbatim, rest): (&str, &[u16]) = match abs.components().next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(_) => (r"\\?\", &wide),
            Prefix::UNC(..) => (r"\\?\UNC\", &wide[2..]),
            _ => return abs,
        },
        _ => return abs,
    };
    let mut out: Vec<u16> = verbatim.encode_utf16().collect();
    out.extend_from_slice(rest);
    PathBuf::from(std::ffi::OsString::from_wide(&out))
}

impl Serialize for WireName {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for WireName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = ByteBuf::deserialize(d)?.into_vec();
        WireName::new(bytes).map_err(D::Error::custom)
    }
}

impl Serialize for WirePath {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(&self.0)
    }
}

impl<'de> Deserialize<'de> for WirePath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Vec::<ByteBuf>::deserialize(d)?;
        WirePath::parse(raw.into_iter().map(ByteBuf::into_vec)).map_err(D::Error::custom)
    }
}

impl fmt::Debug for WireName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0.escape_ascii())
    }
}

impl fmt::Debug for WirePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<_> = self
            .0
            .iter()
            .map(|n| n.0.escape_ascii().to_string())
            .collect();
        write!(f, "\"{}\"", parts.join("/"))
    }
}

#[cfg(test)]
mod tests;
