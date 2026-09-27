//! The file manifest: validated relative paths, chunk size, and chunk math.

use std::collections::HashSet;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

/// A relative path with `/` separators that is safe to join under an output
/// directory on any OS. Only constructible through [`RelPath::parse`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelPath(String);

impl RelPath {
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() {
            bail!("empty path");
        }
        if s.starts_with('/') {
            bail!("absolute path {s:?}");
        }
        if s.contains('\\') {
            bail!("backslash in path {s:?}");
        }
        for component in s.split('/') {
            match component {
                "" => bail!("empty component in path {s:?}"),
                "." | ".." => bail!("{component:?} component in path {s:?}"),
                c if c.contains(':') => bail!("':' (drive prefix or stream) in path {s:?}"),
                c if c.contains('\0') => bail!("NUL in path {s:?}"),
                _ => {}
            }
        }
        Ok(RelPath(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Joins component by component, so no component can reset the base.
    pub fn under(&self, root: &Path) -> PathBuf {
        let mut path = root.to_path_buf();
        path.extend(self.0.split('/'));
        path
    }
}

pub const MIN_CHUNK_SIZE: u32 = 4 << 10;
pub const MAX_CHUNK_SIZE: u32 = 64 << 20;

/// A chunk size in `[MIN_CHUNK_SIZE, MAX_CHUNK_SIZE]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkSize(u32);

impl ChunkSize {
    pub fn new(bytes: u32) -> Result<Self> {
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&bytes) {
            bail!("chunk size {bytes} is outside 4 KiB..=64 MiB");
        }
        Ok(ChunkSize(bytes))
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

/// Parses sizes like `1048576`, `64K`, `64KiB`, `4M`, `4MiB` (binary units).
pub fn parse_size(text: &str) -> Result<u32> {
    let t = text.trim();
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (digits, unit) = t.split_at(split);
    let n: u64 = digits
        .parse()
        .map_err(|_| anyhow!("invalid size {text:?}"))?;
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        _ => bail!("invalid size unit in {text:?}"),
    };
    n.checked_mul(mult)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| anyhow!("size {text:?} is too large"))
}

/// One file of the manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub path: RelPath,
    pub size: u64,
    /// Modification time in nanoseconds since the Unix epoch (0 if unknown).
    pub mtime: u64,
}

/// A file as it travels in `Offer`, before validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferFile {
    pub path: String,
    pub size: u64,
    pub mtime: u64,
}

pub fn mtime_of(meta: &Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// `file_id` value reserved for the end-of-stream frame.
pub const END_FILE_ID: u32 = u32::MAX;

/// A validated manifest: unique paths, fewer than `END_FILE_ID` files.
#[derive(Clone, Debug)]
pub struct Manifest {
    pub chunk_size: ChunkSize,
    pub files: Vec<FileEntry>,
}

impl Manifest {
    pub fn new(chunk_size: ChunkSize, files: Vec<FileEntry>) -> Result<Self> {
        if files.len() >= END_FILE_ID as usize {
            bail!("too many files ({})", files.len());
        }
        let mut seen = HashSet::new();
        for f in &files {
            if !seen.insert(f.path.as_str()) {
                bail!("duplicate path {:?}", f.path.as_str());
            }
        }
        Ok(Manifest { chunk_size, files })
    }

    /// Validates an offer received from the network.
    pub fn from_offer(chunk_size: u32, files: Vec<OfferFile>) -> Result<Self> {
        let chunk_size = ChunkSize::new(chunk_size)?;
        let files = files
            .into_iter()
            .map(|f| {
                Ok(FileEntry {
                    path: RelPath::parse(&f.path)?,
                    size: f.size,
                    mtime: f.mtime,
                })
            })
            .collect::<Result<_>>()?;
        Manifest::new(chunk_size, files)
    }

    pub fn to_offer(&self) -> Vec<OfferFile> {
        self.files
            .iter()
            .map(|f| OfferFile {
                path: f.path.as_str().to_owned(),
                size: f.size,
                mtime: f.mtime,
            })
            .collect()
    }

    pub fn chunk_count(&self, file_id: u32) -> u64 {
        chunk_count(self.files[file_id as usize].size, self.chunk_size)
    }

    pub fn chunk_len(&self, chunk: ChunkId) -> u32 {
        chunk_span(
            self.files[chunk.file as usize].size,
            self.chunk_size,
            chunk.index,
        )
        .1
    }
}

/// A chunk of a file in the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkId {
    pub file: u32,
    pub index: u64,
}

pub fn chunk_count(size: u64, chunk_size: ChunkSize) -> u64 {
    size.div_ceil(u64::from(chunk_size.get()))
}

/// `(offset, len)` of chunk `index`. The caller guarantees
/// `index < chunk_count(size, chunk_size)`.
pub fn chunk_span(size: u64, chunk_size: ChunkSize, index: u64) -> (u64, u32) {
    let cs = u64::from(chunk_size.get());
    let offset = index * cs;
    let len = cs.min(size - offset);
    (offset, len as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs(n: u32) -> ChunkSize {
        ChunkSize::new(n).unwrap()
    }

    #[test]
    fn chunk_math_empty_file_has_no_chunks() {
        assert_eq!(chunk_count(0, cs(4096)), 0);
    }

    #[test]
    fn chunk_math_exact_multiple() {
        let c = cs(4096);
        assert_eq!(chunk_count(3 * 4096, c), 3);
        assert_eq!(chunk_span(3 * 4096, c, 2), (2 * 4096, 4096));
    }

    #[test]
    fn chunk_math_remainder() {
        let c = cs(4096);
        assert_eq!(chunk_count(4096 + 1, c), 2);
        assert_eq!(chunk_span(4096 + 1, c, 0), (0, 4096));
        assert_eq!(chunk_span(4096 + 1, c, 1), (4096, 1));
        assert_eq!(chunk_count(1, c), 1);
        assert_eq!(chunk_span(1, c, 0), (0, 1));
    }

    #[test]
    fn chunk_math_large_file_and_max_chunk() {
        let c = cs(MAX_CHUNK_SIZE);
        let size = 5 * u64::from(MAX_CHUNK_SIZE) + 12345;
        assert_eq!(chunk_count(size, c), 6);
        assert_eq!(
            chunk_span(size, c, 5),
            (5 * u64::from(MAX_CHUNK_SIZE), 12345)
        );
    }

    #[test]
    fn chunk_size_bounds() {
        assert!(ChunkSize::new(MIN_CHUNK_SIZE - 1).is_err());
        assert!(ChunkSize::new(MAX_CHUNK_SIZE + 1).is_err());
        assert!(ChunkSize::new(MIN_CHUNK_SIZE).is_ok());
        assert!(ChunkSize::new(MAX_CHUNK_SIZE).is_ok());
    }

    #[test]
    fn parse_size_suffixes() {
        assert_eq!(parse_size("64K").unwrap(), 65536);
        assert_eq!(parse_size("4MiB").unwrap(), 4 << 20);
        assert_eq!(parse_size("1M").unwrap(), 1 << 20);
        assert_eq!(parse_size("256k").unwrap(), 256 << 10);
        assert_eq!(parse_size("1048576").unwrap(), 1 << 20);
        assert!(parse_size("4X").is_err());
        assert!(parse_size("M").is_err());
        assert!(parse_size("8G").is_err());
    }

    #[test]
    fn relpath_accepts_normal_paths() {
        for ok in ["a", "a/b/c.txt", "dir/.hidden", "a..b/c", "space name/x"] {
            RelPath::parse(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
    }

    #[test]
    fn relpath_rejections() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../x",
            "a/./b",
            ".",
            "a\\b",
            "..\\x",
            "C:/Windows",
            "C:x",
            "a/C:x",
            "file:stream",
            "a//b",
            "a/",
            "//server/share",
            "a/\0b",
        ] {
            assert!(RelPath::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn offer_with_bad_path_or_chunk_size_is_rejected() {
        let f = |p: &str| OfferFile {
            path: p.to_owned(),
            size: 10,
            mtime: 0,
        };
        assert!(Manifest::from_offer(4096, vec![f("ok/file")]).is_ok());
        let err = Manifest::from_offer(4096, vec![f("ok"), f("../evil")]).unwrap_err();
        assert!(err.to_string().contains("../evil"), "{err}");
        assert!(Manifest::from_offer(1, vec![f("ok")]).is_err());
    }

    #[test]
    fn relpath_joins_per_component() {
        let p = RelPath::parse("a/b/c").unwrap().under(Path::new("out"));
        assert_eq!(p, Path::new("out").join("a").join("b").join("c"));
    }

    #[test]
    fn manifest_rejects_duplicates() {
        let f = |p: &str| FileEntry {
            path: RelPath::parse(p).unwrap(),
            size: 1,
            mtime: 0,
        };
        assert!(Manifest::new(cs(4096), vec![f("a"), f("b/a")]).is_ok());
        let err = Manifest::new(cs(4096), vec![f("a"), f("b"), f("a")]).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }
}
