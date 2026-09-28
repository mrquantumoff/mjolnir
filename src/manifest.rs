//! The file manifest: validated relative paths, chunk size, and chunk math.

use std::collections::HashSet;
use std::fs::Metadata;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::names::WirePath;

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
    pub path: WirePath,
    pub size: u64,
    /// Modification time in nanoseconds since the Unix epoch (0 if unknown).
    pub mtime: u64,
}

/// A file as it travels in `Offer`, before validation. `path` has the
/// same encoding as a serialized [`WirePath`]; it is parsed explicitly so a
/// bad name gets a precise error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferFile {
    pub path: Vec<ByteBuf>,
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
/// Most files one transfer may hold; far below `END_FILE_ID`.
pub const MAX_FILES: usize = 10_000_000;

/// A validated manifest: paths unique after case and Unicode folding,
/// fewer than `END_FILE_ID` files.
#[derive(Clone, Debug)]
pub struct Manifest {
    pub chunk_size: ChunkSize,
    pub files: Vec<FileEntry>,
}

impl Manifest {
    pub fn new(chunk_size: ChunkSize, files: Vec<FileEntry>) -> Result<Self> {
        if files.len() > MAX_FILES {
            bail!("too many files ({}, at most {MAX_FILES})", files.len());
        }
        // The receiver's `Have` carries one bitmap per file plus a length
        // prefix of up to 10 bytes, and must fit in one control message.
        // Sizes come from the network, so the sum must not wrap.
        let have_bytes = files.iter().try_fold(0u64, |sum, f| {
            sum.checked_add(chunk_count(f.size, chunk_size).div_ceil(8) + 10)
        });
        if have_bytes.is_none_or(|b| b + 1024 > crate::wire::MAX_CONTROL_LEN as u64) {
            bail!("too many chunks for one transfer; use a larger chunk size");
        }
        let mut seen = HashSet::new();
        for f in &files {
            if !seen.insert(f.path.fold_key()) {
                bail!(
                    "duplicate path {} (paths that differ only in case or Unicode \
                     normalization collide)",
                    f.path.display()
                );
            }
        }
        Ok(Manifest { chunk_size, files })
    }

    /// Validates an offer received from the network.
    pub fn from_offer(chunk_size: u32, files: Vec<OfferFile>) -> Result<Self> {
        let chunk_size = ChunkSize::new(chunk_size)?;
        let files = files
            .into_iter()
            .enumerate()
            .map(|(j, f)| {
                let path = WirePath::parse(f.path.into_iter().map(ByteBuf::into_vec))
                    .with_context(|| format!("file {j} of the offer"))?;
                Ok(FileEntry {
                    path,
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
                path: f
                    .path
                    .components()
                    .iter()
                    .map(|c| ByteBuf::from(c.as_bytes()))
                    .collect(),
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

    fn wire(p: &str) -> WirePath {
        WirePath::parse(p.split('/').map(|c| c.as_bytes().to_vec())).unwrap()
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
    fn offer_with_bad_path_or_chunk_size_is_rejected() {
        let f = |p: &str| OfferFile {
            path: p.split('/').map(|c| ByteBuf::from(c.as_bytes())).collect(),
            size: 10,
            mtime: 0,
        };
        assert!(Manifest::from_offer(4096, vec![f("ok/file")]).is_ok());
        let err = Manifest::from_offer(4096, vec![f("ok"), f("../evil")]).unwrap_err();
        assert!(format!("{err:#}").contains("file 1"), "{err:#}");
        assert!(Manifest::from_offer(1, vec![f("ok")]).is_err());
    }

    #[test]
    fn manifest_rejects_offers_whose_have_would_not_fit() {
        let huge = FileEntry {
            path: wire("huge"),
            size: 1 << 50,
            mtime: 0,
        };
        let err = Manifest::new(cs(4096), vec![huge.clone()]).unwrap_err();
        assert!(err.to_string().contains("too many chunks"), "{err}");
        assert!(Manifest::new(cs(MAX_CHUNK_SIZE), vec![huge]).is_ok());
    }

    #[test]
    fn huge_sizes_are_rejected_without_overflow() {
        let files = (0..40_000)
            .map(|j| FileEntry {
                path: wire(&format!("f{j}")),
                size: u64::MAX,
                mtime: 0,
            })
            .collect();
        let err = Manifest::new(cs(4096), files).unwrap_err();
        assert!(err.to_string().contains("too many chunks"), "{err}");
    }

    #[test]
    fn manifest_rejects_duplicates() {
        let f = |p: &str| FileEntry {
            path: wire(p),
            size: 1,
            mtime: 0,
        };
        assert!(Manifest::new(cs(4096), vec![f("a"), f("b/a")]).is_ok());
        let err = Manifest::new(cs(4096), vec![f("a"), f("b"), f("a")]).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
        let err = Manifest::new(cs(4096), vec![f("README"), f("readme")]).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
        let err = Manifest::new(cs(4096), vec![f("caf\u{e9}"), f("cafe\u{301}")]).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
        let err = Manifest::new(cs(4096), vec![f("A\u{3A3}"), f("a\u{3C3}")]).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }
}
