//! The file manifest: validated relative paths, chunk size, and chunk math.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::Metadata;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::names::{NameError, WireName, WirePath};

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

/// A validated manifest: files, directories, and their parents name
/// distinct paths after case and Unicode folding, and there are fewer than
/// `END_FILE_ID` files.
#[derive(Clone, Debug)]
pub struct Manifest {
    pub chunk_size: ChunkSize,
    pub files: Vec<FileEntry>,
    /// Every directory under the sent roots, empty ones included.
    pub dirs: Vec<WirePath>,
}

impl Manifest {
    pub fn new(chunk_size: ChunkSize, files: Vec<FileEntry>, dirs: Vec<WirePath>) -> Result<Self> {
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
        check_namespace(&files, &dirs)?;
        Ok(Manifest {
            chunk_size,
            files,
            dirs,
        })
    }

    /// Validates an offer received from the network.
    pub fn from_offer(
        chunk_size: u32,
        files: Vec<OfferFile>,
        dirs: Vec<Vec<ByteBuf>>,
    ) -> Result<Self> {
        let chunk_size = ChunkSize::new(chunk_size)?;
        let files = files
            .into_iter()
            .enumerate()
            .map(|(j, f)| {
                let path =
                    parse_offered(f.path).with_context(|| format!("file {j} of the offer"))?;
                Ok(FileEntry {
                    path,
                    size: f.size,
                    mtime: f.mtime,
                })
            })
            .collect::<Result<_>>()?;
        let dirs = dirs
            .into_iter()
            .enumerate()
            .map(|(j, d)| parse_offered(d).with_context(|| format!("directory {j} of the offer")))
            .collect::<Result<_>>()?;
        Manifest::new(chunk_size, files, dirs)
    }

    pub fn to_offer(&self) -> Vec<OfferFile> {
        self.files
            .iter()
            .map(|f| OfferFile {
                path: offered(&f.path),
                size: f.size,
                mtime: f.mtime,
            })
            .collect()
    }

    /// What the receiver keys its staging directory by: the sender's key,
    /// the chunk size, and every file's path, size, and mtime. A later
    /// session resumes only under the same identity.
    pub fn identity(&self, peer: &crate::keys::PublicKey) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"mjolnir transfer v2");
        h.update(&peer.0);
        h.update(&self.chunk_size.get().to_be_bytes());
        h.update(&postcard::to_allocvec(&self.to_offer()).expect("offer files serialize"));
        *h.finalize().as_bytes()
    }

    pub fn offer_dirs(&self) -> Vec<Vec<ByteBuf>> {
        self.dirs.iter().map(offered).collect()
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

fn parse_offered(path: Vec<ByteBuf>) -> Result<WirePath, NameError> {
    WirePath::parse(path.into_iter().map(ByteBuf::into_vec))
}

fn offered(path: &WirePath) -> Vec<ByteBuf> {
    path.components()
        .iter()
        .map(|c| ByteBuf::from(c.as_bytes()))
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    /// A directory implied as the parent of a listed path.
    Parent,
}

/// One name the receiver creates: the first `len` components of `path`.
#[derive(Clone, Copy)]
struct Node<'a> {
    path: &'a WirePath,
    len: usize,
    kind: Kind,
}

impl Node<'_> {
    fn components(&self) -> &[WireName] {
        &self.path.components()[..self.len]
    }

    fn describe(&self) -> String {
        let own = self.path.prefix(self.len).display();
        match self.kind {
            Kind::File => format!("file {own}"),
            Kind::Dir => format!("directory {own}"),
            Kind::Parent => format!("directory {own} (parent of {})", self.path.display()),
        }
    }
}

/// Files, directories, and every parent of either share one namespace on
/// the receiver, so no two of them may fold to the same key unless they
/// are the same directory.
fn check_namespace(files: &[FileEntry], dirs: &[WirePath]) -> Result<()> {
    let mut names = HashMap::new();
    let listed = files
        .iter()
        .map(|f| (&f.path, Kind::File))
        .chain(dirs.iter().map(|d| (d, Kind::Dir)));
    for (path, kind) in listed {
        let depth = path.components().len();
        claim(
            &mut names,
            path.fold_key(),
            Node {
                path,
                len: depth,
                kind,
            },
        )?;
        for len in (1..depth).rev() {
            let parent = Node {
                path,
                len,
                kind: Kind::Parent,
            };
            if !claim(&mut names, path.prefix(len).fold_key(), parent)? {
                break;
            }
        }
    }
    Ok(())
}

/// Records `node` under `key`. Returns false when `node` is a parent that
/// was already recorded, and with it all of its own parents.
fn claim<'a>(names: &mut HashMap<String, Node<'a>>, key: String, node: Node<'a>) -> Result<bool> {
    let old = match names.entry(key) {
        Entry::Vacant(v) => {
            v.insert(node);
            return Ok(true);
        }
        Entry::Occupied(o) => o.into_mut(),
    };
    let same = old.components() == node.components();
    match (old.kind, node.kind) {
        (Kind::Dir | Kind::Parent, Kind::Parent) if same => return Ok(false),
        (Kind::Parent, Kind::Dir) if same => {
            *old = node;
            return Ok(true);
        }
        (Kind::Dir, Kind::Dir) if same => bail!("directory {} is listed twice", old.path.display()),
        _ => {}
    }
    let why = if same {
        ""
    } else {
        " (names that differ only in case or Unicode normalization collide)"
    };
    bail!(
        "duplicate name: {} and {}{why}",
        old.describe(),
        node.describe()
    )
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

/// Bytes the read-back checks (verification and `--hash`) take per claim
/// and per read: chunks smaller than this are claimed and read as a run
/// of adjacent chunks, then hashed one by one.
pub const RUN_BYTES: u32 = 64 << 10;
/// The longest run, reached at `MIN_CHUNK_SIZE`.
pub const MAX_RUN: usize = (RUN_BYTES / MIN_CHUNK_SIZE) as usize;

/// Chunks per read-back run: as many as fit in `RUN_BYTES`, at least one.
pub fn run_len(chunk_size: ChunkSize) -> u64 {
    u64::from((RUN_BYTES / chunk_size.get()).max(1))
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

    fn file(p: &str) -> FileEntry {
        FileEntry {
            path: wire(p),
            size: 1,
            mtime: 0,
        }
    }

    fn namespace(files: &[&str], dirs: &[&str]) -> Result<Manifest> {
        Manifest::new(
            cs(4096),
            files.iter().map(|p| file(p)).collect(),
            dirs.iter().map(|p| wire(p)).collect(),
        )
    }

    fn rejected(files: &[&str], dirs: &[&str]) -> String {
        namespace(files, dirs).unwrap_err().to_string()
    }

    #[test]
    fn offer_with_bad_path_or_chunk_size_is_rejected() {
        let path = |p: &str| p.split('/').map(|c| ByteBuf::from(c.as_bytes())).collect();
        let f = |p: &str| OfferFile {
            path: path(p),
            size: 10,
            mtime: 0,
        };
        assert!(Manifest::from_offer(4096, vec![f("ok/file")], vec![path("ok")]).is_ok());
        let err = Manifest::from_offer(4096, vec![f("ok"), f("../evil")], Vec::new()).unwrap_err();
        assert!(format!("{err:#}").contains("file 1"), "{err:#}");
        let err =
            Manifest::from_offer(4096, Vec::new(), vec![path("d"), path("x/..")]).unwrap_err();
        assert!(format!("{err:#}").contains("directory 1"), "{err:#}");
        assert!(Manifest::from_offer(1, vec![f("ok")], Vec::new()).is_err());
    }

    #[test]
    fn manifest_rejects_offers_whose_have_would_not_fit() {
        let huge = FileEntry {
            path: wire("huge"),
            size: 1 << 50,
            mtime: 0,
        };
        let err = Manifest::new(cs(4096), vec![huge.clone()], Vec::new()).unwrap_err();
        assert!(err.to_string().contains("too many chunks"), "{err}");
        assert!(Manifest::new(cs(MAX_CHUNK_SIZE), vec![huge], Vec::new()).is_ok());
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
        let err = Manifest::new(cs(4096), files, Vec::new()).unwrap_err();
        assert!(err.to_string().contains("too many chunks"), "{err}");
    }

    #[test]
    fn manifest_rejects_duplicates() {
        assert!(namespace(&["a", "b/a"], &[]).is_ok());
        assert!(rejected(&["a", "b", "a"], &[]).contains("duplicate"));
        assert!(rejected(&["README", "readme"], &[]).contains("duplicate"));
        assert!(rejected(&["caf\u{e9}", "cafe\u{301}"], &[]).contains("duplicate"));
        assert!(rejected(&["A\u{3A3}", "a\u{3C3}"], &[]).contains("duplicate"));
    }

    #[test]
    fn manifest_accepts_a_tree_with_its_directories() {
        let m = namespace(
            &["tree/a/b/c/deep.txt", "tree/a/top.txt", "single.bin"],
            &["tree", "tree/a", "tree/a/b", "tree/a/b/c", "tree/empty"],
        )
        .unwrap();
        assert_eq!(m.dirs.len(), 5);
        assert!(namespace(&["x/a", "x/b"], &[]).is_ok());
    }

    #[test]
    fn manifest_rejects_a_file_that_is_a_parent() {
        let err = rejected(&["a", "a/b"], &[]);
        assert!(
            err.contains("file a and directory a (parent of a/b)"),
            "{err}"
        );
        let err = rejected(&["x/A/b", "x/a"], &[]);
        assert!(err.contains("x/A/b") && err.contains("file x/a"), "{err}");
    }

    #[test]
    fn manifest_rejects_a_file_and_directory_differing_in_case() {
        let err = rejected(&["tree/a"], &["tree", "tree/A"]);
        assert!(err.contains("file tree/a and directory tree/A"), "{err}");
    }

    #[test]
    fn manifest_rejects_directories_differing_in_case() {
        let err = rejected(&[], &["Docs", "docs"]);
        assert!(err.contains("directory Docs and directory docs"), "{err}");
        let err = rejected(&["Docs/x"], &["docs"]);
        assert!(
            err.contains("Docs/x") && err.contains("directory docs"),
            "{err}"
        );
        let err = rejected(&["A/x", "a/y"], &[]);
        assert!(err.contains("A/x") && err.contains("a/y"), "{err}");
    }

    #[test]
    fn manifest_rejects_a_directory_equal_to_a_file() {
        let err = rejected(&["a"], &["a"]);
        assert!(err.contains("file a and directory a"), "{err}");
        let err = rejected(&[], &["d", "d"]);
        assert!(err.contains("directory d is listed twice"), "{err}");
    }

    #[test]
    fn manifest_rejects_parents_differing_in_normalization() {
        let err = rejected(&["caf\u{e9}/a", "cafe\u{301}/b"], &[]);
        assert!(err.contains("duplicate"), "{err}");
        let err = rejected(&["caf\u{e9}/a"], &["cafe\u{301}"]);
        assert!(err.contains("duplicate"), "{err}");
    }
}
