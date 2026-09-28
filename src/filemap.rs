//! The file map: directory structure and metadata, captured on the sender
//! and applied by the receiver after every file is in place. See "File map"
//! in `docs/PROTOCOL.md`.

use std::cmp::Reverse;
use std::collections::HashSet;
use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use filetime::FileTime;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::manifest::Manifest;
use crate::names::WirePath;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMap {
    pub entries: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub path: WirePath,
    pub kind: EntryKind,
    /// Permission bits, `st_mode & 0o7777`.
    pub mode: Option<u32>,
    /// Nanoseconds since the Unix epoch.
    pub mtime: Option<i64>,
    pub atime: Option<i64>,
    /// `(uid, gid)`.
    pub owner: Option<(u32, u32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File { file_id: u32 },
    Dir,
}

/// What the sender puts in the map (`send --preserve`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preserve {
    pub perms: bool,
    pub times: bool,
    pub owner: bool,
}

impl Preserve {
    pub const NONE: Preserve = Preserve {
        perms: false,
        times: false,
        owner: false,
    };
}

impl Default for Preserve {
    fn default() -> Self {
        Preserve {
            perms: true,
            ..Preserve::NONE
        }
    }
}

impl FromStr for Preserve {
    type Err = anyhow::Error;

    /// `none`, or a comma-separated list of `perms`, `times`, `owner`.
    fn from_str(s: &str) -> Result<Self> {
        if s.trim() == "none" {
            return Ok(Preserve::NONE);
        }
        let mut p = Preserve::NONE;
        for item in s.split(',') {
            match item.trim() {
                "perms" => p.perms = true,
                "times" => p.times = true,
                "owner" => p.owner = true,
                other => {
                    bail!("unknown preserve item {other:?}; expected perms, times, owner, or none")
                }
            }
        }
        Ok(p)
    }
}

/// The receiver's guard against a hostile or careless sender.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPolicy {
    /// Keep setuid, setgid, and sticky (`recv --allow-special-bits`).
    pub allow_special_bits: bool,
    /// Chown when running as root on Unix (`recv --allow-owner`).
    pub allow_owner: bool,
}

/// A file to send. Its `file_id` is its index in [`Captured::files`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedFile {
    pub source: PathBuf,
    pub path: WirePath,
    pub size: u64,
    /// Nanoseconds since the Unix epoch, 0 if unknown, as `Offer` carries it.
    pub mtime: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Captured {
    pub files: Vec<CapturedFile>,
    pub map: FileMap,
    /// Sources that are not sent, each with why.
    pub skipped: Vec<Skipped>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub path: PathBuf,
    pub reason: SkipReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// A special file or a link to one.
    NotRegular,
    /// Any link, when links are not followed.
    NotFollowed,
    /// A link whose target does not exist.
    Dangling,
    /// A directory link back to `ancestor`, which is already being walked,
    /// or, without one, a chain of links that never reaches a target.
    Loop { ancestor: Option<PathBuf> },
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::NotRegular => f.write_str("not a regular file or directory"),
            SkipReason::NotFollowed => f.write_str("symbolic link, not followed"),
            SkipReason::Dangling => f.write_str("dangling symbolic link"),
            SkipReason::Loop { ancestor: None } => f.write_str("symlink loop"),
            SkipReason::Loop {
                ancestor: Some(ancestor),
            } => write!(f, "symlink loop back to {}", ancestor.display()),
        }
    }
}

impl FileMap {
    /// Checks that every `File` entry names its file in the offer and every
    /// `Dir` entry one of its directories.
    pub fn check(&self, offer: &Manifest) -> Result<()> {
        let dirs: HashSet<&WirePath> = offer.dirs.iter().collect();
        for entry in &self.entries {
            match entry.kind {
                EntryKind::File { file_id } => {
                    let offered = offer.files.get(file_id as usize).with_context(|| {
                        format!(
                            "file map entry {} has file_id {file_id}, but the offer has {} files",
                            entry.path.display(),
                            offer.files.len()
                        )
                    })?;
                    ensure!(
                        offered.path == entry.path,
                        "file map entry {} does not match offered file {file_id} ({})",
                        entry.path.display(),
                        offered.path.display()
                    );
                }
                EntryKind::Dir => ensure!(
                    dirs.contains(&entry.path),
                    "file map entry {} is a directory the offer does not list",
                    entry.path.display()
                ),
            }
        }
        Ok(())
    }
}

/// Walks the sender's roots, naming them the way the sender does: a file
/// root is its own name, and a directory root's name prefixes everything
/// under it. With `follow_symlinks`, links, roots included, are sent as
/// their targets' contents and metadata under the link's own name; without
/// it, they are skipped.
pub fn capture(roots: &[PathBuf], preserve: Preserve, follow_symlinks: bool) -> Result<Captured> {
    ensure!(!roots.is_empty(), "nothing to send");
    let mut out = Captured::default();
    for root in roots {
        let own = fs::symlink_metadata(root);
        let own = own.with_context(|| format!("reading {}", root.display()))?;
        if own.is_symlink() && !follow_symlinks {
            out.skip(root.clone(), SkipReason::NotFollowed);
            continue;
        }
        let meta = fs::metadata(root).with_context(|| format!("reading {}", root.display()))?;
        let base = if own.is_symlink() {
            root.file_name().map(PathBuf::from)
        } else {
            root.canonicalize()
                .with_context(|| format!("resolving {}", root.display()))?
                .file_name()
                .map(PathBuf::from)
        };
        if meta.is_file() {
            let name = base.with_context(|| format!("{} has no file name", root.display()))?;
            out.push_file(root.clone(), &name, &meta, preserve)?;
            continue;
        }
        if !meta.is_dir() {
            out.skip(root.clone(), SkipReason::NotRegular);
            continue;
        }
        let walk = WalkDir::new(root)
            .follow_links(follow_symlinks)
            .follow_root_links(follow_symlinks)
            .sort_by_file_name();
        for entry in walk {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => match unfollowable(&e) {
                    Some((path, reason)) => {
                        out.skip(path, reason);
                        continue;
                    }
                    None => return Err(e).with_context(|| format!("walking {}", root.display())),
                },
            };
            let inner = entry.path().strip_prefix(root)?;
            let named = match &base {
                Some(base) => base.join(inner),
                None => inner.to_path_buf(),
            };
            if named.as_os_str().is_empty() {
                continue;
            }
            let meta = if entry.depth() == 0 {
                meta.clone()
            } else {
                entry
                    .metadata()
                    .with_context(|| format!("reading {}", entry.path().display()))?
            };
            let file_type = entry.file_type();
            if file_type.is_dir() {
                let path = wire_path(&named, entry.path())?;
                out.map
                    .entries
                    .push(entry_for(path, EntryKind::Dir, &meta, preserve));
            } else if file_type.is_file() {
                out.push_file(entry.into_path(), &named, &meta, preserve)?;
            } else if file_type.is_symlink() {
                out.skip(entry.into_path(), SkipReason::NotFollowed);
            } else {
                out.skip(entry.into_path(), SkipReason::NotRegular);
            }
        }
    }
    Ok(out)
}

/// A walk error that only means one followed link cannot be sent.
fn unfollowable(e: &walkdir::Error) -> Option<(PathBuf, SkipReason)> {
    let path = e.path()?.to_path_buf();
    if let Some(ancestor) = e.loop_ancestor() {
        let ancestor = Some(ancestor.to_path_buf());
        return Some((path, SkipReason::Loop { ancestor }));
    }
    let io = e.io_error()?;
    if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_symlink()) {
        return None;
    }
    let reason = if io.kind() == io::ErrorKind::NotFound {
        SkipReason::Dangling
    } else if is_link_cycle(io) {
        SkipReason::Loop { ancestor: None }
    } else {
        return None;
    };
    Some((path, reason))
}

#[cfg(unix)]
fn is_link_cycle(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(windows)]
fn is_link_cycle(e: &io::Error) -> bool {
    const ERROR_CANT_RESOLVE_FILENAME: i32 = 1921;
    e.raw_os_error() == Some(ERROR_CANT_RESOLVE_FILENAME)
}

impl Captured {
    fn skip(&mut self, path: PathBuf, reason: SkipReason) {
        self.skipped.push(Skipped { path, reason });
    }

    fn push_file(
        &mut self,
        source: PathBuf,
        named: &Path,
        meta: &Metadata,
        preserve: Preserve,
    ) -> Result<()> {
        let path = wire_path(named, &source)?;
        let file_id = u32::try_from(self.files.len()).context("too many files")?;
        self.map.entries.push(entry_for(
            path.clone(),
            EntryKind::File { file_id },
            meta,
            preserve,
        ));
        self.files.push(CapturedFile {
            source,
            path,
            size: meta.len(),
            mtime: meta
                .modified()
                .ok()
                .and_then(unix_nanos)
                .and_then(|n| u64::try_from(n).ok())
                .unwrap_or(0),
        });
        Ok(())
    }
}

fn wire_path(named: &Path, source: &Path) -> Result<WirePath> {
    WirePath::from_os_path(named).with_context(|| format!("cannot send {}", source.display()))
}

fn entry_for(path: WirePath, kind: EntryKind, meta: &Metadata, preserve: Preserve) -> Entry {
    let times = |t: io::Result<SystemTime>| t.ok().and_then(unix_nanos).filter(|_| preserve.times);
    Entry {
        path,
        kind,
        mode: preserve.perms.then(|| mode_of(meta)),
        mtime: times(meta.modified()),
        atime: times(meta.accessed()),
        owner: owner_of(meta).filter(|_| preserve.owner),
    }
}

fn unix_nanos(t: SystemTime) -> Option<i64> {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).ok(),
        Err(e) => i64::try_from(e.duration().as_nanos()).ok().map(|n| -n),
    }
}

fn file_time(nanos: i64) -> FileTime {
    const NS: i64 = 1_000_000_000;
    FileTime::from_unix_time(nanos.div_euclid(NS), nanos.rem_euclid(NS) as u32)
}

#[cfg(unix)]
fn mode_of(meta: &Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o7777
}

/// Windows has no mode bits, so they are synthesized from the read-only
/// attribute.
#[cfg(windows)]
fn mode_of(meta: &Metadata) -> u32 {
    let mode = if meta.is_dir() { 0o755 } else { 0o644 };
    if meta.permissions().readonly() {
        mode & !0o222
    } else {
        mode
    }
}

#[cfg(unix)]
fn owner_of(meta: &Metadata) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.uid(), meta.gid()))
}

#[cfg(windows)]
fn owner_of(_: &Metadata) -> Option<(u32, u32)> {
    None
}

/// Creates every directory, then applies file metadata, then directory
/// metadata deepest first, so neither new entries nor a read-only
/// directory can undo or block the rest. Never fails; each problem becomes
/// a warning.
pub fn apply(map: &FileMap, out_dir: &Path, policy: ApplyPolicy) -> Vec<String> {
    let mut warnings = Vec::new();
    let chown = match owner_refusal(policy) {
        None => true,
        Some(reason) => {
            if map.entries.iter().any(|e| e.owner.is_some()) {
                warnings.push(format!("file ownership not applied: {reason}"));
            }
            false
        }
    };
    let (mut dirs, files): (Vec<&Entry>, Vec<&Entry>) =
        map.entries.iter().partition(|e| e.kind == EntryKind::Dir);
    for dir in &dirs {
        if let Err(e) = fs::create_dir_all(dir.path.to_local_path(out_dir)) {
            warnings.push(format!(
                "{}: cannot create directory: {e}",
                dir.path.display()
            ));
        }
    }
    dirs.sort_by_key(|e| Reverse(e.path.components().len()));
    for entry in files.into_iter().chain(dirs) {
        let applied = open_entry(out_dir, &entry.path)
            .map_err(anyhow::Error::from)
            .and_then(|file| apply_entry(entry, &file, policy, chown));
        if let Err(e) = applied {
            warnings.push(format!("{}: {e:#}", entry.path.display()));
        }
    }
    warnings
}

/// Why metadata is not applied through a link.
fn link_refused() -> io::Error {
    io::Error::other("is a symbolic link on the receiver; metadata not applied")
}

/// Opens an entry under `out_dir` for its metadata calls, following no
/// symbolic link on the way: each parent is opened with `O_NOFOLLOW`
/// relative to the one before, so a link swapped in after the check
/// cannot redirect a chmod, chown, or utime to a file outside `out_dir`.
#[cfg(unix)]
fn open_entry(out_dir: &Path, path: &WirePath) -> io::Result<fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let relative = path.to_local_path(Path::new(""));
    let names = relative
        .components()
        .map(|c| CString::new(c.as_os_str().as_bytes()).map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    let mut current = fs::File::open(out_dir)?;
    for (i, name) in names.iter().enumerate() {
        let dir_only = if i + 1 < names.len() {
            libc::O_DIRECTORY
        } else {
            0
        };
        let flags =
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | dir_only;
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::ELOOP) | Some(libc::ENOTDIR) => link_refused(),
                _ => e,
            });
        }
        current = unsafe { fs::File::from_raw_fd(fd) };
    }
    Ok(current)
}

/// Opens an entry under `out_dir` for its metadata calls without following
/// a reparse point (symbolic link or junction), checking every parent the
/// same way. Unlike the Unix walk, a parent could still be swapped between
/// its check and the final open.
#[cfg(windows)]
fn open_entry(out_dir: &Path, path: &WirePath) -> io::Result<fs::File> {
    let parts = path.components();
    for depth in 1..parts.len() {
        let parent = WirePath::parse(parts[..depth].iter().map(|c| c.as_bytes().to_vec()))
            .map_err(io::Error::other)?;
        open_no_reparse(&parent.to_local_path(out_dir), false)?;
    }
    open_no_reparse(&path.to_local_path(out_dir), true)
}

#[cfg(windows)]
fn open_no_reparse(local: &Path, write: bool) -> io::Result<fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let access = FILE_READ_ATTRIBUTES | if write { FILE_WRITE_ATTRIBUTES } else { 0 };
    let file = fs::OpenOptions::new()
        .access_mode(access)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(local)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(link_refused());
    }
    Ok(file)
}

/// Owner goes first because chown clears setuid and setgid. Every call
/// goes through `file`, the handle `open_entry` opened without following
/// links, never through the path again.
fn apply_entry(entry: &Entry, file: &fs::File, policy: ApplyPolicy, chown: bool) -> Result<()> {
    let meta = file.metadata()?;
    if meta.is_dir() != (entry.kind == EntryKind::Dir) {
        bail!(
            "is not a {}; metadata not applied",
            if meta.is_dir() { "file" } else { "directory" }
        );
    }
    if chown && let Some((uid, gid)) = entry.owner {
        set_owner(file, uid, gid).context("cannot set owner")?;
    }
    if entry.mtime.is_some() || entry.atime.is_some() {
        filetime::set_file_handle_times(
            file,
            entry.atime.map(file_time),
            entry.mtime.map(file_time),
        )
        .context("cannot set times")?;
    }
    if let Some(mode) = entry.mode {
        set_mode(file, &meta, mode, policy).context("cannot set permissions")?;
    }
    Ok(())
}

#[cfg(unix)]
fn owner_refusal(policy: ApplyPolicy) -> Option<&'static str> {
    if !policy.allow_owner {
        Some("the receiver was not started with --allow-owner")
    } else if unsafe { libc::geteuid() } != 0 {
        Some("the receiver is not running as root")
    } else {
        None
    }
}

#[cfg(windows)]
fn owner_refusal(_: ApplyPolicy) -> Option<&'static str> {
    Some("Windows receivers do not apply Unix owners")
}

#[cfg(unix)]
fn set_owner(file: &fs::File, uid: u32, gid: u32) -> io::Result<()> {
    std::os::unix::fs::fchown(file, Some(uid), Some(gid))
}

#[cfg(windows)]
fn set_owner(_: &fs::File, _: u32, _: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_mode(file: &fs::File, _: &Metadata, mode: u32, policy: ApplyPolicy) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let keep = if policy.allow_special_bits {
        0o7777
    } else {
        0o777
    };
    file.set_permissions(fs::Permissions::from_mode(mode & keep))
}

/// Only the read-only attribute, set through the handle.
#[cfg(windows)]
fn set_mode(file: &fs::File, meta: &Metadata, mode: u32, _: ApplyPolicy) -> io::Result<()> {
    let mut perms = meta.permissions();
    perms.set_readonly(mode & 0o200 == 0);
    file.set_permissions(perms)
}

#[cfg(test)]
mod tests;
