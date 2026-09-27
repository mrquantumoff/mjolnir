//! The file map: directory structure and metadata, captured on the sender
//! and applied by the receiver after every file is in place. See "File map"
//! in `docs/PROTOCOL.md`.

use std::cmp::Reverse;
use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use filetime::FileTime;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

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
    /// Symbolic links and special files, which are not sent.
    pub skipped: Vec<PathBuf>,
}

impl FileMap {
    /// Checks that every `File` entry names its file in the offer.
    pub fn check(&self, offer: &[WirePath]) -> Result<()> {
        for entry in &self.entries {
            if let EntryKind::File { file_id } = entry.kind {
                let offered = offer.get(file_id as usize).with_context(|| {
                    format!(
                        "file map entry {} has file_id {file_id}, but the offer has {} files",
                        entry.path.display(),
                        offer.len()
                    )
                })?;
                ensure!(
                    *offered == entry.path,
                    "file map entry {} does not match offered file {file_id} ({})",
                    entry.path.display(),
                    offered.display()
                );
            }
        }
        Ok(())
    }
}

/// Walks the sender's roots, naming them the way the sender does: a file
/// root is its own name, and a directory root's name prefixes everything
/// under it. Links are not followed.
pub fn capture(roots: &[PathBuf], preserve: Preserve) -> Result<Captured> {
    ensure!(!roots.is_empty(), "nothing to send");
    let mut out = Captured::default();
    for root in roots {
        let meta = fs::metadata(root).with_context(|| format!("reading {}", root.display()))?;
        let base = root
            .canonicalize()
            .with_context(|| format!("resolving {}", root.display()))?
            .file_name()
            .map(PathBuf::from);
        if meta.is_file() {
            let name = base.with_context(|| format!("{} has no file name", root.display()))?;
            out.push_file(root.clone(), &name, &meta, preserve)?;
            continue;
        }
        if !meta.is_dir() {
            out.skipped.push(root.clone());
            continue;
        }
        for entry in WalkDir::new(root).sort_by_file_name() {
            let entry = entry.with_context(|| format!("walking {}", root.display()))?;
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
            } else {
                out.skipped.push(entry.into_path());
            }
        }
    }
    Ok(out)
}

impl Captured {
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
        let local = entry.path.to_local_path(out_dir);
        if let Err(e) = apply_entry(entry, &local, policy, chown) {
            warnings.push(format!("{}: {e}", entry.path.display()));
        }
    }
    warnings
}

/// Owner goes first because chown clears setuid and setgid.
fn apply_entry(entry: &Entry, local: &Path, policy: ApplyPolicy, chown: bool) -> Result<()> {
    let meta = fs::symlink_metadata(local)?;
    if meta.file_type().is_symlink() {
        bail!("is a symbolic link on the receiver; metadata not applied");
    }
    if meta.is_dir() != (entry.kind == EntryKind::Dir) {
        bail!(
            "is not a {}; metadata not applied",
            if meta.is_dir() { "file" } else { "directory" }
        );
    }
    if chown && let Some((uid, gid)) = entry.owner {
        set_owner(local, uid, gid).context("cannot set owner")?;
    }
    if entry.mtime.is_some() || entry.atime.is_some() {
        set_times(
            local,
            entry.atime.map(file_time),
            entry.mtime.map(file_time),
        )
        .context("cannot set times")?;
    }
    if let Some(mode) = entry.mode {
        set_mode(local, mode, policy).context("cannot set permissions")?;
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
fn set_owner(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
}

#[cfg(windows)]
fn set_owner(_: &Path, _: u32, _: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_times(path: &Path, atime: Option<FileTime>, mtime: Option<FileTime>) -> io::Result<()> {
    match (atime, mtime) {
        (Some(a), Some(m)) => filetime::set_file_times(path, a, m),
        (None, Some(m)) => filetime::set_file_mtime(path, m),
        (Some(a), None) => filetime::set_file_atime(path, a),
        (None, None) => Ok(()),
    }
}

/// Opens with only `FILE_WRITE_ATTRIBUTES`, which a read-only file allows,
/// so applying the map a second time still works.
#[cfg(windows)]
fn set_times(path: &Path, atime: Option<FileTime>, mtime: Option<FileTime>) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let file = fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    filetime::set_file_handle_times(&file, atime, mtime)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32, policy: ApplyPolicy) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let keep = if policy.allow_special_bits {
        0o7777
    } else {
        0o777
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode & keep))
}

#[cfg(windows)]
fn set_mode(path: &Path, mode: u32, _: ApplyPolicy) -> io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_readonly(mode & 0o200 == 0);
    fs::set_permissions(path, perms)
}

#[cfg(test)]
mod tests;
