//! Directory listing for the path picker.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Serialize)]
pub struct Listing {
    pub path: String,
    pub parent: Option<String>,
    pub roots: Vec<String>,
    pub entries: Vec<Entry>,
}

/// `name` is shown lossily. `path` is `None` when the full path is not valid
/// Unicode: the API cannot name such an entry exactly, so the UI offers only
/// its parent folder, whose recursion handles the raw name.
#[derive(Serialize)]
pub struct Entry {
    pub name: String,
    pub path: Option<String>,
    pub is_dir: bool,
    pub size: Option<u64>,
}

fn lossy(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

pub fn home_dir() -> PathBuf {
    std::env::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

/// Lists `dir` (the home directory when `None`), directories first, then by
/// case-insensitive name. Entries whose metadata cannot be read are skipped.
pub fn list(dir: Option<&Path>) -> std::io::Result<Listing> {
    let path = std::path::absolute(dir.map_or_else(home_dir, Path::to_path_buf))?;
    let mut entries: Vec<Entry> = std::fs::read_dir(&path)?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let path = e.path();
            let meta = std::fs::metadata(&path).or_else(|_| e.metadata()).ok()?;
            Some(Entry {
                name: e.file_name().to_string_lossy().into_owned(),
                path: path.to_str().map(str::to_owned),
                is_dir: meta.is_dir(),
                size: meta.is_file().then_some(meta.len()),
            })
        })
        .collect();
    entries.sort_by(|a, b| match b.is_dir.cmp(&a.is_dir) {
        Ordering::Equal => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        other => other,
    });
    Ok(Listing {
        path: lossy(&path),
        parent: path.parent().map(lossy),
        roots: roots(),
        entries,
    })
}

#[cfg(windows)]
fn roots() -> Vec<String> {
    (b'A'..=b'Z')
        .map(|d| format!("{}:\\", d as char))
        .filter(|p| Path::new(p).exists())
        .collect()
}

#[cfg(not(windows))]
fn roots() -> Vec<String> {
    vec!["/".to_string()]
}
