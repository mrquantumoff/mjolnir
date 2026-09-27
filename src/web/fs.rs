//! Directory listing for the path picker.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Serialize)]
pub struct Listing {
    pub path: PathBuf,
    pub parent: Option<PathBuf>,
    pub roots: Vec<PathBuf>,
    pub entries: Vec<Entry>,
}

#[derive(Serialize)]
pub struct Entry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: Option<u64>,
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
                is_dir: meta.is_dir(),
                size: meta.is_file().then_some(meta.len()),
                path,
            })
        })
        .collect();
    entries.sort_by(|a, b| match b.is_dir.cmp(&a.is_dir) {
        Ordering::Equal => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        other => other,
    });
    Ok(Listing {
        parent: path.parent().map(Path::to_path_buf),
        roots: roots(),
        entries,
        path,
    })
}

#[cfg(windows)]
fn roots() -> Vec<PathBuf> {
    (b'A'..=b'Z')
        .map(|d| PathBuf::from(format!("{}:\\", d as char)))
        .filter(|p| p.exists())
        .collect()
}

#[cfg(not(windows))]
fn roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}
