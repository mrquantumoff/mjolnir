//! Per-file chunk presence: a lock-free bitset and its on-disk checkpoint.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Bit `k` is chunk `k`.
pub struct AtomicBitset {
    words: Vec<AtomicU64>,
    len: u64,
}

impl AtomicBitset {
    pub fn new(len: u64) -> Self {
        let words = (0..len.div_ceil(64)).map(|_| AtomicU64::new(0)).collect();
        AtomicBitset { words, len }
    }

    /// Builds from the wire/state byte form (bit `k` = byte `k / 8`, bit
    /// `k % 8`, least significant first), a word at a time. Bits past
    /// `len` are ignored.
    pub fn from_bytes(len: u64, bytes: &[u8]) -> Self {
        let words = (0..len.div_ceil(64))
            .map(|w| {
                let mut raw = [0u8; 8];
                let start = (w * 8) as usize;
                if start < bytes.len() {
                    let n = (bytes.len() - start).min(8);
                    raw[..n].copy_from_slice(&bytes[start..start + n]);
                }
                AtomicU64::new(u64::from_le_bytes(raw) & Self::mask(len, w))
            })
            .collect();
        AtomicBitset { words, len }
    }

    /// The valid bits of word `w` of a bitset `len` long.
    fn mask(len: u64, w: u64) -> u64 {
        let valid = len - w * 64;
        if valid >= 64 {
            u64::MAX
        } else {
            (1u64 << valid) - 1
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn count_zeros(&self) -> u64 {
        self.len - self.count_ones()
    }

    /// Snapshot of the words; bits past `len` are always zero.
    pub fn words(&self) -> Vec<u64> {
        self.words
            .iter()
            .map(|w| w.load(Ordering::Acquire))
            .collect()
    }

    /// Indices of clear bits, ascending, scanned a word at a time.
    pub fn zeros(&self) -> impl Iterator<Item = u64> + '_ {
        self.words.iter().enumerate().flat_map(move |(w, word)| {
            let mut clear = !word.load(Ordering::Acquire) & Self::mask(self.len, w as u64);
            std::iter::from_fn(move || {
                if clear == 0 {
                    return None;
                }
                let bit = clear.trailing_zeros() as u64;
                clear &= clear - 1;
                Some(w as u64 * 64 + bit)
            })
        })
    }

    pub fn first_zero(&self) -> Option<u64> {
        self.zeros().next()
    }

    pub fn last_zero(&self) -> Option<u64> {
        self.words.iter().enumerate().rev().find_map(|(w, word)| {
            let clear = !word.load(Ordering::Acquire) & Self::mask(self.len, w as u64);
            (clear != 0).then(|| w as u64 * 64 + 63 - clear.leading_zeros() as u64)
        })
    }

    /// Whether any bit clear in `before` is set here.
    pub fn gained_over(&self, before: &AtomicBitset) -> bool {
        self.words
            .iter()
            .zip(&before.words)
            .enumerate()
            .any(|(w, (now, then))| {
                !then.load(Ordering::Acquire)
                    & now.load(Ordering::Acquire)
                    & Self::mask(self.len, w as u64)
                    != 0
            })
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Sets bit `k`; returns whether it was newly set.
    pub fn set(&self, k: u64) -> bool {
        let mask = 1u64 << (k % 64);
        self.words[(k / 64) as usize].fetch_or(mask, Ordering::AcqRel) & mask == 0
    }

    /// Clears bit `k`; returns whether it was set.
    pub fn clear(&self, k: u64) -> bool {
        let mask = 1u64 << (k % 64);
        self.words[(k / 64) as usize].fetch_and(!mask, Ordering::AcqRel) & mask != 0
    }

    pub fn get(&self, k: u64) -> bool {
        self.words[(k / 64) as usize].load(Ordering::Acquire) >> (k % 64) & 1 == 1
    }

    pub fn count_ones(&self) -> u64 {
        self.words
            .iter()
            .map(|w| u64::from(w.load(Ordering::Acquire).count_ones()))
            .sum()
    }

    pub fn is_full(&self) -> bool {
        self.count_ones() == self.len
    }

    /// Snapshot in the byte form, `ceil(len / 8)` bytes long.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len.div_ceil(8) as usize);
        for w in &self.words {
            out.extend_from_slice(&w.load(Ordering::Acquire).to_le_bytes());
        }
        out.truncate(self.len.div_ceil(8) as usize);
        out
    }
}

/// The receiver's `.mjolnir-state` file contents.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartState {
    pub size: u64,
    pub mtime: u64,
    pub chunk_size: u32,
    pub bitmap: Vec<u8>,
}

impl PartState {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        postcard::from_bytes(&bytes).with_context(|| format!("parsing {}", path.display()))
    }

    /// Atomically and durably replaces `path`: write an owner-only temp
    /// file, sync it, rename over, sync the directory.
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = tmp_path(path);
        let bytes = postcard::to_allocvec(self)?;
        let mut file = crate::fsops::open_private(&tmp, true)
            .with_context(|| format!("creating {}", tmp.display()))?;
        file.set_len(0)?;
        file.write_all(&bytes)?;
        file.sync_data()?;
        drop(file);
        crate::fsops::rename_durable(&tmp, path, true)
            .with_context(|| format!("replacing {}", path.display()))
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_and_count() {
        let b = AtomicBitset::new(130);
        assert!(!b.get(0));
        assert!(b.set(0));
        assert!(!b.set(0));
        assert!(b.set(64));
        assert!(b.set(129));
        assert!(b.get(129) && b.get(64) && !b.get(1));
        assert_eq!(b.count_ones(), 3);
        assert!(b.clear(64));
        assert!(!b.clear(64));
        assert!(!b.get(64));
        assert!(b.set(64));
        assert!(!b.is_full());
        for k in 0..130 {
            b.set(k);
        }
        assert!(b.is_full());
    }

    #[test]
    fn snapshot_roundtrip_and_byte_order() {
        let b = AtomicBitset::new(11);
        b.set(0);
        b.set(9);
        b.set(10);
        let bytes = b.to_bytes();
        assert_eq!(bytes, vec![0b0000_0001, 0b0000_0110]);
        let c = AtomicBitset::from_bytes(11, &bytes);
        assert_eq!(c.to_bytes(), bytes);
        assert_eq!(c.count_ones(), 3);
    }

    #[test]
    fn from_bytes_ignores_bits_past_len_and_short_input() {
        let c = AtomicBitset::from_bytes(3, &[0xFF]);
        assert_eq!(c.count_ones(), 3);
        let d = AtomicBitset::from_bytes(20, &[0xFF]);
        assert_eq!(d.count_ones(), 8);
    }

    #[test]
    fn word_scans_match_bit_scans() {
        for len in [0u64, 1, 63, 64, 65, 130, 1000] {
            let b = AtomicBitset::new(len);
            for k in (0..len).filter(|k| k % 7 == 0 || k % 11 == 3) {
                b.set(k);
            }
            let slow: Vec<u64> = (0..len).filter(|&k| !b.get(k)).collect();
            assert_eq!(b.zeros().collect::<Vec<_>>(), slow, "{len}");
            assert_eq!(b.count_zeros(), slow.len() as u64);
            assert_eq!(b.first_zero(), slow.first().copied());
            assert_eq!(b.last_zero(), slow.last().copied());
            assert_eq!(
                AtomicBitset::from_bytes(len, &b.to_bytes()).to_bytes(),
                b.to_bytes()
            );
            let later = AtomicBitset::from_bytes(len, &b.to_bytes());
            assert!(!later.gained_over(&b));
            if let Some(k) = slow.first() {
                later.set(*k);
                assert!(later.gained_over(&b));
                assert!(!b.gained_over(&later));
            }
        }
    }

    #[test]
    fn empty_bitset_is_full() {
        let b = AtomicBitset::new(0);
        assert!(b.is_full());
        assert!(b.to_bytes().is_empty());
    }

    #[test]
    fn state_file_persist_roundtrip() {
        let dir = std::env::temp_dir().join(format!("mjolnir-bitset-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.mjolnir-state");
        let bits = AtomicBitset::new(100);
        for k in (0..100).step_by(3) {
            bits.set(k);
        }
        let state = PartState {
            size: 100 * 4096,
            mtime: 42,
            chunk_size: 4096,
            bitmap: bits.to_bytes(),
        };
        state.save(&path).unwrap();
        state.save(&path).unwrap();
        let loaded = PartState::load(&path).unwrap();
        assert_eq!(loaded, state);
        assert_eq!(
            AtomicBitset::from_bytes(100, &loaded.bitmap).to_bytes(),
            bits.to_bytes()
        );
        assert!(!tmp_path(&path).exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
