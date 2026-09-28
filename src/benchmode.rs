//! Switches for measuring where time goes, read once from the
//! `MJOLNIR_BENCH` environment variable (a comma-separated list). They exist
//! for `scripts/bench.sh` and are never on in normal use.
//!
//! - `discard`: the receiver drops each chunk's plaintext instead of writing
//!   it to the part file. The output is then wrong, so pair it with
//!   `--no-verify` and do not check the result.
//! - `memory-source`: the sender reads every file into memory before it
//!   connects and serves chunks from there instead of from disk.
//!
//! `MJOLNIR_WRITERS_PER_FILE=N` caps how many pool workers may be inside
//! one file's chunk write at once; unset means no cap.

use std::sync::OnceLock;

#[derive(Debug, Default)]
pub(crate) struct BenchMode {
    pub(crate) discard: bool,
    pub(crate) memory_source: bool,
    pub(crate) writers_per_file: Option<usize>,
}

pub(crate) fn get() -> &'static BenchMode {
    static MODE: OnceLock<BenchMode> = OnceLock::new();
    MODE.get_or_init(|| {
        let mut mode = BenchMode::default();
        for item in std::env::var("MJOLNIR_BENCH")
            .unwrap_or_default()
            .split(',')
        {
            match item.trim() {
                "discard" => mode.discard = true,
                "memory-source" => mode.memory_source = true,
                _ => {}
            }
        }
        mode.writers_per_file = std::env::var("MJOLNIR_WRITERS_PER_FILE")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n| n > 0);
        if mode.discard || mode.memory_source || mode.writers_per_file.is_some() {
            eprintln!("mjolnir: benchmark mode {mode:?}");
        }
        mode
    })
}
