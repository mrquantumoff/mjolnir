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
//! `MJOLNIR_WRITERS_PER_FILE=N` sets how many pool workers may be inside
//! one file's chunk write at once. The default is 1; larger values
//! reproduce the inode-lock contention measured in `docs/BENCHMARKS.md`.

use std::sync::OnceLock;

#[derive(Debug)]
pub(crate) struct BenchMode {
    pub(crate) discard: bool,
    pub(crate) memory_source: bool,
    pub(crate) writers_per_file: usize,
}

pub(crate) fn get() -> &'static BenchMode {
    static MODE: OnceLock<BenchMode> = OnceLock::new();
    MODE.get_or_init(|| {
        let mut mode = BenchMode {
            discard: false,
            memory_source: false,
            writers_per_file: 1,
        };
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
            .filter(|&n| n > 0)
            .unwrap_or(1);
        if mode.discard || mode.memory_source || mode.writers_per_file != 1 {
            eprintln!("mjolnir: benchmark mode {mode:?}");
        }
        mode
    })
}
