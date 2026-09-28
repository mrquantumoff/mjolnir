//! The sender's chunk scheduler: which chunk each data connection sends
//! next. A connection owns one file's work and claims it in order, so its
//! reads stay sequential and the receiver sees that file's chunks arrive in
//! order on one connection. When a connection runs out it takes the largest
//! unowned file; when every file is owned it steals the second half of the
//! largest owned range, so a transfer of fewer files than connections still
//! uses every connection, with the overlap on one file bounded.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use crate::bitset::AtomicBitset;
use crate::manifest::ChunkId;

/// A range is not split when either half would be smaller than this; the
/// remainder is shared one chunk at a time instead.
const MIN_SPLIT: u64 = 8;

pub(crate) struct Scheduler {
    state: Mutex<State>,
}

struct State {
    /// Every piece of unclaimed work; `None` once exhausted.
    entries: Vec<Option<Entry>>,
    /// `(remaining, entry)` for entries nobody owns.
    unowned: BTreeSet<(u64, usize)>,
    /// The entry each connection owns.
    owners: HashMap<u32, usize>,
}

struct Entry {
    file: u32,
    chunks: Chunks,
}

/// Chunks of one file still to claim, in ascending order.
enum Chunks {
    Range { next: u64, end: u64 },
    List { items: Vec<u64>, next: usize },
}

impl Chunks {
    fn remaining(&self) -> u64 {
        match self {
            Chunks::Range { next, end } => end - next,
            Chunks::List { items, next } => (items.len() - next) as u64,
        }
    }

    fn pop(&mut self) -> Option<u64> {
        if self.remaining() == 0 {
            return None;
        }
        match self {
            Chunks::Range { next, .. } => {
                *next += 1;
                Some(*next - 1)
            }
            Chunks::List { items, next } => {
                *next += 1;
                Some(items[*next - 1])
            }
        }
    }

    /// Takes the second half; both halves stay in ascending order.
    fn split_off(&mut self) -> Chunks {
        match self {
            Chunks::Range { next, end } => {
                let mid = *next + (*end - *next) / 2;
                let tail = Chunks::Range {
                    next: mid,
                    end: *end,
                };
                *end = mid;
                tail
            }
            Chunks::List { items, next } => {
                let mid = *next + (items.len() - *next) / 2;
                Chunks::List {
                    items: items.split_off(mid),
                    next: 0,
                }
            }
        }
    }
}

impl Scheduler {
    /// One entry per file with chunks missing from `have`: a range when the
    /// missing chunks are contiguous, a list otherwise.
    pub(crate) fn new(have: &[AtomicBitset]) -> Self {
        let mut state = State {
            entries: Vec::new(),
            unowned: BTreeSet::new(),
            owners: HashMap::new(),
        };
        for (file, bits) in have.iter().enumerate() {
            let missing = bits.count_zeros();
            let Some((first, last)) = bits.first_zero().zip(bits.last_zero()) else {
                continue;
            };
            // A contiguous gap needs no list at all: its bounds say it all.
            let chunks = if last - first + 1 == missing {
                Chunks::Range {
                    next: first,
                    end: last + 1,
                }
            } else {
                Chunks::List {
                    items: bits.zeros().collect(),
                    next: 0,
                }
            };
            state.insert_unowned(Entry {
                file: file as u32,
                chunks,
            });
        }
        Scheduler {
            state: Mutex::new(state),
        }
    }

    /// The next chunk for `conn`, or `None` when nothing is left.
    pub(crate) fn claim(&self, conn: u32) -> Option<ChunkId> {
        let mut state = self.state.lock().unwrap();
        if let Some(&id) = state.owners.get(&conn) {
            if let Some(chunk) = state.pop(id) {
                return Some(chunk);
            }
            state.owners.remove(&conn);
        }
        if let Some(largest) = state.unowned.pop_last() {
            let id = largest.1;
            state.owners.insert(conn, id);
            return state.pop(id);
        }
        let victim = state.largest_owned()?;
        let entry = state.entries[victim].as_mut().unwrap();
        if entry.chunks.remaining() < 2 * MIN_SPLIT {
            return state.pop(victim);
        }
        let stolen = Entry {
            file: entry.file,
            chunks: entry.chunks.split_off(),
        };
        let id = state.push(stolen);
        state.owners.insert(conn, id);
        state.pop(id)
    }

    /// Gives up `conn`'s file so another connection can take it over.
    pub(crate) fn release(&self, conn: u32) {
        let mut state = self.state.lock().unwrap();
        if let Some(id) = state.owners.remove(&conn) {
            let remaining = state.entries[id].as_ref().unwrap().chunks.remaining();
            state.unowned.insert((remaining, id));
        }
    }
}

impl State {
    fn push(&mut self, entry: Entry) -> usize {
        self.entries.push(Some(entry));
        self.entries.len() - 1
    }

    fn insert_unowned(&mut self, entry: Entry) {
        let remaining = entry.chunks.remaining();
        let id = self.push(entry);
        self.unowned.insert((remaining, id));
    }

    /// Pops from an owned entry, dropping the entry once it is empty.
    fn pop(&mut self, id: usize) -> Option<ChunkId> {
        let entry = self.entries[id].as_mut()?;
        let index = entry.chunks.pop()?;
        let file = entry.file;
        if entry.chunks.remaining() == 0 {
            self.entries[id] = None;
            self.owners.retain(|_, owned| *owned != id);
        }
        Some(ChunkId { file, index })
    }

    fn largest_owned(&self) -> Option<usize> {
        self.owners
            .values()
            .copied()
            .max_by_key(|&id| (self.entries[id].as_ref().unwrap().chunks.remaining(), id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::thread;

    fn have(chunks: &[u64], present: impl Fn(u32, u64) -> bool) -> Vec<AtomicBitset> {
        chunks
            .iter()
            .enumerate()
            .map(|(file, &n)| {
                let bits = AtomicBitset::new(n);
                for k in (0..n).filter(|&k| present(file as u32, k)) {
                    bits.set(k);
                }
                bits
            })
            .collect()
    }

    /// Every connection claims in turn until nothing is left; returns each
    /// connection's claims in order.
    fn drain(sched: &Scheduler, connections: u32) -> Vec<Vec<ChunkId>> {
        let mut claims = vec![Vec::new(); connections as usize];
        let mut live: Vec<u32> = (0..connections).collect();
        while !live.is_empty() {
            live.retain(|&conn| match sched.claim(conn) {
                Some(chunk) => {
                    claims[conn as usize].push(chunk);
                    true
                }
                None => false,
            });
        }
        claims
    }

    fn assert_exactly_once(claims: &[Vec<ChunkId>], chunks: &[u64]) {
        let mut seen = HashSet::new();
        for chunk in claims.iter().flatten() {
            assert!(seen.insert((chunk.file, chunk.index)), "{chunk:?} twice");
        }
        let total: u64 = chunks.iter().sum();
        assert_eq!(seen.len() as u64, total);
    }

    /// Maximal ascending runs of one file's indices; each run must be
    /// contiguous, which is what keeps reads sequential.
    fn assert_sequential_runs(claims: &[ChunkId]) {
        for pair in claims.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            if a.file == b.file && b.index > a.index {
                assert_eq!(b.index, a.index + 1, "gap between {a:?} and {b:?}");
            }
        }
    }

    #[test]
    fn enough_files_means_one_connection_per_file() {
        let chunks = [40, 40, 40, 40];
        let sched = Scheduler::new(&have(&chunks, |_, _| false));
        let claims = drain(&sched, 4);
        assert_exactly_once(&claims, &chunks);
        let mut owner: HashMap<u32, usize> = HashMap::new();
        for (conn, list) in claims.iter().enumerate() {
            for chunk in list {
                assert_eq!(*owner.entry(chunk.file).or_insert(conn), conn);
            }
            assert_sequential_runs(list);
        }
    }

    #[test]
    fn the_largest_unowned_file_goes_first() {
        let chunks = [4, 1, 17, 33, 9, 25];
        let sched = Scheduler::new(&have(&chunks, |_, _| false));
        let first: Vec<u32> = (0..3).map(|conn| sched.claim(conn).unwrap().file).collect();
        assert_eq!(first, [3, 5, 2]);
        // Connection 1 runs out of file 5 only after 25 claims; until then
        // nobody else touches it.
        for _ in 1..25 {
            assert_eq!(sched.claim(1).unwrap().file, 5);
        }
        assert_eq!(sched.claim(1).unwrap().file, 4);
    }

    #[test]
    fn one_file_splits_into_disjoint_sequential_ranges() {
        let chunks = [1000];
        let sched = Scheduler::new(&have(&chunks, |_, _| false));
        let claims = drain(&sched, 8);
        assert_exactly_once(&claims, &chunks);
        for list in &claims {
            assert!(!list.is_empty(), "every connection got work");
            assert_sequential_runs(list);
        }
    }

    #[test]
    fn a_tiny_range_is_shared_instead_of_split() {
        let chunks = [2 * MIN_SPLIT - 1];
        let sched = Scheduler::new(&have(&chunks, |_, _| false));
        let claims = drain(&sched, 3);
        assert_exactly_once(&claims, &chunks);
        assert!(claims.iter().all(|list| !list.is_empty()));
    }

    #[test]
    fn sparse_repair_lists_come_out_ascending() {
        let chunks = [100, 100];
        let sched = Scheduler::new(&have(&chunks, |file, k| (k + u64::from(file)) % 3 != 0));
        let claims = drain(&sched, 2);
        for list in &claims {
            for pair in list.windows(2) {
                assert!(pair[0].index < pair[1].index);
            }
        }
        let got: HashSet<_> = claims.iter().flatten().map(|c| (c.file, c.index)).collect();
        let want: HashSet<_> = (0..2u32)
            .flat_map(|f| (0..100).map(move |k| (f, k)))
            .filter(|&(f, k)| (k + u64::from(f)) % 3 == 0)
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn released_work_is_taken_over() {
        let chunks = [50];
        let sched = Scheduler::new(&have(&chunks, |_, _| false));
        let first = sched.claim(0).unwrap();
        assert_eq!(first.index, 0);
        sched.release(0);
        let claims = drain(&sched, 2);
        let mut all: Vec<_> = claims.iter().flatten().map(|c| c.index).collect();
        all.sort_unstable();
        assert_eq!(all, (1..50).collect::<Vec<_>>());
    }

    /// Metadata cost of starting a round, old way against new, on 2^26
    /// chunks (a 256 GiB file at 4 KiB, or 64 TiB at 1 MiB). Run with
    /// `cargo test --release --lib bench_round_metadata -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_round_metadata() {
        use std::hint::black_box;
        use std::time::Instant;
        let n = 1u64 << 26;
        type Shape = Box<dyn Fn(u64) -> bool>;
        let shapes: [(&str, Shape); 3] = [
            ("fresh", Box::new(|_| false)),
            ("contiguous resume", Box::new(move |k| k < n / 2)),
            ("fragmented", Box::new(|k| k % 3 != 0)),
        ];
        for (name, present) in shapes {
            let bits = AtomicBitset::new(n);
            for k in (0..n).filter(|&k| present(k)) {
                bits.set(k);
            }
            let have = [bits];
            let started = Instant::now();
            let queue: Vec<ChunkId> = have
                .iter()
                .enumerate()
                .flat_map(|(f, b)| {
                    (0..b.len()).filter(|&k| !b.get(k)).map(move |k| ChunkId {
                        file: f as u32,
                        index: k,
                    })
                })
                .collect();
            let missing: Vec<u64> = (0..have[0].len()).filter(|&k| !have[0].get(k)).collect();
            let contiguous = missing
                .first()
                .zip(missing.last())
                .is_some_and(|(&a, &z)| z - a + 1 == missing.len() as u64);
            black_box((&queue, &missing, contiguous));
            let old = started.elapsed();
            let old_bytes = queue.len() * std::mem::size_of::<ChunkId>() + missing.len() * 8;
            drop((queue, missing));

            let started = Instant::now();
            let count = have[0].count_zeros();
            let sched = Scheduler::new(&have);
            let list_bytes = match &sched.state.lock().unwrap().entries[..] {
                [
                    Some(Entry {
                        chunks: Chunks::List { items, .. },
                        ..
                    }),
                ] => items.len() * 8,
                _ => 0,
            };
            black_box((count, &sched));
            let new = started.elapsed();
            eprintln!(
                "{name:>18}: old {old:?} and {} MiB; new {new:?} and {} MiB",
                old_bytes >> 20,
                list_bytes >> 20
            );
        }
    }

    #[test]
    fn concurrent_claims_cover_everything_exactly_once() {
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut rand = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for _ in 0..20 {
            let files = 1 + rand(6) as usize;
            let chunks: Vec<u64> = (0..files).map(|_| 1 + rand(300)).collect();
            let sparse = rand(2) == 1;
            let salt = rand(1000);
            let bits = have(&chunks, |f, k| {
                sparse && (k * 7 + u64::from(f) + salt) % 3 == 0
            });
            let want: HashSet<_> = bits
                .iter()
                .enumerate()
                .flat_map(|(f, b)| {
                    (0..b.len())
                        .filter(|&k| !b.get(k))
                        .map(move |k| (f as u32, k))
                })
                .collect();
            let sched = Scheduler::new(&bits);
            let connections = 1 + rand(12) as u32;
            let releases = rand(4);
            let claims: Vec<Vec<ChunkId>> = thread::scope(|s| {
                let handles: Vec<_> = (0..connections)
                    .map(|conn| {
                        let sched = &sched;
                        s.spawn(move || {
                            let mut mine = Vec::new();
                            while let Some(chunk) = sched.claim(conn) {
                                mine.push(chunk);
                                if u64::from(conn) < releases && mine.len() % 5 == 0 {
                                    sched.release(conn);
                                }
                            }
                            mine
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            let mut seen = HashSet::new();
            for chunk in claims.iter().flatten() {
                assert!(seen.insert((chunk.file, chunk.index)), "{chunk:?} twice");
            }
            assert_eq!(seen, want);
        }
    }
}
