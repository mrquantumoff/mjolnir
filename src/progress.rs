//! Live transfer progress shared between a transfer and its UI, plus the
//! cancellation flag the UI sets.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering::Relaxed};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum Phase {
    Connecting,
    Handshaking,
    Transferring,
    /// The receiver is reading chunks back to check their digests.
    Verifying,
    /// `send --hash`: the sender re-reads its files for chunk digests and
    /// the receiver compares them.
    Hashing,
    Finishing,
    Done,
    Failed,
}

const PHASES: [Phase; 8] = [
    Phase::Connecting,
    Phase::Handshaking,
    Phase::Transferring,
    Phase::Verifying,
    Phase::Hashing,
    Phase::Finishing,
    Phase::Done,
    Phase::Failed,
];

/// Counters a transfer updates as it runs. Share it through an `Arc`; every
/// field is an atomic, so reading it never blocks the transfer. Totals and
/// `*_done` count the chunks this session still had to move, not chunks a
/// resumed transfer already held. During `Phase::Verifying` they count the
/// receiver's read-back of every chunk instead.
#[derive(Debug)]
pub struct Progress {
    pub bytes_done: AtomicU64,
    pub bytes_total: AtomicU64,
    pub chunks_done: AtomicU64,
    pub chunks_total: AtomicU64,
    pub active_connections: AtomicU64,
    phase: AtomicU8,
    /// Time spent in each phase, indexed by `Phase as usize`, in ns, and
    /// when the current phase began, in ns since `created`.
    phase_ns: [AtomicU64; PHASES.len()],
    phase_began: AtomicU64,
    created: Instant,
    /// Set to stop the transfer. Sockets close promptly and the call returns
    /// [`Cancelled::Local`]; the receiver keeps its part and state files so
    /// a later run resumes.
    pub cancel: AtomicBool,
}

impl Default for Progress {
    fn default() -> Self {
        Progress {
            bytes_done: AtomicU64::new(0),
            bytes_total: AtomicU64::new(0),
            chunks_done: AtomicU64::new(0),
            chunks_total: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            phase: AtomicU8::new(Phase::Connecting as u8),
            phase_ns: Default::default(),
            phase_began: AtomicU64::new(0),
            created: Instant::now(),
            cancel: AtomicBool::new(false),
        }
    }
}

/// A plain copy of [`Progress`] at one instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProgressSnapshot {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub chunks_done: u64,
    pub chunks_total: u64,
    pub active_connections: u64,
    pub phase: Phase,
    pub cancelled: bool,
}

impl Progress {
    pub fn phase(&self) -> Phase {
        PHASES[usize::from(self.phase.load(Relaxed))]
    }

    pub(crate) fn set_phase(&self, phase: Phase) {
        let now = self.now_ns();
        let began = self.phase_began.swap(now, Relaxed);
        let old = self.phase.swap(phase as u8, Relaxed);
        self.phase_ns[usize::from(old)].fetch_add(now.saturating_sub(began), Relaxed);
    }

    fn now_ns(&self) -> u64 {
        u64::try_from(self.created.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// Time spent in each phase so far, the current one included, skipping
    /// phases never entered.
    pub fn phase_times(&self) -> Vec<(Phase, Duration)> {
        let current = usize::from(self.phase.load(Relaxed));
        let running = self.now_ns().saturating_sub(self.phase_began.load(Relaxed));
        PHASES
            .iter()
            .enumerate()
            .map(|(i, &p)| {
                let ns = self.phase_ns[i].load(Relaxed) + if i == current { running } else { 0 };
                (p, Duration::from_nanos(ns))
            })
            .filter(|&(_, d)| !d.is_zero())
            .collect()
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Relaxed)
    }

    pub(crate) fn set_totals(&self, chunks: u64, bytes: u64) {
        self.chunks_total.store(chunks, Relaxed);
        self.bytes_total.store(bytes, Relaxed);
    }

    pub(crate) fn reset_counts(&self) {
        self.set_totals(0, 0);
        self.chunks_done.store(0, Relaxed);
        self.bytes_done.store(0, Relaxed);
    }

    pub(crate) fn add_chunk(&self, bytes: u64) {
        self.chunks_done.fetch_add(1, Relaxed);
        self.bytes_done.fetch_add(bytes, Relaxed);
    }

    pub fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            bytes_done: self.bytes_done.load(Relaxed),
            bytes_total: self.bytes_total.load(Relaxed),
            chunks_done: self.chunks_done.load(Relaxed),
            chunks_total: self.chunks_total.load(Relaxed),
            active_connections: self.active_connections.load(Relaxed),
            phase: self.phase(),
            cancelled: self.is_cancelled(),
        }
    }

    /// Records the outcome: `Done` or `Failed`, and any error from a
    /// cancelled run becomes [`Cancelled::Local`].
    pub(crate) fn conclude<T>(&self, result: anyhow::Result<T>) -> anyhow::Result<T> {
        match result {
            Ok(v) => {
                self.set_phase(Phase::Done);
                Ok(v)
            }
            Err(e) => {
                self.set_phase(Phase::Failed);
                // A local cancel wins over whatever error it raced with,
                // including a peer's cancel.
                if self.is_cancelled() {
                    Err(Cancelled::Local.into())
                } else {
                    Err(e)
                }
            }
        }
    }
}

/// Counts one live data connection for as long as it is held.
pub(crate) struct ActiveConnection<'a>(&'a Progress);

impl<'a> ActiveConnection<'a> {
    pub(crate) fn new(progress: &'a Progress) -> Self {
        progress.active_connections.fetch_add(1, Relaxed);
        ActiveConnection(progress)
    }
}

impl Drop for ActiveConnection<'_> {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Relaxed);
    }
}

/// The error a cancelled transfer returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cancelled {
    /// This side's `Progress::cancel` was set.
    Local,
    /// The peer cancelled and said so on the control channel.
    Peer,
}

impl fmt::Display for Cancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Cancelled::Local => "transfer cancelled",
            Cancelled::Peer => "the peer cancelled the transfer",
        })
    }
}

impl std::error::Error for Cancelled {}

/// A one-shot stop signal that a periodic thread can sleep on.
#[derive(Default)]
pub(crate) struct Stop {
    stopped: Mutex<bool>,
    cv: Condvar,
}

impl Stop {
    pub(crate) fn stop(&self) {
        *self.stopped.lock().unwrap() = true;
        self.cv.notify_all();
    }

    /// Sleeps up to `timeout`; returns true once stopped.
    pub(crate) fn wait(&self, timeout: Duration) -> bool {
        let guard = self.stopped.lock().unwrap();
        *self
            .cv
            .wait_timeout_while(guard, timeout, |stopped| !*stopped)
            .unwrap()
            .0
    }
}
