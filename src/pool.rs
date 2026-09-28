//! The crypto worker pool and the chunk buffer pool. Connections only move
//! bytes; sealing, opening, and the disk writes that follow run here, on as
//! many threads as the machine has cores.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

/// Worker count for `threads = 0`: one per core.
pub(crate) fn resolve_threads(threads: usize) -> usize {
    match threads {
        0 => thread::available_parallelism().map_or(4, |n| n.get()),
        n => n,
    }
}

/// A FIFO of jobs that `threads` workers drain by calling [`Pool::work`].
/// Jobs are plain values, so submitting one allocates nothing.
pub(crate) struct Pool<J> {
    state: Mutex<PoolState<J>>,
    cv: Condvar,
    threads: usize,
}

struct PoolState<J> {
    jobs: VecDeque<J>,
    closed: bool,
}

impl<J> Pool<J> {
    pub(crate) fn new(threads: usize) -> Self {
        Pool {
            state: Mutex::new(PoolState {
                jobs: VecDeque::with_capacity(4 * threads),
                closed: false,
            }),
            cv: Condvar::new(),
            threads,
        }
    }

    pub(crate) fn threads(&self) -> usize {
        self.threads
    }

    pub(crate) fn submit(&self, job: J) {
        self.state.lock().unwrap().jobs.push_back(job);
        self.cv.notify_one();
    }

    /// Runs jobs until the pool is closed and empty.
    pub(crate) fn work(&self, mut handle: impl FnMut(J)) {
        loop {
            let job = {
                let mut state = self.state.lock().unwrap();
                loop {
                    if let Some(job) = state.jobs.pop_front() {
                        break job;
                    }
                    if state.closed {
                        return;
                    }
                    state = self.cv.wait(state).unwrap();
                }
            };
            handle(job);
        }
    }

    /// Lets workers exit once the queue is empty.
    pub(crate) fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.cv.notify_all();
    }
}

/// A fixed set of chunk-sized buffers. Taking from an empty pool blocks,
/// which is what stops a reader from outrunning the workers.
pub(crate) struct Buffers {
    free: Mutex<Vec<Vec<u8>>>,
    cv: Condvar,
}

/// Buffers held at once: `2 * threads + connections`, shrunk to fit in
/// 1 GiB but never fewer than `threads`.
pub(crate) fn buffer_count(threads: usize, connections: usize, buf_len: usize) -> usize {
    let wanted = 2 * threads + connections;
    let fits = (1usize << 30) / buf_len.max(1);
    wanted.min(fits).max(threads)
}

impl Buffers {
    pub(crate) fn new(count: usize, len: usize) -> Self {
        Buffers {
            free: Mutex::new((0..count).map(|_| vec![0u8; len]).collect()),
            cv: Condvar::new(),
        }
    }

    /// Waits for a buffer; gives up with `None` once `stop` returns true.
    pub(crate) fn take(&self, stop: &dyn Fn() -> bool) -> Option<Vec<u8>> {
        let mut free = self.free.lock().unwrap();
        loop {
            if let Some(buf) = free.pop() {
                return Some(buf);
            }
            if stop() {
                return None;
            }
            free = self
                .cv
                .wait_timeout(free, Duration::from_millis(100))
                .unwrap()
                .0;
        }
    }

    pub(crate) fn try_take(&self) -> Option<Vec<u8>> {
        self.free.lock().unwrap().pop()
    }

    pub(crate) fn give(&self, buf: Vec<u8>) {
        self.free.lock().unwrap().push(buf);
        self.cv.notify_one();
    }
}

/// A counting semaphore that never blocks: `try_acquire` hands out at most
/// `max` permits at once, and a permit returns itself when dropped.
pub(crate) struct Permits {
    used: AtomicUsize,
    max: usize,
}

pub(crate) struct Permit(Arc<Permits>);

impl Permits {
    pub(crate) fn new(max: usize) -> Arc<Self> {
        Arc::new(Permits {
            used: AtomicUsize::new(0),
            max,
        })
    }

    pub(crate) fn try_acquire(self: &Arc<Self>) -> Option<Permit> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.max).then_some(n + 1)
            })
            .ok()
            .map(|_| Permit(self.clone()))
    }

    #[cfg(test)]
    fn in_use(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A blocking counting semaphore: `enter` waits for one of `max` slots and
/// the guard gives it back.
pub(crate) struct Gate {
    free: Mutex<usize>,
    cv: Condvar,
}

pub(crate) struct GateGuard<'a>(&'a Gate);

impl Gate {
    pub(crate) fn new(max: usize) -> Self {
        Gate {
            free: Mutex::new(max),
            cv: Condvar::new(),
        }
    }

    pub(crate) fn enter(&self) -> GateGuard<'_> {
        let mut free = self.free.lock().unwrap();
        while *free == 0 {
            free = self.cv.wait(free).unwrap();
        }
        *free -= 1;
        GateGuard(self)
    }
}

impl Drop for GateGuard<'_> {
    fn drop(&mut self) {
        *self.0.free.lock().unwrap() += 1;
        self.0.cv.notify_one();
    }
}

/// Counts jobs submitted but not finished, so a round can wait for its
/// frames to land before it reports what is present.
#[derive(Default)]
pub(crate) struct InFlight {
    count: Mutex<u64>,
    cv: Condvar,
}

impl InFlight {
    pub(crate) fn add(&self) {
        *self.count.lock().unwrap() += 1;
    }

    pub(crate) fn done(&self) {
        let mut count = self.count.lock().unwrap();
        *count -= 1;
        if *count == 0 {
            self.cv.notify_all();
        }
    }

    pub(crate) fn wait_idle(&self) {
        let mut count = self.count.lock().unwrap();
        while *count > 0 {
            count = self.cv.wait(count).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    #[test]
    fn pool_runs_every_job_then_exits_on_close() {
        let pool = Pool::new(4);
        let sum = AtomicU64::new(0);
        thread::scope(|s| {
            for _ in 0..pool.threads() {
                s.spawn(|| {
                    pool.work(|n: u64| {
                        sum.fetch_add(n, Relaxed);
                    })
                });
            }
            for n in 1..=1000 {
                pool.submit(n);
            }
            pool.close();
        });
        assert_eq!(sum.into_inner(), 500_500);
    }

    #[test]
    fn permits_never_exceed_the_limit() {
        let permits = Permits::new(3);
        let held: Vec<_> = (0..5).filter_map(|_| permits.try_acquire()).collect();
        assert_eq!(held.len(), 3);
        assert!(permits.try_acquire().is_none());
        drop(held);
        assert_eq!(permits.in_use(), 0);
        let racers: Vec<_> = thread::scope(|s| {
            let handles: Vec<_> = (0..64).map(|_| s.spawn(|| permits.try_acquire())).collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(racers.iter().flatten().count(), 3);
    }

    #[test]
    fn buffer_count_bounds() {
        assert_eq!(buffer_count(8, 4, 1 << 20), 20);
        assert_eq!(buffer_count(32, 8, 64 << 20), 32);
        assert_eq!(buffer_count(2, 1, 256 << 20), 4);
    }

    #[test]
    fn take_blocks_until_give_and_honors_stop() {
        let buffers = Buffers::new(1, 8);
        let first = buffers.take(&|| false).unwrap();
        assert!(buffers.take(&|| true).is_none());
        thread::scope(|s| {
            s.spawn(|| buffers.give(first));
            assert_eq!(buffers.take(&|| false).unwrap().len(), 8);
        });
    }
}
