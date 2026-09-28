//! Registry of transfers started from the web UI. Each job runs its blocking
//! library call on its own thread and records the outcome when it returns.

use std::any::Any;
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Instant, SystemTime};

use serde::Serialize;

use super::api::JobSpec;
use crate::progress::PhaseTimes;
use crate::{Cancelled, Progress};

pub type JobId = u64;

/// A finished transfer's report: fixed-size totals, then lists that grow
/// with the number of files.
#[derive(Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub totals: Totals,
    pub file_hashes: Vec<FileHash>,
    pub warnings: Vec<String>,
    pub skipped: Vec<String>,
}

#[derive(Clone, Copy, Serialize)]
pub struct Totals {
    pub files: u64,
    pub bytes: u64,
    pub elapsed_ms: u64,
    pub verified: bool,
    pub hashed: bool,
    pub chunks_resent: u64,
    pub repaired_chunks: u64,
    pub hash_repaired_chunks: u64,
    pub stale_chunks: u64,
    pub duplicate_chunks: u64,
    pub phase_times: PhaseMs,
}

/// What the transfer list carries of a report: its totals and how long
/// each list is. The lists come from the transfer's own endpoint.
#[derive(Serialize)]
pub struct Summary {
    #[serde(flatten)]
    totals: Totals,
    file_hash_count: usize,
    warning_count: usize,
    skipped_count: usize,
}

impl From<&Report> for Summary {
    fn from(r: &Report) -> Summary {
        Summary {
            totals: r.totals,
            file_hash_count: r.file_hashes.len(),
            warning_count: r.warnings.len(),
            skipped_count: r.skipped.len(),
        }
    }
}

/// Milliseconds per stage, fractional so short phases stay visible.
#[derive(Clone, Copy, Serialize)]
pub struct PhaseMs {
    pub connect_ms: f64,
    pub transfer_ms: f64,
    pub verify_ms: f64,
    pub hash_ms: f64,
    pub finalize_ms: f64,
}

impl From<PhaseTimes> for PhaseMs {
    fn from(t: PhaseTimes) -> PhaseMs {
        let ms = |d: std::time::Duration| d.as_secs_f64() * 1000.0;
        PhaseMs {
            connect_ms: ms(t.connect),
            transfer_ms: ms(t.transfer),
            verify_ms: ms(t.verify),
            hash_ms: ms(t.hash),
            finalize_ms: ms(t.finalize),
        }
    }
}

#[derive(Clone, Serialize)]
pub struct FileHash {
    pub path: String,
    pub hash: String,
}

pub enum JobState {
    Running,
    Ended { at: Instant, outcome: Outcome },
}

pub enum Outcome {
    /// Shared so a view can take it out of the registry lock cheaply.
    Done(Arc<Report>),
    Failed(String),
    Cancelled,
}

pub struct Job {
    pub id: JobId,
    pub created_at: SystemTime,
    pub started: Instant,
    pub spec: JobSpec,
    pub progress: Arc<Progress>,
    pub state: JobState,
}

impl Job {
    pub fn is_running(&self) -> bool {
        matches!(self.state, JobState::Running)
    }

    pub fn elapsed_ms(&self) -> u64 {
        let end = match self.state {
            JobState::Running => Instant::now(),
            JobState::Ended { at, .. } => at,
        };
        end.duration_since(self.started).as_millis() as u64
    }
}

/// Transfers running at once, across the whole process.
const MAX_RUNNING: usize = 16;
/// Ended transfers kept for the UI; the oldest go first.
const MAX_ENDED: usize = 100;

pub struct Jobs {
    next_id: AtomicU64,
    map: Mutex<BTreeMap<JobId, Job>>,
    max_running: usize,
    max_ended: usize,
}

impl Default for Jobs {
    fn default() -> Self {
        Jobs::with_limits(MAX_RUNNING, MAX_ENDED)
    }
}

pub enum RemoveError {
    NotFound,
    Running,
}

/// `spawn` refused the job: `MAX_RUNNING` are already running.
pub struct Busy(pub usize);

impl Jobs {
    fn with_limits(max_running: usize, max_ended: usize) -> Self {
        Jobs {
            next_id: AtomicU64::new(0),
            map: Mutex::default(),
            max_running,
            max_ended,
        }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<JobId, Job>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers the job and runs `work` on a new thread, unless
    /// `max_running` jobs are running already. The job's state leaves
    /// `Running` exactly once: when `work` returns or panics, or at once
    /// if the thread cannot be started.
    pub fn spawn<F>(self: &Arc<Self>, spec: JobSpec, work: F) -> Result<JobId, Busy>
    where
        F: FnOnce(Arc<Progress>) -> anyhow::Result<Report> + Send + 'static,
    {
        let progress = Arc::new(Progress::default());
        let id = {
            let mut map = self.lock();
            if map.values().filter(|j| j.is_running()).count() >= self.max_running {
                return Err(Busy(self.max_running));
            }
            let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
            map.insert(
                id,
                Job {
                    id,
                    created_at: SystemTime::now(),
                    started: Instant::now(),
                    spec,
                    progress: progress.clone(),
                    state: JobState::Running,
                },
            );
            id
        };
        let jobs = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name(format!("mjolnir-job-{id}"))
            .spawn(move || {
                let outcome = match catch_unwind(AssertUnwindSafe(|| work(progress))) {
                    Ok(Ok(report)) => Outcome::Done(Arc::new(report)),
                    Ok(Err(e)) if e.downcast_ref() == Some(&Cancelled::Local) => Outcome::Cancelled,
                    Ok(Err(e)) => Outcome::Failed(format!("{e:#}")),
                    Err(panic) => Outcome::Failed(format!(
                        "internal error: {}",
                        panic_message(panic.as_ref())
                    )),
                };
                jobs.end(id, outcome);
            });
        if let Err(e) = spawned {
            self.end(id, Outcome::Failed(format!("cannot start a thread: {e}")));
        }
        Ok(id)
    }

    /// Records the outcome, then drops the oldest ended jobs beyond
    /// `max_ended`.
    fn end(&self, id: JobId, outcome: Outcome) {
        let mut map = self.lock();
        if let Some(job) = map.get_mut(&id) {
            job.state = JobState::Ended {
                at: Instant::now(),
                outcome,
            };
        }
        let ended: Vec<JobId> = map
            .values()
            .filter(|j| !j.is_running())
            .map(|j| j.id)
            .collect();
        for old in &ended[..ended.len().saturating_sub(self.max_ended)] {
            map.remove(old);
        }
    }

    #[cfg(test)]
    fn count(&self) -> usize {
        self.lock().len()
    }

    pub fn with<T>(&self, id: JobId, f: impl FnOnce(&Job) -> T) -> Option<T> {
        self.lock().get(&id).map(f)
    }

    pub fn map_newest_first<T>(&self, f: impl FnMut(&Job) -> T) -> Vec<T> {
        self.lock().values().rev().map(f).collect()
    }

    /// `(id, out_dir)` of every receive job still running.
    pub fn running_receivers(&self) -> Vec<(JobId, std::path::PathBuf)> {
        self.lock()
            .values()
            .filter(|job| job.is_running())
            .filter_map(|job| match &job.spec {
                JobSpec::Receive { out_dir, .. } => Some((job.id, out_dir.clone())),
                JobSpec::Send { .. } => None,
            })
            .collect()
    }

    pub fn cancel(&self, id: JobId) -> bool {
        self.with(id, |job| job.progress.cancel.store(true, Ordering::Relaxed))
            .is_some()
    }

    pub fn remove(&self, id: JobId) -> Result<(), RemoveError> {
        let mut map = self.lock();
        match map.get(&id) {
            None => Err(RemoveError::NotFound),
            Some(job) if job.is_running() => Err(RemoveError::Running),
            Some(_) => {
                map.remove(&id);
                Ok(())
            }
        }
    }
}

fn panic_message(panic: &(dyn Any + Send)) -> &str {
    match (panic.downcast_ref::<&str>(), panic.downcast_ref::<String>()) {
        (Some(s), _) => s,
        (_, Some(s)) => s,
        _ => "the transfer thread panicked",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn spec() -> JobSpec {
        JobSpec::Send {
            addr: "127.0.0.1:1".into(),
            peer: String::new(),
            paths: Vec::new(),
            connections: 1,
            chunk_size: 4096,
            cipher: crate::Cipher::default(),
            threads: 1,
            hash: false,
            preserve: Default::default(),
        }
    }

    fn report() -> Report {
        Report {
            totals: Totals {
                files: 0,
                bytes: 0,
                elapsed_ms: 0,
                verified: true,
                hashed: false,
                chunks_resent: 0,
                repaired_chunks: 0,
                hash_repaired_chunks: 0,
                stale_chunks: 0,
                duplicate_chunks: 0,
                phase_times: PhaseTimes::default().into(),
            },
            file_hashes: Vec::new(),
            warnings: Vec::new(),
            skipped: Vec::new(),
        }
    }

    fn wait_ended(jobs: &Jobs, id: JobId) {
        for _ in 0..500 {
            if jobs.with(id, |j| !j.is_running()) == Some(true) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("job {id} is still running");
    }

    fn failure(jobs: &Jobs, id: JobId) -> Option<String> {
        jobs.with(id, |j| match &j.state {
            JobState::Ended {
                outcome: Outcome::Failed(e),
                ..
            } => Some(e.clone()),
            _ => None,
        })
        .flatten()
    }

    #[test]
    fn a_panicking_job_ends_as_failed() {
        let jobs = Arc::new(Jobs::default());
        let id = jobs.spawn(spec(), |_| panic!("boom")).ok().unwrap();
        wait_ended(&jobs, id);
        assert_eq!(failure(&jobs, id).as_deref(), Some("internal error: boom"));
        assert!(jobs.remove(id).is_ok());
    }

    #[test]
    fn running_jobs_are_capped_and_ended_ones_pruned() {
        let jobs = Arc::new(Jobs::with_limits(2, 3));
        let (release, gate) = mpsc::channel::<()>();
        let gate = Arc::new(Mutex::new(gate));
        let blocked: Vec<JobId> = (0..2)
            .map(|_| {
                let gate = gate.clone();
                let work = move |_| {
                    gate.lock().unwrap().recv().unwrap();
                    Ok(report())
                };
                jobs.spawn(spec(), work).ok().unwrap()
            })
            .collect();
        assert!(matches!(jobs.spawn(spec(), |_| Ok(report())), Err(Busy(2))));

        for _ in &blocked {
            release.send(()).unwrap();
        }
        for id in &blocked {
            wait_ended(&jobs, *id);
        }
        for _ in 0..3 {
            let id = jobs.spawn(spec(), |_| Ok(report())).ok().unwrap();
            wait_ended(&jobs, id);
        }
        assert_eq!(jobs.count(), 3);
        assert!(blocked.iter().all(|id| jobs.with(*id, |_| ()).is_none()));
    }
}
