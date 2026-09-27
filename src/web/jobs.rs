//! Registry of transfers started from the web UI. Each job runs its blocking
//! library call on its own thread and records the outcome when it returns.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Instant, SystemTime};

use serde::Serialize;

use super::api::JobSpec;
use crate::progress::PhaseTimes;
use crate::{Cancelled, Progress};

pub type JobId = u64;

#[derive(Clone, Serialize)]
pub struct Report {
    pub files: u64,
    pub bytes: u64,
    pub elapsed_ms: u64,
    pub verified: bool,
    pub hashed: bool,
    pub chunks_resent: u64,
    pub repaired_chunks: u64,
    pub hash_repaired_chunks: u64,
    pub duplicate_chunks: u64,
    pub file_hashes: Vec<FileHash>,
    pub warnings: Vec<String>,
    pub skipped: Vec<String>,
    pub phase_times: PhaseMs,
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
    Done(Report),
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

#[derive(Default)]
pub struct Jobs {
    next_id: AtomicU64,
    map: Mutex<BTreeMap<JobId, Job>>,
}

pub enum RemoveError {
    NotFound,
    Running,
}

impl Jobs {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<JobId, Job>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers the job, then runs `work` on a new thread. The job's state
    /// leaves `Running` exactly once, when `work` returns.
    pub fn spawn<F>(self: &Arc<Self>, spec: JobSpec, work: F) -> JobId
    where
        F: FnOnce(Arc<Progress>) -> anyhow::Result<Report> + Send + 'static,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let progress = Arc::new(Progress::default());
        self.lock().insert(
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
        let jobs = Arc::clone(self);
        std::thread::spawn(move || {
            let outcome = match work(progress) {
                Ok(report) => Outcome::Done(report),
                Err(e) if e.downcast_ref() == Some(&Cancelled::Local) => Outcome::Cancelled,
                Err(e) => Outcome::Failed(format!("{e:#}")),
            };
            if let Some(job) = jobs.lock().get_mut(&id) {
                job.state = JobState::Ended {
                    at: Instant::now(),
                    outcome,
                };
            }
        });
        id
    }

    pub fn with<T>(&self, id: JobId, f: impl FnOnce(&Job) -> T) -> Option<T> {
        self.lock().get(&id).map(f)
    }

    pub fn map_newest_first<T>(&self, f: impl FnMut(&Job) -> T) -> Vec<T> {
        self.lock().values().rev().map(f).collect()
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
