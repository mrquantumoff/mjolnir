//! The process-wide request to stop: Ctrl-C, or a Stop from the Windows
//! service manager. Long-running commands end on it, whichever made it.

use std::sync::Mutex;

type Hook = Box<dyn FnOnce() + Send>;

enum State {
    Running(Vec<Hook>),
    Requested,
}

static STATE: Mutex<State> = Mutex::new(State::Running(Vec::new()));

/// Asks the process to stop and runs every hook registered so far. Only
/// the first call does anything.
pub fn request() {
    let hooks = match std::mem::replace(&mut *STATE.lock().unwrap(), State::Requested) {
        State::Running(hooks) => hooks,
        State::Requested => return,
    };
    for hook in hooks {
        hook();
    }
}

pub fn is_requested() -> bool {
    matches!(*STATE.lock().unwrap(), State::Requested)
}

/// Runs `hook` on the request, or right away if it was already made.
pub fn on_request(hook: impl FnOnce() + Send + 'static) {
    let mut state = STATE.lock().unwrap();
    match &mut *state {
        State::Running(hooks) => hooks.push(Box::new(hook)),
        State::Requested => {
            drop(state);
            hook();
        }
    }
}

/// Completes once the request is made.
pub async fn requested() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    on_request(move || {
        let _ = tx.send(());
    });
    let _ = rx.await;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

    use super::*;

    // One test, because the request cannot be taken back.
    #[test]
    fn hooks_run_once_whether_registered_before_or_after() {
        let runs = Arc::new(AtomicU32::new(0));
        let count = || {
            let runs = runs.clone();
            move || {
                runs.fetch_add(1, Relaxed);
            }
        };
        on_request(count());
        let waiter = std::thread::spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(requested())
        });
        assert!(!is_requested());
        assert_eq!(runs.load(Relaxed), 0);
        request();
        request();
        assert!(is_requested());
        assert_eq!(runs.load(Relaxed), 1);
        on_request(count());
        assert_eq!(runs.load(Relaxed), 2);
        waiter.join().unwrap();
    }
}
