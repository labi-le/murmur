//! Per-direction stream deadlines.
//!
//! `quinn` has no per-stream deadline API, so read and write deadlines are enforced here: a read
//! or write whose deadline has passed fails with
//! `ErrorKind::TimedOut`, and a task armed on the deadline wakes whatever I/O is waiting so the
//! timeout is observed even when no packet arrives.

use std::sync::Arc;
use std::task::{Context, Waker};

use parking_lot::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;

struct State {
    /// `None` means no deadline, and no timer.
    at: Option<Instant>,
    reached: bool,
    /// Shared with the armed timer, which cannot take this lock itself while `expired` holds it.
    waker: Arc<Mutex<Option<Waker>>>,
    timer: Option<JoinHandle<()>>,
}

pub(super) struct Deadline {
    state: Mutex<State>,
}

impl Deadline {
    pub(super) fn new() -> Self {
        Self { state: Mutex::new(State { at: None, reached: false, waker: Arc::new(Mutex::new(None)), timer: None }) }
    }

    pub(super) fn set(&self, deadline: Option<Instant>) {
        let mut state = self.state.lock();
        state.at = deadline;
        state.reached = false;
        if let Some(timer) = state.timer.take() {
            timer.abort();
        }
    }

    /// Reports whether the deadline has passed, keeping one timer armed against the caller's waker
    /// for as long as it has not.
    pub(super) fn expired(&self, cx: &Context<'_>) -> bool {
        let mut state = self.state.lock();
        let Some(at) = state.at else { return false };
        if state.reached {
            return true;
        }
        if state.timer.is_none() {
            let waker = Arc::clone(&state.waker);
            state.timer = Some(tokio::spawn(async move {
                tokio::time::sleep_until(at).await;
                let pending_waker = waker.lock().take();
                if let Some(waker) = pending_waker {
                    waker.wake();
                }
            }));
        }
        *state.waker.lock() = Some(cx.waker().clone());
        let expired = at <= Instant::now();
        if expired {
            state.reached = true;
        }
        drop(state);
        expired
    }
}
