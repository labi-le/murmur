//! A resettable deadline and the latched close signal its waiters observe.
//!
//! [`PipeDeadline`] holds a point in time at which it fires; [`CloseSignal`] is the latched flag a
//! waiter polls or awaits. Both are shared by reference, so one deadline can be observed by many
//! waiters and re-armed while they wait.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use parking_lot::Mutex;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture, WaitForCancellationFutureOwned};

/// A latched flag: once closed it stays closed, every registered waiter is woken, and a waiter
/// arriving afterwards sees the closed state at once.
#[derive(Debug, Default)]
pub struct CloseSignal {
    closed: CancellationToken,
}

impl CloseSignal {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the signal is already closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    pub fn close(&self) {
        self.closed.cancel();
    }

    /// An owned subscription for a poll-based reader that has to keep its registration across
    /// polls; see [`CloseSignalWaiter`].
    pub fn owned_waiter(&self) -> WaitForCancellationFutureOwned {
        self.closed.clone().cancelled_owned()
    }

    /// Resolves once the signal is closed.
    ///
    /// Dropping the returned future deregisters the waiter, so a cancelled wait does not keep its
    /// task alive until the close.
    pub fn wait(&self) -> WaitForCancellationFuture<'_> {
        self.closed.cancelled()
    }
}

/// One poll-based reader's registration on a [`CloseSignal`].
///
/// Polling replaces the registered waker in place and dropping the waiter releases exactly that
/// waker, nothing being shared with, or scanned on behalf of, another waiter. The signal is
/// tracked by identity because a re-armed `PipeDeadline` hands out a different one.
#[derive(Debug, Default)]
pub struct CloseSignalWaiter {
    signal: Option<Arc<CloseSignal>>,
    registered: Option<Pin<Box<WaitForCancellationFutureOwned>>>,
}

impl CloseSignalWaiter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `signal` is closed now, registering `cx`'s waker for the close otherwise.
    ///
    /// The caller re-fetches `signal` on every poll, which is how a re-armed deadline's fresh
    /// signal replaces the retired subscription instead of being missed.
    pub fn poll_closed(&mut self, signal: &Arc<CloseSignal>, cx: &mut Context<'_>) -> bool {
        let closed = signal.is_closed() || self.registration(signal).as_mut().poll(cx).is_ready();
        if closed {
            self.registered = None;
            self.signal = None;
        }
        closed
    }

    /// Releases the waker the last poll registered while keeping the pinned subscription, so the
    /// next poll re-registers without allocating again.
    pub fn reset(&mut self, signal: &Arc<CloseSignal>) {
        if let Some(registered) = self.registered.as_mut() {
            registered.set(signal.owned_waiter());
            self.signal = Some(Arc::clone(signal));
        }
    }

    fn registration(&mut self, signal: &Arc<CloseSignal>) -> &mut Pin<Box<WaitForCancellationFutureOwned>> {
        let subscribed = matches!(&self.signal, Some(known) if Arc::ptr_eq(known, signal));
        if !subscribed {
            // `set` drops the retired subscription in place, which is what releases its waker.
            match self.registered.take() {
                Some(mut registered) => {
                    registered.set(signal.owned_waiter());
                    self.registered = Some(registered);
                }
                None => self.registered = Some(Box::pin(signal.owned_waiter())),
            }
            self.signal = Some(Arc::clone(signal));
        }
        self.registered.get_or_insert_with(|| Box::pin(signal.owned_waiter()))
    }
}

/// A point in time at which the deadline fires, and the signal it fires through.
#[derive(Debug)]
pub struct PipeDeadline {
    mu: Arc<Mutex<PipeDeadlineInner>>,
}

#[derive(Debug)]
struct PipeDeadlineInner {
    timer: Option<tokio::task::JoinHandle<()>>,
    cancel: Arc<CloseSignal>,
    /// Bumped by every `set`, so a timer that fired out of an already-replaced arm can tell.
    generation: u64,
}

#[must_use]
pub fn make_pipe_deadline() -> PipeDeadline {
    PipeDeadline {
        mu: Arc::new(Mutex::new(PipeDeadlineInner {
            timer: None,
            cancel: Arc::new(CloseSignal::new()),
            generation: 0,
        })),
    }
}

impl PipeDeadline {
    /// Arms the deadline at `t`. Firing is signalled by closing the channel
    /// [`PipeDeadline::wait`] hands out; an already-fired deadline is re-armed by a `t` in the
    /// future.
    ///
    /// `None` disarms it. A `t` in the past fires it immediately.
    ///
    /// A `set` that races an already-firing timer always wins: the timer closes the signal only if
    /// the generation it captured is still current under this method's own mutex.
    pub fn set(&self, t: Option<DateTime<Utc>>) {
        let mut inner = self.mu.lock();

        if let Some(timer) = inner.timer.take() {
            timer.abort();
        }
        inner.generation += 1;
        let generation = inner.generation;

        let closed = inner.cancel.is_closed();
        let Some(t) = t else {
            // Disarmed: waiters registered on a signal that already fired need a fresh one.
            if closed {
                inner.cancel = Arc::new(CloseSignal::new());
            }
            return;
        };

        let until = t.signed_duration_since(Utc::now());
        if until > TimeDelta::zero() {
            // The signal is reused while it has not fired, so a waiter that registered before the
            // re-arm is still woken by the new timer.
            if closed {
                inner.cancel = Arc::new(CloseSignal::new());
            }
            let cancel = Arc::clone(&inner.cancel);
            let mu = Arc::clone(&self.mu);
            inner.timer = Some(tokio::spawn(async move {
                tokio::time::sleep(until.to_std().unwrap_or(Duration::MAX)).await;
                let inner = mu.lock();
                if inner.generation == generation {
                    cancel.close();
                }
            }));
            return;
        }

        // Already due: close now rather than waiting for a timer to fire.
        if !closed {
            inner.cancel.close();
        }
    }

    /// The signal that closes when the deadline is exceeded.
    #[must_use]
    pub fn wait(&self) -> Arc<CloseSignal> {
        Arc::clone(&self.mu.lock().cancel)
    }
}

#[must_use]
pub fn is_closed_chan(c: &CloseSignal) -> bool {
    c.is_closed()
}

/// A signal that is closed from the start, i.e. an always-ready channel.
#[must_use]
pub fn make_filled_chan() -> CloseSignal {
    let ch = CloseSignal::new();
    ch.close();
    ch
}

#[cfg(test)]
mod tests {
    use std::future::{poll_fn, Future};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Weak;
    use std::task::{Poll, Wake, Waker};
    use std::time::Instant;

    use super::*;

    struct WakeCount(AtomicUsize);

    impl WakeCount {
        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A waker whose task counts its wakeups, with a `Weak` handle for checking whether some
    /// registration still retains it.
    fn counting_waker() -> (Waker, Arc<WakeCount>, Weak<WakeCount>) {
        let task = Arc::new(WakeCount(AtomicUsize::new(0)));
        let weak = Arc::downgrade(&task);
        (Waker::from(Arc::clone(&task)), task, weak)
    }

    #[test]
    fn cancelling_a_wait_releases_the_waiting_task_before_the_signal_closes() {
        let signal = CloseSignal::new();
        let (waker, task, retired) = counting_waker();
        let mut waiting = Box::pin(signal.wait());
        assert!(waiting.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());

        drop(waiting);
        drop(waker);
        drop(task);

        assert!(!signal.is_closed());
        assert!(retired.upgrade().is_none(), "a cancelled wait must not keep its task alive until close");
    }

    /// A polled waiter registers its waker exactly once; the closed signal releases it again
    /// rather than keeping the task alive until the signal is dropped.
    #[test]
    fn a_waiter_first_polled_on_a_closed_signal_is_ready_and_retains_no_waker() {
        let signal = Arc::new(CloseSignal::new());
        signal.close();

        let (waker, task, task_ref) = counting_waker();
        let mut waiter = CloseSignalWaiter::new();
        assert!(waiter.poll_closed(&signal, &mut Context::from_waker(&waker)));

        drop(waker);
        drop(task);
        assert!(task_ref.upgrade().is_none(), "a closed signal must not register the waker");
    }

    #[test]
    fn one_close_wakes_every_concurrent_polled_waiter() {
        let signal = Arc::new(CloseSignal::new());
        let mut waiters = Vec::new();
        for _ in 0..4 {
            let (waker, task, _) = counting_waker();
            let mut waiter = CloseSignalWaiter::new();
            assert!(!waiter.poll_closed(&signal, &mut Context::from_waker(&waker)));
            waiters.push((waiter, task));
        }

        signal.close();
        for (mut waiter, task) in waiters {
            assert_eq!(task.count(), 1, "every polled waiter is woken by one close");
            let waker = Waker::from(Arc::clone(&task));
            assert!(waiter.poll_closed(&signal, &mut Context::from_waker(&waker)));
        }
    }

    /// Re-subscribing to the signal a re-armed deadline handed out must drop the retired
    /// subscription, so the retired signal can neither retain nor wake the waiter.
    #[test]
    fn resubscribing_releases_the_retired_waker_and_close_wakes_the_current_one() {
        let first = Arc::new(CloseSignal::new());
        let second = Arc::new(CloseSignal::new());

        let (first_waker, first_task, first_ref) = counting_waker();
        let mut waiter = CloseSignalWaiter::new();
        assert!(!waiter.poll_closed(&first, &mut Context::from_waker(&first_waker)));
        drop(first_waker);
        drop(first_task);
        assert!(first_ref.upgrade().is_some(), "the first subscription must hold the waker");

        let (second_waker, second_task, _) = counting_waker();
        assert!(!waiter.poll_closed(&second, &mut Context::from_waker(&second_waker)));

        assert!(first_ref.upgrade().is_none(), "resubscribing must release the retired waker");

        first.close();
        assert_eq!(second_task.count(), 0, "the retired signal must not wake the current waiter");
        second.close();
        assert_eq!(second_task.count(), 1);
        assert!(waiter.poll_closed(&second, &mut Context::from_waker(&second_waker)));
    }

    #[test]
    fn dropping_one_polled_waiter_releases_only_its_own_registration() {
        let signal = Arc::new(CloseSignal::new());

        let (retired_waker, retired_task, retired_ref) = counting_waker();
        let mut retired = CloseSignalWaiter::new();
        assert!(!retired.poll_closed(&signal, &mut Context::from_waker(&retired_waker)));
        drop(retired_waker);
        drop(retired_task);

        let (active_waker, active_task, active_ref) = counting_waker();
        let mut active = CloseSignalWaiter::new();
        assert!(!active.poll_closed(&signal, &mut Context::from_waker(&active_waker)));

        drop(retired);
        assert!(retired_ref.upgrade().is_none(), "dropping a waiter releases its own waker");
        assert!(active_ref.upgrade().is_some(), "another waiter's registration is untouched");

        signal.close();
        assert_eq!(active_task.count(), 1);
        assert!(active.poll_closed(&signal, &mut Context::from_waker(&active_waker)));
    }

    /// A completed operation resets its waiter: the waker goes away, the subscription stays.
    #[test]
    fn reset_releases_the_registered_waker_and_leaves_the_waiter_usable() {
        let signal = Arc::new(CloseSignal::new());

        let (first_waker, first_task, first_ref) = counting_waker();
        let mut waiter = CloseSignalWaiter::new();
        assert!(!waiter.poll_closed(&signal, &mut Context::from_waker(&first_waker)));
        waiter.reset(&signal);
        drop(first_waker);
        drop(first_task);
        assert!(first_ref.upgrade().is_none(), "reset must release the waker of the completed poll");

        let (next_waker, next_task, _) = counting_waker();
        assert!(!waiter.poll_closed(&signal, &mut Context::from_waker(&next_waker)));
        signal.close();
        assert_eq!(next_task.count(), 1);
    }

    /// Re-arming while the previous signal has not fired reuses it, so a waiter that registered
    /// before the re-arm is still woken by the new timer rather than being stranded.
    #[tokio::test]
    async fn a_re_armed_deadline_still_wakes_a_registered_waiter() {
        let pd = make_pipe_deadline();
        pd.set(Some(Utc::now() + TimeDelta::seconds(60)));
        let armed = pd.wait();
        assert!(!armed.is_closed());

        let mut waiter = CloseSignalWaiter::new();
        let registered = poll_fn(|cx| if waiter.poll_closed(&armed, cx) { Poll::Ready(()) } else { Poll::Pending });
        tokio::pin!(registered);
        assert!(futures::poll!(&mut registered).is_pending());

        pd.set(Some(Utc::now() + TimeDelta::milliseconds(20)));

        tokio::time::timeout(Duration::from_millis(500), registered)
            .await
            .expect("a waiter registered before the deadline was re-armed must still be woken");
    }

    /// A deadline already in the past fires without waiting for a timer, and disarming a fired
    /// deadline hands the next waiter a fresh signal.
    #[tokio::test]
    async fn a_past_deadline_fires_at_once_and_disarming_re_arms_it() {
        let pd = make_pipe_deadline();
        pd.set(Some(Utc::now() - TimeDelta::seconds(1)));
        assert!(pd.wait().is_closed());

        pd.set(None);
        let re_armed = pd.wait();
        assert!(!re_armed.is_closed());

        tokio::time::timeout(Duration::from_millis(50), re_armed.wait())
            .await
            .expect_err("a disarmed deadline must not fire");
    }

    /// A `set` racing an already-firing timer must win, so a re-arm is not cut short and a clear is
    /// not overruled. Heavy: real timers and 4000 iterations spin-waiting onto the firing edge (a
    /// paused clock removes the race), so `make test-heavy` runs it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "heavy: 4000-iteration real-timer race soak, see make test-heavy"]
    async fn pipe_deadline_set_always_wins_a_race_with_the_firing_timer() {
        for i in 0..4000u32 {
            let deadline = make_pipe_deadline();
            deadline.set(Some(Utc::now() + TimeDelta::microseconds(300)));
            let until = Instant::now() + Duration::from_micros(300 + u64::from(i % 1500));
            while Instant::now() < until {
                std::hint::spin_loop();
            }
            if i % 2 == 0 {
                deadline.set(None);
            } else {
                deadline.set(Some(Utc::now() + TimeDelta::seconds(60)));
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
            assert!(!deadline.wait().is_closed(), "iteration {i}: a set must win a race with an already-firing timer");
        }
    }

    /// Every waiter registered before the close is woken, and a waiter arriving after it returns
    /// immediately.
    #[tokio::test]
    async fn every_registered_waiter_is_woken_by_one_close() {
        let signal = Arc::new(CloseSignal::new());
        let mut waiters = Vec::new();
        for _ in 0..4 {
            let signal = Arc::clone(&signal);
            waiters.push(tokio::spawn(async move { signal.wait().await }));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;

        signal.close();
        for waiter in waiters {
            tokio::time::timeout(Duration::from_millis(500), waiter)
                .await
                .expect("every registered waiter is woken")
                .expect("no panic");
        }
        signal.wait().await;
        assert!(make_filled_chan().is_closed());
    }
}
