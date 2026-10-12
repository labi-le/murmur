//!
//! A BSD-style-licensed singleflight implementation, copied and modified.
//!
//! Copyright 2013 the original authors, use of this source code is governed by a BSD-style
//! license.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use futures::FutureExt;
use parking_lot::Mutex;
use tokio::sync::{oneshot, watch};

/// Marks a call whose execution stopped without returning, which here is a cancelled executor
/// task.
#[derive(Debug, thiserror::Error)]
#[error("the task was aborted before it returned")]
pub(crate) struct TaskAbortedError;

/// An arbitrary value recovered from a panic with the stack trace of the call.
#[derive(Debug)]
pub(crate) struct PanicError {
    value: String,
    stack: String,
}

impl fmt::Display for PanicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n\n{}", self.value, self.stack)
    }
}

impl std::error::Error for PanicError {}

fn new_panic_error(payload: &(dyn Any + Send)) -> anyhow::Error {
    let value = if let Some(value) = payload.downcast_ref::<&str>() {
        (*value).to_owned()
    } else if let Some(value) = payload.downcast_ref::<String>() {
        value.clone()
    } else {
        "panic".to_owned()
    };
    // A stack backtrace is captured here, and its first line is dropped because the panic may no longer
    // be on the stack that reports it; a `Backtrace` has no such line.
    anyhow::Error::new(PanicError { value, stack: std::backtrace::Backtrace::capture().to_string() })
}

/// Several callers can receive the same `error`; `anyhow::Error` is not `Clone`, so the
/// shared error is reference counted and materialized with [`SharedError::into_anyhow`].
#[derive(Clone, Debug)]
pub struct SharedError(Arc<anyhow::Error>);

impl SharedError {
    #[must_use]
    pub fn new(err: anyhow::Error) -> Self {
        Self(Arc::new(err))
    }

    #[must_use]
    pub fn into_anyhow(self) -> anyhow::Error {
        anyhow::Error::new(self)
    }

    pub(crate) fn is<E: fmt::Display + fmt::Debug + Send + Sync + 'static>(&self) -> bool {
        self.0.is::<E>()
    }
}

impl fmt::Display for SharedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl std::error::Error for SharedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// `Result[T]` holds the results of `do_`, so they can be passed on a channel. No value is stored
/// next to an error.
#[derive(Debug)]
pub struct Result<T> {
    pub val: Option<T>,
    pub err: Option<SharedError>,
    pub shared: bool,
}

impl<T: Clone> Result<T> {
    pub fn outcome(&self) -> anyhow::Result<T> {
        match (&self.err, &self.val) {
            (Some(err), _) => Err(err.clone().into_anyhow()),
            (None, Some(val)) => Ok(val.clone()),
            (None, None) => Err(anyhow::anyhow!("call finished without value or error")),
        }
    }
}

/// `Call` is an in-flight or completed `do_` call.
///
/// The fields written before completion are kept apart from those read after it; the completion
/// is published through the watch channel and the counters are read independently.
pub struct Call<T> {
    done: watch::Sender<Option<Arc<Result<T>>>>,
    dups: AtomicUsize,
    chans: Mutex<Vec<oneshot::Sender<Result<T>>>>,
}

impl<T> fmt::Debug for Call<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call").finish_non_exhaustive()
    }
}

impl<T> Call<T> {
    fn new() -> Self {
        let (done, _receiver) = watch::channel(None);
        Self { done, dups: AtomicUsize::new(0), chans: Mutex::new(Vec::new()) }
    }
}

impl<T: Clone + Send + Sync> Call<T> {
    // cancel-safe: the watch receiver only reports a value it has already stored.
    #[expect(clippy::expect_used, reason = "the call owns the sender, so it outlives every waiter")]
    async fn wait(&self) -> Arc<Result<T>> {
        let mut receiver = self.done.subscribe();
        loop {
            let updated = receiver.borrow_and_update().clone();
            if let Some(result) = updated {
                return result;
            }
            receiver.changed().await.expect("a waiter holds the call, so the sender cannot be dropped");
        }
    }
}

/// `Group` represents a class of work and forms a namespace in which units of work can be executed
/// with duplicate suppression.
#[derive(Debug)]
pub struct Group<T> {
    pub mu: Mutex<HashMap<String, Arc<Call<T>>>>,
    pub store_result: bool,
}

impl<T> Default for Group<T> {
    fn default() -> Self {
        Self { mu: Mutex::new(HashMap::new()), store_result: false }
    }
}

/// Runs the epilogue of the call from `Drop` so that an
/// executor whose task is cancelled is reported as `TaskAbortedError` instead of leaving waiters parked.
#[derive(Debug)]
struct CallGuard<'g, T: Clone + Send + Sync + 'static> {
    group: &'g Group<T>,
    call: Arc<Call<T>>,
    key: &'g str,
    outcome: Option<anyhow::Result<T>>,
    normal_return: bool,
    recovered: bool,
    finished: bool,
    published: Option<Arc<Result<T>>>,
}

impl<'g, T: Clone + Send + Sync + 'static> CallGuard<'g, T> {
    const fn new(group: &'g Group<T>, call: Arc<Call<T>>, key: &'g str) -> Self {
        Self {
            group,
            call,
            key,
            outcome: None,
            normal_return: false,
            recovered: false,
            finished: false,
            published: None,
        }
    }

    #[expect(
        clippy::panic,
        reason = "a panic recovered from the call is re-raised for the caller, as the contract states"
    )]
    fn finish(&mut self) -> Option<Arc<Result<T>>> {
        if self.finished {
            return self.published.clone();
        }
        self.finished = true;

        if !self.normal_return && !self.recovered {
            self.outcome = Some(Err(anyhow::Error::new(TaskAbortedError)));
        }

        {
            let mut m = self.group.mu.lock();
            if !self.group.store_result && m.get(self.key).is_some_and(|c| Arc::ptr_eq(c, &self.call)) {
                m.remove(self.key);
            }
        }

        let shared = self.call.dups.load(Ordering::SeqCst) > 0;
        let result = Arc::new(match self.outcome.take() {
            Some(Ok(val)) => Result { val: Some(val), err: None, shared },
            Some(Err(err)) => Result { val: None, err: Some(SharedError::new(err)), shared },
            None => Result { val: None, err: None, shared },
        });
        self.published = Some(Arc::clone(&result));

        if let Some(err) = result.err.as_ref().filter(|err| err.is::<PanicError>()) {
            // The waiters cannot be unblocked by a result, so the panic is kept.
            self.call.done.send_replace(Some(Arc::clone(&result)));
            let message = err.to_string();
            panic!("{message}");
        }

        // Every other outcome, `TaskAbortedError` included, is published to the waiters on `done`
        // and to the senders queued in `chans`, so a cancelled call reaches the callers that were
        // already waiting on it.
        self.call.done.send_replace(Some(Arc::clone(&result)));
        for chan in self.call.chans.lock().drain(..) {
            let _ = chan.send(Result { val: result.val.clone(), err: result.err.clone(), shared });
        }

        self.published.clone()
    }
}

impl<T: Clone + Send + Sync + 'static> Drop for CallGuard<'_, T> {
    fn drop(&mut self) {
        self.finish();
    }
}

impl<T: Clone + Send + Sync + 'static> Group<T> {
    /// Executes and returns the results of the given function, making sure that only one execution
    /// is in-flight for a given key at a time. If a duplicate comes in, the duplicate caller waits
    /// for the original to complete and receives the same results. The returned flag reports
    /// whether the value was given to multiple callers.
    // cancel-safe: the completion runs from `CallGuard::drop`, so a cancelled caller still
    // publishes an outcome to the waiters.
    pub async fn do_<F, Fut>(&self, key: &str, f: F) -> (anyhow::Result<T>, bool)
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = anyhow::Result<T>> + Send,
    {
        let (call, duplicate) = {
            let mut m = self.mu.lock();
            let found = if let Some(call) = m.get(key) {
                call.dups.fetch_add(1, Ordering::SeqCst);
                (Arc::clone(call), true)
            } else {
                let call = Arc::new(Call::new());
                m.insert(key.to_owned(), Arc::clone(&call));
                (call, false)
            };
            drop(m);
            found
        };

        if duplicate {
            let result = call.wait().await;
            if let Some(err) = result.err.as_ref() {
                assert!(!err.is::<PanicError>(), "{err}");
            }
            return (result.outcome(), true);
        }

        self.do_call(&call, key, f).await
    }

    /// Like [`Group::do_`] but returns a channel that receives the result when it is ready.
    ///
    /// The call is completed by a spawned task, so the group has to be held in an `Arc`. A call
    /// retained by `store_result` answers a later caller with its stored result.
    // The lint resolves its level from the enclosing item, so the expectation sits here.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the `chans` guard spans the read of `done`, so `finish` cannot drain between the two"
    )]
    pub fn do_chan<F, Fut>(self: &Arc<Self>, key: &str, f: F) -> oneshot::Receiver<Result<T>>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let call = {
            let mut m = self.mu.lock();
            if let Some(call) = m.get(key) {
                call.dups.fetch_add(1, Ordering::SeqCst);
                let mut chans = call.chans.lock();
                let published = call.done.borrow().clone();
                // A call retained by `store_result` was drained once already, so its stored result
                // answers this caller instead of a sender nobody will drain.
                if let Some(result) = published {
                    drop(chans);
                    let _ = tx.send(Result { val: result.val.clone(), err: result.err.clone(), shared: result.shared });
                } else {
                    chans.push(tx);
                }
                return rx;
            }
            let call = Arc::new(Call::new());
            call.chans.lock().push(tx);
            m.insert(key.to_owned(), Arc::clone(&call));
            drop(m);
            call
        };

        let group = Arc::clone(self);
        let key = key.to_owned();
        tokio::spawn(async move {
            let _ = group.do_call(&call, &key, f).await;
        });

        rx
    }

    /// Handles the single call for a key.
    // cancel-safe: `CallGuard::drop` finishes the call when the future is dropped.
    async fn do_call<F, Fut>(&self, call: &Arc<Call<T>>, key: &str, f: F) -> (anyhow::Result<T>, bool)
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = anyhow::Result<T>> + Send,
    {
        let mut guard = CallGuard::new(self, Arc::clone(call), key);

        let payload = match catch_unwind(AssertUnwindSafe(f)) {
            Ok(future) => match AssertUnwindSafe(future).catch_unwind().await {
                Ok(outcome) => {
                    guard.normal_return = true;
                    guard.outcome = Some(outcome);
                    None
                }
                Err(payload) => Some(payload),
            },
            Err(payload) => Some(payload),
        };

        if let Some(payload) = payload.as_ref() {
            guard.outcome = Some(Err(new_panic_error(&**payload)));
            guard.recovered = true;
        }

        let published = guard.finish();
        drop(guard);

        let outcome = match published {
            Some(result) => result.outcome(),
            None => Err(anyhow::anyhow!("call finished without result")),
        };
        (outcome, call.dups.load(Ordering::SeqCst) > 0)
    }

    /// Tells singleflight to forget about a key. Future calls to `do_` for this key will call the
    /// function rather than waiting for an earlier call to complete.
    pub fn forget(&self, key: &str) {
        self.mu.lock().remove(key);
    }

    pub fn reset(&self) {
        *self.mu.lock() = HashMap::new();
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn do_chan_delivers_a_result_published_before_the_caller_arrived() {
        let Group { mu, .. } = Group::<i32>::default();
        let group = Arc::new(Group { mu, store_result: true });

        let first = group.do_chan("k", || async { Ok(1) });
        assert_eq!(first.await.expect("the first call resolves").outcome().unwrap(), 1);

        let mut second = group.do_chan("k", || async { Ok(2) });
        let got = match futures::poll!(&mut second) {
            Poll::Ready(Ok(result)) => result,
            Poll::Ready(Err(err)) => panic!("the second receiver was dropped without a result: {err}"),
            Poll::Pending => panic!("the retained call left the second receiver with no sender to wake it"),
        };
        assert_eq!(got.outcome().unwrap(), 1, "the stored result answers, not the closure's");
    }

    #[tokio::test]
    async fn aborting_a_retained_call_reaches_the_waiter_registered_before_the_abort() {
        let Group { mu, .. } = Group::<i32>::default();
        let group = Arc::new(Group { mu, store_result: true });

        let running = {
            let group = Arc::clone(&group);
            tokio::spawn(async move {
                group.do_("k", || async { std::future::pending::<anyhow::Result<i32>>().await }).await
            })
        };
        // `do_` inserts the call before it awaits the closure, so the key means the guard is live.
        while !group.mu.lock().contains_key("k") {
            tokio::task::yield_now().await;
        }

        let attached = group.do_chan("k", || async { Ok(2) });
        running.abort();
        assert!(running.await.is_err_and(|err| err.is_cancelled()), "the first call is aborted, not completed");

        let early = timeout(Duration::from_secs(5), attached)
            .await
            .expect("the abort wakes the waiter attached before it")
            .expect("the abort result is delivered instead of the sender being dropped");
        let err = early.err.expect("the aborted call reports an error");
        assert!(err.is::<TaskAbortedError>(), "the attached waiter sees the abort, not another failure");
        assert!(early.val.is_none(), "no value is stored next to the abort");

        // The abort stays stored, so a caller arriving after it is answered as well.
        let late = group.do_chan("k", || async { Ok(3) });
        let stored = match futures::poll!(late) {
            Poll::Ready(Ok(result)) => result,
            Poll::Ready(Err(err)) => panic!("the later receiver was dropped without a result: {err}"),
            Poll::Pending => panic!("the retained call left the later receiver with no sender to wake it"),
        };
        assert!(stored.err.is_some_and(|err| err.is::<TaskAbortedError>()), "the later waiter sees the same abort");
        assert!(stored.val.is_none(), "no value is stored next to the abort");
    }

    #[tokio::test]
    async fn aborting_a_call_that_is_not_retained_delivers_the_abort_to_the_waiter() {
        let group = Arc::new(Group::<i32>::default());

        let running = {
            let group = Arc::clone(&group);
            tokio::spawn(async move {
                group.do_("k", || async { std::future::pending::<anyhow::Result<i32>>().await }).await
            })
        };
        while !group.mu.lock().contains_key("k") {
            tokio::task::yield_now().await;
        }

        let attached = group.do_chan("k", || async { Ok(2) });
        running.abort();
        assert!(running.await.is_err_and(|err| err.is_cancelled()), "the first call is aborted, not completed");

        let early = timeout(Duration::from_secs(5), attached)
            .await
            .expect("the abort wakes the waiter attached before it")
            .expect("the abort result is delivered instead of the sender being dropped");
        assert!(early.err.is_some_and(|err| err.is::<TaskAbortedError>()), "the attached waiter sees the abort");
        assert!(group.mu.lock().is_empty(), "a call that is not retained leaves the map on completion");
    }
}
