use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use tokio::sync::watch;

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

/// `Result[T]` is the outcome of one `Single` call. No value is stored next to an error.
#[derive(Debug)]
pub struct Result<T> {
    pub val: Option<T>,
    pub err: Option<SharedError>,
    pub time: DateTime<Utc>,
}

impl<T: Clone> Result<T> {
    fn outcome(&self) -> anyhow::Result<T> {
        match (&self.err, &self.val) {
            (Some(err), _) => Err(err.clone().into_anyhow()),
            (None, Some(val)) => Ok(val.clone()),
            (None, None) => Err(anyhow::anyhow!("single call finished without value or error")),
        }
    }
}

pub(crate) struct Call<T> {
    done: watch::Sender<Option<Arc<Result<T>>>>,
}

impl<T> fmt::Debug for Call<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call").finish_non_exhaustive()
    }
}

impl<T> Call<T> {
    fn new() -> Self {
        let (done, _receiver) = watch::channel(None);
        Self { done }
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

#[derive(Debug)]
pub(crate) struct State<T> {
    call: Option<Arc<Call<T>>>,
    result: Option<Arc<Result<T>>>,
}

/// `Single[T]` suppresses duplicate calls: the first caller runs `fn`, the others wait for its
/// result and share it, and the result stays cached for `wait`.
#[derive(Debug)]
pub struct Single<T> {
    pub(crate) wait: Duration,
    pub(crate) mux: Mutex<State<T>>,
}

enum Step<T> {
    Cached(Arc<Result<T>>),
    Wait(Arc<Call<T>>),
    Own(Arc<Call<T>>),
}

impl<T: Clone + Send + Sync + 'static> Single<T> {
    /// Returns `(v, err, shared)`; the error and the shared flag become
    /// `(anyhow::Result<T>, bool)`.
    // NOT cancel-safe: an owner cancelled inside `f` leaves the in-flight call behind, and a later
    // caller waits on a result that never arrives.
    pub async fn do_<F, Fut>(&self, f: F) -> (anyhow::Result<T>, bool)
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = anyhow::Result<T>> + Send,
    {
        let step = {
            let mut state = self.mux.lock();
            let cached = state.result.clone().filter(|result| !self.expired(result.time));
            let step = if let Some(result) = cached {
                Step::Cached(result)
            } else {
                // The result has expired, clear it
                state.result = None;
                if let Some(call) = state.call.clone() {
                    Step::Wait(call)
                } else {
                    let call = Arc::new(Call::new());
                    state.call = Some(Arc::clone(&call));
                    Step::Own(call)
                }
            };
            drop(state);
            step
        };

        match step {
            Step::Cached(result) => (result.outcome(), true),
            Step::Wait(call) => {
                let result = call.wait().await;
                (result.outcome(), true)
            }
            Step::Own(call) => {
                let result = Arc::new(match f().await {
                    Ok(val) => Result { val: Some(val), err: None, time: Utc::now() },
                    Err(err) => Result { val: None, err: Some(SharedError::new(err)), time: Utc::now() },
                });

                call.done.send_replace(Some(Arc::clone(&result)));

                let mut state = self.mux.lock();
                // maybe reset when fn is running
                if state.call.as_ref().is_some_and(|c| Arc::ptr_eq(c, &call)) {
                    state.call = None;
                    state.result = Some(Arc::clone(&result));
                }
                drop(state);

                (result.outcome(), false)
            }
        }
    }

    pub fn reset(&self) {
        let mut state = self.mux.lock();
        state.call = None;
        state.result = None;
    }

    fn expired(&self, time: DateTime<Utc>) -> bool {
        match Utc::now().signed_duration_since(time).to_std() {
            Ok(elapsed) => elapsed >= self.wait,
            Err(_) => false,
        }
    }
}

#[must_use]
pub const fn new_single<T>(wait: Duration) -> Single<T> {
    Single { wait, mux: Mutex::new(State { call: None, result: None }) }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI32, Ordering};

    use tokio::time::sleep;

    use super::*;

    #[tokio::test]
    async fn basic() {
        let single = Arc::new(new_single::<i32>(Duration::from_millis(200)));
        let foo = Arc::new(AtomicI32::new(0));
        let shard_count = Arc::new(AtomicI32::new(0));

        let mut handles = Vec::new();
        for _ in 0..5 {
            let single = Arc::clone(&single);
            let foo = Arc::clone(&foo);
            let shard_count = Arc::clone(&shard_count);
            handles.push(tokio::spawn(async move {
                let call = move || {
                    let foo = Arc::clone(&foo);
                    async move {
                        foo.fetch_add(1, Ordering::SeqCst);
                        sleep(Duration::from_millis(20)).await;
                        Ok(0)
                    }
                };
                let (_, shared) = single.do_(call).await;
                if shared {
                    shard_count.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for handle in handles {
            handle.await.expect("task panicked");
        }
        assert_eq!(1, foo.load(Ordering::SeqCst));
        assert_eq!(4, shard_count.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn timer() {
        let single = new_single::<i32>(Duration::from_millis(200));
        let foo = Arc::new(AtomicI32::new(0));
        let call = || {
            let foo = Arc::clone(&foo);
            async move {
                foo.fetch_add(1, Ordering::SeqCst);
                Ok(0)
            }
        };

        let _ = single.do_(call).await;
        sleep(Duration::from_millis(100)).await;
        let (_, shared) = single.do_(call).await;

        assert_eq!(1, foo.load(Ordering::SeqCst));
        assert!(shared);
    }

    #[tokio::test]
    async fn reset() {
        let single = new_single::<i32>(Duration::from_millis(200));
        let foo = Arc::new(AtomicI32::new(0));
        let call = || {
            let foo = Arc::clone(&foo);
            async move {
                foo.fetch_add(1, Ordering::SeqCst);
                Ok(0)
            }
        };

        let _ = single.do_(call).await;
        single.reset();
        let _ = single.do_(call).await;

        assert_eq!(2, foo.load(Ordering::SeqCst));
    }
}
