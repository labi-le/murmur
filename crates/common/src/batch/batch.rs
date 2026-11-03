use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

pub type Option<T> = Box<dyn FnOnce(&mut Batch<T>)>;

#[derive(Clone, Debug)]
pub struct Result<T> {
    pub value: T,
    pub err: core::option::Option<Arc<anyhow::Error>>,
}

#[derive(Debug)]
pub struct Error {
    pub key: String,
    pub err: Arc<anyhow::Error>,
}

#[must_use]
pub fn with_concurrency_num<T>(n: usize) -> Option<T> {
    Box::new(move |b: &mut Batch<T>| {
        b.queue = Some(Arc::new(Semaphore::new(n)));
    })
}

#[derive(Debug)]
struct Inner<T> {
    result: Mutex<HashMap<String, Result<T>>>,
    inflight: AtomicUsize,
    notify: Notify,
    err: OnceLock<Arc<Error>>,
    cancel: CancellationToken,
}

/// Like a task group, but with a ceiling on the number of concurrent tasks.
#[derive(Debug)]
pub struct Batch<T> {
    inner: Arc<Inner<T>>,
    queue: core::option::Option<Arc<Semaphore>>,
}

/// Counts one spawned task.
struct Done<T> {
    inner: Arc<Inner<T>>,
}

impl<T> Drop for Done<T> {
    fn drop(&mut self) {
        self.inner.inflight.fetch_sub(1, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }
}

impl<T> Batch<T> {
    pub fn spawn<F, Fut>(&self, key: &str, f: F)
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = (T, core::option::Option<anyhow::Error>)> + Send,
    {
        self.inner.inflight.fetch_add(1, Ordering::SeqCst);
        let inner = Arc::clone(&self.inner);
        let queue = self.queue.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            let _done = Done { inner: Arc::clone(&inner) };
            let Some(queue) = queue else {
                run(&inner, &key, f).await;
                return;
            };
            let permit = queue.acquire_owned().await.ok();
            run(&inner, &key, f).await;
            drop(permit);
        });
    }

    // cancel-safe: the wait only reads the in-flight counter and waits on a notification.
    pub async fn wait(&self) -> core::option::Option<Arc<Error>> {
        while self.inner.inflight.load(Ordering::SeqCst) != 0 {
            let notified = self.inner.notify.notified();
            if self.inner.inflight.load(Ordering::SeqCst) == 0 {
                break;
            }
            notified.await;
        }
        self.inner.cancel.cancel();
        self.inner.err.get().cloned()
    }

    // cancel-safe: it awaits `wait`, which is itself cancel-safe.
    pub async fn wait_and_get_result(&self) -> (HashMap<String, Result<T>>, core::option::Option<Arc<Error>>)
    where
        T: Clone,
    {
        let err = self.wait().await;
        (self.result(), err)
    }

    #[must_use]
    pub fn result(&self) -> HashMap<String, Result<T>>
    where
        T: Clone,
    {
        self.inner.result.lock().clone()
    }
}

// cancel-safe: the result slot is only written after the callback resolves, so a dropped call
// leaves the key absent rather than half-written.
async fn run<T, F, Fut>(inner: &Arc<Inner<T>>, key: &str, f: F)
where
    T: Send + 'static,
    F: FnOnce() -> Fut,
    Fut: Future<Output = (T, core::option::Option<anyhow::Error>)>,
{
    let (value, err) = f().await;

    let err = err.map(Arc::new);
    if let Some(err) = &err {
        inner.err.get_or_init(|| {
            inner.cancel.cancel();
            Arc::new(Error { key: key.to_owned(), err: Arc::clone(err) })
        });
    }

    inner.result.lock().insert(key.to_owned(), Result { value, err });
}

impl<T> Batch<T> {
    #[must_use]
    pub fn new(ctx: &CancellationToken, opts: Vec<Option<T>>) -> (Self, CancellationToken) {
        let ctx = ctx.child_token();

        let mut b = Self {
            inner: Arc::new(Inner {
                result: Mutex::new(HashMap::new()),
                inflight: AtomicUsize::new(0),
                notify: Notify::new(),
                err: OnceLock::new(),
                cancel: ctx.clone(),
            }),
            queue: None,
        };

        for o in opts {
            o(&mut b);
        }

        (b, ctx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use anyhow::anyhow;
    use tokio::time::sleep;

    use super::*;

    #[tokio::test]
    async fn test_batch() {
        let (b, _) = Batch::<String>::new(&CancellationToken::new(), vec![]);

        let now = Instant::now();
        b.spawn("foo", || async {
            sleep(Duration::from_millis(100)).await;
            ("foo".to_owned(), None)
        });
        b.spawn("bar", || async {
            sleep(Duration::from_millis(150)).await;
            ("bar".to_owned(), None)
        });
        let (result, err) = b.wait_and_get_result().await;

        assert!(err.is_none());

        let duration = now.elapsed();
        assert!(duration < Duration::from_millis(200));
        assert_eq!(2, result.len());

        for (k, v) in result {
            assert!(v.err.is_none());
            assert_eq!(k, v.value);
        }
    }

    #[tokio::test]
    async fn test_batch_with_concurrency_num() {
        let (b, _) = Batch::<String>::new(&CancellationToken::new(), vec![with_concurrency_num(3)]);

        let now = Instant::now();
        for i in 0..7 {
            let idx = i;
            b.spawn(&idx.to_string(), move || async move {
                sleep(Duration::from_millis(100)).await;
                (idx.to_string(), None)
            });
        }
        let (result, _) = b.wait_and_get_result().await;
        let duration = now.elapsed();
        assert!(duration > Duration::from_millis(260));
        assert_eq!(7, result.len());

        for (k, v) in result {
            assert!(v.err.is_none());
            assert_eq!(k, v.value);
        }
    }

    #[tokio::test]
    async fn test_batch_context() {
        let (b, ctx) = Batch::<String>::new(&CancellationToken::new(), vec![]);

        b.spawn("error", || async {
            sleep(Duration::from_millis(100)).await;
            (String::new(), Some(anyhow!("test error")))
        });

        let child = ctx.clone();
        b.spawn("ctx", move || async move {
            child.cancelled().await;
            (String::new(), Some(anyhow!("context canceled")))
        });

        let (result, err) = b.wait_and_get_result().await;

        assert!(err.is_some());
        assert_eq!("error", err.as_ref().expect("error is set").key);

        assert!(result["ctx"].err.is_some());
        assert_eq!("context canceled", result["ctx"].err.as_ref().expect("error is set").to_string());
    }
}
