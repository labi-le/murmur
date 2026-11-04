use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use parking_lot::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
struct Shared<T> {
    result: Option<T>,
    err: Option<Arc<anyhow::Error>>,
    cancel: Option<CancellationToken>,
    picked: bool,
}

/// Provides synchronization and context cancelation across groups of tasks
/// working on subtasks of a common task.
#[derive(Debug)]
pub struct Picker<T> {
    shared: Arc<Mutex<Shared<T>>>,
    tasks: JoinSet<()>,
}

/// The derived context is not stored on the picker; the caller is its only user and holds it.
pub(crate) fn new_picker<T>(cancel: CancellationToken) -> Picker<T> {
    Picker {
        shared: Arc::new(Mutex::new(Shared { result: None, err: None, cancel: Some(cancel), picked: false })),
        tasks: JoinSet::new(),
    }
}

/// a new picker and an associated context derived from `ctx`, cancelled
/// when the first element returns.
#[must_use]
pub fn with_context<T>(ctx: &CancellationToken) -> (Picker<T>, CancellationToken) {
    let ctx = ctx.child_token();

    (new_picker(ctx.clone()), ctx)
}

/// a new picker and an associated context derived from `ctx` with timeout.
#[must_use]
pub fn with_timeout<T>(ctx: &CancellationToken, timeout: Duration) -> (Picker<T>, CancellationToken) {
    let ctx = ctx.child_token();
    let picker = new_picker(ctx.clone());

    let timeout_ctx = ctx.clone();
    tokio::spawn(async move {
        // cancel-safe: both arms are tokio primitives that lose nothing when dropped, and the token
        // is cancelled only by the branch that completed.
        tokio::select! {
            () = tokio::time::sleep(timeout) => timeout_ctx.cancel(),
            () = timeout_ctx.cancelled() => {}
        }
    });

    (picker, ctx)
}

impl<T> Picker<T> {
    /// Calls `f` in a new task. The first successful call cancels the group, and its result is
    /// returned by [`Picker::wait`].
    pub fn spawn<F>(&mut self, f: F)
    where
        F: Future<Output = Result<T>> + Send + 'static,
        T: Send + 'static,
    {
        let shared = Arc::clone(&self.shared);

        self.tasks.spawn(async move {
            match f.await {
                Ok(ret) => {
                    let mut guard = shared.lock();
                    if !guard.picked {
                        guard.picked = true;
                        guard.result = Some(ret);
                        if let Some(cancel) = guard.cancel.take() {
                            cancel.cancel();
                        }
                    }
                }
                Err(err) => {
                    let mut guard = shared.lock();
                    if guard.err.is_none() {
                        guard.err = Some(Arc::new(err));
                    }
                }
            }
        });
    }

    /// Waits until every function call from [`Picker::spawn`] has returned,
    /// then returns the first successful result (if any).
    pub async fn wait(&mut self) -> Option<T> {
        // cancel-safe: every await precedes the one synchronous take from the shared state, and
        // `JoinSet::join_next` removes only tasks it already completed.
        while self.tasks.join_next().await.is_some() {}

        let (result, cancel) = {
            let mut guard = self.shared.lock();
            (guard.result.take(), guard.cancel.take())
        };
        if let Some(cancel) = cancel {
            cancel.cancel();
        }

        result
    }

    /// The first error, or `None` when all succeeded. `anyhow::Error` is not
    /// cloneable, so the error is handed out behind an `Arc`.
    #[must_use]
    pub fn error(&self) -> Option<Arc<anyhow::Error>> {
        self.shared.lock().err.clone()
    }

    /// cancels the picker context and releases resources associated with
    /// it. If [`Picker::wait`] has been called, then there is no need to call this.
    pub fn close(&self) {
        let mut guard = self.shared.lock();
        if let Some(cancel) = guard.cancel.take() {
            cancel.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sleep_and_send<T: Send + 'static>(
        ctx: &CancellationToken,
        delay: u64,
        input: T,
    ) -> impl Future<Output = Result<T>> + Send {
        let ctx = ctx.clone();
        async move {
            tokio::select! {
                () = tokio::time::sleep(Duration::from_millis(delay)) => Ok(input),
                () = ctx.cancelled() => Err(anyhow::anyhow!("context canceled")),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_picker_basic() {
        let (mut picker, ctx) = with_context::<i32>(&CancellationToken::new());
        picker.spawn(sleep_and_send(&ctx, 200, 2));
        picker.spawn(sleep_and_send(&ctx, 100, 1));

        let number = picker.wait().await;
        assert_eq!(Some(1), number);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_picker_timeout() {
        let (mut picker, ctx) = with_timeout::<i32>(&CancellationToken::new(), Duration::from_millis(5));
        picker.spawn(sleep_and_send(&ctx, 100, 1));

        let number = picker.wait().await;
        assert_eq!(None, number);
        assert!(picker.error().is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_picker_second_success_dropped() {
        let (mut picker, ctx) = with_context::<i32>(&CancellationToken::new());

        // First spawn returns Ok
        picker.spawn(sleep_and_send(&ctx, 100, 1));
        let first = picker.wait().await;
        assert_eq!(Some(1), first);

        // Second spawn returns Ok but should be dropped (already picked)
        picker.spawn(sleep_and_send(&ctx, 50, 2));
        let second = picker.wait().await;
        assert_eq!(None, second);
    }
}
