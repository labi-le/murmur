use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Runs `f` on its own task once `ctx` is cancelled; the returned stop function reports whether
/// it won the race and thereby kept `f` from running. Dropping the stop function without calling
/// it leaves `f` armed, as dropping the `stop` value does.
pub(crate) fn after_func<F>(ctx: &CancellationToken, f: F) -> impl Fn() -> bool + Send + Sync + 'static
where
    F: FnOnce() + Send + 'static,
{
    let stop = Arc::new(Notify::new());
    let claimed = Arc::new(AtomicBool::new(false));
    let token = ctx.clone();
    let watcher_stop = Arc::clone(&stop);
    let watcher_claimed = Arc::clone(&claimed);
    tokio::spawn(async move {
        tokio::select! {
            () = token.cancelled() => {
                if !watcher_claimed.swap(true, Ordering::SeqCst) {
                    tokio::spawn(async move { f() });
                }
            }
            () = watcher_stop.notified() => {}
        }
    });

    move || {
        if claimed.swap(true, Ordering::SeqCst) {
            return false;
        }
        stop.notify_one();
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::*;

    const SHORT_DURATION: Duration = Duration::from_millis(1);
    const VERY_LONG_DURATION: Duration = Duration::from_secs(1000 * 3600);

    #[tokio::test]
    async fn test_after_func_called_after_cancel() {
        let ctx = CancellationToken::new();
        let done = Arc::new(Notify::new());
        let done_tx = Arc::clone(&done);
        let stop = after_func(&ctx, move || done_tx.notify_one());
        tokio::select! {
            () = done.notified() => panic!("AfterFunc called before context is done"),
            () = tokio::time::sleep(SHORT_DURATION) => {}
        }
        ctx.cancel();
        tokio::select! {
            () = done.notified() => {}
            () = tokio::time::sleep(VERY_LONG_DURATION) => panic!("AfterFunc not called after context is canceled"),
        }
        assert!(!stop(), "stop() = true, want false");
    }

    #[tokio::test]
    async fn test_after_func_called_after_timeout() {
        let ctx = CancellationToken::new();
        let timeout_ctx = ctx.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(SHORT_DURATION).await;
            timeout_ctx.cancel();
        });
        let done = Arc::new(Notify::new());
        let done_tx = Arc::clone(&done);
        let _ = after_func(&ctx, move || done_tx.notify_one());
        tokio::select! {
            () = done.notified() => {}
            () = tokio::time::sleep(VERY_LONG_DURATION) => panic!("AfterFunc not called after context is canceled"),
        }
        cancel_task.await.expect("timeout task joins");
    }

    #[tokio::test]
    async fn test_after_func_called_immediately() {
        let ctx = CancellationToken::new();
        ctx.cancel();
        let done = Arc::new(Notify::new());
        let done_tx = Arc::clone(&done);
        let _ = after_func(&ctx, move || done_tx.notify_one());
        tokio::select! {
            () = done.notified() => {}
            () = tokio::time::sleep(VERY_LONG_DURATION) => panic!("AfterFunc not called for already-canceled context"),
        }
    }

    #[tokio::test]
    async fn test_after_func_not_called_after_stop() {
        let ctx = CancellationToken::new();
        let done = Arc::new(Notify::new());
        let done_tx = Arc::clone(&done);
        let stop = after_func(&ctx, move || done_tx.notify_one());
        assert!(stop(), "stop() = false, want true");
        ctx.cancel();
        tokio::select! {
            () = done.notified() => panic!("AfterFunc called for already-canceled context"),
            () = tokio::time::sleep(SHORT_DURATION) => {}
        }
        assert!(!stop(), "stop() = true, want false");
    }

    // This test verifies that canceling a context does not block waiting for AfterFuncs to finish.
    #[tokio::test]
    async fn test_after_func_called_asynchronously() {
        let ctx = CancellationToken::new();
        let done = Arc::new(Notify::new());
        let done_tx = Arc::clone(&done);
        let stop = after_func(&ctx, move || done_tx.notify_one());
        ctx.cancel();
        // After cancel returns, the AfterFunc runs and wakes the test task.
        tokio::select! {
            () = done.notified() => {}
            () = tokio::time::sleep(VERY_LONG_DURATION) => panic!("AfterFunc not called after context is canceled"),
        }
        let _ = stop();
    }
}
