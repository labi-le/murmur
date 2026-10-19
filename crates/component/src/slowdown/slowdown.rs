use std::future::Future;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::backoff::Backoff;

#[derive(Debug)]
pub struct SlowDown {
    pub(crate) err_times: AtomicI64,
    pub(crate) backoff: Backoff,
}

impl Default for SlowDown {
    fn default() -> Self {
        Self {
            err_times: AtomicI64::new(0),
            backoff: Backoff {
                attempt: AtomicU64::new(0),
                min: Duration::from_millis(10),
                max: Duration::from_secs(1),
                factor: 2.0,
                jitter: true,
            },
        }
    }
}

impl SlowDown {
    // cancel-safe: the wait holds no state -- the backoff counters are only touched by the caller
    // once the wrapped call returns.
    pub async fn wait(&self, ctx: &CancellationToken) -> anyhow::Result<()> {
        tokio::select! {
            () = tokio::time::sleep(self.backoff.duration()) => {}
            () = ctx.cancelled() => {
                return Err(anyhow::anyhow!("context canceled"));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

pub async fn do_<T, F, Fut>(s: &SlowDown, ctx: &CancellationToken, f: F) -> anyhow::Result<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    if s.err_times.load(Ordering::SeqCst) > 10 {
        s.wait(ctx).await?;
    }
    match f().await {
        Ok(t) => {
            s.err_times.store(0, Ordering::SeqCst);
            s.backoff.reset();
            Ok(t)
        }
        Err(err) => {
            s.err_times.fetch_add(1, Ordering::SeqCst);
            Err(err)
        }
    }
}
