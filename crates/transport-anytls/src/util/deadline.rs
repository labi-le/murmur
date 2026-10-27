use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Creates a watcher that runs `time_out` once `ddl` elapses.
///
/// `CancellationToken::cancel` is idempotent, so the returned `done` can be called any number of
/// times. The watcher is a spawned task, so this must be called from a context that has a tokio
/// runtime; cancelling drops the pending sleep.
pub fn new_deadline_watcher(
    ddl: Duration,
    time_out: impl FnOnce() + Send + 'static,
) -> impl Fn() + Send + Sync + 'static {
    let cancel = CancellationToken::new();
    let done = cancel.clone();
    let _watcher = tokio::spawn(async move {
        tokio::select! {
            () = cancel.cancelled() => {}
            () = tokio::time::sleep(ddl) => time_out(),
        }
    });
    move || done.cancel()
}
