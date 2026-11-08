use std::any::Any;
use std::backtrace::Backtrace;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Runs `f` every `d` until `ctx` is cancelled.
///
/// A panicking `f` is logged and then stops the routine. No stack trace is available at the panic
/// site, so the report carries the `Backtrace` captured where the panic is caught. The routine is
/// spawned on the ambient tokio runtime.
pub fn start_routine(ctx: CancellationToken, d: Duration, f: impl Fn() + Send + 'static) {
    let _routine = tokio::spawn(async move {
        loop {
            tokio::time::sleep(d).await;
            if let Err(payload) = catch_unwind(AssertUnwindSafe(&f)) {
                murmur_log::errorln!("[BUG] {} {}", panic_message(&*payload), Backtrace::force_capture());
                return;
            }
            if ctx.is_cancelled() {
                return;
            }
        }
    });
}

/// Renders the value recovered from a panic.
fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        format!("{payload:?}")
    }
}
