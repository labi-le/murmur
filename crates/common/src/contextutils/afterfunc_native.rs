use tokio_util::sync::CancellationToken;

/// Runs `f` on its own task once `ctx` is cancelled; the returned stop function reports whether
/// it won the race and thereby kept `f` from running.
pub fn after_func<F>(ctx: &CancellationToken, f: F) -> impl Fn() -> bool + Send + Sync + 'static
where
    F: FnOnce() + Send + 'static,
{
    super::afterfunc_compact::after_func(ctx, f)
}
