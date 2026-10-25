use tokio_util::sync::CancellationToken;

use super::withoutcancel_compact::WithoutCancelCtx;

/// Returns a context that is never cancelled and has no deadline; there is no null parent to
/// reject, unlike the panic a null parent would raise.
#[must_use]
pub fn without_cancel(parent: &CancellationToken) -> CancellationToken {
    WithoutCancelCtx::new(parent).done()
}
