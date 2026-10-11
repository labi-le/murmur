use tokio_util::sync::CancellationToken;

/// A context that is never cancelled and never expired.
#[derive(Debug, Clone)]
pub(crate) struct WithoutCancelCtx {
    done: CancellationToken,
}

impl WithoutCancelCtx {
    pub(crate) fn new(_parent: &CancellationToken) -> Self {
        Self { done: CancellationToken::new() }
    }

    /// The context is cancelled by nothing, so the token is never cancelled.
    pub(crate) fn done(&self) -> CancellationToken {
        self.done.clone()
    }
}
