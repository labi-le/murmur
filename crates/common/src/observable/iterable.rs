use tokio::sync::mpsc;

/// The source of a [`super::observable::Observable`].
///
/// The receive-only channel is a copyable handle; the one receiving half is handed over
/// instead, since the observable drains it exactly once.
pub type Iterable<T> = mpsc::Receiver<T>;
