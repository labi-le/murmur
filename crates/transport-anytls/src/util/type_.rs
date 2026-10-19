use futures::future::BoxFuture;
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::Conn;

/// The dial-out callable type: given a cancellation token, it yields a future resolving to a
/// connection or an error. Box or share it to store (`Box<DialOutFunc>` / `Arc<DialOutFunc>`).
pub type DialOutFunc = dyn Fn(&CancellationToken) -> BoxFuture<'static, anyhow::Result<Box<dyn Conn>>> + Send + Sync;
