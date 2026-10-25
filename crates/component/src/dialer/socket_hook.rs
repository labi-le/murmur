use std::sync::Arc;

use futures::future::BoxFuture;
use parking_lot::RwLock;

use super::control::{add_control_to_dialer, add_control_to_listen_config, StdDialer, StdListenConfig};

/// A plain closure rather than a trait, since it is assigned directly.
pub type SocketControl = Arc<dyn Fn(String, String, usize) -> BoxFuture<'static, anyhow::Result<()>> + Send + Sync>;

static DEFAULT_SOCKET_HOOK: RwLock<Option<SocketControl>> = RwLock::new(None);

/// The process-wide hook, read and assigned directly.
pub fn default_socket_hook() -> Option<SocketControl> {
    DEFAULT_SOCKET_HOOK.read().clone()
}

pub fn set_default_socket_hook(hook: Option<SocketControl>) {
    *DEFAULT_SOCKET_HOOK.write() = hook;
}

/// Applies the process-wide hook to a dialer; the doubled `to` in the name is kept for continuity.
pub(crate) fn socket_hook_to_to_dialer(dialer: &mut StdDialer) {
    add_control_to_dialer(
        dialer,
        Arc::new(|_ctx, network, address, fd| {
            Box::pin(async move {
                match default_socket_hook() {
                    Some(hook) => hook(network, address, fd).await,
                    None => Err(anyhow::anyhow!("socket hook is nil")),
                }
            })
        }),
    );
}

pub(crate) fn socket_hook_to_listen_config(lc: &mut StdListenConfig) {
    add_control_to_listen_config(
        lc,
        Arc::new(|_ctx, network, address, fd| {
            Box::pin(async move {
                match default_socket_hook() {
                    Some(hook) => hook(network, address, fd).await,
                    None => Err(anyhow::anyhow!("socket hook is nil")),
                }
            })
        }),
    );
}
