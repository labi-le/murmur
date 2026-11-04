use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use murmur_common_net::io::Stream;

use super::tunnel_api::TunnelDialOptions;

pub type WrapConnFn =
    Arc<dyn Fn(Box<dyn Stream>) -> Pin<Box<dyn Future<Output = anyhow::Result<Box<dyn Stream>>> + Send>> + Send + Sync>;
#[derive(Clone)]
pub struct ClientEarlyHandshake {
    pub(crate) request_payload: Vec<u8>,
    pub(crate) handle_response: Option<Arc<dyn Fn(&[u8]) -> anyhow::Result<()> + Send + Sync>>,
    pub(crate) ready: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    pub(crate) wrap_conn: Option<WrapConnFn>,
}

impl core::fmt::Debug for ClientEarlyHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientEarlyHandshake")
            .field("request_payload_len", &self.request_payload.len())
            .field("has_handle_response", &self.handle_response.is_some())
            .field("has_ready", &self.ready.is_some())
            .field("has_wrap_conn", &self.wrap_conn.is_some())
            .finish_non_exhaustive()
    }
}

pub(crate) struct TunnelServerEarlyHandshake {
    pub(crate) prepare: Arc<dyn Fn(&[u8]) -> anyhow::Result<PreparedServerEarlyHandshake> + Send + Sync>,
}

pub(crate) struct PreparedServerEarlyHandshake {
    pub(crate) response_payload: Vec<u8>,
    pub(crate) wrap_conn: Option<WrapConnFn>,
    pub(crate) user_hash: String,
}

pub(crate) async fn apply_early_handshake_or_upgrade(
    raw: Box<dyn Stream>,
    opts: &TunnelDialOptions,
) -> anyhow::Result<Box<dyn Stream>> {
    if let Some(early_handshake) = &opts.early_handshake {
        if let Some(wrap_conn) = &early_handshake.wrap_conn {
            if early_handshake.ready.as_ref().is_none_or(|ready| ready()) {
                return wrap_conn(raw).await;
            }
        }
    }
    if let Some(upgrade) = &opts.upgrade {
        return upgrade(raw).await;
    }
    Ok(raw)
}
