use std::sync::{Arc, LazyLock};

use anyhow::Result;
use hickory_proto::op::Message;
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;

use super::resolver::ResolverError;

/// A shared `Service`, the Rust form of the interface value.
pub type SharedService = Arc<dyn Service + Send + Sync>;

#[async_trait::async_trait]
pub trait Service: Send + Sync {
    async fn serve_msg(&self, ctx: &CancellationToken, msg: &Message) -> Result<Message>;
}

static DEFAULT_SERVICE: LazyLock<RwLock<Option<SharedService>>> = LazyLock::new(|| RwLock::new(None));

pub fn default_service() -> Option<SharedService> {
    DEFAULT_SERVICE.read().clone()
}

pub fn set_default_service(service: Option<SharedService>) {
    *DEFAULT_SERVICE.write() = service;
}

pub async fn serve_msg(ctx: &CancellationToken, msg: &Message) -> Result<Message> {
    if let Some(server) = default_service() {
        return server.serve_msg(ctx, msg).await;
    }

    Err(ResolverError::IpNotFound.into())
}
