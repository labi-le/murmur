//! The metadata type (`murmur_sing::metadata::Metadata`, re-exported by `super::sing` as
//! `SingMetadata`) is mirrored once.
//!
//! The two names below are that one type, so `FnHandler` hands `ListenerHandler` the same value.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;

use murmur_common_net::io::Stream;
use murmur_sing::metadata::Metadata as SingMetadata;
use murmur_sing::network::PacketConn as SingPacketConn;

use super::context::SingContext;

pub type NewConnectionFn = Arc<
    dyn Fn(SingContext, Box<dyn Stream>, SingMetadata) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;
pub type NewPacketConnectionFn = Arc<
    dyn Fn(SingContext, Box<dyn SingPacketConn>, SingMetadata) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;
pub type NewErrorFn = Arc<dyn Fn(SingContext, anyhow::Error) + Send + Sync>;

#[derive(Clone, Default)]
pub struct FnHandler {
    pub new_connection_fn: Option<NewConnectionFn>,
    pub new_packet_connection_fn: Option<NewPacketConnectionFn>,
    pub new_error_fn: Option<NewErrorFn>,
}

impl core::fmt::Debug for FnHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The handler slots hold erased closures without a `Debug` bound.
        let Self { new_connection_fn, new_packet_connection_fn, new_error_fn } = self;
        f.debug_struct("FnHandler")
            .field("new_connection_fn", &new_connection_fn.is_some())
            .field("new_packet_connection_fn", &new_packet_connection_fn.is_some())
            .field("new_error_fn", &new_error_fn.is_some())
            .finish()
    }
}

impl FnHandler {
    pub async fn new_connection(&self, ctx: SingContext, conn: Box<dyn Stream>, metadata: SingMetadata) -> Result<()> {
        match &self.new_connection_fn {
            None => Ok(()),
            Some(f) => f(ctx, conn, metadata).await,
        }
    }

    pub async fn new_packet_connection(
        &self,
        ctx: SingContext,
        conn: Box<dyn SingPacketConn>,
        metadata: SingMetadata,
    ) -> Result<()> {
        match &self.new_packet_connection_fn {
            None => Ok(()),
            Some(f) => f(ctx, conn, metadata).await,
        }
    }

    pub fn new_error(&self, ctx: SingContext, err: anyhow::Error) {
        if let Some(f) = &self.new_error_fn {
            f(ctx, err);
        }
    }
}
