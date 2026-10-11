use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use tokio_util::sync::CancellationToken;

use murmur_common_net::bufconn::{BufferedConn, BufioReader};
use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::{Conn, PacketConn};

use crate::quic::Conn as QuicConn;

/// The `ClientClosed` and `TooManyOpenStreams` error kinds.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("tuic: client closed")]
    ClientClosed,
    #[error("tuic: too many open streams")]
    TooManyOpenStreams,
}

pub type DialFunc =
    Arc<dyn Fn(CancellationToken) -> BoxFuture<'static, anyhow::Result<Arc<dyn QuicConn>>> + Send + Sync>;

#[async_trait]
pub trait Client: Send + Sync {
    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> anyhow::Result<Box<dyn Conn>>;

    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> anyhow::Result<Box<dyn PacketConn>>;

    fn open_streams(&self) -> i64;

    fn last_visited(&self) -> DateTime<Utc>;

    fn set_last_visited(&self, last: DateTime<Utc>);

    fn close(&self);
}

#[async_trait]
pub trait ServerHandler: Send + Sync {
    fn auth_ok(&self) -> bool;

    fn handle_timeout(&self);

    /// The accepted stream's buffered conn is passed to the stream handler and the handler
    /// hands that same conn to `HandleTcpFn`, which spawns the tunnel with it; taking it by
    /// value is what lets the Rust callback own the relay.
    async fn handle_stream(&self, conn: BufferedConn) -> anyhow::Result<()>;

    async fn handle_message(&self, message: &[u8]) -> anyhow::Result<()>;

    async fn handle_uni_stream(&self, reader: &mut BufioReader) -> anyhow::Result<()>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdpRelayMode(pub u8);

impl UdpRelayMode {
    pub const QUIC: Self = Self(0);
    pub const NATIVE: Self = Self(1);
}
