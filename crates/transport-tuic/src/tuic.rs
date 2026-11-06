use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::common;
use crate::types::type_ as types_type;
use crate::{v4, v5};
use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::{Conn, PacketConn};

pub type ClientOptionV4 = v4::client::ClientOption;
pub type ClientOptionV5 = v5::client::ClientOption;

pub use common::congestion::{DEFAULT_CONNECTION_RECEIVE_WINDOW, DEFAULT_STREAM_RECEIVE_WINDOW};
pub use v4::protocol::gen_tkn;
pub use v4::protocol::PACKET_OVER_HEAD as PACKET_OVER_HEAD_V4;
pub use v5::frag::MAX_FRAG_SIZE as MAX_FRAG_SIZE_V5;
pub use v5::protocol::PACKET_OVER_HEAD as PACKET_OVER_HEAD_V5;

pub type UdpRelayMode = types_type::UdpRelayMode;
pub const QUIC: UdpRelayMode = types_type::UdpRelayMode::QUIC;
pub const NATIVE: UdpRelayMode = types_type::UdpRelayMode::NATIVE;

///
/// `v4::client::Client` and `v5::client::Client` share one [`types_type::DialFunc`] and one QUIC
/// session type, but keep separate types.
///
/// v4's `dial_context`/`listen_packet` need `self: &Arc<Self>` so the keep-alive handle they attach
/// to the returned conn keeps the finalizer alive, while v5's reach their `ClientOuter` through
/// `&self`. `PoolClient`'s client list is the only place the `Client` name is used as a
/// value, so this enum stands in for the interface directly. `id` gives pool code an identity to
/// compare against the best-client comparison.
#[derive(Clone, Debug)]
pub struct Client {
    id: Arc<()>,
    backend: ClientBackend,
}

#[derive(Clone, Debug)]
enum ClientBackend {
    V4(Arc<v4::client::Client>),
    V5(v5::client::Client),
}

impl Client {
    fn from_v4(inner: Arc<v4::client::Client>) -> Self {
        Self { id: Arc::new(()), backend: ClientBackend::V4(inner) }
    }

    fn from_v5(inner: v5::client::Client) -> Self {
        Self { id: Arc::new(()), backend: ClientBackend::V5(inner) }
    }

    /// the interface identity comparison (`client != bestClient`).
    pub(crate) fn ptr_eq(a: &Self, b: &Self) -> bool {
        Arc::ptr_eq(&a.id, &b.id)
    }

    pub async fn dial_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> anyhow::Result<Box<dyn Conn>> {
        match &self.backend {
            ClientBackend::V4(c) => c.dial_context(ctx, metadata).await,
            ClientBackend::V5(c) => c.dial_context(ctx.clone(), metadata).await,
        }
    }

    /// Returns `Arc<dyn PacketConn>` rather than a plain
    /// because v4's backend hands back an `Arc` and v5's a `Box`; `PoolClient` re-wraps either
    /// through `common::net::new_ref_packet_conn`, which itself takes an `Arc`.
    pub async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> anyhow::Result<Arc<dyn PacketConn>> {
        match &self.backend {
            ClientBackend::V4(c) => {
                let pc = c.listen_packet(ctx).await?;
                let pc: Arc<dyn PacketConn> = pc.into_packet_conn();
                Ok(pc)
            }
            ClientBackend::V5(c) => {
                let pc = c.listen_packet(ctx.clone(), metadata).await?;
                Ok(Arc::from(pc))
            }
        }
    }

    #[must_use]
    pub fn open_streams(&self) -> i64 {
        match &self.backend {
            ClientBackend::V4(c) => c.open_streams(),
            ClientBackend::V5(c) => c.open_streams(),
        }
    }

    #[must_use]
    pub fn last_visited(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.backend {
            ClientBackend::V4(c) => c.last_visited(),
            ClientBackend::V5(c) => c.last_visited(),
        }
    }

    pub fn set_last_visited(&self, last: chrono::DateTime<chrono::Utc>) {
        match &self.backend {
            ClientBackend::V4(c) => c.set_last_visited(last),
            ClientBackend::V5(c) => c.set_last_visited(last),
        }
    }

    /// `v5::client::Client` exposes no delegated `close` (the promoted
    /// inner close is not re-exposed by that file's wrapper). This method's only call
    /// site (`PoolClient::get_client`'s eviction loop) already checked `open_streams() == 0`
    /// and is about to drop its own last reference right after calling this, so v5's
    /// `ClientOuter::Drop` (which spawns the equivalent `force_close`) already covers it.
    pub fn close(&self) {
        if let ClientBackend::V4(c) = &self.backend {
            c.close();
        }
    }
}

pub fn new_client_v4(client_option: Arc<ClientOptionV4>, udp: bool, dial_fn: types_type::DialFunc) -> Client {
    Client::from_v4(v4::client::new_client(client_option, udp, dial_fn))
}

pub fn new_client_v5(client_option: ClientOptionV5, udp: bool, dial_fn: types_type::DialFunc) -> Client {
    Client::from_v5(v5::client::new_client(client_option, udp, dial_fn))
}
