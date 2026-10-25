//! The QUIC client surface `transport/hysteria` drives, and the `quinn` session that implements
//! it.
//!
//! The dial path builds the QUIC transport around the packet conn and hands it to the client
//! connect step. Here [`Transport`] is that same seam and [`new_transport_factory`] supplies the
//! concrete `quinn`-backed transport [`ClientTransport`](super::client::ClientTransport) is built
//! with, so the packet conn the obfuscator/hop/wechat/faketcp wrappers produced really does carry
//! the QUIC session instead of a stand-in.
//!
//! Wire compatibility rests on three things `quinn` provides without configuration: QUIC v1
//! (RFC 9000) with TLS 1.3, the ALPN from the injected TLS config, and RFC 9221 DATAGRAM frames.
//! Everything else that changes observable behaviour — flow control windows, keep-alive, PMTU
//! discovery, the Brutal rate swapped in over the control stream, the exact stream-ID numbering —
//! is mapped explicitly in [`conn`] and [`congestion`].

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::{Addr, PacketConn};

mod congestion;
mod conn;
mod deadline;
mod socket;
#[cfg(test)]
mod tests;

pub use conn::{new_transport_factory, QuinnConn};

/// QUIC configuration, carrying the fields the hysteria client sets. The zero value is the
/// default.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub initial_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub initial_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub keep_alive_period: Duration,
    pub disable_path_mtu_discovery: bool,
    pub enable_datagrams: bool,
}

/// The TLS configuration the QUIC handshake runs with.
///
/// The QUIC session runs its handshake inside `rustls`, which cannot apply uTLS fingerprinting,
/// so this hands over the `rustls` form of the same configuration rather than the configuration
/// itself: certificate verification, roots, client authentication, resumption and the key log all
/// carry over, and ALPN/SNI come from the same fields the original config would have used.
pub trait TlsConfig: Send + Sync {
    fn rustls_client_config(&self) -> anyhow::Result<rustls::ClientConfig>;

    /// The server name: the name the server certificate is verified against, and the one sent in
    /// the handshake. `rustls::ClientConfig` does not keep it, and the client always sets one (the
    /// server address, or the `sni` option).
    fn server_name(&self) -> &str;
}

pub trait Conn: Send + Sync {
    fn as_any(&self) -> &dyn std::any::Any;
}

#[async_trait]
pub trait Transport: Send + Sync {
    /// The transport owns the packet conn and closes it once its connection is gone.
    fn set_created_conn(&self, created_conn: bool);
    /// The transport is closed once its one connection is gone.
    fn set_single_use(&self, single_use: bool);
    async fn dial(
        &self,
        ctx: CancellationToken,
        addr: &dyn Addr,
        tls_config: &dyn TlsConfig,
        quic_config: &Config,
    ) -> anyhow::Result<Arc<dyn Conn>>;
}

/// Builds the QUIC transport around a packet conn; injected because this crate implements no QUIC
/// transport of its own.
pub type TransportFactory = Arc<dyn Fn(Arc<dyn PacketConn>) -> Box<dyn Transport> + Send + Sync>;
