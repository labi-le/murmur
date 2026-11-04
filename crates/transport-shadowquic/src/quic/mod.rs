//! The QUIC session this crate drives, built on `quinn`.
//!
//! TLS 1.3 is swapped for the JLS handshake by implementing `quinn`'s crypto
//! plug-in traits over `murmur_jls_tls`'s QUIC-mode handshake (see [`crypto`]),
//! which leaves `quinn` in charge of the packet layer, streams, datagrams and
//! loss recovery. [`conn`] wraps quinn's connections and endpoints in the
//! surface `transport/shadowquic` drives.
//!
//! One endpoint-config behaviour has no equivalent here and is documented where it is lost:
//! setting the congestion controller (quinn binds a congestion controller when a connection
//! is created, so [`CongestionOption`] carries the choice to endpoint construction instead).
//! `allow_0rtt` is carried through: `conn::QuinnTransport::dial_early` takes quinn's 0-RTT path
//! when the client config kept a ticket, and the server's tickets advertise 0-RTT exactly when
//! `allow_0rtt` is set.

mod conn;
mod crypto;
mod deadline;
mod socket;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use murmur_jls_tls::{JlsUser, ServerConfig as JlsServerConfig};
use murmur_quic::jls::{EarlyListener, TransportFactory};
use murmur_quic::Config;
use murmur_std_compat::net::PacketConn;
use rustls::RootCertStore;

use conn::{QuinnListener, QuinnTransportFactory};
use crypto::JlsQuicClientConfig;

/// The congestion controller and initial window to apply once a connection exists.
///
/// quinn binds a controller when a connection is created, so it is taken when the endpoint is
/// built.
#[derive(Clone, Debug, Default)]
pub struct CongestionOption {
    pub name: String,
    pub cwnd: i32,
}

/// Binds an early listener over a JLS-authenticated `quinn` endpoint.
pub fn listen_early(
    packet_conn: Box<dyn PacketConn>,
    tls: Arc<JlsServerConfig>,
    config: Config,
    congestion: CongestionOption,
) -> anyhow::Result<Arc<dyn EarlyListener>> {
    let listener: Arc<QuinnListener> = QuinnListener::new(packet_conn, tls, config, congestion)?;
    Ok(listener)
}

/// The client half of a transport: the JLS credentials, the ClientHello's server name, the
/// trust anchors, and the congestion controller the connection is created with.
///
/// The trust anchors are what an unauthenticated peer's certificate is checked against. The
/// The `Config` itself is not needed here because `dial`/`dial_early` take one per call.
#[must_use]
pub fn transport_factory(
    user: JlsUser,
    server_name: String,
    alpn: Vec<String>,
    root_certs: Arc<RootCertStore>,
    time: Option<murmur_jls_tls::TimeFn>,
    congestion: CongestionOption,
) -> Arc<dyn TransportFactory> {
    let crypto = Arc::new(JlsQuicClientConfig::new(alpn, user, root_certs, time));
    QuinnTransportFactory::new(crypto, server_name, congestion)
}
