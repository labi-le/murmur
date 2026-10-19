//! The one QUIC session `transport/tuic` runs on.
//!
//! This module drives `quinn` behind the [`Conn`] surface, so `v4`, `v5`,
//! the pooled client, the server handlers and `common::dial` all share a single connection type
//! instead of the three disjoint mirrors this package used to carry.
//!
//! Two QUIC config behaviours have no quinn counterpart and are applied where quinn allows
//! them instead:
//!
//! * Congestion control runs against a live connection, while quinn binds a
//!   controller when the endpoint is built, so [`CongestionOption`] carries the choice into
//!   endpoint construction.
//! * 0-RTT collapses into `dial` because the TUIC client never resumes: it sets
//!   no client session cache, so no TLS 1.3 ticket is stored and the early-return channel never
//!   fires, leaving the early dial to wait for the handshake exactly like the plain dial. Contrast
//!   the shadow-quic outbound, whose one-entry client session cache is what makes that
//!   transport's 0-RTT real.
//! * `bbr-profile` is carried by [`CongestionOption`] but has no quinn counterpart; see
//!   [`congestion_factory`].

mod conn;
mod socket;

use std::cmp::Ordering;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::old_addr_to_socket_addr;
use murmur_common_pool as pool;
use murmur_quic::{ApplicationErrorCode, ConnectionState, ConnectionStats, ReceiveStream, SendStream, Stream};
use murmur_std_compat::net::PacketConn;

use conn::QuinnConn;
use socket::PacketConnSocket;

pub use crate::congestion_v2::bbr_sender::Profile;
pub use murmur_quic::{Config, DatagramTooLargeError};

/// The config defaults, applied by [`effective_config`] so a
/// partially filled `Config` does not reach quinn as a zero.
const INITIAL_STREAM_RECEIVE_WINDOW: u64 = 2 * 1024 * 1024;
const MAX_STREAM_RECEIVE_WINDOW: u64 = 6 * 1024 * 1024;
const INITIAL_CONNECTION_RECEIVE_WINDOW: u64 = INITIAL_STREAM_RECEIVE_WINDOW * 3 / 2;
const MAX_CONNECTION_RECEIVE_WINDOW: u64 = 15 * 1024 * 1024;
const MAX_INCOMING_STREAMS: i64 = 100;
const MAX_INCOMING_STREAMS_CLAMP: i64 = 1 << 60;
/// The advertised server stream limit is `(1 << 32) - 1`, and the
/// listener sends it for both the stream and unidirectional-stream counts. quinn's
/// `StreamsState::new` eagerly materializes one stream-table entry per admitted stream id before
/// the connection carries a byte (`quinn-proto-0.11.18/src/connection/streams/state.rs:203-207`),
/// and quinn's transport-parameter check rejects only a count above the protocol maximum, `1 << 60`,
/// so the value would have the accepting side build a ~4.3-billion-entry table. The trusttunnel
/// slice measured exactly that failure mode with `1 << 60`: 900s with no progress, against 0.53s
/// at quinn's own default of 100. `1 << 12` still clears that default by 40x — the limit that
/// would make a client queue its concurrent streams — at a bounded 4096-entry table, while a TUIC
/// client self-limits to `max-open-streams` (100 plus 10% headroom by default).
const MAX_QUINN_INCOMING_STREAMS: i64 = 1 << 12;
const INITIAL_PACKET_SIZE: u16 = 1280;
const MIN_INITIAL_PACKET_SIZE: u16 = 1200;
const MAX_PACKET_BUFFER_SIZE: u16 = 1452;

/// The surface `transport/tuic` drives on a QUIC session.
#[async_trait]
pub trait Conn: Send + Sync {
    fn local_addr(&self) -> Box<dyn murmur_std_compat::net::Addr>;
    fn remote_addr(&self) -> Box<dyn murmur_std_compat::net::Addr>;
    fn close_with_error(&self, code: ApplicationErrorCode, reason: &str) -> Result<()>;
    fn config(&self) -> Config;
    fn connection_stats(&self) -> ConnectionStats;
    fn connection_state(&self) -> ConnectionState;
    /// The cancellation context, only ever read for its done channel.
    fn context(&self) -> CancellationToken;
    /// The handshake-complete signal, which may never fire.
    async fn handshake_complete(&self);
    fn export_keying_material(&self, label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>>;
    async fn open_stream(&self, ctx: &CancellationToken) -> Result<Box<dyn Stream>>;
    async fn open_uni_stream(&self, ctx: &CancellationToken) -> Result<Box<dyn SendStream>>;
    async fn accept_stream(&self, ctx: &CancellationToken) -> Result<Box<dyn Stream>>;
    async fn accept_uni_stream(&self, ctx: &CancellationToken) -> Result<Box<dyn ReceiveStream>>;
    fn send_datagram(&self, data: &[u8]) -> Result<()>;
    async fn receive_datagram(&self, ctx: &CancellationToken) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait EarlyListener: Send + Sync {
    async fn accept(&self, ctx: &CancellationToken) -> Result<Arc<dyn Conn>>;
    fn close(&self) -> io::Result<()>;
}

/// The `congestion-controller`/`cwnd`/`bbr-profile` arguments of congestion control, taken at
/// endpoint construction because quinn binds the controller there.
#[derive(Clone, Debug, Default)]
pub struct CongestionOption {
    pub name: String,
    pub cwnd: i32,
    /// The `bbr-profile`, read only by the `bbr`/`bbr_meta_v2` arm.
    pub profile: Profile,
}

/// Mapped onto the `quinn` controller that carries the same algorithm. `bbr_meta_v1`/
/// `bbr_meta_v2` both run quinn's BBR; `cwnd` seeds its initial window.
///
/// `bbr-profile` cannot follow: the profile tunes the vendored sender's pacing gains,
/// CWND gains, STARTUP round-trip count, overshoot detection, loss multiplier, STARTUP ack
/// aggregation and bandwidth-sampler flags, while quinn's `BbrConfig` exposes only `initial_window`
/// (`quinn-proto-0.11.18/src/congestion/bbr/mod.rs:517-529`). A non-default profile is therefore
/// reported instead of dropped in silence. Fail-closed is deliberately not used: any profile
/// string is accepted, so refusing would turn a working configuration into a dial error.
#[must_use]
pub fn congestion_factory(option: &CongestionOption) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> {
    let cwnd = if option.cwnd == 0 { 32 } else { option.cwnd };
    let initial_window = u64::try_from(cwnd).ok().filter(|cwnd| *cwnd > 0).map(|cwnd| cwnd * 1200);
    match option.name.as_str() {
        "new_reno" => {
            let mut config = quinn::congestion::NewRenoConfig::default();
            if let Some(window) = initial_window {
                config.initial_window(window);
            }
            Arc::new(config)
        }
        // the `bbr_meta_v1` sender takes no profile, so a `bbr-profile` next to it is ignored.
        "bbr_meta_v1" => {
            let mut config = quinn::congestion::BbrConfig::default();
            if let Some(window) = initial_window {
                config.initial_window(window);
            }
            Arc::new(config)
        }
        "bbr_meta_v2" | "bbr" => {
            if matches!(option.profile, Profile::ProfileConservative | Profile::ProfileAggressive) {
                murmur_log::warnln!(
                    "tuic: bbr-profile '{}' has no quinn equivalent; the BBR controller keeps quinn's parameters",
                    option.profile
                );
            }
            let mut config = quinn::congestion::BbrConfig::default();
            if let Some(window) = initial_window {
                config.initial_window(window);
            }
            Arc::new(config)
        }
        _ => {
            let mut config = quinn::congestion::CubicConfig::default();
            if let Some(window) = initial_window {
                config.initial_window(window);
            }
            Arc::new(config)
        }
    }
}

/// A `Config` with the defaults filled in.
///
/// They are applied inside the transport before the config reaches a connection, and the server's
/// authentication timeout reads the handshake idle timeout off the result, so the defaults have to be
/// visible on the stored config too.
#[must_use]
pub fn effective_config(mut config: Config) -> Config {
    if config.handshake_idle_timeout.is_zero() {
        config.handshake_idle_timeout = Duration::from_secs(5);
    }
    if config.max_idle_timeout.is_zero() {
        config.max_idle_timeout = Duration::from_secs(30);
    }
    if config.initial_stream_receive_window == 0 {
        config.initial_stream_receive_window = INITIAL_STREAM_RECEIVE_WINDOW;
    }
    if config.max_stream_receive_window == 0 {
        config.max_stream_receive_window = MAX_STREAM_RECEIVE_WINDOW;
    }
    if config.initial_connection_receive_window == 0 {
        config.initial_connection_receive_window = INITIAL_CONNECTION_RECEIVE_WINDOW;
    }
    if config.max_connection_receive_window == 0 {
        config.max_connection_receive_window = MAX_CONNECTION_RECEIVE_WINDOW;
    }
    config.max_incoming_streams = normalize_incoming_streams(config.max_incoming_streams);
    config.max_incoming_uni_streams = normalize_incoming_streams(config.max_incoming_uni_streams);
    if config.initial_packet_size == 0 {
        config.initial_packet_size = INITIAL_PACKET_SIZE;
    }
    config.initial_packet_size = config.initial_packet_size.clamp(MIN_INITIAL_PACKET_SIZE, MAX_PACKET_BUFFER_SIZE);
    config
}

/// A negative count forbids the peer's streams, zero means
/// the default, and anything above `1 << 60` is clipped.
fn normalize_incoming_streams(value: i64) -> i64 {
    match value.cmp(&0) {
        Ordering::Less => 0,
        Ordering::Equal => MAX_INCOMING_STREAMS,
        Ordering::Greater => value.min(MAX_INCOMING_STREAMS_CLAMP),
    }
}

/// The config fields this session maps onto quinn's `TransportConfig`.
///
/// quinn has no counterpart for `handshake_idle_timeout` (it bounds the handshake with the idle
/// timeout), for `allow_0rtt` (quinn's client gate is `Connecting::into_0rtt`, which is never
/// calls — the TUIC client stores no session ticket to resume, see the module note — and the
/// server advertisement is applied from `allow_0rtt` in `server::new_server`) or for
/// `disable_path_manager` (quinn never migrates a connection on its own). `initial_stream_receive_window`/
/// `initial_connection_receive_window` are dropped too: quinn advertises the configured maximum
/// from the first packet, so only the max receive windows exist as knobs. The two incoming-stream
/// counts are capped by [`MAX_QUINN_INCOMING_STREAMS`] rather than forwarded, for the reason
/// recorded there.
fn transport_config(config: &Config, congestion: &CongestionOption) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    if let Ok(idle) = config.max_idle_timeout.try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    if !config.keep_alive_period.is_zero() {
        transport.keep_alive_interval(Some(config.keep_alive_period));
    }
    if let Ok(window) = quinn::VarInt::try_from(config.max_stream_receive_window) {
        transport.stream_receive_window(window);
    }
    if let Ok(window) = quinn::VarInt::try_from(config.max_connection_receive_window) {
        transport.receive_window(window);
    }
    if let Ok(streams) = quinn::VarInt::try_from(
        u64::try_from(config.max_incoming_streams.min(MAX_QUINN_INCOMING_STREAMS)).unwrap_or_default(),
    ) {
        transport.max_concurrent_bidi_streams(streams);
    }
    if let Ok(streams) = quinn::VarInt::try_from(
        u64::try_from(config.max_incoming_uni_streams.min(MAX_QUINN_INCOMING_STREAMS)).unwrap_or_default(),
    ) {
        transport.max_concurrent_uni_streams(streams);
    }
    if config.enable_datagrams {
        // quinn bounds its datagram buffers in bytes where a single DATAGRAM frame is bounded;
        // the frame limit itself is enforced in `QuinnConn::send_datagram`.
        let buffer = usize::try_from(config.max_datagram_frame_size).unwrap_or(0).max(pool::UDP_BUFFER_SIZE);
        transport.datagram_receive_buffer_size(Some(buffer));
        transport.datagram_send_buffer_size(buffer);
    }
    if config.disable_path_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    transport.initial_mtu(config.initial_packet_size);
    transport.congestion_controller_factory(congestion_factory(congestion));
    transport
}

/// The supported versions, which quinn negotiates at the endpoint rather than at the transport.
fn endpoint_config(config: &Config) -> quinn::EndpointConfig {
    let mut endpoint = quinn::EndpointConfig::default();
    if !config.versions.is_empty() {
        endpoint.supported_versions(config.versions.clone());
    }
    endpoint
}

/// The client credentials one QUIC transport shares: a `rustls` client config plus the
/// server name its ClientHello carries.
#[derive(Clone)]
pub struct ClientTls {
    pub config: Arc<rustls::ClientConfig>,
    pub server_name: String,
}

impl std::fmt::Debug for ClientTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The TLS config can carry client certificates, so only the public server name is printed.
        f.debug_struct("ClientTls").field("server_name", &self.server_name).finish_non_exhaustive()
    }
}

/// The server credentials every accepted connection shares.
#[derive(Clone)]
pub struct ServerTls {
    pub config: Arc<rustls::ServerConfig>,
}

impl std::fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The config holds the private key, so no field is printed.
        f.debug_struct("ServerTls").finish_non_exhaustive()
    }
}

fn runtime() -> Result<Arc<dyn quinn::Runtime>> {
    quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("tuic: no async runtime available for quinn"))
}

/// Opens one QUIC session over the packet conn the
/// dialer produced.
///
/// Cancel-safe: a cancelled dial closes the endpoint it started, which tears the half-open
/// session down with it; a completed dial hands back an owned connection.
pub async fn dial(
    ctx: &CancellationToken,
    packet_conn: Arc<dyn PacketConn>,
    remote: SocketAddr,
    tls: Arc<ClientTls>,
    config: Config,
    congestion: CongestionOption,
) -> Result<Arc<dyn Conn>> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from((*tls.config).clone())
        .map_err(|err| anyhow::anyhow!("tuic: invalid client TLS config: {err}"))?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(transport_config(&config, &congestion)));

    let local_addr = match packet_conn.local_addr() {
        Ok(addr) => old_addr_to_socket_addr(addr.as_ref())?,
        Err(_) => match remote {
            SocketAddr::V4(_) => SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
        },
    };
    let socket = PacketConnSocket::new(packet_conn, local_addr)?;
    let endpoint = quinn::Endpoint::new_with_abstract_socket(endpoint_config(&config), None, socket, runtime()?)?;
    let connecting = endpoint
        .connect_with(client, remote, &tls.server_name)
        .map_err(|err| anyhow::anyhow!("tuic: dial {remote}: {err}"))?;
    let connection = tokio::select! {
        () = ctx.cancelled() => {
            endpoint.close(quinn::VarInt::from_u32(0), b"");
            anyhow::bail!("tuic: dial cancelled");
        }
        connected = connecting => connected?,
    };
    Ok(Arc::new(QuinnConn::new(connection, local_addr, remote, config)))
}

struct QuinnListener {
    endpoint: quinn::Endpoint,
    config: Config,
}

#[async_trait]
impl EarlyListener for QuinnListener {
    /// Cancel-safe: a cancelled accept drops only the in-flight `accept()` future; the endpoint
    /// and its queued incoming connections are untouched.
    // cancel-safe: quinn's `Endpoint::accept` keeps the incoming handshake in the background, so a dropped accept leaves the connection to be accepted again.
    async fn accept(&self, ctx: &CancellationToken) -> Result<Arc<dyn Conn>> {
        loop {
            let incoming = tokio::select! {
                () = ctx.cancelled() => anyhow::bail!("tuic: listener closed"),
                incoming = self.endpoint.accept() => incoming,
            };
            let Some(incoming) = incoming else {
                anyhow::bail!("tuic: endpoint closed");
            };
            let remote_addr = incoming.remote_address();
            let Ok(connecting) = incoming.accept() else { continue };
            let local_addr = self.endpoint.local_addr()?;
            match connecting.await {
                Ok(connection) => {
                    return Ok(Arc::new(QuinnConn::new(connection, local_addr, remote_addr, self.config.clone())))
                }
                Err(err) => {
                    // An unauthenticated peer never reaches the stream handlers: the TLS
                    // handshake is what rejects it, and quinn drops the connection itself.
                    murmur_log::debugln!("tuic: handshake failed: {err}");
                }
            }
        }
    }

    fn close(&self) -> io::Result<()> {
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
        Ok(())
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the exported `listen_early` surface takes the TLS material and congestion options \
              as owned values, matching the early-listening call shape; taking them by \
              reference would change the crate's public API"
)]
pub fn listen_early(
    packet_conn: Arc<dyn PacketConn>,
    tls: Arc<ServerTls>,
    config: Config,
    congestion: CongestionOption,
) -> Result<Arc<dyn EarlyListener>> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from((*tls.config).clone())
        .map_err(|err| anyhow::anyhow!("tuic: invalid server TLS config: {err}"))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(transport_config(&config, &congestion)));

    let local_addr = old_addr_to_socket_addr(packet_conn.local_addr()?.as_ref())?;
    let socket = PacketConnSocket::new(packet_conn, local_addr)?;
    let endpoint =
        quinn::Endpoint::new_with_abstract_socket(endpoint_config(&config), Some(server), socket, runtime()?)?;
    Ok(Arc::new(QuinnListener { endpoint, config }))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::future::join_all;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    use murmur_component_ca::keypair::{new_random_tls_key_pair, x509_key_pair, KeyPairType};
    use murmur_component_tls::utls;

    use super::*;

    /// The advertised server limit is `(1 << 32) - 1`, sent as both
    /// `max_incoming_streams` and `max_incoming_uni_streams`.
    fn listener_config() -> Config {
        effective_config(Config {
            max_incoming_streams: i64::from(u32::MAX),
            max_incoming_uni_streams: i64::from(u32::MAX),
            ..Config::default()
        })
    }

    fn tls_pair() -> (Arc<ServerTls>, Arc<ClientTls>) {
        let (certificate_pem, private_key_pem, _) =
            new_random_tls_key_pair(KeyPairType::P256).expect("a generated test key pair");
        let certificate = x509_key_pair(certificate_pem.as_bytes(), private_key_pem.as_bytes())
            .expect("the generated PEM yields a certificate");
        let server = utls::server_rustls_config(&utls::Config {
            certificates: vec![certificate],
            next_protos: vec!["h3".to_owned()],
            ..Default::default()
        })
        .expect("the listener's rustls config");
        let client = utls::client_rustls_config(&utls::Config {
            insecure_skip_verify: true,
            next_protos: vec!["h3".to_owned()],
            ..Default::default()
        })
        .expect("the dialer's rustls config");
        (
            Arc::new(ServerTls { config: Arc::new(server) }),
            Arc::new(ClientTls { config: Arc::new(client), server_name: "localhost".to_owned() }),
        )
    }

    /// The negative control for [`MAX_QUINN_INCOMING_STREAMS`]: the `(1 << 32) - 1` still has to
    /// admit more concurrent client streams than quinn's default of 100, the limit that would
    /// otherwise queue them. The streams are only all open at once if the listener's advertised
    /// stream credit allows it, since quinn's `open_bi` resolves only once the peer's credit does.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_client_streams_past_quinns_default_all_open() {
        const STREAMS: usize = 128;

        let (server_tls, client_tls) = tls_pair();
        let ctx = CancellationToken::new();

        let server_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind the listener socket");
        let server_addr = server_socket.local_addr().expect("the listener socket address");
        let listener =
            listen_early(Arc::new(server_socket), server_tls, listener_config(), CongestionOption::default())
                .expect("start the listener");

        let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel();
        let accept_ctx = ctx.clone();
        let acceptor = tokio::spawn(async move {
            let conn = listener.accept(&accept_ctx).await.expect("accept the client");
            let mut held = Vec::with_capacity(STREAMS);
            for _ in 0..STREAMS {
                held.push(conn.accept_stream(&accept_ctx).await.expect("accept a client stream"));
            }
            accepted_tx.send(()).expect("the test holds the receiver");
            accept_ctx.cancelled().await;
            let _ = listener.close();
        });

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind the client socket");
        let client = dial(
            &ctx,
            Arc::new(client_socket),
            server_addr,
            client_tls,
            effective_config(Config::default()),
            CongestionOption::default(),
        )
        .await
        .expect("dial the listener");

        let opened =
            tokio::time::timeout(Duration::from_secs(20), join_all((0..STREAMS).map(|_| client.open_stream(&ctx))))
                .await
                .expect("a client stream is still queued behind the listener's stream limit");
        let mut open_streams = Vec::with_capacity(STREAMS);
        for stream in opened {
            let mut stream = stream.expect("every client stream opens");
            // quinn announces a stream to the peer with its first frame, so the listener only
            // observes the stream once it carries a byte.
            AsyncWriteExt::write_all(&mut stream, b"\0").await.expect("the stream's first byte");
            open_streams.push(stream);
        }
        tokio::time::timeout(Duration::from_secs(20), accepted_rx.recv())
            .await
            .expect("the listener admits every concurrent stream")
            .expect("the accept task reports");

        ctx.cancel();
        let _ = acceptor.await;
        drop(open_streams);
        client.close_with_error(0, "test complete").expect("close the connection");
    }

    /// `bbr-profile` reaches the controller choice as [`CongestionOption::profile`], and every
    /// profile still builds quinn's own BBR: `BbrConfig` has no knob for any of them.
    #[test]
    fn a_bbr_profile_rides_in_the_option_and_leaves_quinns_controller_alone() {
        assert_eq!(Profile::from("conservative"), Profile::ProfileConservative);
        assert_eq!(Profile::from("aggressive"), Profile::ProfileAggressive);
        assert_eq!(Profile::from("standard"), Profile::ProfileStandard);
        assert_eq!(Profile::from(""), Profile::ProfileStandard);
        assert_eq!(Profile::from("nonsense"), Profile::ProfileStandard);
        assert_eq!(CongestionOption::default().profile, Profile::ProfileStandard);

        fn built(name: &str, profile: Profile) -> (Box<dyn std::any::Any>, u64) {
            let controller = congestion_factory(&CongestionOption { name: name.to_owned(), cwnd: 16, profile })
                .build(std::time::Instant::now(), 1200);
            let window = controller.initial_window();
            (controller.into_any(), window)
        }

        for profile in [Profile::ProfileStandard, Profile::ProfileConservative, Profile::ProfileAggressive] {
            let (controller, window) = built("bbr", profile);
            assert!(controller.is::<quinn::congestion::Bbr>(), "{profile}");
            assert_eq!(window, 16 * 1200, "{profile}");
        }

        assert!(built("bbr_meta_v1", Profile::ProfileAggressive).0.is::<quinn::congestion::Bbr>());
        assert!(built("cubic", Profile::ProfileAggressive).0.is::<quinn::congestion::Cubic>());
        assert!(built("new_reno", Profile::ProfileAggressive).0.is::<quinn::congestion::NewReno>());
    }
}
