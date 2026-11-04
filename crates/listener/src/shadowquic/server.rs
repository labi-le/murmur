//! This listener is bound with a QUIC stack whose TLS 1.3 is replaced by the JLS handshake. The
//! same substitution is made over `quinn` here:
//!
//! `murmur_transport_shadowquic::quic` implements quinn's crypto plug-in over
//! `murmur_jls_tls`'s QUIC-mode handshake and wraps a quinn endpoint in the
//! `jls::EarlyListener` surface `transport/shadowquic`'s server drives.
//!
//! One congestion-control hook has no counterpart and is documented where it is lost: the
//! congestion-controller selection, which quinn offers no way to apply after a connection exists
//! and which carries the Brutal rate negotiated over the `murmur-brutal` extension. The 0-RTT
//! allowance (`config.zero_rtt`) reaches the handshake as its counterpart: tickets advertise 0-RTT only when
//! it is set, and only those tickets can be resumed with an early flight.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::addition::{with_in_name, with_special_rules, Addition};
use murmur_adapter_inbound::packet::new_packet;
use murmur_common::sockopt::reuse_common::udp_reuseaddr;
use murmur_common::utils::mbps::string_to_bps;
use murmur_common_net::io::{udp_addr_from_socket_addr, Datagram, DatagramAsOldPacketConn};
use murmur_constant::listener::InboundListenConfig;
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_jls_tls::{JlsUser as JlsTlsUser, ServerConfig as JlsServerConfig};
use murmur_listener_config::shadowquic::ShadowQuicServer;
use murmur_listener_inner::udp::handle_udp;
use murmur_listener_sing::sing::{new_listener_handler, ListenerConfig};
use murmur_log::warnln;
use murmur_quic::jls::ListenEarlyFn;
use murmur_quic::{Config, JlsConfig, JlsUser, TlsConfig};
use murmur_std_compat::net::{Addr, PacketConn};
use murmur_transport_jls::cert::new_self_signed_cert;
use murmur_transport_shadowquic::quic as shadowquic_quic;
use murmur_transport_shadowquic::quic_version::{default_quic_versions, parse_quic_versions};
use murmur_transport_shadowquic::server::{HandleTcpFn, HandleUdpFn, Server, ServerOption};
use murmur_transport_tuic::tuic::{DEFAULT_CONNECTION_RECEIVE_WINDOW, DEFAULT_STREAM_RECEIVE_WINDOW};

pub const SERVER_MAX_INCOMING_STREAMS: i64 = (1_i64 << 32) - 1;

/// The default initial packet size, also `murmur_quic::congestion::INITIAL_PACKET_SIZE` (1280
/// bytes); the config field is a `u16`.
const DEFAULT_INITIAL_PACKET_SIZE: u16 = 1280;

pub struct Listener {
    closed: Arc<AtomicBool>,
    config: ShadowQuicServer,
    udp_listeners: Vec<Arc<dyn Datagram>>,
    servers: Vec<Arc<Server>>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("servers", &self.servers.len())
            .finish_non_exhaustive()
    }
}

/// Shared [`Datagram`], forwarded between [`Listener::udp_listeners`] and the QUIC server bound
/// atop it via the S11 [`DatagramAsOldPacketConn`] bridge `Server::new` still requires.
struct SharedDatagram(Arc<dyn Datagram>);

#[async_trait]
impl Datagram for SharedDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.0.close()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.0.as_socket()
    }
}

/// Marker for `ServerOption.tls_config`: the JLS credentials reach the listener through
/// `listen_early`, so the trait carries no payload.
#[derive(Clone)]
struct ShadowQuicTlsConfig;

impl TlsConfig for ShadowQuicTlsConfig {}

pub async fn new(
    config: ShadowQuicServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Listener> {
    if config.jls_upstream.addr.trim().is_empty() {
        return Err(anyhow!("shadowquic: jls-upstream.addr is required"));
    }
    let additions =
        if additions.is_empty() { vec![with_in_name("DEFAULT-SHADOWQUIC"), with_special_rules("")] } else { additions };

    let h = new_listener_handler(ListenerConfig {
        tunnel: Arc::clone(&tunnel),
        type_: Type::SHADOWQUIC,
        additions: additions.clone(),
        udp_timeout: std::time::Duration::default(),
        mux_option: config.mux_option.clone(),
    })?;
    let h = Arc::new(h);

    // The TLS configuration is built here: TLS 1.3 minimum, `Time` from the NTP clock, then the
    // generated certificate, the ALPN list and the JLS credentials below.
    let cert = new_self_signed_cert()?;
    let alpn = if config.alpn.is_empty() { vec!["h3".to_owned()] } else { config.alpn.clone() };
    let jls_server_name = if config.jls_upstream.sni.is_empty() {
        default_jls_server_name(&config.jls_upstream.addr)
    } else {
        config.jls_upstream.sni.clone()
    };
    let jls_tls = Arc::new(JlsServerConfig {
        users: config
            .users
            .iter()
            .map(|user| JlsTlsUser { username: user.username.clone(), password: user.password.clone() })
            .collect(),
        server_name: jls_server_name,
        alpn: alpn.clone(),
        cert_der: cert.cert_der,
        key: cert.key,
    });

    let mut config = config;
    if config.max_idle_time == 0 {
        config.max_idle_time = 30000;
    }
    if config.max_datagram_frame_size == 0 {
        config.max_datagram_frame_size = 1400;
    }
    if config.cwnd == 0 {
        config.cwnd = 32;
    }

    // The packet dialer a JLS config would carry has no field in this crate's config, so this
    // is kept for parity but unwired (see the module doc).
    let _jls_packet_dialer = {
        let tunnel = Arc::clone(&tunnel);
        let proxy = config.jls_upstream.proxy.clone();
        move |network: &str, address: &str| handle_udp(Some(Arc::clone(&tunnel)), network, address, &proxy)
    };

    let quic_versions = if config.quic_versions.is_empty() {
        default_quic_versions()
    } else {
        parse_quic_versions(&config.quic_versions)?
    };

    let handle_tcp_fn: HandleTcpFn = Arc::new({
        let h = Arc::clone(&h);
        move |conn, addr, extra_additions| {
            let h = Arc::clone(&h);
            let extra_additions = extra_additions.to_vec();
            tokio::spawn(async move {
                // S11: remove with murmur-std-compat — `transport_shadowquic::server::HandleTcpFn` is still
                // `murmur_std_compat::net::Conn`-typed.
                let conn = Box::new(murmur_common_net::io::OldConnAsStream(conn));
                h.handle_socket(&addr, conn, &extra_additions).await;
            });
            Ok(())
        }
    });
    let handle_udp_fn: HandleUdpFn = Arc::new({
        let tunnel = Arc::clone(&tunnel);
        let additions = additions.clone();
        move |addr, packet, extra_additions| {
            let mut new_additions = additions.clone();
            if !extra_additions.is_empty() {
                new_additions.extend_from_slice(extra_additions);
            }
            let (packet, metadata) = new_packet(&addr, Arc::from(packet), Type::SHADOWQUIC, &new_additions);
            tunnel.handle_udp_packet(packet, metadata);
            Ok(())
        }
    });

    let quic_config = build_quic_config(&config, quic_versions, jls_tls.server_name.clone());

    let option = Arc::new(ServerOption {
        handle_tcp_fn: Some(handle_tcp_fn),
        handle_udp_fn: Some(handle_udp_fn),
        tls_config: Arc::new(ShadowQuicTlsConfig),
        quic_config: Arc::clone(&quic_config),
        congestion_controller: config.congestion_controller.clone(),
        send_bps: string_to_bps(&config.up),
        receive_bps: string_to_bps(&config.down),
        ignore_client_bandwidth: config.ignore_client_bandwidth,
        cwnd: config.cwnd,
        bbr_profile: config.bbr_profile.clone(),
    });
    let congestion =
        shadowquic_quic::CongestionOption { name: config.congestion_controller.clone(), cwnd: config.cwnd };

    let listen_early: ListenEarlyFn = Arc::new(move |pc, _tls_conf, quic_conf| {
        shadowquic_quic::listen_early(pc, Arc::clone(&jls_tls), quic_conf.as_ref().clone(), congestion.clone())
    });

    let closed = Arc::new(AtomicBool::new(false));
    let (udp_listeners, servers) = bind_servers(&config.listen, &lc, &option, &listen_early, &closed).await?;

    Ok(Listener { closed, config, udp_listeners, servers })
}

/// Builds one QUIC datagram listener and its server for every comma-separated `listen` address.
async fn bind_servers(
    listen: &str,
    lc: &Arc<dyn InboundListenConfig>,
    option: &Arc<ServerOption>,
    listen_early: &ListenEarlyFn,
    closed: &Arc<AtomicBool>,
) -> Result<(Vec<Arc<dyn Datagram>>, Vec<Arc<Server>>)> {
    let mut udp_listeners: Vec<Arc<dyn Datagram>> = Vec::new();
    let mut servers: Vec<Arc<Server>> = Vec::new();

    for addr in listen.split(',') {
        let addr = addr.trim();
        if addr.is_empty() {
            continue;
        }
        let datagram: Arc<dyn Datagram> = Arc::from(lc.listen_packet(&CancellationToken::new(), "udp", addr).await?);
        // S11: remove with murmur-std-compat, once murmur_common::sockopt::reuse_common::udp_reuseaddr takes &dyn Datagram
        if let Err(err) = udp_reuseaddr(&DatagramAsOldPacketConn(SharedDatagram(Arc::clone(&datagram)))) {
            warnln!("Failed to Reuse UDP Address: {err}");
        }
        udp_listeners.push(Arc::clone(&datagram));

        // S11: remove with murmur-std-compat, once transport_shadowquic::server::Server::new takes Box<dyn Datagram>
        let pc: Box<dyn PacketConn> = Box::new(DatagramAsOldPacketConn(SharedDatagram(datagram)));
        let server = Server::new(Arc::clone(option), pc, Arc::clone(listen_early))?;
        let server = Arc::new(server);
        servers.push(Arc::clone(&server));

        let closed = Arc::clone(closed);
        tokio::spawn(async move {
            if let Err(err) = server.serve().await {
                if !closed.load(Ordering::SeqCst) {
                    warnln!("ShadowQuic server closed: {err}");
                }
            }
        });
    }

    Ok((udp_listeners, servers))
}

/// The QUIC config, with the receive windows defaulted from the transport constants.
fn build_quic_config(
    config: &ShadowQuicServer,
    quic_versions: Vec<murmur_quic::Version>,
    jls_server_name: String,
) -> Arc<Config> {
    let initial_stream_receive_window =
        if config.receive_window_conn == 0 { DEFAULT_STREAM_RECEIVE_WINDOW / 10 } else { config.receive_window_conn };
    let max_stream_receive_window =
        if config.receive_window_conn == 0 { DEFAULT_STREAM_RECEIVE_WINDOW } else { config.receive_window_conn };
    let initial_connection_receive_window =
        if config.receive_window == 0 { DEFAULT_CONNECTION_RECEIVE_WINDOW / 10 } else { config.receive_window };
    let max_connection_receive_window =
        if config.receive_window == 0 { DEFAULT_CONNECTION_RECEIVE_WINDOW } else { config.receive_window };

    Arc::new(Config {
        versions: quic_versions,
        jls: Some(JlsConfig {
            enable: true,
            user: JlsUser::default(),
            users: Vec::new(),
            server_name: jls_server_name,
        }),
        handshake_idle_timeout: std::time::Duration::default(),
        max_idle_timeout: std::time::Duration::from_millis(u64::try_from(config.max_idle_time.max(0)).unwrap_or(0)),
        initial_stream_receive_window: u64::try_from(initial_stream_receive_window).unwrap_or(0),
        max_stream_receive_window: u64::try_from(max_stream_receive_window).unwrap_or(0),
        initial_connection_receive_window: u64::try_from(initial_connection_receive_window).unwrap_or(0),
        max_connection_receive_window: u64::try_from(max_connection_receive_window).unwrap_or(0),
        max_incoming_streams: SERVER_MAX_INCOMING_STREAMS,
        max_incoming_uni_streams: SERVER_MAX_INCOMING_STREAMS,
        keep_alive_period: std::time::Duration::default(),
        initial_packet_size: DEFAULT_INITIAL_PACKET_SIZE,
        disable_path_mtu_discovery: config.disable_mtu_discovery,
        allow_0rtt: config.zero_rtt,
        enable_datagrams: true,
        max_datagram_frame_size: i64::from(config.max_datagram_frame_size),
        disable_path_manager: false,
    })
}

fn default_jls_server_name(upstream_addr: &str) -> String {
    let host = match murmur_common_net::split_host_port(upstream_addr) {
        Ok((host, _, _)) => host,
        Err(_) => upstream_addr.to_owned(),
    };
    if IpAddr::from_str(&host).is_ok() {
        return String::new();
    }
    if host.contains(':') {
        return String::new();
    }
    host
}

impl Listener {
    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        let mut ret_err: Option<anyhow::Error> = None;
        for server in &self.servers {
            if let Err(err) = server.close() {
                ret_err = Some(err.into());
            }
        }
        for lis in &self.udp_listeners {
            if let Err(err) = lis.close() {
                ret_err = Some(err.into());
            }
        }
        match ret_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    #[must_use]
    pub fn config(&self) -> ShadowQuicServer {
        self.config.clone()
    }

    pub fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        fn boxed_addr(addr: SocketAddr) -> Box<dyn Addr> {
            Box::new(udp_addr_from_socket_addr(addr))
        }
        self.udp_listeners.iter().filter_map(|lis| lis.local_addr().ok()).map(boxed_addr).collect()
    }
}

#[cfg(test)]
mod tests {
    //! This drives the listener's own `new`/`serve` instead of the inbound wrapper: a real JLS
    //! client dials the bound UDP socket, completes the handshake, and its bytes reach
    //! `Tunnel::handle_tcp_conn` with the tunnel's reply coming back over the same stream.

    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use murmur_adapter_inbound::listen::default_listen_config;
    use murmur_common_net::io::Stream;
    use murmur_component_ca::config::get_cert_pool;
    use murmur_component_nat::table::Table;
    use murmur_constant::adapters::{NatTable, UDPPacket};
    use murmur_constant::metadata::{Metadata, NetWork};
    use murmur_listener_config::shadowquic::{ShadowQuicJLSUpstream, ShadowQuicUser};
    use murmur_quic::jls::{Conn as JlsConn, TransportFactory as JlsTransportFactory};
    use murmur_quic::{VERSION1, VERSION2};
    use murmur_std_compat::net::{PacketConn, UdpAddr};
    use murmur_testsupport_probe::ensure_test_crypto_provider;
    use murmur_transport::socks5::socks5;
    use murmur_transport_shadowquic::protocol::{write_request, COMMAND_CONNECT};
    use murmur_transport_shadowquic::quic::{transport_factory, CongestionOption};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const USERNAME: &str = "shadowquic-user";
    const PASSWORD: &str = "shadowquic-password";
    const ALPN: &[&str] = &["h3"];
    const TARGET: &str = "192.0.2.1:1";
    const PAYLOAD: &[u8] = b"shadowquic-listener-payload";
    const CONCURRENT_STREAMS: usize = 150;
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

    fn client_user() -> JlsTlsUser {
        JlsTlsUser { username: USERNAME.to_owned(), password: PASSWORD.to_owned() }
    }

    /// Echoes every length-prefixed frame back and records what it relayed. The framing stands in
    /// for the payload length a real protocol layer (HTTP, TLS) carries on the wire, so a test can
    /// hold several streams open without knowing which one a read belongs to.
    struct RecordingTunnel {
        relays: Mutex<Vec<(Metadata, Vec<u8>)>>,
    }

    #[async_trait]
    impl Tunnel for RecordingTunnel {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, metadata: Metadata) {
            let mut prefix = [0u8; 4];
            if conn.read_exact(&mut prefix).await.is_err() {
                return;
            }
            let mut payload = vec![0u8; u32::from_be_bytes(prefix) as usize];
            if conn.read_exact(&mut payload).await.is_err() {
                return;
            }
            self.relays.lock().expect("tunnel state lock").push((metadata, payload.clone()));
            let mut frame = prefix.to_vec();
            frame.extend_from_slice(&payload);
            let _ = conn.write_all(&frame).await;
            let _ = conn.flush().await;
        }

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {}

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    fn server_config(quic_versions: &[&str]) -> ShadowQuicServer {
        ShadowQuicServer {
            enable: true,
            listen: "127.0.0.1:0".to_owned(),
            users: vec![ShadowQuicUser { username: USERNAME.to_owned(), password: PASSWORD.to_owned() }],
            jls_upstream: ShadowQuicJLSUpstream { addr: "127.0.0.1:1".to_owned(), ..Default::default() },
            alpn: ALPN.iter().map(|alpn| (*alpn).to_owned()).collect(),
            quic_versions: quic_versions.iter().map(|version| (*version).to_owned()).collect(),
            ..Default::default()
        }
    }

    async fn start(quic_versions: &[&str]) -> (Listener, SocketAddr, Arc<RecordingTunnel>) {
        let tunnel = Arc::new(RecordingTunnel { relays: Mutex::new(Vec::new()) });
        let listener_tunnel = Arc::clone(&tunnel);
        let listener_tunnel: Arc<dyn Tunnel> = listener_tunnel;
        let listener = new(server_config(quic_versions), default_listen_config(), listener_tunnel, Vec::new())
            .await
            .expect("shadowquic listener construction");
        let addr = listener
            .addr_list()
            .first()
            .and_then(|addr| addr.string().parse().ok())
            .expect("the listener reports its bound address");
        (listener, addr, tunnel)
    }

    /// A `PacketConn` over a `tokio::net::UdpSocket`, standing in for the dialer's proxy-aware
    /// conn (`murmur_transport_shadowquic::quic::tests`' own client socket).
    struct SocketPacketConn {
        socket: tokio::net::UdpSocket,
        closed: CancellationToken,
    }

    #[async_trait]
    impl PacketConn for SocketPacketConn {
        async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
            let (n, addr) = tokio::select! {
                () = self.closed.cancelled() => return Err(io::Error::new(io::ErrorKind::NotConnected, "closed")),
                result = self.socket.recv_from(buf) => result?,
            };
            Ok((n, Box::new(UdpAddr::from(addr))))
        }

        async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
            self.socket.send_to(buf, murmur_common_net::io::old_addr_to_socket_addr(addr)?).await
        }

        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(UdpAddr::from(self.socket.local_addr()?)))
        }

        fn close(&self) -> io::Result<()> {
            self.closed.cancel();
            Ok(())
        }
    }

    struct MarkerTls;

    impl TlsConfig for MarkerTls {}

    fn client_quic_config(versions: &[u32]) -> Config {
        Config {
            versions: versions.to_vec(),
            enable_datagrams: true,
            max_datagram_frame_size: 1400,
            ..Config::default()
        }
    }

    async fn dial(addr: SocketAddr, alpn: &[&str], user: JlsTlsUser, versions: &[u32]) -> Result<Arc<dyn JlsConn>> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let packet_conn = SocketPacketConn { socket, closed: CancellationToken::new() };
        let factory = transport_factory(
            user,
            "example.com".to_owned(),
            alpn.iter().map(|alpn| (*alpn).to_owned()).collect(),
            get_cert_pool(),
            None,
            CongestionOption { name: "bbr".to_owned(), cwnd: 32 },
        );
        let transport = JlsTransportFactory::new_transport(factory.as_ref(), Arc::new(packet_conn), 0);
        transport.set_created_conn(true);
        transport.set_single_use(true);
        transport.dial(&CancellationToken::new(), &UdpAddr::from(addr), &MarkerTls, &client_quic_config(versions)).await
    }

    /// Opens a stream on `conn`, asks the listener to relay `payload` to [`TARGET`], and returns
    /// the bytes the tunnel echoed back.
    async fn relay(conn: &Arc<dyn JlsConn>, payload: &[u8]) -> Vec<u8> {
        let mut stream = conn.open_stream_sync(&CancellationToken::new()).await.expect("open a stream");
        let target = socks5::parse_addr(TARGET).expect("valid target address");
        write_request(&mut *stream, COMMAND_CONNECT, &target).await.expect("write the CONNECT request");
        let mut frame = u32::try_from(payload.len()).expect("payload fits a u32").to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        stream.write_all(&frame).await.expect("write the frame");
        stream.flush().await.expect("flush the frame");

        let mut prefix = [0u8; 4];
        tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut prefix))
            .await
            .expect("the tunnel's reply arrives in time")
            .expect("read the tunnel's reply prefix");
        let mut echoed = vec![0u8; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut echoed).await.expect("read the tunnel's reply");
        echoed
    }

    #[tokio::test]
    async fn listener_relays_a_jls_client_stream_through_the_tunnel() {
        ensure_test_crypto_provider();
        let (listener, addr, tunnel) = start(&["v1"]).await;

        let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, dial(addr, ALPN, client_user(), &[VERSION1]))
            .await
            .expect("the JLS handshake completes in time")
            .expect("the JLS handshake succeeds");

        assert_eq!(relay(&conn, PAYLOAD).await, PAYLOAD, "the payload round-trips through the tunnel handler");

        let relays = tunnel.relays.lock().expect("tunnel state lock");
        let (metadata, received) = relays.first().expect("the tunnel handler was reached");
        assert_eq!(received, PAYLOAD, "the tunnel handler saw the client's payload");
        assert_eq!(metadata.type_, Type::SHADOWQUIC, "the metadata carries the listener's type");
        assert_eq!(metadata.network, NetWork::TCP, "a CONNECT stream maps to a TCP metadata");
        assert_eq!(metadata.dst_ip, Some(IpAddr::V4("192.0.2.1".parse().expect("valid ipv4"))));
        assert_eq!(metadata.dst_port, 1, "the CONNECT request's port reaches the metadata");
        drop(relays);

        let _ = conn.close_with_error(0, "");
        listener.close().expect("shadowquic listener close");
    }

    /// The listener's stream limit must exceed quinn's own default of 100; the
    /// stream limit would have the accepting side materialize a stream-table entry
    /// for every one of its ~4.3 billion slots before relaying anything (see
    /// `murmur_transport_shadowquic::quic`'s clamp), which this many simultaneous streams catch.
    #[tokio::test]
    async fn concurrent_streams_beyond_quinns_default_are_all_relayed() {
        ensure_test_crypto_provider();
        let (listener, addr, tunnel) = start(&["v1"]).await;

        let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, dial(addr, ALPN, client_user(), &[VERSION1]))
            .await
            .expect("the JLS handshake completes in time")
            .expect("the JLS handshake succeeds");

        let payloads: Vec<Vec<u8>> =
            (0..CONCURRENT_STREAMS).map(|i| format!("shadowquic-stream-{i}").into_bytes()).collect();
        let echoed = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            futures::future::join_all(payloads.iter().map(|payload| relay(&conn, payload))),
        )
        .await
        .expect("every concurrent stream is relayed in time");
        assert_eq!(echoed, payloads, "each stream's payload round-trips unchanged");
        assert_eq!(tunnel.relays.lock().expect("tunnel state lock").len(), CONCURRENT_STREAMS);

        let _ = conn.close_with_error(0, "");
        listener.close().expect("shadowquic listener close");
    }

    #[tokio::test]
    async fn wrong_password_fails_the_handshake_and_never_reaches_the_tunnel() {
        ensure_test_crypto_provider();
        let (listener, addr, tunnel) = start(&["v1"]).await;

        let wrong = JlsTlsUser { username: USERNAME.to_owned(), password: "wrong".to_owned() };
        let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, dial(addr, ALPN, wrong, &[VERSION1]))
            .await
            .expect("the handshake fails rather than hanging");
        assert!(result.is_err(), "a client with the wrong password must not establish a session");
        assert!(tunnel.relays.lock().expect("tunnel state lock").is_empty(), "no stream may reach the tunnel");

        listener.close().expect("shadowquic listener close");
    }

    #[tokio::test]
    async fn unknown_alpn_fails_the_handshake_and_never_reaches_the_tunnel() {
        ensure_test_crypto_provider();
        let (listener, addr, tunnel) = start(&["v1"]).await;

        let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, dial(addr, &["not-h3"], client_user(), &[VERSION1]))
            .await
            .expect("the handshake fails rather than hanging");
        assert!(result.is_err(), "a client offering an unconfigured ALPN must not establish a session");
        assert!(tunnel.relays.lock().expect("tunnel state lock").is_empty(), "no stream may reach the tunnel");

        listener.close().expect("shadowquic listener close");
    }

    /// The shadow-quic test runs both QUIC versions, and v2 differs below the handshake:
    /// RFC 9369 salts and labels the initial keys differently, so only a dial that ends up on the
    /// v2 key schedule relays anything.
    #[tokio::test]
    async fn a_v2_client_handshakes_and_carries_a_payload() {
        ensure_test_crypto_provider();
        let (listener, addr, tunnel) = start(&["v2"]).await;

        let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, dial(addr, ALPN, client_user(), &[VERSION2]))
            .await
            .expect("the v2 JLS handshake completes in time")
            .expect("the v2 JLS handshake succeeds");

        assert_eq!(relay(&conn, PAYLOAD).await, PAYLOAD, "the payload round-trips on the v2 key schedule");
        let relays = tunnel.relays.lock().expect("tunnel state lock");
        let (metadata, received) = relays.first().expect("the tunnel handler was reached");
        assert_eq!(received, PAYLOAD, "the tunnel handler saw the v2 client's payload");
        assert_eq!(metadata.type_, Type::SHADOWQUIC, "the metadata carries the listener's type");
        drop(relays);

        let _ = conn.close_with_error(0, "");
        listener.close().expect("shadowquic listener close");
    }

    /// A client that insists on a version the listener does not offer must fail closed rather than
    /// fall back to a version its own endpoint never advertised.
    #[tokio::test]
    async fn an_unoffered_client_version_fails_closed() {
        ensure_test_crypto_provider();
        let (listener, addr, tunnel) = start(&["v1"]).await;

        let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, dial(addr, ALPN, client_user(), &[VERSION2]))
            .await
            .expect("the handshake fails rather than hanging");
        assert!(result.is_err(), "a client offering only an unconfigured version must not establish a session");
        assert!(tunnel.relays.lock().expect("tunnel state lock").is_empty(), "no stream may reach the tunnel");

        listener.close().expect("shadowquic listener close");
    }
}
