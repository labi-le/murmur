//! `transport::tuic::server::new_server` builds the `quinn` early listener itself from
//! `ServerOption::tls_config`.
//!
//! This file only hands it the `rustls::ServerConfig` that `utls::server_rustls_config` derives
//! from the TLS configuration shape, ALPN included.
//!
//! `handle_tcp_fn` hands the owned stream conn to `ListenerHandler::handle_socket` in a spawned
//! task; the handler owns
//! the TUIC type/additions (`Type::TUIC` plus `in_name`), so the socket construction, the special
//! fqdn branch and the per-connection additions all stay in that one path.
//! The QUIC config is built here field for field and travels to
//! `transport::tuic::server::new_server`, which turns it into the `quinn` transport settings.
//! The 0-RTT allowance, the path manager and the initial (as opposed to maximum) receive windows
//! have no quinn knob and are documented in `murmur_transport_tuic::quic::transport_config`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::addition::{with_in_name, with_special_rules, Addition};
use murmur_adapter_inbound::packet::new_packet;
use murmur_common::sockopt::reuse_common::udp_reuseaddr;
use murmur_common_net::io::{udp_addr_from_socket_addr, Datagram, DatagramAsOldPacketConn, OldConnAsStream};
use murmur_component_ca::auth::{
    client_auth_type_from_string, NO_CLIENT_CERT, REQUIRE_AND_VERIFY_CLIENT_CERT, VERIFY_CLIENT_CERT_IF_GIVEN,
};
use murmur_component_ca::keypair::{load_certificates, new_tls_key_pair_loader};
use murmur_component_ech::load_ech_key;
use murmur_component_tls::utls::{self as tls_c, ClientHelloInfo};
use murmur_constant::adapters::UDPPacket;
use murmur_constant::listener::InboundListenConfig;
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::tuic::TuicServer;
use murmur_listener_sing::sing::{new_listener_handler, ListenerConfig as SingListenerConfig};
use murmur_log::warnln;
use murmur_quic::Config as QuicConfig;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn};
use murmur_transport::socks5::socks5;
use murmur_transport_tuic::quic;
use murmur_transport_tuic::server as tuic_server;
use murmur_transport_tuic::tuic::{
    gen_tkn, DEFAULT_CONNECTION_RECEIVE_WINDOW, DEFAULT_STREAM_RECEIVE_WINDOW, PACKET_OVER_HEAD_V4, PACKET_OVER_HEAD_V5,
};

/// The server's incoming-stream limit, `(1 << 32) - 1`, feeds both the bidirectional and
/// unidirectional stream limits.
///
/// quinn eagerly materializes one stream-table entry per admitted id, so
/// this value never reaches it unchanged:
/// `murmur_transport_tuic::quic` clamps the count to its `MAX_QUINN_INCOMING_STREAMS` (1 << 12)
/// before quinn sees it, and that clamp is where the bound belongs, not this constant.
pub const SERVER_MAX_INCOMING_STREAMS: u32 = u32::MAX;

pub struct Listener {
    closed: Arc<AtomicBool>,
    config: TuicServer,
    udp_listeners: Vec<Arc<dyn Datagram>>,
    servers: Vec<Arc<tuic_server::Server>>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("servers", &self.servers.len())
            .finish_non_exhaustive()
    }
}

/// S11: remove with murmur-std-compat, once `tuic_server::new_server`/`udp_reuseaddr` take `Arc<dyn Datagram>`.
struct SharedDatagram(Arc<dyn Datagram>);

#[async_trait]
impl Datagram for SharedDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        self.0.send_to(buf, addr).await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn close(&self) -> std::io::Result<()> {
        self.0.close()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.0.as_socket()
    }
}

/// The QUIC config field for field; see the module doc for the knobs with no quinn counterpart.
fn build_quic_config(config: &TuicServer, max_datagram_frame_size: usize) -> Arc<QuicConfig> {
    Arc::new(QuicConfig {
        max_idle_timeout: Duration::from_millis(u64::try_from(config.max_idle_time).unwrap_or(0)),
        max_incoming_streams: i64::from(SERVER_MAX_INCOMING_STREAMS),
        max_incoming_uni_streams: i64::from(SERVER_MAX_INCOMING_STREAMS),
        enable_datagrams: true,
        allow_0rtt: true,
        disable_path_manager: true,
        initial_stream_receive_window: (DEFAULT_STREAM_RECEIVE_WINDOW / 10) as u64,
        max_stream_receive_window: DEFAULT_STREAM_RECEIVE_WINDOW as u64,
        initial_connection_receive_window: (DEFAULT_CONNECTION_RECEIVE_WINDOW / 10) as u64,
        max_connection_receive_window: DEFAULT_CONNECTION_RECEIVE_WINDOW as u64,
        max_datagram_frame_size: i64::try_from(max_datagram_frame_size).unwrap_or(0),
        ..QuicConfig::default()
    })
}

pub async fn new(
    config: TuicServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: &[Addition],
) -> Result<Listener> {
    let mut config = config;
    let additions: Vec<Addition> = if additions.is_empty() {
        vec![with_in_name("DEFAULT-TUIC"), with_special_rules("")]
    } else {
        additions.to_vec()
    };

    let h = Arc::new(new_listener_handler(SingListenerConfig {
        tunnel: Arc::clone(&tunnel),
        type_: Type::TUIC,
        additions: additions.clone(),
        udp_timeout: Duration::ZERO,
        mux_option: config.mux_option.clone(),
    })?);

    let mut tls_config = crate::tls_server_config(Arc::new(murmur_ntp::time::now));
    tls_config.min_version = tls_c::VERSION_TLS13;
    let cert_loader = new_tls_key_pair_loader(&config.certificate, &config.private_key)?;
    tls_config.get_certificate = Some(Arc::new(move |_info: &ClientHelloInfo| cert_loader().map(Some)));
    tls_config.client_auth = client_auth_type_from_string(&config.client_auth_type);
    if !config.client_auth_cert.is_empty() && tls_config.client_auth == NO_CLIENT_CERT {
        tls_config.client_auth = REQUIRE_AND_VERIFY_CLIENT_CERT;
    }
    if tls_config.client_auth == VERIFY_CLIENT_CERT_IF_GIVEN || tls_config.client_auth == REQUIRE_AND_VERIFY_CLIENT_CERT
    {
        tls_config.client_cas = Some(load_certificates(&config.client_auth_cert)?);
    }

    if !config.ech_key.is_empty() {
        load_ech_key(&config.ech_key, &mut tls_config)?;
    }
    tls_config.next_protos = if config.alpn.is_empty() { vec!["h3".to_owned()] } else { config.alpn.clone() };
    let server_tls = Arc::new(quic::ServerTls { config: Arc::new(tls_c::server_rustls_config(&tls_config)?) });

    if config.max_idle_time == 0 {
        config.max_idle_time = 15000;
    }
    if config.authentication_timeout == 0 {
        config.authentication_timeout = 1000;
    }

    let packet_over_head: usize = if config.token.is_empty() { *PACKET_OVER_HEAD_V5 } else { *PACKET_OVER_HEAD_V4 };

    if config.cwnd == 0 {
        config.cwnd = 32;
    }

    if config.max_udp_relay_packet_size == 0 {
        config.max_udp_relay_packet_size = 1500;
    }
    let mut max_datagram_frame_size = usize::try_from(config.max_udp_relay_packet_size).unwrap_or(0) + packet_over_head;
    if max_datagram_frame_size > 1400 {
        max_datagram_frame_size = 1400;
    }
    config.max_udp_relay_packet_size = i32::try_from(max_datagram_frame_size - packet_over_head).unwrap_or(0);

    let quic_config = build_quic_config(&config, max_datagram_frame_size);

    let handle_tcp_fn: tuic_server::HandleTcpFn = Arc::new({
        let handler = Arc::clone(&h);
        move |conn: Box<dyn NetConn>, addr: socks5::Addr, extra_additions: &[Addition]| -> Result<()> {
            let handler = Arc::clone(&handler);
            let extra_additions = extra_additions.to_vec();
            tokio::spawn(async move {
                // S11: remove with murmur-std-compat, once the transport's HandleTcpFn takes a `Stream`.
                let conn = Box::new(OldConnAsStream(conn));
                handler.handle_socket(&addr, conn, &extra_additions).await;
            });
            Ok(())
        }
    });
    let handle_udp_fn: tuic_server::HandleUdpFn = {
        let tunnel = Arc::clone(&tunnel);
        let additions = additions.clone();
        Arc::new(move |addr: socks5::Addr, packet: Arc<dyn UDPPacket>, extra_additions: &[Addition]| -> Result<()> {
            let mut new_additions = additions.clone();
            if !extra_additions.is_empty() {
                new_additions.extend_from_slice(extra_additions);
            }
            let (packet, metadata) = new_packet(&addr, packet, Type::TUIC, &new_additions);
            tunnel.handle_udp_packet(packet, metadata);
            Ok(())
        })
    };

    let mut option = tuic_server::ServerOption {
        handle_tcp_fn,
        handle_udp_fn,
        tls_config: server_tls,
        quic_config,
        tokens: Vec::new(),
        users: HashMap::new(),
        congestion_controller: config.congestion_controller.clone(),
        authentication_timeout: Duration::from_millis(u64::try_from(config.authentication_timeout).unwrap_or(0)),
        max_udp_relay_packet_size: usize::try_from(config.max_udp_relay_packet_size).unwrap_or(0),
        cwnd: config.cwnd,
        bbr_profile: config.bbr_profile.clone(),
    };
    if !config.token.is_empty() {
        option.tokens = config.token.iter().map(|token| gen_tkn(token)).collect();
    }
    if !config.users.is_empty() {
        option.users =
            config.users.iter().map(|(uuid, password)| (uuid_from_string_or_nil(uuid), password.clone())).collect();
    }

    let option = Arc::new(option);

    let closed = Arc::new(AtomicBool::new(false));
    let (udp_listeners, servers) = bind_servers(&config.listen, &lc, &option, &closed).await?;

    Ok(Listener { closed, config, udp_listeners, servers })
}

/// Builds one QUIC datagram listener and its server for every comma-separated `listen` address.
async fn bind_servers(
    listen: &str,
    lc: &Arc<dyn InboundListenConfig>,
    option: &Arc<tuic_server::ServerOption>,
    closed: &Arc<AtomicBool>,
) -> Result<(Vec<Arc<dyn Datagram>>, Vec<Arc<tuic_server::Server>>)> {
    let mut udp_listeners: Vec<Arc<dyn Datagram>> = Vec::new();
    let mut servers: Vec<Arc<tuic_server::Server>> = Vec::new();

    for addr in listen.split(',') {
        let datagram: Arc<dyn Datagram> = Arc::from(lc.listen_packet(&CancellationToken::new(), "udp", addr).await?);

        // S11: remove with murmur-std-compat, once murmur_common::sockopt::reuse_common::udp_reuseaddr takes &dyn Datagram
        if let Err(err) = udp_reuseaddr(&DatagramAsOldPacketConn(SharedDatagram(Arc::clone(&datagram)))) {
            warnln!("Failed to Reuse UDP Address: {err}");
        }

        udp_listeners.push(Arc::clone(&datagram));

        // S11: remove with murmur-std-compat, once transport_tuic::server::new_server takes Arc<dyn Datagram>
        let ul: Arc<dyn PacketConn> = Arc::new(DatagramAsOldPacketConn(SharedDatagram(datagram)));
        let server = Arc::new(tuic_server::new_server(Arc::clone(option), ul)?);
        servers.push(Arc::clone(&server));

        let server_task = Arc::clone(&server);
        let closed_task = Arc::clone(closed);
        tokio::spawn(async move { if server_task.serve().await.is_err() && closed_task.load(Ordering::SeqCst) {} });
    }

    Ok((udp_listeners, servers))
}

fn uuid_from_string_or_nil(s: &str) -> [u8; 16] {
    uuid::Uuid::parse_str(s).unwrap_or_default().into_bytes()
}

impl Listener {
    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        let mut ret_err: Option<anyhow::Error> = None;
        for server in &self.servers {
            if let Err(err) = server.close() {
                ret_err = Some(err);
            }
        }
        for conn in &self.udp_listeners {
            if let Err(err) = conn.close() {
                ret_err = Some(err.into());
            }
        }
        ret_err.map_or(Ok(()), Err)
    }

    #[must_use]
    pub fn config(&self) -> TuicServer {
        self.config.clone()
    }

    pub fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        fn boxed_addr(addr: SocketAddr) -> Box<dyn Addr> {
            Box::new(udp_addr_from_socket_addr(addr))
        }
        self.udp_listeners.iter().filter_map(|conn| conn.local_addr().ok()).map(boxed_addr).collect()
    }
}
