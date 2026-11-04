//! DEVIATION: the `Listener` keeps its own listener and packet-conn handles.
//!
//! It hands the same values to the trust-tunnel `Service`, which closes them.
//! `transport::trusttunnel::service::Service` already takes exclusive ownership of the
//! accepted listener/conn (`start` consumes `Option<Box<dyn Listener>>`/`Option<Box<dyn
//! PacketConn>>`), so this crate hands ownership to the `Service` and keeps only the resolved
//! `Box<dyn Addr>` for the address list; `Listener::close` closes each `Service`, which in turn closes
//! the socket it owns exactly once instead of twice.
//!
//! DEVIATION: `MultiAddrListener::close` is synchronous but
//! `Service::close` is `async`; this bridges with `tokio::task::block_in_place` +
//! `Handle::current().block_on`, the same pattern already used by `tunnel::tunnel` for sync-context
//! DNS resolution.
//! NEEDED SHIM ITEM: `murmur_std_compat::net::Addr` has no clone method, so the address list rebuilds a local
//! `StaticAddr` stand-in from the `network()`/`string()` captured at listen time instead of
//! returning the original `Addr` value.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::addition::{with_in_name, with_special_rules, Addition};
use murmur_common::sockopt::reuse_common::raw_conn_reuseaddr;
use murmur_common_net::io::{
    udp_addr_from_socket_addr, Acceptor, AcceptorAsOldListener, Datagram, DatagramAsOldPacketConn, Stream,
};
use murmur_common_net::sing::ExtendedConn as SingExtendedConn;
use murmur_compat::sing_buf::Buffer;
use murmur_component_ca::auth::{
    client_auth_type_from_string, NO_CLIENT_CERT, REQUIRE_AND_VERIFY_CLIENT_CERT, VERIFY_CLIENT_CERT_IF_GIVEN,
};
use murmur_component_ca::keypair::{load_certificates, new_tls_key_pair_loader};
use murmur_component_ech::load_ech_key;
use murmur_component_tls::utls::{ClientHelloInfo, Config as TlsConfig};
use murmur_constant::listener::{InboundListenConfig, MultiAddrListener};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::trusttunnel::TrustTunnelServer;
use murmur_listener_sing::context::SingContext;
use murmur_listener_sing::sing::{
    new_listener_handler, ListenerConfig as SingListenerConfig, ListenerHandler, MuxOption,
};
use murmur_log::warnln;
use murmur_sing::metadata::Socksaddr;
use murmur_sing::network::{PacketConn as SingPacketConn, PacketReader, PacketWriter};
use murmur_std_compat::net::{Addr, TcpAddr};
use murmur_transport_trusttunnel::service::{
    Handler as TrustTunnelHandler, Service as TrustTunnelService, ServiceOptions, SingMetadata as TtSingMetadata,
};

/// An address stand-in for the address list; see the module doc.
#[derive(Debug)]
struct StaticAddr {
    network: String,
    address: String,
}

impl Addr for StaticAddr {
    fn network(&self) -> &str {
        &self.network
    }

    fn string(&self) -> String {
        self.address.clone()
    }
}

fn capture_addr(addr: &dyn Addr) -> Box<dyn Addr> {
    Box::new(StaticAddr { network: addr.network().to_owned(), address: addr.string() })
}

/// Bridges the listener handler's connection entry points (which this crate's
/// `sing` module already implements) onto `transport::trusttunnel::service::Handler`'s local
/// vocabulary (`SingContext`'s cancellation is unused by either side, so a fresh default context
/// stands in for a plain context).
struct SingHandlerAdapter(Arc<ListenerHandler>);

#[async_trait]
impl TrustTunnelHandler for SingHandlerAdapter {
    async fn new_connection(
        &self,
        _ctx: &CancellationToken,
        conn: Box<dyn SingExtendedConn>,
        metadata: TtSingMetadata,
    ) -> Result<()> {
        let conn: Box<dyn Stream> = conn;
        self.0.new_connection(SingContext::default(), conn, metadata).await
    }

    async fn new_packet_connection(
        &self,
        _ctx: &CancellationToken,
        conn: Arc<dyn SingPacketConn>,
        metadata: TtSingMetadata,
    ) -> Result<()> {
        let conn: Box<dyn SingPacketConn> = Box::new(SharedPacketConn(conn));
        self.0.new_packet_connection(SingContext::default(), conn, metadata).await
    }
}

/// Adapts a shared `Arc<dyn SingPacketConn>` to the owned `Box<dyn SingPacketConn>`
/// `ListenerHandler::new_packet_connection` expects; every method below is `&self`, so the
/// wrapper only adds one layer of indirection over the shared conn.
struct SharedPacketConn(Arc<dyn SingPacketConn>);

#[async_trait]
impl PacketReader for SharedPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        self.0.read_packet(buffer).await
    }
}

#[async_trait]
impl PacketWriter for SharedPacketConn {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        self.0.write_packet(buffer, destination).await
    }
}

#[async_trait]
impl SingPacketConn for SharedPacketConn {
    async fn close(&self) -> io::Result<()> {
        self.0.close().await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr()
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_write_deadline(deadline)
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_deadline(deadline)
    }
}

pub struct Listener {
    closed: Arc<AtomicBool>,
    config: TrustTunnelServer,
    addrs: Vec<Box<dyn Addr>>,
    services: Vec<Arc<TrustTunnelService>>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("services", &self.services.len())
            .finish_non_exhaustive()
    }
}

async fn close_all(
    services: &[Arc<TrustTunnelService>],
    tcp_listener: Option<Box<dyn Acceptor>>,
    udp_conn: Option<Box<dyn Datagram>>,
) -> Result<()> {
    let mut ret_err: Option<anyhow::Error> = None;
    for service in services {
        if let Err(err) = service.close().await {
            ret_err = Some(err);
        }
    }
    if let Some(listener) = tcp_listener {
        if let Err(err) = listener.close() {
            ret_err = Some(err.into());
        }
    }
    if let Some(conn) = udp_conn {
        if let Err(err) = conn.close() {
            ret_err = Some(err.into());
        }
    }
    ret_err.map_or(Ok(()), Err)
}

/// Builds the server TLS config from the inbound's certificate/ECH/client-auth settings.
fn build_tls_config(config: &TrustTunnelServer) -> Result<TlsConfig> {
    let mut tls_config = crate::tls_server_config(Arc::new(murmur_ntp::time::now));
    if !config.certificate.is_empty() && !config.private_key.is_empty() {
        let cert_loader = new_tls_key_pair_loader(&config.certificate, &config.private_key)?;
        tls_config.certificates = vec![cert_loader()?];
        tls_config.get_certificate = Some(Arc::new(move |_info: &ClientHelloInfo| cert_loader().map(Some)));

        if !config.ech_key.is_empty() {
            load_ech_key(&config.ech_key, &mut tls_config)?;
        }
    }
    tls_config.client_auth = client_auth_type_from_string(&config.client_auth_type);
    if !config.client_auth_cert.is_empty() && tls_config.client_auth == NO_CLIENT_CERT {
        tls_config.client_auth = REQUIRE_AND_VERIFY_CLIENT_CERT;
    }
    if tls_config.client_auth == VERIFY_CLIENT_CERT_IF_GIVEN || tls_config.client_auth == REQUIRE_AND_VERIFY_CLIENT_CERT
    {
        tls_config.client_cas = Some(load_certificates(&config.client_auth_cert)?);
    }
    Ok(tls_config)
}

// S11: remove with murmur-std-compat, once transport_trusttunnel::service::Service::start takes Box<dyn Acceptor>/Box<dyn Datagram>.
fn old_listener(l: Box<dyn Acceptor>) -> Box<dyn murmur_std_compat::net::Listener> {
    Box::new(AcceptorAsOldListener(l))
}

fn old_packet_conn(c: Box<dyn Datagram>) -> Box<dyn murmur_std_compat::net::PacketConn> {
    Box::new(DatagramAsOldPacketConn(c))
}

pub async fn new(
    config: TrustTunnelServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: &[Addition],
) -> Result<Listener> {
    let mut config = config;
    let additions: Vec<Addition> = if additions.is_empty() {
        vec![with_in_name("DEFAULT-TRUSTTUNNEL"), with_special_rules("")]
    } else {
        additions.to_vec()
    };

    let tls_config = build_tls_config(&config)?;

    let h = Arc::new(new_listener_handler(SingListenerConfig {
        tunnel: Arc::clone(&tunnel),
        type_: Type::TRUSTTUNNEL,
        additions,
        udp_timeout: std::time::Duration::ZERO,
        mux_option: MuxOption::default(),
    })?);

    if tls_config.get_certificate.is_none() {
        return Err(anyhow!("disallow using TrustTunnel without certificates config"));
    }

    if config.network.is_empty() {
        config.network = vec!["tcp".to_owned()];
    }
    let mut listen_tcp = false;
    let mut listen_udp = false;
    for network in &config.network {
        let network = network.to_lowercase();
        if network.starts_with("tcp") {
            listen_tcp = true;
        } else if network.starts_with("udp") {
            listen_udp = true;
        }
    }

    let tls_config = Arc::new(tls_config);
    let mut addrs: Vec<Box<dyn Addr>> = Vec::new();
    let mut services: Vec<Arc<TrustTunnelService>> = Vec::new();

    for addr in config.listen.split(',') {
        let mut tcp_listener: Option<Box<dyn Acceptor>> = None;
        let mut udp_conn: Option<Box<dyn Datagram>> = None;

        if listen_tcp {
            let listener = match lc.listen(&CancellationToken::new(), "tcp", addr).await {
                Ok(listener) => listener,
                Err(err) => {
                    let _ = close_all(&services, None, None).await;
                    return Err(err);
                }
            };
            if let Ok(a) = listener.addr() {
                addrs.push(capture_addr(&TcpAddr::from(a)));
            }
            tcp_listener = Some(listener);
        }

        if listen_udp {
            let conn = match lc.listen_packet(&CancellationToken::new(), "udp", addr).await {
                Ok(conn) => conn,
                Err(err) => {
                    let _ = close_all(&services, tcp_listener, None).await;
                    return Err(err);
                }
            };
            if let Some(socket) = conn.as_socket() {
                if let Err(err) = raw_conn_reuseaddr(&*socket) {
                    warnln!("Failed to Reuse UDP Address: {err}");
                }
            }
            if let Ok(a) = conn.local_addr() {
                addrs.push(capture_addr(&udp_addr_from_socket_addr(a)));
            }
            udp_conn = Some(conn);
        }

        let service = TrustTunnelService::new(ServiceOptions {
            ctx: CancellationToken::new(),
            handler: Arc::new(SingHandlerAdapter(Arc::clone(&h))),
            icmp_handler: None,
            quic_congestion_control: config.congestion_controller.clone(),
            quic_cwnd: config.cwnd,
            quic_bbr_profile: config.bbr_profile.clone(),
        });
        service.update_users(config.users.clone().into_iter().collect());
        let tcp_listener = tcp_listener.map(old_listener);
        let udp_conn = udp_conn.map(old_packet_conn);
        if let Err(err) = service.start(tcp_listener, udp_conn, Some(Arc::clone(&tls_config))).await {
            let _ = close_all(&services, None, None).await;
            return Err(err);
        }

        services.push(service);
    }

    Ok(Listener { closed: Arc::new(AtomicBool::new(false)), config, addrs, services })
}

impl MultiAddrListener for Listener {
    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(close_all(&self.services, None, None))
        })
    }

    fn config(&self) -> String {
        self.config.to_string()
    }

    fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        self.addrs.iter().map(|a| capture_addr(a.as_ref())).collect()
    }
}
