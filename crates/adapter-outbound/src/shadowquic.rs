//! `ShadowQuic` rides a JLS-extended TLS/QUIC stack.
//!
//! Both halves live in this tree —
//! `murmur_jls_tls` carries the JLS handshake, and `murmur_transport_shadowquic::quic` runs it
//! over `quinn`, so the `username`, `password`, `sni` and `alpn` options all reach a working
//! handshake. The one congestion-control behaviour quinn cannot reproduce — the
//! controller is bound when the connection is created — is documented where it is lost in
//! `murmur_transport_shadowquic::quic`; 0-RTT and the `zero-rtt` option are carried through that
//! module.

use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use murmur_common::utils::mbps::string_to_bps;
use murmur_component::dialer::bind::join_host_port;
use murmur_component::dialer::options::{
    with_interface, with_only_single_stack, with_prefer_ipv4, with_prefer_ipv6, with_routing_mark,
    Option as DialerOption,
};
use murmur_component_ca::config::get_cert_pool;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, Dialer as CDialer, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter,
    ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_jls_tls::JlsUser;
use murmur_ntp::time::now as ntp_now;
use murmur_quic::jls::TransportFactory;
use murmur_quic::{Config, TlsConfig};
use murmur_transport_shadowquic::client::{new_client, Client, ClientOption, DialFunc};
use murmur_transport_shadowquic::dial::{dial_quic, DialQuicOption, PacketDialer as ShadowQuicPacketDialer};
use murmur_transport_shadowquic::quic::{transport_factory, CongestionOption};
use murmur_transport_shadowquic::quic_version::{default_quic_versions, parse_quic_versions};

/// The dial options, rebuilt from plain fields so the dial closure below can reconstruct them
/// fresh on every call instead of cloning a `Vec<Box<dyn Fn>>` (`DialerOption` is not `Clone`).
fn shadowquic_dial_options(
    interface: &str,
    routing_mark: i32,
    prefer: murmur_constant::dns::DNSPrefer,
) -> Vec<DialerOption> {
    use murmur_constant::dns::DNSPrefer;
    let mut opts: Vec<DialerOption> = Vec::new();
    if !interface.is_empty() {
        opts.push(with_interface(interface));
    }
    if routing_mark != 0 {
        opts.push(with_routing_mark(routing_mark));
    }
    match prefer {
        DNSPrefer::IPV4_ONLY => opts.push(with_only_single_stack(true)),
        DNSPrefer::IPV6_ONLY => opts.push(with_only_single_stack(false)),
        DNSPrefer::IPV4_PREFER => opts.push(with_prefer_ipv4()),
        DNSPrefer::IPV6_PREFER => opts.push(with_prefer_ipv6()),
        _ => {}
    }
    opts
}

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};

pub struct ShadowQuic {
    self_weak: Weak<Self>,
    base: Base,
    option: ShadowQuicOption,
    client: Client,
}

impl core::fmt::Debug for ShadowQuic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShadowQuic").field("name", &self.option.name).finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ShadowQuicOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port", default)]
    pub port: i32,
    #[serde(rename = "username", default)]
    pub username: String,
    #[serde(rename = "password", default)]
    pub password: String,
    #[serde(rename = "sni", default)]
    pub sni: String,
    #[serde(rename = "alpn", default)]
    pub alpn: Option<Vec<String>>,
    #[serde(rename = "quic-versions", default)]
    pub quic_versions: Vec<String>,
    #[serde(rename = "udp-over-stream", default)]
    pub udp_over_stream: bool,
    #[serde(rename = "zero-rtt", default)]
    pub zero_rtt: bool,
    #[serde(rename = "keep-alive-interval", default)]
    pub keep_alive_interval: i32,
    #[serde(rename = "congestion-controller", default)]
    pub congestion_controller: String,
    #[serde(rename = "up", default)]
    pub up: String,
    #[serde(rename = "down", default)]
    pub down: String,
    #[serde(rename = "cwnd", default)]
    pub cwnd: i32,
    #[serde(rename = "bbr-profile", default)]
    pub bbr_profile: String,
    #[serde(rename = "recv-window-conn", default)]
    pub receive_window_conn: i32,
    #[serde(rename = "recv-window", default)]
    pub receive_window: i32,
    #[serde(rename = "disable-mtu-discovery", default)]
    pub disable_mtu_discovery: bool,
    #[serde(rename = "max-datagram-frame-size", default)]
    pub max_datagram_frame_size: i32,
    #[serde(rename = "max-open-streams", default)]
    pub max_open_streams: i32,
}

impl core::fmt::Debug for ShadowQuicOption {
    /// Redacts `password` so `{:?}` cannot leak the credential.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShadowQuicOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("sni", &self.sni)
            .field("alpn", &self.alpn)
            .field("quic_versions", &self.quic_versions)
            .field("udp_over_stream", &self.udp_over_stream)
            .field("zero_rtt", &self.zero_rtt)
            .field("keep_alive_interval", &self.keep_alive_interval)
            .field("congestion_controller", &self.congestion_controller)
            .field("up", &self.up)
            .field("down", &self.down)
            .field("cwnd", &self.cwnd)
            .field("bbr_profile", &self.bbr_profile)
            .field("receive_window_conn", &self.receive_window_conn)
            .field("receive_window", &self.receive_window)
            .field("disable_mtu_discovery", &self.disable_mtu_discovery)
            .field("max_datagram_frame_size", &self.max_datagram_frame_size)
            .field("max_open_streams", &self.max_open_streams)
            .finish_non_exhaustive()
    }
}

/// The packet dialer, over the outbound's real dialer.
struct RealPacketDialer {
    dialer: Arc<dyn CDialer>,
}

#[async_trait]
impl ShadowQuicPacketDialer for RealPacketDialer {
    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
        r_addr_port: std::net::SocketAddr,
    ) -> Result<Box<dyn murmur_std_compat::net::PacketConn>> {
        let pc = self.dialer.listen_packet(ctx, network, address, Some(r_addr_port)).await?;
        // S11: remove with std-compat (murmur_transport_shadowquic::dial::PacketDialer still murmur_std_compat::net::PacketConn based)
        Ok(Box::new(murmur_common_net::io::DatagramAsOldPacketConn(pc)))
    }
}

/// `dial_quic` receives a fully populated TLS config, but the JLS credentials that config
/// carries are read from the `ShadowQuicOption` by `shadowquic_transport_factory` instead: the
/// transport takes the server name, ALPN, trust anchors and user from the factory, and
/// `dial_quic` only forwards this marker to it.
struct EmptyQuicTlsConfig;
impl TlsConfig for EmptyQuicTlsConfig {}

/// the inline QUIC transport over the packet conn. The session itself comes from
/// `murmur_transport_shadowquic::quic`, which drives `quinn` with the JLS handshake implemented in
/// `murmur_jls_tls`.
fn shadowquic_transport_factory(option: &ShadowQuicOption, congestion: CongestionOption) -> Arc<dyn TransportFactory> {
    let alpn = option.alpn.clone().unwrap_or_else(|| vec!["h3".to_owned()]);
    let server_name = if option.sni.is_empty() { option.server.clone() } else { option.sni.clone() };
    transport_factory(
        JlsUser { username: option.username.clone(), password: option.password.clone() },
        server_name,
        alpn,
        get_cert_pool(),
        Some(Arc::new(ntp_now)),
        congestion,
    )
}

impl ShadowQuic {
    pub fn new(mut option: ShadowQuicOption) -> Result<Arc<Self>> {
        let port =
            u16::try_from(option.port).map_err(|_| anyhow!("ShadowQuic: port {} is out of range", option.port))?;
        let addr = join_host_port(&option.server, port);

        if option.max_datagram_frame_size == 0 {
            option.max_datagram_frame_size = 1400;
        }
        if option.max_open_streams == 0 {
            option.max_open_streams = 1024;
        }
        if option.cwnd == 0 {
            option.cwnd = 32;
        }

        let quic_versions = if option.quic_versions.is_empty() {
            default_quic_versions()
        } else {
            parse_quic_versions(&option.quic_versions)?
        };

        let default_stream_window = murmur_transport_tuic::tuic::DEFAULT_STREAM_RECEIVE_WINDOW;
        let default_connection_window = murmur_transport_tuic::tuic::DEFAULT_CONNECTION_RECEIVE_WINDOW;
        let mut quic_config = Config {
            versions: quic_versions,
            max_stream_receive_window: u64::from(option.receive_window_conn.max(0).cast_unsigned()),
            max_connection_receive_window: u64::from(option.receive_window.max(0).cast_unsigned()),
            max_incoming_streams: i64::from(option.max_open_streams),
            max_incoming_uni_streams: i64::from(option.max_open_streams),
            disable_path_mtu_discovery: option.disable_mtu_discovery,
            allow_0rtt: option.zero_rtt,
            max_datagram_frame_size: i64::from(option.max_datagram_frame_size),
            enable_datagrams: true,
            ..Config::default()
        };
        if option.keep_alive_interval > 0 {
            let keep_alive_millis = u64::from(option.keep_alive_interval.cast_unsigned());
            quic_config.keep_alive_period = Duration::from_millis(keep_alive_millis);
        }
        if option.receive_window_conn == 0 {
            quic_config.max_stream_receive_window = u64::try_from(default_stream_window).unwrap_or_default();
        }
        if option.receive_window == 0 {
            quic_config.max_connection_receive_window = u64::try_from(default_connection_window).unwrap_or_default();
        }

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: addr.clone(),
            type_: AdapterType::SHADOW_QUIC,
            provider_name: option.basic_option.provider_name.clone(),
            udp: true,
            xudp: false,
            tfo: false,
            mptcp: false,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
        });
        base.dialer = Some(option.basic_option.new_dialer(base.dial_options()));

        let dial: DialFunc = {
            let interface = option.basic_option.interface.clone();
            let routing_mark = option.basic_option.routing_mark;
            let prefer = option.basic_option.ip_version;
            let dialer = base.dialer.clone().ok_or_else(|| anyhow!("ShadowQuic: dialer was not set"))?;
            let zero_rtt = option.zero_rtt;
            let congestion = CongestionOption { name: option.congestion_controller.clone(), cwnd: option.cwnd };
            let transport_factory = shadowquic_transport_factory(&option, congestion);
            let quic_config = Arc::new(quic_config);
            Arc::new(move |ctx: CancellationToken| {
                let addr = addr.clone();
                let dial_options = shadowquic_dial_options(&interface, routing_mark, prefer);
                let dialer = Arc::clone(&dialer);
                let quic_config = Arc::clone(&quic_config);
                let transport_factory = Arc::clone(&transport_factory);
                Box::pin(async move {
                    let p_dialer: Arc<dyn ShadowQuicPacketDialer> = Arc::new(RealPacketDialer { dialer });
                    let (_packet_conn, quic_conn) = dial_quic(
                        &ctx,
                        &addr,
                        dial_options,
                        p_dialer,
                        Arc::new(EmptyQuicTlsConfig),
                        quic_config,
                        DialQuicOption { early: zero_rtt, connection_id_length: 0 },
                        transport_factory,
                    )
                    .await?;
                    Ok(quic_conn)
                })
            })
        };

        let client_option = ClientOption {
            dial: Some(dial),
            udp_over_stream: option.udp_over_stream,
            congestion_controller: option.congestion_controller.clone(),
            send_bps: string_to_bps(&option.up),
            receive_bps: string_to_bps(&option.down),
            cwnd: option.cwnd,
            bbr_profile: option.bbr_profile.clone(),
        };
        let client = new_client(Some(Arc::new(client_option)));

        Ok(Arc::new_cyclic(|self_weak| Self { self_weak: Weak::clone(self_weak), base, option, client }))
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("ShadowQuic: adapter dropped while still in use"))
    }
}

#[async_trait]
impl CProxyAdapter for ShadowQuic {
    fn name(&self) -> String {
        self.base.name()
    }

    fn type_(&self) -> AdapterType {
        self.base.type_()
    }

    fn addr(&self) -> String {
        self.base.addr()
    }

    fn support_udp(&self) -> bool {
        self.base.support_udp()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let conn = self.client.dial_context(ctx, metadata).await?;
        // S11: remove with std-compat (murmur_transport_shadowquic::client::Client::dial_context still returns old murmur_std_compat::net::Conn)
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(conn)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.resolve_udp(ctx, metadata).await?;
        let pc = self.client.listen_packet(ctx, metadata).await?;
        // S11: remove with std-compat (murmur_transport_shadowquic::client::Client::listen_packet still returns old murmur_std_compat::net::PacketConn)
        Ok(new_packet_conn(Arc::new(murmur_common_net::io::OldPacketConnAsDatagram(pc)), self.self_arc()?))
    }

    fn proxy_info(&self) -> ProxyInfo {
        let mut info = self.base.proxy_info();
        info.dialer_proxy.clone_from(&self.option.basic_option.dialer_proxy);
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    fn support_uot(&self) -> bool {
        self.base.support_uot()
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.base.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(self.client.close()))
            .map_err(Into::into)
    }
}

#[async_trait]
impl ProxyAdapter for ShadowQuic {
    fn dial_options(&self) -> Vec<DialerOption> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}
