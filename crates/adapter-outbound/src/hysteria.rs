use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use parking_lot::Mutex as SyncMutex;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::ech::ECHOptions;
use murmur_common::utils::mbps::string_to_bps;
use murmur_component::dialer::bind::join_host_port;
use murmur_component_ca as ca;
use murmur_component_ech::ech::Config as EchConfig;
use murmur_component_tls::utls as tls_c;
use murmur_constant::adapters::{
    Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_log::infoln;
use murmur_sing::metadata::parse_socksaddr;
use murmur_std_compat::net::{Addr, PacketConn as NetPacketConn, UdpAddr};
use murmur_transport_hysteria::congestion::brutal::new_brutal_sender;
use murmur_transport_hysteria::core::client::{Client as HyClient, UdpConn};
use murmur_transport_hysteria::obfs::obfs::Obfuscator;
use murmur_transport_hysteria::obfs::xplus::new_xplus_obfuscator;
use murmur_transport_hysteria::pmtud_fix::DISABLE_PATH_MTU_DISCOVERY;
use murmur_transport_hysteria::transport::client::ClientTransport;
use murmur_transport_hysteria::transport::quic::{
    new_transport_factory, Config as QuicConfig, TlsConfig as QuicTlsConfig,
};
use murmur_transport_hysteria::utils::misc::PacketDialer;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::util::resolve_udp_addr;

pub(crate) const MBPS_TO_BPS: u64 = 125_000;

pub(crate) const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 15_728_640;
pub(crate) const DEFAULT_CONNECTION_RECEIVE_WINDOW: u64 = 67_108_864;

pub(crate) const DEFAULT_ALPN: &str = "hysteria";
pub(crate) const DEFAULT_PROTOCOL: &str = "udp";
pub(crate) const DEFAULT_HOP_INTERVAL: i32 = 10;

pub struct Hysteria {
    base: Base,
    option: HysteriaOption,
    client: Arc<HyClient>,

    tls_config: Arc<SyncMutex<tls_c::Config>>,
    ech_config: Option<Arc<EchConfig>>,

    self_weak: std::sync::Weak<Self>,
}

impl std::fmt::Debug for Hysteria {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria").field("name", &self.base.name()).finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct HysteriaOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port", default)]
    pub port: i32,
    #[serde(rename = "ports", default)]
    pub ports: String,
    #[serde(rename = "protocol", default)]
    pub protocol: String,
    #[serde(rename = "obfs-protocol", default)]
    pub obfs_protocol: String,
    #[serde(rename = "up")]
    pub up: String,
    #[serde(rename = "up-speed", default)]
    pub up_speed: i32,
    #[serde(rename = "down")]
    pub down: String,
    #[serde(rename = "down-speed", default)]
    pub down_speed: i32,
    #[serde(rename = "auth", default)]
    pub auth: String,
    #[serde(rename = "auth-str", default)]
    pub auth_string: String,
    #[serde(rename = "obfs", default)]
    pub obfs: String,
    #[serde(rename = "sni", default)]
    pub sni: String,
    #[serde(rename = "ech-opts", default)]
    pub ech_opts: ECHOptions,
    #[serde(rename = "skip-cert-verify", default)]
    pub skip_cert_verify: bool,
    #[serde(rename = "name-cert-verify", default)]
    pub name_cert_verify: String,
    #[serde(rename = "fingerprint", default)]
    pub fingerprint: String,
    #[serde(rename = "certificate", default)]
    pub certificate: String,
    #[serde(rename = "private-key", default)]
    pub private_key: String,
    #[serde(rename = "alpn", default)]
    pub alpn: Option<Vec<String>>,
    #[serde(rename = "recv-window-conn", default)]
    pub receive_window_conn: u64,
    #[serde(rename = "recv-window", default)]
    pub receive_window: u64,
    #[serde(rename = "disable-mtu-discovery", default)]
    pub disable_mtu_discovery: bool,
    #[serde(rename = "fast-open", default)]
    pub fast_open: bool,
    #[serde(rename = "hop-interval", default)]
    pub hop_interval: i32,
}

impl std::fmt::Debug for HysteriaOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysteriaOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

impl HysteriaOption {
    pub fn speed(&self) -> Result<(u64, u64)> {
        let up = string_to_bps(&self.up);
        if up == 0 {
            return Err(anyhow!("invaild upload speed: {}", self.up));
        }

        let down = string_to_bps(&self.down);
        if down == 0 {
            return Err(anyhow!("invaild download speed: {}", self.down));
        }

        Ok((up, down))
    }
}

struct HyDialerWithContext {
    ctx: CancellationToken,
    dialer: Arc<dyn murmur_constant::adapters::Dialer>,
    listen_ctx: CancellationToken,
    prefer: murmur_constant::dns::DNSPrefer,
    ech_config: Option<Arc<EchConfig>>,
    tls_config: Arc<SyncMutex<tls_c::Config>>,
}

#[async_trait]
impl PacketDialer for HyDialerWithContext {
    async fn listen_packet(&self, r_addr: &dyn Addr) -> Result<Box<dyn NetPacketConn>> {
        let r_addr_port = r_addr.string().parse::<std::net::SocketAddr>().ok();
        let pc = self.dialer.listen_packet(&self.listen_ctx, "udp", "", r_addr_port).await?;
        // S11: remove with std-compat (murmur_transport_hysteria::utils::misc::PacketDialer still murmur_std_compat::net::PacketConn based)
        let pc: Box<dyn NetPacketConn> = Box::new(murmur_common_net::io::DatagramAsOldPacketConn(pc));
        Ok(pc)
    }

    fn context(&self) -> CancellationToken {
        self.ctx.clone()
    }

    async fn remote_addr(&self, host: &str) -> Result<Box<dyn Addr>> {
        let udp_addr = resolve_udp_addr(&self.listen_ctx, "udp", host, self.prefer).await?;
        if let Some(ech) = &self.ech_config {
            let mut config = self.tls_config.lock().clone();
            ech.client_handle(self.listen_ctx.clone(), &mut config).await?;
            *self.tls_config.lock() = config;
        }
        Ok(Box::new(udp_addr))
    }
}

struct HyPacketConn {
    inner: Box<dyn UdpConn>,
}

#[async_trait]
impl murmur_common_net::io::Datagram for HyPacketConn {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)> {
        let (b, addr_str) = self.inner.read_from().await.map_err(|e| std::io::Error::other(e.to_string()))?;
        let n = buf.len().min(b.len());
        let (Some(dst), Some(src)) = (buf.get_mut(..n), b.get(..n)) else {
            return Err(std::io::Error::other("hysteria: datagram shorter than the copy length"));
        };
        dst.copy_from_slice(src);
        Ok((n, parse_udp_addr_string(&addr_str)))
    }

    async fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> std::io::Result<usize> {
        self.inner.write_to(buf, &addr.to_string()).await.map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        murmur_common_net::io::old_addr_to_socket_addr(self.inner.local_addr().as_ref())
    }

    fn close(&self) -> std::io::Result<()> {
        self.inner.close().map_err(|e| std::io::Error::other(e.to_string()))
    }
}

fn parse_udp_addr_string(addr_str: &str) -> std::net::SocketAddr {
    let addr = parse_socksaddr(addr_str)
        .udp_addr()
        .unwrap_or_else(|| UdpAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));
    murmur_common_net::io::old_addr_to_socket_addr(&addr)
        .unwrap_or_else(|_| std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
}

/// A TLS config wrapper implementing the hysteria transport's `TlsConfig` seam.
///
/// The TLS config stays the authority the dialer resolves ECH against (the same value is handed to
/// every packet dialer); the QUIC session only needs its `rustls` form, and the server name is held
/// alongside it because the trait hands it out by reference.
struct HyTlsConfig {
    config: Arc<SyncMutex<tls_c::Config>>,
    server_name: String,
}

impl QuicTlsConfig for HyTlsConfig {
    fn rustls_client_config(&self) -> Result<rustls::ClientConfig> {
        tls_c::client_rustls_config(&self.config.lock())
    }

    fn server_name(&self) -> &str {
        &self.server_name
    }
}

fn build_tls_config(option: &HysteriaOption) -> Result<tls_c::Config> {
    let server_name = if option.sni.is_empty() { option.server.clone() } else { option.sni.clone() };
    let mut tls_config = ca::config::get_tls_config(ca::config::Option {
        tls_config: Some(tls_c::Config {
            server_name,
            insecure_skip_verify: option.skip_cert_verify,
            min_version: tls_c::VERSION_TLS13,
            rand: None,
            time: None,
            certificates: Vec::new(),
            get_certificate: None,
            get_client_certificate: None,
            verify_peer_certificate: None,
            verify_connection: None,
            root_cas: None,
            next_protos: Vec::new(),
            client_auth: tls_c::ClientAuthType::default(),
            client_cas: None,
            cipher_suites: None,
            session_tickets_disabled: false,
            max_version: 0,
            curve_preferences: None,
            renegotiation: tls_c::RenegotiationSupport::default(),
            key_log_writer: None,
            encrypted_client_hello_config_list: Vec::new(),
            encrypted_client_hello_rejection_verify: None,
            encrypted_client_hello_keys: Vec::new(),
            get_encrypted_client_hello_keys: None,
            session_id_generator: None,
        }),
        fingerprint: option.fingerprint.clone(),
        name_cert_verify: option.name_cert_verify.clone(),
        certificate: option.certificate.clone(),
        private_key: option.private_key.clone(),
        zero_trust: false,
    })?;

    if let Some(alpn) = &option.alpn {
        tls_config.next_protos.clone_from(alpn);
    } else {
        tls_config.next_protos = vec![DEFAULT_ALPN.to_owned()];
    }
    Ok(tls_config)
}

fn build_quic_config(option: &HysteriaOption) -> QuicConfig {
    let mut quic_config = QuicConfig {
        initial_stream_receive_window: option.receive_window_conn,
        max_stream_receive_window: option.receive_window_conn,
        initial_connection_receive_window: option.receive_window,
        max_connection_receive_window: option.receive_window,
        keep_alive_period: Duration::from_secs(10),
        disable_path_mtu_discovery: option.disable_mtu_discovery,
        enable_datagrams: true,
    };
    if option.receive_window == 0 {
        quic_config.initial_stream_receive_window = DEFAULT_STREAM_RECEIVE_WINDOW / 10;
        quic_config.max_stream_receive_window = DEFAULT_STREAM_RECEIVE_WINDOW;
        quic_config.initial_connection_receive_window = DEFAULT_CONNECTION_RECEIVE_WINDOW / 10;
        quic_config.max_connection_receive_window = DEFAULT_CONNECTION_RECEIVE_WINDOW;
    }
    quic_config
}

impl Hysteria {
    pub fn new(mut option: HysteriaOption) -> Result<Arc<Self>> {
        let port = u16::try_from(option.port).map_err(|_| anyhow!("invalid port"))?;
        let addr = join_host_port(&option.server, port);
        let ports = option.ports.clone();

        let tls_config = build_tls_config(&option)?;

        let ech_config = option.ech_opts.parse()?.map(Arc::new);
        let tls_client_config = Arc::new(SyncMutex::new(tls_config));

        let quic_config = build_quic_config(&option);
        if !option.obfs_protocol.is_empty() {
            option.protocol.clone_from(&option.obfs_protocol);
        }
        if option.protocol.is_empty() {
            DEFAULT_PROTOCOL.clone_into(&mut option.protocol);
        }
        if option.hop_interval == 0 {
            option.hop_interval = DEFAULT_HOP_INTERVAL;
        }
        let hop_interval = Duration::from_secs(u64::from(option.hop_interval.max(0).cast_unsigned()));
        if !quic_config.disable_path_mtu_discovery && DISABLE_PATH_MTU_DISCOVERY {
            infoln!("hysteria: Path MTU Discovery is not yet supported on this platform");
        }

        let auth = if option.auth.is_empty() {
            option.auth_string.clone().into_bytes()
        } else {
            STANDARD.decode(&option.auth)?
        };

        let obfuscator: Option<Arc<dyn Obfuscator>> = if option.obfs.is_empty() {
            None
        } else {
            Some(Arc::new(new_xplus_obfuscator(option.obfs.clone().into_bytes())))
        };

        let (mut up, mut down) = option.speed()?;
        if option.up_speed != 0 {
            up = i64::from(option.up_speed).cast_unsigned().wrapping_mul(MBPS_TO_BPS);
        }
        if option.down_speed != 0 {
            down = i64::from(option.down_speed).cast_unsigned().wrapping_mul(MBPS_TO_BPS);
        }

        let congestion_factory: murmur_transport_hysteria::core::client::CongestionFactory =
            Arc::new(|ref_bps: u64| Box::new(new_brutal_sender(ref_bps.cast_signed())));

        let client_transport = Arc::new(ClientTransport::new(new_transport_factory()));

        // The seam needs the server name by value: `quinn` reports the SNI without taking the
        // shared TLS config's lock, while `rustls_client_config` still reads that config.
        let hy_tls: Arc<dyn QuicTlsConfig> = Arc::new(HyTlsConfig {
            server_name: tls_client_config.lock().server_name.clone(),
            config: Arc::clone(&tls_client_config),
        });

        let client = HyClient::new_client(
            addr.clone(),
            ports,
            option.protocol.clone(),
            auth,
            hy_tls,
            quic_config,
            client_transport,
            up,
            down,
            Some(congestion_factory),
            obfuscator,
            hop_interval,
            option.fast_open,
        )
        .map_err(|e| anyhow!("hysteria {addr} create error: {e}"))?;

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr,
            type_: murmur_constant::adapters::AdapterType::HYSTERIA,
            provider_name: option.basic_option.provider_name.clone(),
            udp: true,
            xudp: false,
            tfo: option.fast_open,
            mptcp: false,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
        });
        base.dialer = Some(option.basic_option.new_dialer(base.dial_options()));

        Ok(Arc::new_cyclic(|self_weak| Self {
            base,
            option,
            client,
            tls_config: tls_client_config,
            ech_config,
            self_weak: std::sync::Weak::clone(self_weak),
        }))
    }

    fn gen_hdc(&self, ctx: &CancellationToken) -> Result<Arc<dyn PacketDialer>> {
        let dialer =
            self.base.dialer.clone().ok_or_else(|| anyhow!("Base.dialer set by NewHysteria before DialContext"))?;
        Ok(Arc::new(HyDialerWithContext {
            ctx: CancellationToken::new(),
            dialer,
            listen_ctx: ctx.clone(),
            prefer: self.base.prefer,
            ech_config: self.ech_config.clone(),
            tls_config: Arc::clone(&self.tls_config),
        }))
    }

    fn self_arc(&self) -> Result<Arc<dyn ProxyAdapter>> {
        self.self_weak
            .upgrade()
            .map(|arc| -> Arc<dyn ProxyAdapter> { arc })
            .ok_or_else(|| anyhow!("Hysteria dropped while listen_packet_context is running"))
    }
}

#[async_trait]
impl CProxyAdapter for Hysteria {
    fn name(&self) -> String {
        self.base.name()
    }

    fn type_(&self) -> murmur_constant::adapters::AdapterType {
        self.base.type_()
    }

    fn addr(&self) -> String {
        self.base.addr()
    }

    fn support_udp(&self) -> bool {
        self.base.support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        let mut info = self.base.proxy_info();
        info.dialer_proxy.clone_from(&self.option.basic_option.dialer_proxy);
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let tcp_conn = self.client.dial_tcp(&metadata.string(), metadata.dst_port, self.gen_hdc(ctx)?).await?;
        // S11: remove with std-compat (murmur_transport_hysteria::core::client::Client::dial_tcp still returns old murmur_std_compat::net::Conn)
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(tcp_conn)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.resolve_udp(ctx, metadata).await?;
        let udp_conn = self.client.dial_udp(self.gen_hdc(ctx)?).await?;
        let hy_pc: Arc<dyn murmur_common_net::io::Datagram> = Arc::new(HyPacketConn { inner: udp_conn });

        Ok(new_packet_conn(hy_pc, self.self_arc()?))
    }

    /// Not overridden; keeps `Base`'s `false`.
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
    }
}

#[async_trait]
impl ProxyAdapter for Hysteria {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}
