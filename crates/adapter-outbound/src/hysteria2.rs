//! The QUIC session, the HTTP/3 authentication exchange, the proxy streams and the UDP relay come
//! from `murmur_transport_hysteria2`; this file is the option surface plus the adapter behaviour.
//!
//! Three behaviours have no counterpart in the transport's API:
//!
//! * `realm-opts`: the transport excludes the `realm`, so the client half — control-plane
//!   `connect`, STUN discovery and the UDP hole-punch — lives in [`crate::hysteria2_realm`] and
//!   hands the punched socket to `ClientOptions` as an ordinary packet conn.
//! * `bbr-profile`: `CongestionOption` carries only the controller name and `cwnd`, and quinn binds
//!   its controller when the endpoint is built, so neither the profile argument nor the
//!   post-auth congestion-sender swap is reachable.
//! * `handshake-timeout` of 0 means "no independent timeout", but the transport applies
//!   `ClientOptions::handshake_timeout` unconditionally, where zero would expire before the first
//!   packet, so [`NO_HANDSHAKE_TIMEOUT`] stands in.
//!
//! The client is also built on the first dial rather than at construction: the server name is
//! resolved and the packet listener bound inside the transport's own dial, both async, while
//! `ClientOptions` want the resolved address and the bound packet conn up front.

use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use parking_lot::Mutex as SyncMutex;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

use crate::ech::ECHOptions;
use murmur_common::utils::mbps::string_to_bps;
use murmur_common::utils::range::new_unsigned_range;
use murmur_common::utils::ranges::new_unsigned_ranges;
use murmur_common_net::io::{DatagramAsOldPacketConn, OldConnAsStream};
use murmur_common_net::new_thread_safe_packet_conn;
use murmur_component::dialer::bind::join_host_port;
use murmur_component_ca as ca;
use murmur_component_ech::ech::Config as EchConfig;
use murmur_component_tls::utls as tls_c;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, Dialer as CDialer, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter,
    ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_sing::metadata::{parse_socksaddr_host_port, Socksaddr};
use murmur_std_compat::net::PacketConn as NetPacketConn;
use murmur_transport_hysteria2::quic::{CongestionOption, QuicConfig};
use murmur_transport_hysteria2::{Client as Hy2Client, ClientOptions, Obfs};

use super::base::{
    arc_packet_conn_as_datagram, new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter,
};
use super::hysteria2_realm::RealmClient;
use super::util::resolve_udp_addr;

/// The hop-interval bounds.
const MIN_HOP_INTERVAL_SECS: u64 = 5;
const DEFAULT_HOP_INTERVAL_SECS: u64 = 30;

/// An empty ALPN defaults to HTTP/3.
const DEFAULT_ALPN: &str = "h3";

/// Stands in for the "no independent handshake timeout" (see the module doc).
const NO_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30 * 24 * 60 * 60);

pub struct Hysteria2 {
    self_weak: Weak<Self>,
    base: Base,
    option: Hysteria2Option,

    client: OnceCell<Arc<Hy2Client>>,
    tls_config: tls_c::Config,
    rustls_config: Arc<rustls::ClientConfig>,
    ech_config: Option<Arc<EchConfig>>,
    obfs: Option<Obfs>,
    server_name: String,
    quic_config: QuicConfig,
    congestion: CongestionOption,
    handshake_timeout: Duration,
    udp_mtu: usize,
    server_ports: Vec<u16>,
    hop_interval: Duration,
    hop_interval_max: Duration,
    /// `None` means `realm-opts.enable` is unset.
    realm: Option<RealmClient>,
    /// Kept so `close` can release the socket the session was built on.
    packet_conn: SyncMutex<Option<Arc<dyn NetPacketConn>>>,
}

impl std::fmt::Debug for Hysteria2 {
    /// Redacts the option's password material so a stray `{:?}` cannot log it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2").field("server_name", &self.server_name).finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Hysteria2Option {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name", default)]
    pub name: String,
    #[serde(rename = "server", default)]
    pub server: String,
    #[serde(rename = "port", default)]
    pub port: i32,
    #[serde(rename = "ports", default)]
    pub ports: String,
    #[serde(rename = "hop-interval", default)]
    pub hop_interval: String,
    #[serde(rename = "up", default)]
    pub up: String,
    #[serde(rename = "down", default)]
    pub down: String,
    #[serde(rename = "password", default)]
    pub password: String,
    #[serde(rename = "obfs", default)]
    pub obfs: String,
    #[serde(rename = "obfs-password", default)]
    pub obfs_password: String,
    #[serde(rename = "obfs-min-packet-size", default)]
    pub obfs_min_packet_size: i32,
    #[serde(rename = "obfs-max-packet-size", default)]
    pub obfs_max_packet_size: i32,
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
    #[serde(rename = "cwnd", default)]
    pub cwnd: i32,
    #[serde(rename = "bbr-profile", default)]
    pub bbr_profile: String,
    #[serde(rename = "udp-mtu", default)]
    pub udp_mtu: i32,
    #[serde(rename = "handshake-timeout", default)]
    pub handshake_timeout: i32,
    #[serde(rename = "realm-opts", default)]
    pub realm_opts: Hysteria2RealmOption,
    #[serde(rename = "initial-stream-receive-window", default)]
    pub initial_stream_receive_window: u64,
    #[serde(rename = "max-stream-receive-window", default)]
    pub max_stream_receive_window: u64,
    #[serde(rename = "initial-connection-receive-window", default)]
    pub initial_connection_receive_window: u64,
    #[serde(rename = "max-connection-receive-window", default)]
    pub max_connection_receive_window: u64,
}

impl std::fmt::Debug for Hysteria2Option {
    /// Redacts the password, obfs password and key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Option")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("password", &"<redacted>")
            .field("obfs_password", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Hysteria2RealmOption {
    #[serde(rename = "enable", default)]
    pub enable: bool,
    #[serde(rename = "server-url", default)]
    pub server_url: String,
    #[serde(rename = "token", default)]
    pub token: String,
    #[serde(rename = "realm-id", default)]
    pub realm_id: String,
    #[serde(rename = "stun-servers", default)]
    pub stun_servers: Vec<String>,
    #[serde(rename = "sni", default)]
    pub sni: String,
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
}

impl std::fmt::Debug for Hysteria2RealmOption {
    /// Redacts the realm token and the key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2RealmOption")
            .field("enable", &self.enable)
            .field("realm_id", &self.realm_id)
            .field("token", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// The SNI replaces the server name rather than being left empty for it.
fn server_name(server: &str, sni: &str) -> String {
    if sni.is_empty() {
        server.to_owned()
    } else {
        sni.to_owned()
    }
}

/// Parses the port ranges, then expands them.
fn parse_server_ports(ports: &str) -> Result<Vec<u16>> {
    let ranges = new_unsigned_ranges::<u16>(ports)?;
    let mut server_ports = Vec::new();
    for range in &ranges {
        for port in range.start()..=range.end() {
            server_ports.push(port);
        }
    }
    Ok(server_ports)
}

/// the `start`/`end` clamp of the configured `hop-interval`, which only runs alongside `ports`.
fn parse_hop_intervals(hop_interval: &str) -> Result<(Duration, Duration)> {
    let hop_range = new_unsigned_range::<u64>(hop_interval)?;
    let mut start = hop_range.start();
    let mut end = hop_range.end();
    if start == 0 {
        start = DEFAULT_HOP_INTERVAL_SECS;
    } else if start < MIN_HOP_INTERVAL_SECS {
        start = MIN_HOP_INTERVAL_SECS;
    }
    if end < start {
        end = start;
    }
    Ok((Duration::from_secs(start), Duration::from_secs(end)))
}

/// the `switch option.Obfs`; the messages are `Obfs::new`'s, so they stay unprefixed.
fn parse_obfs(option: &Hysteria2Option) -> Result<Option<Obfs>> {
    if option.obfs.is_empty() {
        return Ok(None);
    }
    let obfs = Obfs::new(
        &option.obfs,
        &option.obfs_password,
        usize::try_from(option.obfs_min_packet_size.max(0)).map_err(|_| anyhow!("invalid obfs packet size"))?,
        usize::try_from(option.obfs_max_packet_size.max(0)).map_err(|_| anyhow!("invalid obfs packet size"))?,
    )
    .map_err(|err| anyhow!("{err}"))?;
    Ok(Some(obfs))
}

/// The client's TLS material: the TLS config, its rustls form, and the configured ECH.
fn build_tls_state(
    option: &Hysteria2Option,
    server_name: &str,
) -> Result<(tls_c::Config, Arc<rustls::ClientConfig>, Option<Arc<EchConfig>>)> {
    let mut tls_config = ca::config::get_tls_config(ca::config::Option {
        tls_config: Some(tls_c::Config {
            server_name: server_name.to_owned(),
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
    }
    if tls_config.next_protos.is_empty() {
        tls_config.next_protos = vec![DEFAULT_ALPN.to_owned()];
    }
    let ech_config = option.ech_opts.parse()?.map(Arc::new);
    let rustls_config = Arc::new(tls_c::client_rustls_config(&tls_config)?);
    Ok((tls_config, rustls_config, ech_config))
}

/// The QUIC parameters: `EnableDatagrams = !UDPDisabled`, with path MTU discovery left alone.
fn build_quic_config(option: &Hysteria2Option) -> QuicConfig {
    QuicConfig {
        initial_stream_receive_window: option.initial_stream_receive_window,
        max_stream_receive_window: option.max_stream_receive_window,
        initial_connection_receive_window: option.initial_connection_receive_window,
        max_connection_receive_window: option.max_connection_receive_window,
        disable_path_mtu_discovery: false,
        enable_datagrams: true,
        max_idle_timeout: Duration::ZERO,
        keep_alive_period: Duration::ZERO,
    }
}

impl Hysteria2 {
    pub fn new(option: Hysteria2Option) -> Result<Arc<Self>> {
        let Ok(port) = u16::try_from(option.port) else {
            bail!("invalid port");
        };
        let addr = join_host_port(&option.server, port);

        let obfs = parse_obfs(&option)?;
        let server_name = server_name(&option.server, &option.sni);

        let (tls_config, rustls_config, ech_config) = build_tls_state(&option, &server_name)?;

        let server_ports = if option.ports.is_empty() { Vec::new() } else { parse_server_ports(&option.ports)? };
        let (hop_interval, hop_interval_max) = if server_ports.is_empty() {
            (Duration::ZERO, Duration::ZERO)
        } else {
            parse_hop_intervals(&option.hop_interval)?
        };
        if option.port == 0 && server_ports.is_empty() {
            bail!("invalid port");
        }

        let quic_config = build_quic_config(&option);

        let handshake_timeout = if option.handshake_timeout <= 0 {
            NO_HANDSHAKE_TIMEOUT
        } else {
            Duration::from_secs(u64::from(option.handshake_timeout.unsigned_abs()))
        };

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr,
            type_: AdapterType::HYSTERIA2,
            provider_name: option.basic_option.provider_name.clone(),
            udp: true,
            xudp: false,
            // The base construction passes neither, so a configured tfo/mptcp stays inert here too.
            tfo: false,
            mptcp: false,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
        });
        let congestion = CongestionOption { name: "bbr".to_owned(), cwnd: option.cwnd };
        let udp_mtu = usize::try_from(option.udp_mtu.max(0)).unwrap_or_default();
        let dialer = option.basic_option.new_dialer(base.dial_options());
        base.dialer = Some(Arc::clone(&dialer));
        // A realm is refused together with port hopping, since both choose the address the session
        // dials.
        let realm = if option.realm_opts.enable {
            if !server_ports.is_empty() {
                bail!("realm and port hopping are mutually exclusive");
            }
            Some(RealmClient::new(&option.realm_opts, dialer)?)
        } else {
            None
        };

        Ok(Arc::new_cyclic(|self_weak| Self {
            self_weak: Weak::clone(self_weak),
            base,
            option,
            client: OnceCell::new(),
            tls_config,
            rustls_config,
            ech_config,
            obfs,
            server_name,
            quic_config,
            congestion,
            handshake_timeout,
            udp_mtu,
            server_ports,
            hop_interval,
            hop_interval_max,
            realm,
            packet_conn: SyncMutex::new(None),
        }))
    }
}

impl Hysteria2 {
    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("Hysteria2 adapter dropped while still in use"))
    }

    /// The client is built on the first dial, where the server name can be resolved and the packet
    /// conn bound (see the module doc).
    async fn client(&self, ctx: &CancellationToken) -> Result<Arc<Hy2Client>> {
        self.client.get_or_try_init(|| self.build_client(ctx)).await.map(Arc::clone)
    }

    async fn build_client(&self, ctx: &CancellationToken) -> Result<Arc<Hy2Client>> {
        let addr = self.base.addr();
        let (server_address, packet_conn): (Socksaddr, Arc<dyn NetPacketConn>) = if let Some(realm) = &self.realm {
            // `offer_new` runs inside the same handshake-timeout context as the QUIC dial.
            let (packet_conn, peer) = tokio::time::timeout(self.handshake_timeout, realm.offer_new(ctx))
                .await
                .map_err(|_| anyhow!("hysteria2: handshake timeout"))??;
            (peer, packet_conn)
        } else {
            let dialer: Arc<dyn CDialer> =
                self.base.dialer.clone().ok_or_else(|| anyhow!("hysteria2 {addr}: no dialer configured"))?;
            let remote = SocketAddr::try_from(&resolve_udp_addr(ctx, "udp", &addr, self.base.prefer).await?)?;
            let packet_conn: Arc<dyn NetPacketConn> =
                Arc::new(DatagramAsOldPacketConn(dialer.listen_packet(ctx, "udp", "", Some(remote)).await?));
            (Socksaddr::from_socket_addr(remote), packet_conn)
        };
        *self.packet_conn.lock() = Some(Arc::clone(&packet_conn));

        let tls = match &self.ech_config {
            Some(ech) => {
                let mut tls_config = self.tls_config.clone();
                ech.client_handle(ctx.clone(), &mut tls_config).await?;
                Arc::new(tls_c::client_rustls_config(&tls_config)?)
            }
            None => Arc::clone(&self.rustls_config),
        };

        let options = ClientOptions {
            password: self.option.password.clone(),
            server_address,
            server_ports: self.server_ports.clone(),
            hop_interval: self.hop_interval,
            hop_interval_max: self.hop_interval_max,
            send_bps: string_to_bps(&self.option.up),
            receive_bps: string_to_bps(&self.option.down),
            obfs: self.obfs.clone(),
            server_name: self.server_name.clone(),
            tls,
            quic: self.quic_config.clone(),
            udp_disabled: false,
            udp_mtu: self.udp_mtu,
            congestion: self.congestion.clone(),
            handshake_timeout: self.handshake_timeout,
            packet_conn,
        };
        Ok(Arc::new(Hy2Client::new(options)?))
    }
}

#[async_trait]
impl CProxyAdapter for Hysteria2 {
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

    fn proxy_info(&self) -> ProxyInfo {
        let mut info = self.base.proxy_info();
        info.dialer_proxy.clone_from(&self.option.basic_option.dialer_proxy);
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let client = self.client(ctx).await?;
        let destination = parse_socksaddr_host_port(&metadata.string(), metadata.dst_port);
        let conn = client.dial_conn(ctx, destination).await?;
        // S11: remove with std-compat (transport-hysteria2::client::Client still returns old murmur_std_compat::net::Conn)
        Ok(new_conn(Box::new(OldConnAsStream(conn)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.resolve_udp(ctx, metadata).await?;
        let client = self.client(ctx).await?;
        let pc = client.listen_packet(ctx).await?;
        let pc: Arc<dyn NetPacketConn> = Arc::from(pc);
        let pc = new_thread_safe_packet_conn(pc).into_packet_conn();
        Ok(new_packet_conn(arc_packet_conn_as_datagram(pc), self.self_arc()?))
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
        if let Some(client) = self.client.get() {
            client.close_with_error("proxy removed")?;
        }
        let pc = self.packet_conn.lock().take();
        if let Some(pc) = pc {
            let _ = pc.close();
        }
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for Hysteria2 {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

#[cfg(test)]
mod tests {
    use murmur_common_net::io::old_addr_to_socket_addr;
    use murmur_component_ca::keypair::{new_random_tls_key_pair, KeyPairType};
    use murmur_constant::dns::DNSPrefer;
    use murmur_constant::metadata::NetWork;
    use murmur_std_compat::net::{Conn as NetConn, UdpAddr};
    use murmur_transport_hysteria2::service::{ServerHandler, Service, ServiceOptions};
    use rustls::pki_types::PrivateKeyDer;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::hysteria2_realm::test_support as realm;

    const PASSWORD: &str = "test-password";
    const PAYLOAD: &[u8] = b"hysteria2-adapter-payload";
    const TIMEOUT: Duration = Duration::from_secs(20);

    fn minimal() -> Hysteria2Option {
        Hysteria2Option {
            name: "hysteria2-test".to_owned(),
            server: "127.0.0.1".to_owned(),
            port: 443,
            password: PASSWORD.to_owned(),
            skip_cert_verify: true,
            ..Default::default()
        }
    }

    #[test]
    fn every_option_field_decodes_from_its_wire_name() {
        let option: Hysteria2Option = serde_yaml::from_str(
            r#"
name: h2
server: example.com
port: 8443
ports: 200-202
hop-interval: 10-20
up: 100 mbps
down: 50 mbps
password: pw
obfs: gecko
obfs-password: obfs-pw
obfs-min-packet-size: 600
obfs-max-packet-size: 1300
sni: sni.example.com
skip-cert-verify: true
name-cert-verify: verify.example.com
fingerprint: chrome
certificate: cert-pem
private-key: key-pem
alpn: [h3]
cwnd: 64
bbr-profile: aggressive
udp-mtu: 1400
handshake-timeout: 8
initial-stream-receive-window: 1
max-stream-receive-window: 2
initial-connection-receive-window: 3
max-connection-receive-window: 4
interface-name: eth0
routing-mark: 7
ip-version: ipv4
dialer-proxy: other
tfo: true
mptcp: true
realm-opts:
  enable: true
  server-url: "https://realm.example.com"
  token: tok
  realm-id: realm
  stun-servers: ["stun.example.com:3478"]
  sni: realm-sni.example.com
  skip-cert-verify: true
  name-cert-verify: realm-verify.example.com
  fingerprint: firefox
  certificate: realm-cert
  private-key: realm-key
  alpn: [h3]
"#,
        )
        .expect("the option decodes");

        assert_core_fields_decoded(&option);
        assert_tls_fields_decoded(&option);
        assert_window_fields_decoded(&option);
        assert_basic_fields_decoded(&option);
        assert_realm_fields_decoded(&option);
    }

    fn assert_core_fields_decoded(option: &Hysteria2Option) {
        assert_eq!(option.name, "h2");
        assert_eq!(option.server, "example.com");
        assert_eq!(option.port, 8443);
        assert_eq!(option.ports, "200-202");
        assert_eq!(option.hop_interval, "10-20");
        assert_eq!(option.up, "100 mbps");
        assert_eq!(option.down, "50 mbps");
        assert_eq!(option.password, "pw");
        assert_eq!(option.obfs, "gecko");
        assert_eq!(option.obfs_password, "obfs-pw");
        assert_eq!(option.obfs_min_packet_size, 600);
        assert_eq!(option.obfs_max_packet_size, 1300);
    }

    fn assert_tls_fields_decoded(option: &Hysteria2Option) {
        assert_eq!(option.sni, "sni.example.com");
        assert!(option.skip_cert_verify);
        assert_eq!(option.name_cert_verify, "verify.example.com");
        assert_eq!(option.fingerprint, "chrome");
        assert_eq!(option.certificate, "cert-pem");
        assert_eq!(option.private_key, "key-pem");
        assert_eq!(option.alpn.as_deref(), Some(&["h3".to_owned()][..]));
    }

    fn assert_window_fields_decoded(option: &Hysteria2Option) {
        assert_eq!(option.cwnd, 64);
        assert_eq!(option.bbr_profile, "aggressive");
        assert_eq!(option.udp_mtu, 1400);
        assert_eq!(option.handshake_timeout, 8);
        assert_eq!(option.initial_stream_receive_window, 1);
        assert_eq!(option.max_stream_receive_window, 2);
        assert_eq!(option.initial_connection_receive_window, 3);
        assert_eq!(option.max_connection_receive_window, 4);
    }

    fn assert_basic_fields_decoded(option: &Hysteria2Option) {
        assert_eq!(option.basic_option.interface, "eth0");
        assert_eq!(option.basic_option.routing_mark, 7);
        assert_eq!(option.basic_option.ip_version, DNSPrefer::IPV4_ONLY);
        assert_eq!(option.basic_option.dialer_proxy, "other");
        assert!(option.basic_option.tfo);
        assert!(option.basic_option.mptcp);
    }

    fn assert_realm_fields_decoded(option: &Hysteria2Option) {
        assert!(option.realm_opts.enable);
        assert_eq!(option.realm_opts.server_url, "https://realm.example.com");
        assert_eq!(option.realm_opts.token, "tok");
        assert_eq!(option.realm_opts.realm_id, "realm");
        assert_eq!(option.realm_opts.stun_servers, ["stun.example.com:3478"]);
        assert_eq!(option.realm_opts.sni, "realm-sni.example.com");
        assert!(option.realm_opts.skip_cert_verify);
        assert_eq!(option.realm_opts.name_cert_verify, "realm-verify.example.com");
        assert_eq!(option.realm_opts.fingerprint, "firefox");
        assert_eq!(option.realm_opts.certificate, "realm-cert");
        assert_eq!(option.realm_opts.private_key, "realm-key");
        assert_eq!(option.realm_opts.alpn.as_deref(), Some(&["h3".to_owned()][..]));
    }

    #[test]
    fn defaults_leave_every_unset_field_at_its_zero_value() {
        let option = Hysteria2Option::default();
        assert_eq!(option.port, 0);
        assert_eq!(option.ports, "");
        assert_eq!(option.hop_interval, "");
        assert!(option.alpn.is_none());
        assert!(!option.realm_opts.enable);
        assert!(!option.basic_option.tfo);
        assert!(!option.basic_option.mptcp);
    }

    #[test]
    fn the_sni_replaces_the_server_name() {
        assert_eq!(server_name("example.com", ""), "example.com");
        assert_eq!(server_name("example.com", "sni.example.com"), "sni.example.com");
    }

    #[test]
    fn ports_expand_and_hop_intervals_clamp_to_the_documented_bounds() {
        assert_eq!(parse_server_ports("200,300-302").expect("parse ports"), vec![200, 300, 301, 302]);
        assert_eq!(parse_server_ports("400").expect("parse a single port"), vec![400]);
        assert!(parse_server_ports("").expect("an empty list is no ports").is_empty());
        let too_many = (1..=29).map(|port| port.to_string()).collect::<Vec<_>>().join(",");
        assert!(parse_server_ports(&too_many).expect_err("too many ranges").to_string().contains("28"));

        assert_eq!(parse_hop_intervals("").expect("default"), (Duration::from_secs(30), Duration::from_secs(30)));
        assert_eq!(
            parse_hop_intervals("3-4").expect("below the floor"),
            (Duration::from_secs(5), Duration::from_secs(5))
        );
        assert_eq!(
            parse_hop_intervals("10-20").expect("inside the window"),
            (Duration::from_secs(10), Duration::from_secs(20))
        );
        assert_eq!(
            parse_hop_intervals("30-10").expect("an inverted range normalises"),
            (Duration::from_secs(10), Duration::from_secs(30))
        );
    }

    #[test]
    fn obfs_selection_follows_the_switch() {
        let mut option = minimal();
        assert!(parse_obfs(&option).expect("no obfs configured").is_none());

        option.obfs = "salamander".to_owned();
        assert_eq!(parse_obfs(&option).expect_err("a missing password").to_string(), "missing obfs password");
        option.obfs_password = "obfs-pw".to_owned();
        assert_eq!(parse_obfs(&option).expect("salamander"), Some(Obfs::Salamander(Arc::from(&b"obfs-pw"[..]))));

        option.obfs = "gecko".to_owned();
        let Some(Obfs::Gecko { min_packet_size, max_packet_size, .. }) = parse_obfs(&option).expect("gecko") else {
            panic!("gecko keeps its kind");
        };
        assert_eq!((min_packet_size, max_packet_size), (512, 1200));

        option.obfs = "nonesuch".to_owned();
        assert_eq!(parse_obfs(&option).expect_err("an unknown kind").to_string(), "unknown obfs type: nonesuch");
    }

    #[test]
    fn a_ports_list_carries_the_configuration_without_a_port() {
        let mut option = minimal();
        option.port = 0;
        let err = Hysteria2::new(option.clone()).expect_err("no port at all");
        assert_eq!(err.to_string(), "invalid port");

        option.ports = "200-202".to_owned();
        option.hop_interval = "10-20".to_owned();
        let adapter = Hysteria2::new(option).expect("a ports list is enough");
        assert_eq!(adapter.type_(), AdapterType::HYSTERIA2);
        assert_eq!(adapter.addr(), "127.0.0.1:0");
        assert!(adapter.support_udp());
    }

    /// The client rejects the pair outright, since both choose the dial address.
    #[test]
    fn a_realm_config_rejects_port_hopping() {
        let mut option = minimal();
        option.ports = "200-202".to_owned();
        option.realm_opts.enable = true;
        option.realm_opts.server_url = "https://realm.example.com".to_owned();
        let err = Hysteria2::new(option).expect_err("realm and hopping are exclusive").to_string();
        assert_eq!(err, "realm and port hopping are mutually exclusive");
    }

    #[test]
    fn a_realm_config_requires_a_control_server_url() {
        let mut option = minimal();
        option.realm_opts.enable = true;
        let err = Hysteria2::new(option).expect_err("no control plane to ask").to_string();
        assert_eq!(err, "create control client: control server URL is required");
    }

    /// The whole realm block is gated on `enable`, so an unused `realm-opts` stays inert.
    #[test]
    fn a_disabled_realm_is_not_validated() {
        let mut option = minimal();
        option.realm_opts.server_url = "not-a-url".to_owned();
        let adapter = Hysteria2::new(option).expect("a disabled realm is left alone");
        assert_eq!(adapter.type_(), AdapterType::HYSTERIA2);
    }

    /// The server half of the round trip: `transport_hysteria2`'s own `Service`, fed a rustls
    /// config with the `h3` ALPN the client's default offers.
    fn server_tls() -> Arc<rustls::ServerConfig> {
        let (cert_pem, key_pem, _) = new_random_tls_key_pair(KeyPairType::P256).expect("generate a test key pair");
        let certificate = tls_c::Certificate {
            certificate: vec![pem_section(&cert_pem, "CERTIFICATE")],
            private_key: Some(PrivateKeyDer::Pkcs8(pem_section(&key_pem, "PRIVATE KEY").into())),
            ..Default::default()
        };
        let config = tls_c::Config {
            min_version: tls_c::VERSION_TLS13,
            next_protos: vec![DEFAULT_ALPN.to_owned()],
            get_certificate: Some(Arc::new(move |_info: &tls_c::ClientHelloInfo| Ok(Some(certificate.clone())))),
            ..Default::default()
        };
        Arc::new(tls_c::server_rustls_config(&config).expect("build the server rustls config"))
    }

    fn pem_section(pem: &str, label: &str) -> Vec<u8> {
        ca::config::pem_sections(pem.as_bytes())
            .into_iter()
            .find(|(section, _, _)| section == label)
            .map(|(_, der, _)| der)
            .unwrap_or_else(|| panic!("no {label} section in the generated PEM"))
    }

    async fn start_server(handler: Arc<dyn ServerHandler>, obfs: Option<Obfs>) -> (u16, Arc<Service>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind the server socket");
        let port = socket.local_addr().expect("the server socket's address").port();
        let packet_conn: Arc<dyn NetPacketConn> = Arc::new(socket);
        (port, start_server_on(packet_conn, handler, obfs))
    }

    fn start_server_on(
        packet_conn: Arc<dyn NetPacketConn>,
        handler: Arc<dyn ServerHandler>,
        obfs: Option<Obfs>,
    ) -> Arc<Service> {
        let service = Service::new(ServiceOptions {
            send_bps: 0,
            receive_bps: 0,
            ignore_client_bandwidth: false,
            obfs,
            tls: server_tls(),
            // The service enables datagrams unless UDP is disabled.
            quic: QuicConfig { enable_datagrams: true, ..QuicConfig::default() },
            udp_disabled: false,
            congestion: CongestionOption::default(),
            udp_mtu: 0,
            handler,
            masquerade: None,
        });
        service.update_users(vec!["test-user".to_owned()], vec![PASSWORD.to_owned()]);
        service.start(packet_conn).expect("start the hysteria2 server");
        service
    }

    #[derive(Default)]
    struct EchoHandler {
        echoed: SyncMutex<Vec<u8>>,
        requested: SyncMutex<Option<String>>,
    }

    #[async_trait]
    impl ServerHandler for EchoHandler {
        async fn new_connection(
            &self,
            _source: Socksaddr,
            destination: Socksaddr,
            mut conn: Box<dyn NetConn>,
        ) -> Result<()> {
            *self.requested.lock() = Some(destination.string());
            let mut buf = vec![0u8; PAYLOAD.len()];
            conn.read_exact(&mut buf).await?;
            self.echoed.lock().extend_from_slice(&buf);
            conn.write_all(&buf).await?;
            Ok(())
        }

        async fn new_packet_connection(
            &self,
            _source: Socksaddr,
            _destination: Socksaddr,
            _conn: Box<dyn NetPacketConn>,
        ) -> Result<()> {
            Ok(())
        }
    }

    async fn echo_round_trip(option: Hysteria2Option) -> (Arc<EchoHandler>, Vec<u8>) {
        let handler = Arc::new(EchoHandler::default());
        let obfs_password = option.obfs_password.clone();
        let obfs = if option.obfs.is_empty() {
            None
        } else {
            Some(Obfs::new(&option.obfs, &obfs_password, 0, 0).expect("build the server's obfs"))
        };
        let concrete = Arc::clone(&handler);
        let server_handler: Arc<dyn ServerHandler> = concrete;
        let (port, _service) = start_server(server_handler, obfs).await;

        let adapter = Hysteria2::new(Hysteria2Option { port: i32::from(port), ..option }).expect("build the outbound");
        let ctx = CancellationToken::new();
        let mut metadata = Metadata { host: "example.com".to_owned(), dst_port: 80, ..Default::default() };
        let mut conn = tokio::time::timeout(TIMEOUT, adapter.dial_context(&ctx, &mut metadata))
            .await
            .expect("the dial completes in time")
            .expect("the dial reaches the server");

        conn.write_all(PAYLOAD).await.expect("write the payload");
        conn.flush().await.expect("flush the payload");
        let mut buf = vec![0u8; PAYLOAD.len()];
        tokio::time::timeout(TIMEOUT, conn.read_exact(&mut buf))
            .await
            .expect("the echo arrives in time")
            .expect("read the echo");
        (handler, buf)
    }

    #[tokio::test]
    async fn dial_context_carries_a_payload_against_a_real_server() {
        let (handler, echo) = echo_round_trip(minimal()).await;
        assert_eq!(echo, PAYLOAD, "the tunnel carries the payload back");
        assert_eq!(&*handler.echoed.lock(), PAYLOAD, "the server received the payload");
        assert_eq!(handler.requested.lock().as_deref(), Some("example.com:80"), "the server saw the address");
    }

    #[tokio::test]
    async fn salamander_matches_between_the_adapter_and_the_server() {
        let option = Hysteria2Option {
            obfs: "salamander".to_owned(),
            obfs_password: "obfs-shared-secret".to_owned(),
            ..minimal()
        };
        let (handler, echo) = echo_round_trip(option).await;
        assert_eq!(echo, PAYLOAD, "the obfuscated tunnel carries the payload back");
        assert_eq!(&*handler.echoed.lock(), PAYLOAD, "the server received the payload");
    }

    #[tokio::test]
    async fn a_wrong_password_is_refused_by_the_server() {
        let handler: Arc<dyn ServerHandler> = Arc::new(EchoHandler::default());
        let (port, _service) = start_server(handler, None).await;
        let option = Hysteria2Option { port: i32::from(port), password: "not-the-password".to_owned(), ..minimal() };
        let adapter = Hysteria2::new(option).expect("build the outbound");

        let ctx = CancellationToken::new();
        let mut metadata = Metadata { host: "example.com".to_owned(), dst_port: 80, ..Default::default() };
        let err = tokio::time::timeout(TIMEOUT, adapter.dial_context(&ctx, &mut metadata))
            .await
            .expect("the dial finishes in time")
            .err()
            .expect("the server refuses an unknown password");
        assert!(err.to_string().contains("authentication failed"), "{err}");
    }

    struct UdpHandler {
        sender: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        destination: SyncMutex<Option<String>>,
    }

    #[async_trait]
    impl ServerHandler for UdpHandler {
        async fn new_connection(
            &self,
            _source: Socksaddr,
            _destination: Socksaddr,
            _conn: Box<dyn NetConn>,
        ) -> Result<()> {
            Ok(())
        }

        async fn new_packet_connection(
            &self,
            _source: Socksaddr,
            destination: Socksaddr,
            conn: Box<dyn NetPacketConn>,
        ) -> Result<()> {
            *self.destination.lock() = Some(destination.string());
            let sender = self.sender.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                if let Ok((len, _)) = conn.read_from(&mut buf).await {
                    let _ = sender.send(buf[..len].to_vec());
                }
            });
            Ok(())
        }
    }

    #[tokio::test]
    async fn listen_packet_context_relays_a_datagram() {
        let (sender, mut received) = tokio::sync::mpsc::unbounded_channel();
        let handler = Arc::new(UdpHandler { sender, destination: SyncMutex::new(None) });
        let concrete = Arc::clone(&handler);
        let server_handler: Arc<dyn ServerHandler> = concrete;
        let (port, _service) = start_server(server_handler, None).await;

        let adapter =
            Hysteria2::new(Hysteria2Option { port: i32::from(port), ..minimal() }).expect("build the outbound");
        let ctx = CancellationToken::new();
        let mut metadata = Metadata {
            network: NetWork::UDP,
            host: "127.0.0.1".to_owned(),
            dst_port: 9999,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ..Default::default()
        };
        let pc = tokio::time::timeout(TIMEOUT, adapter.listen_packet_context(&ctx, &mut metadata))
            .await
            .expect("the relay opens in time")
            .expect("open the udp relay");

        let target = UdpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let sent = pc.write_to(PAYLOAD, &target).await.expect("send the datagram");
        assert_eq!(sent, PAYLOAD.len());

        let datagram = tokio::time::timeout(TIMEOUT, received.recv())
            .await
            .expect("the datagram arrives in time")
            .expect("the server's udp handler saw a datagram");
        assert_eq!(datagram, PAYLOAD, "the relay carries the datagram");
        assert_eq!(handler.destination.lock().as_deref(), Some("127.0.0.1:9999"));
    }

    const REALM_TOKEN: &str = "realm-token";
    const REALM_ID: &str = "realm";

    #[derive(Clone)]
    struct ControlRequest {
        method: String,
        path: String,
        authorization: String,
        body: serde_json::Value,
    }

    struct ConnectPunch {
        client_addresses: Vec<SocketAddr>,
        nonce: String,
        obfs: String,
    }

    struct RealmHarness {
        control_port: u16,
        stun_port: u16,
        peer_port: u16,
        requests: Arc<SyncMutex<Vec<ControlRequest>>>,
    }

    /// As the punch packet conn on a registered server: punch and STUN datagrams leave the
    /// service's socket, everything else reaches it. Here the test answers the punch itself, so no
    /// hysteria2 server realm support is needed to drive the client.
    struct PunchDemux {
        inner: Arc<dyn NetPacketConn>,
        metadata: Arc<SyncMutex<Option<realm::PunchMetadata>>>,
        punches: tokio::sync::mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    }

    #[async_trait]
    impl NetPacketConn for PunchDemux {
        async fn read_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, Box<dyn murmur_std_compat::net::Addr>)> {
            loop {
                let (n, addr) = self.inner.read_from(buf).await?;
                let Some(metadata) = *self.metadata.lock() else { return Ok((n, addr)) };
                if realm::decode_packet(&buf[..n], &metadata).is_err() {
                    return Ok((n, addr));
                }
                if let Ok(from) = old_addr_to_socket_addr(addr.as_ref()) {
                    let _ = self.punches.send((buf[..n].to_vec(), from));
                }
            }
        }

        async fn write_to(&self, buf: &[u8], addr: &dyn murmur_std_compat::net::Addr) -> std::io::Result<usize> {
            self.inner.write_to(buf, addr).await
        }

        fn local_addr(&self) -> std::io::Result<Box<dyn murmur_std_compat::net::Addr>> {
            self.inner.local_addr()
        }

        fn close(&self) -> std::io::Result<()> {
            self.inner.close()
        }
    }

    async fn start_realm_harness(
        handler: Arc<dyn ServerHandler>,
    ) -> (RealmHarness, Arc<Service>, Arc<dyn NetPacketConn>) {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind the peer socket"));
        let peer = socket.local_addr().expect("the peer's address");
        let peer_conn = Arc::clone(&socket);
        let peer_conn: Arc<dyn NetPacketConn> = peer_conn;
        let (punch_tx, punch_rx) = tokio::sync::mpsc::unbounded_channel();
        let metadata = Arc::new(SyncMutex::new(None));
        let demux: Arc<dyn NetPacketConn> =
            Arc::new(PunchDemux { inner: Arc::clone(&peer_conn), metadata: Arc::clone(&metadata), punches: punch_tx });
        let service = start_server_on(Arc::clone(&demux), handler, None);
        let stun_port = start_stun_server().await;
        let (punch_notify, punch_notified) = tokio::sync::mpsc::unbounded_channel();
        let (control_port, requests) = start_control_plane(peer, punch_notify).await;
        tokio::spawn(answer_punch(peer_conn, metadata, punch_notified, punch_rx));
        let harness = RealmHarness { control_port, stun_port, peer_port: peer.port(), requests };
        (harness, service, demux)
    }

    fn realm_option(harness: &RealmHarness) -> Hysteria2Option {
        Hysteria2Option {
            port: i32::from(harness.peer_port),
            realm_opts: Hysteria2RealmOption {
                enable: true,
                server_url: format!("http://127.0.0.1:{}", harness.control_port),
                token: REALM_TOKEN.to_owned(),
                realm_id: REALM_ID.to_owned(),
                stun_servers: vec![format!("127.0.0.1:{}", harness.stun_port)],
                ..Default::default()
            },
            ..minimal()
        }
    }

    /// The server-puncher response, played by the test against the client's hellos.
    async fn answer_punch(
        socket: Arc<dyn NetPacketConn>,
        metadata: Arc<SyncMutex<Option<realm::PunchMetadata>>>,
        mut notified: tokio::sync::mpsc::UnboundedReceiver<ConnectPunch>,
        mut punches: tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    ) {
        let Some(connect) = notified.recv().await else { return };
        let punch =
            realm::decode_metadata(&connect.nonce, &connect.obfs).expect("the connect body carries the metadata");
        *metadata.lock() = Some(punch);
        let mut hello = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = hello.tick() => {
                    let packet = realm::encode_packet(realm::HELLO, &punch);
                    for address in &connect.client_addresses {
                        let _ = socket.write_to(&packet, &UdpAddr::from(*address)).await;
                    }
                }
                Some((data, from)) = punches.recv() => {
                    if matches!(realm::decode_packet(&data, &punch), Ok(realm::HELLO)) {
                        let packet = realm::encode_packet(realm::ACK, &punch);
                        let _ = socket.write_to(&packet, &UdpAddr::from(from)).await;
                        return;
                    }
                }
            }
        }
    }

    /// The control plane's two client routes: `POST /v1/{id}/connect` with the realm token answers
    /// with the registered peer's address, and its punch notification reaches the peer.
    async fn start_control_plane(
        peer: SocketAddr,
        punches: tokio::sync::mpsc::UnboundedSender<ConnectPunch>,
    ) -> (u16, Arc<SyncMutex<Vec<ControlRequest>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind the fake control plane");
        let port = listener.local_addr().expect("the control plane's address").port();
        let requests = Arc::new(SyncMutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                let recorded = Arc::clone(&recorded);
                let punches = punches.clone();
                tokio::spawn(async move {
                    let Some(request) = read_control_request(&mut stream).await else { return };
                    recorded.lock().push(request.clone());
                    let response = control_response(&request, peer, &punches);
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (port, requests)
    }

    fn control_response(
        request: &ControlRequest,
        peer: SocketAddr,
        punches: &tokio::sync::mpsc::UnboundedSender<ConnectPunch>,
    ) -> String {
        let bad_request = |message: &str| http_body(400, "Bad Request", &error_body("bad_request", message));
        if request.method != "POST" || !request.path.ends_with("/connect") {
            return http_body(404, "Not Found", &error_body("not_found", "unknown path"));
        }
        if request.authorization != format!("Bearer {REALM_TOKEN}") {
            return http_body(401, "Unauthorized", &error_body("invalid_token", "invalid realm token"));
        }
        let Some(raw_addresses) = request.body["addresses"].as_array() else { return bad_request("invalid addresses") };
        let mut client_addresses = Vec::new();
        for address in raw_addresses {
            let Some(address) = address.as_str().and_then(|address| address.parse::<SocketAddr>().ok()) else {
                return bad_request("invalid addresses");
            };
            client_addresses.push(address);
        }
        let nonce = request.body["nonce"].as_str().unwrap_or_default().to_owned();
        let obfs = request.body["obfs"].as_str().unwrap_or_default().to_owned();
        let _ = punches.send(ConnectPunch { client_addresses, nonce: nonce.clone(), obfs: obfs.clone() });
        let body = serde_json::json!({ "addresses": [peer.to_string()], "nonce": nonce, "obfs": obfs }).to_string();
        http_body(200, "OK", &body)
    }

    fn http_body(status: u16, reason: &str, body: &str) -> String {
        let head = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n");
        format!("{head}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    }

    fn error_body(code: &str, message: &str) -> String {
        serde_json::json!({ "error": code, "message": message }).to_string()
    }

    async fn read_control_request(stream: &mut tokio::net::TcpStream) -> Option<ControlRequest> {
        let mut raw = Vec::new();
        let mut chunk = [0u8; 1024];
        let head_end = loop {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                return None;
            }
            raw.extend_from_slice(&chunk[..read]);
            if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
        let mut lines = head.split("\r\n");
        let mut request_line = lines.next()?.split(' ');
        let method = request_line.next()?.to_owned();
        let path = request_line.next()?.to_owned();
        let mut authorization = String::new();
        let mut content_length = 0;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else { continue };
            if name.eq_ignore_ascii_case("authorization") {
                authorization = value.trim().to_owned();
            } else if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = raw[head_end..].to_vec();
        while body.len() < content_length {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        Some(ControlRequest {
            method,
            path,
            authorization,
            body: serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        })
    }

    async fn start_stun_server() -> u16 {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind the fake STUN server");
        let port = socket.local_addr().expect("the STUN server's address").port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            loop {
                let Ok((read, from)) = socket.recv_from(&mut buf).await else { return };
                if let Some(response) = binding_response(&buf[..read], from) {
                    let _ = socket.send_to(&response, from).await;
                }
            }
        });
        port
    }

    /// `internal/stun`'s wire format, encoded from the peer's side: XOR-MAPPED-ADDRESS over the
    /// source address of the binding request.
    fn binding_response(request: &[u8], mapped: SocketAddr) -> Option<Vec<u8>> {
        if request.len() < 20 || request[..2] != [0x00, 0x01] || request[4..8] != [0x21, 0x12, 0xa4, 0x42] {
            return None;
        }
        let transaction_id = &request[8..20];
        let (family, ip) = match mapped.ip() {
            IpAddr::V4(v4) => (0x01u8, v4.octets().to_vec()),
            IpAddr::V6(v6) => (0x02u8, v6.octets().to_vec()),
        };
        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        key[4..].copy_from_slice(transaction_id);
        let mut value = vec![0u8, family];
        value.extend_from_slice(&(mapped.port() ^ 0x2112).to_be_bytes());
        value.extend(ip.iter().enumerate().map(|(i, byte)| byte ^ key[i]));

        let mut response = vec![0u8; 20];
        response[..2].copy_from_slice(&[0x01, 0x01]);
        response[2..4].copy_from_slice(&u16::try_from(value.len() + 4).expect("attribute length").to_be_bytes());
        response[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response[8..].copy_from_slice(transaction_id);
        response.extend_from_slice(&0x0020u16.to_be_bytes());
        response.extend_from_slice(&u16::try_from(value.len()).expect("value length").to_be_bytes());
        response.extend_from_slice(&value);
        Some(response)
    }

    #[tokio::test]
    async fn a_realm_config_dials_through_the_punched_socket() {
        let handler = Arc::new(EchoHandler::default());
        let server_handler = Arc::clone(&handler);
        let server_handler: Arc<dyn ServerHandler> = server_handler;
        let (harness, _service, _demux) = start_realm_harness(server_handler).await;
        let adapter = Hysteria2::new(realm_option(&harness)).expect("build the outbound");

        let ctx = CancellationToken::new();
        let mut metadata = Metadata { host: "example.com".to_owned(), dst_port: 80, ..Default::default() };
        let mut conn = tokio::time::timeout(TIMEOUT, adapter.dial_context(&ctx, &mut metadata))
            .await
            .expect("the realm dial completes in time")
            .expect("the punched socket reaches the server");

        conn.write_all(PAYLOAD).await.expect("write the payload");
        conn.flush().await.expect("flush the payload");
        let mut buf = vec![0u8; PAYLOAD.len()];
        tokio::time::timeout(TIMEOUT, conn.read_exact(&mut buf))
            .await
            .expect("the echo arrives in time")
            .expect("read the echo");
        assert_eq!(buf, PAYLOAD, "the tunnel carries the payload back");
        assert_eq!(&*handler.echoed.lock(), PAYLOAD, "the server received the payload");

        let requests = harness.requests.lock();
        assert_eq!(requests.len(), 1, "one realm connect per dial");
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, format!("/v1/{REALM_ID}/connect"));
        assert_eq!(request.authorization, format!("Bearer {REALM_TOKEN}"));
        let addresses = request.body["addresses"].as_array().expect("the client's STUN addresses");
        assert_eq!(addresses.len(), 1, "the v4 family is the one the fake STUN server answered");
        assert!(addresses[0].as_str().is_some_and(|address| address.starts_with("127.0.0.1:")), "{addresses:?}");
        assert_eq!(request.body["nonce"].as_str().map(str::len), Some(32));
        assert_eq!(request.body["obfs"].as_str().map(str::len), Some(64));
    }

    #[tokio::test]
    async fn a_realm_config_fails_closed_when_the_control_plane_is_unreachable() {
        let stun_port = start_stun_server().await;
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
        let dead_port = reserved.local_addr().expect("the reserved address").port();
        drop(reserved);

        let mut option = minimal();
        option.realm_opts = Hysteria2RealmOption {
            enable: true,
            server_url: format!("http://127.0.0.1:{dead_port}"),
            token: REALM_TOKEN.to_owned(),
            realm_id: REALM_ID.to_owned(),
            stun_servers: vec![format!("127.0.0.1:{stun_port}")],
            ..Default::default()
        };
        let adapter = Hysteria2::new(option).expect("the adapter still builds");

        let ctx = CancellationToken::new();
        let mut metadata = Metadata { host: "example.com".to_owned(), dst_port: 80, ..Default::default() };
        let err = tokio::time::timeout(TIMEOUT, adapter.dial_context(&ctx, &mut metadata))
            .await
            .expect("the dial finishes in time")
            .err()
            .expect("an unreachable control plane fails the dial");
        let message = err.to_string();
        assert!(message.contains("realm connect"), "{message}");
        assert!(message.contains(&format!("http://127.0.0.1:{dead_port}/v1/{REALM_ID}/connect")), "{message}");
    }

    #[tokio::test]
    async fn a_realm_config_without_stun_servers_fails_closed() {
        let mut option = minimal();
        option.realm_opts.enable = true;
        option.realm_opts.server_url = "http://127.0.0.1:1".to_owned();
        let adapter = Hysteria2::new(option).expect("the adapter still builds");

        let ctx = CancellationToken::new();
        let mut metadata = Metadata { host: "example.com".to_owned(), dst_port: 80, ..Default::default() };
        let err = tokio::time::timeout(TIMEOUT, adapter.dial_context(&ctx, &mut metadata))
            .await
            .expect("the dial finishes in time")
            .err()
            .expect("discovery without a STUN server fails the dial");
        assert_eq!(err.to_string(), "resolve STUN servers: no STUN servers resolved");
    }
}
