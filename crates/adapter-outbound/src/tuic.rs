//! The QUIC session comes from `murmur_transport_tuic::quic`, the one `quinn`-backed QUIC mirror
//! that `v4`, `v5`, the pooled client and `common::dial::dial_quic` share.
//!
//! `dial()` follows the same packet-dial path as `hysteria.rs`/`shadowquic.rs`; two of its steps
//! differ from that path only in shape:
//!
//! * The early-dial option (`reduce-rtt`) collapses into `dial`, which is exact parity: the TUIC
//!   client caches no session, so it stores no resumable ticket, and the early dial waits for the
//!   handshake to complete exactly like the plain one.
//! * Congestion control becomes the `CongestionOption` the dial is given, because quinn binds a
//!   controller when the endpoint is built; `bbr-profile` rides in that option.
//!
//! `murmur_sing::uot` provides the destination-request and conn helpers.

use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::ech::ECHOptions;
use murmur_component::dialer::bind::join_host_port;
use murmur_component_ca as ca;
use murmur_component_ech::ech::Config as EchConfig;
use murmur_component_tls::utls as tls_c;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, Dialer as CDialer, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter,
    ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_sing::metadata::Socksaddr;
use murmur_sing::uot;
use murmur_std_compat::net::PacketConn as NetPacketConn;
use murmur_transport_tuic::common::dial::{dial_quic, PacketDialer as TuicPacketDialer};
use murmur_transport_tuic::pool_client::{new_pool_client_v4, new_pool_client_v5, PoolClient};
use murmur_transport_tuic::quic::Conn as QuicConn;
use murmur_transport_tuic::quic::{self as tuic_quic, ClientTls, Config as QuicConfig, CongestionOption, Profile};
use murmur_transport_tuic::tuic::{
    gen_tkn, ClientOptionV4, ClientOptionV5, UdpRelayMode, DEFAULT_CONNECTION_RECEIVE_WINDOW,
    DEFAULT_STREAM_RECEIVE_WINDOW, MAX_FRAG_SIZE_V5, NATIVE, PACKET_OVER_HEAD_V4, PACKET_OVER_HEAD_V5,
    QUIC as TUIC_QUIC,
};
use murmur_transport_tuic::types::type_::DialFunc;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::util::resolve_udp_addr;

/// The dial's congestion option, built from the controller name, `cwnd` and `bbr-profile`.
fn congestion_option(option: &TuicOption) -> CongestionOption {
    CongestionOption {
        name: option.congestion_controller.clone(),
        cwnd: option.cwnd,
        profile: Profile::from(option.bbr_profile.as_str()),
    }
}

pub struct Tuic {
    self_weak: Weak<Self>,
    base: Base,
    option: TuicOption,
    client: Arc<PoolClient>,

    quic_config: Arc<QuicConfig>,
    tls_config: Arc<tls_c::Config>,
    #[allow(dead_code, reason = "ECHOpts is parsed into echConfig and never read back")]
    ech_config: Option<Arc<EchConfig>>,
}

impl std::fmt::Debug for Tuic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tuic").field("name", &self.base.name()).finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools, reason = "the option struct mirrors the protocol's flag set field for field")]
pub struct TuicOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port", default)]
    pub port: i32,
    #[serde(rename = "token", default)]
    pub token: String,
    #[serde(rename = "uuid", default)]
    pub uuid: String,
    #[serde(rename = "password", default)]
    pub password: String,
    #[serde(rename = "ip", default)]
    pub ip: String,
    #[serde(rename = "heartbeat-interval", default)]
    pub heartbeat_interval: i32,
    #[serde(rename = "alpn", default)]
    pub alpn: Option<Vec<String>>,
    /// The `reduce-rtt` flag. Early dialing can never return before the handshake in the TUIC
    /// client (see the module note), so the flag is parsed but not routed further.
    #[serde(rename = "reduce-rtt", default)]
    pub reduce_rtt: bool,
    #[serde(rename = "request-timeout", default)]
    pub request_timeout: i32,
    #[serde(rename = "udp-relay-mode", default)]
    pub udp_relay_mode: String,
    #[serde(rename = "congestion-controller", default)]
    pub congestion_controller: String,
    #[serde(rename = "disable-sni", default)]
    pub disable_sni: bool,
    #[serde(rename = "max-udp-relay-packet-size", default)]
    pub max_udp_relay_packet_size: i32,

    #[serde(rename = "fast-open", default)]
    pub fast_open: bool,
    #[serde(rename = "max-open-streams", default)]
    pub max_open_streams: i32,
    #[serde(rename = "cwnd", default)]
    pub cwnd: i32,
    /// `bbr-profile`, read only when the congestion controller is `bbr` or `bbr_meta_v2`.
    #[serde(rename = "bbr-profile", default)]
    pub bbr_profile: String,
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
    #[serde(rename = "recv-window-conn", default)]
    pub receive_window_conn: i32,
    #[serde(rename = "recv-window", default)]
    pub receive_window: i32,
    #[serde(rename = "disable-mtu-discovery", default)]
    pub disable_mtu_discovery: bool,
    #[serde(rename = "max-datagram-frame-size", default)]
    pub max_datagram_frame_size: i32,
    #[serde(rename = "sni", default)]
    pub sni: String,
    #[serde(rename = "ech-opts", default)]
    pub ech_opts: ECHOptions,

    #[serde(rename = "udp-over-stream", default)]
    pub udp_over_stream: bool,
    #[serde(rename = "udp-over-stream-version", default)]
    pub udp_over_stream_version: i32,
}

impl std::fmt::Debug for TuicOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("token", &"<redacted>")
            .field("password", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// The packet dialer, over the outbound's real dialer.
struct RealPacketDialer {
    dialer: Arc<dyn CDialer>,
}

#[async_trait]
impl TuicPacketDialer for RealPacketDialer {
    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
        r_addr_port: SocketAddr,
    ) -> Result<Box<dyn NetPacketConn>> {
        let pc = self.dialer.listen_packet(ctx, network, address, Some(r_addr_port)).await?;
        // S11: remove with std-compat (murmur_transport_tuic::common::dial::PacketDialer still murmur_std_compat::net::PacketConn based)
        Ok(Box::new(murmur_common_net::io::DatagramAsOldPacketConn(pc)))
    }
}

/// The dial callback handed to the pool client. The closure keeps only a `Weak`, so the pool
/// it feeds can live inside the adapter without a reference cycle.
fn tuic_dial_fn(self_weak: &Weak<Tuic>) -> DialFunc {
    let self_weak = Weak::clone(self_weak);
    Arc::new(move |ctx: CancellationToken| {
        let self_weak = Weak::clone(&self_weak);
        Box::pin(async move {
            let tuic = self_weak.upgrade().ok_or_else(|| anyhow!("Tuic: adapter dropped while still in use"))?;
            tuic.dial(&ctx).await
        })
    })
}

/// `disable-sni` empties the server name and turns verification off. `rustls` still needs a name
/// to build a ClientHello, and it puts no SNI on the wire for a literal IP, so the resolved peer
/// stands in for the emptied name.
fn quic_server_name(server_name: &str, remote: SocketAddr) -> String {
    if server_name.is_empty() {
        remote.ip().to_string()
    } else {
        server_name.to_owned()
    }
}

/// The client TLS config: the `sni` override, then the ALPN list.
fn client_tls_config(option: &TuicOption) -> Result<tls_c::Config> {
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
        tls_config.next_protos = vec!["h3".to_owned()];
    }
    Ok(tls_config)
}

/// Applies the zero-value defaults and the datagram-size arithmetic to the option.
fn normalize_option(option: &mut TuicOption) -> Result<()> {
    if option.request_timeout == 0 {
        option.request_timeout = 8000;
    }
    if option.heartbeat_interval <= 0 {
        option.heartbeat_interval = 10000;
    }
    if option.max_udp_relay_packet_size == 0 {
        option.max_udp_relay_packet_size = 1252;
    }
    if option.max_open_streams == 0 {
        option.max_open_streams = 100;
    }
    if option.cwnd == 0 {
        option.cwnd = 32;
    }

    let overhead = if option.token.is_empty() { *PACKET_OVER_HEAD_V5 } else { *PACKET_OVER_HEAD_V4 };
    let packet_over_head =
        i32::try_from(overhead).map_err(|_| anyhow!("tuic: packet overhead {overhead} does not fit an i32"))?;

    if option.max_datagram_frame_size == 0 {
        option.max_datagram_frame_size = option.max_udp_relay_packet_size + packet_over_head;
    }
    if option.max_datagram_frame_size > 1400 {
        option.max_datagram_frame_size = 1400;
    }
    option.max_udp_relay_packet_size = option.max_datagram_frame_size - packet_over_head;
    Ok(())
}

/// `ceil(value / 10)` for both signs; the signed `div_ceil` is still unstable (`int_roundings`).
fn ceil_div_10(value: i64) -> i64 {
    value.div_euclid(10) + i64::from(value.rem_euclid(10) != 0)
}

/// The `quinn::Config` the dial is built on, with the receive windows and keep-alive it carries.
fn build_quic_config(option: &TuicOption) -> Result<QuicConfig> {
    let max_open_streams = i64::from(option.max_open_streams);
    let quic_max_open_streams = max_open_streams + ceil_div_10(max_open_streams);
    let receive_window_conn = u64::from(option.receive_window_conn.max(0).cast_unsigned());
    let receive_window = u64::from(option.receive_window.max(0).cast_unsigned());

    let mut config = QuicConfig {
        initial_stream_receive_window: receive_window_conn,
        max_stream_receive_window: receive_window_conn,
        initial_connection_receive_window: receive_window,
        max_connection_receive_window: receive_window,
        max_incoming_streams: quic_max_open_streams,
        max_incoming_uni_streams: quic_max_open_streams,
        keep_alive_period: Duration::from_millis(u64::from(option.heartbeat_interval.max(0).cast_unsigned())),
        disable_path_mtu_discovery: option.disable_mtu_discovery,
        max_datagram_frame_size: i64::from(option.max_datagram_frame_size),
        enable_datagrams: true,
        ..QuicConfig::default()
    };
    if option.receive_window_conn == 0 {
        config.initial_stream_receive_window = u64::try_from(DEFAULT_STREAM_RECEIVE_WINDOW / 10)?;
        config.max_stream_receive_window = u64::try_from(DEFAULT_STREAM_RECEIVE_WINDOW)?;
    }
    if option.receive_window == 0 {
        config.initial_connection_receive_window = u64::try_from(DEFAULT_CONNECTION_RECEIVE_WINDOW / 10)?;
        config.max_connection_receive_window = u64::try_from(DEFAULT_CONNECTION_RECEIVE_WINDOW)?;
    }
    Ok(config)
}

/// The client-side stream cap, held just under the connection-wide one.
fn effective_max_open_streams(option: &TuicOption) -> i64 {
    let max_open_streams = i64::from(option.max_open_streams);
    let adjusted =
        if max_open_streams == 100 { max_open_streams - ceil_div_10(max_open_streams) } else { max_open_streams };
    adjusted.max(1)
}

/// The pooled client every stream is handed to: v5 when no token is set, v4 otherwise.
fn build_client(
    option: &TuicOption,
    udp_relay_mode: UdpRelayMode,
    max_open_streams: i64,
    max_udp_relay_packet_size: usize,
    dial: DialFunc,
) -> Arc<PoolClient> {
    if option.token.is_empty() {
        let client_option = ClientOptionV5 {
            uuid: uuid::Uuid::parse_str(&option.uuid).unwrap_or_else(|_| uuid::Uuid::nil()).into_bytes(),
            password: option.password.clone(),
            udp_relay_mode,
            max_udp_relay_packet_size: max_udp_relay_packet_size.min(*MAX_FRAG_SIZE_V5),
            max_open_streams,
        };
        new_pool_client_v5(&client_option, dial)
    } else {
        let client_option = ClientOptionV4 {
            token: gen_tkn(&option.token),
            udp_relay_mode,
            request_timeout: Duration::from_millis(u64::from(option.request_timeout.max(0).cast_unsigned())),
            max_udp_relay_packet_size,
            fast_open: option.fast_open,
            max_open_streams,
        };
        new_pool_client_v4(&client_option, dial)
    }
}

impl Tuic {
    pub fn new(mut option: TuicOption) -> Result<Arc<Self>> {
        let configured_port = option.port;
        let port =
            u16::try_from(configured_port).map_err(|_| anyhow!("tuic: port {configured_port} is out of range"))?;
        let mut addr = join_host_port(&option.server, port);
        let mut tls_config = client_tls_config(&option)?;
        normalize_option(&mut option)?;

        let udp_relay_mode = if option.udp_relay_mode == "quic" { TUIC_QUIC } else { NATIVE };
        let quic_config = build_quic_config(&option)?;

        if !option.ip.is_empty() {
            addr = join_host_port(&option.ip, port);
        }
        if option.disable_sni {
            tls_config.server_name = String::new();
            tls_config.insecure_skip_verify = true;
        }

        let ech_config = option.ech_opts.parse()?.map(Arc::new);

        match option.udp_over_stream_version {
            v if v == i32::from(uot::VERSION) || v == i32::from(uot::LEGACY_VERSION) => {}
            0 => option.udp_over_stream_version = i32::from(uot::LEGACY_VERSION),
            other => return Err(anyhow!("tuic {addr} unknown udp over stream protocol version: {other}")),
        }

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr,
            type_: AdapterType::TUIC,
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

        let max_open_streams = effective_max_open_streams(&option);
        let max_udp_relay_packet_size = usize::try_from(option.max_udp_relay_packet_size.max(0))?;
        let quic_config = Arc::new(tuic_quic::effective_config(quic_config));
        Ok(Arc::new_cyclic(|self_weak| {
            let dial = tuic_dial_fn(self_weak);
            let client = build_client(&option, udp_relay_mode, max_open_streams, max_udp_relay_packet_size, dial);

            Self {
                self_weak: Weak::clone(self_weak),
                base,
                option,
                client,
                quic_config,
                tls_config: Arc::new(tls_config),
                ech_config,
            }
        }))
    }

    async fn dial(&self, ctx: &CancellationToken) -> Result<Arc<dyn QuicConn>> {
        let addr = self.base.addr();
        let remote = SocketAddr::try_from(&resolve_udp_addr(ctx, "udp", &addr, self.base.prefer).await?)?;
        let p_dialer: Arc<dyn TuicPacketDialer> = Arc::new(RealPacketDialer {
            dialer: self.base.dialer.clone().ok_or_else(|| anyhow!("tuic {addr}: no dialer configured"))?,
        });
        let tls = Arc::new(ClientTls {
            config: Arc::new(tls_c::client_rustls_config(&self.tls_config)?),
            server_name: quic_server_name(&self.tls_config.server_name, remote),
        });
        // `dial_quic` takes the resolved peer separately from the address its dialer is handed, so
        // every DNS answer this session is built on comes from the one lookup above.
        let (_, quic_conn) = dial_quic(
            ctx,
            &remote.to_string(),
            self.base.dial_options(),
            p_dialer,
            remote,
            tls,
            Arc::clone(&self.quic_config),
            congestion_option(&self.option),
        )
        .await?;
        Ok(quic_conn)
    }
    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("Tuic: adapter dropped while still in use"))
    }
}

#[async_trait]
impl CProxyAdapter for Tuic {
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
        let conn = self.client.dial_context(ctx, metadata).await?;
        // S11: remove with std-compat (transport-tuic::pool_client::PoolClient::dial_context still returns old murmur_std_compat::net::Conn)
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(conn)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.resolve_udp(ctx, metadata).await?;

        if self.option.udp_over_stream {
            let version = self.option.udp_over_stream_version;
            let version = u8::try_from(version)
                .map_err(|_| anyhow!("tuic: udp over stream version {version} is out of range"))?;
            let uot_destination = uot::request_destination(version);
            let mut uot_metadata = metadata.clone();
            uot_metadata.host = uot_destination.fqdn.clone();
            uot_metadata.dst_port = uot_destination.port;
            let c = self.dial_context(ctx, &mut uot_metadata).await?;
            // S11: remove with std-compat (murmur_sing::uot::new_conn/new_lazy_conn still old murmur_std_compat::net::Conn based)
            let c: Box<dyn murmur_std_compat::net::Conn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(c));

            let destination =
                metadata.udp_addr().map(|addr| Socksaddr::from_ip(addr.ip, addr.port)).unwrap_or_default();
            let request = uot::Request { is_connect: false, destination };
            let pc: Arc<dyn NetPacketConn> = if self.option.udp_over_stream_version == i32::from(uot::LEGACY_VERSION) {
                Arc::new(uot::new_conn(c, request))
            } else {
                Arc::new(uot::new_lazy_conn(c, request))
            };
            // S11: remove with std-compat (murmur_sing::uot still old murmur_std_compat::net::PacketConn based)
            return Ok(new_packet_conn(super::base::arc_packet_conn_as_datagram(pc), self.self_arc()?));
        }

        let pc = self.client.listen_packet(ctx, metadata).await?;
        let pc = pc.into_packet_conn();
        // S11: remove with std-compat (common_net::EnhancePacketConn::into_packet_conn still old murmur_std_compat::net::PacketConn based)
        Ok(new_packet_conn(super::base::arc_packet_conn_as_datagram(pc), self.self_arc()?))
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
        self.base.close()
    }
}

#[async_trait]
impl ProxyAdapter for Tuic {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use murmur_component_ca::keypair::{new_random_tls_key_pair, KeyPairType};
    use murmur_transport_tuic::server::{new_server, HandleTcpFn, HandleUdpFn, ServerOption};
    use rustls::pki_types::PrivateKeyDer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const UUID: &str = "ae5f84f6-2f16-4b1f-9f4f-2a2b4c6d8e0f";
    const PASSWORD: &str = "test-password";
    const PAYLOAD: &[u8] = b"tuic-over-quic";
    const TIMEOUT: Duration = Duration::from_secs(20);

    fn pem_section(pem: &str, label: &str) -> Vec<u8> {
        ca::config::pem_sections(pem.as_bytes())
            .into_iter()
            .find(|(section, _, _)| section == label)
            .map(|(_, der, _)| der)
            .unwrap_or_else(|| panic!("no {label} section in the generated PEM"))
    }

    /// The server half of the round trip: `transport_tuic`'s own listener, fed the rustls config
    /// `server_rustls_config` derives from a TLS-config-shaped struct.
    fn server_tls() -> Arc<tuic_quic::ServerTls> {
        let (cert_pem, key_pem, _) = new_random_tls_key_pair(KeyPairType::P256).expect("generate a test key pair");
        let certificate = tls_c::Certificate {
            certificate: vec![pem_section(&cert_pem, "CERTIFICATE")],
            private_key: Some(PrivateKeyDer::Pkcs8(pem_section(&key_pem, "PRIVATE KEY").into())),
            ..Default::default()
        };
        let config = tls_c::Config {
            min_version: tls_c::VERSION_TLS13,
            next_protos: vec!["h3".to_owned()],
            get_certificate: Some(Arc::new(move |_info: &tls_c::ClientHelloInfo| Ok(Some(certificate.clone())))),
            ..Default::default()
        };
        Arc::new(tuic_quic::ServerTls {
            config: Arc::new(tls_c::server_rustls_config(&config).expect("build the server rustls config")),
        })
    }

    /// The dial option carries the parsed `bbr-profile`; the YAML spelling is `bbr-profile`, so a
    /// dropped `serde(rename)` would silently disable the knob again.
    #[test]
    fn the_dial_option_carries_the_configured_bbr_profile() {
        let parsed: TuicOption = serde_json::from_str(
            r#"{"name":"tuic-test","server":"example.com","congestion-controller":"bbr","cwnd":16,"bbr-profile":"aggressive"}"#,
        )
        .expect("the adapter option parses");

        let congestion = congestion_option(&parsed);
        assert_eq!(congestion.name, "bbr");
        assert_eq!(congestion.cwnd, 16);
        assert_eq!(congestion.profile, Profile::ProfileAggressive);

        assert_eq!(congestion_option(&TuicOption::default()).profile, Profile::ProfileStandard);
    }

    /// The adapter's `dial()` has to reach a real TUIC server: the v5 credentials cross the QUIC
    /// session, `handle_tcp_fn` sees the requested address, and the tunnel carries a payload in
    /// both directions.
    #[tokio::test]
    async fn dial_context_completes_against_a_real_server() {
        let echoed: Arc<parking_lot::Mutex<Vec<u8>>> = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let requested: Arc<parking_lot::Mutex<Option<String>>> = Arc::new(parking_lot::Mutex::new(None));
        let handle_tcp_fn: HandleTcpFn = {
            let echoed = Arc::clone(&echoed);
            let requested = Arc::clone(&requested);
            Arc::new(move |mut conn, addr, _additions| {
                *requested.lock() = Some(addr.string());
                let echoed = Arc::clone(&echoed);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; PAYLOAD.len()];
                    if conn.read_exact(&mut buf).await.is_ok() {
                        echoed.lock().extend_from_slice(&buf);
                        let _ = conn.write_all(&buf).await;
                    }
                });
                Ok(())
            })
        };
        let handle_udp_fn: HandleUdpFn = Arc::new(|_addr, _packet, _additions| Ok(()));

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind the server socket");
        let port = socket.local_addr().expect("the server socket's address").port();
        let packet_conn: Arc<dyn NetPacketConn> = Arc::new(socket);
        let server = Arc::new(
            new_server(
                Arc::new(ServerOption {
                    handle_tcp_fn,
                    handle_udp_fn,
                    tls_config: server_tls(),
                    quic_config: Arc::new(tuic_quic::effective_config(QuicConfig {
                        enable_datagrams: true,
                        max_datagram_frame_size: 1400,
                        ..QuicConfig::default()
                    })),
                    tokens: Vec::new(),
                    users: HashMap::from([(
                        uuid::Uuid::parse_str(UUID).expect("the test UUID parses").into_bytes(),
                        PASSWORD.to_owned(),
                    )]),
                    congestion_controller: "bbr".to_owned(),
                    authentication_timeout: Duration::from_secs(5),
                    max_udp_relay_packet_size: 1400,
                    cwnd: 32,
                    bbr_profile: String::new(),
                }),
                packet_conn,
            )
            .expect("start the TUIC server"),
        );
        tokio::spawn(async move {
            let _ = server.serve().await;
        });

        let client = Tuic::new(TuicOption {
            name: "tuic-test".to_owned(),
            server: "127.0.0.1".to_owned(),
            port: i32::from(port),
            uuid: UUID.to_owned(),
            password: PASSWORD.to_owned(),
            skip_cert_verify: true,
            ..Default::default()
        })
        .expect("build the outbound");

        let ctx = CancellationToken::new();
        let mut metadata = Metadata { host: "example.com".to_owned(), dst_port: 80, ..Default::default() };
        let mut conn = tokio::time::timeout(TIMEOUT, client.dial_context(&ctx, &mut metadata))
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
        assert_eq!(&buf[..], PAYLOAD, "the tunnel carries the payload back");
        assert_eq!(&*echoed.lock(), PAYLOAD, "the server received the payload");
        assert_eq!(requested.lock().as_deref(), Some("example.com:80"), "the server saw the requested address");
    }
}
