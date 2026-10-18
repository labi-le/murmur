//! Design choices forced by the trait shapes already landed in other units (see the wave report
//! for the full list):
//! * `self_weak: Weak<Vless>` + `Arc::new_cyclic` gives `listen_packet_context` the `Arc<dyn
//!   base::ProxyAdapter>` that `base::new_packet_conn` retains for `resolve_udp`; `dial_context`
//!   needs no such handle since `base::new_conn` only borrows the adapter.
//! * The TLS material the stream-TLS helper and the `grpc`/`xhttp` dial closures need is pulled
//!   out of `&self` into an owned [`TlsMaterial`] snapshot so the `gun`/`xhttp` transport-maker
//!   closures (built once at construction, called later, possibly concurrently) can carry it
//!   without a self-reference.
//! * `transport::vless::Client::stream_conn` evaluates Vision's TLS capability from the
//!   [`TlsConn`](murmur_component_tls::utls::TlsConn) the TLS layer returns, and for the plain
//!   `tcp` network (the documented Vision transport) also hands it the raw transport below TLS
//!   plus a handle that drains the TLS conn's buffered incoming plaintext at the direct-mode
//!   switch. The `ws`/`http`/`h2`/`grpc`/`xhttp` networks build their conn around the TLS session
//!   and never evaluate its capability, and ShadowTLS/Restls/JLS replace the TLS session with an
//!   erased conn, so `Vless::new` rejects an `xtls-rprx-vision` configuration on those shapes
//!   without VLESS encryption instead of accepting it and failing every dial. With encryption,
//!   Vision wraps the encryption conn and runs padding-only, matching the reference's
//!   `*encryption.CommonConn` case, so the transport restriction does not apply.
//! * `xhttp`'s HTTP/3 download branch needs a raw `quinn::Connection`, not the `transport::tuic`
//!   `murmur_quic`-mirror abstraction (`transport::tuic::common::dial_quic` returns `Arc<dyn
//!   murmur_quic-shaped Conn>`, incompatible with `xhttp::client::DialQuicFunc`). This adapter
//!   dials QUIC directly with `quinn::Endpoint::client`, reusing the rustls-config idiom already
//!   established in `dns::doq`/`transport::trusttunnel::quic`/`transport::masque`, but bypasses
//!   the adapter's dialer (interface/routing-mark/TFO options) doing so — those options are not
//!   honoured for the xhttp HTTP/3 download connection, though its target host still resolves
//!   through the proxy-aware resolver the direct dial uses.
//! * The dial result is closed on any later failure in `dial_context`/`listen_packet_context`,
//!   even though by then it may be wrapped several TLS/transport layers deep. This adapter relies
//!   on `Box<dyn NetConn>`/`SharedConn` `Drop` to close the socket on the same early-return paths
//!   instead of threading a second live handle through for an explicit close call
//!   (`transport::gun` documents the same RAII-for-close substitution).

use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common::utils::global_id::global_id;
use murmur_common_convert::util::rand_user_agent;
use murmur_common_net::io::{OldConnAsStream, StreamAsOldConn};
use murmur_common_net::{new_thread_safe_packet_conn, setup_context_for_conn};
use murmur_component::dialer::bind::{join_host_port, parse_address_port};
use murmur_component::dialer::options::Option as DialerOption;
use murmur_component::resolver::resolver::proxy_server_host_resolver;
use murmur_component_ca as ca;
use murmur_component_ech::Config as EchConfig;
use murmur_component_tls::utls as tls_c;
use murmur_component_tls::utls::{SharedTlsConn, TlsBufferedIncoming, TlsConn};
use murmur_constant::adapters::AdapterType;
use murmur_constant::adapters::{
    Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::dns::DNSPrefer;
use murmur_constant::metadata::{AddrType, Metadata};
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Conn as NetConn, PacketConn};
use murmur_transport::gun;
use murmur_transport_shadowtls as shadowtls;
use murmur_transport_vless::config_pb::Addons;
use murmur_transport_vless::encryption;
use murmur_transport_vless::vision::vision::TlsConnCheck;
use murmur_transport_vless::vless::XRV;
use murmur_transport_vless::vless::{self as vless_client, DstAddr};
use murmur_transport_vmess::h2::H2Config;
use murmur_transport_vmess::http::HttpConfig;
use murmur_transport_vmess::sing::{packetaddr, xudp};
use murmur_transport_vmess::tls::{
    stream_tls_conn as vmess_stream_tls_conn,
    stream_tls_conn_with_raw_handoff as vmess_stream_tls_conn_with_raw_handoff, TlsConfig,
};
use murmur_transport_vmess::websocket::{stream_websocket_conn_public, WebsocketConfig};
use murmur_transport_xhttp as xhttp;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::ech::ECHOptions;
use super::shadowtls::ShadowTLSOptions;
use super::util::resolve_ip_with_resolver;
use super::vmess::{GrpcOptions, Http2Options, HttpOptions, WsOptions};

/// `Vless`. See the module doc for `self_weak`.
pub struct Vless {
    base: Base,
    client: vless_client::Client,
    option: VlessOption,

    encryption: Option<Arc<encryption::client::ClientInstance>>,

    gun_client: Option<Arc<gun::gun::Client>>,
    xhttp_client: Option<Arc<xhttp::client::Client>>,

    ech_config: Option<Arc<EchConfig>>,
    shadow_tls_config: Option<shadowtls::client::Config>,
    jls_config: Option<murmur_transport_jls::Config>,
    restls_config: Option<Arc<murmur_restls::Config>>,
    reality_config: Option<Arc<murmur_reality::RealityClientConfig>>,

    self_weak: Weak<Self>,
}

impl core::fmt::Debug for Vless {
    /// Prints only the identity; `option` carries the UUID and TLS private-key credentials.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vless").field("name", &self.base.name).field("addr", &self.base.addr).finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "wire-format mirror; the flags are independent protocol options, so collapsing them would change the public shape"
)]
pub struct VlessOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port")]
    pub port: u16,
    #[serde(rename = "uuid")]
    pub uuid: String,
    #[serde(rename = "flow", default)]
    pub flow: String,
    #[serde(rename = "tls", default)]
    pub tls: bool,
    #[serde(rename = "alpn", default)]
    pub alpn: Vec<String>,
    #[serde(rename = "udp", default)]
    pub udp: bool,
    #[serde(rename = "packet-addr", default)]
    pub packet_addr: bool,
    #[serde(rename = "xudp", default)]
    pub xudp: bool,
    #[serde(rename = "packet-encoding", default)]
    pub packet_encoding: String,
    #[serde(rename = "encryption", default)]
    pub encryption: String,
    #[serde(rename = "network", default)]
    pub network: String,
    #[serde(rename = "ech-opts", default)]
    pub ech_opts: ECHOptions,
    #[serde(rename = "shadow-tls-opts", default)]
    pub shadow_tls_opts: ShadowTLSOptions,
    #[serde(rename = "restls-opts", default)]
    pub restls_opts: super::base::RestlsOptions,
    #[serde(rename = "jls-opts", default)]
    pub jls_opts: super::jls::JlsOptions,
    #[serde(rename = "reality-opts", default)]
    pub reality_opts: super::base::RealityOpts,
    #[serde(rename = "http-opts", default)]
    pub http_opts: HttpOptions,
    #[serde(rename = "h2-opts", default)]
    pub http2_opts: Http2Options,
    #[serde(rename = "grpc-opts", default)]
    pub grpc_opts: GrpcOptions,
    #[serde(rename = "ws-opts", default)]
    pub ws_opts: WsOptions,
    #[serde(rename = "xhttp-opts", default)]
    pub xhttp_opts: XHTTPOptions,
    #[serde(rename = "ws-headers", default)]
    pub ws_headers: std::collections::HashMap<String, String>,
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
    #[serde(rename = "servername", default)]
    pub server_name: String,
    #[serde(rename = "client-fingerprint", default)]
    pub client_fingerprint: String,
}

impl core::fmt::Debug for VlessOption {
    /// Redacts the `uuid` and `private_key` credentials so a stray `{:?}` cannot log them.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VlessOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("uuid", &"<redacted>")
            .field("flow", &self.flow)
            .field("network", &self.network)
            .field("tls", &self.tls)
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XHTTPOptions {
    #[serde(rename = "path", default)]
    pub path: String,
    #[serde(rename = "host", default)]
    pub host: String,
    #[serde(rename = "mode", default)]
    pub mode: String,
    #[serde(rename = "headers", default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(rename = "no-grpc-header", default)]
    pub no_grpc_header: bool,
    #[serde(rename = "x-padding-bytes", default)]
    pub x_padding_bytes: String,
    #[serde(rename = "x-padding-obfs-mode", default)]
    pub x_padding_obfs_mode: bool,
    #[serde(rename = "x-padding-key", default)]
    pub x_padding_key: String,
    #[serde(rename = "x-padding-header", default)]
    pub x_padding_header: String,
    #[serde(rename = "x-padding-placement", default)]
    pub x_padding_placement: String,
    #[serde(rename = "x-padding-method", default)]
    pub x_padding_method: String,
    #[serde(rename = "uplink-http-method", default)]
    pub uplink_http_method: String,
    #[serde(rename = "session-placement", default)]
    pub session_placement: String,
    #[serde(rename = "session-key", default)]
    pub session_key: String,
    #[serde(rename = "session-table", default)]
    pub session_table: String,
    #[serde(rename = "session-length", default)]
    pub session_length: String,
    #[serde(rename = "seq-placement", default)]
    pub seq_placement: String,
    #[serde(rename = "seq-key", default)]
    pub seq_key: String,
    #[serde(rename = "uplink-data-placement", default)]
    pub uplink_data_placement: String,
    #[serde(rename = "uplink-data-key", default)]
    pub uplink_data_key: String,
    #[serde(rename = "uplink-chunk-size", default)]
    pub uplink_chunk_size: String,
    #[serde(rename = "sc-max-each-post-bytes", default)]
    pub sc_max_each_post_bytes: String,
    #[serde(rename = "sc-min-posts-interval-ms", default)]
    pub sc_min_posts_interval_ms: String,
    /// The XMUX reuse settings.
    #[serde(rename = "reuse-settings", default)]
    pub reuse_settings: Option<XHTTPReuseSettings>,
    #[serde(rename = "download-settings", default)]
    pub download_settings: Option<Box<XHTTPDownloadSettings>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XHTTPReuseSettings {
    #[serde(rename = "max-concurrency", default)]
    pub max_concurrency: String,
    #[serde(rename = "max-connections", default)]
    pub max_connections: String,
    #[serde(rename = "c-max-reuse-times", default)]
    pub c_max_reuse_times: String,
    #[serde(rename = "h-max-request-times", default)]
    pub h_max_request_times: String,
    #[serde(rename = "h-max-reusable-secs", default)]
    pub h_max_reusable_secs: String,
    #[serde(rename = "h-keep-alive-period", default)]
    pub h_keep_alive_period: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XHTTPDownloadSettings {
    #[serde(rename = "path", default)]
    pub path: Option<String>,
    #[serde(rename = "host", default)]
    pub host: Option<String>,
    #[serde(rename = "headers", default)]
    pub headers: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "reuse-settings", default)]
    pub reuse_settings: Option<XHTTPReuseSettings>,
    #[serde(rename = "server", default)]
    pub server: Option<String>,
    #[serde(rename = "port", default)]
    pub port: Option<u16>,
    #[serde(rename = "tls", default)]
    pub tls: Option<bool>,
    #[serde(rename = "alpn", default)]
    pub alpn: Option<Vec<String>>,
    #[serde(rename = "ech-opts", default)]
    pub ech_opts: Option<ECHOptions>,
    #[serde(rename = "shadow-tls-opts", default)]
    pub shadow_tls_opts: Option<ShadowTLSOptions>,
    #[serde(rename = "restls-opts", default)]
    pub restls_opts: Option<super::base::RestlsOptions>,
    #[serde(rename = "jls-opts", default)]
    pub jls_opts: Option<super::jls::JlsOptions>,
    #[serde(rename = "reality-opts", default)]
    pub reality_opts: Option<super::base::RealityOpts>,
    #[serde(rename = "skip-cert-verify", default)]
    pub skip_cert_verify: Option<bool>,
    #[serde(rename = "name-cert-verify", default)]
    pub name_cert_verify: Option<String>,
    #[serde(rename = "fingerprint", default)]
    pub fingerprint: Option<String>,
    #[serde(rename = "certificate", default)]
    pub certificate: Option<String>,
    #[serde(rename = "private-key", default)]
    pub private_key: Option<String>,
    #[serde(rename = "servername", default)]
    pub server_name: Option<String>,
    #[serde(rename = "client-fingerprint", default)]
    pub client_fingerprint: Option<String>,
}

/// The TLS/security-mode material the stream-TLS helper (and the `grpc`/`xhttp` dial closures) read
/// from the option. See the module doc for why this is a free-standing snapshot rather than a
/// `&Vless` receiver.
#[derive(Clone)]
struct TlsMaterial {
    addr: String,
    tls: bool,
    alpn: Vec<String>,
    skip_cert_verify: bool,
    name_cert_verify: String,
    fingerprint: String,
    certificate: String,
    private_key: String,
    client_fingerprint: String,
    server_name: String,
    ech_config: Option<Arc<EchConfig>>,
    shadow_tls_config: Option<shadowtls::client::Config>,
    jls_config: Option<murmur_transport_jls::Config>,
    restls_config: Option<Arc<murmur_restls::Config>>,
    security_mode: String,
    reality_config: Option<Arc<murmur_reality::RealityClientConfig>>,
}

impl TlsMaterial {
    /// The host half of the address.
    fn host(&self) -> String {
        murmur_common_net::tcpip::split_host_port(&self.addr).map(|(host, _, _)| host).unwrap_or_default()
    }
}

/// The capability Vision receives for the conn the adapter actually hands it.
///
/// The reference accepts its encryption conn as a Vision transport even without outer TLS, so an
/// encrypted conn whose TLS check is `Unsupported` becomes padding-only Vision rather than a
/// rejection.
fn vision_capability(tls_check: TlsConnCheck, encrypted: bool) -> TlsConnCheck {
    if encrypted && matches!(tls_check, TlsConnCheck::Unsupported) {
        TlsConnCheck::NoTls
    } else {
        tls_check
    }
}

async fn stream_tls_conn(
    material: &TlsMaterial,
    ctx: &CancellationToken,
    conn: Box<dyn NetConn>,
    is_h2: bool,
    raw_handoff: bool,
) -> Result<Box<dyn TlsConn>> {
    if !material.tls {
        return Ok(Box::new(tls_c::ErasedTlsConn(Box::new(OldConnAsStream(conn)))));
    }

    let mut tls_opts = TlsConfig {
        host: material.host(),
        skip_cert_verify: material.skip_cert_verify,
        name_cert_verify: material.name_cert_verify.clone(),
        finger_print: material.fingerprint.clone(),
        certificate: material.certificate.clone(),
        private_key: material.private_key.clone(),
        client_fingerprint: material.client_fingerprint.clone(),
        ech: material.ech_config.clone(),
        shadow_tls: material.shadow_tls_config.clone(),
        restls: material.restls_config.clone(),
        jls: material.jls_config.clone(),
        next_protos: material.alpn.clone(),
        tls_mirror: None,
        tls_mirror_dialer: None,
        reality: material.reality_config.clone(),
    };

    if is_h2 {
        tls_opts.next_protos = vec!["h2".to_owned()];
    }

    if !material.server_name.is_empty() {
        tls_opts.host = material.server_name.clone();
    }

    if raw_handoff {
        return vmess_stream_tls_conn_with_raw_handoff(ctx, Box::new(OldConnAsStream(conn)), &tls_opts).await;
    }
    vmess_stream_tls_conn(ctx, Box::new(OldConnAsStream(conn)), &tls_opts).await
}

/// The one security mode the configs select; `label` prefixes the mutual-exclusion error.
fn select_security_mode(
    shadow_tls: Option<&shadowtls::client::Config>,
    restls: Option<&Arc<murmur_restls::Config>>,
    jls: Option<&murmur_transport_jls::Config>,
    reality: Option<&Arc<murmur_reality::RealityClientConfig>>,
    label: &str,
) -> Result<&'static str> {
    let mut modes: Vec<&'static str> = Vec::with_capacity(4);
    if shadow_tls.is_some() {
        modes.push("ShadowTLS");
    }
    if restls.is_some() {
        modes.push("Restls");
    }
    if jls.is_some() {
        modes.push("JLS");
    }
    if reality.is_some() {
        modes.push("REALITY");
    }
    if modes.len() > 1 {
        return Err(anyhow!("{label}security modes are mutually exclusive: {}", modes.join(", ")));
    }
    Ok(modes.first().copied().unwrap_or_default())
}

impl Vless {
    #[expect(
        clippy::too_many_lines,
        reason = "linear option assembly: each parsed config feeds the client in one pass"
    )]
    #[expect(
        clippy::cognitive_complexity,
        reason = "one branch per network mode, plus the xhttp download-settings fallbacks"
    )]
    pub fn new(mut option: VlessOption) -> Result<Arc<Self>> {
        let addons: Option<Addons> = if option.flow.len() >= 16 {
            option.flow.truncate(16);
            if option.flow != XRV {
                return Err(anyhow!("unsupported xtls flow type: {}", option.flow));
            }
            Some(Addons { flow: option.flow.clone(), seed: Vec::new() })
        } else {
            None
        };
        let vision_flow = addons.is_some();

        match option.packet_encoding.as_str() {
            "packetaddr" | "packet" => {
                option.packet_addr = true;
                option.xudp = false;
            }
            _ => {
                if !option.packet_addr {
                    option.xudp = true;
                }
            }
        }
        if option.xudp {
            option.packet_addr = false;
        }

        let client = vless_client::new_client(&option.uuid, addons)?;

        let addr = join_host_port(&option.server, option.port);

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: addr.clone(),
            type_: AdapterType::VLESS,
            provider_name: option.basic_option.provider_name.clone(),
            udp: option.udp,
            xudp: option.xudp,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
        });

        let dialer = option.basic_option.new_dialer(base.dial_options());
        base.dialer = Some(Arc::clone(&dialer));

        let encryption = encryption::factory::new_client(&option.encryption)?.map(Arc::new);

        let ech_config = option.ech_opts.parse()?.map(Arc::new);
        let shadow_tls_config = option.shadow_tls_opts.parse()?;
        let restls_config = option.restls_opts.parse(&option.server_name)?;
        let jls_config = option.jls_opts.parse()?;
        let reality_config = option.reality_opts.parse()?.map(Arc::new);

        let security_mode = select_security_mode(
            shadow_tls_config.as_ref(),
            restls_config.as_ref(),
            jls_config.as_ref(),
            reality_config.as_ref(),
            "",
        )?;
        if !security_mode.is_empty() && !option.tls {
            return Err(anyhow!("{security_mode} requires TLS"));
        }

        // Vision needs either a conn that reports its TLS session or the VLESS encryption layer.
        // The framed transports below build their conn around the TLS session and never evaluate
        // one, so without encryption they would defer a guaranteed failure to every dial (which
        // logged `vision: not a valid supported TLS connection`); with encryption, Vision wraps the
        // encryption conn instead, so the underlying transport no longer matters.
        if vision_flow {
            if !option.tls && encryption.is_none() {
                return Err(anyhow!("xtls-rprx-vision requires TLS or VLESS encryption"));
            }
            if encryption.is_none() && matches!(option.network.as_str(), "ws" | "http" | "h2" | "grpc" | "xhttp") {
                return Err(anyhow!("xtls-rprx-vision only supports the tcp network, not {}", option.network));
            }
            if matches!(security_mode, "ShadowTLS" | "Restls" | "JLS") {
                return Err(anyhow!("xtls-rprx-vision requires the TLS session that {security_mode} replaces"));
            }
        }

        let mut gun_client: Option<Arc<gun::gun::Client>> = None;
        let mut xhttp_client: Option<Arc<xhttp::client::Client>> = None;

        match option.network.as_str() {
            "h2" => {
                if option.http2_opts.host.is_empty() {
                    option.http2_opts.host.push("www.example.com".to_owned());
                }
            }
            "grpc" => {
                let dial_dialer = Arc::clone(&dialer);
                let dial_addr = addr.clone();
                let dial_fn: gun::gun::DialFn =
                    Arc::new(move |ctx: CancellationToken, _network: String, _addr: String| {
                        let dialer = Arc::clone(&dial_dialer);
                        let addr = dial_addr.clone();
                        Box::pin(async move {
                            let stream = dialer
                                .dial_context(&ctx, "tcp", &addr)
                                .await
                                .map_err(|err| anyhow!("{addr} connect error: {err}"))?;
                            let conn: Box<dyn murmur_std_compat::net::Conn> = Box::new(StreamAsOldConn::new(stream)); // S11: remove with std-compat
                            Ok(conn)
                        })
                    });

                let gun_config = gun::gun::Config {
                    service_name: option.grpc_opts.grpc_service_name.clone(),
                    user_agent: option.grpc_opts.grpc_user_agent.clone(),
                    host: if option.server_name.is_empty() { addr.clone() } else { option.server_name.clone() },
                    ping_interval: option.grpc_opts.ping_interval,
                };

                let tls_config = if option.tls {
                    let mut tls_config = TlsConfig {
                        host: option.server_name.clone(),
                        skip_cert_verify: option.skip_cert_verify,
                        name_cert_verify: option.name_cert_verify.clone(),
                        finger_print: option.fingerprint.clone(),
                        certificate: option.certificate.clone(),
                        private_key: option.private_key.clone(),
                        client_fingerprint: option.client_fingerprint.clone(),
                        next_protos: vec!["h2".to_owned()],
                        ech: ech_config.clone(),
                        shadow_tls: shadow_tls_config.clone(),
                        restls: restls_config.clone(),
                        jls: jls_config.clone(),
                        tls_mirror: None,
                        tls_mirror_dialer: None,
                        reality: reality_config.clone(),
                    };
                    if option.server_name.is_empty() {
                        let (host, _, _) = murmur_common_net::tcpip::split_host_port(&addr).unwrap_or_default();
                        tls_config.host = host;
                    }
                    Some(tls_config)
                } else {
                    None
                };

                gun_client = Some(Arc::new(gun::gun::new_client(
                    Arc::new(move || {
                        gun::gun::new_transport(Arc::clone(&dial_fn), tls_config.clone(), gun_config.clone())
                    }),
                    option.grpc_opts.max_connections,
                    option.grpc_opts.min_streams,
                    option.grpc_opts.max_streams,
                )));
            }
            "xhttp" => {
                let mut request_host = option.xhttp_opts.host.clone();
                if request_host.is_empty() {
                    request_host =
                        if option.server_name.is_empty() { option.server.clone() } else { option.server_name.clone() };
                    if let Ok(ip) = request_host.parse::<std::net::IpAddr>() {
                        if ip.is_ipv6() {
                            request_host = format!("[{request_host}]");
                        }
                    }
                }

                let mut h_keep_alive_period = std::time::Duration::ZERO;
                let mut reuse_cfg: Option<xhttp::config::ReuseConfig> = None;
                if let Some(rs) = &option.xhttp_opts.reuse_settings {
                    reuse_cfg = Some(xhttp::config::ReuseConfig {
                        max_concurrency: rs.max_concurrency.clone(),
                        max_connections: rs.max_connections.clone(),
                        c_max_reuse_times: rs.c_max_reuse_times.clone(),
                        h_max_request_times: rs.h_max_request_times.clone(),
                        h_max_reusable_secs: rs.h_max_reusable_secs.clone(),
                    });
                    h_keep_alive_period =
                        std::time::Duration::from_secs(u64::try_from(rs.h_keep_alive_period).unwrap_or_default());
                }

                let mut cfg = xhttp::config::Config {
                    host: request_host,
                    path: option.xhttp_opts.path.clone(),
                    mode: option.xhttp_opts.mode.clone(),
                    headers: option.xhttp_opts.headers.clone(),
                    no_grpc_header: option.xhttp_opts.no_grpc_header,
                    x_padding_bytes: option.xhttp_opts.x_padding_bytes.clone(),
                    x_padding_obfs_mode: option.xhttp_opts.x_padding_obfs_mode,
                    x_padding_key: option.xhttp_opts.x_padding_key.clone(),
                    x_padding_header: option.xhttp_opts.x_padding_header.clone(),
                    x_padding_placement: option.xhttp_opts.x_padding_placement.clone(),
                    x_padding_method: option.xhttp_opts.x_padding_method.clone(),
                    uplink_http_method: option.xhttp_opts.uplink_http_method.clone(),
                    session_placement: option.xhttp_opts.session_placement.clone(),
                    session_key: option.xhttp_opts.session_key.clone(),
                    session_table: option.xhttp_opts.session_table.clone(),
                    session_length: option.xhttp_opts.session_length.clone(),
                    seq_placement: option.xhttp_opts.seq_placement.clone(),
                    seq_key: option.xhttp_opts.seq_key.clone(),
                    uplink_data_placement: option.xhttp_opts.uplink_data_placement.clone(),
                    uplink_data_key: option.xhttp_opts.uplink_data_key.clone(),
                    uplink_chunk_size: option.xhttp_opts.uplink_chunk_size.clone(),
                    sc_max_each_post_bytes: option.xhttp_opts.sc_max_each_post_bytes.clone(),
                    sc_min_posts_interval_ms: option.xhttp_opts.sc_min_posts_interval_ms.clone(),
                    reuse_config: reuse_cfg.map(Box::new),
                    no_sse_header: false,
                    sc_stream_up_server_secs: String::new(),
                    sc_max_buffered_posts: String::new(),
                    download_config: None,
                };

                let material = TlsMaterial {
                    addr: addr.clone(),
                    tls: option.tls,
                    alpn: option.alpn.clone(),
                    skip_cert_verify: option.skip_cert_verify,
                    name_cert_verify: option.name_cert_verify.clone(),
                    fingerprint: option.fingerprint.clone(),
                    certificate: option.certificate.clone(),
                    private_key: option.private_key.clone(),
                    client_fingerprint: option.client_fingerprint.clone(),
                    server_name: option.server_name.clone(),
                    ech_config: ech_config.clone(),
                    shadow_tls_config: shadow_tls_config.clone(),
                    restls_config: restls_config.clone(),
                    jls_config: jls_config.clone(),
                    reality_config: reality_config.clone(),
                    security_mode: security_mode.to_owned(),
                };

                let dial_dialer = Arc::clone(&dialer);
                let dial_addr = addr.clone();
                let dial_raw: xhttp::client::DialRawFunc = Arc::new(move |ctx: CancellationToken| {
                    let dialer = Arc::clone(&dial_dialer);
                    let addr = dial_addr.clone();
                    Box::pin(async move {
                        let stream = dialer.dial_context(&ctx, "tcp", &addr).await?;
                        let conn: Box<dyn murmur_std_compat::net::Conn> = Box::new(StreamAsOldConn::new(stream)); // S11: remove with std-compat
                        Ok(conn)
                    })
                });

                let wrap_material = material.clone();
                let wrap_tls: xhttp::client::WrapTlsFunc =
                    Arc::new(move |ctx: CancellationToken, raw: Box<dyn NetConn>, is_h2: bool| {
                        let material = wrap_material.clone();
                        Box::pin(async move {
                            stream_tls_conn(&material, &ctx, raw, is_h2, false)
                                .await
                                .map(|c| -> Box<dyn NetConn> { Box::new(StreamAsOldConn::new(c)) })
                        })
                    });

                let quic_material = material;
                let quic_addr = addr;
                let quic_prefer = base.prefer;
                let dial_quic: xhttp::client::DialQuicFunc =
                    Arc::new(move |ctx: CancellationToken, quic_cfg: xhttp::client::QuicConfig| {
                        let material = quic_material.clone();
                        let addr = quic_addr.clone();
                        Box::pin(async move {
                            if !material.tls {
                                return Err(anyhow!("xhttp HTTP/3 requires TLS"));
                            }
                            if !material.security_mode.is_empty() {
                                return Err(anyhow!("xhttp HTTP/3 does not support {}", material.security_mode));
                            }
                            let mut tls_opts = tls_c::Config {
                                server_name: material.host(),
                                insecure_skip_verify: material.skip_cert_verify,
                                next_protos: vec!["h3".to_owned()],
                                rand: None,
                                time: None,
                                certificates: Vec::new(),
                                get_certificate: None,
                                get_client_certificate: None,
                                verify_peer_certificate: None,
                                verify_connection: None,
                                root_cas: None,
                                client_auth: tls_c::ClientAuthType::default(),
                                client_cas: None,
                                cipher_suites: None,
                                session_tickets_disabled: false,
                                min_version: 0,
                                max_version: 0,
                                curve_preferences: None,
                                renegotiation: tls_c::RenegotiationSupport::default(),
                                key_log_writer: None,
                                encrypted_client_hello_config_list: Vec::new(),
                                encrypted_client_hello_rejection_verify: None,
                                encrypted_client_hello_keys: Vec::new(),
                                get_encrypted_client_hello_keys: None,
                                session_id_generator: None,
                            };
                            if !material.server_name.is_empty() {
                                tls_opts.server_name = material.server_name.clone();
                            }
                            dial_h3_quic(ctx, addr, tls_opts, quic_cfg, quic_prefer).await
                        })
                    });

                let alpn = option.alpn.clone();
                let make_transport = {
                    let dial_raw = Arc::clone(&dial_raw);
                    let wrap_tls = Arc::clone(&wrap_tls);
                    let dial_quic = Arc::clone(&dial_quic);
                    move || {
                        xhttp::client::new_transport(
                            Arc::clone(&dial_raw),
                            Arc::clone(&wrap_tls),
                            Arc::clone(&dial_quic),
                            &alpn,
                            h_keep_alive_period,
                        )
                    }
                };

                let make_download_transport: Option<xhttp::client::TransportMaker> = if let Some(ds) =
                    option.xhttp_opts.download_settings.clone()
                {
                    if cfg.normalized_mode() == "stream-one" {
                        return Err(anyhow!(r#"xhttp mode "stream-one" cannot be used with download-settings"#));
                    }

                    let download_server = ds.server.clone().unwrap_or_else(|| option.server.clone());
                    let download_port = ds.port.unwrap_or(option.port);
                    let download_tls = ds.tls.unwrap_or(option.tls);
                    let download_alpn = ds.alpn.clone().unwrap_or_else(|| option.alpn.clone());
                    let download_skip_cert_verify = ds.skip_cert_verify.unwrap_or(option.skip_cert_verify);
                    let download_name_cert_verify =
                        ds.name_cert_verify.clone().unwrap_or_else(|| option.name_cert_verify.clone());
                    let download_fingerprint = ds.fingerprint.clone().unwrap_or_else(|| option.fingerprint.clone());
                    let download_certificate = ds.certificate.clone().unwrap_or_else(|| option.certificate.clone());
                    let download_private_key = ds.private_key.clone().unwrap_or_else(|| option.private_key.clone());
                    let download_server_name = ds.server_name.clone().unwrap_or_else(|| option.server_name.clone());
                    let download_client_fingerprint =
                        ds.client_fingerprint.clone().unwrap_or_else(|| option.client_fingerprint.clone());

                    let download_ech_config = if let Some(ds_ech) = &ds.ech_opts {
                        ds_ech.parse()?.map(Arc::new)
                    } else {
                        ech_config.clone()
                    };
                    let download_shadow_tls_config = if let Some(ds_stls) = &ds.shadow_tls_opts {
                        ds_stls.parse()?
                    } else {
                        shadow_tls_config.clone()
                    };
                    let download_restls_config = if let Some(ds_restls) = &ds.restls_opts {
                        ds_restls.parse(&download_server_name)?
                    } else {
                        restls_config.clone()
                    };
                    let download_jls_config =
                        if let Some(ds_jls) = &ds.jls_opts { ds_jls.parse()? } else { jls_config.clone() };
                    let download_reality_config = if let Some(ds_reality) = &ds.reality_opts {
                        ds_reality.parse()?.map(Arc::new)
                    } else {
                        reality_config.clone()
                    };

                    let download_security_mode = select_security_mode(
                        download_shadow_tls_config.as_ref(),
                        download_restls_config.as_ref(),
                        download_jls_config.as_ref(),
                        download_reality_config.as_ref(),
                        "xhttp download-settings ",
                    )?;
                    if !download_security_mode.is_empty() && !download_tls {
                        return Err(anyhow!("xhttp download-settings: {download_security_mode} requires TLS"));
                    }

                    let download_addr = join_host_port(&download_server, download_port);

                    let mut download_host = ds.host.clone().unwrap_or_else(|| option.xhttp_opts.host.clone());
                    if download_host.is_empty() {
                        download_host = if download_server_name.is_empty() {
                            download_server
                        } else {
                            download_server_name.clone()
                        };
                        if let Ok(ip) = download_host.parse::<std::net::IpAddr>() {
                            if ip.is_ipv6() {
                                download_host = format!("[{download_host}]");
                            }
                        }
                    }

                    let mut download_h_keep_alive_period = h_keep_alive_period;

                    let mut download_cfg = cfg.clone();
                    download_cfg.host = download_host;
                    download_cfg.path = ds.path.clone().unwrap_or_else(|| option.xhttp_opts.path.clone());
                    download_cfg.headers = ds.headers.clone().unwrap_or_else(|| option.xhttp_opts.headers.clone());

                    if let Some(ds_reuse) = &ds.reuse_settings {
                        download_cfg.reuse_config = Some(Box::new(xhttp::config::ReuseConfig {
                            max_concurrency: ds_reuse.max_concurrency.clone(),
                            max_connections: ds_reuse.max_connections.clone(),
                            c_max_reuse_times: ds_reuse.c_max_reuse_times.clone(),
                            h_max_request_times: ds_reuse.h_max_request_times.clone(),
                            h_max_reusable_secs: ds_reuse.h_max_reusable_secs.clone(),
                        }));
                        let keep_alive = u64::try_from(ds_reuse.h_keep_alive_period).unwrap_or_default();
                        download_h_keep_alive_period = std::time::Duration::from_secs(keep_alive);
                    }

                    cfg.download_config = Some(Box::new(download_cfg));

                    let download_material = TlsMaterial {
                        addr: download_addr.clone(),
                        tls: download_tls,
                        alpn: download_alpn.clone(),
                        skip_cert_verify: download_skip_cert_verify,
                        name_cert_verify: download_name_cert_verify,
                        fingerprint: download_fingerprint,
                        certificate: download_certificate,
                        private_key: download_private_key,
                        client_fingerprint: download_client_fingerprint,
                        server_name: download_server_name,
                        ech_config: download_ech_config,
                        shadow_tls_config: download_shadow_tls_config,
                        restls_config: download_restls_config,
                        jls_config: download_jls_config,
                        reality_config: download_reality_config,
                        security_mode: download_security_mode.to_owned(),
                    };

                    let dl_dial_dialer = Arc::clone(&dialer);
                    let dl_addr = download_addr.clone();
                    let dl_dial_raw: xhttp::client::DialRawFunc = Arc::new(move |ctx: CancellationToken| {
                        let dialer = Arc::clone(&dl_dial_dialer);
                        let addr = dl_addr.clone();
                        Box::pin(async move {
                            let stream = dialer.dial_context(&ctx, "tcp", &addr).await?;
                            let conn: Box<dyn murmur_std_compat::net::Conn> = Box::new(StreamAsOldConn::new(stream)); // S11: remove with std-compat
                            Ok(conn)
                        })
                    });

                    let dl_wrap_material = download_material.clone();
                    let dl_wrap_tls: xhttp::client::WrapTlsFunc =
                        Arc::new(move |ctx: CancellationToken, raw: Box<dyn NetConn>, is_h2: bool| {
                            let material = dl_wrap_material.clone();
                            Box::pin(async move {
                                stream_tls_conn(&material, &ctx, raw, is_h2, false)
                                    .await
                                    .map(|c| -> Box<dyn NetConn> { Box::new(StreamAsOldConn::new(c)) })
                            })
                        });

                    let dl_quic_material = download_material;
                    let dl_quic_addr = download_addr;
                    let dl_dial_quic: xhttp::client::DialQuicFunc =
                        Arc::new(move |ctx: CancellationToken, quic_cfg: xhttp::client::QuicConfig| {
                            let material = dl_quic_material.clone();
                            let addr = dl_quic_addr.clone();
                            Box::pin(async move {
                                if !material.tls {
                                    return Err(anyhow!("xhttp HTTP/3 requires TLS"));
                                }
                                if !material.security_mode.is_empty() {
                                    return Err(anyhow!("xhttp HTTP/3 does not support {}", material.security_mode));
                                }
                                let mut tls_opts = tls_c::Config {
                                    server_name: material.host(),
                                    insecure_skip_verify: material.skip_cert_verify,
                                    next_protos: vec!["h3".to_owned()],
                                    rand: None,
                                    time: None,
                                    certificates: Vec::new(),
                                    get_certificate: None,
                                    get_client_certificate: None,
                                    verify_peer_certificate: None,
                                    verify_connection: None,
                                    root_cas: None,
                                    client_auth: tls_c::ClientAuthType::default(),
                                    client_cas: None,
                                    cipher_suites: None,
                                    session_tickets_disabled: false,
                                    min_version: 0,
                                    max_version: 0,
                                    curve_preferences: None,
                                    renegotiation: tls_c::RenegotiationSupport::default(),
                                    key_log_writer: None,
                                    encrypted_client_hello_config_list: Vec::new(),
                                    encrypted_client_hello_rejection_verify: None,
                                    encrypted_client_hello_keys: Vec::new(),
                                    get_encrypted_client_hello_keys: None,
                                    session_id_generator: None,
                                };
                                if !material.server_name.is_empty() {
                                    tls_opts.server_name = material.server_name.clone();
                                }
                                dial_h3_quic(ctx, addr, tls_opts, quic_cfg, quic_prefer).await
                            })
                        });

                    let download_alpn2 = download_alpn;
                    Some(Arc::new(move || {
                        xhttp::client::new_transport(
                            Arc::clone(&dl_dial_raw),
                            Arc::clone(&dl_wrap_tls),
                            Arc::clone(&dl_dial_quic),
                            &download_alpn2,
                            download_h_keep_alive_period,
                        )
                    }))
                } else {
                    None
                };

                xhttp_client = Some(Arc::new(xhttp::client::Client::new(
                    Arc::new(cfg),
                    Arc::new(make_transport),
                    make_download_transport,
                    reality_config.is_some(),
                )?));
            }
            _ => {}
        }

        Ok(Arc::new_cyclic(|weak| Self {
            base,
            client,
            option,
            encryption,
            gun_client,
            xhttp_client,
            ech_config,
            shadow_tls_config,
            jls_config,
            restls_config,
            reality_config,
            self_weak: Weak::clone(weak),
        }))
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("Vless adapter dropped while still in use"))
    }

    fn tls_material(&self) -> TlsMaterial {
        TlsMaterial {
            addr: self.base.addr.clone(),
            tls: self.option.tls,
            alpn: self.option.alpn.clone(),
            skip_cert_verify: self.option.skip_cert_verify,
            name_cert_verify: self.option.name_cert_verify.clone(),
            fingerprint: self.option.fingerprint.clone(),
            certificate: self.option.certificate.clone(),
            private_key: self.option.private_key.clone(),
            client_fingerprint: self.option.client_fingerprint.clone(),
            server_name: self.option.server_name.clone(),
            ech_config: self.ech_config.clone(),
            shadow_tls_config: self.shadow_tls_config.clone(),
            restls_config: self.restls_config.clone(),
            jls_config: self.jls_config.clone(),
            reality_config: self.reality_config.clone(),
            security_mode: String::new(),
        }
    }

    pub async fn stream_conn_context(
        &self,
        ctx: &CancellationToken,
        mut c: Box<dyn NetConn>,
        metadata: &mut Metadata,
    ) -> Result<Box<dyn NetConn>> {
        let material = self.tls_material();
        let mut tls_check = TlsConnCheck::Unsupported;

        match self.option.network.as_str() {
            "ws" => {
                c = self.stream_ws_conn(ctx, c, &material).await?;
            }
            "http" => {
                c = Box::new(StreamAsOldConn::new(stream_tls_conn(&material, ctx, c, false, false).await?));

                let (host, _, _) = murmur_common_net::tcpip::split_host_port(&self.base.addr).unwrap_or_default();
                let http_opts = HttpConfig {
                    host,
                    method: self.option.http_opts.method.clone(),
                    path: self.option.http_opts.path.clone(),
                    headers: self.option.http_opts.headers.clone().into_iter().collect(),
                };

                c = murmur_transport_vmess::http::stream_http_conn(c, http_opts);
            }
            "h2" => {
                c = Box::new(StreamAsOldConn::new(stream_tls_conn(&material, ctx, c, true, false).await?));

                let h2_opts =
                    H2Config { hosts: self.option.http2_opts.host.clone(), path: self.option.http2_opts.path.clone() };

                c = murmur_transport_vmess::h2::stream_h2_conn(ctx, c, h2_opts).await?;
            }
            "grpc" | "xhttp" => {}
            _ => {
                let mut direct_net = None;
                let mut buffered_incoming: Option<Arc<dyn TlsBufferedIncoming>> = None;
                let vision_active = self.client.addons.as_ref().is_some_and(|addons| addons.flow == XRV);
                let tls_conn: Box<dyn NetConn> = if vision_active {
                    let raw = SharedConn::from_boxed(c);
                    let tls_conn = stream_tls_conn(&material, ctx, Box::new(raw.clone()), false, true).await?;
                    tls_check = TlsConnCheck::evaluate(tls_conn.as_ref());
                    if tls_conn.supports_raw_transport_handoff() {
                        let shared = SharedTlsConn::new(tls_conn);
                        direct_net = Some(raw);
                        buffered_incoming = Some(Arc::new(shared.clone()));
                        Box::new(StreamAsOldConn::new(shared))
                    } else {
                        Box::new(StreamAsOldConn::new(tls_conn))
                    }
                } else {
                    let tls_conn = stream_tls_conn(&material, ctx, c, false, false).await?;
                    tls_check = TlsConnCheck::evaluate(tls_conn.as_ref());
                    Box::new(StreamAsOldConn::new(tls_conn))
                };
                return self
                    .stream_conn_context_inner(ctx, tls_conn, tls_check, direct_net, buffered_incoming, metadata)
                    .await;
            }
        }

        self.stream_conn_context_inner(ctx, c, tls_check, None, None, metadata).await
    }

    /// The `ws` arm of `stream_conn_context`: the websocket framing over the plain or TLS conn.
    async fn stream_ws_conn(
        &self,
        ctx: &CancellationToken,
        c: Box<dyn NetConn>,
        material: &TlsMaterial,
    ) -> Result<Box<dyn NetConn>> {
        let host = material.host();
        let (_, port, _) = murmur_common_net::tcpip::split_host_port(&self.base.addr).unwrap_or_default();
        let mut ws_opts = WebsocketConfig {
            host: host.clone(),
            port,
            path: self.option.ws_opts.path.clone(),
            max_early_data: self.option.ws_opts.max_early_data,
            early_data_header_name: self.option.ws_opts.early_data_header_name.clone(),
            v2ray_http_upgrade: self.option.ws_opts.v2ray_http_upgrade,
            v2ray_http_upgrade_fast_open: self.option.ws_opts.v2ray_http_upgrade_fast_open,
            client_fingerprint: self.option.client_fingerprint.clone(),
            ech_config: self.ech_config.clone(),
            headers: Vec::new(),
            tls: false,
            tls_config: None,
        };

        for (key, value) in &self.option.ws_opts.headers {
            ws_opts.headers.push((key.clone(), value.clone()));
        }

        let c: Box<dyn NetConn> = if self.option.tls {
            let mut server_name = host.clone();
            if !self.option.server_name.is_empty() {
                server_name = self.option.server_name.clone();
            } else if let Some(header_host) = header_get(&ws_opts.headers, "Host") {
                server_name = header_host.to_owned();
            }

            if self.shadow_tls_config.is_some() || self.jls_config.is_some() {
                Box::new(StreamAsOldConn::new(
                    vmess_stream_tls_conn(
                        ctx,
                        Box::new(OldConnAsStream(c)),
                        &TlsConfig {
                            host: server_name,
                            skip_cert_verify: self.option.skip_cert_verify,
                            name_cert_verify: self.option.name_cert_verify.clone(),
                            finger_print: self.option.fingerprint.clone(),
                            certificate: self.option.certificate.clone(),
                            private_key: self.option.private_key.clone(),
                            client_fingerprint: self.option.client_fingerprint.clone(),
                            next_protos: vec!["http/1.1".to_owned()],
                            shadow_tls: self.shadow_tls_config.clone(),
                            jls: self.jls_config.clone(),
                            ech: None,
                            restls: None,
                            tls_mirror: None,
                            tls_mirror_dialer: None,
                            reality: None,
                        },
                    )
                    .await?,
                ))
            } else {
                ws_opts.tls = true;
                let tls_config = ca::config::get_tls_config(ca::config::Option {
                    tls_config: Some(self.ws_tls_config(&server_name)),
                    fingerprint: self.option.fingerprint.clone(),
                    name_cert_verify: self.option.name_cert_verify.clone(),
                    certificate: self.option.certificate.clone(),
                    private_key: self.option.private_key.clone(),
                    zero_trust: false,
                })?;
                ws_opts.tls_config = Some(Arc::new(tls_config));
                c
            }
        } else {
            if header_get(&ws_opts.headers, "Host").is_none_or(str::is_empty) {
                ws_opts.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
                ws_opts.headers.push(("Host".to_owned(), murmur_common_convert::util::rand_host()));
                set_user_agent(&mut ws_opts.headers);
            }
            c
        };
        stream_websocket_conn_public(ctx, c, ws_opts).await
    }

    /// The `tls_c::Config` the websocket TLS wrapper dials with.
    fn ws_tls_config(&self, server_name: &str) -> tls_c::Config {
        tls_c::Config {
            server_name: server_name.to_owned(),
            insecure_skip_verify: self.option.skip_cert_verify,
            next_protos: vec!["http/1.1".to_owned()],
            rand: None,
            time: None,
            certificates: Vec::new(),
            get_certificate: None,
            get_client_certificate: None,
            verify_peer_certificate: None,
            verify_connection: None,
            root_cas: None,
            client_auth: tls_c::ClientAuthType::default(),
            client_cas: None,
            cipher_suites: None,
            session_tickets_disabled: false,
            min_version: 0,
            max_version: 0,
            curve_preferences: None,
            renegotiation: tls_c::RenegotiationSupport::default(),
            key_log_writer: None,
            encrypted_client_hello_config_list: Vec::new(),
            encrypted_client_hello_rejection_verify: None,
            encrypted_client_hello_keys: Vec::new(),
            get_encrypted_client_hello_keys: None,
            session_id_generator: None,
        }
    }

    async fn stream_conn_context_inner(
        &self,
        ctx: &CancellationToken,
        c: Box<dyn NetConn>,
        tls_check: TlsConnCheck,
        direct_net: Option<SharedConn>,
        buffered_incoming: Option<Arc<dyn TlsBufferedIncoming>>,
        metadata: &Metadata,
    ) -> Result<Box<dyn NetConn>> {
        const PACKETADDR_SEQ_PACKET_MAGIC_ADDRESS: &str = "sp.packet-addr.v2fly.arpa";

        let shared = SharedConn::from_boxed(c);
        let mut done = setup_context_for_conn(ctx, shared.clone());

        let result: Result<Box<dyn NetConn>> = async {
            let mut conn: Box<dyn murmur_common_net::io::Stream> = Box::new(OldConnAsStream(shared));

            if let Some(enc) = &self.encryption {
                conn = Box::new(enc.handshake(conn).await?);
            }

            let dst_addr = if metadata.network == murmur_constant::metadata::NetWork::UDP {
                let udp_metadata = if self.option.packet_addr {
                    Metadata {
                        network: murmur_constant::metadata::NetWork::UDP,
                        host: PACKETADDR_SEQ_PACKET_MAGIC_ADDRESS.to_owned(),
                        dst_port: 443,
                        type_: murmur_constant::metadata::Type::default(),
                        src_ip: None,
                        dst_ip: None,
                        src_geo_ip: None,
                        dst_geo_ip: None,
                        src_ipasn: String::new(),
                        dst_ipasn: String::new(),
                        src_port: 0,
                        in_ip: None,
                        in_port: 0,
                        in_name: String::new(),
                        in_user: String::new(),
                        rematch_name: String::new(),
                        dns_mode: murmur_constant::dns::DNSMode::default(),
                        uid: 0,
                        process: String::new(),
                        process_path: String::new(),
                        special_proxy: String::new(),
                        special_rules: String::new(),
                        remote_dst: String::new(),
                        dscp: 0,
                        raw_src_addr: None,
                        raw_dst_addr: None,
                        sniff_host: String::new(),
                    }
                } else {
                    Metadata {
                        network: murmur_constant::metadata::NetWork::UDP,
                        dst_ip: metadata.dst_ip,
                        dst_port: metadata.dst_port,
                        type_: murmur_constant::metadata::Type::default(),
                        src_ip: None,
                        src_geo_ip: None,
                        dst_geo_ip: None,
                        src_ipasn: String::new(),
                        dst_ipasn: String::new(),
                        src_port: 0,
                        in_ip: None,
                        in_port: 0,
                        in_name: String::new(),
                        in_user: String::new(),
                        rematch_name: String::new(),
                        host: String::new(),
                        dns_mode: murmur_constant::dns::DNSMode::default(),
                        uid: 0,
                        process: String::new(),
                        process_path: String::new(),
                        special_proxy: String::new(),
                        special_rules: String::new(),
                        remote_dst: String::new(),
                        dscp: 0,
                        raw_src_addr: None,
                        raw_dst_addr: None,
                        sniff_host: String::new(),
                    }
                };
                parse_vless_addr(&udp_metadata, self.option.xudp)
            } else {
                parse_vless_addr(metadata, false)
            };

            // The reference accepts the VLESS encryption conn as a Vision transport even when no
            // TLS session is present; Vision then pads without ever switching to direct mode.
            let tls_check = vision_capability(tls_check, self.encryption.is_some());
            let stream = self.client.stream_conn(conn, tls_check, direct_net, buffered_incoming, &dst_addr)?;
            let old_conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(stream));
            Ok(old_conn)
        }
        .await;

        let mut result_err = result.as_ref().err().map(|e| anyhow!("{e}"));
        done.call(&mut result_err).await;

        result
    }
}

fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn set_user_agent(headers: &mut Vec<(String, String)>) {
    if header_get(headers, "User-Agent").is_some() {
        return;
    }
    headers.push(("User-Agent".to_owned(), rand_user_agent()));
}

fn parse_vless_addr(metadata: &Metadata, xudp: bool) -> DstAddr {
    let mut addr_type = 0u8;
    let mut addr: Vec<u8> = Vec::new();
    match metadata.addr_type() {
        AddrType::ATYP_IPV4 => {
            addr_type = vless_client::ATYP_IPV4;
            if let Some(std::net::IpAddr::V4(ip)) = metadata.dst_ip {
                addr = ip.octets().to_vec();
            }
        }
        AddrType::ATYP_IPV6 => {
            addr_type = vless_client::ATYP_IPV6;
            if let Some(std::net::IpAddr::V6(ip)) = metadata.dst_ip {
                addr = ip.octets().to_vec();
            }
        }
        AddrType::ATYP_DOMAIN_NAME => {
            addr_type = vless_client::ATYP_DOMAIN_NAME;
            addr = Vec::with_capacity(metadata.host.len() + 1);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the VLESS domain-name length field is one byte, so a longer host is not expressible on the wire"
            )]
            let host_length = metadata.host.len() as u8;
            addr.push(host_length);
            addr.extend_from_slice(metadata.host.as_bytes());
        }
        _ => {}
    }

    DstAddr {
        udp: metadata.network == murmur_constant::metadata::NetWork::UDP,
        addr_type,
        addr,
        port: metadata.dst_port,
        mux: metadata.network == murmur_constant::metadata::NetWork::UDP && xudp,
    }
}

fn build_rustls_client_config(
    server_name: &str,
    skip_cert_verify: bool,
    next_protos: &[String],
) -> Result<Arc<rustls::ClientConfig>> {
    let mut config = if skip_cert_verify {
        rustls::ClientConfig::builder_with_provider(Arc::new(murmur_component_tls::tls12_sequence_nonce_provider()))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerify))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder_with_provider(Arc::new(murmur_component_tls::tls12_sequence_nonce_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates((*ca::config::get_cert_pool()).clone())
            .with_no_client_auth()
    };
    config.alpn_protocols = next_protos.iter().map(|p| p.as_bytes().to_vec()).collect();
    let _ = server_name;
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct NoCertVerify;

impl rustls::client::danger::ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Resolves the target address through murmur's dialer, never the OS resolver the default-resolver hook
/// aborts on; a literal still skips the resolver.
async fn resolve_h3_target(ctx: &CancellationToken, address: &str, prefer: DNSPrefer) -> Result<SocketAddr> {
    let (host, port, _) = murmur_common_net::tcpip::split_host_port(address)?;
    let port: u16 = parse_address_port(&port);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let ip = resolve_ip_with_resolver(ctx, &host, prefer, proxy_server_host_resolver().as_deref())
        .await
        .map_err(|err| anyhow!("xhttp: cannot resolve {address}: {err}"))?;
    Ok(SocketAddr::new(ip, port))
}

/// Dials one HTTP/3 QUIC connection for `xhttp::client::DialQuicFunc`; see the module doc for why
/// this bypasses `transport::tuic::common::dial_quic` and the adapter's dialer.
async fn dial_h3_quic(
    ctx: CancellationToken,
    address: String,
    tls_config: tls_c::Config,
    quic_cfg: xhttp::client::QuicConfig,
    prefer: DNSPrefer,
) -> Result<quinn::Connection> {
    let remote = resolve_h3_target(&ctx, &address, prefer).await?;

    let bind_addr: SocketAddr = if remote.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let socket = murmur_component::dialer::control::bind_quic_client_socket(bind_addr)
        .map_err(|err| anyhow!("failed to bind QUIC endpoint socket: {err}"))?;
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime found"))?;
    let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
        .map_err(|err| anyhow!("failed to create QUIC endpoint: {err}"))?;

    let rustls_config =
        build_rustls_client_config(&tls_config.server_name, tls_config.insecure_skip_verify, &tls_config.next_protos)?;
    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from((*rustls_config).clone())
        .map_err(|err| anyhow!("invalid QUIC TLS config: {err}"))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    let mut transport_config = quinn::TransportConfig::default();
    if let Ok(max_incoming_streams) = u32::try_from(quic_cfg.max_incoming_streams) {
        transport_config.max_concurrent_bidi_streams(max_incoming_streams.into());
    }
    if quic_cfg.keep_alive_period > std::time::Duration::ZERO {
        transport_config.keep_alive_interval(Some(quic_cfg.keep_alive_period));
    }
    if quic_cfg.max_idle_timeout > std::time::Duration::ZERO {
        if let Ok(idle) = quic_cfg.max_idle_timeout.try_into() {
            transport_config.max_idle_timeout(Some(idle));
        }
    }
    client_config.transport_config(Arc::new(transport_config));

    let connecting = endpoint
        .connect_with(client_config, remote, &tls_config.server_name)
        .map_err(|err| anyhow!("failed to dial QUIC connection: {err}"))?;
    connecting.await.map_err(|err| anyhow::Error::from(err).context(format!("opening quic connection to {remote}")))
}

#[async_trait]
impl CProxyAdapter for Vless {
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
        let c = self.dial_conn(ctx).await.map_err(|err| anyhow!("{} connect error: {err}", self.base.addr))?;

        let c = self
            .stream_conn_context(ctx, c, metadata)
            .await
            .map_err(|err| anyhow!("{} connect error: {err}", self.base.addr))?;

        // S11: remove with std-compat (transport-vless/transport-vmess ws/tls/http/h2/gun chain still old murmur_std_compat::net::Conn based)
        Ok(new_conn(Box::new(OldConnAsStream(c)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.base.resolve_udp(ctx, metadata).await?;

        let c = self.dial_conn(ctx).await.map_err(|err| anyhow!("{} connect error: {err}", self.base.addr))?;

        let c = self
            .stream_conn_context(ctx, c, metadata)
            .await
            .map_err(|err| anyhow!("{} connect error: {err}", self.base.addr))?;

        let udp_addr = metadata.udp_addr().ok_or_else(|| anyhow!("{} is not a udp destination", self.base.addr))?;
        let r_addr = SocketAddr::new(udp_addr.ip, udp_addr.port);

        let inner_pc: Arc<dyn PacketConn> = if self.option.xudp {
            let id = if metadata.source_valid() { global_id(&metadata.source_address()) } else { [0; 8] };
            let target = Socksaddr::from_ip(r_addr.ip(), r_addr.port());
            Arc::from(xudp::new_xudp_packet_conn(c, id, target))
        } else if self.option.packet_addr {
            let conn = self.client.packet_conn(Box::new(OldConnAsStream(c)), r_addr);
            Arc::from(packetaddr::wrap_packet_conn(conn))
        } else {
            Arc::from(self.client.packet_conn(Box::new(OldConnAsStream(c)), r_addr))
        };

        let pc = new_thread_safe_packet_conn(inner_pc).into_packet_conn();
        let self_arc = self.self_arc()?;
        // S11: remove with std-compat (transport-vless::Client::packet_conn/common_net::new_thread_safe_packet_conn still old murmur_std_compat::net::PacketConn based)
        Ok(new_packet_conn(super::base::arc_packet_conn_as_datagram(pc), self_arc))
    }

    fn support_uot(&self) -> bool {
        true
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.base.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        let mut errs: Vec<String> = Vec::new();
        if let Some(gun_client) = &self.gun_client {
            if let Err(err) = gun_client.close() {
                errs.push(err.to_string());
            }
        }
        if let Some(xhttp_client) = &self.xhttp_client {
            if let Err(err) = xhttp_client.close() {
                errs.push(err.to_string());
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(errs.join("\n")))
        }
    }
}

impl Vless {
    async fn dial_conn(&self, ctx: &CancellationToken) -> Result<Box<dyn NetConn>> {
        match self.option.network.as_str() {
            "grpc" => {
                let gun_client =
                    self.gun_client.as_ref().ok_or_else(|| anyhow!("grpc network always builds gun_client"))?;
                gun_client.dial().await
            }
            "xhttp" => {
                let xhttp_client =
                    self.xhttp_client.as_ref().ok_or_else(|| anyhow!("xhttp network always builds xhttp_client"))?;
                xhttp_client.dial(ctx.clone()).await
            }
            _ => {
                let dialer =
                    self.base.dialer.clone().ok_or_else(|| anyhow!("Vless.base.dialer is always set by Vless::new"))?;
                let stream = dialer.dial_context(ctx, "tcp", &self.base.addr).await?;
                Ok(Box::new(StreamAsOldConn::new(stream))) // S11: remove with std-compat
            }
        }
    }
}

#[async_trait]
impl ProxyAdapter for Vless {
    fn dial_options(&self) -> Vec<DialerOption> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

#[cfg(test)]
mod tls_conn_tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use murmur_component_tls::utls;
    use murmur_reality::{reality_server_accept, DialDest, RealityClientConfig, RealityServerConfig};
    use murmur_testsupport::TLS_CONFIG;
    use murmur_testsupport_probe::ensure_test_crypto_provider;

    fn test_material() -> TlsMaterial {
        TlsMaterial {
            addr: "example.com:443".to_owned(),
            tls: true,
            alpn: Vec::new(),
            skip_cert_verify: true,
            name_cert_verify: String::new(),
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
            client_fingerprint: String::new(),
            server_name: String::new(),
            ech_config: None,
            shadow_tls_config: None,
            jls_config: None,
            restls_config: None,
            reality_config: None,
            security_mode: String::new(),
        }
    }

    /// Regression test for the `Box<C>`-blanket-`Conn`-impl bug: before `TlsConn`'s blanket was
    /// bound on `ConcreteConn` instead of `NetConn`, `tls_conn.as_any()` on the
    /// `Box<dyn TlsConn>` `stream_tls_conn` returns here answered for the box itself, so
    /// XTLS vision's TLS capability check always saw `Unsupported` even for a real handshake — the
    /// production case this crate's own review flagged for this module's plain-`tcp` network.
    #[tokio::test]
    async fn stream_tls_conn_exposes_the_real_tls_identity_through_the_box() {
        ensure_test_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else { return };
            let server = utls::server(Box::new(stream), TLS_CONFIG.clone());
            let ctx = CancellationToken::new();
            if server.handshake_context(&ctx).await.is_ok() {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let conn: Box<dyn NetConn> = Box::new(stream);
        let ctx = CancellationToken::new();
        let tls_conn = stream_tls_conn(&test_material(), &ctx, conn, false, false).await.expect("tls handshake");

        assert!(
            matches!(TlsConnCheck::evaluate(tls_conn.as_ref()), TlsConnCheck::Supported { .. }),
            "expected the boxed TLS conn's real identity, not the Box<dyn TlsConn> itself"
        );
    }

    #[tokio::test]
    async fn stream_tls_conn_supports_chrome_mtls_with_h2_alpn() {
        ensure_test_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut server_config = (**TLS_CONFIG).clone();
        server_config.client_auth = utls::ClientAuthType::REQUIRE_AND_VERIFY_CLIENT_CERT;
        server_config.client_cas = Some(
            murmur_component_ca::keypair::load_certificates(murmur_testsupport::tls_auth_certificate())
                .expect("client CA"),
        );

        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else { return };
            let mut server = utls::server(Box::new(stream), Arc::new(server_config));
            let ctx = CancellationToken::new();
            let result = server.handshake_context(&ctx).await;
            eprintln!("direct chrome mtls server handshake: {result:?}");
            if result.is_ok() {
                let mut request = [0u8; 5];
                server.read_exact(&mut request).await.expect("server read");
                assert_eq!(&request, b"hello");
                server.write_all(b"world").await.expect("server write");
            }
        });

        let material = TlsMaterial {
            client_fingerprint: "chrome".to_owned(),
            certificate: murmur_testsupport::tls_auth_certificate().to_owned(),
            private_key: murmur_testsupport::tls_auth_private_key().to_owned(),
            ..test_material()
        };
        let stream = TcpStream::connect(addr).await.expect("connect");
        let conn: Box<dyn NetConn> = Box::new(stream);
        let ctx = CancellationToken::new();
        let mut tls_conn = stream_tls_conn(&material, &ctx, conn, true, false).await.expect("h2 mTLS handshake");
        tls_conn.write_all(b"hello").await.expect("client write");
        let mut reply = [0u8; 5];
        tls_conn.read_exact(&mut reply).await.expect("client read");
        assert_eq!(&reply, b"world");
    }

    fn reality_keypair() -> ([u8; 32], [u8; 32]) {
        use rand::RngCore as _;
        let mut private = [0u8; 32];
        rand::rng().fill_bytes(&mut private);
        private[0] &= 0xF8;
        private[31] &= 127;
        private[31] |= 64;
        let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
        (private, public)
    }

    /// The documented VLESS `flow=xtls-rprx-vision` + REALITY combination: the capability the
    /// adapter snapshots for Vision must come from the authenticated REALITY conn, not be lost in
    /// the erased wrapper.
    #[tokio::test]
    async fn reality_conn_is_a_supported_tls13_conn_for_vision() {
        ensure_test_crypto_provider();
        let (server_private, server_public) = reality_keypair();
        let short_id = [0x2Au8; 8];
        let mut server_names = HashSet::new();
        server_names.insert("example.com".to_owned());
        let mut short_ids = HashSet::new();
        short_ids.insert(short_id);
        let dial: DialDest = Arc::new(|| {
            Box::pin(async {
                Err::<murmur_reality::BoxedStream, std::io::Error>(std::io::Error::other(
                    "fallback dest is not dialled",
                ))
            })
        });
        let server_cfg =
            RealityServerConfig::new(server_private, server_names, short_ids, Some(Duration::from_secs(60)), dial);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else { return };
            let mut stream = reality_server_accept(stream, &server_cfg).await.expect("reality authenticate");
            let mut ping = [0u8; 1];
            stream.read_exact(&mut ping).await.expect("post-handshake byte");
            assert_eq!(&ping, b"!");
        });

        let material = TlsMaterial {
            reality_config: Some(Arc::new(RealityClientConfig { public_key: server_public, short_id })),
            client_fingerprint: "chrome".to_owned(),
            ..test_material()
        };
        let ctx = CancellationToken::new();
        let conn: Box<dyn NetConn> = Box::new(TcpStream::connect(addr).await.expect("connect"));
        let mut tls_conn =
            tokio::time::timeout(Duration::from_secs(10), stream_tls_conn(&material, &ctx, conn, false, false))
                .await
                .expect("reality handshake must finish")
                .expect("reality handshake");
        tls_conn.write_all(b"!").await.expect("write inside the reality session");

        assert!(
            matches!(
                TlsConnCheck::evaluate(tls_conn.as_ref()),
                TlsConnCheck::Supported { handshake_complete: true, version: utls::VERSION_TLS13 }
            ),
            "an authenticated REALITY conn must reach Vision as a supported TLS 1.3 session"
        );
        server_task.await.expect("reality server task");
    }

    /// The fix must not widen the gate: an erased stream with no authenticated handshake behind it
    /// stays unusable for Vision.
    #[tokio::test]
    async fn an_unauthenticated_erased_stream_is_not_accepted_for_vision() {
        let (conn, _peer) = murmur_common_net::deadline::pipe_sing::pipe();
        let erased: Box<dyn TlsConn> = Box::new(utls::ErasedTlsConn(Box::new(OldConnAsStream(conn))));
        assert!(matches!(TlsConnCheck::evaluate(erased.as_ref()), TlsConnCheck::Unsupported));
    }
}

#[cfg(test)]
mod jls_option_tests {
    use super::*;

    const JLS: &str = "jls-opts:\n  username: user\n  password: pass\n";
    const REALITY: &str = "reality-opts:\n  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
    const SHADOW_TLS: &str = "shadow-tls-opts:\n  password: p\n  version: 3\n";
    const HEAD: &str = "name: v\nserver: example.com\nport: 443\nuuid: 00000000-0000-0000-0000-000000000001\n";

    fn new_err(extra: &str) -> String {
        let yaml = format!("{HEAD}tls: true\n{extra}");
        let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        Vless::new(option).err().map(|err| err.to_string()).expect("rejected")
    }

    #[test]
    fn credentials_select_jls_while_empty_ones_select_nothing() {
        let yaml = format!("{HEAD}tls: true\n{JLS}");
        let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        let vless = Vless::new(option).expect("accepted");
        let config = vless.jls_config.as_ref().expect("JLS selected");
        assert_eq!((config.user.username.as_str(), config.user.password.as_str()), ("user", "pass"));

        let yaml = format!("{HEAD}tls: true\njls-opts:\n  username: \"\"\n  password: \"\"\n");
        let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        assert!(Vless::new(option).expect("accepted").jls_config.is_none());

        // The credential has to be present and empty: a block that leaves it out already fails to
        // decode (see `crate::jls`), so only this reaches the JLS config parse.
        assert_eq!(new_err("jls-opts:\n  username: user\n  password: \"\"\n"), "jls: password is required");
    }

    #[test]
    fn jls_is_exclusive_with_the_other_security_modes() {
        assert_eq!(new_err(&format!("{JLS}{SHADOW_TLS}")), "security modes are mutually exclusive: ShadowTLS, JLS");
        assert_eq!(new_err(&format!("{JLS}{REALITY}")), "security modes are mutually exclusive: JLS, REALITY");
    }

    #[test]
    fn jls_requires_tls() {
        let yaml = format!("{HEAD}tls: false\n{JLS}");
        let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        let err = Vless::new(option).err().map(|err| err.to_string()).expect("rejected");
        assert_eq!(err, "JLS requires TLS");
    }

    #[test]
    fn xhttp_download_settings_parse_their_own_jls_block() {
        // Construction validates `download-settings` only for the xhttp network, so the network has
        // to select xhttp before either error is reachable; the download credential is present and
        // empty for the same reason as above.
        let download = "xhttp-opts:\n  download-settings:\n    server: download.example.com\n    jls-opts:\n      username: dl\n      password: \"\"\n";
        assert_eq!(new_err(&format!("network: xhttp\n{JLS}{download}")), "jls: password is required");

        let download = "xhttp-opts:\n  download-settings:\n    server: download.example.com\n    jls-opts:\n      username: dl\n      password: dlp\n";
        assert_eq!(
            new_err(&format!("network: xhttp\n{SHADOW_TLS}{download}")),
            "xhttp download-settings security modes are mutually exclusive: ShadowTLS, JLS"
        );

        let yaml = format!("{HEAD}tls: true\nnetwork: xhttp\n{JLS}{download}");
        let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        assert!(Vless::new(option).expect("accepted").xhttp_client.is_some());
    }
}

#[cfg(test)]
mod restls_option_tests {
    use super::*;

    const RESTLS: &str = "restls-opts:\n  password: p\n  version-hint: tls13\n";
    const JLS: &str = "jls-opts:\n  username: user\n  password: pass\n";
    const SHADOW_TLS: &str = "shadow-tls-opts:\n  password: p\n  version: 3\n";
    const HEAD: &str = "name: v\nserver: example.com\nport: 443\nuuid: 00000000-0000-0000-0000-000000000001\n";

    fn new_err(extra: &str) -> String {
        let yaml = format!("{HEAD}tls: true\n{extra}");
        let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        Vless::new(option).err().map(|err| err.to_string()).expect("rejected")
    }

    #[test]
    fn restls_is_exclusive_with_the_other_security_modes_and_requires_tls() {
        assert_eq!(
            new_err(&format!("{RESTLS}{SHADOW_TLS}")),
            "security modes are mutually exclusive: ShadowTLS, Restls"
        );
        assert_eq!(new_err(&format!("{RESTLS}{JLS}")), "security modes are mutually exclusive: Restls, JLS");

        let yaml = format!("{HEAD}tls: false\n{RESTLS}");
        let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        let err = Vless::new(option).err().map(|err| err.to_string()).expect("rejected");
        assert_eq!(err, "Restls requires TLS");
    }

    /// `restls-opts` is parsed with the configured server name verbatim — it is not defaulted to
    /// the server address the way Trojan's `sni` is.
    #[test]
    fn the_restls_server_name_is_the_configured_servername() {
        let yaml = format!("{HEAD}tls: true\nservername: sni.example\n{RESTLS}");
        let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        let vless = Vless::new(option).expect("accepted");
        let config = vless.restls_config.as_ref().expect("Restls selected");
        assert_eq!(config.server_name, "sni.example");
    }

    #[test]
    fn an_empty_block_leaves_the_security_mode_field_alone() {
        let yaml = format!("{HEAD}tls: true\nrestls-opts:\n  password: \"\"\n  version-hint: \"\"\n");
        let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        assert!(Vless::new(option).expect("accepted").restls_config.is_none());
    }
}

/// XTLS Vision wraps the raw TLS record stream. An outbound that cannot hand it a conn reporting
/// its TLS session capability must be rejected at construction: accepting it made every dial log
/// `vision: not a valid supported TLS connection` and fail.
#[cfg(test)]
mod vision_option_tests {
    use super::*;

    const HEAD: &str = concat!(
        "name: v\nserver: example.com\nport: 443\n",
        "uuid: 00000000-0000-0000-0000-000000000001\nflow: xtls-rprx-vision\n",
    );
    const REALITY: &str = "reality-opts:\n  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";

    fn new_err(extra: &str) -> String {
        let yaml = format!("{HEAD}{extra}");
        let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        Vless::new(option).err().map(|err| err.to_string()).expect("rejected")
    }

    fn encryption_value() -> String {
        let (_, client, _) = encryption::key::gen_mlkem768("").expect("gen_mlkem768");
        let (_, password, _) = encryption::key::gen_x25519("").expect("gen_x25519");
        format!("mlkem768x25519plus.native.0rtt.{password}.{client}")
    }

    /// The framed transports build their conn around the TLS session and never evaluate its
    /// capability, so without encryption the pair has to fail here rather than on every dial.
    #[test]
    fn vision_over_a_framed_transport_is_rejected_without_encryption() {
        for network in ["ws", "http", "h2", "grpc", "xhttp"] {
            assert_eq!(
                new_err(&format!("tls: true\nnetwork: {network}\n")),
                format!("xtls-rprx-vision only supports the tcp network, not {network}")
            );
        }
    }

    /// Encryption wraps the selected transport before Vision sees it, so the framed transports are
    /// valid when the encryption conn is what Vision pads.
    #[test]
    fn vision_over_a_framed_transport_is_accepted_with_encryption() {
        let encryption = encryption_value();
        for network in ["ws", "http", "h2", "grpc", "xhttp"] {
            let yaml = format!("{HEAD}tls: true\nnetwork: {network}\nencryption: {encryption}\n");
            let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
            assert!(Vless::new(option).is_ok(), "{network}");
        }
    }

    #[test]
    fn vision_without_tls_or_encryption_is_rejected() {
        assert_eq!(new_err("tls: false\n"), "xtls-rprx-vision requires TLS or VLESS encryption");
        assert_eq!(new_err("tls: false\nencryption: none\n"), "xtls-rprx-vision requires TLS or VLESS encryption");
    }

    /// The reference accepts the VLESS encryption conn as a Vision transport, so real encryption
    /// makes the same shape valid without outer TLS.
    #[test]
    fn vision_without_tls_accepts_real_encryption() {
        let encryption = encryption_value();
        let yaml = format!("{HEAD}tls: false\nencryption: {encryption}\n");
        let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        assert!(Vless::new(option).is_ok());
    }

    #[test]
    fn an_encrypted_conn_without_tls_reaches_vision_as_padding_only() {
        let supported = TlsConnCheck::Supported { handshake_complete: true, version: 0x0304 };
        assert!(matches!(vision_capability(TlsConnCheck::Unsupported, true), TlsConnCheck::NoTls));
        assert!(matches!(vision_capability(TlsConnCheck::Unsupported, false), TlsConnCheck::Unsupported));
        assert!(matches!(
            vision_capability(supported, true),
            TlsConnCheck::Supported { handshake_complete: true, version: 0x0304 }
        ));
    }

    /// ShadowTLS, Restls and JLS replace the TLS session, so the conn Vision receives is erased
    /// and reports no session capability.
    #[test]
    fn vision_with_a_security_mode_that_replaces_tls_is_rejected() {
        for (extra, mode) in [
            ("shadow-tls-opts:\n  password: p\n  version: 3\n", "ShadowTLS"),
            ("restls-opts:\n  password: p\n  version-hint: tls13\n", "Restls"),
            ("jls-opts:\n  username: user\n  password: pass\n", "JLS"),
        ] {
            assert_eq!(
                new_err(&format!("tls: true\n{extra}")),
                format!("xtls-rprx-vision requires the TLS session that {mode} replaces")
            );
        }
    }

    /// The transports that do expose a TLS session keep accepting Vision.
    #[test]
    fn vision_on_tcp_with_a_real_tls_session_is_accepted() {
        let cases = [
            "tls: true\n".to_owned(),
            "tls: true\nnetwork: tcp\n".to_owned(),
            "tls: true\nnetwork: raw\n".to_owned(),
            format!("tls: true\nclient-fingerprint: chrome\n{REALITY}"),
        ];
        for extra in cases {
            let yaml = format!("{HEAD}{extra}");
            let option: VlessOption = yaml_serde::from_str(&yaml).expect("option decodes");
            assert!(Vless::new(option).is_ok(), "{extra}");
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod udp_mode_tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use murmur_constant::metadata::NetWork;

    #[tokio::test]
    async fn selected_udp_mode_produces_the_corresponding_vless_wire_packets() {
        for (encoding, command, destination, packet) in [
            ("xudp", 3, None, vec![0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 1, 2, 3, 4, 0, 3, b'a', b'b', b'c']),
            ("packetaddr", 2, Some("sp.packet-addr.v2fly.arpa"), vec![0, 10, 1, 1, 2, 3, 4, 0, 53, b'a', b'b', b'c']),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().expect("listener address").port();
            let server = tokio::spawn(async move {
                let (mut conn, _) = listener.accept().await.expect("accept");
                let mut preface = [0u8; 19];
                conn.read_exact(&mut preface).await.expect("VLESS preface");
                assert_eq!(preface[0], 0);
                assert_eq!(preface[17], 0);
                assert_eq!(preface[18], command);
                if let Some(host) = destination {
                    let mut address = vec![0u8; 3 + 1 + host.len()];
                    conn.read_exact(&mut address).await.expect("VLESS address");
                    assert_eq!(&address[..4], &[1, 187, 2, host.len() as u8]);
                    assert_eq!(&address[4..], host.as_bytes());
                }
                let mut data = vec![0u8; packet.len()];
                conn.read_exact(&mut data).await.expect("UDP packet");
                assert_eq!(data, packet);
                conn.write_all(&[0, 0]).await.expect("VLESS response");
                if command == 3 {
                    conn.write_all(&[0, 4, 0, 0, 2, 1, 0, 3, b'x', b'y', b'z']).await.expect("XUDP reply");
                } else {
                    conn.write_all(&[0, 10, 1, 1, 2, 3, 4, 0, 53, b'x', b'y', b'z']).await.expect("packetaddr reply");
                }
            });
            let adapter = Vless::new(VlessOption {
                name: "udp-wire".to_owned(),
                server: "127.0.0.1".to_owned(),
                port,
                uuid: "00000000-0000-0000-0000-000000000001".to_owned(),
                udp: true,
                packet_encoding: encoding.to_owned(),
                ..Default::default()
            })
            .expect("adapter");
            let mut metadata = Metadata {
                network: NetWork::UDP,
                dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
                dst_port: 53,
                ..Default::default()
            };
            let target = SocketAddr::new(metadata.dst_ip.expect("target IP"), metadata.dst_port);
            tokio::time::timeout(Duration::from_secs(3), async {
                let conn =
                    adapter.listen_packet_context(&CancellationToken::new(), &mut metadata).await.expect("packet conn");
                conn.as_packet_conn()
                    .write_to(b"abc", &murmur_std_compat::net::UdpAddr::from(target))
                    .await
                    .expect("send UDP packet");
                let mut reply = [0u8; 8];
                let (size, source) = conn.as_packet_conn().read_from(&mut reply).await.expect("receive UDP packet");
                assert_eq!(&reply[..size], b"xyz");
                assert_eq!(
                    murmur_common_net::io::old_addr_to_socket_addr(source.as_ref()).expect("reply address"),
                    target
                );
                server.await.expect("server");
            })
            .await
            .expect("UDP wire exchange timed out");
        }
    }

    #[tokio::test]
    async fn xudp_allows_second_destination_while_reply_read_is_pending() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("address").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut preface = [0u8; 19];
            stream.read_exact(&mut preface).await.expect("VLESS preface");
            assert_eq!(preface[18], 3);
            let mut first = [0u8; 19];
            stream.read_exact(&mut first).await.expect("first XUDP packet");
            assert_eq!(&first, &[0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 1, 2, 3, 4, 0, 3, b'a', b'b', b'c']);
            let mut second = [0u8; 19];
            stream.read_exact(&mut second).await.expect("second XUDP packet");
            assert_eq!(&second, &[0, 12, 0, 0, 2, 1, 2, 0, 54, 1, 5, 6, 7, 8, 0, 3, b'd', b'e', b'f']);
            stream
                .write_all(&[0, 0, 0, 12, 0, 0, 2, 1, 2, 0, 54, 1, 5, 6, 7, 8, 0, 3, b'x', b'y', b'z'])
                .await
                .expect("VLESS and XUDP response");
        });
        let adapter = Vless::new(VlessOption {
            name: "xudp-destinations".to_owned(),
            server: "127.0.0.1".to_owned(),
            port,
            uuid: "00000000-0000-0000-0000-000000000001".to_owned(),
            udp: true,
            packet_encoding: "xudp".to_owned(),
            ..Default::default()
        })
        .expect("adapter");
        let first: SocketAddr = "1.2.3.4:53".parse().expect("first target");
        let second: SocketAddr = "5.6.7.8:54".parse().expect("second target");
        let mut metadata =
            Metadata { network: NetWork::UDP, dst_ip: Some(first.ip()), dst_port: first.port(), ..Default::default() };
        tokio::time::timeout(Duration::from_secs(3), async {
            let conn =
                adapter.listen_packet_context(&CancellationToken::new(), &mut metadata).await.expect("packet conn");
            conn.as_packet_conn()
                .write_to(b"abc", &murmur_std_compat::net::UdpAddr::from(first))
                .await
                .expect("first datagram");
            let reader = Arc::clone(&conn);
            let pending_reply = tokio::spawn(async move {
                let mut reply = [0u8; 8];
                let (len, address) = reader.as_packet_conn().read_from(&mut reply).await.expect("reply");
                (reply, len, address)
            });
            tokio::task::yield_now().await;
            conn.as_packet_conn()
                .write_to(b"def", &murmur_std_compat::net::UdpAddr::from(second))
                .await
                .expect("second datagram");
            let (reply, len, address) = pending_reply.await.expect("reader");
            assert_eq!(&reply[..len], b"xyz");
            assert_eq!(murmur_common_net::io::old_addr_to_socket_addr(address.as_ref()).expect("source"), second);
            server.await.expect("server");
        })
        .await
        .expect("XUDP concurrent exchange timed out");
    }
}

#[cfg(test)]
mod resolve_h3_target_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use async_trait::async_trait;
    use hickory_proto::op::Message;

    use super::*;
    use murmur_component::resolver::resolver::{set_proxy_server_host_resolver, Resolver, SharedResolver};

    /// Answers one canned address and records every host it was asked for.
    struct RecordingResolver {
        answer: IpAddr,
        asked: parking_lot::Mutex<Vec<String>>,
    }

    impl RecordingResolver {
        fn answer(&self, host: &str) -> Result<Vec<IpAddr>> {
            self.asked.lock().push(host.to_owned());
            Ok(vec![self.answer])
        }
    }

    #[async_trait]
    impl Resolver for RecordingResolver {
        async fn lookup_ip(&self, _ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
            self.answer(host)
        }

        async fn lookup_ipv4(&self, _ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
            self.answer(host)
        }

        async fn lookup_ipv6(&self, _ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
            self.answer(host)
        }

        async fn resolve_ech(&self, _ctx: &CancellationToken, _host: &str) -> Result<Vec<u8>> {
            panic!("the recording resolver only resolves addresses")
        }

        async fn exchange_context(&self, _ctx: &CancellationToken, _m: &Message) -> Result<Message> {
            panic!("the recording resolver only resolves addresses")
        }

        fn invalid(&self) -> bool {
            true
        }

        fn clear_cache(&self) {}

        fn reset_connection(&self) {}
    }

    #[tokio::test]
    async fn h3_names_resolve_through_the_port_resolver_and_literals_do_not() {
        let previous: Option<SharedResolver> = proxy_server_host_resolver();
        let resolver = Arc::new(RecordingResolver {
            answer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            asked: parking_lot::Mutex::new(Vec::new()),
        });
        let installed = Arc::clone(&resolver);
        let installed: SharedResolver = installed;
        set_proxy_server_host_resolver(Some(installed));

        let ctx = CancellationToken::new();
        let target = resolve_h3_target(&ctx, "example.com:443", DNSPrefer::DUAL_STACK).await.expect("resolve");
        assert_eq!(SocketAddr::from(([192, 0, 2, 7], 443)), target);
        assert_eq!(vec!["example.com".to_owned()], *resolver.asked.lock());

        let literal: SocketAddr = "192.0.2.9:8443".parse().unwrap();
        let resolved = resolve_h3_target(&ctx, &literal.to_string(), DNSPrefer::DUAL_STACK).await.expect("literal");
        assert_eq!(literal, resolved);
        assert_eq!(vec!["example.com".to_owned()], *resolver.asked.lock(), "a literal must not reach the resolver");

        set_proxy_server_host_resolver(previous);
    }
}
