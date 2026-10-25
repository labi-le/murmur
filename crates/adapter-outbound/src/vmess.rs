//! `VMess` outbound adapter; its AEAD client is bridged through the in-file `sing_vmess_shim`.
//!
//! The `VMess` AEAD client this adapter dials through is not available from any crate in this tree
//! and is not part of the wave's canonical vocabulary. `sing_vmess_shim` keeps the option
//! validation faithful (UUID parsing, security-cipher validation), but every dial method returns
//! `NEEDED CRATE: sing-vmess client (AEAD protocol)` instead of the real handshake (see the wave
//! report). The connection helper is called with the adapter's own `Arc<Vmess>`; the self-`Arc`
//! problem is resolved with `Arc::new_cyclic` + a `self_weak: Weak<Self>` field, the convention
//! this wave settled on for every `adapter::outbound` unit.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use murmur_common::utils::global_id::global_id;
use murmur_common_net::tcpip::split_host_port;
use murmur_component::dialer::bind::join_host_port;
use murmur_component_ca as ca;
use murmur_component_ech as ech;
use murmur_component_proxydialer as proxydialer;
use murmur_component_tls as tls_c;
use murmur_constant::adapters::AdapterType;
use murmur_constant::adapters::{Conn as CConn, PacketConn as CPacketConn, ProxyAdapter as CProxyAdapter, ProxyInfo};
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_ntp as ntp;
use murmur_sing::metadata::{parse_socksaddr_host_port, Socksaddr};
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport::gun;
use murmur_transport_mekya as mekya;
use murmur_transport_mkcp as mkcp;
use murmur_transport_shadowtls as shadowtls;
use murmur_transport_vmess::h2::{stream_h2_conn, H2Config};
use murmur_transport_vmess::http::{stream_http_conn, HttpConfig};
use murmur_transport_vmess::tls::{stream_tls_conn, TlsConfig};
use murmur_transport_vmess::websocket::{stream_websocket_conn_public, WebsocketConfig};

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::ech::ECHOptions;
use super::shadowtls::ShadowTLSOptions;
use super::tlsmirror::TLSMirrorOptions;

#[must_use]
pub fn err_udp_remote_addr_mismatch() -> anyhow::Error {
    anyhow!("udp packet dropped due to mismatched remote address")
}

/// The early-conn boundary: `murmur_std_compat::net::Conn` carries no `as_any`,
/// so a generic `Box<dyn NetConn>` cannot be tested for the sing
/// early-conn chain, mirroring `adapter::outbound::shadowsocks`'s own shim.
fn need_handshake(_conn: &dyn NetConn) -> bool {
    false
}

pub struct Vmess {
    self_weak: Weak<Self>,
    base: Base,
    client: sing_vmess_shim::Client,
    option: VmessOption,
    gun_client: std::sync::OnceLock<Arc<gun::gun::Client>>,
    mekya_client: std::sync::OnceLock<Arc<mekya::client::Client>>,
    ech_config: Option<Arc<ech::Config>>,
    shadow_tls_config: Option<shadowtls::client::Config>,
    jls_config: Option<murmur_transport_jls::Config>,
    restls_config: Option<Arc<murmur_restls::Config>>,
    reality_config: Option<Arc<murmur_reality::RealityClientConfig>>,
}

impl core::fmt::Debug for Vmess {
    /// Prints only the identity; `option` carries the UUID and TLS private-key credentials.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vmess").field("name", &self.base.name).field("addr", &self.base.addr).finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "wire-format mirror; the flags are independent protocol options, so collapsing them would change the public shape"
)]
pub struct VmessOption {
    #[serde(flatten)]
    pub basic: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port")]
    pub port: u16,
    #[serde(rename = "uuid")]
    pub uuid: String,
    #[serde(rename = "alterId")]
    pub alter_id: i32,
    #[serde(rename = "cipher")]
    pub cipher: String,
    #[serde(rename = "udp", default)]
    pub udp: bool,
    #[serde(rename = "network", default)]
    pub network: String,
    #[serde(rename = "tls", default)]
    pub tls: bool,
    #[serde(rename = "alpn", default)]
    pub alpn: Vec<String>,
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
    #[serde(rename = "tlsmirror-opts", default)]
    pub tls_mirror_opts: TLSMirrorOptions,
    #[serde(rename = "mekya-opts", default)]
    pub mekya_opts: MekyaOptions,
    #[serde(rename = "mkcp-opts", default)]
    pub mkcp_opts: MkcpOptions,
    #[serde(rename = "http-opts", default)]
    pub http_opts: HttpOptions,
    #[serde(rename = "h2-opts", default)]
    pub http2_opts: Http2Options,
    #[serde(rename = "grpc-opts", default)]
    pub grpc_opts: GrpcOptions,
    #[serde(rename = "ws-opts", default)]
    pub ws_opts: WsOptions,
    #[serde(rename = "packet-addr", default)]
    pub packet_addr: bool,
    #[serde(rename = "xudp", default)]
    pub xudp: bool,
    #[serde(rename = "packet-encoding", default)]
    pub packet_encoding: String,
    #[serde(rename = "global-padding", default)]
    pub global_padding: bool,
    #[serde(rename = "authenticated-length", default)]
    pub authenticated_length: bool,
    #[serde(rename = "client-fingerprint", default)]
    pub client_fingerprint: String,
}

impl core::fmt::Debug for VmessOption {
    /// Redacts the `uuid` and `private_key` credentials so a stray `{:?}` cannot log them.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VmessOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("uuid", &"<redacted>")
            .field("alter_id", &self.alter_id)
            .field("cipher", &self.cipher)
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MkcpOptions {
    #[serde(rename = "mtu", default)]
    pub mtu: u32,
    #[serde(rename = "tti", default)]
    pub tti: u32,
    #[serde(rename = "uplink-capacity", default)]
    pub uplink_capacity: u32,
    #[serde(rename = "downlink-capacity", default)]
    pub downlink_capacity: u32,
    #[serde(rename = "congestion", default)]
    pub congestion: bool,
    #[serde(rename = "write-buffer", default)]
    pub write_buffer: u32,
    #[serde(rename = "read-buffer", default)]
    pub read_buffer: u32,
    #[serde(rename = "seed", default)]
    pub seed: String,
    #[serde(rename = "header", default)]
    pub header: String,
}

impl MkcpOptions {
    #[must_use]
    pub fn build(&self) -> mkcp::config::Config {
        mkcp::config::Config {
            mtu: self.mtu,
            tti: self.tti,
            uplink_capacity: self.uplink_capacity,
            downlink_capacity: self.downlink_capacity,
            congestion: self.congestion,
            write_buffer: self.write_buffer,
            read_buffer: self.read_buffer,
            seed: self.seed.clone(),
            header: self.header.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MekyaOptions {
    #[serde(rename = "url", default)]
    pub url: String,
    #[serde(rename = "h2-pool-size", default)]
    pub h2_pool_size: i64,
    #[serde(rename = "max-write-delay", default)]
    pub max_write_delay: i64,
    #[serde(rename = "max-request-size", default)]
    pub max_request_size: i64,
    #[serde(rename = "polling-interval-initial", default)]
    pub polling_interval_initial: i64,
    #[serde(rename = "max-write-size", default)]
    pub max_write_size: i64,
    #[serde(rename = "max-write-duration-ms", default)]
    pub max_write_duration_ms: i64,
    #[serde(rename = "max-simultaneous-write-connection", default)]
    pub max_simultaneous_write_connection: i64,
    #[serde(rename = "packet-writing-buffer", default)]
    pub packet_writing_buffer: i64,
    #[serde(rename = "kcp", default)]
    pub kcp: MkcpOptions,
}

impl MekyaOptions {
    #[must_use]
    pub fn build(&self) -> mekya::config::Config {
        mekya::config::Config {
            kcp: self.kcp.build(),
            url: self.url.clone(),
            h2_pool_size: self.h2_pool_size,
            max_write_delay: self.max_write_delay,
            max_request_size: self.max_request_size,
            polling_interval_initial: self.polling_interval_initial,
            max_write_size: self.max_write_size,
            max_write_duration_ms: self.max_write_duration_ms,
            max_simultaneous_write_connection: self.max_simultaneous_write_connection,
            packet_writing_buffer: self.packet_writing_buffer,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HttpOptions {
    #[serde(rename = "method", default)]
    pub method: String,
    #[serde(rename = "path", default)]
    pub path: Vec<String>,
    #[serde(rename = "headers", default)]
    pub headers: HashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Http2Options {
    #[serde(rename = "host", default)]
    pub host: Vec<String>,
    #[serde(rename = "path", default)]
    pub path: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GrpcOptions {
    #[serde(rename = "grpc-service-name", default)]
    pub grpc_service_name: String,
    #[serde(rename = "grpc-user-agent", default)]
    pub grpc_user_agent: String,
    #[serde(rename = "ping-interval", default)]
    pub ping_interval: i32,
    #[serde(rename = "max-connections", default)]
    pub max_connections: i32,
    #[serde(rename = "min-streams", default)]
    pub min_streams: i32,
    #[serde(rename = "max-streams", default)]
    pub max_streams: i32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WsOptions {
    #[serde(rename = "path", default)]
    pub path: String,
    #[serde(rename = "headers", default)]
    pub headers: HashMap<String, String>,
    #[serde(rename = "max-early-data", default)]
    pub max_early_data: i64,
    #[serde(rename = "early-data-header-name", default)]
    pub early_data_header_name: String,
    #[serde(rename = "v2ray-http-upgrade", default)]
    pub v2ray_http_upgrade: bool,
    #[serde(rename = "v2ray-http-upgrade-fast-open", default)]
    pub v2ray_http_upgrade_fast_open: bool,
}

impl Vmess {
    pub fn new(option: VmessOption) -> Result<Arc<Self>> {
        let security = option.cipher.to_lowercase();

        let client = sing_vmess_shim::new_client(
            &option.uuid,
            &security,
            option.alter_id,
            option.global_padding,
            option.authenticated_length,
            ntp::time::now,
        )?;

        let mut option = option;
        match option.packet_encoding.as_str() {
            "packetaddr" | "packet" => option.packet_addr = true,
            "xudp" => option.xudp = true,
            _ => {}
        }
        if option.xudp {
            option.packet_addr = false;
        }

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: join_host_port(&option.server, option.port),
            type_: AdapterType::VMESS,
            provider_name: option.basic.provider_name.clone(),
            udp: option.udp,
            xudp: option.xudp,
            tfo: option.basic.tfo,
            mptcp: option.basic.mptcp,
            interface: option.basic.interface.clone(),
            routing_mark: option.basic.routing_mark,
            prefer: option.basic.ip_version,
        });
        base.dialer = Some(option.basic.new_dialer(base.dial_options()));

        let ech_config = option.ech_opts.parse()?.map(Arc::new);
        let shadow_tls_config = option.shadow_tls_opts.parse()?;
        let restls_config = option.restls_opts.parse(&option.server_name)?;
        let jls_config = option.jls_opts.parse()?;
        let reality_config = option.reality_opts.parse()?.map(Arc::new);

        let mut security_modes = Vec::new();
        if shadow_tls_config.is_some() {
            security_modes.push("ShadowTLS");
        }
        if restls_config.is_some() {
            security_modes.push("Restls");
        }
        if jls_config.is_some() {
            security_modes.push("JLS");
        }
        if reality_config.is_some() {
            security_modes.push("REALITY");
        }
        if !option.tls_mirror_opts.primary_key.is_empty() {
            security_modes.push("TLSMirror");
        }
        if security_modes.len() > 1 {
            return Err(anyhow!("security modes are mutually exclusive: {}", security_modes.join(", ")));
        }
        let security_mode = security_modes.first().copied().unwrap_or_default();
        if !security_mode.is_empty() && !option.tls {
            return Err(anyhow!("{security_mode} requires TLS"));
        }
        if (option.network == "mkcp" || option.network == "kcp")
            && matches!(security_mode, "ShadowTLS" | "Restls" | "JLS")
        {
            return Err(anyhow!("{security_mode} only supports TCP transports"));
        }

        if option.network == "h2" && option.http2_opts.host.is_empty() {
            option.http2_opts.host.push("www.example.com".to_owned());
        }
        if option.network == "mekya" && option.alpn.is_empty() {
            option.alpn = vec!["h2".to_owned(), "http/1.1".to_owned()];
        }

        let addr = base.addr.clone();
        let vmess = Arc::new_cyclic(|self_weak| Self {
            self_weak: Weak::clone(self_weak),
            base,
            client,
            gun_client: std::sync::OnceLock::new(),
            mekya_client: std::sync::OnceLock::new(),
            ech_config,
            shadow_tls_config,
            jls_config,
            restls_config,
            reality_config,
            option: option.clone(),
        });

        Self::setup_network_clients(&vmess, &option, &addr)?;

        Ok(vmess)
    }

    /// Arms the transport clients for the transports that need one dialled up front.
    fn setup_network_clients(vmess: &Arc<Self>, option: &VmessOption, address: &str) -> Result<()> {
        match option.network.as_str() {
            "mekya" => {
                let mut cfg = option.mekya_opts.build();
                if cfg.url.is_empty() {
                    cfg.url = format!("https://{address}");
                }
                let vmess_for_dial = Arc::clone(vmess);
                let dial: mekya::client::DialFunc = Arc::new(move |ctx: CancellationToken| {
                    let vmess = Arc::clone(&vmess_for_dial);
                    Box::pin(async move {
                        let raw = vmess
                            .base
                            .dialer
                            .clone()
                            .ok_or_else(|| anyhow!("dialer is not configured"))?
                            .dial_context(&ctx, "tcp", &vmess.base.addr())
                            .await?;
                        let raw: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(raw)); // S11: remove with std-compat
                        let conn = vmess.stream_tls_conn_default_typed(&ctx, raw, false).await?;
                        let conn: Box<dyn mekya::client::AnyConn> = Box::new(sing_vmess_shim::ErasedConn(conn));
                        Ok(conn)
                    })
                });
                let mekya_client = mekya::client::new_client(&CancellationToken::new(), dial, cfg)?;
                let _ = vmess.mekya_client.set(Arc::new(mekya_client));
            }
            "grpc" => {
                let vmess_for_dial = Arc::clone(vmess);
                let dial_fn: gun::gun::DialFn =
                    Arc::new(move |_ctx: CancellationToken, _network: String, _address: String| {
                        let vmess = Arc::clone(&vmess_for_dial);
                        Box::pin(async move {
                            let stream = vmess
                                .base
                                .dialer
                                .clone()
                                .ok_or_else(|| anyhow!("dialer is not configured"))?
                                .dial_context(&CancellationToken::new(), "tcp", &vmess.base.addr())
                                .await
                                .map_err(|e| anyhow!("{} connect error: {}", vmess.base.addr(), e))?;
                            let conn: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(stream)); // S11: remove with std-compat
                            Ok(conn)
                        })
                    });

                let host = if option.server_name.is_empty() { address } else { option.server_name.as_str() };
                let gun_config = gun::gun::Config {
                    service_name: option.grpc_opts.grpc_service_name.clone(),
                    user_agent: option.grpc_opts.grpc_user_agent.clone(),
                    host: host.to_owned(),
                    ping_interval: option.grpc_opts.ping_interval,
                };

                let tls_config = if option.tls {
                    let mut cfg = TlsConfig {
                        host: option.server_name.clone(),
                        skip_cert_verify: option.skip_cert_verify,
                        name_cert_verify: option.name_cert_verify.clone(),
                        finger_print: option.fingerprint.clone(),
                        certificate: option.certificate.clone(),
                        private_key: option.private_key.clone(),
                        client_fingerprint: option.client_fingerprint.clone(),
                        next_protos: vec!["h2".to_owned()],
                        ech: vmess.ech_config.clone(),
                        shadow_tls: vmess.shadow_tls_config.clone(),
                        restls: vmess.restls_config.clone(),
                        jls: vmess.jls_config.clone(),
                        tls_mirror: option.tls_mirror_opts.build(),
                        tls_mirror_dialer: vmess.make_tls_mirror_dialer(),
                        reality: vmess.reality_config.clone(),
                    };
                    if option.server_name.is_empty() {
                        let (host, _, _) =
                            split_host_port(address).unwrap_or_else(|_| (address.to_owned(), String::new(), false));
                        cfg.host = host;
                    }
                    Some(cfg)
                } else {
                    None
                };

                let maker_gun_config = gun_config;
                let maker: Arc<dyn Fn() -> Arc<gun::gun::Transport> + Send + Sync> = Arc::new(move || {
                    gun::gun::new_transport(Arc::clone(&dial_fn), tls_config.clone(), maker_gun_config.clone())
                });
                let gun_client = gun::gun::new_client(
                    maker,
                    option.grpc_opts.max_connections,
                    option.grpc_opts.min_streams,
                    option.grpc_opts.max_streams,
                );
                let _ = vmess.gun_client.set(Arc::new(gun_client));
            }
            _ => {}
        }
        Ok(())
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("Vmess adapter dropped while in use"))
    }

    fn websocket_config(&self) -> (String, WebsocketConfig) {
        let (host, port, _) =
            split_host_port(&self.base.addr()).unwrap_or_else(|_| (self.base.addr(), String::new(), false));
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
        (host, ws_opts)
    }

    async fn ws_tls_conn(
        &self,
        ctx: &CancellationToken,
        mut c: Box<dyn NetConn>,
        host: &str,
        ws_opts: &mut WebsocketConfig,
    ) -> Result<Box<dyn NetConn>> {
        let mut server_name = host.to_owned();
        if !self.option.server_name.is_empty() {
            server_name = self.option.server_name.clone();
        } else if let Some((_, value)) = ws_opts.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Host")) {
            server_name = value.clone();
        }

        if self.shadow_tls_config.is_some() || self.restls_config.is_some() || self.jls_config.is_some() {
            c = Box::new(murmur_common_net::io::StreamAsOldConn::new(
                stream_tls_conn(
                    ctx,
                    Box::new(murmur_common_net::io::OldConnAsStream(c)),
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
                        restls: self.restls_config.clone(),
                        jls: self.jls_config.clone(),
                        ech: None,
                        tls_mirror: None,
                        tls_mirror_dialer: None,
                        reality: None,
                    },
                )
                .await?,
            ));
        } else if !self.option.tls_mirror_opts.primary_key.is_empty() {
            c = self.stream_tls_conn_default(ctx, c, false).await?;
        } else {
            ws_opts.tls = true;
            let tls_config = ca::config::get_tls_config(ca::config::Option {
                tls_config: Some(tls_c::utls::Config {
                    server_name: server_name.clone(),
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
                    client_auth: tls_c::utls::ClientAuthType::default(),
                    client_cas: None,
                    cipher_suites: None,
                    session_tickets_disabled: false,
                    min_version: 0,
                    max_version: 0,
                    curve_preferences: None,
                    renegotiation: tls_c::utls::RenegotiationSupport::default(),
                    key_log_writer: None,
                    encrypted_client_hello_config_list: Vec::new(),
                    encrypted_client_hello_rejection_verify: None,
                    encrypted_client_hello_keys: Vec::new(),
                    get_encrypted_client_hello_keys: None,
                    session_id_generator: None,
                }),
                fingerprint: self.option.fingerprint.clone(),
                name_cert_verify: self.option.name_cert_verify.clone(),
                certificate: self.option.certificate.clone(),
                private_key: self.option.private_key.clone(),
                zero_trust: false,
            })?;
            ws_opts.tls_config = Some(Arc::new(tls_config));
        }
        Ok(c)
    }

    async fn stream_conn_context(
        &self,
        ctx: &CancellationToken,
        mut c: Box<dyn NetConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn NetConn>> {
        match self.option.network.as_str() {
            "ws" => {
                let (host, mut ws_opts) = self.websocket_config();
                if self.option.tls {
                    c = self.ws_tls_conn(ctx, c, &host, &mut ws_opts).await?;
                }
                c = stream_websocket_conn_public(ctx, c, ws_opts).await?;
            }
            "http" => {
                c = self.stream_tls_conn_default(ctx, c, false).await?;
                let (host, _, _) =
                    split_host_port(&self.base.addr()).unwrap_or_else(|_| (self.base.addr(), String::new(), false));
                let http_opts = HttpConfig {
                    host,
                    method: self.option.http_opts.method.clone(),
                    path: self.option.http_opts.path.clone(),
                    headers: self.option.http_opts.headers.clone().into_iter().collect(),
                };
                c = stream_http_conn(c, http_opts);
            }
            "h2" => {
                c = self.stream_tls_conn_default(ctx, c, true).await?;
                let h2_opts =
                    H2Config { hosts: self.option.http2_opts.host.clone(), path: self.option.http2_opts.path.clone() };
                c = stream_h2_conn(ctx, c, h2_opts).await?;
            }
            "grpc" | "mekya" => {}
            _ => {
                c = self.stream_tls_conn_default(ctx, c, false).await?;
            }
        }
        self.finish_stream_conn_context(ctx, c, metadata).await
    }

    async fn finish_stream_conn_context(
        &self,
        _ctx: &CancellationToken,
        c: Box<dyn NetConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn NetConn>> {
        let use_early = need_handshake(c.as_ref());
        // the connection is cancel-closed once `ctx` is done before the
        // handshake below returns; `common::net::context::setup_context_for_conn` takes ownership
        // of the conn through `SharedConn`, which does not fit this call site's need to keep using
        // `c` afterward without restructuring the shared connection. Deviation: not wired here (see the
        // wave report); the handshake still observes `ctx` cancellation through the dial/stream
        // calls it awaits.

        let result = if metadata.network == NetWork::UDP {
            if self.option.xudp {
                let global = if metadata.source_valid() { global_id(&metadata.source_address()) } else { [0u8; 8] };
                let dest = socksaddr_from_udp(metadata);
                if use_early {
                    Ok(self.client.dial_early_xudp_packet_conn(c, global, dest))
                } else {
                    self.client.dial_xudp_packet_conn(c, global, dest).await
                }
            } else if self.option.packet_addr {
                let magic =
                    Socksaddr { fqdn: sing_vmess_shim::SEQ_PACKET_MAGIC_ADDRESS.to_owned(), addr: None, port: 443 };
                let real_dest = socksaddr_from_udp(metadata);
                let conn = if use_early {
                    Ok(self.client.dial_early_packet_conn(c, magic))
                } else {
                    self.client.dial_packet_conn(c, magic).await
                };
                conn.map(|c| sing_vmess_shim::wrap_bind_conn(c, real_dest))
            } else {
                let dest = socksaddr_from_udp(metadata);
                if use_early {
                    Ok(self.client.dial_early_packet_conn(c, dest))
                } else {
                    self.client.dial_packet_conn(c, dest).await
                }
            }
        } else {
            let dest = parse_socksaddr_host_port(&metadata.string(), metadata.dst_port);
            if use_early {
                Ok(self.client.dial_early_conn(c, dest))
            } else {
                self.client.dial_conn(c, dest).await
            }
        };

        result
    }

    /// The typed stream helper with `is_h2 = false`. Returns the `TlsConn` identity so callers
    /// that need to inspect the negotiated TLS state (mekya's ALPN check) still can;
    /// [`stream_tls_conn_default`] is the plain `NetConn` wrapper for callers that do not.
    async fn stream_tls_conn_default_typed(
        &self,
        ctx: &CancellationToken,
        conn: Box<dyn NetConn>,
        is_h2: bool,
    ) -> Result<Box<dyn tls_c::utls::TlsConn>> {
        if !self.option.tls {
            return Ok(Box::new(tls_c::utls::ErasedTlsConn(Box::new(murmur_common_net::io::OldConnAsStream(conn)))));
        }
        let (host, _, _) =
            split_host_port(&self.base.addr()).unwrap_or_else(|_| (self.base.addr(), String::new(), false));
        let mut tls_opts = TlsConfig {
            host,
            skip_cert_verify: self.option.skip_cert_verify,
            name_cert_verify: self.option.name_cert_verify.clone(),
            finger_print: self.option.fingerprint.clone(),
            certificate: self.option.certificate.clone(),
            private_key: self.option.private_key.clone(),
            client_fingerprint: self.option.client_fingerprint.clone(),
            ech: self.ech_config.clone(),
            shadow_tls: self.shadow_tls_config.clone(),
            restls: self.restls_config.clone(),
            jls: self.jls_config.clone(),
            next_protos: self.option.alpn.clone(),
            tls_mirror: self.option.tls_mirror_opts.build(),
            tls_mirror_dialer: self.make_tls_mirror_dialer(),
            reality: self.reality_config.clone(),
        };
        if is_h2 {
            tls_opts.next_protos = vec!["h2".to_owned()];
        }
        if !self.option.server_name.is_empty() {
            tls_opts.host = self.option.server_name.clone();
        }
        stream_tls_conn(ctx, Box::new(murmur_common_net::io::OldConnAsStream(conn)), &tls_opts).await
    }

    async fn stream_tls_conn_default(
        &self,
        ctx: &CancellationToken,
        conn: Box<dyn NetConn>,
        is_h2: bool,
    ) -> Result<Box<dyn NetConn>> {
        self.stream_tls_conn_default_typed(ctx, conn, is_h2)
            .await
            .map(|c| -> Box<dyn NetConn> { Box::new(murmur_common_net::io::StreamAsOldConn::new(c)) })
    }

    /// The proxydialer's dial entry point, bridged into `tlsmirror::config::EnrollmentDialer`.
    fn make_tls_mirror_dialer(&self) -> Option<murmur_transport_tlsmirror::config::EnrollmentDialer> {
        let Ok(self_arc) = self.self_arc() else {
            return None;
        };
        let dialer = proxydialer::proxydialer::new(self_arc, false);
        Some(Arc::new(
            move |ctx: murmur_transport_tlsmirror::enrollment::DialCtx, network: &'static str, address: String| {
                let dialer = Arc::clone(&dialer);
                Box::pin(async move {
                    let stream = murmur_transport_tlsmirror::enrollment::AMBIENT_DIAL_CTX
                        .scope(ctx.clone(), dialer.dial_context(ctx.token(), network, &address))
                        .await?;
                    let conn: Box<dyn murmur_std_compat::net::Conn> =
                        Box::new(murmur_common_net::io::StreamAsOldConn::new(stream)); // S11: remove with std-compat
                    Ok(conn)
                })
            },
        ))
    }

    async fn dial_context_inner(&self, ctx: &CancellationToken) -> Result<Box<dyn NetConn>> {
        match self.option.network.as_str() {
            "grpc" => {
                self.gun_client.get().cloned().ok_or_else(|| anyhow!("grpc transport is not configured"))?.dial().await
            }
            "mekya" => {
                self.mekya_client
                    .get()
                    .cloned()
                    .ok_or_else(|| anyhow!("mekya transport is not configured"))?
                    .dial(ctx)
                    .await
            }
            "mkcp" | "kcp" => {
                let raw = self
                    .base
                    .dialer
                    .clone()
                    .ok_or_else(|| anyhow!("dialer is not configured"))?
                    .dial_context(ctx, "udp", &self.base.addr())
                    .await?;
                let raw: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(raw)); // S11: remove with std-compat
                mkcp::conn::dial(raw, self.option.mkcp_opts.build()).await.map(|c| -> Box<dyn NetConn> { Box::new(c) })
            }
            _ => {
                let stream = self
                    .base
                    .dialer
                    .clone()
                    .ok_or_else(|| anyhow!("dialer is not configured"))?
                    .dial_context(ctx, "tcp", &self.base.addr())
                    .await?;
                Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(stream)))
                // S11: remove with std-compat
            }
        }
    }
}

#[async_trait]
impl CProxyAdapter for Vmess {
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
        info.dialer_proxy.clone_from(&self.option.basic.dialer_proxy);
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let raw =
            self.dial_context_inner(ctx).await.map_err(|e| anyhow!("{} connect error: {}", self.base.addr(), e))?;
        match self.stream_conn_context(ctx, raw, metadata).await {
            // S11: remove with std-compat (ws/tls/h2/grpc/mekya/mkcp transport chain still old murmur_std_compat::net::Conn based)
            Ok(c) => Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(c)), self)),
            Err(e) => Err(anyhow!("{} connect error: {}", self.base.addr(), e)),
        }
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.resolve_udp(ctx, metadata).await?;

        let raw =
            self.dial_context_inner(ctx).await.map_err(|e| anyhow!("{} connect error: {}", self.base.addr(), e))?;
        let c = match self.stream_conn_context(ctx, raw, metadata).await {
            Ok(c) => c,
            Err(e) => return Err(anyhow!("{} connect error: {}", self.base.addr(), e)),
        };

        // S11: remove with std-compat (ws/tls/h2/grpc/mekya/mkcp transport chain still old murmur_std_compat::net::Conn based)
        let pc = vmess_packet_conn(Box::new(murmur_common_net::io::OldConnAsStream(c)), metadata);
        Ok(new_packet_conn(Arc::from(pc), self.self_arc()?))
    }

    fn support_uot(&self) -> bool {
        true
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.base.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn murmur_constant::adapters::Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        let mut errors = Vec::new();
        if let Some(gun_client) = self.gun_client.get() {
            if let Err(e) = gun_client.close() {
                errors.push(e.to_string());
            }
        }
        if let Some(mekya_client) = self.mekya_client.get() {
            if let Err(e) = mekya_client.close() {
                errors.push(e.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(errors.join("\n")))
        }
    }
}

#[async_trait]
impl ProxyAdapter for Vmess {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

fn socksaddr_from_udp(metadata: &Metadata) -> Socksaddr {
    if let Some(addr) = metadata.udp_addr() {
        Socksaddr { fqdn: String::new(), addr: Some(addr.ip), port: addr.port }
    } else {
        Socksaddr::default()
    }
}

struct VmessPacketConn {
    conn: tokio::sync::Mutex<Box<dyn murmur_common_net::io::Stream>>,
    r_addr: Option<SocketAddr>,
}

fn vmess_packet_conn(
    conn: Box<dyn murmur_common_net::io::Stream>,
    metadata: &Metadata,
) -> Box<dyn murmur_common_net::io::Datagram> {
    let r_addr = metadata.udp_addr().and_then(|addr| SocketAddr::try_from(&addr).ok());
    Box::new(VmessPacketConn { conn: tokio::sync::Mutex::new(conn), r_addr })
}

#[async_trait]
impl murmur_common_net::io::Datagram for VmessPacketConn {
    /// Sends to the packet's fixed remote address. `VMess` doesn't support full cone NAT by
    /// design: verify the destination matches `r_addr` and drop the packet otherwise.
    async fn send_to(&self, b: &[u8], addr: SocketAddr) -> io::Result<usize> {
        use tokio::io::AsyncWriteExt;
        if self.r_addr != Some(addr) {
            return Err(io::Error::other(err_udp_remote_addr_mismatch()));
        }
        let mut conn = self.conn.lock().await;
        conn.write(b).await
    }

    async fn recv_from(&self, b: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        use tokio::io::AsyncReadExt;
        let n = {
            let mut conn = self.conn.lock().await;
            conn.read(b).await?
        };
        let addr = self.r_addr.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));
        Ok((n, addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.conn.try_lock().map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "packet conn busy"))?.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        let conn = self.conn.try_lock().map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "packet conn busy"))?;
        murmur_common_net::io::close_stream(conn.as_ref())
    }
}

/// Bridges the real AEAD-2 engine (`transport::vmess::sing`) into the shape
/// `adapter::outbound::vmess` calls through. `ErasedConn` below carries the dialed conn's
/// `TlsConn` identity into `mekya::client::AnyConn` explicitly, so mekya's ALPN check can still
/// see the negotiated TLS state.
mod sing_vmess_shim {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    use anyhow::Result;
    use chrono::{DateTime, Utc};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use murmur_common_net::io::Stream;
    use murmur_component_tls::utls::TlsConn;
    use murmur_sing::metadata::Socksaddr;
    use murmur_std_compat::net::Conn as NetConn;
    use murmur_transport_mekya::client::AnyConn;
    use murmur_transport_vmess::sing::{client, packetaddr, xudp};

    /// `packetaddr::SEQ_PACKET_MAGIC_ADDRESS`: the magic address that marks a packet-address
    /// frame.
    pub(super) const SEQ_PACKET_MAGIC_ADDRESS: &str = packetaddr::SEQ_PACKET_MAGIC_ADDRESS;

    pub(super) struct Client {
        inner: client::Client,
    }

    pub(super) fn new_client(
        uuid_str: &str,
        security: &str,
        alter_id: i32,
        global_padding: bool,
        authenticated_length: bool,
        time_func: fn() -> DateTime<Utc>,
    ) -> Result<Client> {
        let uuid = murmur_common::utils::uuid::uuid_map(uuid_str);
        let inner = client::Client::new(uuid, security, alter_id, global_padding, authenticated_length, time_func)?;
        Ok(Client { inner })
    }

    impl Client {
        pub(crate) async fn dial_conn(&self, c: Box<dyn NetConn>, dst: Socksaddr) -> Result<Box<dyn NetConn>> {
            self.inner.dial_conn(c, dst).await
        }

        pub(crate) fn dial_early_conn(&self, c: Box<dyn NetConn>, dst: Socksaddr) -> Box<dyn NetConn> {
            self.inner.dial_early_conn(c, dst)
        }

        pub(crate) async fn dial_packet_conn(&self, c: Box<dyn NetConn>, dst: Socksaddr) -> Result<Box<dyn NetConn>> {
            self.inner.dial_packet_conn(c, dst).await
        }

        pub(crate) fn dial_early_packet_conn(&self, c: Box<dyn NetConn>, dst: Socksaddr) -> Box<dyn NetConn> {
            self.inner.dial_early_packet_conn(c, dst)
        }

        pub(crate) async fn dial_xudp_packet_conn(
            &self,
            c: Box<dyn NetConn>,
            global_id: [u8; 8],
            dst: Socksaddr,
        ) -> Result<Box<dyn NetConn>> {
            let mux_conn: Box<dyn NetConn> = Box::new(self.inner.dial_mux_conn(c, dst.clone()).await?);
            Ok(xudp::new_xudp_conn(mux_conn, global_id, dst))
        }

        pub(crate) fn dial_early_xudp_packet_conn(
            &self,
            c: Box<dyn NetConn>,
            global_id: [u8; 8],
            dst: Socksaddr,
        ) -> Box<dyn NetConn> {
            let mux_conn: Box<dyn NetConn> = Box::new(self.inner.dial_early_mux_conn(c, dst.clone()));
            xudp::new_xudp_conn(mux_conn, global_id, dst)
        }
    }

    /// `packetaddr::wrap_bind_conn`, the packet-address bind wrapper.
    pub(super) fn wrap_bind_conn(conn: Box<dyn NetConn>, target: Socksaddr) -> Box<dyn NetConn> {
        packetaddr::wrap_bind_conn(conn, target)
    }

    /// Wraps the dialed conn's [`TlsConn`] identity in a concrete, `'static` type carrying an
    /// explicit, non-blanket [`AnyConn`] impl that forwards `as_any` to the wrapped conn instead
    /// of answering in place of the wrapper: the ALPN check needs to see the
    /// real handshake state, not this bridge's own identity.
    pub(super) struct ErasedConn(pub(crate) Box<dyn TlsConn>);

    impl AnyConn for ErasedConn {
        fn as_any(&self) -> &dyn std::any::Any {
            TlsConn::as_any(self.0.as_ref())
        }
    }

    impl AsyncRead for ErasedConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ErasedConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl Stream for ErasedConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            self.0.local_addr()
        }

        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            self.0.peer_addr()
        }

        fn shutdown_read(&self) -> io::Result<()> {
            self.0.shutdown_read()
        }

        fn shutdown_write(&self) -> io::Result<()> {
            self.0.shutdown_write()
        }

        fn old_conn(&self) -> Option<&dyn NetConn> {
            self.0.old_conn()
        }
    }
}

#[cfg(test)]
mod jls_option_tests {
    use super::*;

    const JLS: &str = "jls-opts:\n  username: user\n  password: pass\n";
    const SHADOW_TLS: &str = "shadow-tls-opts:\n  password: p\n  version: 3\n";
    const REALITY: &str = "reality-opts:\n  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
    const HEAD: &str = "name: v\nserver: example.com\nport: 443\nuuid: 00000000-0000-0000-0000-000000000001\nalterId: 0\ncipher: auto\n";

    fn new_err(extra: &str) -> String {
        let yaml = format!("{HEAD}tls: true\n{extra}");
        let option: VmessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        Vmess::new(option).err().map(|err| err.to_string()).expect("rejected")
    }

    #[test]
    fn credentials_select_jls_while_empty_ones_select_nothing() {
        let yaml = format!("{HEAD}tls: true\n{JLS}");
        let option: VmessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        let vmess = Vmess::new(option).expect("accepted");
        let config = vmess.jls_config.as_ref().expect("JLS selected");
        assert_eq!((config.user.username.as_str(), config.user.password.as_str()), ("user", "pass"));

        let yaml = format!("{HEAD}tls: true\njls-opts:\n  username: \"\"\n  password: \"\"\n");
        let option: VmessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        assert!(Vmess::new(option).expect("accepted").jls_config.is_none());

        // The credential has to be present and empty: a block that leaves it out already fails to
        // decode (see `crate::jls`), so only this reaches the JLS config parse.
        assert_eq!(new_err("jls-opts:\n  username: \"\"\n  password: pass\n"), "jls: username is required");
    }

    #[test]
    fn jls_is_exclusive_with_the_other_security_modes() {
        assert_eq!(new_err(&format!("{JLS}{SHADOW_TLS}")), "security modes are mutually exclusive: ShadowTLS, JLS");
        assert_eq!(new_err(&format!("{JLS}{REALITY}")), "security modes are mutually exclusive: JLS, REALITY");
    }

    #[test]
    fn jls_requires_tls_and_rejects_the_kcp_transports() {
        let yaml = format!("{HEAD}tls: false\n{JLS}");
        let option: VmessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        let err = Vmess::new(option).err().map(|err| err.to_string()).expect("rejected");
        assert_eq!(err, "JLS requires TLS");

        for network in ["kcp", "mkcp"] {
            let yaml = format!("{HEAD}tls: true\nnetwork: {network}\n{JLS}");
            let option: VmessOption = yaml_serde::from_str(&yaml).expect("option decodes");
            let err = Vmess::new(option).err().map(|err| err.to_string()).expect("rejected");
            assert_eq!(err, "JLS only supports TCP transports", "network {network}");
        }
    }
}

#[cfg(test)]
mod restls_option_tests {
    use super::*;

    const RESTLS: &str = "restls-opts:\n  password: p\n  version-hint: tls13\n";
    const JLS: &str = "jls-opts:\n  username: user\n  password: pass\n";
    const SHADOW_TLS: &str = "shadow-tls-opts:\n  password: p\n  version: 3\n";
    const HEAD: &str = "name: v\nserver: example.com\nport: 443\nuuid: 00000000-0000-0000-0000-000000000001\nalterId: 0\ncipher: auto\n";

    fn new_err(extra: &str) -> String {
        let yaml = format!("{HEAD}tls: true\n{extra}");
        let option: VmessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        Vmess::new(option).err().map(|err| err.to_string()).expect("rejected")
    }

    #[test]
    fn restls_is_exclusive_with_the_other_security_modes() {
        assert_eq!(
            new_err(&format!("{RESTLS}{SHADOW_TLS}")),
            "security modes are mutually exclusive: ShadowTLS, Restls"
        );
        assert_eq!(new_err(&format!("{RESTLS}{JLS}")), "security modes are mutually exclusive: Restls, JLS");
    }

    #[test]
    fn restls_requires_tls_and_rejects_the_kcp_transports() {
        let yaml = format!("{HEAD}tls: false\n{RESTLS}");
        let option: VmessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        let err = Vmess::new(option).err().map(|err| err.to_string()).expect("rejected");
        assert_eq!(err, "Restls requires TLS");

        for network in ["kcp", "mkcp"] {
            let yaml = format!("{HEAD}tls: true\nnetwork: {network}\n{RESTLS}");
            let option: VmessOption = yaml_serde::from_str(&yaml).expect("option decodes");
            let err = Vmess::new(option).err().map(|err| err.to_string()).expect("rejected");
            assert_eq!(err, "Restls only supports TCP transports", "network {network}");
        }
    }

    /// `restls-opts` is parsed with the configured server name verbatim, not with the resolved dial
    /// host.
    #[test]
    fn the_restls_server_name_is_the_configured_servername() {
        let yaml = format!("{HEAD}tls: true\nservername: sni.example\n{RESTLS}");
        let option: VmessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        let vmess = Vmess::new(option).expect("accepted");
        let config = vmess.restls_config.as_ref().expect("Restls selected");
        assert_eq!(config.server_name, "sni.example");
    }

    #[test]
    fn an_empty_block_leaves_the_security_mode_field_alone() {
        let yaml = format!("{HEAD}tls: true\nrestls-opts:\n  password: \"\"\n  version-hint: \"\"\n");
        let option: VmessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        assert!(Vmess::new(option).expect("accepted").restls_config.is_none());
    }
}

#[cfg(test)]
mod shadow_tls_option_tests {
    use super::*;

    const HEAD: &str = "name: v\nserver: example.com\nport: 443\nuuid: 00000000-0000-0000-0000-000000000001\nalterId: 0\ncipher: auto\n";

    /// A shadow-tls v3 block is accepted, so it must survive config construction far enough for the
    /// mutual-exclusion check to run; this adapter refuses it only when a connection is dialled.
    #[tokio::test]
    async fn a_v3_block_builds_a_config_but_refuses_to_dial() {
        let yaml = format!("{HEAD}tls: true\nshadow-tls-opts:\n  password: p\n  version: 3\n");
        let option: VmessOption = yaml_serde::from_str(&yaml).expect("option decodes");
        let vmess = Vmess::new(option).expect("accepted");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let stream = tokio::net::TcpStream::connect(listener.local_addr().expect("address")).await.expect("connect");

        let tls_config = TlsConfig {
            host: "example.com".to_owned(),
            shadow_tls: vmess.shadow_tls_config.clone(),
            ..Default::default()
        };
        // `stream` is never read or written: the version gate runs before the handshake.
        let err = match stream_tls_conn(&CancellationToken::new(), Box::new(stream), &tls_config).await {
            Ok(_) => panic!("v3 must not dial"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("no Rust implementation"), "{err}");
    }
}
