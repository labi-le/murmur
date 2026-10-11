//! The trusttunnel outbound: a pooled client bridged into the synchronous adapter shape.
//!
//! `transport::trusttunnel::client::PoolClient::new` is `async fn` (its QUIC branch builds an h3
//! round tripper via async setup); this adapter
//! bridges that with `tokio::task::block_in_place` + `Handle::current().block_on`, the same idiom
//! already used for the synchronous `Close` methods elsewhere in this wave (`hysteria.rs`,
//! `masque.rs`, `sudoku.rs`).

use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::ech::ECHOptions;
use murmur_common_net::new_thread_safe_packet_conn;
use murmur_component::dialer::bind::join_host_port;
use murmur_component::dialer::options::{
    with_interface, with_only_single_stack, with_prefer_ipv4, with_prefer_ipv6, with_routing_mark,
    Option as DialerOption,
};
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::dns::DNSPrefer;
use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::PacketConn as NetPacketConn;
use murmur_transport_trusttunnel::client::{ClientOptions, PoolClient};
use murmur_transport_vmess::tls::TlsConfig;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};

/// The dial options, rebuilt from plain fields on each call so
/// `trusttunnel::client::DialOptionsFunc` (`Arc<dyn Fn() -> Vec<DialerOption>>`) never needs to
/// clone a `Vec<Box<dyn Fn>>` (`DialerOption` is not `Clone`).
fn trusttunnel_dial_options_fn(
    interface: String,
    routing_mark: i32,
    prefer: DNSPrefer,
) -> murmur_transport_trusttunnel::client::DialOptionsFunc {
    Arc::new(move || {
        let mut opts: Vec<DialerOption> = Vec::new();
        if !interface.is_empty() {
            opts.push(with_interface(&interface));
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
    })
}

pub struct TrustTunnel {
    self_weak: Weak<Self>,
    base: Base,
    client: Arc<PoolClient>,
    option: TrustTunnelOption,
}

impl std::fmt::Debug for TrustTunnel {
    /// Redacts the option block, which carries the tunnel credentials.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustTunnel")
            .field("name", &self.base.name())
            .field("addr", &self.base.addr())
            .finish_non_exhaustive()
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "the option struct mirrors the trusttunnel configuration flags field for field; the flags are independent protocol options and collapsing them would change the public shape"
)]
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TrustTunnelOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port", default)]
    pub port: i32,
    #[serde(rename = "username", default)]
    pub user_name: String,
    #[serde(rename = "password", default)]
    pub password: String,
    #[serde(rename = "alpn", default)]
    pub alpn: Option<Vec<String>>,
    #[serde(rename = "sni", default)]
    pub sni: String,
    #[serde(rename = "ech-opts", default)]
    pub ech_opts: ECHOptions,
    #[serde(rename = "client-fingerprint", default)]
    pub client_fingerprint: String,
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
    #[serde(rename = "udp", default)]
    pub udp: bool,
    #[serde(rename = "health-check", default)]
    pub health_check: bool,
    #[serde(rename = "quic", default)]
    pub quic: bool,
    #[serde(rename = "congestion-controller", default)]
    pub congestion_controller: String,
    #[serde(rename = "cwnd", default)]
    pub cwnd: i32,
    #[serde(rename = "bbr-profile", default)]
    pub bbr_profile: String,
    #[serde(rename = "max-connections", default)]
    pub max_connections: i32,
    #[serde(rename = "min-streams", default)]
    pub min_streams: i32,
    #[serde(rename = "max-streams", default)]
    pub max_streams: i32,
}

impl std::fmt::Debug for TrustTunnelOption {
    /// Redacts `password` and `private_key` so `{:?}` cannot leak credentials.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustTunnelOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("user_name", &self.user_name)
            .field("password", &"<redacted>")
            .field("sni", &self.sni)
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("udp", &self.udp)
            .field("health_check", &self.health_check)
            .field("quic", &self.quic)
            .field("cwnd", &self.cwnd)
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl TrustTunnel {
    pub fn new(option: TrustTunnelOption) -> Result<Arc<Self>> {
        let port = u16::try_from(option.port).map_err(|_| anyhow!("invalid port: {}", option.port))?;
        let addr = join_host_port(&option.server, port);

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: addr.clone(),
            type_: AdapterType::TRUST_TUNNEL,
            provider_name: option.basic_option.provider_name.clone(),
            udp: option.udp,
            xudp: false,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
        });
        let dialer = option.basic_option.new_dialer(base.dial_options());
        base.dialer = Some(Arc::clone(&dialer));

        let ech_config = option.ech_opts.parse()?.map(Arc::new);
        let mut tls_config = TlsConfig {
            host: option.sni.clone(),
            skip_cert_verify: option.skip_cert_verify,
            name_cert_verify: option.name_cert_verify.clone(),
            next_protos: option.alpn.clone().unwrap_or_default(),
            finger_print: option.fingerprint.clone(),
            certificate: option.certificate.clone(),
            private_key: option.private_key.clone(),
            client_fingerprint: option.client_fingerprint.clone(),
            ech: ech_config,
            shadow_tls: None,
            restls: None,
            jls: None,
            tls_mirror: None,
            tls_mirror_dialer: None,
            reality: None,
        };
        if tls_config.host.is_empty() {
            tls_config.host.clone_from(&option.server);
        }

        let t_option = ClientOptions {
            dialer,
            dial_options: Some(trusttunnel_dial_options_fn(
                option.basic_option.interface.clone(),
                option.basic_option.routing_mark,
                option.basic_option.ip_version,
            )),
            server: addr,
            username: option.user_name.clone(),
            password: option.password.clone(),
            tls_config: Arc::new(tls_config),
            quic: option.quic,
            quic_congestion_control: option.congestion_controller.clone(),
            quic_cwnd: option.cwnd,
            quic_bbr_profile: option.bbr_profile.clone(),
            health_check: option.health_check,
            max_connections: option.max_connections,
            min_streams: option.min_streams,
            max_streams: option.max_streams,
        };

        let client = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(PoolClient::new(CancellationToken::new(), t_option))
        })?;

        Ok(Arc::new_cyclic(|self_weak| Self { self_weak: Weak::clone(self_weak), base, client, option }))
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("TrustTunnel: adapter dropped while still in use"))
    }
}

#[async_trait]
impl CProxyAdapter for TrustTunnel {
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

    async fn dial_context(&self, _ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let c = self.client.dial(&metadata.remote_address()).await?;
        // S11: remove with std-compat (transport-trusttunnel::client::PoolClient::dial still returns old murmur_std_compat::net::Conn)
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(c)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.resolve_udp(ctx, metadata).await?;

        let pc = self.client.listen_packet().await?;
        let pc: Arc<dyn NetPacketConn> = Arc::new(pc);
        let pc = new_thread_safe_packet_conn(pc).into_packet_conn();
        // S11: remove with std-compat (common_net::new_thread_safe_packet_conn still old murmur_std_compat::net::PacketConn based)
        Ok(new_packet_conn(super::base::arc_packet_conn_as_datagram(pc), self.self_arc()?))
    }

    fn support_uot(&self) -> bool {
        true
    }

    fn proxy_info(&self) -> ProxyInfo {
        let mut info = self.base.proxy_info();
        info.dialer_proxy.clone_from(&self.option.basic_option.dialer_proxy);
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
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
impl ProxyAdapter for TrustTunnel {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}
