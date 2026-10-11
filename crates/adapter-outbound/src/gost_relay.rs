use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use murmur_constant::adapters::AdapterType;
use murmur_constant::adapters::{
    Conn as CConn, Dialer as CDialer, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_transport::gost::relay::{new_relay_dialer, RelayOption};

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::util::safe_conn_close;

#[derive(Clone, Default, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools, reason = "the option struct mirrors the protocol's flag set field for field")]
pub struct GostRelayOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port")]
    pub port: i32,
    #[serde(rename = "forward", default)]
    pub forward: bool,
    #[serde(rename = "udp", default)]
    pub udp: bool,
    #[serde(rename = "tls", default)]
    pub tls: bool,
    #[serde(rename = "mux", default)]
    pub mux: bool,
    #[serde(rename = "sni", default)]
    pub sni: String,
    #[serde(rename = "username", default)]
    pub username: String,
    #[serde(rename = "password", default)]
    pub password: String,
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
    #[serde(rename = "client-fingerprint", default)]
    pub client_fingerprint: String,
}

impl std::fmt::Debug for GostRelayOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GostRelayOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("password", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// `self_weak` upgrades to the `Arc<GostRelay>` the `g` receiver already is,
/// needed only by `new_packet_conn` (which retains the adapter for `resolve_udp`); populated by
/// `Arc::new_cyclic` — DEVIATION, see the wave report.
pub struct GostRelay {
    base: Base,
    dialer: Arc<dyn CDialer>,
    option: GostRelayOption,
    self_weak: Weak<Self>,
}

impl std::fmt::Debug for GostRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GostRelay").field("addr", &self.base.addr()).finish_non_exhaustive()
    }
}

impl GostRelay {
    pub fn new(option: GostRelayOption) -> Result<Arc<Self>> {
        if option.server.is_empty() || option.port <= 0 || option.port > 0xffff {
            return Err(anyhow!("gost-relay {} requires a valid server and port", option.name));
        }

        let addr = murmur_component::dialer::bind::join_host_port(&option.server, option.port);

        let relay = Arc::new_cyclic(|weak| {
            let base = Base::new(BaseOption {
                name: option.name.clone(),
                addr,
                type_: AdapterType::GOST_RELAY,
                provider_name: option.basic_option.provider_name.clone(),
                udp: option.udp,
                tfo: option.basic_option.tfo,
                mptcp: option.basic_option.mptcp,
                interface: option.basic_option.interface.clone(),
                routing_mark: option.basic_option.routing_mark,
                prefer: option.basic_option.ip_version,
                xudp: false,
            });

            let dial_options = base.dial_options();
            let base_dialer = option.basic_option.new_dialer(dial_options);
            let relay_option = RelayOption {
                server: option.server.clone(),
                port: option.port,
                forward: option.forward,
                tls: option.tls,
                mux: option.mux,
                sni: option.sni.clone(),
                username: option.username.clone(),
                password: option.password.clone(),
                skip_cert_verify: option.skip_cert_verify,
                name_cert_verify: option.name_cert_verify.clone(),
                fingerprint: option.fingerprint.clone(),
                certificate: option.certificate.clone(),
                private_key: option.private_key.clone(),
                client_fingerprint: option.client_fingerprint.clone(),
            };
            let dialer = new_relay_dialer(base_dialer, Some(&relay_option));

            Self { base, dialer, option, self_weak: Weak::clone(weak) }
        });

        Ok(relay)
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("GostRelay adapter dropped while still in use"))
    }
}

#[async_trait]
impl CProxyAdapter for GostRelay {
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
        info.smux = self.option.mux;
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let c = match self.dialer.dial_context(ctx, "tcp", &metadata.remote_address()).await {
            Ok(c) => c,
            Err(err) => return Err(anyhow!("{} connect error: {err}", self.base.addr())),
        };
        safe_conn_close(Some(c.as_ref()), false);
        Ok(new_conn(c, self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.resolve_udp(ctx, metadata).await?;
        let addr_port = metadata.addr_port();
        let pc = self
            .dialer
            .listen_packet(ctx, "udp", "", addr_port)
            .await
            .map_err(|err| anyhow!("{} udp connect error: {err}", self.base.addr()))?;
        Ok(new_packet_conn(Arc::from(pc), self.self_arc()?))
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
impl ProxyAdapter for GostRelay {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}
