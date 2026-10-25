use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::ech::ECHOptions;
use crate::shadowtls::ShadowTLSOptions;
use murmur_common_net::new_thread_safe_packet_conn;
use murmur_component::dialer::bind::join_host_port;
use murmur_component_proxydialer::sing::new_sing_dialer;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_sing::metadata::{parse_socksaddr_host_port, Socksaddr};
use murmur_sing::uot;
use murmur_std_compat::net::PacketConn as NetPacketConn;
use murmur_transport_anytls::client::{new_client, Client, ClientConfig};
use murmur_transport_vmess::tls::TlsConfig;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};

pub struct AnyTLS {
    self_weak: Weak<Self>,
    base: Base,
    client: Arc<Client>,
    option: AnyTLSOption,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AnyTLSOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port", default)]
    pub port: i32,
    #[serde(rename = "password")]
    pub password: String,
    #[serde(rename = "alpn", default)]
    pub alpn: Option<Vec<String>>,
    #[serde(rename = "sni", default)]
    pub sni: String,
    #[serde(rename = "ech-opts", default)]
    pub ech_opts: ECHOptions,
    #[serde(rename = "shadow-tls-opts", default)]
    pub shadow_tls_opts: ShadowTLSOptions,
    #[serde(rename = "restls-opts", default)]
    pub restls_opts: super::base::RestlsOptions,
    #[serde(rename = "jls-opts", default)]
    pub jls_opts: super::jls::JlsOptions,
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
    #[serde(rename = "client-metadata", default)]
    pub client_metadata: String,
    #[serde(rename = "idle-session-check-interval", default)]
    pub idle_session_check_interval: i32,
    #[serde(rename = "idle-session-timeout", default)]
    pub idle_session_timeout: i32,
    #[serde(rename = "min-idle-session", default)]
    pub min_idle_session: i32,
    #[serde(rename = "disable-reuse", default)]
    pub disable_reuse: bool,
}

impl core::fmt::Debug for AnyTLSOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `basic_option` has no `Debug`; the password and private key are never printed.
        f.debug_struct("AnyTLSOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("sni", &self.sni)
            .field("udp", &self.udp)
            .field("password", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for AnyTLS {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AnyTLS").field("name", &self.base.name).finish_non_exhaustive()
    }
}

impl AnyTLS {
    pub fn new(option: AnyTLSOption) -> Result<Arc<Self>> {
        let port = u16::try_from(option.port).map_err(|_| anyhow!("invalid port"))?;
        let addr = join_host_port(&option.server, port);

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr,
            type_: AdapterType::ANY_TLS,
            provider_name: option.basic_option.provider_name.clone(),
            udp: option.udp,
            xudp: false,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
        });
        base.dialer = Some(option.basic_option.new_dialer(base.dial_options()));
        let dialer = base.dialer.clone().ok_or_else(|| anyhow!("dialer set above"))?;
        let sing_dialer = new_sing_dialer(dialer);
        let idle_check = Duration::from_secs(u64::from(option.idle_session_check_interval.max(0).unsigned_abs()));
        let idle_timeout = Duration::from_secs(u64::from(option.idle_session_timeout.max(0).unsigned_abs()));

        let mut t_option = ClientConfig {
            password: option.password.clone(),
            server: parse_socksaddr_host_port(&option.server, port),
            dialer: sing_dialer,
            client_metadata: option.client_metadata.clone(),
            idle_session_check_interval: idle_check,
            idle_session_timeout: idle_timeout,
            min_idle_session: option.min_idle_session,
            disable_reuse: option.disable_reuse,
            tls_config: TlsConfig::default(),
        };

        let ech_config = option.ech_opts.parse()?.map(Arc::new);
        let shadow_tls_config = option.shadow_tls_opts.parse()?;
        let restls_config = option.restls_opts.parse(&option.sni)?;
        let jls_config = option.jls_opts.parse()?;
        let mut security_modes: Vec<&'static str> = Vec::with_capacity(2);
        if shadow_tls_config.is_some() {
            security_modes.push("ShadowTLS");
        }
        if restls_config.is_some() {
            security_modes.push("Restls");
        }
        if jls_config.is_some() {
            security_modes.push("JLS");
        }
        if security_modes.len() > 1 {
            return Err(anyhow!("security modes are mutually exclusive: {}", security_modes.join(", ")));
        }

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
            shadow_tls: shadow_tls_config,
            restls: restls_config,
            jls: jls_config,
            tls_mirror: None,
            tls_mirror_dialer: None,
            reality: None,
        };
        if tls_config.host.is_empty() {
            tls_config.host.clone_from(&option.server);
        }
        t_option.tls_config = tls_config;

        let ctx = CancellationToken::new();
        let client = new_client(&ctx, t_option);

        Ok(Arc::new_cyclic(|self_weak| Self { self_weak: Weak::clone(self_weak), base, client, option }))
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("AnyTLS: adapter dropped while still in use"))
    }
}

#[async_trait]
impl CProxyAdapter for AnyTLS {
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
        let destination = parse_socksaddr_host_port(&metadata.string(), metadata.dst_port);
        let c = self.client.create_proxy(ctx, destination).await?;
        // S11: remove with std-compat (murmur_transport_anytls::client::Client::create_proxy still returns old murmur_std_compat::net::Conn)
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(c)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.resolve_udp(ctx, metadata).await?;

        let c = self.client.create_proxy(ctx, uot::request_destination(2)).await?;

        let destination = metadata.udp_addr().map(|addr| Socksaddr::from_ip(addr.ip, addr.port)).unwrap_or_default();
        let request = uot::Request { is_connect: false, destination };
        let lazy = uot::new_lazy_conn(c, request);
        let pc: Arc<dyn NetPacketConn> = new_thread_safe_packet_conn(Arc::new(lazy)).into_packet_conn();
        // S11: remove with std-compat (uot::Conn/thread_safe_packet_conn chain still old murmur_std_compat::net::PacketConn based)
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
        self.client.close().map_err(Into::into)
    }
}

#[async_trait]
impl ProxyAdapter for AnyTLS {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

#[cfg(test)]
mod jls_option_tests {
    use super::*;

    const JLS: &str = "jls-opts:\n  username: user\n  password: pass\n";
    const SHADOW_TLS: &str = "shadow-tls-opts:\n  password: p\n  version: 3\n";
    const HEAD: &str = "name: a\nserver: example.com\nport: 443\npassword: p\n";

    fn new_err(extra: &str) -> String {
        let yaml = format!("{HEAD}{extra}");
        let option: AnyTLSOption = yaml_serde::from_str(&yaml).expect("option decodes");
        AnyTLS::new(option).err().map(|err| err.to_string()).expect("rejected")
    }

    #[test]
    fn jls_is_exclusive_with_shadow_tls() {
        assert_eq!(new_err(&format!("{JLS}{SHADOW_TLS}")), "security modes are mutually exclusive: ShadowTLS, JLS");
    }

    /// `AnyTLS` hands its `TlsConfig` straight to the client construction, so the exclusivity check is
    /// the observable proof that the parsed credentials reached the same field ShadowTLS competes
    /// for: an empty block must leave that field empty, or ShadowTLS would be rejected here.
    #[tokio::test]
    async fn empty_credentials_leave_the_security_mode_field_alone() {
        let yaml = format!(
            "{HEAD}shadow-tls-opts:\n  password: p\n  version: 3\njls-opts:\n  username: \"\"\n  password: \"\"\n"
        );
        let option: AnyTLSOption = yaml_serde::from_str(&yaml).expect("option decodes");
        assert!(AnyTLS::new(option).is_ok());

        // The credential has to be present and empty: a block that leaves it out already fails to
        // decode (see `crate::jls`), so only this reaches the JLS config parse.
        let yaml = format!("{HEAD}jls-opts:\n  username: \"\"\n  password: pass\n");
        let option: AnyTLSOption = yaml_serde::from_str(&yaml).expect("option decodes");
        let err = AnyTLS::new(option).err().map(|err| err.to_string()).expect("rejected");
        assert_eq!(err, "jls: username is required");
    }
}

#[cfg(test)]
mod restls_option_tests {
    use super::*;

    const RESTLS: &str = "restls-opts:\n  password: p\n  version-hint: tls13\n";
    const JLS: &str = "jls-opts:\n  username: user\n  password: pass\n";
    const SHADOW_TLS: &str = "shadow-tls-opts:\n  password: p\n  version: 3\n";
    const HEAD: &str = "name: a\nserver: example.com\nport: 443\npassword: p\n";

    fn new_err(extra: &str) -> String {
        let yaml = format!("{HEAD}{extra}");
        let option: AnyTLSOption = yaml_serde::from_str(&yaml).expect("option decodes");
        AnyTLS::new(option).err().map(|err| err.to_string()).expect("rejected")
    }

    #[test]
    fn restls_is_exclusive_with_the_other_security_modes() {
        assert_eq!(
            new_err(&format!("{RESTLS}{SHADOW_TLS}")),
            "security modes are mutually exclusive: ShadowTLS, Restls"
        );
        assert_eq!(new_err(&format!("{RESTLS}{JLS}")), "security modes are mutually exclusive: Restls, JLS");
    }

    /// Accepting a config builds the transport client, whose session routine needs a Tokio runtime.
    #[tokio::test]
    async fn an_empty_block_leaves_the_security_mode_field_alone() {
        let yaml = format!("{HEAD}restls-opts:\n  password: \"\"\n  version-hint: \"\"\n");
        let option: AnyTLSOption = yaml_serde::from_str(&yaml).expect("option decodes");
        assert!(AnyTLS::new(option).is_ok());
    }
}
