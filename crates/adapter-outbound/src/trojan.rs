use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::ech::ECHOptions;
use crate::shadowtls::ShadowTLSOptions;
use crate::vmess::{GrpcOptions, WsOptions};
use murmur_common::shared_conn::SharedConn;
use murmur_common_net::{setup_context_for_conn, split_host_port};
use murmur_component::dialer::bind::join_host_port;
use murmur_component_ca as ca;
use murmur_component_ech::ech::Config as EchConfig;
use murmur_component_tls::utls as tls_c;
use murmur_constant::adapters::{
    Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport::gun;
use murmur_transport::trojan::trojan as trojan_transport;
use murmur_transport_shadowsocks::core::cipher::{pick_cipher, Cipher};
use murmur_transport_shadowtls as shadowtls;
use murmur_transport_vmess::tls::TlsConfig;
use murmur_transport_vmess::websocket::{stream_websocket_conn_public, WebsocketConfig};

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::util::serializes_socks_addr;

pub struct Trojan {
    base: Base,
    option: TrojanOption,
    hex_password: [u8; trojan_transport::KEY_LENGTH],

    gun_client: Option<Arc<gun::gun::Client>>,

    ech_config: Option<Arc<EchConfig>>,
    shadow_tls_config: Option<shadowtls::client::Config>,
    jls_config: Option<murmur_transport_jls::Config>,
    restls_config: Option<Arc<murmur_restls::Config>>,
    reality_config: Option<Arc<murmur_reality::RealityClientConfig>>,

    ss_cipher: Option<Box<dyn Cipher>>,

    self_weak: Weak<Self>,
}

impl core::fmt::Debug for Trojan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `hex_password` and the nested option blocks must never reach a log.
        f.debug_struct("Trojan").field("name", &self.base.name).finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TrojanOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port")]
    pub port: i32,
    #[serde(rename = "password")]
    pub password: String,
    #[serde(rename = "alpn", default)]
    pub alpn: Option<Vec<String>>,
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
    #[serde(rename = "udp", default)]
    pub udp: bool,
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
    #[serde(rename = "grpc-opts", default)]
    pub grpc_opts: GrpcOptions,
    #[serde(rename = "ws-opts", default)]
    pub ws_opts: WsOptions,
    #[serde(rename = "ss-opts", default)]
    pub ss_opts: TrojanSsOption,
    #[serde(rename = "client-fingerprint", default)]
    pub client_fingerprint: String,
}

impl core::fmt::Debug for TrojanOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `basic_option` has no `Debug`; the credentials and the plugin blocks are never printed.
        f.debug_struct("TrojanOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("sni", &self.sni)
            .field("network", &self.network)
            .field("udp", &self.udp)
            .field("password", &"<redacted>")
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// `TrojanSSOption`: the shadowsocks plugin block carried alongside trojan.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TrojanSsOption {
    #[serde(rename = "enabled", default)]
    pub enabled: bool,
    #[serde(rename = "method", default)]
    pub method: String,
    #[serde(rename = "password", default)]
    pub password: String,
}

impl core::fmt::Debug for TrojanSsOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The plugin password must never reach a log.
        f.debug_struct("TrojanSsOption")
            .field("enabled", &self.enabled)
            .field("method", &self.method)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Trojan {
    #[expect(
        clippy::too_many_lines,
        reason = "linear option assembly: each parsed config feeds the client in one pass"
    )]
    pub fn new(mut option: TrojanOption) -> Result<Arc<Self>> {
        let port = u16::try_from(option.port).map_err(|_| anyhow!("invalid port"))?;
        let addr = join_host_port(&option.server, port);

        if option.sni.is_empty() {
            option.sni.clone_from(&option.server);
        }

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr,
            type_: murmur_constant::adapters::AdapterType::TROJAN,
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

        let hex_password = trojan_transport::key(&option.password);

        let ech_config = option.ech_opts.parse()?.map(Arc::new);
        let shadow_tls_config = option.shadow_tls_opts.parse()?;
        let restls_config = option.restls_opts.parse(&option.sni)?;
        let jls_config = option.jls_opts.parse()?;
        let reality_config = option.reality_opts.parse()?.map(Arc::new);

        let mut security_modes: Vec<&'static str> = Vec::with_capacity(3);
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
        if security_modes.len() > 1 {
            return Err(anyhow!("security modes are mutually exclusive: {}", security_modes.join(", ")));
        }

        let ss_cipher = if option.ss_opts.enabled {
            if option.ss_opts.password.is_empty() {
                return Err(anyhow!("empty password"));
            }
            if option.ss_opts.method.is_empty() {
                "AES-128-GCM".clone_into(&mut option.ss_opts.method);
            }
            Some(pick_cipher(&option.ss_opts.method, None, &option.ss_opts.password)?)
        } else {
            None
        };

        let gun_client = if option.network == "grpc" {
            let dial_addr = base.addr.clone();
            let dialer_for_gun = base.dialer.clone().ok_or_else(|| anyhow!("dialer set above"))?;
            let dial_fn: gun::gun::DialFn = Arc::new(move |ctx, _network, _addr| {
                let dialer_for_gun = Arc::clone(&dialer_for_gun);
                let dial_addr = dial_addr.clone();
                Box::pin(async move {
                    let stream = dialer_for_gun
                        .dial_context(&ctx, "tcp", &dial_addr)
                        .await
                        .map_err(|e| anyhow!("{dial_addr} connect error: {e}"))?;
                    let conn: Box<dyn murmur_std_compat::net::Conn> =
                        Box::new(murmur_common_net::io::StreamAsOldConn::new(stream)); // S11: remove with std-compat
                    Ok(conn)
                })
            });

            let tls_config = TlsConfig {
                host: option.sni.clone(),
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

            let gun_config = gun::gun::Config {
                service_name: option.grpc_opts.grpc_service_name.clone(),
                user_agent: option.grpc_opts.grpc_user_agent.clone(),
                host: option.sni.clone(),
                ping_interval: option.grpc_opts.ping_interval,
            };

            let maker: Arc<dyn Fn() -> Arc<gun::gun::Transport> + Send + Sync> = Arc::new(move || {
                gun::gun::new_transport(Arc::clone(&dial_fn), Some(tls_config.clone()), gun_config.clone())
            });

            let client = gun::gun::new_client(
                maker,
                option.grpc_opts.max_connections,
                option.grpc_opts.min_streams,
                option.grpc_opts.max_streams,
            );
            Some(Arc::new(client))
        } else {
            None
        };

        let this = Arc::new_cyclic(|self_weak| Self {
            base,
            hex_password,
            gun_client,
            ech_config,
            shadow_tls_config,
            restls_config,
            jls_config,
            reality_config,
            ss_cipher,
            self_weak: Weak::clone(self_weak),
            option,
        });

        Ok(this)
    }

    #[expect(clippy::too_many_lines, reason = "the ws/grpc/default branch order mirrors the TLS wrapping order")]
    async fn stream_conn_context(
        &self,
        ctx: &CancellationToken,
        mut c: Box<dyn NetConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn NetConn>> {
        match self.option.network.as_str() {
            "ws" => {
                let (host, port, _) = split_host_port(&self.base.addr).unwrap_or_default();

                let mut ws_opts = WebsocketConfig {
                    host,
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

                if !self.option.sni.is_empty() {
                    ws_opts.host = self.option.sni.clone();
                }

                for (key, value) in &self.option.ws_opts.headers {
                    ws_opts.headers.push((key.clone(), value.clone()));
                }

                let alpn = if let Some(alpn) = &self.option.alpn {
                    alpn.clone()
                } else {
                    trojan_transport::DEFAULT_WEBSOCKET_ALPN.iter().map(|s| (*s).to_owned()).collect()
                };

                if self.shadow_tls_config.is_some() || self.restls_config.is_some() || self.jls_config.is_some() {
                    c = Box::new(murmur_common_net::io::StreamAsOldConn::new(
                        murmur_transport_vmess::tls::stream_tls_conn(
                            ctx,
                            Box::new(murmur_common_net::io::OldConnAsStream(c)),
                            &TlsConfig {
                                host: self.option.sni.clone(),
                                skip_cert_verify: self.option.skip_cert_verify,
                                name_cert_verify: self.option.name_cert_verify.clone(),
                                finger_print: self.option.fingerprint.clone(),
                                certificate: self.option.certificate.clone(),
                                private_key: self.option.private_key.clone(),
                                client_fingerprint: self.option.client_fingerprint.clone(),
                                next_protos: vec!["http/1.1".to_owned()],
                                ech: None,
                                shadow_tls: self.shadow_tls_config.clone(),
                                restls: self.restls_config.clone(),
                                jls: self.jls_config.clone(),
                                tls_mirror: None,
                                tls_mirror_dialer: None,
                                reality: None,
                            },
                        )
                        .await?,
                    ));
                } else {
                    ws_opts.tls = true;
                    let tls_config = ca::config::get_tls_config(ca::config::Option {
                        tls_config: Some(tls_c::Config {
                            next_protos: alpn,
                            min_version: tls_c::VERSION_TLS12,
                            insecure_skip_verify: self.option.skip_cert_verify,
                            server_name: self.option.sni.clone(),
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
                        fingerprint: self.option.fingerprint.clone(),
                        name_cert_verify: self.option.name_cert_verify.clone(),
                        certificate: self.option.certificate.clone(),
                        private_key: self.option.private_key.clone(),
                        zero_trust: false,
                    })?;
                    ws_opts.tls_config = Some(Arc::new(tls_config));
                }

                c = stream_websocket_conn_public(ctx, c, ws_opts).await?;
            }
            "grpc" => {}
            _ => {
                let alpn = if let Some(alpn) = &self.option.alpn {
                    alpn.clone()
                } else {
                    trojan_transport::DEFAULT_ALPN.iter().map(|s| (*s).to_owned()).collect()
                };
                c = Box::new(murmur_common_net::io::StreamAsOldConn::new(
                    murmur_transport_vmess::tls::stream_tls_conn(
                        ctx,
                        Box::new(murmur_common_net::io::OldConnAsStream(c)),
                        &TlsConfig {
                            host: self.option.sni.clone(),
                            skip_cert_verify: self.option.skip_cert_verify,
                            name_cert_verify: self.option.name_cert_verify.clone(),
                            finger_print: self.option.fingerprint.clone(),
                            certificate: self.option.certificate.clone(),
                            private_key: self.option.private_key.clone(),
                            client_fingerprint: self.option.client_fingerprint.clone(),
                            next_protos: alpn,
                            ech: self.ech_config.clone(),
                            shadow_tls: self.shadow_tls_config.clone(),
                            restls: self.restls_config.clone(),
                            jls: self.jls_config.clone(),
                            tls_mirror: None,
                            tls_mirror_dialer: None,
                            reality: self.reality_config.clone(),
                        },
                    )
                    .await?,
                ));
            }
        }

        self.write_trojan_header(ctx, c, metadata).await
    }

    async fn write_trojan_header(
        &self,
        ctx: &CancellationToken,
        c: Box<dyn NetConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn NetConn>> {
        let c: Box<dyn NetConn> = match &self.ss_cipher {
            Some(cipher) => cipher.stream_conn(c)?,
            None => c,
        };

        let shared = SharedConn::from_boxed(c);
        let mut done = setup_context_for_conn(ctx, shared.clone());

        let command = if metadata.network == NetWork::UDP {
            trojan_transport::COMMAND_UDP
        } else {
            trojan_transport::COMMAND_TCP
        };
        let addr = serializes_socks_addr(metadata);
        let result = trojan_transport::write_header(&mut shared.clone(), &self.hex_password, command, &addr).await;

        let mut err = result.err().map(anyhow::Error::new);
        done.call(&mut err).await;
        match err {
            Some(err) => Err(err),
            None => Ok(Box::new(shared)),
        }
    }

    async fn raw_dial_context(&self, ctx: &CancellationToken) -> Result<Box<dyn NetConn>> {
        if self.option.network == "grpc" {
            let client = self.gun_client.as_ref().ok_or_else(|| anyhow!("gun client set when network is grpc"))?;
            return client.dial().await;
        }
        let dialer = self
            .base
            .dialer
            .as_ref()
            .ok_or_else(|| anyhow!("Base.dialer set by NewTrojan before DialContext is called"))?;
        let stream = dialer.dial_context(ctx, "tcp", &self.base.addr).await?;
        Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(stream))) // S11: remove with std-compat
    }
}

#[async_trait]
impl CProxyAdapter for Trojan {
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
        let c = self.raw_dial_context(ctx).await.map_err(|e| anyhow!("{}: connect error: {e}", self.base.addr))?;

        let c = self
            .stream_conn_context(ctx, c, metadata)
            .await
            .map_err(|e| anyhow!("{}: connect error: {e}", self.base.addr))?;

        // S11: remove with std-compat
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(c)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.resolve_udp(ctx, metadata).await?;

        let c = self.raw_dial_context(ctx).await.map_err(|e| anyhow!("{}: connect error: {e}", self.base.addr))?;

        let c = self
            .stream_conn_context(ctx, c, metadata)
            .await
            .map_err(|e| anyhow!("{}: connect error: {e}", self.base.addr))?;

        let pc = trojan_transport::new_packet_conn(c);
        let self_arc =
            self.self_weak.upgrade().ok_or_else(|| anyhow!("Trojan dropped while listen_packet_context is running"))?;
        Ok(new_packet_conn(Arc::new(pc), self_arc))
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
        let mut errs = Vec::new();
        if let Some(client) = &self.gun_client {
            if let Err(e) = client.close() {
                errs.push(e.to_string());
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(errs.join("\n")))
        }
    }
}

#[async_trait]
impl ProxyAdapter for Trojan {
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
    const REALITY: &str = "reality-opts:\n  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
    const HEAD: &str = "name: t\nserver: example.com\nport: 443\npassword: p\n";

    fn new_err(extra: &str) -> String {
        let yaml = format!("{HEAD}{extra}");
        let option: TrojanOption = serde_yaml::from_str(&yaml).expect("option decodes");
        Trojan::new(option).err().map(|err| err.to_string()).expect("rejected")
    }

    #[test]
    fn credentials_select_jls_while_empty_ones_select_nothing() {
        let yaml = format!("{HEAD}{JLS}");
        let option: TrojanOption = serde_yaml::from_str(&yaml).expect("option decodes");
        let trojan = Trojan::new(option).expect("accepted");
        let config = trojan.jls_config.as_ref().expect("JLS selected");
        assert_eq!((config.user.username.as_str(), config.user.password.as_str()), ("user", "pass"));

        let yaml = format!("{HEAD}jls-opts:\n  username: \"\"\n  password: \"\"\n");
        let option: TrojanOption = serde_yaml::from_str(&yaml).expect("option decodes");
        assert!(Trojan::new(option).expect("accepted").jls_config.is_none());

        // The credential has to be present and empty: a block that leaves it out already fails to
        // decode (see `crate::jls`), so only this reaches the JLS config parse.
        assert_eq!(new_err("jls-opts:\n  username: \"\"\n  password: pass\n"), "jls: username is required");
    }

    #[test]
    fn jls_is_exclusive_with_the_other_security_modes() {
        assert_eq!(new_err(&format!("{JLS}{SHADOW_TLS}")), "security modes are mutually exclusive: ShadowTLS, JLS");
        assert_eq!(new_err(&format!("{JLS}{REALITY}")), "security modes are mutually exclusive: JLS, REALITY");
    }
}

#[cfg(test)]
mod restls_option_tests {
    use super::*;

    const RESTLS: &str = "restls-opts:\n  password: p\n  version-hint: tls13\n";
    const JLS: &str = "jls-opts:\n  username: user\n  password: pass\n";
    const SHADOW_TLS: &str = "shadow-tls-opts:\n  password: p\n  version: 3\n";
    const REALITY: &str = "reality-opts:\n  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
    const HEAD: &str = "name: t\nserver: example.com\nport: 443\npassword: p\n";

    fn new_err(extra: &str) -> String {
        let yaml = format!("{HEAD}{extra}");
        let option: TrojanOption = serde_yaml::from_str(&yaml).expect("option decodes");
        Trojan::new(option).err().map(|err| err.to_string()).expect("rejected")
    }

    #[test]
    fn restls_is_exclusive_with_the_other_security_modes() {
        assert_eq!(
            new_err(&format!("{RESTLS}{SHADOW_TLS}")),
            "security modes are mutually exclusive: ShadowTLS, Restls"
        );
        assert_eq!(new_err(&format!("{RESTLS}{JLS}")), "security modes are mutually exclusive: Restls, JLS");
        assert_eq!(new_err(&format!("{RESTLS}{REALITY}")), "security modes are mutually exclusive: Restls, REALITY");
    }

    /// `restls-opts` is parsed with the SNI, which construction has already defaulted to the server
    /// — so an unset `sni` must not leave the Restls server name empty.
    #[test]
    fn the_restls_server_name_follows_the_sni_default() {
        let yaml = format!("{HEAD}{RESTLS}");
        let option: TrojanOption = serde_yaml::from_str(&yaml).expect("option decodes");
        let trojan = Trojan::new(option).expect("accepted");
        let config = trojan.restls_config.as_ref().expect("Restls selected");
        assert_eq!(config.server_name, "example.com");

        let yaml = format!("{HEAD}sni: sni.example\n{RESTLS}");
        let option: TrojanOption = serde_yaml::from_str(&yaml).expect("option decodes");
        let trojan = Trojan::new(option).expect("accepted");
        let config = trojan.restls_config.as_ref().expect("Restls selected");
        assert_eq!(config.server_name, "sni.example");
    }

    #[test]
    fn an_empty_block_leaves_the_security_mode_field_alone() {
        let yaml = format!("{HEAD}restls-opts:\n  password: \"\"\n  version-hint: \"\"\n");
        let option: TrojanOption = serde_yaml::from_str(&yaml).expect("option decodes");
        assert!(Trojan::new(option).expect("accepted").restls_config.is_none());
    }
}
