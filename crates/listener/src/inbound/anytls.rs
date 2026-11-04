use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::anytls::server as anytls_server;
use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::inbound::jls::JLSConfig;
use crate::inbound::restls::ResTLS;
use crate::inbound::shadowtls::ShadowTLS;
use murmur_constant::listener::{InboundConfig, InboundListener, MultiAddrListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::anytls::AnyTLSServer;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct AnyTLSOption {
    pub base: BaseOption,
    pub users: BTreeMap<String, String>,
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub shadow_tls: ShadowTLS,
    pub res_tls: ResTLS,
    pub jls_config: JLSConfig,
    pub allow_insecure: bool,
    pub padding_scheme: String,
}

impl InboundConfig for AnyTLSOption {
    fn name(&self) -> String {
        self.base.name()
    }

    fn equal(&self, config: &dyn InboundConfig) -> bool {
        config_equal(self, config)
    }

    fn option_to_string(&self) -> String {
        option_to_string(self)
    }
}

pub struct AnyTLS {
    base: Base,
    config: Arc<AnyTLSOption>,
    l: Mutex<Option<Arc<dyn MultiAddrListener>>>,
    vs: AnyTLSServer,
}

impl core::fmt::Debug for AnyTLS {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AnyTLS").field("base", &self.base).field("config", &self.config).finish_non_exhaustive()
    }
}

impl AnyTLS {
    pub fn new(options: Arc<AnyTLSOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        let vs = AnyTLSServer {
            enable: true,
            listen: base.raw_address(),
            users: options.users.clone(),
            certificate: options.certificate.clone(),
            private_key: options.private_key.clone(),
            client_auth_type: options.client_auth_type.clone(),
            client_auth_cert: options.client_auth_cert.clone(),
            ech_key: options.ech_key.clone(),
            shadow_tls: options.shadow_tls.build(),
            res_tls: options.res_tls.build(),
            jls_config: options.jls_config.build(),
            allow_insecure: options.allow_insecure,
            padding_scheme: options.padding_scheme.clone(),
        };
        Ok(Self { base, config: options, l: Mutex::new(None), vs })
    }
}

#[async_trait]
impl InboundListener for AnyTLS {
    fn name(&self) -> String {
        self.base.config().name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let l = anytls_server::new(self.vs.clone(), self.base.listen_config(), tunnel, self.base.additions()).await?;
        *self.l.lock() = Some(l);
        infoln!("AnyTLS[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        if let Some(l) = self.l.lock().as_ref() {
            return l.close();
        }
        Ok(())
    }

    fn address(&self) -> String {
        let addr_list: Vec<String> = self
            .l
            .lock()
            .as_ref()
            .map(|l| l.addr_list().iter().map(|addr| addr.string()).collect())
            .unwrap_or_default();
        addr_list.join(",")
    }

    fn raw_address(&self) -> String {
        self.base.raw_address()
    }

    fn config(&self) -> Arc<dyn InboundConfig> {
        upcast_config(Arc::clone(&self.config))
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use super::*;
    use murmur_adapter_outbound::anytls::{AnyTLS as OutAnyTLS, AnyTLSOption as OutAnyTLSOption};
    use murmur_adapter_outbound::ech::ECHOptions;
    use murmur_constant::adapters::ProxyAdapter;
    use murmur_testsupport::{
        ech_config_base64, ech_key_pem, tls_auth_certificate, tls_auth_private_key, tls_certificate, tls_fingerprint,
        tls_private_key, HttpTestTunnel, USER_UUID,
    };

    async fn test_inbound_anytls(inbound_options: AnyTLSOption, mut outbound_options: OutAnyTLSOption) {
        let inbound_options = AnyTLSOption {
            base: BaseOption {
                name_str: "anytls_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            users: BTreeMap::from([("test".to_owned(), USER_UUID.clone())]),
            ..inbound_options
        };
        let inbound = AnyTLS::new(Arc::new(inbound_options)).expect("anytls inbound construction");

        let tunnel = HttpTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("anytls inbound listen");

        let addr_port: std::net::SocketAddr = inbound.address().parse().expect("bound address");

        outbound_options.name = "anytls_outbound".to_owned();
        outbound_options.server = addr_port.ip().to_string();
        outbound_options.port = addr_port.port() as i32;
        outbound_options.password = USER_UUID.clone();
        outbound_options.basic_option.dialer_for_api = Some(tunnel.new_dialer());
        let api_tunnel = Arc::clone(&tunnel);
        outbound_options.basic_option.tunnel_for_api = Some(api_tunnel);

        let out = OutAnyTLS::new(outbound_options).expect("anytls outbound construction");

        tunnel.do_test(out.as_ref()).await;

        let _ = out.close();
        inbound.close().expect("anytls inbound close");
        tunnel.close();
    }

    /// The session arms a three second SYNACK watchdog: it bounds a peer that dials behind the
    /// proxy, not the proxy's own dial. A current-thread runtime serializes the client handshake
    /// with the peer's dial, so a loaded test binary can starve that dial past the deadline and
    /// close the reused session mid-handshake; the multi-thread runtime lets the dial proceed the
    /// way the task scheduler does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_inbound_anytls_tls() {
        let inbound_options = AnyTLSOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ..Default::default()
        };
        let outbound_options = OutAnyTLSOption { fingerprint: tls_fingerprint().to_owned(), ..Default::default() };
        test_inbound_anytls(inbound_options.clone(), outbound_options.clone()).await;

        let mut ech_inbound = inbound_options.clone();
        ech_inbound.ech_key = ech_key_pem().to_owned();
        let mut ech_outbound = outbound_options.clone();
        ech_outbound.ech_opts =
            ECHOptions { enable: true, config: ech_config_base64().to_owned(), ..Default::default() };
        test_inbound_anytls(ech_inbound, ech_outbound).await;

        let mut mtls_inbound = inbound_options.clone();
        mtls_inbound.client_auth_cert = tls_auth_certificate().to_owned();
        let mut mtls_outbound = outbound_options.clone();
        mtls_outbound.certificate = tls_auth_certificate().to_owned();
        mtls_outbound.private_key = tls_auth_private_key().to_owned();
        test_inbound_anytls(mtls_inbound, mtls_outbound).await;

        let mut mtls_ech_inbound = inbound_options;
        mtls_ech_inbound.client_auth_cert = tls_auth_certificate().to_owned();
        mtls_ech_inbound.ech_key = ech_key_pem().to_owned();
        let mut mtls_ech_outbound = outbound_options;
        mtls_ech_outbound.certificate = tls_auth_certificate().to_owned();
        mtls_ech_outbound.private_key = tls_auth_private_key().to_owned();
        mtls_ech_outbound.ech_opts =
            ECHOptions { enable: true, config: ech_config_base64().to_owned(), ..Default::default() };
        test_inbound_anytls(mtls_ech_inbound, mtls_ech_outbound).await;
    }
}
