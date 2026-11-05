use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::hysteria2_realm::server::Listener as RealmListener;
use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use murmur_constant::listener::{InboundConfig, InboundListener, MultiAddrListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::hysteria2_realm as lc_hysteria2_realm;
use murmur_log::infoln;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Hysteria2RealmServerOption {
    pub base: BaseOption,
    pub token: String,
    pub max_realms: i32,
    pub max_realms_per_ip: i32,
    pub trusted_proxy_header: String,
    pub realm_name_pattern: String,
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub alpn: Vec<String>,
}

impl InboundConfig for Hysteria2RealmServerOption {
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

pub struct Hysteria2RealmServer {
    base: Base,
    config: Arc<Hysteria2RealmServerOption>,
    l: Mutex<Option<Arc<dyn MultiAddrListener>>>,
    ts: lc_hysteria2_realm::Hysteria2RealmServer,
}

impl core::fmt::Debug for Hysteria2RealmServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hysteria2RealmServer")
            .field("base", &self.base)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Hysteria2RealmServer {
    pub fn new(options: Arc<Hysteria2RealmServerOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        let ts = lc_hysteria2_realm::Hysteria2RealmServer {
            enable: true,
            listen: base.raw_address(),
            token: options.token.clone(),
            max_realms: options.max_realms,
            max_realms_per_ip: options.max_realms_per_ip,
            trusted_proxy_header: options.trusted_proxy_header.clone(),
            realm_name_pattern: options.realm_name_pattern.clone(),
            certificate: options.certificate.clone(),
            private_key: options.private_key.clone(),
            client_auth_type: options.client_auth_type.clone(),
            client_auth_cert: options.client_auth_cert.clone(),
            ech_key: options.ech_key.clone(),
            alpn: options.alpn.clone(),
        };
        Ok(Self { base, config: options, l: Mutex::new(None), ts })
    }
}

#[async_trait]
impl InboundListener for Hysteria2RealmServer {
    fn name(&self) -> String {
        self.config.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let listener: Arc<dyn MultiAddrListener> = Arc::new(
            RealmListener::new(self.ts.clone(), self.base.listen_config(), tunnel, &self.base.additions()).await?,
        );
        *self.l.lock() = Some(listener);
        infoln!("Hysteria2_Realm[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        if let Some(l) = self.l.lock().as_ref() {
            return l.close();
        }
        Ok(())
    }

    fn address(&self) -> String {
        let addr_list: Vec<String> =
            self.l.lock().as_ref().map(|l| l.addr_list().iter().map(|a| a.string()).collect()).unwrap_or_default();
        addr_list.join(",")
    }

    fn raw_address(&self) -> String {
        self.base.raw_address()
    }

    fn config(&self) -> Arc<dyn InboundConfig> {
        upcast_config(Arc::clone(&self.config))
    }
}
