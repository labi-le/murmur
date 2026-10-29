use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::http::server as http_server;
use crate::inbound::auth::{get_auth_store, AuthUsers};
use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use murmur_constant::listener::{InboundConfig, InboundListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::auth::AuthServer;
use murmur_listener_config::reality::RealityConfig;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct HTTPOption {
    pub base: BaseOption,
    pub users: AuthUsers,
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub reality_config: Option<RealityConfig>,
}

impl InboundConfig for HTTPOption {
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

#[derive(Debug)]
pub struct HTTP {
    base: Base,
    config: Arc<HTTPOption>,
    l: Mutex<Vec<http_server::Listener>>,
}

impl HTTP {
    pub fn new(options: Arc<HTTPOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        Ok(Self { base, config: options, l: Mutex::new(Vec::new()) })
    }
}

#[async_trait]
impl InboundListener for HTTP {
    fn name(&self) -> String {
        self.base.config().name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let lc = self.base.listen_config();
        let mut listeners = Vec::new();
        for addr in self.base.raw_address().split(',') {
            let config = AuthServer {
                enable: true,
                listen: addr.to_owned(),
                auth_store: get_auth_store(&self.config.users),
                certificate: self.config.certificate.clone(),
                private_key: self.config.private_key.clone(),
                client_auth_type: self.config.client_auth_type.clone(),
                client_auth_cert: self.config.client_auth_cert.clone(),
                ech_key: self.config.ech_key.clone(),
                reality_config: self.config.reality_config.clone(),
            };
            let l = http_server::new_with_config(config, Arc::clone(&lc), Arc::clone(&tunnel), &self.base.additions())
                .await?;
            listeners.push(l);
        }
        *self.l.lock() = listeners;
        infoln!("HTTP[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        let mut errs = Vec::new();
        for l in self.l.lock().iter() {
            if let Err(err) = l.close() {
                errs.push(format!("close tcp listener {} err: {err}", l.address()));
            }
        }
        if !errs.is_empty() {
            return Err(anyhow::anyhow!(errs.join("\n")));
        }
        Ok(())
    }

    fn address(&self) -> String {
        self.l.lock().iter().map(http_server::Listener::address).collect::<Vec<_>>().join(",")
    }

    fn raw_address(&self) -> String {
        self.base.raw_address()
    }

    fn config(&self) -> Arc<dyn InboundConfig> {
        upcast_config(Arc::clone(&self.config))
    }
}
