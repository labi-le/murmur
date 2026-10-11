use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::redir::tcp as redir_tcp;
use murmur_constant::listener::{InboundConfig, InboundListener, Listener as ConstListener};
use murmur_constant::tunnel::Tunnel;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct RedirOption {
    pub base: BaseOption,
}

impl InboundConfig for RedirOption {
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

pub struct Redir {
    base: Base,
    config: Arc<RedirOption>,
    l: Mutex<Vec<redir_tcp::Listener>>,
}

impl core::fmt::Debug for Redir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Redir").field("base", &self.base).field("config", &self.config).finish_non_exhaustive()
    }
}

impl Redir {
    pub fn new(options: Arc<RedirOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        Ok(Self { base, config: options, l: Mutex::new(Vec::new()) })
    }
}

#[async_trait]
impl InboundListener for Redir {
    fn name(&self) -> String {
        self.base.config().name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let mut listeners = Vec::new();
        for addr in self.base.raw_address().split(',') {
            let l = redir_tcp::new(addr, Arc::clone(&tunnel), &self.base.additions()).await?;
            listeners.push(l);
        }
        *self.l.lock() = listeners;
        infoln!("Redir[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        let mut errs = Vec::new();
        for l in self.l.lock().iter() {
            if let Err(err) = l.close() {
                errs.push(format!("close redir listener {} err: {err}", l.address()));
            }
        }
        if !errs.is_empty() {
            return Err(anyhow::anyhow!(errs.join("\n")));
        }
        Ok(())
    }

    fn address(&self) -> String {
        self.l.lock().iter().map(murmur_constant::listener::Listener::address).collect::<Vec<_>>().join(",")
    }

    fn raw_address(&self) -> String {
        self.base.raw_address()
    }

    fn config(&self) -> Arc<dyn InboundConfig> {
        upcast_config(Arc::clone(&self.config))
    }
}
