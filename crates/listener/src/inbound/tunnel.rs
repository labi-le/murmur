use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::tunnel::tcp as tunnel_tcp;
use crate::tunnel::udp as tunnel_udp;
use murmur_constant::listener::{InboundConfig, InboundListener, Listener as ConstListener};
use murmur_constant::tunnel::Tunnel as TunnelTrait;
use murmur_log::infoln;
use murmur_log::warnln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TunnelOption {
    pub base: BaseOption,
    pub network: Vec<String>,
    pub target: String,
}

impl InboundConfig for TunnelOption {
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

pub struct Tunnel {
    base: Base,
    config: Arc<TunnelOption>,
    ttl: Mutex<Vec<Arc<tunnel_tcp::Listener>>>,
    tul: Mutex<Vec<Arc<tunnel_udp::PacketConn>>>,
}

impl core::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tunnel").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Tunnel {
    pub fn new(options: Arc<TunnelOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        Ok(Self { base, config: options, ttl: Mutex::new(Vec::new()), tul: Mutex::new(Vec::new()) })
    }
}

#[async_trait]
impl InboundListener for Tunnel {
    fn name(&self) -> String {
        self.base.config().name()
    }

    async fn listen(&self, tunnel: Arc<dyn TunnelTrait>) -> Result<()> {
        let lc = self.base.listen_config();
        let mut ttl = Vec::new();
        let mut tul = Vec::new();
        for addr in self.base.raw_address().split(',') {
            for network in &self.config.network {
                match network.as_str() {
                    "tcp" => {
                        let l = tunnel_tcp::new(
                            addr,
                            &self.config.target,
                            &self.config.base.special_proxy,
                            Arc::clone(&lc),
                            Arc::clone(&tunnel),
                            self.base.additions(),
                        )
                        .await?;
                        ttl.push(l);
                    }
                    "udp" => {
                        let l = tunnel_udp::new_udp(
                            addr,
                            &self.config.target,
                            &self.config.base.special_proxy,
                            Arc::clone(&lc),
                            Arc::clone(&tunnel),
                            self.base.additions(),
                        )
                        .await?;
                        tul.push(l);
                    }
                    other => {
                        warnln!("unknown network type: {other}, passed");
                    }
                }
            }
        }
        *self.ttl.lock() = ttl;
        *self.tul.lock() = tul;
        infoln!("Tunnel[{}]({})proxy listening at: {}", self.name(), self.config.target, self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        let mut errs = Vec::new();
        for l in self.ttl.lock().iter() {
            if let Err(err) = l.close() {
                errs.push(format!("close tcp listener {} err: {err}", l.address()));
            }
        }
        for l in self.tul.lock().iter() {
            if let Err(err) = l.close() {
                errs.push(format!("close udp listener {} err: {err}", l.address()));
            }
        }
        if !errs.is_empty() {
            return Err(anyhow::anyhow!(errs.join("\n")));
        }
        Ok(())
    }

    fn address(&self) -> String {
        let mut addr_list: Vec<String> = self.ttl.lock().iter().map(|l| format!("tcp://{}", l.address())).collect();
        addr_list.extend(self.tul.lock().iter().map(|l| format!("udp://{}", l.address())));
        addr_list.join(",")
    }

    fn raw_address(&self) -> String {
        self.base.raw_address()
    }

    fn config(&self) -> Arc<dyn InboundConfig> {
        upcast_config(Arc::clone(&self.config))
    }
}
