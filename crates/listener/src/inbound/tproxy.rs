use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use murmur_constant::listener::{InboundConfig, InboundListener, Listener as ConstListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_tproxy::tproxy as tproxy_tcp;
use murmur_listener_tproxy::udp as tproxy_udp;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TProxyOption {
    pub base: BaseOption,
    pub udp: bool,
}

impl InboundConfig for TProxyOption {
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

pub struct TProxy {
    base: Base,
    config: Arc<TProxyOption>,
    l_udp: Mutex<Vec<Arc<tproxy_udp::UdpListener>>>,
    l_tcp: Mutex<Vec<Arc<tproxy_tcp::Listener>>>,
    udp: bool,
}

impl core::fmt::Debug for TProxy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TProxy").field("base", &self.base).field("config", &self.config).finish_non_exhaustive()
    }
}

impl TProxy {
    pub fn new(options: Arc<TProxyOption>) -> Result<Self> {
        let udp = options.udp;
        let base = Base::new(Arc::new(options.base.clone()))?;
        Ok(Self { base, config: options, l_udp: Mutex::new(Vec::new()), l_tcp: Mutex::new(Vec::new()), udp })
    }
}

#[async_trait]
impl InboundListener for TProxy {
    fn name(&self) -> String {
        self.base.config().name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let mut tcp_listeners = Vec::new();
        let mut udp_listeners = Vec::new();
        for addr in self.base.raw_address().split(',') {
            let l_tcp = tproxy_tcp::new(addr, Arc::clone(&tunnel), self.base.additions()).await?;
            tcp_listeners.push(l_tcp);
            if self.udp {
                let l_udp = tproxy_udp::new_udp(addr, Arc::clone(&tunnel), self.base.additions()).await?;
                udp_listeners.push(l_udp);
            }
        }
        *self.l_tcp.lock() = tcp_listeners;
        *self.l_udp.lock() = udp_listeners;
        infoln!("TProxy[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        let mut errs = Vec::new();
        for l in self.l_tcp.lock().iter() {
            if let Err(err) = l.close() {
                errs.push(format!("close tcp listener {} err: {err}", l.address()));
            }
        }
        for l in self.l_udp.lock().iter() {
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
        self.l_tcp.lock().iter().map(|l| l.address()).collect::<Vec<_>>().join(",")
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
    use super::*;
    use crate::inbound::tunnel::TunnelOption;

    #[test]
    fn equal_identical_configs() {
        let a = TProxyOption { base: BaseOption { name_str: "tp-1".into(), ..Default::default() }, udp: true };
        let b = TProxyOption { base: BaseOption { name_str: "tp-1".into(), ..Default::default() }, udp: true };
        assert!(InboundConfig::equal(&a, &b));
    }

    #[test]
    fn equal_rejects_differing_field() {
        let a = TProxyOption { base: BaseOption { name_str: "tp-1".into(), ..Default::default() }, udp: true };
        let b = TProxyOption { base: BaseOption { name_str: "tp-1".into(), ..Default::default() }, udp: false };
        assert!(!InboundConfig::equal(&a, &b));
    }

    #[test]
    fn equal_rejects_differing_serialized_fields_across_types() {
        let a = TProxyOption { base: BaseOption { name_str: "tp-1".into(), ..Default::default() }, udp: true };
        let other =
            TunnelOption { base: BaseOption { name_str: "tp-1".into(), ..Default::default() }, ..Default::default() };
        assert!(!InboundConfig::equal(&a, &other));
    }
}
