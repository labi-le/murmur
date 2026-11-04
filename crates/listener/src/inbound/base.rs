use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use murmur_adapter_inbound::addition::{with_in_name, with_special_proxy, with_special_rules, Addition};
use murmur_adapter_inbound::listen::new_listen_config;
use murmur_common::utils::ranges::{new_unsigned_ranges, IntRanges};
use murmur_constant::listener::{InboundConfig, InboundListenConfig, InboundListener};
use murmur_constant::tunnel::Tunnel;

#[derive(Debug)]
pub struct Base {
    config: Arc<BaseOption>,
    name: String,
    listen_addr: IpAddr,
    ports: IntRanges<u16>,
}

impl Base {
    pub fn new(options: Arc<BaseOption>) -> Result<Self> {
        let mut owned = Arc::unwrap_or_clone(options);
        if owned.listen.is_empty() {
            "0.0.0.0".clone_into(&mut owned.listen);
        }
        let addr = IpAddr::from_str(&owned.listen)?;
        let ports = new_unsigned_ranges::<u16>(&owned.port)?;
        let name = owned.name();
        Ok(Self { name, listen_addr: addr, ports, config: Arc::new(owned) })
    }

    #[must_use]
    pub fn raw_address(&self) -> String {
        if self.ports.is_empty() {
            return SocketAddr::new(self.listen_addr, 0).to_string();
        }
        let mut address = Vec::with_capacity(self.ports.len());
        self.ports.range(|port| {
            address.push(SocketAddr::new(self.listen_addr, port).to_string());
            true
        });
        address.join(",")
    }

    #[must_use]
    pub fn additions(&self) -> Vec<Addition> {
        self.config.additions()
    }

    #[must_use]
    pub fn listen_config(&self) -> Arc<dyn InboundListenConfig> {
        self.config.listen_config()
    }

    #[must_use]
    pub fn config(&self) -> Arc<BaseOption> {
        Arc::clone(&self.config)
    }
}

#[async_trait]
impl InboundListener for Base {
    fn name(&self) -> String {
        self.name.clone()
    }

    async fn listen(&self, _tunnel: Arc<dyn Tunnel>) -> Result<()> {
        Ok(())
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }

    fn address(&self) -> String {
        Self::raw_address(self)
    }

    fn raw_address(&self) -> String {
        Self::raw_address(self)
    }

    fn config(&self) -> Arc<dyn InboundConfig> {
        upcast_config(Arc::clone(&self.config))
    }
}

#[derive(Clone, Default, serde::Serialize)]
pub struct BaseOption {
    pub name_str: String,
    pub listen: String,
    pub port: String,
    pub special_rules: String,
    pub special_proxy: String,
    pub routing_mark: i32,
    #[serde(skip)]
    pub listen_config_for_api: Option<Arc<dyn InboundListenConfig>>,
}

impl std::fmt::Debug for BaseOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BaseOption")
            .field("name_str", &self.name_str)
            .field("listen", &self.listen)
            .field("port", &self.port)
            .field("special_rules", &self.special_rules)
            .field("special_proxy", &self.special_proxy)
            .field("routing_mark", &self.routing_mark)
            .field("listen_config_for_api", &self.listen_config_for_api.is_some())
            .finish()
    }
}

impl BaseOption {
    #[must_use]
    pub fn name(&self) -> String {
        self.name_str.clone()
    }

    #[must_use]
    pub fn additions(&self) -> Vec<Addition> {
        vec![
            with_in_name(&self.name_str),
            with_special_rules(&self.special_rules),
            with_special_proxy(&self.special_proxy),
        ]
    }

    #[must_use]
    pub fn listen_config(&self) -> Arc<dyn InboundListenConfig> {
        if let Some(lc) = &self.listen_config_for_api {
            return Arc::clone(lc);
        }
        let mut lc = new_listen_config();
        lc.set_route_mark(self.routing_mark);
        Arc::new(lc)
    }
}

impl InboundConfig for BaseOption {
    fn name(&self) -> String {
        self.name()
    }

    fn equal(&self, config: &dyn InboundConfig) -> bool {
        config_equal(self, config)
    }

    fn option_to_string(&self) -> String {
        option_to_string(self)
    }
}

pub fn option_to_string<T: serde::Serialize>(option: &T) -> String {
    serde_json::to_string(option).unwrap_or_default()
}

pub fn config_equal(this: &dyn InboundConfig, config: &dyn InboundConfig) -> bool {
    this.option_to_string() == config.option_to_string()
}

/// Upcasts a listener's concrete option pointer to the `Arc<dyn InboundConfig>` its `config`
/// returns.
#[must_use]
pub fn upcast_config<T: InboundConfig + 'static>(config: Arc<T>) -> Arc<dyn InboundConfig> {
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::tproxy::TProxyOption;

    #[test]
    fn equal_identical_configs() {
        let a = BaseOption { name_str: "in-1".into(), listen: "0.0.0.0".into(), ..Default::default() };
        let b = BaseOption { name_str: "in-1".into(), listen: "0.0.0.0".into(), ..Default::default() };
        assert!(InboundConfig::equal(&a, &b));
    }

    #[test]
    fn equal_rejects_differing_field() {
        let a = BaseOption { name_str: "in-1".into(), ..Default::default() };
        let b = BaseOption { name_str: "in-2".into(), ..Default::default() };
        assert!(!InboundConfig::equal(&a, &b));
    }
    #[test]
    fn equal_rejects_differing_serialized_fields_across_types() {
        let a = BaseOption { name_str: "in-1".into(), ..Default::default() };
        let other = TProxyOption { base: BaseOption { name_str: "in-1".into(), ..Default::default() }, udp: false };
        assert!(!InboundConfig::equal(&a, &other));
    }
}
