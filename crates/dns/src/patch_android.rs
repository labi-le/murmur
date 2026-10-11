#![cfg(feature = "cmfa")]

use std::sync::{Arc, LazyLock};

use anyhow::Result;
use parking_lot::RwLock;

use murmur_component::resolver::{clear_cache, reset_connection};

use super::resolver::{DnsClient, NameServer, NsNetType};
use super::system::SystemClient;
use super::util::transform;

static SYSTEM_RESOLVER: LazyLock<RwLock<Vec<Arc<dyn DnsClient>>>> = LazyLock::new(|| RwLock::new(Vec::new()));

pub fn flush_cache_with_default_resolver() {
    clear_cache();
    reset_connection();
}

pub fn update_system_dns(addr: &[String]) {
    if addr.is_empty() {
        *SYSTEM_RESOLVER.write() = Vec::new();
        return;
    }

    let ns: Vec<NameServer> = addr
        .iter()
        .map(|d| NameServer {
            net: NsNetType::Udp,
            addr: d.clone(),
            proxy_adapter: None,
            proxy_name: String::new(),
            params: std::collections::HashMap::new(),
            prefer_h3: false,
        })
        .collect();
    *SYSTEM_RESOLVER.write() = transform(&ns, None);
}

#[cfg(all(target_os = "android", feature = "cmfa"))]
impl SystemClient {
    pub(crate) fn get_dns_clients(&self) -> Result<Vec<Arc<dyn DnsClient>>> {
        Ok(SYSTEM_RESOLVER.read().clone())
    }

    pub(crate) fn reset_connection_impl(&self) {
        for client in SYSTEM_RESOLVER.read().iter() {
            client.reset_connection();
        }
    }
}
