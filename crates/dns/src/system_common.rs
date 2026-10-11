use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;

use murmur_component::dialer::bind::join_host_port;
use murmur_component::resolver::system::is_system_dns_blacklisted;
use murmur_log::debugln;

#[cfg(not(target_os = "windows"))]
use super::system_posix::dns_read_config;
#[cfg(target_os = "windows")]
use super::system_windows::dns_read_config;

use super::resolver::{DnsClient, NameServer, NsNetType};
use super::system::{SystemClient, SystemDnsClient, SYSTEM_DNS_DELETE_TIMES, SYSTEM_DNS_FLUSH_TIME};
use super::util::transform;

#[cfg(any(not(target_os = "android"), not(feature = "cmfa")))]
impl SystemClient {
    pub(crate) fn get_dns_clients(&self) -> Result<Vec<Arc<dyn DnsClient>>> {
        let mut state = self.state.lock();
        let mut result_err = None;

        if state.last_flush.elapsed().unwrap_or(SYSTEM_DNS_FLUSH_TIME) > SYSTEM_DNS_FLUSH_TIME {
            match dns_read_config() {
                Ok(nameservers) => {
                    debugln!("[DNS] system dns update to {nameservers:?}");
                    for addr in &nameservers {
                        if is_system_dns_blacklisted(&[addr.as_str()]) {
                            continue;
                        }
                        if !state.dns_clients.contains_key(addr) {
                            let clients = transform(
                                &[NameServer {
                                    net: NsNetType::Udp,
                                    addr: join_host_port(addr, "53"),
                                    proxy_adapter: None,
                                    proxy_name: String::new(),
                                    params: std::collections::HashMap::new(),
                                    prefer_h3: false,
                                }],
                                None,
                            );
                            if let Some(client) = clients.into_iter().next() {
                                state
                                    .dns_clients
                                    .insert(addr.clone(), SystemDnsClient { disable_times: 0, dns_client: client });
                            }
                        }
                    }

                    let mut available = 0u32;
                    let known: Vec<String> = state.dns_clients.keys().cloned().collect();
                    for nameserver in known {
                        let keep = nameservers.contains(&nameserver);
                        let Some(entry) = state.dns_clients.get_mut(&nameserver) else {
                            continue;
                        };
                        if keep {
                            entry.disable_times = 0;
                            available += 1;
                        } else if entry.disable_times > SYSTEM_DNS_DELETE_TIMES {
                            state.dns_clients.remove(&nameserver);
                        } else {
                            entry.disable_times += 1;
                        }
                    }
                    if available > 0 {
                        state.last_flush = SystemTime::now();
                    }
                }
                Err(err) => result_err = Some(err),
            }
        }

        let dns_clients: Vec<Arc<dyn DnsClient>> = state
            .dns_clients
            .values()
            .filter(|client| client.disable_times == 0)
            .map(|client| Arc::clone(&client.dns_client))
            .collect();
        drop(state);

        if !dns_clients.is_empty() {
            return Ok(dns_clients);
        }
        match result_err {
            Some(err) => Err(err),
            None => Ok(Vec::new()),
        }
    }

    #[expect(
        clippy::unused_self,
        reason = "the platform hook is symmetric with the android override that needs `self`; dropping the receiver would change the crate-visible signature"
    )]
    pub(crate) const fn reset_connection_impl(&self) {}
}
