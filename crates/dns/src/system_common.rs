use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{anyhow, Error, Result};

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
    /// Reads the platform resolver configuration when the flush window has elapsed, on a blocking
    /// thread: the path can be a network mount, and this is called from a runtime worker.
    ///
    /// The failure is returned rather than raised so the caller can report it only once the cache
    /// turns out to be empty.
    pub(crate) async fn refresh_dns_config(&self) -> Option<Error> {
        if !self.flush_due() {
            return None;
        }

        let config = match tokio::task::spawn_blocking(dns_read_config).await {
            Ok(config) => config,
            Err(err) => Err(anyhow!("the system resolver configuration read did not finish: {err}")),
        };
        self.apply_dns_config(config)
    }

    fn flush_due(&self) -> bool {
        self.state.lock().last_flush.elapsed().unwrap_or(SYSTEM_DNS_FLUSH_TIME) > SYSTEM_DNS_FLUSH_TIME
    }

    /// The window is re-checked under the lock so two concurrent refreshes cannot apply the same
    /// configuration twice.
    fn apply_dns_config(&self, config: Result<Vec<String>>) -> Option<Error> {
        let mut state = self.state.lock();
        if state.last_flush.elapsed().unwrap_or(SYSTEM_DNS_FLUSH_TIME) <= SYSTEM_DNS_FLUSH_TIME {
            return None;
        }
        let nameservers = match config {
            Ok(nameservers) => nameservers,
            Err(err) => return Some(err),
        };

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
                    state.dns_clients.insert(addr.clone(), SystemDnsClient { disable_times: 0, dns_client: client });
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
        None
    }

    /// The clients the cache holds, without touching the platform configuration: `address` is
    /// synchronous and the refresh belongs to [`Self::refresh_dns_config`].
    pub(crate) fn get_dns_clients(&self) -> Vec<Arc<dyn DnsClient>> {
        let state = self.state.lock();
        state
            .dns_clients
            .values()
            .filter(|client| client.disable_times == 0)
            .map(|client| Arc::clone(&client.dns_client))
            .collect()
    }

    #[expect(
        clippy::unused_self,
        reason = "the platform hook is symmetric with the android override that needs `self`; dropping the receiver would change the crate-visible signature"
    )]
    pub(crate) const fn reset_connection_impl(&self) {}
}
