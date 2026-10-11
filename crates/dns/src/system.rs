use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use async_trait::async_trait;
use hickory_proto::op::Message;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use murmur_component::resolver::resolver::set_system_resolver;

use super::resolver::{Config, DnsClient, NameServer, NsNetType, Resolvers};
use super::util::{batch_exchange, transform};

pub(crate) const SYSTEM_DNS_FLUSH_TIME: Duration = Duration::from_secs(5 * 60);
/// The delete count: twelve rounds of five minutes, sixty minutes in total.
pub(crate) const SYSTEM_DNS_DELETE_TIMES: u32 = 12;

pub(crate) struct SystemDnsClient {
    pub(crate) disable_times: u32,
    pub(crate) dns_client: Arc<dyn DnsClient>,
}

/// The mutable half of [`SystemClient`], guarded by a mutex.
pub(crate) struct SystemClientState {
    pub(crate) dns_clients: HashMap<String, SystemDnsClient>,
    pub(crate) last_flush: SystemTime,
}

pub(crate) struct SystemClient {
    pub(crate) state: Mutex<SystemClientState>,
    default_ns: Vec<Arc<dyn DnsClient>>,
}

fn new_system_client_with_default_ns(default_ns: Vec<Arc<dyn DnsClient>>) -> Arc<SystemClient> {
    Arc::new(SystemClient {
        state: Mutex::new(SystemClientState { dns_clients: HashMap::new(), last_flush: SystemTime::UNIX_EPOCH }),
        default_ns,
    })
}

pub(crate) fn new_system_client() -> Arc<dyn DnsClient> {
    new_system_client_with_default_ns(Vec::new())
}

#[async_trait]
impl DnsClient for SystemClient {
    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        let config_err = self.refresh_dns_config().await;
        let mut clients = self.get_dns_clients();
        let no_cache = clients.is_empty();
        if no_cache && !self.default_ns.is_empty() {
            clients.clone_from(&self.default_ns);
        }
        // A read failure is only fatal when neither the cache nor the built-in set has anything.
        let err = if no_cache && self.default_ns.is_empty() { config_err } else { None };
        if let Some(err) = err {
            return Err(err);
        }
        let (msg, _cache) = batch_exchange(ctx, &clients, m).await?;
        Ok(msg)
    }

    fn address(&self) -> String {
        let mut clients = self.get_dns_clients();
        let is_default = if clients.is_empty() && !self.default_ns.is_empty() {
            clients.clone_from(&self.default_ns);
            "[defaultNS]"
        } else {
            ""
        };
        let addrs: Vec<String> = clients.iter().map(|client| client.address()).collect();
        format!("system{is_default}({})", addrs.join(","))
    }

    fn reset_connection(&self) {
        self.reset_connection_impl();
    }
}

/// Installs the default system resolver. `main.rs` calls this explicitly as its first statement:
/// there is no language-level package initializer to do it.
pub fn init() {
    let default_ns = transform(
        &[
            NameServer {
                net: NsNetType::Udp,
                addr: "114.114.114.114:53".to_owned(),
                proxy_adapter: None,
                proxy_name: String::new(),
                params: HashMap::new(),
                prefer_h3: false,
            },
            NameServer {
                net: NsNetType::Udp,
                addr: "8.8.8.8:53".to_owned(),
                proxy_adapter: None,
                proxy_name: String::new(),
                params: HashMap::new(),
                prefer_h3: false,
            },
        ],
        None,
    );
    let c = new_system_client_with_default_ns(default_ns);
    let mut resolvers = Resolvers::new(Config::default());
    resolvers.resolver.main = vec![c];
    set_system_resolver(Some(Arc::new(resolvers.resolver)));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `address` is synchronous, so the reopen of the flush window must not be served from the sync
    /// accessor: it reports the cache, and the read belongs to `refresh_dns_config`.
    #[test]
    fn the_sync_accessor_reports_the_cache_without_reading_the_platform_configuration() {
        let client = new_system_client_with_default_ns(Vec::new());

        assert!(
            client.get_dns_clients().is_empty(),
            "the synchronous accessor answered from the platform configuration instead of the cache"
        );
    }
}
