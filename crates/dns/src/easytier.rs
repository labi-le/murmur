use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::Message;
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;

use super::resolver::DnsClient;

struct EasyTierResolverEntry {
    id: u64,
    client: Arc<dyn DnsClient>,
}

static EASY_TIER_RESOLVER_ID: AtomicU64 = AtomicU64::new(0);
static EASY_TIER_RESOLVERS: LazyLock<RwLock<HashMap<String, EasyTierResolverEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub fn register_easy_tier_dns_client(name: &str, client: Arc<dyn DnsClient>) -> impl Fn() + Send + Sync + 'static {
    let id = EASY_TIER_RESOLVER_ID.fetch_add(1, Ordering::SeqCst) + 1;
    EASY_TIER_RESOLVERS.write().insert(name.to_owned(), EasyTierResolverEntry { id, client });

    let name = name.to_owned();
    move || {
        let mut resolvers = EASY_TIER_RESOLVERS.write();
        if resolvers.get(&name).is_some_and(|entry| entry.id == id) {
            resolvers.remove(&name);
        }
    }
}

pub(crate) struct EasyTierDnsClient {
    name: String,
}

pub(crate) fn new_easytier_client(addr: &str) -> Arc<dyn DnsClient> {
    Arc::new(EasyTierDnsClient { name: addr.to_owned() })
}

#[async_trait]
impl DnsClient for EasyTierDnsClient {
    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        let client = EASY_TIER_RESOLVERS.read().get(&self.name).map(|entry| Arc::clone(&entry.client));
        let Some(client) = client else {
            return Err(anyhow!("proxy {:?} does not provide EasyTier DNS", self.name));
        };
        client.exchange_context(ctx, m).await
    }

    fn address(&self) -> String {
        format!("easytier://{}", self.name)
    }

    fn reset_connection(&self) {}
}
