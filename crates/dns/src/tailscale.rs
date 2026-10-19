use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::Message;
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;

use super::resolver::DnsClient;

struct TailscaleResolverEntry {
    id: u64,
    client: Arc<dyn DnsClient>,
}

static TAILSCALE_RESOLVER_ID: AtomicU64 = AtomicU64::new(0);
static TAILSCALE_RESOLVERS: LazyLock<RwLock<HashMap<String, TailscaleResolverEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub fn register_tailscale_dns_client(name: &str, client: Arc<dyn DnsClient>) -> impl Fn() + Send + Sync + 'static {
    let id = TAILSCALE_RESOLVER_ID.fetch_add(1, Ordering::SeqCst) + 1;
    TAILSCALE_RESOLVERS.write().insert(name.to_owned(), TailscaleResolverEntry { id, client });

    let name = name.to_owned();
    move || {
        let mut resolvers = TAILSCALE_RESOLVERS.write();
        if resolvers.get(&name).is_some_and(|entry| entry.id == id) {
            resolvers.remove(&name);
        }
    }
}

pub(crate) struct TailscaleDnsClient {
    name: String,
}

pub(crate) fn new_tailscale_client(addr: &str) -> Arc<dyn DnsClient> {
    Arc::new(TailscaleDnsClient { name: addr.to_owned() })
}

#[async_trait]
impl DnsClient for TailscaleDnsClient {
    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        let client = TAILSCALE_RESOLVERS.read().get(&self.name).map(|entry| Arc::clone(&entry.client));
        let Some(client) = client else {
            return Err(anyhow!("proxy {:?} does not provide Tailscale DNS", self.name));
        };
        client.exchange_context(ctx, m).await
    }

    fn address(&self) -> String {
        format!("tailscale://{}", self.name)
    }

    fn reset_connection(&self) {}
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{MessageType, OpCode};

    use super::*;

    struct LabelledClient(&'static str);

    #[async_trait]
    impl DnsClient for LabelledClient {
        async fn exchange_context(&self, _ctx: &CancellationToken, _m: &Message) -> Result<Message> {
            Err(anyhow!("answered by {}", self.0))
        }

        fn address(&self) -> String {
            self.0.to_owned()
        }

        fn reset_connection(&self) {}
    }

    fn query() -> Message {
        Message::new(0, MessageType::Query, OpCode::Query)
    }

    #[tokio::test]
    async fn a_replaced_registration_outlives_the_handle_that_replaced_it() {
        let name = "replaced-proxy";
        let unregister_first = register_tailscale_dns_client(name, Arc::new(LabelledClient("first")));
        let unregister_second = register_tailscale_dns_client(name, Arc::new(LabelledClient("second")));
        let client = new_tailscale_client(name);
        let ctx = CancellationToken::new();

        unregister_first();
        assert_eq!(client.exchange_context(&ctx, &query()).await.unwrap_err().to_string(), "answered by second");

        unregister_second();
        assert_eq!(
            client.exchange_context(&ctx, &query()).await.unwrap_err().to_string(),
            "proxy \"replaced-proxy\" does not provide Tailscale DNS"
        );
    }

    #[test]
    fn an_unregistered_proxy_keeps_its_address() {
        assert_eq!(new_tailscale_client("never-registered").address(), "tailscale://never-registered");
    }
}
