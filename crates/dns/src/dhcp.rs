use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::Message;
use ipnet::IpNet;
use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use murmur_component::dhcp::dhcp::resolve_dns_from_dhcp;
use murmur_component::dialer::bind::join_host_port;
use murmur_component::iface::iface::resolve_interface;

use super::resolver::{DnsClient, NameServer, NsNetType};
use super::util::{batch_exchange, transform};

const IFACE_TTL: Duration = Duration::from_secs(20);
const DHCP_TTL: Duration = Duration::from_secs(60 * 60);
const DHCP_TIMEOUT: Duration = Duration::from_secs(60);

struct DhcpClientState {
    iface_invalidate: Option<Instant>,
    dns_invalidate: Option<Instant>,
    iface_addr: Option<IpNet>,
    resolving: bool,
    clients: Option<Vec<Arc<dyn DnsClient>>>,
    err: Option<String>,
}

pub(crate) struct DhcpClient {
    iface_name: String,
    state: Mutex<DhcpClientState>,
    notify: Notify,
    self_ref: Weak<Self>,
}

pub(crate) fn new_dhcp_client(addr: &str) -> Arc<dyn DnsClient> {
    Arc::new_cyclic(|weak| DhcpClient {
        iface_name: addr.to_owned(),
        state: Mutex::new(DhcpClientState {
            iface_invalidate: None,
            dns_invalidate: None,
            iface_addr: None,
            resolving: false,
            clients: None,
            err: None,
        }),
        notify: Notify::new(),
        self_ref: Weak::clone(weak),
    })
}

#[async_trait]
impl DnsClient for DhcpClient {
    fn address(&self) -> String {
        let clients = self.state.lock().clients.clone().unwrap_or_default();
        let addrs: Vec<String> = clients.iter().map(|client| client.address()).collect();
        addrs.join(",")
    }

    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        let clients = self.resolve(ctx).await?;
        let (msg, _cache) = batch_exchange(ctx, &clients, m).await?;
        Ok(msg)
    }

    fn reset_connection(&self) {
        let clients = self.state.lock().clients.clone().unwrap_or_default();
        for client in clients {
            client.reset_connection();
        }
    }
}

impl DhcpClient {
    // cancel-safe: it only reads the shared state and waits on the notify or the context, so nothing is
    // left half-updated.
    async fn resolve(&self, ctx: &CancellationToken) -> Result<Vec<Arc<dyn DnsClient>>> {
        match self.invalidate().await {
            Ok(should_spawn) => {
                if should_spawn {
                    if let Some(strong) = self.self_ref.upgrade() {
                        spawn_resolve(strong);
                    }
                }
            }
            Err(err) => {
                self.state.lock().err = Some(err.to_string());
            }
        }

        loop {
            let (clients, err, resolving) = {
                let state = self.state.lock();
                (state.clients.clone(), state.err.clone(), state.resolving)
            };

            if clients.is_none() && err.is_none() {
                if resolving {
                    tokio::select! {
                        () = self.notify.notified() => continue,
                        () = ctx.cancelled() => return Err(anyhow!("context canceled")),
                    }
                }
                return Err(anyhow!("context canceled"));
            }

            if let Some(err) = err {
                return Err(anyhow!(err));
            }
            return Ok(clients.unwrap_or_default());
        }
    }

    /// Returns whether a fresh resolution was started.
    async fn invalidate(&self) -> Result<bool> {
        let now = Instant::now();

        let iface_invalidate = self.state.lock().iface_invalidate;
        if let Some(iface_invalidate) = iface_invalidate {
            if now < iface_invalidate {
                return Ok(false);
            }
        }

        let iface_obj = resolve_interface(&self.iface_name).await?;
        let addr = iface_obj.pick_ipv4_addr(None)?;

        let mut state = self.state.lock();
        state.iface_invalidate = Some(now + IFACE_TTL);

        if let Some(dns_invalidate) = state.dns_invalidate {
            if now < dns_invalidate && state.iface_addr == Some(addr) {
                return Ok(false);
            }
        }

        state.dns_invalidate = Some(now + DHCP_TTL);
        state.iface_addr = Some(addr);

        if state.resolving {
            return Ok(false);
        }
        state.resolving = true;
        drop(state);
        Ok(true)
    }
}

fn spawn_resolve(client: Arc<DhcpClient>) {
    tokio::spawn(async move {
        let dhcp_ctx = CancellationToken::new();
        let timeout_token = dhcp_ctx.clone();
        let timeout_task = tokio::spawn(async move {
            tokio::time::sleep(DHCP_TIMEOUT).await;
            timeout_token.cancel();
        });

        let result = resolve_dns_from_dhcp(&dhcp_ctx, &client.iface_name).await;
        timeout_task.abort();

        let (clients, err) = match result {
            Ok(dns) => {
                let nameserver: Vec<NameServer> = dns
                    .iter()
                    .map(|item| NameServer {
                        net: NsNetType::Udp,
                        addr: join_host_port(&item.to_string(), "53"),
                        proxy_adapter: None,
                        proxy_name: client.iface_name.clone(),
                        params: std::collections::HashMap::new(),
                        prefer_h3: false,
                    })
                    .collect();
                (Some(transform(&nameserver, None)), None)
            }
            Err(err) => (None, Some(err.to_string())),
        };

        {
            let mut state = client.state.lock();
            state.resolving = false;
            state.clients = clients;
            state.err = err;
        }
        client.notify.notify_waiters();
    });
}
