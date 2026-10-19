//! A dialer that resolves the proxy to use by name from a tunnel's proxy table.
//!
//! Whether a tunnel exposes proxies is a structural capability check, not identity: `proxies()`
//! on `constant::tunnel::Tunnel` defaults to `None`, and the crate's `tunnel::tunnel::Tunnel`
//! singleton is the only override to `Some`; `listener::tlsmirror::EnrollmentTunnel` embeds a
//! tunnel but keeps that default.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use super::proxydialer;
use murmur_common_net::io::{Datagram, Stream};
use murmur_constant::adapters::{Dialer, Proxy, ProxyAdapter};
use murmur_constant::tunnel::Tunnel;

struct ByNameProxyDialer {
    proxy_name: String,
    tunnel: Arc<dyn Tunnel>,
}

impl ByNameProxyDialer {
    fn proxies(&self) -> Result<HashMap<String, Arc<dyn Proxy>>> {
        self.tunnel.proxies().ok_or_else(|| anyhow!("tunnel is invalid, must be proxydialer.Tunnel"))
    }
}

#[async_trait]
impl Dialer for ByNameProxyDialer {
    // cancel-safe: a cancelled dial drops the connection the inner dial had just opened.
    async fn dial_context(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Stream>> {
        let proxies = self.proxies()?;
        let Some(proxy) = proxies.get(&self.proxy_name) else {
            return Err(anyhow!("proxyName[{}] not found", self.proxy_name));
        };
        // Bind unannotated so `Arc::clone` infers `Arc<dyn Proxy>`, then let the
        // upcast to `ProxyAdapter` (a supertrait) happen in its own coercion.
        let proxy_arc = Arc::clone(proxy);
        let proxy: Arc<dyn ProxyAdapter> = proxy_arc;
        proxydialer::new(proxy, true).dial_context(ctx, network, address).await
    }

    // cancel-safe: a cancelled listen drops the packet conn the inner listen had just bound.
    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
        r_addr_port: Option<SocketAddr>,
    ) -> Result<Box<dyn Datagram>> {
        let proxies = self.proxies()?;
        let Some(proxy) = proxies.get(&self.proxy_name) else {
            return Err(anyhow!("proxyName[{}] not found", self.proxy_name));
        };
        // Bind unannotated so `Arc::clone` infers `Arc<dyn Proxy>`, then let the
        // upcast to `ProxyAdapter` (a supertrait) happen in its own coercion.
        let proxy_arc = Arc::clone(proxy);
        let proxy: Arc<dyn ProxyAdapter> = proxy_arc;
        proxydialer::new(proxy, true).listen_packet(ctx, network, address, r_addr_port).await
    }
}

pub fn new_by_name(proxy_name: String, tunnel: Arc<dyn Tunnel>) -> Arc<dyn Dialer> {
    Arc::new(ByNameProxyDialer { proxy_name, tunnel })
}
