use portable_atomic::AtomicU64;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::Result;
use hickory_proto::op::Message;
use parking_lot::RwLock;
use rand::seq::IndexedRandom;
use tokio_util::sync::CancellationToken;

use murmur_common::utils::slice::filter;
use murmur_component_trie::domain::DomainTrie;

use super::host::{new_hosts, parse_addr, unmap_addr, Hosts};

/// A `Resolver` trait object, the Rust form of the interface value.
pub type ResolverRef = dyn Resolver + Send + Sync;

/// A shared `Resolver`.
pub type SharedResolver = Arc<ResolverRef>;

/// Sentinel errors of a resolver lookup.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ResolverError {
    #[error("couldn't find ip")]
    IpNotFound,
    #[error("ip version error")]
    IpVersion,
    #[error("ipv6 disabled")]
    Ipv6Disabled,
    #[error("couldn't find ip: {host}")]
    IpNotFoundForHost { host: String },
}

impl ResolverError {
    #[must_use]
    pub const fn is_ip_not_found(&self) -> bool {
        matches!(self, Self::IpNotFound | Self::IpNotFoundForHost { .. })
    }
}

#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    async fn lookup_ip(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>>;
    async fn lookup_ipv4(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>>;
    async fn lookup_ipv6(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>>;
    async fn resolve_ech(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<u8>>;
    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message>;
    fn invalid(&self) -> bool;
    fn clear_cache(&self);
    fn reset_connection(&self);
}

static DEFAULT_RESOLVER: LazyLock<RwLock<Option<SharedResolver>>> = LazyLock::new(|| RwLock::new(None));
static PROXY_SERVER_HOST_RESOLVER: LazyLock<RwLock<Option<SharedResolver>>> = LazyLock::new(|| RwLock::new(None));
static DIRECT_HOST_RESOLVER: LazyLock<RwLock<Option<SharedResolver>>> = LazyLock::new(|| RwLock::new(None));
static SYSTEM_RESOLVER: LazyLock<RwLock<Option<SharedResolver>>> = LazyLock::new(|| RwLock::new(None));
static DEFAULT_HOSTS: LazyLock<RwLock<Arc<Hosts>>> =
    LazyLock::new(|| RwLock::new(Arc::new(new_hosts(DomainTrie::new()))));
static DISABLE_IPV6: AtomicBool = AtomicBool::new(true);
static DEFAULT_DNS_TIMEOUT_NANOS: AtomicU64 = AtomicU64::new(5_000_000_000);

pub fn default_resolver() -> Option<SharedResolver> {
    DEFAULT_RESOLVER.read().clone()
}

pub fn set_default_resolver(resolver: Option<SharedResolver>) {
    *DEFAULT_RESOLVER.write() = resolver;
}

pub fn proxy_server_host_resolver() -> Option<SharedResolver> {
    PROXY_SERVER_HOST_RESOLVER.read().clone()
}

pub fn set_proxy_server_host_resolver(resolver: Option<SharedResolver>) {
    *PROXY_SERVER_HOST_RESOLVER.write() = resolver;
}

pub fn direct_host_resolver() -> Option<SharedResolver> {
    DIRECT_HOST_RESOLVER.read().clone()
}

pub fn set_direct_host_resolver(resolver: Option<SharedResolver>) {
    *DIRECT_HOST_RESOLVER.write() = resolver;
}

/// Installed by the dns module before any lookup runs.
pub fn system_resolver() -> SharedResolver {
    #[expect(
        clippy::expect_used,
        reason = "the signature has no failure channel; the dns module installs the resolver before any lookup"
    )]
    let resolver = SYSTEM_RESOLVER.read().clone().expect("nil SystemResolver");
    resolver
}

/// The installed system resolver, or `None` before the dns module installs one.
///
/// `system_resolver` panics in that state, so a caller that installs its own (a test, a pre-init
/// embed) reads it here to restore the previous value afterwards.
pub fn system_resolver_opt() -> Option<SharedResolver> {
    SYSTEM_RESOLVER.read().clone()
}

pub fn set_system_resolver(resolver: Option<SharedResolver>) {
    *SYSTEM_RESOLVER.write() = resolver;
}

pub fn default_hosts() -> Arc<Hosts> {
    DEFAULT_HOSTS.read().clone()
}

pub fn set_default_hosts(hosts: Hosts) {
    *DEFAULT_HOSTS.write() = Arc::new(hosts);
}

/// Whether IPv6 is disabled, true by default.
pub fn disable_ipv6() -> bool {
    DISABLE_IPV6.load(Ordering::Relaxed)
}

pub fn set_disable_ipv6(disable: bool) {
    DISABLE_IPV6.store(disable, Ordering::Relaxed);
}

pub fn default_dns_timeout() -> Duration {
    Duration::from_nanos(DEFAULT_DNS_TIMEOUT_NANOS.load(Ordering::Relaxed))
}

pub fn set_default_dns_timeout(timeout: Duration) {
    let nanos = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
    DEFAULT_DNS_TIMEOUT_NANOS.store(nanos, Ordering::Relaxed);
}

pub async fn lookup_ipv4_with_resolver(
    ctx: &CancellationToken,
    host: &str,
    r: Option<&ResolverRef>,
) -> Result<Vec<IpAddr>> {
    let hosts = default_hosts();
    if let Some((node, true)) = hosts.search(host, false).await {
        let addrs = filter(&node.ips, IpAddr::is_ipv4);
        if !addrs.is_empty() {
            return Ok(addrs);
        }
    }

    if let Ok(ip) = parse_addr(host) {
        let ip = unmap_addr(ip);
        if ip.is_ipv4() {
            return Ok(vec![ip]);
        }
        return Err(ResolverError::IpVersion.into());
    }

    if let Some(r) = r.filter(|r| r.invalid()) {
        return r.lookup_ipv4(ctx, host).await;
    }

    system_resolver().lookup_ipv4(ctx, host).await
}

pub async fn lookup_ipv4(ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
    lookup_ipv4_with_resolver(ctx, host, default_resolver().as_deref()).await
}

/// A random element of `ips`; `None` when it is empty.
fn random_ip(ips: &[IpAddr]) -> Option<IpAddr> {
    ips.choose(&mut rand::rng()).copied()
}

pub async fn resolve_ipv4_with_resolver(
    ctx: &CancellationToken,
    host: &str,
    r: Option<&ResolverRef>,
) -> Result<IpAddr> {
    let ips = lookup_ipv4_with_resolver(ctx, host, r).await?;
    random_ip(&ips).ok_or_else(|| ResolverError::IpNotFoundForHost { host: host.to_owned() }.into())
}

pub async fn resolve_ipv4(ctx: &CancellationToken, host: &str) -> Result<IpAddr> {
    resolve_ipv4_with_resolver(ctx, host, default_resolver().as_deref()).await
}

pub async fn lookup_ipv6_with_resolver(
    ctx: &CancellationToken,
    host: &str,
    r: Option<&ResolverRef>,
) -> Result<Vec<IpAddr>> {
    if disable_ipv6() {
        return Err(ResolverError::Ipv6Disabled.into());
    }

    let hosts = default_hosts();
    if let Some((node, true)) = hosts.search(host, false).await {
        let addrs = filter(&node.ips, IpAddr::is_ipv6);
        if !addrs.is_empty() {
            return Ok(addrs);
        }
    }

    if let Ok(ip) = parse_addr(host) {
        let ip = unmap_addr(ip);
        if ip.is_ipv6() {
            return Ok(vec![ip]);
        }
        return Err(ResolverError::IpVersion.into());
    }

    if let Some(r) = r.filter(|r| r.invalid()) {
        return r.lookup_ipv6(ctx, host).await;
    }

    system_resolver().lookup_ipv6(ctx, host).await
}

pub async fn lookup_ipv6(ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
    lookup_ipv6_with_resolver(ctx, host, default_resolver().as_deref()).await
}

pub async fn resolve_ipv6_with_resolver(
    ctx: &CancellationToken,
    host: &str,
    r: Option<&ResolverRef>,
) -> Result<IpAddr> {
    let ips = lookup_ipv6_with_resolver(ctx, host, r).await?;
    random_ip(&ips).ok_or_else(|| ResolverError::IpNotFoundForHost { host: host.to_owned() }.into())
}

pub async fn resolve_ipv6(ctx: &CancellationToken, host: &str) -> Result<IpAddr> {
    resolve_ipv6_with_resolver(ctx, host, default_resolver().as_deref()).await
}

pub async fn lookup_ip_with_resolver(
    ctx: &CancellationToken,
    host: &str,
    r: Option<&ResolverRef>,
) -> Result<Vec<IpAddr>> {
    let hosts = default_hosts();
    if let Some((node, true)) = hosts.search(host, false).await {
        return Ok(node.ips);
    }

    if let Some(r) = r.filter(|r| r.invalid()) {
        if disable_ipv6() {
            return r.lookup_ipv4(ctx, host).await;
        }
        return r.lookup_ip(ctx, host).await;
    } else if disable_ipv6() {
        return lookup_ipv4_with_resolver(ctx, host, r).await;
    }

    if let Ok(ip) = parse_addr(host) {
        return Ok(vec![unmap_addr(ip)]);
    }

    system_resolver().lookup_ip(ctx, host).await
}

pub async fn lookup_ip(ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
    lookup_ip_with_resolver(ctx, host, default_resolver().as_deref()).await
}

pub async fn resolve_ip_with_resolver(ctx: &CancellationToken, host: &str, r: Option<&ResolverRef>) -> Result<IpAddr> {
    let ips = lookup_ip_with_resolver(ctx, host, r).await?;
    let (ipv4s, ipv6s) = sortation_addr(&ips);
    let candidates = if ipv4s.is_empty() { &ipv6s } else { &ipv4s };
    random_ip(candidates).ok_or_else(|| ResolverError::IpNotFoundForHost { host: host.to_owned() }.into())
}

pub async fn resolve_ip(ctx: &CancellationToken, host: &str) -> Result<IpAddr> {
    resolve_ip_with_resolver(ctx, host, default_resolver().as_deref()).await
}

pub async fn resolve_ip_prefer6_with_resolver(
    ctx: &CancellationToken,
    host: &str,
    r: Option<&ResolverRef>,
) -> Result<IpAddr> {
    let ips = lookup_ip_with_resolver(ctx, host, r).await?;
    let (ipv4s, ipv6s) = sortation_addr(&ips);
    let candidates = if ipv6s.is_empty() { &ipv4s } else { &ipv6s };
    random_ip(candidates).ok_or_else(|| ResolverError::IpNotFoundForHost { host: host.to_owned() }.into())
}

pub async fn resolve_ip_prefer6(ctx: &CancellationToken, host: &str) -> Result<IpAddr> {
    resolve_ip_prefer6_with_resolver(ctx, host, default_resolver().as_deref()).await
}

pub async fn resolve_ech_with_resolver(
    ctx: &CancellationToken,
    host: &str,
    r: Option<&ResolverRef>,
) -> Result<Vec<u8>> {
    if let Some(r) = r.filter(|r| r.invalid()) {
        return r.resolve_ech(ctx, host).await;
    }
    system_resolver().resolve_ech(ctx, host).await
}

pub async fn resolve_ech(ctx: &CancellationToken, host: &str) -> Result<Vec<u8>> {
    resolve_ech_with_resolver(ctx, host, default_resolver().as_deref()).await
}

pub fn clear_cache() {
    if let Some(resolver) = default_resolver() {
        tokio::spawn(async move { resolver.clear_cache() });
    }
    let resolver = system_resolver();
    tokio::spawn(async move { resolver.clear_cache() });
}

pub fn reset_connection() {
    if let Some(resolver) = default_resolver() {
        tokio::spawn(async move { resolver.reset_connection() });
    }
    let resolver = system_resolver();
    tokio::spawn(async move { resolver.reset_connection() });
}

#[must_use]
pub fn sortation_addr(ips: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>) {
    let mut ipv4s = Vec::new();
    let mut ipv6s = Vec::new();
    for v in ips {
        if unmap_addr(*v).is_ipv4() {
            ipv4s.push(*v);
        } else {
            ipv6s.push(*v);
        }
    }
    (ipv4s, ipv6s)
}
