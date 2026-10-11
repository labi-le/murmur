use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Result};
use chrono::Utc;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::rdata::svcb::SvcParamValue;
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use murmur_common::arc::arc as goarc;
use murmur_common::lru::lrucache as golru;
use murmur_common::singleflight::singleflight;
use murmur_component::resolver::resolver::{default_dns_timeout, ResolverError, SharedResolver};
use murmur_component_trie::domain::DomainTrie;
use murmur_constant::adapters::ProxyAdapter;
use murmur_constant::matcher::{DomainMatcher, IpMatcher};
use murmur_log::warnln;

use super::policy::{DnsPolicy, DomainMatcherPolicy, DomainTriePolicy};
use super::util::{
    batch_exchange, get_msg_from_cache, is_ip_request, msg_to_domain, msg_to_ip, put_msg_to_cache, question, transform,
};

#[async_trait::async_trait]
pub trait DnsClient: Send + Sync {
    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message>;
    fn address(&self) -> String;
    fn reset_connection(&self);

    /// Whether this client wraps another one it can hand back. Overridden only by the two
    /// `util.rs` wrappers.
    fn unwrap_inner(&self) -> Option<Arc<dyn DnsClient>> {
        None
    }

    /// Whether this client is the rcode client. Overridden only by `RcodeClient`; a wrapper around
    /// one must not answer `true`, so the check targets the concrete type rather than anything it
    /// might be wrapped in.
    fn is_rcode_client(&self) -> bool {
        false
    }
}

pub(crate) trait DnsCache: Send + Sync {
    fn get_with_expire(&self, key: &str) -> (Option<Message>, Option<chrono::DateTime<Utc>>, bool);
    fn set_with_expire(&self, key: &str, value: Message, expire: chrono::DateTime<Utc>);
    fn clear(&self);
}

impl DnsCache for golru::LruCache<String, Option<Message>> {
    fn get_with_expire(&self, key: &str) -> (Option<Message>, Option<chrono::DateTime<Utc>>, bool) {
        self.get_with_expire(key.to_owned())
    }

    fn set_with_expire(&self, key: &str, value: Message, expire: chrono::DateTime<Utc>) {
        Self::set_with_expire(self, key.to_owned(), Some(value), expire);
    }

    fn clear(&self) {
        Self::clear(self);
    }
}

impl DnsCache for goarc::ARC<String, Option<Message>> {
    fn get_with_expire(&self, key: &str) -> (Option<Message>, Option<chrono::DateTime<Utc>>, bool) {
        Self::get_with_expire(self, &key.to_owned())
    }

    fn set_with_expire(&self, key: &str, value: Message, expire: chrono::DateTime<Utc>) {
        Self::set_with_expire(self, key.to_owned(), Some(value), expire);
    }

    fn clear(&self) {
        Self::clear(self);
    }
}

/// The singleflight `Result` publishes a value alongside an error (the closure can return both),
/// which a batch exchange abuses to smuggle a retry counter through the result's opcode.
/// `singleflight::Group<T>` here only carries `anyhow::Result<T>`, so the retry counter is tracked
/// with this external atomic instead; the capped-retry behaviour is preserved, the Opcode-smuggling
/// trick is not reproduced.
type RetryCounter = Arc<AtomicI32>;

/// `Resolver`.
///
/// All collection fields are reference-counted so the whole struct is cheaply `Clone`, which lets
/// exchange helpers move an owned snapshot into `'static` spawned tasks the way the methods close
/// over `r *Resolver` directly.
#[derive(Clone)]
pub struct Resolver {
    pub(crate) ipv6_timeout: Duration,
    pub(crate) main: Vec<Arc<dyn DnsClient>>,
    pub(crate) fallback: Option<Vec<Arc<dyn DnsClient>>>,
    pub(crate) fallback_domain_filters: Vec<Arc<dyn DomainMatcher>>,
    pub(crate) fallback_ip_filters: Vec<Arc<dyn IpMatcher>>,
    pub(crate) fallback_lazy_query: bool,
    pub(crate) group: Arc<singleflight::Group<Message>>,
    pub(crate) cache: Arc<dyn DnsCache>,
    pub(crate) policy: Option<Vec<Arc<dyn DnsPolicy>>>,
    #[expect(
        clippy::struct_field_names,
        reason = "the field names the resolver used as the default; renaming it would obscure that role, and the config layer reads the crate-visible name"
    )]
    pub(crate) default_resolver: Option<Arc<Self>>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("ipv6_timeout", &self.ipv6_timeout)
            .field("main", &self.main.len())
            .field("fallback", &self.fallback.as_ref().map(Vec::len))
            .field("policies", &self.policy.as_ref().map(Vec::len))
            .field("fallback_lazy_query", &self.fallback_lazy_query)
            .finish_non_exhaustive()
    }
}

/// Derives a `CancellationToken` cancelled after `dur` or when `parent` is cancelled, mirroring
fn with_timeout_token(parent: &CancellationToken, dur: Duration) -> CancellationToken {
    let child = parent.child_token();
    let sleeper = child.clone();
    tokio::spawn(async move {
        tokio::select! {
            () = tokio::time::sleep(dur) => sleeper.cancel(),
            () = sleeper.cancelled() => {}
        }
    });
    child
}

fn fqdn_name(host: &str) -> Result<Name> {
    let mut name: Name = host.parse().map_err(|err| anyhow!("invalid domain name {host}: {err}"))?;
    name.set_fqdn(true);
    Ok(name)
}

impl Resolver {
    pub async fn lookup_ip_primary_ipv4(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
        let (tx, rx) = oneshot::channel();
        let resolver = self.clone();
        let ctx6 = ctx.clone();
        let host6 = host.to_owned();
        tokio::spawn(async move {
            if let Ok(ip) = resolver.lookup_ip_inner(&ctx6, &host6, RecordType::AAAA).await {
                let _ = tx.send(ip);
            }
        });

        match self.lookup_ip_inner(ctx, host, RecordType::A).await {
            Ok(ips) => Ok(ips),
            Err(_) => rx.await.map_err(|_| ResolverError::IpNotFound.into()),
        }
    }

    // cancel-safe: the IPv6 lookup runs in its own task and only its result channel is raced here.
    pub async fn lookup_ip(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
        let (tx, rx) = oneshot::channel();
        let resolver = self.clone();
        let ctx6 = ctx.clone();
        let host6 = host.to_owned();
        tokio::spawn(async move {
            if let Ok(ip) = resolver.lookup_ip_inner(&ctx6, &host6, RecordType::AAAA).await {
                let _ = tx.send(ip);
            }
        });

        let ipv4_result = self.lookup_ip_inner(ctx, host, RecordType::A).await;
        let mut ips = ipv4_result.as_ref().map(Clone::clone).unwrap_or_default();
        let wait_ipv6 = if self.ipv6_timeout > Duration::ZERO { self.ipv6_timeout } else { Duration::from_millis(100) };

        tokio::select! {
            result = rx => {
                match result {
                    Ok(ipv6s) => ips.extend(ipv6s),
                    Err(_) => {
                        if ipv4_result.is_err() {
                            return Err(ResolverError::IpNotFound.into());
                        }
                    }
                }
            }
            () = tokio::time::sleep(wait_ipv6) => {}
        }

        Ok(ips)
    }

    pub async fn lookup_ipv4(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
        self.lookup_ip_inner(ctx, host, RecordType::A).await
    }

    pub async fn lookup_ipv6(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
        self.lookup_ip_inner(ctx, host, RecordType::AAAA).await
    }

    fn should_ip_fallback(&self, ip: IpAddr) -> bool {
        self.fallback_ip_filters.iter().any(|filter| filter.match_ip(ip))
    }

    pub async fn resolve_ech(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<u8>> {
        let name = fqdn_name(host)?;
        let query = question(name, RecordType::HTTPS);

        let msg = self.exchange_context(ctx, &query).await?;
        for rr in &msg.answers {
            if let RData::HTTPS(https) = &rr.data {
                for (_, value) in &https.0.svc_params {
                    if let SvcParamValue::EchConfigList(ech) = value {
                        return Ok(ech.0.clone());
                    }
                }
            }
        }
        Err(anyhow!("no ECH config found in DNS records"))
    }

    /// A batch of DNS requests with a cancellation context, using the cache.
    // cancel-safe: it races only the singleflight receiver, and the cancelled arm hands the retry to a
    // spawned task.
    pub async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        let q = m.queries.first().ok_or_else(|| anyhow!("should have one question at least"))?.clone();
        let domain = msg_to_domain(m);
        let (cached, expire_time, hit) = get_msg_from_cache(self.cache.as_ref(), &q);

        let mut continue_fetch = false;
        let result = if hit {
            let (Some(mut msg), Some(expire_time)) = (cached, expire_time) else {
                return Err(anyhow!("cache hit is missing its message or expire time"));
            };
            murmur_log::debugln!(
                "[DNS] cache hit {} --> {}, expire at {}",
                domain,
                super::util::msg_to_log_string(&msg),
                expire_time.format("%Y-%m-%d %H:%M:%S")
            );
            let now = Utc::now();
            if expire_time < now {
                super::util::set_msg_ttl(&mut msg, 1);
                continue_fetch = true;
            } else {
                let remaining = (expire_time - now).num_seconds().max(0);
                super::util::update_msg_ttl(&mut msg, u32::try_from(remaining).unwrap_or(u32::MAX));
            }
            Ok(msg)
        } else {
            self.exchange_without_cache(ctx, m).await
        };

        let is_ctx_done = matches!(&result, Err(err) if err.downcast_ref::<CtxDoneError>().is_some());
        if continue_fetch || is_ctx_done {
            let resolver = self.clone();
            let m = m.clone();
            tokio::spawn(async move {
                let ctx = CancellationToken::new();
                let child = with_timeout_token(&ctx, default_dns_timeout());
                let _ = resolver.exchange_without_cache(&child, &m).await;
            });
        }

        result
    }

    /// A batch of dns requests, and it does NOT read from cache.
    // cancel-safe: the exchange runs in a spawned singleflight task, so a cancelled wait drops only the
    // receiver.
    async fn exchange_without_cache(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        const RETRY_MAX: i32 = 3;
        let q = m.queries.first().ok_or_else(|| anyhow!("should have one question at least"))?.clone();
        let key = singleflight_key(&q);
        let retry_num: RetryCounter = Arc::new(AtomicI32::new(0));

        let rx = self.spawn_exchange_call(&key, m.clone(), q.clone(), Arc::clone(&retry_num));

        tokio::select! {
            biased;
            result = rx => self.finish_exchange_result(result, &key, m, &q, retry_num, RETRY_MAX).await,
            () = ctx.cancelled() => {
                let resolver = self.clone();
                let key2 = key.clone();
                let m2 = m.clone();
                let q2 = q.clone();
                let retry_num2 = Arc::clone(&retry_num);
                tokio::spawn(async move {
                    let rx = resolver.spawn_exchange_call(&key2, m2.clone(), q2.clone(), Arc::clone(&retry_num2));
                    if let Ok(res) = rx.await {
                        if res.err.is_some() && !res.shared && retry_num2.load(Ordering::SeqCst) < RETRY_MAX {
                            retry_num2.fetch_add(1, Ordering::SeqCst);
                            let _ = resolver.spawn_exchange_call(&key2, m2, q2, retry_num2).await;
                        }
                    }
                });
                Err(anyhow::Error::new(CtxDoneError))
            }
        }
    }

    async fn finish_exchange_result(
        &self,
        result: std::result::Result<singleflight::Result<Message>, oneshot::error::RecvError>,
        key: &str,
        m: &Message,
        q: &Query,
        retry_num: RetryCounter,
        retry_max: i32,
    ) -> Result<Message> {
        let res = result.map_err(|_| anyhow!("singleflight call dropped"))?;
        if res.err.is_some() && !res.shared && retry_num.load(Ordering::SeqCst) < retry_max {
            retry_num.fetch_add(1, Ordering::SeqCst);
            let _ = self.spawn_exchange_call(key, m.clone(), q.clone(), retry_num).await;
        }

        match (res.val, res.err) {
            (Some(msg), None) => Ok(msg),
            (_, Some(err)) => Err(err.into_anyhow()),
            (None, None) => Err(anyhow!("dns exchange produced no result")),
        }
    }

    fn spawn_exchange_call(
        &self,
        key: &str,
        m: Message,
        q: Query,
        _retry_num: RetryCounter,
    ) -> oneshot::Receiver<singleflight::Result<Message>> {
        let resolver = self.clone();
        self.group.do_chan(key, move || {
            let resolver = resolver.clone();
            async move {
                let ctx = CancellationToken::new();
                let child = with_timeout_token(&ctx, default_dns_timeout());

                let (msg, cache) = if is_ip_request(&q) {
                    let msg = resolver.ip_exchange(&child, &m).await?;
                    (msg, true)
                } else {
                    let matched = resolver.match_policy(&m);
                    if matched.is_empty() {
                        batch_exchange(&child, &resolver.main, &m).await?
                    } else {
                        batch_exchange(&child, &matched, &m).await?
                    }
                };

                if cache {
                    put_msg_to_cache(resolver.cache.as_ref(), &q, &msg);
                }
                Ok(msg)
            }
        })
    }

    fn match_policy(&self, m: &Message) -> Vec<Arc<dyn DnsClient>> {
        let Some(policies) = &self.policy else { return Vec::new() };
        let domain = msg_to_domain(m);
        if domain.is_empty() {
            return Vec::new();
        }
        for policy in policies {
            let matched = policy.match_(&domain);
            if !matched.is_empty() {
                return matched;
            }
        }
        Vec::new()
    }

    fn should_only_query_fallback(&self, m: &Message) -> bool {
        if self.fallback.is_none() || self.fallback_domain_filters.is_empty() {
            return false;
        }
        let domain = msg_to_domain(m);
        if domain.is_empty() {
            return false;
        }
        self.fallback_domain_filters.iter().any(|filter| filter.match_domain(&domain))
    }

    async fn ip_exchange(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        let matched = self.match_policy(m);
        if !matched.is_empty() {
            let rx = Self::async_exchange(ctx, matched, m.clone());
            return rx.await.map_err(|_| anyhow!("resolver task dropped"))?;
        }

        if self.should_only_query_fallback(m) {
            let fallback = self.fallback.clone().unwrap_or_default();
            let rx = Self::async_exchange(ctx, fallback, m.clone());
            return rx.await.map_err(|_| anyhow!("resolver task dropped"))?;
        }

        let msg_rx = Self::async_exchange(ctx, self.main.clone(), m.clone());

        let Some(fallback) = self.fallback.clone() else {
            return msg_rx.await.map_err(|_| anyhow!("resolver task dropped"))?;
        };

        let mut fallback_rx =
            if self.fallback_lazy_query { None } else { Some(Self::async_exchange(ctx, fallback.clone(), m.clone())) };

        let res = msg_rx.await.map_err(|_| anyhow!("resolver task dropped"))?;
        if let Ok(msg) = &res {
            let ips = msg_to_ip(msg);
            if !ips.is_empty() {
                let should_not_fallback = ips.iter().all(|ip| !self.should_ip_fallback(*ip));
                if should_not_fallback {
                    return res;
                }
            }
        }

        let fallback_rx = match fallback_rx.take() {
            Some(rx) => rx,
            None => Self::async_exchange(ctx, fallback, m.clone()),
        };
        fallback_rx.await.map_err(|_| anyhow!("resolver task dropped"))?
    }

    async fn lookup_ip_inner(&self, ctx: &CancellationToken, host: &str, dns_type: RecordType) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            let ip = ip.to_canonical();
            let is_ipv4 = ip.is_ipv4();
            #[expect(
                clippy::if_same_then_else,
                reason = "the A and AAAA arms both return the parsed address, so the arms are identical"
            )]
            return if dns_type == RecordType::AAAA && !is_ipv4 {
                Ok(vec![ip])
            } else if dns_type == RecordType::A && is_ipv4 {
                Ok(vec![ip])
            } else {
                Err(ResolverError::IpVersion.into())
            };
        }

        let name = fqdn_name(host)?;
        let query = question(name, dns_type);

        let msg = self.exchange_context(ctx, &query).await?;
        let ips = msg_to_ip(&msg);
        if ips.is_empty() {
            return Err(ResolverError::IpNotFound.into());
        }
        Ok(ips)
    }

    fn async_exchange(
        ctx: &CancellationToken,
        clients: Vec<Arc<dyn DnsClient>>,
        msg: Message,
    ) -> oneshot::Receiver<Result<Message>> {
        let (tx, rx) = oneshot::channel();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let res = batch_exchange(&ctx, &clients, &msg).await.map(|(msg, _)| msg);
            let _ = tx.send(res);
        });
        rx
    }

    /// `Invalid`, returning whether this resolver can be used.
    #[must_use]
    pub fn invalid(&self) -> bool {
        !self.main.is_empty()
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    pub fn reset_connection(&self) {
        for c in &self.main {
            c.reset_connection();
        }
        if let Some(fallback) = &self.fallback {
            for c in fallback {
                c.reset_connection();
            }
        }
        if let Some(dr) = &self.default_resolver {
            dr.reset_connection();
        }
    }
}

/// A local marker error meaning the enclosing context was cancelled or its deadline elapsed.
#[derive(Debug, thiserror::Error)]
#[error("context canceled or deadline exceeded")]
struct CtxDoneError;

#[async_trait::async_trait]
impl murmur_component::resolver::resolver::Resolver for Resolver {
    async fn lookup_ip(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
        Self::lookup_ip(self, ctx, host).await
    }

    async fn lookup_ipv4(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
        Self::lookup_ipv4(self, ctx, host).await
    }

    async fn lookup_ipv6(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
        Self::lookup_ipv6(self, ctx, host).await
    }

    async fn resolve_ech(&self, ctx: &CancellationToken, host: &str) -> Result<Vec<u8>> {
        Self::resolve_ech(self, ctx, host).await
    }

    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        Self::exchange_context(self, ctx, m).await
    }

    fn invalid(&self) -> bool {
        Self::invalid(self)
    }

    fn clear_cache(&self) {
        Self::clear_cache(self);
    }

    fn reset_connection(&self) {
        Self::reset_connection(self);
    }
}

fn singleflight_key(q: &Query) -> String {
    format!("{}|{}|{}", q.name, q.query_type, q.query_class)
}

/// The closed set of transports a nameserver URL scheme can spell; kept as a variant per spelling
/// so every `==` comparison in this file and `transform` stays exact without re-parsing a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NsNetType {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    System,
    Tailscale,
    Easytier,
    Dhcp,
    Rcode,
}

#[derive(Clone)]
pub struct NameServer {
    pub net: NsNetType,
    pub addr: String,
    pub proxy_adapter: Option<Arc<dyn ProxyAdapter>>,
    pub proxy_name: String,
    pub params: HashMap<String, String>,
    pub prefer_h3: bool,
}

impl std::fmt::Debug for NameServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NameServer")
            .field("net", &self.net)
            .field("addr", &self.addr)
            .field("proxy_name", &self.proxy_name)
            .field("prefer_h3", &self.prefer_h3)
            .finish_non_exhaustive()
    }
}

impl NameServer {
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        self.net == other.net
            && self.addr == other.addr
            && proxy_adapter_eq(self.proxy_adapter.as_ref(), other.proxy_adapter.as_ref())
            && self.proxy_name == other.proxy_name
            && self.params == other.params
            && self.prefer_h3 == other.prefer_h3
    }

    /// Reports whether two `NameServer`s share the same
    /// transport and may reuse a single client, comparing all fields except wrapper-only params.
    #[must_use]
    pub fn transport_equal(&self, other: &Self) -> bool {
        let params_equal = |a: &HashMap<String, String>, b: &HashMap<String, String>| {
            a.iter().all(|(k, v)| super::util::is_wrapper_only_param(k) || b.get(k) == Some(v))
        };
        self.net == other.net
            && self.addr == other.addr
            && proxy_adapter_eq(self.proxy_adapter.as_ref(), other.proxy_adapter.as_ref())
            && self.proxy_name == other.proxy_name
            && self.prefer_h3 == other.prefer_h3
            && params_equal(&self.params, &other.params)
            && params_equal(&other.params, &self.params)
    }
}

fn proxy_adapter_eq(a: Option<&Arc<dyn ProxyAdapter>>, b: Option<&Arc<dyn ProxyAdapter>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

pub struct Policy {
    pub domain: String,
    pub matcher: Option<Arc<dyn DomainMatcher>>,
    pub name_servers: Vec<NameServer>,
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("domain", &self.domain)
            .field("match_all", &self.matcher.is_none())
            .field("name_servers", &self.name_servers.len())
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
pub struct Config {
    pub main: Vec<NameServer>,
    pub fallback: Vec<NameServer>,
    pub default: Vec<NameServer>,
    pub proxy_server: Vec<NameServer>,
    pub direct_server: Vec<NameServer>,
    pub direct_follow_policy: bool,
    pub ipv6: bool,
    pub ipv6_timeout: u32,
    pub fallback_ip_filter: Vec<Arc<dyn IpMatcher>>,
    pub fallback_domain_filter: Vec<Arc<dyn DomainMatcher>>,
    pub fallback_lazy_query: bool,
    pub policy: Vec<Policy>,
    pub proxy_server_policy: Vec<Policy>,
    pub cache_algorithm: String,
    pub cache_max_size: i32,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("main", &self.main.len())
            .field("fallback", &self.fallback.len())
            .field("default", &self.default.len())
            .field("proxy_server", &self.proxy_server.len())
            .field("direct_server", &self.direct_server.len())
            .field("policies", &self.policy.len())
            .field("cache_algorithm", &self.cache_algorithm)
            .field("cache_max_size", &self.cache_max_size)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub(crate) fn new_cache(&self) -> Arc<dyn DnsCache> {
        let max_size = if self.cache_max_size == 0 { 4096 } else { self.cache_max_size };
        match self.cache_algorithm.as_str() {
            "arc" => Arc::new(goarc::ARC::<String, Option<Message>>::new(vec![goarc::with_size(max_size)])),
            _ => Arc::new(golru::new::<String, Option<Message>>(vec![
                golru::with_size(usize::try_from(max_size.max(0)).unwrap_or_default()),
                golru::with_stale(true),
            ])),
        }
    }
}

#[derive(Debug)]
pub struct Resolvers {
    pub resolver: Resolver,
    pub proxy_resolver: Option<Resolver>,
    pub direct_resolver: Option<Resolver>,
}

impl Resolvers {
    pub fn clear_cache(&self) {
        self.resolver.clear_cache();
        if let Some(r) = &self.proxy_resolver {
            r.clear_cache();
        }
        if let Some(r) = &self.direct_resolver {
            r.clear_cache();
        }
    }

    pub fn reset_connection(&self) {
        self.resolver.reset_connection();
        if let Some(r) = &self.proxy_resolver {
            r.reset_connection();
        }
        if let Some(r) = &self.direct_resolver {
            r.reset_connection();
        }
    }
}

impl Resolver {
    pub fn from_client(client: Arc<dyn DnsClient>) -> Self {
        Self {
            ipv6_timeout: Duration::ZERO,
            main: vec![client],
            fallback: None,
            fallback_domain_filters: Vec::new(),
            fallback_ip_filters: Vec::new(),
            fallback_lazy_query: false,
            group: Arc::new(singleflight::Group::default()),
            cache: Config::default().new_cache(),
            policy: None,
            default_resolver: None,
        }
    }
}

fn cache_transform(
    cache: &mut Vec<(NameServer, Arc<dyn DnsClient>)>,
    default_resolver: &SharedResolver,
    nameservers: &[NameServer],
) -> Vec<Arc<dyn DnsClient>> {
    let mut result = Vec::new();
    'outer: for ns in nameservers {
        let mut reusable_transport: Option<Arc<dyn DnsClient>> = None;
        for (cached_ns, cached_client) in cache.iter() {
            if cached_ns.equal(ns) {
                result.push(Arc::clone(cached_client));
                continue 'outer;
            }
            if reusable_transport.is_none() && cached_ns.transport_equal(ns) {
                reusable_transport = Some(Arc::clone(cached_client));
            }
        }

        let dc = if let Some(raw) = reusable_transport {
            transform_util::rewrap_client(raw, &ns.params)
        } else {
            let built = transform(std::slice::from_ref(ns), Some(Arc::clone(default_resolver)));
            match built.into_iter().next() {
                Some(dc) => dc,
                None => continue,
            }
        };

        cache.push((ns.clone(), Arc::clone(&dc)));
        result.push(dc);
    }
    result
}

use super::util as transform_util;

fn make_policy(
    cache: &mut Vec<(NameServer, Arc<dyn DnsClient>)>,
    default_resolver: &SharedResolver,
    policies: &[Policy],
) -> Vec<Arc<dyn DnsPolicy>> {
    let mut dns_policies: Vec<Arc<dyn DnsPolicy>> = Vec::new();
    let mut trie_policy: Option<DomainTrie<Vec<Arc<dyn DnsClient>>>> = None;

    let insert_policy = |dns_policies: &mut Vec<Arc<dyn DnsPolicy>>,
                         trie_policy: &mut Option<DomainTrie<Vec<Arc<dyn DnsClient>>>>,
                         policy: Option<Arc<dyn DnsPolicy>>| {
        if let Some(mut trie) = trie_policy.take() {
            trie.optimize();
            dns_policies.push(Arc::new(DomainTriePolicy(trie)));
        }
        if let Some(policy) = policy {
            dns_policies.push(policy);
        }
    };

    for policy in policies {
        if let Some(matcher) = &policy.matcher {
            let dns_clients = cache_transform(cache, default_resolver, &policy.name_servers);
            insert_policy(
                &mut dns_policies,
                &mut trie_policy,
                Some(Arc::new(DomainMatcherPolicy { matcher: Arc::clone(matcher), dns_clients })),
            );
        } else {
            if trie_policy.is_none() {
                trie_policy = Some(DomainTrie::new());
            }
            let dns_clients = cache_transform(cache, default_resolver, &policy.name_servers);
            if let Some(trie) = trie_policy.as_mut() {
                if let Err(err) = trie.insert(&policy.domain, dns_clients) {
                    warnln!("[DNS] skip invalid nameserver policy: {err}");
                }
            }
        }
    }
    insert_policy(&mut dns_policies, &mut trie_policy, None);
    dns_policies
}

impl Resolvers {
    #[must_use]
    pub fn new(config: Config) -> Self {
        let default_resolver = Resolver {
            ipv6_timeout: Duration::from_millis(u64::from(config.ipv6_timeout)),
            main: transform(&config.default, None),
            fallback: None,
            fallback_domain_filters: Vec::new(),
            fallback_ip_filters: Vec::new(),
            fallback_lazy_query: false,
            group: Arc::new(singleflight::Group::default()),
            cache: config.new_cache(),
            policy: None,
            default_resolver: None,
        };
        let default_resolver = Arc::new(default_resolver);
        let default_resolver_copy = Arc::clone(&default_resolver);
        let default_resolver_shared: SharedResolver = default_resolver_copy;

        let mut name_server_cache: Vec<(NameServer, Arc<dyn DnsClient>)> = Vec::new();

        let main = cache_transform(&mut name_server_cache, &default_resolver_shared, &config.main);
        let policy_list = make_policy(&mut name_server_cache, &default_resolver_shared, &config.policy);

        let mut r = Resolver {
            ipv6_timeout: Duration::from_millis(u64::from(config.ipv6_timeout)),
            main,
            fallback: None,
            fallback_domain_filters: Vec::new(),
            fallback_ip_filters: Vec::new(),
            fallback_lazy_query: false,
            group: Arc::new(singleflight::Group::default()),
            cache: config.new_cache(),
            policy: if policy_list.is_empty() { None } else { Some(policy_list) },
            default_resolver: Some(Arc::clone(&default_resolver)),
        };

        let proxy_resolver = if config.proxy_server.is_empty() {
            None
        } else {
            let main = cache_transform(&mut name_server_cache, &default_resolver_shared, &config.proxy_server);
            let policy_list =
                make_policy(&mut name_server_cache, &default_resolver_shared, &config.proxy_server_policy);
            Some(Resolver {
                ipv6_timeout: Duration::from_millis(u64::from(config.ipv6_timeout)),
                main,
                fallback: None,
                fallback_domain_filters: Vec::new(),
                fallback_ip_filters: Vec::new(),
                fallback_lazy_query: false,
                group: Arc::new(singleflight::Group::default()),
                cache: config.new_cache(),
                policy: if policy_list.is_empty() { None } else { Some(policy_list) },
                default_resolver: None,
            })
        };

        let direct_resolver = if config.direct_server.is_empty() {
            None
        } else {
            let main = cache_transform(&mut name_server_cache, &default_resolver_shared, &config.direct_server);
            Some(Resolver {
                ipv6_timeout: Duration::from_millis(u64::from(config.ipv6_timeout)),
                main,
                fallback: None,
                fallback_domain_filters: Vec::new(),
                fallback_ip_filters: Vec::new(),
                fallback_lazy_query: false,
                group: Arc::new(singleflight::Group::default()),
                cache: config.new_cache(),
                policy: if config.direct_follow_policy { r.policy.clone() } else { None },
                default_resolver: None,
            })
        };

        if !config.fallback.is_empty() {
            r.fallback = Some(cache_transform(&mut name_server_cache, &default_resolver_shared, &config.fallback));
            r.fallback_ip_filters = config.fallback_ip_filter;
            r.fallback_domain_filters = config.fallback_domain_filter;
            r.fallback_lazy_query = config.fallback_lazy_query;
        }

        Self { resolver: r, proxy_resolver, direct_resolver }
    }
}

/// The nameserver parser, installed once at startup by the config layer.
pub static PARSE_NAME_SERVER: OnceLock<Box<dyn Fn(&[String]) -> Result<Vec<NameServer>> + Send + Sync>> =
    OnceLock::new();

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::RecordType;
    use tokio_util::sync::CancellationToken;

    use murmur_constant::matcher::{DomainMatcher, IpMatcher};

    use super::{fqdn_name, question, Config, DnsClient, NameServer, NsNetType, Policy, Resolver, Resolvers};

    struct SuffixMatcher(&'static str);

    impl DomainMatcher for SuffixMatcher {
        fn match_domain(&self, domain: &str) -> bool {
            domain.ends_with(self.0)
        }
    }

    struct V4CidrMatcher {
        network: std::net::Ipv4Addr,
        prefix: u32,
    }

    impl IpMatcher for V4CidrMatcher {
        fn match_ip(&self, ip: std::net::IpAddr) -> bool {
            let std::net::IpAddr::V4(ip) = ip else { return false };
            let mask = if self.prefix == 0 { 0 } else { !0u32 << (32 - self.prefix) };
            (u32::from(ip) & mask) == (u32::from(self.network) & mask)
        }
    }

    fn ns_rcode(addr: &str) -> NameServer {
        NameServer {
            net: NsNetType::Rcode,
            addr: addr.to_owned(),
            proxy_adapter: None,
            proxy_name: String::new(),
            params: HashMap::new(),
            prefer_h3: false,
        }
    }

    fn rcode_client(addr: &str) -> Arc<dyn DnsClient> {
        Arc::new(super::super::rcode::new_rcode_client(addr))
    }

    fn msg_for(domain: &str) -> Message {
        if domain.is_empty() {
            return Message::new(0, MessageType::Query, OpCode::Query);
        }
        question(fqdn_name(domain).expect("valid domain"), RecordType::A)
    }

    fn addresses(clients: &[Arc<dyn DnsClient>]) -> Vec<String> {
        clients.iter().map(|c| c.address()).collect()
    }

    struct RecordingClient {
        seen: std::sync::Mutex<Vec<Message>>,
    }

    #[async_trait::async_trait]
    impl DnsClient for RecordingClient {
        async fn exchange_context(&self, _ctx: &CancellationToken, m: &Message) -> anyhow::Result<Message> {
            self.seen.lock().expect("lock").push(m.clone());
            let mut reply = Message::new(m.metadata.id, MessageType::Response, OpCode::Query);
            reply.metadata.response_code = hickory_proto::op::ResponseCode::NoError;
            Ok(reply)
        }

        fn address(&self) -> String {
            "recording://".to_owned()
        }

        fn reset_connection(&self) {}
    }

    // Lookup queries set the recursion-desired bit; without it, RD-honouring resolvers answer
    // SERVFAIL.
    #[tokio::test]
    async fn lookup_queries_reach_the_upstream_with_recursion_desired() {
        let recording = Arc::new(RecordingClient { seen: std::sync::Mutex::new(Vec::new()) });
        let recording_copy = Arc::clone(&recording);
        let client: Arc<dyn DnsClient> = recording_copy;
        let resolver = Resolver::from_client(client);

        let _ = resolver.lookup_ipv4(&CancellationToken::new(), "example.com").await;

        let seen = recording.seen.lock().expect("lock").clone();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].metadata.recursion_desired);
        assert_eq!(seen[0].queries.len(), 1);
        assert_eq!(seen[0].queries[0].query_type, RecordType::A);
        assert_eq!(seen[0].queries[0].name.to_string(), "example.com.");
    }

    // The first entry in `policy:` order whose matcher matches wins.
    #[test]
    fn match_policy_prefers_the_earlier_trie_policy_over_a_later_overlapping_matcher_policy() {
        let config = Config {
            policy: vec![
                Policy { domain: "+.example.cn".to_owned(), matcher: None, name_servers: vec![ns_rcode("success")] },
                Policy {
                    domain: String::new(),
                    matcher: Some(Arc::new(SuffixMatcher(".cn"))),
                    name_servers: vec![ns_rcode("refused")],
                },
            ],
            ..Config::default()
        };
        let resolvers = Resolvers::new(config);

        assert_eq!(addresses(&resolvers.resolver.match_policy(&msg_for("sub.example.cn"))), ["rcode://success"]);
        assert_eq!(addresses(&resolvers.resolver.match_policy(&msg_for("other.cn"))), ["rcode://refused"]);
        assert!(resolvers.resolver.match_policy(&msg_for("example.com")).is_empty());
    }

    #[test]
    fn match_policy_prefers_the_earlier_matcher_policy_over_a_later_trie_policy() {
        let config = Config {
            policy: vec![
                Policy {
                    domain: String::new(),
                    matcher: Some(Arc::new(SuffixMatcher(".cn"))),
                    name_servers: vec![ns_rcode("refused")],
                },
                Policy { domain: "+.example.cn".to_owned(), matcher: None, name_servers: vec![ns_rcode("success")] },
            ],
            ..Config::default()
        };
        let resolvers = Resolvers::new(config);

        assert_eq!(addresses(&resolvers.resolver.match_policy(&msg_for("sub.example.cn"))), ["rcode://refused"]);
    }

    #[test]
    fn match_policy_first_matching_matcher_policy_wins_when_both_match() {
        let config = Config {
            policy: vec![
                Policy {
                    domain: String::new(),
                    matcher: Some(Arc::new(SuffixMatcher(".com"))),
                    name_servers: vec![ns_rcode("success")],
                },
                Policy {
                    domain: String::new(),
                    matcher: Some(Arc::new(SuffixMatcher("le.com"))),
                    name_servers: vec![ns_rcode("refused")],
                },
            ],
            ..Config::default()
        };
        let resolvers = Resolvers::new(config);

        assert_eq!(addresses(&resolvers.resolver.match_policy(&msg_for("example.com"))), ["rcode://success"]);
    }

    #[test]
    fn match_policy_returns_no_clients_for_a_message_with_no_question() {
        let config = Config {
            policy: vec![Policy {
                domain: "+.example.cn".to_owned(),
                matcher: None,
                name_servers: vec![ns_rcode("success")],
            }],
            ..Config::default()
        };
        let resolvers = Resolvers::new(config);

        assert!(resolvers.resolver.match_policy(&msg_for("")).is_empty());
    }

    // `DomainTrie::insert` writes a "+.X" policy's data to both the exact node "X" and its
    // dot-wildcard child, so a later "+."-form entry silently overwrites an earlier exact-domain
    // entry for the same name.
    #[test]
    fn match_policy_a_later_complex_wildcard_policy_overwrites_an_earlier_exact_domain_entry() {
        let config = Config {
            policy: vec![
                Policy { domain: "example.com".to_owned(), matcher: None, name_servers: vec![ns_rcode("success")] },
                Policy { domain: "+.example.com".to_owned(), matcher: None, name_servers: vec![ns_rcode("refused")] },
            ],
            ..Config::default()
        };
        let resolvers = Resolvers::new(config);

        assert_eq!(addresses(&resolvers.resolver.match_policy(&msg_for("example.com"))), ["rcode://refused"]);
        assert_eq!(addresses(&resolvers.resolver.match_policy(&msg_for("sub.example.com"))), ["rcode://refused"]);
        assert!(resolvers.resolver.match_policy(&msg_for("other.com")).is_empty());
    }

    #[test]
    fn should_only_query_fallback_false_when_no_fallback_configured() {
        let resolver = Resolver::from_client(rcode_client("success"));
        assert!(!resolver.should_only_query_fallback(&msg_for("cn.example.com")));
    }

    #[test]
    fn should_only_query_fallback_false_when_fallback_set_but_no_domain_filters() {
        let base = Resolver::from_client(rcode_client("success"));
        let resolver = Resolver { fallback: Some(vec![rcode_client("refused")]), ..base };
        assert!(!resolver.should_only_query_fallback(&msg_for("cn.example.com")));
    }

    #[test]
    fn should_only_query_fallback_true_only_when_a_fallback_domain_filter_matches() {
        let base = Resolver::from_client(rcode_client("success"));
        let resolver = Resolver {
            fallback: Some(vec![rcode_client("refused")]),
            fallback_domain_filters: vec![Arc::new(SuffixMatcher(".cn"))],
            ..base
        };
        assert!(resolver.should_only_query_fallback(&msg_for("cn.example.cn")));
        assert!(!resolver.should_only_query_fallback(&msg_for("cn.example.com")));
        assert!(!resolver.should_only_query_fallback(&msg_for("")));
    }

    // OR over `fallback-filter.geoip`/`ipcidr` matchers.
    #[test]
    fn should_ip_fallback_true_only_when_an_ip_filter_matches() {
        let base = Resolver::from_client(rcode_client("success"));
        let resolver = Resolver {
            fallback_ip_filters: vec![Arc::new(V4CidrMatcher { network: "10.0.0.0".parse().unwrap(), prefix: 8 })],
            ..base
        };
        assert!(resolver.should_ip_fallback("10.1.2.3".parse().unwrap()));
        assert!(!resolver.should_ip_fallback("11.1.2.3".parse().unwrap()));
    }

    // A resolver is built only when the matching nameserver
    // list is non-empty, keeping proxy-server and direct nameservers independent of the main
    // resolver's client set.
    #[test]
    fn resolvers_new_builds_proxy_and_direct_resolvers_only_when_their_nameservers_are_set() {
        let empty = Resolvers::new(Config::default());
        assert!(empty.proxy_resolver.is_none());
        assert!(empty.direct_resolver.is_none());

        let with_proxy = Resolvers::new(Config {
            main: vec![ns_rcode("success")],
            proxy_server: vec![ns_rcode("refused")],
            direct_server: vec![ns_rcode("name_error")],
            ..Config::default()
        });
        assert_eq!(addresses(&with_proxy.resolver.main), ["rcode://success"]);
        assert_eq!(addresses(&with_proxy.proxy_resolver.unwrap().main), ["rcode://refused"]);
        assert_eq!(addresses(&with_proxy.direct_resolver.unwrap().main), ["rcode://name_error"]);
    }

    #[test]
    fn resolvers_new_direct_resolver_follows_the_main_policy_only_when_configured() {
        fn one_policy() -> Vec<Policy> {
            vec![Policy { domain: "example.com".to_owned(), matcher: None, name_servers: vec![ns_rcode("success")] }]
        }

        let not_following = Resolvers::new(Config {
            direct_server: vec![ns_rcode("refused")],
            policy: one_policy(),
            direct_follow_policy: false,
            ..Config::default()
        });
        assert!(not_following.direct_resolver.unwrap().policy.is_none());

        let following = Resolvers::new(Config {
            direct_server: vec![ns_rcode("refused")],
            policy: one_policy(),
            direct_follow_policy: true,
            ..Config::default()
        });
        assert!(following.direct_resolver.unwrap().policy.is_some());
    }
}
