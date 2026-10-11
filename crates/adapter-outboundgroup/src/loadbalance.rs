//! The effective-TLD-plus-one semantics come from the `psl` crate (a compiled Mozilla Public Suffix
//! List).
//!
//! The helper below matches the crate's upfront empty-label validation and its "cannot derive
//! eTLD+1" error for a bare or unlisted top-level domain.

use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use murmur_common::lru::{self, LruCache};
use murmur_common::utils::global_id::map_hash;
use murmur_common_callback::callback::new_first_write_call_back_conn;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_constant::provider::interface::ProxyProvider;

use super::groupbase::{GroupBase, GroupBaseOption};
use super::parser::GroupCommonOption;
use super::util::{need_handshake, ProxyGroup};

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct LoadBalanceOption {
    #[serde(rename = "strategy", default)]
    pub strategy: String,
}

type StrategyFn = Box<dyn Fn(&[Arc<dyn Proxy>], Option<&Metadata>, bool) -> Arc<dyn Proxy> + Send + Sync>;

pub struct LoadBalance {
    self_weak: Weak<Self>,
    group_base: GroupBase,
    disable_udp: bool,
    strategy_fn: StrategyFn,
    test_url: String,
    expected_status: String,
}

impl core::fmt::Debug for LoadBalance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadBalance")
            .field("group_base", &self.group_base)
            .field("disable_udp", &self.disable_udp)
            .field("test_url", &self.test_url)
            .field("expected_status", &self.expected_status)
            .finish_non_exhaustive()
    }
}

fn effective_tld_plus_one(domain: &str) -> Result<String> {
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err(anyhow!("publicsuffix: empty label in domain {domain:?}"));
    }
    psl::domain_str(domain)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("publicsuffix: cannot derive eTLD+1 for domain {domain:?}"))
}

fn netip_string(ip: Option<IpAddr>) -> String {
    ip.map_or_else(|| "invalid IP".to_owned(), |ip| ip.to_string())
}

fn get_key(metadata: Option<&Metadata>) -> String {
    let Some(metadata) = metadata else { return String::new() };

    if !metadata.host.is_empty() {
        if metadata.host.parse::<IpAddr>().is_ok() {
            return metadata.host.clone();
        }
        if let Ok(etld) = effective_tld_plus_one(&metadata.host) {
            return etld;
        }
    }

    match metadata.dst_ip {
        Some(ip) => ip.to_string(),
        None => String::new(),
    }
}

fn get_key_with_src_and_dst(metadata: Option<&Metadata>) -> String {
    let dst = get_key(metadata);
    let src = metadata.map_or_else(String::new, |m| netip_string(m.src_ip));
    format!("{src}{dst}")
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "jump consistent hashing is defined over these f64/i64 conversions; the result is a \
              bucket index bounded by `buckets`"
)]
fn jump_hash(mut key: u64, buckets: i32) -> i32 {
    let mut b: i64 = 0;
    let mut j: i64 = 0;
    while j < i64::from(buckets) {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = ((b + 1) as f64 * ((1i64 << 31) as f64 / (((key >> 33) + 1) as f64))) as i64;
    }
    b as i32
}

fn first_or_fallback(proxies: &[Arc<dyn Proxy>], empty_fallback: &Arc<dyn Proxy>) -> Arc<dyn Proxy> {
    proxies.first().map_or_else(|| Arc::clone(empty_fallback), Arc::clone)
}

fn now_unix_nano() -> i64 {
    chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
}

fn strategy_round_robin(url: String, empty_fallback: Arc<dyn Proxy>) -> StrategyFn {
    let idx = Mutex::new(0usize);
    Box::new(move |proxies: &[Arc<dyn Proxy>], _metadata, touch: bool| -> Arc<dyn Proxy> {
        let mut idx_guard = idx.lock();
        let length = proxies.len();
        let mut i = 0usize;

        let result = loop {
            if i >= length {
                break first_or_fallback(proxies, &empty_fallback);
            }
            let id = (*idx_guard + i) % length;
            let Some(proxy) = proxies.get(id) else {
                break first_or_fallback(proxies, &empty_fallback);
            };
            if proxy.alive_for_test_url(&url) {
                i += 1;
                break Arc::clone(proxy);
            }
            i += 1;
        };

        if touch {
            *idx_guard = (*idx_guard + i) % length;
        }

        result
    })
}

fn strategy_consistent_hashing(url: String, empty_fallback: Arc<dyn Proxy>) -> StrategyFn {
    const MAX_RETRY: i32 = 5;
    Box::new(move |proxies: &[Arc<dyn Proxy>], metadata, _touch: bool| -> Arc<dyn Proxy> {
        let mut key = map_hash(&get_key(metadata));
        let buckets = i32::try_from(proxies.len()).unwrap_or(i32::MAX);
        for _ in 0..MAX_RETRY {
            let idx = usize::try_from(jump_hash(key, buckets)).unwrap_or_default();
            if let Some(proxy) = proxies.get(idx) {
                if proxy.alive_for_test_url(&url) {
                    return Arc::clone(proxy);
                }
            }
            key = key.wrapping_add(1);
        }

        for proxy in proxies {
            if proxy.alive_for_test_url(&url) {
                return Arc::clone(proxy);
            }
        }

        first_or_fallback(proxies, &empty_fallback)
    })
}

fn strategy_sticky_sessions(url: String, empty_fallback: Arc<dyn Proxy>) -> StrategyFn {
    const MAX_RETRY: i32 = 5;
    let ttl_secs: i64 = Duration::from_secs(600).as_secs().cast_signed();
    let lru_cache: LruCache<u64, i32> = lru::new(vec![lru::with_age(ttl_secs), lru::with_size(1000)]);

    Box::new(move |proxies: &[Arc<dyn Proxy>], metadata, _touch: bool| -> Arc<dyn Proxy> {
        let key = map_hash(&get_key_with_src_and_dst(metadata));
        let length = i32::try_from(proxies.len()).unwrap_or(i32::MAX);
        let (mut idx, has) = lru_cache.get(&key);
        if !has || idx >= length {
            idx = jump_hash(key.wrapping_add(now_unix_nano().cast_unsigned()), length);
        }

        let original_idx = idx;
        let mut now_idx = idx;
        for _ in 1..MAX_RETRY {
            let candidate = usize::try_from(now_idx).unwrap_or_default();
            if let Some(proxy) = proxies.get(candidate) {
                if proxy.alive_for_test_url(&url) {
                    if !has || now_idx != original_idx {
                        lru_cache.set(key, now_idx);
                    }
                    return Arc::clone(proxy);
                }
            }
            now_idx = jump_hash(key.wrapping_add(now_unix_nano().cast_unsigned()), length);
        }

        lru_cache.set(key, 0);
        first_or_fallback(proxies, &empty_fallback)
    })
}

impl LoadBalance {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "public constructor signature is part of this crate's adapter API; callers own the \
                  deserialized option"
    )]
    pub fn new(
        option: GroupCommonOption,
        load_balance_option: LoadBalanceOption,
        empty_fallback: Arc<dyn Proxy>,
        providers: Vec<Arc<dyn ProxyProvider>>,
    ) -> Result<Arc<Self>> {
        let strategy_fn: StrategyFn = match load_balance_option.strategy.as_str() {
            "" | "consistent-hashing" => strategy_consistent_hashing(option.url.clone(), Arc::clone(&empty_fallback)),
            "round-robin" => strategy_round_robin(option.url.clone(), Arc::clone(&empty_fallback)),
            "sticky-sessions" => strategy_sticky_sessions(option.url.clone(), Arc::clone(&empty_fallback)),
            other => return Err(anyhow!("unsupported strategy: {other}")),
        };

        let group_base = GroupBase::new(GroupBaseOption {
            name: option.name,
            type_: AdapterType::LOAD_BALANCE,
            hidden: option.hidden,
            icon: option.icon,
            filter: option.filter,
            exclude_filter: option.exclude_filter,
            exclude_type: option.exclude_type,
            test_timeout: option.test_timeout,
            max_failed_times: option.max_failed_times,
            empty_fallback,
            providers,
        });

        Ok(Arc::new_cyclic(|self_weak| Self {
            self_weak: Weak::clone(self_weak),
            group_base,
            strategy_fn,
            disable_udp: option.disable_udp,
            test_url: option.url,
            expected_status: option.expected_status,
        }))
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("LoadBalance adapter dropped while still in use"))
    }

    fn health_check_closure(&self) -> impl Fn() + Send + Sync + 'static {
        let weak = Weak::clone(&self.self_weak);
        move || {
            let weak = Weak::clone(&weak);
            tokio::spawn(async move {
                if let Some(this) = weak.upgrade() {
                    this.group_base.health_check().await;
                }
            });
        }
    }

    fn unwrap_proxy(&self, metadata: &Metadata, touch: bool) -> Arc<dyn Proxy> {
        let proxies = self.group_base.get_proxies(touch);
        (self.strategy_fn)(&proxies, Some(metadata), touch)
    }
}

#[async_trait]
impl CProxyAdapter for LoadBalance {
    fn name(&self) -> String {
        self.group_base.base.name()
    }

    fn type_(&self) -> AdapterType {
        self.group_base.base.type_()
    }

    fn addr(&self) -> String {
        self.group_base.base.addr()
    }

    fn support_udp(&self) -> bool {
        !self.disable_udp
    }

    fn proxy_info(&self) -> ProxyInfo {
        self.group_base.base.proxy_info()
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        let all: Vec<String> = self.group_base.get_proxies(false).iter().map(|p| p.name()).collect();
        Ok(serde_json::to_vec(&serde_json::json!({
            "type": self.type_().string(),
            "all": all,
            "testUrl": self.test_url,
            "expectedStatus": self.expected_status,
            "hidden": self.group_base.hidden(),
            "icon": self.group_base.icon(),
            "emptyFallback": self.group_base.empty_fallback().name(),
        }))?)
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let proxy = self.unwrap_proxy(metadata, true);
        let dial_type = proxy.type_();
        let mut c = match proxy.dial_context(ctx, metadata).await {
            Ok(conn) => conn,
            Err(err) => {
                self.group_base.on_dial_failed(dial_type, &err, self.health_check_closure());
                return Err(err);
            }
        };
        c.append_to_chains(self.self_arc()?);

        if need_handshake(&*c) {
            let weak = Weak::clone(&self.self_weak);
            c = new_first_write_call_back_conn(
                c,
                Box::new(move |err: Option<anyhow::Error>| {
                    let Some(this) = weak.upgrade() else { return };
                    match err {
                        None => this.group_base.on_dial_success(),
                        Some(err) => this.group_base.on_dial_failed(dial_type, &err, this.health_check_closure()),
                    }
                }),
            );
        }

        Ok(c)
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        let proxy = self.unwrap_proxy(metadata, true);
        let pc = proxy.listen_packet_context(ctx, metadata).await?;
        pc.append_to_chains(self.self_arc()?);
        Ok(pc)
    }

    fn support_uot(&self) -> bool {
        self.group_base.base.support_uot()
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.unwrap_proxy(metadata, false).is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        Some(self.unwrap_proxy(metadata, touch))
    }

    fn close(&self) -> Result<()> {
        self.group_base.base.close()
    }
}

#[async_trait]
impl ProxyGroup for LoadBalance {
    fn providers(&self) -> Vec<Arc<dyn ProxyProvider>> {
        self.group_base.providers.clone()
    }

    fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.group_base.get_proxies(false)
    }

    fn now(&self) -> String {
        String::new()
    }

    fn touch(&self) {
        self.group_base.touch();
    }

    fn hidden(&self) -> bool {
        self.group_base.hidden()
    }

    fn icon(&self) -> String {
        self.group_base.icon()
    }

    async fn url_test(
        &self,
        ctx: &CancellationToken,
        url: &str,
        expected_status: murmur_common::utils::ranges::IntRanges<u16>,
    ) -> Result<std::collections::HashMap<String, u16>> {
        self.group_base.url_test(ctx, url, expected_status).await
    }
}

#[cfg(test)]
mod tests {
    use super::effective_tld_plus_one;

    #[test]
    fn two_label_domain() {
        assert_eq!(effective_tld_plus_one("foo.example.com").unwrap(), "example.com");
    }

    #[test]
    fn multi_label_public_suffix() {
        assert_eq!(effective_tld_plus_one("example.co.uk").unwrap(), "example.co.uk");
    }

    #[test]
    fn deep_subdomain_of_multi_label_suffix() {
        assert_eq!(effective_tld_plus_one("foo.bar.example.co.uk").unwrap(), "example.co.uk");
    }

    #[test]
    fn no_etld_plus_one_for_bare_tld() {
        assert!(effective_tld_plus_one("com").is_err());
    }
}
