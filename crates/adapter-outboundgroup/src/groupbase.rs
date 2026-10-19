//! `fancy_regex::Regex::new` compiles a pattern with no flags, matching
//! `adapter/provider/healthcheck.rs`'s own mapping (the no-flag case is not case-insensitive).
//!
//! An invalid pattern panics rather than returning an error; that panic only ever fires on a bad
//! user-supplied filter at config-parse time.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use fancy_regex::Regex;
use parking_lot::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use murmur_adapter_outbound::base::{Base, BaseOption};
use murmur_common::atomic::type_::{new_bool, Bool};
use murmur_common::errors::error_is;
use murmur_common::utils::ranges::IntRanges;
use murmur_constant::adapters::{AdapterType, ErrNotSupport, Proxy};
use murmur_constant::provider::interface::{ProxyProvider, VehicleType};
use murmur_log::debugln;
use murmur_log::warnln;

fn equal_fold(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right) || left.to_lowercase() == right.to_lowercase()
}

#[allow(clippy::panic, reason = "the regexp2.MustCompile panics on an invalid pattern")]
pub(crate) fn must_compile_regexp2(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| panic!("regexp2: invalid pattern {pattern:?}: {err}"))
}

struct FailedState {
    times: i32,
    time: Option<DateTime<Utc>>,
}

/// Holds the failed-test-guarded fields on their own `Arc` so `GroupBase::on_dial_failed` can
/// hand a background `tokio::spawn`ed task a `'static` handle to them without requiring `GroupBase`
/// itself to live behind an `Arc`.
struct FailedTracker {
    name: String,
    test_timeout: i32,
    max_failed_times: i32,
    state: Mutex<FailedState>,
}

struct ProxiesCache {
    provider_versions: Vec<u32>,
    provider_proxies: Vec<Arc<dyn Proxy>>,
}

pub struct GroupBase {
    pub(crate) base: Base,
    hidden: bool,
    icon: String,
    filter_regs: Vec<Regex>,
    exclude_filter_regs: Vec<Regex>,
    exclude_type_array: Vec<String>,
    pub(crate) providers: Vec<Arc<dyn ProxyProvider>>,
    failed_testing: Bool,
    failed: Arc<FailedTracker>,
    empty_fallback: Arc<dyn Proxy>,
    proxies_cache: Mutex<ProxiesCache>,
}

impl core::fmt::Debug for GroupBase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GroupBase")
            .field("base", &self.base)
            .field("hidden", &self.hidden)
            .field("icon", &self.icon)
            .finish_non_exhaustive()
    }
}

pub struct GroupBaseOption {
    pub name: String,
    pub type_: AdapterType,
    pub hidden: bool,
    pub icon: String,
    pub filter: String,
    pub exclude_filter: String,
    pub exclude_type: String,
    pub test_timeout: i32,
    pub max_failed_times: i32,
    pub empty_fallback: Arc<dyn Proxy>,
    pub providers: Vec<Arc<dyn ProxyProvider>>,
}

impl core::fmt::Debug for GroupBaseOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GroupBaseOption")
            .field("name", &self.name)
            .field("type_", &self.type_)
            .field("hidden", &self.hidden)
            .field("icon", &self.icon)
            .finish_non_exhaustive()
    }
}

impl GroupBase {
    pub fn new(opt: GroupBaseOption) -> Self {
        let exclude_type_array: Vec<String> = if opt.exclude_type.is_empty() {
            Vec::new()
        } else {
            opt.exclude_type.split('|').map(str::to_owned).collect()
        };

        let exclude_filter_regs: Vec<Regex> = if opt.exclude_filter.is_empty() {
            Vec::new()
        } else {
            opt.exclude_filter.split('`').map(must_compile_regexp2).collect()
        };

        let filter_regs: Vec<Regex> =
            if opt.filter.is_empty() { Vec::new() } else { opt.filter.split('`').map(must_compile_regexp2).collect() };

        let name = opt.name.clone();
        let base = Base::new(BaseOption { name: opt.name, type_: opt.type_, ..Default::default() });

        let test_timeout = if opt.test_timeout == 0 { 5000 } else { opt.test_timeout };
        let max_failed_times = if opt.max_failed_times == 0 { 5 } else { opt.max_failed_times };

        Self {
            base,
            hidden: opt.hidden,
            icon: opt.icon,
            filter_regs,
            exclude_filter_regs,
            exclude_type_array,
            providers: opt.providers,
            failed_testing: new_bool(false),
            failed: Arc::new(FailedTracker {
                name,
                test_timeout,
                max_failed_times,
                state: Mutex::new(FailedState { times: 0, time: None }),
            }),
            empty_fallback: opt.empty_fallback,
            proxies_cache: Mutex::new(ProxiesCache { provider_versions: Vec::new(), provider_proxies: Vec::new() }),
        }
    }

    pub const fn hidden(&self) -> bool {
        self.hidden
    }

    pub fn icon(&self) -> String {
        self.icon.clone()
    }

    pub fn empty_fallback(&self) -> Arc<dyn Proxy> {
        Arc::clone(&self.empty_fallback)
    }

    pub fn touch(&self) {
        for provider in &self.providers {
            provider.touch();
        }
    }

    pub fn get_proxies(&self, touch: bool) -> Vec<Arc<dyn Proxy>> {
        let mut provider_versions = Vec::with_capacity(self.providers.len());
        for provider in &self.providers {
            if touch {
                provider.touch();
            }
            provider_versions.push(provider.version());
        }

        let mut cache = self.proxies_cache.lock();

        if provider_versions == cache.provider_versions {
            return cache.provider_proxies.clone();
        }

        let mut proxies: Vec<Arc<dyn Proxy>> = Vec::new();
        if self.filter_regs.is_empty() {
            for provider in &self.providers {
                proxies.extend(provider.proxies());
            }
        } else {
            for provider in &self.providers {
                if provider.vehicle_type() == VehicleType::COMPATIBLE {
                    proxies.extend(provider.proxies());
                    continue;
                }

                let mut new_proxies = Vec::new();
                let mut proxies_set = HashSet::new();
                for filter_reg in &self.filter_regs {
                    for p in provider.proxies() {
                        let name = p.name();
                        if filter_reg.is_match(&name).unwrap_or(false) && proxies_set.insert(name) {
                            new_proxies.push(p);
                        }
                    }
                }
                proxies.extend(new_proxies);
            }
        }

        if self.providers.len() > 1 && self.filter_regs.len() > 1 {
            let mut new_proxies = Vec::new();
            let mut proxies_set = HashSet::new();
            for filter_reg in &self.filter_regs {
                for p in &proxies {
                    let name = p.name();
                    if filter_reg.is_match(&name).unwrap_or(false) && proxies_set.insert(name) {
                        new_proxies.push(Arc::clone(p));
                    }
                }
            }
            for p in &proxies {
                let name = p.name();
                if proxies_set.insert(name) {
                    new_proxies.push(Arc::clone(p));
                }
            }
            proxies = new_proxies;
        }

        if !self.exclude_filter_regs.is_empty() {
            proxies.retain(|p| {
                let name = p.name();
                !self.exclude_filter_regs.iter().any(|reg| reg.is_match(&name).unwrap_or(false))
            });
        }

        if !self.exclude_type_array.is_empty() {
            proxies.retain(|p| {
                let m_type = p.type_().string();
                !self.exclude_type_array.iter().any(|excl| equal_fold(&m_type, excl))
            });
        }

        if proxies.is_empty() {
            return vec![self.empty_fallback()];
        }

        cache.provider_versions = provider_versions;
        cache.provider_proxies.clone_from(&proxies);

        proxies
    }

    pub async fn url_test(
        &self,
        ctx: &CancellationToken,
        url: &str,
        expected_status: IntRanges<u16>,
    ) -> Result<HashMap<String, u16>> {
        let proxies = self.get_proxies(false);
        let mut set = JoinSet::new();
        for proxy in proxies {
            let ctx = ctx.clone();
            let url = url.to_owned();
            let expected_status = expected_status.clone();
            set.spawn(async move {
                let result = proxy.url_test(&ctx, &url, expected_status).await;
                (proxy.name(), result)
            });
        }

        let mut mp = HashMap::new();
        while let Some(joined) = set.join_next().await {
            if let Ok((name, Ok(delay))) = joined {
                mp.insert(name, delay);
            }
        }

        if mp.is_empty() {
            Err(anyhow!("get delay: all proxies timeout"))
        } else {
            Ok(mp)
        }
    }

    pub(crate) fn on_dial_failed(
        &self,
        adapter_type: AdapterType,
        err: &anyhow::Error,
        health_check: impl Fn() + Send + Sync + 'static,
    ) {
        if matches!(
            adapter_type,
            AdapterType::DIRECT
                | AdapterType::COMPATIBLE
                | AdapterType::REJECT
                | AdapterType::PASS
                | AdapterType::REJECT_DROP
        ) {
            return;
        }

        if error_is::<ErrNotSupport>(err) {
            return;
        }

        let failed = Arc::clone(&self.failed);
        let err_message = err.to_string();
        tokio::spawn(async move {
            if err_message.contains("connection refused") {
                health_check();
                return;
            }

            let mut state = failed.state.lock();
            state.times += 1;
            if state.times == 1 {
                debugln!("ProxyGroup: {} first failed", failed.name);
                state.time = Some(Utc::now());
            } else {
                let expired = match state.time {
                    Some(time) => {
                        Utc::now().signed_duration_since(time)
                            > chrono::Duration::milliseconds(i64::from(failed.test_timeout))
                    }
                    None => true,
                };
                if expired {
                    state.times = 0;
                    return;
                }

                debugln!("ProxyGroup: {} failed count: {}", failed.name, state.times);
                if state.times >= failed.max_failed_times {
                    warnln!("because {} failed multiple times, activate health check", failed.name);
                    health_check();
                }
            }
        });
    }

    pub(crate) async fn health_check(&self) {
        if self.failed_testing.load() {
            return;
        }

        self.failed_testing.store(true);
        let mut set = JoinSet::new();
        for provider in &self.providers {
            let provider = Arc::clone(provider);
            set.spawn(async move {
                provider.health_check().await;
            });
        }
        while set.join_next().await.is_some() {}

        self.failed_testing.store(false);
        self.failed.state.lock().times = 0;
    }

    pub(crate) fn on_dial_success(&self) {
        if !self.failed_testing.load() {
            self.failed.state.lock().times = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use anyhow::anyhow;

    use super::{GroupBase, GroupBaseOption};
    use crate::parser::GroupCommonOption;
    use crate::selector::{Selector, SelectorOption};
    use crate::util::{as_proxy_group, as_select_able};
    use murmur_adapter::adapter::Proxy;
    use murmur_adapter_outbound::direct::new_direct;
    use murmur_adapter_outbound::reject::new_reject;
    use murmur_constant::adapters::{err_not_support, AdapterType, Proxy as CProxy};

    fn group_base(max_failed_times: i32) -> GroupBase {
        GroupBase::new(GroupBaseOption {
            name: "test".to_owned(),
            type_: AdapterType::HTTP,
            hidden: false,
            icon: String::new(),
            filter: String::new(),
            exclude_filter: String::new(),
            exclude_type: String::new(),
            test_timeout: 5000,
            max_failed_times,
            empty_fallback: Proxy::new(new_reject()),
            providers: Vec::new(),
        })
    }

    /// `on_dial_failed` hands the bookkeeping to a `tokio::spawn`ed task with no internal await
    /// points; yielding a handful of times is enough for the runtime to run it to completion.
    async fn settle() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn on_dial_failed_ignores_err_not_support_even_wrapped_with_context() {
        let group = group_base(1);
        let called = Arc::new(AtomicBool::new(false));
        let health_check = {
            let called = Arc::clone(&called);
            move || called.store(true, Ordering::SeqCst)
        };
        let err = err_not_support().context("dial");

        group.on_dial_failed(AdapterType::HTTP, &err, health_check);
        settle().await;

        assert!(!called.load(Ordering::SeqCst), "err_not_support must not trigger the health check");
        assert_eq!(group.failed.state.lock().times, 0, "err_not_support must not count as a failure");
    }

    #[tokio::test]
    async fn on_dial_failed_counts_a_real_dial_error() {
        let group = group_base(1);
        let called = Arc::new(AtomicBool::new(false));
        let health_check = {
            let called = Arc::clone(&called);
            move || called.store(true, Ordering::SeqCst)
        };
        let err = anyhow!("x");

        group.on_dial_failed(AdapterType::HTTP, &err, health_check);
        settle().await;

        assert_eq!(group.failed.state.lock().times, 1, "a non-ErrNotSupport error must count as a failure");
    }

    /// Relocated from `adapter::adapter`'s own tests (crate split: this crate already depends on
    /// `adapter`, so the integration point moved here instead of `adapter` gaining a dev-only
    /// dependency back on this crate).
    #[test]
    fn wrapping_a_capable_adapter_hides_its_group_capabilities() {
        let empty_fallback = Proxy::new(new_direct());
        let selector =
            Selector::new(GroupCommonOption::default(), SelectorOption::default(), empty_fallback, Vec::new())
                .expect("selector construction");
        assert!(as_proxy_group(&*selector).is_some());
        assert!(as_select_able(&*selector).is_some());

        let proxy = Proxy::new(selector);
        assert!(as_proxy_group(&*proxy).is_none());
        assert!(as_select_able(&*proxy).is_none());
        assert!(as_proxy_group(&*proxy.adapter()).is_some());
        assert!(as_select_able(&*proxy.adapter()).is_some());
    }
}
