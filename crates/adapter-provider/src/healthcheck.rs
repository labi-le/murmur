//! Each check takes a `tokio::sync::Semaphore` permit (limit 10) before spawning into a
//! `tokio::task::JoinSet`, blocking the spawning loop once the limit is reached.
//!
//! The `JoinSet` is awaited to completion.
//!
//! `fancy_regex::Regex::new` compiles a pattern with no flags, matching the mapping
//! `murmur_rules_common::domain_regex` uses when no case-insensitive flag is set.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use fancy_regex::Regex;
use parking_lot::Mutex;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use murmur_common::atomic::value::TypedValue;
use murmur_common::singledo::singledo::{new_single, Single};
use murmur_common::utils::ranges::IntRanges;
use murmur_common::utils::uuid::new_uuid_v4;
use murmur_constant::adapters::Proxy;
use murmur_log::debugln;

#[derive(Clone, Debug, Default)]
pub struct HealthCheckOption {
    pub url: String,
    pub interval: u32,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ExtraOption {
    pub(crate) expected_status: IntRanges<u16>,
    pub(crate) filters: HashSet<String>,
}

struct HealthCheckMutable {
    interval: Duration,
    extra: HashMap<String, ExtraOption>,
}

pub struct HealthCheck {
    ctx: CancellationToken,
    pub(crate) url: String,
    mutable: Mutex<HealthCheckMutable>,
    proxies: parking_lot::RwLock<Vec<Arc<dyn Proxy>>>,
    lazy: bool,
    pub(crate) expected_status: IntRanges<u16>,
    last_touch: TypedValue<Option<chrono::DateTime<Utc>>>,
    single_do: Single<()>,
    timeout: Duration,
}

impl std::fmt::Debug for HealthCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthCheck")
            .field("url", &self.url)
            .field("lazy", &self.lazy)
            .field("expected_status", &self.expected_status)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl HealthCheck {
    // cancel-safe: `close` cancels the token this loop selects on, and an interrupted check is
    // single-flight guarded, so the next tick re-runs it.
    pub(crate) async fn process(self: Arc<Self>) {
        let interval = self.mutable.lock().interval;
        let mut ticker = tokio::time::interval(interval);
        // `tokio::time::interval` fires its first tick immediately; a conventional ticker waits one
        // full interval before its first tick, so that immediate tick is consumed up front.
        ticker.tick().await;

        let detached = Arc::clone(&self);
        tokio::spawn(async move { detached.check().await });

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let last_touch = self.last_touch.load();
                    let since = last_touch
                        .and_then(|t| Utc::now().signed_duration_since(t).to_std().ok())
                        .unwrap_or(Duration::MAX);
                    let interval = self.mutable.lock().interval;
                    if !self.lazy || since < interval {
                        self.check().await;
                    } else {
                        debugln!("Skip once health check because we are lazy");
                    }
                }
                () = self.ctx.cancelled() => {
                    return;
                }
            }
        }
    }

    pub(crate) fn set_proxies(&self, proxies: Vec<Arc<dyn Proxy>>) {
        *self.proxies.write() = proxies;
    }

    pub(crate) fn register_health_check_task(
        &self,
        url: &str,
        expected_status: IntRanges<u16>,
        filter: &str,
        interval: u32,
    ) {
        let url = url.trim();
        if url.is_empty() || url == self.url {
            debugln!("ignore invalid health check url: {url}");
            return;
        }

        let mut mutable = self.mutable.lock();

        // If the provider has not set up health checks, then modify it to be the same as the
        // group's interval.
        if mutable.interval == Duration::ZERO {
            mutable.interval = Duration::from_secs(u64::from(interval));
        }

        // Prioritize the use of previously registered configurations, especially those from
        // provider.
        if let Some(existing) = mutable.extra.get_mut(url) {
            if url != self.url && !filter.is_empty() {
                split_and_add_filters_to_extra(filter, existing);
            }

            debugln!("health check url: {url} exists");
            return;
        }

        let mut option = ExtraOption { filters: HashSet::new(), expected_status };
        split_and_add_filters_to_extra(filter, &mut option);
        mutable.extra.insert(url.to_owned(), option);
    }

    pub(crate) fn auto(&self) -> bool {
        self.mutable.lock().interval != Duration::ZERO
    }

    pub(crate) fn touch(&self) {
        self.last_touch.store(Some(Utc::now()));
    }

    pub(crate) async fn check(&self) {
        if self.proxies.read().is_empty() {
            return;
        }

        let _ = self
            .single_do
            .do_(|| async {
                let id = new_uuid_v4().to_string();
                debugln!("Start New Health Checking {{{id}}}");
                let semaphore = Arc::new(Semaphore::new(10));
                let mut tasks = JoinSet::new();

                // Execute the default health check.
                let default_option =
                    ExtraOption { filters: HashSet::new(), expected_status: self.expected_status.clone() };
                self.execute(&mut tasks, &semaphore, &self.url, &id, &default_option).await;

                // Execute the extra health checks.
                let extra_snapshot: Vec<(String, ExtraOption)> = {
                    let mutable = self.mutable.lock();
                    mutable.extra.iter().map(|(url, option)| (url.clone(), option.clone())).collect()
                };
                for (url, option) in &extra_snapshot {
                    self.execute(&mut tasks, &semaphore, url, &id, option).await;
                }

                while tasks.join_next().await.is_some() {}
                debugln!("Finish A Health Checking {{{id}}}");
                anyhow::Ok(())
            })
            .await;
    }

    async fn execute(
        &self,
        tasks: &mut JoinSet<()>,
        semaphore: &Arc<Semaphore>,
        url: &str,
        uid: &str,
        option: &ExtraOption,
    ) {
        let url = url.trim();
        if url.is_empty() {
            debugln!("Health Check has been skipped due to testUrl is empty, {{{uid}}}");
            return;
        }

        let expected_status = option.expected_status.clone();
        let filter_reg = if option.filters.is_empty() {
            None
        } else {
            let filters: Vec<&str> = option.filters.iter().map(String::as_str).collect();
            let pattern = filters.join("|");
            let Ok(regex) = Regex::new(&pattern) else {
                debugln!("Health Check has been skipped due to an invalid filter regex, {{{uid}}}");
                return;
            };
            Some(regex)
        };

        let proxies = self.proxies.read().clone();
        for proxy in proxies {
            if let Some(filter_reg) = &filter_reg {
                if !filter_reg.is_match(&proxy.name()).unwrap_or(false) {
                    continue;
                }
            }

            let Ok(permit) = Arc::clone(semaphore).acquire_owned().await else { return };

            let ctx = self.ctx.clone();
            let timeout = self.timeout;
            let url = url.to_owned();
            let uid = uid.to_owned();
            let expected_status = expected_status.clone();

            tasks.spawn(async move {
                let _permit = permit;

                let child = ctx.child_token();
                let timeout_ctx = child.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(timeout).await;
                    timeout_ctx.cancel();
                });

                debugln!("Health Checking, proxy: {}, url: {url}, id: {{{uid}}}", proxy.name());
                let _ = proxy.url_test(&child, &url, expected_status).await;
                child.cancel();
                debugln!(
                    "Health Checked, proxy: {}, url: {url}, alive: {}, delay: {} ms uid: {{{uid}}}",
                    proxy.name(),
                    proxy.alive_for_test_url(&url),
                    proxy.last_delay_for_test_url(&url),
                );
            });
        }
    }

    pub(crate) fn close(&self) {
        self.ctx.cancel();
    }
}

fn split_and_add_filters_to_extra(filter: &str, option: &mut ExtraOption) {
    let filter = filter.trim();
    if !filter.is_empty() {
        for regex in filter.split('`') {
            let regex = regex.trim();
            if !regex.is_empty() {
                option.filters.insert(regex.to_owned());
            }
        }
    }
}

#[must_use]
pub fn new_health_check(
    proxies: Vec<Arc<dyn Proxy>>,
    url: &str,
    timeout: u32,
    interval: u32,
    lazy: bool,
    expected_status: IntRanges<u16>,
) -> Arc<HealthCheck> {
    let (expected_status, interval) =
        if url.is_empty() { (IntRanges::default(), 0) } else { (expected_status, interval) };
    let timeout = if timeout == 0 { 5000 } else { timeout };

    Arc::new(HealthCheck {
        ctx: CancellationToken::new(),
        url: url.to_owned(),
        mutable: Mutex::new(HealthCheckMutable {
            interval: Duration::from_secs(u64::from(interval)),
            extra: HashMap::new(),
        }),
        proxies: parking_lot::RwLock::new(proxies),
        lazy,
        expected_status,
        last_touch: TypedValue::new(),
        single_do: new_single(Duration::from_secs(1)),
        timeout: Duration::from_millis(u64::from(timeout)),
    })
}
