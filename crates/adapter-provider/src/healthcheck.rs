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

                debugln!("Health Checking, proxy: {}, url: {url}, id: {{{uid}}}", proxy.name());
                let test = proxy.url_test(&child, &url, expected_status);
                tokio::pin!(test);
                // cancel-safe: the pinned probe future resumes where it left off after the sleep
                // arm wins, and the timeout arm awaits it instead of dropping it, so the history
                // publication inside `url_test` still runs.
                let finished = tokio::select! {
                    _ = &mut test => true,
                    () = tokio::time::sleep(timeout) => false,
                };
                if !finished {
                    child.cancel();
                    let _ = test.await;
                }
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use murmur_adapter::adapter::Proxy as AdapterProxy;
    use murmur_adapter_outbound::direct::new_direct;
    use murmur_common::utils::ranges::{new_unsigned_ranges, IntRanges};
    use murmur_constant::adapters::{
        AdapterType, Conn, DelayHistory, PacketConn, Proxy, ProxyAdapter, ProxyInfo, ProxyState,
    };
    use murmur_constant::metadata::Metadata;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::runtime::Handle;
    use tokio_util::sync::CancellationToken;

    use super::new_health_check;

    struct StubAdapter;

    #[async_trait]
    impl ProxyAdapter for StubAdapter {
        fn name(&self) -> String {
            "stub-adapter".to_owned()
        }

        fn type_(&self) -> AdapterType {
            AdapterType::DIRECT
        }

        fn addr(&self) -> String {
            String::new()
        }

        fn support_udp(&self) -> bool {
            false
        }

        fn proxy_info(&self) -> ProxyInfo {
            ProxyInfo::default()
        }

        fn marshal_json(&self) -> anyhow::Result<Vec<u8>> {
            Ok(Vec::new())
        }

        async fn dial_context(
            &self,
            _ctx: &CancellationToken,
            _metadata: &mut Metadata,
        ) -> anyhow::Result<Box<dyn Conn>> {
            Err(anyhow::anyhow!("stub cannot dial"))
        }

        async fn listen_packet_context(
            &self,
            _ctx: &CancellationToken,
            _metadata: &mut Metadata,
        ) -> anyhow::Result<Arc<dyn PacketConn>> {
            Err(anyhow::anyhow!("stub cannot listen"))
        }

        fn support_uot(&self) -> bool {
            false
        }

        fn is_l3_protocol(&self, _metadata: &Metadata) -> bool {
            false
        }

        fn unwrap(&self, _metadata: &Metadata, _touch: bool) -> Option<Arc<dyn Proxy>> {
            None
        }

        fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum ProbeMode {
        Fast,
        Stall,
    }

    struct StubProxy {
        name: String,
        mode: ProbeMode,
        completed: AtomicUsize,
    }

    impl StubProxy {
        fn new(name: &str, mode: ProbeMode) -> Arc<Self> {
            Arc::new(Self { name: name.to_owned(), mode, completed: AtomicUsize::new(0) })
        }
    }

    #[async_trait]
    impl ProxyAdapter for StubProxy {
        fn name(&self) -> String {
            self.name.clone()
        }

        fn type_(&self) -> AdapterType {
            AdapterType::DIRECT
        }

        fn addr(&self) -> String {
            String::new()
        }

        fn support_udp(&self) -> bool {
            false
        }

        fn proxy_info(&self) -> ProxyInfo {
            ProxyInfo::default()
        }

        fn marshal_json(&self) -> anyhow::Result<Vec<u8>> {
            Ok(Vec::new())
        }

        async fn dial_context(
            &self,
            _ctx: &CancellationToken,
            _metadata: &mut Metadata,
        ) -> anyhow::Result<Box<dyn Conn>> {
            Err(anyhow::anyhow!("stub cannot dial"))
        }

        async fn listen_packet_context(
            &self,
            _ctx: &CancellationToken,
            _metadata: &mut Metadata,
        ) -> anyhow::Result<Arc<dyn PacketConn>> {
            Err(anyhow::anyhow!("stub cannot listen"))
        }

        fn support_uot(&self) -> bool {
            false
        }

        fn is_l3_protocol(&self, _metadata: &Metadata) -> bool {
            false
        }

        fn unwrap(&self, _metadata: &Metadata, _touch: bool) -> Option<Arc<dyn Proxy>> {
            None
        }

        fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Proxy for StubProxy {
        fn adapter(&self) -> Arc<dyn ProxyAdapter> {
            Arc::new(StubAdapter)
        }

        fn alive_for_test_url(&self, _url: &str) -> bool {
            false
        }

        fn delay_history(&self) -> Vec<DelayHistory> {
            Vec::new()
        }

        fn extra_delay_histories(&self) -> HashMap<String, ProxyState> {
            HashMap::new()
        }

        fn last_delay_for_test_url(&self, _url: &str) -> u16 {
            0
        }

        async fn url_test(
            &self,
            ctx: &CancellationToken,
            _url: &str,
            _expected_status: IntRanges<u16>,
        ) -> anyhow::Result<u16> {
            if matches!(self.mode, ProbeMode::Stall) {
                ctx.cancelled().await;
            }
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(1)
        }
    }

    fn health_check(proxies: &[Arc<StubProxy>], timeout_ms: u32) -> Arc<super::HealthCheck> {
        let proxies: Vec<Arc<dyn Proxy>> = proxies
            .iter()
            .map(|proxy| -> Arc<dyn Proxy> {
                let cloned: Arc<StubProxy> = Arc::clone(proxy);
                cloned
            })
            .collect();
        new_health_check(proxies, "http://health.example/", timeout_ms, 0, false, IntRanges::default())
    }

    #[tokio::test(start_paused = true)]
    async fn completed_probes_retire_their_timeout_task_immediately() {
        let baseline = Handle::current().metrics().num_alive_tasks();
        let proxies: Vec<Arc<StubProxy>> =
            (0..397).map(|i| StubProxy::new(&format!("stub-{i}"), ProbeMode::Fast)).collect();
        let hc = health_check(&proxies, 30_000);

        hc.check().await;

        assert_eq!(
            Handle::current().metrics().num_alive_tasks(),
            baseline,
            "a completed probe must not leave a timeout task sleeping until the deadline"
        );
        for (i, proxy) in proxies.iter().enumerate() {
            assert_eq!(proxy.completed.load(Ordering::SeqCst), 1, "probe {i} did not run to completion");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_probe_is_cancelled_at_the_deadline_and_still_completes() {
        let proxy = StubProxy::new("stalled", ProbeMode::Stall);
        let hc = health_check(std::slice::from_ref(&proxy), 30_000);
        let started = tokio::time::Instant::now();

        hc.check().await;

        assert_eq!(
            proxy.completed.load(Ordering::SeqCst),
            1,
            "the timeout must cancel the probe and await its completion so history publication still runs"
        );
        assert!(
            started.elapsed() >= Duration::from_secs(30),
            "the probe should be cancelled by the configured timeout, not earlier"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn close_cancels_outstanding_probes_before_the_deadline() {
        let proxy = StubProxy::new("stalled", ProbeMode::Stall);
        let hc = health_check(std::slice::from_ref(&proxy), 30_000);
        let checking = {
            let hc = Arc::clone(&hc);
            tokio::spawn(async move { hc.check().await })
        };
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let started = tokio::time::Instant::now();

        hc.close();
        checking.await.unwrap();

        assert_eq!(proxy.completed.load(Ordering::SeqCst), 1, "provider close must complete the in-flight probe");
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "provider close must terminate the probe instead of waiting for the timeout"
        );
    }

    async fn accept_head(listener: TcpListener) -> TcpStream {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let read = stream.read(&mut request).await.unwrap();
        assert!(read > 0, "the probe must send a HEAD request before the responder replies");
        stream
    }

    #[tokio::test]
    async fn a_real_probe_publishes_its_delay_and_retires_the_timeout_task() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut stream = accept_head(listener).await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });

        let proxy = AdapterProxy::new(new_direct());
        let url = format!("http://{addr}/health");
        let expected = new_unsigned_ranges::<u16>("200").unwrap();
        let proxy_arc: Arc<AdapterProxy> = Arc::clone(&proxy);
        let proxy_dyn: Arc<dyn Proxy> = proxy_arc;
        let hc = new_health_check(vec![proxy_dyn], &url, 5000, 0, false, expected);

        hc.check().await;

        assert!(proxy.alive_for_test_url(&url), "a 200 response must publish an alive state");
        assert_ne!(proxy.last_delay_for_test_url(&url), 0, "a successful probe must publish a measured delay");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn a_real_stalled_probe_is_cancelled_at_the_deadline_and_publishes_an_unhealthy_state() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let _stream = accept_head(listener).await;
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let proxy = AdapterProxy::new(new_direct());
        let url = format!("http://{addr}/health");
        let expected = new_unsigned_ranges::<u16>("200").unwrap();
        let proxy_arc: Arc<AdapterProxy> = Arc::clone(&proxy);
        let proxy_dyn: Arc<dyn Proxy> = proxy_arc;
        let hc = new_health_check(vec![proxy_dyn], &url, 200, 0, false, expected);
        let started = Instant::now();

        hc.check().await;

        assert!(
            !proxy.alive_for_test_url(&url),
            "the timed-out probe must publish an unhealthy state instead of leaving the previous one"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "the probe must be cancelled by the configured timeout, not earlier"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the probe must finish shortly after its own timeout, without waiting for the client timeout"
        );
        responder.abort();
        let _ = responder.await;
    }
}
