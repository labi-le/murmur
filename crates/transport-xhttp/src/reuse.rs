use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::client::TransportMaker;
use super::config::{Range, ReuseConfig, RoundTripper};

pub(crate) struct ReuseEntry {
    transport: Arc<dyn RoundTripper>,

    open_usage: AtomicI32,
    left_requests: AtomicI32,
    reuse_count: AtomicI32,
    max_reuse_times: i32,
    unreusable_at: Option<Instant>,

    closed: AtomicBool,
}

impl ReuseEntry {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn close(&self) {
        if self.closed.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return;
        }
        murmur_common_httputils::force_close::close_transport(self.transport.as_ref());
    }

    fn release(self: &Arc<Self>) {
        let remaining = self.open_usage.fetch_sub(1, Ordering::SeqCst) - 1;
        let remaining = if remaining < 0 {
            self.open_usage.store(0, Ordering::SeqCst);
            0
        } else {
            remaining
        };

        if remaining == 0 {
            let now = Instant::now();
            if self.left_requests.load(Ordering::SeqCst) <= 0
                || (self.max_reuse_times > 0 && self.reuse_count.load(Ordering::SeqCst) >= self.max_reuse_times)
                || self.unreusable_at.is_some_and(|at| now > at)
            {
                self.close();
            }
        }
    }
}

pub struct ReuseTransport {
    pub(crate) entry: Arc<ReuseEntry>,
    removed: AtomicBool,
}

impl std::fmt::Debug for ReuseTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReuseTransport")
            .field("open_usage", &self.entry.open_usage)
            .field("removed", &self.removed)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl RoundTripper for ReuseTransport {
    // cancel-safe: delegates to the inner transport's own `round_trip`/`read_datagram` and holds no state of its own, so it inherits that implementation's cancel safety.
    async fn round_trip(&self, req: super::config::Request) -> anyhow::Result<super::config::Response> {
        self.entry.transport.round_trip(req).await
    }

    async fn ensure_connected(&self, ctx: tokio_util::sync::CancellationToken) -> anyhow::Result<()> {
        self.entry.transport.ensure_connected(ctx).await
    }

    fn peer_addr(&self) -> Option<(Box<dyn murmur_std_compat::net::Addr>, Box<dyn murmur_std_compat::net::Addr>)> {
        self.entry.transport.peer_addr()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl murmur_common_httputils::force_close::RoundTripper for ReuseTransport {
    fn close_idle_connections(&self) {}

    fn close_http2_connections(&self) {}

    fn close(&self) {
        if self.removed.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return;
        }
        self.entry.release();
    }
}

pub struct ReuseManager {
    max_concurrency: i64,
    max_connections: i64,
    c_max_reuse_times: Range,
    h_max_request_times: Range,
    h_max_reusable_secs: Range,
    maker: TransportMaker,
    inner: Mutex<Vec<Arc<ReuseEntry>>>,
}

impl std::fmt::Debug for ReuseManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReuseManager")
            .field("max_concurrency", &self.max_concurrency)
            .field("max_connections", &self.max_connections)
            .field("c_max_reuse_times", &self.c_max_reuse_times)
            .field("h_max_request_times", &self.h_max_request_times)
            .field("h_max_reusable_secs", &self.h_max_reusable_secs)
            .finish_non_exhaustive()
    }
}

impl ReuseManager {
    pub fn new(cfg: Option<&ReuseConfig>, make_transport: TransportMaker) -> anyhow::Result<Option<Self>> {
        let Some(cfg) = cfg else {
            return Ok(None);
        };
        let (concurrency, connections) = ReuseConfig::resolve_manager_config(Some(cfg))?;
        let (c_max_reuse_times, h_max_request_times, h_max_reusable_secs) =
            ReuseConfig::resolve_entry_config(Some(cfg))?;
        Ok(Some(Self {
            max_concurrency: concurrency.rand(),
            max_connections: connections.rand(),
            c_max_reuse_times,
            h_max_request_times,
            h_max_reusable_secs,
            maker: make_transport,
            inner: Mutex::new(Vec::new()),
        }))
    }

    /// Closes the manager; the method tolerates a missing manager, so this takes `Option<&ReuseManager>` to
    /// match every call site.
    pub fn close(this: Option<&Self>) {
        let Some(this) = this else {
            return;
        };
        let mut entries = this.inner.lock();
        for entry in entries.iter() {
            entry.close();
        }
        entries.clear();
    }

    fn cleanup_locked(entries: &mut Vec<Arc<ReuseEntry>>, now: Instant) {
        entries.retain(|entry| {
            if entry.is_closed() {
                return false;
            }
            if entry.left_requests.load(Ordering::SeqCst) <= 0 && entry.open_usage.load(Ordering::SeqCst) == 0 {
                entry.close();
                return false;
            }
            if entry.unreusable_at.is_some_and(|at| now > at) && entry.open_usage.load(Ordering::SeqCst) == 0 {
                entry.close();
                return false;
            }
            true
        });
    }

    fn pick_locked(entries: &[Arc<ReuseEntry>], max_concurrency: i64) -> Option<Arc<ReuseEntry>> {
        let mut best: Option<&Arc<ReuseEntry>> = None;
        for entry in entries {
            if entry.is_closed() {
                continue;
            }
            if entry.left_requests.load(Ordering::SeqCst) <= 0 {
                continue;
            }
            if entry.max_reuse_times > 0 && entry.reuse_count.load(Ordering::SeqCst) >= entry.max_reuse_times {
                continue;
            }
            if max_concurrency > 0 && i64::from(entry.open_usage.load(Ordering::SeqCst)) >= max_concurrency {
                continue;
            }
            if best.is_none_or(|b| entry.open_usage.load(Ordering::SeqCst) < b.open_usage.load(Ordering::SeqCst)) {
                best = Some(entry);
            }
        }
        best.cloned()
    }

    const fn should_create_locked(entries: &[Arc<ReuseEntry>], max_connections: i64) -> bool {
        if entries.is_empty() {
            return true;
        }
        if max_connections > 0 {
            return (entries.len() as u64) < max_connections.cast_unsigned();
        }
        false
    }

    fn new_entry_locked(
        &self,
        entries: &mut Vec<Arc<ReuseEntry>>,
        transport: Arc<dyn RoundTripper>,
        now: Instant,
    ) -> Arc<ReuseEntry> {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the draw is stored in an i32, truncating a larger value"
        )]
        let left_requests =
            if self.h_max_request_times.max > 0 { self.h_max_request_times.rand() as i32 } else { (1i32 << 30) - 1 };
        let unreusable_at = if self.h_max_reusable_secs.max > 0 {
            Some(now + Duration::from_secs(self.h_max_reusable_secs.rand().max(0).cast_unsigned()))
        } else {
            None
        };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the draw is stored in an i32, truncating a larger value"
        )]
        let max_reuse_times = if self.c_max_reuse_times.max > 0 { self.c_max_reuse_times.rand() as i32 } else { 0 };

        let entry = Arc::new(ReuseEntry {
            transport,
            open_usage: AtomicI32::new(0),
            left_requests: AtomicI32::new(left_requests),
            reuse_count: AtomicI32::new(0),
            max_reuse_times,
            unreusable_at,
            closed: AtomicBool::new(false),
        });

        entries.push(Arc::clone(&entry));
        entry
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the guard must span the pick-then-create sequence, so the maker runs under the same lock"
    )]
    pub fn transport(&self) -> Arc<dyn RoundTripper> {
        let now = Instant::now();

        let mut entries = self.inner.lock();
        Self::cleanup_locked(&mut entries, now);

        let entry = if Self::should_create_locked(&entries, self.max_connections) {
            None
        } else {
            Self::pick_locked(&entries, self.max_concurrency)
        };
        let reused = entry.is_some();

        let entry = if let Some(entry) = entry {
            entry
        } else {
            let transport = (self.maker)();
            self.new_entry_locked(&mut entries, transport, now)
        };

        if reused {
            entry.reuse_count.fetch_add(1, Ordering::SeqCst);
        }

        entry.open_usage.fetch_add(1, Ordering::SeqCst);
        if entry.left_requests.load(Ordering::SeqCst) > 0 {
            entry.left_requests.fetch_sub(1, Ordering::SeqCst);
        }

        Arc::new(ReuseTransport { entry, removed: AtomicBool::new(false) })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicI64;

    use super::*;
    use crate::config::Response;

    struct TestRoundTripper {
        id: i64,
    }

    #[async_trait::async_trait]
    impl RoundTripper for TestRoundTripper {
        async fn round_trip(&self, _req: super::super::config::Request) -> anyhow::Result<Response> {
            panic!("not used in reuse manager unit tests");
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl murmur_common_httputils::force_close::RoundTripper for TestRoundTripper {}

    fn make_test_transport_factory(counter: Arc<AtomicI64>) -> TransportMaker {
        Arc::new(move || {
            let id = counter.fetch_add(1, Ordering::SeqCst) + 1;
            Arc::new(TestRoundTripper { id })
        })
    }

    fn transport_id(rt: &dyn RoundTripper) -> i64 {
        let reuse = rt.as_any().downcast_ref::<ReuseTransport>().expect("reuse transport");
        reuse.entry.transport.as_any().downcast_ref::<TestRoundTripper>().expect("test round tripper").id
    }

    #[test]
    fn test_manager_reuse_same_entry() {
        let created = Arc::new(AtomicI64::new(0));
        let manager = ReuseManager::new(
            Some(&ReuseConfig {
                max_concurrency: "1".to_owned(),
                max_connections: "1".to_owned(),
                h_max_request_times: "10".to_owned(),
                ..ReuseConfig::default()
            }),
            make_test_transport_factory(created),
        )
        .expect("valid config")
        .expect("manager for non-nil config");

        let transport1 = manager.transport();
        let id1 = transport_id(transport1.as_ref());
        transport1.close();

        let transport2 = manager.transport();
        let id2 = transport_id(transport2.as_ref());
        assert_eq!(id1, id2, "expected same transport to be reused, got {id1} and {id2}");

        transport2.close();
        ReuseManager::close(Some(&manager));
    }

    #[test]
    fn test_manager_respect_max_connections() {
        let created = Arc::new(AtomicI64::new(0));
        let manager = ReuseManager::new(
            Some(&ReuseConfig {
                max_concurrency: "2".to_owned(),
                max_connections: "2".to_owned(),
                h_max_request_times: "100".to_owned(),
                ..ReuseConfig::default()
            }),
            make_test_transport_factory(created),
        )
        .expect("valid config")
        .expect("manager for non-nil config");

        let transport1 = manager.transport();
        let id1 = transport_id(transport1.as_ref());
        let transport2 = manager.transport();
        let id2 = transport_id(transport2.as_ref());
        let transport3 = manager.transport();
        let id3 = transport_id(transport3.as_ref());
        let transport4 = manager.transport();
        let id4 = transport_id(transport4.as_ref());
        let transport5 = manager.transport();
        let id5 = transport_id(transport5.as_ref());

        assert_ne!(id1, id2, "expected the second transport to be new");
        assert!(id3 == id1 || id3 == id2, "expected the third transport to be reused");
        assert!(id4 == id1 || id4 == id2, "expected the fourth transport to be reused");
        assert!(id5 != id1 && id5 != id2, "expected the fifth transport to be new");

        transport1.close();
        transport2.close();
        transport3.close();
        transport4.close();
        transport5.close();
        ReuseManager::close(Some(&manager));
    }

    #[test]
    fn test_manager_rotate_on_request_limit() {
        let created = Arc::new(AtomicI64::new(0));
        let manager = ReuseManager::new(
            Some(&ReuseConfig {
                max_concurrency: "1".to_owned(),
                max_connections: "1".to_owned(),
                h_max_request_times: "1".to_owned(),
                ..ReuseConfig::default()
            }),
            make_test_transport_factory(created),
        )
        .expect("valid config")
        .expect("manager for non-nil config");

        let transport1 = manager.transport();
        let id1 = transport_id(transport1.as_ref());
        transport1.close();

        let transport2 = manager.transport();
        let id2 = transport_id(transport2.as_ref());
        assert_ne!(id1, id2, "expected new transport after request limit, got same id {id1}");

        transport2.close();
        ReuseManager::close(Some(&manager));
    }

    #[test]
    fn test_manager_rotate_on_reusable_secs() {
        let created = Arc::new(AtomicI64::new(0));
        let manager = ReuseManager::new(
            Some(&ReuseConfig {
                max_concurrency: "1".to_owned(),
                max_connections: "1".to_owned(),
                h_max_request_times: "100".to_owned(),
                h_max_reusable_secs: "1".to_owned(),
                ..ReuseConfig::default()
            }),
            make_test_transport_factory(created),
        )
        .expect("valid config")
        .expect("manager for non-nil config");

        let transport1 = manager.transport();
        let id1 = transport_id(transport1.as_ref());

        std::thread::sleep(Duration::from_millis(1100));
        transport1.close();

        let transport2 = manager.transport();
        let id2 = transport_id(transport2.as_ref());
        assert_ne!(id1, id2, "expected new transport after reusable timeout, got same id {id1}");

        transport2.close();
        ReuseManager::close(Some(&manager));
    }

    #[test]
    fn test_manager_rotate_on_conn_reuse_limit() {
        let created = Arc::new(AtomicI64::new(0));
        let manager = ReuseManager::new(
            Some(&ReuseConfig {
                max_concurrency: "1".to_owned(),
                max_connections: "1".to_owned(),
                c_max_reuse_times: "1".to_owned(),
                h_max_request_times: "100".to_owned(),
                ..ReuseConfig::default()
            }),
            make_test_transport_factory(created),
        )
        .expect("valid config")
        .expect("manager for non-nil config");

        let transport1 = manager.transport();
        let id1 = transport_id(transport1.as_ref());
        transport1.close();

        let transport2 = manager.transport();
        let id2 = transport_id(transport2.as_ref());
        assert_eq!(id1, id2, "expected first reuse to use same transport, got {id1} and {id2}");

        transport2.close();

        let transport3 = manager.transport();
        let id3 = transport_id(transport3.as_ref());
        assert_ne!(id3, id2, "expected new transport after c-max-reuse-times limit, got same id {id3}");

        transport3.close();
        ReuseManager::close(Some(&manager));
    }
}
