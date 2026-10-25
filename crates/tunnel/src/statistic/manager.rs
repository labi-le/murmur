use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use murmur_common::atomic::type_::{new_int64, Int64};
use murmur_common::xsync::map::Map;
use murmur_component_memory::memory::get_memory_info;

use super::tracker::{Tracker, TrackerInfo};

/// The process-wide [`Manager`], whose ticker starts on first use.
pub static DEFAULT_MANAGER: LazyLock<Arc<Manager>> = LazyLock::new(|| {
    let manager = Arc::new(Manager {
        connections: Map::default(),
        upload_temp: new_int64(0),
        download_temp: new_int64(0),
        upload_blip: new_int64(0),
        download_blip: new_int64(0),
        upload_total: new_int64(0),
        download_total: new_int64(0),
        pid: std::process::id().cast_signed(),
        memory: AtomicU64::new(0),
    });

    let handle = Arc::clone(&manager);
    tokio::spawn(handle.handle());
    manager
});

pub struct Manager {
    connections: Map<String, Arc<dyn Tracker>>,
    upload_temp: Int64,
    download_temp: Int64,
    upload_blip: Int64,
    download_blip: Int64,
    upload_total: Int64,
    download_total: Int64,
    pid: i32,
    memory: AtomicU64,
}

impl Manager {
    pub fn join(&self, c: Arc<dyn Tracker>) {
        self.connections.store(c.id(), c);
    }

    pub fn leave(&self, c: &dyn Tracker) {
        self.connections.delete(c.id());
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Tracker>> {
        self.connections.load(&id.to_owned())
    }

    pub fn range(&self, f: impl FnMut(&Arc<dyn Tracker>) -> bool) {
        let mut f = f;
        self.connections.range(|_key, value| f(value));
    }

    pub fn push_uploaded(&self, size: i64) {
        self.upload_temp.add(size);
        self.upload_total.add(size);
    }

    pub fn push_downloaded(&self, size: i64) {
        self.download_temp.add(size);
        self.download_total.add(size);
    }

    pub fn now(&self) -> (i64, i64) {
        (self.upload_blip.load(), self.download_blip.load())
    }

    pub fn total(&self) -> (i64, i64) {
        (self.upload_total.load(), self.download_total.load())
    }

    /// The sampled RSS, refreshed from `/proc` first; reading `/proc` is async in this crate.
    // cancel-safe: a cancelled refresh keeps the previously sampled value.
    pub async fn memory(&self) -> u64 {
        self.update_memory().await;
        self.memory.load(Ordering::SeqCst)
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut connections = Vec::new();
        self.range(|c| {
            connections.push(c.info());
            true
        });
        Snapshot {
            download_total: self.download_total.load(),
            upload_total: self.upload_total.load(),
            connections,
            memory: self.memory.load(Ordering::SeqCst),
        }
    }

    /// Refreshes the sampled RSS, ignoring a failed read.
    // cancel-safe: a cancelled `/proc` read leaves the previous value in place.
    async fn update_memory(&self) {
        let Ok(stat) = get_memory_info(self.pid).await else {
            return;
        };
        self.memory.store(stat.rss, Ordering::SeqCst);
    }

    pub fn reset_statistic(&self) {
        self.upload_temp.store(0);
        self.upload_blip.store(0);
        self.upload_total.store(0);
        self.download_temp.store(0);
        self.download_blip.store(0);
        self.download_total.store(0);
    }

    // NOT cancel-safe: a cancel between the two blip swaps loses one window.
    pub async fn handle(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        // A tokio interval ticks immediately; the ticker waits a second for its first tick.
        ticker.tick().await;

        loop {
            ticker.tick().await;
            self.upload_blip.store(self.upload_temp.swap(0));
            self.download_blip.store(self.download_temp.swap(0));
        }
    }
}

impl fmt::Debug for Manager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manager").field("pid", &self.pid).finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(rename = "downloadTotal")]
    pub download_total: i64,
    #[serde(rename = "uploadTotal")]
    pub upload_total: i64,
    #[serde(rename = "connections", with = "super::tracker::tracker_infos_json")]
    pub connections: Vec<Arc<TrackerInfo>>,
    #[serde(rename = "memory")]
    pub memory: u64,
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    use super::*;
    use crate::statistic::tracker::TcpTracker;
    use murmur_constant::adapters::{Chain, Connection, ProxyAdapter};
    use murmur_constant::metadata::Metadata;
    use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

    /// No conn mock exists, so the tracker runs over a duplex pair.
    struct FakeConn(DuplexStream);

    impl AsyncRead for FakeConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for FakeConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl murmur_common_net::io::Stream for FakeConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }

        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 443))
        }
    }

    impl murmur_common_net::io::ExtendedStream for FakeConn {}

    impl Connection for FakeConn {
        fn chains(&self) -> Chain {
            Chain(vec!["direct".to_owned()])
        }

        fn provider_chains(&self) -> Chain {
            Chain(vec!["provider".to_owned()])
        }

        fn append_to_chains(&self, _adapter: Arc<dyn ProxyAdapter>) {}

        fn remote_destination(&self) -> String {
            "example.com:443".to_owned()
        }
    }

    struct FakeRule;

    impl Rule for FakeRule {
        fn rule_type(&self) -> RuleType {
            RuleType::DOMAIN_SUFFIX
        }

        fn match_(&self, _metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
            (true, Cow::Borrowed(""))
        }

        fn adapter(&self) -> String {
            "DIRECT".to_owned()
        }

        fn payload(&self) -> String {
            "example.com".to_owned()
        }

        fn provider_names(&self) -> Vec<String> {
            Vec::new()
        }
    }

    fn test_manager() -> Arc<Manager> {
        Arc::new(Manager {
            connections: Map::default(),
            upload_temp: new_int64(0),
            download_temp: new_int64(0),
            upload_blip: new_int64(0),
            download_blip: new_int64(0),
            upload_total: new_int64(0),
            download_total: new_int64(0),
            pid: std::process::id() as i32,
            memory: AtomicU64::new(0),
        })
    }

    fn tracked_conn(
        manager: &Arc<Manager>,
        rule: Option<Arc<dyn Rule>>,
        upload_total: i64,
    ) -> (DuplexStream, TcpTracker, Metadata) {
        let (client, server) = tokio::io::duplex(64);
        let mut metadata = Metadata::default();
        let tracker = TcpTracker::new(Box::new(FakeConn(server)), manager, &mut metadata, rule, upload_total, 0, true);
        (client, tracker, metadata)
    }

    /// Companion to `tracker_close_shuts_down_a_layered_tcp_stream` below: a non-socket
    /// `Stream` that does not override `shutdown_read`/`shutdown_write` (`FakeConn`, backed by a
    /// `tokio::io::duplex` pipe — same shape as a `TLS`/mux conn whose inner transport has no
    /// real OS socket to shut down) leaves `Stream`'s no-op defaults in effect, so
    /// `Tracker::close` cannot release it that way. This is not a regression: the pre-migration
    /// `impl Conn for FakeConn` had the identical explicit no-op `close()`. The peer must NOT see
    /// EOF; it must time out.
    #[tokio::test]
    async fn tracker_close_does_not_unblock_a_duplex_backed_conn_with_default_shutdown() {
        let manager = test_manager();
        let (mut client, tracker, _metadata) = tracked_conn(&manager, None, 0);

        murmur_common_net::io::close_stream(&tracker).expect("tracker close succeeds");

        let mut buf = [0u8; 1];
        let result = tokio::time::timeout(Duration::from_millis(200), client.read(&mut buf)).await;
        assert!(
            result.is_err(),
            "a duplex-backed conn whose Stream impl does not override shutdown_read/shutdown_write \
             must not unblock the peer on Tracker::close (Stream::shutdown_* defaults to a no-op, \
             matching the old Conn::close() no-op this FakeConn always had)"
        );
    }

    /// `Tracker::close` now calls `shutdown_read`/`shutdown_write` instead of the old `close()`;
    /// proves that still actually releases the OS socket through a layered conn (`CancellableStream`
    /// wrapping a real `TcpStream`, not the bare `TcpStream` itself — the layering is what a real
    /// TLS/mux conn's `Stream` impl forwards through) by observing the peer see EOF.
    #[tokio::test]
    async fn tracker_close_shuts_down_a_layered_tcp_stream() {
        use murmur_common_net::io::{CancellableStream, ExtendedStream, Stream as NetStream};

        struct LayeredTcp(CancellableStream<tokio::net::TcpStream>);

        impl AsyncRead for LayeredTcp {
            fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for LayeredTcp {
            fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_flush(cx)
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
            }
        }

        impl NetStream for LayeredTcp {
            fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
                self.0.local_addr()
            }

            fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
                self.0.peer_addr()
            }

            fn shutdown_read(&self) -> io::Result<()> {
                self.0.shutdown_read()
            }

            fn shutdown_write(&self) -> io::Result<()> {
                self.0.shutdown_write()
            }
        }

        impl ExtendedStream for LayeredTcp {}

        impl Connection for LayeredTcp {
            fn chains(&self) -> Chain {
                Chain::default()
            }

            fn provider_chains(&self) -> Chain {
                Chain::default()
            }

            fn append_to_chains(&self, _adapter: Arc<dyn ProxyAdapter>) {}

            fn remote_destination(&self) -> String {
                String::new()
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_task = tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let mut client = client_task.await.unwrap();

        let manager = test_manager();
        let mut metadata = Metadata::default();
        let tracker = TcpTracker::new(
            Box::new(LayeredTcp(CancellableStream::new(server))),
            &manager,
            &mut metadata,
            None,
            0,
            0,
            false,
        );

        murmur_common_net::io::close_stream(&tracker).expect("tracker close succeeds");

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("peer read did not time out")
            .expect("peer read does not error");
        assert_eq!(n, 0, "peer must see EOF once the layered conn's socket half-closes");
    }

    /// The production shape a `StreamAsOldConn`-wrapped conn actually takes
    /// (the shadowsocks outbound's `udp_over_tcp` path: a new-`Stream` dial result gets
    /// bridged back to the old `Conn` for a not-yet-migrated caller, then wrapped forward to
    /// `Stream` again so it can sit in a `TcpTracker`). `FakeConn` never overrides
    /// `shutdown_read`/`shutdown_write`, and `StreamAsOldConn::old_conn` only forwards past itself
    /// when its own wrapped `Stream` answers `Some` (`Stream::old_conn`'s default is `None`), so
    /// the round trip bottoms out on the same no-op `Stream::shutdown_*` defaults as
    /// `tracker_close_does_not_unblock_a_duplex_backed_conn_with_default_shutdown` above: that
    /// test's pinned behaviour still holds after the `StreamAsOldConn` bridge became real.
    #[tokio::test]
    async fn tracker_close_through_stream_as_old_conn_bridge_does_not_unblock_a_duplex_backed_conn() {
        use murmur_common_net::io::{OldConnAsStream, StreamAsOldConn};

        struct BridgedFakeConn(OldConnAsStream<StreamAsOldConn<FakeConn>>);

        impl AsyncRead for BridgedFakeConn {
            fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for BridgedFakeConn {
            fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_flush(cx)
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
            }
        }

        impl murmur_common_net::io::Stream for BridgedFakeConn {
            fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
                self.0.local_addr()
            }

            fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
                self.0.peer_addr()
            }

            fn shutdown_read(&self) -> io::Result<()> {
                self.0.shutdown_read()
            }

            fn shutdown_write(&self) -> io::Result<()> {
                self.0.shutdown_write()
            }
        }

        impl murmur_common_net::io::ExtendedStream for BridgedFakeConn {}

        impl Connection for BridgedFakeConn {
            fn chains(&self) -> Chain {
                Chain::default()
            }

            fn provider_chains(&self) -> Chain {
                Chain::default()
            }

            fn append_to_chains(&self, _adapter: Arc<dyn ProxyAdapter>) {}

            fn remote_destination(&self) -> String {
                String::new()
            }
        }

        let (mut client, server) = tokio::io::duplex(64);
        let bridged = BridgedFakeConn(OldConnAsStream(StreamAsOldConn::new(FakeConn(server))));

        let manager = test_manager();
        let mut metadata = Metadata::default();
        let tracker = TcpTracker::new(Box::new(bridged), &manager, &mut metadata, None, 0, 0, false);

        murmur_common_net::io::close_stream(&tracker).expect("tracker close succeeds");

        let mut buf = [0u8; 1];
        let result = tokio::time::timeout(Duration::from_millis(200), client.read(&mut buf)).await;
        assert!(
            result.is_err(),
            "a duplex-backed conn bridged through StreamAsOldConn must not unblock the peer on \
             Tracker::close: StreamAsOldConn::close only reaches a real inner close through \
             Stream::old_conn, which stays None for a Stream that was never itself an old Conn"
        );
    }

    /// The regression this migration introduced: a wrapped conn whose real teardown lives
    /// solely in the legacy compat `Conn::close()` (the shape the outbound base adapter's
    /// `new_conn` produces — `OldConnAsStream(ConnWrapper(..))` — and every protocol conn that
    /// never overrides `Stream::shutdown_read`/`shutdown_write`, e.g. the vmess sing client)
    /// must still be released by `Tracker::close`, reached through `Stream::old_conn`.
    #[tokio::test]
    async fn tracker_close_reaches_a_conn_whose_teardown_lives_only_in_old_conn_close() {
        use murmur_common_net::io::OldConnAsStream;
        use murmur_std_compat::net::{Addr, Conn as NetConn, ExtendedConn as NetExtendedConn, TcpAddr};

        struct RealCloseOnlyConn(parking_lot::Mutex<Option<DuplexStream>>);

        impl AsyncRead for RealCloseOnlyConn {
            fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                let mut guard = self.get_mut().0.lock();
                match guard.as_mut() {
                    Some(inner) => Pin::new(inner).poll_read(cx, buf),
                    None => Poll::Ready(Ok(())),
                }
            }
        }

        impl AsyncWrite for RealCloseOnlyConn {
            fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
                let mut guard = self.get_mut().0.lock();
                match guard.as_mut() {
                    Some(inner) => Pin::new(inner).poll_write(cx, buf),
                    None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                }
            }
            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                let mut guard = self.get_mut().0.lock();
                match guard.as_mut() {
                    Some(inner) => Pin::new(inner).poll_flush(cx),
                    None => Poll::Ready(Ok(())),
                }
            }
            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                let mut guard = self.get_mut().0.lock();
                match guard.as_mut() {
                    Some(inner) => Pin::new(inner).poll_shutdown(cx),
                    None => Poll::Ready(Ok(())),
                }
            }
        }

        impl NetConn for RealCloseOnlyConn {
            fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
                Ok(Box::new(TcpAddr::from(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))))
            }

            fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
                Ok(Box::new(TcpAddr::from(std::net::SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 443))))
            }

            fn close(&self) -> io::Result<()> {
                *self.0.lock() = None;
                Ok(())
            }
        }

        impl NetExtendedConn for RealCloseOnlyConn {}

        impl Connection for RealCloseOnlyConn {
            fn chains(&self) -> Chain {
                Chain::default()
            }

            fn provider_chains(&self) -> Chain {
                Chain::default()
            }

            fn append_to_chains(&self, _adapter: Arc<dyn ProxyAdapter>) {}

            fn remote_destination(&self) -> String {
                String::new()
            }
        }

        let (mut client, server) = tokio::io::duplex(64);
        let conn = OldConnAsStream(RealCloseOnlyConn(parking_lot::Mutex::new(Some(server))));

        let manager = test_manager();
        let mut metadata = Metadata::default();
        let tracker = TcpTracker::new(Box::new(conn), &manager, &mut metadata, None, 0, 0, false);

        murmur_common_net::io::close_stream(&tracker).expect("tracker close succeeds");

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("peer read did not time out")
            .expect("peer read does not error");
        assert_eq!(
            n, 0,
            "peer must see EOF when Tracker::close reaches the wrapped conn's real teardown \
             through Stream::old_conn, not just Stream::shutdown_read/shutdown_write no-op defaults"
        );
    }

    /// `dns_dialer.rs::dial_context`'s TCP branch now wraps a `TcpTracker` in `StreamAsOldConn`
    /// to satisfy its still-old `Box<dyn Conn>` return type (`TcpTracker` no longer implements
    /// `Conn` itself). This does not compile against a `TcpTracker` that lacks the close-only
    /// view's `Stream::old_conn` target, so it pins that wiring: closing through the wrapper must
    /// still reach `Tracker::close` and deregister from the manager.
    #[tokio::test]
    async fn tracker_close_reaches_the_manager_through_the_stream_as_old_conn_boundary_bridge() {
        use murmur_common_net::io::StreamAsOldConn;

        let manager = test_manager();
        let (_client, tracker, _metadata) = tracked_conn(&manager, None, 0);
        let id = tracker.id();
        assert!(manager.get(&id).is_some());

        let bridged: Box<dyn murmur_std_compat::net::Conn> = Box::new(StreamAsOldConn::new(tracker));
        murmur_std_compat::net::Conn::close(&*bridged).expect("bridged close succeeds");

        assert!(manager.get(&id).is_none(), "close through the boundary bridge must deregister the tracker");
    }

    #[tokio::test]
    async fn manager_joins_and_leaves_trackers() {
        let manager = test_manager();
        let (_client, tracker, metadata) = tracked_conn(&manager, None, 0);

        assert_eq!("example.com:443", metadata.remote_dst);
        assert_eq!(Chain(vec!["direct".to_owned()]), tracker.chains());
        assert_eq!(Chain(vec!["provider".to_owned()]), tracker.provider_chains());

        let id = tracker.id();
        assert!(manager.get(&id).is_some());
        assert_eq!(1, manager.connections.size());

        let mut ids = Vec::new();
        manager.range(|c| {
            ids.push(c.id());
            true
        });
        assert_eq!(vec![id.clone()], ids);

        assert!(manager.get("missing").is_none());
        murmur_common_net::io::close_stream(&tracker).expect("the tracked close succeeds");
        assert!(manager.get(&id).is_none());
        assert_eq!(0, manager.connections.size());
    }

    #[tokio::test]
    async fn tcp_tracker_counts_both_directions() {
        let manager = test_manager();
        let (mut client, mut tracker, _metadata) = tracked_conn(&manager, None, 8);

        client.write_all(b"hello").await.expect("the peer write succeeds");
        let mut download = [0u8; 5];
        tracker.read_exact(&mut download).await.expect("the tracked read succeeds");
        assert_eq!(b"hello", &download);

        tracker.write_all(b"world!").await.expect("the tracked write succeeds");
        let mut upload = [0u8; 6];
        client.read_exact(&mut upload).await.expect("the peer read succeeds");
        assert_eq!(b"world!", &upload);

        let info = tracker.info();
        // 6 written plus the upload total the tracker was created with.
        assert_eq!(14, info.upload_total.load());
        assert_eq!(5, info.download_total.load());
        assert_eq!((14, 5), manager.total());

        let snapshot = manager.snapshot();
        assert_eq!(14, snapshot.upload_total);
        assert_eq!(5, snapshot.download_total);
        assert_eq!(1, snapshot.connections.len());

        manager.reset_statistic();
        assert_eq!((0, 0), manager.total());
        assert_eq!((0, 0), manager.now());
        // `reset_statistic` leaves the per-tracker counters alone.
        assert_eq!(14, tracker.info().upload_total.load());
    }

    #[tokio::test]
    async fn snapshot_json_keeps_the_wire_field_names() {
        let manager = test_manager();
        let (_client, tracker, _metadata) = tracked_conn(&manager, Some(Arc::new(FakeRule)), 0);

        let json = serde_json::to_value(manager.snapshot()).expect("the snapshot serializes");
        assert_eq!(0, json["uploadTotal"]);
        assert_eq!(0, json["downloadTotal"]);
        assert_eq!(0, json["memory"]);

        let connection = &json["connections"][0];
        assert_eq!(0, connection["upload"]);
        assert_eq!(0, connection["download"]);
        assert_eq!("DomainSuffix", connection["rule"]);
        assert_eq!("example.com", connection["rulePayload"]);
        assert_eq!(serde_json::json!(["direct"]), connection["chains"]);
        assert_eq!(serde_json::json!(["provider"]), connection["providerChains"]);
        assert_eq!("example.com:443", connection["metadata"]["remoteDestination"]);
        let id = connection["id"].as_str().expect("the id is a string");
        assert!(uuid::Uuid::parse_str(id).is_ok(), "the id is a UUID string");
        let start = connection["start"].as_str().expect("the start is a string");
        assert!(chrono::DateTime::parse_from_rfc3339(start).is_ok(), "the start is RFC 3339");

        assert_eq!("example.com:443", tracker.remote_destination());
    }

    /// The connections field stays `null` until a tracker registers, so an idle manager
    /// renders `null` there rather than `[]`.
    #[tokio::test]
    async fn an_empty_snapshot_renders_null_connections() {
        let manager = test_manager();
        let json = serde_json::to_value(manager.snapshot()).expect("the snapshot serializes");
        assert!(json["connections"].is_null(), "{json}");

        let parsed: Snapshot = serde_json::from_value(json).expect("the snapshot parses back");
        assert!(parsed.connections.is_empty());
    }

    /// Every connection's `metadata` object under `/connections` has exactly this key set.
    #[tokio::test]
    async fn connection_metadata_key_set_matches_the_wire_field_names() {
        let manager = test_manager();
        let (_client, _tracker, _metadata) = tracked_conn(&manager, None, 0);

        let json = serde_json::to_value(manager.snapshot()).expect("the snapshot serializes");
        let metadata = json["connections"][0]["metadata"].as_object().expect("metadata serializes to an object");

        let mut actual: Vec<&str> = metadata.keys().map(String::as_str).collect();
        actual.sort_unstable();
        let mut expected: Vec<&str> = vec![
            "network",
            "type",
            "sourceIP",
            "destinationIP",
            "sourceGeoIP",
            "destinationGeoIP",
            "sourceIPASN",
            "destinationIPASN",
            "sourcePort",
            "destinationPort",
            "inboundIP",
            "inboundPort",
            "inboundName",
            "inboundUser",
            "rematchName",
            "host",
            "dnsMode",
            "uid",
            "process",
            "processPath",
            "specialProxy",
            "specialRules",
            "remoteDestination",
            "dscp",
            "sniffHost",
        ];
        expected.sort_unstable();
        assert_eq!(actual, expected);

        assert!(metadata["sourcePort"].is_string(), "the port field renders as a string");
        assert!(metadata["destinationPort"].is_string());
        assert!(metadata["inboundPort"].is_string());
    }
}
