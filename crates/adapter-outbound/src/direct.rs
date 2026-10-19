use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use murmur_component::dialer::dialer::{dial_context, new_dialer};
use murmur_component::dialer::options::with_resolver;
use murmur_component::resolver::resolver::direct_host_resolver;
use murmur_component_loopback::detector::{Detector, DetectorExt};
use murmur_constant::adapters::AdapterType;
use murmur_constant::adapters::{
    Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::util::resolve_ip_with_resolver;

/// `self_weak` upgrades to the `Arc<Direct>` the `d` receiver already is.
///
/// It is needed only by `new_packet_conn` (which retains the adapter for `resolve_udp`);
/// populated by each constructor via `Arc::new_cyclic` — DEVIATION, see the wave report.
pub struct Direct {
    base: Base,
    loop_back: Option<Arc<Detector>>,
    self_weak: Weak<Self>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DirectOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
}

impl core::fmt::Debug for DirectOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `basic_option` has no `Debug`.
        f.debug_struct("DirectOption").field("name", &self.name).finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Direct {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Direct")
            .field("name", &self.base.name)
            .field("loop_back", &self.loop_back)
            .finish_non_exhaustive()
    }
}

impl Direct {
    #[must_use]
    pub fn new(option: DirectOption) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            base: Base::new(BaseOption {
                name: option.name,
                type_: AdapterType::DIRECT,
                provider_name: option.basic_option.provider_name.clone(),
                udp: true,
                tfo: option.basic_option.tfo,
                mptcp: option.basic_option.mptcp,
                interface: option.basic_option.interface.clone(),
                routing_mark: option.basic_option.routing_mark,
                prefer: option.basic_option.ip_version,
                addr: String::new(),
                xudp: false,
            }),
            loop_back: Detector::new_detector(),
            self_weak: Weak::clone(weak),
        })
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("Direct adapter dropped while still in use"))
    }

    async fn resolve_udp_impl(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        let direct_resolver = direct_host_resolver();
        let default_resolver = murmur_component::resolver::resolver::default_resolver();
        let resolvers_differ = match (&direct_resolver, &default_resolver) {
            (None, None) => false,
            (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
            _ => true,
        };
        if (!metadata.resolved() || resolvers_differ) && !metadata.host.is_empty() {
            let ip = resolve_ip_with_resolver(ctx, &metadata.host, self.base.prefer, direct_resolver.as_deref())
                .await
                .map_err(|err| anyhow!("can't resolve ip: {err}"))?;
            metadata.dst_ip = Some(ip);
        }
        Ok(())
    }
}

#[async_trait]
impl CProxyAdapter for Direct {
    fn name(&self) -> String {
        self.base.name()
    }

    fn type_(&self) -> AdapterType {
        self.base.type_()
    }

    fn addr(&self) -> String {
        self.base.addr()
    }

    fn support_udp(&self) -> bool {
        self.base.support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        self.base.proxy_info()
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        self.loop_back.check_conn(metadata)?;
        let mut opts = self.base.dial_options();
        opts.push(with_resolver(direct_host_resolver()));
        let c = dial_context(ctx, "tcp", &metadata.remote_address(), opts).await?;
        let conn = new_conn(c, self);
        Ok(self.loop_back.new_conn(conn))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.loop_back.check_packet_conn(metadata).await?;
        self.resolve_udp_impl(ctx, metadata).await?;
        let addr_port = metadata.addr_port();
        let pc = new_dialer(self.base.dial_options()).listen_packet(ctx, "udp", "", addr_port).await?;
        let packet_conn = new_packet_conn(Arc::from(pc), self.self_arc()?);
        Ok(self.loop_back.new_packet_conn(packet_conn))
    }

    fn support_uot(&self) -> bool {
        self.base.support_uot()
    }

    fn is_l3_protocol(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        self.base.close()
    }
}

#[async_trait]
impl ProxyAdapter for Direct {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.resolve_udp_impl(ctx, metadata).await
    }
}

#[must_use]
pub fn new_direct() -> Arc<Direct> {
    Arc::new_cyclic(|weak| Direct {
        base: Base::new(BaseOption {
            name: "DIRECT".to_owned(),
            type_: AdapterType::DIRECT,
            udp: true,
            prefer: murmur_constant::dns::DNSPrefer::DUAL_STACK,
            addr: String::new(),
            provider_name: String::new(),
            xudp: false,
            tfo: false,
            mptcp: false,
            interface: String::new(),
            routing_mark: 0,
        }),
        loop_back: Detector::new_detector(),
        self_weak: Weak::clone(weak),
    })
}

#[must_use]
pub fn new_compatible() -> Arc<Direct> {
    Arc::new_cyclic(|weak| Direct {
        base: Base::new(BaseOption {
            name: "COMPATIBLE".to_owned(),
            type_: AdapterType::COMPATIBLE,
            udp: true,
            prefer: murmur_constant::dns::DNSPrefer::DUAL_STACK,
            addr: String::new(),
            provider_name: String::new(),
            xudp: false,
            tfo: false,
            mptcp: false,
            interface: String::new(),
            routing_mark: 0,
        }),
        loop_back: Detector::new_detector(),
        self_weak: Weak::clone(weak),
    })
}

#[cfg(test)]
mod dial_close_bridge_tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{CProxyAdapter, Direct, DirectOption};
    use crate::base::BasicOption;
    use murmur_common_net::io::Stream as NetStream;
    use murmur_constant::metadata::{Metadata, NetWork, Type};

    /// Proves that closing the outbound adapter's conn the way production actually does -
    /// `shutdown_read`/`shutdown_write` on the `Box<dyn Conn>`, the same pair
    /// `tunnel::statistic::tracker::TcpTracker::close` calls - reached through `new_conn`'s
    /// `deadline::conn::Conn` wrapper around the `StreamAsOldConn`/`TfoConn` bridge introduced by
    /// the `Stream` migration, still closes the real socket: the accepting peer must observe EOF,
    /// not a connection left dangling behind the bridge. `TfoConn::shutdown_write` (not `close`,
    /// which `Stream` has none of) now itself cancels a pending dial and forwards to the dialed
    /// socket, so `tfo=true` reaches the peer exactly like `tfo=false`.
    async fn dial_and_close_reaches_peer_eof(tfo: bool) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "peer must see the dialer's write before close");
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.unwrap();
        });

        let direct = Direct::new(DirectOption {
            basic_option: BasicOption { tfo, ..Default::default() },
            name: "direct-close-test".to_owned(),
        });
        let mut metadata = Metadata {
            network: NetWork::TCP,
            type_: Type::INNER,
            dst_ip: Some(addr.ip()),
            dst_port: addr.port(),
            ..Default::default()
        };
        let ctx = tokio_util::sync::CancellationToken::new();
        let mut conn = direct.dial_context(&ctx, &mut metadata).await.unwrap();
        conn.write_all(b"ping").await.unwrap();
        NetStream::shutdown_read(conn.as_ref()).unwrap();
        NetStream::shutdown_write(conn.as_ref()).unwrap();

        tokio::time::timeout(Duration::from_secs(5), accept)
            .await
            .expect("peer must observe EOF within the timeout")
            .unwrap();
    }

    #[tokio::test]
    async fn plain_tcp_dial_close_reaches_peer_eof() {
        dial_and_close_reaches_peer_eof(false).await;
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn tfo_dial_close_reaches_peer_eof() {
        dial_and_close_reaches_peer_eof(true).await;
    }

    /// Regression for `agent://ReviewNetS3`'s P1 finding: `TfoConn::shutdown_write` used to set
    /// `closed` and cancel, identical to a full close, so `StreamAsOldConn::close_write` (which
    /// forwards to it, `TfoConn` having no `old_conn`) turned `relay_inner`'s post-send
    /// `close_write` into a full close. The client then failed every later read of the peer's
    /// reply with `BrokenPipe` instead of seeing it. Once dialed, the close-write reaches the
    /// dialed connection's own half-close and never touches `closed`; this proves the same holds
    /// here for both `tfo=false` and `tfo=true`.
    async fn half_close_lets_the_reply_through(tfo: bool) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
        });

        let direct = Direct::new(DirectOption {
            basic_option: BasicOption { tfo, ..Default::default() },
            name: "direct-half-close-test".to_owned(),
        });
        let mut metadata = Metadata {
            network: NetWork::TCP,
            type_: Type::INNER,
            dst_ip: Some(addr.ip()),
            dst_port: addr.port(),
            ..Default::default()
        };
        let ctx = tokio_util::sync::CancellationToken::new();
        let mut conn = direct.dial_context(&ctx, &mut metadata).await.unwrap();
        conn.write_all(b"ping").await.unwrap();
        NetStream::shutdown_write(conn.as_ref()).unwrap();

        let mut reply = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut reply))
            .await
            .expect("read after close_write must not hang")
            .expect("read after close_write must not fail");
        assert_eq!(&reply[..n], b"pong", "half-close must not poison the read direction");

        tokio::time::timeout(Duration::from_secs(5), accept).await.expect("peer task must finish").unwrap();
    }

    #[tokio::test]
    async fn plain_tcp_half_close_lets_the_reply_through() {
        half_close_lets_the_reply_through(false).await;
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn tfo_half_close_lets_the_reply_through() {
        half_close_lets_the_reply_through(true).await;
    }

    /// `close_read` must not poison the write direction either: it now only forwards to the
    /// dialed conn once dialed, leaving `closed` alone.
    async fn close_read_then_write_still_writes(tfo: bool) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut collected = Vec::new();
            let mut buf = [0u8; 16];
            while !collected.ends_with(b"ping") {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0, "peer closed before sending ping");
                collected.extend_from_slice(&buf[..n]);
            }
        });

        let direct = Direct::new(DirectOption {
            basic_option: BasicOption { tfo, ..Default::default() },
            name: "direct-close-read-test".to_owned(),
        });
        let mut metadata = Metadata {
            network: NetWork::TCP,
            type_: Type::INNER,
            dst_ip: Some(addr.ip()),
            dst_port: addr.port(),
            ..Default::default()
        };
        let ctx = tokio_util::sync::CancellationToken::new();
        let mut conn = direct.dial_context(&ctx, &mut metadata).await.unwrap();
        if tfo {
            // TFO carries the first write as early data, so dial the conn before closing read.
            conn.write_all(b"warm").await.unwrap();
            conn.flush().await.unwrap();
        }
        NetStream::shutdown_read(conn.as_ref()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), conn.write_all(b"ping"))
            .await
            .expect("write after close_read must not hang")
            .expect("write after close_read must still succeed");

        tokio::time::timeout(Duration::from_secs(5), accept).await.expect("peer task must finish").unwrap();
    }

    #[tokio::test]
    async fn plain_tcp_close_read_then_write_still_writes() {
        close_read_then_write_still_writes(false).await;
    }

    #[tokio::test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn tfo_close_read_then_write_still_writes() {
        close_read_then_write_still_writes(true).await;
    }

    /// Regression for `agent://ReviewS10U2`'s P2 finding: `TcpTracker::close` (via `Stream::old_conn`
    /// then `Conn::close`, exactly what `common_net::io::close_stream` does) used to reach only
    /// `shutdown_read`/`shutdown_write` for a DIRECT conn (no real `old_conn`), which is a clean
    /// half-close: a parked read observes `Ok(0)` (EOF), not an error, so a relay treats the kill
    /// as an ordinary half-close and keeps waiting on the other side forever. A full close makes a
    /// parked `Read` fail instead. Fails on `9d22fa74` (the read below returns `Ok(0)`,
    /// never an error); passes once `ConnWrapper`'s close-only `old_conn` fallback arms its
    /// `CancellableStream` deadlines on `close`.
    #[tokio::test]
    async fn killing_a_parked_read_errors_instead_of_eof() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream
        });

        let direct = Direct::new(DirectOption { name: "direct-kill-test".to_owned(), ..Default::default() });
        let mut metadata = Metadata {
            network: NetWork::TCP,
            type_: Type::INNER,
            dst_ip: Some(addr.ip()),
            dst_port: addr.port(),
            ..Default::default()
        };
        let ctx = tokio_util::sync::CancellationToken::new();
        let conn = direct.dial_context(&ctx, &mut metadata).await.unwrap();
        let _peer = tokio::time::timeout(Duration::from_secs(5), accept).await.unwrap().unwrap();

        // Mirrors `TcpTrackerInner.conn: parking_lot::Mutex<Box<dyn ConstantConn>>`: locked only
        // for the span of a single poll, not across the whole read, so a concurrent
        // `close_stream` call never deadlocks behind a parked read.
        let conn = std::sync::Arc::new(parking_lot::Mutex::new(conn));
        let read_conn = std::sync::Arc::clone(&conn);
        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            std::future::poll_fn(|cx| {
                let mut guard = read_conn.lock();
                let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
                match std::pin::Pin::new(&mut **guard).poll_read(cx, &mut read_buf) {
                    std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(read_buf.filled().len())),
                    std::task::Poll::Ready(Err(err)) => std::task::Poll::Ready(Err(err)),
                    std::task::Poll::Pending => std::task::Poll::Pending,
                }
            })
            .await
        });

        // Give the read a moment to actually park before killing the conn.
        tokio::time::sleep(Duration::from_millis(20)).await;
        murmur_common_net::io::close_stream(&**conn.lock()).unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), read_task)
            .await
            .expect("killed conn must wake the parked read within the timeout")
            .unwrap();
        assert!(result.is_err(), "killing the conn must fail the parked read with an error, not Ok(0)/EOF");
    }
}
