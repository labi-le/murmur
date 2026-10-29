//! A dialer that adapts a proxy adapter's shared packet conn to the `Dialer` trait.
//!
//! A proxy adapter's `listen_packet_context` returns a shared `Arc<dyn constant::adapters::PacketConn>`
//! (concrete adapters commonly need `&self` interior mutability shared across tasks), but the
//! `Dialer` trait's `listen_packet` returns an exclusively owned
//! `Box<dyn murmur_std_compat::net::PacketConn>`.
//! `ArcPacketConn` bridges the two by forwarding to the shared value from behind a `Box`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{Datagram, OldPacketConnAsDatagram, Stream};
use murmur_common_net::new_bind_packet_conn;
use murmur_constant::adapters::{Dialer, PacketConn as ConstantPacketConn, ProxyAdapter};
use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_std_compat::net::{Addr, PacketConn as NetPacketConn};
use murmur_tunnel::statistic::manager::DEFAULT_MANAGER;
use murmur_tunnel::statistic::tracker::{TcpTracker, UdpTracker};

struct ProxyDialer {
    proxy: Arc<dyn ProxyAdapter>,
    statistic: bool,
}

pub fn new(proxy: Arc<dyn ProxyAdapter>, statistic: bool) -> Arc<dyn Dialer> {
    Arc::new(ProxyDialer { proxy, statistic })
}

#[async_trait]
impl Dialer for ProxyDialer {
    // cancel-safe: the statistic trackers are registered only after the inner dial returns, and a
    // cancelled dial drops the connection the inner dial had just opened.
    async fn dial_context(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Stream>> {
        let mut current_meta = Metadata { type_: Type::INNER, ..Metadata::default() };
        current_meta.set_remote_address(address)?;

        if network.contains("udp") {
            let pc = self.listen_packet_(ctx, &mut current_meta).await?;
            if !current_meta.resolved() {
                if let Err(err) = pc.resolve_udp(ctx, &mut current_meta).await {
                    let _ = pc.close();
                    return Err(err);
                }
            }
            let Some(udp_addr) = current_meta.udp_addr() else {
                return Err(anyhow::anyhow!("udp metadata has no resolved address"));
            };
            let r_addr = murmur_common_net::io::socket_addr_from_udp_addr(&udp_addr);
            return Ok(new_bind_packet_conn(pc, r_addr));
        }

        let conn = self.proxy.dial_context(ctx, &mut current_meta).await?;
        let conn: Box<dyn Stream> = if self.statistic {
            Box::new(TcpTracker::new(conn, &DEFAULT_MANAGER, &mut current_meta, None, 0, 0, false))
        } else {
            conn
        };
        Ok(conn)
    }

    // cancel-safe: the statistic tracker is registered only after the inner listen returns, and a
    // cancelled listen drops the packet conn the inner listen had just bound.
    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        _address: &str,
        r_addr_port: Option<SocketAddr>,
    ) -> Result<Box<dyn Datagram>> {
        if !network.starts_with("udp") {
            return Err(anyhow::anyhow!("proxyDialer only support udp network, but got: {network}"));
        }
        let (dst_ip, dst_port) = match r_addr_port {
            Some(addr) => (Some(addr.ip()), addr.port()),
            None => (None, 0),
        };
        let mut current_meta = Metadata { type_: Type::INNER, dst_ip, dst_port, ..Metadata::default() };
        let pc = self.listen_packet_(ctx, &mut current_meta).await?;
        Ok(Box::new(OldPacketConnAsDatagram(ArcPacketConn(pc))))
    }
}

impl ProxyDialer {
    // cancel-safe: the tracker is registered only after the inner listen returns, so a dropped
    // call leaves no tracker to leak.
    async fn listen_packet_(
        &self,
        ctx: &CancellationToken,
        current_meta: &mut Metadata,
    ) -> Result<Arc<dyn ConstantPacketConn>> {
        current_meta.network = NetWork::UDP;
        let pc = self.proxy.listen_packet_context(ctx, current_meta).await?;
        let pc: Arc<dyn ConstantPacketConn> =
            if self.statistic { UdpTracker::new(pc, &DEFAULT_MANAGER, current_meta, None, 0, 0, false) } else { pc };
        Ok(pc)
    }
}

/// Bridges a shared `Arc<dyn murmur_std_compat::net::PacketConn>` into
/// `Box<dyn murmur_std_compat::net::PacketConn>`, so
/// the trait's exclusive-ownership vocabulary can carry the proxy adapter's shared packet conn.
struct ArcPacketConn(Arc<dyn NetPacketConn>);

#[async_trait]
impl NetPacketConn for ArcPacketConn {
    // cancel-safe: it only forwards to the shared packet conn it wraps.
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.0.read_from(buf).await
    }

    // cancel-safe: it only forwards to the shared packet conn it wraps.
    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.0.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.0.close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_write_deadline(deadline)
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.0.as_socket()
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    use super::*;
    use murmur_constant::adapters::{AdapterType, Chain, Connection, ProxyInfo};

    struct FakeConn(DuplexStream, &'static str);

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

    impl Stream for FakeConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(std::net::Ipv4Addr::new(192, 0, 2, 1).into(), 443))
        }
    }

    impl murmur_common_net::io::ExtendedStream for FakeConn {}

    impl Connection for FakeConn {
        fn chains(&self) -> Chain {
            Chain::default()
        }
        fn provider_chains(&self) -> Chain {
            Chain::default()
        }
        fn append_to_chains(&self, _adapter: Arc<dyn ProxyAdapter>) {}
        fn remote_destination(&self) -> String {
            self.1.to_owned()
        }
    }

    struct FakeProxyAdapter(parking_lot::Mutex<Option<DuplexStream>>, &'static str);

    #[async_trait]
    impl ProxyAdapter for FakeProxyAdapter {
        fn name(&self) -> String {
            "fake".to_owned()
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
        fn marshal_json(&self) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        async fn dial_context(
            &self,
            _ctx: &CancellationToken,
            _metadata: &mut Metadata,
        ) -> Result<Box<dyn murmur_constant::adapters::Conn>> {
            let server = self.0.lock().take().expect("dial_context called once");
            Ok(Box::new(FakeConn(server, self.1)))
        }
        async fn listen_packet_context(
            &self,
            _ctx: &CancellationToken,
            _metadata: &mut Metadata,
        ) -> Result<Arc<dyn ConstantPacketConn>> {
            Err(anyhow::anyhow!("fake adapter cannot listen"))
        }
        fn support_uot(&self) -> bool {
            false
        }
        fn is_l3_protocol(&self, _metadata: &Metadata) -> bool {
            false
        }
        fn unwrap(&self, _metadata: &Metadata, _touch: bool) -> Option<Arc<dyn murmur_constant::adapters::Proxy>> {
            None
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    fn count_by_marker(marker: &str) -> usize {
        let mut n = 0;
        DEFAULT_MANAGER.range(|c| {
            if c.remote_destination() == marker {
                n += 1;
            }
            true
        });
        n
    }

    /// The statistic=true path every dialer-proxy outbound takes.
    /// Before the fix, this returned `StreamAsOldConn::new(TcpTracker)`, whose `close()` fell back
    /// to `Stream::old_conn` (`None` for `TcpTracker`), never reaching `Tracker::close`: the entry
    /// stayed in `DEFAULT_MANAGER` forever and the wrapped conn's socket fd was never released.
    #[tokio::test]
    async fn statistic_dial_conn_leaves_the_manager_on_close() {
        const MARKER: &str = "proxydialer-test-marker.example:1";
        let (_client, server) = tokio::io::duplex(64);
        let adapter: Arc<dyn ProxyAdapter> = Arc::new(FakeProxyAdapter(parking_lot::Mutex::new(Some(server)), MARKER));
        let dialer = new(adapter, true);
        let ctx = CancellationToken::new();

        let conn = dialer.dial_context(&ctx, "tcp", "198.51.100.7:9").await.expect("dial succeeds");
        assert_eq!(1, count_by_marker(MARKER), "tracker must be registered right after dial");

        murmur_common_net::io::close_stream(conn.as_ref()).expect("close succeeds");

        assert_eq!(
            0,
            count_by_marker(MARKER),
            "closing the dialer-proxy's returned conn must leave DEFAULT_MANAGER, not leak the \
             tracker entry and its socket fd forever"
        );
    }
}
