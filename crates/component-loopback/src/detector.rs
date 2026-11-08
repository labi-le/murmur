//! Loopback detector and its absent-receiver dispatch.
//!
//! DEVIATION: Rust has no absent-receiver methods, so `new_detector` returns `Option<Arc<Detector>>`
//! and the disabled case lives in the [`DetectorExt`] extension trait implemented for that
//! `Option`, returning its input unchanged (or `None`); the enabled logic is an inherent
//! `Detector` method or associated function.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use anyhow::Result;

use murmur_common::xsync::map::{ComputeOp, Map, MapKey};
use murmur_common_callback::close_callback::{new_close_callback_conn, new_close_callback_packet_conn, CloseFunc};
use murmur_component::iface::iface::is_local_ip;
use murmur_constant::adapters::{Conn as ConstantConn, PacketConn as ConstantPacketConn};
use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_constant_features::CMFA;

/// Folded together with the environment override into one lazily evaluated flag.
static DISABLE_LOOP_BACK_DETECTOR: LazyLock<bool> = LazyLock::new(|| {
    let disabled =
        std::env::var("DISABLE_LOOPBACK_DETECTOR").ok().and_then(|v| v.parse::<bool>().ok()).unwrap_or(false);
    disabled || CMFA
});

/// `ErrReject`: the formatted remote address is carried in the error itself, and callers match it
/// with `downcast_ref`.
#[derive(Debug, thiserror::Error)]
#[error("reject loopback connection to: {remote}")]
pub struct ErrReject {
    pub remote: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct TcpEndpoint {
    local: SocketAddr,
    peer: Option<SocketAddr>,
}

impl MapKey for TcpEndpoint {}

fn canonical_address(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

fn register<K: MapKey>(map: &Map<K, usize>, key: K) {
    map.compute(key, |count, _| (count.unwrap_or_default() + 1, ComputeOp::UpdateOp));
}

fn unregister<K: MapKey>(map: &Map<K, usize>, key: K) {
    map.compute(key, |count, _| match count {
        Some(count) if count > 1 => (count - 1, ComputeOp::UpdateOp),
        _ => (0, ComputeOp::DeleteOp),
    });
}

pub struct Detector {
    conn_map: Map<TcpEndpoint, usize>,
    conn_sources: Map<SocketAddr, usize>,
    packet_conn_map: Map<u16, ()>,
}

// `Map` has no `Debug`, so the tables themselves cannot be printed.
impl std::fmt::Debug for Detector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detector")
            .field("conn_map_len", &self.conn_map.size())
            .field("packet_conn_map_len", &self.packet_conn_map.size())
            .finish_non_exhaustive()
    }
}

impl Detector {
    #[must_use]
    pub fn new_detector() -> Option<Arc<Self>> {
        if *DISABLE_LOOP_BACK_DETECTOR {
            return None;
        }
        Some(Arc::new(Self { conn_map: Map::default(), conn_sources: Map::default(), packet_conn_map: Map::default() }))
    }

    /// Registers both TCP endpoints; different peers may share the same local address.
    fn new_conn(detector: &Arc<Self>, conn: Box<dyn ConstantConn>) -> Box<dyn ConstantConn> {
        let Ok(local) = conn.local_addr() else {
            return conn;
        };
        let endpoint =
            TcpEndpoint { local: canonical_address(local), peer: conn.peer_addr().ok().map(canonical_address) };
        register(&detector.conn_sources, endpoint.local);
        register(&detector.conn_map, endpoint);
        let this = Arc::clone(detector);
        let close_func: CloseFunc = Box::new(move || {
            unregister(&this.conn_map, endpoint);
            unregister(&this.conn_sources, endpoint.local);
        });
        new_close_callback_conn(conn, close_func)
    }

    /// Registers the packet conn's port and wraps it in a close callback.
    fn new_packet_conn(detector: &Arc<Self>, conn: Arc<dyn ConstantPacketConn>) -> Arc<dyn ConstantPacketConn> {
        let mut metadata = Metadata::default();
        let local_addr = conn.local_addr().ok();
        if metadata.set_remote_addr(local_addr.as_deref()).is_err() {
            return conn;
        }
        let Some(conn_addr) = metadata.addr_port() else {
            return conn;
        };

        let port = conn_addr.port();
        detector.packet_conn_map.store(port, ());
        let this = Arc::clone(detector);
        let close_func: CloseFunc = Box::new(move || {
            this.packet_conn_map.delete(port);
        });
        new_close_callback_packet_conn(conn, close_func)
    }

    /// Explicit TCP proxies retain the physical inbound endpoint separately from the requested target.
    fn check_conn(&self, metadata: &Metadata) -> Result<()> {
        let Some(source) = metadata.source_addr_port() else {
            return Ok(());
        };
        let source = canonical_address(source);
        let explicit_tcp = metadata.network == NetWork::TCP
            && matches!(metadata.type_, Type::HTTP | Type::HTTPS | Type::SOCKS4 | Type::SOCKS5);
        let inbound = metadata
            .in_ip
            .map(|ip| ip.to_canonical())
            .filter(|ip| !ip.is_unspecified())
            .filter(|_| metadata.in_port != 0);
        let reflected = if let Some(inbound) = inbound.filter(|_| explicit_tcp) {
            let peer = canonical_address(SocketAddr::new(inbound, metadata.in_port));
            self.conn_map.load(&TcpEndpoint { local: source, peer: Some(peer) }).is_some()
                || self.conn_map.load(&TcpEndpoint { local: source, peer: None }).is_some()
        } else {
            // Transparent or incomplete metadata cannot distinguish physical TCP destinations.
            self.conn_sources.load(&source).is_some()
        };
        if reflected {
            return Err(ErrReject { remote: metadata.remote_address() }.into());
        }
        Ok(())
    }

    /// Rejects a packet conn whose source address is already registered. `is_local_ip` resolves
    /// interface addresses asynchronously, so this method (and the [`DetectorExt`] wrapper) is
    /// `async`.
    async fn check_packet_conn(&self, metadata: &Metadata) -> Result<()> {
        let Some(conn_addr) = metadata.source_addr_port() else {
            return Ok(());
        };

        let is_local_ip = is_local_ip(conn_addr.ip()).await?;
        if !is_local_ip && !conn_addr.ip().is_loopback() {
            return Ok(());
        }

        if self.packet_conn_map.load(&conn_addr.port()).is_some() {
            return Err(ErrReject { remote: metadata.remote_address() }.into());
        }
        Ok(())
    }
}

/// Absent-receiver dispatch for every detector method, implemented for the `Option` that stands
/// in for a possibly-absent detector.
#[async_trait::async_trait]
pub trait DetectorExt {
    fn new_conn(&self, conn: Box<dyn ConstantConn>) -> Box<dyn ConstantConn>;
    fn new_packet_conn(&self, conn: Arc<dyn ConstantPacketConn>) -> Arc<dyn ConstantPacketConn>;
    fn check_conn(&self, metadata: &Metadata) -> Result<()>;
    async fn check_packet_conn(&self, metadata: &Metadata) -> Result<()>;
}

#[async_trait::async_trait]
impl DetectorExt for Option<Arc<Detector>> {
    fn new_conn(&self, conn: Box<dyn ConstantConn>) -> Box<dyn ConstantConn> {
        match self {
            Some(l) => Detector::new_conn(l, conn),
            None => conn,
        }
    }

    fn new_packet_conn(&self, conn: Arc<dyn ConstantPacketConn>) -> Arc<dyn ConstantPacketConn> {
        match self {
            Some(l) => Detector::new_packet_conn(l, conn),
            None => conn,
        }
    }

    fn check_conn(&self, metadata: &Metadata) -> Result<()> {
        match self {
            Some(l) => l.check_conn(metadata),
            None => Ok(()),
        }
    }

    async fn check_packet_conn(&self, metadata: &Metadata) -> Result<()> {
        match self {
            Some(l) => l.check_packet_conn(metadata).await,
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use murmur_common_net::io::{ExtendedStream, Stream};
    use murmur_constant::adapters::{Chain, Connection, ProxyAdapter};
    use murmur_constant::metadata::Type;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::{TcpListener, TcpSocket, TcpStream};

    struct SocketConn(TcpStream);

    impl AsyncRead for SocketConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for SocketConn {
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

    impl Stream for SocketConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.0.local_addr()
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.0.peer_addr()
        }
    }

    impl ExtendedStream for SocketConn {}

    impl Connection for SocketConn {
        fn chains(&self) -> Chain {
            Chain::default()
        }

        fn provider_chains(&self) -> Chain {
            Chain::default()
        }

        fn append_to_chains(&self, _adapter: Arc<dyn ProxyAdapter>) {}

        fn remote_destination(&self) -> String {
            self.0.peer_addr().unwrap().to_string()
        }
    }

    fn inbound_metadata(stream: &TcpStream) -> Metadata {
        let source = stream.peer_addr().unwrap();
        let inbound = stream.local_addr().unwrap();
        Metadata {
            type_: Type::SOCKS5,
            src_ip: Some(source.ip()),
            src_port: source.port(),
            in_ip: Some(inbound.ip()),
            in_port: inbound.port(),
            // A SOCKS request's target is not the physical inbound endpoint.
            dst_ip: Some("192.0.2.1".parse().unwrap()),
            dst_port: 443,
            ..Metadata::default()
        }
    }

    #[tokio::test]
    async fn shared_tcp_source_does_not_alias_distinct_peers_or_lose_loop_registration() {
        let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_socket = TcpSocket::new_v4().unwrap();
        first_socket.set_reuseaddr(true).unwrap();
        first_socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let source = first_socket.local_addr().unwrap();
        let first = first_socket.connect(first_listener.local_addr().unwrap()).await.unwrap();
        let (first_inbound, _) = first_listener.accept().await.unwrap();
        let second_socket = TcpSocket::new_v4().unwrap();
        second_socket.set_reuseaddr(true).unwrap();
        second_socket.bind(source).unwrap();
        let second = second_socket.connect(second_listener.local_addr().unwrap()).await.unwrap();
        let (second_inbound, _) = second_listener.accept().await.unwrap();
        assert_eq!(first.local_addr().unwrap(), second.local_addr().unwrap());

        let detector = Arc::new(Detector {
            conn_map: Map::default(),
            conn_sources: Map::default(),
            packet_conn_map: Map::default(),
        });
        let first = Detector::new_conn(&detector, Box::new(SocketConn(first)));
        let first_metadata = inbound_metadata(&first_inbound);
        let second_metadata = inbound_metadata(&second_inbound);
        for type_ in [Type::HTTP, Type::HTTPS, Type::SOCKS4, Type::SOCKS5] {
            let mut reflected = first_metadata.clone();
            reflected.type_ = type_;
            let mut unrelated = second_metadata.clone();
            unrelated.type_ = type_;
            assert!(detector.check_conn(&reflected).is_err(), "a reflected outgoing TCP connection is a loop");
            assert!(detector.check_conn(&unrelated).is_ok(), "a distinct TCP peer sharing the source is not a loop");
        }

        let second = Detector::new_conn(&detector, Box::new(SocketConn(second)));
        assert!(detector.check_conn(&first_metadata).is_err());
        assert!(detector.check_conn(&second_metadata).is_err());
        drop(first);
        assert!(detector.check_conn(&first_metadata).is_ok());
        assert!(detector.check_conn(&second_metadata).is_err(), "dropping one peer must not unregister another");

        let mut mapped = second_metadata.clone();
        mapped.src_ip = Some("::ffff:127.0.0.1".parse().unwrap());
        mapped.in_ip = mapped.src_ip;
        assert!(detector.check_conn(&mapped).is_err(), "IPv4-mapped addresses denote the same connection");
        let mut unknown = first_metadata.clone();
        unknown.in_ip = None;
        unknown.in_port = 0;
        assert!(detector.check_conn(&unknown).is_err(), "missing inbound endpoints retain conservative loop rejection");
        let mut unspecified = first_metadata.clone();
        unspecified.in_ip = Some("::ffff:0.0.0.0".parse().unwrap());
        assert!(detector.check_conn(&unspecified).is_err());
        let mut transparent = first_metadata.clone();
        for type_ in [Type::TPROXY, Type::REDIR, Type::TUN, Type::INNER] {
            transparent.type_ = type_;
            assert!(detector.check_conn(&transparent).is_err(), "transparent metadata retains source-based detection");
        }
        drop(second);
        assert!(detector.check_conn(&second_metadata).is_ok());
        assert!(detector.check_conn(&unknown).is_ok());
        assert!(detector.check_conn(&unspecified).is_ok());
        assert!(detector.check_conn(&transparent).is_ok());
    }

    #[test]
    fn smoke_socketaddr_map_key() {
        let m = Map::<SocketAddr, i32>::new(&[]);
        let a1: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let a2: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        m.store(a1, 1);
        m.store(a2, 2);
        assert_eq!(m.load(&a1), Some(1));
        assert_eq!(m.load(&a2), Some(2));
        m.delete(a1);
        assert!(m.load(&a1).is_none());
        assert_eq!(m.load(&a2), Some(2));
    }
}
