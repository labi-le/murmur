//! The transport seam between the mieru underlays and whoever owns the sockets.
//!
//! The seam takes a dialer and a listener factory rather than concrete sockets, so the caller's
//! own dialer and listen config supply the interface binding, routing mark and dialer-proxy chain
//! the underlays would otherwise bypass.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

/// A duplex byte stream. `Sync` because a mieru stream is shared: it is safe to read and write
/// from either task.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + ?Sized> AsyncReadWrite for T {}

/// A boxed duplex stream.
pub type Stream = Pin<Box<dyn AsyncReadWrite>>;

/// Boxes a duplex stream for [`Stream`].
///
/// A `Box<dyn Trait>` cannot be coerced into `Box<dyn AsyncReadWrite>` unless one trait is a
/// declared supertrait of the other, so a caller arriving with its own erased stream
/// (`Box<dyn common_net::io::Stream>`) hands the delegation to this wrapper instead.
pub fn boxed_stream<T: AsyncReadWrite + Unpin + 'static>(inner: T) -> Stream {
    Box::pin(DelegatingStream { inner })
}

struct DelegatingStream<T> {
    inner: T,
}

impl<T: AsyncRead + Unpin> AsyncRead for DelegatingStream<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for DelegatingStream<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A stream plus its local and peer socket addresses.
pub struct DialedStream {
    pub stream: Stream,
    pub local_addr: io::Result<SocketAddr>,
    pub peer_addr: io::Result<SocketAddr>,
}

impl core::fmt::Debug for DialedStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DialedStream")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

/// A datagram socket reduced to what the packet underlay uses.
#[async_trait::async_trait]
pub trait PacketIo: Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// A datagram socket plus its local address and the peer it sends to.
pub struct DialedPacket {
    pub socket: Arc<dyn PacketIo>,
    pub local_addr: io::Result<SocketAddr>,
    /// Where datagrams go. A listener has no peer, so the server side leaves this unused.
    pub peer_addr: SocketAddr,
}

impl core::fmt::Debug for DialedPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DialedPacket")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

/// the `Dialer`/`PacketDialer` as mieru's client uses them. The host is a name or an IP literal
/// and the dialer owns resolution, so the proxy's resolver stays in charge.
#[async_trait::async_trait]
pub trait ClientDialer: Send + Sync {
    /// `ctx` is the caller's dial context, so a cancelled request also abandons the underlay dial
    /// the underlay dial would still be running.
    async fn dial_stream(&self, ctx: &CancellationToken, host: &str, port: u16) -> io::Result<DialedStream>;

    async fn dial_packet(&self, ctx: &CancellationToken, host: &str, port: u16) -> io::Result<DialedPacket>;
}

/// One accepted stream, with the addresses the session reports as its own.
pub struct AcceptedStream {
    pub stream: Stream,
    pub local_addr: io::Result<SocketAddr>,
    pub peer_addr: io::Result<SocketAddr>,
}

impl core::fmt::Debug for AcceptedStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AcceptedStream")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

/// the `StreamListenerFactory` as mieru's server uses it.
#[async_trait::async_trait]
pub trait Acceptor: Send + Sync {
    async fn accept(&self) -> io::Result<AcceptedStream>;
    fn close(&self) -> io::Result<()>;
    fn addr(&self) -> io::Result<SocketAddr>;
}

/// One endpoint a server binds, already bound by whoever owns the listen config.
pub enum ServerEndpoint {
    Stream(Arc<dyn Acceptor>),
    Packet(Arc<dyn PacketIo>),
}

impl core::fmt::Debug for ServerEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Stream(_) => f.write_str("Stream(..)"),
            Self::Packet(_) => f.write_str("Packet(..)"),
        }
    }
}

/// The default dialer: plain `TcpStream`/`UdpSocket`, for a caller that supplies no dialer.
///
/// It resolves through the OS resolver like mieru's own default; an embedding proxy
/// injects its own dialer instead (`MieruDialer` in `adapter-outbound/src/mieru.rs`), so this
/// path has no caller there.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDialer;

#[async_trait::async_trait]
impl ClientDialer for SystemDialer {
    async fn dial_stream(&self, ctx: &CancellationToken, host: &str, port: u16) -> io::Result<DialedStream> {
        let stream = tokio::select! {
            biased;
            () = ctx.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "dial cancelled")),
            res = tokio::net::TcpStream::connect((host, port)) => res?,
        };
        let _ = stream.set_nodelay(true);
        let local_addr = stream.local_addr();
        let peer_addr = stream.peer_addr();
        Ok(DialedStream { stream: Box::pin(stream), local_addr, peer_addr })
    }

    async fn dial_packet(&self, ctx: &CancellationToken, host: &str, port: u16) -> io::Result<DialedPacket> {
        let mut resolved = tokio::select! {
            biased;
            () = ctx.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "dial cancelled")),
            res = tokio::net::lookup_host((host, port)) => res?,
        };
        let peer_addr = resolved
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address found for {host}")))?;
        let bind_addr = if peer_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = Arc::new(tokio::net::UdpSocket::bind(bind_addr).await?);
        let local_addr = socket.local_addr();
        Ok(DialedPacket { socket, local_addr, peer_addr })
    }
}

#[async_trait::async_trait]
impl<T: PacketIo + ?Sized> PacketIo for Arc<T> {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        (**self).recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        (**self).send_to(buf, target).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        (**self).local_addr()
    }
}

#[async_trait::async_trait]
impl PacketIo for tokio::net::UdpSocket {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Self::recv_from(self, buf).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        Self::send_to(self, buf, target).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }
}

#[async_trait::async_trait]
impl Acceptor for tokio::net::TcpListener {
    // cancel-safe: tokio's `TcpListener::accept` parks until a connection is ready and a dropped accept leaves the queued connection for the next call.
    async fn accept(&self) -> io::Result<AcceptedStream> {
        let (stream, peer_addr) = Self::accept(self).await?;
        let _ = stream.set_nodelay(true);
        let local_addr = stream.local_addr();
        Ok(AcceptedStream { stream: Box::pin(stream), local_addr, peer_addr: Ok(peer_addr) })
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }

    fn addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }
}
