//! The `Stream`/`ExtendedStream`/`Datagram` contract and the `Addr`-dissolution helpers are owned
//! by [`murmur_common::net`] and re-exported here.
//!
//! They are re-exported so that the crates below `murmur-common-net` can implement them; what
//! stays here is the socket-backed and bridge machinery built on top.

use std::any::Any;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{Instant, Sleep};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

pub use murmur_common::net::{
    close_stream, old_addr_to_socket_addr, socket_addr_from_udp_addr, Datagram, ExtendedStream, Stream,
};

use murmur_common::shared_conn::Conn as SharedConnConn;
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr, Conn, ExtendedConn, Listener, PacketConn, TcpAddr, UdpAddr};

use super::sing::UpstreamNode;

/// The wrapped value seen as a reader only, which hides the bulk-write path a TCP conn would
/// otherwise expose.
#[derive(Debug)]
pub struct ReadOnlyReader<R> {
    pub reader: R,
}

/// `WriteOnlyWriter`: the wrapped value seen as a writer only.
#[derive(Debug)]
pub struct WriteOnlyWriter<W> {
    pub writer: W,
}

impl<R> AsyncRead for ReadOnlyReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl<W> AsyncWrite for WriteOnlyWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

/// Narrower datagram trait for the FQDN-carrying sites (tuic UoT, socks5 UDP relay,
/// ssr/shadowsocks packet).
///
/// Those sites must forward a domain name through a NAT/session table without resolving it
/// early. Kept separate so the pure-`SocketAddr` implementors (hysteria hop/obfs, kcptun, mkcp,
/// …) don't carry dead `Socksaddr` plumbing.
#[async_trait]
pub trait NamedDatagram: Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Socksaddr)>;
    async fn send_to(&self, buf: &[u8], addr: &Socksaddr) -> io::Result<usize>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Replaces `Listener`.
#[async_trait]
pub trait Acceptor: Send + Sync {
    async fn accept(&self) -> io::Result<Box<dyn Stream>>;
    fn close(&self) -> io::Result<()> {
        Ok(())
    }
    fn addr(&self) -> io::Result<SocketAddr>;
}

#[async_trait]
impl<D: NamedDatagram + ?Sized> NamedDatagram for Box<D> {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        (**self).recv_from(buf).await
    }
    async fn send_to(&self, buf: &[u8], addr: &Socksaddr) -> io::Result<usize> {
        (**self).send_to(buf, addr).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        (**self).local_addr()
    }
    fn close(&self) -> io::Result<()> {
        (**self).close()
    }
}

#[async_trait]
impl<T: Acceptor + ?Sized> Acceptor for Box<T> {
    // cancel-safe: forwards to the wrapped acceptor's `accept` and only boxes the result, so a dropped call leaves the listener exactly as it was.
    async fn accept(&self) -> io::Result<Box<dyn Stream>> {
        (**self).accept().await
    }
    fn close(&self) -> io::Result<()> {
        (**self).close()
    }
    fn addr(&self) -> io::Result<SocketAddr> {
        (**self).addr()
    }
}

#[async_trait]
impl Acceptor for TcpListener {
    // cancel-safe: tokio's `TcpListener::accept` parks until a connection is ready and a dropped accept leaves the queued connection for the next call.
    async fn accept(&self) -> io::Result<Box<dyn Stream>> {
        let (stream, _) = Self::accept(self).await?;
        let _ = stream.set_nodelay(true);
        Ok(Box::new(stream))
    }
    fn addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }
}

#[derive(Debug)]
pub struct TcpAcceptor {
    listener: TcpListener,
    closed: CancellationToken,
}

impl TcpAcceptor {
    pub fn new(listener: TcpListener) -> Self {
        Self { listener, closed: CancellationToken::new() }
    }
}

#[async_trait]
impl Acceptor for TcpAcceptor {
    async fn accept(&self) -> io::Result<Box<dyn Stream>> {
        // cancel-safe: tokio's accept leaves an unaccepted connection in the listener's queue.
        let (stream, _) = tokio::select! {
            biased;
            () = self.closed.cancelled() => return Err(closed_conn_err()),
            result = self.listener.accept() => result?,
        };
        let _ = stream.set_nodelay(true);
        Ok(Box::new(stream))
    }

    fn close(&self) -> io::Result<()> {
        self.closed.cancel();
        Ok(())
    }

    fn addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

#[derive(Debug)]
pub struct UdpAcceptor {
    socket: UdpSocket,
    closed: CancellationToken,
}

impl UdpAcceptor {
    pub fn new(socket: UdpSocket) -> Self {
        Self { socket, closed: CancellationToken::new() }
    }

    pub(crate) fn raw_socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub(crate) fn close_token(&self) -> CancellationToken {
        self.closed.clone()
    }
}

#[async_trait]
impl Datagram for UdpAcceptor {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // cancel-safe: tokio's recv_from drops no datagram; the close branch reports an already-fired cancel.
        tokio::select! {
            biased;
            () = self.closed.cancelled() => Err(closed_conn_err()),
            result = self.socket.recv_from(buf) => result,
        }
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.closed.cancel();
        Ok(())
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        Some(socket2::SockRef::from(&self.socket))
    }

    // `new_enhance_datagram` recognizes this wrapper as a raw-socket source separately. Returning
    // the wrapper here keeps `Datagram::as_any` honest and lets the enhanced path retain closure
    // cancellation while it uses the inner socket's readiness registration.
    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }

    fn into_std_udp(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        self.socket.into_std()
    }
}

/// Temporary bridge: exposes any [`Stream`] as the old `Conn`, so call sites not yet migrated
/// (slices S1-S10) keep compiling against a `Stream`-backed value.
///
/// Deleted in slice S11 alongside the old traits.
#[derive(Debug)]
pub struct StreamAsOldConn<S> {
    stream: CancellableStream<S>,
}

impl<S: Stream> StreamAsOldConn<S> {
    pub fn new(inner: S) -> Self {
        Self { stream: CancellableStream::new(inner) }
    }
}

impl<S: Stream> AsyncRead for StreamAsOldConn<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl<S: Stream> AsyncWrite for StreamAsOldConn<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

fn boxed_addr<T: Addr>(addr: T) -> Box<dyn Addr> {
    Box::new(addr)
}

fn closed_conn_err() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "use of closed network connection")
}

/// `StreamAsOldConn` forwards its whole `Conn` surface to the [`CancellableStream`] it wraps,
/// which owns the closed-latch and `old_conn`-deadline-forwarding logic shared with
/// [`SharedConnConn`]'s impl below.
impl<S: Stream> Conn for StreamAsOldConn<S> {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.stream.old_local_addr()
    }
    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.stream.old_remote_addr()
    }
    fn close(&self) -> io::Result<()> {
        self.stream.old_close()
    }
    fn close_read(&self) -> io::Result<()> {
        self.stream.old_close_read()
    }
    fn close_write(&self) -> io::Result<()> {
        self.stream.old_close_write()
    }
    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.stream.old_set_deadline(deadline)
    }
    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.stream.old_set_read_deadline(deadline)
    }
    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.stream.old_set_write_deadline(deadline)
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.stream.as_socket()
    }
}

impl<S: ExtendedStream> ExtendedConn for StreamAsOldConn<S> {
    /// The bound carries no node, so the old splice walk stays unanswered; callers that need it
    /// go through the [`UpstreamNode`] impl below.
    fn upstream(&self) -> Option<&dyn Any> {
        None
    }
    fn reader_replaceable(&self) -> bool {
        self.stream.get_ref().reader_replaceable()
    }
    fn writer_replaceable(&self) -> bool {
        self.stream.get_ref().writer_replaceable()
    }
}

/// The counterpart of the `OldConnAsStream` impl: a runtime-typed net conn keeps its
/// wrapper discoverable, whereas the split traits do not, and a node lost here cannot be
/// reached by the node walk — which is what the shadow-tls user lookup walks.
impl<S: Stream + UpstreamNode> UpstreamNode for StreamAsOldConn<S> {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&self.stream)
    }
}

/// Temporary bridge, the reverse of [`StreamAsOldConn`]: exposes any old `Conn` as a [`Stream`].
///
/// `local_addr`/`peer_addr` fail with `io::ErrorKind::Unsupported` for an old `Conn` whose `Addr`
/// isn't socket-backed (`TcpAddr`/`UdpAddr`) — e.g. `deadline::pipe_sing::PipeConn`, which reports
/// a `PipeAddr` with no `SocketAddr` equivalent.
#[derive(Debug)]
pub struct OldConnAsStream<C>(pub C);

impl<C: Conn> AsyncRead for OldConnAsStream<C> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<C: Conn> AsyncWrite for OldConnAsStream<C> {
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

/// The reverse of [`socket_addr_from_udp_addr`]: a `SocketAddrV6::scope_id` becomes `UdpAddr`'s
/// numeric zone.
#[must_use]
pub fn udp_addr_from_socket_addr(addr: SocketAddr) -> UdpAddr {
    let mut udp = UdpAddr::from(addr);
    if let SocketAddr::V6(v6) = addr {
        if v6.scope_id() != 0 {
            udp.zone = v6.scope_id().to_string();
        }
    }
    udp
}

impl<C: Conn> Stream for OldConnAsStream<C> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.0.local_addr()?.as_ref())
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.0.remote_addr()?.as_ref())
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.0.close_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.0.close_write()
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.0.as_socket()
    }
    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(&self.0)
    }
}

impl<C: ExtendedConn> ExtendedStream for OldConnAsStream<C> {
    fn reader_replaceable(&self) -> bool {
        self.0.reader_replaceable()
    }
    fn writer_replaceable(&self) -> bool {
        self.0.writer_replaceable()
    }
}

/// Temporary bridge: exposes any [`Datagram`] as the old `PacketConn`.
#[derive(Debug)]
pub struct DatagramAsOldPacketConn<D>(pub D);

#[async_trait]
impl<D: Datagram + 'static> PacketConn for DatagramAsOldPacketConn<D> {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let (n, addr) = self.0.recv_from(buf).await?;
        Ok((n, Box::new(udp_addr_from_socket_addr(addr))))
    }
    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.0.send_to(buf, old_addr_to_socket_addr(addr)?).await
    }
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr().map(|a| boxed_addr(udp_addr_from_socket_addr(a)))
    }
    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.0.as_socket()
    }
    fn into_std_udp(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Box::new(self.0).into_std_udp()
    }
}

/// Temporary bridge: exposes any [`NamedDatagram`] as the old `PacketConn`, converting the peer
/// address through [`Socksaddr`]'s IP case.
///
/// The old trait has no FQDN vocabulary, so a genuinely-FQDN peer address fails
/// `read_from`/`write_to` with `Unsupported`.
#[derive(Debug)]
pub struct NamedDatagramAsOldPacketConn<D>(pub D);

#[async_trait]
impl<D: NamedDatagram + 'static> PacketConn for NamedDatagramAsOldPacketConn<D> {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let (n, addr) = self.0.recv_from(buf).await?;
        let addr = addr.addr_port().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "FQDN peer address has no old Addr equivalent")
        })?;
        Ok((n, Box::new(udp_addr_from_socket_addr(addr))))
    }
    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.0.send_to(buf, &Socksaddr::from(old_addr_to_socket_addr(addr)?)).await
    }
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr().map(|a| boxed_addr(udp_addr_from_socket_addr(a)))
    }
    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
}

/// Temporary bridge, the reverse of [`NamedDatagramAsOldPacketConn`]: exposes any old
/// `PacketConn` as a [`NamedDatagram`].
///
/// Conversion goes through [`Socksaddr`]'s IP case; the old trait has no FQDN vocabulary to
/// preserve.
#[derive(Debug)]
pub struct OldPacketConnAsNamedDatagram<P>(pub P);

#[async_trait]
impl<P: PacketConn> NamedDatagram for OldPacketConnAsNamedDatagram<P> {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (n, addr) = self.0.read_from(buf).await?;
        Ok((n, Socksaddr::from(old_addr_to_socket_addr(addr.as_ref())?)))
    }
    async fn send_to(&self, buf: &[u8], addr: &Socksaddr) -> io::Result<usize> {
        let socket_addr = addr.addr_port().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "FQDN peer address has no old Addr equivalent")
        })?;
        self.0.write_to(buf, &udp_addr_from_socket_addr(socket_addr)).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.0.local_addr()?.as_ref())
    }
    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
}

/// Temporary bridge, the reverse of [`DatagramAsOldPacketConn`]: exposes any old
/// `PacketConn` as a [`Datagram`], converting through [`old_addr_to_socket_addr`].
#[derive(Debug)]
pub struct OldPacketConnAsDatagram<P>(pub P);

#[async_trait]
impl<P: PacketConn> Datagram for OldPacketConnAsDatagram<P> {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, addr) = self.0.read_from(buf).await?;
        Ok((n, old_addr_to_socket_addr(addr.as_ref())?))
    }
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.0.write_to(buf, &udp_addr_from_socket_addr(addr)).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.0.local_addr()?.as_ref())
    }
    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
}

/// Temporary bridge: exposes any [`Acceptor`] as the old `Listener`.
#[derive(Debug)]
pub struct AcceptorAsOldListener<A>(pub A);

#[async_trait]
impl<A: Acceptor> Listener for AcceptorAsOldListener<A> {
    // cancel-safe: forwards to the wrapped acceptor's `accept` and only boxes the result, so a dropped call leaves the listener exactly as it was.
    async fn accept(&self) -> io::Result<Box<dyn Conn>> {
        let stream = self.0.accept().await?;
        Ok(Box::new(StreamAsOldConn::new(stream)))
    }
    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
    fn addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.addr().map(|a| boxed_addr(TcpAddr::from(a)))
    }
}

/// Temporary bridge: exposes any old `Listener` as an [`Acceptor`], for a listener
/// crate boundary (e.g. a TLS `Listener` wrapper) that has not migrated yet.
#[derive(Debug)]
pub struct OldListenerAsAcceptor<L>(pub L);

#[async_trait]
impl<L: Listener> Acceptor for OldListenerAsAcceptor<L> {
    // cancel-safe: forwards to the wrapped acceptor's `accept` and only boxes the result, so a dropped call leaves the listener exactly as it was.
    async fn accept(&self) -> io::Result<Box<dyn Stream>> {
        let conn = self.0.accept().await?;
        Ok(Box::new(OldConnAsStream(conn)))
    }
    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
    fn addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.0.addr()?.as_ref())
    }
}

/// Class 2 of the §3 deadline design: a cross-task cancel of a blocked read/write.
///
/// Deadline classes 1 and 4 — a single-task blocking op (dialer connect/handshake timeouts), or a
/// handshake's several sequential reads within one task — need no wrapper type at all: wrap the
/// call, or the whole handshake future, in `tokio::time::timeout` at the call site instead of
/// threading a deadline through the conn. Classes 2 and 3 below (`CancellableStream`,
/// `IdleTimeout`) cover the two cases that do need a standing combinator: a deadline set from
/// another task, and a deadline reset by traffic.
///
/// Class 2: a cross-task cancel of a blocked read/write, replacing
/// `common/net/deadline/{conn,pipe,pipe_sing}.rs`'s hand-rolled `PipeDeadline`. Wraps any
/// `AsyncRead + AsyncWrite` and races each poll against a [`CancellationToken`]; a cancelled
/// token turns a parked read/write into `io::ErrorKind::TimedOut`, mirroring the
/// A deadline set from a watchdog task as another task is parked in a read.
#[derive(Debug)]
pub struct CancellableStream<S> {
    inner: S,
    read_deadline: Arc<DeadlineToken>,
    write_deadline: Arc<DeadlineToken>,
    read_cancel: Option<(u64, Pin<Box<WaitForCancellationFutureOwned>>)>,
    write_cancel: Option<(u64, Pin<Box<WaitForCancellationFutureOwned>>)>,
    closed: AtomicBool,
}

impl<S> CancellableStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_deadline: Arc::new(DeadlineToken::new()),
            write_deadline: Arc::new(DeadlineToken::new()),
            read_cancel: None,
            write_cancel: None,
            closed: AtomicBool::new(false),
        }
    }

    /// A cloned, `Arc`-shared handle onto the read-side deadline.
    ///
    /// Unlike the stream itself, this can be moved into a watchdog task while the stream is
    /// separately moved into (or split across) the task(s) that read/write it, and still arm,
    /// re-arm or clear the same deadline those polls race against. Mirrors
    /// `Conn::set_read_deadline` (a cleared deadline lets a parked read reach the inner stream
    /// again, unlike a plain `CancellationToken`, which cannot be un-cancelled).
    pub fn read_deadline(&self) -> Arc<DeadlineToken> {
        Arc::clone(&self.read_deadline)
    }

    /// Borrowed access to the wrapped value, for callers that need a capability the [`Stream`]
    /// forwarding methods below don't expose (e.g. [`ExtendedStream::reader_replaceable`]).
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// The write-side counterpart of [`CancellableStream::read_deadline`]; also races
    /// `poll_flush`/`poll_shutdown`, not just `poll_write`.
    pub fn write_deadline(&self) -> Arc<DeadlineToken> {
        Arc::clone(&self.write_deadline)
    }

    fn poll_read_cancelled(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        let (token, generation) = self.read_deadline.token_with_generation();
        if token.is_cancelled() {
            self.read_cancel = None;
            return Poll::Ready(io::Error::new(io::ErrorKind::TimedOut, "read cancelled"));
        }
        let ready = {
            // A stale generation drops the cached waiter, which the insert below rebuilds.
            if !matches!(&self.read_cancel, Some((gen, _)) if *gen == generation) {
                self.read_cancel = None;
            }
            let (_, cancel) = self.read_cancel.get_or_insert_with(|| (generation, Box::pin(token.cancelled_owned())));
            cancel.as_mut().poll(cx).is_ready()
        };
        if ready {
            self.read_cancel = None;
            return Poll::Ready(io::Error::new(io::ErrorKind::TimedOut, "read cancelled"));
        }
        Poll::Pending
    }

    fn poll_write_cancelled(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        let (token, generation) = self.write_deadline.token_with_generation();
        if token.is_cancelled() {
            self.write_cancel = None;
            return Poll::Ready(io::Error::new(io::ErrorKind::TimedOut, "write cancelled"));
        }
        let ready = {
            // A stale generation drops the cached waiter, which the insert below rebuilds.
            if !matches!(&self.write_cancel, Some((gen, _)) if *gen == generation) {
                self.write_cancel = None;
            }
            let (_, cancel) = self.write_cancel.get_or_insert_with(|| (generation, Box::pin(token.cancelled_owned())));
            cancel.as_mut().poll(cx).is_ready()
        };
        if ready {
            self.write_cancel = None;
            return Poll::Ready(io::Error::new(io::ErrorKind::TimedOut, "write cancelled"));
        }
        Poll::Pending
    }
}

/// Deadline setters mirrored through the bridge: unlike the earlier
/// design (abandon a poll the instant the token has already fired), every poll below tries the
/// wrapped `inner` **first**, on every call, even past an already-expired deadline. This is the
/// actual fix for the class of bug the anytls/tlsmirror/shadowtls reviews found: when `inner` is,
/// or transparently wraps, an old `Conn` ([`Stream::old_conn`]) whose own poll already
/// races the *same* deadline (forwarded by [`StreamAsOldConn::set_read_deadline`]/
/// `set_write_deadline`) internally, `inner` gets an actual chance every poll to observe that and
/// safely tear down its own in-flight state — instead of this wrapper unilaterally deciding
/// first and abandoning `inner`'s still-in-flight future. Only once `inner` itself has genuinely
/// stayed `Pending` on *this* poll does the wrapper fall back to its own `read_deadline`/
/// `write_deadline` race, which is what actually enforces the deadline for a plain stream with no
/// `old_conn` (e.g. a raw `TcpStream`, cancel-safe: dropping and reissuing its poll loses no
/// state) or for an old `Conn` whose own deadline setter for this direction is a no-op.
impl<S: AsyncRead + Unpin> AsyncRead for CancellableStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(closed_conn_err()));
        }
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                this.read_cancel = None;
                Poll::Ready(result)
            }
            Poll::Pending => match this.poll_read_cancelled(cx) {
                Poll::Ready(err) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CancellableStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(closed_conn_err()));
        }
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(result) => {
                this.write_cancel = None;
                Poll::Ready(result)
            }
            Poll::Pending => match this.poll_write_cancelled(cx) {
                Poll::Ready(err) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            },
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(closed_conn_err()));
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => match this.poll_write_cancelled(cx) {
                Poll::Ready(err) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            },
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(closed_conn_err()));
        }
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => match this.poll_write_cancelled(cx) {
                Poll::Ready(err) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<S: Stream> Stream for CancellableStream<S> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.inner.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.shutdown_write()
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.inner.as_socket()
    }
    fn old_conn(&self) -> Option<&dyn Conn> {
        self.inner.old_conn()
    }
}

/// The hop [`StreamAsOldConn`]'s walk has to cross; without it the forward stops one level too
/// early.
impl<S: Stream + UpstreamNode> UpstreamNode for CancellableStream<S> {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&self.inner)
    }
}

// S11: remove in U8, when the final old-`Conn` bridge is deleted.
/// The old-`Conn`-bridge surface both [`SharedConnConn`] (below) and [`StreamAsOldConn`] expose:
/// closing latches [`CancellableStream::is_closed`] so a later `set_*_deadline` cannot re-arm a
/// closed conn's own tokens, and every deadline setter that forwards to [`Stream::old_conn`]
/// delays this bridge's own fallback token by [`Self::OLD_CONN_FALLBACK_GRACE`] so `old_conn`'s
/// own timer — armed at the exact requested instant — always wins the race instead of the
/// fallback abandoning a poll `old_conn` was about to resolve cleanly (see
/// `StreamAsOldConn::set_deadline`'s original doc for the measured race).
impl<S: Stream> CancellableStream<S> {
    const OLD_CONN_FALLBACK_GRACE: Duration = Duration::from_millis(20);

    fn fallback_deadline(deadline: Option<Instant>, forwarded: bool) -> Option<Instant> {
        if forwarded {
            deadline.map(|d| d + Self::OLD_CONN_FALLBACK_GRACE)
        } else {
            deadline
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn mark_closed(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    pub fn old_local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Stream::local_addr(self).map(|a| boxed_addr(TcpAddr::from(a)))
    }

    pub fn old_remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Stream::peer_addr(self).map(|a| boxed_addr(TcpAddr::from(a)))
    }

    pub fn old_close(&self) -> io::Result<()> {
        self.mark_closed();
        let now = Instant::now();
        self.read_deadline().set(Some(now));
        self.write_deadline().set(Some(now));
        close_stream(self)
    }

    pub fn old_close_read(&self) -> io::Result<()> {
        if let Some(inner) = self.get_ref().old_conn() {
            return inner.close_read();
        }
        self.read_deadline().set(Some(Instant::now()));
        self.shutdown_read()
    }

    pub fn old_close_write(&self) -> io::Result<()> {
        if let Some(inner) = self.get_ref().old_conn() {
            return inner.close_write();
        }
        self.write_deadline().set(Some(Instant::now()));
        self.shutdown_write()
    }

    pub fn old_set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        if self.is_closed() {
            return Err(closed_conn_err());
        }
        let inner = self.get_ref().old_conn();
        let fallback = Self::fallback_deadline(deadline, inner.is_some());
        self.read_deadline().set(fallback);
        self.write_deadline().set(fallback);
        if let Some(inner) = inner {
            inner.set_deadline(deadline)?;
        }
        Ok(())
    }

    pub fn old_set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        if self.is_closed() {
            return Err(closed_conn_err());
        }
        let inner = self.get_ref().old_conn();
        self.read_deadline().set(Self::fallback_deadline(deadline, inner.is_some()));
        if let Some(inner) = inner {
            inner.set_read_deadline(deadline)?;
        }
        Ok(())
    }

    pub fn old_set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        if self.is_closed() {
            return Err(closed_conn_err());
        }
        let inner = self.get_ref().old_conn();
        self.write_deadline().set(Self::fallback_deadline(deadline, inner.is_some()));
        if let Some(inner) = inner {
            inner.set_write_deadline(deadline)?;
        }
        Ok(())
    }
}

// S11: remove in U8, when the final old-`Conn` bridge is deleted.
impl<S: Stream> SharedConnConn for CancellableStream<S> {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.old_local_addr()
    }
    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.old_remote_addr()
    }
    fn close(&self) -> io::Result<()> {
        self.old_close()
    }
    fn close_read(&self) -> io::Result<()> {
        self.old_close_read()
    }
    fn close_write(&self) -> io::Result<()> {
        self.old_close_write()
    }
    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.old_set_deadline(deadline)
    }
    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.old_set_read_deadline(deadline)
    }
    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.old_set_write_deadline(deadline)
    }
}

/// Deadline class 3 (§3): an idle timer reset by every successful read/write.
///
/// Replaces the per-protocol idle-deadline reimplementations in
/// mux/hop/session-keepalive protocols (`transport/hysteria/conns/udp/hop.rs`,
/// `transport/sudoku/multiplex/*`, `transport/mkcp`, `transport/kcptun`).
#[derive(Debug)]
pub struct IdleTimeout<S> {
    inner: S,
    duration: Duration,
    deadline: std::sync::Mutex<Instant>,
    read_sleep: Pin<Box<Sleep>>,
    write_sleep: Pin<Box<Sleep>>,
}

impl<S> IdleTimeout<S> {
    pub fn new(inner: S, duration: Duration) -> Self {
        let deadline = Instant::now() + duration;
        Self {
            inner,
            duration,
            deadline: std::sync::Mutex::new(deadline),
            read_sleep: Box::pin(tokio::time::sleep_until(deadline)),
            write_sleep: Box::pin(tokio::time::sleep_until(deadline)),
        }
    }

    /// Pushes the shared deadline out by `duration`; the next poll of either direction's `Sleep`
    /// picks it up via [`IdleTimeout::poll_read_expired`]/[`IdleTimeout::poll_write_expired`].
    fn bump_deadline(&self) {
        let deadline = Instant::now() + self.duration;
        *self.deadline.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = deadline;
    }

    fn current_deadline(&self) -> Instant {
        *self.deadline.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn poll_read_expired(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        let deadline = self.current_deadline();
        self.read_sleep.as_mut().reset(deadline);
        match self.read_sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(io::Error::new(io::ErrorKind::TimedOut, "idle timeout")),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write_expired(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        let deadline = self.current_deadline();
        self.write_sleep.as_mut().reset(deadline);
        match self.write_sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(io::Error::new(io::ErrorKind::TimedOut, "idle timeout")),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTimeout<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(err) = this.poll_read_expired(cx) {
            return Poll::Ready(Err(err));
        }
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.bump_deadline();
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTimeout<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Poll::Ready(err) = this.poll_write_expired(cx) {
            return Poll::Ready(Err(err));
        }
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = poll {
            if n > 0 {
                this.bump_deadline();
            }
        }
        poll
    }
    /// Races the write-side idle timer (a `BufWriter`/TLS/mux framer may do the real I/O here
    /// rather than in `poll_write`), but does not reset it: a flush is bookkeeping, not traffic.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(err) = this.poll_write_expired(cx) {
            return Poll::Ready(Err(err));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(err) = this.poll_write_expired(cx) {
            return Poll::Ready(Err(err));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: Stream> Stream for IdleTimeout<S> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.inner.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.shutdown_write()
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.inner.as_socket()
    }
    fn old_conn(&self) -> Option<&dyn Conn> {
        self.inner.old_conn()
    }
}

/// A resettable, cross-task point-in-time deadline.
///
/// Replaces `deadline/pipe.rs`'s hand-rolled `PipeDeadline` for the sites in this module that
/// adapt an old `{Conn,PacketConn}` deadline setter onto a [`CancellationToken`] race (§3 class
/// 2/3, where the wrapped value has no single inner [`Stream`]/[`Datagram`] for
/// [`CancellableStream`]/[`IdleTimeout`] to wrap, so the race is written out by hand at the call
/// site instead).
///
/// `set` mirrors `PipeDeadline::set`: re-arming while the current token has not yet fired reuses
/// that token, so a caller already racing [`DeadlineToken::token`]'s result still gets woken by the
/// new deadline; re-arming after it has fired swaps in a fresh, uncancelled token.
#[derive(Debug)]
pub struct DeadlineToken {
    inner: Arc<std::sync::Mutex<DeadlineTokenInner>>,
}

#[derive(Debug)]
struct DeadlineTokenInner {
    timer: Option<tokio::task::JoinHandle<()>>,
    token: CancellationToken,
    generation: u64,
}

impl Default for DeadlineToken {
    fn default() -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(DeadlineTokenInner {
                timer: None,
                token: CancellationToken::new(),
                generation: 0,
            })),
        }
    }
}

impl DeadlineToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Arms (or re-arms) the deadline at `deadline`; `None` clears any pending timer without
    /// cancelling the token already in force.
    ///
    /// Bumps the generation under the same lock the firing timer checks before it cancels, so a
    /// `set` racing an already-firing timer always wins: either it runs before the timer's lock
    /// and the timer sees a stale generation and skips the cancel, or it runs after and observes
    /// the token already cancelled.
    pub fn set(&self, deadline: Option<Instant>) {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(timer) = inner.timer.take() {
            timer.abort();
        }
        inner.generation += 1;
        let generation = inner.generation;
        let already_cancelled = inner.token.is_cancelled();
        let Some(deadline) = deadline else {
            if already_cancelled {
                inner.token = CancellationToken::new();
            }
            return;
        };
        if deadline > Instant::now() {
            if already_cancelled {
                inner.token = CancellationToken::new();
            }
            let shared = Arc::clone(&self.inner);
            inner.timer = Some(tokio::spawn(async move {
                tokio::time::sleep_until(deadline).await;
                let inner = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if inner.generation == generation {
                    inner.token.cancel();
                }
            }));
            return;
        }
        if !already_cancelled {
            inner.token.cancel();
        }
    }

    /// The token currently in force; race a blocked poll/future against `token().cancelled()`.
    #[must_use]
    pub fn token(&self) -> CancellationToken {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).token.clone()
    }

    /// The token currently in force along with its generation.
    ///
    /// A cached [`WaitForCancellationFutureOwned`] built from an older generation must be
    /// discarded and rebuilt rather than polled, since `set` can have swapped in a fresh,
    /// uncancelled token.
    #[must_use]
    pub fn token_with_generation(&self) -> (CancellationToken, u64) {
        let inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        (inner.token.clone(), inner.generation)
    }
}

#[cfg(test)]
mod deadline_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};
    use std::time::Duration;

    use std::net::SocketAddrV6;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn tcp_acceptor_close_rejects_the_next_accept_without_a_client() {
        let listener = TcpAcceptor::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        listener.close().unwrap();
        listener.close().unwrap();

        let err = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("closed accept must not block")
            .err()
            .expect("closed accept must fail");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn tcp_acceptor_close_interrupts_a_pending_accept_but_not_an_accepted_stream() {
        let listener = TcpAcceptor::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let mut client = TcpStream::connect(listener.addr().unwrap()).await.unwrap();
        let mut accepted = listener.accept().await.unwrap();
        let mut next = Box::pin(listener.accept());
        let wake_count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wake_count));
        let mut context = Context::from_waker(&waker);
        assert!(next.as_mut().poll(&mut context).is_pending());
        assert_eq!(wake_count.0.load(Ordering::SeqCst), 0);

        listener.close().unwrap();
        assert!(wake_count.0.load(Ordering::SeqCst) > 0, "close must wake the pending accept");
        let err = tokio::time::timeout(Duration::from_secs(1), next)
            .await
            .expect("pending accept must wake")
            .err()
            .expect("pending accept must fail");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        client.write_all(b"alive").await.unwrap();
        let mut received = [0; 5];
        tokio::time::timeout(Duration::from_secs(1), accepted.read_exact(&mut received))
            .await
            .expect("accepted stream must remain readable")
            .unwrap();
        assert_eq!(&received, b"alive");
        accepted.write_all(b"still").await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut received))
            .await
            .expect("accepted stream must remain writable")
            .unwrap();
        assert_eq!(&received, b"still");
    }

    #[tokio::test]
    async fn udp_acceptor_close_rejects_the_next_receive_without_a_packet() {
        let socket = UdpAcceptor::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        socket.close().unwrap();
        socket.close().unwrap();

        let err = tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut [0; 1]))
            .await
            .expect("closed receive must not block")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn udp_acceptor_close_interrupts_a_pending_receive() {
        let socket = UdpAcceptor::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut received = [0; 1];
        let mut pending = Box::pin(socket.recv_from(&mut received));
        let wake_count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wake_count));
        let mut context = Context::from_waker(&waker);
        assert!(pending.as_mut().poll(&mut context).is_pending());
        assert_eq!(wake_count.0.load(Ordering::SeqCst), 0);

        socket.close().unwrap();
        assert!(wake_count.0.load(Ordering::SeqCst) > 0, "close must wake the pending receive");
        let err = tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .expect("pending receive must wake")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn udp_acceptor_enhanced_receive_stops_after_close() {
        let socket: Arc<dyn Datagram> = Arc::new(UdpAcceptor::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()));
        let enhanced = crate::packet::datagram::new_enhance_datagram(Arc::clone(&socket));
        let pending = enhanced.wait_read_from();
        tokio::pin!(pending);
        assert!(futures::poll!(pending.as_mut()).is_pending());

        socket.close().unwrap();
        let (_, _, _, result) = tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .expect("enhanced receive must wake after close");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn cancellable_stream_unblocks_pending_read_from_another_task() {
        let (_writer, reader) = tokio::io::duplex(64);
        let mut cancellable = CancellableStream::new(reader);
        let read_deadline = cancellable.read_deadline();

        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            cancellable.read(&mut buf).await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        read_deadline.set(Some(Instant::now()));

        let err = read_task.await.unwrap().expect_err("cancelled read must error");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// Reproduces the review's split-halves probe: a `tokio::io::split` reader parked in one task
    /// and a writer parked in another must each get woken by their own deadline, not just whichever
    /// half happened to poll last.
    #[tokio::test]
    async fn cancellable_stream_wakes_both_split_halves_independently() {
        let (a, _b) = tokio::io::duplex(1);
        let cancellable = CancellableStream::new(a);
        let read_deadline = cancellable.read_deadline();
        let write_deadline = cancellable.write_deadline();
        let (mut read_half, mut write_half) = tokio::io::split(cancellable);

        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            read_half.read(&mut buf).await
        });
        // `_b`'s duplex buffer is 1 byte; the second write blocks with no reader draining it.
        let write_task = tokio::spawn(async move {
            write_half.write_all(b"xx").await?;
            write_half.write_all(b"yy").await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        read_deadline.set(Some(Instant::now()));
        write_deadline.set(Some(Instant::now()));

        let read_err = read_task.await.unwrap().expect_err("parked read must be cancelled");
        assert_eq!(read_err.kind(), io::ErrorKind::TimedOut);
        let write_err = write_task.await.unwrap().expect_err("parked write must be cancelled");
        assert_eq!(write_err.kind(), io::ErrorKind::TimedOut);
    }

    /// Reproduces the review's `BufWriter` probe: `poll_write` alone buffers and returns `Ready`,
    /// so only a flush that races the write deadline can unblock a peer that stopped reading.
    #[tokio::test]
    async fn cancellable_stream_flush_honours_write_deadline() {
        let (a, _b) = tokio::io::duplex(1);
        let cancellable = CancellableStream::new(a);
        let write_deadline = cancellable.write_deadline();
        let mut buffered = BufWriter::with_capacity(64, cancellable);

        buffered.write_all(&[0u8; 8]).await.unwrap();
        let flush_task = tokio::spawn(async move { buffered.flush().await });

        tokio::time::sleep(Duration::from_millis(20)).await;
        write_deadline.set(Some(Instant::now()));

        let err = tokio::time::timeout(Duration::from_secs(1), flush_task)
            .await
            .expect("flush must unblock once the write deadline fires")
            .unwrap()
            .expect_err("flush past the write deadline must error");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// Reproduces the review's interrupt-then-resume probe (`tunnel/tunnel.rs`'s peek-then-relay):
    /// `set_read_deadline(Some(now))` kicks a parked read, then `set_read_deadline(None)` must let
    /// the same stream keep reading normally, not fail forever.
    #[tokio::test]
    async fn cancellable_stream_read_deadline_rearms_after_clearing() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut cancellable = CancellableStream::new(reader);
        let read_deadline = cancellable.read_deadline();

        let mut buf = [0u8; 4];
        let read_task = tokio::spawn(async move {
            let n = cancellable.read(&mut buf).await;
            (cancellable, buf, n)
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        read_deadline.set(Some(Instant::now()));
        let (mut cancellable, _buf, n) = read_task.await.unwrap();
        assert_eq!(n.expect_err("interrupted read must error").kind(), io::ErrorKind::TimedOut);

        read_deadline.set(None);
        writer.write_all(b"ok").await.unwrap();
        let mut buf = [0u8; 2];
        cancellable.read_exact(&mut buf).await.expect("clearing the deadline must let reads resume");
        assert_eq!(&buf, b"ok");
    }

    #[tokio::test]
    async fn idle_timeout_resets_on_every_read() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut idle = IdleTimeout::new(reader, Duration::from_millis(80));

        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 1];
            for _ in 0..3 {
                idle.read_exact(&mut buf).await?;
            }
            idle.read(&mut buf).await
        });

        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(40)).await;
            writer.write_all(b"x").await.unwrap();
        }

        let err = read_task.await.unwrap().expect_err("idle stream must time out once writes stop");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// Reproduces the review's `IdleTimeout` `BufWriter` probe: a flush that blocks in the inner
    /// stream must still be covered by the idle timer, and must not itself reset it.
    #[tokio::test]
    async fn idle_timeout_flush_expires_and_does_not_reset() {
        let (a, _b) = tokio::io::duplex(1);
        let idle = IdleTimeout::new(a, Duration::from_millis(50));
        let mut buffered = BufWriter::with_capacity(64, idle);

        buffered.write_all(&[0u8; 8]).await.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(1), buffered.flush())
            .await
            .expect("flush must not hang past the idle timeout")
            .expect_err("flush blocked past the idle duration must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn shutdown_write_half_closes_a_tcp_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        client.shutdown_write().unwrap();

        let mut buf = [0u8; 8];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "server must observe EOF after the client half-closes its write side");

        server.write_all(b"still open").await.unwrap();
        let mut recv = [0u8; 16];
        let n = client.read(&mut recv).await.unwrap();
        assert_eq!(&recv[..n], b"still open", "client read side stays open after shutdown_write");
    }

    #[tokio::test]
    async fn deadline_token_reused_across_rearm_wakes_earlier_waiter() {
        let deadline = DeadlineToken::new();
        deadline.set(Some(Instant::now() + Duration::from_secs(60)));
        let armed = deadline.token();
        assert!(!armed.is_cancelled());

        let registered = armed.clone().cancelled_owned();
        tokio::pin!(registered);
        assert!(futures::future::FutureExt::now_or_never(&mut registered).is_none());

        deadline.set(Some(Instant::now() + Duration::from_millis(20)));

        tokio::time::timeout(Duration::from_millis(500), registered)
            .await
            .expect("token registered before the deadline was re-armed must still be cancelled");
    }

    #[tokio::test]
    async fn deadline_token_cleared_does_not_cancel() {
        let deadline = DeadlineToken::new();
        deadline.set(Some(Instant::now() + Duration::from_millis(20)));
        deadline.set(None);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(!deadline.token().is_cancelled(), "clearing the deadline must abort the pending timer");
    }

    /// Reproduces the review's wrapper-`Addr` probe: an `Addr` that only implements `addr_port`
    /// (like `Socksaddr`, or a wrapper that forwards it) must still convert, and a `SocketAddrV6`
    /// scope must round-trip through `UdpAddr`'s numeric zone in both directions.
    #[tokio::test]
    async fn old_addr_to_socket_addr_falls_back_to_addr_port() {
        #[derive(Debug)]
        struct AddrPortOnly(SocketAddr);
        impl Addr for AddrPortOnly {
            fn network(&self) -> &str {
                "udp"
            }
            fn string(&self) -> String {
                self.0.to_string()
            }
            fn addr_port(&self) -> Option<murmur_std_compat::net::AddrPort> {
                Some(murmur_std_compat::net::AddrPort { port: self.0.port(), ip: Some(self.0.ip()), fqdn: None })
            }
        }

        let want: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let got = old_addr_to_socket_addr(&AddrPortOnly(want)).expect("addr_port fallback must succeed");
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn old_addr_to_socket_addr_falls_back_to_display_string() {
        #[derive(Debug)]
        struct DisplayOnly(SocketAddr);
        impl Addr for DisplayOnly {
            fn network(&self) -> &str {
                "udp"
            }
            fn string(&self) -> String {
                self.0.to_string()
            }
        }

        let want: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        let got = old_addr_to_socket_addr(&DisplayOnly(want)).expect("Display fallback must succeed");
        assert_eq!(got, want);
    }

    #[test]
    fn udp_addr_zone_round_trips_through_socket_addr_v6_scope_id() {
        let addr: SocketAddr = "[fe80::1]:53".parse().unwrap();
        let with_scope = match addr {
            SocketAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(*v6.ip(), v6.port(), 0, 7)),
            SocketAddr::V4(_) => unreachable!(),
        };

        let udp = udp_addr_from_socket_addr(with_scope);
        assert_eq!(udp.zone, "7");

        let back = socket_addr_from_udp_addr(&udp);
        assert_eq!(back, with_scope);
    }

    /// Regression for `agent://ReviewNetS1`'s P1: the cached cancel future used to survive a
    /// completed read, so an interrupt-then-clear with no reader parked (a completed read, then
    /// `set(Some(now))`, then `set(None)`) made the *next* read fail `TimedOut` even with data
    /// ready — `tunnel/tunnel.rs`'s peek-then-relay ordering. Fails on be7f135f.
    #[tokio::test]
    async fn cancellable_stream_read_after_idle_interrupt_and_clear_succeeds() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut cancellable = CancellableStream::new(reader);
        let read_deadline = cancellable.read_deadline();

        writer.write_all(b"a").await.unwrap();
        let mut buf = [0u8; 1];
        cancellable.read_exact(&mut buf).await.unwrap();

        read_deadline.set(Some(Instant::now()));
        read_deadline.set(None);

        writer.write_all(b"b").await.unwrap();
        cancellable
            .read_exact(&mut buf)
            .await
            .expect("read after interrupt+clear with no reader parked must succeed, not reuse a stale cancel future");
    }

    /// Same P1, the expire-then-re-arm shape: a deadline that already fired while idle, then
    /// re-armed further out, must not leave the next read racing the fired future.
    #[tokio::test]
    async fn cancellable_stream_read_after_deadline_expires_idle_then_rearms_succeeds() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut cancellable = CancellableStream::new(reader);
        let read_deadline = cancellable.read_deadline();

        read_deadline.set(Some(Instant::now() + Duration::from_millis(20)));
        writer.write_all(b"a").await.unwrap();
        let mut buf = [0u8; 1];
        cancellable.read_exact(&mut buf).await.unwrap();

        tokio::time::sleep(Duration::from_millis(60)).await;
        read_deadline.set(Some(Instant::now() + Duration::from_secs(60)));

        writer.write_all(b"b").await.unwrap();
        cancellable
            .read_exact(&mut buf)
            .await
            .expect("read after re-arming an expired-while-idle deadline must succeed");
    }

    /// Same P1, write side: `poll_write`/`poll_flush`/`poll_shutdown` share the same bug.
    #[tokio::test]
    async fn cancellable_stream_write_after_idle_interrupt_and_clear_succeeds() {
        let (writer, mut reader) = tokio::io::duplex(64);
        let mut cancellable = CancellableStream::new(writer);
        let write_deadline = cancellable.write_deadline();

        cancellable.write_all(b"a").await.unwrap();
        write_deadline.set(Some(Instant::now()));
        write_deadline.set(None);

        cancellable.write_all(b"b").await.expect("write after interrupt+clear with no writer parked must succeed");
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ab");
    }

    /// Regression for `agent://ReviewNetS1`'s P3: `DeadlineToken::set`'s `abort()` cannot stop a
    /// timer already past `sleep_until` and inside its own `cancel()`, so a `set(None)` racing the
    /// fire used to leave the token cancelled 1 time in ~4000. The generation check under the same
    /// lock the timer uses makes a `clear` always win regardless of the race's outcome.
    ///
    /// Heavy: 4000 iterations, each spin-waiting on the real clock to land within microseconds of
    /// the timer's firing edge (a coarser `tokio::time::sleep`-based wait cannot hit that window,
    /// and pausing virtual time would remove the real race this test exists to catch), so it is
    /// not run on every gate. See `make test-heavy`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "heavy: 4000-iteration real-timer race soak, see make test-heavy"]
    async fn deadline_token_clear_always_wins_a_race_with_the_firing_timer() {
        let iters = 4000u32;
        for i in 0..iters {
            let deadline_token = DeadlineToken::new();
            let deadline = Instant::now() + Duration::from_micros(300);
            deadline_token.set(Some(deadline));
            let jitter = Duration::from_micros(u64::from(i % 1500));
            let until = deadline + jitter;
            while Instant::now() < until {
                std::hint::spin_loop();
            }
            deadline_token.set(None);
            tokio::time::sleep(Duration::from_millis(1)).await;
            assert!(
                !deadline_token.token().is_cancelled(),
                "iteration {i}: clearing the deadline must always win a race with an already-firing timer"
            );
        }
    }

    struct DxConn(tokio::io::DuplexStream);
    impl AsyncRead for DxConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for DxConn {
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
    impl Stream for DxConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }
    }

    /// Regression for `ReviewNetS0`'s deferred bug 6: `StreamAsOldConn::close()` used to only
    /// call `shutdown_read`/`shutdown_write`, which default to `Ok(())` for a non-socket
    /// [`Stream`] like `tokio::io::duplex` — a real close through the bridge was a silent no-op,
    /// so a parked read never woke up and later reads/writes kept working. `close()` must now
    /// interrupt a parked read (via the bridge's own [`DeadlineToken`]s) and keep failing every
    /// read/write after.
    #[tokio::test]
    async fn stream_as_old_conn_close_interrupts_a_parked_read_and_marks_closed() {
        let (_writer, reader) = tokio::io::duplex(64);
        let bridged: Box<dyn Conn> = Box::new(StreamAsOldConn::new(DxConn(reader)));
        let shared = murmur_common::shared_conn::SharedConn::from_boxed(bridged);

        let reading = shared.clone();
        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            reading.read(&mut buf).await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        shared.close().expect("close");

        let err = read_task
            .await
            .unwrap()
            .expect_err("close() on a non-socket Stream must interrupt a parked read, not silently do nothing");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        let mut buf = [0u8; 1];
        let reading_again = shared.clone();
        let after = reading_again.read(&mut buf).await;
        assert_eq!(
            after.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe,
            "reads must keep failing after close(), not silently succeed"
        );
    }

    /// Same bug 6: `set_read_deadline` was never overridden on the bridge, so it was the old
    /// `Conn` trait's default no-op — a deadline set through the bridge never fired. It must now
    /// be backed by a real [`DeadlineToken`], the same as [`CancellableStream`].
    #[tokio::test]
    async fn stream_as_old_conn_set_read_deadline_takes_effect() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut bridged = StreamAsOldConn::new(DxConn(reader));

        Conn::set_read_deadline(&bridged, Some(Instant::now() + Duration::from_millis(20))).unwrap();
        let mut buf = [0u8; 1];
        let err = bridged.read(&mut buf).await.expect_err("an armed read deadline on a non-socket Stream must fire");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        Conn::set_read_deadline(&bridged, None).unwrap();
        writer.write_all(b"x").await.unwrap();
        bridged.read_exact(&mut buf).await.expect("clearing the deadline must let reads resume");
        assert_eq!(buf[0], b'x');
    }

    /// A `Stream` can answer [`Stream::old_conn`] with `Some` for close/half-close purposes while
    /// that inner `Conn`'s own `set_read_deadline` (or `set_write_deadline`) stays the trait's
    /// no-op default for a direction it cannot itself enforce — e.g. a quic `ReceiveStream` half
    /// with no deadline setter of its own (`transport-tuic`/`transport-shadowquic`,
    /// `a456ec5e`'s split read/write locks). `CancellableStream` must still enforce that
    /// direction's deadline itself in that case: it always tries `inner` first every poll (so a
    /// genuinely deadline-aware `old_conn`, like tlsmirror/shadowtls/anytls's, resolves and tears
    /// its own state down first), but falls back to its own token once `inner` itself stays
    /// `Pending`.
    struct NoReadDeadlineConn(tokio::io::DuplexStream);
    impl AsyncRead for NoReadDeadlineConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for NoReadDeadlineConn {
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
    impl Conn for NoReadDeadlineConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(boxed_addr(TcpAddr::from("127.0.0.1:1".parse::<SocketAddr>().unwrap())))
        }
        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(boxed_addr(TcpAddr::from("127.0.0.1:2".parse::<SocketAddr>().unwrap())))
        }
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
        // `set_read_deadline` deliberately not overridden: stays the trait's no-op default.
    }
    impl Stream for NoReadDeadlineConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }
        fn old_conn(&self) -> Option<&dyn Conn> {
            Some(self)
        }
    }

    #[tokio::test]
    async fn stream_as_old_conn_read_deadline_still_enforced_when_old_conns_own_setter_is_a_no_op() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut bridged = StreamAsOldConn::new(NoReadDeadlineConn(reader));

        Conn::set_read_deadline(&bridged, Some(Instant::now() + Duration::from_millis(20))).unwrap();
        let mut buf = [0u8; 1];
        let err = bridged
            .read(&mut buf)
            .await
            .expect_err("must still time out even though old_conn's own set_read_deadline is a no-op");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        Conn::set_read_deadline(&bridged, None).unwrap();
        writer.write_all(b"x").await.unwrap();
        bridged.read_exact(&mut buf).await.expect("clearing the deadline must let reads resume");
        assert_eq!(buf[0], b'x');
    }

    /// Regression for `ReviewS11U1`: `SharedConnConn::close` on a bare `CancellableStream` (the
    /// `SharedConn::new(CancellableStream::new(stream))` path, with no `StreamAsOldConn` in
    /// between) used to carry no closed-latch of its own, so a `set_read_deadline` issued after
    /// `close()` re-armed the read token with a live deadline and silently un-closed the conn.
    #[tokio::test]
    async fn cancellable_stream_set_deadline_after_close_does_not_reopen_it() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut cancellable = CancellableStream::new(DxConn(reader));
        SharedConnConn::close(&cancellable).unwrap();

        let err = SharedConnConn::set_read_deadline(&cancellable, None)
            .expect_err("set_read_deadline after close() must not be able to re-open the conn");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        writer.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 1];
        let err = cancellable
            .read(&mut buf)
            .await
            .expect_err("reads must keep failing after close(), even once set_read_deadline is attempted again");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    /// Regression for `ReviewS11U1`: the same `SharedConnConn` impl forwarded a deadline to
    /// `old_conn` without [`CancellableStream::OLD_CONN_FALLBACK_GRACE`]'s delay, so its own
    /// fallback token could fire at the exact requested instant instead of `OLD_CONN_FALLBACK_GRACE`
    /// later — the same race `StreamAsOldConn::set_deadline`'s grace exists to avoid, but skipped
    /// on this path. With an `old_conn` whose own read-deadline setter is a no-op
    /// ([`NoReadDeadlineConn`]), only the fallback token ever fires, so its firing time directly
    /// exposes whether the grace was applied.
    #[tokio::test]
    async fn cancellable_stream_set_read_deadline_delays_fallback_by_the_grace_when_forwarding() {
        let (_writer, reader) = tokio::io::duplex(64);
        let mut cancellable = CancellableStream::new(NoReadDeadlineConn(reader));

        let armed_at = Instant::now();
        SharedConnConn::set_read_deadline(&cancellable, Some(armed_at + Duration::from_millis(20))).unwrap();
        let mut buf = [0u8; 1];
        let err = cancellable.read(&mut buf).await.expect_err("must still time out via the fallback token");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            armed_at.elapsed() >= Duration::from_millis(30),
            "fallback must fire at least OLD_CONN_FALLBACK_GRACE after the requested deadline, not exactly at it: \
             elapsed {:?}",
            armed_at.elapsed()
        );
    }
}
