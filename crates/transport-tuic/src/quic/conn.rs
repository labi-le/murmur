//! `quinn` connections and streams behind the [`super::Conn`] surface.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_quic::{
    ApplicationErrorCode, Config, ConnectionState, ConnectionStats, JlsState, ReceiveStream, SendStream, Stream,
    StreamErrorCode, StreamId, StreamReadHalf, StreamWriteHalf, TlsConnectionState,
};
use murmur_std_compat::net::{Addr, UdpAddr};

use super::Conn;

/// Suspends the poll on an armed stream deadline and surfaces an elapsed one the way the
/// deadline setters do: `Pending` while the timer runs, `TimedOut` once it
/// fires, and no error when no deadline is set.
macro_rules! poll_deadline {
    ($deadline:expr, $cx:expr) => {{
        let expired = {
            let mut deadline = $deadline.lock();
            ready!(deadline.poll_expired($cx))
        };
        match expired {
            Ok(()) => {}
            Err(err) => return Poll::Ready(Err(err)),
        }
    }};
}

/// A deadline armed through `set_read_deadline`/`set_write_deadline`. `quinn` 0.11 dropped the
/// per-stream deadline setters, so they are enforced here. The
/// `Mutex` around it is what lets a `&self` setter reach the state.
struct Deadline {
    at: Option<tokio::time::Instant>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Deadline {
    const fn new() -> Self {
        Self { at: None, sleep: None }
    }

    fn set(&mut self, at: Option<tokio::time::Instant>) {
        self.at = at;
        self.sleep = at.map(|at| Box::pin(tokio::time::sleep_until(at)));
    }

    /// Cancel-safe: it only registers a waker on a timer and never touches connection state.
    fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(at) = self.at else { return Poll::Ready(Ok(())) };
        let sleep = self.sleep.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
        match Future::poll(sleep.as_mut(), cx) {
            Poll::Ready(()) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "quic stream deadline exceeded")))
            }
            Poll::Pending => Poll::Ready(Ok(())),
        }
    }
}

struct SendHalf {
    stream: quinn::SendStream,
    deadline: Mutex<Deadline>,
}

struct RecvHalf {
    stream: quinn::RecvStream,
    deadline: Mutex<Deadline>,
}

impl SendHalf {
    fn new(stream: quinn::SendStream) -> Self {
        Self { stream, deadline: Mutex::new(Deadline::new()) }
    }
}

impl RecvHalf {
    fn new(stream: quinn::RecvStream) -> Self {
        Self { stream, deadline: Mutex::new(Deadline::new()) }
    }
}

pub(crate) struct QuinnConn {
    connection: quinn::Connection,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    config: Config,
    max_datagram_frame_size: i64,
    closed: CancellationToken,
}

impl QuinnConn {
    pub(crate) fn new(
        connection: quinn::Connection,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: Config,
    ) -> Self {
        let closed = CancellationToken::new();
        let token = closed.clone();
        let watched = connection.clone();
        tokio::spawn(async move {
            watched.closed().await;
            token.cancel();
        });
        let max_datagram_frame_size = config.max_datagram_frame_size;
        Self { connection, local_addr, remote_addr, config, max_datagram_frame_size, closed }
    }
}

fn stream_id(id: quinn::StreamId) -> StreamId {
    // quinn numbers a stream as bit 0 initiator, bit 1 direction and the rest the index, so the
    // raw value is what `StreamId` holds.
    i64::try_from(u64::from(id)).unwrap_or(i64::MAX)
}

fn addr(socket_addr: SocketAddr) -> Box<dyn Addr> {
    Box::new(UdpAddr::from(socket_addr))
}

fn var_int(code: StreamErrorCode) -> quinn::VarInt {
    // A stream error code that does not fit a varint cannot be put on the wire at all; quinn's
    // `VarInt::from_u32` saturates the same way the `StreamErrorCode` conversion does.
    quinn::VarInt::from_u32(u32::try_from(code).unwrap_or(u32::MAX))
}

fn closed_stream() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "quic stream is closed")
}

#[async_trait]
impl Conn for QuinnConn {
    fn local_addr(&self) -> Box<dyn Addr> {
        addr(self.local_addr)
    }

    fn remote_addr(&self) -> Box<dyn Addr> {
        addr(self.remote_addr)
    }

    fn close_with_error(&self, code: ApplicationErrorCode, reason: &str) -> anyhow::Result<()> {
        let code = u32::try_from(code)
            .map_err(|_| anyhow::anyhow!("tuic: application error code {code} does not fit QUIC's 32-bit varint"))?;
        self.connection.close(quinn::VarInt::from_u32(code), reason.as_bytes());
        Ok(())
    }

    fn config(&self) -> Config {
        self.config.clone()
    }

    fn connection_stats(&self) -> ConnectionStats {
        let stats = self.connection.stats();
        ConnectionStats {
            packets_lost: stats.path.lost_packets,
            packets_sent: stats.path.sent_packets,
            smoothed_rtt: stats.path.rtt,
            latest_rtt: self.connection.rtt(),
            current_mtu: stats.path.current_mtu,
        }
    }

    fn connection_state(&self) -> ConnectionState {
        // There is no JLS handshake here, so `tls.jls` keeps its `Disabled` default.
        ConnectionState { tls: TlsConnectionState { jls: JlsState::default() } }
    }

    fn context(&self) -> CancellationToken {
        self.closed.clone()
    }

    // cancel-safe: it never waits; a dropped future leaves nothing behind.
    async fn handshake_complete(&self) {}

    fn export_keying_material(&self, label: &[u8], context: &[u8], length: usize) -> anyhow::Result<Vec<u8>> {
        let mut output = vec![0u8; length];
        self.connection
            .export_keying_material(&mut output, label, context)
            .map_err(|err| anyhow::anyhow!("tuic: export keying material: {err:?}"))?;
        Ok(output)
    }

    /// Cancel-safe: quinn's `open_bi` is cancel-safe — dropping it before it resolves opens no
    /// stream — and the `select!` arm only cancels the wait.
    async fn open_stream(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn Stream>> {
        let (send, recv) = tokio::select! {
            () = ctx.cancelled() => anyhow::bail!("tuic: open stream cancelled"),
            opened = self.connection.open_bi() => opened?,
        };
        Ok(Box::new(QuinnStream { send: Mutex::new(SendHalf::new(send)), recv: Mutex::new(RecvHalf::new(recv)) }))
    }

    /// Cancel-safe: as [`Conn::open_stream`].
    async fn open_uni_stream(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn SendStream>> {
        let send = tokio::select! {
            () = ctx.cancelled() => anyhow::bail!("tuic: open uni stream cancelled"),
            opened = self.connection.open_uni() => opened?,
        };
        Ok(Box::new(QuinnSendStream { send: Mutex::new(SendHalf::new(send)) }))
    }

    /// Cancel-safe: quinn's `accept_bi` is cancel-safe — an unconsumed incoming stream stays
    /// queued for the next call.
    async fn accept_stream(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn Stream>> {
        let (send, recv) = tokio::select! {
            () = ctx.cancelled() => anyhow::bail!("tuic: accept stream cancelled"),
            accepted = self.connection.accept_bi() => accepted?,
        };
        Ok(Box::new(QuinnStream { send: Mutex::new(SendHalf::new(send)), recv: Mutex::new(RecvHalf::new(recv)) }))
    }

    /// Cancel-safe: as [`Conn::accept_stream`].
    async fn accept_uni_stream(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn ReceiveStream>> {
        let recv = tokio::select! {
            () = ctx.cancelled() => anyhow::bail!("tuic: accept uni stream cancelled"),
            accepted = self.connection.accept_uni() => accepted?,
        };
        Ok(Box::new(QuinnRecvStream { recv: Mutex::new(RecvHalf::new(recv)) }))
    }

    fn send_datagram(&self, data: &[u8]) -> anyhow::Result<()> {
        let len = i64::try_from(data.len())
            .map_err(|_| anyhow::anyhow!("tuic: datagram of {} bytes exceeds the QUIC limit", data.len()))?;
        if self.max_datagram_frame_size > 0 && len > self.max_datagram_frame_size {
            return Err(
                murmur_quic::DatagramTooLargeError { max_datagram_payload_size: self.max_datagram_frame_size }.into()
            );
        }
        self.connection.send_datagram(Bytes::copy_from_slice(data)).map_err(|err| anyhow::anyhow!("tuic: {err}"))
    }

    /// Cancel-safe: quinn's `read_datagram` is cancel-safe — an unconsumed datagram stays queued.
    async fn receive_datagram(&self, ctx: &CancellationToken) -> anyhow::Result<Vec<u8>> {
        let datagram = tokio::select! {
            () = ctx.cancelled() => anyhow::bail!("tuic: receive datagram cancelled"),
            received = self.connection.read_datagram() => received?,
        };
        Ok(datagram.to_vec())
    }
}

struct QuinnStream {
    send: Mutex<SendHalf>,
    recv: Mutex<RecvHalf>,
}

impl AsyncRead for QuinnStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut recv = self.get_mut().recv.lock();
        poll_deadline!(recv.deadline, cx);
        Pin::new(&mut recv.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuinnStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut send = self.get_mut().send.lock();
        poll_deadline!(send.deadline, cx);
        Pin::new(&mut send.stream).poll_write(cx, buf).map_err(|err| io::Error::other(err.to_string()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut send = self.get_mut().send.lock();
        poll_deadline!(send.deadline, cx);
        Pin::new(&mut send.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut send = self.get_mut().send.lock();
        poll_deadline!(send.deadline, cx);
        Pin::new(&mut send.stream).poll_shutdown(cx)
    }
}

impl Stream for QuinnStream {
    fn stream_id(&self) -> StreamId {
        stream_id(self.send.lock().stream.id())
    }

    fn cancel_read(&self, error_code: StreamErrorCode) {
        let _ = self.recv.lock().stream.stop(var_int(error_code));
    }

    fn cancel_write(&self, error_code: StreamErrorCode) {
        let _ = self.send.lock().stream.reset(var_int(error_code));
    }

    fn close(&self) -> io::Result<()> {
        self.send.lock().stream.finish().map_err(|_| closed_stream())
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.recv.lock().deadline.lock().set(deadline);
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.send.lock().deadline.lock().set(deadline);
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.set_read_deadline(deadline)?;
        self.set_write_deadline(deadline)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamReadHalf>, Box<dyn StreamWriteHalf>) {
        let recv = Mutex::into_inner(self.recv);
        let send = Mutex::into_inner(self.send);
        (Box::new(QuinnStreamReadHalf(Mutex::new(recv))), Box::new(QuinnStreamWriteHalf(Mutex::new(send))))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct QuinnStreamReadHalf(Mutex<RecvHalf>);

impl AsyncRead for QuinnStreamReadHalf {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut recv = self.get_mut().0.lock();
        poll_deadline!(recv.deadline, cx);
        Pin::new(&mut recv.stream).poll_read(cx, buf)
    }
}

impl StreamReadHalf for QuinnStreamReadHalf {
    fn cancel_read(&self, error_code: StreamErrorCode) {
        let _ = self.0.lock().stream.stop(var_int(error_code));
    }
}

struct QuinnStreamWriteHalf(Mutex<SendHalf>);

impl AsyncWrite for QuinnStreamWriteHalf {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut send = self.get_mut().0.lock();
        poll_deadline!(send.deadline, cx);
        Pin::new(&mut send.stream).poll_write(cx, buf).map_err(|err| io::Error::other(err.to_string()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut send = self.get_mut().0.lock();
        poll_deadline!(send.deadline, cx);
        Pin::new(&mut send.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut send = self.get_mut().0.lock();
        poll_deadline!(send.deadline, cx);
        Pin::new(&mut send.stream).poll_shutdown(cx)
    }
}

impl StreamWriteHalf for QuinnStreamWriteHalf {
    fn close(&self) -> io::Result<()> {
        self.0.lock().stream.finish().map_err(|_| closed_stream())
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.lock().deadline.lock().set(deadline);
        Ok(())
    }
}

struct QuinnSendStream {
    send: Mutex<SendHalf>,
}

impl AsyncWrite for QuinnSendStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut send = self.get_mut().send.lock();
        poll_deadline!(send.deadline, cx);
        Pin::new(&mut send.stream).poll_write(cx, buf).map_err(|err| io::Error::other(err.to_string()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut send = self.get_mut().send.lock();
        poll_deadline!(send.deadline, cx);
        Pin::new(&mut send.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut send = self.get_mut().send.lock();
        poll_deadline!(send.deadline, cx);
        Pin::new(&mut send.stream).poll_shutdown(cx)
    }
}

impl SendStream for QuinnSendStream {
    fn stream_id(&self) -> StreamId {
        stream_id(self.send.lock().stream.id())
    }

    fn cancel_write(&self, error_code: StreamErrorCode) {
        let _ = self.send.lock().stream.reset(var_int(error_code));
    }

    fn close(&self) -> io::Result<()> {
        self.send.lock().stream.finish().map_err(|_| closed_stream())
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.send.lock().deadline.lock().set(deadline);
        Ok(())
    }
}

struct QuinnRecvStream {
    recv: Mutex<RecvHalf>,
}

impl AsyncRead for QuinnRecvStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut recv = self.get_mut().recv.lock();
        poll_deadline!(recv.deadline, cx);
        Pin::new(&mut recv.stream).poll_read(cx, buf)
    }
}

impl ReceiveStream for QuinnRecvStream {
    fn stream_id(&self) -> StreamId {
        stream_id(self.recv.lock().stream.id())
    }

    fn cancel_read(&self, error_code: StreamErrorCode) {
        let _ = self.recv.lock().stream.stop(var_int(error_code));
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.recv.lock().deadline.lock().set(deadline);
        Ok(())
    }
}
