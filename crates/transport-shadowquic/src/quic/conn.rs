//! `quinn` connections and endpoints behind the surface `transport/shadowquic` drives.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use murmur_common_net::io::old_addr_to_socket_addr;
use murmur_jls_tls::{JlsStatus as TlsJlsStatus, ServerConfig as JlsServerConfig};
use murmur_log::debugln;
use murmur_quic::jls::{congestion::CongestionControlEx, Conn, EarlyListener, Transport, TransportFactory};
use murmur_quic::{
    ApplicationErrorCode, Config, ConnectionState, ConnectionStats, JlsState, JlsStatus, ReceiveStream, SendStream,
    Stream, StreamErrorCode, StreamId, StreamReadHalf, StreamWriteHalf, TlsConfig, TlsConnectionState,
};
use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};
use parking_lot::Mutex;
use quinn::{SendDatagramError, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use super::crypto::{JlsHandshakeData, JlsQuicClientConfig, JlsQuicServerConfig};
use super::deadline::Deadline;
use super::socket::PacketConnSocket;
use super::CongestionOption;

/// The datagram-too-large error, reported when a datagram exceeds the configured maximum frame
/// size.
#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("DATAGRAM frame too large (maximum: {max_datagram_payload_size} bytes)")]
pub(super) struct DatagramTooLarge {
    pub max_datagram_payload_size: i64,
}

fn timed_out(direction: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{direction} deadline exceeded"))
}

fn closed_stream() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "stream already closed")
}

/// A stream error reaches the caller as the peer's `STOP_SENDING`/`RESET_STREAM` code, the value
/// the stream error carries. quinn's remaining variants are local states of the same
/// stream, and are reported as a bare stream error too.
fn stream_error(code: VarInt) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, format!("stream error {}", u64::from(code)))
}

/// The wire-level JLS status, which `murmur_jls_tls` and `murmur_quic` each declare
/// for the same wire-level states.
fn jls_status(status: TlsJlsStatus) -> JlsStatus {
    match status {
        TlsJlsStatus::Disabled => JlsStatus::Disabled,
        TlsJlsStatus::Unauthenticated => JlsStatus::Unauthenticated,
        TlsJlsStatus::Authenticated => JlsStatus::Authenticated,
    }
}

fn read_error(err: quinn::ReadError) -> io::Error {
    match err {
        quinn::ReadError::Reset(code) => stream_error(code),
        quinn::ReadError::ConnectionLost(err) => io::Error::new(io::ErrorKind::NotConnected, err),
        quinn::ReadError::ClosedStream => closed_stream(),
        quinn::ReadError::IllegalOrderedRead => io::Error::new(io::ErrorKind::InvalidData, "out-of-order stream read"),
        quinn::ReadError::ZeroRttRejected => {
            io::Error::new(io::ErrorKind::ConnectionReset, "0-RTT rejected by the server")
        }
    }
}

fn write_error(err: quinn::WriteError) -> io::Error {
    match err {
        quinn::WriteError::Stopped(code) => stream_error(code),
        quinn::WriteError::ConnectionLost(err) => io::Error::new(io::ErrorKind::NotConnected, err),
        quinn::WriteError::ClosedStream => closed_stream(),
        quinn::WriteError::ZeroRttRejected => {
            io::Error::new(io::ErrorKind::ConnectionReset, "0-RTT rejected by the server")
        }
    }
}

/// quinn numbers streams with the standard bit layout (bit 0 initiator, bit 1 direction,
/// the rest the index), so the raw varint is what the `StreamId` holds.
fn stream_id(id: quinn::StreamId) -> StreamId {
    i64::try_from(u64::from(id)).unwrap_or_default()
}

fn error_code(code: StreamErrorCode) -> VarInt {
    VarInt::from_u64(code).unwrap_or(VarInt::MAX)
}

pub(crate) struct QuinnConn {
    connection: quinn::Connection,
    /// The local address is that of the packet conn the transport was built
    /// over rather than quinn's own view of the path, so it comes from the socket.
    local_addr: SocketAddr,
    config: Config,
    closed: CancellationToken,
    /// The endpoint that owns this connection's socket, when the dial built one. quinn drives
    /// all I/O through the endpoint, so it has to outlive the connection or nothing moves; the
    /// field is never read because holding it is the whole point.
    _endpoint: Option<quinn::Endpoint>,
}

impl QuinnConn {
    pub(crate) fn new(
        connection: quinn::Connection,
        local_addr: SocketAddr,
        config: Config,
        endpoint: Option<quinn::Endpoint>,
    ) -> Self {
        let closed = CancellationToken::new();
        let token = closed.clone();
        let watched = connection.clone();
        let teardown = endpoint.clone();
        tokio::spawn(async move {
            watched.closed().await;
            token.cancel();
            // The transport is torn down once its connection is gone; quinn's equivalent is
            // closing the endpoint the dial built for that one connection.
            if let Some(endpoint) = teardown {
                endpoint.close(VarInt::from_u32(0), b"");
            }
        });
        Self { connection, local_addr, config, closed, _endpoint: endpoint }
    }

    fn jls_state(&self) -> JlsState {
        match self.connection.handshake_data().and_then(|data| data.downcast::<JlsHandshakeData>().ok()) {
            Some(data) => JlsState { status: jls_status(data.status), user: data.user },
            None => JlsState::default(),
        }
    }

    fn addr(socket_addr: SocketAddr) -> Box<dyn Addr> {
        Box::new(UdpAddr::from(socket_addr))
    }
}

#[async_trait]
impl Conn for QuinnConn {
    fn closed(&self) -> CancellationToken {
        self.closed.clone()
    }

    // cancel-safe: the only state these waits touch is quinn's own stream credit, which a
    // dropped future leaves exactly as the peer's stream limits describe it.
    async fn open_stream_sync(&self, ctx: &CancellationToken) -> Result<Box<dyn Stream>> {
        let (send, recv) = tokio::select! {
            () = ctx.cancelled() => anyhow::bail!("shadowquic: open stream cancelled"),
            opened = self.connection.open_bi() => opened?,
        };
        Ok(Box::new(QuinnStream::new(send, recv)))
    }

    // cancel-safe: as `open_stream_sync`.
    async fn open_uni_stream_sync(&self, ctx: &CancellationToken) -> Result<Box<dyn SendStream>> {
        let send = tokio::select! {
            () = ctx.cancelled() => anyhow::bail!("shadowquic: open stream cancelled"),
            opened = self.connection.open_uni() => opened?,
        };
        Ok(Box::new(QuinnSendStream::new(send)))
    }

    // cancel-safe: an accepted stream that the cancelled wait never took stays queued in quinn.
    async fn accept_stream(&self, ctx: &CancellationToken) -> Result<Box<dyn Stream>> {
        let (send, recv) = tokio::select! {
            () = ctx.cancelled() => anyhow::bail!("shadowquic: accept stream cancelled"),
            accepted = self.connection.accept_bi() => accepted?,
        };
        Ok(Box::new(QuinnStream::new(send, recv)))
    }

    // cancel-safe: as `accept_stream`.
    async fn accept_uni_stream(&self, ctx: &CancellationToken) -> Result<Box<dyn ReceiveStream>> {
        let recv = tokio::select! {
            () = ctx.cancelled() => anyhow::bail!("shadowquic: accept stream cancelled"),
            accepted = self.connection.accept_uni() => accepted?,
        };
        Ok(Box::new(QuinnRecvStream::new(recv)))
    }

    fn local_addr(&self) -> Box<dyn Addr> {
        Self::addr(self.local_addr)
    }

    fn remote_addr(&self) -> Box<dyn Addr> {
        Self::addr(self.connection.remote_address())
    }

    fn close_with_error(&self, code: ApplicationErrorCode, message: &str) -> io::Result<()> {
        self.connection.close(VarInt::from_u64(code).unwrap_or(VarInt::MAX), message.as_bytes());
        Ok(())
    }

    fn config(&self) -> Config {
        self.config.clone()
    }

    fn set_congestion_control(&self, _cc: Box<dyn CongestionControlEx>) {
        // quinn picks a congestion controller from the endpoint's `TransportConfig` when a
        // connection is created and offers no way to swap it afterwards, so setting the
        // congestion controller — and with it the Brutal rate negotiated over the
        // `murmur-brutal` extension — has no effect on an established connection here. The
        // `congestion-controller` option itself is honoured through `TransportConfig`.
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
        ConnectionState { tls: TlsConnectionState { jls: self.jls_state() } }
    }

    // cancel-safe: `Connection::read_datagram` only yields a datagram it has already taken off the
    // socket, and quinn drops an unconsumed one either way.
    async fn receive_datagram(&self, ctx: &CancellationToken) -> Result<Vec<u8>> {
        let data = tokio::select! {
            () = ctx.cancelled() => anyhow::bail!("shadowquic: receive datagram cancelled"),
            data = self.connection.read_datagram() => data?,
        };
        Ok(data.to_vec())
    }

    fn send_datagram(&self, data: Vec<u8>) -> Result<()> {
        let configured = self.config.max_datagram_frame_size;
        if configured > 0 && i64::try_from(data.len()).unwrap_or(i64::MAX) > configured {
            return Err(DatagramTooLarge { max_datagram_payload_size: configured }.into());
        }
        match self.connection.send_datagram(Bytes::from(data)) {
            Ok(()) => Ok(()),
            Err(SendDatagramError::TooLarge) => {
                let limit = i64::try_from(self.connection.max_datagram_size().unwrap_or_default()).unwrap_or_default();
                Err(DatagramTooLarge { max_datagram_payload_size: limit }.into())
            }
            Err(SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled) => {
                Err(anyhow::anyhow!("shadowquic: datagrams are not enabled on this connection"))
            }
            Err(err) => Err(anyhow::anyhow!("shadowquic: {err}")),
        }
    }
}

/// A `quinn` stream adapted to the stream surface this crate exposes.
///
/// The `&self` surface needs interior mutability: each
/// direction carries a lock taken only for the duration of one non-blocking operation, which is
/// the "one concurrent reader, one concurrent writer" rule a QUIC stream follows.
struct QuinnStream {
    send: Mutex<quinn::SendStream>,
    recv: Mutex<quinn::RecvStream>,
    read_deadline: Deadline,
    write_deadline: Deadline,
}

impl QuinnStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            read_deadline: Deadline::new(),
            write_deadline: Deadline::new(),
        }
    }
}

impl AsyncRead for QuinnStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_deadline.expired(cx) {
            return Poll::Ready(Err(timed_out("read")));
        }
        this.recv.lock().poll_read_buf(cx, buf).map_err(read_error)
    }
}

impl AsyncWrite for QuinnStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_deadline.expired(cx) {
            return Poll::Ready(Err(timed_out("write")));
        }
        Pin::new(&mut *this.send.lock()).poll_write(cx, buf).map_err(write_error)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().send.lock()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().send.lock()).poll_shutdown(cx)
    }
}

impl Stream for QuinnStream {
    fn stream_id(&self) -> StreamId {
        stream_id(self.send.lock().id())
    }

    fn cancel_read(&self, code: StreamErrorCode) {
        self.recv.lock().stop(error_code(code)).ok();
    }

    fn cancel_write(&self, code: StreamErrorCode) {
        self.send.lock().reset(error_code(code)).ok();
    }

    /// Closes the send direction only; the receive direction stays open
    /// until the peer finishes with it or the stream is reset.
    fn close(&self) -> io::Result<()> {
        self.send.lock().finish().map_err(|_| closed_stream())
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.read_deadline.set(deadline);
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.write_deadline.set(deadline);
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.set_read_deadline(deadline)?;
        self.set_write_deadline(deadline)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamReadHalf>, Box<dyn StreamWriteHalf>) {
        let Self { send, recv, read_deadline, write_deadline } = *self;
        (
            Box::new(QuinnStreamReadHalf { recv, deadline: read_deadline }),
            Box::new(QuinnStreamWriteHalf { send, deadline: write_deadline }),
        )
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct QuinnSendStream {
    send: Mutex<quinn::SendStream>,
    deadline: Deadline,
}

impl QuinnSendStream {
    fn new(send: quinn::SendStream) -> Self {
        Self { send: Mutex::new(send), deadline: Deadline::new() }
    }
}

impl AsyncWrite for QuinnSendStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.deadline.expired(cx) {
            return Poll::Ready(Err(timed_out("write")));
        }
        Pin::new(&mut *this.send.lock()).poll_write(cx, buf).map_err(write_error)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().send.lock()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().send.lock()).poll_shutdown(cx)
    }
}

impl SendStream for QuinnSendStream {
    fn stream_id(&self) -> StreamId {
        stream_id(self.send.lock().id())
    }

    fn cancel_write(&self, code: StreamErrorCode) {
        self.send.lock().reset(error_code(code)).ok();
    }

    fn close(&self) -> io::Result<()> {
        self.send.lock().finish().map_err(|_| closed_stream())
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.deadline.set(deadline);
        Ok(())
    }
}

struct QuinnRecvStream {
    recv: Mutex<quinn::RecvStream>,
    deadline: Deadline,
}

impl QuinnRecvStream {
    fn new(recv: quinn::RecvStream) -> Self {
        Self { recv: Mutex::new(recv), deadline: Deadline::new() }
    }
}

impl AsyncRead for QuinnRecvStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.deadline.expired(cx) {
            return Poll::Ready(Err(timed_out("read")));
        }
        this.recv.lock().poll_read_buf(cx, buf).map_err(read_error)
    }
}

impl ReceiveStream for QuinnRecvStream {
    fn stream_id(&self) -> StreamId {
        stream_id(self.recv.lock().id())
    }

    fn cancel_read(&self, code: StreamErrorCode) {
        self.recv.lock().stop(error_code(code)).ok();
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.deadline.set(deadline);
        Ok(())
    }
}

struct QuinnStreamReadHalf {
    recv: Mutex<quinn::RecvStream>,
    deadline: Deadline,
}

impl AsyncRead for QuinnStreamReadHalf {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.deadline.expired(cx) {
            return Poll::Ready(Err(timed_out("read")));
        }
        this.recv.lock().poll_read_buf(cx, buf).map_err(read_error)
    }
}

impl StreamReadHalf for QuinnStreamReadHalf {
    fn cancel_read(&self, code: StreamErrorCode) {
        self.recv.lock().stop(error_code(code)).ok();
    }
}

struct QuinnStreamWriteHalf {
    send: Mutex<quinn::SendStream>,
    deadline: Deadline,
}

impl AsyncWrite for QuinnStreamWriteHalf {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.deadline.expired(cx) {
            return Poll::Ready(Err(timed_out("write")));
        }
        Pin::new(&mut *this.send.lock()).poll_write(cx, buf).map_err(write_error)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().send.lock()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().send.lock()).poll_shutdown(cx)
    }
}

impl StreamWriteHalf for QuinnStreamWriteHalf {
    fn close(&self) -> io::Result<()> {
        self.send.lock().finish().map_err(|_| closed_stream())
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.deadline.set(deadline);
        Ok(())
    }
}

/// A bound early listener: a `quinn` endpoint whose connections complete a JLS handshake.
pub(crate) struct QuinnListener {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
    config: Config,
}

impl QuinnListener {
    /// Binds the endpoint over the caller's packet
    /// conn; the JLS handshake itself runs per accepted connection.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the crate-internal constructor takes the endpoint's congestion selection by value; `quic/mod.rs`'s `listen_early` hands its own parameter straight over"
    )]
    pub(crate) fn new(
        packet_conn: Box<dyn PacketConn>,
        tls: Arc<JlsServerConfig>,
        config: Config,
        congestion: CongestionOption,
    ) -> Result<Arc<Self>> {
        let socket = PacketConnSocket::new(Arc::from(packet_conn))?;
        let local_addr = quinn::AsyncUdpSocket::local_addr(socket.as_ref())?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(JlsQuicServerConfig::new(tls, config.allow_0rtt)));
        server.transport_config(Arc::new(transport_config(&config, &congestion)));
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config(&config),
            Some(server),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        Ok(Arc::new(Self { endpoint, local_addr, config }))
    }
}

#[async_trait]
impl EarlyListener for QuinnListener {
    // cancel-safe: the loop carries no state between iterations, and a handshake that is dropped
    // mid-flight is discarded by quinn like any other unaccepted connection.
    async fn accept(&self, ctx: &CancellationToken) -> Result<Arc<dyn Conn>> {
        loop {
            let incoming = tokio::select! {
                () = ctx.cancelled() => anyhow::bail!("shadowquic: listener closed"),
                incoming = self.endpoint.accept() => incoming,
            };
            let Some(incoming) = incoming else {
                anyhow::bail!("shadowquic: endpoint closed");
            };
            let Ok(connecting) = incoming.accept() else { continue };
            match connecting.await {
                Ok(connection) => {
                    return Ok(Arc::new(QuinnConn::new(connection, self.local_addr, self.config.clone(), None)))
                }
                // A handshake that never authenticates is dropped here: the JLS credentials are
                // checked inside the handshake, so nothing unauthenticated reaches the handlers.
                Err(err) => debugln!("ShadowQuic handshake failed: {err}"),
            }
        }
    }

    fn close(&self) -> io::Result<()> {
        self.endpoint.close(VarInt::from_u32(0), b"");
        Ok(())
    }
}

/// The JLS credentials and server name every connection this transport factory builds shares.
pub(crate) struct TransportInner {
    crypto: Arc<JlsQuicClientConfig>,
    server_name: String,
}

/// A transport: one packet conn, one endpoint,
/// and the JLS credentials the handshake authenticates with. The config is not held here
/// because the dial takes one per call, and `dial_quic` supplies the same one.
pub(crate) struct QuinnTransportFactory {
    inner: Arc<TransportInner>,
    congestion: CongestionOption,
}

impl QuinnTransportFactory {
    pub(crate) fn new(
        crypto: Arc<JlsQuicClientConfig>,
        server_name: String,
        congestion: CongestionOption,
    ) -> Arc<Self> {
        Arc::new(Self { inner: Arc::new(TransportInner { crypto, server_name }), congestion })
    }
}

impl TransportFactory for QuinnTransportFactory {
    fn new_transport(&self, conn: Arc<dyn PacketConn>, _connection_id_length: i32) -> Box<dyn Transport> {
        Box::new(QuinnTransport { conn, inner: Arc::clone(&self.inner), congestion: self.congestion.clone() })
    }
}

pub(crate) struct QuinnTransport {
    conn: Arc<dyn PacketConn>,
    inner: Arc<TransportInner>,
    congestion: CongestionOption,
}

#[async_trait]
impl Transport for QuinnTransport {
    fn set_created_conn(&self, _created_conn: bool) {
        // Setting this says the transport owns the packet conn of the
        // connections it creates, and `dial_quic` already keeps that conn alive alongside the
        // connection it hands back, so there is nothing left to record here.
    }

    fn set_single_use(&self, _single_use: bool) {
        // One transport can serve several dials and is torn down after the first when
        // single-use is set. Every dial here builds its own endpoint and hands it to its
        // connection, so both cases already behave the same way.
    }

    // cancel-safe: on cancellation `connect` closes the endpoint it built and drops the
    // half-open connection, reachable through the connection's own closed future.
    async fn dial(
        &self,
        ctx: &CancellationToken,
        addr: &UdpAddr,
        _tls_conf: &dyn TlsConfig,
        conf: &Config,
    ) -> Result<Arc<dyn Conn>> {
        self.connect(ctx, addr, conf).await
    }

    // cancel-safe: as `dial`, and a ticket the config kept lets quinn hand the connection back
    // before the handshake finishes, which is what `dial_early` does.
    async fn dial_early(
        &self,
        ctx: &CancellationToken,
        addr: &UdpAddr,
        _tls_conf: &dyn TlsConfig,
        conf: &Config,
    ) -> Result<Arc<dyn Conn>> {
        let (endpoint, connecting, local_addr) = self.begin_dial(addr, conf)?;
        let connection = match connecting.into_0rtt() {
            Ok((connection, accepted)) => {
                // This `Conn` surface has no place to report quinn's accepted-0RTT
                // notification, and
                // quinn keeps the same answer on `Connection::accepted_0rtt`; dropping the future
                // only gives up the notification, not the connection.
                drop(accepted);
                return Ok(Arc::new(QuinnConn::new(connection, local_addr, conf.clone(), Some(endpoint))));
            }
            // No early keys to send with, so this dial is the ordinary one.
            Err(connecting) => await_dial(ctx, endpoint.clone(), connecting).await?,
        };
        Ok(Arc::new(QuinnConn::new(connection, local_addr, conf.clone(), Some(endpoint))))
    }
}

/// The client endpoint and half-open connection a dial starts from. [`QuinnTransport::connect`]
/// awaits the handshake; `dial_early` may first take quinn's 0-RTT path.
impl QuinnTransport {
    fn begin_dial(&self, addr: &UdpAddr, conf: &Config) -> Result<(quinn::Endpoint, quinn::Connecting, SocketAddr)> {
        let remote = old_addr_to_socket_addr(addr)?;
        let crypto = Arc::clone(&self.inner.crypto);
        let crypto: Arc<dyn quinn::crypto::ClientConfig> = crypto;
        let mut client = quinn::ClientConfig::new(crypto);
        client.transport_config(Arc::new(transport_config(conf, &self.congestion)));
        // The client dials with the first configured version; quinn instead
        // defaults the client to v1 and rejects a version its endpoint did not advertise.
        if let Some(version) = conf.versions.first() {
            client.version(*version);
        }
        let socket = PacketConnSocket::new(Arc::clone(&self.conn))?;
        let local_addr = quinn::AsyncUdpSocket::local_addr(socket.as_ref())?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config(conf),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let connecting = endpoint.connect_with(client, remote, &self.inner.server_name)?;
        Ok((endpoint, connecting, local_addr))
    }
}

/// Waits for a half-open connection, closing its endpoint if the dial is cancelled.
// cancel-safe: nothing is handed to the caller before the handshake resolves, and the endpoint
// this future owns is dropped with it, so a cancellation abandons the attempt.
async fn await_dial(
    ctx: &CancellationToken,
    endpoint: quinn::Endpoint,
    connecting: quinn::Connecting,
) -> Result<quinn::Connection> {
    Ok(tokio::select! {
        () = ctx.cancelled() => {
            endpoint.close(VarInt::from_u32(0), b"");
            anyhow::bail!("shadowquic: dial cancelled");
        }
        result = connecting => result?,
    })
}

impl QuinnTransport {
    // cancel-safe: nothing reaches the caller until the handshake resolves, and a cancelled dial
    // closes the endpoint it built, so dropping the future tears the attempt down.
    async fn connect(&self, ctx: &CancellationToken, addr: &UdpAddr, conf: &Config) -> Result<Arc<dyn Conn>> {
        let (endpoint, connecting, local_addr) = self.begin_dial(addr, conf)?;
        let connection = await_dial(ctx, endpoint.clone(), connecting).await?;
        // quinn drives I/O through the endpoint, so it is handed to the connection rather than
        // dropped here, which would stop all further reads and writes.
        Ok(Arc::new(QuinnConn::new(connection, local_addr, conf.clone(), Some(endpoint))))
    }
}

/// The `Config` fields that decide which versions an endpoint speaks. quinn 0.11 has no
/// handshake-idle-timeout knob, so `Config::handshake_idle_timeout` is not mapped.
fn endpoint_config(config: &Config) -> quinn::EndpointConfig {
    let mut endpoint = quinn::EndpointConfig::default();
    if !config.versions.is_empty() {
        endpoint.supported_versions(config.versions.clone());
    }
    endpoint
}

/// The incoming-stream limit this session passes to quinn, for both stream kinds.
///
/// Sending the full 32-bit stream count for both incoming-stream limits would have quinn's
/// `StreamsState::new` materializes one stream-table entry per admitted stream id before the
/// connection carries a byte (`quinn-proto-0.11.18/src/connection/streams/state.rs:203-207`), and
/// quinn's transport-parameter check rejects only a count above `MAX_STREAM_COUNT`, `1 << 60`, so
/// the value would have the accepting side build a ~4.3-billion-entry table. `1 << 12` still
/// clears quinn's own default of 100 by 40x — the limit that would queue a client's concurrent
/// streams — at a bounded 4096-entry table. Same clamp, same reason as `transport-tuic`'s and
/// `transport-trusttunnel`'s own.
const MAX_QUINN_INCOMING_STREAMS: i64 = 1 << 12;

/// The `Config` fields this session maps onto quinn's `TransportConfig`. quinn derives the
/// initial windows from the maximums and sizes packets from its own MTU probe, so
/// `Config::initial_stream_receive_window`, `initial_connection_receive_window` and
/// `initial_packet_size` are not mapped either.
fn transport_config(config: &Config, congestion: &CongestionOption) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    if let Some(idle) = idle_timeout(config.max_idle_timeout) {
        transport.max_idle_timeout(Some(idle));
    }
    if !config.keep_alive_period.is_zero() {
        transport.keep_alive_interval(Some(config.keep_alive_period));
    }
    if let Some(window) = var_int(config.max_stream_receive_window) {
        transport.stream_receive_window(window);
    }
    if let Some(window) = var_int(config.max_connection_receive_window) {
        transport.receive_window(window);
    }
    if let Some(streams) =
        var_int(u64::try_from(config.max_incoming_streams.min(MAX_QUINN_INCOMING_STREAMS)).unwrap_or_default())
    {
        transport.max_concurrent_bidi_streams(streams);
    }
    if let Some(streams) =
        var_int(u64::try_from(config.max_incoming_uni_streams.min(MAX_QUINN_INCOMING_STREAMS)).unwrap_or_default())
    {
        transport.max_concurrent_uni_streams(streams);
    }
    if config.enable_datagrams {
        // quinn bounds its datagram buffers in bytes; the configured maximum frame size bounds a
        // single frame instead and is enforced in `QuinnConn::send_datagram`.
        transport.datagram_receive_buffer_size(Some(usize::MAX));
        transport.datagram_send_buffer_size(usize::try_from(config.max_datagram_frame_size).unwrap_or_default());
    } else {
        transport.datagram_receive_buffer_size(None);
    }
    if config.disable_path_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    transport.congestion_controller_factory(congestion_factory(&congestion.name, congestion.cwnd));
    transport
}

/// A zero timeout means "unset", and anything past 2^62 milliseconds is a varint
/// quinn cannot encode, so both keep quinn's own default.
fn idle_timeout(duration: Duration) -> Option<quinn::IdleTimeout> {
    if duration.is_zero() {
        return None;
    }
    duration.try_into().ok()
}

/// A receive window or stream limit as quinn's `VarInt`, or `None` when the option is unset or
/// exceeds the 2^62 a QUIC varint can encode (quinn rejects it, so the default is kept instead).
fn var_int(value: u64) -> Option<VarInt> {
    (value > 0).then(|| VarInt::try_from(value).unwrap_or(VarInt::MAX))
}

fn congestion_factory(name: &str, cwnd: i32) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> {
    let initial_window = u64::try_from(cwnd).ok().filter(|cwnd| *cwnd > 0).map(|cwnd| cwnd.saturating_mul(1200));
    match name {
        "new_reno" | "newreno" => {
            let mut config = quinn::congestion::NewRenoConfig::default();
            if let Some(window) = initial_window {
                config.initial_window(window);
            }
            Arc::new(config)
        }
        "bbr" | "bbr_meta_v1" | "bbr_meta_v2" => {
            let mut config = quinn::congestion::BbrConfig::default();
            if let Some(window) = initial_window {
                config.initial_window(window);
            }
            Arc::new(config)
        }
        _ => {
            let mut config = quinn::congestion::CubicConfig::default();
            if let Some(window) = initial_window {
                config.initial_window(window);
            }
            Arc::new(config)
        }
    }
}
