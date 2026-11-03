//! `quinn` connections behind the conn/stream surface `core/client.rs` drives, and the transport
//! the dial path builds inline.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::ReadBuf;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::old_addr_to_socket_addr;
use murmur_quic::congestion::CongestionControlEx;
use murmur_quic::hysteria::{Conn as RawQuicConn, Stream as RawQuicStream};
use murmur_quic::{ApplicationErrorCode, DatagramTooLargeError, StreamErrorCode, StreamId};
use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};
use quinn::{Connection, Endpoint, SendDatagramError, VarInt};

use super::congestion::HysteriaCongestion;
use super::deadline::Deadline;
use super::socket::PacketConnSocket;
use super::{Config, Conn, TlsConfig, Transport, TransportFactory};
use crate::core::client::wrap_quic_conn;

/// A QUIC transport over `quinn`: one packet conn, one endpoint, one connection.
pub struct QuinnConn {
    connection: Connection,
    endpoint: Endpoint,
    local_addr: SocketAddr,
    congestion: Arc<HysteriaCongestion>,
}

impl std::fmt::Debug for QuinnConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuinnConn")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.connection.remote_address())
            .finish_non_exhaustive()
    }
}

impl QuinnConn {
    fn addr(socket_addr: SocketAddr) -> Box<dyn Addr> {
        Box::new(UdpAddr::from(socket_addr))
    }
}

#[async_trait]
impl RawQuicConn for QuinnConn {
    /// The local address of the packet conn the transport was built over, which is the address
    /// the QUIC packets go out from.
    fn local_addr(&self) -> Box<dyn Addr> {
        Self::addr(self.local_addr)
    }

    fn remote_addr(&self) -> Box<dyn Addr> {
        Self::addr(self.connection.remote_address())
    }

    async fn open_stream_sync(&self) -> anyhow::Result<Arc<dyn RawQuicStream>> {
        let (send, recv) = self.connection.open_bi().await.map_err(|err| anyhow!("{err}"))?;
        Ok(Arc::new(QuinnStream::new(send, recv)))
    }

    /// Opens a stream without waiting for stream credit: it reports the failure instead, and
    /// `core/client.rs` reconnects on it.
    fn open_stream(&self) -> anyhow::Result<Arc<dyn RawQuicStream>> {
        let mut open = Box::pin(self.connection.open_bi());
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        match open.as_mut().poll(&mut cx) {
            Poll::Ready(Ok((send, recv))) => Ok(Arc::new(QuinnStream::new(send, recv))),
            Poll::Ready(Err(err)) => Err(anyhow!("{err}")),
            Poll::Pending => Err(anyhow!("no stream credit available")),
        }
    }

    /// Installs the Brutal sender, reached once the server's `ServerHello` carries the rate it has
    /// to pace at.
    fn set_congestion_control(&self, cc: Box<dyn CongestionControlEx>) {
        self.congestion.install(cc);
    }

    /// Sends CONNECTION_CLOSE and tears the session down.
    fn close_with_error(&self, code: ApplicationErrorCode, reason: &str) -> anyhow::Result<()> {
        let code = VarInt::from_u64(code).unwrap_or(VarInt::MAX);
        self.connection.close(code, reason.as_bytes());
        self.endpoint.close(code, reason.as_bytes());
        Ok(())
    }

    // cancel-safe: quinn's `read_datagram` either hands over a queued datagram or yields nothing, and a dropped future leaves the datagram queued.
    async fn receive_datagram(&self) -> anyhow::Result<Vec<u8>> {
        self.connection.read_datagram().await.map(|data| data.to_vec()).map_err(|err| anyhow!("{err}"))
    }

    /// Sends an unreliable DATAGRAM frame. `quinn` applies two bounds (the peer's
    /// `max_datagram_frame_size` and the path MTU estimate), and the error it raises has to carry
    /// the limit itself because `core/client.rs` fragments the message against it.
    fn send_datagram(&self, data: &[u8]) -> anyhow::Result<()> {
        match self.connection.send_datagram(Bytes::copy_from_slice(data)) {
            Ok(()) => Ok(()),
            Err(SendDatagramError::TooLarge) => Err(DatagramTooLargeError {
                max_datagram_payload_size: i64::try_from(self.connection.max_datagram_size().unwrap_or_default())
                    .unwrap_or_default(),
            }
            .into()),
            Err(SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled) => {
                Err(anyhow!("datagram support disabled"))
            }
            Err(err) => Err(anyhow!("{err}")),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

///
/// The `&self` surface hysteria shares across tasks needs interior mutability here: each direction
/// carries a mutex taken only for the duration of a poll, matching the "one concurrent reader, one
/// concurrent writer" rule for a QUIC stream.
pub(super) struct QuinnStream {
    send: Mutex<quinn::SendStream>,
    recv: Mutex<quinn::RecvStream>,
    read_deadline: Deadline,
    write_deadline: Deadline,
    context: CancellationToken,
}

impl QuinnStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            read_deadline: Deadline::new(),
            write_deadline: Deadline::new(),
            context: CancellationToken::new(),
        }
    }

    /// A stream error reaches the caller as the peer's `STOP_SENDING`/`RESET_STREAM` code.
    /// `quinn`'s remaining variants are all local states of the same stream and are reported as a
    /// bare stream error too.
    fn reset_error(code: VarInt) -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionReset, format!("stream error {}", u64::from(code)))
    }

    fn read_error(err: quinn::ReadError) -> io::Error {
        match err {
            quinn::ReadError::Reset(code) => Self::reset_error(code),
            quinn::ReadError::ConnectionLost(err) => io::Error::new(io::ErrorKind::NotConnected, err),
            quinn::ReadError::ClosedStream => io::Error::new(io::ErrorKind::BrokenPipe, "stream already closed"),
            quinn::ReadError::IllegalOrderedRead => {
                io::Error::new(io::ErrorKind::InvalidData, "out-of-order stream read")
            }
            quinn::ReadError::ZeroRttRejected => {
                io::Error::new(io::ErrorKind::ConnectionReset, "0-RTT rejected by the server")
            }
        }
    }

    fn write_error(err: quinn::WriteError) -> io::Error {
        match err {
            quinn::WriteError::Stopped(code) => Self::reset_error(code),
            quinn::WriteError::ConnectionLost(err) => io::Error::new(io::ErrorKind::NotConnected, err),
            quinn::WriteError::ClosedStream => io::Error::new(io::ErrorKind::BrokenPipe, "stream already closed"),
            quinn::WriteError::ZeroRttRejected => {
                io::Error::new(io::ErrorKind::ConnectionReset, "0-RTT rejected by the server")
            }
        }
    }
}

impl RawQuicStream for QuinnStream {
    fn stream_id(&self) -> StreamId {
        // stream IDs use the standard QUIC bit layout (bit 0 initiator, bit 1 direction, the rest
        // the index), so the raw value is what the `StreamID` holds.
        i64::try_from(u64::from(self.send.lock().id())).unwrap_or_default()
    }

    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.read_deadline.expired(cx) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "read deadline exceeded")));
        }
        let mut recv = self.recv.lock();
        match recv.poll_read_buf(cx, buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(Self::read_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.write_deadline.expired(cx) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "write deadline exceeded")));
        }
        let mut send = self.send.lock();
        Pin::new(&mut *send).poll_write(cx, buf).map_err(Self::write_error)
    }

    fn cancel_read(&self, code: StreamErrorCode) {
        self.recv.lock().stop(VarInt::from_u64(code).unwrap_or(VarInt::MAX)).ok();
        self.context.cancel();
    }

    fn cancel_write(&self, code: StreamErrorCode) {
        self.send.lock().reset(VarInt::from_u64(code).unwrap_or(VarInt::MAX)).ok();
        self.context.cancel();
    }

    /// Closes the send direction only; the receive direction stays open until the peer finishes
    /// with it or the stream is reset.
    fn close(&self) -> io::Result<()> {
        self.send.lock().finish().map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stream already closed"))
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
        self.read_deadline.set(deadline);
        self.write_deadline.set(deadline);
        Ok(())
    }

    fn context(&self) -> CancellationToken {
        self.context.clone()
    }
}

struct QuinnTransport {
    conn: Arc<dyn PacketConn>,
    created_conn: AtomicBool,
    single_use: AtomicBool,
}

#[async_trait]
impl Transport for QuinnTransport {
    fn set_created_conn(&self, created_conn: bool) {
        self.created_conn.store(created_conn, Ordering::Relaxed);
    }

    fn set_single_use(&self, single_use: bool) {
        self.single_use.store(single_use, Ordering::Relaxed);
    }

    // cancel-safe: the cancelled arm closes the endpoint it created, and the connection is returned only
    // after the handshake resolves.
    async fn dial(
        &self,
        ctx: CancellationToken,
        addr: &dyn Addr,
        tls_config: &dyn TlsConfig,
        quic_config: &Config,
    ) -> anyhow::Result<Arc<dyn Conn>> {
        let socket = PacketConnSocket::new(Arc::clone(&self.conn))?;
        let local_addr = quinn::AsyncUdpSocket::local_addr(socket.as_ref())?;

        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config.rustls_client_config()?)
            .map_err(|err| anyhow!("invalid TLS config for quic: {err}"))?;
        let congestion = HysteriaCongestion::new();
        let mut transport = quinn::TransportConfig::default();
        transport_config(&mut transport, quic_config, Arc::clone(&congestion));
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        client.transport_config(Arc::new(transport));

        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;

        // The dial path takes the name from the cloned TLS config and falls back to the host it is
        // dialling; an empty name fails the handshake.
        let remote = old_addr_to_socket_addr(addr)?;
        let server_name = match tls_config.server_name() {
            "" => remote.ip().to_string(),
            name => name.to_owned(),
        };
        let connecting = endpoint.connect_with(client, remote, &server_name).map_err(|err| anyhow!("{err}"))?;
        let connection = tokio::select! {
            () = ctx.cancelled() => {
                endpoint.close(VarInt::from_u32(0), b"");
                return Err(anyhow!("hysteria: quic dial cancelled"));
            }
            result = connecting => result.map_err(|err| anyhow!("{err}"))?,
        };

        // The transport closes once its single connection is gone, and closes the packet conn with
        // it when the transport owns it.
        let created_conn = self.created_conn.load(Ordering::Relaxed);
        if created_conn || self.single_use.load(Ordering::Relaxed) {
            let conn = Arc::clone(&self.conn);
            let endpoint = endpoint.clone();
            let closing = connection.clone();
            tokio::spawn(async move {
                closing.closed().await;
                endpoint.close(VarInt::from_u32(0), b"");
                if created_conn {
                    conn.close().ok();
                }
            });
        }

        Ok(wrap_quic_conn(Arc::new(QuinnConn { connection, endpoint, local_addr, congestion })))
    }
}

/// The config fields this session maps onto quinn's `TransportConfig`. A field left
/// at the zero value keeps quinn's own default, which is already 100 for both maximum incoming
/// stream counts, and CUBIC is the default congestion controller too.
fn transport_config(transport: &mut quinn::TransportConfig, config: &Config, congestion: Arc<HysteriaCongestion>) {
    if config.max_stream_receive_window > 0 {
        transport.stream_receive_window(VarInt::try_from(config.max_stream_receive_window).unwrap_or(VarInt::MAX));
    }
    if config.max_connection_receive_window > 0 {
        transport.receive_window(VarInt::try_from(config.max_connection_receive_window).unwrap_or(VarInt::MAX));
    }
    if !config.keep_alive_period.is_zero() {
        transport.keep_alive_interval(Some(config.keep_alive_period));
    }
    if config.disable_path_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    if !config.enable_datagrams {
        // quinn advertises `max_datagram_frame_size` whenever a receive buffer is configured, so
        // `enable_datagrams: false` is the absence of one.
        transport.datagram_receive_buffer_size(None);
    }
    transport.congestion_controller_factory(congestion);
}

/// The transport factory `ClientTransport::new` takes.
#[must_use]
pub fn new_transport_factory() -> TransportFactory {
    Arc::new(|conn: Arc<dyn PacketConn>| {
        Box::new(QuinnTransport { conn, created_conn: AtomicBool::new(false), single_use: AtomicBool::new(false) })
    })
}
