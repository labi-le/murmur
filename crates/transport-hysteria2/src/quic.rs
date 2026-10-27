//! The QUIC session hysteria2 runs over: a `quinn` endpoint carrying raw
//! streams and datagrams beside an HTTP/3 transport.
//!
//! Two behaviours of that surface have no drop-in equivalent and are reproduced here rather than
//! dropped:
//!
//! * Stream dispatch — the protocol opens a bidirectional stream whose first frame is `0x401`,
//!   not HTTP/3. The `h3` crate has no such hook, so [`ServerConnection`] wraps `h3`'s QUIC
//!   traits, sniffs the first frame type of every incoming stream and routes `0x401` to
//!   [`ServerConnection::tcp_requests`] while handing HTTP/3 requests to `h3` unchanged.
//! * Setting congestion control to a Brutal sender — quinn binds a controller when the connection
//!   is created and offers no way to swap it, and the protocol only learns the rate after the auth
//!   exchange completes. [`CongestionOption`] is therefore applied when the connection is built,
//!   from the configured controller name and window; the negotiated rate is only reported in the log.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use parking_lot::Mutex;
use tokio::io::{AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::old_addr_to_socket_addr;
use murmur_std_compat::net::{PacketConn, UdpAddr};

use crate::packet::{DatagramError, DatagramTooLarge, QuicDatagrams};

/// The default QUIC flow-control windows, idle timeout and keep-alive period.
pub const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 8_388_608;
pub const DEFAULT_CONN_RECEIVE_WINDOW: u64 = DEFAULT_STREAM_RECEIVE_WINDOW * 5 / 2;
pub const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(10);

/// The QUIC configuration, restricted to the fields the protocol sets.
#[derive(Clone, Debug, Default)]
pub struct QuicConfig {
    /// The per-stream flow-control window quinn advertises at handshake.
    pub initial_stream_receive_window: u64,
    /// The ceiling the reference grows its stream window to; quinn's is fixed at the initial one.
    pub max_stream_receive_window: u64,
    /// The connection flow-control window quinn advertises at handshake.
    pub initial_connection_receive_window: u64,
    /// The ceiling the reference grows its connection window to, droppable for the same reason as
    /// [`Self::max_stream_receive_window`]; only `quinn::Connection::set_receive_window` raises it later.
    pub max_connection_receive_window: u64,
    pub max_idle_timeout: Duration,
    pub keep_alive_period: Duration,
    pub disable_path_mtu_discovery: bool,
    pub enable_datagrams: bool,
}

/// The congestion controller quinn binds when the connection is created.
#[derive(Clone, Debug, Default)]
pub struct CongestionOption {
    pub name: String,
    pub cwnd: i32,
}

impl QuicConfig {
    /// Fills in zero-valued fields, applied once so client and server agree.
    #[must_use]
    pub fn with_defaults(mut self) -> Self {
        if self.max_stream_receive_window == 0 {
            self.max_stream_receive_window = DEFAULT_STREAM_RECEIVE_WINDOW;
        }
        if self.initial_stream_receive_window == 0 {
            self.initial_stream_receive_window = DEFAULT_STREAM_RECEIVE_WINDOW;
        }
        if self.max_connection_receive_window == 0 {
            self.max_connection_receive_window = DEFAULT_CONN_RECEIVE_WINDOW;
        }
        if self.initial_connection_receive_window == 0 {
            self.initial_connection_receive_window = DEFAULT_CONN_RECEIVE_WINDOW;
        }
        if self.max_idle_timeout.is_zero() {
            self.max_idle_timeout = DEFAULT_MAX_IDLE_TIMEOUT;
        }
        if self.keep_alive_period.is_zero() {
            self.keep_alive_period = DEFAULT_KEEP_ALIVE_PERIOD;
        }
        self
    }
}

fn var_int(value: u64) -> Option<quinn::VarInt> {
    (value > 0).then(|| quinn::VarInt::try_from(value).unwrap_or(quinn::VarInt::MAX))
}

fn congestion_factory(option: &CongestionOption) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> {
    let initial_window = (option.cwnd > 0).then(|| u64::from(option.cwnd.cast_unsigned()) * 1200);
    match option.name.as_str() {
        "new_reno" | "newreno" => {
            let mut config = quinn::congestion::NewRenoConfig::default();
            if let Some(window) = initial_window {
                config.initial_window(window);
            }
            Arc::new(config)
        }
        _ => {
            let mut config = quinn::congestion::BbrConfig::default();
            if let Some(window) = initial_window {
                config.initial_window(window);
            }
            Arc::new(config)
        }
    }
}

/// The config fields this session maps onto quinn's `TransportConfig`.
///
/// The two `initial_*_receive_window` fields are the flow-control windows quinn advertises in the
/// handshake and then maintains (quinn-proto's `TransportParameters` fills `initial_max_data` from
/// `receive_window` and `initial_max_stream_data_{bidi_local,bidi_remote,uni}` from
/// `stream_receive_window`). The two `max_*` fields are the ceiling the reference grows its window
/// to as it measures the path; quinn has no counterpart, because its window is the advertised value
/// for the connection's lifetime — only the connection window can be raised later, through
/// `quinn::Connection::set_receive_window`.
#[must_use]
pub fn transport_config(config: &QuicConfig, congestion: &CongestionOption) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(quinn::IdleTimeout::try_from(config.max_idle_timeout).ok());
    transport.keep_alive_interval(Some(config.keep_alive_period));
    if let Some(window) = var_int(config.initial_stream_receive_window) {
        transport.stream_receive_window(window);
    }
    if let Some(window) = var_int(config.initial_connection_receive_window) {
        transport.receive_window(window);
    }
    if config.enable_datagrams {
        transport.datagram_receive_buffer_size(Some(usize::MAX));
        transport.datagram_send_buffer_size(usize::MAX);
    }
    if config.disable_path_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    transport.congestion_controller_factory(congestion_factory(congestion));
    transport
}

/// A `quinn::AsyncUdpSocket` over a `murmur_std_compat::net::PacketConn`, so the obfuscating
/// wrapper the dialer produced carries the session.
pub struct PacketConnSocket {
    local_addr: SocketAddr,
    send: Mutex<tokio_util::sync::PollSender<(Vec<u8>, SocketAddr)>>,
    recv: Mutex<tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    recv_task: tokio::task::JoinHandle<()>,
    send_task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for PacketConnSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketConnSocket").field("local_addr", &self.local_addr).finish_non_exhaustive()
    }
}

impl PacketConnSocket {
    pub fn new(conn: Arc<dyn PacketConn>) -> io::Result<Arc<Self>> {
        let local_addr = old_addr_to_socket_addr(conn.local_addr()?.as_ref())?;
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

        let recv_conn = Arc::clone(&conn);
        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, addr)) = recv_conn.read_from(&mut buf).await {
                let Ok(addr) = old_addr_to_socket_addr(addr.as_ref()) else { continue };
                let (payload, _) = buf.split_at(n);
                if recv_tx.send((payload.to_vec(), addr)).await.is_err() {
                    break;
                }
            }
        });

        let send_task = tokio::spawn(async move {
            while let Some((data, addr)) = send_rx.recv().await {
                if conn.write_to(&data, &UdpAddr::from(addr)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Arc::new(Self {
            local_addr,
            send: Mutex::new(tokio_util::sync::PollSender::new(send_tx)),
            recv: Mutex::new(recv_rx),
            recv_task,
            send_task,
        }))
    }
}

impl Drop for PacketConnSocket {
    fn drop(&mut self) {
        // The packet connection is cached across endpoints; old workers must not consume its I/O.
        self.recv_task.abort();
        self.send_task.abort();
    }
}

impl quinn::AsyncUdpSocket for PacketConnSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SendPoller(self))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        let mut guard = self.send.lock();
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        match guard.poll_reserve(&mut cx) {
            Poll::Ready(Ok(())) => {
                guard.send_item((transmit.contents.to_vec(), transmit.destination)).map_err(|_| closed())
            }
            Poll::Ready(Err(_)) | Poll::Pending => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "packet conn send buffer is full"))
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.recv.lock();
        match rx.poll_recv(cx) {
            Poll::Ready(Some((data, addr))) => {
                let (Some(target), Some(meta)) = (bufs.first_mut(), meta.first_mut()) else {
                    return Poll::Ready(Ok(0));
                };
                let len = data.len().min(target.len());
                let (payload, _) = data.split_at(len);
                ReadBuf::new(target).put_slice(payload);
                *meta = quinn::udp::RecvMeta { addr, len, stride: len, ecn: None, dst_ip: None };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(closed())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

struct SendPoller(Arc<PacketConnSocket>);

impl std::fmt::Debug for SendPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SendPoller").field(&self.0).finish()
    }
}

impl quinn::UdpPoller for SendPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.send.lock().poll_reserve(cx).map_err(|_| closed())
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "packet conn closed")
}

/// The QUIC connection handle the client and server both drive.
#[derive(Debug)]
pub struct QuicConn {
    pub connection: quinn::Connection,
    /// quinn drives I/O through the endpoint, so the client keeps it alive next to the connection.
    _endpoint: Option<quinn::Endpoint>,
}

impl QuicConn {
    #[must_use]
    pub fn new(connection: quinn::Connection) -> Arc<Self> {
        Arc::new(Self { connection, _endpoint: None })
    }

    /// The client additionally holds the endpoint that owns the socket.
    #[must_use]
    pub fn with_endpoint(connection: quinn::Connection, endpoint: quinn::Endpoint) -> Arc<Self> {
        Arc::new(Self { connection, _endpoint: Some(endpoint) })
    }

    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// The connection's local address; quinn 0.11 only reports the peer's address, so this is that.
    #[must_use]
    pub fn local_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub async fn open_stream(&self) -> io::Result<QuicStream> {
        let (send, recv) = self.connection.open_bi().await.map_err(io::Error::other)?;
        Ok(QuicStream { send, recv })
    }

    pub async fn accept_stream(&self) -> io::Result<QuicStream> {
        let (send, recv) = self.connection.accept_bi().await.map_err(io::Error::other)?;
        Ok(QuicStream { send, recv })
    }

    pub fn close_with_error(&self, code: u64, reason: &str) -> io::Result<()> {
        let code = quinn::VarInt::try_from(code).unwrap_or(quinn::VarInt::from_u32(0));
        self.connection.close(code, reason.as_bytes());
        Ok(())
    }

    /// The cancellation token the hop loop and the datagram loop both select on.
    #[must_use]
    pub fn context(&self) -> CancellationToken {
        let token = CancellationToken::new();
        let cancelled = token.clone();
        let connection = self.connection.clone();
        tokio::spawn(async move {
            connection.closed().await;
            cancelled.cancel();
        });
        token
    }
}

#[async_trait::async_trait]
impl QuicDatagrams for QuicConn {
    fn send_datagram(&self, data: &[u8]) -> Result<(), DatagramError> {
        match self.connection.send_datagram(Bytes::copy_from_slice(data)) {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::TooLarge) => {
                Err(DatagramTooLarge { max_datagram_payload_size: self.connection.max_datagram_size().unwrap_or(0) }
                    .into())
            }
            Err(quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled) => {
                Err(DatagramError::Io(io::Error::new(io::ErrorKind::Unsupported, "datagram support disabled")))
            }
            Err(err) => Err(DatagramError::Io(io::Error::other(err))),
        }
    }

    // cancel-safe: quinn's `read_datagram` either hands over a queued datagram or yields nothing, and a dropped future leaves the datagram queued.
    async fn receive_datagram(&self) -> io::Result<Vec<u8>> {
        Ok(self.connection.read_datagram().await?.to_vec())
    }
}

/// A QUIC stream as one duplex handle.
#[derive(Debug)]
pub struct QuicStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl QuicStream {
    pub fn cancel_read(&mut self) {
        let _ = self.recv.stop(quinn::VarInt::from_u32(0));
    }

    /// Closes only the send direction.
    pub fn finish(&mut self) -> io::Result<()> {
        self.send.finish().map_err(|err| io::Error::other(err.to_string()))
    }

    pub fn reset(&mut self) {
        let _ = self.send.reset(quinn::VarInt::from_u32(0));
    }
}

/// Hands a protocol header to `send`, keeping whatever the send half did not take in `header`.
///
/// A write into [`quinn::SendStream`] carries only what the peer's flow-control window has room for,
/// so a header taller than the window goes out a prefix at a time: `Poll::Ready(Ok(()))` once every
/// byte is on the wire, `Poll::Pending` with the remainder still in `header` for the poll that
/// follows. Quinn only reports a zero-byte write for an empty buffer, and the loop condition rules
/// that out, so each poll that answers `Ready` has advanced.
pub(crate) fn poll_write_header(
    send: &mut quinn::SendStream,
    cx: &mut Context<'_>,
    header: &mut BytesMut,
) -> Poll<io::Result<()>> {
    while !header.is_empty() {
        match AsyncWrite::poll_write(Pin::new(&mut *send), cx, &header[..]) {
            Poll::Ready(Ok(written)) => header.advance(written),
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

/// The encoded width of a QUIC varint, whose top two bits select it.
#[must_use]
pub const fn frame_type_len(first: u8) -> usize {
    1usize << (first >> 6)
}

/// The value of the QUIC varint that starts with `first`, once `rest` completes it.
#[must_use]
pub fn decode_frame_type(first: u8, rest: &[u8]) -> u64 {
    let mut value = u64::from(first & 0x3f);
    for byte in rest {
        value = (value << 8) | u64::from(*byte);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FRAME_TYPE_TCP_REQUEST;

    #[tokio::test]
    async fn dropping_endpoint_preserves_next_datagram_for_reused_packet_conn() {
        use quinn::AsyncUdpSocket as _;

        let conn = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = conn.local_addr().unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let socket = PacketConnSocket::new(Arc::<tokio::net::UdpSocket>::clone(&conn)).unwrap();
        let mut buf = [0u8; 64];
        let mut meta = [quinn::udp::RecvMeta::default()];

        // Receiving once ensures the old worker has entered its read loop before teardown.
        peer.send_to(b"warmup", addr).await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut [io::IoSliceMut::new(&mut buf)], &mut meta)),
        )
        .await
        .expect("the original socket receives the warmup")
        .unwrap();

        let weak_socket = Arc::downgrade(&socket);
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            quinn::default_runtime().unwrap(),
        )
        .unwrap();
        drop(endpoint);
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak_socket.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the endpoint releases its socket adapter");

        peer.send_to(b"first packet after teardown", addr).await.unwrap();
        // Both old workers must retire before a replacement can mask a stolen datagram.
        tokio::time::timeout(Duration::from_secs(2), async {
            while Arc::strong_count(&conn) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the old socket workers release the cached packet connection");

        let replacement = PacketConnSocket::new(conn).unwrap();
        let received = tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| replacement.poll_recv(cx, &mut [io::IoSliceMut::new(&mut buf)], &mut meta)),
        )
        .await
        .expect("the replacement receives the first datagram without a retransmission")
        .unwrap();
        assert_eq!(received, 1);
        assert_eq!(meta[0].addr, peer_addr);
        assert_eq!(&buf[..meta[0].len], b"first packet after teardown");
    }

    #[test]
    fn config_zero_values_take_the_defaults() {
        let config = QuicConfig::default().with_defaults();
        assert_eq!(config.max_stream_receive_window, DEFAULT_STREAM_RECEIVE_WINDOW);
        assert_eq!(config.initial_stream_receive_window, DEFAULT_STREAM_RECEIVE_WINDOW);
        assert_eq!(config.max_connection_receive_window, DEFAULT_CONN_RECEIVE_WINDOW);
        assert_eq!(config.initial_connection_receive_window, DEFAULT_CONN_RECEIVE_WINDOW);
        assert_eq!(config.max_idle_timeout, Duration::from_secs(30));
        assert_eq!(config.keep_alive_period, Duration::from_secs(10));
    }

    #[test]
    fn config_explicit_values_are_kept() {
        let config = QuicConfig {
            max_stream_receive_window: 1,
            max_connection_receive_window: 2,
            max_idle_timeout: Duration::from_secs(5),
            keep_alive_period: Duration::from_secs(6),
            ..Default::default()
        }
        .with_defaults();
        assert_eq!(config.max_stream_receive_window, 1);
        assert_eq!(config.max_connection_receive_window, 2);
        assert_eq!(config.max_idle_timeout, Duration::from_secs(5));
        assert_eq!(config.keep_alive_period, Duration::from_secs(6));
    }

    #[test]
    fn frame_type_width_follows_the_quic_varint_prefix() {
        assert_eq!(frame_type_len(0x00), 1);
        assert_eq!(frame_type_len(0x40), 2);
        assert_eq!(frame_type_len(0x80), 4);
        assert_eq!(frame_type_len(0xc0), 8);
        assert_eq!(FRAME_TYPE_TCP_REQUEST, 0x401);
        assert_eq!(frame_type_len(0x44), 2);
    }

    #[test]
    fn var_int_saturates_instead_of_wrapping_an_oversized_window() {
        assert_eq!(var_int(0), None);
        assert_eq!(var_int(1), Some(quinn::VarInt::from_u32(1)));
        assert_eq!(var_int(u64::MAX), Some(quinn::VarInt::MAX));
    }
}
