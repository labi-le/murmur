//!
//! The QUIC session comes from [`crate::quic`], the one `quinn`-backed connection this
//! workspace drives, so v4 shares [`types::type_::DialFunc`] with v5.

use std::any::Any;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use bytes::BytesMut;
use chrono::{DateTime, Utc};
use parking_lot::Mutex as SyncMutex;
use rand::random;
use tokio::io::{AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as TokioMutex;
use tokio_util::sync::CancellationToken;

use crate::types;
use crate::types::type_ as types_type;
use murmur_common::atomic::value::TypedValue;
use murmur_common::xsync::map::Map;
use murmur_common_net::io::{close_stream, StreamAsOldConn};
use murmur_common_net::{
    new_buffered_conn, new_early_conn, new_extended_conn, new_ref_conn, new_ref_packet_conn, pipe, EarlyConnResponse,
    EnhancePacketConn, ExtendedConn,
};
use murmur_common_pool as pool;
use murmur_constant::adapters::{DEFAULT_TCP_TIMEOUT, DEFAULT_UDP_TIMEOUT};
use murmur_constant::metadata::Metadata;
use murmur_log::debugln;
use murmur_std_compat::net::{Conn, PacketConn};

use super::packet;
use super::protocol;
use crate::quic::Conn as QuicConn;
use murmur_quic::ReceiveStream;

/// A never-cancelled token, standing in at the call sites that never cancel.
static BACKGROUND: std::sync::LazyLock<CancellationToken> = std::sync::LazyLock::new(CancellationToken::new);

pub struct ClientOption {
    pub token: [u8; 32],
    pub udp_relay_mode: types_type::UdpRelayMode,
    pub request_timeout: Duration,
    pub max_udp_relay_packet_size: usize,
    pub fast_open: bool,
    pub max_open_streams: i64,
}

impl core::fmt::Debug for ClientOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientOption")
            .field("token", &"<redacted>")
            .field("udp_relay_mode", &self.udp_relay_mode)
            .field("request_timeout", &self.request_timeout)
            .field("max_udp_relay_packet_size", &self.max_udp_relay_packet_size)
            .field("fast_open", &self.fast_open)
            .field("max_open_streams", &self.max_open_streams)
            .finish()
    }
}

type UdpConn = Arc<TokioMutex<Box<dyn Conn>>>;

/// If `err` wraps an `io::Error`, rebuild an owned `anyhow::Error` that keeps the same
/// `io::ErrorKind` so [`is_net_error`] still recognises it once ownership crosses a borrow
/// boundary; otherwise fall back to the message text.
fn result_err<T>(result: &anyhow::Result<T>) -> Option<anyhow::Error> {
    result.as_ref().err().map(|err| match err.downcast_ref::<io::Error>() {
        Some(io_err) => anyhow::Error::from(io::Error::new(io_err.kind(), io_err.to_string())),
        None => anyhow::anyhow!(err.to_string()),
    })
}

/// Whether the error is a network-origin `io::Error`.
fn is_net_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<io::Error>().is_some()
}

pub(crate) struct ClientImpl {
    option: Arc<ClientOption>,
    dial_fn: types_type::DialFunc,
    udp: bool,

    quic_conn: SyncMutex<Option<Arc<dyn QuicConn>>>,
    dial_lock: TokioMutex<()>,

    open_streams: AtomicI64,
    closed: AtomicBool,

    udp_input_map: Map<u32, UdpConn>,

    last_visited: TypedValue<Option<DateTime<Utc>>>,
}

impl core::fmt::Debug for ClientImpl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientImpl")
            .field("udp", &self.udp)
            .field("open_streams", &self.open_streams())
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl ClientImpl {
    fn new(option: Arc<ClientOption>, dial_fn: types_type::DialFunc, udp: bool) -> Self {
        Self {
            option,
            dial_fn,
            udp,
            quic_conn: SyncMutex::new(None),
            dial_lock: TokioMutex::new(()),
            open_streams: AtomicI64::new(0),
            closed: AtomicBool::new(false),
            udp_input_map: Map::default(),
            last_visited: TypedValue::default(),
        }
    }

    fn open_streams(&self) -> i64 {
        self.open_streams.load(Ordering::SeqCst)
    }

    /// Returns the cached QUIC session, dialing one if needed. [`Self::dial_lock`] is a
    /// `tokio::sync` mutex held across the awaited dial so concurrent callers serialize on the
    /// single in-flight dial; [`Self::quic_conn`] stays a `parking_lot` mutex so
    /// [`Self::force_close`] can read/clear it synchronously (needed from `Client::drop`).
    async fn get_quic_conn(self: &Arc<Self>, ctx: &CancellationToken) -> anyhow::Result<Arc<dyn QuicConn>> {
        let _dial_guard = self.dial_lock.lock().await;
        let cached = self.quic_conn.lock().clone();
        if let Some(conn) = cached {
            return Ok(conn);
        }
        let quic_conn = (self.dial_fn)(ctx.clone()).await?;

        {
            let this = Arc::clone(self);
            let qc = Arc::clone(&quic_conn);
            tokio::spawn(async move {
                let _ = this.send_authentication(qc).await;
            });
        }

        if self.udp {
            let this = Arc::clone(self);
            let qc = Arc::clone(&quic_conn);
            tokio::spawn(async move {
                match this.option.udp_relay_mode {
                    types_type::UdpRelayMode::QUIC => {
                        let _ = this.handle_uni_stream(qc).await;
                    }
                    _ => {
                        let _ = this.handle_message(qc).await;
                    }
                }
            });
        }

        *self.quic_conn.lock() = Some(Arc::clone(&quic_conn));
        self.open_streams.store(0, Ordering::SeqCst);
        Ok(quic_conn)
    }

    async fn send_authentication(self: Arc<Self>, quic_conn: Arc<dyn QuicConn>) -> anyhow::Result<()> {
        let result = self.send_authentication_impl(&quic_conn).await;
        self.defer_quic_conn(Some(Arc::clone(&quic_conn)), result_err(&result));
        result
    }

    async fn send_authentication_impl(&self, quic_conn: &Arc<dyn QuicConn>) -> anyhow::Result<()> {
        let mut stream = quic_conn.open_uni_stream(&BACKGROUND).await?;
        let mut buf = pool::get_buffer();
        if let Err(err) = protocol::new_authenticate(self.option.token).write_to(&mut buf) {
            pool::put_buffer(buf);
            return Err(err.into());
        }
        let write_result = stream.write_all(&buf).await;
        pool::put_buffer(buf);
        write_result?;
        stream.close()?;
        Ok(())
    }

    async fn handle_uni_stream(self: Arc<Self>, quic_conn: Arc<dyn QuicConn>) -> anyhow::Result<()> {
        let result = self.handle_uni_stream_loop(&quic_conn).await;
        self.defer_quic_conn(Some(Arc::clone(&quic_conn)), result_err(&result));
        result
    }

    async fn handle_uni_stream_loop(self: &Arc<Self>, quic_conn: &Arc<dyn QuicConn>) -> anyhow::Result<()> {
        loop {
            let stream = quic_conn.accept_uni_stream(&BACKGROUND).await?;
            let this = Arc::clone(self);
            let qc = Arc::clone(quic_conn);
            tokio::spawn(async move {
                this.handle_uni_stream_datagram(qc, stream).await;
            });
        }
    }

    async fn handle_uni_stream_datagram(
        self: Arc<Self>,
        quic_conn: Arc<dyn QuicConn>,
        mut stream: Box<dyn ReceiveStream>,
    ) {
        let (result, assoc_id) = self.handle_uni_stream_datagram_impl(&mut stream).await;
        self.defer_quic_conn(Some(Arc::clone(&quic_conn)), result_err(&result));
        if result.is_err() && assoc_id != 0 {
            let (conn, loaded) = self.udp_input_map.load_and_delete(&assoc_id);
            if loaded {
                if let Some(conn) = conn {
                    if let Ok(guard) = conn.try_lock() {
                        let _ = guard.close();
                    }
                }
            }
        }
        stream.cancel_read(0);
    }

    async fn handle_uni_stream_datagram_impl(&self, stream: &mut Box<dyn ReceiveStream>) -> (anyhow::Result<()>, u32) {
        let command_head = match protocol::read_command_head(stream).await {
            Ok(head) => head,
            Err(err) => return (Err(err.into()), 0),
        };
        if command_head.type_ != protocol::CommandType::PACKET_TYPE {
            return (Ok(()), 0);
        }
        let packet = match protocol::read_packet_with_head(command_head, stream).await {
            Ok(packet) => packet,
            Err(err) => return (Err(err), 0),
        };
        let mut assoc_id = 0u32;
        if self.udp && self.option.udp_relay_mode == types_type::UdpRelayMode::QUIC {
            assoc_id = packet.assoc_id;
            if let Some(conn) = self.udp_input_map.load(&assoc_id) {
                let mut buf = BytesMut::with_capacity(packet.bytes_len());
                if packet.write_to(&mut buf).is_ok() {
                    let _ = conn.lock().await.write_all(&buf).await;
                }
            }
        }
        (Ok(()), assoc_id)
    }

    async fn handle_message(self: Arc<Self>, quic_conn: Arc<dyn QuicConn>) -> anyhow::Result<()> {
        let result = self.handle_message_loop(&quic_conn).await;
        self.defer_quic_conn(Some(Arc::clone(&quic_conn)), result_err(&result));
        result
    }

    async fn handle_message_loop(self: &Arc<Self>, quic_conn: &Arc<dyn QuicConn>) -> anyhow::Result<()> {
        loop {
            let message = quic_conn.receive_datagram(&BACKGROUND).await?;
            let this = Arc::clone(self);
            let qc = Arc::clone(quic_conn);
            tokio::spawn(async move {
                this.handle_message_datagram(qc, message).await;
            });
        }
    }

    async fn handle_message_datagram(self: Arc<Self>, quic_conn: Arc<dyn QuicConn>, message: Vec<u8>) {
        let (result, assoc_id) = self.handle_message_datagram_impl(&message).await;
        self.defer_quic_conn(Some(Arc::clone(&quic_conn)), result_err(&result));
        if result.is_err() && assoc_id != 0 {
            let (conn, loaded) = self.udp_input_map.load_and_delete(&assoc_id);
            if loaded {
                if let Some(conn) = conn {
                    if let Ok(guard) = conn.try_lock() {
                        let _ = guard.close();
                    }
                }
            }
        }
    }

    async fn handle_message_datagram_impl(&self, message: &[u8]) -> (anyhow::Result<()>, u32) {
        let mut reader = protocol::SliceReader::new(message);
        let command_head = match protocol::read_command_head(&mut reader).await {
            Ok(head) => head,
            Err(err) => return (Err(err.into()), 0),
        };
        if command_head.type_ != protocol::CommandType::PACKET_TYPE {
            return (Ok(()), 0);
        }
        let packet = match protocol::read_packet_with_head(command_head, &mut reader).await {
            Ok(packet) => packet,
            Err(err) => return (Err(err), 0),
        };
        let mut assoc_id = 0u32;
        if self.udp && self.option.udp_relay_mode == types_type::UdpRelayMode::NATIVE {
            assoc_id = packet.assoc_id;
            if let Some(conn) = self.udp_input_map.load(&assoc_id) {
                let _ = conn.lock().await.write_all(message).await;
            }
        }
        (Ok(()), assoc_id)
    }

    fn defer_quic_conn(&self, quic_conn: Option<Arc<dyn QuicConn>>, err: Option<anyhow::Error>) {
        if err.as_ref().is_some_and(is_net_error) {
            self.force_close(quic_conn, err);
        }
    }

    /// Closes the session synchronously so it can run from `Client::drop`; every field it
    /// touches (`quic_conn`, `udp_input_map`) supports synchronous access for exactly this reason.
    fn force_close(&self, quic_conn: Option<Arc<dyn QuicConn>>, err: Option<anyhow::Error>) {
        let mut guard = self.quic_conn.lock();
        let quic_conn = quic_conn.or_else(|| guard.clone());
        if let Some(qc) = &quic_conn {
            if guard.as_ref().is_some_and(|c| Arc::ptr_eq(c, qc)) {
                *guard = None;
            }
        }
        drop(guard);
        let err_str = err.map(|e| e.to_string()).unwrap_or_default();
        if let Some(qc) = &quic_conn {
            let _ = qc.close_with_error(protocol::PROTOCOL_ERROR, &err_str);
        }
        self.udp_input_map.range(|key, conn| {
            if let Ok(guard) = conn.try_lock() {
                let _ = guard.close();
            }
            self.udp_input_map.delete(*key);
            true
        });
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if self.open_streams() == 0 {
            self.force_close(None, Some(types_type::Error::ClientClosed.into()));
        }
    }

    async fn dial_context(
        self: &Arc<Self>,
        ctx: &CancellationToken,
        metadata: &Metadata,
    ) -> anyhow::Result<Box<dyn Conn>> {
        let quic_conn = self.get_quic_conn(ctx).await?;
        let open_streams = self.open_streams.fetch_add(1, Ordering::SeqCst) + 1;
        if open_streams >= self.option.max_open_streams {
            self.open_streams.fetch_sub(1, Ordering::SeqCst);
            return Err(types_type::Error::TooManyOpenStreams.into());
        }

        let stream_result = self.dial_stream(&quic_conn, metadata).await;
        self.defer_quic_conn(Some(Arc::clone(&quic_conn)), result_err(&stream_result));
        let stream = stream_result?;
        let mut buf_conn = new_buffered_conn(new_extended_conn(stream));
        if self.option.fast_open {
            let response = DialResponse::new(self.option.request_timeout);
            let early: Box<dyn ExtendedConn> = new_early_conn(buf_conn, response);
            return Ok(Box::new(StreamAsOldConn::new(early)));
        }

        if self.option.request_timeout > Duration::ZERO {
            let _ = buf_conn.set_read_deadline(Some(tokio::time::Instant::now() + self.option.request_timeout));
        }
        let response = match protocol::read_response(&mut buf_conn).await {
            Ok(response) => response,
            Err(err) => {
                let _ = buf_conn.close();
                return Err(err);
            }
        };
        if response.is_failed() {
            let _ = buf_conn.close();
            return Err(anyhow::anyhow!("connect failed"));
        }
        let _ = buf_conn.set_read_deadline(None);
        Ok(Box::new(buf_conn))
    }

    /// Opens one stream on the session, the unit the dialer's stream closure performs.
    async fn dial_stream(
        self: &Arc<Self>,
        quic_conn: &Arc<dyn QuicConn>,
        metadata: &Metadata,
    ) -> anyhow::Result<Box<dyn murmur_common_net::io::Stream>> {
        let mut buf = pool::get_buffer();
        if let Err(err) = protocol::new_connect(protocol::new_address(metadata)).write_to(&mut buf) {
            pool::put_buffer(buf);
            self.open_streams.fetch_sub(1, Ordering::SeqCst);
            return Err(err.into());
        }
        let quic_stream = match quic_conn.open_stream(&BACKGROUND).await {
            Ok(stream) => stream,
            Err(err) => {
                pool::put_buffer(buf);
                self.open_streams.fetch_sub(1, Ordering::SeqCst);
                return Err(err);
            }
        };

        let this = Arc::clone(self);
        let quic_conn_for_timer = Arc::clone(quic_conn);
        let mut stream = types::stream::new_quic_stream_conn(
            quic_stream,
            quic_conn.local_addr(),
            quic_conn.remote_addr(),
            Some(Box::new(move || {
                let this = Arc::clone(&this);
                let quic_conn = Arc::clone(&quic_conn_for_timer);
                tokio::spawn(async move {
                    tokio::time::sleep(DEFAULT_TCP_TIMEOUT).await;
                    let open_streams = this.open_streams.fetch_sub(1, Ordering::SeqCst) - 1;
                    if open_streams == 0 && this.closed.load(Ordering::SeqCst) {
                        this.force_close(Some(quic_conn), Some(types_type::Error::ClientClosed.into()));
                    }
                });
            })),
        );

        let write_result = stream.write_all(&buf).await;
        pool::put_buffer(buf);
        if let Err(err) = write_result {
            let _ = close_stream(&*stream);
            return Err(err.into());
        }
        Ok(stream)
    }

    async fn listen_packet(self: &Arc<Self>, ctx: &CancellationToken) -> anyhow::Result<Arc<dyn PacketConn>> {
        let quic_conn = self.get_quic_conn(ctx).await?;
        let open_streams = self.open_streams.fetch_add(1, Ordering::SeqCst) + 1;
        if open_streams >= self.option.max_open_streams {
            self.open_streams.fetch_sub(1, Ordering::SeqCst);
            return Err(types_type::Error::TooManyOpenStreams.into());
        }

        let (pipe1, pipe2) = pipe();
        let pipe1: UdpConn = Arc::new(TokioMutex::new(Box::new(pipe1)));
        let conn_id = loop {
            let candidate: u32 = random();
            let (_, loaded) = self.udp_input_map.load_or_store(candidate, Arc::clone(&pipe1));
            if !loaded {
                break candidate;
            }
        };

        // S11: remove in U8, when the final net bridge is deleted.
        let input_conn = new_buffered_conn(new_extended_conn(murmur_common_net::io::OldConnAsStream(pipe2)));

        let this_for_close = Arc::clone(self);
        let quic_conn_for_close = Arc::clone(&quic_conn);
        let close_defer_fn: packet::CloseDeferFn = Arc::new(move || {
            this_for_close.udp_input_map.delete(conn_id);
            let this = Arc::clone(&this_for_close);
            let quic_conn = Arc::clone(&quic_conn_for_close);
            tokio::spawn(async move {
                tokio::time::sleep(DEFAULT_UDP_TIMEOUT).await;
                let open_streams = this.open_streams.fetch_sub(1, Ordering::SeqCst) - 1;
                if open_streams == 0 && this.closed.load(Ordering::SeqCst) {
                    this.force_close(Some(quic_conn), Some(types_type::Error::ClientClosed.into()));
                }
            });
        });

        let this_for_defer = Arc::clone(self);
        let defer_quic_conn_fn: packet::DeferQuicConnFn = Arc::new(move |quic_conn, err| {
            this_for_defer.defer_quic_conn(Some(quic_conn), err);
        });

        let pc = packet::new_quic_stream_packet_conn(
            conn_id,
            quic_conn,
            Some(input_conn),
            self.option.udp_relay_mode,
            self.option.max_udp_relay_packet_size,
            Some(defer_quic_conn_fn),
            Some(close_defer_fn),
            None,
        );
        Ok(Arc::new(murmur_common_net::io::DatagramAsOldPacketConn(pc)))
    }
}

/// Reads the fixed 3-byte command-head + reply response layout
/// with raw `poll_read` calls: `EarlyConnResponse::poll_response` has no executor to `.await` the
/// async reader helpers on, so this hand-rolls the response parse as a manual
/// byte accumulator instead.
struct DialResponse {
    request_timeout: Duration,
    read_deadline_set: bool,
    buf: [u8; 3],
    filled: usize,
}

impl DialResponse {
    const fn new(request_timeout: Duration) -> Self {
        Self { request_timeout, read_deadline_set: false, buf: [0u8; 3], filled: 0 }
    }
}

impl EarlyConnResponse for DialResponse {
    fn poll_response(&mut self, cx: &mut TaskContext<'_>, conn: &mut dyn ExtendedConn) -> Poll<anyhow::Result<()>> {
        if !self.read_deadline_set {
            if self.request_timeout > Duration::ZERO {
                if let Some(inner) = conn.old_conn() {
                    let _ = inner.set_read_deadline(Some(tokio::time::Instant::now() + self.request_timeout));
                }
            }
            self.read_deadline_set = true;
        }
        while self.filled < self.buf.len() {
            let Some(rest) = self.buf.get_mut(self.filled..) else {
                break;
            };
            let mut read_buf = ReadBuf::new(rest);
            match Pin::new(&mut *conn).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        let _ = close_stream(&*conn);
                        return Poll::Ready(Err(anyhow::anyhow!(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))));
                    }
                    self.filled += n;
                }
                Poll::Ready(Err(err)) => {
                    let _ = close_stream(&*conn);
                    return Poll::Ready(Err(err.into()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let type_ = protocol::CommandType(self.buf[1]);
        if type_ != protocol::CommandType::RESPONSE_TYPE {
            let _ = close_stream(&*conn);
            return Poll::Ready(Err(anyhow::anyhow!("error command type: {type_}")));
        }
        if self.buf[2] == 0xff {
            let _ = close_stream(&*conn);
            return Poll::Ready(Err(anyhow::anyhow!("connect failed")));
        }
        if let Some(inner) = conn.old_conn() {
            let _ = inner.set_read_deadline(None);
        }
        Poll::Ready(Ok(()))
    }
}

/// `Client`, a distinct handle so the connection is closed once every external handle to it (not
/// `ClientImpl`, which background tasks keep alive on their own) is gone.
///
/// `Drop` is the deterministic Rust analogue: `new_client` always hands back an `Arc`, and
/// `Client::dial_context`/`listen_packet` keep that same `Arc<Client>` alive as the `ref_` of the
/// conn/packet-conn they return, so a live stream postpones the close.
#[derive(Debug)]
pub struct Client {
    inner: Arc<ClientImpl>,
}

impl Client {
    pub async fn dial_context(
        self: &Arc<Self>,
        ctx: &CancellationToken,
        metadata: &Metadata,
    ) -> anyhow::Result<Box<dyn Conn>> {
        let conn = self.inner.dial_context(ctx, metadata).await?;
        let this = Arc::clone(self);
        let ref_: Arc<dyn Any + Send + Sync> = this;
        // S11: remove in U5, once this module's own dial_context returns Stream.
        let extended: Box<dyn ExtendedConn> = new_ref_conn(murmur_common_net::io::OldConnAsStream(conn), ref_);
        Ok(Box::new(StreamAsOldConn::new(extended)))
    }

    pub async fn listen_packet(
        self: &Arc<Self>,
        ctx: &CancellationToken,
    ) -> anyhow::Result<Arc<dyn EnhancePacketConn>> {
        let pc = self.inner.listen_packet(ctx).await?;
        let this = Arc::clone(self);
        let ref_: Arc<dyn Any + Send + Sync> = this;
        Ok(new_ref_packet_conn(pc, ref_))
    }

    #[must_use]
    pub fn open_streams(&self) -> i64 {
        self.inner.open_streams()
    }

    #[must_use]
    pub fn last_visited(&self) -> Option<DateTime<Utc>> {
        self.inner.last_visited.load()
    }

    pub fn set_last_visited(&self, last: DateTime<Utc>) {
        self.inner.last_visited.store(Some(last));
    }

    pub fn close(&self) {
        self.inner.close();
    }

    fn force_close(&self) {
        self.inner.force_close(None, Some(types_type::Error::ClientClosed.into()));
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        debugln!("Close TuicV4 Client at {:p}", self);
        self.force_close();
    }
}

/// Builds a client. Returns `Arc<Client>` rather than a raw pointer.
///
/// [`Client::dial_context`] and [`Client::listen_packet`] need to hand out a keep-alive handle onto
/// the same `Client` identity that `Drop` (the finalizer) runs on, which needs shared
/// ownership.
pub fn new_client(client_option: Arc<ClientOption>, udp: bool, dial_fn: types_type::DialFunc) -> Arc<Client> {
    let inner = Arc::new(ClientImpl::new(client_option, dial_fn, udp));
    let client = Arc::new(Client { inner });
    debugln!("New TuicV4 Client at {:p}", Arc::as_ptr(&client));
    client
}
