//!
//! `Client`/`ClientImpl` are split so the finalizer can fire once the *external* handle becomes
//! unreachable.
//!
//! The background tasks captured inside `ClientImpl` keep it alive
//! independently; this crate mirrors that with two Arc levels: [`ClientImpl`] (cloned directly into
//! every spawned task) and `ClientOuter`, whose `Drop` is the finalizer equivalent and is reached
//! only through the outward-facing [`Client`] handle.

use std::any::Any;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as TokioMutex;
use tokio_util::sync::CancellationToken;

use crate::quic::Conn as QuicConn;
use crate::types;
use murmur_common::atomic::type_::{Bool as AtomicBoolValue, Int64 as AtomicI64Value};
use murmur_common::atomic::value::TypedValue;
use murmur_common::xsync;
use murmur_common_net::io::{close_stream, Datagram, StreamAsOldConn};
use murmur_common_net::{new_buffered_conn, new_extended_conn, new_ref_conn, pipe};
use murmur_common_pool as pool;
use murmur_constant::adapters::{DEFAULT_TCP_TIMEOUT, DEFAULT_UDP_TIMEOUT};
use murmur_constant::metadata::Metadata;
use murmur_log as log;
use murmur_quic::ReceiveStream;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn};

use super::packet::QuicStreamPacketConn;
use super::protocol;

/// A never-cancelled token, standing in at the call sites that never cancel.
static BACKGROUND: std::sync::LazyLock<CancellationToken> = std::sync::LazyLock::new(CancellationToken::new);

#[derive(Clone)]
pub struct ClientOption {
    pub uuid: [u8; 16],
    pub password: String,
    pub udp_relay_mode: types::type_::UdpRelayMode,
    pub max_udp_relay_packet_size: usize,
    pub max_open_streams: i64,
}

impl core::fmt::Debug for ClientOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientOption")
            .field("uuid", &"<redacted>")
            .field("password", &"<redacted>")
            .field("udp_relay_mode", &self.udp_relay_mode)
            .field("max_udp_relay_packet_size", &self.max_udp_relay_packet_size)
            .field("max_open_streams", &self.max_open_streams)
            .finish()
    }
}

/// A conn shared by an association id, written from the client's dispatch loops
/// (`handle_uni_stream`/`handle_message`) and read from a [`QuicStreamPacketConn`]. A conn
/// tolerates concurrent `Write` calls from multiple tasks; `AsyncWrite::poll_write` needs `&mut`,
/// so the shared handle stored in `udp_input_map` carries its own lock to preserve that guarantee.
type UdpInputConn = Arc<TokioMutex<Box<dyn NetConn>>>;

pub(crate) struct ClientImpl {
    option: ClientOption,
    dial_fn: types::type_::DialFunc,
    udp: bool,

    quic_conn: TokioMutex<Option<Arc<dyn QuicConn>>>,

    open_streams: AtomicI64Value,
    closed: AtomicBoolValue,

    udp_input_map: xsync::map::Map<u16, UdpInputConn>,

    /// Only ready for `PoolClient`.
    last_visited: TypedValue<Option<DateTime<Utc>>>,
}

impl core::fmt::Debug for ClientImpl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientImpl")
            .field("udp", &self.udp)
            .field("open_streams", &self.open_streams())
            .field("closed", &self.closed.load())
            .finish_non_exhaustive()
    }
}

impl ClientImpl {
    fn open_streams(&self) -> i64 {
        self.open_streams.load()
    }

    fn last_visited(&self) -> Option<DateTime<Utc>> {
        self.last_visited.load()
    }

    fn set_last_visited(&self, last: DateTime<Utc>) {
        self.last_visited.store(Some(last));
    }

    async fn get_quic_conn(self: &Arc<Self>, ctx: CancellationToken) -> anyhow::Result<Arc<dyn QuicConn>> {
        let mut guard = self.quic_conn.lock().await;
        if let Some(quic_conn) = guard.as_ref() {
            return Ok(Arc::clone(quic_conn));
        }
        let quic_conn = (self.dial_fn)(ctx).await?;

        {
            let this = Arc::clone(self);
            let quic_conn = Arc::clone(&quic_conn);
            tokio::spawn(async move {
                let _ = this.send_authentication(&quic_conn).await;
            });
        }

        if self.udp && self.option.udp_relay_mode == types::type_::UdpRelayMode::QUIC {
            let this = Arc::clone(self);
            let quic_conn = Arc::clone(&quic_conn);
            tokio::spawn(async move {
                let _ = this.handle_uni_stream(&quic_conn).await;
            });
        }
        {
            let this = Arc::clone(self);
            let quic_conn = Arc::clone(&quic_conn);
            // Always handleMessage because tuicV5 uses a datagram to send the Heartbeat.
            tokio::spawn(async move {
                let _ = this.handle_message(&quic_conn).await;
            });
        }

        *guard = Some(Arc::clone(&quic_conn));
        drop(guard);
        self.open_streams.store(0);
        Ok(quic_conn)
    }

    async fn send_authentication(self: &Arc<Self>, quic_conn: &Arc<dyn QuicConn>) -> anyhow::Result<()> {
        let result = self.send_authentication_inner(quic_conn).await;
        self.defer_quic_conn(quic_conn, result.as_ref().err()).await;
        result
    }

    async fn send_authentication_inner(&self, quic_conn: &Arc<dyn QuicConn>) -> anyhow::Result<()> {
        let mut stream = quic_conn.open_uni_stream(&BACKGROUND).await?;
        let mut buf = pool::get_buffer();
        let token = match protocol::gen_token(quic_conn.as_ref(), self.option.uuid, &self.option.password) {
            Ok(token) => token,
            Err(err) => {
                pool::put_buffer(buf);
                return Err(err);
            }
        };
        protocol::new_authenticate(self.option.uuid, token).write_to(&mut buf);
        let write_result = stream.write_all(&buf).await;
        pool::put_buffer(buf);
        write_result?;
        stream.close()?;
        Ok(())
    }

    async fn handle_uni_stream(self: &Arc<Self>, quic_conn: &Arc<dyn QuicConn>) -> anyhow::Result<()> {
        loop {
            let stream = match quic_conn.accept_uni_stream(&BACKGROUND).await {
                Ok(stream) => stream,
                Err(err) => {
                    self.defer_quic_conn(quic_conn, Some(&err)).await;
                    return Err(err);
                }
            };
            let this = Arc::clone(self);
            let quic_conn = Arc::clone(quic_conn);
            tokio::spawn(async move {
                this.handle_uni_stream_one(&quic_conn, stream).await;
            });
        }
    }

    async fn handle_uni_stream_one(
        self: &Arc<Self>,
        quic_conn: &Arc<dyn QuicConn>,
        mut stream: Box<dyn ReceiveStream>,
    ) {
        let mut assoc_id: u16 = 0;
        let result = self.handle_uni_stream_one_inner(&mut *stream, &mut assoc_id).await;
        self.defer_quic_conn(quic_conn, result.as_ref().err()).await;
        if result.is_err() && assoc_id != 0 {
            if let (Some(conn), true) = self.udp_input_map.load_and_delete(&assoc_id) {
                let _ = conn.lock().await.close();
            }
        }
        stream.cancel_read(0);
    }

    async fn handle_uni_stream_one_inner(
        &self,
        stream: &mut dyn ReceiveStream,
        assoc_id: &mut u16,
    ) -> anyhow::Result<()> {
        let command_head = protocol::read_command_head(stream).await?;
        if command_head.type_ == protocol::CommandType::PACKET_TYPE {
            let packet = protocol::read_packet_with_head(command_head, stream).await?;
            if self.udp && self.option.udp_relay_mode == types::type_::UdpRelayMode::QUIC {
                *assoc_id = packet.assoc_id;
                if let Some(conn) = self.udp_input_map.load(assoc_id) {
                    let mut buf = pool::get_buffer();
                    packet.write_to(&mut buf);
                    let _ = conn.lock().await.write_all(&buf).await;
                    pool::put_buffer(buf);
                }
            }
        }
        Ok(())
    }

    async fn handle_message(self: &Arc<Self>, quic_conn: &Arc<dyn QuicConn>) -> anyhow::Result<()> {
        loop {
            let message = match quic_conn.receive_datagram(&BACKGROUND).await {
                Ok(message) => message,
                Err(err) => {
                    self.defer_quic_conn(quic_conn, Some(&err)).await;
                    return Err(err);
                }
            };
            let this = Arc::clone(self);
            let quic_conn = Arc::clone(quic_conn);
            tokio::spawn(async move {
                this.handle_message_one(&quic_conn, message).await;
            });
        }
    }

    async fn handle_message_one(self: &Arc<Self>, quic_conn: &Arc<dyn QuicConn>, message: Vec<u8>) {
        let mut assoc_id: u16 = 0;
        let result = self.handle_message_one_inner(&message, &mut assoc_id).await;
        self.defer_quic_conn(quic_conn, result.as_ref().err()).await;
        if result.is_err() && assoc_id != 0 {
            if let (Some(conn), true) = self.udp_input_map.load_and_delete(&assoc_id) {
                let _ = conn.lock().await.close();
            }
        }
    }

    async fn handle_message_one_inner(&self, message: &[u8], assoc_id: &mut u16) -> anyhow::Result<()> {
        let mut reader = std::io::Cursor::new(message);
        let command_head = protocol::read_command_head(&mut reader).await?;
        match command_head.type_ {
            protocol::CommandType::PACKET_TYPE => {
                let packet = protocol::read_packet_with_head(command_head, &mut reader).await?;
                if self.udp && self.option.udp_relay_mode == types::type_::UdpRelayMode::NATIVE {
                    *assoc_id = packet.assoc_id;
                    if let Some(conn) = self.udp_input_map.load(assoc_id) {
                        let _ = conn.lock().await.write_all(message).await;
                    }
                }
            }
            protocol::CommandType::HEARTBEAT_TYPE => {
                let heartbeat = protocol::read_heartbeat_with_head(command_head)?;
                let _ = heartbeat.bytes_len();
            }
            _ => {}
        }
        Ok(())
    }

    async fn defer_quic_conn(self: &Arc<Self>, quic_conn: &Arc<dyn QuicConn>, err: Option<&anyhow::Error>) {
        if super::packet::is_net_error_ref(err) {
            self.force_close(Some(quic_conn), err.map(|err| anyhow::anyhow!("{err}"))).await;
        }
    }

    async fn force_close(self: &Arc<Self>, quic_conn: Option<&Arc<dyn QuicConn>>, err: Option<anyhow::Error>) {
        let mut guard = self.quic_conn.lock().await;
        let quic_conn: Option<Arc<dyn QuicConn>> = match quic_conn {
            Some(quic_conn) => Some(Arc::clone(quic_conn)),
            None => guard.clone(),
        };
        if let (Some(quic_conn), Some(current)) = (&quic_conn, guard.as_ref()) {
            if Arc::ptr_eq(quic_conn, current) {
                *guard = None;
            }
        }
        drop(guard);

        let err_str = err.map(|err| err.to_string()).unwrap_or_default();
        if let Some(quic_conn) = &quic_conn {
            let _ = quic_conn.close_with_error(protocol::PROTOCOL_ERROR, &err_str);
        }

        let map = &self.udp_input_map;
        let mut to_close = Vec::new();
        map.range(|key, value| {
            to_close.push((*key, Arc::clone(value)));
            true
        });
        for (key, conn) in to_close {
            let _ = conn.lock().await.close();
            map.delete(key);
        }
    }

    #[allow(
        dead_code,
        reason = "tuic.rs's Client::close deliberately does not delegate here: the only call site drops its last Arc right after, and ClientOuter's Drop already runs the equivalent force_close"
    )]
    fn close(self: &Arc<Self>) {
        self.closed.store(true);
        if self.open_streams.load() == 0 {
            let this = Arc::clone(self);
            tokio::spawn(async move {
                this.force_close(None, Some(types::type_::Error::ClientClosed.into())).await;
            });
        }
    }

    async fn dial_context(
        self: &Arc<Self>,
        ctx: CancellationToken,
        metadata: &Metadata,
    ) -> anyhow::Result<Box<dyn NetConn>> {
        let quic_conn = self.get_quic_conn(ctx).await?;
        let open_streams = self.open_streams.add(1);
        if open_streams >= self.option.max_open_streams {
            self.open_streams.add(-1);
            return Err(types::type_::Error::TooManyOpenStreams.into());
        }
        let result = self.dial_context_inner(&quic_conn, metadata).await;
        self.defer_quic_conn(&quic_conn, result.as_ref().err()).await;
        result.map(|stream| -> Box<dyn NetConn> { Box::new(StreamAsOldConn::new(stream)) })
    }

    async fn dial_context_inner(
        self: &Arc<Self>,
        quic_conn: &Arc<dyn QuicConn>,
        metadata: &Metadata,
    ) -> anyhow::Result<Box<dyn murmur_common_net::io::Stream>> {
        let mut buf = pool::get_buffer();
        protocol::new_connect(protocol::new_address(metadata)).write_to(&mut buf);
        let quic_stream = match quic_conn.open_stream(&BACKGROUND).await {
            Ok(quic_stream) => quic_stream,
            Err(err) => {
                self.open_streams.add(-1);
                pool::put_buffer(buf);
                return Err(err);
            }
        };

        let this = Arc::clone(self);
        let quic_conn_for_close = Arc::clone(quic_conn);
        let close_defer_fn: types::stream::CloseDeferFn = Box::new(move || {
            let this = Arc::clone(&this);
            let quic_conn_for_close = Arc::clone(&quic_conn_for_close);
            tokio::spawn(async move {
                tokio::time::sleep(DEFAULT_TCP_TIMEOUT).await;
                let open_streams = this.open_streams.add(-1);
                if open_streams == 0 && this.closed.load() {
                    this.force_close(Some(&quic_conn_for_close), Some(types::type_::Error::ClientClosed.into())).await;
                }
            });
        });
        let mut stream = types::stream::new_quic_stream_conn(
            quic_stream,
            quic_conn.local_addr(),
            quic_conn.remote_addr(),
            Some(close_defer_fn),
        );

        let write_result = stream.write_all(&buf).await;
        pool::put_buffer(buf);
        if let Err(err) = write_result {
            let _ = close_stream(&*stream);
            return Err(err.into());
        }
        Ok(stream)
    }

    async fn listen_packet(
        self: &Arc<Self>,
        ctx: CancellationToken,
        _metadata: &mut Metadata,
    ) -> anyhow::Result<Arc<QuicStreamPacketConn>> {
        let quic_conn = self.get_quic_conn(ctx).await?;
        let open_streams = self.open_streams.add(1);
        if open_streams >= self.option.max_open_streams {
            self.open_streams.add(-1);
            return Err(types::type_::Error::TooManyOpenStreams.into());
        }

        let (pipe1, pipe2) = pipe();
        let pipe1: UdpInputConn = Arc::new(TokioMutex::new(Box::new(pipe1)));
        let mut conn_id;
        loop {
            conn_id = rand::rng().random_range(0u16..0xFFFFu16);
            let (_, loaded) = self.udp_input_map.load_or_store(conn_id, Arc::clone(&pipe1));
            if !loaded {
                break;
            }
        }

        let this_defer = Arc::clone(self);
        let defer_quic_conn_fn: super::packet::DeferQuicConnFn = Arc::new(move |quic_conn, err| {
            let this = Arc::clone(&this_defer);
            let quic_conn = Arc::clone(quic_conn);
            let err = err.map(|err| anyhow::anyhow!("{err}"));
            tokio::spawn(async move {
                this.defer_quic_conn(&quic_conn, err.as_ref()).await;
            });
        });

        let this_close = Arc::clone(self);
        let quic_conn_for_close = Arc::clone(&quic_conn);
        let close_defer_fn: super::packet::CloseDeferFn = Arc::new(move || {
            this_close.udp_input_map.delete(conn_id);
            let this = Arc::clone(&this_close);
            let quic_conn = Arc::clone(&quic_conn_for_close);
            tokio::spawn(async move {
                tokio::time::sleep(DEFAULT_UDP_TIMEOUT).await;
                let open_streams = this.open_streams.add(-1);
                if open_streams == 0 && this.closed.load() {
                    this.force_close(Some(&quic_conn), Some(types::type_::Error::ClientClosed.into())).await;
                }
            });
        });

        let pc = QuicStreamPacketConn::new(
            conn_id,
            Arc::clone(&quic_conn),
            // S11: remove in U8, when the final net bridge is deleted.
            Some(new_buffered_conn(new_extended_conn(murmur_common_net::io::OldConnAsStream(pipe2)))),
            self.option.udp_relay_mode,
            self.option.max_udp_relay_packet_size,
            Some(defer_quic_conn_fn),
            Some(close_defer_fn),
            None,
        );
        Ok(pc)
    }
}

/// The inner pointer. `Drop` is the finalizer, reached only once every outward-facing [`Client`]
/// handle (and every [`RefPacketConn`] still holding one) is gone.
#[derive(Debug)]
struct ClientOuter(Arc<ClientImpl>);

impl Drop for ClientOuter {
    fn drop(&mut self) {
        log::debugln!("Close TuicV5 Client at {:p}", Arc::as_ptr(&self.0));
        let inner = Arc::clone(&self.0);
        tokio::spawn(async move {
            inner.force_close(None, Some(types::type_::Error::ClientClosed.into())).await;
        });
    }
}

#[derive(Clone, Debug)]
pub struct Client(Arc<ClientOuter>);

impl Client {
    fn inner(&self) -> &Arc<ClientImpl> {
        &self.0 .0
    }

    #[must_use]
    pub fn open_streams(&self) -> i64 {
        self.inner().open_streams()
    }

    #[must_use]
    pub fn last_visited(&self) -> Option<DateTime<Utc>> {
        self.inner().last_visited()
    }

    pub fn set_last_visited(&self, last: DateTime<Utc>) {
        self.inner().set_last_visited(last);
    }

    pub async fn dial_context(
        &self,
        ctx: CancellationToken,
        metadata: &mut Metadata,
    ) -> anyhow::Result<Box<dyn NetConn>> {
        let conn = self.inner().dial_context(ctx, metadata).await?;
        let this = Arc::clone(&self.0);
        let ref_: Arc<dyn Any + Send + Sync> = this;
        // S11: remove in U5, once this module's own dial_context returns Stream.
        Ok(Box::new(StreamAsOldConn::new(new_ref_conn(murmur_common_net::io::OldConnAsStream(conn), ref_))))
    }

    pub async fn listen_packet(
        &self,
        ctx: CancellationToken,
        metadata: &mut Metadata,
    ) -> anyhow::Result<Box<dyn PacketConn>> {
        let pc = self.inner().listen_packet(ctx, metadata).await?;
        Ok(Box::new(RefPacketConn { pc, _ref: Arc::clone(&self.0) }))
    }
}

/// Keeps `t` (the [`ClientOuter`], whose `Drop` is the client's
/// finalizer) alive for as long as the packet conn returned from `ListenPacket` is in use.
struct RefPacketConn {
    pc: Arc<QuicStreamPacketConn>,
    _ref: Arc<ClientOuter>,
}

#[async_trait::async_trait]
impl PacketConn for RefPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, Box<dyn Addr>)> {
        let (n, addr) = Datagram::recv_from(&*self.pc, buf).await?;
        Ok((n, Box::new(murmur_common_net::io::udp_addr_from_socket_addr(addr))))
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> std::io::Result<usize> {
        let addr = murmur_common_net::io::old_addr_to_socket_addr(addr)?;
        Datagram::send_to(&*self.pc, buf, addr).await
    }

    fn local_addr(&self) -> std::io::Result<Box<dyn Addr>> {
        let addr = Datagram::local_addr(&*self.pc)?;
        Ok(Box::new(murmur_common_net::io::udp_addr_from_socket_addr(addr)))
    }

    fn close(&self) -> std::io::Result<()> {
        Datagram::close(&*self.pc)
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> std::io::Result<()> {
        self.pc.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> std::io::Result<()> {
        self.pc.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> std::io::Result<()> {
        self.pc.set_write_deadline(deadline)
    }
}

/// Builds a client. The finalizer becomes [`ClientOuter`]'s `Drop`.
pub fn new_client(client_option: ClientOption, udp: bool, dial_fn: types::type_::DialFunc) -> Client {
    let inner = Arc::new(ClientImpl {
        option: client_option,
        dial_fn,
        udp,
        quic_conn: TokioMutex::new(None),
        open_streams: AtomicI64Value::default(),
        closed: AtomicBoolValue::default(),
        udp_input_map: xsync::map::Map::default(),
        last_visited: TypedValue::default(),
    });
    let client = Client(Arc::new(ClientOuter(inner)));
    log::debugln!("New TuicV5 Client at {:p}", Arc::as_ptr(&client.0));
    client
}
