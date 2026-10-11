//! Modified from: <https://github.com/Qv2ray/gun-lite>.
//!
//! The transport dials through `hyper`'s HTTP/2 client half directly; the outer transport and the
//! inner client collapse into one type here, since this crate has no fork-level connection pool
//! to layer under it.
//!
//! The runtime assertions the source performs on its writer and reader
//! have no Rust equivalent for a `Pin<Box<dyn AsyncWrite>>`/`Pin<Box<dyn AsyncRead>>`: closing
//! drops the trait object instead (RAII stands in place of an explicit close call), and the flush
//! probe is dropped outright since the writer half this crate owns is always a pipe writer, which
//! never flushes — the branch is dead code in the source it mirrors.
//!
//! The ALPN mismatch check inspects the dialed conn's TLS connection state.
//! `vmess::tls::stream_tls_conn` now returns `Box<dyn TlsConn>`, whose
//! `tls_connection_state()` runs the same check on the plain-TLS/uTLS branches.
//!
//! A second live handle to the dialed conn would close the socket directly, but
//! `hyper`'s HTTP/2 handshake takes ownership of its `io`
//! argument, so there is no duplicate handle to store. Instead the returned [`Conn`]'s
//! `on_close` hook tears down the whole [`Transport`] (aborting its connection-driving task),
//! which severs the same underlying socket synchronously with the caller's close call.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::StreamExt as _;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::client::conn::http2;
use hyper::header::{HeaderValue, CONTENT_TYPE, USER_AGENT};
use hyper::{HeaderMap, Method, Request, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex as SyncMutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::io::{ReaderStream, StreamReader};
use tokio_util::sync::CancellationToken;

use murmur_common_httputils::addr::{new_addr_context, GotConnInfo, NetAddr};
use murmur_common_httputils::force_close;
use murmur_common_net::sing::{ExtendedWriter, UpstreamNode};
use murmur_common_pool as pool;
use murmur_compat::sing_buf::Buffer;
use murmur_constant::adapters::DEFAULT_TLS_TIMEOUT;
use murmur_std_compat::net::{Addr, Conn as NetConn};
use murmur_transport_vmess::tls::{stream_tls_conn, TlsConfig};

use super::utils::{read_u_variant, u_varint_len};

pub const HTTP2_NEXT_PROTO_TLS: &str = "h2";

/// The unbuffered pipe between `Conn`'s writer half and the outgoing HTTP/2 request body.
const UPLOAD_PIPE_CAPACITY: usize = 64 * 1024;

const MAX_VARINT_LEN_64: usize = 10;

#[derive(thiserror::Error, Debug)]
pub enum GunError {
    #[error("invalid length")]
    InvalidLength,
    #[error("buffer too small")]
    SmallBuffer,
}

fn default_header() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    headers.insert(USER_AGENT, HeaderValue::from_static("grpc-go/1.36.0"));
    headers
}

pub type DialFn =
    Arc<dyn Fn(CancellationToken, String, String) -> BoxFuture<'static, Result<Box<dyn NetConn>>> + Send + Sync>;

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub service_name: String,
    pub user_agent: String,
    pub host: String,
    pub ping_interval: i32,
}

pub type InitFn = Arc<dyn Fn(Arc<NetAddr>) -> BoxFuture<'static, Result<Pin<Box<dyn AsyncRead + Send>>>> + Send + Sync>;

fn put_uvarint(buf: &mut [u8], mut x: u64) -> usize {
    let mut i = 0;
    while x >= 0x80 {
        let (Some(slot), Ok(byte)) = (buf.get_mut(i), u8::try_from(x & 0x7f)) else {
            return i;
        };
        *slot = byte | 0x80;
        x >>= 7;
        i += 1;
    }
    let (Some(slot), Ok(byte)) = (buf.get_mut(i), u8::try_from(x)) else {
        return i;
    };
    *slot = byte;
    i + 1
}

fn err_short_frame() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "gun: frame buffer too small")
}

/// Writes the 5-byte gRPC message header plus the protobuf field tag and payload length into
/// `buf`, and yields the payload region that follows them.
fn write_frame_header(buf: &mut [u8], var_len: usize, data_len: usize) -> io::Result<&mut [u8]> {
    let frame_len = u32::try_from(1 + var_len + data_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "gun: gRPC frame exceeds the 4-byte length field"))?;
    let (flag, rest) = buf.split_first_mut().ok_or_else(err_short_frame)?;
    *flag = 0x00;
    let (length, rest) = rest.split_at_mut(4);
    length.copy_from_slice(&frame_len.to_be_bytes());
    let (compressed, rest) = rest.split_first_mut().ok_or_else(err_short_frame)?;
    *compressed = 0x0A;
    let (varint, payload) = rest.split_at_mut(var_len);
    put_uvarint(varint, data_len as u64);
    Ok(payload)
}

fn err_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

struct InitState {
    reader: Option<Pin<Box<dyn AsyncRead + Send>>>,
    remain: usize,
}

fn read_locked<'a>(
    state: &'a mut InitState,
    b: &'a mut [u8],
) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
    Box::pin(async move {
        let Some(reader) = state.reader.as_mut() else {
            return Err(err_closed());
        };
        if state.remain > 0 {
            let size = state.remain.min(b.len());
            let Some(buf) = b.get_mut(..size) else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "gun: short read buffer"));
            };
            let n = reader.read(buf).await?;
            state.remain -= n;
            return Ok(n);
        }

        if let Err(err) = reader.read_exact(&mut [0u8; 6]).await {
            return if err.kind() == io::ErrorKind::UnexpectedEof { Ok(0) } else { Err(err) };
        }

        let Some(reader) = state.reader.as_mut() else {
            return Err(err_closed());
        };
        let payload_len = read_u_variant(reader).await.map_err(|_| io::Error::other(GunError::InvalidLength))?;
        state.remain = usize::try_from(payload_len).map_err(|_| io::Error::other(GunError::InvalidLength))?;
        read_locked(state, b).await
    })
}

/// `Conn`, minus the poll-driven `AsyncRead`/`AsyncWrite` glue, which lives on [`Conn`] so the
/// futures it drives can be boxed and polled independently of `&self`/`&mut self` borrows.
struct Shared {
    init_fn: InitFn,
    net_addr: Arc<NetAddr>,
    writer: AsyncMutex<Option<Pin<Box<dyn AsyncWrite + Send>>>>,
    closer: SyncMutex<Option<Box<dyn NetConn>>>,
    init: AsyncMutex<Option<Result<(), Arc<anyhow::Error>>>>,
    state: AsyncMutex<InitState>,
    closed: SyncMutex<bool>,
    on_close: SyncMutex<Option<Box<dyn FnOnce() + Send>>>,
    deadline: SyncMutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Shared {
    fn new(init_fn: InitFn, writer: Pin<Box<dyn AsyncWrite + Send>>) -> Arc<Self> {
        Arc::new(Self {
            init_fn,
            net_addr: Arc::new(NetAddr::default()),
            writer: AsyncMutex::new(Some(writer)),
            closer: SyncMutex::new(None),
            init: AsyncMutex::new(None),
            state: AsyncMutex::new(InitState { reader: None, remain: 0 }),
            closed: SyncMutex::new(false),
            on_close: SyncMutex::new(None),
            deadline: SyncMutex::new(None),
        })
    }

    /// Holding the async lock across the whole initializer gives
    /// every concurrent caller the same block-until-done, cache-forever result.
    async fn init(&self) -> Result<(), Arc<anyhow::Error>> {
        let mut guard = self.init.lock().await;
        if let Some(result) = &*guard {
            return result.clone();
        }
        let outcome = (self.init_fn)(Arc::clone(&self.net_addr)).await;
        let result = match outcome {
            Ok(reader) => {
                let mut state = self.state.lock().await;
                if *self.closed.lock() {
                    drop(state);
                    drop(reader);
                    Err(Arc::new(anyhow!(err_closed())))
                } else {
                    state.reader = Some(reader);
                    drop(state);
                    Ok(())
                }
            }
            Err(err) => Err(Arc::new(err)),
        };
        *guard = Some(result.clone());
        result
    }

    async fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        self.init().await.map_err(|err| io::Error::other(format!("{err}")))?;
        let mut state = self.state.lock().await;
        read_locked(&mut state, b).await
    }

    async fn write(&self, b: &[u8]) -> io::Result<usize> {
        let data_len = b.len();
        let var_len = u_varint_len(data_len as u64);
        let mut buf = pool::get(6 + var_len + data_len);
        write_frame_header(&mut buf, var_len, data_len)?.copy_from_slice(b);

        let write_result = {
            let mut guard = self.writer.lock().await;
            match guard.as_mut() {
                Some(writer) => writer.write_all(&buf).await,
                None => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            }
        };
        let _ = pool::put(buf);

        let err = match write_result {
            Ok(()) => None,
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => match self.init().await {
                Ok(()) => Some(err),
                Err(init_err) => Some(io::Error::other(format!("{init_err}"))),
            },
            Err(err) => Some(err),
        };
        match err {
            Some(err) => Err(err),
            None => Ok(data_len),
        }
    }

    /// Forwards to the duplex half feeding the h2 request body: `Shared.writer` is a
    /// `tokio::io::duplex` half, and the actual TLS write reaches the wire through the spawned
    /// `hyper::client::conn::http2` connection task driving the other half (see
    /// `Transport::ensure_connected`), which flushes on every poll the same way `H2Conn`
    /// (`transport/vmess/h2.rs`) does. Forwarding here still matters: it drains any bytes
    /// `writer.write_all` reported as accepted but had not yet handed to the duplex's paired
    /// reader.
    async fn flush(&self) -> io::Result<()> {
        let mut guard = self.writer.lock().await;
        match guard.as_mut() {
            Some(writer) => writer.flush().await,
            None => Ok(()),
        }
    }

    async fn write_buffer(&self, buffer: &mut Buffer) -> io::Result<()> {
        let data_len = buffer.len();
        let var_len = u_varint_len(data_len as u64);
        let header = buffer.extend_header(6 + var_len);
        write_frame_header(header, var_len, data_len)?;

        let result = {
            let mut guard = self.writer.lock().await;
            match guard.as_mut() {
                Some(writer) => writer.write_all(buffer.bytes()).await,
                None => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            }
        };
        buffer.release();

        match result {
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => match self.init().await {
                Ok(()) => Err(err),
                Err(init_err) => Err(io::Error::other(format!("{init_err}"))),
            },
            other => other,
        }
    }

    /// The writer/reader are torn down through the same async locks
    /// `read`/`write` hold across their I/O, in a spawned task, since a synchronous `try_lock`
    /// would silently skip the teardown whenever a read or write happens to be in flight —
    /// where closing the underlying writer or response body interrupts a
    /// blocked call directly, this still lets an in-flight read/write finish before its slot is
    /// cleared, but it always eventually clears it instead of leaking the connection open.
    fn close(self: &Arc<Self>) -> io::Result<()> {
        let mut closed = self.closed.lock();
        if *closed {
            return Ok(());
        }
        *closed = true;
        drop(closed);

        let shared = Arc::clone(self);
        tokio::spawn(async move {
            *shared.writer.lock().await = None;
            shared.state.lock().await.reader = None;
        });

        let mut messages = Vec::new();
        let conn_closer = self.closer.lock().take();
        if let Some(conn) = conn_closer {
            if let Err(err) = conn.close() {
                messages.push(err.to_string());
            }
        }
        let on_close = self.on_close.lock().take();
        if let Some(callback) = on_close {
            callback();
        }

        if messages.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(messages.join("\n")))
        }
    }
}

type ReadFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;
type WriteFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;
type FlushFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'static>>;

pub struct Conn {
    shared: Arc<Shared>,
    read: SyncMutex<Option<ReadFuture>>,
    write: SyncMutex<Option<WriteFuture>>,
    flush: SyncMutex<Option<FlushFuture>>,
    read_buf: SyncMutex<Vec<u8>>,
    write_buf: SyncMutex<Vec<u8>>,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}

impl Conn {
    pub fn new(init_fn: InitFn, writer: Pin<Box<dyn AsyncWrite + Send>>) -> Self {
        Self {
            shared: Shared::new(init_fn, writer),
            read: SyncMutex::new(None),
            write: SyncMutex::new(None),
            flush: SyncMutex::new(None),
            read_buf: SyncMutex::new(Vec::new()),
            write_buf: SyncMutex::new(Vec::new()),
        }
    }

    /// The embedded `NetAddr` the transport was built with.
    pub fn net_addr(&self) -> Arc<NetAddr> {
        Arc::clone(&self.shared.net_addr)
    }

    pub fn set_closer(&self, closer: Box<dyn NetConn>) {
        *self.shared.closer.lock() = Some(closer);
    }

    pub fn set_on_close(&self, f: impl FnOnce() + Send + 'static) {
        *self.shared.on_close.lock() = Some(Box::new(f));
    }

    pub async fn init(&self) -> Result<()> {
        self.shared.init().await.map_err(|err| anyhow!("{err}"))
    }

    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "the frame header plus the widest uvarint is 16, well inside i32"
    )]
    pub const fn front_headroom(&self) -> i32 {
        (6 + MAX_VARINT_LEN_64) as i32
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut read = this.read.lock();
        if read.is_none() {
            let shared = Arc::clone(&this.shared);
            let mut tmp = std::mem::take(&mut *this.read_buf.lock());
            tmp.clear();
            tmp.resize(buf.remaining(), 0);
            *read = Some(Box::pin(async move {
                let result = shared.read(&mut tmp).await;
                (tmp, result)
            }));
        }
        let Some(future) = read.as_mut() else {
            return Poll::Ready(Err(err_closed()));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready((tmp, result)) => {
                *read = None;
                drop(read);
                match result {
                    Ok(n) => {
                        let Some(chunk) = tmp.get(..n) else {
                            *this.read_buf.lock() = tmp;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "gun: read reported more bytes than the buffer it was given",
                            )));
                        };
                        buf.put_slice(chunk);
                        *this.read_buf.lock() = tmp;
                        Poll::Ready(Ok(()))
                    }
                    Err(err) => {
                        *this.read_buf.lock() = tmp;
                        Poll::Ready(Err(err))
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut write = this.write.lock();
        if write.is_none() {
            let shared = Arc::clone(&this.shared);
            let mut data = std::mem::take(&mut *this.write_buf.lock());
            data.clear();
            data.extend_from_slice(buf);
            *write = Some(Box::pin(async move {
                let result = shared.write(&data).await;
                (data, result)
            }));
        }
        let Some(future) = write.as_mut() else {
            return Poll::Ready(Err(err_closed()));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready((data, result)) => {
                *write = None;
                drop(write);
                *this.write_buf.lock() = data;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut flush = this.flush.lock();
        if flush.is_none() {
            let shared = Arc::clone(&this.shared);
            *flush = Some(Box::pin(async move { shared.flush().await }));
        }
        let Some(future) = flush.as_mut() else {
            return Poll::Ready(Err(err_closed()));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                *flush = None;
                drop(flush);
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl NetConn for Conn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.shared.net_addr.local_addr_result()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.shared.net_addr.remote_addr_result()
    }

    fn close(&self) -> io::Result<()> {
        self.shared.close()
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.set_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.set_deadline(deadline)
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let previous = self.shared.deadline.lock().take();
        if let Some(handle) = previous {
            handle.abort();
        }
        if let Some(instant) = deadline {
            let shared = Arc::clone(&self.shared);
            let handle = tokio::spawn(async move {
                tokio::time::sleep_until(instant).await;
                let _ = shared.close();
            });
            *self.shared.deadline.lock() = Some(handle);
        }
        Ok(())
    }
}

impl UpstreamNode for Conn {
    fn front_headroom(&self) -> Option<i32> {
        Some(self.front_headroom())
    }
}

#[async_trait]
impl ExtendedWriter for Conn {
    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        self.shared.write_buffer(buffer).await
    }
}

type ReqBody = StreamBody<futures::stream::BoxStream<'static, io::Result<Frame<Bytes>>>>;

pub struct Transport {
    dial_fn: DialFn,
    tls_config: Option<TlsConfig>,
    cfg: Config,
    ctx: CancellationToken,
    close_once: std::sync::Once,
    count: AtomicI64,
    send_request: AsyncMutex<Option<http2::SendRequest<ReqBody>>>,
    connection_task: SyncMutex<Option<tokio::task::JoinHandle<()>>>,
    local_remote: SyncMutex<Option<(Arc<dyn Addr>, Arc<dyn Addr>)>>,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport").field("cfg", &self.cfg).finish_non_exhaustive()
    }
}

impl force_close::RoundTripper for Transport {
    fn close(&self) {
        let handle = self.connection_task.lock().take();
        if let Some(handle) = handle {
            handle.abort();
        }
        if let Ok(mut guard) = self.send_request.try_lock() {
            *guard = None;
        }
    }
}

impl Transport {
    pub fn close(&self) -> Result<()> {
        self.close_once.call_once(|| {
            self.ctx.cancel();
            force_close::close_transport(self);
        });
        Ok(())
    }

    /// The transport's dial path, with its TLS timeout and the ALPN check documented at the top of
    /// this file.
    // cancel-safe: the dialled connection is owned by the timed block, so a timeout drops it rather than
    // leaving it reachable by a caller.
    async fn dial_and_wrap_tls(&self) -> Result<Box<dyn NetConn>> {
        let dial_fn = Arc::clone(&self.dial_fn);
        let tls_config = self.tls_config.clone();
        let host = self.cfg.host.clone();
        let ctx = self.ctx.clone();
        let fut = async move {
            let pconn = dial_fn(ctx.clone(), "tcp".to_owned(), host).await?;
            let Some(tls_config) = tls_config else {
                return Ok(pconn);
            };
            let conn =
                stream_tls_conn(&ctx, Box::new(murmur_common_net::io::OldConnAsStream(pconn)), &tls_config).await?;
            // Every wrapper that does not return the negotiated ALPN is excluded:
            // Shadow-TLS, restls, reality and TLS-mirror all unset.
            if tls_config.shadow_tls.is_none()
                && tls_config.restls.is_none()
                && tls_config.reality.is_none()
                && tls_config.tls_mirror.is_none()
            {
                let state = conn.tls_connection_state();
                if state.negotiated_protocol != HTTP2_NEXT_PROTO_TLS {
                    let _ = murmur_common_net::io::close_stream(conn.as_ref());
                    return Err(anyhow!(
                        "http2: unexpected ALPN protocol {}, want {}",
                        state.negotiated_protocol,
                        HTTP2_NEXT_PROTO_TLS
                    ));
                }
            }
            let conn: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(conn));
            Ok(conn)
        };
        tokio::time::timeout(DEFAULT_TLS_TIMEOUT, fut).await.map_err(|_| anyhow!("gun: dial timed out"))?
    }

    /// The implicit connection reuse inside the transport's round trip, standing in place of a TLS
    /// dial plus the `hyper` HTTP/2 handshake this build drives directly.
    async fn ensure_connected(&self) -> Result<http2::SendRequest<ReqBody>> {
        let mut guard = self.send_request.lock().await;
        if let Some(send_request) = &*guard {
            if !send_request.is_closed() {
                return Ok(send_request.clone());
            }
        }

        let conn = self.dial_and_wrap_tls().await?;
        let local = conn.local_addr().ok().map(Arc::<dyn Addr>::from);
        let remote = conn.remote_addr().ok().map(Arc::<dyn Addr>::from);
        if let (Some(local), Some(remote)) = (local, remote) {
            *self.local_remote.lock() = Some((local, remote));
        }

        let io = TokioIo::new(conn);
        let mut builder = http2::Builder::new(TokioExecutor::new());
        let ping_interval = u64::try_from(self.cfg.ping_interval).unwrap_or(0);
        if ping_interval > 0 {
            builder.keep_alive_interval(std::time::Duration::from_secs(ping_interval));
        }
        let (send_request, connection) = builder.handshake(io).await?;
        let handle = tokio::spawn(async move {
            let _ = connection.await;
        });
        *self.connection_task.lock() = Some(handle);
        let cached = send_request.clone();
        *guard = Some(send_request);
        drop(guard);
        Ok(cached)
    }

    /// One dial attempt, without the connection counter and close hook [`Transport::dial`] adds.
    async fn dial_conn(&self) -> Result<Conn> {
        let service_name = if self.cfg.service_name.is_empty() { "GunService" } else { &self.cfg.service_name };
        let path = service_name_to_path(service_name);

        let (client_half, server_half) = tokio::io::duplex(UPLOAD_PIPE_CAPACITY);
        let body_stream = ReaderStream::new(server_half).map(|chunk| chunk.map(Frame::data)).boxed();
        let body = StreamBody::new(body_stream);

        let mut header = default_header();
        if !self.cfg.user_agent.is_empty() {
            if let Ok(value) = HeaderValue::from_str(&self.cfg.user_agent) {
                header.insert(USER_AGENT, value);
            }
        }

        let uri: Uri = format!("https://{}{}", self.cfg.host, path).parse()?;
        let mut request = Request::builder().method(Method::POST).uri(uri).version(Version::HTTP_2).body(body)?;
        *request.headers_mut() = header;

        let send_request = self.ensure_connected().await?;
        let request_slot = SyncMutex::new(Some(request));

        let init_fn: InitFn = Arc::new(move |_addr: Arc<NetAddr>| {
            let request = request_slot.lock().take();
            let mut send_request = send_request.clone();
            Box::pin(async move {
                let request = request.ok_or_else(|| anyhow!("gun: conn already initialized"))?;
                let response = send_request.send_request(request).await?;
                let stream = response.into_body().into_data_stream().map(|res| res.map_err(io::Error::other));
                let reader: Pin<Box<dyn AsyncRead + Send>> = Box::pin(StreamReader::new(stream));
                Ok(reader)
            })
        });

        let conn = Conn::new(init_fn, Box::pin(client_half));
        let local_remote = self.local_remote.lock().clone();
        if let Some((local, remote)) = local_remote {
            let trace = new_addr_context(conn.net_addr());
            if let Some(got_conn) = trace.got_conn {
                let conn_addr: Arc<dyn NetConn> = Arc::new(AddrOnlyConn { local, remote });
                got_conn(&GotConnInfo { conn: conn_addr, reused: false });
            }
        }
        Ok(conn)
    }

    /// Only the start of the one-time init is awaited, never the round trip
    /// itself: a gRPC-style duplex handler commonly withholds its response headers until the
    /// client's first request frame arrives, which `dial` itself would then block on.
    pub async fn dial(self: &Arc<Self>) -> Result<Box<dyn NetConn>> {
        let conn = self.dial_conn().await?;
        self.count.fetch_add(1, Ordering::SeqCst);
        let this = Arc::clone(self);
        conn.set_on_close(move || {
            this.count.fetch_add(-1, Ordering::SeqCst);
        });
        let shared = Arc::clone(&conn.shared);
        tokio::spawn(async move {
            let _ = shared.init().await;
        });
        Ok(Box::new(conn))
    }
}

/// A conn that only ever reports its local and remote addresses, standing in as
/// the traced conn when this build has already dialed and only needs the address
/// pair.
struct AddrOnlyConn {
    local: Arc<dyn Addr>,
    remote: Arc<dyn Addr>,
}

impl std::fmt::Debug for AddrOnlyConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddrOnlyConn").finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct SharedAddr(Arc<dyn Addr>);

impl Addr for SharedAddr {
    fn network(&self) -> &str {
        self.0.network()
    }

    fn string(&self) -> String {
        self.0.string()
    }

    fn addr_port(&self) -> Option<murmur_std_compat::net::AddrPort> {
        self.0.addr_port()
    }

    fn raw_addr(&self) -> Option<&dyn Addr> {
        self.0.raw_addr()
    }

    fn as_iface_prefix(&self) -> Option<ipnet::IpNet> {
        self.0.as_iface_prefix()
    }

    fn as_sock_addr(&self) -> Option<murmur_std_compat::net::SockAddr> {
        self.0.as_sock_addr()
    }
}

impl AsyncRead for AddrOnlyConn {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }
}

impl AsyncWrite for AddrOnlyConn {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl NetConn for AddrOnlyConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(SharedAddr(Arc::clone(&self.local))))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(SharedAddr(Arc::clone(&self.remote))))
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

pub fn new_transport(dial_fn: DialFn, tls_config: Option<TlsConfig>, gun_cfg: Config) -> Arc<Transport> {
    Arc::new(Transport {
        dial_fn,
        tls_config,
        cfg: gun_cfg,
        ctx: CancellationToken::new(),
        close_once: std::sync::Once::new(),
        count: AtomicI64::new(0),
        send_request: AsyncMutex::new(None),
        connection_task: SyncMutex::new(None),
        local_remote: SyncMutex::new(None),
    })
}

#[must_use]
pub fn service_name_to_path(service_name: &str) -> String {
    if service_name.starts_with('/') {
        return service_name.to_owned();
    }
    format!("/{service_name}/Tun")
}

struct ClientState {
    transports: Vec<Arc<Transport>>,
}

pub struct Client {
    state: SyncMutex<ClientState>,
    max_connections: i32,
    min_streams: i32,
    max_streams: i32,
    maker: Arc<dyn Fn() -> Arc<Transport> + Send + Sync>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("max_connections", &self.max_connections)
            .field("min_streams", &self.min_streams)
            .field("max_streams", &self.max_streams)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub async fn dial(&self) -> Result<Box<dyn NetConn>> {
        self.get_transport().dial().await
    }

    pub fn close(&self) -> Result<()> {
        let transports = std::mem::take(&mut self.state.lock().transports);
        let mut messages = Vec::new();
        for transport in transports {
            if let Err(err) = transport.close() {
                messages.push(err.to_string());
            }
        }
        if messages.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(messages.join("\n")))
        }
    }

    fn get_transport(&self) -> Arc<Transport> {
        let mut state = self.state.lock();
        let mut chosen: Option<Arc<Transport>> = None;
        for transport in &state.transports {
            let better = match &chosen {
                None => true,
                Some(current) => transport.count.load(Ordering::SeqCst) < current.count.load(Ordering::SeqCst),
            };
            if better {
                chosen = Some(Arc::clone(transport));
            }
        }
        let Some(transport) = chosen else {
            return self.new_transport_locked(&mut state);
        };
        let num_streams = transport.count.load(Ordering::SeqCst);
        if num_streams == 0 {
            drop(state);
            return transport;
        }
        let connections = i64::try_from(state.transports.len()).unwrap_or(i64::MAX);
        if self.max_connections > 0 {
            if connections >= i64::from(self.max_connections) || num_streams < i64::from(self.min_streams) {
                drop(state);
                return transport;
            }
        } else if self.max_streams > 0 && num_streams < i64::from(self.max_streams) {
            drop(state);
            return transport;
        }
        self.new_transport_locked(&mut state)
    }

    fn new_transport_locked(&self, state: &mut ClientState) -> Arc<Transport> {
        let transport = (self.maker)();
        state.transports.push(Arc::clone(&transport));
        transport
    }
}

pub fn new_client(
    maker: Arc<dyn Fn() -> Arc<Transport> + Send + Sync>,
    max_connections: i32,
    min_streams: i32,
    max_streams: i32,
) -> Client {
    let (max_connections, min_streams, max_streams) = if max_connections == 0 && min_streams == 0 && max_streams == 0 {
        (1, min_streams, max_streams)
    } else {
        (max_connections, min_streams, max_streams)
    };
    Client {
        state: SyncMutex::new(ClientState { transports: Vec::new() }),
        max_connections,
        min_streams,
        max_streams,
        maker,
    }
}

pub async fn stream_gun_with_conn(
    conn: Box<dyn NetConn>,
    tls_config: Option<TlsConfig>,
    gun_cfg: Config,
) -> Result<Box<dyn NetConn>> {
    let raw = Arc::new(AsyncMutex::new(Some(conn)));
    let dial_fn: DialFn = Arc::new(move |_ctx, _network, _addr| {
        let raw = Arc::clone(&raw);
        Box::pin(async move { raw.lock().await.take().ok_or_else(|| anyhow!("gun: underlying conn already used")) })
    });

    let transport = new_transport(dial_fn, tls_config, gun_cfg);
    let conn = transport.dial_conn().await?;
    let closing_transport = Arc::clone(&transport);
    conn.set_on_close(move || {
        let _ = closing_transport.close();
    });
    let shared = Arc::clone(&conn.shared);
    tokio::spawn(async move {
        let _ = shared.init().await;
    });
    Ok(Box::new(conn))
}

#[cfg(test)]
mod tests {
    use futures::future::BoxFuture;
    use tokio::io::AsyncReadExt;

    use super::*;

    fn never_init() -> InitFn {
        Arc::new(|_addr| -> BoxFuture<'static, Result<Pin<Box<dyn AsyncRead + Send>>>> {
            Box::pin(async { Err(anyhow!("test init not expected")) })
        })
    }

    /// Regression test for the `Box<C>`-blanket-`Conn`-impl bug: `TlsConn`'s blanket used to bind
    /// on `NetConn` directly, and `common/net/io.rs`'s `impl<C: Conn + ?Sized> Conn for Box<C>`
    /// makes `Box<dyn TlsConn>` a `NetConn` too, so the box itself satisfied that blanket and
    /// `conn.tls_connection_state()` answered with the box's own identity instead of the boxed
    /// uTLS conn's — `get_tls_connection_state` always failed its downcast and reported
    /// `negotiated_protocol: ""`, even though the real handshake negotiated `h2`, spuriously
    /// failing this dial. `TlsConn`'s blanket now binds on `ConcreteConn`
    /// (`component::tls::utls`), which nothing forwards through `Box`, so the box no longer
    /// qualifies and dispatch always reaches the boxed conn's own vtable.
    #[tokio::test]
    async fn dial_and_wrap_tls_reads_alpn_through_the_box_not_the_box_identity() {
        use murmur_component_tls::utls;
        use murmur_testsupport::TLS_CONFIG;
        use murmur_testsupport_probe::ensure_test_crypto_provider;
        use murmur_transport_vmess::tls::TlsConfig;

        ensure_test_crypto_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else { return };
            let server = utls::server(Box::new(stream), TLS_CONFIG.clone());
            let ctx = CancellationToken::new();
            if server.handshake_context(&ctx).await.is_ok() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });

        let dial_fn: DialFn = Arc::new(move |_ctx, _network, _addr| {
            Box::pin(async move {
                let stream = tokio::net::TcpStream::connect(addr).await?;
                let boxed: Box<dyn NetConn> = Box::new(stream);
                Ok(boxed)
            })
        });

        let tls_config = TlsConfig {
            host: "example.com".to_owned(),
            skip_cert_verify: true,
            next_protos: vec![HTTP2_NEXT_PROTO_TLS.to_owned()],
            ..Default::default()
        };

        let transport = new_transport(dial_fn, Some(tls_config), Config::default());
        let result = transport.dial_and_wrap_tls().await;
        assert!(result.is_ok(), "expected the negotiated h2 ALPN to be read correctly, got {:?}", result.err());
    }

    /// The ALPN gate is skipped for every wrapper that does not report a
    /// negotiated ALPN: shadow-TLS, restls, reality and TLS-mirror all unset.
    /// A REALITY conn's wrapper state is an `ErasedTlsConn`, whose `tls_connection_state()` falls
    /// through `get_tls_connection_state` to the default empty protocol, so gating on the
    /// shadow-TLS and TLS-mirror options alone rejected every REALITY dial to a gRPC server.
    #[tokio::test]
    async fn reality_wrapped_conn_passes_the_alpn_gate() {
        use std::collections::HashSet;

        use murmur_reality::{
            reality_server_accept, BoxedStream, DialDest, RealityClientConfig, RealityServerConfig, MAX_SHORT_ID_LEN,
        };
        use murmur_transport_vmess::tls::TlsConfig;

        // A fixed X25519 pair; the public half must match the server's private half, and nothing
        // here needs a fresh key per run.
        let server_private: [u8; 32] = [
            0x9c, 0x1b, 0x1f, 0x5a, 0x1e, 0x0a, 0x1c, 0x1d, 0x3f, 0x5a, 0x7b, 0x9d, 0x1f, 0x3a, 0x5c, 0x7e, 0x9b, 0x1d,
            0x3f, 0x5a, 0x7c, 0x9e, 0x1b, 0x3d, 0x5f, 0x7a, 0x9c, 0x1e, 0x3b, 0x5d, 0x7f, 0x9a,
        ];
        let server_public: [u8; 32] = [
            0xbb, 0x21, 0x82, 0xce, 0xb8, 0xf4, 0xfd, 0x9d, 0x1a, 0xfc, 0x86, 0xfb, 0x9f, 0x94, 0xb9, 0x17, 0x28, 0x10,
            0x75, 0x87, 0xd9, 0xac, 0x6a, 0xc5, 0x81, 0xda, 0xf1, 0x12, 0xbc, 0x38, 0x36, 0x46,
        ];
        let short_id = [0x42u8; MAX_SHORT_ID_LEN];
        let mut server_names = HashSet::new();
        server_names.insert("example.test".to_owned());
        let mut short_ids = HashSet::new();
        short_ids.insert(short_id);
        let dial_dest: DialDest = Arc::new(|| {
            Box::pin(async {
                let (a, b) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    let mut a = a;
                    let mut buf = [0u8; 4096];
                    while matches!(a.read(&mut buf).await, Ok(n) if n > 0) {}
                });
                let boxed: BoxedStream = Box::new(b);
                Ok(boxed)
            })
        });
        let server_cfg = RealityServerConfig::new(
            server_private,
            server_names,
            short_ids,
            Some(std::time::Duration::from_secs(300)),
            dial_dest,
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else { return };
            if let Ok(mut stream) = reality_server_accept(stream, &server_cfg).await {
                let mut buf = [0u8; 64];
                while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
            }
        });

        let dial_fn: DialFn = Arc::new(move |_ctx, _network, _addr| {
            Box::pin(async move {
                let stream = tokio::net::TcpStream::connect(addr).await?;
                let boxed: Box<dyn NetConn> = Box::new(stream);
                Ok(boxed)
            })
        });

        let tls_config = TlsConfig {
            host: "example.test".to_owned(),
            next_protos: vec![HTTP2_NEXT_PROTO_TLS.to_owned()],
            // REALITY runs over uTLS, so a REALITY config with no client fingerprint is rejected;
            // every config converter defaults it to `chrome`.
            client_fingerprint: "chrome".to_owned(),
            reality: Some(Arc::new(RealityClientConfig { public_key: server_public, short_id })),
            ..Default::default()
        };

        let transport = new_transport(dial_fn, Some(tls_config), Config::default());
        let result = transport.dial_and_wrap_tls().await;
        assert!(
            result.is_ok(),
            "a REALITY conn carries no negotiated ALPN and must not be gated on it: {:?}",
            result.err()
        );
    }

    /// The wire bytes for a 5-byte payload: `00 00 00 00 07 0a 05 68 65 6c 6c 6f`.
    #[tokio::test]
    async fn write_frames_short_payload() {
        let (client, mut server) = tokio::io::duplex(64);
        let shared = Shared::new(never_init(), Box::pin(client));

        let n = shared.write(b"hello").await.unwrap();
        assert_eq!(n, 5);

        let mut got = [0u8; 12];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [0x00, 0x00, 0x00, 0x00, 0x07, 0x0a, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);
    }

    /// The length varint becomes two bytes at 128 payload bytes: a 500-byte payload frames as the
    /// six-byte fixed header `00 00 01 f7` plus the varint `0a f4 03`.
    #[tokio::test]
    async fn write_frames_multi_byte_varint_length() {
        let (client, mut server) = tokio::io::duplex(1024);
        let shared = Shared::new(never_init(), Box::pin(client));

        let payload = vec![0xABu8; 500];
        let n = shared.write(&payload).await.unwrap();
        assert_eq!(n, 500);

        let mut header = [0u8; 8];
        server.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [0x00, 0x00, 0x00, 0x01, 0xf7, 0x0a, 0xf4, 0x03]);

        let mut body = vec![0u8; 500];
        server.read_exact(&mut body).await.unwrap();
        assert_eq!(body, payload);
    }
}
