//!
//! the server handler returns a handler that, on a matching gRPC request,
//! writes response headers and then blocks the current task inside the connection handler
//! before returning.
//!
//! `hyper`'s request handler cannot keep a `Response` open while still writing
//! to it, so — mirroring `transport/xhttp/server.rs` and `transport/mekya/server.rs` — this build
//! returns the streamed `Response` immediately (backed by an `mpsc`-channel body) and drives
//! the connection handler in a spawned task; the wrapper's `closed` flag becomes a
//! `Arc<AtomicBool>` flipped once that task's connection-handler call returns, since the wrapper handed
//! to the connection handler is consumed by value, whereas the source keeps closing the wrapper on the
//! same pointer afterwards.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::StreamExt as _;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::StreamReader;

use murmur_common_httputils::addr::{set_addr_from_request, NetAddr};
use murmur_common_net::sing::{new_deadline_conn, ExtendedConn, UpstreamNode};
use murmur_compat::sing_buf::Buffer;
use murmur_std_compat::net::Conn as NetConn;

use super::gun::{service_name_to_path, Conn as GunConn, InitFn};

/// The response body channel's buffer, in frames: a response writer has no equivalent bound
/// (every write is flushed immediately), so this is a generous, arbitrary backpressure limit,
/// matching `transport/xhttp/server.rs`'s identical adapter.
const RESPONSE_CHANNEL_CAPACITY: usize = 32;

type ResponseBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;
type ChannelSender = tokio::sync::mpsc::Sender<Bytes>;

/// Stands in for `http_body_util::channel::Channel` (its `channel` Cargo feature is not enabled
/// for this crate; see `transport/xhttp/server.rs`'s identical adapter).
struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
}

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, std::convert::Infallible>>> {
        self.rx.poll_recv(cx).map(|chunk| chunk.map(|chunk| Ok(hyper::body::Frame::data(chunk))))
    }
}

fn channel_body(buffer: usize) -> (ChannelSender, ChannelBody) {
    let (tx, rx) = tokio::sync::mpsc::channel(buffer);
    (tx, ChannelBody { rx })
}

/// `Pin<Box<dyn AsyncWrite + Send>>` over the response's `mpsc` channel, standing in place of the
/// response writer on the `writer` side of `gun.Conn`.
struct ChannelWriter {
    tx: ChannelSender,
    pending: Option<Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>>,
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.is_none() {
            let data = Bytes::copy_from_slice(buf);
            let len = data.len();
            let tx = this.tx.clone();
            this.pending = Some(Box::pin(async move {
                tx.send(data).await.map(|()| len).map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
            }));
        }
        let Some(pending) = this.pending.as_mut() else {
            return Poll::Ready(Err(err_closed()));
        };
        match pending.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.pending = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Conceals the h2-special typed error before it returns to the
/// caller.
struct H2RequestBodyWrapper<R> {
    inner: R,
}

impl<R: AsyncRead + Unpin> AsyncRead for H2RequestBodyWrapper<R> {
    /// The body wrapper's read. The EOF guard has no Rust equivalent: EOF is `Ok(0)`, never an
    /// `Err`, so every `Err` this sees is remapped unconditionally.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_read(cx, buf) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(io::Error::new(err.kind(), format!("h2: {err}")))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// `ConnHandler`, adapted to yield a future since this build's tunnel handlers are async.
///
/// Mirrors the `futures::future::BoxFuture` convention used elsewhere in this crate, e.g.
/// `transport/xhttp/server.rs::ConnHandler`.
pub type ConnHandler = Arc<dyn Fn(Box<dyn ExtendedConn>) -> BoxFuture<'static, ()> + Send + Sync>;

/// The request handler trait, narrowed to the one method this package's request handling needs.
#[async_trait]
pub trait Handler: Send + Sync {
    async fn serve(&self, req: Request<Incoming>) -> Response<ResponseBody>;
}

/// The default fallback: an empty multiplexer answers every request `404`.
struct DefaultHandler;

#[async_trait]
impl Handler for DefaultHandler {
    async fn serve(&self, _req: Request<Incoming>) -> Response<ResponseBody> {
        let mut response = Response::new(http_body_util::Empty::<Bytes>::new().boxed());
        *response.status_mut() = StatusCode::NOT_FOUND;
        response
    }
}

pub struct ServerOption {
    pub service_name: String,
    pub conn_handler: ConnHandler,
    pub http_handler: Option<Arc<dyn Handler>>,
}

impl std::fmt::Debug for ServerOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerOption")
            .field("service_name", &self.service_name)
            .field("http_handler", &self.http_handler.is_some())
            .finish_non_exhaustive()
    }
}

/// The connection wrapper, rejecting a write after the handler finishes, avoiding a panic on `gun.Conn`.
/// A mutex guards `write`/`write_buffer` across their whole duration (holding it
/// across the delegated call); the wrapper checks-then-delegates against an `AtomicBool` instead of
/// holding a lock across the delegated `.await`, since the point of the guard — refusing writes
/// once [`Handler::serve`]'s spawned task has finished driving the connection handler — does not need
/// mutual exclusion between concurrent writers, only the one-shot "have we finished" observation.
pub(crate) struct H2ConnWrapper {
    extended_conn: Box<dyn ExtendedConn>,
    closed: Arc<AtomicBool>,
}

pub(crate) fn err_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

impl AsyncRead for H2ConnWrapper {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().extended_conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2ConnWrapper {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(err_closed()));
        }
        Pin::new(&mut *this.extended_conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().extended_conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().extended_conn).poll_shutdown(cx)
    }
}

impl murmur_common_net::io::Stream for H2ConnWrapper {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.extended_conn.local_addr()
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.extended_conn.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.extended_conn.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.extended_conn.shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn NetConn> {
        self.extended_conn.old_conn()
    }
}

impl murmur_common_net::io::ExtendedStream for H2ConnWrapper {
    fn reader_replaceable(&self) -> bool {
        murmur_common_net::io::ExtendedStream::reader_replaceable(&self.extended_conn)
    }
    fn writer_replaceable(&self) -> bool {
        murmur_common_net::io::ExtendedStream::writer_replaceable(&self.extended_conn)
    }
}

impl UpstreamNode for H2ConnWrapper {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&*self.extended_conn)
    }

    fn reader_replaceable(&self) -> Option<bool> {
        UpstreamNode::reader_replaceable(&*self.extended_conn)
    }

    fn writer_replaceable(&self) -> Option<bool> {
        UpstreamNode::writer_replaceable(&*self.extended_conn)
    }

    fn front_headroom(&self) -> Option<i32> {
        self.extended_conn.front_headroom()
    }

    fn rear_headroom(&self) -> Option<i32> {
        self.extended_conn.rear_headroom()
    }

    fn lazy_headroom(&self) -> bool {
        self.extended_conn.lazy_headroom()
    }

    fn reader_mtu(&self) -> Option<i32> {
        self.extended_conn.reader_mtu()
    }

    fn writer_mtu(&self) -> Option<i32> {
        self.extended_conn.writer_mtu()
    }
}

#[async_trait]
impl ExtendedConn for H2ConnWrapper {
    /// The promoted `ExtendedConn::read_buffer`, not overridden by the wrapper.
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        self.extended_conn.read_buffer(buffer).await
    }

    /// `write_buffer` on a closed wrapper returns the closed error without releasing `buffer`, where
    /// the only concrete implementation reachable here releases on its own return paths instead;
    /// that (leaking) behaviour is kept as is.
    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(err_closed());
        }
        self.extended_conn.write_buffer(buffer).await
    }
}

#[must_use]
pub fn new_server_handler(options: ServerOption) -> GunServerHandler {
    let path = service_name_to_path(&options.service_name);
    let http_handler = options.http_handler.unwrap_or_else(|| Arc::new(DefaultHandler));
    GunServerHandler { path, conn_handler: options.conn_handler, http_handler }
}

/// the anonymous handler the constructor returns.
pub struct GunServerHandler {
    path: String,
    conn_handler: ConnHandler,
    http_handler: Arc<dyn Handler>,
}

impl std::fmt::Debug for GunServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GunServerHandler").field("path", &self.path).finish_non_exhaustive()
    }
}

#[async_trait]
impl Handler for GunServerHandler {
    async fn serve(&self, request: Request<Incoming>) -> Response<ResponseBody> {
        let is_grpc_post = request.uri().path() == self.path
            && request.method() == Method::POST
            && request
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|content_type| content_type.starts_with("application/grpc"));

        if !is_grpc_post {
            return self.http_handler.serve(request).await;
        }

        let (tx, body) = channel_body(RESPONSE_CHANNEL_CAPACITY);
        let writer: Pin<Box<dyn AsyncWrite + Send>> = Box::pin(ChannelWriter { tx, pending: None });

        let request_once: StdMutex<Option<Request<Incoming>>> = StdMutex::new(Some(request));
        let init_fn: InitFn = Arc::new(move |addr: Arc<NetAddr>| {
            let mut guard = request_once.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let request = guard.take();
            drop(guard);
            Box::pin(async move {
                let Some(request) = request else {
                    return Err(anyhow::anyhow!("gun: server Conn init_fn invoked more than once"));
                };
                set_addr_from_request(&addr, &request);
                let incoming_stream =
                    request.into_body().into_data_stream().map(|chunk| chunk.map_err(io::Error::other));
                let reader: Pin<Box<dyn AsyncRead + Send>> =
                    Box::pin(H2RequestBodyWrapper { inner: StreamReader::new(incoming_stream) });
                Ok(reader)
            })
        });

        let conn = GunConn::new(init_fn, writer);
        let _ = conn.init().await;

        // S11: remove in U5, once gun::Conn implements Stream.
        let deadline_conn = new_deadline_conn(murmur_common_net::io::OldConnAsStream(conn));
        let closed = Arc::new(AtomicBool::new(false));
        let wrapper: Box<dyn ExtendedConn> =
            Box::new(H2ConnWrapper { extended_conn: deadline_conn, closed: Arc::clone(&closed) });

        let conn_handler = Arc::clone(&self.conn_handler);
        tokio::spawn(async move {
            conn_handler(wrapper).await;
            closed.store(true, Ordering::SeqCst);
        });

        let mut response = Response::new(body.boxed());
        *response.status_mut() = StatusCode::OK;
        response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
        response.headers_mut().insert(HeaderName::from_static("te"), HeaderValue::from_static("trailers"));
        response
    }
}
