//! `hyper`'s HTTP/2 client half runs over the already-established conn, speaking a single
//! duplex-streamed request/response.
//!
//! The request body is fed through a `tokio::io::duplex`, and the response body — polled directly
//! via `hyper::body::Body::poll_frame` — is what the reader drains.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::future::BoxFuture;
use futures::StreamExt as _;
use http_body_util::StreamBody;
use hyper::body::{Body as HttpBody, Frame, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex as SyncMutex;
use rand::Rng as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{Mutex as AsyncMutex, OnceCell};
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{OldConnAsStream, Stream, StreamAsOldConn};
use murmur_common_net::setup_context_for_conn;
use murmur_std_compat::net::{Addr, Conn as NetConn};

/// The unbuffered pipe's buffering: the pipe blocks the writer until the reader drains,
/// this build's duplex tolerates a bounded amount of unread data instead.
const UPLOAD_PIPE_CAPACITY: usize = 64 * 1024;

#[derive(Clone, Debug, Default)]
pub struct H2Config {
    pub hosts: Vec<String>,
    pub path: String,
}

type ReqBody = StreamBody<futures::stream::BoxStream<'static, Result<Frame<Bytes>, io::Error>>>;

/// The response body, read directly through `hyper::body::Body::poll_frame` instead of an
/// intermediate channel since the response is already in hand once `establish` returns.
struct IncomingReader {
    body: Incoming,
    leftover: Option<Bytes>,
}

impl AsyncRead for IncomingReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(data) = this.leftover.take() {
                let n = data.len().min(buf.remaining());
                let (chunk, _) = data.split_at(n);
                buf.put_slice(chunk);
                if n < data.len() {
                    this.leftover = Some(data.slice(n..));
                }
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        this.leftover = Some(data);
                    }
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(io::Error::other(err))),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Reads and writes touch the response body and request writer directly with no lock, relying on
/// the conn's (and, once established, two independent objects') concurrent-read/write guarantee.
/// The `Arc<AsyncMutex<Inner>>` this type used to share between them held its guard
/// across each side's pending network `.await`, so a client-speaks-first exchange (read pending
/// on `common::net::relay`'s read-first poll order while a write is ready to go out) stalled the
/// write behind the unrelated read, the same class of hang as finding 21.
/// `reader` and `pwriter` now live behind their own
/// `tokio::sync::Mutex`, mirroring that fix's `ReadInner`/`WriteInner` split; `established`
/// coordinates the one-time connection-establishment RoundTrip so it runs exactly once and is
/// awaited (not re-executed) by whichever side reaches it first, without holding either the
/// reader or the pwriter lock while that RoundTrip is in flight.
struct Inner {
    send_request: SyncMutex<hyper::client::conn::http2::SendRequest<ReqBody>>,
    cfg: H2Config,
    established: OnceCell<()>,
    reader: AsyncMutex<Option<IncomingReader>>,
    pwriter: AsyncMutex<Option<DuplexStream>>,
}

impl Inner {
    async fn establish_once(&self) -> io::Result<()> {
        if self.cfg.hosts.is_empty() {
            return Err(io::Error::other("hosts is empty"));
        }
        let index = rand::rng().random_range(0..self.cfg.hosts.len());
        let host = self.cfg.hosts.get(index).ok_or_else(|| io::Error::other("hosts is empty"))?.clone();
        let path = self.cfg.path.clone();

        let (client_half, server_half) = tokio::io::duplex(UPLOAD_PIPE_CAPACITY);
        let body_stream = ReaderStream::new(server_half).map(|chunk| chunk.map(Frame::data)).boxed();
        let body = StreamBody::new(body_stream);

        let uri: hyper::Uri = format!("https://{host}{path}").parse().map_err(io::Error::other)?;
        let request = hyper::Request::builder()
            .method("PUT")
            .uri(uri)
            .header("Accept-Encoding", "identity")
            .version(hyper::Version::HTTP_2)
            .body(body)
            .map_err(io::Error::other)?;

        let response_future = self.send_request.lock().send_request(request);
        let response = response_future.await.map_err(io::Error::other)?;

        *self.pwriter.lock().await = Some(client_half);
        *self.reader.lock().await = Some(IncomingReader { body: response.into_body(), leftover: None });
        Ok(())
    }

    async fn ensure_established(&self) -> io::Result<()> {
        self.established.get_or_try_init(|| self.establish_once()).await?;
        Ok(())
    }

    async fn do_read(&self, b: &mut [u8]) -> io::Result<usize> {
        self.ensure_established().await?;
        let mut guard = self.reader.lock().await;
        guard.as_mut().ok_or_else(|| io::Error::other("reader not installed"))?.read(b).await
    }

    async fn do_write(&self, b: &[u8]) -> io::Result<usize> {
        self.ensure_established().await?;
        let mut guard = self.pwriter.lock().await;
        guard.as_mut().ok_or_else(|| io::Error::other("writer not installed"))?.write(b).await
    }
}

type ReadFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;
type WriteFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;

/// The h2 conn holds its transport conn as a private field rather than exposing it, so it
/// promotes close, the addresses and the deadline setters but not the half-close accessors — a
/// half-close type-assertion on this conn fails and does nothing.
/// Forwarding through the bare `SharedConn` would answer that assertion by reaching the TLS/TCP
/// connection the whole h2 session runs on, turning a relay half-close into a full shutdown; this
/// view forwards only the capabilities the `h2Conn` actually has.
struct H2Transport(SharedConn);

/// Never actually polled — [`H2Transport`] only ever answers [`NetConn`]'s capability methods
/// through [`Stream::old_conn`] — but [`NetConn`] requires `AsyncRead + AsyncWrite`, so this
/// forwards to the same [`SharedConn`] `H2Conn` itself reads and writes through.
impl AsyncRead for H2Transport {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2Transport {
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

impl NetConn for H2Transport {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr()
    }
    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.remote_addr()
    }
    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_deadline(deadline)
    }
    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_read_deadline(deadline)
    }
    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_write_deadline(deadline)
    }
}

pub struct H2Conn {
    inner: Arc<Inner>,
    conn: SharedConn,
    close_view: H2Transport,
    read: SyncMutex<Option<ReadFuture>>,
    write: SyncMutex<Option<WriteFuture>>,
    read_buf: SyncMutex<Vec<u8>>,
    write_buf: SyncMutex<Vec<u8>>,
}

impl AsyncRead for H2Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut read = this.read.lock();
        if read.is_none() {
            let inner = Arc::clone(&this.inner);
            let mut tmp = std::mem::take(&mut *this.read_buf.lock());
            tmp.clear();
            tmp.resize(buf.remaining(), 0);
            *read = Some(Box::pin(async move {
                let result = inner.do_read(&mut tmp).await;
                (tmp, result)
            }));
        }
        let Some(future) = read.as_mut() else {
            return Poll::Ready(Err(io::Error::other("read future was just installed")));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready((tmp, result)) => {
                *read = None;
                drop(read);
                match result {
                    Ok(n) => {
                        let (chunk, _) = tmp.split_at(n);
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

impl AsyncWrite for H2Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut write = this.write.lock();
        if write.is_none() {
            let inner = Arc::clone(&this.inner);
            let mut data = std::mem::take(&mut *this.write_buf.lock());
            data.clear();
            data.extend_from_slice(buf);
            *write = Some(Box::pin(async move {
                let result = inner.do_write(&data).await;
                (data, result)
            }));
        }
        let Some(future) = write.as_mut() else {
            return Poll::Ready(Err(io::Error::other("write future was just installed")));
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

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl Stream for H2Conn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        OldConnAsStream(self.conn.clone()).local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        OldConnAsStream(self.conn.clone()).peer_addr()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        NetConn::as_socket(&self.conn)
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(&self.close_view)
    }
}

impl std::fmt::Debug for H2Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Conn").finish_non_exhaustive()
    }
}

pub async fn stream_h2_conn(
    ctx: &CancellationToken,
    conn: Box<dyn NetConn>,
    cfg: H2Config,
) -> anyhow::Result<Box<dyn NetConn>> {
    let shared = SharedConn::from_boxed(conn);
    let mut done = setup_context_for_conn(ctx, shared.clone());

    let result: anyhow::Result<Box<dyn NetConn>> = async {
        let io = TokioIo::new(shared.clone());
        let (send_request, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(io).await?;
        let connection_task: BoxFuture<'static, ()> = Box::pin(async move {
            let _ = connection.await;
        });
        tokio::spawn(connection_task);

        let conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(H2Conn {
            inner: Arc::new(Inner {
                send_request: SyncMutex::new(send_request),
                cfg: cfg.clone(),
                established: OnceCell::new(),
                reader: AsyncMutex::new(None),
                pwriter: AsyncMutex::new(None),
            }),
            conn: shared.clone(),
            close_view: H2Transport(shared.clone()),
            read: SyncMutex::new(None),
            write: SyncMutex::new(None),
            read_buf: SyncMutex::new(Vec::new()),
            write_buf: SyncMutex::new(Vec::new()),
        }));
        Ok(conn)
    }
    .await;

    let mut err = result.as_ref().err().map(|err| anyhow::anyhow!("{err}"));
    done.call(&mut err).await;
    match err {
        Some(err) => Err(err),
        None => result,
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::{IpAddr, Ipv4Addr};

    use futures::stream;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use murmur_std_compat::net::{Addr, TcpAddr};

    struct DuplexConn(DuplexStream);

    impl AsyncRead for DuplexConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DuplexConn {
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

    impl NetConn for DuplexConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Finding 21 regression, extended to `H2Conn`: the
    /// in-process HTTP/2 server answers with response headers but a body that never produces a
    /// frame and never ends, so `H2Conn::read` is left pending on a silent peer exactly like
    /// `common::net::relay`'s read-first poll order leaves a client-speaks-first exchange
    /// pending. Before the read/write lock split, both `reader` and `pwriter` lived behind one
    /// `Arc<AsyncMutex<Inner>>` held across the pending read's network `.await` inside
    /// `establish`, so a concurrent write never reached the wire and this test timed out. After
    /// the split, `establish` runs once (shared via `OnceCell`, not re-executed) to install both
    /// halves, and the write completes through its own independent `pwriter` lock without
    /// waiting on the unrelated pending read.
    #[tokio::test]
    async fn write_does_not_block_behind_pending_read() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let service = service_fn(|_req: hyper::Request<Incoming>| async move {
                let never: stream::BoxStream<'static, Result<Frame<Bytes>, Infallible>> = stream::pending().boxed();
                Ok::<_, Infallible>(hyper::Response::new(StreamBody::new(never)))
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server_io), service)
                .await;
        });

        let cfg = H2Config { hosts: vec!["example.com".to_owned()], path: "/".to_owned() };
        let ctx = CancellationToken::new();
        let conn = stream_h2_conn(&ctx, Box::new(DuplexConn(client_io)), cfg).await.expect("h2 handshake must succeed");
        let (mut read_half, mut write_half) = tokio::io::split(conn);

        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            read_half.read(&mut buf).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let write_result = tokio::time::timeout(std::time::Duration::from_secs(3), write_half.write_all(b"hi")).await;
        assert!(write_result.is_ok(), "write blocked behind the pending read (finding 21 regression)");
        write_result.unwrap().unwrap();

        read_task.abort();
        server_task.abort();
    }

    /// Regression for the review of `152f46e2`: `H2Conn` used to answer `Stream::old_conn` with
    /// the bare `SharedConn` its hyper client runs on, so `StreamAsOldConn::close_write` (a relay
    /// half-close, e.g. `common-net::sing::relay_inner` after the inbound side hits EOF) reached
    /// through to a real `shutdown(SHUT_WR)` on the underlying TCP socket. hyper's h2 server
    /// treats that as the whole connection ending and tears it down, cutting a vless-over-h2
    /// download short even though the `h2Conn` has no half-close accessor and a `close_write`
    /// there is a no-op. This test fails on `152f46e2` (times out reading `tail`) and passes once
    /// `old_conn` answers with `H2Transport` instead.
    #[tokio::test]
    async fn close_write_does_not_cut_an_h2_download_short() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server_task = tokio::spawn(async move {
            let (server_io, _) = listener.accept().await.expect("accept");
            let service = service_fn(|_req: hyper::Request<Incoming>| async move {
                let body: stream::BoxStream<'static, Result<Frame<Bytes>, Infallible>> =
                    stream::once(async { Ok(Frame::data(Bytes::from_static(b"first"))) })
                        .chain(stream::once(async {
                            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                            Ok(Frame::data(Bytes::from_static(b"tail")))
                        }))
                        .boxed();
                Ok::<_, Infallible>(hyper::Response::new(StreamBody::new(body)))
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server_io), service)
                .await;
        });

        let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let client: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(client));
        let cfg = H2Config { hosts: vec!["example.com".to_owned()], path: "/".to_owned() };
        let ctx = CancellationToken::new();
        let mut conn = stream_h2_conn(&ctx, client, cfg).await.expect("h2 handshake must succeed");

        conn.write_all(b"").await.expect("trigger the deferred h2 handshake");

        let mut first = [0u8; 5];
        conn.read_exact(&mut first).await.expect("read the first chunk");
        assert_eq!(&first, b"first");

        conn.close_write().expect("close_write");

        let mut tail = [0u8; 4];
        tokio::time::timeout(std::time::Duration::from_secs(3), conn.read_exact(&mut tail))
            .await
            .expect("close_write must not cut the download short")
            .expect("still able to read the tail chunk after close_write");
        assert_eq!(&tail, b"tail");

        server_task.abort();
    }
}
