//! The server side drives one HTTP/2 server over the raw carrier and turns each inbound HTTP/2
//! request into one accepted connection.
//!
//! The request body is the read side, the flushed-after-every-write response body is the write
//! side, and a `200` status is sent before the conn is handed out. The client side drives one
//! HTTP/2 transport over the same carrier and turns each `Open` into an HTTP/2 CONNECT request
//! whose response body / request body pipe become the read/write sides, with the read side
//! blocking until the response headers arrive.
//!
//! Both ends use the raw `h2` crate codec rather than a full HTTP server/transport, since both
//! ends of the multiplexed session live in this one file and don't need real HTTP request-line
//! semantics.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use h2::client::{self, ResponseFuture, SendRequest};
use h2::server;
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode, Uri};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use crate::session::{MuxConn, MuxStream, Session};
use murmur_log::warnln;

/// The max read frame size on both the server and the client transport. The `h2` default is
/// 16 KiB, so leaving it unset would make this crate reject the 32 KiB frames a peer is willing
/// to send.
const MAX_FRAME_SIZE: u32 = 32 * 1024;

/// The streams one carrier may hold open at once: the h2 `SETTINGS_MAX_CONCURRENT_STREAMS` a peer
/// is told, which h2 enforces by resetting anything past it.
const MAX_CONCURRENT_STREAMS: u32 = 1024;

/// The inbound queue depth: the accept loop stops admitting while the service is this far behind,
/// the way the smux session's accept queue does.
const ACCEPT_BACKLOG: usize = 256;

struct RecvHalf {
    stream: RecvStream,
    pending: Bytes,
}

impl RecvHalf {
    fn new(stream: RecvStream) -> Self {
        Self { stream, pending: Bytes::new() }
    }

    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = buf.remaining().min(self.pending.len());
                let chunk = self.pending.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match self.stream.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    let _ = self.stream.flow_control().release_capacity(chunk.len());
                    self.pending = chunk;
                }
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Err(crate::error::wrap_error(io::Error::other(err))))
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

struct SendHalf {
    stream: SendStream<Bytes>,
    end_of_stream: bool,
}

impl SendHalf {
    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.stream.reserve_capacity(buf.len());
        match self.stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                let n = capacity.min(buf.len());
                let data = Bytes::copy_from_slice(buf.split_at(n).0);
                self.stream.send_data(data, false).map_err(|err| crate::error::wrap_error(io::Error::other(err)))?;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(crate::error::wrap_error(io::Error::other(err)))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "h2 stream closed"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush() -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(&mut self) -> Poll<io::Result<()>> {
        if !self.end_of_stream {
            let _ = self.stream.send_data(Bytes::new(), true);
            self.end_of_stream = true;
        }
        Poll::Ready(Ok(()))
    }
}

trait H2ReadHalf: Send {
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>>;
}

impl H2ReadHalf for RecvHalf {
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Self::poll_read(self, cx, buf)
    }
}

/// The blocking read that waits on the connection setup to deliver the response
/// body: here that's waiting on the `h2` `ResponseFuture` for the response headers. the
/// The late-connection wrapper also arms a timeout timer that cancels the request, and the setup
/// error is made permanent, so [`Latched`] replays it on every later read.
#[derive(Clone)]
struct Latched {
    kind: io::ErrorKind,
    message: String,
}

impl Latched {
    fn new(err: &io::Error) -> Self {
        Self { kind: err.kind(), message: err.to_string() }
    }

    /// Only ever observed inside the `mem::replace` that installs a real value in the same
    /// statement, never returned to a caller.
    fn placeholder() -> Self {
        Self { kind: io::ErrorKind::Other, message: String::new() }
    }

    fn to_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

enum ClientRead {
    Waiting { response: ResponseFuture, deadline: Pin<Box<tokio::time::Sleep>> },
    Ready(RecvHalf),
    Failed(Latched),
}

struct ClientReadState {
    state: ClientRead,
}

impl ClientReadState {
    fn waiting(response: ResponseFuture, deadline: Duration) -> Self {
        Self { state: ClientRead::Waiting { response, deadline: Box::pin(tokio::time::sleep(deadline)) } }
    }
}

impl H2ReadHalf for ClientReadState {
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // Taking the state out ends every borrow before the next transition writes it back.
        let state = std::mem::replace(&mut self.state, ClientRead::Failed(Latched::placeholder()));
        match state {
            ClientRead::Failed(err) => {
                let replayed = err.to_error();
                self.state = ClientRead::Failed(err);
                Poll::Ready(Err(replayed))
            }
            ClientRead::Ready(mut recv) => {
                let polled = recv.poll_read(cx, buf);
                self.state = ClientRead::Ready(recv);
                polled
            }
            ClientRead::Waiting { mut response, mut deadline } => {
                let outcome = match Pin::new(&mut response).poll(cx) {
                    Poll::Ready(Ok(response)) if response.status() == StatusCode::OK => {
                        Ok(RecvHalf::new(response.into_body()))
                    }
                    Poll::Ready(Ok(response)) => {
                        Err(io::Error::other(format!("unexpected status: {}", response.status())))
                    }
                    Poll::Ready(Err(err)) => Err(io::Error::other(err)),
                    Poll::Pending if deadline.as_mut().poll(cx).is_ready() => {
                        Err(io::Error::new(io::ErrorKind::TimedOut, "sing-mux: h2mux connect timed out"))
                    }
                    Poll::Pending => {
                        self.state = ClientRead::Waiting { response, deadline };
                        return Poll::Pending;
                    }
                };
                match outcome {
                    Ok(mut recv) => {
                        let polled = recv.poll_read(cx, buf);
                        self.state = ClientRead::Ready(recv);
                        polled
                    }
                    Err(err) => {
                        self.state = ClientRead::Failed(Latched::new(&err));
                        Poll::Ready(Err(err))
                    }
                }
            }
        }
    }
}

struct H2Stream<R: H2ReadHalf> {
    recv: R,
    send: SendHalf,
    active: Arc<AtomicUsize>,
}

impl<R: H2ReadHalf> Drop for H2Stream<R> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<R: H2ReadHalf + Unpin> AsyncRead for H2Stream<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.recv.poll_read(cx, buf)
    }
}

impl<R: H2ReadHalf + Unpin> AsyncWrite for H2Stream<R> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.send.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        SendHalf::poll_flush()
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send.poll_shutdown()
    }
}

#[derive(Debug)]
pub struct H2MuxServerSession {
    inbound: AsyncMutex<mpsc::Receiver<Box<dyn MuxStream>>>,
    active: Arc<AtomicUsize>,
    done: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl H2MuxServerSession {
    #[must_use]
    pub fn new(conn: Box<dyn MuxConn>) -> Self {
        let (tx, rx) = mpsc::channel(ACCEPT_BACKLOG);
        let active = Arc::new(AtomicUsize::new(0));
        let task_active = Arc::clone(&active);
        let done = Arc::new(AtomicBool::new(false));
        let task_done = Arc::clone(&done);
        let task = tokio::spawn(async move {
            let mut connection = match server::Builder::new()
                .max_frame_size(MAX_FRAME_SIZE)
                .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
                .handshake(conn)
                .await
            {
                Ok(connection) => connection,
                Err(err) => {
                    warnln!("sing-mux: h2mux server handshake failed: {err}");
                    task_done.store(true, Ordering::SeqCst);
                    return;
                }
            };
            loop {
                match connection.accept().await {
                    Some(Ok((request, mut respond))) => {
                        #[expect(
                            clippy::expect_used,
                            reason = "a 200 status over an empty body is a fixed, always-valid head"
                        )]
                        let response =
                            Response::builder().status(StatusCode::OK).body(()).expect("valid response head");
                        let Ok(send_stream) = respond.send_response(response, false) else {
                            continue;
                        };
                        task_active.fetch_add(1, Ordering::SeqCst);
                        let recv = RecvHalf::new(request.into_body());
                        let send = SendHalf { stream: send_stream, end_of_stream: false };
                        let stream: Box<dyn MuxStream> =
                            Box::new(H2Stream { recv, send, active: Arc::clone(&task_active) });
                        if tx.send(stream).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(err)) => {
                        warnln!("sing-mux: h2mux server connection error: {err}");
                        break;
                    }
                    None => break,
                }
            }
            task_done.store(true, Ordering::SeqCst);
        });
        Self { inbound: AsyncMutex::new(rx), active, done, task }
    }
}

#[async_trait]
impl Session for H2MuxServerSession {
    async fn open(&self, _tcp_timeout: Duration) -> io::Result<Box<dyn MuxStream>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "h2mux server session cannot open streams"))
    }

    // cancel-safe: receives from a channel, so a dropped call leaves the queued item for the next one.
    async fn accept(&self) -> io::Result<Box<dyn MuxStream>> {
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "h2mux server session closed"))
    }

    fn num_streams(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    async fn close(&self) -> io::Result<()> {
        self.done.store(true, Ordering::SeqCst);
        self.task.abort();
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    fn can_take_new_request(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct H2MuxClientSession {
    send_request: Mutex<SendRequest<Bytes>>,
    active: Arc<AtomicUsize>,
    done: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl H2MuxClientSession {
    pub async fn new(conn: Box<dyn MuxConn>) -> io::Result<Self> {
        let (send_request, connection) = client::Builder::new()
            .max_frame_size(MAX_FRAME_SIZE)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .handshake(conn)
            .await
            .map_err(io::Error::other)?;
        let done = Arc::new(AtomicBool::new(false));
        let task_done = Arc::clone(&done);
        let task = tokio::spawn(async move {
            if let Err(err) = connection.await {
                warnln!("sing-mux: h2mux client connection error: {err}");
            }
            task_done.store(true, Ordering::SeqCst);
        });
        Ok(Self { send_request: Mutex::new(send_request), active: Arc::new(AtomicUsize::new(0)), done, task })
    }
}

#[async_trait]
impl Session for H2MuxClientSession {
    async fn open(&self, tcp_timeout: Duration) -> io::Result<Box<dyn MuxStream>> {
        let send_request = self.send_request.lock().clone();
        let mut send_request = send_request.ready().await.map_err(io::Error::other)?;
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(Uri::from_static("https://localhost"))
            .body(())
            .map_err(io::Error::other)?;
        let (response_future, send_stream) = send_request.send_request(request, false).map_err(io::Error::other)?;
        self.active.fetch_add(1, Ordering::SeqCst);
        let recv = ClientReadState::waiting(response_future, tcp_timeout);
        let send = SendHalf { stream: send_stream, end_of_stream: false };
        Ok(Box::new(H2Stream { recv, send, active: Arc::clone(&self.active) }))
    }

    // cancel-safe: returns immediately without touching shared state.
    async fn accept(&self) -> io::Result<Box<dyn MuxStream>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "h2mux client session cannot accept streams"))
    }

    fn num_streams(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    async fn close(&self) -> io::Result<()> {
        self.done.store(true, Ordering::SeqCst);
        self.task.abort();
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    /// Asks the h2 connection whether it can carry
    /// another stream; answering `false` unconditionally makes [`crate::client::Client`] open a
    /// fresh carrier per stream instead of multiplexing.
    fn can_take_new_request(&self) -> bool {
        let mut send_request = self.send_request.lock().clone();
        let mut cx = Context::from_waker(Waker::noop());
        matches!(Pin::new(&mut send_request).poll_ready(&mut cx), Poll::Ready(Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::{
        client, Bytes, H2MuxClientSession, H2MuxServerSession, Method, Request, ResponseFuture, SendStream, Uri,
        ACCEPT_BACKLOG, MAX_CONCURRENT_STREAMS,
    };
    use crate::padding::new_padding_conn;
    use crate::session::MuxConn;
    use crate::session::Session;

    #[tokio::test]
    async fn round_trip_over_a_padded_carrier() {
        let (client_io, server_io) = duplex(64 * 1024);
        let client_io: Box<dyn MuxConn> = new_padding_conn(Box::new(client_io));
        let server_io: Box<dyn MuxConn> = new_padding_conn(Box::new(server_io));
        let server = H2MuxServerSession::new(server_io);
        let client = H2MuxClientSession::new(client_io).await.expect("client handshake");

        let mut client_stream = client.open(Duration::from_secs(5)).await.expect("open");
        let mut server_stream = tokio::time::timeout(Duration::from_secs(5), server.accept())
            .await
            .expect("accept within 5s")
            .expect("accept");

        client_stream.write_all(b"hello from client").await.expect("client write");
        let mut buf = [0u8; 32];
        let n = server_stream.read(&mut buf).await.expect("server read");
        assert_eq!(&buf[..n], b"hello from client");
    }

    #[tokio::test]
    async fn round_trip_over_duplex() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server = H2MuxServerSession::new(Box::new(server_io));
        let client = H2MuxClientSession::new(Box::new(client_io)).await.expect("client handshake");

        let mut client_stream = client.open(Duration::from_secs(5)).await.expect("open");
        let mut server_stream = server.accept().await.expect("accept");

        assert_eq!(client.num_streams(), 1);
        assert_eq!(server.num_streams(), 1);

        client_stream.write_all(b"hello from client").await.expect("client write");
        client_stream.flush().await.expect("client flush");
        let mut buf = [0u8; 32];
        let n = server_stream.read(&mut buf).await.expect("server read");
        assert_eq!(&buf[..n], b"hello from client");

        server_stream.write_all(b"hello from server").await.expect("server write");
        server_stream.flush().await.expect("server flush");
        let mut buf = [0u8; 32];
        let n = client_stream.read(&mut buf).await.expect("client read");
        assert_eq!(&buf[..n], b"hello from server");

        drop(client_stream);
        drop(server_stream);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(client.num_streams(), 0);
        assert_eq!(server.num_streams(), 0);

        assert!(!client.is_closed());
        assert!(!server.is_closed());
        client.close().await.expect("client close");
        server.close().await.expect("server close");
        assert!(client.is_closed());
        assert!(server.is_closed());
    }

    #[tokio::test]
    async fn server_cannot_open_and_client_cannot_accept() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server = H2MuxServerSession::new(Box::new(server_io));
        let client = H2MuxClientSession::new(Box::new(client_io)).await.expect("client handshake");

        assert!(!server.can_take_new_request());
        assert!(client.can_take_new_request());
        let open_err = server.open(Duration::from_secs(1)).await.err().expect("server open is unsupported");
        let accept_err = client.accept().await.err().expect("client accept is unsupported");
        assert_eq!(open_err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(accept_err.kind(), std::io::ErrorKind::Unsupported);
    }

    /// Waits for the session's admitted-stream count to stop moving, then reports it.
    async fn settled_num_streams(server: &H2MuxServerSession) -> usize {
        let mut last = 0;
        let mut stable = 0;
        for _ in 0..300 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let now = server.num_streams();
            stable = if now == last { stable + 1 } else { 0 };
            if stable >= 5 {
                break;
            }
            last = now;
        }
        server.num_streams()
    }

    /// A peer that opens streams faster than the service drains them cannot drive the session's
    /// admitted set: the queue stops the accept loop and the peer is told a ceiling instead of
    /// unlimited concurrency.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_peer_cannot_admit_more_streams_than_the_backlog() {
        let (client_io, server_io) = duplex(256 * 1024);
        let server = H2MuxServerSession::new(Box::new(server_io));

        let (mut send_request, connection) =
            client::Builder::new().handshake(client_io).await.expect("client handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });

        // Kept alive, so the peer holds every stream it opened; nothing ever accepts them.
        let mut held: Vec<(ResponseFuture, SendStream<Bytes>)> = Vec::new();
        while held.len() < ACCEPT_BACKLOG + 64 {
            let mut ready = send_request.ready().await.expect("another stream fits");
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri(Uri::from_static("https://localhost"))
                .body(())
                .expect("request");
            held.push(ready.send_request(request, true).expect("send"));
            send_request = ready;
        }

        let admitted = settled_num_streams(&server).await;
        assert!(
            admitted <= ACCEPT_BACKLOG + 1,
            "the session admits at most its backlog plus its hand-off, got {admitted}"
        );
        assert_eq!(
            send_request.current_max_send_streams(),
            MAX_CONCURRENT_STREAMS as usize,
            "the peer must be told a ceiling rather than unlimited concurrency"
        );
    }
}
