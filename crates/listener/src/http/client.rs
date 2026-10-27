//! The HTTP client tunnels every new backend connection through a pipe plus
//! `tunnel.handle_tcp_conn`.
//!
//! A pooled client keeps idle connections alive and never follows redirects. This crate drops
//! the pool: every request dials a fresh tunnel connection and does a fresh HTTP/1.1 handshake,
//! the same trade-off `transport/mekya/client.rs`'s `H1Transport` already documents for this
//! crate. `hyper::client::conn` never follows redirects or adds `Accept-Encoding` on its own, so
//! no extra code is needed to match that behaviour.
//!
//! The request body streams to the backend as the dial proceeds, and the response is read back
//! the same way. The client connection (`conn`, the accepted
//! `BufferedConn`) is shared through an `Arc<tokio::sync::Mutex<_>>` (`SharedConnReader`): a
//! background task locks it to pump the declared request body straight into an `mpsc` channel
//! feeding [`SignalingBody`], hyper's outgoing request body, so the largest thing ever held
//! in memory for the request is one `PUMP_CHUNK_SIZE` chunk, never the whole body. `do_request`
//! itself never locks the connection until the pump is done, so there is no real contention, only
//! ownership shared across the task boundary. A mutex (rather than `tokio::io::split`, which
//! opaquely hides the inner `BufferedConn`) is what keeps `BufferedConn::peek` reachable, which
//! `transfer::read_trailer`'s bare-LF lookahead needs. A channel of results, rather than a duplex
//! byte-pipe, is what lets a pump failure (client closes mid-body, malformed chunk) reach hyper
//! *as an error*: a duplex pipe's writer half being dropped
//! after a failure is indistinguishable from a clean EOF, so hyper would treat the body as
//! complete and write a chunked encoder's `0\r\n\r\n` terminator for a body that never actually
//! finished, exactly the desync a truncated chunked upload must not produce (the backend must see
//! the request as unterminated, matching a writer that never closes the chunked encoder when the
//! body copy fails). `do_request` always waits for the pump to finish and reclaims the sole
//! `BufferedConn` back out of the `Arc` before returning, whether the round trip succeeded or not,
//! so the caller (`proxy.rs::forward`) can still write a response (or close) on the same
//! connection either way. The one case that cannot be recovered is the pump task panicking (never
//! triggered by remote input: `hack::pump_body` only ever returns `Err`, it does not panic), in
//! which case `do_request` reports no connection to reuse, and the caller then must simply close.
//!
//! The outgoing request's URI carries only the path and query (origin-form), rather than the full
//! absolute-form URI a forward proxy client sent. `proxy.rs::forward` already moved `Host` into an
//! explicit header for exactly this reason (see its module doc). The backend dial target is
//! therefore no longer recoverable from the outgoing request's URI (it has no authority);
//! `authority` and `scheme` carry it separately, taken straight from the parsed
//! [`Request`](super::hack::Request).

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use hyper::body::{Frame, Incoming};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use murmur_adapter_inbound::addition::Addition;
use murmur_adapter_inbound::http::new_http;
use murmur_common_net::bufconn::BufferedConn;
use murmur_common_net::pipe;
use murmur_component::dialer::bind::join_host_port;
use murmur_constant::tunnel::Tunnel;
use murmur_transport::socks5::socks5;

use super::hack::{pump_body, split_host_port, BodySink};

/// One item handed from [`ChannelSink`] to [`SignalingBody`]: a data chunk carrying its own
/// completion ack, or the pump's terminal error. Each chunk gets its own [`oneshot`] rather than
/// a shared signal so `flush` can never be woken by a stale signal left over from an earlier
/// chunk or from the body's very first (pre-chunk) poll.
enum BodyItem {
    Data(Bytes, oneshot::Sender<()>),
    Err(io::Error),
}

/// A chunk's ack fires once the bytes it contributed to hyper's write buffer have actually left
/// that buffer over the real wire, not merely once hyper has asked for the next frame: hyper
/// 1.11.1's h1 write buffer (`proto::h1::io::Buffered::poll_flush`) loops calling the underlying
/// `AsyncWrite::poll_write` until its buffer is fully drained, and only calls the underlying
/// `poll_flush` — where [`FlushAckedIo`] fires acks — once that loop breaks; if any `poll_write`
/// call along the way returns `Pending` (e.g. `pipe()`, whose own writes block until
/// the tunnel's peer actually reads them), the whole `Buffered::poll_flush` call returns `Pending`
/// too, without ever reaching ours. So firing a chunk's ack from [`SignalingBody`] itself, on the
/// next `poll_frame` going `Pending`, is not sound: hyper can still ask for (and receive) a later
/// frame — including [`ChannelSink`]'s error frame — in a *separate* `poll_write` call that runs
/// before the still-pending flush of an earlier chunk ever gets retried, since hyper's write loop
/// (`Dispatcher::poll_loop`) tries `poll_write` again before `poll_flush` on every iteration. Only
/// the wrapped transport's own `poll_flush` returning `Ready` proves every chunk staged so far
/// already reached the far end of the pipe.
struct FlushAckedIo<W> {
    inner: W,
    acks: Arc<Mutex<VecDeque<oneshot::Sender<()>>>>,
}

impl<W: AsyncRead + Unpin> AsyncRead for FlushAckedIo<W> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for FlushAckedIo<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            let mut acks = this.acks.lock();
            for ack in acks.drain(..) {
                let _ = ack.send(());
            }
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Hyper's outgoing request body for the forward path. Handing out a chunk pushes its ack onto
/// [`FlushAckedIo`]'s shared queue rather than firing it here: see that type's doc for why a
/// `Pending` poll is not the right signal.
struct SignalingBody {
    rx: mpsc::Receiver<BodyItem>,
    acks: Arc<Mutex<VecDeque<oneshot::Sender<()>>>>,
}

impl hyper::body::Body for SignalingBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, io::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(BodyItem::Data(bytes, ack))) => {
                self.acks.lock().push_back(ack);
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Some(BodyItem::Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Bounded channel capacity between the pump task and hyper's outgoing body stream: an
/// unbuffered pipe blocks the writer until the reader drains, so this crate tolerates a small
/// amount of read-ahead instead.
const BODY_PUMP_CHANNEL_CAPACITY: usize = 4;

struct ChannelSink {
    tx: mpsc::Sender<BodyItem>,
    chunk_ack: Option<oneshot::Receiver<()>>,
}

#[async_trait]
impl BodySink for ChannelSink {
    async fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.tx
            .send(BodyItem::Data(Bytes::copy_from_slice(data), ack_tx))
            .await
            .map_err(|_| anyhow!("body receiver dropped"))?;
        self.chunk_ack = Some(ack_rx);
        Ok(())
    }

    /// the per-chunk flush (see `hack::BodySink::flush`'s doc) is a synchronous flush on the same
    /// task that just wrote the chunk. This crate hands chunks to hyper's outgoing
    /// body ([`SignalingBody`]) through an `mpsc` channel instead, driven by hyper's own
    /// connection task (spawned in `do_request`); waiting on the chunk's own ack — fired only once
    /// [`FlushAckedIo`] confirms the wrapped transport actually flushed it — is what makes this a
    /// hard guarantee instead of a race.
    async fn flush(&mut self) -> Result<()> {
        if let Some(ack_rx) = self.chunk_ack.take() {
            ack_rx.await.map_err(|_| anyhow!("chunk flush was never acknowledged (connection closed)"))?;
        }
        Ok(())
    }
}

/// A handle to the accepted client connection shared between the body-pump task (reads only) and
/// `do_request` itself (idle until the pump finishes, then reclaimed to write the response). The
/// split exists only to satisfy Rust ownership across the spawned task, not to allow real
/// concurrent reads and writes, since one task reads the body while the caller's own task drives
/// the round trip. A shared mutex costs nothing extra over `tokio::io::split`'s own internal one,
/// and unlike `split`'s opaque halves, it keeps
/// [`BufferedConn::peek`](murmur_common_net::bufconn::BufferedConn::peek) reachable, which
/// `transfer::read_trailer`'s bare-LF lookahead needs (see `transfer.rs`'s module doc).
struct SharedConnReader(Arc<tokio::sync::Mutex<BufferedConn>>);

#[async_trait]
impl super::transfer::ChunkSrc for SharedConnReader {
    async fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().await.read(buf).await
    }

    async fn peek(&mut self, n: usize) -> (Vec<u8>, io::Result<()>) {
        let mut conn = self.0.lock().await;
        let (bytes, err) = BufferedConn::peek(&mut conn, n).await;
        (bytes.to_vec(), err)
    }

    async fn buffered_len(&mut self) -> usize {
        self.0.lock().await.buffered()
    }

    async fn buffered_has_newline(&mut self) -> bool {
        let conn = self.0.lock().await;
        conn.reader().is_some_and(|r| r.buffered_bytes().contains(&b'\n'))
    }
}

/// The client, minus the connection pool (see the module doc). A pooled client
/// captures `additions` by its mutable backing slice so `proxy.rs` can rewrite the in-user entry
/// after construction and have every later call see it. This crate instead takes the current
/// `additions` as a parameter on every call, which observes the same latest value.
pub(crate) struct Client {
    tunnel: Arc<dyn Tunnel>,
}

pub(crate) fn new_client(tunnel: Arc<dyn Tunnel>) -> Client {
    Client { tunnel }
}

impl Client {
    /// The dial plus the request round trip, streamed (see
    /// the module doc). `conn` is the accepted client connection, read for its
    /// addresses before anything is shared, then wrapped in `Arc<Mutex<_>>` so the body pump can
    /// stream the request body while `do_request` stays free for the caller's eventual response.
    /// `authority` and `scheme` are the parsed request's own `authority`/`scheme`
    /// (`hack::Request`). The scheme's default port is filled in before dialing when the request
    /// URI has none, so this crate does the same explicitly since it dials directly.
    ///
    /// Always returns a `BufferedConn` to write a response (or close) on, whether the round trip
    /// succeeded or not; see the module doc for the one unrecoverable exception.
    pub(crate) async fn do_request(
        &self,
        conn: BufferedConn,
        request: http::Request<()>,
        authority: &str,
        scheme: &str,
        content_length: Option<u64>,
        chunked: bool,
        additions: &[Addition],
    ) -> (Result<hyper::Response<Incoming>>, Option<BufferedConn>) {
        let (host, port) = split_host_port(authority).map_or_else(
            || (authority.to_owned(), if scheme == "https" { "443" } else { "80" }.to_owned()),
            |(h, p)| (h.to_owned(), p.to_owned()),
        );
        let dst_authority = join_host_port(&host, &port);
        let Some(dst_addr) = socks5::parse_addr(&dst_authority) else {
            return (Err(anyhow!("{}", socks5::ERR_ADDRESS_NOT_SUPPORTED)), Some(conn));
        };

        let (left, right) = pipe();
        let (tunnel_conn, metadata) = new_http(&dst_addr, &conn, Box::new(right), additions);
        let tunnel = Arc::clone(&self.tunnel);
        tokio::spawn(async move {
            tunnel.handle_tcp_conn(Box::new(murmur_common_net::io::OldConnAsStream(tunnel_conn)), metadata).await;
        });

        let conn = Arc::new(tokio::sync::Mutex::new(conn));
        let conn_for_pump = Arc::clone(&conn);
        let (tx, rx) = mpsc::channel::<BodyItem>(BODY_PUMP_CHANNEL_CAPACITY);
        let pump_task = tokio::spawn(async move {
            let mut sink = ChannelSink { tx: tx.clone(), chunk_ack: None };
            let mut src = SharedConnReader(conn_for_pump);
            let result = pump_body(&mut src, &mut sink, content_length, chunked).await;
            if let Err(err) = &result {
                let _ = tx.send(BodyItem::Err(io::Error::other(err.to_string()))).await;
            }
            result
        });

        let acks: Arc<Mutex<VecDeque<oneshot::Sender<()>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let body = SignalingBody { rx, acks: Arc::clone(&acks) };
        let outgoing = hyper::Request::from_parts(request.into_parts().0, body);

        let handshake_result: Result<hyper::Response<Incoming>> = async {
            let io = TokioIo::new(FlushAckedIo { inner: left, acks });
            let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(sender.send_request(outgoing).await?)
        }
        .await;

        let pump_result = match pump_task.await {
            Ok(result) => result,
            Err(err) => return (Err(anyhow!("body pump task panicked: {err}")), None),
        };
        let Ok(conn) = Arc::try_unwrap(conn) else {
            return (Err(anyhow!("body pump task left the connection shared")), None);
        };
        let conn = conn.into_inner();

        match (handshake_result, pump_result) {
            (Ok(response), Ok(())) => (Ok(response), Some(conn)),
            (Ok(_), Err(err)) | (Err(err), _) => (Err(err), Some(conn)),
        }
    }
}
