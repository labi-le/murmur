//! The WS stream conn embeds a connection and a WebSocket reader directly, reading/writing through
//! them synchronously.
//!
//! `Read`/`Write` on a Rust `AsyncRead`/`AsyncWrite` impl only ever receive
//! `Pin<&mut Self>` for the duration of one `poll_*` call, so the in-flight async operation is kept
//! in a boxed future stored between polls (matching the pattern already used by
//! `transport/anytls/session/stream.rs`'s `StreamConn`). Doing so needs the connection and reader
//! state reachable from a `'static` future; unlike a raw socket conn (safely concurrent for
//! Read/Write since it is backed directly by the OS socket), a naive single `Arc<AsyncMutex<Inner>>`
//! shared between read and write would hold one lock across a pending read's network wait, starving
//! a concurrent write the peer is waiting on to send the read's own next bytes (the deadlock
//! `transport::vmess::websocket::WebsocketConn` avoids by splitting `read_inner` from
//! `write_inner`). This build does the same: `read_inner`/`write_inner` are separate `AsyncMutex`es
//! over a shared `SharedConn`, so a pending read and a pending write never block each other. A
//! recover guard around a pooled-buffer panic has no equivalent since nothing here panics. Writes
//! use the own model instead of a stored future: the `Write` only checks the write deadline on
//! entry, then blocks until the frame write finishes; a bridge-layer timeout can only abandon the
//! `poll_write` *call*, not an already-committed write, so `poll_write` accepts `buf` immediately,
//! spawns the frame write, and surfaces its result as backpressure on the next
//! `poll_write`/`poll_flush`/`poll_shutdown` (see `WsStreamConn::poll_pending_write`) rather than
//! risk returning `Pending`/`Err` for bytes already on their way to the peer.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{CancellableStream, Stream};
use murmur_ws::{ErrNoFrameAdvance, OpCode, Reader, State, OP_BINARY, OP_TEXT, STATUS_NORMAL_CLOSURE};

struct ReadInner {
    conn: SharedConn,
    state: State,
    reader: Reader,
}

impl ReadInner {
    /// The read loop body, minus the panic-recovery guard (see module docs).
    async fn read_ws(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.reader.read(&mut self.conn, buf).await {
                Ok(n) => return Ok(n),
                Err(err) => {
                    if !is_no_frame_advance(&err) {
                        return Err(err);
                    }
                }
            }

            let Some(hdr) = self.reader.next_frame(&mut self.conn).await? else {
                return Ok(0);
            };
            if hdr.op_code.is_control() {
                murmur_ws::handle_control_frame(&mut self.reader, &mut self.conn, self.state, &hdr).await?;
                continue;
            }
            if (hdr.op_code & (OP_BINARY | OP_TEXT)) == OpCode(0) {
                self.reader.discard(&mut self.conn).await?;
            }
        }
    }
}

struct WriteInner {
    conn: SharedConn,
    state: State,
}

impl WriteInner {
    async fn write_ws(&mut self, buf: &[u8]) -> io::Result<usize> {
        murmur_ws::write_message(&mut self.conn, self.state, OP_BINARY, buf).await?;
        Ok(buf.len())
    }
}

fn is_no_frame_advance(err: &io::Error) -> bool {
    err.get_ref().is_some_and(<dyn std::error::Error + Send + Sync + 'static>::is::<ErrNoFrameAdvance>)
}

type ReadFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;

type PendingWrite = Arc<Mutex<Option<tokio::task::JoinHandle<io::Result<usize>>>>>;

/// the embedded connection promotes close, local address and remote address onto the WS stream conn,
/// but not the read and write half-closes: this view answers [`Stream::old_conn`], [`Stream::shutdown_write`] and
/// [`murmur_std_compat::net::Conn::close_write`] with the close frame plus the underlying conn's close.
struct WsStreamCloseView {
    conn: SharedConn,
    state: State,
    /// Shared with [`WsStreamConn::pending_write`]: `close` waits for a frame write already
    /// accepted by `poll_write` before sending the close frame, so the invariant (`Write`
    /// returns only after the frame reaches the wire, so a later `Close` always follows it) holds
    /// even though `poll_write` here returns as soon as the frame write is spawned.
    pending_write: PendingWrite,
}

impl AsyncRead for WsStreamCloseView {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for WsStreamCloseView {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().conn).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl murmur_std_compat::net::Conn for WsStreamCloseView {
    fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        self.conn.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        self.conn.remote_addr()
    }

    /// Best-effort close-frame send, then close the underlying conn.
    /// Waits for a write already accepted by [`WsStreamConn::poll_write`] first (see
    /// `pending_write`'s doc), bounded by a write deadline the way `Session::write_control_frame`
    /// bounds anytls's own control-frame send: a peer that never drains its read side must not
    /// wedge `close` forever behind a write it will never ack. If that write failed, possibly
    /// mid-frame, the close frame is skipped: an expired deadline stays expired, so
    /// `WriteMessage` fails and only the conn close runs, and a close frame after a torn frame
    /// would reach the peer as payload.
    fn close(&self) -> io::Result<()> {
        let mut conn = self.conn.clone();
        let state = self.state;
        let pending = self.pending_write.lock().take();
        tokio::spawn(async move {
            if let Some(handle) = pending {
                let _ = conn.set_write_deadline(Some(tokio::time::Instant::now() + std::time::Duration::from_secs(5)));
                if !matches!(handle.await, Ok(Ok(_))) {
                    let _ = conn.close();
                    return;
                }
                let _ = conn.set_write_deadline(None);
            }
            let _ = murmur_ws::write_message(
                &mut conn,
                state,
                murmur_ws::OP_CLOSE,
                &murmur_ws::new_close_frame_body(STATUS_NORMAL_CLOSURE, b""),
            )
            .await;
            let _ = conn.close();
        });
        Ok(())
    }

    /// The write-close fallback: the WS stream conn has no `CloseWrite` to call, so
    /// both reach `Close`. The old-`Conn` entry point matters because every bridge above this conn
    /// (`CancellableStream::old_close_write`, `deadline::Conn::close_write`) prefers a wrapped
    /// `old_conn` over forwarding to its own inner stream's `shutdown_write`.
    fn close_write(&self) -> io::Result<()> {
        murmur_std_compat::net::Conn::close(self)
    }
}

pub(crate) struct WsStreamConn {
    read_inner: Arc<AsyncMutex<ReadInner>>,
    write_inner: Arc<AsyncMutex<WriteInner>>,
    conn: SharedConn,
    close_view: WsStreamCloseView,
    read: Mutex<Option<ReadFuture>>,
    /// Bytes an in-flight read (or a bridge-abandoned one) delivered that did not fit in the
    /// caller's buffer at the time; served to the next `poll_read` call before starting a new
    /// read. `leftover[leftover_pos..]` is the unconsumed tail.
    leftover: Vec<u8>,
    leftover_pos: usize,
    /// the `Write` checks the write deadline only on entry, then blocks until the frame write
    /// finishes and returns its own result; a bridge layer (`StreamAsOldConn`'s
    /// `CancellableStream`) can only time the `poll_write` *call* out, not the write itself, so
    /// returning `Pending`/`Err` from a call that has already committed `buf` to the wire would
    /// break `AsyncWrite`'s contract (an error or `Pending` must mean the buffer was not taken).
    /// `poll_write` instead accepts the bytes immediately and spawns the frame write so it
    /// completes (and releases `write_inner`'s lock) even if the caller never polls this conn
    /// again; its result becomes backpressure on the next `poll_write`/`poll_flush`/
    /// `poll_shutdown` call.
    pending_write: PendingWrite,
    read_buf: Vec<u8>,
}

impl WsStreamConn {
    fn new(conn: Box<dyn Stream>, state: State) -> Self {
        let shared = SharedConn::new(CancellableStream::new(conn));
        let read_inner = ReadInner { conn: shared.clone(), state, reader: Reader::new(state) };
        let write_inner = WriteInner { conn: shared.clone(), state };
        let pending_write: PendingWrite = Arc::new(Mutex::new(None));
        let close_view = WsStreamCloseView { conn: shared.clone(), state, pending_write: Arc::clone(&pending_write) };
        Self {
            read_inner: Arc::new(AsyncMutex::new(read_inner)),
            write_inner: Arc::new(AsyncMutex::new(write_inner)),
            conn: shared,
            close_view,
            read: Mutex::new(None),
            leftover: Vec::new(),
            leftover_pos: 0,
            pending_write,
            read_buf: Vec::new(),
        }
    }

    /// Polls a still-running background write (if any), clearing it and surfacing its result.
    /// Called before every `poll_write`/`poll_flush`/`poll_shutdown` so a previous write's error
    /// is never silently dropped and a caller that keeps writing gets real backpressure.
    fn poll_pending_write(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut pending = self.pending_write.lock();
        let Some(handle) = pending.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let joined = match Pin::new(handle).poll(cx) {
            Poll::Ready(joined) => joined,
            Poll::Pending => return Poll::Pending,
        };
        *pending = None;
        drop(pending);
        Poll::Ready(joined.unwrap_or_else(|err| Err(io::Error::other(err))).map(|_| ()))
    }
}

impl AsyncRead for WsStreamConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.leftover_pos < this.leftover.len() {
            let (_, available) = this.leftover.split_at(this.leftover_pos);
            let n = available.len().min(buf.remaining());
            buf.put_slice(available.split_at(n).0);
            this.leftover_pos += n;
            if this.leftover_pos == this.leftover.len() {
                this.leftover.clear();
                this.leftover_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        let mut read = this.read.lock();
        if read.is_none() {
            let inner = Arc::clone(&this.read_inner);
            let mut tmp = std::mem::take(&mut this.read_buf);
            tmp.clear();
            tmp.resize(buf.remaining(), 0);
            *read = Some(Box::pin(async move {
                let mut guard = inner.lock().await;
                let result = guard.read_ws(&mut tmp).await;
                drop(guard);
                (tmp, result)
            }));
        }
        let Some(future) = read.as_mut() else {
            return Poll::Ready(Err(io::Error::other("read future missing")));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready((tmp, result)) => {
                *read = None;
                drop(read);
                match result {
                    Ok(n) => {
                        let copy = n.min(buf.remaining());
                        let (head, tail) = tmp.split_at(copy);
                        buf.put_slice(head);
                        if copy < n {
                            this.leftover.clear();
                            this.leftover.extend_from_slice(tail.split_at(n - copy).0);
                            this.leftover_pos = 0;
                        }
                        this.read_buf = tmp;
                        Poll::Ready(Ok(()))
                    }
                    Err(err) => {
                        this.read_buf = tmp;
                        Poll::Ready(Err(err))
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WsStreamConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let inner = Arc::clone(&this.write_inner);
        let data = buf.to_vec();
        let len = data.len();
        let handle = tokio::spawn(async move {
            let mut guard = inner.lock().await;
            guard.write_ws(&data).await
        });
        *this.pending_write.lock() = Some(handle);
        Poll::Ready(Ok(len))
    }

    /// Drains any still-running background write first (surfacing its error as this call's
    /// result), then forwards straight to the shared conn (e.g. a `tokio_rustls`/TLS stream)
    /// rather than through `write_inner`'s lock a second time: the underlying conn buffers writes
    /// internally the way a `BufWriter` does, so a caller awaiting a peer response after a write
    /// must not be left stuck behind an unrelated pending read holding `read_inner`.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => {}
            ready_err @ Poll::Ready(Err(_)) => return ready_err,
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl Stream for WsStreamConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        murmur_common_net::io::old_addr_to_socket_addr(&*self.conn.local_addr()?)
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        murmur_common_net::io::old_addr_to_socket_addr(&*self.conn.remote_addr()?)
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        Some(&self.close_view)
    }

    /// the connection embedding promotes only the interface's methods, so the write-close and
    /// the network close both fall back to `Close()` here — the close frame plus the underlying
    /// conn's close. Swallowing it stranded `relay_streams_inner`, whose other direction only
    /// ends once this conn does.
    fn shutdown_write(&self) -> io::Result<()> {
        murmur_std_compat::net::Conn::close(&self.close_view)
    }

    /// The read half-close has no `Close` fallback, so it stays a no-op.
    fn shutdown_read(&self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn new_ws_stream_conn(conn: Box<dyn Stream>, state: State) -> Box<dyn Stream> {
    Box::new(WsStreamConn::new(conn, state))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use rand::RngCore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use murmur_common::shared_conn::SharedConn;
    use murmur_common_net::io::{CancellableStream, Stream};
    use murmur_component_ca::keypair::{new_random_tls_key_pair, new_tls_key_pair_loader, KeyPairType};
    use murmur_component_tls::utls::{client as tls_client, server as tls_server, Config as TlsConfig};
    use murmur_ws::{STATE_CLIENT_SIDE, STATE_SERVER_SIDE};

    use super::super::tunnel_ws::compute_ws_accept;
    use super::new_ws_stream_conn;

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|pos| pos + 4)
    }

    /// Hang detection, not a latency budget: high enough that only a task that stopped making
    /// progress trips it, even on an oversubscribed host. Trips here first mean check
    /// `--test-threads` against `available_parallelism`, not the code under test.
    const HANG_DEADLINE: Duration = Duration::from_secs(60);

    /// Concurrent connection count scaled to the host: enough over `available_parallelism` to
    /// force real queueing, with a floor so a low-core host still exercises genuine concurrency.
    fn concurrency_width() -> usize {
        std::thread::available_parallelism().map(std::num::NonZeroUsize::get).unwrap_or(1).saturating_mul(8).max(16)
    }

    /// Concurrency repro for the client-side HTTP masquerade handshake write over TLS
    /// (`tunnel_ws::dial_ws`'s `conn.write_all(&request)` immediately followed by reading the
    /// upgrade response, and `WsStreamConn`'s subsequent frame writes) never being left stuck
    /// behind buffered-but-unflushed ciphertext. Pattern adapted from
    /// `component::tls::utls::tests::run_raw_http_roundtrip_then_echo`.
    #[tokio::test]
    async fn concurrent_ws_handshake_over_tls_then_frame_echo_never_hangs() {
        let (cert_pem, key_pem, _fp) = new_random_tls_key_pair(KeyPairType::P256).expect("key generation");
        let loader = new_tls_key_pair_loader(&cert_pem, &key_pem).expect("valid cert");
        let cert_for_server = loader().expect("cert loads");

        let server_config = Arc::new(TlsConfig { certificates: vec![cert_for_server], ..Default::default() });
        let client_config = Arc::new(TlsConfig { insecure_skip_verify: true, ..Default::default() });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");

        let n = concurrency_width();

        let mut client_tasks = Vec::with_capacity(n);
        for i in 0..n {
            let client_config = Arc::clone(&client_config);
            client_tasks.push(tokio::spawn(async move {
                tokio::time::timeout(HANG_DEADLINE, async move {
                    let raw = TcpStream::connect(addr).await.expect("client connect");
                    let tls_conn = tls_client(Box::new(raw), client_config);
                    tls_conn.handshake().await.expect("client tls handshake");
                    let mut conn: Box<dyn Stream> = Box::new(tls_conn);

                    let mut key_bytes = [0u8; 16];
                    rand::rng().fill_bytes(&mut key_bytes);
                    let ws_key = STANDARD.encode(key_bytes);
                    let request = format!(
                        "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {ws_key}\r\n\r\n"
                    );
                    conn.write_all(request.as_bytes()).await.expect("client handshake write");
                    conn.flush().await.expect("client handshake flush");

                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = conn.read(&mut chunk).await.expect("client handshake response read");
                        assert!(n > 0, "task {i}: server closed before sending handshake response");
                        buf.extend_from_slice(&chunk[..n]);
                        if find_header_end(&buf).is_some() {
                            break;
                        }
                    }
                    assert!(buf.starts_with(b"HTTP/1.1 101"), "task {i}: unexpected handshake status");

                    let mut ws_conn = new_ws_stream_conn(conn, STATE_CLIENT_SIDE);
                    ws_conn.write_all(b"PING").await.expect("client ping write");
                    ws_conn.flush().await.expect("client ping flush");
                    let mut pong = [0u8; 4];
                    ws_conn.read_exact(&mut pong).await.expect("client pong read");
                    assert_eq!(&pong, b"PONG", "task {i} got unexpected echo reply");
                })
                .await
                .unwrap_or_else(|_| panic!("task {i} did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect"));
            }));
        }

        let mut server_tasks = Vec::with_capacity(n);
        for i in 0..n {
            let (raw, _) = listener.accept().await.expect("accept");
            let server_config = Arc::clone(&server_config);
            server_tasks.push(tokio::spawn(async move {
                tokio::time::timeout(HANG_DEADLINE, async move {
                    let tls_conn = tls_server(Box::new(raw), server_config);
                    tls_conn.handshake().await.expect("server tls handshake");
                    let mut conn: Box<dyn Stream> = Box::new(tls_conn);

                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = conn.read(&mut chunk).await.expect("server handshake request read");
                        assert!(n > 0, "task {i}: client closed before sending handshake request");
                        buf.extend_from_slice(&chunk[..n]);
                        if find_header_end(&buf).is_some() {
                            break;
                        }
                    }

                    let mut headers = [httparse::EMPTY_HEADER; 32];
                    let mut req = httparse::Request::new(&mut headers);
                    req.parse(&buf).expect("parse handshake request");
                    let ws_key = req
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("sec-websocket-key"))
                        .map(|h| String::from_utf8_lossy(h.value).into_owned())
                        .expect("missing sec-websocket-key");
                    let accept = compute_ws_accept(&ws_key);

                    let response = format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                         Sec-WebSocket-Accept: {accept}\r\n\r\n"
                    );
                    conn.write_all(response.as_bytes()).await.expect("server handshake response write");
                    conn.flush().await.expect("server handshake response flush");

                    let mut ws_conn = new_ws_stream_conn(conn, STATE_SERVER_SIDE);
                    let mut ping = [0u8; 4];
                    ws_conn.read_exact(&mut ping).await.expect("server ping read");
                    assert_eq!(&ping, b"PING", "task {i} server got unexpected ping");
                    ws_conn.write_all(b"PONG").await.expect("server pong write");
                    ws_conn.flush().await.expect("server pong flush");
                })
                .await
                .unwrap_or_else(|_| panic!("task {i} did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect"));
            }));
        }

        for task in client_tasks {
            task.await.expect("client task panicked");
        }
        for task in server_tasks {
            task.await.expect("server task panicked");
        }
    }

    /// Regression test for the deadlock fixed in this module: `WsStreamConn` used to guard both
    /// the read and the write path with the same `AsyncMutex<Inner>`, held across the pending
    /// network I/O rather than released before it. A peer that withholds its reply until it has
    /// read the client's next frame — exactly what a tunnelled handshake does — starves the write
    /// behind the blocked read forever. The test server does exactly that: it sends nothing back
    /// until it has read a frame from the client, so a concurrent read and write on the same
    /// `WsStreamConn` must both make progress for the exchange to complete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_read_write_on_same_conn_never_deadlocks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test connection");

            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).await.expect("read request");
                buf.extend_from_slice(&chunk[..n]);
                if find_header_end(&buf).is_some() {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&buf).into_owned();
            let ws_key = request
                .lines()
                .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
                .expect("client sent Sec-WebSocket-Key")
                .trim()
                .to_owned();
            let accept = compute_ws_accept(&ws_key);
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.expect("write 101 response");

            let mut header = [0u8; 2];
            stream.read_exact(&mut header).await.expect("read client frame header");
            let masked_len = usize::from(header[1] & 0x7f);
            let mut mask = [0u8; 4];
            stream.read_exact(&mut mask).await.expect("read client frame mask");
            let mut payload = vec![0u8; masked_len];
            stream.read_exact(&mut payload).await.expect("read client frame payload");
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
            assert_eq!(payload, b"second-flight");

            let reply = b"server-reply";
            let mut frame = vec![0x82u8, u8::try_from(reply.len()).expect("reply fits a single-byte length")];
            frame.extend_from_slice(reply);
            stream.write_all(&frame).await.expect("write reply frame");
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect to test listener");
        let mut key_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut key_bytes);
        let ws_key = STANDARD.encode(key_bytes);
        let request = format!(
            "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {ws_key}\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.expect("client handshake write");

        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await.expect("client handshake response read");
            buf.extend_from_slice(&chunk[..n]);
            if find_header_end(&buf).is_some() {
                break;
            }
        }
        assert!(buf.starts_with(b"HTTP/1.1 101"), "unexpected handshake status");

        let conn: Box<dyn Stream> = Box::new(stream);
        let ws_conn = new_ws_stream_conn(conn, STATE_CLIENT_SIDE);
        let (mut read_half, mut write_half) = tokio::io::split(ws_conn);

        let read_task = tokio::spawn(async move {
            let mut reply = [0u8; 64];
            let n = read_half.read(&mut reply).await.expect("read server reply");
            reply[..n].to_vec()
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let write_task =
            tokio::spawn(async move { write_half.write_all(b"second-flight").await.expect("write second flight") });

        let (read_result, write_result) =
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(read_task, write_task) })
                .await
                .expect("concurrent read+write on the same ws_stream_conn deadlocked");
        write_result.expect("write task panicked");
        assert_eq!(read_result.expect("read task panicked"), b"server-reply");

        server.await.expect("server task panicked");
    }

    /// Regression for the review of `1f2ee5f7`'s P1 finding: `WsStreamCloseView::close` used to
    /// send the close frame and close the underlying conn as soon as it was called, without
    /// waiting for a frame write `poll_write` had already accepted (spawned) but which might
    /// still be running. On a multi-thread runtime the close task often ran before or during the
    /// data task, dropping or cutting mid-frame bytes the caller was told were written - breaking
    /// the rule that once `Write` returns, its bytes always reach the peer before a
    /// later `Close`. Repeated (like the anytls sibling test) because the loss depended on task
    /// scheduling; real TCP loopback so the frame write is genuine async I/O that can interleave
    /// with the close task across OS threads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accepted_write_reaches_the_peer_before_close() {
        const FIRST: u8 = 0xAA;
        const REST: [u8; 16] = [0xCC; 16];

        for iteration in 0..300 {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
            let addr = listener.local_addr().expect("listener addr");

            let server = tokio::spawn(async move {
                let (raw, _) = listener.accept().await.expect("accept test connection");
                let conn: Box<dyn Stream> = Box::new(raw);
                let mut ws_conn = new_ws_stream_conn(conn, STATE_SERVER_SIDE);

                let mut received = Vec::new();
                let mut chunk = [0u8; 64];
                loop {
                    match tokio::time::timeout(Duration::from_secs(2), ws_conn.read(&mut chunk)).await {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => received.extend_from_slice(&chunk[..n]),
                        // The client tears down its conn right after the close frame (see
                        // `WsStreamCloseView::close`), which can race the server's own
                        // close-frame ack write; that race is orthogonal to whether the data
                        // frames already arrived, so it ends the loop like a clean EOF instead
                        // of failing the test.
                        Ok(Err(_)) => break,
                        Err(_) => panic!("iteration {iteration}: server read timed out, peer likely stuck"),
                    }
                }
                received
            });

            let raw = TcpStream::connect(addr).await.expect("connect to test listener");
            let conn: Box<dyn Stream> = Box::new(raw);
            let mut ws_conn = new_ws_stream_conn(conn, STATE_CLIENT_SIDE);

            ws_conn.write_all(&[FIRST]).await.expect("first write accepted");
            ws_conn.flush().await.expect("first flush");
            ws_conn.write_all(&REST).await.expect("second write accepted");
            murmur_common_net::io::close_stream(&*ws_conn).expect("close accepted");

            let received = server.await.expect("server task panicked");
            let mut expected = vec![FIRST];
            expected.extend_from_slice(&REST);
            assert_eq!(
                received, expected,
                "iteration {iteration}: an accepted write must fully reach the peer before close"
            );
        }
    }

    /// Regression test for the review-of-410dbcba P2: when the close-time deadline tears an
    /// accepted frame write because the peer is stalled, close must not follow the torn frame
    /// with a close frame, which the peer would read as payload once it drains.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn close_after_a_torn_write_sends_no_foreign_bytes() {
        const FILL: u8 = 0xAB;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = tokio::spawn(async move {
            let (raw, _) = listener.accept().await.expect("accept test connection");
            tokio::time::sleep(Duration::from_secs(8)).await;
            let conn: Box<dyn Stream> = Box::new(raw);
            let mut ws_conn = new_ws_stream_conn(conn, STATE_SERVER_SIDE);
            let mut received = Vec::new();
            let mut chunk = [0u8; 64 * 1024];
            while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), ws_conn.read(&mut chunk)).await {
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..n]);
            }
            received
        });

        let raw = TcpStream::connect(addr).await.expect("connect to test listener");
        let conn: Box<dyn Stream> = Box::new(raw);
        let mut ws_conn = new_ws_stream_conn(conn, STATE_CLIENT_SIDE);
        let huge = vec![FILL; 32 * 1024 * 1024];
        ws_conn.write_all(&huge).await.expect("the write is accepted");
        murmur_common_net::io::close_stream(&*ws_conn).expect("close accepted");

        let received = server.await.expect("server task panicked");
        assert!(received.len() < huge.len(), "the stalled peer should see a torn frame");
        assert!(received.iter().all(|&b| b == FILL), "no close-frame bytes may follow a torn frame as payload");
    }

    /// Regression for the relay teardown that never finished: the write half-close a relay issues
    /// after a peer EOF reached neither this conn's own `Stream::shutdown_write` nor the old-`Conn`
    /// `close_write` that every bridge above it prefers over forwarding, so nothing reached the wire
    /// and the opposite relay direction waited forever. A fallback to `Close()` at
    /// this layer,
    /// so the peer must see a close frame and this conn's own reads must end. Both entry points run,
    /// because the relay's reaches the old-`Conn` one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_write_closes_the_peer_stream_and_this_read_side() {
        const REQUEST: &[u8; 4] = b"REQ!";
        const MASK: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

        for old_conn_entry_point in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
            let addr = listener.local_addr().expect("listener local addr");

            let server = tokio::spawn(async move {
                let (raw, _) = listener.accept().await.expect("accept test connection");
                let conn: Box<dyn Stream> = Box::new(raw);
                let mut conn = new_ws_stream_conn(conn, STATE_SERVER_SIDE);

                let mut request = [0u8; 4];
                conn.read_exact(&mut request).await.expect("server request frame read");
                assert_eq!(&request, REQUEST, "server got unexpected request payload");

                let mut conn: Box<dyn Stream> = if old_conn_entry_point {
                    let shared = SharedConn::new(CancellableStream::new(conn));
                    shared.close_write().expect("old-Conn write half close");
                    Box::new(shared)
                } else {
                    conn.shutdown_write().expect("write half close");
                    conn
                };

                let mut chunk = [0u8; 64];
                let after = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut chunk)).await;
                assert!(
                    matches!(after, Ok(Ok(0)) | Ok(Err(_))),
                    "the closed conn must stop serving reads, got {after:?}"
                );
            });

            let mut client = TcpStream::connect(addr).await.expect("connect to test listener");
            let mut frame = vec![0x82u8, 0x80 | u8::try_from(REQUEST.len()).expect("length fits a masked byte")];
            frame.extend_from_slice(&MASK);
            frame.extend(REQUEST.iter().enumerate().map(|(i, byte)| byte ^ MASK[i % 4]));
            client.write_all(&frame).await.expect("client frame write");
            client.flush().await.expect("client frame flush");

            let mut received = Vec::new();
            loop {
                let mut chunk = [0u8; 64];
                match tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk)).await {
                    Ok(Ok(0)) | Ok(Err(_)) => break,
                    Ok(Ok(n)) => {
                        received.extend_from_slice(&chunk[..n]);
                        if received.len() >= 4 {
                            break;
                        }
                    }
                    Err(_) => panic!("client read timed out: the write half-close never reached the peer"),
                }
            }
            assert_eq!(received, vec![0x88, 0x02, 0x03, 0xe8], "client got unexpected shutdown_write bytes");

            server.await.expect("server task panicked");
        }
    }
}
