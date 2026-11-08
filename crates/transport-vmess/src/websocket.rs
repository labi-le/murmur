//! The WebSocket handshake is written as raw bytes and the response is read one byte at a time
//! until the terminating blank line.
//!
//! Reading one byte at a time needs no shared buffered-reader state, so the read never over-reads
//! past the header block into the caller's first application-layer bytes (a deviation from
//! internal buffering, not from the bytes placed on the wire).
//! `murmur_ws` provides the WebSocket frame codec (see that module's docs); the streaming
//! per-frame read loop mirrors `WsStreamConn` in `transport-sudoku`'s
//! `obfs/httpmask/ws_stream_conn.rs` for the same `Pin<&mut Self>`-per-poll reason. The
//! post-upgrade wrapping starts from the already-upgraded raw conn a caller's HTTP server produced
//! (e.g. via `hyper::upgrade::on`): the `101 Switching Protocols` response is written by that
//! server, and no Rust HTTP server in this crate exposes an equivalent hijack (see the wave
//! report).

use std::any::Any;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures::task::AtomicWaker;
use parking_lot::Mutex as SyncMutex;
use rand::Rng as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{OldConnAsStream, StreamAsOldConn};
use murmur_common_net::{
    get_websocket_sec_accept, new_cached_conn, new_deadline_conn, new_early_conn, EarlyConnResponse,
    ExtendedConn as CommonExtendedConn,
};
use murmur_compat::sing_buf::Buffer;
use murmur_component_ech as ech;
use murmur_component_tls::utls as tls_c;
use murmur_log as log;
use murmur_std_compat::net::{Addr, Conn as NetConn, ExtendedConn as NetExtendedConn};
use murmur_ws;
use murmur_ws::{
    ErrNoFrameAdvance, OpCode, Reader, State, OP_BINARY, OP_CLOSE, OP_TEXT, STATE_CLIENT_SIDE, STATE_SERVER_SIDE,
    STATUS_NORMAL_CLOSURE,
};

#[derive(Clone, Default)]
pub struct WebsocketConfig {
    pub host: String,
    pub port: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub tls: bool,
    pub tls_config: Option<Arc<tls_c::Config>>,
    pub ech_config: Option<Arc<ech::Config>>,
    pub max_early_data: i64,
    pub early_data_header_name: String,
    pub client_fingerprint: String,
    pub v2ray_http_upgrade: bool,
    pub v2ray_http_upgrade_fast_open: bool,
}

impl std::fmt::Debug for WebsocketConfig {
    // Header values and the TLS/ECH configs are withheld: they carry credentials (a user id, an
    // `Authorization` token) and key material that must not reach a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("path", &self.path)
            .field("headers", &"<redacted>")
            .field("tls", &self.tls)
            .field("max_early_data", &self.max_early_data)
            .field("early_data_header_name", &self.early_data_header_name)
            .field("client_fingerprint", &self.client_fingerprint)
            .field("v2ray_http_upgrade", &self.v2ray_http_upgrade)
            .field("v2ray_http_upgrade_fast_open", &self.v2ray_http_upgrade_fast_open)
            .finish_non_exhaustive()
    }
}

fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// Canonicalizes a header key: uppercase the first letter and any letter following a hyphen,
/// lowercase the rest (`Sec-WebSocket-Key` becomes `Sec-Websocket-Key`). Every header key is
/// canonicalized before sending and before the keys are sorted, so both the wire casing and the
/// header order depend on this.
fn canonical_header_key(key: &str) -> String {
    let mut result = String::with_capacity(key.len());
    let mut upper = true;
    for ch in key.chars() {
        if ch == '-' {
            result.push(ch);
            upper = true;
        } else if upper {
            result.extend(ch.to_uppercase());
            upper = false;
        } else {
            result.extend(ch.to_lowercase());
        }
    }
    result
}

fn ed_to_raw_url(s: &str) -> String {
    s.chars()
        .filter_map(|c| match c {
            '+' => Some('-'),
            '/' => Some('_'),
            '=' => None,
            other => Some(other),
        })
        .collect()
}

fn decode_ed(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(ed_to_raw_url(s)).map_err(|err| anyhow!("{err}"))
}

fn decode_xray_0rtt(sec_protocol: Option<&str>) -> Option<Vec<u8>> {
    let sec_protocol = sec_protocol.filter(|s| !s.is_empty())?;
    decode_ed(sec_protocol).ok()
}

#[must_use]
pub fn is_web_socket_upgrade(headers: &[(String, String)]) -> bool {
    header_get(headers, "Upgrade").is_some_and(|v| v == "websocket")
}

#[must_use]
pub fn is_v2ray_http_update(headers: &[(String, String)]) -> bool {
    is_web_socket_upgrade(headers) && header_get(headers, "Sec-WebSocket-Key").is_none()
}

// Read ownership is independent of the writer, so a blocked read cannot prevent an upload.
struct ReadInner {
    conn: Box<dyn NetConn>,
    state: State,
    reader: Reader,
    writer: Arc<AsyncMutex<WriteInner>>,
}

impl ReadInner {
    // NOT cancel-safe: framing progress lives in the retained read future.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "guard is moved into send and cannot be dropped by the reader"
    )]
    async fn read_ws(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        loop {
            match self.reader.read(&mut *self.conn, b).await {
                // The codec reports an empty frame as zero bytes, not transport EOF.
                Ok(0) => continue,
                Ok(n) => {
                    return Ok(n);
                }
                Err(err) => {
                    if !err
                        .get_ref()
                        .is_some_and(<dyn std::error::Error + Send + Sync + 'static>::is::<ErrNoFrameAdvance>)
                    {
                        return Err(err);
                    }
                }
            }
            let Some(header) = self.reader.next_frame(&mut *self.conn).await? else {
                return Ok(0);
            };
            if header.op_code.is_control() {
                let mut control = ControlIo { conn: &mut *self.conn, response: Vec::new() };
                let result = murmur_ws::handle_control_frame(&mut self.reader, &mut control, self.state, &header).await;
                if !control.response.is_empty() {
                    let mut guard = WriterGuard::new(Arc::clone(&self.writer).lock_owned().await);
                    let writer = guard.writer();
                    writer.check_open()?;
                    writer.closed = header.op_code == OP_CLOSE;
                    writer.buffer = control.response;
                    tokio::spawn(WriteInner::send(guard, true)).await.map_err(io::Error::other)??;
                }
                result?;
                continue;
            }
            if (header.op_code & (OP_BINARY | OP_TEXT)) == OpCode(0) {
                self.reader.discard(&mut *self.conn).await?;
            }
        }
    }
}

struct ControlIo<'a> {
    conn: &'a mut dyn NetConn,
    response: Vec<u8>,
}

impl AsyncRead for ControlIo<'_> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for ControlIo<'_> {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().response.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

struct WriteInner {
    conn: Box<dyn NetConn>,
    state: State,
    buffer: Vec<u8>,
    error: Option<(io::ErrorKind, String)>,
    closed: bool,
    ready: Arc<AtomicWaker>,
    shutdown: CancellationToken,
}

struct WriterGuard {
    inner: Option<tokio::sync::OwnedMutexGuard<WriteInner>>,
    ready: Arc<AtomicWaker>,
}

impl WriterGuard {
    fn new(inner: tokio::sync::OwnedMutexGuard<WriteInner>) -> Self {
        Self { ready: Arc::clone(&inner.ready), inner: Some(inner) }
    }

    #[expect(clippy::expect_used, reason = "inner is Some from construction until Drop takes it before waking waiters")]
    fn writer(&mut self) -> &mut WriteInner {
        self.inner.as_deref_mut().expect("writer guard exists until Drop")
    }
}

impl Drop for WriterGuard {
    fn drop(&mut self) {
        drop(self.inner.take());
        self.ready.wake();
    }
}

struct WriterLifetime(CancellationToken);

impl Drop for WriterLifetime {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl WriteInner {
    fn check_error(&self) -> io::Result<()> {
        if let Some((kind, message)) = &self.error {
            return Err(io::Error::new(*kind, message.clone()));
        }
        Ok(())
    }

    fn check_open(&self) -> io::Result<()> {
        self.check_error()?;
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "websocket writer is closed"));
        }
        Ok(())
    }

    // NOT cancel-safe: only owner teardown may interrupt a partially written frame.
    async fn send(mut guard: WriterGuard, encoded: bool) -> io::Result<()> {
        let writer = guard.writer();
        let Self { conn, state, buffer, shutdown, .. } = writer;
        let send = async {
            if encoded {
                conn.write_all(buffer).await?;
            } else {
                murmur_ws::write_message_owned(&mut **conn, *state, OP_BINARY, buffer).await?;
            }
            conn.flush().await
        };
        let result = tokio::select! {
            biased;
            () = shutdown.cancelled() => Err(io::Error::new(io::ErrorKind::BrokenPipe, "websocket owner dropped")),
            result = send => result,
        };
        if let Err(error) = &result {
            writer.error = Some((error.kind(), error.to_string()));
        }
        writer.buffer.clear();
        result
    }
}

type ReadFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;

pub struct WebsocketConn {
    read_inner: Arc<AsyncMutex<ReadInner>>,
    write_inner: Arc<AsyncMutex<WriteInner>>,
    conn: SharedConn,
    read: SyncMutex<Option<ReadFuture>>,
    writer_ready: Arc<AtomicWaker>,
    read_buf: SyncMutex<Vec<u8>>,
    writer_lifetime: SyncMutex<Option<WriterLifetime>>,
}

impl AsyncRead for WebsocketConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut read = this.read.lock();
        if read.is_none() {
            let inner = Arc::clone(&this.read_inner);
            let mut tmp = std::mem::take(&mut *this.read_buf.lock());
            let r = buf.remaining();
            tmp.resize(r, 0);
            *read = Some(Box::pin(async move {
                let mut guard = inner.lock().await;
                let result = guard.read_ws(&mut tmp).await;
                drop(guard);
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
                        let Some(filled) = tmp.get(..n) else {
                            return Poll::Ready(Err(io::Error::other("read filled more than the buffer holds")));
                        };
                        buf.put_slice(filled);
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

impl AsyncWrite for WebsocketConn {
    #[expect(clippy::significant_drop_tightening, reason = "guard is moved into the send future before polling it")]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut guard = std::task::ready!(self.get_mut().poll_writer(cx));
        let writer = guard.writer();
        writer.check_open()?;
        writer.buffer.clear();
        let accepted = buf.len().min(16 * 1024);
        let (payload, _) = buf.split_at(accepted);
        writer.buffer.extend_from_slice(payload);
        let mut send = Box::pin(WriteInner::send(guard, false));
        match send.as_mut().poll(cx) {
            Poll::Ready(result) => result?,
            Poll::Pending => {
                // The accepted frame must outlive cancellation of the caller's write future.
                tokio::spawn(send);
            }
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = std::task::ready!(self.get_mut().poll_writer(cx));
        let writer = guard.writer();
        writer.check_error()?;
        let result = Pin::new(&mut *writer.conn).poll_flush(cx);
        drop(guard);
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = std::task::ready!(self.get_mut().poll_writer(cx));
        let writer = guard.writer();
        writer.check_error()?;
        writer.closed = true;
        let result = Pin::new(&mut *writer.conn).poll_shutdown(cx);
        drop(guard);
        result
    }
}

impl WebsocketConn {
    fn poll_writer(&self, cx: &Context<'_>) -> Poll<WriterGuard> {
        if let Ok(writer) = Arc::clone(&self.write_inner).try_lock_owned() {
            let _ = self.writer_ready.take();
            return Poll::Ready(WriterGuard::new(writer));
        }
        self.writer_ready.register(cx.waker());
        match Arc::clone(&self.write_inner).try_lock_owned() {
            Ok(writer) => {
                let _ = self.writer_ready.take();
                Poll::Ready(WriterGuard::new(writer))
            }
            Err(_) => Poll::Pending,
        }
    }

    // cancel-safe: after acquiring ownership, a task finishes the accepted frame independently.
    pub async fn write_buffer(&self, buffer: &mut Buffer) -> io::Result<()> {
        let mut guard = WriterGuard::new(Arc::clone(&self.write_inner).lock_owned().await);
        let writer = guard.writer();
        writer.check_open()?;
        writer.buffer.clear();
        writer.buffer.extend_from_slice(buffer.bytes());
        buffer.release();
        tokio::spawn(WriteInner::send(guard, false)).await.map_err(io::Error::other)?
    }

    pub const fn front_headroom(&self) -> i32 {
        14
    }
}

impl NetConn for WebsocketConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        let Some(lifetime) = self.writer_lifetime.lock().take() else {
            return Ok(());
        };
        let conn = self.conn.clone();
        let inner = Arc::clone(&self.write_inner);
        let ready = Arc::clone(&self.writer_ready);
        tokio::spawn(async move {
            let _lifetime = lifetime;
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            let _ = conn.set_write_deadline(Some(deadline));
            // NOT cancel-safe: timeout tears down the underlay instead of reusing a partial frame.
            let close = async {
                let mut writer = inner.lock_owned().await;
                writer.check_error()?;
                if !writer.closed {
                    writer.closed = true;
                    let state = writer.state;
                    murmur_ws::write_message(
                        &mut *writer.conn,
                        state,
                        OP_CLOSE,
                        &murmur_ws::new_close_frame_body(STATUS_NORMAL_CLOSURE, b""),
                    )
                    .await?;
                    writer.conn.flush().await?;
                }
                drop(writer);
                Ok::<_, io::Error>(())
            };
            let _ = tokio::time::timeout_at(deadline, close).await;
            ready.wake();
            let _ = conn.close();
        });
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_write_deadline(deadline)
    }
}

impl NetExtendedConn for WebsocketConn {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(&self.conn)
    }
}

impl std::fmt::Debug for WebsocketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketConn").finish_non_exhaustive()
    }
}

fn new_websocket_conn(conn: Box<dyn NetConn>, state: State) -> WebsocketConn {
    let shared = SharedConn::from_boxed(conn);
    let writer_ready = Arc::new(AtomicWaker::new());
    let shutdown = CancellationToken::new();
    let write_inner = Arc::new(AsyncMutex::new(WriteInner {
        conn: Box::new(shared.clone()),
        state,
        buffer: Vec::new(),
        error: None,
        closed: false,
        ready: Arc::clone(&writer_ready),
        shutdown: shutdown.clone(),
    }));
    let read_inner = ReadInner {
        conn: Box::new(shared.clone()),
        state,
        reader: Reader::new(state),
        writer: Arc::clone(&write_inner),
    };
    WebsocketConn {
        read_inner: Arc::new(AsyncMutex::new(read_inner)),
        write_inner,
        conn: shared,
        read: SyncMutex::new(None),
        writer_ready,
        read_buf: SyncMutex::new(Vec::new()),
        writer_lifetime: SyncMutex::new(Some(WriterLifetime(shutdown))),
    }
}

/// The byte-exact read of the response status line and header block (see the module doc), with no
/// buffered reader: one byte at a time until `\r\n\r\n`, so no application-layer byte is ever
/// consumed past the header boundary.
async fn read_http_response_header(conn: &mut dyn NetConn) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        conn.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > 64 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "websocket response header too large"));
        }
    }
}

struct ParsedResponse {
    status: u16,
    headers: Vec<(String, String)>,
}

fn parse_http_response(raw: &[u8]) -> Result<ParsedResponse> {
    let mut parsed = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut parsed);
    let httparse::Status::Complete(_) =
        response.parse(raw).map_err(|err| anyhow!("vmess: invalid websocket handshake response: {err}"))?
    else {
        return Err(anyhow!("vmess: incomplete websocket handshake response"));
    };
    let status = response.code.ok_or_else(|| anyhow!("vmess: missing websocket handshake status"))?;
    let headers =
        response.headers.iter().map(|h| (h.name.to_owned(), String::from_utf8_lossy(h.value).into_owned())).collect();
    Ok(ParsedResponse { status, headers })
}

/// The early-conn closure for `v2ray_http_upgrade_fast_open`: reads and validates the deferred `101`
/// response on the connection's first read, mirroring [`read_http_response_header`] and the
/// status/header checks in [`stream_websocket_conn`] a byte at a time across `poll_response` calls
/// instead of `.await`, the same shape `transport::tuic::v4::client`'s `DialResponse` uses.
struct WsFastOpenResponse {
    header: Vec<u8>,
    byte: [u8; 1],
}

impl WsFastOpenResponse {
    fn new() -> Self {
        Self { header: Vec::with_capacity(256), byte: [0u8; 1] }
    }
}

impl EarlyConnResponse for WsFastOpenResponse {
    fn poll_response(&mut self, cx: &mut Context<'_>, conn: &mut dyn CommonExtendedConn) -> Poll<Result<()>> {
        while !self.header.ends_with(b"\r\n\r\n") {
            if self.header.len() > 64 * 1024 {
                return Poll::Ready(Err(anyhow!("websocket response header too large")));
            }
            let mut read_buf = ReadBuf::new(&mut self.byte);
            match Pin::new(&mut *conn).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    if read_buf.filled().is_empty() {
                        return Poll::Ready(Err(anyhow!(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))));
                    }
                    self.header.push(self.byte[0]);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
                Poll::Pending => return Poll::Pending,
            }
        }

        let response = match parse_http_response(&self.header) {
            Ok(response) => response,
            Err(err) => return Poll::Ready(Err(err)),
        };
        let connection_upgrade =
            header_get(&response.headers, "Connection").is_some_and(|v| v.eq_ignore_ascii_case("upgrade"));
        let upgrade_websocket =
            header_get(&response.headers, "Upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
        if response.status != 101 || !connection_upgrade || !upgrade_websocket {
            return Poll::Ready(Err(anyhow!("unexpected status: {}", response.status)));
        }
        Poll::Ready(Ok(()))
    }
}

/// The base64 of the 20-byte `Sec-Websocket-Accept` hash, so the wire length is fixed.
const ACCEPT_SIZE: usize = 28;

/// Wraps `conn` in the configured TLS stack, or returns it untouched for a plain `ws://` dial.
async fn maybe_wrap_tls(
    ctx: &CancellationToken,
    conn: Box<dyn NetConn>,
    c: &WebsocketConfig,
) -> Result<Box<dyn NetConn>> {
    if !c.tls {
        return Ok(conn);
    }
    let mut tls_config = c.tls_config.as_ref().map_or_else(
        || crate::tls::client_tls_config(String::new(), false, vec!["http/1.1".to_owned()]),
        |cfg| (**cfg).clone(),
    );
    if tls_config.server_name.is_empty() && !tls_config.insecure_skip_verify {
        tls_config.server_name = c.host.clone();
    }

    let (fingerprint, ok) = tls_c::get_fingerprint(&c.client_fingerprint);
    let stream = Box::new(OldConnAsStream(conn));
    if ok {
        let mut utls_config = tls_c::u_config(&tls_config);
        if let Some(ech) = &c.ech_config {
            ech.client_handle_utls(ctx.clone(), &mut utls_config).await?;
        }
        let mut tls_conn = tls_c::uclient(stream, Arc::new(utls_config), fingerprint);
        tls_c::build_websocket_handshake_state(&mut tls_conn)?;
        tls_conn.handshake_context(ctx).await?;
        Ok(Box::new(StreamAsOldConn::new(tls_conn)))
    } else {
        if let Some(ech) = &c.ech_config {
            ech.client_handle(ctx.clone(), &mut tls_config).await?;
        }
        let tls_conn = tls_c::client(stream, Arc::new(tls_config));
        tls_conn.handshake_context(ctx).await?;
        Ok(Box::new(StreamAsOldConn::new(tls_conn)))
    }
}

/// Builds the upgrade request (see the module doc) with the `Sec-Websocket-Key` it advertises; the
/// key comes back so the caller can check `Sec-Websocket-Accept`. Early data rides in `path` when
/// `early_data_header_name` is empty, otherwise in a header.
fn build_upgrade_request(c: &WebsocketConfig, path: &mut String, early_data: Option<&str>) -> (String, Vec<u8>) {
    let mut headers = c.headers.clone();
    let host_override = header_get(&headers, "host").filter(|v| !v.is_empty()).map(str::to_owned);
    let user_agent_override = header_get(&headers, "user-agent").map(str::to_owned);
    headers.retain(|(k, _)| {
        !k.eq_ignore_ascii_case("connection")
            && !k.eq_ignore_ascii_case("upgrade")
            && !k.eq_ignore_ascii_case("host")
            && !k.eq_ignore_ascii_case("user-agent")
    });

    let host_header = host_override.unwrap_or_else(|| c.host.clone());
    let user_agent = user_agent_override.unwrap_or_else(|| murmur_constant::version::USER_AGENT.to_owned());

    let sec_key = if c.v2ray_http_upgrade {
        String::new()
    } else {
        let mut bytes = [0u8; 16];
        rand::rng().fill(&mut bytes);
        base64::engine::general_purpose::STANDARD.encode(bytes)
    };

    let mut sorted_headers: Vec<(String, String)> =
        headers.iter().map(|(k, v)| (canonical_header_key(k), v.clone())).collect();
    sorted_headers.push(("Connection".to_owned(), "Upgrade".to_owned()));
    sorted_headers.push(("Upgrade".to_owned(), "websocket".to_owned()));
    if !c.v2ray_http_upgrade {
        sorted_headers.push(("Sec-Websocket-Version".to_owned(), "13".to_owned()));
        sorted_headers.push(("Sec-Websocket-Key".to_owned(), sec_key.clone()));
    }

    if let Some(early_data) = early_data {
        if c.early_data_header_name.is_empty() {
            path.push_str(early_data);
        } else {
            let ed_key = canonical_header_key(&c.early_data_header_name);
            sorted_headers.retain(|(k, _)| *k != ed_key);
            sorted_headers.push((ed_key, early_data.to_owned()));
        }
    }

    sorted_headers.sort_by(|a, b| a.0.cmp(&b.0));

    let mut request = Vec::with_capacity(512);
    request.extend_from_slice(format!("GET {path} HTTP/1.1\r\n").as_bytes());
    request.extend_from_slice(format!("Host: {host_header}\r\n").as_bytes());
    if !user_agent.is_empty() {
        request.extend_from_slice(format!("User-Agent: {user_agent}\r\n").as_bytes());
    }
    for (key, value) in &sorted_headers {
        request.extend_from_slice(format!("{key}: {value}\r\n").as_bytes());
    }
    request.extend_from_slice(b"\r\n");
    (sec_key, request)
}

async fn stream_websocket_conn(
    ctx: &CancellationToken,
    conn: Box<dyn NetConn>,
    c: &WebsocketConfig,
    early_data: Option<&str>,
) -> Result<Box<dyn NetConn>> {
    let u = url::Url::parse(&format!("ws://placeholder{}", ensure_leading_slash(&c.path)))
        .map_err(|err| anyhow!("parse url {} error: {err}", c.path))?;

    let mut path = u.path().to_owned();
    if let Some(query) = u.query() {
        path = format!("{path}?{query}");
    }
    if !path.starts_with('/') {
        path = format!("/{path}");
    }

    let mut conn = maybe_wrap_tls(ctx, conn, c).await?;

    let (sec_key, request) = build_upgrade_request(c, &mut path, early_data);

    if ctx.is_cancelled() {
        return Err(anyhow!("context canceled"));
    }
    // A raw socket write synchronously pushes every byte to the socket before returning, so the
    // request needs no explicit flush. `tokio_rustls`'s
    // `TlsStream` behaves like a `BufWriter` instead: `poll_write` may report the plaintext as
    // consumed while ciphertext is still buffered internally, so a bare `write_all` can leave the
    // upgrade request sitting in that buffer forever once nothing else polls the connection.

    conn.write_all(&request).await?;
    conn.flush().await?;

    if c.v2ray_http_upgrade && c.v2ray_http_upgrade_fast_open {
        // S11: remove in U5, once this module's own conn is Stream-typed.
        let early: Box<dyn CommonExtendedConn> = new_early_conn(OldConnAsStream(conn), WsFastOpenResponse::new());
        return Ok(Box::new(StreamAsOldConn::new(early)));
    }

    let header_bytes = read_http_response_header(&mut *conn).await?;
    let response = parse_http_response(&header_bytes)?;

    let connection_upgrade =
        header_get(&response.headers, "Connection").is_some_and(|v| v.eq_ignore_ascii_case("upgrade"));
    let upgrade_websocket =
        header_get(&response.headers, "Upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if response.status != 101 || !connection_upgrade || !upgrade_websocket {
        return Err(anyhow!("unexpected status: {}", response.status));
    }

    if c.v2ray_http_upgrade {
        return Ok(conn);
    }

    if log::level() == log::LogLevel::DEBUG {
        let sec_accept = header_get(&response.headers, "Sec-Websocket-Accept").unwrap_or_default();
        if sec_accept.len() != ACCEPT_SIZE {
            return Err(anyhow!("unexpected Sec-Websocket-Accept length: {}", sec_accept.len()));
        }
        if get_websocket_sec_accept(&sec_key) != sec_accept {
            return Err(anyhow!("unexpected Sec-Websocket-Accept"));
        }
    }

    let ws_conn = new_websocket_conn(conn, STATE_CLIENT_SIDE);
    Ok(Box::new(StreamAsOldConn::new(new_deadline_conn(OldConnAsStream(ws_conn)))))
}

fn ensure_leading_slash(path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

enum WsedcState {
    NotDialed,
    Dialed(SharedConn),
}

struct WsedcInner {
    state: WsedcState,
    underlay: SharedConn,
    config: Arc<WebsocketConfig>,
}

impl WsedcInner {
    async fn dial(&mut self, ctx: &CancellationToken, early_data: &[u8]) -> Result<()> {
        let cap = usize::try_from(self.config.max_early_data.max(0)).unwrap_or(0);
        let take = early_data.len().min(cap);
        let (head, tail) = early_data.split_at(take);
        let encoded = URL_SAFE_NO_PAD.encode(head);

        let underlay: Box<dyn NetConn> = Box::new(self.underlay.clone());
        let result = stream_websocket_conn(ctx, underlay, &self.config, Some(&encoded)).await;
        let mut conn = match result {
            Ok(conn) => SharedConn::from_boxed(conn),
            Err(err) => {
                ctx.cancel();
                let _ = self.underlay.close();
                return Err(anyhow!("failed to dial WebSocket: {err}"));
            }
        };

        self.state = WsedcState::Dialed(conn.clone());
        if !tail.is_empty() {
            conn.write_all(tail).await?;
            conn.flush().await?;
        }
        Ok(())
    }
}

type PendingReadWrite = SyncMutex<Option<Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send>>>>;
type PendingFlush = SyncMutex<Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>>;

pub struct WebsocketWithEarlyDataConn {
    inner: Arc<AsyncMutex<WsedcInner>>,
    dialed_notify: Arc<Notify>,
    dialed_flag: Arc<AtomicBool>,
    ctx: CancellationToken,
    underlay: SharedConn,
    read: PendingReadWrite,
    write: PendingReadWrite,
    flush: PendingFlush,
    read_buf: SyncMutex<Vec<u8>>,
    write_buf: SyncMutex<Vec<u8>>,
}

impl WebsocketWithEarlyDataConn {
    /// The early-data read path. Only the state check (dialed or not) runs under
    /// `inner`'s lock; the actual read runs on a cloned `SharedConn` handle after the lock is
    /// released, for the same full-duplex reason `WebsocketConn` above splits `read_inner` from
    /// `write_inner`: holding one lock across a pending read would block a concurrent write the
    /// peer is waiting on to send the read's own next bytes.
    // cancel-safe: it re-reads the shared dial state on entry and the connection handle it clones is
    // owned by this future, so a drop leaves nothing half-dialed behind.
    async fn do_read(
        inner: Arc<AsyncMutex<WsedcInner>>,
        dialed_notify: Arc<Notify>,
        ctx: CancellationToken,
        b: &mut [u8],
    ) -> io::Result<usize> {
        loop {
            let dialed = {
                let guard = inner.lock().await;
                match &guard.state {
                    WsedcState::Dialed(conn) => Some(conn.clone()),
                    WsedcState::NotDialed => None,
                }
            };
            if let Some(conn) = dialed {
                return conn.read(b).await;
            }
            tokio::select! {
                () = dialed_notify.notified() => {}
                () = ctx.cancelled() => return Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            }
        }
    }

    /// The early-data write path. See `do_read`'s doc: the dialed connection is
    /// cloned out from under `inner`'s lock before writing to it, so a pending write never blocks
    /// behind a concurrent read (or vice versa).
    async fn do_write(
        inner: Arc<AsyncMutex<WsedcInner>>,
        dialed_notify: Arc<Notify>,
        dialed_flag: Arc<AtomicBool>,
        ctx: CancellationToken,
        b: Vec<u8>,
    ) -> io::Result<usize> {
        if ctx.is_cancelled() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        let mut guard = inner.lock().await;
        if let WsedcState::Dialed(conn) = &guard.state {
            let mut conn = conn.clone();
            drop(guard);
            conn.write_all(&b).await?;
            conn.flush().await?;
            return Ok(b.len());
        }
        guard.dial(&ctx, &b).await.map_err(io::Error::other)?;
        drop(guard);
        dialed_flag.store(true, Ordering::SeqCst);
        dialed_notify.notify_waiters();
        Ok(b.len())
    }

    /// Forwards to the dialed conn; before dialing there is nothing buffered to flush.
    async fn do_flush(inner: Arc<AsyncMutex<WsedcInner>>, ctx: CancellationToken) -> io::Result<()> {
        if ctx.is_cancelled() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        let guard = inner.lock().await;
        if let WsedcState::Dialed(conn) = &guard.state {
            let mut conn = conn.clone();
            drop(guard);
            conn.flush().await?;
        }
        Ok(())
    }
}

impl AsyncRead for WebsocketWithEarlyDataConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut read = this.read.lock();
        if read.is_none() {
            let inner = Arc::clone(&this.inner);
            let dialed_notify = Arc::clone(&this.dialed_notify);
            let ctx = this.ctx.clone();
            let mut tmp = std::mem::take(&mut *this.read_buf.lock());
            let r = buf.remaining();
            tmp.resize(r, 0);
            *read = Some(Box::pin(async move {
                let result = Self::do_read(inner, dialed_notify, ctx, &mut tmp).await;
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
                        let Some(filled) = tmp.get(..n) else {
                            return Poll::Ready(Err(io::Error::other("read filled more than the buffer holds")));
                        };
                        buf.put_slice(filled);
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

impl AsyncWrite for WebsocketWithEarlyDataConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut write = this.write.lock();
        if write.is_none() {
            let inner = Arc::clone(&this.inner);
            let dialed_notify = Arc::clone(&this.dialed_notify);
            let dialed_flag = Arc::clone(&this.dialed_flag);
            let ctx = this.ctx.clone();
            let mut data = std::mem::take(&mut *this.write_buf.lock());
            data.clear();
            data.extend_from_slice(buf);
            *write = Some(Box::pin(async move {
                let result = Self::do_write(inner, dialed_notify, dialed_flag, ctx, data.clone()).await;
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

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut flush = this.flush.lock();
        if flush.is_none() {
            let inner = Arc::clone(&this.inner);
            let ctx = this.ctx.clone();
            *flush = Some(Box::pin(Self::do_flush(inner, ctx)));
        }
        let Some(future) = flush.as_mut() else {
            return Poll::Ready(Err(io::Error::other("flush future was just installed")));
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

impl NetConn for WebsocketWithEarlyDataConn {
    fn close(&self) -> io::Result<()> {
        self.ctx.cancel();
        if self.dialed_flag.load(Ordering::SeqCst) {
            if let Ok(guard) = self.inner.try_lock() {
                if let WsedcState::Dialed(conn) = &guard.state {
                    return conn.close();
                }
            }
        }
        self.underlay.close()
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        if self.dialed_flag.load(Ordering::SeqCst) {
            if let Ok(guard) = self.inner.try_lock() {
                if let WsedcState::Dialed(conn) = &guard.state {
                    return conn.local_addr();
                }
            }
        }
        self.underlay.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        if self.dialed_flag.load(Ordering::SeqCst) {
            if let Ok(guard) = self.inner.try_lock() {
                if let WsedcState::Dialed(conn) = &guard.state {
                    return conn.remote_addr();
                }
            }
        }
        self.underlay.remote_addr()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.set_read_deadline(deadline)?;
        self.set_write_deadline(deadline)
    }

    /// A no-op before dialing.
    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        if self.dialed_flag.load(Ordering::SeqCst) {
            if let Ok(guard) = self.inner.try_lock() {
                if let WsedcState::Dialed(conn) = &guard.state {
                    return conn.set_read_deadline(deadline);
                }
            }
        }
        Ok(())
    }

    /// A no-op before dialing.
    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        if self.dialed_flag.load(Ordering::SeqCst) {
            if let Ok(guard) = self.inner.try_lock() {
                if let WsedcState::Dialed(conn) = &guard.state {
                    return conn.set_write_deadline(deadline);
                }
            }
        }
        Ok(())
    }
}

impl NetExtendedConn for WebsocketWithEarlyDataConn {
    /// Always the underlay, dialed or not.
    fn upstream(&self) -> Option<&dyn Any> {
        Some(&self.underlay)
    }
}

impl WebsocketWithEarlyDataConn {
    pub const fn front_headroom(&self) -> i32 {
        14
    }

    pub fn need_handshake(&self) -> bool {
        !self.dialed_flag.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for WebsocketWithEarlyDataConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketWithEarlyDataConn").finish_non_exhaustive()
    }
}

fn stream_websocket_with_early_data_conn(conn: Box<dyn NetConn>, c: WebsocketConfig) -> Box<dyn NetConn> {
    let underlay = SharedConn::from_boxed(conn);
    let ctx = CancellationToken::new();
    let wsedc = WebsocketWithEarlyDataConn {
        inner: Arc::new(AsyncMutex::new(WsedcInner {
            state: WsedcState::NotDialed,
            underlay: underlay.clone(),
            config: Arc::new(c),
        })),
        dialed_notify: Arc::new(Notify::new()),
        dialed_flag: Arc::new(AtomicBool::new(false)),
        ctx,
        underlay,
        read: SyncMutex::new(None),
        write: SyncMutex::new(None),
        flush: SyncMutex::new(None),
        read_buf: SyncMutex::new(Vec::new()),
        write_buf: SyncMutex::new(Vec::new()),
    };
    Box::new(StreamAsOldConn::new(new_deadline_conn(OldConnAsStream(wsedc))))
}

pub async fn stream_websocket_conn_public(
    ctx: &CancellationToken,
    conn: Box<dyn NetConn>,
    mut c: WebsocketConfig,
) -> Result<Box<dyn NetConn>> {
    if let Ok(u) = url::Url::parse(&format!("ws://placeholder{}", ensure_leading_slash(&c.path))) {
        if let Some((_, ed_value)) = u.query_pairs().find(|(k, _)| k == "ed") {
            if let Ok(ed) = ed_value.parse::<i64>() {
                c.max_early_data = ed;
                "Sec-WebSocket-Protocol".clone_into(&mut c.early_data_header_name);
                let filtered: Vec<(String, String)> =
                    u.query_pairs().filter(|(k, _)| k != "ed").map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
                let mut path = u.path().to_owned();
                if !filtered.is_empty() {
                    let query = filtered.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
                    path = format!("{path}?{query}");
                }
                c.path = path;
            }
        }
    }

    if c.max_early_data > 0 {
        return Ok(stream_websocket_with_early_data_conn(conn, c));
    }

    stream_websocket_conn(ctx, conn, &c, None).await
}

/// The module doc records the signature deviation.
#[must_use]
pub fn stream_upgraded_websocket_conn(
    conn: Box<dyn NetConn>,
    sec_websocket_key: Option<&str>,
    sec_websocket_protocol: Option<&str>,
) -> Box<dyn NetConn> {
    let is_raw = sec_websocket_key.is_none();

    let mut conn = if is_raw { conn } else { Box::new(new_websocket_conn(conn, STATE_SERVER_SIDE)) };
    if !is_raw {
        conn = Box::new(StreamAsOldConn::new(new_deadline_conn(OldConnAsStream(conn))));
    }

    if let Some(ed_buf) = decode_xray_0rtt(sec_websocket_protocol) {
        if !ed_buf.is_empty() {
            conn = Box::new(new_cached_conn(OldConnAsStream(conn), ed_buf));
        }
    }

    conn
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    #[derive(Debug)]
    struct BoundedWire(tokio::io::DuplexStream);

    impl AsyncRead for BoundedWire {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for BoundedWire {
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

    impl NetConn for BoundedWire {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    // NOT cancel-safe: a timeout deliberately tears down both test endpoints on failure.
    async fn pending_data_then_control(close: bool) {
        let (client, mut peer) = tokio::io::duplex(32);
        let mut conn = new_websocket_conn(Box::new(BoundedWire(client)), STATE_SERVER_SIDE);
        let payload = [0x55; 512];
        let first = std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut conn).poll_write(cx, &payload))).await;
        if let Poll::Ready(result) = first {
            assert_eq!(result.expect("accept data"), payload.len());
        }

        let mut prefix = [0; 32];
        peer.read_exact(&mut prefix).await.expect("partial frame reached peer");
        assert_eq!(&prefix[..4], &[0x82, 126, 2, 0]);
        let control = if close { 0x88 } else { 0x89 };
        peer.write_all(&[control, 0x80, 0, 0, 0, 0]).await.expect("send masked control");
        let mut reply = [0; 1];
        let _ = std::future::poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut reply);
            Poll::Ready(Pin::new(&mut conn).poll_read(cx, &mut buf))
        })
        .await;

        let receive = async {
            let mut rest = vec![0; 512 + 4 - prefix.len() + 2];
            peer.read_exact(&mut rest[..2]).await.expect("next two wire bytes");
            assert_eq!(&rest[..2], &[0x55, 0x55], "control header split the data frame");
            peer.read_exact(&mut rest[2..]).await.expect("complete data and control response");
            let mut wire = prefix.to_vec();
            wire.extend(rest);
            assert_eq!(&wire[4..516], &payload);
            assert_eq!(&wire[516..], &[if close { 0x88 } else { 0x8a }, 0]);
            if !close {
                peer.write_all(&[0x82, 0x81, 0, 0, 0, 0, 0x42]).await.expect("send application reply");
            }
        };
        let read = async {
            let result = conn.read(&mut reply).await;
            if close {
                assert!(result.is_err());
            } else {
                assert_eq!(result.expect("read after pong"), 1);
                assert_eq!(reply, [0x42]);
            }
        };
        tokio::join!(receive, read);
    }

    #[tokio::test]
    async fn websocket_pending_data_and_ping_keep_frames_ordered_after_write_cancellation() {
        tokio::time::timeout(Duration::from_secs(5), pending_data_then_control(false))
            .await
            .expect("pending data must drain without polling the cancelled writer");
    }

    #[tokio::test]
    async fn websocket_pending_data_and_peer_close_keep_frames_ordered() {
        tokio::time::timeout(Duration::from_secs(5), pending_data_then_control(true))
            .await
            .expect("close must follow the complete data frame");
    }

    #[tokio::test]
    async fn websocket_cancelled_write_wait_accepts_only_replacement_bytes() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client, mut peer) = tokio::io::duplex(32);
            let mut conn = new_websocket_conn(Box::new(BoundedWire(client)), STATE_SERVER_SIDE);
            conn.write_all(&[0x55; 512]).await.expect("buffer first frame");
            let pending =
                std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut conn).poll_write(cx, &[0x66; 128]))).await;
            assert!(pending.is_pending());
            assert_eq!(conn.write(&[]).await.expect("empty write"), 0);
            let receive = async {
                let mut wire = vec![0; 516 + 3];
                peer.read_exact(&mut wire).await.expect("receive both frames");
                assert_eq!(&wire[..4], &[0x82, 126, 2, 0]);
                assert_eq!(&wire[4..516], &[0x55; 512]);
                assert_eq!(&wire[516..], &[0x82, 1, 0x77]);
            };
            let write = async {
                assert_eq!(conn.write(&[0x77]).await.expect("replacement write"), 1);
                conn.flush().await.expect("flush accepted frames");
            };
            tokio::join!(receive, write);
        })
        .await
        .expect("replaced writer must not retain an unaccepted payload");
    }

    #[tokio::test]
    async fn websocket_buffered_write_failure_reaches_flush_and_later_writes() {
        let (client, peer) = tokio::io::duplex(32);
        let mut conn = new_websocket_conn(Box::new(BoundedWire(client)), STATE_SERVER_SIDE);
        conn.write_all(&[0x55; 512]).await.expect("buffer frame");
        drop(peer);
        let error = tokio::time::timeout(Duration::from_secs(5), conn.flush())
            .await
            .expect("failed drain wakes flush")
            .expect_err("flush exposes write error");
        assert_eq!(conn.write(&[0x77]).await.expect_err("write remains failed").kind(), error.kind());
        assert_eq!(conn.shutdown().await.expect_err("shutdown remains failed").kind(), error.kind());
    }

    #[tokio::test]
    async fn websocket_drop_releases_pending_drain_without_peer_progress() {
        let (client, mut peer) = tokio::io::duplex(32);
        let mut conn = new_websocket_conn(Box::new(BoundedWire(client)), STATE_SERVER_SIDE);
        conn.write_all(&[0x55; 512]).await.expect("accept pending frame");
        peer.write_all(&[0; 32]).await.expect("fill abandoned receive buffer");
        drop(conn);
        tokio::time::timeout(Duration::from_secs(5), async {
            peer.write_all(&[0]).await.expect_err("dropping websocket must release its blocked drain");
        })
        .await
        .expect("release cannot require the peer to drain outgoing data");
    }

    #[tokio::test]
    async fn websocket_drop_after_close_preserves_ordered_pending_frames() {
        let (client, mut peer) = tokio::io::duplex(32);
        let mut conn = new_websocket_conn(Box::new(BoundedWire(client)), STATE_SERVER_SIDE);
        conn.write_all(&[0x55; 512]).await.expect("accept pending frame");
        conn.close().expect("request orderly close");
        drop(conn);
        let mut wire = vec![0; 516 + 4];
        tokio::time::timeout(Duration::from_secs(5), peer.read_exact(&mut wire))
            .await
            .expect("close retains drain ownership")
            .expect("read data then close");
        assert_eq!(&wire[..4], &[0x82, 126, 2, 0]);
        assert_eq!(&wire[4..516], &[0x55; 512]);
        assert_eq!(&wire[516..], &[0x88, 2, 3, 232]);
    }

    #[tokio::test]
    async fn websocket_local_close_follows_pending_data_and_rejects_later_writes() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client, mut peer) = tokio::io::duplex(32);
            let mut conn = new_websocket_conn(Box::new(BoundedWire(client)), STATE_SERVER_SIDE);
            conn.write_all(&[0x55; 512]).await.expect("accept data frame");
            conn.close().expect("schedule close");
            let mut wire = vec![0; 516 + 4];
            peer.read_exact(&mut wire).await.expect("data then close");
            assert_eq!(&wire[..4], &[0x82, 126, 2, 0]);
            assert_eq!(&wire[4..516], &[0x55; 512]);
            assert_eq!(&wire[516..], &[0x88, 2, 3, 232]);
            assert_eq!(conn.write(&[0x77]).await.expect_err("no data after close").kind(), io::ErrorKind::BrokenPipe);
        })
        .await
        .expect("close drains the outstanding frame without its caller");
    }

    /// Regression test for the live differential-test failure: with an explicit `host` override
    /// in `ws-headers` when a Cloudflare Worker fronts the node, the writer used to
    /// write two `Host:` header lines — one unconditionally derived from `host:port`, and a
    /// second from the override — which a strict fronting CDN rejected with 403/429. Exactly one
    /// `Host:` line is written (the override, with no port), plus a default `User-Agent` line, then
    /// the remaining headers canonicalized and sorted alphabetically by key.
    #[tokio::test]
    async fn stream_websocket_conn_sends_the_expected_upgrade_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test connection");
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).await.expect("read request");
                if n == 0 || buf.ends_with(b"\r\n\r\n") {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            buf
        });

        let stream = TcpStream::connect(addr).await.expect("connect to test listener");
        let conn: Box<dyn NetConn> = Box::new(stream);

        let config = WebsocketConfig {
            host: "104.21.58.246".to_owned(),
            port: "443".to_owned(),
            path: "/vl/MoCdc0wOC7T6JiYflef9hYfM".to_owned(),
            headers: vec![("Host".to_owned(), "q2-phbest7v2a8iuowpr.g0xigfh41wwnv39y-b3rzmht.workers.dev".to_owned())],
            ..Default::default()
        };

        let ctx = CancellationToken::new();
        let _ = stream_websocket_conn_public(&ctx, conn, config).await;

        let request = String::from_utf8(server.await.expect("server task")).expect("utf8 request");
        assert_eq!(request.matches("Host:").count(), 1, "duplicate Host header: {request:?}");

        let mut lines = request.split("\r\n");
        assert_eq!(lines.next(), Some("GET /vl/MoCdc0wOC7T6JiYflef9hYfM HTTP/1.1"));
        assert_eq!(lines.next(), Some("Host: q2-phbest7v2a8iuowpr.g0xigfh41wwnv39y-b3rzmht.workers.dev"));
        assert_eq!(lines.next(), Some(&format!("User-Agent: {}", murmur_constant::version::USER_AGENT)[..]));
        assert_eq!(lines.next(), Some("Connection: Upgrade"));
        assert!(lines.next().is_some_and(|line| line.starts_with("Sec-Websocket-Key: ")));
        assert_eq!(lines.next(), Some("Sec-Websocket-Version: 13"));
        assert_eq!(lines.next(), Some("Upgrade: websocket"));
        assert_eq!(lines.next(), Some(""));
        assert_eq!(lines.next(), Some(""));
        assert_eq!(lines.next(), None);
    }

    /// With `v2ray_http_upgrade` and `v2ray_http_upgrade_fast_open` both set, the upgrade request is
    /// written and the `101` read and validation are deferred to the connection's first read. The test server here withholds its `101` response until it has
    /// read the client's early payload, so a client that (incorrectly) blocks on the `101` before
    /// returning — the pre-fix behaviour — deadlocks against this server and times out.
    #[tokio::test]
    async fn v2ray_http_upgrade_fast_open_writes_before_reading_101() {
        const PAYLOAD: &[u8] = b"fast-open-payload";

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test connection");

            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let header_end = loop {
                let n = stream.read(&mut chunk).await.expect("read request");
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };

            let mut payload = buf.split_off(header_end);
            while payload.len() < PAYLOAD.len() {
                let n = stream.read(&mut chunk).await.expect("read early payload before responding");
                payload.extend_from_slice(&chunk[..n]);
            }
            assert_eq!(&payload[..PAYLOAD.len()], PAYLOAD);

            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                .await
                .expect("write 101 response");
        });

        let stream = TcpStream::connect(addr).await.expect("connect to test listener");
        let conn: Box<dyn NetConn> = Box::new(stream);
        let config = WebsocketConfig {
            host: "127.0.0.1".to_owned(),
            port: addr.port().to_string(),
            path: "/ws".to_owned(),
            v2ray_http_upgrade: true,
            v2ray_http_upgrade_fast_open: true,
            ..Default::default()
        };

        let ctx = CancellationToken::new();
        let mut ws_conn =
            tokio::time::timeout(Duration::from_secs(5), stream_websocket_conn_public(&ctx, conn, config))
                .await
                .expect("fast-open dial must return before the server's 101 response arrives")
                .expect("client ws fast-open handshake");

        tokio::time::timeout(Duration::from_secs(5), ws_conn.write_all(PAYLOAD))
            .await
            .expect("fast-open write must not wait for the deferred 101 check")
            .expect("write early payload");

        let mut trailing = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), ws_conn.read(&mut trailing))
            .await
            .expect("deferred 101 validation must complete once the server responds")
            .expect("read after fast-open dial");
        assert_eq!(n, 0, "server closes right after the 101 response with no further bytes");

        server.await.expect("server task panicked");
    }

    /// Regression test for the deadlock fixed in this module: `WebsocketWithEarlyDataConn` used
    /// to guard both the read and the write path with the same `AsyncMutex`, held across the
    /// pending network I/O rather than released before it (the same class of bug `WebsocketConn`
    /// above already avoids by splitting `read_inner` from `write_inner`). A peer that withholds
    /// its next message until it has received the client's next flight — any real TLS handshake
    /// tunnelled over this transport — starves the write behind the blocked read forever. The test
    /// server does exactly that: it sends nothing back until it has read a second frame from the
    /// client, so a concurrent read and write on the dialed connection must both make progress for
    /// the exchange to complete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn early_data_conn_concurrent_read_write_never_deadlocks() {
        use murmur_common_net::get_websocket_sec_accept;
        use tokio::io::AsyncWriteExt as _;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test connection");

            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).await.expect("read request");
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&buf).into_owned();
            let sec_key = request
                .lines()
                .find_map(|line| line.strip_prefix("Sec-Websocket-Key: "))
                .expect("client sent Sec-Websocket-Key")
                .trim()
                .to_owned();
            let accept = get_websocket_sec_accept(&sec_key);
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-Websocket-Accept: {accept}\r\n\r\n"
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

        let stream = TcpStream::connect(addr).await.expect("connect to test listener");
        let conn: Box<dyn NetConn> = Box::new(stream);
        let config = WebsocketConfig {
            host: "127.0.0.1".to_owned(),
            port: addr.port().to_string(),
            path: "/ws?ed=2048".to_owned(),
            ..Default::default()
        };
        let ctx = CancellationToken::new();
        let mut ws_conn =
            stream_websocket_conn_public(&ctx, conn, config).await.expect("client ws early-data handshake");
        ws_conn.write_all(b"first-flight").await.expect("early-data write dials the connection");

        let (mut read_half, mut write_half) = tokio::io::split(ws_conn);
        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let n = read_half.read(&mut buf).await.expect("read server reply");
            buf[..n].to_vec()
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let write_task =
            tokio::spawn(async move { write_half.write_all(b"second-flight").await.expect("write second flight") });

        let (read_result, write_result) =
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(read_task, write_task) })
                .await
                .expect("concurrent read+write on a dialed early-data conn deadlocked");
        write_result.expect("write task panicked");
        assert_eq!(read_result.expect("read task panicked"), b"server-reply");

        server.await.expect("server task panicked");
    }

    /// A control frame may legally arrive between the fragments of one message (RFC 6455 §5.4), but
    /// `poll_read` turns a zero-length `read_ws` into a zero-length `ReadBuf` put, which every
    /// `AsyncRead` caller reads as end-of-stream. The equivalent test in `murmur_ws` drives its
    /// reader through a hand-written loop, so it cannot see a regression in this adapter;
    /// the server here holds the connection open after the final fragment so a truncating read
    /// fails on a live socket rather than passing for a legitimate EOF.
    #[tokio::test]
    async fn websocket_conn_reads_across_an_interleaved_ping_between_fragments() {
        use murmur_ws::{Header, OP_CONTINUATION, OP_PING};

        const TIMEOUT: Duration = Duration::from_secs(5);

        async fn server_frame(wire: &mut Vec<u8>, fin: bool, op_code: OpCode, payload: &[u8]) {
            let hdr = Header { fin, rsv: 0, op_code, masked: false, mask: [0; 4], length: payload.len() as i64 };
            murmur_ws::write_header(wire, &hdr).await.expect("encode server frame header");
            wire.extend_from_slice(payload);
        }

        // A non-final text fragment, an interleaved ping, and the final continuation. Server to
        // client frames are unmasked, which is what the client-side `Reader` expects.
        let mut wire = Vec::new();
        server_frame(&mut wire, false, OP_TEXT, b"hello").await;
        server_frame(&mut wire, true, OP_PING, b"hi").await;
        server_frame(&mut wire, true, OP_CONTINUATION, b"world").await;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test connection");

            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).await.expect("read upgrade request");
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&buf).into_owned();
            let sec_key = request
                .lines()
                .find_map(|line| line.strip_prefix("Sec-Websocket-Key: "))
                .expect("client sent Sec-Websocket-Key")
                .trim()
                .to_owned();
            let accept = get_websocket_sec_accept(&sec_key);
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-Websocket-Accept: {accept}\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.expect("write 101 response");
            stream.write_all(&wire).await.expect("write the fragmented message");
            stream.flush().await.expect("flush the fragmented message");

            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        let stream = TcpStream::connect(addr).await.expect("connect to test listener");
        let conn: Box<dyn NetConn> = Box::new(stream);
        let config = WebsocketConfig {
            host: "127.0.0.1".to_owned(),
            port: addr.port().to_string(),
            path: "/ws".to_owned(),
            ..Default::default()
        };
        let ctx = CancellationToken::new();
        let mut ws_conn = tokio::time::timeout(TIMEOUT, stream_websocket_conn_public(&ctx, conn, config))
            .await
            .expect("client ws handshake must not hang")
            .expect("client ws handshake");

        let mut got = [0u8; 10];
        tokio::time::timeout(TIMEOUT, ws_conn.read_exact(&mut got))
            .await
            .expect("the whole message must arrive while the server still holds the connection open")
            .expect("read the fragmented message");
        assert_eq!(&got, b"helloworld");

        server.abort();
    }

    /// Relocated from `component::tls::utls`'s own test module (crate split: this crate already
    /// depends on `component::tls` normally, so the integration test that drives the real
    /// [`stream_websocket_conn_public`] handshake through `component::tls::server` moved here
    /// instead of `component::tls` gaining a dev-only dependency back on this crate).
    ///
    /// Regression test for the WebSocket concurrency defect fixed in `rust/README.md`
    /// ("Known defects"): `stream_websocket_conn_public` used to leave a fraction of concurrent
    /// requests stranded in the TLS write buffer with no flush to drain them. Reproduces in
    /// seconds where the real trojan tests needed a full-suite run to show the same stall.
    #[tokio::test]
    async fn concurrent_real_ws_handshake_over_tls_never_hangs() {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Empty, Full};
        use hyper::header::{CONNECTION, UPGRADE};
        use hyper::service::service_fn;
        use hyper::{Request, Response, StatusCode};
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto;
        use murmur_common_net::websocket::get_websocket_sec_accept;
        use murmur_component_ca::keypair::{new_random_tls_key_pair, new_tls_key_pair_loader, KeyPairType};
        use tokio_util::sync::CancellationToken;

        const HANG_DEADLINE: Duration = Duration::from_secs(60);
        fn concurrency_width() -> usize {
            std::thread::available_parallelism().map(std::num::NonZeroUsize::get).unwrap_or(1).saturating_mul(8).max(16)
        }

        let (cert_pem, key_pem, fingerprint) = new_random_tls_key_pair(KeyPairType::P256).expect("key generation");
        let loader = new_tls_key_pair_loader(&cert_pem, &key_pem).expect("valid cert");
        let cert_for_server = loader().expect("cert loads");

        let server_config = Arc::new(tls_c::Config {
            certificates: vec![cert_for_server],
            next_protos: vec!["http/1.1".to_owned()],
            ..Default::default()
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");
        let (host, port) = (addr.ip().to_string(), addr.port().to_string());

        let n = concurrency_width();

        let mut client_tasks = Vec::with_capacity(n);
        for _ in 0..n {
            let host = host.clone();
            let port = port.clone();
            let fingerprint = fingerprint.clone();
            client_tasks.push(tokio::spawn(async move {
                let raw = TcpStream::connect(addr).await.expect("client connect");
                let ws_opts = WebsocketConfig {
                    host: host.clone(),
                    port,
                    path: "/ws".to_owned(),
                    tls: true,
                    tls_config: Some(Arc::new(tls_c::Config {
                        next_protos: vec!["http/1.1".to_owned()],
                        server_name: host,
                        insecure_skip_verify: true,
                        ..Default::default()
                    })),
                    ..Default::default()
                };
                let _ = fingerprint;
                let ctx = CancellationToken::new();
                tokio::time::timeout(
                    HANG_DEADLINE,
                    stream_websocket_conn_public(&ctx, Box::new(raw), ws_opts),
                )
                .await
                .expect("client ws handshake did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect")
                .expect("client ws handshake failed");
            }));
        }

        let mut server_tasks = Vec::with_capacity(n);
        for _ in 0..n {
            let (raw, _) = listener.accept().await.expect("accept");
            let server_config = Arc::clone(&server_config);
            server_tasks.push(tokio::spawn(async move {
                let tls_conn = tls_c::server(Box::new(raw), server_config);
                let io = TokioIo::new(tls_conn);
                let svc = service_fn(|mut req: Request<hyper::body::Incoming>| async move {
                    if req.uri().path() != "/ws" {
                        return Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Empty::<Bytes>::new().boxed())
                                .unwrap(),
                        );
                    }
                    let sec_key = req
                        .headers()
                        .get("sec-websocket-key")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned)
                        .unwrap_or_default();
                    let accept = get_websocket_sec_accept(&sec_key);
                    let on_upgrade = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        let _ = on_upgrade.await;
                    });
                    Ok(Response::builder()
                        .status(StatusCode::SWITCHING_PROTOCOLS)
                        .header(UPGRADE, "websocket")
                        .header(CONNECTION, "Upgrade")
                        .header("Sec-WebSocket-Accept", accept)
                        .body(Empty::<Bytes>::new().boxed())
                        .unwrap())
                });
                let builder = auto::Builder::new(TokioExecutor::new());
                tokio::time::timeout(HANG_DEADLINE, builder.serve_connection_with_upgrades(io, svc))
                    .await
                    .expect("server serve_connection did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect")
                    .expect("server serve_connection failed");
            }));
        }

        for task in client_tasks {
            task.await.expect("client task panicked");
        }
        for task in server_tasks {
            task.await.expect("server task panicked");
        }
        let _ = Full::<Bytes>::default();
    }

    /// Relocated from `component::tls::utls`'s own test module (crate split: this crate already
    /// depends on both `component::tls` and `component::ca` normally, so the integration test
    /// that generates a real certificate through `component::ca::keypair` and drives it over a
    /// real [`stream_websocket_conn_public`] handshake moved here instead of `component::tls`
    /// gaining a dev-only dependency back on this crate).
    #[tokio::test]
    async fn concurrent_real_websocket_conn_then_echo_over_tls_repro() {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Empty};
        use hyper::header::{CONNECTION, UPGRADE};
        use hyper::service::service_fn;
        use hyper::{Request, Response, StatusCode};
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto;
        use murmur_common_net::websocket::get_websocket_sec_accept;
        use murmur_component_ca::keypair::{new_random_tls_key_pair, new_tls_key_pair_loader, KeyPairType};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio_util::sync::CancellationToken;

        const HANG_DEADLINE: Duration = Duration::from_secs(60);
        fn concurrency_width() -> usize {
            std::thread::available_parallelism().map(std::num::NonZeroUsize::get).unwrap_or(1).saturating_mul(8).max(16)
        }

        let (cert_pem, key_pem, _fp) = new_random_tls_key_pair(KeyPairType::P256).expect("key generation");
        let loader = new_tls_key_pair_loader(&cert_pem, &key_pem).expect("valid cert");
        let cert_for_server = loader().expect("cert loads");

        let server_config = Arc::new(tls_c::Config {
            certificates: vec![cert_for_server],
            next_protos: vec!["http/1.1".to_owned()],
            ..Default::default()
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");
        let (host, port) = (addr.ip().to_string(), addr.port().to_string());

        let n = concurrency_width();

        let mut client_tasks = Vec::with_capacity(n);
        for i in 0..n {
            let host = host.clone();
            let port = port.clone();
            client_tasks.push(tokio::spawn(async move {
                tokio::time::timeout(HANG_DEADLINE, async move {
                    let raw = TcpStream::connect(addr).await.expect("client connect");
                    let ws_opts = WebsocketConfig {
                        host: host.clone(),
                        port,
                        path: "/ws".to_owned(),
                        tls: true,
                        tls_config: Some(Arc::new(tls_c::Config {
                            next_protos: vec!["http/1.1".to_owned()],
                            server_name: host,
                            insecure_skip_verify: true,
                            ..Default::default()
                        })),
                        ..Default::default()
                    };
                    let ctx = CancellationToken::new();
                    let mut conn =
                        stream_websocket_conn_public(&ctx, Box::new(raw), ws_opts).await.expect("client ws handshake");
                    conn.write_all(b"PING").await.expect("client ping write");
                    let mut pong = [0u8; 4];
                    conn.read_exact(&mut pong).await.expect("client pong read");
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
                    let tls_conn = tls_c::server(Box::new(raw), server_config);
                    let io = TokioIo::new(tls_conn);
                    let svc = service_fn(move |mut req: Request<hyper::body::Incoming>| async move {
                        if req.uri().path() != "/ws" {
                            return Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Empty::<Bytes>::new().boxed())
                                    .unwrap(),
                            );
                        }
                        let sec_key = req
                            .headers()
                            .get("sec-websocket-key")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned)
                            .unwrap_or_default();
                        let accept = get_websocket_sec_accept(&sec_key);
                        let on_upgrade = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            let Ok(upgraded) = on_upgrade.await else {
                                return;
                            };
                            let Ok(parts) = auto::upgrade::downcast::<TokioIo<tls_c::Conn>>(upgraded) else {
                                return;
                            };
                            let conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(parts.io.into_inner()));
                            let mut conn = stream_upgraded_websocket_conn(conn, Some(&sec_key), None);
                            let mut ping = [0u8; 4];
                            conn.read_exact(&mut ping).await.expect("server ping read");
                            assert_eq!(&ping, b"PING", "task {i} server got unexpected ping");
                            conn.write_all(b"PONG").await.expect("server pong write");
                        });
                        Ok(Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header(UPGRADE, "websocket")
                            .header(CONNECTION, "Upgrade")
                            .header("Sec-WebSocket-Accept", accept)
                            .body(Empty::<Bytes>::new().boxed())
                            .unwrap())
                    });
                    let builder = auto::Builder::new(TokioExecutor::new());
                    builder.serve_connection_with_upgrades(io, svc).await.expect("server serve_connection failed");
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

    /// Relocated alongside the test above, same reason: nests a second `hyper` connection over
    /// the websocket conn, needing both `component::tls` and `component::ca`.
    #[tokio::test]
    async fn concurrent_nested_hyper_over_websocket_conn_repro() {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Empty, Full};
        use hyper::header::{CONNECTION, UPGRADE};
        use hyper::service::service_fn;
        use hyper::{Request, Response, StatusCode};
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto;
        use murmur_common_net::websocket::get_websocket_sec_accept;
        use murmur_component_ca::keypair::{new_random_tls_key_pair, new_tls_key_pair_loader, KeyPairType};
        use tokio::net::{TcpListener, TcpStream};
        use tokio_util::sync::CancellationToken;

        const HANG_DEADLINE: Duration = Duration::from_secs(60);
        fn concurrency_width() -> usize {
            std::thread::available_parallelism().map(std::num::NonZeroUsize::get).unwrap_or(1).saturating_mul(8).max(16)
        }

        struct AsAsyncIo(Box<dyn NetConn>);

        impl AsyncRead for AsAsyncIo {
            fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut *self.get_mut().0).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for AsAsyncIo {
            fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
                Pin::new(&mut *self.get_mut().0).poll_write(cx, buf)
            }
            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut *self.get_mut().0).poll_flush(cx)
            }
            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut *self.get_mut().0).poll_shutdown(cx)
            }
        }

        let (cert_pem, key_pem, _fp) = new_random_tls_key_pair(KeyPairType::P256).expect("key generation");
        let loader = new_tls_key_pair_loader(&cert_pem, &key_pem).expect("valid cert");
        let cert_for_server = loader().expect("cert loads");

        let server_config = Arc::new(tls_c::Config {
            certificates: vec![cert_for_server],
            next_protos: vec!["http/1.1".to_owned()],
            ..Default::default()
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");
        let (host, port) = (addr.ip().to_string(), addr.port().to_string());

        let n = concurrency_width();

        let mut client_tasks = Vec::with_capacity(n);
        for i in 0..n {
            let host = host.clone();
            let port = port.clone();
            client_tasks.push(tokio::spawn(async move {
                tokio::time::timeout(HANG_DEADLINE, async move {
                    let raw = TcpStream::connect(addr).await.expect("client connect");
                    let ws_opts = WebsocketConfig {
                        host: host.clone(),
                        port,
                        path: "/ws".to_owned(),
                        tls: true,
                        tls_config: Some(Arc::new(tls_c::Config {
                            next_protos: vec!["http/1.1".to_owned()],
                            server_name: host,
                            insecure_skip_verify: true,
                            ..Default::default()
                        })),
                        ..Default::default()
                    };
                    let ctx = CancellationToken::new();
                    let conn =
                        stream_websocket_conn_public(&ctx, Box::new(raw), ws_opts).await.expect("client ws handshake");
                    let io = TokioIo::new(AsAsyncIo(conn));
                    let (mut sender, hyper_conn) =
                        hyper::client::conn::http1::handshake(io).await.expect("inner client http1 handshake");
                    tokio::spawn(hyper_conn);
                    let size = (i % 64 + 1) * 1024;
                    let mut body_bytes = vec![0u8; size];
                    for (idx, byte) in body_bytes.iter_mut().enumerate() {
                        *byte = ((i.wrapping_mul(2654435761).wrapping_add(idx)) % 256) as u8;
                    }
                    let body_bytes = Bytes::from(body_bytes);
                    let req = Request::post("/echo")
                        .header(hyper::header::HOST, "x")
                        .body(Full::<Bytes>::from(body_bytes.clone()))
                        .expect("valid request");
                    let response = sender.send_request(req).await.expect("inner client request failed");
                    assert_eq!(response.status(), StatusCode::OK, "task {i} unexpected status");
                    let body = response.into_body().collect().await.expect("inner body collect").to_bytes();
                    assert_eq!(body, body_bytes, "task {i} got unexpected echo body");
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
                    let tls_conn = tls_c::server(Box::new(raw), server_config);
                    let io = TokioIo::new(tls_conn);
                    let svc = service_fn(move |mut req: Request<hyper::body::Incoming>| async move {
                        if req.uri().path() != "/ws" {
                            return Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Empty::<Bytes>::new().boxed())
                                    .unwrap(),
                            );
                        }
                        let sec_key = req
                            .headers()
                            .get("sec-websocket-key")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned)
                            .unwrap_or_default();
                        let accept = get_websocket_sec_accept(&sec_key);
                        let on_upgrade = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            let Ok(upgraded) = on_upgrade.await else {
                                return;
                            };
                            let Ok(parts) = auto::upgrade::downcast::<TokioIo<tls_c::Conn>>(upgraded) else {
                                return;
                            };
                            let conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(parts.io.into_inner()));
                            let conn = stream_upgraded_websocket_conn(conn, Some(&sec_key), None);
                            let inner_io = TokioIo::new(AsAsyncIo(conn));
                            let inner_svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                                let body = req.into_body().collect().await?.to_bytes();
                                Ok::<_, anyhow::Error>(Response::new(Full::<Bytes>::from(body)))
                            });
                            let inner_builder = auto::Builder::new(TokioExecutor::new());
                            let _ = inner_builder.serve_connection(inner_io, inner_svc).await;
                        });
                        Ok(Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header(UPGRADE, "websocket")
                            .header(CONNECTION, "Upgrade")
                            .header("Sec-WebSocket-Accept", accept)
                            .body(Empty::<Bytes>::new().boxed())
                            .unwrap())
                    });
                    let builder = auto::Builder::new(TokioExecutor::new());
                    builder.serve_connection_with_upgrades(io, svc).await.expect("server serve_connection failed");
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
}
