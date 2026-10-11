use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use parking_lot::Mutex;
use rand::rng;
use rand::RngCore as _;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, ReadBuf, ReadHalf, WriteHalf,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use murmur_common_net::io::{close_stream, Stream};

use super::conn_helpers::{try_close_read, try_close_write, write_full};
use super::early_handshake::TunnelServerEarlyHandshake;
use super::halfpipe::new_half_pipe;
use super::masker::looks_like_http_request_start;
use super::masker::PATHS;
use super::pathroot::{normalize_path_root, strip_path_root};
use super::tunnel_api::{HandleResult, TunnelMode};
use super::tunnel_dial::TUNNEL_STREAM_EOF_HEADER;
use super::tunnel_ws_server::looks_like_web_socket_upgrade;
use super::ws_auth::TunnelAuth;

pub(crate) struct TunnelServerOptions {
    pub(crate) mode: String,
    pub(crate) path_root: String,
    pub(crate) auth_key: String,
    pub(crate) auth_skew: Duration,
    pub(crate) pass_through_on_reject: bool,
    pub(crate) pull_read_timeout: Duration,
    pub(crate) session_ttl: Duration,
    pub(crate) early_handshake: Option<TunnelServerEarlyHandshake>,
}

pub(crate) const TUNNEL_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Caps the live session table: `/session` needs no credential, and each entry holds a half-pipe
/// and a reaper task until `session_ttl` of inactivity, so time alone does not bound the table.
const MAX_SESSIONS: usize = 1024;

struct TunnelSession {
    read_half: tokio::sync::Mutex<Option<ReadHalf<Box<dyn Stream>>>>,
    write_half: tokio::sync::Mutex<Option<WriteHalf<Box<dyn Stream>>>>,
    last_active: Mutex<Instant>,
    uplink_closed: AtomicBool,
    downlink_closed: AtomicBool,
    closed: CancellationToken,

    upload_mu: tokio::sync::Mutex<()>,
    next_upload_seq: AtomicU64,
    pull_mu: Mutex<Option<Arc<SessionPullLease>>>,
    downlink_mu: Mutex<Vec<u8>>,
}

/// The session-pull lease. The lease also owns the raw conn and force-closes it on stop;
/// this crate races every blocking read/write against `cancel` instead (see
/// `begin_session_pull`/`pull_read`), so the lease does not need to own a connection.
struct SessionPullLease {
    cancel: CancellationToken,
    done: CancellationToken,
}

impl SessionPullLease {
    fn new() -> Arc<Self> {
        Arc::new(Self { cancel: CancellationToken::new(), done: CancellationToken::new() })
    }

    /// `CancellationToken::cancel` is already idempotent, so no
    /// separate stop-once is needed.
    fn stop(&self) {
        self.cancel.cancel();
    }
}

impl TunnelSession {
    fn new(conn: Box<dyn Stream>) -> Arc<Self> {
        let (read_half, write_half) = tokio::io::split(conn);
        Arc::new(Self {
            read_half: tokio::sync::Mutex::new(Some(read_half)),
            write_half: tokio::sync::Mutex::new(Some(write_half)),
            last_active: Mutex::new(Instant::now()),
            uplink_closed: AtomicBool::new(false),
            downlink_closed: AtomicBool::new(false),
            closed: CancellationToken::new(),
            upload_mu: tokio::sync::Mutex::new(()),
            next_upload_seq: AtomicU64::new(1),
            pull_mu: Mutex::new(None),
            downlink_mu: Mutex::new(Vec::new()),
        })
    }

    /// `sess.conn.Close()`. Reunites the split halves and closes the underlying conn for
    /// good; further reads/writes on this session observe a closed conn.
    async fn close_conn(&self) {
        let r = self.read_half.lock().await.take();
        let w = self.write_half.lock().await.take();
        if let (Some(r), Some(w)) = (r, w) {
            let conn = r.unsplit(w);
            let _ = close_stream(&*conn);
        }
    }

    /// Reunites the split halves just long enough to half-close
    /// the write side, then re-splits so reads keep working.
    async fn close_write_conn(&self) {
        let mut r_guard = self.read_half.lock().await;
        let mut w_guard = self.write_half.lock().await;
        if let (Some(r), Some(w)) = (r_guard.take(), w_guard.take()) {
            let conn = r.unsplit(w);
            let _ = conn.shutdown_write();
            let (r, w) = tokio::io::split(conn);
            *r_guard = Some(r);
            drop(r_guard);
            *w_guard = Some(w);
        }
    }
}

pub(crate) const ERR_UPLOAD_SEQUENCE_GAP_MESSAGE: &str = "upload sequence gap";

fn err_upload_sequence_gap() -> anyhow::Error {
    anyhow!(ERR_UPLOAD_SEQUENCE_GAP_MESSAGE)
}

fn is_upload_sequence_gap(err: &anyhow::Error) -> bool {
    err.to_string() == ERR_UPLOAD_SEQUENCE_GAP_MESSAGE
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionDirection {
    Uplink,
    Downlink,
}

pub(crate) struct TunnelServer {
    pub(crate) mode: TunnelMode,
    pub(crate) path_root: String,
    pub(crate) pass_through_on_reject: bool,
    pub(crate) auth: Option<TunnelAuth>,

    pull_read_timeout: Duration,
    session_ttl: Duration,
    pub(crate) early_handshake: Option<TunnelServerEarlyHandshake>,

    sessions: Mutex<HashMap<String, Arc<TunnelSession>>>,
}

pub(crate) fn new_tunnel_server(opts: TunnelServerOptions) -> Arc<TunnelServer> {
    let mode = TunnelMode::normalize(&opts.mode);
    let path_root = normalize_path_root(&opts.path_root);
    let auth = TunnelAuth::new(&opts.auth_key, opts.auth_skew);
    let mut timeout = opts.pull_read_timeout;
    if timeout.is_zero() {
        timeout = Duration::from_secs(10);
    }
    let mut ttl = opts.session_ttl;
    if ttl.is_zero() {
        ttl = Duration::from_secs(120);
    }
    Arc::new(TunnelServer {
        mode,
        path_root,
        pass_through_on_reject: opts.pass_through_on_reject,
        auth,
        pull_read_timeout: timeout,
        session_ttl: ttl,
        early_handshake: opts.early_handshake,
        sessions: Mutex::new(HashMap::new()),
    })
}

impl TunnelServer {
    /// Inspects `raw_conn`. If it is an HTTP tunnel request
    /// (stream/poll), it is handled here and:
    ///   - starts a tunnel and returns a conn that carries the raw Sudoku stream (stream or poll
    ///     session pipe)
    ///   - or reports the request as handled if it is a poll control request (push/pull) and no
    ///     Sudoku handshake should run on this TCP conn
    ///
    /// If it is not an HTTP tunnel request (or server mode is legacy), it returns
    /// `HandlePassThrough` with a conn that replays any pre-read bytes.
    pub(crate) async fn handle_conn(
        self: &Arc<Self>,
        mut raw_conn: Box<dyn Stream>,
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        let deadline = Instant::now() + TUNNEL_HEADER_READ_TIMEOUT;
        let mut first = [0u8; 4];
        match read_full_best_effort(&mut raw_conn, &mut first, deadline).await {
            Ok(()) => {}
            Err((n, err)) => {
                if n > 0 {
                    let pre = first.get(..n).unwrap_or_default().to_vec();
                    return Ok((HandleResult::PassThrough, Some(new_pre_buffered_conn(raw_conn, pre))));
                }
                return Err(err);
            }
        }
        let pc = pre_buffered_conn(raw_conn, first.to_vec(), false);
        let mut br = BufReader::new(pc);

        if !looks_like_http_request_start(&first) {
            let conn: Box<dyn Stream> = into_boxed_conn(br.into_inner());
            return Ok((HandleResult::PassThrough, Some(conn)));
        }

        let header_result = read_http_header(&mut br, deadline).await;
        let raw_conn = into_boxed_conn(br.into_inner());
        let (req, header_bytes, buffered) = match header_result {
            Ok(v) => v,
            Err(err) => {
                return Ok((
                    HandleResult::PassThrough,
                    Some(new_pre_buffered_conn(
                        raw_conn,
                        build_invalid_http_replay_prefix(&first, &err.header_bytes, &err.buffered),
                    )),
                ));
            }
        };

        let replay_prefix = build_http_replay_prefix(&header_bytes, &buffered);

        let tunnel_header = if looks_like_web_socket_upgrade(&req.headers) {
            Some(TunnelMode::Ws)
        } else {
            TunnelMode::from_header(req.headers.get("x-sudoku-tunnel").map_or("", String::as_str))
        };
        let Some(tunnel_header) = tunnel_header else {
            return Ok((HandleResult::PassThrough, Some(new_pre_buffered_conn(raw_conn, replay_prefix))));
        };

        if self.mode == TunnelMode::Legacy {
            return self.reject_or_404(raw_conn, replay_prefix).await;
        }

        match tunnel_header {
            TunnelMode::Stream => {
                if self.mode != TunnelMode::Stream && self.mode != TunnelMode::Auto {
                    return self.reject_or_404(raw_conn, replay_prefix).await;
                }
                self.handle_stream(raw_conn, &req, &header_bytes, &buffered).await
            }
            TunnelMode::Poll => {
                if self.mode != TunnelMode::Poll && self.mode != TunnelMode::Auto {
                    return self.reject_or_404(raw_conn, replay_prefix).await;
                }
                self.handle_poll(raw_conn, &req, &header_bytes, &buffered).await
            }
            TunnelMode::Ws => {
                if self.mode != TunnelMode::Ws && self.mode != TunnelMode::Auto {
                    return self.reject_or_404(raw_conn, replay_prefix).await;
                }
                self.handle_ws(raw_conn, &req, &header_bytes, &buffered).await
            }
            TunnelMode::Legacy | TunnelMode::Auto => self.reject_or_404(raw_conn, replay_prefix).await,
        }
    }

    async fn reject_or_404(
        &self,
        mut raw_conn: Box<dyn Stream>,
        prefix: Vec<u8>,
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        if self.pass_through_on_reject {
            return Ok((HandleResult::PassThrough, Some(new_rejected_pre_buffered_conn(raw_conn, prefix))));
        }
        let _ = write_simple_http_response(&mut raw_conn, 404, "not found").await;
        let _ = close_stream(&*raw_conn);
        Ok((HandleResult::Done, None))
    }
}

async fn read_full_best_effort(
    conn: &mut Box<dyn Stream>,
    buf: &mut [u8],
    deadline: Instant,
) -> std::result::Result<(), (usize, anyhow::Error)> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let (_, rest) = buf.split_at_mut(filled);
        match tokio::time::timeout_at(deadline, AsyncReadExt::read(conn, rest)).await {
            Ok(Ok(0)) => return Err((filled, anyhow!(io::Error::from(io::ErrorKind::UnexpectedEof)))),
            Ok(Ok(n)) => filled += n,
            Ok(Err(err)) => return Err((filled, err.into())),
            Err(_elapsed) => return Err((filled, anyhow!(io::Error::from(io::ErrorKind::TimedOut)))),
        }
    }
    Ok(())
}

fn build_http_replay_prefix(header_bytes: &[u8], buffered: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header_bytes.len() + buffered.len());
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(buffered);
    out
}

fn build_invalid_http_replay_prefix(first: &[u8], header_bytes: &[u8], buffered: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(first.len() + header_bytes.len() + buffered.len());
    if header_bytes.is_empty() || !header_bytes.starts_with(first) {
        out.extend_from_slice(first);
    }
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(buffered);
    out
}

pub(crate) struct HttpRequestHeader {
    pub(crate) method: String,
    /// Path + query.
    pub(crate) target: String,
    /// Lower-case keys.
    pub(crate) headers: HashMap<String, String>,
}

/// The HTTP-header read's error path also carries the bytes consumed so far and any
/// already-buffered bytes, since all four values are returned regardless of `err`.
struct ReadHeaderError {
    header_bytes: Vec<u8>,
    buffered: Vec<u8>,
}

const MAX_HEADER_BYTES: usize = 32 * 1024;

async fn read_line(
    r: &mut BufReader<PreBufferedConn>,
    consumed: &mut Vec<u8>,
    deadline: Instant,
) -> std::result::Result<Vec<u8>, anyhow::Error> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let mut line = Vec::new();
    let remaining = MAX_HEADER_BYTES.saturating_sub(consumed.len());
    let limit = remaining as u64 + 1;
    // Bound the individual `read_until`, not the whole header read, so a timeout cancels only
    // this future: `line` (owned by this call, not the cancelled future) keeps whatever partial
    // line it had already read, matching the line reader, which appends the partial line to
    // `consumed` before returning its error rather than discarding it.
    let result = tokio::time::timeout_at(deadline, (&mut *r).take(limit).read_until(b'\n', &mut line)).await;
    if !line.is_empty() {
        consumed.extend_from_slice(&line);
    }
    if consumed.len() > MAX_HEADER_BYTES {
        return Err(anyhow!("http header too large"));
    }
    match result {
        Err(_elapsed) => return Err(anyhow!(io::Error::from(io::ErrorKind::TimedOut))),
        Ok(Err(err)) => return Err(err.into()),
        Ok(Ok(_)) => {}
    }
    if !line.ends_with(b"\n") {
        return Err(anyhow!(io::Error::from(io::ErrorKind::UnexpectedEof)));
    }
    Ok(line)
}

async fn read_http_header(
    r: &mut BufReader<PreBufferedConn>,
    deadline: Instant,
) -> std::result::Result<(HttpRequestHeader, Vec<u8>, Vec<u8>), ReadHeaderError> {
    let mut consumed = Vec::new();

    let Ok(line) = read_line(r, &mut consumed, deadline).await else {
        return Err(ReadHeaderError { header_bytes: consumed.clone(), buffered: read_all_buffered(r) });
    };
    let line_str = String::from_utf8_lossy(&line);
    let line_str = line_str.trim_end_matches(['\r', '\n']);
    let mut parts = line_str.splitn(3, ' ');
    let (Some(method), Some(target), Some(_version)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(ReadHeaderError { header_bytes: consumed.clone(), buffered: read_all_buffered(r) });
    };
    let mut req = HttpRequestHeader { method: method.to_owned(), target: target.to_owned(), headers: HashMap::new() };

    loop {
        let Ok(line) = read_line(r, &mut consumed, deadline).await else {
            return Err(ReadHeaderError { header_bytes: consumed.clone(), buffered: read_all_buffered(r) });
        };
        let trimmed = String::from_utf8_lossy(&line);
        let trimmed = trimmed.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((k, v)) = trimmed.split_once(':') else {
            continue;
        };
        let k = k.trim().to_lowercase();
        let v = v.trim().to_owned();
        if k.is_empty() {
            continue;
        }
        req.headers.entry(k).or_insert(v);
    }

    let buffered = read_all_buffered(r);
    Ok((req, consumed, buffered))
}

fn read_all_buffered(r: &BufReader<PreBufferedConn>) -> Vec<u8> {
    r.buffer().to_vec()
}

#[allow(
    dead_code,
    reason = "recorded/rejected back is_http_mask_rejected/get_buffered_and_recorded; unreachable because listener/sudoku/server.rs's is_http_mask_rejected can never recover the concrete PreBufferedConn behind a Box<dyn Stream>, per that file's module-level DEVIATION note"
)]
pub(crate) struct PreBufferedConn {
    conn: Box<dyn Stream>,
    buf: Vec<u8>,
    recorded: Vec<u8>,
    rejected: bool,
}

#[allow(
    dead_code,
    reason = "same DEVIATION as the struct: is_http_mask_rejected/get_buffered_and_recorded are unreachable through the Box<dyn Stream> erasure at listener/sudoku/server.rs"
)]
impl PreBufferedConn {
    pub(crate) const fn is_http_mask_rejected(&self) -> bool {
        self.rejected
    }

    pub(crate) fn get_buffered_and_recorded(&self) -> Vec<u8> {
        self.recorded.clone()
    }
}

fn pre_buffered_conn(conn: Box<dyn Stream>, pre: Vec<u8>, rejected: bool) -> PreBufferedConn {
    PreBufferedConn { conn, recorded: pre.clone(), buf: pre, rejected }
}

pub(crate) fn new_pre_buffered_conn(conn: Box<dyn Stream>, pre: Vec<u8>) -> Box<dyn Stream> {
    Box::new(pre_buffered_conn(conn, pre, false))
}

pub(crate) fn new_rejected_pre_buffered_conn(conn: Box<dyn Stream>, pre: Vec<u8>) -> Box<dyn Stream> {
    Box::new(pre_buffered_conn(conn, pre, true))
}

fn into_boxed_conn(conn: PreBufferedConn) -> Box<dyn Stream> {
    Box::new(conn)
}

impl AsyncRead for PreBufferedConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.buf.is_empty() {
            let n = this.buf.len().min(buf.remaining());
            let (head, _) = this.buf.split_at(n);
            buf.put_slice(head);
            this.buf.drain(..n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(this.conn.as_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for PreBufferedConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(self.get_mut().conn.as_mut()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().conn.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().conn.as_mut()).poll_shutdown(cx)
    }
}

impl Stream for PreBufferedConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        try_close_read(self.conn.as_ref())
    }

    fn shutdown_write(&self) -> io::Result<()> {
        try_close_write(self.conn.as_ref())
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.old_conn()
    }
}

/// The body conn: the "Stream-One" full-duplex mode's connection. Its reader decodes the request
/// body (raw/content-length/chunked) and its writer HTTP/1.1-chunk-encodes every `Write` and
/// flushes immediately, matching the standard chunked reader/writer pair.
///
/// Deviation: the full close and the write half-close run their multi-step chunk-terminator plus
/// underlying close sequence synchronously and return its error. `Conn::close`/`close_write`
/// are sync `&self` methods in this crate, so the equivalent sequence is dispatched onto a
/// background task (best-effort, matching the error-swallowing done at every
/// other call site of this conn) instead of being awaited by the caller.
struct BodyConn {
    local_addr: std::net::SocketAddr,
    remote_addr: std::net::SocketAddr,
    body_rx: tokio::sync::mpsc::Receiver<io::Result<bytes::Bytes>>,
    write_tx: tokio::sync::mpsc::Sender<BodyWriteItem>,
    write_close_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    close_all: CancellationToken,
    flush: Mutex<Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>>,
}

/// One item on `BodyConn`'s write queue: a chunk of payload, or a barrier that the background
/// writer task acknowledges once every chunk queued before it has been written and flushed to
/// `write_half` — the background task already flushes after every chunk (see `new_body_conn`),
/// so acknowledging a barrier needs no extra I/O, only FIFO ordering against the chunks ahead of
/// it. This is what makes `BodyConn::poll_flush` (below) an honest flush instead of a no-op that
/// returns before a queued write has actually reached the wire.
enum BodyWriteItem {
    Chunk(bytes::Bytes),
    Flush(tokio::sync::oneshot::Sender<()>),
}

enum BodyLength {
    Raw,
    Fixed(u64),
    Chunked,
}

fn body_length(headers: &HashMap<String, String>) -> Result<BodyLength> {
    let te = headers.get("transfer-encoding").map(|v| v.to_lowercase()).unwrap_or_default();
    if te.contains("chunked") {
        return Ok(BodyLength::Chunked);
    }
    if let Some(cl) = headers.get("content-length") {
        let n: i64 = cl.trim().parse().map_err(|_| anyhow!("invalid content-length"))?;
        if n < 0 {
            return Err(anyhow!("invalid content-length"));
        }
        return Ok(BodyLength::Fixed(n.cast_unsigned()));
    }
    Ok(BodyLength::Raw)
}

/// Builds a new request-body reader: spawns the decode task and returns the receiving half as a plain
/// stream of already-decoded body chunks (`None` batching not required by any caller: every
/// caller either reads the whole body up to a cap, or feeds it straight into [`BodyConn`]).
fn new_request_body_reader(
    mut read_half: ReadHalf<Box<dyn Stream>>,
    headers: &HashMap<String, String>,
) -> Result<tokio::sync::mpsc::Receiver<io::Result<bytes::Bytes>>> {
    let length = body_length(headers)?;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        match length {
            BodyLength::Raw => {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    match read_half.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let (chunk, _) = buf.split_at(n);
                            if tx.send(Ok(bytes::Bytes::copy_from_slice(chunk))).await.is_err() {
                                return;
                            }
                        }
                        Err(err) => {
                            let _ = tx.send(Err(err)).await;
                            return;
                        }
                    }
                }
            }
            BodyLength::Fixed(mut remaining) => {
                let mut buf = vec![0u8; 32 * 1024];
                while remaining > 0 {
                    let cap = buf.len().min(usize::try_from(remaining).unwrap_or(usize::MAX));
                    let (dst, _) = buf.split_at_mut(cap);
                    match read_half.read(dst).await {
                        Ok(0) => {
                            let _ = tx.send(Err(io::Error::from(io::ErrorKind::UnexpectedEof))).await;
                            return;
                        }
                        Ok(n) => {
                            remaining -= n as u64;
                            let (chunk, _) = buf.split_at(n);
                            if tx.send(Ok(bytes::Bytes::copy_from_slice(chunk))).await.is_err() {
                                return;
                            }
                        }
                        Err(err) => {
                            let _ = tx.send(Err(err)).await;
                            return;
                        }
                    }
                }
            }
            BodyLength::Chunked => loop {
                match read_chunked_frame(&mut read_half, &tx).await {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(err) => {
                        let _ = tx.send(Err(err)).await;
                        return;
                    }
                }
            },
        }
    });
    Ok(rx)
}

const MAX_CHUNK_SIZE_LINE_BYTES: usize = 4096;
const CHUNK_READ_BUF_SIZE: usize = 32 * 1024;

/// Reads one HTTP/1.1 chunked-encoding frame, streaming its data to `tx` in pieces
/// of at most `CHUNK_READ_BUF_SIZE` bytes rather than allocating the whole peer-declared chunk
/// length up front (a standard chunked reader copies into the caller's buffer the same
/// way and never allocates from the declared length). Returns `Ok(false)` once the terminating
/// `0\r\n` chunk has been consumed.
async fn read_chunked_frame(
    r: &mut ReadHalf<Box<dyn Stream>>,
    tx: &tokio::sync::mpsc::Sender<io::Result<bytes::Bytes>>,
) -> io::Result<bool> {
    let mut size_line = Vec::new();
    let mut byte = [0u8; 1];
    let mut raw_len = 0usize;
    loop {
        r.read_exact(&mut byte).await?;
        raw_len += 1;
        if raw_len > MAX_CHUNK_SIZE_LINE_BYTES + 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "header line too long"));
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            size_line.push(byte[0]);
        }
    }
    let size_str = String::from_utf8_lossy(&size_line);
    let size_str = size_str.split(';').next().unwrap_or("").trim();
    let mut remaining = usize::from_str_radix(size_str, 16)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed chunked encoding"))?;
    if remaining == 0 {
        let mut trailer = [0u8; 2];
        let _ = r.read_exact(&mut trailer).await;
        return Ok(false);
    }
    let mut buf = vec![0u8; CHUNK_READ_BUF_SIZE.min(remaining)];
    while remaining > 0 {
        let cap = buf.len().min(remaining);
        let (dst, _) = buf.split_at_mut(cap);
        r.read_exact(dst).await?;
        remaining -= cap;
        let (chunk, _) = buf.split_at(cap);
        if tx.send(Ok(bytes::Bytes::copy_from_slice(chunk))).await.is_err() {
            return Ok(false);
        }
    }
    let mut crlf = [0u8; 2];
    r.read_exact(&mut crlf).await?;
    if &crlf != b"\r\n" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed chunked encoding"));
    }
    Ok(true)
}

/// A full write framed as one HTTP/1.1 chunk (hex size + CRLF + data + CRLF).
async fn write_chunk(w: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<()> {
    let header = format!("{:x}\r\n", data.len());
    write_full(w, header.as_bytes()).await?;
    write_full(w, data).await?;
    write_full(w, b"\r\n").await?;
    Ok(())
}

/// Chunked writer close: writes the terminating `0\r\n` (no final CRLF; the
/// caller writes that separately).
async fn write_chunk_end(w: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
    write_full(w, b"0\r\n").await.map_err(Into::into)
}

fn new_body_conn(conn: Box<dyn Stream>, headers: &HashMap<String, String>) -> Result<Box<dyn Stream>> {
    let local_addr = conn.local_addr()?;
    let remote_addr = conn.peer_addr()?;
    let (read_half, mut write_half) = tokio::io::split(conn);
    let body_rx = new_request_body_reader(read_half, headers)?;

    let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<BodyWriteItem>(64);
    let (write_close_tx, write_close_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::pin!(write_close_rx);
        loop {
            // NOT cancel-safe: a drop skips the chunked-encoding trailer and the shutdown that the
            // close arm writes; the spawned task is never aborted.
            tokio::select! {
                biased;
                _ = &mut write_close_rx => {
                    let _ = write_chunk_end(&mut write_half).await;
                    let _ = write_full(&mut write_half, b"\r\n").await;
                    let _ = write_half.flush().await;
                    let _ = write_half.shutdown().await;
                    return;
                }
                item = write_rx.recv() => {
                    match item {
                        None => return,
                        Some(BodyWriteItem::Flush(ack)) => {
                            let _ = ack.send(());
                        }
                        Some(BodyWriteItem::Chunk(chunk)) => {
                            if write_chunk(&mut write_half, &chunk).await.is_err() {
                                return;
                            }
                            if write_half.flush().await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    });

    Ok(Box::new(BodyConn {
        local_addr,
        remote_addr,
        body_rx,
        write_tx,
        write_close_tx: Mutex::new(Some(write_close_tx)),
        close_all: CancellationToken::new(),
        flush: Mutex::new(None),
    }))
}

impl AsyncRead for BodyConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().body_rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let n = chunk.len().min(buf.remaining());
                let (head, _) = chunk.split_at(n);
                buf.put_slice(head);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(err)),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for BodyConn {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.write_tx.try_send(BodyWriteItem::Chunk(bytes::Bytes::copy_from_slice(buf))) {
            Ok(()) => {
                // A later chunk queued behind a barrier already stored in `self.flush` would let
                // the next poll_flush complete on that stale barrier before this chunk is
                // written. Drop it so the next flush queues a fresh barrier behind this chunk.
                *this.flush.lock() = None;
                Poll::Ready(Ok(buf.len()))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Poll::Pending,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
        }
    }

    /// Waits for the background writer task (`new_body_conn`) to have written and flushed every
    /// chunk queued before this call, instead of the previous bare `Poll::Ready(Ok(()))`, which
    /// returned before a queued write had necessarily reached `write_half` at all.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut flush = this.flush.lock();
        let write_tx = this.write_tx.clone();
        let future = flush.get_or_insert_with(|| {
            Box::pin(async move {
                let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
                if write_tx.send(BodyWriteItem::Flush(ack_tx)).await.is_err() {
                    return Ok(());
                }
                let _ = ack_rx.await;
                Ok(())
            })
        });
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                *flush = None;
                drop(flush);
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for BodyConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(self.local_addr)
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(self.remote_addr)
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.close_all.cancel();
        Ok(())
    }

    fn shutdown_write(&self) -> io::Result<()> {
        let write_close_tx = self.write_close_tx.lock().take();
        if let Some(tx) = write_close_tx {
            let _ = tx.send(());
        }
        Ok(())
    }
}

impl TunnelServer {
    pub(crate) async fn reject_or_reply(
        &self,
        mut raw_conn: Box<dyn Stream>,
        header_bytes: &[u8],
        buffered: &[u8],
        code: u16,
        body: &str,
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        if self.pass_through_on_reject {
            let prefix = build_http_replay_prefix(header_bytes, buffered);
            return Ok((HandleResult::PassThrough, Some(new_rejected_pre_buffered_conn(raw_conn, prefix))));
        }
        let _ = write_simple_http_response(&mut raw_conn, code, body).await;
        let _ = close_stream(&*raw_conn);
        Ok((HandleResult::Done, None))
    }

    async fn handle_stream(
        self: &Arc<Self>,
        mut raw_conn: Box<dyn Stream>,
        req: &HttpRequestHeader,
        header_bytes: &[u8],
        buffered: &[u8],
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        let Ok(u) = Url::parse(&format!("http://placeholder{}", ensure_leading_slash(&req.target))) else {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
        };

        let (path, ok) = strip_path_root(&self.path_root, u.path());
        if !ok || !is_allowed_base_path(&path) {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 404, "not found").await;
        }
        let query: HashMap<String, String> = u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        let token = query.get("token").cloned().unwrap_or_default();
        let close_flag = query.get("close").map(String::as_str) == Some("1");
        let fin_flag = query.get("fin").map(String::as_str) == Some("1");

        match req.method.to_uppercase().as_str() {
            "GET" => {
                if token.is_empty() && path == "/session" {
                    let Ok(early_payload) = super::tunnel_dial::parse_early_data_query(&u) else {
                        return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
                    };
                    return self.session_authorize(raw_conn, header_bytes, buffered, &early_payload).await;
                }
                if !token.is_empty() && path == "/stream" {
                    if self.pass_through_on_reject && !self.session_has(&token) {
                        return self.reject_or_reply(raw_conn, header_bytes, buffered, 404, "not found").await;
                    }
                    return self.stream_pull(raw_conn, &token).await;
                }
                self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await
            }
            "POST" => {
                if !token.is_empty() && path == "/api/v1/upload" {
                    if close_flag {
                        self.session_close(&token).await;
                        let _ = write_simple_http_response(&mut raw_conn, 200, "").await;
                        let _ = close_stream(&*raw_conn);
                        return Ok((HandleResult::Done, None));
                    }
                    if fin_flag {
                        self.session_close_write(&token).await;
                        let _ = write_simple_http_response(&mut raw_conn, 200, "").await;
                        let _ = close_stream(&*raw_conn);
                        return Ok((HandleResult::Done, None));
                    }
                    if self.pass_through_on_reject && !self.session_has(&token) {
                        return self.reject_or_reply(raw_conn, header_bytes, buffered, 404, "not found").await;
                    }
                    let Ok(sequence) = parse_upload_sequence(&u) else {
                        return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
                    };
                    let pre = new_pre_buffered_conn(raw_conn, buffered.to_vec());
                    let (read_half, mut write_half) = tokio::io::split(pre);
                    let Ok(body_rx) = new_request_body_reader(read_half, &req.headers) else {
                        let _ = write_simple_http_response(&mut write_half, 400, "bad request").await;
                        return Ok((HandleResult::Done, None));
                    };
                    let Ok(payload) = drain_body(body_rx, (1 << 20) + 1).await else {
                        let _ = write_simple_http_response(&mut write_half, 400, "bad request").await;
                        return Ok((HandleResult::Done, None));
                    };
                    return self.stream_push_from_payload(write_half, &token, sequence, payload).await;
                }

                if write_tunnel_response_header(&mut raw_conn).await.is_err() {
                    let _ = close_stream(&*raw_conn);
                    return Ok((HandleResult::Done, None));
                }

                let stream = match new_body_conn(new_pre_buffered_conn(raw_conn, buffered.to_vec()), &req.headers) {
                    Ok(stream) => stream,
                    Err(err) => return Err(err),
                };
                Ok((HandleResult::StartTunnel(None), Some(stream)))
            }
            _ => self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await,
        }
    }

    async fn handle_poll(
        self: &Arc<Self>,
        mut raw_conn: Box<dyn Stream>,
        req: &HttpRequestHeader,
        header_bytes: &[u8],
        buffered: &[u8],
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        let Ok(u) = Url::parse(&format!("http://placeholder{}", ensure_leading_slash(&req.target))) else {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
        };

        let (path, ok) = strip_path_root(&self.path_root, u.path());
        if !ok || !is_allowed_base_path(&path) {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 404, "not found").await;
        }
        let query: HashMap<String, String> = u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        let token = query.get("token").cloned().unwrap_or_default();
        let close_flag = query.get("close").map(String::as_str) == Some("1");
        let fin_flag = query.get("fin").map(String::as_str) == Some("1");

        match req.method.to_uppercase().as_str() {
            "GET" => {
                if token.is_empty() && path == "/session" {
                    let Ok(early_payload) = super::tunnel_dial::parse_early_data_query(&u) else {
                        return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
                    };
                    return self.session_authorize(raw_conn, header_bytes, buffered, &early_payload).await;
                }
                if path == "/stream" {
                    if self.pass_through_on_reject && !self.session_has(&token) {
                        return self.reject_or_reply(raw_conn, header_bytes, buffered, 404, "not found").await;
                    }
                    return self.poll_pull(raw_conn, &token).await;
                }
                self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await
            }
            "POST" => {
                if path != "/api/v1/upload" {
                    return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
                }
                if token.is_empty() {
                    return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "missing token").await;
                }
                if close_flag {
                    self.session_close(&token).await;
                    let _ = write_simple_http_response(&mut raw_conn, 200, "").await;
                    let _ = close_stream(&*raw_conn);
                    return Ok((HandleResult::Done, None));
                }
                if fin_flag {
                    self.session_close_write(&token).await;
                    let _ = write_simple_http_response(&mut raw_conn, 200, "").await;
                    let _ = close_stream(&*raw_conn);
                    return Ok((HandleResult::Done, None));
                }
                if self.pass_through_on_reject && !self.session_has(&token) {
                    return self.reject_or_reply(raw_conn, header_bytes, buffered, 404, "not found").await;
                }
                let Ok(sequence) = parse_upload_sequence(&u) else {
                    return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
                };
                let pre = new_pre_buffered_conn(raw_conn, buffered.to_vec());
                let (read_half, mut write_half) = tokio::io::split(pre);
                let Ok(body_rx) = new_request_body_reader(read_half, &req.headers) else {
                    let _ = write_simple_http_response(&mut write_half, 400, "bad request").await;
                    return Ok((HandleResult::Done, None));
                };
                let Ok(payload) = drain_body(body_rx, 1 << 20).await else {
                    let _ = write_simple_http_response(&mut write_half, 400, "bad request").await;
                    return Ok((HandleResult::Done, None));
                };
                self.poll_push_from_payload(write_half, &token, sequence, payload).await
            }
            _ => self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await,
        }
    }

    async fn session_authorize(
        self: &Arc<Self>,
        mut raw_conn: Box<dyn Stream>,
        header_bytes: &[u8],
        buffered: &[u8],
        early_payload: &[u8],
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        let token = new_session_token();

        let (c1, c2) = new_half_pipe();
        let mut response_payload: Vec<u8> = Vec::new();
        let user_hash: String;
        let mut early_user_hash: Option<String> = None;
        let mut out_conn: Box<dyn Stream> = c1;

        if !early_payload.is_empty() {
            if let Some(eh) = &self.early_handshake {
                match (eh.prepare)(early_payload) {
                    Err(_) => {
                        let _ = close_stream(&*c2);
                        return self.reject_or_reply(raw_conn, header_bytes, buffered, 404, "not found").await;
                    }
                    Ok(prepared) => {
                        response_payload = prepared.response_payload;
                        user_hash = prepared.user_hash;
                        if let Some(wrap) = prepared.wrap_conn {
                            match wrap(out_conn).await {
                                Err(_) => {
                                    let _ = close_stream(&*c2);
                                    let _ = write_simple_http_response(&mut raw_conn, 500, "internal error").await;
                                    let _ = close_stream(&*raw_conn);
                                    return Ok((HandleResult::Done, None));
                                }
                                Ok(wrapped) => {
                                    out_conn = wrapped;
                                    early_user_hash = Some(user_hash.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        let sess = TunnelSession::new(c2);
        if !self.insert_session(token.clone(), Arc::clone(&sess)) {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 503, "service unavailable").await;
        }

        {
            let server = Arc::clone(self);
            let reap_token = token.clone();
            tokio::spawn(async move { server.reap_later(reap_token).await });
        }

        if let Err(err) = write_token_http_response(&mut raw_conn, &token, &response_payload).await {
            self.session_close(&token).await;
            let _ = close_stream(&*raw_conn);
            return Err(err);
        }
        let _ = close_stream(&*raw_conn);
        Ok((HandleResult::StartTunnel(early_user_hash), Some(out_conn)))
    }

    // cancel-safe: each iteration re-reads the session table, so a drop only stops the reaper.
    async fn reap_later(self: Arc<Self>, token: String) {
        if self.session_ttl.is_zero() {
            return;
        }
        let ttl = self.session_ttl;
        let mut wait_for = ttl;
        loop {
            let Some(sess) = self.sessions.lock().get(&token).cloned() else { return };

            tokio::select! {
                () = tokio::time::sleep(wait_for) => {}
                () = sess.closed.cancelled() => return,
            }

            let Some(sess) = self.sessions.lock().get(&token).cloned() else { return };
            let idle = Instant::now().saturating_duration_since(*sess.last_active.lock());
            let active = sess.pull_mu.lock().is_some();

            let should_reap = {
                let mut sessions = self.sessions.lock();
                match sessions.get(&token) {
                    Some(current) if Arc::ptr_eq(current, &sess) => {}
                    _ => return,
                }
                if idle >= ttl && !active {
                    sessions.remove(&token);
                    true
                } else {
                    false
                }
            };
            if should_reap {
                let lease = sess.pull_mu.lock().clone();
                if let Some(lease) = lease {
                    lease.stop();
                }
                sess.close_conn().await;
                return;
            }

            let mut next = ttl.saturating_sub(idle);
            if active && next < ttl {
                next = ttl;
            }
            if next < Duration::from_millis(50) {
                next = Duration::from_millis(50);
            }
            wait_for = next;
        }
    }

    fn session_has(&self, token: &str) -> bool {
        self.sessions.lock().contains_key(token)
    }

    /// Reserves a slot in the session table: `false` means [`MAX_SESSIONS`] are already live, and
    /// the caller must refuse the request rather than grow the table.
    fn insert_session(&self, token: String, sess: Arc<TunnelSession>) -> bool {
        let mut sessions = self.sessions.lock();
        if sessions.len() >= MAX_SESSIONS {
            return false;
        }
        sessions.insert(token, sess);
        true
    }

    fn session_get(&self, token: &str) -> Option<Arc<TunnelSession>> {
        let sess = self.sessions.lock().get(token).cloned()?;
        *sess.last_active.lock() = Instant::now();
        Some(sess)
    }

    fn session_touch(&self, token: &str, sess: &Arc<TunnelSession>) -> bool {
        let sessions = self.sessions.lock();
        match sessions.get(token) {
            Some(current) if Arc::ptr_eq(current, sess) => {
                *sess.last_active.lock() = Instant::now();
                true
            }
            _ => false,
        }
    }

    async fn session_close(&self, token: &str) {
        let Some(sess) = self.sessions.lock().remove(token) else { return };
        sess.closed.cancel();
        let lease = sess.pull_mu.lock().clone();
        if let Some(lease) = lease {
            lease.stop();
        }
        sess.close_conn().await;
    }

    async fn session_close_write(&self, token: &str) {
        self.session_half_close(token, SessionDirection::Uplink).await;
    }

    async fn session_half_close(&self, token: &str, direction: SessionDirection) {
        let mut close_write = false;
        let Some(sess) = ({
            let mut sessions = self.sessions.lock();
            let Some(sess) = sessions.get(token).cloned() else { return };
            *sess.last_active.lock() = Instant::now();
            match direction {
                SessionDirection::Uplink => {
                    if !sess.uplink_closed.swap(true, Ordering::SeqCst) {
                        close_write = true;
                    }
                }
                SessionDirection::Downlink => {
                    sess.downlink_closed.store(true, Ordering::SeqCst);
                }
            }
            if sess.uplink_closed.load(Ordering::SeqCst) && sess.downlink_closed.load(Ordering::SeqCst) {
                sessions.remove(token);
                drop(sessions);
                sess.closed.cancel();
            }
            Some(sess)
        }) else {
            return;
        };

        if close_write {
            sess.close_write_conn().await;
        }

        let still_present = self.sessions.lock().contains_key(token);
        if !still_present {
            sess.close_conn().await;
        }
    }

    async fn write_session_upload(
        &self,
        token: &str,
        sess: &Arc<TunnelSession>,
        sequence: u64,
        payload: &[u8],
    ) -> Result<()> {
        let _upload_guard = sess.upload_mu.lock().await;

        if !self.session_touch(token, sess) {
            return Err(io::Error::from(io::ErrorKind::NotConnected).into());
        }

        let next = sess.next_upload_seq.load(Ordering::SeqCst);
        match sequence.cmp(&next) {
            std::cmp::Ordering::Less => return Ok(()),
            std::cmp::Ordering::Greater => return Err(err_upload_sequence_gap()),
            std::cmp::Ordering::Equal => {}
        }

        if !payload.is_empty() {
            let mut guard = sess.write_half.lock().await;
            let Some(w) = guard.as_mut() else {
                return Err(io::Error::from(io::ErrorKind::NotConnected).into());
            };
            let written = tokio::time::timeout(Duration::from_secs(30), write_full(w, payload)).await;
            drop(guard);
            match written {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => return Err(io::Error::from(io::ErrorKind::TimedOut).into()),
            }
        }
        sess.next_upload_seq.store(next + 1, Ordering::SeqCst);
        Ok(())
    }

    /// A push from a poll-mode payload, combined with the caller's body-read step.
    async fn poll_push_from_payload(
        &self,
        mut write_half: WriteHalf<Box<dyn Stream>>,
        token: &str,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        let Some(sess) = self.session_get(token) else {
            let _ = write_simple_http_response(&mut write_half, 403, "forbidden").await;
            return Ok((HandleResult::Done, None));
        };

        let mut decoded_payload = Vec::new();
        for line in payload.split(|&b| b == b'\n') {
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }
            let Ok(decoded) = BASE64_STANDARD.decode(line) else {
                let _ = write_simple_http_response(&mut write_half, 400, "bad request").await;
                return Ok((HandleResult::Done, None));
            };
            if decoded.is_empty() {
                continue;
            }
            decoded_payload.extend_from_slice(&decoded);
        }

        if let Err(err) = self.write_session_upload(token, &sess, sequence, &decoded_payload).await {
            if !is_upload_sequence_gap(&err) {
                self.session_close(token).await;
            }
            let _ = write_upload_result_response(&mut write_half, &err).await;
            return Ok((HandleResult::Done, None));
        }

        let _ = write_simple_http_response(&mut write_half, 200, "").await;
        Ok((HandleResult::Done, None))
    }

    /// A push from a stream-mode payload, combined with the caller's body-draining step.
    async fn stream_push_from_payload(
        &self,
        mut write_half: WriteHalf<Box<dyn Stream>>,
        token: &str,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        const MAX_UPLOAD_BYTES: usize = 1 << 20;
        let Some(sess) = self.session_get(token) else {
            let _ = write_simple_http_response(&mut write_half, 403, "forbidden").await;
            return Ok((HandleResult::Done, None));
        };
        if payload.len() > MAX_UPLOAD_BYTES {
            let _ = write_simple_http_response(&mut write_half, 413, "too large").await;
            return Ok((HandleResult::Done, None));
        }

        if let Err(err) = self.write_session_upload(token, &sess, sequence, &payload).await {
            if !is_upload_sequence_gap(&err) {
                self.session_close(token).await;
            }
            let _ = write_upload_result_response(&mut write_half, &err).await;
            return Ok((HandleResult::Done, None));
        }

        let _ = write_simple_http_response(&mut write_half, 200, "").await;
        Ok((HandleResult::Done, None))
    }

    async fn stream_pull(
        self: &Arc<Self>,
        raw_conn: Box<dyn Stream>,
        token: &str,
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        self.session_pull(raw_conn, token, false, PullEncoding::Raw).await
    }

    async fn poll_pull(
        self: &Arc<Self>,
        raw_conn: Box<dyn Stream>,
        token: &str,
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        self.session_pull(raw_conn, token, true, PullEncoding::Poll).await
    }

    /// A new pull forces the previous pull's
    /// blocked read to wake by closing its raw conn and resetting the session pipe's read
    /// deadline; this crate instead lets `session_pull_loop` race every blocking read/write
    /// against `lease.cancel`, so cancellation wakes it immediately without touching a conn the
    /// lease does not own.
    async fn begin_session_pull(&self, token: &str, sess: &Arc<TunnelSession>) -> Option<Arc<SessionPullLease>> {
        loop {
            if !self.session_touch(token, sess) {
                return None;
            }
            let previous = {
                let mut pull_mu = sess.pull_mu.lock();
                if pull_mu.is_none() {
                    let lease = SessionPullLease::new();
                    *pull_mu = Some(Arc::clone(&lease));
                    return Some(lease);
                }
                pull_mu.clone()
            };
            if let Some(previous) = previous {
                previous.stop();
                previous.done.cancelled().await;
            }
        }
    }

    fn end_session_pull(sess: &Arc<TunnelSession>, lease: &Arc<SessionPullLease>) {
        let mut pull_mu = sess.pull_mu.lock();
        if let Some(current) = pull_mu.as_ref() {
            if Arc::ptr_eq(current, lease) {
                *pull_mu = None;
            }
        }
        drop(pull_mu);
        lease.done.cancel();
    }

    fn pending_downlink(sess: &TunnelSession) -> Vec<u8> {
        sess.downlink_mu.lock().clone()
    }

    fn store_downlink(sess: &TunnelSession, payload: &[u8]) {
        let mut guard = sess.downlink_mu.lock();
        if guard.is_empty() {
            guard.extend_from_slice(payload);
        }
    }

    fn acknowledge_downlink(sess: &TunnelSession, n: usize) {
        if n == 0 {
            return;
        }
        let mut guard = sess.downlink_mu.lock();
        if n >= guard.len() {
            guard.clear();
        } else {
            guard.drain(0..n);
        }
    }

    async fn session_pull(
        self: &Arc<Self>,
        mut raw_conn: Box<dyn Stream>,
        token: &str,
        keepalive: bool,
        encoding: PullEncoding,
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        let Some(sess) = self.session_get(token) else {
            let _ = write_simple_http_response(&mut raw_conn, 403, "forbidden").await;
            let _ = close_stream(&*raw_conn);
            return Ok((HandleResult::Done, None));
        };

        let Some(lease) = self.begin_session_pull(token, &sess).await else {
            let _ = write_simple_http_response(&mut raw_conn, 403, "forbidden").await;
            let _ = close_stream(&*raw_conn);
            return Ok((HandleResult::Done, None));
        };

        let result = self.session_pull_loop(&mut raw_conn, token, &sess, &lease, keepalive, encoding).await;
        Self::end_session_pull(&sess, &lease);
        let _ = close_stream(&*raw_conn);
        result.map(|()| (HandleResult::Done, None))
    }

    /// The session-pull body, run once the HTTP response header and the pull
    /// lease are in place. Returns `Err` only for the initial header-write failure; every other
    /// exit is folded into `Ok(())`.
    async fn session_pull_loop(
        self: &Arc<Self>,
        raw_conn: &mut Box<dyn Stream>,
        token: &str,
        sess: &Arc<TunnelSession>,
        lease: &Arc<SessionPullLease>,
        keepalive: bool,
        encoding: PullEncoding,
    ) -> Result<()> {
        write_session_pull_response_header(raw_conn).await?;

        let mut bw = BufWriter::with_capacity(32 * 1024, raw_conn);
        let mut stream_eof = false;
        let mut buf = vec![0u8; 32 * 1024];

        loop {
            if lease.cancel.is_cancelled() {
                break;
            }

            let mut payload = Self::pending_downlink(sess);
            let read_outcome = if payload.is_empty() {
                let outcome = pull_read(sess, lease, self.pull_read_timeout, &mut buf).await;
                if let PullReadOutcome::Read(n) = outcome {
                    let (read_bytes, _) = buf.split_at(n);
                    Self::store_downlink(sess, read_bytes);
                    payload = Self::pending_downlink(sess);
                }
                Some(outcome)
            } else {
                None
            };

            if !payload.is_empty() {
                if !self.session_touch(token, sess) {
                    break;
                }
                let write_res =
                    tokio::time::timeout(self.pull_read_timeout, write_pull_payload(&mut bw, encoding, &payload)).await;
                match write_res {
                    Ok(Ok(())) => {}
                    _ => break,
                }
                if bw.flush().await.is_err() {
                    break;
                }
                Self::acknowledge_downlink(sess, payload.len());
            }

            match read_outcome {
                None | Some(PullReadOutcome::Read(_)) => {}
                Some(PullReadOutcome::Cancelled) => break,
                Some(PullReadOutcome::TimedOut) => {
                    if lease.cancel.is_cancelled() {
                        break;
                    }
                    if keepalive {
                        let _ = write_chunk(&mut bw, b"\n").await;
                        let _ = bw.flush().await;
                        let _ = self.session_touch(token, sess);
                    }
                    break;
                }
                Some(PullReadOutcome::Eof) => {
                    stream_eof = true;
                    self.session_half_close(token, SessionDirection::Downlink).await;
                    break;
                }
                Some(PullReadOutcome::Err) => {
                    self.session_close(token).await;
                    break;
                }
            }
        }

        let _ = write_chunk_end(&mut bw).await;
        if stream_eof {
            let _ = write_full(&mut bw, format!("{TUNNEL_STREAM_EOF_HEADER}: 1\r\n").as_bytes()).await;
        }
        let _ = write_full(&mut bw, b"\r\n").await;
        let _ = bw.flush().await;
        Ok(())
    }
}

/// A new session token. `rand::rng()` is a CSPRNG (ChaCha-based `ThreadRng`) and never fails,
/// unlike a portable OS random source.
fn new_session_token() -> String {
    let mut b = [0u8; 16];
    rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn parse_upload_sequence(u: &Url) -> Result<u64> {
    let raw = u
        .query_pairs()
        .find(|(k, _)| k == super::tunnel_dial::TUNNEL_UPLOAD_SEQUENCE_QUERY)
        .map(|(_, v)| v.trim().to_owned())
        .unwrap_or_default();
    if raw.is_empty() {
        return Err(anyhow!("missing upload sequence"));
    }
    let value: u64 = raw.parse().map_err(|_| anyhow!("invalid upload sequence"))?;
    if value == 0 {
        return Err(anyhow!("invalid upload sequence"));
    }
    Ok(value)
}

/// The response-writing half of an upload result; the caller (which may only hold a
/// `WriteHalf`, not a full `Box<dyn Stream>`) is responsible for closing afterward.
async fn write_upload_result_response(w: &mut (impl AsyncWrite + Unpin), err: &anyhow::Error) -> Result<()> {
    if is_upload_sequence_gap(err) {
        write_simple_http_response(w, 409, "sequence gap").await
    } else {
        write_simple_http_response(w, 410, "gone").await
    }
}

/// The session-pull's write-payload callback: `stream_pull` uses [`PullEncoding::Raw`] (one
/// chunk of raw bytes), `poll_pull` uses [`PullEncoding::Poll`] (base64 line + newline, two
/// chunks).
#[derive(Clone, Copy)]
enum PullEncoding {
    Raw,
    Poll,
}

// NOT cancel-safe: a dropped timeout between the chunk frame and its body leaves the peer's
// chunked encoding cut mid-frame.
async fn write_pull_payload(w: &mut (impl AsyncWrite + Unpin), encoding: PullEncoding, payload: &[u8]) -> Result<()> {
    match encoding {
        PullEncoding::Raw => write_chunk(w, payload).await,
        PullEncoding::Poll => {
            let line = BASE64_STANDARD.encode(payload);
            write_chunk(w, line.as_bytes()).await?;
            write_chunk(w, b"\n").await
        }
    }
}

/// Outcome of one bounded read from a [`TunnelSession`]'s uplink pipe inside the pull loop.
enum PullReadOutcome {
    Cancelled,
    TimedOut,
    Read(usize),
    Eof,
    Err,
}

/// `sess.conn.SetReadDeadline(time.Now().Add(s.pullReadTimeout)); sess.conn.Read(buf)`,
/// additionally raced against `lease.cancel` so a pull takeover interrupts a pending read
/// immediately instead of waiting out the read timeout.
// cancel-safe: a cancelled read leaves the half's buffered bytes intact, releases the read lock,
// and only interrupts the wait on the deadline/lease race.
async fn pull_read(
    sess: &TunnelSession,
    lease: &SessionPullLease,
    timeout: Duration,
    buf: &mut [u8],
) -> PullReadOutcome {
    let mut guard = sess.read_half.lock().await;
    let Some(r) = guard.as_mut() else { return PullReadOutcome::Eof };
    let outcome = tokio::select! {
        () = lease.cancel.cancelled() => PullReadOutcome::Cancelled,
        res = tokio::time::timeout(timeout, r.read(buf)) => match res {
            Ok(Ok(0)) => PullReadOutcome::Eof,
            Ok(Ok(n)) => PullReadOutcome::Read(n),
            // Some `Conn` implementations (e.g. `HalfPipeConn`) surface end-of-stream as
            // an `UnexpectedEof` error rather than `Ok(0)`; treat both the same way.
            Ok(Err(err)) if err.kind() == io::ErrorKind::UnexpectedEof => PullReadOutcome::Eof,
            Ok(Err(_)) => PullReadOutcome::Err,
            Err(_) => PullReadOutcome::TimedOut,
        },
    };
    drop(guard);
    outcome
}

fn ensure_leading_slash(target: &str) -> String {
    if target.starts_with('/') {
        target.to_owned()
    } else {
        format!("/{target}")
    }
}

fn is_allowed_base_path(path: &str) -> bool {
    PATHS.contains(&path)
}

// cancel-safe: receives from a channel, and a dropped `recv` leaves the message queued for the next call.
async fn drain_body(mut rx: tokio::sync::mpsc::Receiver<io::Result<bytes::Bytes>>, cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = rx.recv().await {
        let chunk = chunk?;
        out.extend_from_slice(&chunk);
        if out.len() > cap {
            out.truncate(cap);
            break;
        }
    }
    Ok(out)
}

async fn write_tunnel_response_header(w: &mut Box<dyn Stream>) -> Result<()> {
    write_full(
        w,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nCache-Control: no-store\r\nPragma: no-cache\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\n\r\n",
    )
    .await?;
    Ok(())
}

async fn write_session_pull_response_header(w: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
    let body = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nTrailer: {TUNNEL_STREAM_EOF_HEADER}\r\nCache-Control: no-store\r\nPragma: no-cache\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\n\r\n"
    );
    write_full(w, body.as_bytes()).await?;
    Ok(())
}

async fn write_simple_http_response(w: &mut (impl AsyncWrite + Unpin), code: u16, body: &str) -> Result<()> {
    let body = if body.is_empty() { status_text(code) } else { body };
    let body = body.trim_end_matches(['\r', '\n']);
    let text = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        status_text(code),
        body.len()
    );
    write_full(w, text.as_bytes()).await?;
    Ok(())
}

async fn write_token_http_response(w: &mut (impl AsyncWrite + Unpin), token: &str, early_payload: &[u8]) -> Result<()> {
    let token = token.trim_end_matches(['\r', '\n']);
    let mut body = format!("token={token}");
    if !early_payload.is_empty() {
        body.push_str("\ned=");
        body.push_str(&URL_SAFE_NO_PAD.encode(early_payload));
    }
    body.push_str("\ncap=");
    body.push_str(super::tunnel_dial::TUNNEL_UPLOAD_SEQUENCE_CAP);
    let text = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nPragma: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    write_full(w, text.as_bytes()).await?;
    Ok(())
}

const fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        413 => "Request Entity Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};

    use anyhow::anyhow;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader, DuplexStream};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, oneshot};

    use super::*;
    use crate::obfs::httpmask::tunnel_api::{dial_tunnel, TunnelDialOptions};
    use crate::obfs::httpmask::tunnel_conn_poll::dial_poll;
    use crate::obfs::httpmask::tunnel_conn_stream::dial_stream;
    use murmur_component::dialer::options::NetDialerFunc;

    struct PipeConn(DuplexStream);

    impl AsyncRead for PipeConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PipeConn {
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

    impl Stream for PipeConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }

        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    fn pipe_pair() -> (Box<dyn Stream>, Box<dyn Stream>) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (Box::new(PipeConn(a)), Box::new(PipeConn(b)))
    }

    fn no_op_options() -> TunnelServerOptions {
        TunnelServerOptions {
            mode: String::new(),
            path_root: String::new(),
            auth_key: String::new(),
            auth_skew: Duration::ZERO,
            pass_through_on_reject: false,
            pull_read_timeout: Duration::ZERO,
            session_ttl: Duration::ZERO,
            early_handshake: None,
        }
    }

    struct HttpResponseInfo {
        status: u16,
        trailers: HashMap<String, String>,
    }

    /// Reads a raw HTTP/1.1 response (chunked or `Content-Length`-framed, with an optional
    /// chunked trailer) without requiring a preceding
    /// request write on the same conn (session pull and push write unprompted responses).
    async fn read_http_response(conn: Box<dyn Stream>) -> HttpResponseInfo {
        let mut r = TokioBufReader::new(conn);

        let mut status_line = String::new();
        r.read_line(&mut status_line).await.expect("read status line");
        let status: u16 =
            status_line.split_whitespace().nth(1).expect("status code field").parse().expect("parse status code");

        let mut headers = HashMap::new();
        loop {
            let mut line = String::new();
            r.read_line(&mut line).await.expect("read header line");
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((k, v)) = trimmed.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
            }
        }

        let mut trailers = HashMap::new();
        if headers.get("transfer-encoding").map(String::as_str) == Some("chunked") {
            loop {
                let mut size_line = String::new();
                r.read_line(&mut size_line).await.expect("read chunk size");
                let size = usize::from_str_radix(size_line.trim(), 16).expect("parse chunk size");
                if size == 0 {
                    loop {
                        let mut trailer_line = String::new();
                        r.read_line(&mut trailer_line).await.expect("read trailer line");
                        let trimmed = trailer_line.trim_end_matches(['\r', '\n']);
                        if trimmed.is_empty() {
                            break;
                        }
                        if let Some((k, v)) = trimmed.split_once(':') {
                            trailers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
                        }
                    }
                    break;
                }
                let mut chunk = vec![0u8; size];
                r.read_exact(&mut chunk).await.expect("read chunk body");
                let mut crlf = [0u8; 2];
                r.read_exact(&mut crlf).await.expect("read chunk terminator");
            }
        } else if let Some(len) = headers.get("content-length").and_then(|v| v.parse::<usize>().ok()) {
            let mut body = vec![0u8; len];
            r.read_exact(&mut body).await.expect("read body");
        }

        HttpResponseInfo { status, trailers }
    }

    #[allow(
        clippy::type_complexity,
        reason = "the test helper hands back the bound address, the accepted-connection receiver and the shutdown closure as one tuple"
    )]
    async fn start_test_tunnel_server(
        server: Arc<TunnelServer>,
    ) -> (String, mpsc::UnboundedReceiver<Box<dyn Stream>>, Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>>>)
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let addr = listener.local_addr().expect("listener addr").to_string();
        let (tunnels_tx, tunnels_rx) = mpsc::unbounded_channel();

        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((raw, _)) = listener.accept().await else { return };
                let server = Arc::clone(&server);
                let tunnels_tx = tunnels_tx.clone();
                tokio::spawn(async move {
                    let raw: Box<dyn Stream> = Box::new(raw);
                    if let Ok((HandleResult::StartTunnel(_), Some(tunnel))) = server.handle_conn(raw).await {
                        let _ = tunnels_tx.send(tunnel);
                    }
                });
            }
        });

        let stop: Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>>> = Box::new(move || {
            Box::pin(async move {
                accept_task.abort();
                let _ = accept_task.await;
            })
        });

        (addr, tunnels_rx, stop)
    }

    fn direct_dialer() -> Arc<dyn murmur_component::dialer::options::NetDialer> {
        Arc::new(NetDialerFunc::new(move |_ctx, _network, address| {
            Box::pin(async move {
                let stream = TcpStream::connect(&address).await?;
                let stream: Box<dyn Stream> = Box::new(stream);
                Ok(stream)
            })
        }))
    }

    /// Reads to the end, treating end-of-stream as success. `HalfPipeConn` surfaces
    /// end-of-stream as an `UnexpectedEof` error rather than `Ok(0)` (see `pull_read`'s equivalent
    /// handling above); mirror the unwrapping here instead of using `AsyncReadExt::read_to_end`,
    /// which only recognizes `Ok(0)` as EOF.
    async fn read_all_tolerating_eof(mut r: impl AsyncRead + Unpin) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match r.read(&mut chunk).await {
                Ok(0) => return Ok(buf),
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(buf),
                Err(err) => return Err(err),
            }
        }
    }

    #[tokio::test]
    async fn tunnel_half_close_preserves_response() {
        for mode in ["stream", "poll", "auto"] {
            tokio::time::timeout(Duration::from_secs(15), async {
                let server = new_tunnel_server(TunnelServerOptions {
                    mode: "auto".to_owned(),
                    pull_read_timeout: Duration::from_millis(50),
                    session_ttl: Duration::from_secs(2),
                    ..no_op_options()
                });
                let (addr, mut tunnels, stop) = start_test_tunnel_server(server).await;

                let opts = TunnelDialOptions {
                    mode: mode.to_owned(),
                    dial_context: Some(direct_dialer()),
                    ..Default::default()
                };
                let ctx = CancellationToken::new();
                let conn = tokio::time::timeout(Duration::from_secs(5), async {
                    match mode {
                        "stream" => dial_stream(&ctx, &addr, &opts).await,
                        "poll" => dial_poll(&ctx, &addr, opts).await,
                        _ => dial_tunnel(&ctx, &addr, opts).await,
                    }
                })
                .await
                .expect("dial timeout")
                .expect("dial");
                let mut conn = conn;

                let mut tunnel = tokio::time::timeout(Duration::from_secs(5), tunnels.recv())
                    .await
                    .expect("tunnel timeout")
                    .expect("tunnel channel closed");

                let request = b"request body";
                let response = b"response after request EOF";
                let (server_done_tx, server_done_rx) = oneshot::channel();
                tokio::spawn(async move {
                    let result: Result<()> = async {
                        let got = read_all_tolerating_eof(&mut tunnel).await?;
                        if got != request {
                            return Err(anyhow!("unexpected request body: {got:?}"));
                        }
                        tunnel.write_all(response).await?;
                        tunnel.shutdown_write()?;
                        Ok(())
                    }
                    .await;
                    let _ = server_done_tx.send(result);
                });

                conn.write_all(request).await.expect("write request");
                conn.shutdown_write().expect("close write");
                let mut got = Vec::new();
                conn.read_to_end(&mut got).await.expect("read response");
                assert_eq!(got, response, "response mismatch for {mode}");
                server_done_rx.await.expect("server done recv").expect("server");

                stop().await;
            })
            .await
            .unwrap_or_else(|_| panic!("tunnel_half_close_preserves_response timed out for mode {mode}"));
        }
    }

    #[tokio::test]
    async fn tunnel_server_session_control_is_idempotent() {
        for mode in [TunnelMode::Stream, TunnelMode::Poll] {
            for control in ["fin", "close"] {
                let server = new_tunnel_server(TunnelServerOptions {
                    mode: "auto".to_owned(),
                    pass_through_on_reject: true,
                    ..no_op_options()
                });
                let (client_conn, server_conn) = pipe_pair();

                let handle_task = tokio::spawn(async move { server.handle_conn(server_conn).await });

                let request = format!(
                    "POST /api/v1/upload?token=already-closed&{control}=1 HTTP/1.1\r\n\
                     Host: example.com\r\n\
                     X-Sudoku-Tunnel: {mode}\r\n\
                     Content-Length: 0\r\n\r\n",
                    mode = mode.as_str(),
                );
                let mut client_conn = client_conn;
                client_conn.write_all(request.as_bytes()).await.expect("write control request");

                let resp = read_http_response(client_conn).await;
                let result = handle_task.await.expect("handle join").expect("handle control request");
                assert_eq!(result.0, HandleResult::Done, "control result for {control}/{mode:?}");
                assert_eq!(resp.status, 200, "control status for {control}/{mode:?}");
            }
        }
    }

    #[tokio::test]
    async fn tunnel_server_pull_takeover_serializes_readers() {
        let token = "pull-takeover";

        let (_app_conn, session_conn) = new_half_pipe();
        let server = new_tunnel_server(no_op_options());
        let sess = TunnelSession::new(session_conn);
        server.sessions.lock().insert(token.to_owned(), Arc::clone(&sess));

        let first = server.begin_session_pull(token, &sess).await;
        let first = first.expect("first pull did not acquire a lease");

        let server_task = Arc::clone(&server);
        let sess_task = Arc::clone(&sess);
        let (second_tx, mut second_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let lease = server_task.begin_session_pull(token, &sess_task).await;
            let _ = second_tx.send(lease);
        });

        tokio::select! {
            lease = second_rx.recv() => {
                assert!(lease.flatten().is_none(), "second pull acquired the lease before takeover completed");
            }
            () = tokio::time::sleep(Duration::from_millis(25)) => {}
        }

        TunnelServer::end_session_pull(&sess, &first);
        match tokio::time::timeout(Duration::from_secs(1), second_rx.recv()).await {
            Ok(Some(Some(second))) => {
                TunnelServer::end_session_pull(&sess, &second);
            }
            Ok(Some(None)) => panic!("second pull did not acquire the lease after takeover"),
            _ => panic!("second pull remained blocked after first lease ended"),
        }
    }

    #[tokio::test]
    async fn tunnel_server_downlink_half_close_keeps_uplink() {
        for mode in ["stream", "poll"] {
            tokio::time::timeout(Duration::from_secs(15), async {
                let token = "half-closed-session";

                let (app_conn, session_conn) = new_half_pipe();
                let server = new_tunnel_server(TunnelServerOptions {
                    pull_read_timeout: Duration::from_millis(20),
                    ..no_op_options()
                });
                let sess = TunnelSession::new(session_conn);
                server.sessions.lock().insert(token.to_owned(), Arc::clone(&sess));

                let mut app_conn = app_conn;
                let app_done = tokio::spawn(async move {
                    app_conn.write_all(b"response").await?;
                    app_conn.shutdown_write()?;
                    let tail = read_all_tolerating_eof(&mut app_conn).await?;
                    if tail != b"tail" {
                        return Err(anyhow!("tail = {tail:?}"));
                    }
                    Ok::<(), anyhow::Error>(())
                });

                let (client_conn, server_conn) = pipe_pair();
                let server_task = Arc::clone(&server);
                let pull_done = tokio::spawn(async move {
                    if mode == "stream" {
                        server_task.stream_pull(server_conn, token).await
                    } else {
                        server_task.poll_pull(server_conn, token).await
                    }
                });

                let resp = read_http_response(client_conn).await;
                pull_done.await.expect("pull join").expect("pull");
                assert_eq!(resp.status, 200, "status: got {} want 200", resp.status);
                assert_eq!(
                    resp.trailers.get(&TUNNEL_STREAM_EOF_HEADER.to_ascii_lowercase()).map(String::as_str),
                    Some("1"),
                    "EOF trailer"
                );
                assert!(server.session_has(token), "session removed after downlink EOF");

                let (client_conn, server_conn) = pipe_pair();
                let (_read_half, write_half) = tokio::io::split(server_conn);
                let push_body: Vec<u8> = if mode == "stream" {
                    b"tail".to_vec()
                } else {
                    let mut encoded = BASE64_STANDARD.encode(b"tail").into_bytes();
                    encoded.push(b'\n');
                    encoded
                };
                let server_task = Arc::clone(&server);
                let push_done = tokio::spawn(async move {
                    if mode == "stream" {
                        server_task.stream_push_from_payload(write_half, token, 1, push_body).await
                    } else {
                        server_task.poll_push_from_payload(write_half, token, 1, push_body).await
                    }
                });
                let resp = read_http_response(client_conn).await;
                push_done.await.expect("push join").expect("push");
                assert_eq!(resp.status, 200, "push status: got {} want 200", resp.status);

                server.session_close_write(token).await;
                app_done.await.expect("app join").expect("application");
                assert!(!server.session_has(token), "session retained after both directions closed");
            })
            .await
            .unwrap_or_else(|_| panic!("tunnel_server_downlink_half_close_keeps_uplink timed out for mode {mode}"));
        }
    }

    /// Regression test for the sibling of the flush defect: closing a TLS-backed `raw_conn`
    /// right after `write_simple_http_response` (the pattern every reject/session-control call
    /// site in this file uses) must not drop ciphertext `component::tls::utls::Conn`'s TLS layer
    /// is still holding. `rustls` caps its outgoing plaintext/ciphertext buffers at 64KiB
    /// (`DEFAULT_BUFFER_LIMIT`), so a single `poll_write` call for a body under that cap is
    /// accepted and reported as fully written in one shot regardless of how much of it actually
    /// reached the socket; shrinking the server's send buffer and the client's receive buffer to
    /// a couple KiB, with nobody reading yet, guarantees most of that body is still sitting in
    /// the TLS layer, unsent, the instant `write_simple_http_response` returns and `close()` is
    /// called — exactly the buffered-residue-at-close case this test exists to catch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn write_then_close_over_tls_delivers_full_response() {
        use murmur_component_ca::keypair::{new_random_tls_key_pair, new_tls_key_pair_loader, KeyPairType};
        use murmur_component_tls::utls::{client as tls_client, server as tls_server, Config as TlsConfig};

        fn shrink_send_buffer(stream: &TcpStream) {
            socket2::SockRef::from(stream).set_send_buffer_size(2 * 1024).expect("set send buffer size");
        }

        fn shrink_recv_buffer(stream: &TcpStream) {
            socket2::SockRef::from(stream).set_recv_buffer_size(2 * 1024).expect("set recv buffer size");
        }

        let (cert_pem, key_pem, _fp) = new_random_tls_key_pair(KeyPairType::P256).expect("key generation");
        let loader = new_tls_key_pair_loader(&cert_pem, &key_pem).expect("valid cert");
        let cert_for_server = loader().expect("cert loads");

        let server_tls_config = Arc::new(TlsConfig { certificates: vec![cert_for_server], ..Default::default() });
        let client_tls_config = Arc::new(TlsConfig { insecure_skip_verify: true, ..Default::default() });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");

        let client_raw = TcpStream::connect(addr).await.expect("client connect");
        shrink_recv_buffer(&client_raw);
        let (server_raw, _) = listener.accept().await.expect("accept");
        shrink_send_buffer(&server_raw);

        let mut client_conn = tls_client(Box::new(client_raw), client_tls_config);
        let server_conn = tls_server(Box::new(server_raw), server_tls_config);
        let (client_hs, server_hs) = tokio::join!(client_conn.handshake(), server_conn.handshake());
        client_hs.expect("client handshake");
        server_hs.expect("server handshake");

        // Comfortably under rustls's 64KiB `DEFAULT_BUFFER_LIMIT` (including the ~90-byte HTTP
        // header `write_simple_http_response` prepends), so the whole body is accepted by a
        // single `poll_write` call and `write_all` returns success without needing any read on
        // the peer side at all.
        let body = "x".repeat(50_000);

        let mut server_conn: Box<dyn Stream> = Box::new(server_conn);
        write_simple_http_response(&mut server_conn, 200, &body).await.expect("write response");

        let read_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match tokio::io::AsyncReadExt::read(&mut client_conn, &mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            buf
        });
        close_stream(&*server_conn).expect("close");

        let received = tokio::time::timeout(Duration::from_secs(30), read_task)
            .await
            .expect("read timed out")
            .expect("read task panicked");

        let header_end =
            received.windows(4).position(|w| w == b"\r\n\r\n").expect("no header terminator in received bytes") + 4;
        let received_body = &received[header_end..];
        assert_eq!(received_body.len(), body.len(), "response body truncated by close");
        assert_eq!(received_body, body.as_bytes(), "response body corrupted");
    }

    /// Regression test for the P0 finding: a chunk-size line declaring an implausible size
    /// (`0x7fffffffffffffff` bytes) used to be turned straight into `vec![0u8; size]`, which
    /// aborts the whole process on allocation failure. The fix streams data in bounded pieces and
    /// never allocates more than one piece at a time, so a short read (far fewer bytes than
    /// declared, then EOF) surfaces as a prompt `UnexpectedEof` instead of an allocator abort.
    #[tokio::test]
    async fn chunked_body_reports_short_read_without_preallocating_declared_size() {
        let (server, mut client) = pipe_pair();
        let (server_read, _server_write) = tokio::io::split(server);
        let mut headers = HashMap::new();
        headers.insert("transfer-encoding".to_owned(), "chunked".to_owned());
        let mut rx = new_request_body_reader(server_read, &headers).expect("body reader setup");

        client.write_all(b"7fffffffffffffff\r\nhello").await.expect("write chunk header + short body");
        drop(client);

        let result = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("must fail promptly on a short read rather than blocking on an unmet multi-exabyte declared size");
        let err =
            result.expect("channel closed before yielding the short-read error").expect_err("expected a read error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Regression test for the P0 finding: the chunk-size line was accumulated with no length
    /// cap. A peer that never sends a newline used to grow that buffer without bound.
    #[tokio::test]
    async fn chunked_frame_rejects_oversized_size_line() {
        let (server, mut client) = pipe_pair();
        let (server_read, _server_write) = tokio::io::split(server);
        let mut headers = HashMap::new();
        headers.insert("transfer-encoding".to_owned(), "chunked".to_owned());
        let mut rx = new_request_body_reader(server_read, &headers).expect("body reader setup");

        let garbage = vec![b'1'; MAX_CHUNK_SIZE_LINE_BYTES + 16];
        client.write_all(&garbage).await.expect("write oversized chunk-size line");
        drop(client);

        let result = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("must reject an oversized chunk-size line promptly");
        let err = result.expect("channel closed before yielding the error").expect_err("expected an error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Pins the `MAX_CHUNK_SIZE_LINE_BYTES + 1` boundary (item 7 of the P3 batch) against the
    /// standard chunked reader over a 32 KiB buffer, which accepts a 4095-byte
    /// chunk-size line (content plus the terminating CRLF fits inside one buffered read) and
    /// rejects one of 4096 bytes with `header line too long`.
    #[tokio::test]
    async fn chunked_frame_accepts_4095_byte_size_line() {
        let (server, mut client) = pipe_pair();
        let (server_read, _server_write) = tokio::io::split(server);
        let mut headers = HashMap::new();
        headers.insert("transfer-encoding".to_owned(), "chunked".to_owned());
        let mut rx = new_request_body_reader(server_read, &headers).expect("body reader setup");

        let mut size_line = b"1;".to_vec();
        size_line.resize(4095, b'a');
        client.write_all(&size_line).await.expect("write 4095-byte chunk-size line");
        client.write_all(b"\r\nZ\r\n0\r\n\r\n").await.expect("write chunk body and terminator");
        drop(client);

        let result = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("must accept a 4095-byte chunk-size line promptly");
        let chunk = result.expect("channel closed before yielding the chunk").expect("expected the chunk data");
        assert_eq!(&chunk[..], b"Z");
    }

    /// Companion to `chunked_frame_accepts_4095_byte_size_line`: one byte longer is rejected,
    /// matching the `header line too long` boundary.
    #[tokio::test]
    async fn chunked_frame_rejects_4096_byte_size_line() {
        let (server, mut client) = pipe_pair();
        let (server_read, _server_write) = tokio::io::split(server);
        let mut headers = HashMap::new();
        headers.insert("transfer-encoding".to_owned(), "chunked".to_owned());
        let mut rx = new_request_body_reader(server_read, &headers).expect("body reader setup");

        let mut size_line = b"1;".to_vec();
        size_line.resize(4096, b'a');
        client.write_all(&size_line).await.expect("write 4096-byte chunk-size line");
        client.write_all(b"\r\n").await.expect("write terminating CRLF");
        drop(client);

        let result = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("must reject a 4096-byte chunk-size line promptly");
        let err = result.expect("channel closed before yielding the error").expect_err("expected an error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "header line too long");
    }

    /// Regression test for the P1 finding: `read_line` used to call `read_until` with no cap,
    /// buffering an entire unterminated line before checking it against `MAX_HEADER_BYTES`. The
    /// fix bounds the read itself via `Take`, so a peer that never sends `\n` cannot make
    /// `consumed` grow past the configured cap.
    #[tokio::test]
    async fn read_line_rejects_oversized_header_line_without_unbounded_buffering() {
        let (server, mut client) = pipe_pair();
        let mut r = BufReader::new(pre_buffered_conn(server, Vec::new(), false));
        let mut consumed = Vec::new();

        tokio::spawn(async move {
            let garbage = vec![b'a'; MAX_HEADER_BYTES + 4096];
            let _ = client.write_all(&garbage).await;
            drop(client);
        });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            read_line(&mut r, &mut consumed, Instant::now() + Duration::from_secs(30)),
        )
        .await
        .expect("read_line must reject an oversized line promptly rather than buffering it all");
        let err = result.expect_err("expected an error for an oversized header line");
        assert_eq!(err.to_string(), "http header too large");
        assert!(consumed.len() <= MAX_HEADER_BYTES + 1, "read_line must not buffer far beyond the configured cap");
    }

    #[tokio::test]
    async fn body_conn_poll_flush_waits_for_chunk_queued_after_a_pending_flush() {
        let (local, mut peer) = tokio::io::duplex(6);
        let local: Box<dyn Stream> = Box::new(PipeConn(local));
        let mut conn = new_body_conn(local, &HashMap::new()).unwrap();

        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(Pin::new(&mut conn).poll_write(&mut cx, b"A"), Poll::Ready(Ok(1))));
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(
            matches!(Pin::new(&mut conn).poll_flush(&mut cx), Poll::Pending),
            "first flush poll must be pending on the async ack"
        );
        assert!(matches!(Pin::new(&mut conn).poll_write(&mut cx, b"B"), Poll::Ready(Ok(1))));

        let flushed = tokio::time::timeout(
            Duration::from_millis(200),
            std::future::poll_fn(|cx| Pin::new(&mut conn).poll_flush(cx)),
        )
        .await;
        assert!(flushed.is_err(), "stale flush returned Ok(Ok(())) while chunk B was unwritten");

        let mut frame_a = [0u8; 6];
        peer.read_exact(&mut frame_a).await.unwrap();
        assert_eq!(&frame_a, b"1\r\nA\r\n");

        tokio::time::timeout(Duration::from_millis(500), std::future::poll_fn(|cx| Pin::new(&mut conn).poll_flush(cx)))
            .await
            .expect("flush must complete once B has been written")
            .unwrap();

        let mut frame_b = [0u8; 6];
        peer.read_exact(&mut frame_b).await.unwrap();
        assert_eq!(&frame_b, b"1\r\nB\r\n");
    }

    /// Regression for `b3ca51ce`: moving the `TUNNEL_HEADER_READ_TIMEOUT` deadline into
    /// `read_full_best_effort` covered only the first 4-byte sniff, leaving `read_http_header`
    /// unbounded. A client that sends an HTTP-looking prefix and then stalls before completing
    /// the request line pinned `handle_conn` (and the socket) forever. Bound with a real timeout
    /// well past `TUNNEL_HEADER_READ_TIMEOUT` (15s) so a regression fails the test instead of
    /// hanging the suite.
    #[tokio::test]
    async fn header_read_is_bounded_by_tunnel_header_read_timeout() {
        let (mut client, server_conn) = tokio::io::duplex(4096);
        let server = new_tunnel_server(no_op_options());

        let handle = tokio::spawn(async move {
            let conn: Box<dyn Stream> = Box::new(PipeConn(server_conn));
            server.handle_conn(conn).await
        });

        client.write_all(b"GET /").await.expect("write sniff + partial request line");

        let result = tokio::time::timeout(TUNNEL_HEADER_READ_TIMEOUT + Duration::from_secs(10), handle)
            .await
            .expect("handle_conn must return once the header-read deadline elapses, not hang")
            .expect("handle_conn task must not panic");

        drop(client);
        let _ = result;
    }

    /// Regression for the review of `1f2ee5f7`'s P3 finding: bounding the header read by wrapping
    /// `read_http_header` in an outer `timeout_at` cancelled that future when the deadline fired,
    /// discarding every complete line and the partial in-progress line it had already consumed
    /// (both live in locals owned by the cancelled future's stack frame). The fallback replay
    /// then only had the original 4-byte sniff to replay, corrupting the stream for whatever
    /// legacy/fallback handler reads it next. Pushing the deadline into `read_line` itself (so
    /// only one `read_until` call is ever cancelled, and `line`/`consumed` are locals of the
    /// *caller*, not the cancelled future) keeps every byte the client already sent.
    #[tokio::test]
    async fn header_timeout_replay_prefix_keeps_every_consumed_byte() {
        let (mut client, server_conn) = tokio::io::duplex(4096);
        let server = new_tunnel_server(no_op_options());

        let handle = tokio::spawn(async move {
            let conn: Box<dyn Stream> = Box::new(PipeConn(server_conn));
            server.handle_conn(conn).await
        });

        // Two complete header lines, then a third with no trailing `\n`: the read stalls exactly
        // inside `read_line`'s in-progress call.
        client.write_all(b"GET /x HTTP/1.1\r\nHost: a\r\nX-Partial: y").await.expect("write partial header");

        let (result, mut conn) = tokio::time::timeout(TUNNEL_HEADER_READ_TIMEOUT + Duration::from_secs(10), handle)
            .await
            .expect("handle_conn must return once the header-read deadline elapses, not hang")
            .expect("handle_conn task must not panic")
            .expect("handle_conn must not error");
        assert!(matches!(result, HandleResult::PassThrough), "expected a pass-through result, got {result:?}");
        let mut conn = conn.take().expect("pass-through result must carry a replay conn");

        client.write_all(b"TAIL").await.expect("write trailing bytes after the timeout");
        drop(client);

        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut got))
            .await
            .expect("reading the replay conn must not hang")
            .expect("read replay conn");
        assert_eq!(
            got, b"GET /x HTTP/1.1\r\nHost: a\r\nX-Partial: yTAIL",
            "the replay must carry every byte the client sent, not just the original 4-byte sniff"
        );
    }

    #[tokio::test]
    async fn session_table_refuses_sessions_past_the_cap() {
        let server = new_tunnel_server(TunnelServerOptions {
            mode: "auto".to_owned(),
            session_ttl: Duration::from_secs(120),
            ..no_op_options()
        });

        let mut accepted = 0usize;
        let mut refused = 0usize;
        let mut tunnels = Vec::new();
        for _ in 0..(MAX_SESSIONS + 8) {
            let (mut client, server_conn) = tokio::io::duplex(4096);
            let server = Arc::clone(&server);
            let handle = tokio::spawn(async move {
                let conn: Box<dyn Stream> = Box::new(PipeConn(server_conn));
                server.handle_conn(conn).await
            });

            client
                .write_all(b"GET /session HTTP/1.1\r\nHost: example.com\r\nX-Sudoku-Tunnel: stream\r\n\r\n")
                .await
                .expect("write session request");

            let (result, tunnel) = tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect("session request must not hang")
                .expect("handle_conn task")
                .expect("handle_conn result");

            let mut status = [0u8; 12];
            client.read_exact(&mut status).await.expect("read session status line");
            let status = std::str::from_utf8(&status).expect("status line is ASCII");

            match result {
                HandleResult::StartTunnel(_) => {
                    assert_eq!(status, "HTTP/1.1 200", "admitted session status");
                    accepted += 1;
                    tunnels.push(tunnel.expect("an admitted session carries its tunnel conn"));
                }
                HandleResult::Done => {
                    assert_eq!(status, "HTTP/1.1 503", "refused session status");
                    refused += 1;
                }
                HandleResult::PassThrough => panic!("a /session request must not pass through"),
            }
        }

        assert_eq!(accepted, MAX_SESSIONS, "sessions admitted before the cap");
        assert_eq!(refused, 8, "requests refused once the table was full");
        assert_eq!(server.sessions.lock().len(), MAX_SESSIONS, "live sessions in the table");
    }
}
