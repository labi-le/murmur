use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::Stream;

use super::tunnel_api::{apply_tunnel_headers, TunnelDialOptions, TunnelMode};
use super::tunnel_conn_queue::QueuedConn;
use super::tunnel_dial::{
    dial_session, dial_session_with_client, send_session_control, session_preconnect_count, HttpClientTarget,
    SessionDialInfo, TunnelHttpTransport, TUNNEL_STREAM_EOF_HEADER,
};
use super::tunnel_retry::{
    close_idle_connections, is_dial_error, is_retryable_http_transport_error, is_retryable_status_code, next_backoff,
    wait_retry,
};

struct PollConnShared {
    queued_conn: Arc<QueuedConn>,
    ctx: CancellationToken,
    client: Arc<TunnelHttpTransport>,
    owner: Option<Arc<TunnelHttpTransport>>,
    push_url: String,
    pull_url: String,
    fin_url: String,
    close_url: String,
    header_host: String,
    upload_seq: AtomicU64,
}

impl PollConnShared {
    fn closed_err(&self) -> anyhow::Error {
        self.queued_conn.closed_err()
    }

    fn close_with_error(self: &Arc<Self>, err: Option<anyhow::Error>) {
        self.queued_conn.close_with_error(err);
        self.ctx.cancel();

        let this = Arc::clone(self);
        tokio::spawn(async move {
            best_effort_close_session_local(&this.client, &this.close_url, &this.header_host).await;
        });

        if let Some(owner) = &self.owner {
            owner.close();
        }
    }
}

async fn best_effort_close_session_local(client: &TunnelHttpTransport, close_url: &str, header_host: &str) {
    let _ = send_session_control(client, close_url, header_host, TunnelMode::Poll).await;
}

pub(crate) struct PollConn {
    shared: Arc<PollConnShared>,
}

impl AsyncRead for PollConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.shared.queued_conn.poll_read(cx, buf)
    }
}

impl AsyncWrite for PollConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.shared.queued_conn.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for PollConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(self.shared.queued_conn.local_addr())
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(self.shared.queued_conn.remote_addr())
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.shared.close_with_error(Some(anyhow::Error::from(io::Error::from(io::ErrorKind::BrokenPipe))));
        Ok(())
    }

    /// The queued conn's write shutdown, promoted onto the poll conn.
    fn shutdown_write(&self) -> io::Result<()> {
        let shared = Arc::clone(&self.shared);
        tokio::spawn(async move {
            let _ = shared.queued_conn.close_write().await;
        });
        Ok(())
    }
}

pub(crate) async fn dial_poll(
    ctx: &CancellationToken,
    server_address: &str,
    opts: TunnelDialOptions,
) -> anyhow::Result<Box<dyn Stream>> {
    let info = dial_session(ctx, server_address, &opts, TunnelMode::Poll).await?;
    new_poll_conn(info, opts).await
}

pub(crate) async fn dial_poll_with_client(
    ctx: &CancellationToken,
    client: Arc<TunnelHttpTransport>,
    target: HttpClientTarget,
    opts: TunnelDialOptions,
) -> anyhow::Result<Box<dyn Stream>> {
    let info =
        dial_session_with_client(ctx, client, target, TunnelMode::Poll, &opts, session_preconnect_count()).await?;
    new_poll_conn(info, opts).await
}

async fn new_poll_conn(info: SessionDialInfo, opts: TunnelDialOptions) -> anyhow::Result<Box<dyn Stream>> {
    let shared = Arc::new(PollConnShared {
        queued_conn: Arc::new(QueuedConn::new()),
        ctx: CancellationToken::new(),
        client: info.client,
        owner: info.owner,
        push_url: info.push_url,
        pull_url: info.pull_url,
        fin_url: info.fin_url,
        close_url: info.close_url,
        header_host: info.header_host,
        upload_seq: AtomicU64::new(0),
    });

    tokio::spawn(pull_loop(Arc::clone(&shared)));
    tokio::spawn(push_loop(Arc::clone(&shared)));

    let mut out_conn: Box<dyn Stream> = Box::new(PollConn { shared: Arc::clone(&shared) });

    if let Some(early_handshake) = &opts.early_handshake {
        if let Some(wrap_conn) = &early_handshake.wrap_conn {
            if early_handshake.ready.as_ref().is_none_or(|ready| ready()) {
                return match wrap_conn(out_conn).await {
                    Ok(wrapped) => Ok(wrapped),
                    Err(err) => {
                        shared.close_with_error(Some(anyhow::Error::from(io::Error::from(io::ErrorKind::BrokenPipe))));
                        Err(err)
                    }
                };
            }
        }
    }
    if let Some(upgrade) = &opts.upgrade {
        out_conn = match upgrade(out_conn).await {
            Ok(wrapped) => wrapped,
            Err(err) => {
                shared.close_with_error(Some(anyhow::Error::from(io::Error::from(io::ErrorKind::BrokenPipe))));
                drop(shared);
                return Err(err);
            }
        };
    }
    drop(shared);
    Ok(out_conn)
}

async fn pull_loop(shared: Arc<PollConnShared>) {
    const MIN_BACKOFF: Duration = Duration::from_millis(10);
    const MAX_BACKOFF: Duration = Duration::from_millis(250);

    let mut backoff = MIN_BACKOFF;
    loop {
        if shared.queued_conn.closed.is_cancelled() {
            return;
        }

        let req = match http::Request::builder()
            .method(http::Method::GET)
            .uri(&shared.pull_url)
            .body(Full::new(Bytes::new()))
        {
            Ok(mut req) => {
                apply_tunnel_headers(req.headers_mut(), &shared.header_host, TunnelMode::Poll);
                req
            }
            Err(err) => {
                shared.close_with_error(Some(err.into()));
                return;
            }
        };

        let resp = match shared.client.send(req).await {
            Ok(resp) => resp,
            Err(err) => {
                if is_dial_error(&err) || is_retryable_http_transport_error(&err) {
                    close_idle_connections(&shared.client).await;
                    let closed_err = closed_err_fn(&shared);
                    if wait_retry(&shared.queued_conn.closed, Some(&closed_err), backoff).await.is_err() {
                        return;
                    }
                    backoff = next_backoff(backoff, MIN_BACKOFF, MAX_BACKOFF);
                    continue;
                }
                shared.close_with_error(Some(anyhow::anyhow!("poll pull request failed: {err}")));
                return;
            }
        };

        if resp.status() != http::StatusCode::OK {
            if is_retryable_status_code(resp.status()) {
                discard_body_limited(resp.into_body(), 4 * 1024).await;
                close_idle_connections(&shared.client).await;
                let closed_err = closed_err_fn(&shared);
                if wait_retry(&shared.queued_conn.closed, Some(&closed_err), backoff).await.is_err() {
                    return;
                }
                backoff = next_backoff(backoff, MIN_BACKOFF, MAX_BACKOFF);
                continue;
            }
            let status = resp.status();
            shared.close_with_error(Some(anyhow::anyhow!("poll pull bad status: {status}")));
            return;
        }

        match stream_pull_lines(&shared, resp.into_body()).await {
            Ok(true) => {
                shared.queued_conn.mark_read_eof();
                return;
            }
            Ok(false) => {
                backoff = MIN_BACKOFF;
            }
            Err(PullStreamError::Closed) => return,
            Err(PullStreamError::Retryable) => {
                close_idle_connections(&shared.client).await;
                let closed_err = closed_err_fn(&shared);
                if wait_retry(&shared.queued_conn.closed, Some(&closed_err), backoff).await.is_err() {
                    return;
                }
                backoff = next_backoff(backoff, MIN_BACKOFF, MAX_BACKOFF);
            }
            Err(PullStreamError::Fatal(err)) => {
                shared.close_with_error(Some(anyhow::anyhow!("poll pull scan failed: {err}")));
                return;
            }
            Err(PullStreamError::DecodeFailed(err)) => {
                shared.close_with_error(Some(err));
                return;
            }
        }
    }
}

fn closed_err_fn(shared: &Arc<PollConnShared>) -> impl Fn() -> anyhow::Error + Send + Sync {
    let shared = Arc::clone(shared);
    move || shared.closed_err()
}

enum PullStreamError {
    Closed,
    Retryable,
    Fatal(anyhow::Error),
    DecodeFailed(anyhow::Error),
}

/// The line-scanner loop inside the pull loop: reads base64 lines from the streamed
/// response body and forwards decoded payloads to `rxc`. Returns `Ok(true)` when the
/// [`TUNNEL_STREAM_EOF_HEADER`] trailer marks the session closed, `Ok(false)` at a clean end of
/// stream (poll again).
async fn stream_pull_lines(
    shared: &Arc<PollConnShared>,
    mut body: hyper::body::Incoming,
) -> Result<bool, PullStreamError> {
    let mut pending: Vec<u8> = Vec::new();
    let mut trailer_eof = false;

    loop {
        let frame = match body.frame().await {
            Some(Ok(frame)) => frame,
            Some(Err(err)) => {
                let err: anyhow::Error = err.into();
                return if is_retryable_http_transport_error(&err) {
                    Err(PullStreamError::Retryable)
                } else {
                    Err(PullStreamError::Fatal(err))
                };
            }
            None => break,
        };

        if frame.is_trailers() {
            if let Ok(trailers) = frame.into_trailers() {
                if trailers.get(TUNNEL_STREAM_EOF_HEADER).and_then(|v| v.to_str().ok()) == Some("1") {
                    trailer_eof = true;
                }
            }
            continue;
        }
        let Ok(data) = frame.into_data() else { continue };
        pending.extend_from_slice(&data);

        while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=pos).collect();
            deliver_pull_line(shared, &line).await?;
        }
    }

    if !pending.is_empty() {
        deliver_pull_line(shared, &pending).await?;
        pending.clear();
    }

    Ok(trailer_eof)
}

/// the inner line-scan body: decodes one base64 line (trailing `\r\n`/`\n` stripped) and
/// forwards the payload to `rxc`.
// NOT cancel-safe: the decoded line is dropped if the hand-off send is cancelled.
async fn deliver_pull_line(shared: &Arc<PollConnShared>, raw_line: &[u8]) -> Result<(), PullStreamError> {
    let line = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() {
        return Ok(());
    }
    let payload = match STANDARD.decode(line) {
        Ok(payload) => payload,
        Err(err) => return Err(PullStreamError::DecodeFailed(anyhow::anyhow!("poll pull decode failed: {err}"))),
    };
    tokio::select! {
        res = shared.queued_conn.rxc_tx.send(Bytes::from(payload)) => {
            if res.is_err() {
                return Err(PullStreamError::Closed);
            }
        }
        () = shared.queued_conn.closed.cancelled() => return Err(PullStreamError::Closed),
    }
    Ok(())
}

// NOT cancel-safe: a drop leaves the batch buffer unflushed and skips `complete_write`, so a
// writer waiting on `write_done` never wakes.
async fn push_loop(shared: Arc<PollConnShared>) {
    const MAX_BATCH_BYTES: usize = 64 * 1024;
    const FLUSH_INTERVAL: Duration = Duration::from_millis(5);
    const MAX_LINE_RAW_BYTES: usize = 16 * 1024;
    const MIN_BACKOFF: Duration = Duration::from_millis(10);
    const MAX_BACKOFF: Duration = Duration::from_millis(250);

    let mut buf: Vec<u8> = Vec::new();
    let mut pending_raw = 0usize;

    let flush = |buf: &mut Vec<u8>, pending_raw: &mut usize| {
        let shared = Arc::clone(&shared);
        let payload = std::mem::take(buf);
        *pending_raw = 0;
        async move {
            if payload.is_empty() {
                return Ok(());
            }
            let sequence = shared.upload_seq.fetch_add(1, Ordering::SeqCst) + 1;
            let request_url = super::tunnel_dial::upload_url(&shared.push_url, sequence)?;

            let closed_err = closed_err_fn(&shared);
            super::tunnel_retry::retry_persistent(
                &shared.queued_conn.closed,
                Some(&closed_err),
                MIN_BACKOFF,
                MAX_BACKOFF,
                {
                    let shared = Arc::clone(&shared);
                    let request_url = request_url.clone();
                    let payload = payload.clone();
                    move || {
                        let shared = Arc::clone(&shared);
                        let request_url = request_url.clone();
                        let payload = payload.clone();
                        async move { push_attempt(&shared, &request_url, payload).await }
                    }
                },
            )
            .await?;

            Ok::<(), anyhow::Error>(())
        }
    };

    let mut sleep = Box::pin(tokio::time::sleep(FLUSH_INTERVAL));

    loop {
        let mut write_ch_rx = shared.queued_conn.write_ch_rx.lock().await;
        tokio::select! {
            maybe_chunk = write_ch_rx.recv() => {
                drop(write_ch_rx);
                let Some(chunk) = maybe_chunk else { continue };
                if chunk.is_empty() {
                    continue;
                }
                if let Err(err) = enqueue_chunk(&chunk, &mut buf, &mut pending_raw, MAX_LINE_RAW_BYTES, MAX_BATCH_BYTES, &flush).await {
                    fail_push(&shared, &format!("poll push flush failed: {err}"));
                    return;
                }
                if pending_raw >= MAX_BATCH_BYTES {
                    if let Err(err) = flush(&mut buf, &mut pending_raw).await {
                        fail_push(&shared, &format!("poll push flush failed: {err}"));
                        return;
                    }
                    sleep.as_mut().reset(tokio::time::Instant::now() + FLUSH_INTERVAL);
                }
            }
            () = &mut sleep => {
                drop(write_ch_rx);
                if let Err(err) = flush(&mut buf, &mut pending_raw).await {
                    fail_push(&shared, &format!("poll push flush failed: {err}"));
                    return;
                }
                sleep.as_mut().reset(tokio::time::Instant::now() + FLUSH_INTERVAL);
            }
            () = shared.queued_conn.write_closed.cancelled() => {
                drain_write_closed(
                    &shared,
                    write_ch_rx,
                    &mut buf,
                    &mut pending_raw,
                    MAX_LINE_RAW_BYTES,
                    MAX_BATCH_BYTES,
                    &flush,
                )
                .await;
                return;
            }
            () = shared.queued_conn.closed.cancelled() => {
                drop(write_ch_rx);
                shared.queued_conn.complete_write(Some(shared.closed_err()));
                return;
            }
        }
    }
}

async fn push_attempt(shared: &Arc<PollConnShared>, request_url: &str, payload: Vec<u8>) -> anyhow::Result<()> {
    let mut req =
        http::Request::builder().method(http::Method::POST).uri(request_url).body(Full::new(Bytes::from(payload)))?;
    apply_tunnel_headers(req.headers_mut(), &shared.header_host, TunnelMode::Poll);
    req.headers_mut().insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain"));

    let resp = match shared.client.send(req).await {
        Ok(resp) => resp,
        Err(err) => {
            close_idle_connections(&shared.client).await;
            return Err(err);
        }
    };
    let status = resp.status();
    discard_body_limited(resp.into_body(), 4 * 1024).await;
    if status != http::StatusCode::OK {
        let err = super::tunnel_retry::status_error(status, status.canonical_reason().unwrap_or(""));
        if is_retryable_http_transport_error(&err) {
            close_idle_connections(&shared.client).await;
        }
        return Err(err);
    }
    Ok(())
}

/// Drains the chunks still queued after a half-close, then finishes the write side.
async fn drain_write_closed<F, Fut>(
    shared: &Arc<PollConnShared>,
    mut write_ch_rx: tokio::sync::MutexGuard<'_, tokio::sync::mpsc::Receiver<Bytes>>,
    buf: &mut Vec<u8>,
    pending_raw: &mut usize,
    max_line_raw_bytes: usize,
    max_batch_bytes: usize,
    flush: &F,
) where
    F: Fn(&mut Vec<u8>, &mut usize) -> Fut + Sync,
    Fut: Future<Output = anyhow::Result<()>> + Send,
{
    loop {
        match write_ch_rx.try_recv() {
            Ok(chunk) if !chunk.is_empty() => {
                if let Err(err) =
                    enqueue_chunk(&chunk, buf, pending_raw, max_line_raw_bytes, max_batch_bytes, flush).await
                {
                    fail_push(shared, &format!("poll push flush failed: {err}"));
                    return;
                }
            }
            Ok(_) => {}
            Err(_) => {
                drop(write_ch_rx);
                if let Err(err) = flush(buf, pending_raw).await {
                    fail_push(shared, &format!("poll push flush failed: {err}"));
                    return;
                }
                if let Err(err) = best_effort_send_fin(shared).await {
                    fail_push(shared, &format!("poll FIN failed: {err}"));
                    return;
                }
                shared.queued_conn.complete_write(None);
                return;
            }
        }
    }
}

/// A failure records the error and closes the conn, together with the
/// deferred write completion: every push-loop failure both records the write error on
/// the queued conn and tears down the whole poll conn (pull side included).
fn fail_push(shared: &Arc<PollConnShared>, message: &str) {
    shared.queued_conn.complete_write(Some(anyhow::anyhow!("{message}")));
    shared.close_with_error(Some(anyhow::anyhow!("{message}")));
}

async fn best_effort_send_fin(shared: &Arc<PollConnShared>) -> anyhow::Result<()> {
    send_session_control(&shared.client, &shared.fin_url, &shared.header_host, TunnelMode::Poll).await
}

/// Reads at most `limit` bytes of
/// the response body and stops, instead of buffering the whole (possibly unbounded) body.
async fn discard_body_limited(mut body: hyper::body::Incoming, limit: usize) {
    let mut read = 0usize;
    while read < limit {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    read += data.len();
                }
            }
            _ => break,
        }
    }
}

async fn enqueue_chunk<F, Fut>(
    chunk: &[u8],
    buf: &mut Vec<u8>,
    pending_raw: &mut usize,
    max_line_raw_bytes: usize,
    max_batch_bytes: usize,
    flush: &F,
) -> anyhow::Result<()>
where
    F: Fn(&mut Vec<u8>, &mut usize) -> Fut + Sync,
    Fut: Future<Output = anyhow::Result<()>> + Send,
{
    let mut rest = chunk;
    while !rest.is_empty() {
        let split = rest.len().min(max_line_raw_bytes);
        let (piece, remainder) = rest.split_at(split);
        rest = remainder;

        let encoded = STANDARD.encode(piece);
        if *pending_raw + piece.len() > max_batch_bytes || buf.len() + encoded.len() + 1 > max_batch_bytes * 2 {
            flush(buf, pending_raw).await?;
        }
        buf.extend_from_slice(encoded.as_bytes());
        buf.push(b'\n');
        *pending_raw += piece.len();
    }
    Ok(())
}
