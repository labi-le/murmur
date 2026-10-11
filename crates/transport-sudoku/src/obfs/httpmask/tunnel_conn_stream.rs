//! "stream" mode uses split-stream to stay CDN-friendly by default.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::Stream;

use super::early_handshake::apply_early_handshake_or_upgrade;
use super::tunnel_api::{apply_tunnel_headers, TunnelDialOptions, TunnelMode};
use super::tunnel_conn_queue::QueuedConn;
use super::tunnel_dial::{
    best_effort_close_session, dial_session, dial_session_with_client, session_preconnect_count, upload_url,
    HttpClientTarget, SessionDialInfo, TunnelHttpTransport, TUNNEL_STREAM_EOF_HEADER,
};
use super::tunnel_retry::{
    close_idle_connections, is_retryable_http_transport_error, is_retryable_status_code, next_backoff, status_error,
};

pub(crate) async fn dial_stream(
    ctx: &CancellationToken,
    server_address: &str,
    opts: &TunnelDialOptions,
) -> Result<Box<dyn Stream>> {
    dial_stream_split(ctx, server_address, opts).await
}

struct StreamSplitConnInner {
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

pub(crate) struct StreamSplitConn(Arc<StreamSplitConnInner>);

impl Clone for StreamSplitConn {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl StreamSplitConn {
    fn close_with_error(&self, err: anyhow::Error) {
        self.0.queued_conn.close_with_error(Some(err));
        self.0.ctx.cancel();
        let this = self.clone();
        tokio::spawn(async move {
            best_effort_close_session(&this.0.client, &this.0.close_url, &this.0.header_host, TunnelMode::Stream).await;
            if let Some(owner) = &this.0.owner {
                owner.close();
            }
        });
    }
}

impl AsyncRead for StreamSplitConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.get_mut().0.queued_conn.poll_read(cx, buf)
    }
}

impl AsyncWrite for StreamSplitConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().0.queued_conn.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for StreamSplitConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(self.0.queued_conn.local_addr())
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(self.0.queued_conn.remote_addr())
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.close_with_error(anyhow!(io::Error::from(io::ErrorKind::BrokenPipe)));
        Ok(())
    }

    fn shutdown_write(&self) -> io::Result<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let _ = this.0.queued_conn.close_write().await;
        });
        Ok(())
    }
}

pub(crate) async fn dial_stream_split(
    ctx: &CancellationToken,
    server_address: &str,
    opts: &TunnelDialOptions,
) -> Result<Box<dyn Stream>> {
    let info = dial_session(ctx, server_address, opts, TunnelMode::Stream).await?;
    new_stream_split_conn(info, opts).await
}

pub(crate) async fn dial_stream_with_client(
    ctx: &CancellationToken,
    client: Arc<TunnelHttpTransport>,
    target: HttpClientTarget,
    opts: &TunnelDialOptions,
) -> Result<Box<dyn Stream>> {
    let info =
        dial_session_with_client(ctx, client, target, TunnelMode::Stream, opts, session_preconnect_count()).await?;
    new_stream_split_conn(info, opts).await
}

async fn new_stream_split_conn(info: SessionDialInfo, opts: &TunnelDialOptions) -> Result<Box<dyn Stream>> {
    let c = StreamSplitConn(Arc::new(StreamSplitConnInner {
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
    }));

    tokio::spawn(pull_loop(c.clone()));
    tokio::spawn(push_loop(c.clone()));

    let out_conn = match apply_early_handshake_or_upgrade(Box::new(c.clone()), opts).await {
        Ok(out_conn) => out_conn,
        Err(err) => {
            let _ = murmur_common_net::io::close_stream(&c);
            return Err(err);
        }
    };

    Ok(out_conn)
}

const IDLE_BACKOFF: Duration = Duration::from_millis(25);
const PULL_MIN_BACKOFF: Duration = Duration::from_millis(10);
const PULL_MAX_BACKOFF: Duration = Duration::from_millis(250);

// NOT cancel-safe: a drop abandons the in-flight pull response, so the reader loses whatever the
// server had already sent on it.
async fn pull_loop(c: StreamSplitConn) {
    let mut backoff = PULL_MIN_BACKOFF;

    loop {
        if c.0.queued_conn.closed.is_cancelled() {
            return;
        }

        let Ok(req) = build_get_request(&c.0.pull_url, &c.0.header_host) else {
            let _ = murmur_common_net::io::close_stream(&c);
            return;
        };

        let resp = tokio::select! {
            result = c.0.client.send(req) => result,
            () = c.0.ctx.cancelled() => Err(anyhow!(io::Error::from(io::ErrorKind::BrokenPipe))),
        };

        let mut resp = match resp {
            Ok(resp) => resp,
            Err(err) => {
                if super::tunnel_retry::is_dial_error(&err) || is_retryable_http_transport_error(&err) {
                    if pull_wait_retry(&c, backoff).await {
                        return;
                    }
                    backoff = next_backoff(backoff, PULL_MIN_BACKOFF, PULL_MAX_BACKOFF);
                    continue;
                }
                let _ = murmur_common_net::io::close_stream(&c);
                return;
            }
        };
        backoff = PULL_MIN_BACKOFF;
        if resp.status() != http::StatusCode::OK {
            let retryable = is_retryable_status_code(resp.status());
            let _ = resp.body_mut().collect().await;
            if retryable {
                if pull_wait_retry(&c, backoff).await {
                    return;
                }
                backoff = next_backoff(backoff, PULL_MIN_BACKOFF, PULL_MAX_BACKOFF);
                continue;
            }
            let _ = murmur_common_net::io::close_stream(&c);
            return;
        }
        match pull_body(&c, &mut resp).await {
            PullBody::Drained { read_any } => {
                backoff = PULL_MIN_BACKOFF;
                if !read_any {
                    tokio::select! {
                        () = tokio::time::sleep(IDLE_BACKOFF) => {}
                        () = c.0.queued_conn.closed.cancelled() => return,
                    }
                }
            }
            PullBody::Retry => {
                if pull_wait_retry(&c, backoff).await {
                    return;
                }
                backoff = next_backoff(backoff, PULL_MIN_BACKOFF, PULL_MAX_BACKOFF);
            }
            PullBody::Stop => return,
        }
    }
}

/// Outcome of draining one pull response body.
enum PullBody {
    /// The body ended on its own; `read_any` records whether any payload was forwarded.
    Drained { read_any: bool },
    /// The body failed retryably; the caller waits out the backoff.
    Retry,
    /// The connection must stop.
    Stop,
}

async fn pull_wait_retry(c: &StreamSplitConn, backoff: Duration) -> bool {
    close_idle_connections(&c.0.client).await;
    super::tunnel_retry::wait_retry(&c.0.queued_conn.closed, Some(&|| c.0.queued_conn.closed_err()), backoff)
        .await
        .is_err()
}

async fn pull_send_chunk(c: &StreamSplitConn, data: &[u8]) -> bool {
    let payload = Bytes::copy_from_slice(data);
    tokio::select! {
        result = c.0.queued_conn.rxc_tx.send(payload) => result.is_ok(),
        () = c.0.queued_conn.closed.cancelled() => false,
    }
}

async fn pull_body(c: &StreamSplitConn, resp: &mut http::Response<Incoming>) -> PullBody {
    let mut read_any = false;
    loop {
        let frame = tokio::select! {
            frame = resp.frame() => frame,
            () = c.0.queued_conn.closed.cancelled() => {
                return PullBody::Stop;
            }
        };
        match frame {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    if !data.is_empty() {
                        read_any = true;
                        if !pull_send_chunk(c, data).await {
                            return PullBody::Stop;
                        }
                    }
                }
                if let Some(trailers) = frame.trailers_ref() {
                    if trailers.get(TUNNEL_STREAM_EOF_HEADER).map(http::HeaderValue::as_bytes) == Some(b"1") {
                        c.0.queued_conn.mark_read_eof();
                        return PullBody::Stop;
                    }
                }
            }
            Some(Err(rerr)) => {
                if is_retryable_http_transport_error(&anyhow!(rerr)) {
                    return PullBody::Retry;
                }
                let _ = murmur_common_net::io::close_stream(c);
                return PullBody::Stop;
            }
            None => return PullBody::Drained { read_any },
        }
    }
}

const MAX_BATCH_BYTES: usize = 256 * 1024;
const FLUSH_INTERVAL: Duration = Duration::from_millis(5);
const PUSH_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const PUSH_MIN_BACKOFF: Duration = Duration::from_millis(10);
const PUSH_MAX_BACKOFF: Duration = Duration::from_millis(250);

/// NOT cancel-safe: the batch has already been split off `buf`, so a drop loses that payload.
async fn push_flush(buf: &mut BytesMut, c: &StreamSplitConn) -> Result<()> {
    let c = c.clone();
    if buf.is_empty() {
        return Ok::<(), anyhow::Error>(());
    }
    let sequence = c.0.upload_seq.fetch_add(1, Ordering::SeqCst) + 1;
    let request_url = upload_url(&c.0.push_url, sequence)?;
    let payload = buf.split().freeze();

    let closed_err = || c.0.queued_conn.closed_err();
    let result: Result<()> = super::tunnel_retry::retry_persistent(&c.0.queued_conn.closed, Some(&closed_err), PUSH_MIN_BACKOFF, PUSH_MAX_BACKOFF, || {
            let c = c.clone();
            let payload = payload.clone();
            let request_url = request_url.clone();
            async move {
                let mut req = http::Request::builder()
                    .method(http::Method::POST)
                    .uri(&request_url)
                    .body(Full::new(payload))?;
                apply_tunnel_headers(req.headers_mut(), &c.0.header_host, TunnelMode::Stream);
                req.headers_mut().insert(http::header::HOST, http::HeaderValue::from_str(&c.0.header_host)?);
                req.headers_mut().insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/octet-stream"));

                let resp = tokio::select! {
                    result = c.0.client.send(req) => result,
                    () = tokio::time::sleep(PUSH_REQUEST_TIMEOUT) => Err(anyhow!(io::Error::from(io::ErrorKind::TimedOut))),
                };
                let resp = match resp {
                    Ok(resp) => resp,
                    Err(err) => {
                        close_idle_connections(&c.0.client).await;
                        return Err(err);
                    }
                };
                let status = resp.status();
                let _ = resp.collect().await;
                if status != http::StatusCode::OK {
                    let err = status_error(status, status.canonical_reason().unwrap_or(""));
                    if is_retryable_http_transport_error(&err) {
                        close_idle_connections(&c.0.client).await;
                    }
                    return Err(err);
                }
                Ok(())
            }
        })
        .await;
    result?;
    drop(c);
    Ok(())
}

async fn push_loop(c: StreamSplitConn) {
    let mut buf = BytesMut::new();
    let mut write_err: Option<anyhow::Error>;

    let mut timer = tokio::time::interval(FLUSH_INTERVAL);
    timer.tick().await;
    let mut write_rx = c.0.queued_conn.write_ch_rx.lock().await;

    loop {
        tokio::select! {
            biased;
            () = c.0.queued_conn.closed.cancelled() => {
                write_err = Some(c.0.queued_conn.closed_err());
                break;
            }
            () = c.0.queued_conn.write_closed.cancelled() => {
                loop {
                    if let Ok(b) = write_rx.try_recv() {
                        if b.is_empty() {
                            continue;
                        }
                        if buf.len() + b.len() > MAX_BATCH_BYTES {
                            if let Err(err) = push_flush(&mut buf, &c).await {
                                write_err = Some(anyhow!("stream push flush failed: {err}"));
                                c.close_with_error(anyhow!("stream push flush failed: {err}"));
                                c.0.queued_conn.complete_write(write_err.take());
                                return;
                            }
                        }
                        buf.extend_from_slice(&b);
                    } else {
                        if let Err(err) = push_flush(&mut buf, &c).await {
                            write_err = Some(anyhow!("stream push flush failed: {err}"));
                            c.close_with_error(anyhow!("stream push flush failed: {err}"));
                            c.0.queued_conn.complete_write(write_err.take());
                            return;
                        }
                        if let Err(err) = super::tunnel_dial::send_session_control(&c.0.client, &c.0.fin_url, &c.0.header_host, TunnelMode::Stream).await {
                            let err = anyhow!("stream FIN failed: {err}");
                            write_err = Some(err);
                            c.close_with_error(anyhow!("stream FIN failed"));
                            c.0.queued_conn.complete_write(write_err.take());
                            return;
                        }
                        c.0.queued_conn.complete_write(None);
                        return;
                    }
                }
            }
            b = write_rx.recv() => {
                let Some(b) = b else { continue };
                if b.is_empty() {
                    continue;
                }
                if buf.len() + b.len() > MAX_BATCH_BYTES {
                    if let Err(err) = push_flush(&mut buf, &c).await {
                        write_err = Some(anyhow!("stream push flush failed: {err}"));
                        c.close_with_error(anyhow!("stream push flush failed: {err}"));
                        c.0.queued_conn.complete_write(write_err.take());
                        return;
                    }
                }
                buf.extend_from_slice(&b);
                if buf.len() >= MAX_BATCH_BYTES {
                    if let Err(err) = push_flush(&mut buf, &c).await {
                        write_err = Some(anyhow!("stream push flush failed: {err}"));
                        c.close_with_error(anyhow!("stream push flush failed: {err}"));
                        c.0.queued_conn.complete_write(write_err.take());
                        return;
                    }
                }
            }
            _ = timer.tick() => {
                if let Err(err) = push_flush(&mut buf, &c).await {
                    write_err = Some(anyhow!("stream push flush failed: {err}"));
                    c.close_with_error(anyhow!("stream push flush failed: {err}"));
                    c.0.queued_conn.complete_write(write_err.take());
                    return;
                }
            }
        }
    }
    c.0.queued_conn.complete_write(write_err);
}

fn build_get_request(url: &str, header_host: &str) -> Result<http::Request<Full<Bytes>>> {
    let mut req = http::Request::builder().method(http::Method::GET).uri(url).body(Full::new(Bytes::new()))?;
    apply_tunnel_headers(req.headers_mut(), header_host, TunnelMode::Stream);
    req.headers_mut().insert(http::header::HOST, http::HeaderValue::from_str(header_host)?);
    Ok(req)
}
