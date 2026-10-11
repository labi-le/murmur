//! This build speaks the already-negotiated carrier connection with `hyper`'s HTTP/1.1 and HTTP/2
//! client halves.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use rand::Rng as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::{Addr, Conn as NetConn};

use super::config::{TrafficGenerator, TrafficStep};

/// A shared `NetConn`, so the carrier connection can be closed while an
/// HTTP client half still owns the IO half.
#[derive(Clone)]
pub(crate) struct SharedConn(Arc<Mutex<Box<dyn NetConn>>>);

impl SharedConn {
    pub(crate) fn new(conn: Box<dyn NetConn>) -> Self {
        Self(Arc::new(Mutex::new(conn)))
    }

    pub(crate) fn close(&self) {
        let _ = self.0.lock().close();
    }
}

impl AsyncRead for SharedConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().0.lock();
        Pin::new(&mut **conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for SharedConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut conn = self.get_mut().0.lock();
        Pin::new(&mut **conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().0.lock();
        Pin::new(&mut **conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().0.lock();
        Pin::new(&mut **conn).poll_shutdown(cx)
    }
}

impl NetConn for SharedConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.lock().local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.lock().remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.0.lock().close()
    }
}

#[async_trait::async_trait]
pub(crate) trait TrafficHttpTransport: Send + Sync {
    async fn round_trip(&self, req: Request<Full<Bytes>>) -> Result<Response<Incoming>>;
}

struct TrafficHttp1Transport {
    send_request: AsyncMutex<hyper::client::conn::http1::SendRequest<Full<Bytes>>>,
}

#[async_trait::async_trait]
impl TrafficHttpTransport for TrafficHttp1Transport {
    // cancel-safe: delegates to the inner transport's own `round_trip`/`read_datagram` and holds no state of its own, so it inherits that implementation's cancel safety.
    async fn round_trip(&self, req: Request<Full<Bytes>>) -> Result<Response<Incoming>> {
        let mut send_request = self.send_request.lock().await;
        Ok(send_request.send_request(req).await?)
    }
}

struct TrafficHttp2Transport {
    send_request: AsyncMutex<hyper::client::conn::http2::SendRequest<Full<Bytes>>>,
}

#[async_trait::async_trait]
impl TrafficHttpTransport for TrafficHttp2Transport {
    // cancel-safe: delegates to the inner transport's own `round_trip`/`read_datagram` and holds no state of its own, so it inherits that implementation's cancel safety.
    async fn round_trip(&self, req: Request<Full<Bytes>>) -> Result<Response<Incoming>> {
        let mut send_request = self.send_request.lock().await;
        Ok(send_request.send_request(req).await?)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CarrierAlpn {
    Http1,
    Http2,
}

impl CarrierAlpn {
    fn parse(alpn: &str) -> Result<Self> {
        match alpn {
            "h2" => Ok(Self::Http2),
            "http/1.1" | "" => Ok(Self::Http1),
            other => Err(anyhow!("tlsmirror: unknown carrier ALPN {other:?}")),
        }
    }
}

pub(crate) async fn new_traffic_http_transport(
    conn: SharedConn,
    alpn: CarrierAlpn,
) -> Result<Arc<dyn TrafficHttpTransport>> {
    match alpn {
        CarrierAlpn::Http2 => {
            let io = TokioIo::new(conn);
            let (send_request, connection) =
                hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(io).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(Arc::new(TrafficHttp2Transport { send_request: AsyncMutex::new(send_request) }))
        }
        CarrierAlpn::Http1 => {
            let io = TokioIo::new(conn);
            let (send_request, connection) = hyper::client::conn::http1::Builder::new().handshake(io).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(Arc::new(TrafficHttp1Transport { send_request: AsyncMutex::new(send_request) }))
        }
    }
}

pub(crate) async fn run_traffic_generator(
    ctx: &CancellationToken,
    conn: SharedConn,
    cfg: Option<&TrafficGenerator>,
    alpn: &str,
    ready: impl FnOnce() + Send + 'static,
    recall: &CancellationToken,
) {
    let steps_empty = cfg.is_none_or(|cfg| cfg.steps.is_empty());
    if steps_empty {
        let mut conn = conn;
        let _ = tokio::io::copy(&mut conn, &mut tokio::io::sink()).await;
        return;
    }
    let Some(cfg) = cfg else {
        return;
    };

    let Ok(alpn) = CarrierAlpn::parse(alpn) else {
        conn.close();
        return;
    };
    let Ok(transport) = new_traffic_http_transport(conn.clone(), alpn).await else {
        conn.close();
        return;
    };

    let mut ready = Some(ready);
    let mut mark_ready = move || {
        if let Some(ready) = ready.take() {
            ready();
        }
    };

    let mut current = 0usize;
    while !ctx.is_cancelled() {
        let Some(step) = cfg.steps.get(current) else {
            conn.close();
            return;
        };
        if run_traffic_step(ctx, transport.as_ref(), step, alpn).await.is_err() {
            return;
        }
        if step.connection_ready {
            mark_ready();
        }
        if step.connection_recall_exit && (recall.is_cancelled() || ctx.is_cancelled()) {
            conn.close();
            return;
        }
        match choose_next_traffic_step(step, current) {
            Ok(Some(next)) => current = next,
            Ok(None) => current += 1,
            Err(_) => return,
        }
    }
}

pub(crate) fn traffic_generator_waits_for_ready(cfg: Option<&TrafficGenerator>) -> bool {
    match cfg {
        Some(cfg) => cfg.steps.iter().any(|step| step.connection_ready),
        None => false,
    }
}

async fn run_traffic_step(
    ctx: &CancellationToken,
    transport: &dyn TrafficHttpTransport,
    step: &TrafficStep,
    alpn: CarrierAlpn,
) -> Result<()> {
    run_traffic_step_with_clock(ctx, transport, step, alpn, std::time::Instant::now, wait_traffic_step).await
}

async fn run_traffic_step_with_clock<W, WFut>(
    ctx: &CancellationToken,
    transport: &dyn TrafficHttpTransport,
    step: &TrafficStep,
    alpn: CarrierAlpn,
    now: fn() -> std::time::Instant,
    wait: W,
) -> Result<()>
where
    W: FnOnce(CancellationToken, Duration) -> WFut,
    WFut: Future<Output = Result<()>>,
{
    let hostname = hostname_only(&step.host);
    let uri: http::Uri = format!("https://{}{}", step.host, step.path).parse()?;
    let method = Method::from_bytes(step.method.as_bytes())?;
    let mut builder = Request::builder().method(method).uri(uri).header(http::header::HOST, hostname);
    for header in &step.headers {
        if header.name.is_empty() {
            continue;
        }
        let name = HeaderName::from_bytes(header.name.as_bytes())?;
        if !header.value.is_empty() {
            builder = builder.header(name.clone(), HeaderValue::from_str(&header.value)?);
        }
        for value in &header.values {
            builder = builder.header(name.clone(), HeaderValue::from_str(value)?);
        }
    }
    let req = builder.body(Full::new(Bytes::new()))?;

    let start = now();
    let resp = transport.round_trip(req).await?;

    let finish_request = |resp: Response<Incoming>| async move {
        let result = resp.into_body().collect().await;
        result.map(|_| ()).map_err(anyhow::Error::from)
    };
    if step.h2_do_not_wait_for_download_finish && alpn == CarrierAlpn::Http2 {
        tokio::spawn(finish_request(resp));
    } else {
        finish_request(resp).await?;
    }
    let elapsed = now().duration_since(start);
    let delay = step.wait_time.duration()?;
    if delay > elapsed {
        wait(ctx.clone(), delay.saturating_sub(elapsed)).await?;
    }
    Ok(())
}

// cancel-safe: it only races the step delay against the context.
async fn wait_traffic_step(ctx: CancellationToken, delay: Duration) -> Result<()> {
    tokio::select! {
        () = ctx.cancelled() => Err(anyhow!("context canceled")),
        () = tokio::time::sleep(delay) => Ok(()),
    }
}

/// Chooses the next traffic step. `Ok(None)` is the zero-delay, no-next-step result.
fn choose_next_traffic_step(step: &TrafficStep, current: usize) -> Result<Option<usize>> {
    if step.next_step.is_empty() {
        return Ok(None);
    }
    let total: i64 = step.next_step.iter().map(|candidate| i64::from(candidate.weight)).sum();
    if total <= 0 {
        return Err(anyhow!("tlsmirror: invalid next-step weight total {total}"));
    }
    let selected = rand::rng().random_range(0..total);
    let mut cursor: i64 = 0;
    for candidate in &step.next_step {
        if cursor >= selected {
            return Ok(Some(candidate.goto_location));
        }
        cursor += i64::from(candidate.weight);
    }
    Ok(Some(current + 1))
}

fn hostname_only(host: &str) -> &str {
    let Some((name, port)) = host.rsplit_once(':') else { return host };
    if port.chars().all(|c| c.is_ascii_digit()) {
        return name;
    }
    host
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    use crate::config::{TimeSpec, TrafficTransferCandidate};

    use super::*;

    async fn start_capture_server() -> (String, oneshot::Receiver<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr").to_string();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept test connection");
            let (read_half, mut write_half) = tokio::io::split(stream);
            let mut reader = BufReader::new(read_half);
            let mut headers = Vec::new();
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await.expect("read request line");
                if n == 0 || line == "\r\n" {
                    break;
                }
                headers.push(line.trim_end().to_owned());
            }
            let _ = write_half.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
            let _ = tx.send(headers);
        });
        (addr, rx)
    }

    async fn dial_http1_transport(addr: &str) -> Arc<dyn TrafficHttpTransport> {
        let stream = TcpStream::connect(addr).await.expect("connect test listener");
        let conn = SharedConn::new(Box::new(stream));
        new_traffic_http_transport(conn, CarrierAlpn::Http1).await.expect("build http/1.1 transport")
    }

    #[tokio::test]
    async fn http1_does_not_add_connection_header() {
        let (addr, headers_rx) = start_capture_server().await;
        let transport = dial_http1_transport(&addr).await;
        let ctx = CancellationToken::new();
        let step = TrafficStep {
            host: "example.com".to_owned(),
            path: "/".to_owned(),
            method: "GET".to_owned(),
            ..Default::default()
        };

        run_traffic_step(&ctx, transport.as_ref(), &step, CarrierAlpn::Http1).await.expect("run traffic step");

        let headers = headers_rx.await.expect("captured headers");
        assert!(
            !headers.iter().any(|line| line.to_ascii_lowercase().starts_with("connection:")),
            "unexpected Connection header: {headers:?}"
        );
    }

    #[tokio::test]
    async fn wait_time_includes_request_time() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr").to_string();
        let request_delay = Duration::from_millis(100);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept test connection");
            let (read_half, mut write_half) = tokio::io::split(stream);
            let mut reader = BufReader::new(read_half);
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await.expect("read request headers");
                if n == 0 || line == "\r\n" {
                    break;
                }
            }
            tokio::time::sleep(request_delay).await;
            let _ = write_half.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
        });

        let transport = dial_http1_transport(&addr).await;
        let ctx = CancellationToken::new();
        let wait_time = Duration::from_millis(300);
        let step = TrafficStep {
            host: "example.com".to_owned(),
            path: "/".to_owned(),
            method: "GET".to_owned(),
            wait_time: TimeSpec { base_nanoseconds: wait_time.as_nanos() as u64, ..Default::default() },
            ..Default::default()
        };

        let waited = Arc::new(Mutex::new(None));
        let waited_for_spy = Arc::clone(&waited);
        let wall_start = std::time::Instant::now();
        run_traffic_step_with_clock(
            &ctx,
            transport.as_ref(),
            &step,
            CarrierAlpn::Http1,
            std::time::Instant::now,
            move |_ctx, delay| {
                let waited_for_spy = Arc::clone(&waited_for_spy);
                async move {
                    *waited_for_spy.lock() = Some(delay);
                    Ok(())
                }
            },
        )
        .await
        .expect("run traffic step with clock");
        let measured_elapsed = wall_start.elapsed();

        let waited_dur = waited.lock().take().expect("wait was not invoked");
        let expected = wait_time.saturating_sub(measured_elapsed);
        let diff = waited_dur.abs_diff(expected);
        assert!(diff < Duration::from_millis(30), "waited={waited_dur:?} expected~={expected:?}");
    }

    #[tokio::test]
    async fn uses_v2ray_host_semantics() {
        let (addr, headers_rx) = start_capture_server().await;
        let transport = dial_http1_transport(&addr).await;
        let ctx = CancellationToken::new();
        let step = TrafficStep {
            host: "example.com:8443".to_owned(),
            path: "/carrier".to_owned(),
            method: "GET".to_owned(),
            ..Default::default()
        };

        run_traffic_step(&ctx, transport.as_ref(), &step, CarrierAlpn::Http1).await.expect("run traffic step");

        let headers = headers_rx.await.expect("captured headers");
        assert!(
            headers.iter().any(|line| line.eq_ignore_ascii_case("host: example.com")),
            "expected a Host header without the port, got: {headers:?}"
        );
    }

    #[test]
    fn invalid_next_step_weight() {
        let step = TrafficStep {
            next_step: vec![TrafficTransferCandidate { weight: 0, goto_location: 0 }],
            ..Default::default()
        };
        assert!(choose_next_traffic_step(&step, 0).is_err());
    }
}
