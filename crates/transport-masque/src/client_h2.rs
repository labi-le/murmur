//! The HTTP/2 side runs on `hyper`'s HTTP/2 client: [`H2Transport`] carries the client-connection
//! surface this package uses, and [`H2ClientConn`] the single HTTP/2 connection on top of it.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use futures::future::BoxFuture;
use http::{HeaderMap, HeaderValue, Method, Request};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::rt::{Executor, ReadBufCursor, Sleep, Timer};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::masque::connectip::CloseError;
use crate::masque::{quicvarint, uritemplate, url_host, HttpResponse, IpConn};
use murmur_common::contextutils::after_func;
use murmur_std_compat::net::Conn;

const H2_DATAGRAM_CAPSULE_TYPE: u64 = 0;

/// The largest DATAGRAM capsule payload accepted: the capsules carry proxied IP packets, and 64 KiB
/// is the largest IP datagram one can hold. The length comes from the peer, so it is checked before
/// anything is allocated for it.
const MAX_DATAGRAM_CAPSULE_LEN: u64 = 64 * 1024;

/// Bytes skipped at a time when dropping a capsule this client does not act on.
const CAPSULE_DISCARD_CHUNK: usize = 4 * 1024;

const IPV4_HEADER_LEN: usize = 20;

const IPV6_HEADER_LEN: usize = 40;

/// A body the HTTP/2 client never has to stream: a CONNECT request carries its payload in the
/// upgraded stream instead.
type H2Body = Empty<Bytes>;

type DuplexBox = Box<dyn Duplex>;

// Deliberate blanket impl (guideline section 7): `Duplex` is a private marker alias for the
// boxed stream type, not an extension point anyone implements by hand.
trait Duplex: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> Duplex for T {}

/// Bridges tokio IO into `hyper`'s IO traits. hyper's cursor API offers no safe way to fill a
/// cursor in place, so reads are staged through a buffer instead of `unsafe`.
struct HyperIo<T> {
    inner: T,
    scratch: Box<[u8]>,
}

impl<T> HyperIo<T> {
    fn new(inner: T) -> Self {
        Self { inner, scratch: vec![0u8; 16 * 1024].into_boxed_slice() }
    }
}

impl<T: AsyncRead + Unpin> hyper::rt::Read for HyperIo<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, mut buf: ReadBufCursor<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let len = buf.remaining().min(this.scratch.len());
        if len == 0 {
            return Poll::Ready(Ok(()));
        }
        let (stage, _rest) = this.scratch.split_at_mut(len);
        let mut read_buf = ReadBuf::new(stage);
        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                buf.put_slice(read_buf.filled());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite + Unpin> hyper::rt::Write for HyperIo<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
}

/// Bridges `hyper`'s IO traits back to tokio, for the upgraded stream of a CONNECT request.
struct TokioIo<T> {
    inner: T,
    scratch: Box<[u8]>,
}

impl<T> TokioIo<T> {
    fn new(inner: T) -> Self {
        Self { inner, scratch: vec![0u8; 16 * 1024].into_boxed_slice() }
    }
}

impl<T: hyper::rt::Read + Unpin> AsyncRead for TokioIo<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let len = buf.remaining().min(this.scratch.len());
        if len == 0 {
            return Poll::Ready(Ok(()));
        }
        let (stage, _rest) = this.scratch.split_at_mut(len);
        let mut read_buf = hyper::rt::ReadBuf::new(stage);
        let cursor = read_buf.unfilled();
        match hyper::rt::Read::poll_read(Pin::new(&mut this.inner), cx, cursor) {
            Poll::Ready(Ok(())) => {
                // Leaving the cursor untouched is how hyper reports end of stream.
                buf.put_slice(read_buf.filled());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: hyper::rt::Write + Unpin> AsyncWrite for TokioIo<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        hyper::rt::Write::poll_write(Pin::new(&mut self.get_mut().inner), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_flush(Pin::new(&mut self.get_mut().inner), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_shutdown(Pin::new(&mut self.get_mut().inner), cx)
    }

    fn is_write_vectored(&self) -> bool {
        hyper::rt::Write::is_write_vectored(&self.inner)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        hyper::rt::Write::poll_write_vectored(Pin::new(&mut self.get_mut().inner), cx, bufs)
    }
}

#[derive(Clone, Debug, Default)]
struct TokioExecutor;

impl<F> Executor<F> for TokioExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        tokio::spawn(future);
    }
}

struct TokioSleep {
    inner: Pin<Box<tokio::time::Sleep>>,
}

impl Future for TokioSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.inner.as_mut().poll(cx)
    }
}

impl Sleep for TokioSleep {}

#[derive(Clone, Debug, Default)]
struct TokioTimer;

impl Timer for TokioTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep { inner: Box::pin(tokio::time::sleep(duration)) })
    }

    fn sleep_until(&self, deadline: std::time::Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep { inner: Box::pin(tokio::time::sleep_until(deadline.into())) })
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: std::time::Instant) {
        if let Some(mut sleep) = sleep.as_mut().downcast_mut_pin::<TokioSleep>() {
            sleep.inner.as_mut().reset(new_deadline.into());
        }
    }

    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into()
    }
}

/// The HTTP/2 configuration, restricted to the health-check options this transport sets.
#[derive(Debug, Clone)]
pub struct Http2Config {
    /// How long the connection may be idle before a PING is
    /// sent; `None` disables the health check (the zero value).
    pub send_ping_timeout: Option<Duration>,
    /// The default wait for that PING's acknowledgement.
    pub ping_timeout: Duration,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self { send_ping_timeout: None, ping_timeout: Duration::from_secs(15) }
    }
}

pub type DialTlsFn = Arc<
    dyn Fn(CancellationToken, &'static str, String) -> BoxFuture<'static, anyhow::Result<Box<dyn Conn>>> + Send + Sync,
>;

/// The dialed connection is always spoken to as HTTP/2 with no HTTP/1.1 fallback, which is the
/// only mode here.
pub struct H2Transport {
    dial_tls: DialTlsFn,
    http2: Http2Config,
}

impl std::fmt::Debug for H2Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Transport").field("http2", &self.http2).finish_non_exhaustive()
    }
}

impl H2Transport {
    pub fn new(dial_tls: DialTlsFn, http2: Http2Config) -> Self {
        Self { dial_tls, http2 }
    }

    pub async fn new_client_conn(
        &self,
        ctx: &CancellationToken,
        scheme: &str,
        address: &str,
    ) -> anyhow::Result<H2ClientConn> {
        // `scheme` picks TLS inside the transport; the dialer here hands back a secured conn.
        let _ = scheme;
        let conn = (*self.dial_tls)(ctx.clone(), "tcp", address.to_owned()).await?;

        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor);
        builder.timer(TokioTimer);
        if let Some(send_ping_timeout) = self.http2.send_ping_timeout {
            builder.keep_alive_interval(send_ping_timeout);
            builder.keep_alive_timeout(self.http2.ping_timeout);
        }
        let (send_request, connection) = builder.handshake(HyperIo::new(conn)).await?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });

        Ok(H2ClientConn { send_request: tokio::sync::Mutex::new(send_request), driver })
    }
}

/// A single HTTP/2 connection.
pub struct H2ClientConn {
    send_request: tokio::sync::Mutex<hyper::client::conn::http2::SendRequest<H2Body>>,
    driver: JoinHandle<()>,
}

impl std::fmt::Debug for H2ClientConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2ClientConn").finish_non_exhaustive()
    }
}

impl H2ClientConn {
    /// `ClientConn.Reserve`. The fork counts reserved concurrency slots; hyper serialises
    /// requests through its own dispatcher, so only the usability check remains.
    pub fn reserve(&self) -> anyhow::Result<()> {
        let send_request = self.send_request.try_lock().map_err(|_| anyhow!("connection is busy"))?;
        let closed = send_request.is_closed();
        drop(send_request);
        if closed {
            return Err(anyhow!("connection is closed"));
        }
        Ok(())
    }

    /// Closes the connection, interrupting outstanding round trips.
    pub fn close(&self) -> anyhow::Result<()> {
        self.driver.abort();
        Ok(())
    }

    /// Sends the request on this connection only.
    // NOT cancel-safe: the request borrows a locked send half and has already started writing, so a dropped call abandons the request on a connection that cannot be reused safely; the arms that await it drop it only while the connection is being torn down.
    pub async fn round_trip(&self, request: Request<H2Body>) -> anyhow::Result<hyper::Response<Incoming>> {
        let mut send_request = self.send_request.lock().await;
        // the round trip waits for a concurrency slot before sending.
        send_request.ready().await?;
        let response = send_request.send_request(request).await?;
        drop(send_request);
        Ok(response)
    }
}

pub async fn connect_tunnel_h2(
    ctx: CancellationToken,
    h2_transport: &H2Transport,
    connect_uri: &str,
) -> anyhow::Result<(H2ClientConn, Box<dyn IpConn>)> {
    let mut additional_headers = HeaderMap::new();
    additional_headers.insert(http::header::USER_AGENT, HeaderValue::from_static(""));
    let template = uritemplate::Template::must_new(connect_uri);

    let mut h2_headers = additional_headers.clone();
    h2_headers.insert("cf-connect-proto", HeaderValue::from_static("cf-connect-ip"));
    // The client does not support PQC yet.
    h2_headers.insert("pq-enabled", HeaderValue::from_static("false"));

    let cc = h2_transport
        .new_client_conn(&ctx, "https", ":0")
        .await
        .map_err(|err| anyhow!("connect-ip: failed to create client connection: {err}"))?;

    if let Err(err) = cc.reserve() {
        let _ = cc.close();
        return Err(anyhow!("connect-ip: failed to reserve client connection: {err}"));
    }

    let (mut ip_conn, rsp) = match dial_h2(&ctx, &cc, &template, &h2_headers).await {
        Ok(dialed) => dialed,
        Err(err) => {
            let _ = cc.close();
            if err.to_string().contains("tls: access denied") {
                return Err(anyhow!(
                    "login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service"
                ));
            }
            return Err(anyhow!("failed to dial connect-ip over HTTP/2: {err}"));
        }
    };

    if !rsp.is_ok() {
        let _ = ip_conn.close().await;
        let _ = cc.close();
        return Err(anyhow!("failed to dial connect-ip: {}", rsp.status));
    }

    Ok((cc, Box::new(ip_conn)))
}

/// Dials a proxied connection over HTTP/2 CONNECT-IP, which carries proxied packets
/// inside HTTP capsule DATAGRAM frames.
pub(crate) async fn dial_h2(
    ctx: &CancellationToken,
    rt: &H2ClientConn,
    template: &uritemplate::Template,
    additional_headers: &HeaderMap,
) -> anyhow::Result<(H2IpConn, HttpResponse)> {
    if !template.varnames().is_empty() {
        return Err(anyhow!("connect-ip: IP flow forwarding not supported"));
    }

    let url = url::Url::parse(template.raw()).map_err(|err| anyhow!("connect-ip: failed to parse URI: {err}"))?;

    // The request context is detached from `ctx`, which would otherwise close the whole HTTP/2
    // connection rather than this one stream.
    let req_cancel = CancellationToken::new();

    let mut headers = HeaderMap::new();
    for (name, value) in additional_headers {
        if name == http::header::USER_AGENT && value.is_empty() {
            // the encoder drops an empty User-Agent, which is how the default one is suppressed.
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{}", authority_from_url(&url)))
        .body(Empty::<Bytes>::new())
        .map_err(|err| anyhow!("connect-ip: failed to create request: {err}"))?;
    *request.headers_mut() = headers;

    // `req_cancel` is temporarily connected to `ctx` for the duration of the round trip.
    let stop = after_func(ctx, {
        let req_cancel = req_cancel.clone();
        move || req_cancel.cancel()
    });
    let response = rt.round_trip(request).await;
    let _ = stop();

    let mut rsp = response.map_err(|err| anyhow!("connect-ip: failed to send request: {err}"))?;
    if rsp.status().as_u16() < 200 || rsp.status().as_u16() > 299 {
        req_cancel.cancel();
        let status = rsp.status().as_u16();
        return Err(anyhow!("connect-ip: server responded with {status}"));
    }

    // hyper only exposes the tunnel stream of a CONNECT request that was answered with `200`.
    let upgraded = hyper::upgrade::on(&mut rsp).await.map_err(|err| {
        req_cancel.cancel();
        anyhow!("connect-ip: failed to send request: {err}")
    })?;
    let (response_body, request_body) = tokio::io::split::<DuplexBox>(Box::new(TokioIo::new(upgraded)));

    let stream = H2DatagramStream {
        request_body: tokio::sync::Mutex::new(Some(request_body)),
        response_body: tokio::sync::Mutex::new(Some(response_body)),
        cancel: req_cancel,
    };
    let status_code = rsp.status().as_u16();
    let header = rsp.headers().clone();

    Ok((
        H2IpConn { str: stream, close_chan: CancellationToken::new(), close_err: Mutex::new(None) },
        HttpResponse::new(status_code, header),
    ))
}

/// Skips a capsule this client does not act on, through a fixed scratch buffer.
async fn discard_capsule<R: AsyncRead + Unpin>(stream: &mut R, mut remaining: usize) -> anyhow::Result<()> {
    let mut scratch = [0u8; CAPSULE_DISCARD_CHUNK];
    while remaining > 0 {
        let chunk_len = remaining.min(scratch.len());
        let (chunk, _rest) = scratch.split_at_mut(chunk_len);
        stream.read_exact(chunk).await?;
        remaining -= chunk_len;
    }
    Ok(())
}

/// A datagram stream whose two halves are the upgraded request and response bodies.
pub(crate) struct H2DatagramStream {
    request_body: tokio::sync::Mutex<Option<WriteHalf<DuplexBox>>>,
    response_body: tokio::sync::Mutex<Option<ReadHalf<DuplexBox>>>,
    cancel: CancellationToken,
}

impl std::fmt::Debug for H2DatagramStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2DatagramStream").finish_non_exhaustive()
    }
}

impl H2DatagramStream {
    /// Receives one datagram; the context is unused in HTTP/2 mode.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the read half is borrowed out of the locked slot for the whole capsule loop, so the guard spans every await"
    )]
    // NOT cancel-safe: a dropped call has already consumed framing bytes from the stream, so a later read would start mid-frame; the arms that await it drop it only while the connection is being torn down.
    pub(crate) async fn receive_datagram(&self, _ctx: Option<&CancellationToken>) -> anyhow::Result<Vec<u8>> {
        let mut response_body = self.response_body.lock().await;
        let Some(stream) = response_body.as_mut() else {
            return Err(anyhow!("io: read/write on closed pipe"));
        };
        loop {
            let capsule_type = quicvarint::read(stream).await?;
            let payload_len = quicvarint::read(stream).await?;
            if payload_len > MAX_DATAGRAM_CAPSULE_LEN {
                return Err(anyhow!("connect-ip: datagram capsule exceeds {MAX_DATAGRAM_CAPSULE_LEN} bytes"));
            }
            let payload_len =
                usize::try_from(payload_len).map_err(|_err| anyhow!("connect-ip: datagram capsule too large"))?;
            if capsule_type != H2_DATAGRAM_CAPSULE_TYPE {
                discard_capsule(stream, payload_len).await?;
                continue;
            }
            let mut payload = vec![0u8; payload_len];
            stream.read_exact(&mut payload).await?;
            return Ok(payload);
        }
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the write half is borrowed out of the locked slot until the capsule has been written, so the guard spans the await"
    )]
    pub(crate) async fn send_datagram(&self, data: &[u8]) -> anyhow::Result<()> {
        let mut frame: Vec<u8> = Vec::with_capacity(
            quicvarint::len(H2_DATAGRAM_CAPSULE_TYPE) + quicvarint::len(data.len() as u64) + data.len(),
        );
        quicvarint::append(&mut frame, H2_DATAGRAM_CAPSULE_TYPE);
        quicvarint::append(&mut frame, data.len() as u64);
        frame.extend_from_slice(data);

        let mut request_body = self.request_body.lock().await;
        let Some(stream) = request_body.as_mut() else {
            return Err(anyhow!("io: read/write on closed pipe"));
        };
        stream.write_all(&frame).await.map_err(|err| anyhow!("connect-ip: failed to send datagram capsule: {err}"))
    }

    pub(crate) async fn close(&self) -> anyhow::Result<()> {
        // Only the response body's close error is reported; the request body's is discarded.
        let _ = {
            let mut request_body = self.request_body.lock().await;
            match request_body.as_mut() {
                Some(stream) => AsyncWriteExt::shutdown(stream).await,
                None => Ok(()),
            }
        };
        // Dropping the read half ends the response body, which has nothing to report.
        let _ = self.response_body.lock().await.take();
        self.cancel.cancel();
        Ok(())
    }
}

pub(crate) struct H2IpConn {
    str: H2DatagramStream,
    close_chan: CancellationToken,
    close_err: Mutex<Option<CloseError>>,
}

impl std::fmt::Debug for H2IpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2IpConn").field("closed", &self.close_chan.is_cancelled()).finish_non_exhaustive()
    }
}

impl H2IpConn {
    fn close_err(&self) -> Option<CloseError> {
        *self.close_err.lock()
    }

    fn handle_incoming_proxied_packet(data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() {
            return Err(anyhow!("connect-ip: empty packet"));
        }
        match ip_version(data) {
            4 => {
                if data.len() < IPV4_HEADER_LEN {
                    return Err(anyhow!("connect-ip: malformed datagram: too short"));
                }
            }
            6 => {
                if data.len() < IPV6_HEADER_LEN {
                    return Err(anyhow!("connect-ip: malformed datagram: too short"));
                }
            }
            v => return Err(anyhow!("connect-ip: unknown IP versions: {v}")),
        }
        Ok(())
    }

    /// `Ok(false)` stands for the empty packet that is dropped.
    fn compose_datagram(b: &mut [u8]) -> anyhow::Result<bool> {
        if b.is_empty() {
            return Ok(false);
        }
        match ip_version(b) {
            4 => {
                let header =
                    header_mut::<IPV4_HEADER_LEN>(b).ok_or_else(|| anyhow!("connect-ip: IPv4 packet too short"))?;
                let ttl = header[8];
                if ttl <= 1 {
                    return Err(anyhow!("connect-ip: datagram TTL too small: {ttl}"));
                }
                header[8] = ttl - 1;
                let checksum = calculate_ipv4_checksum(header);
                header[10..12].copy_from_slice(&checksum.to_be_bytes());
            }
            6 => {
                let header =
                    header_mut::<IPV6_HEADER_LEN>(b).ok_or_else(|| anyhow!("connect-ip: IPv6 packet too short"))?;
                let hop_limit = header[7];
                if hop_limit <= 1 {
                    return Err(anyhow!("connect-ip: datagram Hop Limit too small: {hop_limit}"));
                }
                header[7] = hop_limit - 1;
            }
            v => return Err(anyhow!("connect-ip: unknown IP versions: {v}")),
        }
        Ok(true)
    }
}

#[async_trait]
impl IpConn for H2IpConn {
    async fn read_packet(&mut self) -> anyhow::Result<Vec<u8>> {
        loop {
            let data = match self.str.receive_datagram(None).await {
                Ok(data) => data,
                Err(err) => {
                    // There are no errors that can be recovered in HTTP/2 mode, so closing lets
                    // the outer read loop exit on the next iteration by returning a closed error.
                    let _ = self.close().await;
                    return match self.close_err() {
                        Some(close_err) => Err(close_err.into()),
                        None => Err(err),
                    };
                }
            };
            if let Err(err) = Self::handle_incoming_proxied_packet(&data) {
                murmur_log::debugln!("dropping proxied packet: {err}");
                continue;
            }
            return Ok(data);
        }
    }

    async fn write_packet(&mut self, b: &mut [u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let composed = match Self::compose_datagram(b) {
            Ok(composed) => composed,
            Err(err) => {
                murmur_log::debugln!("dropping proxied packet ({} bytes) that can't be proxied: {err}", b.len());
                return Ok(None);
            }
        };
        let data: &[u8] = if composed { &b[..] } else { &[] };
        if let Err(err) = self.str.send_datagram(data).await {
            return match self.close_err() {
                Some(close_err) => Err(close_err.into()),
                None => Err(err),
            };
        }
        Ok(None)
    }

    async fn close(&mut self) -> anyhow::Result<()> {
        {
            let mut close_err = self.close_err.lock();
            if close_err.is_none() {
                *close_err = Some(CloseError { remote: false });
                drop(close_err);
                self.close_chan.cancel();
            }
        }
        self.str.close().await
    }
}

pub(crate) fn authority_from_url(u: &url::Url) -> String {
    if u.port().is_some() {
        return url_host(u);
    }
    let host = u.host_str().unwrap_or_default();
    if host.is_empty() {
        return url_host(u);
    }
    format!("{host}:443")
}

/// The mutable `N`-byte packet header at the start of `b`, or `None` when `b` is shorter than one.
fn header_mut<const N: usize>(b: &mut [u8]) -> Option<&mut [u8; N]> {
    b.get_mut(..N)?.try_into().ok()
}

pub(crate) fn ip_version(b: &[u8]) -> u8 {
    b.first().map_or(0, |first| first >> 4)
}

pub(crate) fn calculate_ipv4_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
    let mut sum: u32 = 0;
    for (word_idx, word) in header.chunks_exact(2).enumerate() {
        // The checksum field itself is excluded from its own sum.
        if word_idx == 5 {
            continue;
        }
        let [hi, lo] = word else { continue };
        sum += u32::from(u16::from_be_bytes([*hi, *lo]));
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the fold above leaves the sum below 0x10000, so its low half is the whole value"
    )]
    let folded = sum as u16;
    !folded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1071 §3's worked example.
    #[test]
    fn ipv4_checksum_known_answer() {
        let header: [u8; IPV4_HEADER_LEN] = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10,
            0x0a, 0x0c,
        ];
        assert_eq!(calculate_ipv4_checksum(&header), 0xb1e6);
    }

    /// A capsule whose declared length is past the cap must fail closed before the payload is
    /// allocated: the peer here never writes that payload, so a run that reads it hangs.
    #[tokio::test]
    async fn a_datagram_capsule_past_the_cap_fails_closed_instead_of_allocating() {
        let (response_body, mut peer) = tokio::io::duplex(64);
        let (response_half, _write_half) = tokio::io::split::<DuplexBox>(Box::new(response_body));
        let stream = H2DatagramStream {
            request_body: tokio::sync::Mutex::new(None),
            response_body: tokio::sync::Mutex::new(Some(response_half)),
            cancel: CancellationToken::new(),
        };

        let mut header: Vec<u8> = Vec::new();
        quicvarint::append(&mut header, H2_DATAGRAM_CAPSULE_TYPE);
        quicvarint::append(&mut header, MAX_DATAGRAM_CAPSULE_LEN + 1);
        peer.write_all(&header).await.expect("write the capsule header");

        let result = tokio::time::timeout(Duration::from_secs(5), stream.receive_datagram(None)).await;
        let err = result.expect("the capsule read is bounded").expect_err("a capsule past the cap is rejected");
        assert!(err.to_string().contains("exceeds"), "unexpected error: {err}");
    }

    /// A capsule this client does not act on is skipped through a fixed buffer, and a following
    /// datagram capsule is still returned.
    #[tokio::test]
    async fn an_unknown_capsule_is_skipped_without_losing_the_next_datagram() {
        let (response_body, mut peer) = tokio::io::duplex(64);
        let (response_half, _write_half) = tokio::io::split::<DuplexBox>(Box::new(response_body));
        let stream = H2DatagramStream {
            request_body: tokio::sync::Mutex::new(None),
            response_body: tokio::sync::Mutex::new(Some(response_half)),
            cancel: CancellationToken::new(),
        };

        let mut frames: Vec<u8> = Vec::new();
        quicvarint::append(&mut frames, 0x21);
        quicvarint::append(&mut frames, 4);
        frames.extend_from_slice(b"skip");
        quicvarint::append(&mut frames, H2_DATAGRAM_CAPSULE_TYPE);
        quicvarint::append(&mut frames, 3);
        frames.extend_from_slice(b"abc");
        peer.write_all(&frames).await.expect("write the capsules");

        let data = tokio::time::timeout(Duration::from_secs(5), stream.receive_datagram(None))
            .await
            .expect("the datagram arrives")
            .expect("the capsule after the skipped one is returned");
        assert_eq!(data, b"abc");
    }
}
