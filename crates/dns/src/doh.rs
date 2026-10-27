use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use hickory_proto::op::Message;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;
use url::Url;

use murmur_component::resolver::resolver::SharedResolver;
use murmur_constant::adapters::ProxyAdapter;
use murmur_constant::dns::HTTPVersion;
use murmur_log::debugln;
use murmur_tunnel::dns_dialer::DNSDialer;

use super::doq::{build_quic_client_config, is_quic_retry_error, open_quic_connection};
use super::resolver::DnsClient;

const TRANSPORT_DEFAULT_SEND_PING_TIMEOUT: Duration = Duration::from_secs(30);
#[allow(
    dead_code,
    reason = "mirrors the transportDefaultIdleConnTimeout; this build's single-slot client cache has no background eviction yet, needs a cloneable handle to spawn one"
)]
const TRANSPORT_DEFAULT_IDLE_CONN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ELAPSED_TIME: Duration = Duration::from_secs(30);

pub(crate) fn default_http_versions() -> Vec<HTTPVersion> {
    vec![HTTPVersion::HTTP_VERSION11, HTTPVersion::HTTP_VERSION2]
}

enum ActiveClient {
    H1(AsyncMutex<hyper::client::conn::http1::SendRequest<Empty<Bytes>>>),
    H2(AsyncMutex<hyper::client::conn::http2::SendRequest<Empty<Bytes>>>),
    H3(AsyncMutex<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>),
}

pub(crate) struct DnsOverHttps {
    client: AsyncMutex<Option<Arc<ActiveClient>>>,
    session_cache: Arc<dyn rustls::client::ClientSessionStore>,
    url: Url,
    http_versions: Vec<HTTPVersion>,
    dialer: DNSDialer,
    addr: String,
    skip_cert_verify: bool,
    name_cert_verify: String,
}

pub(crate) fn new_doh_client(
    url_string: &str,
    r: Option<SharedResolver>,
    prefer_h3: bool,
    params: &std::collections::HashMap<String, String>,
    proxy_adapter: Option<Arc<dyn ProxyAdapter>>,
    proxy_name: &str,
) -> Arc<dyn DnsClient> {
    #[expect(
        clippy::expect_used,
        reason = "the fallback is a fixed literal URL, so its parse can only fail through a source-level mistake"
    )]
    let url =
        Url::parse(url_string).unwrap_or_else(|_| Url::parse("https://invalid.invalid/").expect("static URL parses"));

    let mut http_versions = default_http_versions();
    if prefer_h3 {
        http_versions.push(HTTPVersion::HTTP_VERSION3);
    }
    if params.get("h3").map(String::as_str) == Some("true") {
        http_versions = vec![HTTPVersion::HTTP_VERSION3];
    }

    let mut doh = DnsOverHttps {
        client: AsyncMutex::new(None),
        session_cache: Arc::new(rustls::client::ClientSessionMemoryCache::new(32)),
        addr: url.to_string(),
        url,
        dialer: DNSDialer::new(r, proxy_adapter, proxy_name.to_owned()),
        http_versions,
        skip_cert_verify: false,
        name_cert_verify: String::new(),
    };

    if params.get("skip-cert-verify").map(String::as_str) == Some("true") {
        doh.skip_cert_verify = true;
    }
    if let Some(v) = params.get("name-cert-verify") {
        doh.name_cert_verify.clone_from(v);
    }

    Arc::new(doh)
}

#[async_trait::async_trait]
impl DnsClient for DnsOverHttps {
    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        let mut m = m.clone();
        let id = m.metadata.id;
        m.metadata.id = 0;

        let (client, is_cached) =
            self.get_client(ctx).await.map_err(|err| anyhow!("failed to init http client: {err}"))?;
        let mut result = self.exchange_https(ctx, &client, &m).await;

        let mut i = 0;
        while is_cached && Self::should_retry(&result) && i < 2 {
            let client_result = self.reset_client(ctx, result.as_ref().err()).await;
            let client = match client_result {
                Ok(client) => client,
                Err(err) => return Err(anyhow!("failed to reset http client: {err}")),
            };
            result = self.exchange_https(ctx, &client, &m).await;
            i += 1;
        }

        if let Err(err) = &result {
            if !is_context_error(err) {
                let res_err = self.reset_client(ctx, Some(err)).await.err();
                let res_err = res_err.map_or_else(String::new, |e| e.to_string());
                return Err(anyhow!("{err} (resErr:{res_err})"));
            }
        }

        result.map(|mut msg| {
            msg.metadata.id = id;
            msg
        })
    }

    fn address(&self) -> String {
        self.addr.clone()
    }

    fn reset_connection(&self) {
        if let Ok(mut guard) = self.client.try_lock() {
            *guard = None;
        }
    }
}

fn is_context_error(err: &anyhow::Error) -> bool {
    err.to_string().contains("context canceled") || err.to_string().contains("deadline exceeded")
}

impl DnsOverHttps {
    // cancel-safe: it only wraps the request in a timeout, and a dropped request leaves no shared client
    // state behind.
    async fn exchange_https(
        &self,
        ctx: &CancellationToken,
        client: &Arc<ActiveClient>,
        req: &Message,
    ) -> Result<Message> {
        let buf = req.to_vec().map_err(|err| anyhow!("packing message: {err}"))?;

        let mut request_url = self.url.clone();
        request_url.set_query(Some(&format!("dns={}", URL_SAFE_NO_PAD.encode(&buf))));

        let (status, body) =
            tokio::time::timeout(super::doq::DEFAULT_TIMEOUT, self.do_request(ctx, client, &request_url))
                .await
                .map_err(|_| anyhow!("request to {} timed out after {:?}", self.url, super::doq::DEFAULT_TIMEOUT))??;

        if status != 200 {
            return Err(anyhow!("expected status 200, got {status} from {}", self.url));
        }

        let resp = Message::from_vec(&body)
            .map_err(|err| anyhow!("unpacking response from {}: body is {body:?}: {err}", self.url))?;

        if resp.metadata.id != req.metadata.id {
            return Err(anyhow!("id mismatch: response ID does not match query ID"));
        }
        Ok(resp)
    }

    // cancel-safe: the client lock is released with the future, and dropping hyper's `send_request`
    // cancels the request rather than leaving a half-sent exchange behind.
    async fn do_request(
        &self,
        ctx: &CancellationToken,
        client: &Arc<ActiveClient>,
        url: &Url,
    ) -> Result<(u16, Vec<u8>)> {
        match client.as_ref() {
            ActiveClient::H1(send_request) => {
                // DoH over HTTP/1.1 needs origin-form plus a Host header; hyper defaults to
                // absolute-form without one, which a strict DoH server rejects.
                let req = http::Request::builder()
                    .method(http::Method::GET)
                    .uri(url[url::Position::BeforePath..].to_owned())
                    .header(http::header::HOST, &url[url::Position::BeforeHost..url::Position::AfterPort])
                    .header(http::header::ACCEPT, "application/dns-message")
                    .header(http::header::USER_AGENT, "")
                    .body(Empty::<Bytes>::new())?;
                let mut guard = send_request.lock().await;
                let resp = tokio::select! {
                    biased;
                    resp = guard.send_request(req) => resp?,
                    () = ctx.cancelled() => return Err(anyhow!("context canceled")),
                };
                drop(guard);
                let status = resp.status().as_u16();
                let body = resp.into_body().collect().await?.to_bytes().to_vec();
                Ok((status, body))
            }
            ActiveClient::H2(send_request) => {
                let req = http::Request::builder()
                    .method(http::Method::GET)
                    .uri(url.as_str())
                    .header(http::header::ACCEPT, "application/dns-message")
                    .header(http::header::USER_AGENT, "")
                    .body(Empty::<Bytes>::new())?;
                let mut guard = send_request.lock().await;
                let resp = tokio::select! {
                    biased;
                    resp = guard.send_request(req) => resp?,
                    () = ctx.cancelled() => return Err(anyhow!("context canceled")),
                };
                drop(guard);
                let status = resp.status().as_u16();
                let body = resp.into_body().collect().await?.to_bytes().to_vec();
                Ok((status, body))
            }
            ActiveClient::H3(send_request) => {
                let path_and_query = url[url::Position::BeforePath..].to_string();
                let req = http::Request::builder()
                    .method(http::Method::GET)
                    .uri(path_and_query)
                    .header(http::header::ACCEPT, "application/dns-message")
                    .header(http::header::USER_AGENT, "")
                    .body(())?;
                let mut guard = send_request.lock().await;
                let mut stream = tokio::select! {
                    biased;
                    stream = guard.send_request(req) => stream?,
                    () = ctx.cancelled() => return Err(anyhow!("context canceled")),
                };
                drop(guard);
                stream.finish().await?;
                let resp = stream.recv_response().await?;
                let status = resp.status().as_u16();
                let mut body = Vec::new();
                while let Some(mut chunk) = stream.recv_data().await? {
                    use bytes::Buf;
                    let mut b = vec![0u8; chunk.remaining()];
                    chunk.copy_to_slice(&mut b);
                    body.extend_from_slice(&b);
                }
                Ok((status, body))
            }
        }
    }

    fn should_retry(result: &Result<Message>) -> bool {
        let Err(err) = result else { return false };
        if err.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == io::ErrorKind::TimedOut) {
            return true;
        }
        is_quic_retry_error(err)
    }

    async fn reset_client(
        &self,
        ctx: &CancellationToken,
        reset_err: Option<&anyhow::Error>,
    ) -> Result<Arc<ActiveClient>> {
        let mut guard = self.client.lock().await;

        if matches!(reset_err, Some(err) if is_zero_rtt_rejected(err)) {
            debugln!("[{}] resetting the QUIC token store after a 0-RTT rejection", self.url);
        }

        *guard = None;
        debugln!("re-creating the http client due to {}", reset_err.map_or_else(String::new, ToString::to_string));
        let client = self.create_client(ctx).await?;
        *guard = Some(Arc::clone(&client));
        drop(guard);
        Ok(client)
    }

    async fn get_client(&self, ctx: &CancellationToken) -> Result<(Arc<ActiveClient>, bool)> {
        let start = Instant::now();
        let mut guard = self.client.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok((Arc::clone(client), true));
        }

        let elapsed = start.elapsed();
        if elapsed > MAX_ELAPSED_TIME {
            return Err(anyhow!("timeout exceeded: {elapsed:?}"));
        }

        debugln!("creating a new http client");
        let client = self.create_client(ctx).await?;
        *guard = Some(Arc::clone(&client));
        drop(guard);
        Ok((client, false))
    }

    async fn create_client(&self, ctx: &CancellationToken) -> Result<Arc<ActiveClient>> {
        self.create_transport(ctx).await.map_err(|err| anyhow!("[{}] initializing http transport: {err}", self.url))
    }

    async fn create_transport(&self, ctx: &CancellationToken) -> Result<Arc<ActiveClient>> {
        if self.url.scheme() == "http" {
            return self.dial_h1(ctx).await;
        }

        let alpn: Vec<Vec<u8>> = self.http_versions.iter().map(|v| v.0.as_bytes().to_vec()).collect();
        let tls_config = build_quic_client_config(
            self.skip_cert_verify,
            &self.name_cert_verify,
            alpn,
            Arc::clone(&self.session_cache),
        )?;

        if self.http_versions.contains(&HTTPVersion::HTTP_VERSION3) {
            match self.create_transport_h3(ctx, Arc::clone(&tls_config)).await {
                Ok(client) => {
                    debugln!("[{}] using HTTP/3 for this upstream: QUIC was faster", self.url);
                    return Ok(client);
                }
                Err(err) => {
                    debugln!("[{}] using HTTP/2 for this upstream: {err}", self.url);
                }
            }
        }

        if !self.supports_http() {
            return Err(anyhow!("HTTP1/1 and HTTP2 are not supported by this upstream"));
        }

        let stream = self.dial_tls(ctx, tls_config).await?;
        if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
            self.dial_h2(stream).await
        } else {
            self.dial_h1_tls(stream).await
        }
    }

    async fn dial_h1(&self, ctx: &CancellationToken) -> Result<Arc<ActiveClient>> {
        let host = self.url.host_str().ok_or_else(|| anyhow!("missing host in {}", self.url))?;
        let port = self.url.port_or_known_default().unwrap_or(80);
        let raw = self.dialer.dial_context(ctx, "tcp", &format!("{host}:{port}")).await?;
        let io = TokioIo::new(raw);
        let (send_request, connection) = hyper::client::conn::http1::Builder::new().handshake(io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Arc::new(ActiveClient::H1(AsyncMutex::new(send_request))))
    }

    async fn dial_h1_tls(
        &self,
        stream: tokio_rustls::client::TlsStream<Box<dyn murmur_std_compat::net::Conn>>,
    ) -> Result<Arc<ActiveClient>> {
        let io = TokioIo::new(stream);
        let (send_request, connection) = hyper::client::conn::http1::Builder::new().handshake(io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Arc::new(ActiveClient::H1(AsyncMutex::new(send_request))))
    }

    async fn dial_h2(
        &self,
        stream: tokio_rustls::client::TlsStream<Box<dyn murmur_std_compat::net::Conn>>,
    ) -> Result<Arc<ActiveClient>> {
        let io = TokioIo::new(stream);
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        builder.keep_alive_interval(TRANSPORT_DEFAULT_SEND_PING_TIMEOUT);
        let (send_request, connection) = builder.handshake(io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Arc::new(ActiveClient::H2(AsyncMutex::new(send_request))))
    }

    async fn dial_tls(
        &self,
        ctx: &CancellationToken,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<tokio_rustls::client::TlsStream<Box<dyn murmur_std_compat::net::Conn>>> {
        self.tls_dial(ctx, tls_config).await
    }

    // cancel-safe: the raw connection is owned by this future, so a cancelled dial drops it together with
    // the in-flight TLS handshake.
    async fn tls_dial(
        &self,
        ctx: &CancellationToken,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<tokio_rustls::client::TlsStream<Box<dyn murmur_std_compat::net::Conn>>> {
        // The h1/h2 DoH path canonicalizes the URL to host:port (the scheme's default) before
        // the dialer sees it; this hand-rolled TLS conn must do that itself, or a portless
        // endpoint dials as a bare host.
        let host = self.url.host_str().ok_or_else(|| anyhow!("missing host in {}", self.url))?;
        let port = self.url.port_or_known_default().unwrap_or(443);
        let raw_conn = self.dialer.dial_context(ctx, "tcp", &format!("{host}:{port}")).await?;
        let server_name =
            ServerName::try_from(host.to_owned()).map_err(|err| anyhow!("invalid server name: {err}"))?.to_owned();

        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let deadline = tokio::time::sleep(DIAL_TIMEOUT);
        tokio::pin!(deadline);

        tokio::select! {
            biased;
            result = connector.connect(server_name, raw_conn) => result.map_err(anyhow::Error::from),
            () = ctx.cancelled() => Err(anyhow!("context canceled")),
            () = &mut deadline => Err(anyhow!("tls dial timed out after {DIAL_TIMEOUT:?}")),
        }
    }

    /// Runs the QUIC/TLS probe race then builds the
    /// HTTP/3 transport over the winning bootstrap address.
    async fn create_transport_h3(
        &self,
        ctx: &CancellationToken,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<Arc<ActiveClient>> {
        if !self.supports_h3() {
            return Err(anyhow!("HTTP3 support is not enabled"));
        }

        let addr = self.probe_h3(ctx, Arc::clone(&tls_config)).await?;

        let packet_conn = self.dialer.listen_packet(ctx, "udp", &addr.to_string()).await?;
        let host = self.url.host_str().unwrap_or_default().to_owned();
        let connection = open_quic_connection(Arc::from(packet_conn), addr, &host, tls_config).await?;

        let h3_conn = h3_quinn::Connection::new(connection);
        let (mut driver, send_request) =
            h3::client::new(h3_conn).await.map_err(|err| anyhow!("h3 handshake failed: {err}"))?;
        tokio::spawn(async move {
            let _ = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        Ok(Arc::new(ActiveClient::H3(AsyncMutex::new(send_request))))
    }

    async fn dial_quic(
        &self,
        ctx: &CancellationToken,
        addr: std::net::SocketAddr,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<quinn::Connection> {
        let packet_conn = self.dialer.listen_packet(ctx, "udp", &addr.to_string()).await?;
        let host = self.url.host_str().unwrap_or_default().to_owned();
        open_quic_connection(Arc::from(packet_conn), addr, &host, tls_config).await
    }

    // cancel-safe: both probe futures own the connections they open, so the losing branch is dropped
    // along with whatever it had opened.
    async fn probe_h3(
        &self,
        ctx: &CancellationToken,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<std::net::SocketAddr> {
        let host = self.url.host_str().ok_or_else(|| anyhow!("missing host in {}", self.url))?;
        let port = self.url.port_or_known_default().unwrap_or(443);
        let raw_conn = self
            .dialer
            .dial_context(ctx, "udp", &format!("{host}:{port}"))
            .await
            .map_err(|err| anyhow!("failed to dial: {err}"))?;
        let remote = raw_conn.remote_addr()?;
        let addr = super::doq::socket_addr_of(remote.as_ref())?;
        raw_conn.close().ok();

        if self.supports_h3() && !self.supports_http() {
            return Ok(addr);
        }

        let mut probe_tls_config = (*tls_config).clone();
        probe_tls_config.resumption = rustls::client::Resumption::disabled();
        let probe_tls_config = Arc::new(probe_tls_config);

        let quic_fut = self.probe_quic(ctx, addr, Arc::clone(&probe_tls_config));
        let tls_fut = self.probe_tls(ctx, probe_tls_config);
        tokio::pin!(quic_fut);
        tokio::pin!(tls_fut);

        tokio::select! {
            quic_result = &mut quic_fut => match quic_result {
                Err(err) => Err(err),
                Ok(()) => Ok(addr),
            },
            tls_result = &mut tls_fut => match tls_result {
                Err(err) => {
                    debugln!("probing TLS: {err}");
                    Ok(addr)
                }
                Ok(()) => Err(anyhow!("TLS was faster than QUIC, prefer it")),
            },
        }
    }

    // cancel-safe: the QUIC connection it opens is closed before returning, and a cancelled probe closes
    // it the same way.
    async fn probe_quic(
        &self,
        ctx: &CancellationToken,
        addr: std::net::SocketAddr,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<()> {
        let start = Instant::now();
        let conn = self
            .dial_quic(ctx, addr, tls_config)
            .await
            .map_err(|err| anyhow!("opening QUIC connection to {}: {err}", self.address()))?;
        conn.close(quinn::VarInt::from_u32(0), b"");
        debugln!("elapsed on establishing a QUIC connection: {:?}", start.elapsed());
        Ok(())
    }

    // cancel-safe: the TLS stream it opens is dropped before returning, and a cancelled probe drops it the
    // same way.
    async fn probe_tls(&self, ctx: &CancellationToken, tls_config: Arc<rustls::ClientConfig>) -> Result<()> {
        let start = Instant::now();
        let stream = self.tls_dial(ctx, tls_config).await.map_err(|err| anyhow!("opening TLS connection: {err}"))?;
        drop(stream);
        debugln!("elapsed on establishing a TLS connection: {:?}", start.elapsed());
        Ok(())
    }

    fn supports_h3(&self) -> bool {
        self.supported_http_versions().contains(&HTTPVersion::HTTP_VERSION3)
    }

    fn supports_http(&self) -> bool {
        self.supported_http_versions()
            .iter()
            .any(|v| *v == HTTPVersion::HTTP_VERSION11 || *v == HTTPVersion::HTTP_VERSION2)
    }

    fn supported_http_versions(&self) -> Vec<HTTPVersion> {
        if self.http_versions.is_empty() {
            default_http_versions()
        } else {
            self.http_versions.clone()
        }
    }
}

fn is_zero_rtt_rejected(err: &anyhow::Error) -> bool {
    err.to_string().contains("0-RTT rejected")
}
