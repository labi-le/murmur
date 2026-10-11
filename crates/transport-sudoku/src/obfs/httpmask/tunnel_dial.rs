//! Deviation: the HTTP transport pools idle HTTP connections and opportunistically
//! negotiates HTTP/2 over TLS.
//!
//! This crate has no `tower-service` dependency available (not pinned
//! in `Cargo.toml`) to drive `hyper_util::client::legacy::Client`'s connector trait, so
//! `TunnelHttpTransport::send` dials a fresh socket per request (still speculatively pre-warmed by
//! `PreconnectDialer`'s own prepared-socket pool) and always speaks HTTP/1.1. This preserves every
//! request/retry/session code path; it only drops HTTP connection reuse and HTTP/2 as a
//! performance optimization. `close_idle_connections`/`TunnelHttpTransport::clear_idle` are
//! therefore true no-ops on the (nonexistent) HTTP-level pool, forwarded only to the dialer's pool.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio_util::sync::CancellationToken;
use url::Url;

use murmur_common_net::io::Stream;
use murmur_component::dialer::options::NetDialer;
use murmur_component_ca as ca;
use murmur_component_tls::utls::{Config as TlsConfig, VERSION_TLS12};

use super::pathroot::join_path_root;
use super::tunnel_api::{apply_tunnel_headers, TunnelDialOptions, TunnelMode};
use super::tunnel_preconnect::{new_preconnect_dialer, PreconnectDialer};
use super::tunnel_retry::{
    close_idle_connections, is_dial_error, is_retryable_http_transport_error, is_retryable_status_code, next_backoff,
    status_error, wait_retry,
};

pub(crate) const TUNNEL_EARLY_DATA_QUERY_KEY: &str = "ed";
pub(crate) const TUNNEL_EARLY_DATA_HEADER: &str = "X-Sudoku-Early";
pub(crate) const TUNNEL_STREAM_EOF_HEADER: &str = "X-Sudoku-Stream-EOF";
pub(crate) const TUNNEL_UPLOAD_SEQUENCE_QUERY: &str = "seq";
pub(crate) const TUNNEL_UPLOAD_SEQUENCE_CAP: &str = "upload-seq";
pub(crate) const TUNNEL_PRECONNECT_COUNT: i32 = 3;
#[allow(
    dead_code,
    reason = "the tunnel TLS handshake timeout constant, assigned only to a stdlib HTTP transport this crate's simplified per-request dial (module doc above) never builds"
)]
pub(crate) const TUNNEL_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub(crate) struct AuthorizeResponse {
    pub(crate) token: String,
    pub(crate) early_payload: Vec<u8>,
}

pub(crate) fn canonical_header_host(url_host: &str, scheme: &str) -> String {
    let Ok((host, port)) = split_host_port(url_host) else {
        return url_host.to_owned();
    };

    let default_port = match scheme {
        "https" => "443",
        "http" => "80",
        _ => "",
    };
    if default_port.is_empty() || port != default_port {
        return url_host.to_owned();
    }

    if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    }
}

pub(crate) const fn session_preconnect_count() -> i32 {
    TUNNEL_PRECONNECT_COUNT
}

pub(crate) fn parse_authorize_response(body: &[u8]) -> Result<AuthorizeResponse> {
    let text = String::from_utf8_lossy(body);
    let s = text.trim();
    let Some(idx) = s.find("token=") else {
        return Err(anyhow!("missing token"));
    };
    let Some(s) = s.get(idx + "token=".len()..) else {
        return Err(anyhow!("missing token"));
    };
    if s.is_empty() {
        return Err(anyhow!("empty token"));
    }

    let token: String = s.chars().take_while(|&c| c.is_ascii_alphanumeric() || c == '-' || c == '_').collect();
    if token.is_empty() {
        return Err(anyhow!("empty token"));
    }

    let mut out = AuthorizeResponse { token, early_payload: Vec::new() };
    let early_line = find_authorize_field(body, "ed=");
    if !early_line.is_empty() {
        out.early_payload = URL_SAFE_NO_PAD
            .decode(&early_line)
            .map_err(|err| anyhow!("decode early authorize payload failed: {err}"))?;
    }
    if find_authorize_field(body, "cap=") != TUNNEL_UPLOAD_SEQUENCE_CAP {
        return Err(anyhow!("server does not support HTTPMask v0.5 upload sequencing"));
    }
    Ok(out)
}

fn find_authorize_field(body: &[u8], prefix: &str) -> String {
    let text = String::from_utf8_lossy(body);
    for line in text.trim().lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(prefix) {
            return rest.trim().to_owned();
        }
    }
    String::new()
}

pub(crate) fn set_early_data_query(raw_url: &str, payload: &[u8]) -> Result<String> {
    if payload.is_empty() {
        return Ok(raw_url.to_owned());
    }
    let mut u = Url::parse(raw_url)?;
    let encoded = URL_SAFE_NO_PAD.encode(payload);
    let existing: Vec<(String, String)> = u
        .query_pairs()
        .filter(|(k, _)| k != TUNNEL_EARLY_DATA_QUERY_KEY)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    {
        let mut pairs = u.query_pairs_mut();
        pairs.clear();
        for (k, v) in &existing {
            pairs.append_pair(k, v);
        }
        pairs.append_pair(TUNNEL_EARLY_DATA_QUERY_KEY, &encoded);
    }
    Ok(u.to_string())
}

pub(crate) fn parse_early_data_query(u: &Url) -> Result<Vec<u8>> {
    let val = u
        .query_pairs()
        .find(|(k, _)| k == TUNNEL_EARLY_DATA_QUERY_KEY)
        .map(|(_, v)| v.trim().to_owned())
        .unwrap_or_default();
    if val.is_empty() {
        return Ok(Vec::new());
    }
    Ok(URL_SAFE_NO_PAD.decode(&val)?)
}

pub(crate) struct SessionDialInfo {
    pub(crate) client: Arc<TunnelHttpTransport>,
    pub(crate) owner: Option<Arc<TunnelHttpTransport>>,
    pub(crate) push_url: String,
    pub(crate) pull_url: String,
    pub(crate) fin_url: String,
    pub(crate) close_url: String,
    pub(crate) header_host: String,
}

pub(crate) fn upload_url(raw_url: &str, sequence: u64) -> Result<String> {
    let mut u = Url::parse(raw_url)?;
    u.query_pairs_mut().append_pair(TUNNEL_UPLOAD_SEQUENCE_QUERY, &sequence.to_string());
    Ok(u.to_string())
}

/// The tunnel HTTP transport. See the module deviation note: no HTTP-level connection pool.
pub(crate) struct TunnelHttpTransport {
    pub(crate) dialer: PreconnectDialer,
    scheme: String,
}

impl TunnelHttpTransport {
    pub(crate) fn close(&self) {
        self.dialer.close();
    }

    pub(crate) fn clear_idle(&self) {
        self.dialer.clear_idle();
    }

    /// Sends one request through this transport: dial, single HTTP/1.1
    /// request/response, then let the connection drop.
    // cancel-safe: a cancelled request abandons only the in-flight exchange; the connection is
    // dial-scoped and closes when the sender drops.
    pub(crate) async fn send(&self, req: http::Request<Full<Bytes>>) -> Result<http::Response<Incoming>> {
        let ctx = CancellationToken::new();
        let authority = req.uri().authority().map(|a| a.as_str().to_owned()).unwrap_or_default();
        let raw: Box<dyn Stream> = if self.scheme == "https" {
            self.dialer.dial_tls_context(&ctx, "tcp", &authority).await?
        } else {
            self.dialer.dial_context(&ctx, "tcp", &authority).await?
        };

        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(raw)).await?;
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });

        // `req.uri()` carries the full absolute URL (scheme + authority) so `dial_context` above
        // has something to connect to; hyper's HTTP/1.1 client conn writes whatever is in
        // `req.uri()` verbatim as the request-target, which for an absolute-form `Uri` means the
        // wire request line becomes `GET http://host/path HTTP/1.1` instead of origin-form `GET
        // /path HTTP/1.1`. A plain HTTP client strips this down to origin-form automatically
        // for a direct (non-proxy) request; restore that here so the server's path-based routing
        // sees the plain path instead of the whole URL.
        let (mut parts, body) = req.into_parts();
        let path_and_query = parts.uri.path_and_query().map_or("/", |pq| pq.as_str()).to_owned();
        parts.uri = path_and_query.parse()?;
        let req = http::Request::from_parts(parts, body);

        let resp = sender.send_request(req).await?;
        tokio::spawn(async move {
            let _ = conn_task.await;
            drop(sender);
        });
        Ok(resp)
    }
}

pub(crate) struct TunnelHttpClient {
    pub(crate) transport: Arc<TunnelHttpTransport>,
}

#[derive(Clone)]
pub(crate) struct HttpClientTarget {
    pub(crate) scheme: String,
    pub(crate) url_host: String,
    pub(crate) header_host: String,
}

pub(crate) async fn new_http_client(
    server_address: &str,
    tls_enabled: bool,
    host_override: &str,
    dial: Option<Arc<dyn NetDialer>>,
    _max_idle_conns: i32,
) -> Result<(TunnelHttpClient, HttpClientTarget)> {
    let Some(dial) = dial else {
        return Err(anyhow!("httpmask: DialContext is nil"));
    };
    let (scheme, url_host, dial_addr, server_name) =
        normalize_http_dial_target(server_address, tls_enabled, host_override)?;

    let dialer_tls_config = if scheme == "https" {
        let TlsConfig {
            rand,
            time,
            certificates,
            get_certificate,
            get_client_certificate,
            verify_peer_certificate,
            verify_connection,
            root_cas,
            client_auth,
            client_cas,
            insecure_skip_verify,
            cipher_suites,
            session_tickets_disabled,
            max_version,
            curve_preferences,
            renegotiation,
            key_log_writer,
            encrypted_client_hello_config_list,
            encrypted_client_hello_rejection_verify,
            encrypted_client_hello_keys,
            get_encrypted_client_hello_keys,
            session_id_generator,
            ..
        } = TlsConfig::default();
        let ca::config::Option { fingerprint, name_cert_verify, zero_trust, certificate, private_key, .. } =
            ca::config::Option::default();
        let tls_config = ca::config::get_tls_config(ca::config::Option {
            tls_config: Some(TlsConfig {
                rand,
                time,
                certificates,
                get_certificate,
                get_client_certificate,
                verify_peer_certificate,
                verify_connection,
                root_cas,
                next_protos: vec!["h2".to_owned(), "http/1.1".to_owned()],
                server_name: server_name.clone(),
                client_auth,
                client_cas,
                insecure_skip_verify,
                cipher_suites,
                session_tickets_disabled,
                min_version: VERSION_TLS12,
                max_version,
                curve_preferences,
                renegotiation,
                key_log_writer,
                encrypted_client_hello_config_list,
                encrypted_client_hello_rejection_verify,
                encrypted_client_hello_keys,
                get_encrypted_client_hello_keys,
                session_id_generator,
            }),
            fingerprint,
            name_cert_verify,
            zero_trust,
            certificate,
            private_key,
        })?;
        Some(Arc::new(tls_config))
    } else {
        None
    };

    let dialer = new_preconnect_dialer(url_host.clone(), dial_addr, server_name, dialer_tls_config, dial);
    let transport = Arc::new(TunnelHttpTransport { dialer, scheme: scheme.clone() });
    let header_host = canonical_header_host(&url_host, &scheme);
    Ok((TunnelHttpClient { transport }, HttpClientTarget { scheme, url_host, header_host }))
}

pub(crate) async fn dial_session(
    ctx: &CancellationToken,
    server_address: &str,
    opts: &TunnelDialOptions,
    mode: TunnelMode,
) -> Result<SessionDialInfo> {
    let (http_client, target) =
        new_http_client(server_address, opts.tls_enabled, &opts.host_override, opts.dial_context.clone(), 32).await?;

    let mut info = match dial_session_with_client(ctx, Arc::clone(&http_client.transport), target, mode, opts, 0).await
    {
        Ok(info) => info,
        Err(err) => {
            http_client.transport.close();
            return Err(err);
        }
    };
    info.owner = Some(http_client.transport);
    Ok(info)
}

fn build_authorize_request(url: &str, header_host: &str, mode: TunnelMode) -> Result<http::Request<Full<Bytes>>> {
    let mut req = http::Request::builder().method(http::Method::GET).uri(url).body(Full::new(Bytes::new()))?;
    apply_tunnel_headers(req.headers_mut(), header_host, mode);
    req.headers_mut().insert(http::header::HOST, http::HeaderValue::from_str(header_host)?);
    Ok(req)
}

pub(crate) async fn dial_session_with_client(
    ctx: &CancellationToken,
    client: Arc<TunnelHttpTransport>,
    target: HttpClientTarget,
    mode: TunnelMode,
    opts: &TunnelDialOptions,
    preconnect_count: i32,
) -> Result<SessionDialInfo> {
    let header_host = target.header_host.clone();
    let scheme = target.scheme.clone();
    let url_host = target.url_host.clone();

    let mut authorize_url = build_url(&scheme, &url_host, &join_path_root(&opts.path_root, "/session"), "");
    if let Some(early) = &opts.early_handshake {
        if !early.request_payload.is_empty() {
            authorize_url = set_early_data_query(&authorize_url, &early.request_payload)?;
        }
    }

    let cancel_preconnect = client.dialer.preconnect(ctx, scheme == "https", preconnect_count);

    let mut req = build_authorize_request(&authorize_url, &header_host, mode)?;
    let mut backoff = Duration::from_millis(50);
    let mut resp = None;
    for attempt in 0..3 {
        match client.send(req).await {
            Ok(response) => {
                resp = Some(response);
                break;
            }
            Err(err) => {
                if attempt == 2 || !is_retryable_http_transport_error(&err) {
                    cancel_preconnect();
                    return Err(err);
                }
                close_idle_connections(&client).await;
                if let Err(retry_err) = wait_retry(ctx, None, backoff).await {
                    cancel_preconnect();
                    return Err(retry_err);
                }
                backoff = next_backoff(backoff, Duration::from_millis(50), Duration::from_millis(500));
                req = build_authorize_request(&authorize_url, &header_host, mode)?;
            }
        }
    }
    cancel_preconnect();

    let Some(resp) = resp else {
        return Err(anyhow!("httpmask: authorization returned no response"));
    };
    let status = resp.status();
    let body = limited_body(resp, 4 * 1024).await?;
    if status != http::StatusCode::OK {
        return Err(anyhow!(
            "{} authorize bad status: {status} ({})",
            mode.as_str(),
            String::from_utf8_lossy(&body).trim()
        ));
    }

    let auth_resp =
        parse_authorize_response(&body).map_err(|err| anyhow!("{} authorize failed: {err}", mode.as_str()))?;
    let token = auth_resp.token;
    if token.is_empty() {
        return Err(anyhow!("{} authorize empty token", mode.as_str()));
    }
    if let Some(early) = &opts.early_handshake {
        if !auth_resp.early_payload.is_empty() {
            if let Some(handle_response) = &early.handle_response {
                handle_response(&auth_resp.early_payload)?;
            }
        }
    }

    let mut escaped = String::new();
    for (k, v) in url::form_urlencoded::byte_serialize(token.as_bytes()).map(|s| ("", s)) {
        let _ = k;
        let _ = write!(escaped, "{v}");
    }
    let push_url =
        build_url(&scheme, &url_host, &join_path_root(&opts.path_root, "/api/v1/upload"), &format!("token={escaped}"));
    let pull_url =
        build_url(&scheme, &url_host, &join_path_root(&opts.path_root, "/stream"), &format!("token={escaped}"));
    let fin_url = build_url(
        &scheme,
        &url_host,
        &join_path_root(&opts.path_root, "/api/v1/upload"),
        &format!("token={escaped}&fin=1"),
    );
    let close_url = build_url(
        &scheme,
        &url_host,
        &join_path_root(&opts.path_root, "/api/v1/upload"),
        &format!("token={escaped}&close=1"),
    );

    Ok(SessionDialInfo { client, owner: None, push_url, pull_url, fin_url, close_url, header_host })
}

fn build_url(scheme: &str, host: &str, path: &str, query: &str) -> String {
    if query.is_empty() {
        format!("{scheme}://{host}{path}")
    } else {
        format!("{scheme}://{host}{path}?{query}")
    }
}

async fn limited_body(resp: http::Response<Incoming>, limit: usize) -> Result<Bytes> {
    let collected = resp.collect().await?;
    let bytes = collected.to_bytes();
    if bytes.len() > limit {
        Ok(bytes.slice(0..limit))
    } else {
        Ok(bytes)
    }
}

pub(crate) async fn send_session_control(
    client: &TunnelHttpTransport,
    control_url: &str,
    header_host: &str,
    mode: TunnelMode,
) -> Result<()> {
    const MAX_ATTEMPTS: i32 = 3;

    if control_url.is_empty() || header_host.is_empty() {
        return Err(anyhow!("session control endpoint is empty"));
    }

    let close_ctx = CancellationToken::new();
    let deadline_guard = close_ctx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        deadline_guard.cancel();
    });

    let mut last_err: Option<anyhow::Error> = None;
    let mut backoff = Duration::from_millis(50);
    for attempt in 0..MAX_ATTEMPTS {
        let req = build_authorize_request(control_url, header_host, mode)?;
        let req = http::Request::from_parts(
            {
                let (mut parts, _) = req.into_parts();
                parts.method = http::Method::POST;
                parts
            },
            Full::new(Bytes::new()),
        );

        match client.send(req).await {
            Err(err) => {
                if !close_ctx.is_cancelled()
                    && (is_dial_error(&err) || is_retryable_http_transport_error(&err))
                    && attempt + 1 < MAX_ATTEMPTS
                {
                    wait_retry(&close_ctx, None, backoff).await?;
                    backoff *= 2;
                    last_err = Some(err);
                    continue;
                }
                return Err(err);
            }
            Ok(resp) => {
                let status = resp.status();
                let _ = limited_body(resp, 4 * 1024).await;
                if status != http::StatusCode::OK {
                    if status == http::StatusCode::FORBIDDEN
                        || status == http::StatusCode::NOT_FOUND
                        || status == http::StatusCode::GONE
                    {
                        return Ok(());
                    }
                    let err = status_error(status, status.canonical_reason().unwrap_or(""));
                    if is_retryable_status_code(status) && attempt + 1 < MAX_ATTEMPTS {
                        wait_retry(&close_ctx, None, backoff).await?;
                        backoff *= 2;
                        last_err = Some(err);
                        continue;
                    }
                    return Err(err);
                }
                return Ok(());
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("session control failed")))
}

pub(crate) async fn best_effort_close_session(
    client: &TunnelHttpTransport,
    close_url: &str,
    header_host: &str,
    mode: TunnelMode,
) {
    let _ = send_session_control(client, close_url, header_host, mode).await;
}

fn normalize_http_dial_target(
    server_address: &str,
    tls_enabled: bool,
    host_override: &str,
) -> Result<(String, String, String, String)> {
    let (host, port) =
        split_host_port(server_address).map_err(|err| anyhow!("invalid server address {server_address:?}: {err}"))?;

    let (server_name, url_host) = if host_override.is_empty() {
        (host.clone(), join_host_port(&host, &port))
    } else {
        let (override_host, override_port) =
            split_host_port(host_override).unwrap_or_else(|_| (host_override.to_owned(), String::new()));
        let effective_port = if override_port.is_empty() { &port } else { &override_port };
        let url_host = join_host_port(&override_host, effective_port);
        (override_host, url_host)
    };

    let scheme = if tls_enabled { "https" } else { "http" }.to_owned();
    let dial_addr = join_host_port(&host, &port);
    Ok((scheme, url_host, dial_addr, trim_port_for_host(&server_name)))
}

fn trim_port_for_host(host: &str) -> String {
    split_host_port(host).map_or_else(|_| host.to_owned(), |(h, _)| h)
}

fn split_host_port(hostport: &str) -> Result<(String, String)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| anyhow!("address {hostport}: missing ']' in address"))?;
        let (host, tail) = rest.split_at(end);
        let remainder = tail.strip_prefix(']').ok_or_else(|| anyhow!("address {hostport}: missing ']' in address"))?;
        let port = remainder.strip_prefix(':').ok_or_else(|| anyhow!("address {hostport}: missing port in address"))?;
        return Ok((host.to_owned(), port.to_owned()));
    }
    let idx = hostport.rfind(':').ok_or_else(|| anyhow!("address {hostport}: missing port in address"))?;
    let (host, tail) = hostport.split_at(idx);
    let port = tail.strip_prefix(':').ok_or_else(|| anyhow!("address {hostport}: missing port in address"))?;
    if port.contains(':') {
        return Err(anyhow!("address {hostport}: too many colons in address"));
    }
    Ok((host.to_owned(), port.to_owned()))
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_header_host_strips_default_port() {
        assert_eq!(canonical_header_host("example.com:443", "https"), "example.com");
        assert_eq!(canonical_header_host("example.com:8443", "https"), "example.com:8443");
        assert_eq!(canonical_header_host("example.com:80", "http"), "example.com");
        assert_eq!(canonical_header_host("[::1]:443", "https"), "[::1]");
    }

    #[test]
    fn upload_url_appends_sequence() {
        let url = upload_url("https://example.com/api/v1/upload?token=abc", 7).expect("upload url");
        assert!(url.contains("seq=7"));
        assert!(url.contains("token=abc"));
    }

    #[test]
    fn parse_authorize_response_requires_upload_sequence_support() {
        let body = b"token=abc123\ncap=other";
        let err = parse_authorize_response(body).unwrap_err();
        assert!(err.to_string().contains("upload sequencing"));
    }

    #[test]
    fn parse_authorize_response_extracts_token_and_early_payload() {
        let payload = URL_SAFE_NO_PAD.encode(b"hi");
        let body = format!("token=abc123\ned={payload}\ncap=upload-seq");
        let parsed = parse_authorize_response(body.as_bytes()).expect("parse");
        assert_eq!(parsed.token, "abc123");
        assert_eq!(parsed.early_payload, b"hi");
    }

    #[tokio::test]
    async fn send_session_control_retries_transport_eof() {
        use std::sync::atomic::{AtomicI32, Ordering};

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        use murmur_component::dialer::options::NetDialerFunc;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let addr = listener.local_addr().expect("listener addr");

        let calls = Arc::new(AtomicI32::new(0));
        let calls_task = Arc::clone(&calls);
        tokio::spawn(async move {
            for close_before_response in [true, false] {
                let (mut stream, _) = listener.accept().await.expect("accept");
                calls_task.fetch_add(1, Ordering::SeqCst);

                let mut request = Vec::new();
                let mut chunk = [0u8; 512];
                loop {
                    let n = stream.read(&mut chunk).await.expect("read control request");
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..n]);
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }

                if close_before_response {
                    drop(stream);
                    continue;
                }

                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                stream.write_all(response.as_bytes()).await.expect("write control response");
            }
        });

        let dial = Arc::new(NetDialerFunc::new(move |_ctx, _network, _address| {
            Box::pin(async move {
                let stream = TcpStream::connect(addr).await?;
                let stream: Box<dyn Stream> = Box::new(stream);
                Ok(stream)
            })
        }));

        let dialer = new_preconnect_dialer(addr.to_string(), addr.to_string(), String::new(), None, dial);
        let transport = TunnelHttpTransport { dialer, scheme: "http".to_owned() };

        let control_url = format!("http://{addr}/api/v1/upload?token=session&fin=1");
        send_session_control(&transport, &control_url, "example", TunnelMode::Stream)
            .await
            .expect("send session control");
        assert_eq!(calls.load(Ordering::SeqCst), 2, "control calls");
    }
}
