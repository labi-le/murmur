//! One-shot HTTP/1.1 client helpers built on hyper's low-level connection API.
//!
//! DEVIATION: with no `tower-service`-driven `hyper_util::client::legacy::Client` (not pinned in
//! `Cargo.toml`) and no ALPN switch, every call dials a fresh connection and speaks HTTP/1.1, so
//! `DisableKeepAlives`, `MaxIdleConns` and `IdleConnTimeout` are dropped.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::sync::CancellationToken;
use url::Url;

use murmur_common_net::io::{OldConnAsStream, Stream};
use murmur_component::dialer;
use murmur_component_ca as ca;
use murmur_component_tls::utls;
use murmur_constant::adapters::Dialer as ConstantDialer;
use murmur_listener_inner::tcp::{get_tunnel, handle_tcp};

static UA: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new(String::new()));

pub fn ua() -> String {
    UA.read().clone()
}

pub fn set_ua(new_ua: String) {
    *UA.write() = new_ua;
}

#[expect(
    clippy::implicit_hasher,
    reason = "the map is the caller's own request header map; generalizing this public signature over a hasher would change every caller for no behavioral gain"
)]
pub async fn http_request(
    ctx: &CancellationToken,
    url: &str,
    method: &str,
    header: &HashMap<String, Vec<String>>,
    body: std::option::Option<&mut (dyn AsyncRead + Send + Unpin)>,
    options: &[Option],
) -> Result<hyper::Response<Incoming>> {
    let mut opt = Opt::default();
    for o in options {
        o(&mut opt);
    }
    let initial_url = Url::parse(url)?;
    let authorization = basic_authorization(&initial_url);

    let mut method = method.to_uppercase();
    let mut body_bytes = Vec::new();
    if let Some(reader) = body {
        reader.read_to_end(&mut body_bytes).await?;
    }

    // Follow `Location` until ten requests have been sent.
    let mut requests = 0usize;
    let mut previous: std::option::Option<Url> = None;
    let mut url_res = initial_url.clone();
    loop {
        let keep_credentials = keeps_sensitive_headers(&initial_url, &url_res);
        let headers: Vec<(&str, &str)> = header
            .iter()
            .filter(|(name, _)| keep_credentials || !is_sensitive_header(name.as_str()))
            .flat_map(|(name, values)| values.iter().map(move |value| (name.as_str(), value.as_str())))
            .collect();
        let referer = previous.as_ref().and_then(|last| referer_for_url(last, &url_res));
        let response = send_once(
            ctx,
            &opt,
            &method,
            &url_res,
            &headers,
            if keep_credentials { authorization.as_deref() } else { None },
            referer.as_deref(),
            &body_bytes,
        )
        .await?;
        requests += 1;

        let Some((next_method, include_body)) = redirect_behavior(&method, response.status().as_u16()) else {
            return Ok(response);
        };
        let location =
            response.headers().get(http::header::LOCATION).map(|location| location.to_str().map(ToOwned::to_owned));
        let Some(location) = location else {
            return Ok(response);
        };
        let location = location.map_err(|err| anyhow!("failed to parse Location: {err}"))?;
        if requests >= DEFAULT_CHECK_REDIRECT_LIMIT {
            return Err(anyhow!("stopped after {DEFAULT_CHECK_REDIRECT_LIMIT} redirects"));
        }
        let next = url_res.join(&location).map_err(|err| anyhow!("failed to parse Location {location}: {err}"))?;

        method = next_method;
        if !include_body {
            body_bytes.clear();
        }
        previous = Some(std::mem::replace(&mut url_res, next));
    }
}

/// Sends one request of the chain on its own connection.
#[allow(clippy::too_many_arguments)]
async fn send_once(
    ctx: &CancellationToken,
    opt: &Opt,
    method: &str,
    url_res: &Url,
    header: &[(&str, &str)],
    authorization: std::option::Option<&str>,
    referer: std::option::Option<&str>,
    body_bytes: &[u8],
) -> Result<hyper::Response<Incoming>> {
    // An HTTP client sends an origin-form request target and a `Host` header. Handing hyper a
    // full URL makes it send an absolute-form target instead, which is reserved for requests to a
    // proxy: origin servers answer 400. The `Host` header goes missing with it, which alone is
    // enough for an HTTP/1.1 server to reject the request.
    let request_target = match url_res.query() {
        Some(query) => format!("{}?{query}", url_res.path()),
        None => url_res.path().to_owned(),
    };
    let mut req_builder = http::Request::builder().method(method).uri(request_target.as_str());
    for (name, value) in header {
        req_builder = req_builder.header(*name, *value);
    }
    let mut request = req_builder.body(Full::new(Bytes::copy_from_slice(body_bytes)))?;

    if !request.headers().contains_key(http::header::USER_AGENT) {
        request.headers_mut().insert(http::header::USER_AGENT, ua().parse()?);
    }

    if !request.headers().contains_key(http::header::HOST) {
        let default_port = if url_res.scheme() == "https" { 443 } else { 80 };
        let authority = match url_res.port() {
            Some(port) if port != default_port => format!("{}:{port}", url_res.host_str().unwrap_or_default()),
            _ => url_res.host_str().unwrap_or_default().to_owned(),
        };
        request.headers_mut().insert(http::header::HOST, authority.parse()?);
    }

    if let Some(authorization) = authorization {
        request.headers_mut().insert(http::header::AUTHORIZATION, authorization.parse()?);
    }

    if let Some(referer) = referer {
        request.headers_mut().insert(http::header::REFERER, referer.parse()?);
    }

    let mut tls_config = ca::config::get_tls_config(opt.ca_option.clone())?;

    let host = url_res.host_str().ok_or_else(|| anyhow!("missing host in url: {url_res}"))?;
    let scheme = url_res.scheme();
    let port = url_res.port_or_known_default().unwrap_or(if scheme == "https" { 443 } else { 80 });
    let address = format!("{host}:{port}");

    let raw = dial_transport(ctx, opt, "tcp", &address).await?;

    let conn: Box<dyn Stream> = if scheme == "https" {
        if tls_config.server_name.is_empty() {
            tls_config.server_name = host.to_owned();
        }
        let tls_conn = utls::client(raw, Arc::new(tls_config));
        tls_conn.handshake_context(ctx).await?;
        Box::new(tls_conn)
    } else {
        raw
    };

    let io = TokioIo::new(conn);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await.map_err(transport_error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    tokio::select! {
        result = sender.send_request(request) => Ok(result.map_err(transport_error)?),
        () = ctx.cancelled() => Err(anyhow!("context canceled")),
    }
}

/// the transport reports the error underneath itself (end of stream for a peer that closes the
/// connection) where hyper labels every such failure "connection error" and keeps the real error as
/// its source.
fn transport_error(err: hyper::Error) -> anyhow::Error {
    use std::error::Error as _;

    match err.source() {
        Some(cause) => anyhow::Error::msg(cause.to_string()),
        None => anyhow::Error::new(err),
    }
}

/// The error text: `<Op> "<url>": <inner>`, where `Op` is the method with only its
/// first letter upper-cased.
///
/// hyper reports the transport error bare, so a caller whose message reaches the wire (the
/// updater's download errors) keeps the text with this.
#[must_use]
pub fn url_error_text(method: &str, url: &str, err: &anyhow::Error) -> String {
    let mut op = method.to_ascii_lowercase();
    if let Some(first) = op.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    format!("{op} \"{url}\": {err}")
}

/// Stops the redirect chain once ten requests have been sent.
const DEFAULT_CHECK_REDIRECT_LIMIT: usize = 10;

/// The method and body of the next request, or `None` for a non-redirect.
fn redirect_behavior(method: &str, status: u16) -> std::option::Option<(String, bool)> {
    match status {
        301..=303 => {
            let method = if method == "GET" || method == "HEAD" { method.to_owned() } else { "GET".to_owned() };
            Some((method, false))
        }
        307 | 308 => Some((method.to_owned(), true)),
        _ => None,
    }
}

/// The first request's credentials survive only within its domain.
fn keeps_sensitive_headers(initial: &Url, dest: &Url) -> bool {
    is_domain_or_subdomain(dest.host_str().unwrap_or_default(), initial.host_str().unwrap_or_default())
}

/// Whether `sub` is `parent` or a subdomain of it, over already-canonicalised hosts.
fn is_domain_or_subdomain(sub: &str, parent: &str) -> bool {
    if sub == parent {
        return true;
    }
    !sub.contains(':')
        && !sub.contains('%')
        && !parent.is_empty()
        && sub.len() > parent.len()
        && sub.ends_with(parent)
        && sub.as_bytes().get(sub.len() - parent.len() - 1) == Some(&b'.')
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "www-authenticate" | "cookie" | "cookie2" | "proxy-authorization" | "proxy-authenticate"
    )
}

/// Never from https down to http, and never with the userinfo in it.
fn referer_for_url(previous: &Url, next: &Url) -> std::option::Option<String> {
    if previous.scheme() == "https" && next.scheme() == "http" {
        return None;
    }
    let mut referer = previous.clone();
    let _ = referer.set_username("");
    let _ = referer.set_password(None);
    Some(referer.to_string())
}

/// The credential taken from the first request's URL userinfo.
fn basic_authorization(url_res: &Url) -> std::option::Option<String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    if url_res.username().is_empty() && url_res.password().is_none() {
        return None;
    }
    let credentials = STANDARD.encode(format!("{}:{}", url_res.username(), url_res.password().unwrap_or("")));
    Some(format!("Basic {credentials}"))
}

async fn dial_transport(ctx: &CancellationToken, opt: &Opt, network: &str, address: &str) -> Result<Box<dyn Stream>> {
    if let Some(d) = &opt.dialer {
        return d.dial_context(ctx, network, address).await;
    }
    if let Ok(conn) = handle_tcp(get_tunnel(), address, &opt.special_proxy).await {
        return Ok(Box::new(OldConnAsStream(conn)));
    }
    dialer::dialer::dial_context(ctx, network, address, Vec::new()).await
}

pub type Option = Arc<dyn Fn(&mut Opt) + Send + Sync>;

#[derive(Clone, Default)]
pub struct Opt {
    special_proxy: String,
    dialer: std::option::Option<Arc<dyn ConstantDialer>>,
    ca_option: ca::config::Option,
}

impl std::fmt::Debug for Opt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opt")
            .field("special_proxy", &self.special_proxy)
            .field("dialer", &self.dialer.is_some())
            .field("ca_option", &self.ca_option)
            .finish()
    }
}

#[must_use]
pub fn with_special_proxy(name: String) -> Option {
    Arc::new(move |opt: &mut Opt| opt.special_proxy.clone_from(&name))
}

pub fn with_dialer(dialer: Arc<dyn ConstantDialer>) -> Option {
    Arc::new(move |opt: &mut Opt| opt.dialer = Some(Arc::clone(&dialer)))
}

#[must_use]
pub fn with_ca_option(ca_option: ca::config::Option) -> Option {
    Arc::new(move |opt: &mut Opt| opt.ca_option = ca_option.clone())
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// A plaintext request reaches a real socket end to end.
    #[tokio::test]
    async fn http_request_reaches_a_real_plaintext_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.expect("read request");
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("GET / HTTP/1.1"));
            let body = b"ok";
            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            stream.write_all(response.as_bytes()).await.expect("write response head");
            stream.write_all(body).await.expect("write response body");
        });

        let ctx = CancellationToken::new();
        let response = http_request(&ctx, &format!("http://{addr}/"), "GET", &HashMap::new(), None, &[])
            .await
            .expect("http_request should succeed over the real socket");
        assert_eq!(response.status(), 200);
    }

    /// A 302 carries no body of its own, so without following it a download writes an empty file.
    #[tokio::test]
    async fn http_request_follows_a_relative_redirect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.expect("read request");
                let request = String::from_utf8_lossy(&buf[..n]);
                let (head, body) = if request.starts_with("GET /start ") {
                    ("HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "")
                } else {
                    ("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n", "payload")
                };
                stream.write_all(head.as_bytes()).await.expect("write response head");
                stream.write_all(body.as_bytes()).await.expect("write response body");
            }
        });

        let ctx = CancellationToken::new();
        let response = http_request(&ctx, &format!("http://{addr}/start"), "GET", &HashMap::new(), None, &[])
            .await
            .expect("the redirect should be followed");
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(&body[..], b"payload");
    }

    #[tokio::test]
    async fn http_request_stops_after_the_redirect_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await.expect("read request");
                let response =
                    "HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                stream.write_all(response.as_bytes()).await.expect("write response");
            }
        });

        let ctx = CancellationToken::new();
        let err = http_request(&ctx, &format!("http://{addr}/again"), "GET", &HashMap::new(), None, &[])
            .await
            .expect_err("a redirect loop has to stop");
        assert!(err.to_string().contains("stopped after"), "{err}");
    }

    #[test]
    fn url_error_text_formats_method_url_and_inner() {
        assert_eq!(
            url_error_text("GET", "http://192.0.2.1/ui.zip", &anyhow!("EOF")),
            "Get \"http://192.0.2.1/ui.zip\": EOF"
        );
        assert_eq!(url_error_text("POST", "http://192.0.2.1/x", &anyhow!("EOF")), "Post \"http://192.0.2.1/x\": EOF");
    }
}
