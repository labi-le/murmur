//! The background-peek cancellation (detecting an abandoned client connection while a backend
//! request is in flight) has no direct equivalent given this crate's per-request `Client` dial.
//!
//! It is dropped as a documented deviation (see `client.rs`'s module doc): a disconnected
//! client's in-flight backend request still runs to completion, its response simply discarded
//! once the write fails. Likewise, closing idle connections is a no-op here (there is no
//! connection pool to close), so those tracked calls are dropped too.
//!
//! `authenticate` never touches the request body (the request is handed back with its body not yet
//! read). CONNECT never reads its (normally bodyless) request body at all — any bytes sent past the
//! head stay in `BufferedConn` and flow straight into the tunnel, since the authority-form target
//! has no framing headers to declare a body. The WebSocket-upgrade path and the plain forward path
//! both stream their request body straight to the backend with `hack::pump_body` instead of
//! buffering it, and both stream the backend's response straight back (`write_response`), buffering
//! neither side in full.
//!
//! The close/keep-alive decision at the bottom of the loop applies uniformly to every response —
//! the untrusted-auth-failure response, the bad-request response, the bad-gateway response, and an
//! actual backend response alike — because `handle_conn` falls through the same close/
//! `Proxy-Connection` logic regardless of which branch produced the response. A request whose body
//! was never read (untrusted, or never attempted forwarding) is only actually safe to keep alive
//! when the client also never declared a body: the same shared logic carries the same risk for
//! those requests, and this crate matches that behaviour rather than second-guessing it with a wider
//! forced-close net.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use tokio::io::AsyncWriteExt;

use murmur_adapter_inbound::addition::{placeholder, with_in_user, Addition};
use murmur_adapter_inbound::https::new_https;
use murmur_common_net::bufconn::BufferedConn;
use murmur_common_net::io::Stream;
use murmur_common_net::{new_buffered_conn, new_extended_conn};
use murmur_component::auth::auth::{AuthStore, Authenticator};
use murmur_constant::tunnel::Tunnel;
use murmur_log::{debugln, infoln, warnln};
use murmur_std_compat::net::Conn as NetConn;

use super::client::new_client;
use super::hack::{is_chunked, read_request, Request};
use super::transfer::{body_allowed_for_status, no_response_body_expected};
use super::upgrade::{handle_upgrade, is_upgrade_request};
use super::utils::{
    decode_basic_proxy_authorization, parse_basic_proxy_authorization, remove_extra_http_host_port,
    remove_hop_by_hop_headers,
};

/// The response body: either a small, already-materialized body (every response this
/// crate builds itself) or the backend's response body, streamed straight through instead of
/// buffered (see the module doc). `content_length` on the streaming variant is the backend's own
/// declared `Content-Length`, if it sent one and did not also send `Transfer-Encoding: chunked`.
/// `None` means the backend framed its response as chunked or without a declared length, and this
/// crate re-frames it as chunked toward the client.
pub(crate) enum ResponseBody {
    Buffered(Bytes),
    Streaming { incoming: Incoming, content_length: Option<u64> },
}

impl ResponseBody {
    /// Whether this body is known, up front, to carry at least one byte (a positive declared
    /// content length).
    fn is_declared_nonempty(&self) -> bool {
        match self {
            Self::Buffered(bytes) => !bytes.is_empty(),
            Self::Streaming { content_length, .. } => content_length.is_some_and(|len| len > 0),
        }
    }
}

pub(crate) struct RawResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: ResponseBody,
    pub(crate) close: bool,
}

pub(crate) async fn handle_conn(
    c: Box<dyn Stream>,
    tunnel: Arc<dyn Tunnel>,
    store: Arc<dyn AuthStore>,
    additions: &[Addition],
) {
    let mut additions: Vec<Addition> = additions.to_vec();
    additions.push(Arc::new(placeholder));
    let in_user_idx = additions.len() - 1;

    let client = new_client(Arc::clone(&tunnel));
    let mut conn = new_buffered_conn(new_extended_conn(c));

    let authenticator = store.authenticator();
    // P2-http-inuser-spoof-after-auth (deliberately not fixed, kept for authorization parity):
    // once a connection is trusted, it stays trusted for its whole lifetime. `authenticate` below
    // still runs on every request and returns the *claimed* user even on a failed verification (the
    // wrong-password path returns the claimed user, not an empty one), and that claimed user
    // reaches `with_in_user` regardless of whether it was ever verified, because `trusted` is
    // already `true`. A client that authenticates once as `alice` can send a bogus
    // `Proxy-Authorization` claiming `bob` on the same connection and still be routed under
    // `IN-USER,bob` rules. The authorization surface is frozen, so this crate reproduces that
    // behaviour rather than silently diverging from it.
    let mut trusted = authenticator.is_none();
    let mut last_user = String::new();

    loop {
        let Ok(mut request) = read_request(&mut conn).await else { break };

        let remote_addr = conn.remote_addr().map(|addr| addr.string()).unwrap_or_default();
        let keep_alive = request
            .header
            .get("Proxy-Connection")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("keep-alive"));

        let (auth_resp, user) = authenticate(&request, authenticator.as_deref(), &remote_addr);
        if auth_resp.is_none() {
            trusted = true;
        }
        let Some(slot) = additions.get_mut(in_user_idx) else {
            warnln!("[HTTP] IN-USER addition slot {in_user_idx} is missing");
            return;
        };
        *slot = with_in_user(&user);

        let proto_major = request.proto_major;
        let proto_minor = request.proto_minor;
        let method = request.method.clone();

        let mut resp = if !trusted {
            let Some(auth_resp) = auth_resp else {
                warnln!("[HTTP] untrusted connection without an auth response");
                return;
            };
            auth_resp
        } else if method == Method::CONNECT {
            let status_line = format!(
                "HTTP/{proto_major}.{proto_minor} {} {}\r\n\r\n",
                StatusCode::OK.as_u16(),
                "Connection established"
            );
            if conn.write_all(status_line.as_bytes()).await.is_err() {
                break;
            }
            if conn.flush().await.is_err() {
                break;
            }
            let (https_conn, metadata) = new_https(request.authority.as_str(), Box::new(conn), &additions);
            tunnel.handle_tcp_conn(Box::new(murmur_common_net::io::OldConnAsStream(https_conn)), metadata).await;
            return;
        } else {
            request.request_uri.clear();

            if is_upgrade_request(&request.header) {
                handle_upgrade(conn, request, tunnel, &additions).await;
                return;
            }

            if user != last_user {
                last_user = user.clone();
            }

            remove_hop_by_hop_headers(&mut request.header);
            remove_extra_http_host_port(&mut request);

            if request.scheme.is_empty() || request.authority.is_empty() {
                response_with(StatusCode::BAD_REQUEST)
            } else {
                let (result, returned_conn) = forward(&client, conn, &request, &additions).await;
                let Some(next_conn) = returned_conn else {
                    // The connection could not be recovered (see `client.rs`'s module doc):
                    // nothing more can safely be written to it.
                    return;
                };
                conn = next_conn;
                match result {
                    Ok(mut resp) => {
                        remove_hop_by_hop_headers(&mut resp.headers);
                        resp
                    }
                    Err(_) => response_with(StatusCode::BAD_GATEWAY),
                }
            }
        };

        if !keep_alive {
            resp.close = true;
        }
        if keep_alive && resp.body.is_declared_nonempty() {
            resp.close = false;
        }

        if !resp.close {
            resp.headers.insert("Proxy-Connection", HeaderValue::from_static("keep-alive"));
            resp.headers.insert("Connection", HeaderValue::from_static("keep-alive"));
            resp.headers.insert("Keep-Alive", HeaderValue::from_static("timeout=4"));
        }

        let close = resp.close;
        if write_response(&mut conn, proto_major, proto_minor, &method, &mut resp).await.is_err() || close {
            break;
        }
    }

    let _ = conn.close();
}

/// `authenticate`. Never reads `request.body`: the caller decides afterward whether — and how
/// — the body gets read at all.
fn authenticate(
    request: &Request,
    authenticator: Option<&dyn Authenticator>,
    remote_addr: &str,
) -> (Option<RawResponse>, String) {
    let credential = parse_basic_proxy_authorization(&request.header);
    if credential.is_empty() && authenticator.is_some() {
        let mut resp = response_with(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        resp.headers.insert("Proxy-Authenticate", HeaderValue::from_static("Basic"));
        return (Some(resp), String::new());
    }
    let decoded = decode_basic_proxy_authorization(&credential);
    let user = decoded.as_ref().map(|(u, _)| u.clone()).unwrap_or_default();
    let pass = decoded.as_ref().map(|(_, p)| p.clone()).unwrap_or_default();
    let authed = match authenticator {
        None => true,
        Some(authenticator) => decoded.is_ok() && authenticator.verify(&user, &pass),
    };
    if !authed {
        infoln!("Auth failed from {remote_addr}");
        return (Some(response_with(StatusCode::FORBIDDEN)), user);
    }
    debugln!("Auth success from {remote_addr} -> {user}");
    (None, user)
}

fn response_with(status_code: StatusCode) -> RawResponse {
    RawResponse {
        status: status_code,
        headers: HeaderMap::new(),
        body: ResponseBody::Buffered(Bytes::new()),
        close: false,
    }
}

/// The non-CONNECT, non-upgrade forwarding path: the backend round trip, streamed both ways
/// (see the module doc). Always returns a connection to keep using, or to write a final response
/// on before closing, except the one unrecoverable case `client.rs`'s module doc describes.
///
/// The outgoing request is built from the *parsed* framing (`request.content_length`/`chunked`),
/// never from the client's raw `Content-Length`/`Transfer-Encoding` lines (those were already
/// stripped by `hack::read_request`'s `transfer::fix_length`/`parse_transfer_encoding`), so the
/// backend always sees exactly one, valid framing header, deriving the wire framing from
/// `request.content_length`/`request.chunked` rather than copying headers through. The URI
/// carries only the path and query (origin-form): `client.rs::do_request` takes
/// the dial target from `request.authority`/`request.scheme` directly, not from the outgoing
/// request's URI (see its module doc), and `Host` is set explicitly from `request.host`, with a
/// separate `Host:` line.
async fn forward(
    client: &super::client::Client,
    conn: BufferedConn,
    request: &Request,
    additions: &[Addition],
) -> (Result<RawResponse>, Option<BufferedConn>) {
    let uri: http::Uri = match request.path_and_query.parse() {
        Ok(uri) => uri,
        Err(err) => return (Err(anyhow!("{err}")), Some(conn)),
    };
    let mut builder = http::Request::builder().method(request.method.clone()).uri(uri);
    let Some(headers_mut) = builder.headers_mut() else {
        return (Err(anyhow!("request builder always has headers before body()")), Some(conn));
    };
    *headers_mut = request.header.clone();
    let Ok(host_value) = HeaderValue::from_str(&request.host) else {
        return (Err(anyhow!("invalid Host {:?}", request.host)), Some(conn));
    };
    headers_mut.insert(http::header::HOST, host_value);
    if request.chunked {
        headers_mut.insert(http::header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    } else {
        let len = request.content_length.unwrap_or(0);
        headers_mut.insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
    }
    let outgoing = match builder.body(()) {
        Ok(req) => req,
        Err(err) => return (Err(anyhow!("{err}")), Some(conn)),
    };

    let (result, conn) = client
        .do_request(
            conn,
            outgoing,
            &request.authority,
            &request.scheme,
            request.content_length,
            request.chunked,
            additions,
        )
        .await;
    let response = match result {
        Ok(response) => response,
        Err(err) => return (Err(err), conn),
    };

    let version = response.version();
    let (parts, incoming) = response.into_parts();
    let backend_chunked = is_chunked(&parts.headers);
    let declared_content_length = parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    let close = connection_says_close(&parts.headers)
        || (version < Version::HTTP_11 && !connection_says_keep_alive(&parts.headers));

    let body = ResponseBody::Streaming {
        incoming,
        content_length: if backend_chunked { None } else { declared_content_length },
    };

    (Ok(RawResponse { status: parts.status, headers: parts.headers, body, close }), conn)
}

fn connection_says_close(headers: &HeaderMap) -> bool {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|tok| tok.trim().eq_ignore_ascii_case("close"))
}

fn connection_says_keep_alive(headers: &HeaderMap) -> bool {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|tok| tok.trim().eq_ignore_ascii_case("keep-alive"))
}

/// Serialises `resp` onto `conn`. A buffered body gets an accurate `Content-Length`; a streaming
/// body reproduces the backend's own framing: `Content-Length` passed through unchanged when the
/// backend declared one and did not chunk, `Transfer-Encoding: chunked` otherwise.
///
/// `method` is the *request's* method. Body bytes are suppressed purely on `resp.status`: a 1xx
/// or `204` response drops `Content-Length`/`Transfer-Encoding` entirely (a `304` drops
/// `Content-Type` too, which this crate does not specially track), and none of them ever get body
/// bytes. `HEAD` is different: only the *body bytes* are suppressed, so a `HEAD` response to a
/// normal `200` still gets its backend-declared `Content-Length` line, just no bytes after it.
/// Any streaming body byte-suppression still drains the backend's frames here so the round trip
/// finishes cleanly; nothing from it reaches the client either way.
pub(crate) async fn write_response(
    conn: &mut BufferedConn,
    proto_major: u8,
    proto_minor: u8,
    method: &Method,
    resp: &mut RawResponse,
) -> Result<()> {
    let mut head = Vec::new();
    let reason = resp.status.canonical_reason().unwrap_or("");
    head.extend_from_slice(
        format!("HTTP/{proto_major}.{proto_minor} {} {reason}\r\n", resp.status.as_u16()).as_bytes(),
    );
    for (name, value) in &resp.headers {
        if name == http::header::CONTENT_LENGTH || name == http::header::TRANSFER_ENCODING {
            continue;
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }

    if resp.close {
        head.extend_from_slice(b"Connection: close\r\n");
    }

    let headers_allowed = body_allowed_for_status(resp.status);
    let body_bytes_allowed = headers_allowed && !no_response_body_expected(method);

    if !headers_allowed {
        head.extend_from_slice(b"\r\n");
        conn.write_all(&head).await?;
        drain_streaming_body(&mut resp.body).await?;
        conn.flush().await?;
        return Ok(());
    }

    match &mut resp.body {
        ResponseBody::Buffered(bytes) => {
            head.extend_from_slice(format!("Content-Length: {}\r\n\r\n", bytes.len()).as_bytes());
            conn.write_all(&head).await?;
            if body_bytes_allowed {
                conn.write_all(bytes).await?;
            }
        }
        ResponseBody::Streaming { incoming, content_length: Some(len) } => {
            head.extend_from_slice(format!("Content-Length: {len}\r\n\r\n").as_bytes());
            conn.write_all(&head).await?;
            if body_bytes_allowed {
                stream_frames(conn, incoming).await?;
            } else {
                drain_incoming(incoming).await?;
            }
        }
        ResponseBody::Streaming { incoming, content_length: None } => {
            head.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
            conn.write_all(&head).await?;
            if body_bytes_allowed {
                stream_chunked_frames(conn, incoming).await?;
            } else {
                drain_incoming(incoming).await?;
            }
        }
    }
    conn.flush().await?;
    Ok(())
}

/// Reads a streaming backend response to completion without forwarding any of it to the client —
/// used whenever the response status or the request method says no body bytes may reach the
/// client, so the backend round trip still finishes cleanly.
async fn drain_streaming_body(body: &mut ResponseBody) -> Result<()> {
    if let ResponseBody::Streaming { incoming, .. } = body {
        drain_incoming(incoming).await?;
    }
    Ok(())
}

async fn drain_incoming(incoming: &mut Incoming) -> Result<()> {
    while let Some(frame) = incoming.frame().await {
        frame?;
    }
    Ok(())
}

/// Copies exactly the backend's declared `Content-Length` worth of data frames through, verbatim.
async fn stream_frames(conn: &mut BufferedConn, incoming: &mut Incoming) -> Result<()> {
    while let Some(frame) = incoming.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            conn.write_all(&data).await?;
        }
    }
    Ok(())
}

/// Re-frames the backend's data frames as `Transfer-Encoding: chunked` toward the client, the
/// re-chunking a response writer performs for a response whose length it does not know up front.
async fn stream_chunked_frames(conn: &mut BufferedConn, incoming: &mut Incoming) -> Result<()> {
    while let Some(frame) = incoming.frame().await {
        let frame = frame?;
        let Ok(data) = frame.into_data() else { continue };
        if data.is_empty() {
            continue;
        }
        conn.write_all(format!("{:x}\r\n", data.len()).as_bytes()).await?;
        conn.write_all(&data).await?;
        conn.write_all(b"\r\n").await?;
    }
    conn.write_all(b"0\r\n\r\n").await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use portable_atomic::AtomicU64;
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::net::{TcpListener, TcpStream};

    use crate::auth::auth::{new_auth_store, NIL};
    use murmur_common_net::io::Stream;
    use murmur_component::auth::auth::{new_authenticator, AuthUser as ComponentAuthUser};
    use murmur_component_ca::keypair::{new_random_tls_key_pair, new_tls_key_pair_loader, KeyPairType};
    use murmur_component_nat::table::Table;
    use murmur_component_tls::utls::{client as tls_client, server as tls_server, Config as TlsConfig};
    use murmur_constant::adapters::{NatTable, UDPPacket};
    use murmur_constant::metadata::Metadata;
    use murmur_constant::tunnel::Tunnel;

    use super::handle_conn;

    struct EchoTunnel {
        echo_addr: SocketAddr,
    }

    #[async_trait]
    impl Tunnel for EchoTunnel {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, _metadata: Metadata) {
            let Ok(mut upstream) = TcpStream::connect(self.echo_addr).await else { return };
            let _ = tokio::io::copy_bidirectional(&mut *conn, &mut upstream).await;
        }

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
            unreachable!("this test never sends UDP");
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    async fn run_echo_server(listener: TcpListener) {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if conn.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    }

    /// Hang detection, not a latency budget: high enough that only a task that stopped making
    /// progress trips it, even on an oversubscribed host. Trips here first mean check
    /// `--test-threads` against `available_parallelism`, not the code under test.
    const HANG_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

    /// Concurrent connection count scaled to the host: enough over `available_parallelism` to
    /// force real queueing, with a floor so a low-core host still exercises genuine concurrency.
    fn concurrency_width() -> usize {
        std::thread::available_parallelism().map(std::num::NonZeroUsize::get).unwrap_or(1).saturating_mul(8).max(16)
    }

    #[tokio::test]
    async fn concurrent_https_connect_then_relay_over_tls_never_hangs() {
        let (cert_pem, key_pem, _fp) = new_random_tls_key_pair(KeyPairType::P256).expect("key generation");
        let loader = new_tls_key_pair_loader(&cert_pem, &key_pem).expect("valid cert");
        let cert_for_server = loader().expect("cert loads");

        let server_config = Arc::new(TlsConfig {
            certificates: vec![cert_for_server],
            next_protos: vec!["http/1.1".to_owned()],
            ..Default::default()
        });
        let client_config = Arc::new(TlsConfig { insecure_skip_verify: true, ..Default::default() });

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo listener");
        let echo_addr = echo_listener.local_addr().expect("echo listener local addr");
        tokio::spawn(run_echo_server(echo_listener));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy listener local addr");

        let n = concurrency_width();

        let mut client_tasks = Vec::with_capacity(n);
        for i in 0..n {
            let client_config = Arc::clone(&client_config);
            client_tasks.push(tokio::spawn(async move {
                tokio::time::timeout(HANG_DEADLINE, async move {
                    let raw = TcpStream::connect(proxy_addr).await.expect("client connect");
                    let mut tls_conn = tls_client(Box::new(raw), client_config);
                    tls_conn.handshake().await.expect("client handshake");

                    let connect_request = format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n");
                    tls_conn.write_all(connect_request.as_bytes()).await.expect("client CONNECT write");

                    let mut buf = [0u8; 4096];
                    let mut total = 0usize;
                    loop {
                        let n = tls_conn.read(&mut buf[total..]).await.expect("client CONNECT response read");
                        assert!(n > 0, "task {i} server closed before sending CONNECT response");
                        total += n;
                        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let response_line = String::from_utf8_lossy(&buf[..total]);
                    assert!(response_line.contains("200"), "task {i} unexpected CONNECT response: {response_line}");

                    tls_conn.write_all(b"PING").await.expect("client ping write");
                    let mut pong = [0u8; 4];
                    tls_conn.read_exact(&mut pong).await.expect("client pong read");
                    assert_eq!(&pong, b"PING", "task {i} got unexpected echo reply");
                })
                .await
                .unwrap_or_else(|_| panic!("task {i} did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect"));
            }));
        }

        let mut server_tasks = Vec::with_capacity(n);
        for _ in 0..n {
            let (raw, _) = tokio::time::timeout(HANG_DEADLINE, proxy_listener.accept())
                .await
                .expect("accept did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect")
                .expect("accept");
            let server_config = Arc::clone(&server_config);
            let tunnel: Arc<dyn Tunnel> = Arc::new(EchoTunnel { echo_addr });
            server_tasks.push(tokio::spawn(async move {
                tokio::time::timeout(HANG_DEADLINE, async move {
                    let tls_conn = tls_server(Box::new(raw), server_config);
                    handle_conn(Box::new(tls_conn), tunnel, NIL.clone(), &[]).await;
                })
                .await
                .expect("server handling did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect");
            }));
        }

        for task in client_tasks {
            task.await.expect("client task panicked");
        }
        for task in server_tasks {
            task.await.expect("server task panicked");
        }
    }

    #[tokio::test]
    async fn huge_content_length_closes_connection_instead_of_aborting() {
        // The same bytes: parses the headers, dials the tunnel, hits an unexpected EOF copying the
        // body, and writes exactly this 502 before closing. This tunnel accepts and drops the dial,
        // matching a dial that happens before the declared length is known to be bogus.
        struct DiscardTunnel {
            dialled: Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl Tunnel for DiscardTunnel {
            async fn handle_tcp_conn(&self, _conn: Box<dyn Stream>, _metadata: Metadata) {
                self.dialled.notify_one();
            }

            fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
                unreachable!("this test never sends UDP");
            }

            fn nat_table(&self) -> Arc<dyn NatTable> {
                Arc::new(Table::default())
            }
        }

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy listener local addr");
        let dialled = Arc::new(tokio::sync::Notify::new());
        let tunnel: Arc<dyn Tunnel> = Arc::new(DiscardTunnel { dialled: Arc::clone(&dialled) });

        let server_task = tokio::spawn(async move {
            let (conn, _) = tokio::time::timeout(HANG_DEADLINE, proxy_listener.accept())
                .await
                .expect("accept did not complete within the hang-detection deadline")
                .expect("accept");
            tokio::time::timeout(HANG_DEADLINE, handle_conn(Box::new(conn), tunnel, NIL.clone(), &[]))
                .await
                .expect("server handling did not complete within the hang-detection deadline; a preallocation abort would kill the whole test binary instead of timing out here");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("client connect");
        let request = "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1000000000000\r\n\r\n";
        client.write_all(request.as_bytes()).await.expect("client request write");
        client.write_all(&[0u8; 64]).await.expect("client partial body write");
        client.shutdown().await.expect("client shutdown");

        let mut trailing = Vec::new();
        tokio::time::timeout(HANG_DEADLINE, client.read_to_end(&mut trailing))
            .await
            .expect("client read did not complete within the hang-detection deadline")
            .expect("client read");
        // The huge declared length becomes an ordinary short-read error once the real 64 bytes
        // are exhausted, not a multi-terabyte allocation: the server is still alive to answer,
        // and answers with exactly what a real backend round trip would.
        assert_eq!(trailing, b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");

        tokio::time::timeout(HANG_DEADLINE, dialled.notified())
            .await
            .expect("the backend tunnel must still be dialled, same as the client.Do");
        server_task.await.expect("server task panicked");
    }

    #[tokio::test]
    async fn connect_with_ambiguous_authority_closes_without_200() {
        struct UnreachedTunnel;

        #[async_trait]
        impl Tunnel for UnreachedTunnel {
            async fn handle_tcp_conn(&self, _conn: Box<dyn Stream>, _metadata: Metadata) {
                unreachable!("the ReadRequest rejects `a:b:c` before ever writing 200 or dialling");
            }

            fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
                unreachable!("this test never sends UDP");
            }

            fn nat_table(&self) -> Arc<dyn NatTable> {
                Arc::new(Table::default())
            }
        }

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy listener local addr");
        let tunnel: Arc<dyn Tunnel> = Arc::new(UnreachedTunnel);

        let server_task = tokio::spawn(async move {
            let (conn, _) = tokio::time::timeout(HANG_DEADLINE, proxy_listener.accept())
                .await
                .expect("accept did not complete within the hang-detection deadline")
                .expect("accept");
            tokio::time::timeout(HANG_DEADLINE, handle_conn(Box::new(conn), tunnel, NIL.clone(), &[]))
                .await
                .expect("server handling did not complete within the hang-detection deadline");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("client connect");
        // `a:b:c` has two unbracketed colons, which the request-URI parse rejects with an
        // invalid-port error, so the connection just closes.
        client.write_all(b"CONNECT a:b:c HTTP/1.1\r\nHost: a:b:c\r\n\r\n").await.expect("client CONNECT write");

        let mut response = Vec::new();
        tokio::time::timeout(HANG_DEADLINE, client.read_to_end(&mut response))
            .await
            .expect("client read did not complete within the hang-detection deadline")
            .expect("client read");
        assert!(
            response.is_empty(),
            "must close with no response for an unparseable CONNECT authority, got {response:?}"
        );

        server_task.await.expect("server task panicked");
    }

    #[tokio::test]
    async fn connect_with_lenient_authority_still_gets_200_and_dials() {
        struct DiscardTunnel {
            dialled: Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl Tunnel for DiscardTunnel {
            async fn handle_tcp_conn(&self, _conn: Box<dyn Stream>, _metadata: Metadata) {
                self.dialled.notify_one();
            }

            fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
                unreachable!("this test never sends UDP");
            }

            fn nat_table(&self) -> Arc<dyn NatTable> {
                Arc::new(Table::default())
            }
        }

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy listener local addr");
        let dialled = Arc::new(tokio::sync::Notify::new());
        let tunnel: Arc<dyn Tunnel> = Arc::new(DiscardTunnel { dialled: Arc::clone(&dialled) });

        let server_task = tokio::spawn(async move {
            let (conn, _) = tokio::time::timeout(HANG_DEADLINE, proxy_listener.accept())
                .await
                .expect("accept did not complete within the hang-detection deadline")
                .expect("accept");
            tokio::time::timeout(HANG_DEADLINE, handle_conn(Box::new(conn), tunnel, NIL.clone(), &[]))
                .await
                .expect("server handling did not complete within the hang-detection deadline");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("client connect");
        // `a<b:443` has only one colon, so it passes the same ambiguity check `a:b:c` fails. The
        // request-URI parse accepts `<` in a host, `http::Uri` alone would not, so this must
        // still get 200 and reach the dial layer instead of closing silently.
        client.write_all(b"CONNECT a<b:443 HTTP/1.1\r\nHost: a<b:443\r\n\r\n").await.expect("client CONNECT write");

        let mut buf = [0u8; 256];
        let mut total = 0usize;
        loop {
            let n = tokio::time::timeout(HANG_DEADLINE, client.read(&mut buf[total..]))
                .await
                .expect("client CONNECT response read did not complete within the hang-detection deadline")
                .expect("client CONNECT response read");
            assert!(n > 0, "server closed before sending a CONNECT response");
            total += n;
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let response_line = String::from_utf8_lossy(&buf[..total]);
        assert!(response_line.contains("200"), "expected 200 Connection established, got {response_line}");

        tokio::time::timeout(HANG_DEADLINE, dialled.notified())
            .await
            .expect("the backend tunnel must still be dialled for an accepted but http::Uri-rejected authority");

        drop(client);
        server_task.await.expect("server task panicked");
    }

    /// A `Box<dyn Stream>` wrapper that records, without ever holding the bytes themselves: the
    /// total bytes actually read, the largest single buffer capacity a caller ever asked
    /// `poll_read` to fill, and the largest single slice a caller ever handed `poll_write`. A
    /// caller that buffers a whole declared-length body up front (the bug finding 0 fixed) or a
    /// whole backend response up front (finding 2) shows up here as one call near that whole
    /// size; a bounded streaming implementation never exceeds its own fixed chunk size no matter
    /// how large the transfer is.
    #[derive(Clone, Default)]
    struct ConnCounters {
        total_read: Arc<AtomicU64>,
        max_read_capacity: Arc<AtomicUsize>,
        max_write_len: Arc<AtomicUsize>,
    }

    struct CountingConn {
        inner: TcpStream,
        counters: ConnCounters,
    }

    impl AsyncRead for CountingConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.counters.max_read_capacity.fetch_max(buf.remaining(), Ordering::SeqCst);
            let before = buf.filled().len();
            let res = Pin::new(&mut this.inner).poll_read(cx, buf);
            if res.is_ready() {
                let after = buf.filled().len();
                this.counters.total_read.fetch_add((after - before) as u64, Ordering::SeqCst);
            }
            res
        }
    }

    impl AsyncWrite for CountingConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.counters.max_write_len.fetch_max(buf.len(), Ordering::SeqCst);
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl Stream for CountingConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Stream::local_addr(&self.inner)
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Stream::peer_addr(&self.inner)
        }

        fn shutdown_read(&self) -> io::Result<()> {
            Stream::shutdown_read(&self.inner)
        }

        fn shutdown_write(&self) -> io::Result<()> {
            Stream::shutdown_write(&self.inner)
        }
    }

    #[tokio::test]
    async fn unauthenticated_request_with_large_body_is_rejected_without_reading_body() {
        struct UnreachedTunnel;

        #[async_trait]
        impl Tunnel for UnreachedTunnel {
            async fn handle_tcp_conn(&self, _conn: Box<dyn Stream>, _metadata: Metadata) {
                unreachable!("an auth failure must never dial the backend");
            }

            fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
                unreachable!("this test never sends UDP");
            }

            fn nat_table(&self) -> Arc<dyn NatTable> {
                Arc::new(Table::default())
            }
        }

        let users = vec![ComponentAuthUser { user: "alice".to_owned(), pass: "secret".to_owned() }];
        let authenticator = new_authenticator(&users);
        let store = new_auth_store(authenticator);

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy listener local addr");
        let tunnel: Arc<dyn Tunnel> = Arc::new(UnreachedTunnel);
        let counters = ConnCounters::default();
        let counters_for_server = counters.clone();

        let server_task = tokio::spawn(async move {
            let (raw, _) = tokio::time::timeout(HANG_DEADLINE, proxy_listener.accept())
                .await
                .expect("accept did not complete within the hang-detection deadline")
                .expect("accept");
            let counting = CountingConn { inner: raw, counters: counters_for_server };
            tokio::time::timeout(HANG_DEADLINE, handle_conn(Box::new(counting), tunnel, store, &[]))
                .await
                .expect("server handling did not complete within the hang-detection deadline");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("client connect");
        let request = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1000000\r\n\r\n";
        client.write_all(request.as_bytes()).await.expect("client request write");
        let body = vec![0x41u8; 1_000_000];
        client.write_all(&body).await.expect("client body write");

        let mut response = Vec::new();
        tokio::time::timeout(HANG_DEADLINE, client.read_to_end(&mut response))
            .await
            .expect("client read did not complete within the hang-detection deadline")
            .expect("client read");
        assert!(response.starts_with(b"HTTP/1.1 407"), "expected 407 Proxy Authentication Required, got {response:?}");

        server_task.await.expect("server task panicked");

        let read = counters.total_read.load(Ordering::SeqCst);
        assert!(read < 8192, "server must reject on headers alone, without reading the 1 MB body; read {read} bytes");
    }

    struct StreamingBackendTunnel {
        response_len: usize,
    }

    #[async_trait]
    impl Tunnel for StreamingBackendTunnel {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, _metadata: Metadata) {
            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                if conn.read_exact(&mut byte).await.is_err() {
                    return;
                }
                header.push(byte[0]);
                if header.len() >= 4 && header[header.len() - 4..] == *b"\r\n\r\n" {
                    break;
                }
            }
            let header_text = String::from_utf8_lossy(&header);
            let content_length: usize = header_text
                .split("\r\n")
                .find(|line| line.len() > 15 && line[..15].eq_ignore_ascii_case("content-length:"))
                .and_then(|line| line[15..].trim().parse().ok())
                .unwrap_or(0);

            let mut remaining = content_length;
            let mut buf = vec![0u8; 256 * 1024];
            while remaining > 0 {
                let want = remaining.min(buf.len());
                let n = match conn.read(&mut buf[..want]).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };
                remaining -= n;
            }

            let resp_head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", self.response_len);
            if conn.write_all(resp_head.as_bytes()).await.is_err() {
                return;
            }
            let chunk = vec![0xCDu8; 256 * 1024];
            let mut written = 0usize;
            while written < self.response_len {
                let want = (self.response_len - written).min(chunk.len());
                if conn.write_all(&chunk[..want]).await.is_err() {
                    return;
                }
                written += want;
            }
        }

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
            unreachable!("this test never sends UDP");
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    #[tokio::test]
    async fn fifty_megabyte_bodies_pass_through_with_bounded_buffering() {
        const BODY_LEN: usize = 50 * 1024 * 1024;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy listener local addr");
        let tunnel: Arc<dyn Tunnel> = Arc::new(StreamingBackendTunnel { response_len: BODY_LEN });
        let counters = ConnCounters::default();
        let counters_for_server = counters.clone();

        let server_task = tokio::spawn(async move {
            let (raw, _) = tokio::time::timeout(HANG_DEADLINE, proxy_listener.accept())
                .await
                .expect("accept did not complete within the hang-detection deadline")
                .expect("accept");
            let counting = CountingConn { inner: raw, counters: counters_for_server };
            tokio::time::timeout(HANG_DEADLINE, handle_conn(Box::new(counting), tunnel, NIL.clone(), &[]))
                .await
                .expect("server handling did not complete within the hang-detection deadline");
        });

        tokio::time::timeout(HANG_DEADLINE, async {
            let client = TcpStream::connect(proxy_addr).await.expect("client connect");
            let (mut client_read, mut client_write) = client.into_split();

            let write_task = tokio::spawn(async move {
                let request = format!(
                    "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: {BODY_LEN}\r\n\r\n"
                );
                client_write.write_all(request.as_bytes()).await.expect("client request head write");
                let chunk = vec![0xABu8; 1024 * 1024];
                let mut remaining = BODY_LEN;
                while remaining > 0 {
                    let want = remaining.min(chunk.len());
                    client_write.write_all(&chunk[..want]).await.expect("client body chunk write");
                    remaining -= want;
                }
            });

            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                client_read.read_exact(&mut byte).await.expect("client response header read");
                header.push(byte[0]);
                if header.len() >= 4 && header[header.len() - 4..] == *b"\r\n\r\n" {
                    break;
                }
            }
            let header_text = String::from_utf8_lossy(&header);
            assert!(header_text.starts_with("HTTP/1.1 200"), "unexpected status line: {header_text}");
            let declared_len: usize = header_text
                .split("\r\n")
                .find(|line| line.len() > 15 && line[..15].eq_ignore_ascii_case("content-length:"))
                .and_then(|line| line[15..].trim().parse().ok())
                .expect("response declares Content-Length");
            assert_eq!(declared_len, BODY_LEN, "response Content-Length must match the backend's declared length");

            let mut received = 0usize;
            let mut buf = vec![0u8; 1024 * 1024];
            while received < BODY_LEN {
                let n = client_read.read(&mut buf).await.expect("client response body read");
                assert!(n > 0, "connection closed before the full response body arrived");
                received += n;
            }
            assert_eq!(received, BODY_LEN, "must receive exactly the declared response length");

            write_task.await.expect("write task panicked");
        })
        .await
        .expect("client round trip did not complete within the hang-detection deadline");

        server_task.await.expect("server task panicked");

        // The discriminating assertion: neither direction ever handed the connection a
        // buffer anywhere near the 50 MB transfer size. `write_response`'s old, pre-fix code
        // buffered the whole backend response into one `Bytes` and wrote it in a single
        // `write_all` call; streaming caps every write at one backend frame instead.
        let max_read_capacity = counters.max_read_capacity.load(Ordering::SeqCst);
        let max_write_len = counters.max_write_len.load(Ordering::SeqCst);
        assert!(max_read_capacity < 1_000_000, "a single read call was asked to fill {max_read_capacity} bytes");
        assert!(max_write_len < 1_000_000, "a single write call sent {max_write_len} bytes at once");
    }

    /// Reads one raw request head off `conn`, replies with the request line and body joined by
    /// `|`, so a test can assert exactly which request the backend actually received.
    struct ReflectBackendTunnel;

    #[async_trait]
    impl Tunnel for ReflectBackendTunnel {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, _metadata: Metadata) {
            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                if conn.read_exact(&mut byte).await.is_err() {
                    return;
                }
                header.push(byte[0]);
                if header.len() >= 4 && header[header.len() - 4..] == *b"\r\n\r\n" {
                    break;
                }
            }
            let header_text = String::from_utf8_lossy(&header).into_owned();
            let request_line = header_text.split("\r\n").next().unwrap_or("").to_owned();
            let content_length: usize = header_text
                .split("\r\n")
                .find(|line| line.len() > 15 && line[..15].eq_ignore_ascii_case("content-length:"))
                .and_then(|line| line[15..].trim().parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; content_length];
            if content_length > 0 && conn.read_exact(&mut body).await.is_err() {
                return;
            }
            let payload = format!("{request_line}|{}", String::from_utf8_lossy(&body));
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{payload}", payload.len());
            let _ = conn.write_all(resp.as_bytes()).await;
        }

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
            unreachable!("this test never sends UDP");
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    #[tokio::test]
    async fn bare_lf_header_boundary_recovers_second_request() {
        // P1-http-bare-lf-header-boundary: a bare-LF-terminated head used to be misread as ending
        // at the *next* `"\r\n\r\n"` instead of its own real end, silently discarding the bytes in
        // between and desyncing every request after it. `httparse`, this crate's parser, treats a
        // bare `\n` as a valid line ending, so the fixed boundary must land at the correct point:
        // `AAAAA` is the POST's whole body, and the GET that follows is read as its own request
        // rather than being swallowed as leftover POST body.
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy listener local addr");
        let tunnel: Arc<dyn Tunnel> = Arc::new(ReflectBackendTunnel);

        let server_task = tokio::spawn(async move {
            let (conn, _) = tokio::time::timeout(HANG_DEADLINE, proxy_listener.accept())
                .await
                .expect("accept did not complete within the hang-detection deadline")
                .expect("accept");
            tokio::time::timeout(HANG_DEADLINE, handle_conn(Box::new(conn), tunnel, NIL.clone(), &[]))
                .await
                .expect("server handling did not complete within the hang-detection deadline");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("client connect");
        let raw: &[u8] = b"POST http://a/ HTTP/1.1\nContent-Length: 5\nProxy-Connection: keep-alive\n\nAAAAAGET http://b/ HTTP/1.1\r\nHost: b\r\n\r\nBBBBB";
        client.write_all(raw).await.expect("client request write");

        let mut buf = Vec::new();
        tokio::time::timeout(HANG_DEADLINE, client.read_to_end(&mut buf))
            .await
            .expect("client read did not complete within the hang-detection deadline")
            .expect("client read");
        let text = String::from_utf8_lossy(&buf);
        assert_eq!(text.matches("HTTP/1.1 200").count(), 2, "expected exactly two responses, got: {text}");
        assert!(
            text.contains("POST / HTTP/1.1|AAAAA"),
            "first response must reflect the POST forwarded with body AAAAA (bare-LF head correctly bounded): {text}"
        );
        assert!(
            text.contains("GET / HTTP/1.1|"),
            "second response must be the GET the bare-LF fix recovers, not swallowed as POST body: {text}"
        );

        server_task.await.expect("server task panicked");
    }

    struct SequencedResponseTunnel {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Tunnel for SequencedResponseTunnel {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, _metadata: Metadata) {
            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                if conn.read_exact(&mut byte).await.is_err() {
                    return;
                }
                header.push(byte[0]);
                if header.len() >= 4 && header[header.len() - 4..] == *b"\r\n\r\n" {
                    break;
                }
            }
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            // A spec-compliant backend never sends body bytes for a 304, even if it declares a
            // (meaningless) Content-Length; this is exactly the shape that used to make this
            // crate's `write_response` append an unconditional chunked terminator the client never
            // expected.
            let resp = if call == 0 {
                "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n".to_owned()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_owned()
            };
            let _ = conn.write_all(resp.as_bytes()).await;
        }

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
            unreachable!("this test never sends UDP");
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    #[tokio::test]
    async fn keep_alive_304_then_second_request() {
        // P1-http-response-bodyless-chunked: a 304 on a keep-alive connection must leave no body
        // bytes on the wire at all (Content-Length/Transfer-Encoding are dropped for it too, RFC
        // 7232 §4.1) so the next response the client reads is the next request's real response, not
        // whatever this crate used to append after the 304's head.
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy listener local addr");
        let tunnel: Arc<dyn Tunnel> = Arc::new(SequencedResponseTunnel { calls: Arc::new(AtomicUsize::new(0)) });

        let server_task = tokio::spawn(async move {
            let (conn, _) = tokio::time::timeout(HANG_DEADLINE, proxy_listener.accept())
                .await
                .expect("accept did not complete within the hang-detection deadline")
                .expect("accept");
            tokio::time::timeout(HANG_DEADLINE, handle_conn(Box::new(conn), tunnel, NIL.clone(), &[]))
                .await
                .expect("server handling did not complete within the hang-detection deadline");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("client connect");
        let req1 = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n";
        client.write_all(req1.as_bytes()).await.expect("client request 1 write");

        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(HANG_DEADLINE, client.read(&mut chunk))
                .await
                .expect("client response 1 read did not complete within the hang-detection deadline")
                .expect("client response 1 read");
            assert!(n > 0, "server closed before sending the 304");
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let resp1 = String::from_utf8_lossy(&buf).into_owned();
        assert!(resp1.starts_with("HTTP/1.1 304"), "expected a 304, got: {resp1}");
        assert!(!resp1.contains("Content-Length"), "a 304 must drop Content-Length: {resp1}");
        assert!(resp1.ends_with("\r\n\r\n"), "the 304 must end with the head, no body bytes after it: {resp1:?}");

        let req2 = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        client.write_all(req2.as_bytes()).await.expect("client request 2 write");

        let mut buf2 = Vec::new();
        tokio::time::timeout(HANG_DEADLINE, client.read_to_end(&mut buf2))
            .await
            .expect("client response 2 read did not complete within the hang-detection deadline")
            .expect("client response 2 read");
        let resp2 = String::from_utf8_lossy(&buf2);
        assert!(
            resp2.starts_with("HTTP/1.1 200") && resp2.ends_with("OK"),
            "the second response on the same connection must be the fresh 200, not bytes desynced by the 304: {resp2}"
        );

        server_task.await.expect("server task panicked");
    }

    struct CapturingTunnel {
        received: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl Tunnel for CapturingTunnel {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, _metadata: Metadata) {
            let mut buf = vec![0u8; 65536];
            loop {
                match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => self.received.lock().expect("mutex poisoned").extend_from_slice(&buf[..n]),
                }
            }
        }

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
            unreachable!("this test never sends UDP");
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    #[tokio::test]
    async fn truncated_chunked_upload_never_reaches_backend_as_complete() {
        // P2-http-truncated-chunked-forwarded-complete: dropping the pump's sink used to look like
        // a clean end-of-body to hyper, which then appended the chunked terminator even though the
        // upload was truncated mid-chunk. The fix routes the pump's failure into the outgoing body
        // stream as an `Err` frame, so hyper aborts the request instead of finishing it — the
        // backend must never see `0\r\n\r\n` for this upload.
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy listener local addr");
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let tunnel: Arc<dyn Tunnel> = Arc::new(CapturingTunnel { received: Arc::clone(&received) });

        let server_task = tokio::spawn(async move {
            let (conn, _) = tokio::time::timeout(HANG_DEADLINE, proxy_listener.accept())
                .await
                .expect("accept did not complete within the hang-detection deadline")
                .expect("accept");
            let _ = tokio::time::timeout(HANG_DEADLINE, handle_conn(Box::new(conn), tunnel, NIL.clone(), &[])).await;
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("client connect");
        let head = "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        client.write_all(head.as_bytes()).await.expect("client head write");
        // A 5-byte chunk announced, only 3 bytes of it ever sent, then the connection drops.
        client.write_all(b"5\r\nhel").await.expect("client partial chunk write");
        drop(client);

        server_task.await.expect("server task panicked");

        // Give the backend's tunnel task a moment to observe the abort after the server task
        // above already returned (the tunnel dial is a separate spawned task in `client.rs`).
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let got = received.lock().expect("mutex poisoned").clone();
        let got_text = String::from_utf8_lossy(&got);
        assert!(
            !got_text.contains("0\r\n\r\n"),
            "the backend must never see a complete chunked terminator for a truncated upload: {got_text:?}"
        );
    }

    struct SlowDialTunnel {
        echo_addr: SocketAddr,
        dial_delay: std::time::Duration,
    }

    #[async_trait]
    impl Tunnel for SlowDialTunnel {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, _metadata: Metadata) {
            tokio::time::sleep(self.dial_delay).await;
            let Ok(mut upstream) = TcpStream::connect(self.echo_addr).await else { return };
            let _ = tokio::io::copy_bidirectional(&mut *conn, &mut upstream).await;
        }

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
            unreachable!("this test never sends UDP");
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chunked_upload_flushes_prior_chunk_over_real_tcp_before_trailer_error() {
        // P3-http-flush-after-chunk: a chunk already handed to hyper's outgoing body must reach a
        // real backend socket even when a later chunk-size line or trailer fails and ends the
        // body early, matching the flush-after-chunk writer — this is the `tr3-second-line-bad`
        // case
        // (`5\r\nhello\r\n0\r\nX-T: 1\r\nnocolon\r\n\r\n`: a good 5-byte chunk, then a trailer field
        // missing its colon). `SlowDialTunnel` delays the backend dial so the request head is
        // still stuck mid-flight in the tunnel pipe (`common::net::pipe`, whose writes block until
        // read) when `hello` gets buffered behind it — the exact ordering a real backend's dial
        // and accept latency produces, and the one a chunk-ack fired merely on hyper polling for
        // the *next* frame (rather than on the wrapped transport's own `poll_flush` confirming
        // delivery) failed to survive. Runs against a genuine TCP backend (not an in-process
        // `Tunnel` capture, unlike `truncated_chunked_upload_never_reaches_backend_as_complete`
        // above), on a multi-thread runtime, 200 times.
        for _ in 0..200 {
            let upstream_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream listener");
            let upstream_addr = upstream_listener.local_addr().expect("upstream listener local addr");
            let upstream_task = tokio::spawn(async move {
                let (mut conn, _) = upstream_listener.accept().await.expect("upstream accept");
                let mut received = Vec::new();
                conn.read_to_end(&mut received).await.expect("upstream read");
                received
            });

            let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
            let proxy_addr = proxy_listener.local_addr().expect("proxy listener local addr");
            let tunnel: Arc<dyn Tunnel> =
                Arc::new(SlowDialTunnel { echo_addr: upstream_addr, dial_delay: std::time::Duration::from_millis(20) });

            let server_task = tokio::spawn(async move {
                let (conn, _) = tokio::time::timeout(HANG_DEADLINE, proxy_listener.accept())
                    .await
                    .expect("accept did not complete within the hang-detection deadline")
                    .expect("accept");
                let _ =
                    tokio::time::timeout(HANG_DEADLINE, handle_conn(Box::new(conn), tunnel, NIL.clone(), &[])).await;
            });

            let mut client = TcpStream::connect(proxy_addr).await.expect("client connect");
            let head = "POST http://example.com/c HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\
                            Transfer-Encoding: chunked\r\n\r\n";
            client.write_all(head.as_bytes()).await.expect("client head write");
            let body = "5\r\nhello\r\n0\r\nX-T: 1\r\nnocolon\r\n\r\n";
            client.write_all(body.as_bytes()).await.expect("client body write");
            drop(client);

            server_task.await.expect("server task panicked");
            let received = tokio::time::timeout(HANG_DEADLINE, upstream_task)
                .await
                .expect("upstream did not observe EOF within the hang-detection deadline")
                .expect("upstream task panicked");

            let got = String::from_utf8_lossy(&received);
            assert!(
                got.contains("5\r\nhello\r\n"),
                "the already-flushed chunk must reach the real upstream before the trailer error ends the request: {got:?}"
            );
        }
    }
}
