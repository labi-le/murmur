//! Deviation: this crate builds and parses the client-side WebSocket opening handshake directly
//! with `httparse`.
//!
//! `murmur_ws` only mirrors the WebSocket frame codec and its streaming
//! reader/control-frame handling (see that module's docs); the HTTP upgrade request/response
//! machinery has no mirror. The handshake-failure error variants have no
//! equivalent constant here; this crate raises local, behaviour-equivalent `anyhow` errors.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use rand::RngCore;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use url::Url;

use murmur_common_net::io::Stream;
use murmur_component_tls::utls::{client as tls_client, Config as TlsConfig, VERSION_TLS12};
use murmur_ws::STATE_CLIENT_SIDE;

use super::early_handshake::apply_early_handshake_or_upgrade;
use super::masker::{random_choice, trim_port_for_host, ACCEPTS, ACCEPT_ENCODINGS, ACCEPT_LANGUAGES, USER_AGENTS};
use super::pathroot::join_path_root;
use super::tunnel_api::{TunnelDialOptions, TunnelMode};
use super::tunnel_dial::{canonical_header_host, set_early_data_query, TUNNEL_EARLY_DATA_HEADER};
use super::tunnel_preconnect::{with_timeout, TUNNEL_TLS_HANDSHAKE_LIMIT};
use super::tunnel_server::new_pre_buffered_conn;
use super::ws_auth::{TunnelAuth, TUNNEL_AUTH_QUERY_KEY};
use super::ws_stream_conn::new_ws_stream_conn;

pub(crate) fn normalize_ws_scheme_from_address(server_address: &str, tls_enabled: bool) -> (String, String) {
    let addr = server_address.trim();
    if addr.contains("://") {
        if let Ok(u) = Url::parse(addr) {
            match u.scheme().to_lowercase().as_str() {
                "ws" => return ("ws".to_owned(), url_authority(&u)),
                "wss" => return ("wss".to_owned(), url_authority(&u)),
                _ => {}
            }
        }
    }
    if tls_enabled {
        ("wss".to_owned(), addr.to_owned())
    } else {
        ("ws".to_owned(), addr.to_owned())
    }
}

fn url_authority(u: &Url) -> String {
    let host = u.host_str().unwrap_or_default();
    match u.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

pub(crate) fn normalize_ws_dial_target(
    server_address: &str,
    tls_enabled: bool,
    host_override: &str,
) -> Result<(String, String, String, String)> {
    let (scheme, addr) = normalize_ws_scheme_from_address(server_address, tls_enabled);

    let (host, port) = match split_host_port(&addr) {
        Ok(v) => v,
        Err(err) => {
            if addr.contains(':') {
                return Err(anyhow!("invalid server address {server_address:?}: {err}"));
            }
            let port = if scheme == "wss" { "443" } else { "80" };
            (addr.clone(), port.to_owned())
        }
    };

    let (server_name, url_host) = if host_override.is_empty() {
        (host.clone(), join_host_port(&host, &port))
    } else {
        let (split_host, split_port) = split_host_port(host_override).unwrap_or_default();
        let host_part = if split_host.is_empty() { host_override.to_owned() } else { split_host };
        let port_part = if split_port.is_empty() { port.as_str() } else { split_port.as_str() };
        let url_host = join_host_port(&host_part, port_part);
        (host_part, url_host)
    };

    let dial_addr = join_host_port(&host, &port);
    Ok((scheme, url_host, dial_addr, trim_port_for_host(&server_name)))
}

/// Applies the WS headers. `_host` is unused: the helper never
/// reads its `host` parameter (the HTTP `Host` header is set separately by the caller).
pub(crate) fn apply_ws_headers(h: &mut http::HeaderMap, _host: &str) {
    let mut r = rand::rng();
    let ua = random_choice(USER_AGENTS, &mut r);
    let accept = random_choice(ACCEPTS, &mut r);
    let lang = random_choice(ACCEPT_LANGUAGES, &mut r);
    let enc = random_choice(ACCEPT_ENCODINGS, &mut r);

    set_header(h, http::header::USER_AGENT, ua);
    set_header(h, http::header::ACCEPT, accept);
    set_header(h, http::header::ACCEPT_LANGUAGE, lang);
    set_header(h, http::header::ACCEPT_ENCODING, enc);
    set_header(h, http::header::CACHE_CONTROL, "no-cache");
    set_header(h, http::header::PRAGMA, "no-cache");
    if let Ok(name) = http::header::HeaderName::from_bytes(b"x-sudoku-tunnel") {
        set_header(h, name, TunnelMode::Ws.as_str());
    }
    if let Ok(name) = http::header::HeaderName::from_bytes(b"x-sudoku-version") {
        set_header(h, name, "1");
    }
}

fn set_header(h: &mut http::HeaderMap, name: http::header::HeaderName, value: &str) {
    if let Ok(value) = http::HeaderValue::from_str(value) {
        h.insert(name, value);
    }
}

pub(crate) fn compute_ws_accept(key: &str) -> String {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(GUID.as_bytes());
    STANDARD.encode(hasher.finalize())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|pos| pos + 4)
}

/// Reads bytes off `conn` until the HTTP response header terminator (`\r\n\r\n`) is seen. Returns
/// the header bytes (terminator included) and any leftover bytes read past it (data the server
/// may have started sending immediately after the handshake), matching the use of `br.Buffered()`
/// after the dial.
// NOT cancel-safe: the header bytes read so far go with the future; the only caller drops it while
// the dial is being cancelled and discards the connection anyway.
async fn read_ws_response_header(conn: &mut Box<dyn Stream>) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        if let Some(pos) = find_header_end(&buf) {
            let rest = buf.split_off(pos);
            return Ok((buf, rest));
        }
        let n = conn.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        buf.extend_from_slice(chunk.split_at(n).0);
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "websocket response header too large"));
        }
    }
}

fn find_response_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
}

/// The dial deadline and the caller's own cancellation both arrive as a cancelled child token;
/// this names which one it was, so a stalled peer fails with its deadline rather than a bare
/// cancellation.
fn dial_timeout_error(ctx: &CancellationToken) -> anyhow::Error {
    if ctx.is_cancelled() {
        return anyhow!("context canceled");
    }
    anyhow!("httpmask: websocket dial timed out after {TUNNEL_TLS_HANDSHAKE_LIMIT:?}")
}

// cancel-safe: a cancelled dial drops the connection it had just opened, so no state survives.
pub(crate) async fn dial_ws(
    ctx: &CancellationToken,
    server_address: &str,
    opts: TunnelDialOptions,
) -> Result<Box<dyn Stream>> {
    let Some(dial_context) = opts.dial_context.clone() else {
        return Err(anyhow!("httpmask: DialContext is nil"));
    };

    let (scheme, url_host, dial_addr, server_name) =
        normalize_ws_dial_target(server_address, opts.tls_enabled, &opts.host_override)?;

    let http_scheme = if scheme == "wss" { "https" } else { "http" };
    let header_host = canonical_header_host(&url_host, http_scheme);
    let auth = TunnelAuth::new(&opts.auth_key, Duration::default());

    let mut u = Url::parse(&format!("{scheme}://{url_host}{}", join_path_root(&opts.path_root, "/ws")))?;
    if let Some(early) = &opts.early_handshake {
        if !early.request_payload.is_empty() {
            let raw_url = set_early_data_query(u.as_str(), &early.request_payload)?;
            u = Url::parse(&raw_url)?;
        }
    }

    let mut header = http::HeaderMap::new();
    apply_ws_headers(&mut header, &header_host);

    add_ws_auth(&mut header, &mut u, auth.as_ref());

    let mut ws_key_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut ws_key_bytes);
    let ws_key = STANDARD.encode(ws_key_bytes);

    let request = build_ws_request(&u, &header_host, &ws_key, &header);

    // One deadline for the whole handshake: TCP dial, TLS, request write and response header.
    let dial_ctx = with_timeout(ctx, TUNNEL_TLS_HANDSHAKE_LIMIT);
    let deadline_err = |err: anyhow::Error| {
        if dial_ctx.is_cancelled() {
            dial_timeout_error(ctx)
        } else {
            err
        }
    };

    let dialed = dial_context.dial_context(&dial_ctx, "tcp", &dial_addr).await.map_err(deadline_err)?;
    let mut conn: Box<dyn Stream> = if scheme == "wss" {
        let tls_conn = tls_client(dialed, Arc::new(ws_tls_config(&server_name)));
        tls_conn.handshake_context(&dial_ctx).await.map_err(deadline_err)?;
        Box::new(tls_conn)
    } else {
        dialed
    };

    tokio::select! {
        result = conn.write_all(&request) => result?,
        () = dial_ctx.cancelled() => return Err(dial_timeout_error(ctx)),
    }
    tokio::select! {
        result = conn.flush() => result?,
        () = dial_ctx.cancelled() => return Err(dial_timeout_error(ctx)),
    }

    let (header_bytes, leftover) = tokio::select! {
        result = read_ws_response_header(&mut conn) => result?,
        () = dial_ctx.cancelled() => return Err(dial_timeout_error(ctx)),
    };

    let mut parsed = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut parsed);
    let httparse::Status::Complete(_) = response
        .parse(&header_bytes)
        .map_err(|err| anyhow!("httpmask: invalid websocket handshake response: {err}"))?
    else {
        return Err(anyhow!("httpmask: incomplete websocket handshake response"));
    };
    if response.code != Some(101) {
        return Err(anyhow!(
            "httpmask: unexpected websocket handshake status {:?} {}",
            response.code,
            response.reason.unwrap_or_default()
        ));
    }

    let headers: Vec<(String, String)> =
        response.headers.iter().map(|h| (h.name.to_owned(), String::from_utf8_lossy(h.value).into_owned())).collect();

    let accept = find_response_header(&headers, "sec-websocket-accept").unwrap_or_default();
    if accept.trim() != compute_ws_accept(&ws_key) {
        return Err(anyhow!("httpmask: invalid websocket handshake accept"));
    }

    if let Some(value) = find_response_header(&headers, TUNNEL_EARLY_DATA_HEADER) {
        if let Some(early) = &opts.early_handshake {
            if let Some(handle_response) = &early.handle_response {
                let decoded = URL_SAFE_NO_PAD.decode(value.trim())?;
                handle_response(&decoded)?;
            }
        }
    }

    if !leftover.is_empty() {
        conn = new_pre_buffered_conn(conn, leftover);
    }

    let ws_conn = new_ws_stream_conn(conn, STATE_CLIENT_SIDE);
    apply_early_handshake_or_upgrade(ws_conn, &opts).await
}

fn add_ws_auth(header: &mut http::HeaderMap, u: &mut Url, auth: Option<&TunnelAuth>) {
    let Some(auth) = auth else {
        return;
    };
    let token = auth.token(TunnelMode::Ws, "GET", "/ws", chrono::Utc::now());
    if token.is_empty() {
        return;
    }
    if let Ok(value) = http::HeaderValue::from_str(&format!("Bearer {token}")) {
        header.insert(http::header::AUTHORIZATION, value);
    }
    let mut pairs: Vec<(String, String)> = u
        .query_pairs()
        .filter(|(k, _)| k != TUNNEL_AUTH_QUERY_KEY)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    pairs.push((TUNNEL_AUTH_QUERY_KEY.to_owned(), token));
    let mut query_pairs = u.query_pairs_mut();
    query_pairs.clear();
    for (k, v) in &pairs {
        query_pairs.append_pair(k, v);
    }
    drop(query_pairs);
}

fn build_ws_request(u: &Url, header_host: &str, ws_key: &str, header: &http::HeaderMap) -> Vec<u8> {
    let path_and_query = match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_owned(),
    };
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(b"GET ");
    buf.extend_from_slice(path_and_query.as_bytes());
    buf.extend_from_slice(b" HTTP/1.1\r\n");
    buf.extend_from_slice(b"Host: ");
    buf.extend_from_slice(header_host.as_bytes());
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(b"Upgrade: websocket\r\n");
    buf.extend_from_slice(b"Connection: Upgrade\r\n");
    buf.extend_from_slice(b"Sec-WebSocket-Version: 13\r\n");
    buf.extend_from_slice(b"Sec-WebSocket-Key: ");
    buf.extend_from_slice(ws_key.as_bytes());
    buf.extend_from_slice(b"\r\n");
    for (name, value) in header {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

fn ws_tls_config(server_name: &str) -> TlsConfig {
    let TlsConfig {
        rand,
        time,
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        next_protos,
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
    TlsConfig {
        rand,
        time,
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        next_protos,
        server_name: server_name.to_owned(),
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
    }
}

fn split_host_port(hostport: &str) -> Result<(String, String)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, remainder) =
            rest.split_once(']').ok_or_else(|| anyhow!("address {hostport}: missing ']' in address"))?;
        let port = remainder.strip_prefix(':').ok_or_else(|| anyhow!("address {hostport}: missing port in address"))?;
        return Ok((host.to_owned(), port.to_owned()));
    }
    let (host, port) =
        hostport.rsplit_once(':').ok_or_else(|| anyhow!("address {hostport}: missing port in address"))?;
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
    use tokio::io::AsyncReadExt as _;
    use tokio::net::{TcpListener, TcpStream};

    use murmur_component::dialer::options::{NetDialer, NetDialerFunc};

    use super::*;

    fn direct_dialer() -> Arc<dyn NetDialer> {
        Arc::new(NetDialerFunc::new(move |_ctx, _network, address| {
            Box::pin(async move {
                let stream = TcpStream::connect(&address).await?;
                let stream: Box<dyn Stream> = Box::new(stream);
                Ok(stream)
            })
        }))
    }

    #[tokio::test(start_paused = true)]
    async fn dial_ws_fails_on_its_own_deadline_when_the_peer_never_answers_the_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let addr = listener.local_addr().expect("listener addr").to_string();

        let stalling_peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = [0u8; 512];
            let _ = stream.read(&mut request).await;
            std::future::pending::<()>().await;
        });

        let ctx = CancellationToken::new();
        let opts =
            TunnelDialOptions { mode: "ws".to_owned(), dial_context: Some(direct_dialer()), ..Default::default() };

        let Err(err) = tokio::time::timeout(Duration::from_secs(60), dial_ws(&ctx, &addr, opts))
            .await
            .expect("the ws dial must fail on its own deadline instead of parking")
        else {
            panic!("a peer that never answers the handshake must fail the dial");
        };
        assert!(err.to_string().contains("websocket dial timed out after"), "unexpected ws dial error: {err}");
        stalling_peer.abort();
    }
}
