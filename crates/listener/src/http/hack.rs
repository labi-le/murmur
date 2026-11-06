//! `read_request` parses one HTTP/1.x request directly off a buffered connection, bypassing a
//! server abstraction entirely.
//!
//! `proxy.rs`'s loop keeps full manual control that way (CONNECT hijack, keep-alive,
//! background-peek cancellation). No pinned crate exposes a compatible private parser,
//! so this crate re-implements the request-line and header parse with the pinned `httparse` crate
//! directly against the connection, using `httparse`'s own `Status::Complete(n)` — rather than a
//! literal `"\r\n\r\n"` scan — to find the head's real end, since `httparse` also treats a bare
//! `\n` as a valid line ending. The body-framing decisions (`Transfer-Encoding`/`Content-Length`
//! validation, chunk decoding) live in `transfer.rs`. `read_request` parses only the head and
//! records the body's framing (`content_length`/`chunked`); `proxy.rs` authenticates on that
//! before ever touching a body byte, then either drains it into `Request::body` (CONNECT, upgrade)
//! or streams it straight to the backend via `pump_body` (the plain forward path, `client.rs`), so
//! the body stays unread until a handler chooses to consume it.

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use murmur_adapter_inbound::connect_authority;
use murmur_common_net::bufconn::BufferedConn;

use super::transfer;

/// The cap on one request's request line plus header block.
pub(super) const MAX_HEADER_BYTES: usize = 1 << 20;
/// Room `httparse` allocates for parsed headers.
const MAX_HEADERS: usize = 128;

/// The parsed request, restricted to the fields and behaviour this crate's callers use.
pub(crate) struct Request {
    pub(crate) method: Method,
    /// The exact request-target as sent.
    #[expect(
        clippy::struct_field_names,
        reason = "the name keeps the request-target form distinct; `uri` would lose which target form it holds"
    )]
    pub(crate) request_uri: String,
    /// The URL scheme: empty for origin-form and CONNECT's authority-form targets.
    pub(crate) scheme: String,
    /// The URL host (authority: `host[:port]`).
    pub(crate) authority: String,
    /// The URL path plus (`?` + the raw query if present).
    pub(crate) path_and_query: String,
    pub(crate) proto_major: u8,
    pub(crate) proto_minor: u8,
    pub(crate) header: HeaderMap,
    pub(crate) host: String,
    /// The body's framing, taken from the headers `read_request` parsed. The body itself is
    /// never materialized by this crate: CONNECT never reads it at all (the raw bytes are
    /// tunnelled straight through), the upgrade path streams it with `pump_body`, and the forward path
    /// streams it with `pump_body` too (`client.rs`), matching the request body staying unread
    /// until a handler chooses to consume it (see the module doc).
    pub(crate) content_length: Option<u64>,
    pub(crate) chunked: bool,
}

/// Host/port splitting, restricted to what this crate needs: `None` when the input has no
/// `host:port`/`[host]:port` suffix, in which case the caller keeps the whole string as the host.
pub(crate) fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let port = rest.get(end + 1..)?.strip_prefix(':')?;
        if port.is_empty() {
            return None;
        }
        return Some((rest.get(..end)?, port));
    }
    let last = s.rfind(':')?;
    let host = s.get(..last)?;
    if host.contains(':') {
        return None;
    }
    let port = s.get(last + 1..)?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((host, port))
}

pub(crate) fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The request reader. Every failure (including a clean EOF at the start of a request) collapses to
/// one `Err`, since `proxy.rs`'s loop treats any error identically: stop and close the connection.
pub(crate) async fn read_request(conn: &mut BufferedConn) -> Result<Request> {
    let raw = read_header_block(conn, |b| {
        let mut headers_buf = [httparse::EMPTY_HEADER; MAX_HEADERS];
        httparse::Request::new(&mut headers_buf).parse(b)
    })
    .await?;

    let mut headers_buf = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers_buf);
    match parsed.parse(&raw).map_err(|err| anyhow!("malformed request: {err}"))? {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => bail!("malformed request: truncated headers"),
    }

    let method_str = parsed.method.ok_or_else(|| anyhow!("malformed request: missing method"))?;
    let method: Method = method_str.parse().map_err(|_| anyhow!("malformed request: invalid method {method_str}"))?;
    let target = parsed.path.ok_or_else(|| anyhow!("malformed request: missing request target"))?.to_owned();
    let version = parsed.version.ok_or_else(|| anyhow!("malformed request: missing version"))?;

    // CONNECT's authority-form target is parsed by prepending `"http://"` and stripping the
    // scheme back off, so a request-URI parse never mistakes `host:port` for a `scheme:opaque`
    // URL.
    let just_authority = method == Method::CONNECT && !target.starts_with('/');
    let parse_input = if just_authority { format!("http://{target}") } else { target.clone() };
    let parsed_target = connect_authority::parse_request_uri(&parse_input)
        .map_err(|err| anyhow!("malformed request: invalid request-target {target:?}: {err}"))?;
    let (scheme, mut authority, path_and_query, userinfo) = if just_authority {
        (String::new(), parsed_target.host, String::new(), None)
    } else {
        (parsed_target.scheme, parsed_target.host, parsed_target.path_and_query, parsed_target.userinfo)
    };

    let mut header = HeaderMap::new();
    let mut host_headers: Vec<String> = Vec::new();
    for h in parsed.headers.iter() {
        if h.name.is_empty() {
            continue;
        }
        let value = HeaderValue::from_bytes(h.value).map_err(|err| anyhow!("malformed header value: {err}"))?;
        if h.name.eq_ignore_ascii_case("host") {
            host_headers.push(String::from_utf8_lossy(h.value).trim().to_owned());
            continue;
        }
        let name = HeaderName::from_bytes(h.name.as_bytes()).map_err(|err| anyhow!("malformed header name: {err}"))?;
        header.append(name, value);
    }
    // More than one `Host` line is rejected outright.
    if host_headers.len() > 1 {
        bail!("malformed request: too many Host headers");
    }
    let host_header = host_headers.into_iter().next().unwrap_or_default();

    // `host` starts as the parsed URL's authority, falling back to the `Host` header only when
    // that authority is empty (origin-form). `proxy.rs::handle_conn` then immediately
    // re-overrides it from the raw header whenever that is non-empty — the header map keeps
    // `Host` here, unlike this struct's `header` — so the header wins whenever present, and only
    // an absent header falls back to the URL-derived authority.
    if authority.is_empty() {
        authority.clone_from(&host_header);
    }
    let host = if host_header.is_empty() { authority.clone() } else { host_header };

    if let Some((username, password)) = userinfo {
        if !header.contains_key(http::header::AUTHORIZATION) {
            let value = connect_authority::basic_auth_header(&username, &password);
            header.insert(http::header::AUTHORIZATION, HeaderValue::from_str(&value).map_err(|err| anyhow!("{err}"))?);
        }
    }

    let chunked = transfer::parse_transfer_encoding(&mut header, version)?;
    let real_length = transfer::fix_length(&mut header, chunked)?;
    transfer::fix_trailer(&mut header, chunked)?;
    let content_length = if chunked { None } else { Some(real_length) };

    Ok(Request {
        method,
        request_uri: target,
        scheme,
        authority,
        path_and_query,
        proto_major: 1,
        proto_minor: version,
        header,
        host,
        content_length,
        chunked,
    })
}

/// The `is_chunked`/`parse_content_length` for a *response* this crate reads off the wire: the
/// backend's response in `proxy.rs::forward` and the proxy's own response in
/// `upgrade.rs::read_response`. Both stay their original, simpler form (any `chunked` token on
/// any comma-joined `Transfer-Encoding` line, `Content-Length`'s first value via Rust's own
/// `u64` parser): the request-smuggling surface this module's other functions harden is a
/// request this crate parses off a client it does not trust, not a response from the single
/// backend connection this crate itself just dialed.
pub(crate) fn is_chunked(header: &HeaderMap) -> bool {
    header
        .get_all(http::header::TRANSFER_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|enc| enc.trim().eq_ignore_ascii_case("chunked"))
}

pub(crate) fn parse_content_length(header: &HeaderMap) -> Result<Option<u64>> {
    let Some(v) = header.get(http::header::CONTENT_LENGTH) else {
        return Ok(None);
    };
    let v = v.to_str().map_err(|_| anyhow!("malformed Content-Length"))?;
    Ok(Some(v.parse::<u64>().map_err(|_| anyhow!("malformed Content-Length"))?))
}

/// The line reading folded into the head-boundary scan: reads until `httparse` reports the head
/// complete, trying again after every newline byte rather than on a literal `"\r\n\r\n"` match,
/// since `httparse` accepts a bare `\n` as a line ending anywhere
/// in the head, including its final blank line. A prior version of this function scanned for
/// `"\r\n\r\n"` only, silently discarding every byte between a bare-LF-terminated head and the next
/// `"\r\n\r\n"` — this is the fix for that request-boundary desync. `try_parse` is reused for both
/// the request head (`httparse::Request`) and the response head
/// (`upgrade.rs::read_response`'s `httparse::Response`), which need identical boundary handling
/// but different parser types. An empty request line is also rejected, which a bare leading `\r` or
/// `\n` would otherwise produce — `httparse` instead silently treats it as a blank line to skip,
/// which would let a client resynchronize a broken request stream onto whatever follows.
pub(crate) async fn read_header_block(
    conn: &mut BufferedConn,
    mut try_parse: impl FnMut(&[u8]) -> std::result::Result<httparse::Status<usize>, httparse::Error>,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        if buf.len() > MAX_HEADER_BYTES {
            bail!("request headers too large");
        }
        let byte = conn.read_u8().await.map_err(|err| anyhow!("{err}"))?;
        buf.push(byte);
        if buf.len() == 1 && (byte == b'\r' || byte == b'\n') {
            bail!("malformed request: empty line before request line");
        }
        if byte != b'\n' {
            continue;
        }
        match try_parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Ok(httparse::Status::Partial) => {}
            Err(err) => bail!("malformed request: {err}"),
        }
    }
}

pub(crate) async fn read_body(conn: &mut BufferedConn, content_length: Option<u64>, chunked: bool) -> Result<Bytes> {
    if chunked {
        return transfer::read_chunked_body(conn).await;
    }
    let Some(len) = content_length else {
        return Ok(Bytes::new());
    };
    let mut buf = Vec::new();
    (&mut *conn).take(len).read_to_end(&mut buf).await.map_err(|err| anyhow!("{err}"))?;
    if buf.len() as u64 != len {
        bail!("unexpected EOF reading request body");
    }
    Ok(Bytes::from(buf))
}

/// A sink a body pump can forward chunks into, abstracting over "write bytes to a connection"
/// (the upgrade path, `upgrade.rs`, streams straight into a `BufferedConn`) and "send a result to
/// a channel" (the forward path, `client.rs`, needs a pump failure to reach hyper's outgoing body
/// as an error rather than a silently-dropped sink — see `client.rs`'s module doc). `flush` is
/// [`transfer::pump_chunked_body`]'s counterpart to the flush-after-every-write writer: only a
/// chunked *request* body is flushed per write, so a chunk already on the wire survives a later
/// chunk (e.g. a bad trailer) failing the rest of the body — `pump_fixed_body` has no per-write
/// flush, so it does not call it.
#[async_trait::async_trait]
pub(crate) trait BodySink: Send {
    async fn write_chunk(&mut self, data: &[u8]) -> Result<()>;
    async fn flush(&mut self) -> Result<()>;
}

// Blanket impl over a crate-internal trait: nothing downstream can name `BodySink`, so no foreign
// `impl` can collide with it.
#[async_trait::async_trait]
impl<W: AsyncWrite + Unpin + Send> BodySink for W {
    async fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        self.write_all(data).await.map_err(|err| anyhow!("{err}"))
    }

    async fn flush(&mut self) -> Result<()> {
        AsyncWriteExt::flush(self).await.map_err(|err| anyhow!("{err}"))
    }
}

/// Bounded chunk size the streaming pump below reads and forwards at a time: large enough that a
/// fast link isn't dominated by per-call overhead, small enough that memory use stays flat
/// regardless of how large the declared body is.
const PUMP_CHUNK_SIZE: usize = 32 * 1024;

/// Streams a request body from `src` to `sink` per its framing, forwarding each chunk as it
/// arrives instead of materializing the whole body — the streaming counterpart to [`read_body`]
/// for the forward path, which must never buffer a client-declared body in full (see the module
/// doc). `src` is `hack.rs`'s own reader trait bound rather than `BufferedConn` directly because
/// the forward path calls this after splitting the connection's read half away from its write
/// half (`client.rs`).
pub(crate) async fn pump_body<R>(
    src: &mut R,
    sink: &mut impl BodySink,
    content_length: Option<u64>,
    chunked: bool,
) -> Result<()>
where
    R: transfer::ChunkSrc,
{
    if chunked {
        transfer::pump_chunked_body(src, sink, PUMP_CHUNK_SIZE).await
    } else if let Some(len) = content_length {
        pump_fixed_body(src, sink, len).await
    } else {
        Ok(())
    }
}

async fn pump_fixed_body<R: transfer::ChunkSrc>(src: &mut R, sink: &mut impl BodySink, len: u64) -> Result<()> {
    let mut remaining = len;
    let mut buf = vec![0u8; PUMP_CHUNK_SIZE];
    while remaining > 0 {
        let want = usize::try_from(remaining.min(PUMP_CHUNK_SIZE as u64)).unwrap_or(PUMP_CHUNK_SIZE);
        let dest = buf.get_mut(..want).ok_or_else(|| anyhow!("request body chunk is larger than the pump buffer"))?;
        let n = src.read_some(dest).await.map_err(|err| anyhow!("{err}"))?;
        if n == 0 {
            bail!("unexpected EOF reading request body");
        }
        let chunk = buf.get(..n).ok_or_else(|| anyhow!("short read past the request body buffer"))?;
        sink.write_chunk(chunk).await?;
        remaining -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::{TcpListener, TcpStream};

    use murmur_common_net::{new_buffered_conn, new_extended_conn};

    use super::read_request;

    async fn client_conn(request: &[u8]) -> murmur_common_net::bufconn::BufferedConn {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let mut client = TcpStream::connect(addr).await.expect("client connect");
        client.write_all(request).await.expect("client write");
        let (server, _) = listener.accept().await.expect("accept");
        new_buffered_conn(new_extended_conn(server))
    }

    // The absolute-form request-target parse, including its userinfo-to-`Authorization` step.
    #[tokio::test]
    async fn absolute_form_userinfo_query_and_scheme_case_all_fixed() {
        let mut conn = client_conn(b"GET HTTP://user@example.com/a?x=1 HTTP/1.1\r\n\r\n").await;
        let request = read_request(&mut conn).await.expect("request parses");

        assert_eq!(request.scheme, "http");
        assert_eq!(request.path_and_query, "/a?x=1");
        assert_eq!(request.authority, "example.com");
        let auth = request.header.get(http::header::AUTHORIZATION).expect("Authorization header present");
        assert_eq!(auth, "Basic dXNlcjo=");
    }

    // Finding: "Reject empty lines before the request line". Reading the line and then parsing it
    // fails on a leading blank line; `httparse` silently skips it and resynchronizes onto the next
    // line instead.
    #[tokio::test]
    async fn leading_crlf_before_request_line_is_rejected() {
        let mut conn = client_conn(b"\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
        assert!(read_request(&mut conn).await.is_err());
    }
}
