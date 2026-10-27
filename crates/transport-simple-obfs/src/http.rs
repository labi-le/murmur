use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine as _;
use rand::Rng as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use url::Url;

use murmur_common_net::io::{OldConnAsStream, Stream, StreamAsOldConn};
use murmur_common_pool as pool;
use murmur_std_compat::net::Conn;

const DEFAULT_USER_AGENT: &str = murmur_constant::version::USER_AGENT;

const REQ_WRITE_EXCLUDE_HEADER: [&str; 5] = ["Host", "User-Agent", "Content-Length", "Transfer-Encoding", "Trailer"];

/// The RFC 9112 `tchar` set.
const fn is_token_byte(c: u8) -> bool {
    matches!(
        c,
        b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
    )
}

/// The bytes allowed in a header value: VCHAR, SP, HTAB and obs-text.
pub(crate) const fn is_valid_header_value_byte(c: u8) -> bool {
    c == b'\t' || (c >= 0x20 && c <= 0x7e) || c >= 0x80
}

pub(crate) fn trim_string(s: &str) -> &str {
    s.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\r'))
}

fn is_valid_header_field_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_token_byte)
}

fn canonical_mime_header_key(s: &str) -> String {
    let mut upper = true;
    for &c in s.as_bytes() {
        if !is_token_byte(c) {
            return s.to_owned();
        }
        if (upper && c.is_ascii_lowercase()) || (!upper && c.is_ascii_uppercase()) {
            return canonicalize_token(s);
        }
        upper = c == b'-';
    }
    s.to_owned()
}

/// Canonicalizes a header key; keys holding a space are accepted but left uncanonicalized, keys
/// holding any other invalid byte are rejected.
pub(crate) fn canonical_mime_header_key_strict(s: &str) -> Option<String> {
    if s.is_empty() {
        return None;
    }
    let mut no_canon = false;
    for &c in s.as_bytes() {
        if is_token_byte(c) {
            continue;
        }
        if c == b' ' {
            no_canon = true;
            continue;
        }
        return None;
    }
    if no_canon {
        return Some(s.to_owned());
    }
    Some(canonicalize_token(s))
}

fn canonicalize_token(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper = true;
    for c in s.chars() {
        let c = if upper { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() };
        upper = c == '-';
        out.push(c);
    }
    out
}

pub(crate) fn valid_method(method: &str) -> bool {
    !method.is_empty() && method.bytes().all(is_token_byte)
}

fn index_of(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// The header surface the simple-obfs pair uses. Keys are held in canonical form, so iteration
/// follows the sorted write order.
#[derive(Clone, Debug, Default)]
pub(crate) struct Header {
    values: BTreeMap<String, Vec<String>>,
}

impl Header {
    pub(crate) fn set(&mut self, key: &str, value: String) {
        self.values.insert(canonical_mime_header_key(key), vec![value]);
    }

    /// Adds a header entry, with the caller passing a key already canonicalized by the reader.
    pub(crate) fn add(&mut self, key: &str, value: String) {
        self.values.entry(key.to_owned()).or_default().push(value);
    }

    pub(crate) fn get(&self, key: &str) -> String {
        self.values.get(&canonical_mime_header_key(key)).and_then(|values| values.first()).cloned().unwrap_or_default()
    }

    pub(crate) fn has(&self, key: &str) -> bool {
        self.values.contains_key(&canonical_mime_header_key(key))
    }

    /// The raw `Header[key]` lookup, which does not canonicalize.
    pub(crate) fn values(&self, key: &str) -> &[String] {
        self.values.get(key).map_or(&[][..], Vec::as_slice)
    }

    pub(crate) fn del(&mut self, key: &str) {
        self.values.remove(key);
    }

    /// Folded lines extend the previous value.
    pub(crate) fn extend_last_value(&mut self, key: &str, text: &str) {
        if let Some(last) = self.values.get_mut(key).and_then(|values| values.last_mut()) {
            last.push_str(text);
        }
    }

    fn write_subset(&self, out: &mut Vec<u8>, exclude: &[&str]) {
        for (key, values) in &self.values {
            if exclude.contains(&key.as_str()) || !is_valid_header_field_name(key) {
                continue;
            }
            for value in values {
                write_header_field(out, key, value);
            }
        }
    }
}

fn write_header_field(out: &mut Vec<u8>, key: &str, value: &str) {
    let value = value.replace(['\r', '\n'], " ");
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(trim_string(&value).as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// The request surface the simple-obfs pair uses.
#[derive(Debug)]
#[expect(
    clippy::struct_field_names,
    reason = "`request_uri` is the HTTP request-target; the field is shared crate-wide"
)]
pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) request_uri: String,
    pub(crate) header: Header,
    pub(crate) host: String,
    /// The content length: `body.len()` when built by hand, `-1` for a chunked body.
    pub(crate) content_length: i64,
    pub(crate) body: Vec<u8>,
}

/// Builds a request for the body shape this module produces.
pub(crate) fn new_request(method: &str, url: &str, body: Vec<u8>) -> anyhow::Result<Request> {
    let method = if method.is_empty() { "GET" } else { method };
    if !valid_method(method) {
        return Err(anyhow::anyhow!("invalid method {method:?}"));
    }
    let parsed = Url::parse(url)?;
    let host = match parsed.port() {
        Some(port) => format!("{}:{port}", parsed.host_str().unwrap_or_default()),
        None => parsed.host_str().unwrap_or_default().to_owned(),
    };
    Ok(Request {
        method: method.to_owned(),
        request_uri: request_uri(&parsed),
        header: Header::default(),
        host,
        content_length: i64::try_from(body.len())?,
        body,
    })
}

fn request_uri(url: &Url) -> String {
    let mut result = if url.path().is_empty() { "/" } else { url.path() }.to_owned();
    if let Some(query) = url.query() {
        if !query.is_empty() {
            result.push('?');
            result.push_str(query);
        }
    }
    result
}

impl Request {
    /// Whether to send `Content-Length` for a request without transfer encodings.
    fn should_send_content_length(&self) -> bool {
        if self.content_length > 0 {
            return true;
        }
        if self.content_length < 0 {
            return false;
        }
        !matches!(self.method.as_str(), "GET" | "HEAD")
    }

    pub(crate) fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.method.as_bytes());
        out.extend_from_slice(b" ");
        out.extend_from_slice(self.request_uri.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\n");
        write_header_field(out, "Host", &self.host);

        let user_agent =
            if self.header.has("User-Agent") { self.header.get("User-Agent") } else { DEFAULT_USER_AGENT.to_owned() };
        if !user_agent.is_empty() {
            write_header_field(out, "User-Agent", &user_agent);
        }

        if self.should_send_content_length() {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.content_length).as_bytes());
        }

        self.header.write_subset(out, &REQ_WRITE_EXCLUDE_HEADER);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
    }
}

/// The HTTP simple-obfs client.
pub struct HTTPObfs {
    conn: Box<dyn Stream>,
    host: String,
    port: String,
    buf: Option<Vec<u8>>,
    offset: usize,
    first_request: bool,
    first_response: bool,
    pending_read: Option<Vec<u8>>,
    pending_read_len: usize,
    pending_write: Option<Vec<u8>>,
    pending_written: usize,
}

impl HTTPObfs {
    /// Builds the first request, smuggling the payload inside a GET request.
    fn build_request(&self, b: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut rand_bytes = [0u8; 16];
        rand::rng().fill(&mut rand_bytes);
        let mut req = new_request("GET", &format!("http://{}/", self.host), b.to_vec())?;
        let major = rand::rng().random_range(0..54);
        let minor = rand::rng().random_range(0..2);
        req.header.set("User-Agent", format!("curl/7.{major}.{minor}"));
        req.header.set("Upgrade", "websocket".to_owned());
        req.header.set("Connection", "Upgrade".to_owned());
        req.host.clone_from(&self.host);
        if self.port != "80" {
            req.host = format!("{}:{}", self.host, self.port);
        }
        req.header.set("Sec-WebSocket-Key", URL_SAFE.encode(rand_bytes));
        req.content_length = i64::try_from(b.len())?;

        let mut out = Vec::new();
        req.write_to(&mut out);
        Ok(out)
    }
}

impl core::fmt::Debug for HTTPObfs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HTTPObfs")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("offset", &self.offset)
            .field("first_request", &self.first_request)
            .field("first_response", &self.first_response)
            .field("pending_read_len", &self.pending_read_len)
            .field("pending_written", &self.pending_written)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for HTTPObfs {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if let Some(cached) = this.buf.take() {
            let n = std::cmp::min(buf.remaining(), cached.len() - this.offset);
            buf.put_slice(cached.get(this.offset..this.offset + n).unwrap_or_default());
            this.offset += n;
            if this.offset == cached.len() {
                pool::put(cached).ok();
            } else {
                this.buf = Some(cached);
            }
            return Poll::Ready(Ok(()));
        }

        if this.first_response {
            // Held in a local across the loop, then parked back before any `Pending` return.
            let mut pending = if let Some(pending) = this.pending_read.take() {
                pending
            } else {
                this.pending_read_len = 0;
                pool::get(pool::RELAY_BUFFER_SIZE)
            };
            loop {
                let pending_len = this.pending_read_len;
                if let Some(idx) = index_of(pending.get(..pending_len).unwrap_or_default(), b"\r\n\r\n") {
                    this.first_response = false;
                    this.pending_read_len = 0;
                    let length = pending_len - (idx + 4);
                    if length == 0 {
                        pool::put(pending).ok();
                        return Pin::new(&mut *this.conn).poll_read(cx, buf);
                    }
                    let copied = std::cmp::min(buf.remaining(), length);
                    buf.put_slice(pending.get(idx + 4..idx + 4 + copied).unwrap_or_default());
                    if length > copied {
                        pending.truncate(idx + 4 + length);
                        this.buf = Some(pending);
                        this.offset = idx + 4 + copied;
                    } else {
                        pool::put(pending).ok();
                    }
                    return Poll::Ready(Ok(()));
                }

                if pending_len == pending.len() {
                    this.pending_read_len = 0;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "simple-obfs http: response header too long",
                    )));
                }
                let mut read_buf = ReadBuf::new(pending.get_mut(pending_len..).unwrap_or_default());
                match Pin::new(&mut *this.conn).poll_read(cx, &mut read_buf) {
                    Poll::Pending => {
                        this.pending_read = Some(pending);
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(err)) => {
                        pool::put(pending).ok();
                        this.pending_read_len = 0;
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            pool::put(pending).ok();
                            this.pending_read_len = 0;
                            return Poll::Ready(Ok(()));
                        }
                        this.pending_read_len += n;
                    }
                }
            }
        }

        Pin::new(&mut *this.conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for HTTPObfs {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.first_request {
            let pending = if let Some(pending) = this.pending_write.take() {
                pending
            } else {
                let request = match this.build_request(buf) {
                    Ok(request) => request,
                    Err(err) => return Poll::Ready(Err(io::Error::other(err))),
                };
                this.pending_written = 0;
                request
            };
            loop {
                if this.pending_written >= pending.len() {
                    break;
                }
                let chunk = pending.get(this.pending_written..).unwrap_or_default();
                match Pin::new(&mut *this.conn).poll_write(cx, chunk) {
                    Poll::Pending => {
                        this.pending_write = Some(pending);
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(err)) => {
                        this.pending_written = 0;
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Ok(0)) => {
                        this.pending_written = 0;
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    Poll::Ready(Ok(n)) => this.pending_written += n,
                }
            }
            this.pending_written = 0;
            this.first_request = false;
            return Poll::Ready(Ok(buf.len()));
        }

        Pin::new(&mut *this.conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_shutdown(cx)
    }
}

impl Stream for HTTPObfs {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.conn.as_socket()
    }

    fn old_conn(&self) -> Option<&dyn Conn> {
        self.conn.old_conn()
    }
}

/// Creates an HTTP simple-obfs client.
#[must_use]
pub fn new_http_obfs(conn: Box<dyn Conn>, host: String, port: String) -> Box<dyn Conn> {
    let conn: Box<dyn Stream> = Box::new(OldConnAsStream(conn));
    Box::new(StreamAsOldConn::new(HTTPObfs {
        conn,
        host,
        port,
        buf: None,
        offset: 0,
        first_request: true,
        first_response: true,
        pending_read: None,
        pending_read_len: 0,
        pending_write: None,
        pending_written: 0,
    }))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    struct DuplexConn(tokio::io::DuplexStream);

    impl AsyncRead for DuplexConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DuplexConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl Stream for DuplexConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }

        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }
    }

    /// The first-request branch has no injectable randomness on either side of the comparison: a
    /// random 16-byte `Sec-WebSocket-Key` source and random `curl/<major>.<minor>` numbers. The
    /// deterministic parts asserted below are the request line, header order (`Host`,
    /// `User-Agent`, `Content-Length`, then the alphabetically sorted subset `Connection`,
    /// `Sec-Websocket-Key`, `Upgrade`), the exact canonical casing of `Sec-Websocket-Key`, and the
    /// blank line before the smuggled body.
    #[tokio::test]
    async fn build_request_header_order_and_framing() {
        let (client, _server) = tokio::io::duplex(256);
        let obfs = HTTPObfs {
            conn: Box::new(DuplexConn(client)),
            host: "example.com".to_owned(),
            port: "8080".to_owned(),
            buf: None,
            offset: 0,
            first_request: true,
            first_response: true,
            pending_read: None,
            pending_read_len: 0,
            pending_write: None,
            pending_written: 0,
        };

        let request = obfs.build_request(b"hi").unwrap();
        let text = String::from_utf8(request).unwrap();

        let ua_line = text.lines().find(|line| line.starts_with("User-Agent:")).unwrap();
        let ua_value = ua_line.trim_start_matches("User-Agent: ").trim();
        let parts: Vec<&str> = ua_value.strip_prefix("curl/7.").unwrap().split('.').collect();
        let major: u32 = parts[0].parse().unwrap();
        let minor: u32 = parts[1].parse().unwrap();
        assert!(major < 54);
        assert!(minor < 2);

        let key_line = text.lines().find(|line| line.starts_with("Sec-Websocket-Key:")).unwrap();
        let key_value = key_line.trim_start_matches("Sec-Websocket-Key: ").trim();
        let decoded = URL_SAFE.decode(key_value).expect("valid base64");
        assert_eq!(decoded.len(), 16);

        assert_eq!(
            text,
            format!(
                "GET / HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: {ua_value}\r\nContent-Length: 2\r\nConnection: Upgrade\r\nSec-Websocket-Key: {key_value}\r\nUpgrade: websocket\r\n\r\nhi"
            )
        );
    }

    struct FlagConn {
        inner: tokio::io::DuplexStream,
        closes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl AsyncRead for FlagConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for FlagConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }
    impl Conn for FlagConn {
        fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
            Ok(Box::new(murmur_std_compat::net::TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
            Ok(Box::new(murmur_std_compat::net::TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn close(&self) -> io::Result<()> {
            self.closes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// Regression for `agent://ReviewS9Obfs`'s finding: through `StreamAsOldConn(HTTPObfs{conn:
    /// OldConnAsStream(inner)})`, `close()` used to reach only `shutdown_read`/`shutdown_write`,
    /// never the dialed conn's own `close()` (which, for a `TfoConn`, cancels the pending dial).
    /// `Stream::old_conn` forwarding through `HTTPObfs` fixes it.
    #[tokio::test]
    async fn close_reaches_the_dialed_conn() {
        let (_client, server) = tokio::io::duplex(64);
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flag = FlagConn { inner: server, closes: std::sync::Arc::clone(&closes) };
        let obfs = new_http_obfs(Box::new(flag), "example.com".to_owned(), "80".to_owned());
        obfs.close().expect("close");
        assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Parent bug: `HTTPObfs::poll_read`'s first-response branch treated a response header that
    /// arrived on its own — no smuggled payload bytes in the same read — as end of stream: once
    /// `\r\n\r\n` was found, `length` (the trailing bytes past the terminator) was `0`, so it
    /// returned `Poll::Ready(Ok(()))` with `buf` untouched, which every `AsyncRead` caller reads
    /// as a clean EOF. The server and this crate's `HTTPObfsServer` both write the header and the
    /// smuggled payload as separate writes, so a real peer (or a multi-thread runtime interleaving
    /// the two writes) hits this deterministically. The fix falls through to the underlying conn
    /// instead of reporting EOF once the header alone has been consumed.
    #[tokio::test]
    async fn header_and_payload_in_separate_writes_is_not_eof() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (client, server) = tokio::io::duplex(1024);
        let mut obfs = HTTPObfs {
            conn: Box::new(DuplexConn(client)),
            host: "example.com".to_owned(),
            port: "80".to_owned(),
            buf: None,
            offset: 0,
            first_request: false,
            first_response: true,
            pending_read: None,
            pending_read_len: 0,
            pending_write: None,
            pending_written: 0,
        };
        let mut server = DuplexConn(server);

        server
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
            .await
            .expect("write header");

        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let n = obfs.read(&mut buf).await.expect("client read");
            (n, buf)
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        server.write_all(b"payload").await.expect("write payload");

        let (n, buf) = tokio::time::timeout(std::time::Duration::from_secs(5), read_task)
            .await
            .expect("must not hang waiting for the payload write")
            .expect("read task");
        assert_eq!(&buf[..n], b"payload");
    }

    /// Forwards writes untouched but forces every read to complete with at most one byte,
    /// regardless of how much data the peer already delivered. Exercises the client's `\r\n\r\n`
    /// header scan and the server's line-based request parser against the worst-case
    /// segmentation a real TCP stream can deliver.
    struct OneByteAtATime<C>(C);

    impl<C: AsyncRead + Unpin> AsyncRead for OneByteAtATime<C> {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut one = [0u8; 1];
            let mut inner_buf = ReadBuf::new(&mut one);
            match Pin::new(&mut self.get_mut().0).poll_read(cx, &mut inner_buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    if inner_buf.filled().len() == 1 {
                        buf.put_slice(&one);
                    }
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    impl<C: AsyncWrite + Unpin> AsyncWrite for OneByteAtATime<C> {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl Conn for OneByteAtATime<tokio::net::TcpStream> {
        fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
            Conn::local_addr(&self.0)
        }
        fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
            Conn::remote_addr(&self.0)
        }
        fn close(&self) -> io::Result<()> {
            Conn::close(&self.0)
        }
    }

    /// Parent bug: `HTTPObfs::poll_read`'s first-response branch took exactly one `poll_read`
    /// from the underlying conn, and if the response's `\r\n\r\n` terminator wasn't already inside
    /// that single read, it discarded the bytes and reported a spurious zero-byte "read" (EOF to
    /// every caller) instead of accumulating across polls. Over a real socket, forcing every read
    /// on both sides to land one byte at a time — the worst-case segmentation TCP can deliver —
    /// used to fail this with an early EOF; the fix accumulates the response header, and keeps
    /// the server's line-based request parser's partial line alive across a `Pending` the same
    /// way, across as many `poll_read` calls as it takes.
    #[tokio::test(flavor = "multi_thread")]
    async fn interop_1_byte_segments_both_directions() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::{TcpListener, TcpStream};

        use super::super::http_server::new_http_obfs_server;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client_payload = b"hello from client, obfuscated as an http request".to_vec();
        let server_payload = b"hello from server, this is a longer reply payload".to_vec();
        let client_payload_check = client_payload.clone();
        let server_payload_send = server_payload.clone();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut obfs = new_http_obfs_server(Box::new(OneByteAtATime(stream)));
            let mut received = vec![0u8; client_payload_check.len()];
            obfs.read_exact(&mut received).await.expect("server read");
            assert_eq!(received, client_payload_check);
            obfs.write_all(&server_payload_send).await.expect("server write");
            obfs.flush().await.expect("server flush");
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut obfs = new_http_obfs(Box::new(OneByteAtATime(stream)), "example.com".to_owned(), "80".to_owned());
        obfs.write_all(&client_payload).await.expect("client write");
        obfs.flush().await.expect("client flush");
        let mut received = vec![0u8; server_payload.len()];
        obfs.read_exact(&mut received).await.expect("client read");
        assert_eq!(received, server_payload);

        server.await.expect("server task");
    }

    /// The response header and its full smuggled payload arriving together in a single read on
    /// the underlying socket (the common case: one real TCP segment carrying both) must still
    /// hand back exactly the payload when the caller drains it through small reads — pins the
    /// `HTTPObfs::buf`/`offset` leftover-buffering path the accumulator rewrite must not disturb.
    #[tokio::test(flavor = "multi_thread")]
    async fn interop_pipelined_payload_in_same_segment_as_header() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::{TcpListener, TcpStream};

        use super::super::http_server::new_http_obfs_server;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let client_payload = b"ping".to_vec();
        let server_payload = b"a much longer server payload that spans several small caller reads".to_vec();
        let client_payload_check = client_payload.clone();
        let server_payload_send = server_payload.clone();
        let server_payload_check = server_payload.clone();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut obfs = new_http_obfs_server(Box::new(stream));
            let mut received = vec![0u8; client_payload_check.len()];
            obfs.read_exact(&mut received).await.expect("server read");
            assert_eq!(received, client_payload_check);
            obfs.write_all(&server_payload_send).await.expect("server write");
            obfs.flush().await.expect("server flush");
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut obfs = new_http_obfs(Box::new(stream), "example.com".to_owned(), "80".to_owned());
        obfs.write_all(&client_payload).await.expect("client write");
        obfs.flush().await.expect("client flush");

        // Give the server's single `write_all` a chance to land as one TCP segment before the
        // client starts reading it back through a caller buffer far smaller than the payload.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut received = Vec::new();
        let mut chunk = [0u8; 3];
        while received.len() < server_payload_check.len() {
            let n = obfs.read(&mut chunk).await.expect("client read");
            assert!(n > 0, "unexpected EOF before the full payload was read");
            received.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(received, server_payload_check);

        server.await.expect("server task");
    }

    struct PendOnceWriter {
        written: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
        pend_after: Option<usize>,
    }
    impl AsyncRead for PendOnceWriter {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for PendOnceWriter {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let mut written = this.written.lock();
            if let Some(limit) = this.pend_after {
                if written.len() >= limit {
                    this.pend_after = None;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let n = std::cmp::min(buf.len(), limit - written.len());
                written.extend_from_slice(&buf[..n]);
                return Poll::Ready(Ok(n));
            }
            written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl Stream for PendOnceWriter {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }
        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }
    }

    /// Parent bug: `HTTPObfs::poll_write`'s first-request branch set `first_request = false`
    /// before its write loop, not after. A `Pending` partway through writing the smuggled request
    /// (tokio's per-task coop budget forces this even on an idle localhost socket) made the next
    /// `poll_write` call skip straight to `Pin::new(&mut *this.conn).poll_write(cx, buf)` with the
    /// caller's raw payload, corrupting the still-unfinished header. Keeping `first_request` true
    /// until the loop actually completes lets a resumed write finish the header first.
    #[tokio::test]
    async fn write_pending_midway_through_header_keeps_request_intact() {
        use tokio::io::AsyncWriteExt as _;

        let written = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let writer = PendOnceWriter { written: std::sync::Arc::clone(&written), pend_after: Some(40) };
        let mut obfs = HTTPObfs {
            conn: Box::new(writer),
            host: "example.com".to_owned(),
            port: "80".to_owned(),
            buf: None,
            offset: 0,
            first_request: true,
            first_response: true,
            pending_read: None,
            pending_read_len: 0,
            pending_write: None,
            pending_written: 0,
        };
        let body = b"hello world payload".to_vec();
        tokio::time::timeout(std::time::Duration::from_secs(5), obfs.write_all(&body))
            .await
            .expect("must not hang")
            .expect("write_all");

        let got = written.lock().clone();
        let idx = got.windows(4).position(|w| w == b"\r\n\r\n").expect("full header terminator present");
        assert_eq!(&got[idx + 4..], &body[..], "request corrupted after a mid-request Pending: {got:?}");
    }
}
