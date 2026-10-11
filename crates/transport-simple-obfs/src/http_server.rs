use std::io;
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{ready, Context, Poll};

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine as _;
use chrono::Local;
use rand::Rng as _;
use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadBuf};
use url::Url;

use murmur_common_net::io::{OldConnAsStream, Stream, StreamAsOldConn};
use murmur_std_compat::net::Conn;

use super::http::{
    canonical_mime_header_key_strict, is_valid_header_value_byte, trim_string, valid_method, Header, Request,
};

/// The buffered read-ahead size.
const BUF_READER_SIZE: usize = 4096;

const MAX_LINE_LENGTH: usize = 4096;

static V_MAJOR: LazyLock<usize> = LazyLock::new(|| rand::rng().random_range(0..11));

static V_MINOR: LazyLock<usize> = LazyLock::new(|| rand::rng().random_range(0..12));

/// A malformed-request failure, standing in for a protocol-level reader error.
fn protocol_error(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The bytes up to and including the `\n`.
fn poll_read_line<R>(r: &mut R, cx: &mut Context<'_>, line: &mut Vec<u8>, limit: Option<usize>) -> Poll<io::Result<()>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    loop {
        let mut byte = [0u8; 1];
        let n = ready!(poll_read_some(r, cx, &mut byte))?;
        if n == 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Poll::Ready(Ok(()));
        }
        if limit.is_some_and(|limit| line.len() >= limit) {
            return Poll::Ready(Err(protocol_error("header line too long".to_owned())));
        }
    }
}

/// One `Read` call; `Ok(0)` means end of stream.
fn poll_read_some<R>(r: &mut R, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut read_buf = ReadBuf::new(buf);
    ready!(Pin::new(r).poll_read(cx, &mut read_buf))?;
    Poll::Ready(Ok(read_buf.filled().len()))
}

/// The read-exact contract. Unlike a plain stack-buffer read, `buf` is a field on `RequestParser` (as
/// `line` is for header lines), so a `Pending` mid-read leaves the bytes already read in place
/// for the next poll instead of dropping them.
fn poll_read_exact_into<R>(r: &mut R, cx: &mut Context<'_>, buf: &mut Vec<u8>, want: usize) -> Poll<io::Result<()>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    while buf.len() < want {
        let mut tmp = [0u8; 2];
        let n = std::cmp::min(tmp.len(), want - buf.len());
        let read = ready!(poll_read_some(r, cx, tmp.get_mut(..n).unwrap_or_default()))?;
        if read == 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
        }
        buf.extend_from_slice(tmp.get(..read).unwrap_or_default());
    }
    Poll::Ready(Ok(()))
}

/// Strips the line terminator, leaving a stray `\r` in place.
fn strip_line_ending(raw: &[u8]) -> &[u8] {
    let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
    raw.strip_suffix(b"\r").unwrap_or(raw)
}

fn parse_request_line(line: &str) -> Option<(&str, &str, &str)> {
    let (method, rest) = line.split_once(' ')?;
    let (request_uri, proto) = rest.split_once(' ')?;
    Some((method, request_uri, proto))
}

fn parse_http_version(vers: &str) -> Option<(u8, u8)> {
    match vers {
        "HTTP/1.1" => return Some((1, 1)),
        "HTTP/1.0" => return Some((1, 0)),
        _ => {}
    }
    let rest = vers.strip_prefix("HTTP/")?;
    let (major, minor) = rest.split_once('.')?;
    if major.is_empty() || minor.is_empty() {
        return None;
    }
    let major = major.parse::<u8>().ok()?;
    let minor = minor.parse::<u8>().ok()?;
    Some((major, minor))
}

/// Parses a request target; also yields the host.
fn parse_request_uri(rawurl: &str) -> Option<(String, String)> {
    let parsed = if rawurl.starts_with('/') {
        // A path-absolute target carries no authority; the url crate needs a base to parse it.
        Url::parse(&format!("http://example.invalid{rawurl}")).ok()?
    } else {
        Url::parse(rawurl).ok()?
    };
    let mut uri = if parsed.path().is_empty() { "/" } else { parsed.path() }.to_owned();
    if let Some(query) = parsed.query() {
        if !query.is_empty() {
            uri.push('?');
            uri.push_str(query);
        }
    }
    let host = if rawurl.starts_with('/') {
        String::new()
    } else {
        match parsed.port() {
            Some(port) => format!("{}:{port}", parsed.host_str().unwrap_or_default()),
            None => parsed.host_str().unwrap_or_default().to_owned(),
        }
    };
    Some((uri, host))
}

/// Parses a Content-Length as an unsigned 63-bit value.
fn parse_content_length(value: &str) -> io::Result<i64> {
    let value = trim_string(value);
    if value.is_empty() {
        return Err(protocol_error(format!("invalid empty Content-Length {value:?}")));
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(protocol_error(format!("bad Content-Length {value:?}")));
    }
    match value.parse::<u64>() {
        Ok(n) => i64::try_from(n).map_err(|_| protocol_error(format!("bad Content-Length {value:?}"))),
        Err(_) => Err(protocol_error(format!("bad Content-Length {value:?}"))),
    }
}

fn parse_hex_uint(v: &[u8]) -> io::Result<u64> {
    if v.is_empty() {
        return Err(protocol_error("empty hex number for chunk length".to_owned()));
    }
    let mut n: u64 = 0;
    for (i, &b) in v.iter().enumerate() {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(protocol_error("invalid byte in chunk length".to_owned())),
        };
        if i == 16 {
            return Err(protocol_error("http chunk length too large".to_owned()));
        }
        n <<= 4;
        n |= u64::from(digit);
    }
    Ok(n)
}

fn trim_trailing_whitespace(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && matches!(b.get(end - 1), Some(b' ' | b'\t')) {
        end -= 1;
    }
    b.get(..end).unwrap_or_default()
}

/// Leading and trailing spaces and tabs only (not `\r`/`\n`, already stripped by the line reader).
fn trim_ows(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(b.len());
    let end = b.iter().rposition(|&c| c != b' ' && c != b'\t').map_or(start, |i| i + 1);
    b.get(start..end).unwrap_or_default()
}

/// Elides a trailing `\r\n` or bare `\n`, leaving an embedded `\r` (one that is not immediately
/// followed by the line's own `\n`) in place.
fn read_line_keep_cr(raw: &[u8]) -> &[u8] {
    raw.strip_suffix(b"\r").unwrap_or(raw)
}

/// Reads the trailer block as MIME headers, over the bytes already buffered by the `\r\n\r\n`
/// budget scan (proven sufficient: any blank-line boundary a MIME header read would stop at occurs
/// at or before the first literal `\r\n\r\n`, since that substring itself is, read line by line,
/// an empty line immediately followed by another line break). Bare LF ends a line exactly as the
/// line reader above does, and a line starting with a space or tab folds onto the previous line.
/// Returns the number of bytes consumed as the trailer, including its terminating blank line.
/// Anything after that is tunnel data the parser never touched.
fn parse_trailer(buf: &[u8]) -> io::Result<usize> {
    let too_long = || protocol_error("http: suspiciously long trailer after chunked body".to_owned());
    let mut pos = 0usize;
    let mut checked_leading_space = false;
    loop {
        if !checked_leading_space {
            checked_leading_space = true;
            if matches!(buf.get(pos), Some(b' ' | b'\t')) {
                let head = buf.get(pos..).unwrap_or_default();
                let nl = head.iter().position(|&b| b == b'\n').map_or(buf.len(), |i| pos + i);
                let raw = buf.get(pos..std::cmp::min(nl, pos + 80)).unwrap_or_default();
                let text = String::from_utf8_lossy(read_line_keep_cr(raw)).into_owned();
                return Err(protocol_error(format!("malformed MIME header initial line: {text:?}")));
            }
        }

        let rest = buf.get(pos..).unwrap_or_default();
        let Some(nl_rel) = rest.iter().position(|&b| b == b'\n') else {
            return Err(too_long());
        };
        let nl_abs = pos + nl_rel;
        let stripped = read_line_keep_cr(buf.get(pos..nl_abs).unwrap_or_default());
        let mut after = nl_abs + 1;

        if stripped.is_empty() {
            return Ok(after);
        }
        if !stripped.contains(&b':') {
            let text = String::from_utf8_lossy(stripped).into_owned();
            return Err(protocol_error(format!("malformed MIME header: missing colon: {text:?}")));
        }

        let mut folded = trim_ows(stripped).to_vec();
        while matches!(buf.get(after), Some(b' ' | b'\t')) {
            let mut p = after;
            while matches!(buf.get(p), Some(b' ' | b'\t')) {
                p += 1;
            }
            let tail = buf.get(p..).unwrap_or_default();
            let Some(nl_rel2) = tail.iter().position(|&b| b == b'\n') else {
                return Err(too_long());
            };
            let nl_abs2 = p + nl_rel2;
            folded.push(b' ');
            folded.extend_from_slice(trim_ows(read_line_keep_cr(buf.get(p..nl_abs2).unwrap_or_default())));
            after = nl_abs2 + 1;
        }

        let Some(colon) = folded.iter().position(|&b| b == b':') else {
            let text = String::from_utf8_lossy(&folded).into_owned();
            return Err(protocol_error(format!("malformed MIME header line: {text:?}")));
        };
        let (key, value) = (folded.get(..colon).unwrap_or_default(), folded.get(colon + 1..).unwrap_or_default());
        let key_text = String::from_utf8_lossy(key).into_owned();
        if canonical_mime_header_key_strict(&key_text).is_none() {
            let text = String::from_utf8_lossy(&folded).into_owned();
            return Err(protocol_error(format!("malformed MIME header line: {text:?}")));
        }
        if !value.iter().all(|&b| is_valid_header_value_byte(b)) {
            let text = String::from_utf8_lossy(&folded).into_owned();
            return Err(protocol_error(format!("malformed MIME header line: {text:?}")));
        }

        pos = after;
    }
}

/// Parses a request up to the headers, stopped before the body is read so the caller can
/// reject a non-obfs request without consuming its body.
struct RequestParser {
    header_phase: HeaderPhase,
    body_phase: BodyPhase,
    line: Vec<u8>,
    request: Request,
    proto_major: u8,
    proto_minor: u8,
    first_header_line: bool,
    last_header_key: String,
    chunk_excess: i64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HeaderPhase {
    RequestLine,
    HeaderLine,
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BodyPhase {
    /// A zero-length body.
    None,
    /// A body of known length.
    Length(usize),
    /// `Transfer-Encoding: chunked`, tracked by these states.
    ChunkSize,
    ChunkData(usize),
    ChunkEnd,
    /// The (usually empty) trailer headers after the final `0\r\n` chunk
    /// line, consumed up to and including the blank line that terminates them.
    Trailer,
    Done,
}

impl RequestParser {
    fn new() -> Self {
        Self {
            header_phase: HeaderPhase::RequestLine,
            body_phase: BodyPhase::None,
            line: Vec::new(),
            request: Request {
                method: String::new(),
                request_uri: String::new(),
                header: Header::default(),
                host: String::new(),
                content_length: 0,
                body: Vec::new(),
            },
            proto_major: 1,
            proto_minor: 1,
            first_header_line: true,
            last_header_key: String::new(),
            chunk_excess: 0,
        }
    }

    fn poll_headers(&mut self, conn: &mut BufReader<Box<dyn Stream>>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.header_phase {
                HeaderPhase::Done => return Poll::Ready(Ok(())),
                HeaderPhase::RequestLine => {
                    ready!(poll_read_line(conn, cx, &mut self.line, None))?;
                    let line = String::from_utf8_lossy(strip_line_ending(&self.line)).into_owned();
                    let Some((method, request_uri, proto)) = parse_request_line(&line) else {
                        return Poll::Ready(Err(protocol_error(format!("malformed HTTP request {line:?}"))));
                    };
                    if !valid_method(method) {
                        return Poll::Ready(Err(protocol_error(format!("invalid method {method:?}"))));
                    }
                    let Some((major, minor)) = parse_http_version(proto) else {
                        return Poll::Ready(Err(protocol_error(format!("malformed HTTP version {proto:?}"))));
                    };
                    let rawurl = if method == "CONNECT" && !request_uri.starts_with('/') {
                        format!("http://{request_uri}")
                    } else {
                        request_uri.to_owned()
                    };
                    let Some((uri, url_host)) = parse_request_uri(&rawurl) else {
                        return Poll::Ready(Err(protocol_error(format!("invalid URI for request {rawurl:?}"))));
                    };

                    method.clone_into(&mut self.request.method);
                    self.request.request_uri = uri;
                    self.request.host = url_host;
                    self.proto_major = major;
                    self.proto_minor = minor;
                    self.line.clear();
                    self.header_phase = HeaderPhase::HeaderLine;
                }
                HeaderPhase::HeaderLine => {
                    ready!(poll_read_line(conn, cx, &mut self.line, None))?;
                    let raw = strip_line_ending(&self.line).to_vec();
                    self.line.clear();
                    if raw.is_empty() {
                        if let Err(err) = self.finish_headers() {
                            return Poll::Ready(Err(err));
                        }
                        self.header_phase = HeaderPhase::Done;
                        continue;
                    }
                    let folded = matches!(raw.first(), Some(b' ' | b'\t'));
                    if folded {
                        let text = String::from_utf8_lossy(&raw).into_owned();
                        if self.first_header_line {
                            return Poll::Ready(Err(protocol_error(format!(
                                "malformed MIME header initial line: {text:?}"
                            ))));
                        }
                        let text = format!(" {}", trim_string(&text));
                        self.request.header.extend_last_value(&self.last_header_key, &text);
                        continue;
                    }
                    self.first_header_line = false;
                    let text = String::from_utf8_lossy(&raw).into_owned();
                    let text = trim_string(&text).to_owned();
                    let Some(colon) = text.find(':') else {
                        return Poll::Ready(Err(protocol_error(format!(
                            "malformed MIME header: missing colon: {text:?}"
                        ))));
                    };
                    let (key, value) = text.split_at(colon);
                    let Some(key) = canonical_mime_header_key_strict(key) else {
                        return Poll::Ready(Err(protocol_error(format!("malformed MIME header line: {text:?}"))));
                    };
                    let value = value.strip_prefix(':').unwrap_or(value).trim_start_matches([' ', '\t']);
                    if !value.bytes().all(is_valid_header_value_byte) {
                        return Poll::Ready(Err(protocol_error(format!("malformed MIME header line: {text:?}"))));
                    }
                    self.request.header.add(&key, value.to_owned());
                    self.last_header_key = key;
                }
            }
        }
    }

    /// Parses the transfer encoding and fixes the body length.
    fn finish_headers(&mut self) -> io::Result<()> {
        // The host is resolved from the URL or the Host header, and that header is then dropped.
        if self.request.host.is_empty() {
            self.request.host = self.request.header.get("Host");
        }
        self.request.header.del("Host");

        let transfer_encodings = self.request.header.values("Transfer-Encoding").to_vec();
        let mut chunked = false;
        if !transfer_encodings.is_empty() {
            self.request.header.del("Transfer-Encoding");
            // Ignore Transfer-Encoding on HTTP/1.0 requests.
            if self.proto_major > 1 || (self.proto_major == 1 && self.proto_minor >= 1) {
                let [encoding] = transfer_encodings.as_slice() else {
                    return Err(protocol_error(format!("too many transfer encodings: {transfer_encodings:?}")));
                };
                if !encoding.eq_ignore_ascii_case("chunked") {
                    return Err(protocol_error(format!("unsupported transfer encoding: {encoding:?}")));
                }
                chunked = true;
            }
        }

        let mut content_lengths = self.request.header.values("Content-Length").to_vec();
        if content_lengths.len() > 1 {
            let first = trim_string(content_lengths.first().map_or("", String::as_str)).to_owned();
            for value in content_lengths.iter().skip(1) {
                if first != trim_string(value) {
                    return Err(protocol_error(format!(
                        "http: message cannot contain multiple Content-Length headers; got {content_lengths:?}"
                    )));
                }
            }
            self.request.header.del("Content-Length");
            self.request.header.add("Content-Length", first);
            content_lengths = self.request.header.values("Content-Length").to_vec();
        }

        let length = match content_lengths.first() {
            Some(value) => parse_content_length(value)?,
            None => 0,
        };

        self.request.content_length = if chunked {
            self.request.header.del("Content-Length");
            -1
        } else if content_lengths.is_empty() {
            self.request.header.del("Content-Length");
            0
        } else {
            length
        };

        self.body_phase = match self.request.content_length {
            -1 => BodyPhase::ChunkSize,
            length if length > 0 => {
                let Ok(length) = usize::try_from(length) else {
                    return Err(protocol_error("Content-Length does not fit in usize".to_owned()));
                };
                BodyPhase::Length(length)
            }
            _ => BodyPhase::None,
        };
        Ok(())
    }

    fn poll_body(&mut self, conn: &mut BufReader<Box<dyn Stream>>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.body_phase {
                BodyPhase::Done => return Poll::Ready(Ok(())),
                BodyPhase::None => self.body_phase = BodyPhase::Done,
                BodyPhase::Length(remaining) => {
                    let mut chunk = [0u8; 8192];
                    let want = std::cmp::min(remaining, chunk.len());
                    let read = ready!(poll_read_some(conn, cx, chunk.get_mut(..want).unwrap_or_default()))?;
                    if read == 0 {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    }
                    self.request.body.extend_from_slice(chunk.get(..read).unwrap_or_default());
                    self.body_phase =
                        if read == remaining { BodyPhase::Done } else { BodyPhase::Length(remaining - read) };
                }
                BodyPhase::ChunkSize => {
                    ready!(poll_read_line(conn, cx, &mut self.line, Some(BUF_READER_SIZE)))?;
                    let line = std::mem::take(&mut self.line);
                    let Some(cr) = line.iter().position(|&b| b == b'\r') else {
                        return Poll::Ready(Err(protocol_error("chunked line ends with bare LF".to_owned())));
                    };
                    if cr != line.len().saturating_sub(2) {
                        return Poll::Ready(Err(protocol_error("invalid CR in chunked line".to_owned())));
                    }
                    let line = line.get(..cr).unwrap_or_default();
                    if line.len() >= MAX_LINE_LENGTH {
                        return Poll::Ready(Err(protocol_error("header line too long".to_owned())));
                    }
                    let line_len = i64::try_from(line.len()).unwrap_or(i64::MAX);
                    self.chunk_excess = self.chunk_excess.wrapping_add(line_len + 2);
                    let line = trim_trailing_whitespace(line);
                    let line = match line.iter().position(|&b| b == b';') {
                        Some(semi) => line.get(..semi).unwrap_or_default(),
                        None => line,
                    };
                    let size = match parse_hex_uint(line) {
                        Ok(size) => size,
                        Err(err) => return Poll::Ready(Err(err)),
                    };
                    self.chunk_excess =
                        self.chunk_excess.wrapping_sub(16i64.wrapping_add(2i64.wrapping_mul(size.cast_signed())));
                    if self.chunk_excess < 0 {
                        self.chunk_excess = 0;
                    }
                    if self.chunk_excess > 16 * 1024 {
                        return Poll::Ready(Err(protocol_error(
                            "chunked encoding contains too much non-data".to_owned(),
                        )));
                    }
                    let Ok(chunk_len) = usize::try_from(size) else {
                        return Poll::Ready(Err(protocol_error("http chunk length too large".to_owned())));
                    };
                    self.body_phase = if size == 0 { BodyPhase::Trailer } else { BodyPhase::ChunkData(chunk_len) };
                }
                BodyPhase::ChunkData(remaining) => {
                    let mut chunk = [0u8; 8192];
                    let want = std::cmp::min(remaining, chunk.len());
                    let read = ready!(poll_read_some(conn, cx, chunk.get_mut(..want).unwrap_or_default()))?;
                    if read == 0 {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    }
                    self.request.body.extend_from_slice(chunk.get(..read).unwrap_or_default());
                    self.body_phase =
                        if read == remaining { BodyPhase::ChunkEnd } else { BodyPhase::ChunkData(remaining - read) };
                }
                BodyPhase::ChunkEnd => {
                    ready!(poll_read_exact_into(conn, cx, &mut self.line, 2))?;
                    let crlf = std::mem::take(&mut self.line);
                    if crlf != b"\r\n" {
                        return Poll::Ready(Err(protocol_error("malformed chunked encoding".to_owned())));
                    }
                    self.body_phase = BodyPhase::ChunkSize;
                }
                BodyPhase::Trailer => return self.poll_trailer(conn, cx),
            }
        }
    }

    /// The trailer loop: stops at the blank line that terminates the trailer block.
    fn poll_trailer(&mut self, conn: &mut BufReader<Box<dyn Stream>>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.line.ends_with(b"\r\n\r\n") {
                match parse_trailer(&self.line) {
                    Ok(consumed) => {
                        self.request.body.extend_from_slice(self.line.get(consumed..).unwrap_or_default());
                        self.line.clear();
                        self.body_phase = BodyPhase::Done;
                    }
                    Err(err) => return Poll::Ready(Err(err)),
                }
                return Poll::Ready(Ok(()));
            }
            if self.line.len() == 2 && self.line == b"\r\n" {
                self.line.clear();
                self.body_phase = BodyPhase::Done;
                return Poll::Ready(Ok(()));
            }
            if self.line.len() >= BUF_READER_SIZE {
                return Poll::Ready(Err(protocol_error(
                    "http: suspiciously long trailer after chunked body".to_owned(),
                )));
            }
            let mut byte = [0u8; 1];
            let n = ready!(poll_read_some(conn, cx, &mut byte))?;
            if n == 0 {
                let err = if self.line.len() < 2 {
                    protocol_error("http: unexpected EOF reading trailer".to_owned())
                } else {
                    protocol_error("http: suspiciously long trailer after chunked body".to_owned())
                };
                return Poll::Ready(Err(err));
            }
            self.line.push(byte[0]);
        }
    }
}

/// The HTTP simple-obfs server.
pub struct HTTPObfsServer {
    conn: BufReader<Box<dyn Stream>>,
    buf: Option<Vec<u8>>,
    offset: usize,
    first_request: bool,
    first_response: bool,
    parse: Option<RequestParser>,
    pending_response: Option<Vec<u8>>,
    pending_written: usize,
}

impl core::fmt::Debug for HTTPObfsServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HTTPObfsServer")
            .field("offset", &self.offset)
            .field("first_request", &self.first_request)
            .field("first_response", &self.first_response)
            .field("pending_written", &self.pending_written)
            .finish_non_exhaustive()
    }
}

impl HTTPObfsServer {
    fn build_response() -> Vec<u8> {
        let mut rand_bytes = [0u8; 16];
        rand::rng().fill(&mut rand_bytes);
        let major = V_MAJOR.to_string();
        let minor = V_MINOR.to_string();
        let date = Local::now().format("%a, %d %b %Y %H:%M:%S %Z").to_string();
        let accept = URL_SAFE.encode(rand_bytes);
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.{major}.{minor}\r\nDate: {date}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .into_bytes()
    }
}

impl AsyncRead for HTTPObfsServer {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if let Some(cached) = this.buf.take() {
            let n = std::cmp::min(buf.remaining(), cached.len() - this.offset);
            buf.put_slice(cached.get(this.offset..this.offset + n).unwrap_or_default());
            this.offset += n;
            if this.offset == cached.len() {
                this.offset = 0;
            } else {
                this.buf = Some(cached);
            }
            return Poll::Ready(Ok(()));
        }

        if this.first_request {
            let parser = this.parse.get_or_insert_with(RequestParser::new);
            if parser.header_phase != HeaderPhase::Done {
                match parser.poll_headers(&mut this.conn, cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(())) => {}
                }
            }
            if parser.request.method != "GET" || parser.request.header.get("Connection") != "Upgrade" {
                return Poll::Ready(Ok(()));
            }
            match parser.poll_body(&mut this.conn, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {}
            }

            let body = std::mem::take(&mut parser.request.body);
            this.first_request = false;
            let n = std::cmp::min(buf.remaining(), body.len());
            buf.put_slice(body.get(..n).unwrap_or_default());
            if n < body.len() {
                this.buf = Some(body);
                this.offset = n;
            }
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for HTTPObfsServer {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.first_response {
            if this.pending_response.is_none() {
                this.pending_written = 0;
            }
            let pending = this.pending_response.get_or_insert_with(Self::build_response);
            loop {
                if this.pending_written >= pending.len() {
                    break;
                }
                let chunk = pending.get(this.pending_written..).unwrap_or_default();
                match Pin::new(&mut this.conn).poll_write(cx, chunk) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(n)) => this.pending_written += n,
                }
            }
            this.pending_response = None;
            this.pending_written = 0;
            this.first_response = false;
        }

        Pin::new(&mut this.conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl Stream for HTTPObfsServer {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.get_ref().local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.get_ref().peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.get_ref().shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.get_ref().shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.conn.get_ref().as_socket()
    }

    fn old_conn(&self) -> Option<&dyn Conn> {
        self.conn.get_ref().old_conn()
    }
}

/// Creates an HTTP simple-obfs server.
#[must_use]
pub fn new_http_obfs_server(conn: Box<dyn Conn>) -> Box<dyn Conn> {
    let conn: Box<dyn Stream> = Box::new(OldConnAsStream(conn));
    Box::new(StreamAsOldConn::new(HTTPObfsServer {
        conn: BufReader::with_capacity(BUF_READER_SIZE, conn),
        buf: None,
        offset: 0,
        first_request: true,
        first_response: true,
        parse: None,
        pending_response: None,
        pending_written: 0,
    }))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

    use super::*;
    use murmur_std_compat::net::{Addr, TcpAddr};

    struct PipeConn(tokio::io::DuplexStream);

    impl AsyncRead for PipeConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PipeConn {
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

    impl Conn for PipeConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    const UPGRADE_HEADERS: &str =
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nTransfer-Encoding: chunked\r\n\r\n";

    /// Parent bug: `poll_read_line` pushed bytes into `self.line` with no bound while waiting for
    /// `\n`, so a chunk-size line that never terminates grows the `Vec` without limit. A line over
    /// the 4096-byte buffer limit fails closed instead; this pins that outcome.
    #[tokio::test]
    async fn chunk_size_line_over_4096_bytes_errors() {
        let (client_side, server_side) = tokio::io::duplex(1 << 20);
        let mut server = new_http_obfs_server(Box::new(PipeConn(server_side)));
        let mut client = PipeConn(client_side);
        client.write_all(UPGRADE_HEADERS.as_bytes()).await.expect("write request headers");
        client.write_all(&vec![b'0'; 8192]).await.expect("write endless chunk-size line");

        let mut buf = [0u8; 16];
        let result = tokio::time::timeout(Duration::from_secs(5), server.read(&mut buf))
            .await
            .expect("must not hang reading an unterminated chunk-size line");
        let err = result.expect_err("an unterminated 4096+ byte line must be rejected");
        assert_eq!(err.to_string(), "header line too long");
    }

    /// Parent bug: a maliciously large chunk-size line overflowed `i64` (panicking under
    /// `overflow-checks`). The wrapping arithmetic stays silent, and this pins the non-panicking
    /// outcome.
    #[tokio::test]
    async fn chunk_size_overflow_does_not_panic() {
        let (client_side, server_side) = tokio::io::duplex(1 << 16);
        let mut server = new_http_obfs_server(Box::new(PipeConn(server_side)));
        let mut client = PipeConn(client_side);
        let request = format!("{UPGRADE_HEADERS}4000000000000000\r\n");
        client.write_all(request.as_bytes()).await.expect("write request");

        let mut buf = [0u8; 16];
        let result = tokio::time::timeout(Duration::from_millis(200), server.read(&mut buf)).await;
        assert!(result.is_err(), "read should still be pending on the declared (unsent) chunk data, not panicked");
    }

    /// A well-behaved peer's short chunked body must still parse the same as before either fix.
    #[tokio::test]
    async fn well_formed_chunked_body_still_parses() {
        let (client_side, server_side) = tokio::io::duplex(1 << 16);
        let mut server = new_http_obfs_server(Box::new(PipeConn(server_side)));
        let mut client = PipeConn(client_side);
        let request = format!("{UPGRADE_HEADERS}5\r\nhello\r\n0\r\n\r\n");
        client.write_all(request.as_bytes()).await.expect("write request");

        let mut buf = [0u8; 32];
        let n = tokio::time::timeout(Duration::from_secs(5), server.read(&mut buf))
            .await
            .expect("must not hang")
            .expect("read body");
        assert_eq!(&buf[..n], b"hello");
    }

    /// Parent bug: `BodyPhase::ChunkEnd` read the post-chunk-data `\r\n` into a stack-local
    /// buffer through `poll_read_exact`. A `Pending` between the `\r` and the `\n` dropped the
    /// `\r` already read, so the next poll saw `\n` where it expected `\r` and failed with
    /// "malformed chunked encoding". Splitting the writes with a real delay forces a genuine
    /// `Pending` at exactly that boundary.
    #[tokio::test]
    async fn chunk_end_crlf_split_across_writes_is_not_lost() {
        let (client_side, server_side) = tokio::io::duplex(1 << 16);
        let mut server = new_http_obfs_server(Box::new(PipeConn(server_side)));
        let mut client = PipeConn(client_side);
        client.write_all(format!("{UPGRADE_HEADERS}5\r\nhello\r").as_bytes()).await.expect("write up to the CR");

        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let n = server.read(&mut buf).await.expect("server read");
            (n, buf)
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        client.write_all(b"\n0\r\n\r\n").await.expect("write the LF and the trailer");

        let (n, buf) = tokio::time::timeout(Duration::from_secs(5), read_task)
            .await
            .expect("must not hang losing the CR")
            .expect("read task");
        assert_eq!(&buf[..n], b"hello");
    }

    /// Parent bug: the chunked parser moved straight to `Done` on the `0`-size chunk line,
    /// leaving the trailer's terminating `\r\n` (the common no-trailer
    /// case) unconsumed. Those two bytes then reached the tunnel as if they were payload.
    #[tokio::test]
    async fn chunked_trailer_and_final_crlf_are_not_leaked_as_tunnel_payload() {
        let (client_side, server_side) = tokio::io::duplex(1 << 16);
        let mut server = new_http_obfs_server(Box::new(PipeConn(server_side)));
        let mut client = PipeConn(client_side);
        let request = format!("{UPGRADE_HEADERS}5\r\nhello\r\n0\r\n\r\nTUNNELDATA");
        client.write_all(request.as_bytes()).await.expect("write request");

        let mut body = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(5), server.read_exact(&mut body))
            .await
            .expect("must not hang")
            .expect("read body");
        assert_eq!(&body, b"hello");

        let mut tail = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), server.read_exact(&mut tail))
            .await
            .expect("must not hang")
            .expect("read tunnel data after the chunked body");
        assert_eq!(&tail, b"TUNNELDATA");
    }

    /// Every case name, stream and expected `(got, err)` pair below is pinned: `Expect::Ok` gives
    /// the bytes expected after `hello` (empty for the `eof-at-*` cases, which never reach a
    /// terminator); `Expect::Err` gives the exact error text, except `ctl-in-value` and
    /// `nonutf8-key`, where Rust's lossy-UTF8 `{:?}` renders a control byte and an invalid byte
    /// differently — the same divergence the `HeaderLine` arm already has.
    #[tokio::test]
    async fn chunked_trailer_error_texts() {
        enum Expect {
            Ok(Vec<u8>),
            Err(&'static str),
        }

        fn suffix(parts: &[&[u8]]) -> Vec<u8> {
            parts.concat()
        }

        let mut cases: Vec<(String, Vec<u8>, Expect)> = vec![
            ("plain".to_owned(), suffix(&[b"\r\nTAIL"]), Expect::Ok(b"TAIL".to_vec())),
            ("trailer-headers".to_owned(), suffix(&[b"X-A: 1\r\nX-B: 2\r\n\r\nTAIL"]), Expect::Ok(b"TAIL".to_vec())),
            (
                "garbage-trailer".to_owned(),
                suffix(&[b"garbage\r\n\r\nTAIL"]),
                Expect::Err("malformed MIME header: missing colon: \"garbage\""),
            ),
            (
                "long-trailer-many-lines".to_owned(),
                suffix(&[b"X: y\r\n".repeat(2000).as_slice(), b"\r\nTAIL"]),
                Expect::Err("http: suspiciously long trailer after chunked body"),
            ),
            (
                "trailer-4090".to_owned(),
                suffix(&[b"X: y\r\n".repeat(681).as_slice(), b"\r\nTAIL"]),
                Expect::Ok(b"TAIL".to_vec()),
            ),
            (
                "trailer-4090-extra".to_owned(),
                suffix(&[b"X: y\r\n".repeat(681).as_slice(), b"\r\n\r\nTAIL"]),
                Expect::Ok(b"\r\nTAIL".to_vec()),
            ),
            (
                "long-trailer-one-line".to_owned(),
                suffix(&[b"A".repeat(10000).as_slice(), b"\r\n\r\nTAIL"]),
                Expect::Err("http: suspiciously long trailer after chunked body"),
            ),
            (
                "bare-lf-trailer".to_owned(),
                suffix(&[b"\nTAIL"]),
                Expect::Err("http: suspiciously long trailer after chunked body"),
            ),
            (
                "trailer-eof".to_owned(),
                suffix(&[b"X: y\r\n"]),
                Expect::Err("http: suspiciously long trailer after chunked body"),
            ),
            ("trailer-eof-empty".to_owned(), suffix(&[b""]), Expect::Err("http: unexpected EOF reading trailer")),
            ("eof-cr".to_owned(), suffix(&[b"\r"]), Expect::Err("http: unexpected EOF reading trailer")),
            ("eof-x".to_owned(), suffix(&[b"X"]), Expect::Err("http: unexpected EOF reading trailer")),
            ("eof-crlf".to_owned(), suffix(&[b"\r\n"]), Expect::Ok(Vec::new())),
            ("eof-xy".to_owned(), suffix(&[b"XY"]), Expect::Err("http: suspiciously long trailer after chunked body")),
            (
                "eof-crlfcr".to_owned(),
                suffix(&[b"X: y\r\n\r"]),
                Expect::Err("http: suspiciously long trailer after chunked body"),
            ),
            ("exact-term-eof".to_owned(), suffix(&[b"X: y\r\n\r\n"]), Expect::Ok(Vec::new())),
            (
                "tail-has-crlfcrlf".to_owned(),
                suffix(&[b"X: y\r\n\r\nTAIL\r\n\r\nMORE"]),
                Expect::Ok(b"TAIL\r\n\r\nMORE".to_vec()),
            ),
            (
                "fast-tail-has-crlfcrlf".to_owned(),
                suffix(&[b"\r\nTAIL\r\n\r\nMORE"]),
                Expect::Ok(b"TAIL\r\n\r\nMORE".to_vec()),
            ),
            ("lf-lines".to_owned(), suffix(&[b"X: y\nZ: w\r\n\r\nTAIL"]), Expect::Ok(b"TAIL".to_vec())),
            (
                "lf-blank-then-crlfcrlf".to_owned(),
                suffix(&[b"X: y\n\r\nTAIL\r\n\r\nMORE"]),
                Expect::Ok(b"TAIL\r\n\r\nMORE".to_vec()),
            ),
            (
                "lf-lf-then-crlfcrlf".to_owned(),
                suffix(&[b"X: y\n\nTAIL\r\n\r\nMORE"]),
                Expect::Ok(b"TAIL\r\n\r\nMORE".to_vec()),
            ),
            ("lead-lf-then-crlfcrlf".to_owned(), suffix(&[b"\n\r\n\r\nTAIL"]), Expect::Ok(b"\r\n\r\nTAIL".to_vec())),
            ("folded".to_owned(), suffix(&[b"X: y\r\n z\r\n\r\nTAIL"]), Expect::Ok(b"TAIL".to_vec())),
            ("folded-empty".to_owned(), suffix(&[b"X: y\r\n \r\n\r\nTAIL"]), Expect::Ok(b"TAIL".to_vec())),
            (
                "initial-space".to_owned(),
                suffix(&[b" X: y\r\n\r\nTAIL"]),
                Expect::Err("malformed MIME header initial line: \" X: y\""),
            ),
            (
                "trailing-ws-garbage".to_owned(),
                suffix(&[b"garbage  \r\n\r\nTAIL"]),
                Expect::Err("malformed MIME header: missing colon: \"garbage  \""),
            ),
            (
                "cr-in-value".to_owned(),
                suffix(&[b"X: y\r\r\n\r\nTAIL"]),
                Expect::Err("malformed MIME header line: \"X: y\\r\""),
            ),
            (
                "mid-cr-in-value".to_owned(),
                suffix(&[b"X: a\rb\r\n\r\nTAIL"]),
                Expect::Err("malformed MIME header line: \"X: a\\rb\""),
            ),
            ("space-before-colon".to_owned(), suffix(&[b"X : y\r\n\r\nTAIL"]), Expect::Ok(b"TAIL".to_vec())),
            ("empty-key".to_owned(), suffix(&[b": y\r\n\r\nTAIL"]), Expect::Err("malformed MIME header line: \": y\"")),
            (
                "ctl-in-value".to_owned(),
                suffix(&[b"X: a\x01b\r\n\r\nTAIL"]),
                Expect::Err("malformed MIME header line: \"X: a\\u{1}b\""),
            ),
            (
                "nonutf8-key".to_owned(),
                suffix(&[b"X\xff: y\r\n\r\nTAIL"]),
                Expect::Err("malformed MIME header line: \"X\u{fffd}: y\""),
            ),
            ("nonutf8-value".to_owned(), suffix(&[b"X: \xff\xfe\r\n\r\nTAIL"]), Expect::Ok(b"TAIL".to_vec())),
            ("underscore-key".to_owned(), suffix(&[b"X_Y: z\r\n\r\nTAIL"]), Expect::Ok(b"TAIL".to_vec())),
            (
                "cr-only-lines".to_owned(),
                suffix(&[b"X: y\r\r\r\n\r\nTAIL"]),
                Expect::Err("malformed MIME header line: \"X: y\\r\\r\""),
            ),
            ("bad-terminator".to_owned(), Vec::new(), Expect::Err("malformed chunked encoding")),
        ];

        for n in 4090usize..=4101 {
            let fill1 = n - 7;
            let one_line = suffix(&[b"X: ", "a".repeat(fill1).as_bytes(), b"\r\n\r\nTAIL"]);
            let k = fill1 / 6;
            let fill2 = fill1 - 6 * k;
            let multi_line =
                suffix(&[b"X: y\r\n".repeat(k).as_slice(), b"Z: ", "b".repeat(fill2).as_bytes(), b"\r\n\r\nTAIL"]);
            let eof_at = suffix(&[b"X: ", "a".repeat(fill1).as_bytes(), b"\r\n\r\n"]);
            let ok_or_too_long = |tail: Vec<u8>| {
                if n <= 4096 {
                    Expect::Ok(tail)
                } else {
                    Expect::Err("http: suspiciously long trailer after chunked body")
                }
            };
            cases.push((format!("one-line-{n}"), one_line, ok_or_too_long(b"TAIL".to_vec())));
            cases.push((format!("multi-line-{n}"), multi_line, ok_or_too_long(b"TAIL".to_vec())));
            cases.push((format!("eof-at-{n}"), eof_at, ok_or_too_long(Vec::new())));
        }

        for (name, part, expect) in cases {
            let stream = if name == "bad-terminator" {
                format!("{UPGRADE_HEADERS}5\r\nhelloXY0\r\n\r\n").into_bytes()
            } else {
                let mut s = format!("{UPGRADE_HEADERS}5\r\nhello\r\n0\r\n").into_bytes();
                s.extend_from_slice(&part);
                s
            };
            let (client_side, server_side) = tokio::io::duplex(1 << 20);
            let mut server = new_http_obfs_server(Box::new(PipeConn(server_side)));
            let mut client = PipeConn(client_side);
            client.write_all(&stream).await.expect("write stream");
            drop(client);

            let mut got = Vec::new();
            let mut buf = [0u8; 65536];
            let outcome = loop {
                match tokio::time::timeout(Duration::from_secs(5), server.read(&mut buf))
                    .await
                    .unwrap_or_else(|_| panic!("{name}: must not hang"))
                {
                    Ok(0) => break Ok(()),
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(e) => break Err(e),
                }
            };

            match expect {
                Expect::Ok(tail) => {
                    let mut want = b"hello".to_vec();
                    want.extend_from_slice(&tail);
                    assert_eq!(got, want, "{name}: bytes mismatch");
                    assert!(outcome.is_ok(), "{name}: expected clean EOF, got {outcome:?}");
                }
                Expect::Err(message) => {
                    assert!(got.is_empty(), "{name}: expected no bytes before the error, got {got:?}");
                    let err = outcome.expect_err(&format!("{name}: expected an error"));
                    assert_eq!(err.to_string(), message, "{name}: error text mismatch");
                }
            }
        }
    }

    /// A reader that returns `Pending` (self-waking) before every segment, so every split point
    /// and every caller buffer size gets exercised with a real intervening poll, the way the
    /// chunk-CRLF and body regression tests above already do.
    struct Scripted {
        segments: Vec<Vec<u8>>,
        idx: usize,
        off: usize,
        pend: bool,
    }
    impl AsyncRead for Scripted {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            while this.idx < this.segments.len() && this.off == this.segments[this.idx].len() {
                this.idx += 1;
                this.off = 0;
                this.pend = true;
            }
            if this.idx == this.segments.len() {
                return Poll::Ready(Ok(()));
            }
            if this.pend {
                this.pend = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let seg = &this.segments[this.idx];
            let n = std::cmp::min(buf.remaining(), seg.len() - this.off);
            buf.put_slice(&seg[this.off..this.off + n]);
            this.off += n;
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for Scripted {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl Conn for Scripted {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// `ReviewObfsTrailer`'s split-point and caller-buffer matrix for the bytes the trailer fix
    /// hands back as tunnel data: every split point of every case that has a non-empty leftover,
    /// with caller buffers of 1, 7 and 4096, must deliver exactly `hello` followed by that
    /// leftover, whatever byte the split falls on.
    #[tokio::test]
    async fn chunked_trailer_leftover_survives_every_split_point_and_buffer_size() {
        let cases: [(&str, &[u8], &[u8]); 10] = [
            ("plain", b"\r\nTAIL", b"TAIL"),
            ("trailer-headers", b"X-A: 1\r\nX-B: 2\r\n\r\nTAIL", b"TAIL"),
            ("lf-lines", b"X: y\nZ: w\r\n\r\nTAIL", b"TAIL"),
            ("lf-blank-then-crlfcrlf", b"X: y\n\r\nTAIL\r\n\r\nMORE", b"TAIL\r\n\r\nMORE"),
            ("lf-lf-then-crlfcrlf", b"X: y\n\nTAIL\r\n\r\nMORE", b"TAIL\r\n\r\nMORE"),
            ("lead-lf-then-crlfcrlf", b"\n\r\n\r\nTAIL", b"\r\n\r\nTAIL"),
            ("folded", b"X: y\r\n z\r\n\r\nTAIL", b"TAIL"),
            ("folded-empty", b"X: y\r\n \r\n\r\nTAIL", b"TAIL"),
            ("tail-has-crlfcrlf", b"X: y\r\n\r\nTAIL\r\n\r\nMORE", b"TAIL\r\n\r\nMORE"),
            ("fast-tail-has-crlfcrlf", b"\r\nTAIL\r\n\r\nMORE", b"TAIL\r\n\r\nMORE"),
        ];
        let mut failures = Vec::new();
        for (name, suffix, tail) in cases {
            let mut stream = format!("{UPGRADE_HEADERS}5\r\nhello\r\n0\r\n").into_bytes();
            stream.extend_from_slice(suffix);
            let mut expected = b"hello".to_vec();
            expected.extend_from_slice(tail);

            for split in 1..stream.len() {
                for &bufsz in &[1usize, 7, 4096] {
                    let segments = vec![stream[..split].to_vec(), stream[split..].to_vec()];
                    let mut server = new_http_obfs_server(Box::new(Scripted { segments, idx: 0, off: 0, pend: true }));
                    let mut got = Vec::new();
                    let mut buf = vec![0u8; bufsz];
                    let ok = tokio::time::timeout(Duration::from_secs(5), async {
                        loop {
                            match server.read(&mut buf).await {
                                Ok(0) => return true,
                                Ok(n) => got.extend_from_slice(&buf[..n]),
                                Err(_) => return false,
                            }
                        }
                    })
                    .await
                    .unwrap_or(false);
                    if !ok || got != expected {
                        failures.push(format!("{name} split={split} buf={bufsz}: got={got:?} ok={ok}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{} failures, first: {:?}", failures.len(), &failures[..failures.len().min(5)]);
    }

    struct EndlessTrailer {
        prefix: Vec<u8>,
        pos: usize,
        fed: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        since_pending: usize,
    }
    impl AsyncRead for EndlessTrailer {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            const PATTERN: &[u8] = b"X: y\r\n";
            const YIELD_EVERY: usize = 64;
            let this = self.get_mut();
            if this.since_pending >= YIELD_EVERY {
                this.since_pending = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let mut n = 0;
            while buf.remaining() > 0 && this.since_pending < YIELD_EVERY {
                let byte = if this.pos < this.prefix.len() {
                    this.prefix[this.pos]
                } else {
                    PATTERN[(this.pos - this.prefix.len()) % PATTERN.len()]
                };
                this.pos += 1;
                this.since_pending += 1;
                buf.put_slice(&[byte]);
                n += 1;
            }
            this.fed.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for EndlessTrailer {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl Conn for EndlessTrailer {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Parent bug: `BodyPhase::Trailer` bounded each *line* to 4096 bytes but not the trailer as
    /// a whole, so `0\r\n` followed by an endless `X: y\r\n` stream was read forever: 115 MB in
    /// 10s, no error. The trailer read bounds the search for the blank-line terminator to
    /// its 4096-byte buffer and fails with "http: suspiciously long trailer after chunked body".
    #[tokio::test]
    async fn endless_chunked_trailer_errors_in_bounded_time_not_a_hang() {
        let fed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let prefix = format!("{UPGRADE_HEADERS}5\r\nhello\r\n0\r\n").into_bytes();
        let mut server = new_http_obfs_server(Box::new(EndlessTrailer {
            prefix,
            pos: 0,
            fed: std::sync::Arc::clone(&fed),
            since_pending: 0,
        }));
        let mut buf = [0u8; 64];
        let result = tokio::time::timeout(Duration::from_secs(5), server.read(&mut buf)).await;
        let err = result
            .unwrap_or_else(|_| {
                panic!(
                    "endless trailer must error in bounded time, not hang ({} bytes fed)",
                    fed.load(std::sync::atomic::Ordering::Relaxed)
                )
            })
            .expect_err("endless trailer must error");
        assert_eq!(err.to_string(), "http: suspiciously long trailer after chunked body");
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
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn close(&self) -> io::Result<()> {
            self.closes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// Regression for `agent://ReviewS9Obfs`'s finding: `close()` through
    /// `StreamAsOldConn(HTTPObfsServer{conn: OldConnAsStream(inner)})` used to reach only
    /// `shutdown_read`/`shutdown_write`, never the dialed conn's own `close()`.
    #[tokio::test]
    async fn close_reaches_the_dialed_conn() {
        let (_client, server) = tokio::io::duplex(64);
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flag = FlagConn { inner: server, closes: std::sync::Arc::clone(&closes) };
        let obfs = new_http_obfs_server(Box::new(flag));
        obfs.close().expect("close");
        assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
