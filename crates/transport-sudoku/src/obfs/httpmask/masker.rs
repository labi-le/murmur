use std::io;

use rand::Rng;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::conn_helpers::MAX_HTTP_HEADER_BYTES;
use super::pathroot::join_path_root;

pub(crate) const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
];

pub(crate) const ACCEPTS: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "application/octet-stream",
    "*/*",
];

pub(crate) const ACCEPT_LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
];

pub(crate) const ACCEPT_ENCODINGS: &[&str] = &["gzip, deflate, br", "gzip, deflate", "br, gzip, deflate"];

pub(crate) const PATHS: &[&str] = &[
    "/api/v1/upload",
    "/data/sync",
    "/uploads/raw",
    "/api/report",
    "/feed/update",
    "/v2/events",
    "/v1/telemetry",
    "/session",
    "/stream",
    "/ws",
];

const CONTENT_TYPES: &[&str] = &["application/octet-stream", "application/x-protobuf", "application/json"];

/// `LooksLikeHTTPRequestStart`: reports whether peek4 looks like a supported HTTP/1.x request
/// method prefix.
pub(crate) fn looks_like_http_request_start(peek4: &[u8]) -> bool {
    let Some(peek) = peek4.get(..4) else {
        return false;
    };
    matches!(peek, b"GET " | b"POST" | b"HEAD" | b"PUT " | b"OPTI" | b"PATC" | b"DELE")
}

pub(crate) fn trim_port_for_host(host: &str) -> String {
    if host.is_empty() {
        return host.to_owned();
    }
    match murmur_common_net::split_host_port(host) {
        Ok((h, _, true)) if !h.is_empty() => h,
        _ => host.to_owned(),
    }
}

pub(crate) fn random_choice<'a>(choices: &[&'a str], r: &mut impl Rng) -> &'a str {
    choices.get(r.random_range(0..choices.len())).copied().unwrap_or_default()
}

fn append_common_headers(buf: &mut Vec<u8>, host: &str, r: &mut impl Rng) {
    let ua = random_choice(USER_AGENTS, r);
    let accept = random_choice(ACCEPTS, r);
    let lang = random_choice(ACCEPT_LANGUAGES, r);
    let enc = random_choice(ACCEPT_ENCODINGS, r);

    buf.extend_from_slice(b"Host: ");
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(b"\r\nUser-Agent: ");
    buf.extend_from_slice(ua.as_bytes());
    buf.extend_from_slice(b"\r\nAccept: ");
    buf.extend_from_slice(accept.as_bytes());
    buf.extend_from_slice(b"\r\nAccept-Language: ");
    buf.extend_from_slice(lang.as_bytes());
    buf.extend_from_slice(b"\r\nAccept-Encoding: ");
    buf.extend_from_slice(enc.as_bytes());
    buf.extend_from_slice(b"\r\nConnection: keep-alive\r\n");

    buf.extend_from_slice(b"Cache-Control: no-cache\r\nPragma: no-cache\r\n");
}

/// Builds the header bytes synchronously so the non-`Send` `ThreadRng` never has to cross an
/// `.await` in the caller's generated future.
fn build_random_request_header(host: &str, path_root: &str) -> Vec<u8> {
    let mut r = rand::rng();

    let path = join_path_root(path_root, random_choice(PATHS, &mut r));
    let ctype = random_choice(CONTENT_TYPES, &mut r);

    let mut buf = Vec::with_capacity(1024);

    match r.random_range(0..10) {
        0 | 1 => {
            let host_no_port = trim_port_for_host(host);
            let mut key_bytes = [0u8; 16];
            r.fill(&mut key_bytes);
            let ws_key = {
                use base64::engine::general_purpose::STANDARD;
                use base64::Engine as _;
                STANDARD.encode(key_bytes)
            };

            buf.extend_from_slice(b"GET ");
            buf.extend_from_slice(path.as_bytes());
            buf.extend_from_slice(b" HTTP/1.1\r\n");
            append_common_headers(&mut buf, host, &mut r);
            buf.extend_from_slice(
                b"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ",
            );
            buf.extend_from_slice(ws_key.as_bytes());
            buf.extend_from_slice(b"\r\nOrigin: https://");
            buf.extend_from_slice(host_no_port.as_bytes());
            buf.extend_from_slice(b"\r\n\r\n");
        }
        _ => {
            const MIN_CL: i64 = 4 * 1024;
            const MAX_CL: i64 = 10 * 1024 * 1024;
            let content_length = MIN_CL + r.random_range(0..=MAX_CL - MIN_CL);

            buf.extend_from_slice(b"POST ");
            buf.extend_from_slice(path.as_bytes());
            buf.extend_from_slice(b" HTTP/1.1\r\n");
            append_common_headers(&mut buf, host, &mut r);
            buf.extend_from_slice(b"Content-Type: ");
            buf.extend_from_slice(ctype.as_bytes());
            buf.extend_from_slice(b"\r\nContent-Length: ");
            buf.extend_from_slice(content_length.to_string().as_bytes());
            if r.random_range(0..2) == 0 {
                buf.extend_from_slice(b"\r\nX-Requested-With: XMLHttpRequest");
            }
            if r.random_range(0..3) == 0 {
                buf.extend_from_slice(b"\r\nReferer: https://");
                buf.extend_from_slice(trim_port_for_host(host).as_bytes());
                buf.extend_from_slice(b"/");
            }
            buf.extend_from_slice(b"\r\n\r\n");
        }
    }

    buf
}

/// `WriteRandomRequestHeaderWithPathRoot`: like the plain write path but prefixes all paths
/// with `path_root`. `path_root` must be a single segment (e.g. "aabbcc"); invalid inputs are
/// treated as empty (disabled).
pub(crate) async fn write_random_request_header_with_path_root(
    w: &mut (impl AsyncWriteExt + Unpin),
    host: &str,
    path_root: &str,
) -> io::Result<()> {
    let buf = build_random_request_header(host, path_root);
    w.write_all(&buf).await
}

/// `ConsumeHeader`: reads and consumes the HTTP header, returning the consumed bytes.
/// Returns an error if the request is not one of the supported methods, or the header is
/// malformed.
pub(crate) async fn consume_header<R>(r: &mut BufReader<R>) -> (Vec<u8>, io::Result<()>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut consumed = Vec::new();

    let mut line = Vec::new();
    match read_line_capped(r, &mut consumed, &mut line).await {
        Ok(0) => return (consumed, Err(io::Error::from(io::ErrorKind::UnexpectedEof))),
        Ok(_) => {}
        Err(err) => return (consumed, Err(err)),
    }

    let is_supported_method = line.starts_with(b"POST ")
        || line.starts_with(b"GET ")
        || line.starts_with(b"HEAD ")
        || line.starts_with(b"PUT ")
        || line.starts_with(b"DELETE ")
        || line.starts_with(b"OPTIONS ")
        || line.starts_with(b"PATCH ");
    if !is_supported_method {
        let trimmed = String::from_utf8_lossy(&line).trim().to_owned();
        return (
            consumed,
            Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid method or garbage: {trimmed}"))),
        );
    }

    loop {
        match read_line_capped(r, &mut consumed, &mut line).await {
            Ok(0) => return (consumed, Err(io::Error::from(io::ErrorKind::UnexpectedEof))),
            Ok(_) => {}
            Err(err) => return (consumed, Err(err)),
        }

        if line == b"\r\n" || line == b"\n" {
            return (consumed, Ok(()));
        }
    }
}

/// Reads one `\n`-terminated line into `line`, appends it to `consumed`, and stops one byte past
/// [`MAX_HTTP_HEADER_BYTES`] so neither a line without a newline nor an endless run of header
/// lines can grow `consumed` past the cap.
async fn read_line_capped<R>(r: &mut BufReader<R>, consumed: &mut Vec<u8>, line: &mut Vec<u8>) -> io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    line.clear();
    let remaining = MAX_HTTP_HEADER_BYTES.saturating_sub(consumed.len());
    let limit = remaining as u64 + 1;
    let read = (&mut *r).take(limit).read_until(b'\n', line).await;
    if !line.is_empty() {
        consumed.extend_from_slice(line);
    }
    if consumed.len() > MAX_HTTP_HEADER_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "http header too large"));
    }
    read
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, DuplexStream};

    use super::*;

    async fn consume(stream: DuplexStream) -> (Vec<u8>, io::Result<()>) {
        let mut reader = BufReader::new(stream);
        consume_header(&mut reader).await
    }

    /// `GET / HTTP/1.1`, one filler header line and the blank line, `total` bytes in all.
    fn request_header_of_len(total: usize) -> Vec<u8> {
        let first = b"GET / HTTP/1.1\r\n";
        let mut request = first.to_vec();
        request.extend(std::iter::repeat_n(b'A', total - first.len() - 4));
        request.extend_from_slice(b"\r\n\r\n");
        assert_eq!(request.len(), total, "built request length");
        request
    }

    #[tokio::test]
    async fn consume_header_accepts_a_header_at_the_cap_and_refuses_the_byte_past_it() {
        for (total, accepted) in
            [(MAX_HTTP_HEADER_BYTES - 1, true), (MAX_HTTP_HEADER_BYTES, true), (MAX_HTTP_HEADER_BYTES + 1, false)]
        {
            let (mut client, server) = duplex(MAX_HTTP_HEADER_BYTES * 2);
            client.write_all(&request_header_of_len(total)).await.expect("write request header");
            drop(client);

            let (consumed, result) = consume(server).await;
            if accepted {
                result.unwrap_or_else(|err| panic!("a {total}-byte header must be accepted: {err}"));
                assert_eq!(consumed.len(), total, "consumed bytes for a {total}-byte header");
            } else {
                let err = result.err().unwrap_or_else(|| panic!("a {total}-byte header must be refused"));
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                assert_eq!(err.to_string(), "http header too large");
            }
        }
    }

    #[tokio::test]
    async fn consume_header_stops_reading_a_line_that_never_ends() {
        let (mut client, server) = duplex(MAX_HTTP_HEADER_BYTES * 4);
        let mut request = b"GET / HTTP/1.1\r\n".to_vec();
        request.extend(std::iter::repeat_n(b'A', MAX_HTTP_HEADER_BYTES * 3));
        client.write_all(&request).await.expect("write unterminated header");
        drop(client);

        let (consumed, result) = consume(server).await;
        let err = result.expect_err("an unterminated header line must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "http header too large");
        assert!(
            consumed.len() <= MAX_HTTP_HEADER_BYTES + 1,
            "buffered {} bytes of a 96 KiB line with a cap of {MAX_HTTP_HEADER_BYTES}",
            consumed.len()
        );
    }
}
