//! Request framing for the private HTTP server in [`super::hack`]: `parse_transfer_encoding` and
//! `fix_length` decide the body's length ahead of time, and the chunk reader then decodes the
//! body itself once that decision says `chunked`.
//!
//! The response-only framing (the header/body writers and the chunked-request-body decision, reached
//! only when a request is written out) has no equivalent here: this crate's outgoing framing is
//! decided in
//! `proxy.rs::forward` straight from a parsed [`Request`](super::hack::Request), not through a

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use std::io;
use tokio::io::AsyncReadExt;

use murmur_common_net::bufconn::BufferedConn;

/// The line-length cap, also enforced on top of the buffered reader's default-size overflow.
const MAX_CHUNK_LINE: usize = 4096;
/// The chunk-overhead budget: more than this much non-data overhead across the whole body is
/// rejected as a malicious sender.
const MAX_CHUNK_EXCESS: i64 = 16 * 1024;
/// How far the trailer's terminating blank line is looked for: up to the underlying reader's
/// capacity (4096 bytes), matching `MAX_CHUNK_LINE` above.
const MAX_TRAILER_PEEK: usize = 4096;

/// Parses the request's `Transfer-Encoding`. `header` must already have had its request line's fields folded in;
/// this removes `Transfer-Encoding` from `header` whether or not it ends up chunked, and returns
/// whether the request is chunked. HTTP/1.0 requests never see chunked framing.
pub(crate) fn parse_transfer_encoding(header: &mut HeaderMap, proto_minor: u8) -> Result<bool> {
    let values = header_lines(header, &http::header::TRANSFER_ENCODING, "Transfer-Encoding")?;
    header.remove(http::header::TRANSFER_ENCODING);
    if values.is_empty() {
        return Ok(false);
    }
    if proto_minor < 1 {
        return Ok(false);
    }
    if values.len() != 1 {
        bail!("too many transfer encodings: {values:?}");
    }
    let Some(encoding) = values.first() else {
        bail!("missing transfer encoding");
    };
    if !encoding.eq_ignore_ascii_case("chunked") {
        bail!("unsupported transfer encoding: {encoding:?}");
    }
    Ok(true)
}

/// Fixes the body length, restricted to the request side: a backend response's length is never re-derived
/// here, since the response body is streamed straight through hyper's own framing — see
/// `proxy.rs`'s module doc. Returns the body length, folding the "no body" case into `Ok(0)`.
pub(crate) fn fix_length(header: &mut HeaderMap, chunked: bool) -> Result<u64> {
    let content_lens = header_lines(header, &http::header::CONTENT_LENGTH, "Content-Length")?;

    if content_lens.len() > 1 {
        let [first, rest @ ..] = content_lens.as_slice() else {
            bail!("message cannot contain multiple Content-Length headers; got {content_lens:?}");
        };
        let first = first.trim();
        if rest.iter().any(|v| v.trim() != first) {
            bail!("message cannot contain multiple Content-Length headers; got {content_lens:?}");
        }
        let first = first.to_owned();
        header.remove(http::header::CONTENT_LENGTH);
        header.insert(http::header::CONTENT_LENGTH, HeaderValue::from_str(&first).map_err(|err| anyhow!("{err}"))?);
    }

    let n = content_lens.first().map(|first| parse_content_length_value(first.trim())).transpose()?;

    if chunked {
        header.remove(http::header::CONTENT_LENGTH);
        return Ok(0);
    }

    if let Some(n) = n {
        return Ok(n);
    }

    header.remove(http::header::CONTENT_LENGTH);
    Ok(0)
}

/// Fixes the trailer handling: a `Trailer` header on a non-chunked request is left alone (it stays in `Header`
/// unread rather than erroring — "invalid use case", not a malformed request); on a chunked
/// request it is removed from `header` and every field name it announces is checked against the
/// three names a trailer can never carry (they would let a trailer smuggle framing already
/// decided from the head).
pub(crate) fn fix_trailer(header: &mut HeaderMap, chunked: bool) -> Result<()> {
    if !header.contains_key(http::header::TRAILER) {
        return Ok(());
    }
    if !chunked {
        return Ok(());
    }
    let values = header_lines(header, &http::header::TRAILER, "Trailer")?;
    header.remove(http::header::TRAILER);
    for key in values.iter().flat_map(|v| v.split(',')).map(str::trim).filter(|k| !k.is_empty()) {
        if key.eq_ignore_ascii_case("Transfer-Encoding")
            || key.eq_ignore_ascii_case("Trailer")
            || key.eq_ignore_ascii_case("Content-Length")
        {
            bail!("bad trailer key: {key}");
        }
    }
    Ok(())
}

/// Parses `Content-Length`: decimal ASCII digits only, bounded to 63 bits, no sign (so Rust's
/// `+`-accepting `u64::from_str` cannot be used directly).
fn parse_content_length_value(v: &str) -> Result<u64> {
    if v.is_empty() {
        bail!("invalid empty Content-Length");
    }
    if !v.bytes().all(|b| b.is_ascii_digit()) {
        bail!("bad Content-Length {v:?}");
    }
    let n: u64 = v.parse().map_err(|_| anyhow!("bad Content-Length {v:?}"))?;
    if n > (1u64 << 63) - 1 {
        bail!("bad Content-Length {v:?}");
    }
    Ok(n)
}

/// Every raw header line for `name`, one entry per header line on
/// the wire, never split on commas — `Transfer-Encoding: gzip, chunked` is one entry whose value
/// is the literal string `"gzip, chunked"`, not two tokens).
fn header_lines(header: &HeaderMap, name: &http::HeaderName, label: &str) -> Result<Vec<String>> {
    header
        .get_all(name)
        .iter()
        .map(|v| v.to_str().map(str::to_owned))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| anyhow!("malformed {label}"))
}

/// A chunked-body source: every generic reader `ChunkedReader` and [`read_trailer`] need,
/// implemented directly by [`BufferedConn`] (the buffered path, `read_chunked_body`) and by
/// `client.rs`'s `SharedConnReader` (the streamed forward-proxy path, `pump_chunked_body`, whose
/// connection is shared with a concurrent body-pump task). The peek primitive, unlike plain
/// `AsyncRead`, must not remove the bytes it
/// returns from the stream, so a lookahead past the trailer's own end still leaves those bytes
/// for the next request's parse.
#[async_trait::async_trait]
pub(crate) trait ChunkSrc: Send {
    async fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Returns up to `n` buffered bytes without consuming them,
    /// alongside the error (if any) that kept it from returning the full `n`.
    async fn peek(&mut self, n: usize) -> (Vec<u8>, io::Result<()>);

    /// Bytes already sitting in the buffer, with no I/O of its own.
    /// `pump_chunked_body`'s coalescing loop uses this to decide whether continuing to the next
    /// chunk footer or header would need to block on the network, without ever forcing that
    /// block.
    async fn buffered_len(&mut self) -> usize;

    /// Whether the bytes already buffered (no further I/O) contain the
    /// newline ending the next chunk-size line.
    async fn buffered_has_newline(&mut self) -> bool;

    async fn read_u8(&mut self) -> io::Result<u8> {
        let mut b = [0u8; 1];
        self.read_exact(&mut b).await?;
        Ok(b[0])
    }

    // NOT cancel-safe: the loop consumes bytes from the stream as it fills the caller's buffer, so a dropped call leaves the next read mid-field.
    async fn read_exact(&mut self, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = self.read_some(buf).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
            }
            let Some(rest) = buf.get_mut(n..) else {
                return Err(io::Error::other("reader returned more bytes than the buffer holds"));
            };
            buf = rest;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ChunkSrc for BufferedConn {
    async fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        AsyncReadExt::read(self, buf).await
    }

    async fn peek(&mut self, n: usize) -> (Vec<u8>, io::Result<()>) {
        let (bytes, err) = Self::peek(self, n).await;
        (bytes.to_vec(), err)
    }

    async fn buffered_len(&mut self) -> usize {
        Self::buffered(self)
    }

    async fn buffered_has_newline(&mut self) -> bool {
        self.reader().is_some_and(|r| r.buffered_bytes().contains(&b'\n'))
    }
}

/// Reads up to the first `\n` and requires the line to end in exactly one
/// trailing `\r\n` — a bare-LF chunk line, or any other embedded CR, is rejected here, unlike
/// the header block, which stays bare-LF tolerant like the buffered line reader.
async fn read_chunk_line<R: ChunkSrc>(src: &mut R) -> Result<Vec<u8>> {
    let mut scanned = 0usize;
    let len = loop {
        let buffered = src.buffered_len().await;
        let (bytes, _) = src.peek(buffered).await;
        let Some(unscanned) = bytes.get(scanned..) else {
            bail!("chunk line buffer shrank while scanning");
        };
        if let Some(i) = unscanned.iter().position(|&b| b == b'\n') {
            break scanned + i + 1;
        }
        if bytes.len() >= MAX_CHUNK_LINE {
            bail!("header line too long");
        }
        scanned = bytes.len();
        let (more, _) = src.peek(scanned + 1).await;
        if more.len() <= scanned {
            bail!("unexpected EOF reading chunk line");
        }
    };
    let mut line = vec![0u8; len];
    src.read_exact(&mut line).await.map_err(|_| anyhow!("unexpected EOF reading chunk line"))?;
    let Some(cr_idx) = line.iter().position(|&b| b == b'\r') else {
        bail!("chunked line ends with bare LF");
    };
    if cr_idx != line.len() - 2 {
        bail!("invalid CR in chunked line");
    }
    line.truncate(line.len() - 2);
    if line.len() >= MAX_CHUNK_LINE {
        bail!("header line too long");
    }
    Ok(line)
}

/// Trims trailing space/tab only, never leading (a leading space before the
/// chunk size is left for the hex-size parse to reject).
fn trim_trailing_ows(b: &[u8]) -> &[u8] {
    let end = b.iter().rposition(|byte| *byte != b' ' && *byte != b'\t').map_or(0, |i| i + 1);
    b.get(..end).unwrap_or(b)
}

/// Removes the chunk extension: cut at the first `;`, extension contents discarded unparsed.
fn remove_chunk_extension(p: &[u8]) -> &[u8] {
    match p.iter().position(|&b| b == b';') {
        Some(i) => p.get(..i).unwrap_or(p),
        None => p,
    }
}

/// Parses a hex chunk size: 1-16 hex digits, no sign, overflow past 16 digits rejected rather than
/// wrapping.
fn parse_hex_uint(v: &[u8]) -> Result<u64> {
    if v.is_empty() {
        bail!("empty hex number for chunk length");
    }
    let mut n: u64 = 0;
    for (i, &b) in v.iter().enumerate() {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => bail!("invalid byte in chunk length"),
        };
        if i == 16 {
            bail!("http chunk length too large");
        }
        n = (n << 4) | u64::from(d);
    }
    Ok(n)
}

/// The chunk reader, shared by both the buffered (`read_chunked_body`) and the streamed
/// (`pump_chunked_body`) callers in `hack.rs` — one type backs both the drain-everything and the
/// incremental-read callers.
struct ChunkedReader {
    excess: i64,
}

impl ChunkedReader {
    fn new() -> Self {
        Self { excess: 0 }
    }

    /// Begins a chunk. Returns `Some(size)` for a data chunk, or `None` once the terminal `0`
    /// chunk's trailer has been consumed.
    async fn begin_chunk<R: ChunkSrc>(&mut self, src: &mut R) -> Result<Option<u64>> {
        let line = read_chunk_line(src).await?;
        self.excess += i64::try_from(line.len()).unwrap_or(i64::MAX) + 2;
        let line = trim_trailing_ows(&line);
        let line = remove_chunk_extension(line);
        let size = parse_hex_uint(line)?;
        self.excess -= 16 + 2 * i64::try_from(size).unwrap_or(i64::MAX);
        if self.excess < 0 {
            self.excess = 0;
        }
        if self.excess > MAX_CHUNK_EXCESS {
            bail!("chunked encoding contains too much non-data");
        }
        if size == 0 {
            read_trailer(src).await?;
            return Ok(None);
        }
        Ok(Some(size))
    }

    /// The chunk-footer `"\r\n"` check.
    async fn check_end<R: ChunkSrc>(src: &mut R) -> Result<()> {
        let mut crlf = [0u8; 2];
        src.read_exact(&mut crlf).await.map_err(|_| anyhow!("unexpected EOF reading chunk footer"))?;
        if crlf != *b"\r\n" {
            bail!("malformed chunked encoding");
        }
        Ok(())
    }
}

/// The trailer reader, restricted to consuming the trailer block at the right
/// boundary: the trailer's field values are discarded (this crate exposes no
/// trailer for any caller to read).
///
/// Two separate questions: [`see_upcoming_double_crlf`] peeks (without consuming) a growing
/// window up to the underlying reader's capacity — 4096 bytes, the same limit the chunk-line
/// reader above cites — looking
/// for a literal `"\r\n\r\n"` *somewhere ahead*, purely as a DoS bound proving the connection will
/// make progress; that terminator can legitimately belong to a pipelined next request, not the
/// trailer itself. Once that gate passes, the trailer is consumed one field at a time. A line
/// starting with SP/HT where no previous field is open (`"malformed MIME header initial line"`)
/// or a missing colon stops consumption immediately on that physical line, before any
/// continuation is read: both checks run on the unjoined first line. An empty or non-token key
/// byte that also isn't a bare space (which tolerates a space in the key without canonicalising
/// it), or a value byte outside the valid set (HTAB, SP, `0x21..=0x7E`, or `>= 0x80`), is checked
/// only after every obs-fold continuation line for that field has been read and joined, so those
/// two failures stop after the field's last continuation line, not at the line that made it bad.
/// Either way, everything from the stopping
/// point on, including the trailer's own real terminator, is left unread: the caller's next
/// `read_request` then starts on leftover bytes and closes the connection the same way the next
/// request does. Continuation lookahead (`does the next physical line start with SP/HT?`) uses
/// [`ChunkSrc::peek`], never a consuming read, like the whitespace byte lookahead with its
/// read-then-unread pair — so a byte that turns out to start the *next* field, or the trailer's
/// blank terminator, is never mistaken for part of the current line.
async fn read_trailer<R: ChunkSrc>(src: &mut R) -> Result<()> {
    let (peeked, peek_err) = src.peek(2).await;
    if peeked == b"\r\n" {
        src.read_exact(&mut [0u8; 2]).await.map_err(|_| anyhow!("unexpected EOF reading trailer"))?;
        return Ok(());
    }
    if peeked.len() < 2 {
        bail!("unexpected EOF reading trailer");
    }
    if peek_err.is_err() {
        bail!("unexpected EOF reading trailer");
    }

    if !see_upcoming_double_crlf(src).await {
        bail!("suspiciously long trailer after chunked body");
    }

    let mut consumed = 0usize;
    loop {
        let (peek1, _) = src.peek(1).await;
        if matches!(peek1.first(), Some(b' ' | b'\t')) {
            read_one_trailer_line(src, &mut consumed).await?;
            bail!("malformed trailer: initial line starts with whitespace");
        }

        let line = read_one_trailer_line(src, &mut consumed).await?;
        if line.is_empty() {
            break;
        }

        let Some(colon) = line.iter().position(|&b| b == b':') else {
            bail!("malformed trailer: missing colon");
        };
        let Some(key) = line.get(..colon) else {
            bail!("malformed trailer: missing field name");
        };
        let Some(value) = line.get(colon + 1..) else {
            bail!("malformed trailer: missing field value");
        };
        let mut ok = !key.is_empty()
            && key.iter().all(|&b| is_valid_trailer_field_byte(b) || b == b' ')
            && value.iter().all(|&b| is_valid_trailer_value_byte(b));

        loop {
            let (peek1, _) = src.peek(1).await;
            if !matches!(peek1.first(), Some(b' ' | b'\t')) {
                break;
            }
            let cont = read_one_trailer_line(src, &mut consumed).await?;
            ok &= cont.iter().all(|&b| is_valid_trailer_value_byte(b));
        }

        if !ok {
            bail!("malformed trailer: invalid field name or value byte");
        }
    }
    Ok(())
}

/// Reads one physical line (`ChunkSrc::read_u8`, bare-LF tolerant like the buffered reader) and
/// strips exactly one trailing `\r` if the terminator was `\r\n`, returning the line's content
/// without its terminator. Shares `consumed` with the caller across every line of one trailer so
/// the whole block, not just a single line, stays bounded by [`MAX_TRAILER_PEEK`].
async fn read_one_trailer_line<R: ChunkSrc>(src: &mut R, consumed: &mut usize) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        if *consumed >= MAX_TRAILER_PEEK {
            bail!("suspiciously long trailer after chunked body");
        }
        let byte = src.read_u8().await.map_err(|_| anyhow!("unexpected EOF reading trailer"))?;
        *consumed += 1;
        line.push(byte);
        if byte == b'\n' {
            break;
        }
    }
    if line.len() >= 2 && line.get(line.len() - 2) == Some(&b'\r') {
        line.truncate(line.len() - 2);
    } else {
        line.truncate(line.len() - 1);
    }
    Ok(line)
}

/// Grows the peek window one byte at a time starting from 4, stopping
/// the instant a `"\r\n\r\n"` suffix appears; a `Peek` error (buffer full or the connection has
/// nothing more to offer) ends the search without one.
async fn see_upcoming_double_crlf<R: ChunkSrc>(src: &mut R) -> bool {
    let mut peek_size = 4usize;
    loop {
        let (buf, err) = src.peek(peek_size).await;
        if buf.ends_with(b"\r\n\r\n") {
            return true;
        }
        if err.is_err() {
            return false;
        }
        peek_size += 1;
    }
}

/// A valid header field byte: RFC 7230 `tchar`.
fn is_valid_trailer_field_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// A valid header value byte: HTAB, SP, VCHAR (`0x21..=0x7E`) or obs-text (`>= 0x80`) — a bare CR
/// or other control byte is rejected.
fn is_valid_trailer_value_byte(c: u8) -> bool {
    c == 0x09 || (0x20..=0x7e).contains(&c) || c >= 0x80
}

/// A chunked body fully drained into memory: the counterpart to `hack::read_body`'s fixed-length
/// branch, used by CONNECT and the upgrade path, which must materialize their (normally
/// bodyless) request body before handing the connection off.
pub(crate) async fn read_chunked_body<R: ChunkSrc>(src: &mut R) -> Result<Bytes> {
    let mut cr = ChunkedReader::new();
    let mut out = Vec::new();
    loop {
        let Some(size) = cr.begin_chunk(src).await? else {
            return Ok(Bytes::from(out));
        };
        let mut remaining = usize::try_from(size).unwrap_or(usize::MAX);
        while remaining > 0 {
            let before = out.len();
            out.resize(before + remaining, 0);
            let Some(dest) = out.get_mut(before..) else {
                bail!("chunk body offset past the buffer");
            };
            let n = src.read_some(dest).await.map_err(|err| anyhow!("{err}"))?;
            out.truncate(before + n);
            if n == 0 {
                bail!("unexpected EOF reading chunk body");
            }
            remaining -= n;
        }
        ChunkedReader::check_end(src).await?;
    }
}

/// The streaming counterpart to [`read_chunked_body`], forwarding each chunk's data as it
/// arrives instead of materializing the whole body, used by the forward path's `pump_body`
/// (`hack.rs`), which must never buffer a client-declared body in full. It coalesces rather than
/// flushing after every individual `read_some`: it keeps copying into
/// `buf` across a chunk's footer and the next
/// chunk's header as long as those are already sitting in `src`'s buffer (`buffered_len`,
/// `buffered_has_newline` — never forcing the I/O that would make them available), stopping only
/// when `buf` is full or continuing would have to block. One `write_chunk` plus one `flush` then
/// covers everything coalesced into that fill — one flush per fill, not one per wire chunk.
/// Whatever has been coalesced into
/// `buf` is still handed to `sink` and flushed before this returns an error from a later chunk
/// footer, header or body read, so a chunk already accepted still reaches the backend even if the
/// body ends early — the same guarantee the one-flush-per-`write_chunk` version gave.
pub(crate) async fn pump_chunked_body<R: ChunkSrc>(
    src: &mut R,
    sink: &mut impl super::hack::BodySink,
    pump_chunk_size: usize,
) -> Result<()> {
    let mut cr = ChunkedReader::new();
    let mut buf = vec![0u8; pump_chunk_size];
    let mut remaining: u64 = 0;
    let mut check_end = false;

    loop {
        let mut n = 0usize;
        let finished = loop {
            if check_end {
                if n > 0 && src.buffered_len().await < 2 {
                    break false;
                }
                if let Err(err) = ChunkedReader::check_end(src).await {
                    flush_coalesced(&mut *sink, &buf, n).await?;
                    return Err(err);
                }
                check_end = false;
            }
            if remaining == 0 {
                if n > 0 && !(src.buffered_len().await > 0 && src.buffered_has_newline().await) {
                    break false;
                }
                match cr.begin_chunk(src).await {
                    Ok(Some(size)) => {
                        remaining = size;
                        continue;
                    }
                    Ok(None) => break true,
                    Err(err) => {
                        flush_coalesced(&mut *sink, &buf, n).await?;
                        return Err(err);
                    }
                }
            }
            if n == buf.len() {
                break false;
            }
            let room = u64::try_from(buf.len() - n).unwrap_or(u64::MAX);
            let want = usize::try_from(remaining.min(room)).unwrap_or(usize::MAX);
            let dest = buf.get_mut(n..n + want).ok_or_else(|| anyhow!("chunk offset past the pump buffer"))?;
            match src.read_some(dest).await {
                Ok(0) => {
                    flush_coalesced(&mut *sink, &buf, n).await?;
                    bail!("unexpected EOF reading chunk body");
                }
                Ok(read_n) => {
                    n += read_n;
                    remaining -= read_n as u64;
                    if remaining == 0 {
                        check_end = true;
                    }
                }
                Err(err) => {
                    flush_coalesced(&mut *sink, &buf, n).await?;
                    return Err(anyhow!("{err}"));
                }
            }
        };

        flush_coalesced(&mut *sink, &buf, n).await?;
        if finished {
            return Ok(());
        }
    }
}

/// Hands the bytes coalesced into `buf` so far to `sink` and flushes them, so a chunk already
/// accepted still reaches the backend even when a later footer, header or body read fails.
async fn flush_coalesced<S: super::hack::BodySink>(sink: &mut S, buf: &[u8], n: usize) -> Result<()> {
    if n == 0 {
        return Ok(());
    }
    let chunk = buf.get(..n).ok_or_else(|| anyhow!("coalesced chunk exceeds the pump buffer"))?;
    sink.write_chunk(chunk).await?;
    sink.flush().await
}

/// Whether a body is allowed for the status: 1xx, 204 and 304 never carry a body.
pub(crate) fn body_allowed_for_status(status: http::StatusCode) -> bool {
    !(status.is_informational() || status == http::StatusCode::NO_CONTENT || status == http::StatusCode::NOT_MODIFIED)
}

/// Whether no response body is expected: a `HEAD` response never carries a body regardless of status.
pub(crate) fn no_response_body_expected(method: &http::Method) -> bool {
    *method == http::Method::HEAD
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use std::io::Cursor;

    #[async_trait::async_trait]
    impl ChunkSrc for Cursor<Vec<u8>> {
        async fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            AsyncReadExt::read(self, buf).await
        }

        async fn peek(&mut self, n: usize) -> (Vec<u8>, io::Result<()>) {
            let pos = self.position();
            let available = &self.get_ref()[pos as usize..];
            if available.len() >= n {
                (available[..n].to_vec(), Ok(()))
            } else {
                (available.to_vec(), Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")))
            }
        }

        async fn buffered_len(&mut self) -> usize {
            let pos = self.position();
            self.get_ref().len() - pos as usize
        }

        async fn buffered_has_newline(&mut self) -> bool {
            let pos = self.position();
            self.get_ref()[pos as usize..].contains(&b'\n')
        }
    }

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn te_only_exact_chunked_accepted() {
        let mut h = header_map(&[("Transfer-Encoding", "chunked")]);
        assert!(parse_transfer_encoding(&mut h, 1).unwrap());
        assert!(!h.contains_key(http::header::TRANSFER_ENCODING));
    }

    #[test]
    fn te_comma_list_rejected() {
        let mut h = header_map(&[("Transfer-Encoding", "gzip, chunked")]);
        assert!(parse_transfer_encoding(&mut h, 1).is_err());
    }

    #[test]
    fn te_duplicate_lines_rejected() {
        let mut h = header_map(&[("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "chunked")]);
        assert!(parse_transfer_encoding(&mut h, 1).is_err());
    }

    #[test]
    fn te_ignored_on_http_1_0() {
        let mut h = header_map(&[("Transfer-Encoding", "chunked")]);
        assert!(!parse_transfer_encoding(&mut h, 0).unwrap());
    }

    #[test]
    fn cl_duplicate_identical_dedup_ok() {
        let mut h = header_map(&[("Content-Length", "5"), ("Content-Length", "5")]);
        assert_eq!(fix_length(&mut h, false).unwrap(), 5);
        assert_eq!(h.get(http::header::CONTENT_LENGTH).unwrap(), "5");
    }

    #[test]
    fn cl_duplicate_conflicting_rejected() {
        let mut h = header_map(&[("Content-Length", "0"), ("Content-Length", "50")]);
        assert!(fix_length(&mut h, false).is_err());
    }

    #[test]
    fn cl_plus_prefix_rejected() {
        let mut h = header_map(&[("Content-Length", "+5")]);
        assert!(fix_length(&mut h, false).is_err());
    }

    #[test]
    fn cl_dropped_when_chunked() {
        let mut h = header_map(&[("Content-Length", "5"), ("Transfer-Encoding", "chunked")]);
        assert_eq!(fix_length(&mut h, true).unwrap(), 0);
        assert!(!h.contains_key(http::header::CONTENT_LENGTH));
    }

    #[test]
    fn cl_absent_defaults_zero() {
        let mut h = HeaderMap::new();
        assert_eq!(fix_length(&mut h, false).unwrap(), 0);
    }

    #[tokio::test]
    async fn chunk_bare_lf_rejected() {
        let mut src = Cursor::new(b"5\nhello\r\n0\r\n\r\n".to_vec());
        assert!(read_chunked_body(&mut src).await.is_err());
    }

    #[tokio::test]
    async fn chunk_leading_plus_rejected() {
        let mut src = Cursor::new(b"+5\r\nhello\r\n0\r\n\r\n".to_vec());
        assert!(read_chunked_body(&mut src).await.is_err());
    }

    #[tokio::test]
    async fn chunk_extension_stripped() {
        let mut src = Cursor::new(b"5;foo=bar\r\nhello\r\n0\r\n\r\n".to_vec());
        assert_eq!(read_chunked_body(&mut src).await.unwrap(), Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn chunk_too_many_hex_digits_rejected() {
        let mut src = Cursor::new(b"00000000000000005\r\nhello\r\n0\r\n\r\n".to_vec());
        assert!(read_chunked_body(&mut src).await.is_err());
    }

    #[tokio::test]
    async fn chunk_overhead_budget_enforced() {
        let mut body = BytesMut::new();
        for _ in 0..2000 {
            body.extend_from_slice(
                b"1;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nX\r\n",
            );
        }
        body.extend_from_slice(b"0\r\n\r\n");
        let mut src = Cursor::new(body.to_vec());
        assert!(read_chunked_body(&mut src).await.is_err());
    }

    #[tokio::test]
    async fn pump_and_read_agree_on_valid_body() {
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n".to_vec();
        let buffered = read_chunked_body(&mut Cursor::new(raw.clone())).await.unwrap();
        assert_eq!(buffered, Bytes::from_static(b"Wikipedia"));

        let mut sink = Vec::new();
        pump_chunked_body(&mut Cursor::new(raw), &mut sink, 64).await.unwrap();
        assert_eq!(sink, b"Wikipedia");
    }

    #[tokio::test]
    async fn pump_truncated_body_errors() {
        let raw = b"5\r\nhel".to_vec();
        let mut sink = Vec::new();
        assert!(pump_chunked_body(&mut Cursor::new(raw), &mut sink, 64).await.is_err());
    }

    // Covers the trailer reader's CRLFCRLF window and MIME validation: a trailer line with no
    // `:` is rejected, where an earlier version only scanned for a blank line and forwarded the
    // request as complete regardless.
    #[tokio::test]
    async fn trailer_with_malformed_line_is_rejected() {
        let mut src = Cursor::new(b"0\r\nnot a header\r\n\r\n".to_vec());
        assert!(read_chunked_body(&mut src).await.is_err());
    }

    // Regression for ReviewHttpParity round 2, "Stop consuming the trailer at the first malformed
    // line": before this fix, `read_trailer` read all the way to the trailer's
    // own blank line before validating anything, so a malformed line's error arrived only after
    // the trailer's real terminator (and anything past it) had already been swallowed; the next
    // pipelined request was then let through and answered 200, where the trailer reader fails on the
    // bad line immediately, leaves the rest unread, and the connection closes on the next request
    // finding a leftover blank line. Asserts both the failure and the exact consumption boundary.
    #[tokio::test]
    async fn malformed_trailer_line_stops_consumption_before_the_blank_line_or_next_request() {
        let next_request = b"GET /next HTTP/1.1\r\nHost: B\r\n\r\n";

        let mut garbage = Cursor::new([b"0\r\nnot a header\r\n\r\n".as_slice(), next_request].concat());
        assert!(read_chunked_body(&mut garbage).await.is_err());
        assert_eq!(
            usize::try_from(garbage.position()).unwrap(),
            b"0\r\nnot a header\r\n".len(),
            "must stop right after the bad line, before its own blank terminator"
        );
        let mut leftover = Vec::new();
        garbage.read_to_end(&mut leftover).await.unwrap();
        assert_eq!(leftover, [b"\r\n".as_slice(), next_request].concat());

        let mut bare_cr = Cursor::new([b"0\r\n\r\r\n\r\n".as_slice(), next_request].concat());
        assert!(read_chunked_body(&mut bare_cr).await.is_err());
        assert_eq!(
            usize::try_from(bare_cr.position()).unwrap(),
            b"0\r\n\r\r\n".len(),
            "must stop right after the lone-CR line, before its own blank terminator"
        );
    }

    // The peek gate requires a literal `"\r\n\r\n"` to exist ahead before
    // the trailer reader ever attempts to parse a line; a trailer terminated only by a bare `\n`, with
    // no more data following, never satisfies that guard, so the reader blocks forever waiting for
    // more — an indefinitely open connection with no response. This crate's bounded scan for a
    // literal `"\r\n\r\n"` reproduces the same failure mode on a stream that ends without ever
    // producing one.
    #[tokio::test]
    async fn trailer_bare_lf_without_a_following_double_crlf_is_rejected() {
        let mut src = Cursor::new(b"0\r\nX-T: 1\n\n".to_vec());
        assert!(read_chunked_body(&mut src).await.is_err());
    }

    #[tokio::test]
    async fn trailer_obs_fold_continuation_is_joined() {
        let mut src = Cursor::new(b"0\r\nX-T: 1\r\n 2\r\n\r\n".to_vec());
        assert!(read_chunked_body(&mut src).await.is_ok());
    }

    // the peek gate only needs a `"\r\n\r\n"` to exist *somewhere* in the peek
    // window, not inside the trailer itself: a trailer whose own blank line is a bare `\n`, with
    // no `\r\n\r\n` of its own, is still accepted once the gate finds one inside a pipelined next
    // request — the harness's `trailer-bare-lf-then-crlf-next` case. The trailer's own consumption
    // must still stop at its own blank line, leaving the next request's bytes untouched: the
    // lookahead is a peek, never a consuming read.
    #[tokio::test]
    async fn trailer_bare_lf_confirmed_by_upcoming_double_crlf_is_accepted_without_consuming_next_request() {
        let next_request = b"GET /next HTTP/1.1\r\nHost: B\r\n\r\n";
        let mut src = Cursor::new([b"0\r\nX-T: 1\n\n".as_slice(), next_request].concat());
        read_chunked_body(&mut src)
            .await
            .expect("bare-LF trailer confirmed by the pipelined request's own CRLFCRLF must be accepted");
        let consumed = usize::try_from(src.position()).unwrap();
        assert_eq!(consumed, b"0\r\nX-T: 1\n\n".len(), "must stop exactly at the trailer's own blank line");
        let mut leftover = Vec::new();
        src.read_to_end(&mut leftover).await.unwrap();
        assert_eq!(leftover, next_request, "the pipelined next request's bytes must stay unconsumed");
    }

    // Regression for ReviewHttpParity round 3, "Validate the whole trailer line before reading the
    // next trailer line": the round-2 fix only checked for a missing colon on the starting
    // line; the trailer reader also fails, before reading any further line, on a first line that
    // starts with SP/HT (`"malformed MIME header initial line"`), an empty or
    // non-token key, and a value byte outside the valid set (a bare CR
    // or other control byte). Each case must stop consumption at the end of its own bad line,
    // leaving the trailer's blank terminator and the pipelined next request unread — reachable by
    // feeding `0\r\n<line>\r\n\r\n` followed by `GET /next`.
    #[tokio::test]
    async fn malformed_trailer_line_variants_stop_consumption_at_the_bad_line() {
        let next_request = b"GET /next HTTP/1.1\r\nHost: B\r\n\r\n";
        let cases: &[&[u8]] = &[
            b" X-T: 1",     // initial line starts with SP
            b": v",         // empty key
            b"b(d: 1",      // '(' is not a valid field-name byte
            b"X-T: a\x01b", // 0x01 is not a valid value byte
            b"\rX-T: 1",    // bare CR in the key
            b"X-T: a\rb",   // bare CR in the value
        ];
        for bad_line in cases {
            let head = [b"0\r\n".as_slice(), bad_line, b"\r\n\r\n"].concat();
            let mut src = Cursor::new([head.as_slice(), next_request].concat());
            assert!(
                read_chunked_body(&mut src).await.is_err(),
                "trailer line {:?} must be rejected",
                String::from_utf8_lossy(bad_line)
            );
            let expected_consumed = b"0\r\n".len() + bad_line.len() + b"\r\n".len();
            assert_eq!(
                usize::try_from(src.position()).unwrap(),
                expected_consumed,
                "trailer line {:?} must stop consumption right after itself",
                String::from_utf8_lossy(bad_line)
            );
        }
    }

    // Regression for d79a7430 / ReviewHttpR4: a bad key or value byte must not cut consumption
    // short of the stopping point. Every obs-fold continuation line
    // for a field is read before the key/value checks ever run on the joined
    // line, so a bad key or value line is followed to the end of its last continuation before the
    // field is rejected — unlike a missing colon or an initial-whitespace line, both checked on
    // the raw first line before any continuation is read. Six hand-written cases plus four seeded
    // cases all left the pipelined next request open (idle, then answered `200 /next`) but closed
    // the connection in Rust before this fix.
    #[tokio::test]
    async fn malformed_trailer_key_or_value_consumes_continuations_before_rejecting() {
        let next_request = b"GET /next HTTP/1.1\r\nHost: B\r\n\r\n";
        let blocks: &[&[u8]] = &[
            b"b(d: 1\r\n x\r\n",
            b"X-T: a\x01b\r\n x\r\n",
            b": v\r\n\tx\r\n",
            b"\rX-T: 1\r\n x\r\n",
            b"X-T: 1\r\n \x01\r\n y\r\n",
            b"X-T: \x7f\r\n a\r\n\tb\r\n",
            b":\x00ZZ\r\n\t \n     \r\n",
            b":\n\t\r\n",
            b"Z:\"a\x00\n\ta Z\n",
            b"Z9: a Z\nZ!:\tZ\x00Z\r\r\n\t \n \r\n",
        ];
        for block in blocks {
            let head = [b"0\r\n".as_slice(), block].concat();
            let mut src = Cursor::new([head.as_slice(), next_request].concat());
            assert!(
                read_chunked_body(&mut src).await.is_err(),
                "trailer block {:?} must be rejected",
                String::from_utf8_lossy(block)
            );
            let expected_consumed = b"0\r\n".len() + block.len();
            assert_eq!(
                usize::try_from(src.position()).unwrap(),
                expected_consumed,
                "trailer block {:?} must stop consumption after its last continuation line",
                String::from_utf8_lossy(block)
            );
        }
    }

    // The key check accepts a key containing a space without canonicalising it;
    // `httparse`'s token grammar, used before this fix, rejected it outright.
    #[tokio::test]
    async fn trailer_field_name_with_a_space_is_accepted() {
        let mut src = Cursor::new(b"0\r\nbad key: 1\r\n\r\n".to_vec());
        assert!(read_chunked_body(&mut src).await.is_ok());
    }

    #[test]
    fn fix_trailer_rejects_forbidden_field_name() {
        let mut h = header_map(&[("Trailer", "Content-Length")]);
        assert!(fix_trailer(&mut h, true).is_err());
    }
}
