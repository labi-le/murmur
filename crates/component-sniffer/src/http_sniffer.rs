//! Sniffs the `:authority`/`host` of HTTP/1 request headers and HTTP/2 client prefaces.
//!
//! Header blocks are decoded by the local `hpack` submodule, a from-scratch RFC 7541 decoder
//! covering indexed and literal fields, dynamic table size updates and static Huffman.

use std::net::IpAddr;

use thiserror::Error;

use murmur_constant::metadata::NetWork;
use murmur_constant::sniffer::sniffer::Sniffer;

use super::base_sniffer::{BaseSniffer, SnifferConfig};
use super::dispatcher::ErrNoClue;
use super::tls_sniffer::ErrNeedAtLeastData;
use hpack::HpackDecoder;

#[derive(Debug, Error)]
#[error("not an HTTP")]
pub(crate) struct ErrNotHTTP;

#[derive(Debug, Error)]
#[error("host is ip")]
pub(crate) struct ErrHostIsIP;

/// RFC 9110 §9.3; RFC 5789 (PATCH method).
const HTTP_METHODS: [&[u8]; 9] =
    [b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"CONNECT", b"PATCH", b"TRACE"];

/// RFC 9113 §3.4.
const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// RFC 9113 §4.1.
pub(crate) const H2_FRAME_HEADER_LEN: usize = 9;

/// RFC 9113 §6.2 / §6.10.
pub(crate) const H2_FRAME_HEADERS: u8 = 0x1;
pub(crate) const H2_FRAME_SETTINGS: u8 = 0x4;
pub(crate) const H2_FRAME_CONTINUATION: u8 = 0x9;

pub(crate) const H2_FLAG_ACK: u8 = 0x1;
pub(crate) const H2_FLAG_END_HEADERS: u8 = 0x4;
pub(crate) const H2_FLAG_PADDED: u8 = 0x8;
pub(crate) const H2_FLAG_PRIORITY: u8 = 0x20;

/// RFC 9113 §6.5.2.
const HEADER_TABLE_SIZE: u32 = 4096;
/// RFC 9113 §4.2.
pub(crate) const H2_DEFAULT_MAX_FRAME_SIZE: usize = 1 << 14;

#[derive(Debug)]
pub struct HTTPSniffer {
    base: BaseSniffer,
}

impl HTTPSniffer {
    pub fn new(sniffer_config: SnifferConfig) -> anyhow::Result<Self> {
        let mut ports = sniffer_config.ports;
        if ports.is_empty() {
            ports = murmur_common::utils::ranges::IntRanges::from(vec![murmur_common::utils::range::new_range(80, 80)]);
        }
        Ok(Self { base: BaseSniffer::new(ports, NetWork::TCP) })
    }
}

impl Sniffer for HTTPSniffer {
    fn support_network(&self) -> NetWork {
        NetWork::TCP
    }

    fn sniff_data(&self, b: &[u8]) -> anyhow::Result<String> {
        if b.len() < H2_CLIENT_PREFACE.len() {
            if H2_CLIENT_PREFACE.starts_with(b) {
                return Err(ErrNeedAtLeastData::no_clue(b.len() + 1));
            }
            return sniff_http1(b);
        }
        if b.starts_with(H2_CLIENT_PREFACE) {
            return sniff_http2(b);
        }
        sniff_http1(b)
    }

    fn protocol(&self) -> String {
        "http".to_owned()
    }

    fn support_port(&self, port: u16) -> bool {
        self.base.support_port(port)
    }
}

fn is_http_method(method: &[u8]) -> bool {
    HTTP_METHODS.iter().any(|m| method.eq_ignore_ascii_case(m))
}

fn is_http_method_prefix(prefix: &[u8]) -> bool {
    HTTP_METHODS.iter().any(|method| method.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(prefix)))
}

fn sniff_http1(b: &[u8]) -> anyhow::Result<String> {
    let Some(space) = b.iter().position(|&c| c == b' ') else {
        if is_http_method_prefix(b) {
            return Err(ErrNeedAtLeastData::no_clue(b.len() + 1));
        }
        return Err(ErrNotHTTP.into());
    };
    let Some(method) = b.get(..space) else {
        return Err(ErrNoClue.into());
    };
    if !is_http_method(method) {
        return Err(ErrNotHTTP.into());
    }

    let Some(crlf) = find_subslice(b, b"\r\n") else {
        return Err(ErrNeedAtLeastData::no_clue(b.len() + 1));
    };
    let Some(req) = b.get(..crlf) else {
        return Err(ErrNoClue.into());
    };
    if req.len() < 14 {
        return Err(ErrNoClue.into());
    }

    let Some(rest) = req.get(space + 1..) else {
        return Err(ErrNoClue.into());
    };
    let Some(uri_space) = rest.iter().position(|&c| c == b' ') else {
        return Err(ErrNoClue.into());
    };
    let Some(mut uri) = rest.get(..uri_space) else {
        return Err(ErrNoClue.into());
    };
    if uri.is_empty() {
        return Err(ErrNoClue.into());
    }

    if uri.first().is_some_and(|&c| c == b'/' || c == b'*') {
        return parse_header_host_h1(b);
    }

    if let Some(pos) = find_subslice(uri, b"://") {
        let Some(after_scheme) = uri.get(pos + 3..) else {
            return Err(ErrNoClue.into());
        };
        uri = after_scheme;
    }
    if let Some(i) = uri.iter().position(|&c| c == b'/' || c == b'?' || c == b'#') {
        let Some(authority) = uri.get(..i) else {
            return Err(ErrNoClue.into());
        };
        uri = authority;
    }
    if let Some(pos) = uri.iter().position(|&c| c == b'@') {
        let Some(host) = uri.get(pos + 1..) else {
            return Err(ErrNoClue.into());
        };
        uri = host;
    }

    match parse_host(uri) {
        Ok(host) => Ok(host),
        Err(_) => parse_header_host_h1(b),
    }
}

fn parse_header_host_h1(b: &[u8]) -> anyhow::Result<String> {
    let mut rest = b;
    loop {
        let Some(crlf) = find_subslice(rest, b"\r\n") else {
            return Err(ErrNeedAtLeastData::no_clue(b.len() + 1));
        };
        let Some(line) = rest.get(..crlf) else {
            return Err(ErrNoClue.into());
        };
        if line.is_empty() {
            return Err(ErrNoClue.into());
        }
        let Some(tail) = rest.get(crlf + 2..) else {
            return Err(ErrNoClue.into());
        };
        rest = tail;
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            continue;
        };
        let Some(key) = line.get(..colon) else {
            return Err(ErrNoClue.into());
        };
        if !key.eq_ignore_ascii_case(b"host") {
            continue;
        }
        let Some(value) = line.get(colon + 1..) else {
            return Err(ErrNoClue.into());
        };
        let val = trim_ascii_whitespace(value);
        return parse_host(val);
    }
}

/// RFC 9113 §4.1.
fn parse_frame_header(b: &[u8]) -> Option<(&[u8; H2_FRAME_HEADER_LEN], &[u8])> {
    b.split_first_chunk::<H2_FRAME_HEADER_LEN>()
}

/// RFC 9113 §4.2, §4.3, §6.2 and §6.5: rejects a frame that cannot appear where the client
/// preface left the stream.
fn reject_frame(
    length: usize,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    header_stream_id: u32,
    payload_offset: usize,
) -> anyhow::Result<()> {
    if payload_offset == H2_CLIENT_PREFACE.len() + H2_FRAME_HEADER_LEN
        && (frame_type != H2_FRAME_SETTINGS || flags & H2_FLAG_ACK != 0)
    {
        return Err(ErrNoClue.into());
    }
    if length > H2_DEFAULT_MAX_FRAME_SIZE {
        return Err(ErrNoClue.into());
    }
    if frame_type == H2_FRAME_SETTINGS {
        let ack = flags & H2_FLAG_ACK != 0;
        if stream_id != 0 || (ack && length != 0) || (!ack && !length.is_multiple_of(6)) {
            return Err(ErrNoClue.into());
        }
    }
    if header_stream_id == 0 {
        if frame_type == H2_FRAME_CONTINUATION {
            return Err(ErrNoClue.into());
        }
        if frame_type == H2_FRAME_HEADERS && stream_id == 0 {
            return Err(ErrNoClue.into());
        }
    } else if frame_type != H2_FRAME_CONTINUATION || stream_id != header_stream_id {
        return Err(ErrNoClue.into());
    }
    Ok(())
}

/// RFC 9113 §6.2: the header block fragment inside a HEADERS payload, past the optional padding
/// length, padding and priority fields.
fn headers_fragment_bounds(
    payload: &[u8],
    length: usize,
    flags: u8,
    payload_offset: usize,
) -> anyhow::Result<(usize, usize)> {
    let mut start = 0usize;
    let mut end = length;
    if flags & H2_FLAG_PADDED != 0 {
        if length == 0 {
            return Err(ErrNoClue.into());
        }
        let Some(&pad_len) = payload.first() else {
            return Err(ErrNeedAtLeastData::no_clue(payload_offset + 1));
        };
        let pad_len = usize::from(pad_len);
        if pad_len >= length {
            return Err(ErrNoClue.into());
        }
        start += 1;
        end -= pad_len;
    }

    if flags & H2_FLAG_PRIORITY != 0 {
        if end.saturating_sub(start) < 5 {
            return Err(ErrNoClue.into());
        }
        start += 5;
    }
    Ok((start, end))
}

fn sniff_http2(b: &[u8]) -> anyhow::Result<String> {
    let total = b.len();
    let Some(mut b) = b.get(H2_CLIENT_PREFACE.len()..) else {
        return Err(ErrNoClue.into());
    };

    let mut authority = String::new();
    let mut host = String::new();
    let mut header_stream_id = 0u32;

    let mut decoder = HpackDecoder::new(HEADER_TABLE_SIZE);

    loop {
        let Some((header, rest)) = parse_frame_header(b) else {
            return Err(ErrNeedAtLeastData::no_clue(total - b.len() + H2_FRAME_HEADER_LEN));
        };
        let [len_hi, len_mid, len_lo, frame_type, flags, id_0, id_1, id_2, id_3] = *header;
        let length = (usize::from(len_hi) << 16) | (usize::from(len_mid) << 8) | usize::from(len_lo);
        let stream_id =
            (u32::from(id_0) << 24 | u32::from(id_1) << 16 | u32::from(id_2) << 8 | u32::from(id_3)) & 0x7fff_ffff;

        b = rest;
        let payload_offset = total - b.len();
        reject_frame(length, frame_type, flags, stream_id, header_stream_id, payload_offset)?;

        if header_stream_id == 0 {
            if frame_type != H2_FRAME_HEADERS {
                if b.len() < length {
                    return Err(ErrNeedAtLeastData::no_clue(payload_offset + length));
                }
                let Some(rest) = b.get(length..) else {
                    return Err(ErrNoClue.into());
                };
                b = rest;
                continue;
            }
            header_stream_id = stream_id;
        }

        let (fragment_start, fragment_end) = if frame_type == H2_FRAME_HEADERS {
            headers_fragment_bounds(b, length, flags, payload_offset)?
        } else {
            (0, length)
        };

        let mut available_end = b.len();
        if available_end > fragment_end {
            available_end = fragment_end;
        }
        if available_end > fragment_start {
            let Some(fragment) = b.get(fragment_start..available_end) else {
                return Err(ErrNoClue.into());
            };
            let write_result = decoder.write(fragment, |name, value| {
                if name == ":authority" {
                    value.clone_into(&mut authority);
                } else if name == "host" {
                    value.clone_into(&mut host);
                }
            });
            if !authority.is_empty() {
                return parse_host(authority.as_bytes());
            }
            if !host.is_empty() {
                return parse_host(host.as_bytes());
            }
            if write_result.is_err() {
                return Err(ErrNoClue.into());
            }
        }
        if flags & H2_FLAG_END_HEADERS != 0 && (fragment_start == fragment_end || available_end == fragment_end) {
            return Err(ErrNoClue.into());
        }

        if b.len() < length {
            let mut want = payload_offset + length;
            if available_end < fragment_end {
                want = total + 1;
                if b.len() < fragment_start {
                    want = payload_offset + fragment_start + 1;
                }
            }
            return Err(ErrNeedAtLeastData::no_clue(want));
        }
        let Some(rest) = b.get(length..) else {
            return Err(ErrNoClue.into());
        };
        b = rest;
    }
}

fn parse_host(h: &[u8]) -> anyhow::Result<String> {
    if h.is_empty() {
        return Err(ErrNoClue.into());
    }
    let mut hs = String::from_utf8_lossy(h).into_owned();

    if let Ok((host, _, _)) = murmur_common_net::split_host_port(&hs) {
        hs = host;
    }

    if let Some(inner) = hs.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
        hs = inner.to_owned();
    }

    hs = hs.trim_end_matches('.').to_lowercase();
    if hs.is_empty() {
        return Err(ErrNoClue.into());
    }

    if hs.parse::<IpAddr>().is_ok() {
        return Err(ErrHostIsIP.into());
    }

    Ok(hs)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn trim_ascii_whitespace(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !c.is_ascii_whitespace()).map_or(start, |i| i + 1);
    b.get(start..end).unwrap_or_default()
}

mod hpack {
    use std::collections::VecDeque;

    const STATIC_TABLE: [(&str, &str); 61] = [
        (":authority", ""),
        (":method", "GET"),
        (":method", "POST"),
        (":path", "/"),
        (":path", "/index.html"),
        (":scheme", "http"),
        (":scheme", "https"),
        (":status", "200"),
        (":status", "204"),
        (":status", "206"),
        (":status", "304"),
        (":status", "400"),
        (":status", "404"),
        (":status", "500"),
        ("accept-charset", ""),
        ("accept-encoding", "gzip, deflate"),
        ("accept-language", ""),
        ("accept-ranges", ""),
        ("accept", ""),
        ("access-control-allow-origin", ""),
        ("age", ""),
        ("allow", ""),
        ("authorization", ""),
        ("cache-control", ""),
        ("content-disposition", ""),
        ("content-encoding", ""),
        ("content-language", ""),
        ("content-length", ""),
        ("content-location", ""),
        ("content-range", ""),
        ("content-type", ""),
        ("cookie", ""),
        ("date", ""),
        ("etag", ""),
        ("expect", ""),
        ("expires", ""),
        ("from", ""),
        ("host", ""),
        ("if-match", ""),
        ("if-modified-since", ""),
        ("if-none-match", ""),
        ("if-range", ""),
        ("if-unmodified-since", ""),
        ("last-modified", ""),
        ("link", ""),
        ("location", ""),
        ("max-forwards", ""),
        ("proxy-authenticate", ""),
        ("proxy-authorization", ""),
        ("range", ""),
        ("referer", ""),
        ("refresh", ""),
        ("retry-after", ""),
        ("server", ""),
        ("set-cookie", ""),
        ("strict-transport-security", ""),
        ("transfer-encoding", ""),
        ("user-agent", ""),
        ("vary", ""),
        ("via", ""),
        ("www-authenticate", ""),
    ];

    /// RFC 7541 Appendix B, `(code, bit length)` indexed by symbol; entry 256 is EOS.
    #[rustfmt::skip]
    const HUFFMAN_CODES: [(u32, u8); 257] = [
        (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28), (0xfffffe5, 28),
        (0xfffffe6, 28), (0xfffffe7, 28), (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
        (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28), (0xfffffed, 28), (0xfffffee, 28),
        (0xfffffef, 28), (0xffffff0, 28), (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
        (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28), (0xffffff8, 28), (0xffffff9, 28),
        (0xffffffa, 28), (0xffffffb, 28), (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
        (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11), (0x3fa, 10), (0x3fb, 10),
        (0xf9, 8), (0x7fb, 11), (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
        (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6),
        (0x1c, 6), (0x1d, 6), (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
        (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10), (0x1ffa, 13), (0x21, 6),
        (0x5d, 7), (0x5e, 7), (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
        (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7), (0x67, 7), (0x68, 7),
        (0x69, 7), (0x6a, 7), (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
        (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7), (0xfc, 8), (0x73, 7),
        (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
        (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5), (0x24, 6), (0x5, 5),
        (0x25, 6), (0x26, 6), (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
        (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5), (0x2b, 6), (0x76, 7),
        (0x2c, 6), (0x8, 5), (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
        (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11), (0x3ffd, 14),
        (0x1ffd, 13), (0xffffffc, 28), (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
        (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23), (0x3fffd6, 22), (0x7fffda, 23),
        (0x7fffdb, 23), (0x7fffdc, 23), (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
        (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23),
        (0x7fffe2, 23), (0x7fffe3, 23), (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
        (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24), (0x3fffda, 22), (0x1fffdd, 21),
        (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
        (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22),
        (0x7fffeb, 23), (0x7fffec, 23), (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
        (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23), (0xfffea, 20), (0x3fffe2, 22),
        (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
        (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23),
        (0x3fffe8, 22), (0x1ffffec, 25), (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
        (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25), (0x7fff2, 19), (0x1fffe3, 21),
        (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
        (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26), (0xffffffd, 28), (0x7ffffe3, 27),
        (0x7ffffe4, 27), (0x7ffffe5, 27), (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
        (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23), (0x3fffea, 22), (0x3fffeb, 22),
        (0x1ffffee, 25), (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
        (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26), (0x7ffffe7, 27), (0x7ffffe8, 27),
        (0x7ffffe9, 27), (0x7ffffea, 27), (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
        (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26), (0x3fffffff, 30),
    ];

    const NO_CHILD: usize = usize::MAX;

    struct HuffmanTrie {
        children: Vec<[usize; 2]>,
        symbol: Vec<Option<usize>>,
    }

    fn huffman_trie() -> anyhow::Result<&'static HuffmanTrie> {
        static TRIE: std::sync::LazyLock<Option<HuffmanTrie>> = std::sync::LazyLock::new(build_huffman_trie);
        TRIE.as_ref().ok_or_else(|| anyhow::anyhow!("hpack: malformed huffman code table"))
    }

    /// RFC 7541 Appendix B as a decode trie; `None` for a table that cannot be walked.
    fn build_huffman_trie() -> Option<HuffmanTrie> {
        let mut children = vec![[NO_CHILD; 2]];
        let mut symbol: Vec<Option<usize>> = vec![None];
        for (sym, &(code, len)) in HUFFMAN_CODES.iter().enumerate() {
            let mut node = 0usize;
            for i in (0..len).rev() {
                let bit = ((code >> i) & 1) as usize;
                let child = children.get(node).and_then(|entry| entry.get(bit)).copied()?;
                node = if child == NO_CHILD {
                    children.push([NO_CHILD; 2]);
                    symbol.push(None);
                    let next = children.len() - 1;
                    *children.get_mut(node)?.get_mut(bit)? = next;
                    next
                } else {
                    child
                };
            }
            *symbol.get_mut(node)? = Some(sym);
        }
        Some(HuffmanTrie { children, symbol })
    }

    /// Decodes an RFC 7541 §5.2 Huffman-coded string. Trailing padding bits are accepted without
    /// verifying they form an EOS prefix; no test exercises Huffman-coded literals.
    fn huffman_decode(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let trie = huffman_trie()?;
        let mut out = Vec::new();
        let mut node = 0usize;
        let mut bits_since_root = 0u32;
        let total_bits = data.len() * 8;
        for bit_index in 0..total_bits {
            let Some(&byte) = data.get(bit_index / 8) else {
                anyhow::bail!("invalid huffman data");
            };
            let bit = usize::from((byte >> (7 - (bit_index % 8))) & 1);
            let next = trie.children.get(node).and_then(|entry| entry.get(bit)).copied().unwrap_or(NO_CHILD);
            if next == NO_CHILD {
                anyhow::bail!("invalid huffman code");
            }
            node = next;
            bits_since_root += 1;
            if let Some(sym) = trie.symbol.get(node).copied().flatten() {
                if sym == 256 {
                    anyhow::bail!("unexpected huffman EOS");
                }
                out.push(u8::try_from(sym).map_err(|_| anyhow::anyhow!("invalid huffman symbol"))?);
                node = 0;
                bits_since_root = 0;
            }
        }
        if node != 0 && bits_since_root >= 8 {
            anyhow::bail!("invalid huffman padding");
        }
        Ok(out)
    }

    fn decode_integer(buf: &[u8], prefix_bits: u8) -> anyhow::Result<Option<(u64, usize)>> {
        let Some(&first) = buf.first() else {
            return Ok(None);
        };
        let mask: u8 = u8::try_from((1u16 << prefix_bits).wrapping_sub(1))
            .map_err(|_| anyhow::anyhow!("hpack: decoding error: invalid integer prefix"))?;
        let mut value = u64::from(first & mask);
        if value < u64::from(mask) {
            return Ok(Some((value, 1)));
        }
        let mut shift = 0u32;
        let mut i = 1usize;
        loop {
            let Some(&b) = buf.get(i) else {
                return Ok(None);
            };
            value += u64::from(b & 0x7f) << shift;
            i += 1;
            if b & 0x80 == 0 {
                return Ok(Some((value, i)));
            }
            shift += 7;
            // The shift guard runs after the increment, before the next continuation byte is read.
            if shift >= 63 {
                anyhow::bail!("hpack: decoding error: varint integer overflow");
            }
        }
    }

    /// The bytes of `buf` from `pos` on, empty once `pos` is past the end.
    fn tail_from(buf: &[u8], pos: usize) -> &[u8] {
        buf.get(pos..).unwrap_or_default()
    }

    fn read_string(buf: &[u8]) -> anyhow::Result<Option<(String, usize)>> {
        let Some(&first) = buf.first() else {
            return Ok(None);
        };
        let huffman = first & 0x80 != 0;
        let Some((len, int_len)) = decode_integer(buf, 7)? else { return Ok(None) };
        let remaining = (buf.len() - int_len) as u64;
        if len > remaining {
            return Ok(None);
        }
        let total = int_len
            + usize::try_from(len).map_err(|_| anyhow::anyhow!("hpack: decoding error: varint integer overflow"))?;
        let Some(raw) = buf.get(int_len..total) else {
            return Ok(None);
        };
        let s = if huffman {
            String::from_utf8_lossy(&huffman_decode(raw)?).into_owned()
        } else {
            String::from_utf8_lossy(raw).into_owned()
        };
        Ok(Some((s, total)))
    }

    /// A from-scratch RFC 7541 decoder, scoped to this sniffer's needs: it emits every decoded
    /// header field to the supplied callback and otherwise only tracks the dynamic table.
    pub(super) struct HpackDecoder {
        dynamic_table: VecDeque<(String, String)>,
        dynamic_size: usize,
        max_size: usize,
        allowed_max_size: usize,
        buf: Vec<u8>,
    }

    impl HpackDecoder {
        pub(super) const fn new(max_size: u32) -> Self {
            Self {
                dynamic_table: VecDeque::new(),
                dynamic_size: 0,
                max_size: max_size as usize,
                allowed_max_size: max_size as usize,
                buf: Vec::new(),
            }
        }

        fn lookup(&self, index: u64) -> Option<(String, String)> {
            if index == 0 {
                return None;
            }
            let index = usize::try_from(index).ok()?;
            if index <= STATIC_TABLE.len() {
                let &(name, value) = STATIC_TABLE.get(index - 1)?;
                Some((name.to_owned(), value.to_owned()))
            } else {
                self.dynamic_table.get(index - STATIC_TABLE.len() - 1).cloned()
            }
        }

        fn insert_dynamic(&mut self, name: String, value: String) {
            self.dynamic_size += name.len() + value.len() + 32;
            self.dynamic_table.push_front((name, value));
            while self.dynamic_size > self.max_size {
                let Some((name, value)) = self.dynamic_table.pop_back() else { break };
                self.dynamic_size -= name.len() + value.len() + 32;
            }
        }

        /// Tries to parse exactly one header field representation from the head of `buf`.
        /// `Ok(None)` means more data is needed; `Ok(Some(consumed))` reports the byte count to
        /// drop, having already emitted a field or applied a table size update.
        fn try_parse_one(&mut self, buf: &[u8], on_field: &mut dyn FnMut(&str, &str)) -> anyhow::Result<Option<usize>> {
            let Some(&first) = buf.first() else { return Ok(None) };

            if first & 0x80 != 0 {
                let Some((index, consumed)) = decode_integer(buf, 7)? else { return Ok(None) };
                let Some((name, value)) = self.lookup(index) else {
                    anyhow::bail!("hpack: invalid index {index}");
                };
                on_field(&name, &value);
                return Ok(Some(consumed));
            }

            if first & 0x40 != 0 {
                let Some((index, index_len)) = decode_integer(buf, 6)? else { return Ok(None) };
                let mut pos = index_len;
                let name = if index == 0 {
                    let Some((name, name_len)) = read_string(tail_from(buf, pos))? else { return Ok(None) };
                    pos += name_len;
                    name
                } else {
                    let Some((name, _)) = self.lookup(index) else {
                        anyhow::bail!("hpack: invalid index {index}");
                    };
                    name
                };
                let Some((value, value_len)) = read_string(tail_from(buf, pos))? else { return Ok(None) };
                pos += value_len;
                on_field(&name, &value);
                self.insert_dynamic(name, value);
                return Ok(Some(pos));
            }

            if first & 0x20 != 0 {
                let Some((new_size, consumed)) = decode_integer(buf, 5)? else { return Ok(None) };
                // A size update above the decoder's allowed maximum (its initial max size) is
                // rejected with "dynamic table size update too large".
                if new_size > self.allowed_max_size as u64 {
                    anyhow::bail!("hpack: decoding error: dynamic table size update too large");
                }
                let new_size = usize::try_from(new_size)
                    .map_err(|_| anyhow::anyhow!("hpack: decoding error: dynamic table size update too large"))?;
                self.max_size = new_size;
                while self.dynamic_size > self.max_size {
                    let Some((name, value)) = self.dynamic_table.pop_back() else { break };
                    self.dynamic_size -= name.len() + value.len() + 32;
                }
                return Ok(Some(consumed));
            }

            // Literal without indexing (0000xxxx) or never indexed (0001xxxx): both share a
            // 4-bit prefix and are not inserted into the dynamic table.
            let Some((index, index_len)) = decode_integer(buf, 4)? else { return Ok(None) };
            let mut pos = index_len;
            let name = if index == 0 {
                let Some((name, name_len)) = read_string(tail_from(buf, pos))? else { return Ok(None) };
                pos += name_len;
                name
            } else {
                let Some((name, _)) = self.lookup(index) else {
                    anyhow::bail!("hpack: invalid index {index}");
                };
                name
            };
            let Some((value, value_len)) = read_string(tail_from(buf, pos))? else { return Ok(None) };
            pos += value_len;
            on_field(&name, &value);
            Ok(Some(pos))
        }

        pub(super) fn write(&mut self, data: &[u8], mut on_field: impl FnMut(&str, &str)) -> anyhow::Result<()> {
            self.buf.extend_from_slice(data);
            let mut buf = std::mem::take(&mut self.buf);
            let result = loop {
                match self.try_parse_one(&buf, &mut on_field) {
                    Ok(Some(consumed)) => {
                        buf.drain(..consumed);
                    }
                    Ok(None) => break Ok(()),
                    Err(err) => break Err(err),
                }
            };
            self.buf = buf;
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_http2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; H2_FRAME_HEADER_LEN + payload.len()];
        frame[0] = (payload.len() >> 16) as u8;
        frame[1] = (payload.len() >> 8) as u8;
        frame[2] = payload.len() as u8;
        frame[3] = frame_type;
        frame[4] = flags;
        frame[5..9].copy_from_slice(&stream_id.to_be_bytes());
        frame[H2_FRAME_HEADER_LEN..].copy_from_slice(payload);
        frame
    }

    fn make_test_http2_input(frames: &[&[u8]]) -> Vec<u8> {
        let mut input = H2_CLIENT_PREFACE.to_vec();
        input.extend(make_test_http2_frame(H2_FRAME_SETTINGS, 0, 0, &[]));
        for frame in frames {
            input.extend_from_slice(frame);
        }
        input
    }

    fn new_sniffer() -> HTTPSniffer {
        HTTPSniffer::new(SnifferConfig::default()).expect("sniffer constructs")
    }

    #[test]
    fn http1_origin_form() {
        let domain = new_sniffer().sniff_data(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn http1_uppercase_host() {
        let domain = new_sniffer().sniff_data(b"GET / HTTP/1.1\r\nHost: EXAMPLE.COM\r\n\r\n").unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn http1_host_before_end_of_headers() {
        let domain = new_sniffer().sniff_data(b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Large: ").unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn http1_absolute_form() {
        let domain = new_sniffer().sniff_data(b"GET http://example.com/path HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn http1_ip_host_errors() {
        let err = new_sniffer().sniff_data(b"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n").unwrap_err();
        assert!(err.is::<ErrHostIsIP>());
    }

    #[test]
    fn http1_rejects_non_http_prefix() {
        let err = new_sniffer().sniff_data(&[0x16, 0x03, 0x01, 0x00, 0x20]).unwrap_err();
        assert!(err.is::<ErrNotHTTP>());
    }

    #[test]
    fn http1_waits_for_partial_method() {
        let err = new_sniffer().sniff_data(b"GE").unwrap_err();
        let need = err.downcast_ref::<ErrNeedAtLeastData>().expect("need at least data");
        assert_eq!(need.length, 3);
    }

    #[test]
    fn http1_waits_for_complete_host_line() {
        let input = b"GET / HTTP/1.1\r\nHost: example";
        let err = new_sniffer().sniff_data(input).unwrap_err();
        let need = err.downcast_ref::<ErrNeedAtLeastData>().expect("need at least data");
        assert_eq!(need.length, input.len() + 1);
    }

    #[test]
    fn http2_single_headers_frame() {
        let domain = "example.com";
        let mut header_block = vec![0x41, domain.len() as u8];
        header_block.extend_from_slice(domain.as_bytes());
        let frame = make_test_http2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &header_block);
        let input = make_test_http2_input(&[&frame]);
        let result = new_sniffer().sniff_data(&input).unwrap();
        assert_eq!(result, domain);
    }

    #[test]
    fn http2_continuations() {
        let domain = "example.com";
        let mut header_block = vec![0x41, domain.len() as u8];
        header_block.extend_from_slice(domain.as_bytes());
        const FIRST_SPLIT: usize = 4;
        const SECOND_SPLIT: usize = 9;
        let first = make_test_http2_frame(H2_FRAME_HEADERS, 0, 1, &header_block[..FIRST_SPLIT]);
        let second = make_test_http2_frame(H2_FRAME_CONTINUATION, 0, 1, &header_block[FIRST_SPLIT..SECOND_SPLIT]);
        let third = make_test_http2_frame(H2_FRAME_CONTINUATION, H2_FLAG_END_HEADERS, 1, &header_block[SECOND_SPLIT..]);
        let input = make_test_http2_input(&[&first, &second, &third]);
        let result = new_sniffer().sniff_data(&input).unwrap();
        assert_eq!(result, domain);
    }

    #[test]
    fn http2_continuation_on_another_stream_errors() {
        let domain = "example.com";
        let mut header_block = vec![0x41, domain.len() as u8];
        header_block.extend_from_slice(domain.as_bytes());
        const FIRST_SPLIT: usize = 4;
        let first = make_test_http2_frame(H2_FRAME_HEADERS, 0, 1, &header_block[..FIRST_SPLIT]);
        let second = make_test_http2_frame(H2_FRAME_CONTINUATION, H2_FLAG_END_HEADERS, 3, &header_block[FIRST_SPLIT..]);
        let input = make_test_http2_input(&[&first, &second]);
        assert!(new_sniffer().sniff_data(&input).is_err());
    }

    #[test]
    fn http2_interleaved_frame_errors() {
        let domain = "example.com";
        let mut header_block = vec![0x41, domain.len() as u8];
        header_block.extend_from_slice(domain.as_bytes());
        const FIRST_SPLIT: usize = 4;
        let first = make_test_http2_frame(H2_FRAME_HEADERS, 0, 1, &header_block[..FIRST_SPLIT]);
        let settings = make_test_http2_frame(0x4, 0, 0, &[]);
        let third = make_test_http2_frame(H2_FRAME_CONTINUATION, H2_FLAG_END_HEADERS, 1, &header_block[FIRST_SPLIT..]);
        let input = make_test_http2_input(&[&first, &settings, &third]);
        assert!(new_sniffer().sniff_data(&input).is_err());
    }

    #[test]
    fn http2_authority_before_incomplete_frame_payload() {
        let domain = "example.com";
        let mut header_block = vec![0x41, domain.len() as u8];
        header_block.extend_from_slice(domain.as_bytes());
        let mut padded = header_block.clone();
        padded.extend(std::iter::repeat_n(0u8, 1024));
        let frame = make_test_http2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &padded);
        let truncated = &frame[..H2_FRAME_HEADER_LEN + header_block.len()];
        let input = make_test_http2_input(&[truncated]);
        let result = new_sniffer().sniff_data(&input).unwrap();
        assert_eq!(result, domain);
    }

    #[test]
    fn http2_authority_before_invalid_trailing_hpack() {
        let domain = "example.com";
        let mut header_block = vec![0x41, domain.len() as u8];
        header_block.extend_from_slice(domain.as_bytes());
        header_block.push(0x80);
        let frame = make_test_http2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &header_block);
        let input = make_test_http2_input(&[&frame]);
        let result = new_sniffer().sniff_data(&input).unwrap();
        assert_eq!(result, domain);
    }

    #[test]
    fn http2_reads_preface_incrementally() {
        for input in
            [&H2_CLIENT_PREFACE[..1], &H2_CLIENT_PREFACE[..3], &H2_CLIENT_PREFACE[..H2_CLIENT_PREFACE.len() - 1]]
        {
            let err = new_sniffer().sniff_data(input).unwrap_err();
            let need = err.downcast_ref::<ErrNeedAtLeastData>().expect("need at least data");
            assert_eq!(need.length, input.len() + 1);
        }
    }

    #[test]
    fn http2_rejects_invalid_frame_headers_before_payload() {
        let frame_header = |frame_type: u8, flags: u8, stream_id: u32, length: usize| -> Vec<u8> {
            let frame = make_test_http2_frame(frame_type, flags, stream_id, &vec![0u8; length]);
            frame[..H2_FRAME_HEADER_LEN].to_vec()
        };

        let cases: Vec<Vec<u8>> = vec![
            {
                let mut v = H2_CLIENT_PREFACE.to_vec();
                v.extend(frame_header(0x0, 0, 1, 1024));
                v
            },
            {
                let mut v = H2_CLIENT_PREFACE.to_vec();
                v.extend(frame_header(H2_FRAME_SETTINGS, H2_FLAG_ACK, 0, 0));
                v
            },
            make_test_http2_input(&[&frame_header(H2_FRAME_HEADERS, 0, 1, H2_DEFAULT_MAX_FRAME_SIZE + 1)]),
            {
                let mut v = H2_CLIENT_PREFACE.to_vec();
                v.extend(frame_header(H2_FRAME_SETTINGS, 0, 0, 1));
                v
            },
            make_test_http2_input(&[&frame_header(H2_FRAME_CONTINUATION, 0, 1, 1024)]),
            make_test_http2_input(&[&frame_header(H2_FRAME_HEADERS, 0, 0, 1024)]),
            {
                let domain = "example.com";
                let mut header_block = vec![0x41, domain.len() as u8];
                header_block.extend_from_slice(domain.as_bytes());
                const FIRST_SPLIT: usize = 4;
                let first = make_test_http2_frame(H2_FRAME_HEADERS, 0, 1, &header_block[..FIRST_SPLIT]);
                make_test_http2_input(&[&first, &frame_header(H2_FRAME_SETTINGS, 0, 0, 0)])
            },
        ];
        for input in cases {
            let err = new_sniffer().sniff_data(&input).unwrap_err();
            assert!(err.is::<ErrNoClue>());
            assert!(err.downcast_ref::<ErrNeedAtLeastData>().is_none());
        }
    }

    #[test]
    fn http2_continuation_header_missing() {
        let domain = "example.com";
        let mut header_block = vec![0x41, domain.len() as u8];
        header_block.extend_from_slice(domain.as_bytes());
        const FIRST_SPLIT: usize = 4;
        let frame = make_test_http2_frame(H2_FRAME_HEADERS, 0, 1, &header_block[..FIRST_SPLIT]);
        let input = make_test_http2_input(&[&frame]);
        let err = new_sniffer().sniff_data(&input).unwrap_err();
        let need = err.downcast_ref::<ErrNeedAtLeastData>().expect("need at least data");
        assert_eq!(need.length, input.len() + H2_FRAME_HEADER_LEN);
    }

    #[test]
    fn http2_continuation_payload_incomplete() {
        let domain = "example.com";
        let mut header_block = vec![0x41, domain.len() as u8];
        header_block.extend_from_slice(domain.as_bytes());
        const FIRST_SPLIT: usize = 4;
        let first = make_test_http2_frame(H2_FRAME_HEADERS, 0, 1, &header_block[..FIRST_SPLIT]);
        let second = make_test_http2_frame(H2_FRAME_CONTINUATION, H2_FLAG_END_HEADERS, 1, &header_block[FIRST_SPLIT..]);
        let complete = make_test_http2_input(&[&first, &second]);
        let err = new_sniffer().sniff_data(&complete[..complete.len() - 1]).unwrap_err();
        let need = err.downcast_ref::<ErrNeedAtLeastData>().expect("need at least data");
        assert_eq!(need.length, complete.len());
    }

    #[test]
    fn http2_rejects_missing_authority_before_frame_padding() {
        const PADDING_LEN: usize = 128;
        let mut payload = vec![PADDING_LEN as u8, 0x82];
        payload.extend(std::iter::repeat_n(0u8, PADDING_LEN));
        let frame = make_test_http2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_PADDED, 1, &payload);
        let mut input = make_test_http2_input(&[&frame]);
        input.truncate(input.len() - PADDING_LEN);

        let err = new_sniffer().sniff_data(&input).unwrap_err();
        assert!(err.is::<ErrNoClue>());
        assert!(err.downcast_ref::<ErrNeedAtLeastData>().is_none());
    }

    /// RFC 7541 §5.1 integer encoding, used to craft the isolated `HpackDecoder` inputs below.
    fn encode_hpack_int(prefix_bits: u8, prefix_pattern: u8, mut value: u64) -> Vec<u8> {
        let mask = (1u16 << prefix_bits) as u64 - 1;
        let mut out = Vec::new();
        if value < mask {
            out.push(prefix_pattern | value as u8);
            return out;
        }
        out.push(prefix_pattern | mask as u8);
        value -= mask;
        while value >= 128 {
            out.push(((value % 128) as u8) | 0x80);
            value /= 128;
        }
        out.push(value as u8);
        out
    }

    /// A size update above the decoder's allowed maximum (its initial max size) is rejected
    /// rather than applied, so later insertions cannot grow the table unbounded.
    #[test]
    fn hpack_dynamic_table_size_update_above_allowed_max_errors() {
        let mut decoder = HpackDecoder::new(HEADER_TABLE_SIZE);
        let update = encode_hpack_int(5, 0x20, u64::from(HEADER_TABLE_SIZE) + 1);
        let err = decoder.write(&update, |_, _| {}).unwrap_err();
        assert!(err.to_string().contains("dynamic table size update too large"));
    }

    /// The overflow guard bails once the continuation shift reaches 63; accepting that byte let
    /// the next addition shift a u64 by 63 bits and panic in debug builds.
    #[test]
    fn hpack_integer_overflow_errors_without_panicking() {
        let mut decoder = HpackDecoder::new(HEADER_TABLE_SIZE);
        let mut data = vec![0xFFu8];
        data.extend(std::iter::repeat_n(0x80u8, 9));
        let err = decoder.write(&data, |_, _| {}).unwrap_err();
        assert!(err.to_string().contains("overflow"));
    }
}
