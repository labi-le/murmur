//! The wire format: the stream and datagram framing, the authentication headers and the padding
//! filler.
//!
//! These frames are read through an `AsyncRead`; the writers here build the header of a stream's
//! first frame and hand it to QUIC ahead of the payload it announces, which is why the two are
//! separate.

use anyhow::{anyhow, bail, Result};
use bytes::BytesMut;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

pub const MAX_ADDRESS_LENGTH: u64 = 2048;
/// [`MAX_MESSAGE_LENGTH`] as a `usize`, for the buffers it bounds.
const MAX_MESSAGE_LENGTH_USIZE: usize = 2048;
pub const MAX_MESSAGE_LENGTH: u64 = MAX_MESSAGE_LENGTH_USIZE as u64;
pub const MAX_PADDING_LENGTH: u64 = 4096;
pub const MAX_UDP_SIZE: usize = 4096;

const MAX_VAR_INT_1: u64 = 63;
const MAX_VAR_INT_2: u64 = 16383;
const MAX_VAR_INT_4: u64 = 1_073_741_823;
const MAX_VAR_INT_8: u64 = 4_611_686_018_427_387_903;

/// The encoded width of `value`; a value above 62 bits is rejected.
#[must_use]
pub const fn var_int_len(value: u64) -> usize {
    if value <= MAX_VAR_INT_1 {
        1
    } else if value <= MAX_VAR_INT_2 {
        2
    } else if value <= MAX_VAR_INT_4 {
        4
    } else {
        assert!(value <= MAX_VAR_INT_8, "value does not fit into 62 bits");
        8
    }
}

/// Panics rather than truncate once the value exceeds 62 bits. Every caller here feeds it either
/// a protocol constant or a length already bounded by a `MAX_*` above.
pub fn var_int_put(buf: &mut [u8], value: u64) -> usize {
    let len = var_int_len(value);
    let (field, _) = buf.split_at_mut(len);
    let encoded = value.to_be_bytes();
    let (_, payload) = encoded.split_at(encoded.len() - len);
    for (slot, byte) in field.iter_mut().zip(payload) {
        *slot = *byte;
    }
    let prefix = match len {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
    if let Some(first) = field.first_mut() {
        *first |= prefix;
    }
    len
}

pub async fn read_var_int<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    let [first] = first;
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    if len > 1 {
        let mut rest = [0u8; 7];
        let (tail, _) = rest.split_at_mut(len - 1);
        reader.read_exact(tail).await?;
        for byte in tail {
            value = (value << 8) | u64::from(*byte);
        }
    }
    Ok(value)
}

const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// `padding.String`: a half-open `[Min, Max)` run of filler characters.
fn padding(min: usize, max: usize) -> String {
    let mut rng = rand::rng();
    let len = min + rng.random_range(0..(max - min));
    (0..len).map(|_| padding_char(&mut rng)).collect()
}

fn padding_char(rng: &mut impl Rng) -> char {
    let index = rng.random_range(0..PADDING_CHARS.len());
    PADDING_CHARS.get(index).copied().unwrap_or_default() as char
}

fn auth_request_padding() -> String {
    padding(256, 2048)
}

fn auth_response_padding() -> String {
    padding(256, 2048)
}

fn tcp_request_padding() -> String {
    padding(64, 512)
}

fn tcp_response_padding() -> String {
    padding(128, 1024)
}

/// Writes `value` as a QUIC varint at the front of `buf` and hands back the rest of it.
fn put_var_int_at(buf: &mut [u8], value: u64) -> &mut [u8] {
    let len = var_int_len(value);
    let (field, rest) = buf.split_at_mut(len);
    var_int_put(field, value);
    rest
}

/// Copies `bytes` to the front of `buf` and hands back the rest of it.
fn put_bytes_at<'a>(buf: &'a mut [u8], bytes: &[u8]) -> &'a mut [u8] {
    let (field, rest) = buf.split_at_mut(bytes.len());
    field.copy_from_slice(bytes);
    rest
}

/// Writes the request header that precedes the first payload write.
///
/// ```text
/// 0x401 (QUIC varint) | address length (QUIC varint) | address | padding length | padding
/// ```
#[must_use]
pub fn write_tcp_request_header(addr: &str) -> BytesMut {
    let padding = tcp_request_padding();
    let addr_len = addr.len();
    let padding_len = padding.len();
    let header_len = var_int_len(FRAME_TYPE_TCP_REQUEST)
        + var_int_len(addr_len as u64)
        + addr_len
        + var_int_len(padding_len as u64)
        + padding_len;
    let mut header = BytesMut::zeroed(header_len);
    let rest = put_var_int_at(&mut header, FRAME_TYPE_TCP_REQUEST);
    let rest = put_var_int_at(rest, addr_len as u64);
    let rest = put_bytes_at(rest, addr.as_bytes());
    let rest = put_var_int_at(rest, padding_len as u64);
    put_bytes_at(rest, padding.as_bytes());
    header
}

/// Reads a TCP request, returning the destination address and consuming the filler.
pub async fn read_tcp_request<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<String> {
    let frame_type = read_var_int(reader).await?;
    if frame_type != FRAME_TYPE_TCP_REQUEST {
        bail!("invalid frame type");
    }
    let addr_len = read_var_int(reader).await?;
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
        bail!("invalid address length");
    }
    let mut addr = vec![0u8; usize::try_from(addr_len).map_err(|_| anyhow!("invalid address length"))?];
    reader.read_exact(&mut addr).await?;
    let padding = read_padding(reader).await?;
    discard(reader, padding).await?;
    Ok(String::from_utf8(addr)?)
}

/// Writes the response header that precedes the first payload write.
///
/// ```text
/// status (byte, 0=ok, 1=error) | message length (QUIC varint) | message | padding length | padding
/// ```
#[must_use]
pub fn write_tcp_response_header(ok: bool, message: &str) -> BytesMut {
    let padding = tcp_response_padding();
    let message_bytes = message.as_bytes();
    let message_len = message_bytes.len().min(MAX_MESSAGE_LENGTH_USIZE);
    let padding_len = padding.len();
    let header_len = 1 + var_int_len(message_len as u64) + message_len + var_int_len(padding_len as u64) + padding_len;
    let (message_head, _) = message_bytes.split_at(message_len);
    let mut header = BytesMut::with_capacity(header_len);
    header.extend_from_slice(&[u8::from(!ok)]);
    header.extend_from_slice(&var_int(message_len as u64));
    header.extend_from_slice(message_head);
    header.extend_from_slice(&var_int(padding_len as u64));
    header.extend_from_slice(padding.as_bytes());
    header
}

pub async fn read_tcp_response<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<(bool, String)> {
    let mut status = [0u8; 1];
    reader.read_exact(&mut status).await?;
    let ok = status[0] == 0;
    let message_len = read_var_int(reader).await?;
    if message_len > MAX_MESSAGE_LENGTH {
        bail!("invalid message length");
    }
    let mut message = vec![0u8; usize::try_from(message_len).map_err(|_| anyhow!("invalid message length"))?];
    reader.read_exact(&mut message).await?;
    let padding = read_padding(reader).await?;
    discard(reader, padding).await?;
    Ok((ok, String::from_utf8(message)?))
}

async fn read_padding<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<u64> {
    let padding_len = read_var_int(reader).await?;
    if padding_len > MAX_PADDING_LENGTH {
        bail!("invalid padding length");
    }
    Ok(padding_len)
}

async fn discard<R: AsyncRead + Unpin + ?Sized>(reader: &mut R, mut len: u64) -> Result<()> {
    let mut sink = [0u8; 4096];
    while len > 0 {
        let take = usize::try_from(len).unwrap_or(usize::MAX).min(sink.len());
        let (chunk, _) = sink.split_at_mut(take);
        reader.read_exact(chunk).await?;
        len -= take as u64;
    }
    Ok(())
}

fn var_int(value: u64) -> Vec<u8> {
    let mut buf = vec![0u8; var_int_len(value)];
    var_int_put(&mut buf, value);
    buf
}

/// The UDP message and its header size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: String,
    pub data: Vec<u8>,
}

impl UdpMessage {
    #[must_use]
    pub fn header_size(&self) -> usize {
        8 + var_int_len(self.addr.len() as u64) + self.addr.len()
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    #[must_use]
    pub fn serialize(&self) -> BytesMut {
        let mut buffer = BytesMut::with_capacity(self.size());
        buffer.extend_from_slice(&self.session_id.to_be_bytes());
        buffer.extend_from_slice(&self.packet_id.to_be_bytes());
        buffer.extend_from_slice(&[self.frag_id, self.frag_count]);
        buffer.extend_from_slice(&var_int(self.addr.len() as u64));
        buffer.extend_from_slice(self.addr.as_bytes());
        buffer.extend_from_slice(&self.data);
        buffer
    }
}

/// Parses a UDP message, bounding the address by `MAX_MESSAGE_LENGTH`.
pub fn parse_udp_message(message: &[u8]) -> Result<UdpMessage> {
    let Some((header, body)) = message.split_at_checked(8) else {
        bail!("invalid UDP message");
    };
    let Ok([s0, s1, s2, s3, p0, p1, frag_id, frag_count]) = <[u8; 8]>::try_from(header) else {
        bail!("invalid UDP message");
    };
    let session_id = u32::from_be_bytes([s0, s1, s2, s3]);
    let packet_id = u16::from_be_bytes([p0, p1]);
    let (addr, data) = split_address(body, MAX_MESSAGE_LENGTH)?;
    Ok(UdpMessage { session_id, packet_id, frag_id, frag_count, addr, data: data.to_vec() })
}

/// Splits the address off the body, bounded by the caller's limit, on the receiving side.
fn split_address(body: &[u8], limit: u64) -> Result<(String, &[u8])> {
    let Some((&first, rest)) = body.split_first() else {
        bail!("invalid address length");
    };
    let len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let Some((length_bytes, rest)) = rest.split_at_checked(len - 1) else {
        bail!("invalid address length");
    };
    let mut value = u64::from(first & 0x3f);
    for byte in length_bytes {
        value = (value << 8) | u64::from(*byte);
    }
    if value == 0 || value > limit {
        bail!("invalid address length");
    }
    let value = usize::try_from(value).map_err(|_| anyhow!("invalid address length"))?;
    let Some((address, rest)) = rest.split_at_checked(value) else {
        bail!("invalid address length");
    };
    Ok((String::from_utf8(address.to_vec())?, rest))
}

/// The host and path of the authentication endpoint.
pub const URL_HOST: &str = "hysteria";
pub const URL_PATH: &str = "/auth";

pub const REQUEST_HEADER_AUTH: &str = "Hysteria-Auth";
pub const RESPONSE_HEADER_UDP_ENABLED: &str = "Hysteria-UDP";
pub const COMMON_HEADER_CC_RX: &str = "Hysteria-CC-RX";
pub const COMMON_HEADER_PADDING: &str = "Hysteria-Padding";
pub const STATUS_AUTH_OK: u16 = 233;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthRequest {
    pub auth: String,
    /// `0` means unknown: the client asks the server to use bandwidth detection.
    pub rx: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthResponse {
    pub udp_enabled: bool,
    /// `0` means unlimited.
    pub rx: u64,
    /// The server asked the client to run bandwidth detection.
    pub rx_auto: bool,
}

#[must_use]
pub fn auth_request_to_header(request: &AuthRequest) -> http::HeaderMap {
    let padding = auth_request_padding();
    let rx = request.rx.to_string();
    let mut header = http::HeaderMap::new();
    header.insert(REQUEST_HEADER_AUTH, header_value(&request.auth));
    header.insert(COMMON_HEADER_CC_RX, header_value(&rx));
    header.insert(COMMON_HEADER_PADDING, header_value(&padding));
    header
}

/// The padding is alnum and the bandwidth a decimal, so a rejected value can only mean the
/// password carried a byte a header cannot hold; dropping it beats panicking on peer input.
fn header_value(text: &str) -> http::HeaderValue {
    http::HeaderValue::from_str(text).unwrap_or_else(|_| http::HeaderValue::from_static(""))
}

/// Reads the auth request out of the headers; an unparsable `Hysteria-CC-RX` reads as `0`.
#[must_use]
pub fn auth_request_from_header(header: &http::HeaderMap) -> AuthRequest {
    AuthRequest {
        auth: header_text(header, REQUEST_HEADER_AUTH),
        rx: header_text(header, COMMON_HEADER_CC_RX).parse().unwrap_or(0),
    }
}

#[must_use]
pub fn auth_response_to_header(response: &AuthResponse) -> http::HeaderMap {
    let mut header = http::HeaderMap::new();
    header.insert(
        RESPONSE_HEADER_UDP_ENABLED,
        http::HeaderValue::from_static(if response.udp_enabled { "true" } else { "false" }),
    );
    let rx = if response.rx_auto { "auto".to_owned() } else { response.rx.to_string() };
    let padding = auth_response_padding();
    header.insert(COMMON_HEADER_CC_RX, header_value(&rx));
    header.insert(COMMON_HEADER_PADDING, header_value(&padding));
    header
}

#[must_use]
pub fn auth_response_from_header(header: &http::HeaderMap) -> AuthResponse {
    let rx = header_text(header, COMMON_HEADER_CC_RX);
    if rx == "auto" {
        return AuthResponse {
            udp_enabled: header_text(header, RESPONSE_HEADER_UDP_ENABLED).parse().unwrap_or(false),
            rx: 0,
            rx_auto: true,
        };
    }
    AuthResponse {
        udp_enabled: header_text(header, RESPONSE_HEADER_UDP_ENABLED).parse().unwrap_or(false),
        rx: rx.parse().unwrap_or(0),
        rx_auto: false,
    }
}

fn header_text(header: &http::HeaderMap, name: &str) -> String {
    header.get(name).and_then(|value| value.to_str().ok()).unwrap_or_default().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn var_int_round_trips_every_width() {
        for value in [0u64, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824, MAX_VAR_INT_8] {
            let mut buf = [0u8; 8];
            let len = var_int_put(&mut buf, value);
            assert_eq!(len, var_int_len(value));
            let mut decoded = 0u64;
            for (index, byte) in buf[..len].iter().enumerate() {
                decoded = (decoded << 8) | u64::from(if index == 0 { byte & 0x3f } else { *byte });
            }
            assert_eq!(decoded, value, "value {value}");
        }
    }

    #[test]
    fn var_int_put_prefixes_each_width() {
        let mut buf = [0u8; 8];
        assert_eq!(var_int_put(&mut buf, 63), 1);
        assert_eq!(buf[0], 63);
        assert_eq!(var_int_put(&mut buf, 64), 2);
        assert_eq!(buf[0], 0x40);
        assert_eq!(buf[1], 64);
        assert_eq!(var_int_put(&mut buf, 16384), 4);
        assert_eq!(buf[0], 0x80);
        assert_eq!(var_int_put(&mut buf, MAX_VAR_INT_2 + 1), 4);
        let mut buf = [0u8; 8];
        assert_eq!(var_int_put(&mut buf, 1 << 32), 8);
        assert_eq!(buf[0], 0xc0);
    }

    #[tokio::test]
    async fn tcp_request_round_trips_with_payload() {
        let mut stream = write_tcp_request_header("example.com:443");
        stream.extend_from_slice(b"hello");
        let mut cursor = std::io::Cursor::new(stream);
        assert_eq!(read_tcp_request(&mut cursor).await.unwrap(), "example.com:443");
        let mut rest = vec![0u8; 5];
        cursor.read_exact(&mut rest).await.unwrap();
        assert_eq!(rest, b"hello");
    }

    #[tokio::test]
    async fn tcp_request_rejects_foreign_frame_type() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&var_int(0x402));
        let mut cursor = std::io::Cursor::new(stream);
        assert!(read_tcp_request(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn tcp_request_rejects_zero_length_address() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&var_int(FRAME_TYPE_TCP_REQUEST));
        stream.extend_from_slice(&var_int(0));
        let mut cursor = std::io::Cursor::new(stream);
        assert!(read_tcp_request(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn tcp_response_round_trips() {
        let mut stream = write_tcp_response_header(true, "");
        stream.extend_from_slice(b"payload");
        let mut cursor = std::io::Cursor::new(stream);
        assert_eq!(read_tcp_response(&mut cursor).await.unwrap(), (true, String::new()));
        let mut rest = [0u8; 7];
        cursor.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"payload");
    }

    #[tokio::test]
    async fn tcp_response_carries_error_message() {
        let stream = write_tcp_response_header(false, "refused");
        let mut cursor = std::io::Cursor::new(stream);
        assert_eq!(read_tcp_response(&mut cursor).await.unwrap(), (false, String::from("refused")));
    }

    #[tokio::test]
    async fn tcp_response_rejects_oversized_message() {
        let mut stream = vec![0u8];
        stream.extend_from_slice(&var_int(MAX_MESSAGE_LENGTH + 1));
        let mut cursor = std::io::Cursor::new(stream);
        assert!(read_tcp_response(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn tcp_request_padding_is_skipped_and_varint_width_varies() {
        // A 300-byte address forces the 2-byte length varint and a padding length in [64, 512).
        let addr = format!("{}:80", "a".repeat(290));
        let header = write_tcp_request_header(&addr);
        assert_eq!(header[0], 0x44);
        assert_eq!(header[1], 0x01);
        let header_len = header.len();
        let mut cursor = std::io::Cursor::new(header);
        assert_eq!(read_tcp_request(&mut cursor).await.unwrap(), addr);
        assert_eq!(cursor.position() as usize, header_len);
    }

    #[test]
    fn udp_message_round_trips() {
        let message = UdpMessage {
            session_id: 7,
            packet_id: 4242,
            frag_id: 1,
            frag_count: 3,
            addr: "1.2.3.4:53".to_owned(),
            data: vec![9u8; 100],
        };
        let encoded = message.serialize();
        assert_eq!(encoded.len(), message.size());
        assert_eq!(&encoded[..4], &7u32.to_be_bytes());
        assert_eq!(&encoded[4..6], &4242u16.to_be_bytes());
        assert_eq!(encoded[6], 1);
        assert_eq!(encoded[7], 3);
        assert_eq!(encoded[8], 10);
        assert_eq!(parse_udp_message(&encoded).unwrap(), message);
    }

    #[test]
    fn udp_message_accepts_empty_data() {
        let message = UdpMessage {
            session_id: 0,
            packet_id: 1,
            frag_id: 0,
            frag_count: 1,
            addr: "[::1]:1".to_owned(),
            data: Vec::new(),
        };
        assert_eq!(parse_udp_message(&message.serialize()).unwrap(), message);
    }

    #[test]
    fn udp_message_rejects_truncated_header() {
        assert!(parse_udp_message(&[0u8; 7]).is_err());
        assert!(parse_udp_message(&[]).is_err());
    }

    #[test]
    fn udp_message_bounds_the_address_by_max_message_length() {
        // A zero-length or over-long address is rejected; the bound itself is accepted.
        let mut body = vec![0u8; 8];
        body.extend_from_slice(&var_int(0));
        assert!(parse_udp_message(&body).is_err());

        let mut body = vec![0u8; 8];
        body.extend_from_slice(&var_int(MAX_MESSAGE_LENGTH + 1));
        assert!(parse_udp_message(&body).is_err());

        let mut body = vec![0u8; 8];
        body.extend_from_slice(&var_int(MAX_MESSAGE_LENGTH));
        body.extend_from_slice(&vec![b'x'; MAX_MESSAGE_LENGTH as usize]);
        let parsed = parse_udp_message(&body).unwrap();
        assert_eq!(parsed.addr, "x".repeat(MAX_MESSAGE_LENGTH as usize));
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn auth_headers_round_trip() {
        let request = AuthRequest { auth: "secret".to_owned(), rx: 12_345 };
        assert_eq!(auth_request_from_header(&auth_request_to_header(&request)), request);

        let response = AuthResponse { udp_enabled: true, rx: 999, rx_auto: false };
        assert_eq!(auth_response_from_header(&auth_response_to_header(&response)), response);
    }

    #[test]
    fn auth_response_auto_is_distinct_from_zero() {
        let response = AuthResponse { udp_enabled: false, rx: 0, rx_auto: true };
        assert_eq!(auth_response_from_header(&auth_response_to_header(&response)), response);

        let response = AuthResponse { udp_enabled: true, rx: 0, rx_auto: false };
        assert_eq!(auth_response_from_header(&auth_response_to_header(&response)), response);
    }

    #[test]
    fn auth_request_unparsable_bandwidth_reads_as_zero() {
        let mut header = http::HeaderMap::new();
        header.insert(REQUEST_HEADER_AUTH, http::HeaderValue::from_static("pw"));
        header.insert(COMMON_HEADER_CC_RX, http::HeaderValue::from_static("not-a-number"));
        assert_eq!(auth_request_from_header(&header), AuthRequest { auth: "pw".to_owned(), rx: 0 });
    }

    #[tokio::test]
    async fn var_int_reader_rejects_truncated_input() {
        let mut cursor = std::io::Cursor::new(vec![0x40]);
        assert!(read_var_int(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn var_int_reader_handles_eight_byte_width() {
        let mut encoded = vec![0u8; 8];
        let len = var_int_put(&mut encoded, MAX_VAR_INT_8);
        assert_eq!(len, 8);
        let mut cursor = std::io::Cursor::new(encoded);
        assert_eq!(read_var_int(&mut cursor).await.unwrap(), MAX_VAR_INT_8);
    }
}
