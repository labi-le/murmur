use std::fmt;

use thiserror::Error;

use murmur_common::utils::range::new_range;
use murmur_common::utils::ranges::IntRanges;
use murmur_constant::metadata::NetWork;
use murmur_constant::sniffer::sniffer::Sniffer;

use super::base_sniffer::{BaseSniffer, SnifferConfig};
use super::dispatcher::ErrNoClue;

#[derive(Debug, Error)]
#[error("not TLS header")]
pub(crate) struct ErrNotTLS;

#[derive(Debug, Error)]
#[error("not client hello")]
pub(crate) struct ErrNotClientHello;

/// `read_client_hello`'s failure vocabulary: `sniff_tls` and QUIC's `try_assemble` both branch on
/// "need more bytes" versus everything else, so this replaces the `downcast_ref::<ErrNeedAtLeastData>()`
/// at each call site with a `match`.
#[derive(Debug, Error)]
pub(crate) enum ClientHelloError {
    #[error("not enough information for making a decision, need at least length: {0}")]
    NeedMoreData(usize),
    #[error("not client hello")]
    NotClientHello,
    #[error("not TLS header")]
    NotTLS,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub(crate) const TLS_RECORD_HEADER_LEN: usize = 5;
pub(crate) const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const TLS_RECORD_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_MAX_PLAINTEXT: usize = 1 << 14;

/// The error kind a too-short buffer produces; the `err` field always carries [`ErrNoClue`] at every
/// call site here, but keeps the generic shape.
#[derive(Debug)]
pub(crate) struct ErrNeedAtLeastData {
    pub(crate) length: usize,
    source: anyhow::Error,
}

impl ErrNeedAtLeastData {
    pub(crate) const fn new(length: usize, source: anyhow::Error) -> Self {
        Self { length, source }
    }

    pub(crate) fn no_clue(length: usize) -> anyhow::Error {
        Self::new(length, ErrNoClue.into()).into()
    }
}

impl fmt::Display for ErrNeedAtLeastData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, need at least length: {}", self.source, self.length)
    }
}

impl std::error::Error for ErrNeedAtLeastData {}

#[derive(Debug)]
pub struct TLSSniffer {
    base: BaseSniffer,
}

impl TLSSniffer {
    pub fn new(sniffer_config: SnifferConfig) -> anyhow::Result<Self> {
        let mut ports = sniffer_config.ports;
        if ports.is_empty() {
            ports = IntRanges::from(vec![new_range(443, 443)]);
        }
        Ok(Self { base: BaseSniffer::new(ports, NetWork::TCP) })
    }
}

impl Sniffer for TLSSniffer {
    fn support_network(&self) -> NetWork {
        NetWork::TCP
    }

    fn sniff_data(&self, bytes: &[u8]) -> anyhow::Result<String> {
        sniff_tls(bytes)
    }

    fn protocol(&self) -> String {
        "tls".to_owned()
    }

    fn support_port(&self, port: u16) -> bool {
        self.base.support_port(port)
    }
}

pub(crate) const fn is_valid_tls_version(major: u8, _minor: u8) -> bool {
    major == 3
}

/// The `ClientHello` walk's length guard: a field running past `hello_size` is malformed, one
/// running past the buffered bytes only needs more data.
fn need_more(data_len: usize, hello_size: usize, length: usize) -> Result<(), ClientHelloError> {
    if length > hello_size {
        return Err(ClientHelloError::NotClientHello);
    }
    if data_len < length {
        return Err(ClientHelloError::NeedMoreData(length));
    }
    Ok(())
}

fn byte_at(data: &[u8], index: usize) -> Result<u8, ClientHelloError> {
    data.get(index).copied().ok_or_else(|| ClientHelloError::NeedMoreData(index + 1))
}

fn be16_at(data: &[u8], index: usize) -> Result<u16, ClientHelloError> {
    let high = byte_at(data, index)?;
    let low = byte_at(data, index + 1)?;
    Ok(u16::from(high) << 8 | u16::from(low))
}

/// Returns the server name as soon as its complete field is available in a `ClientHello` prefix,
/// including the four-byte handshake header.
pub(crate) fn read_client_hello(data: &[u8]) -> Result<String, ClientHelloError> {
    if data.is_empty() {
        return Err(ClientHelloError::NeedMoreData(1));
    }
    if data.first() != Some(&TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        return Err(ClientHelloError::NotClientHello);
    }
    if data.len() < TLS_HANDSHAKE_HEADER_LEN {
        return Err(ClientHelloError::NeedMoreData(TLS_HANDSHAKE_HEADER_LEN));
    }

    let hello_size = client_hello_size(data)?;
    let data = data.get(..hello_size).unwrap_or(data);
    let need = |length: usize| need_more(data.len(), hello_size, length);

    let mut offset = TLS_HANDSHAKE_HEADER_LEN + 2 + 32;
    need(offset + 1)?;
    let session_id_len = usize::from(byte_at(data, offset)?);
    if session_id_len > 32 {
        return Err(ClientHelloError::NotClientHello);
    }
    offset += 1;
    need(offset + session_id_len)?;
    offset += session_id_len;

    need(offset + 2)?;
    let cipher_suite_len = usize::from(be16_at(data, offset)?);
    if cipher_suite_len % 2 == 1 {
        return Err(ClientHelloError::NotClientHello);
    }
    offset += 2;
    need(offset + cipher_suite_len)?;
    offset += cipher_suite_len;

    need(offset + 1)?;
    let compression_methods_len = usize::from(byte_at(data, offset)?);
    offset += 1;
    need(offset + compression_methods_len)?;
    offset += compression_methods_len;

    if offset == hello_size {
        return Err(ClientHelloError::NotClientHello);
    }
    need(offset + 2)?;

    let extensions_length = usize::from(be16_at(data, offset)?);
    offset += 2;
    let extensions_end = offset + extensions_length;
    if extensions_end != hello_size {
        return Err(ClientHelloError::NotClientHello);
    }

    while offset < extensions_end {
        need(offset + 4)?;
        let extension = be16_at(data, offset)?;
        let length = usize::from(be16_at(data, offset + 2)?);
        offset += 4;
        let field_end = offset + length;
        if field_end > extensions_end {
            return Err(ClientHelloError::NotClientHello);
        }

        if extension == 0x00 {
            if length < 2 {
                return Err(ClientHelloError::NotClientHello);
            }
            need(offset + 2)?;
            let names_len = usize::from(be16_at(data, offset)?);
            offset += 2;
            let names_end = offset + names_len;
            if names_end != field_end {
                return Err(ClientHelloError::NotClientHello);
            }
            while offset < names_end {
                need(offset + 3)?;
                let name_type = byte_at(data, offset)?;
                let host_len = usize::from(be16_at(data, offset + 1)?);
                offset += 3;
                let host_end = offset + host_len;
                if host_end > names_end {
                    return Err(ClientHelloError::NotClientHello);
                }
                need(host_end)?;
                if name_type == 0 {
                    let raw = data.get(offset..host_end).ok_or_else(|| ClientHelloError::NeedMoreData(host_end))?;
                    let server_name = String::from_utf8_lossy(raw).into_owned();
                    if server_name.ends_with('.') {
                        return Err(ClientHelloError::NotClientHello);
                    }
                    return Ok(server_name);
                }
                offset = host_end;
            }
        } else {
            if field_end == extensions_end {
                return Err(ClientHelloError::NotTLS);
            }
            need(field_end)?;
            offset = field_end;
        }
    }

    Err(ClientHelloError::NotTLS)
}

pub(crate) fn client_hello_size(data: &[u8]) -> anyhow::Result<usize> {
    let Some((header, _)) = data.split_first_chunk::<TLS_HANDSHAKE_HEADER_LEN>() else {
        return Err(ErrNoClue.into());
    };
    let [handshake_type, len_hi, len_mid, len_lo] = *header;
    if handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(ErrNotClientHello.into());
    }

    let body_len = (usize::from(len_hi) << 16) | (usize::from(len_mid) << 8) | usize::from(len_lo);
    Ok(TLS_HANDSHAKE_HEADER_LEN + body_len)
}

pub(crate) fn sniff_tls(b: &[u8]) -> anyhow::Result<String> {
    let mut client_hello: Vec<u8> = Vec::new();
    let mut wire_offset = 0usize;

    loop {
        let Some(tail) = b.get(wire_offset..) else {
            return Err(ErrNeedAtLeastData::no_clue(wire_offset + TLS_RECORD_HEADER_LEN));
        };
        let Some((header, _)) = tail.split_first_chunk::<TLS_RECORD_HEADER_LEN>() else {
            return Err(ErrNeedAtLeastData::no_clue(wire_offset + TLS_RECORD_HEADER_LEN));
        };
        let [record_type, major, minor, record_len_hi, record_len_lo] = *header;
        if record_type != TLS_RECORD_TYPE_HANDSHAKE || !is_valid_tls_version(major, minor) {
            return Err(ErrNotTLS.into());
        }

        let record_len = (usize::from(record_len_hi) << 8) | usize::from(record_len_lo);
        if record_len > TLS_MAX_PLAINTEXT {
            return Err(ErrNotTLS.into());
        }
        if record_len == 0 {
            return Err(ErrNotClientHello.into());
        }

        let payload_offset = wire_offset + TLS_RECORD_HEADER_LEN;
        let record_end = payload_offset + record_len;
        let mut payload_end = b.len();
        if payload_end > record_end {
            payload_end = record_end;
        }
        if payload_end < payload_offset {
            payload_end = payload_offset;
        }

        let Some(payload) = b.get(payload_offset..payload_end) else {
            return Err(ErrNeedAtLeastData::no_clue(payload_end));
        };
        if wire_offset == 0 {
            client_hello = payload.to_vec();
        } else {
            client_hello.extend_from_slice(payload);
        }

        match read_client_hello(&client_hello) {
            Ok(domain) => return Ok(domain),
            Err(ClientHelloError::NeedMoreData(length)) => {
                if payload_end < record_end {
                    let mut missing = length - client_hello.len();
                    let remaining = record_end - payload_end;
                    if missing > remaining {
                        missing = remaining;
                    }
                    return Err(ErrNeedAtLeastData::no_clue(payload_end + missing));
                }
            }
            Err(ClientHelloError::NotClientHello) => return Err(ErrNotClientHello.into()),
            Err(ClientHelloError::NotTLS) => return Err(ErrNotTLS.into()),
            Err(ClientHelloError::Other(err)) => return Err(err),
        }
        wire_offset = record_end;
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    mod encoding {
        use byteorder::{BigEndian, ByteOrder};

        pub(super) fn make_test_client_hello(host: &str, padding_len: usize) -> Vec<u8> {
            let mut extensions = Vec::new();
            if !host.is_empty() {
                let server_name = host.as_bytes();
                let server_name_list_len = 1 + 2 + server_name.len();
                let extension_data_len = 2 + server_name_list_len;
                extensions = vec![0u8; 4 + extension_data_len];
                BigEndian::write_u16(&mut extensions[2..4], extension_data_len as u16);
                BigEndian::write_u16(&mut extensions[4..6], server_name_list_len as u16);
                BigEndian::write_u16(&mut extensions[7..9], server_name.len() as u16);
                extensions[9..].copy_from_slice(server_name);
            }
            if padding_len > 0 {
                let mut padding = vec![0u8; 4 + padding_len];
                BigEndian::write_u16(&mut padding[0..2], 0x15);
                BigEndian::write_u16(&mut padding[2..4], padding_len as u16);
                extensions.extend_from_slice(&padding);
            }

            let mut body = Vec::with_capacity(64 + host.len());
            body.extend_from_slice(&[0x03, 0x03]);
            body.extend_from_slice(&[0u8; 32]);
            body.push(0);
            body.extend_from_slice(&[0, 2, 0x13, 0x01]);
            body.extend_from_slice(&[1, 0]);
            let mut ext_len = [0u8; 2];
            BigEndian::write_u16(&mut ext_len, extensions.len() as u16);
            body.extend_from_slice(&ext_len);
            body.extend_from_slice(&extensions);

            let mut hello = vec![
                super::TLS_HANDSHAKE_TYPE_CLIENT_HELLO,
                (body.len() >> 16) as u8,
                (body.len() >> 8) as u8,
                body.len() as u8,
            ];
            hello.extend_from_slice(&body);
            hello
        }

        pub(super) struct TlsRecordBuilder;

        impl TlsRecordBuilder {
            pub(super) fn make_test_tls_records(handshake: &[u8], cuts: &[usize]) -> Vec<u8> {
                let mut records =
                    Vec::with_capacity(handshake.len() + super::super::TLS_RECORD_HEADER_LEN * (cuts.len() + 1));
                let mut start = 0usize;
                let mut boundaries = cuts.to_vec();
                boundaries.push(handshake.len());
                for end in boundaries {
                    let payload = &handshake[start..end];
                    let mut header = [super::super::TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x01, 0, 0];
                    BigEndian::write_u16(&mut header[3..], payload.len() as u16);
                    records.extend_from_slice(&header);
                    records.extend_from_slice(payload);
                    start = end;
                }
                records
            }
        }
    }

    fn make_test_client_hello(host: &str, padding_len: usize) -> Vec<u8> {
        encoding::make_test_client_hello(host, padding_len)
    }

    fn make_test_tls_records(handshake: &[u8], cuts: &[usize]) -> Vec<u8> {
        encoding::TlsRecordBuilder::make_test_tls_records(handshake, cuts)
    }

    #[test]
    fn microsoft_client_hello() {
        #[rustfmt::skip]
        let input: Vec<u8> = vec![
            0x16, 0x03, 0x01, 0x00, 0xc8, 0x01, 0x00, 0x00,
            0xc4, 0x03, 0x03, 0x1a, 0xac, 0xb2, 0xa8, 0xfe,
            0xb4, 0x96, 0x04, 0x5b, 0xca, 0xf7, 0xc1, 0xf4,
            0x2e, 0x53, 0x24, 0x6e, 0x34, 0x0c, 0x58, 0x36,
            0x71, 0x97, 0x59, 0xe9, 0x41, 0x66, 0xe2, 0x43,
            0xa0, 0x13, 0xb6, 0x00, 0x00, 0x20, 0x1a, 0x1a,
            0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
            0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13,
            0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d,
            0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00,
            0x00, 0x7b, 0xba, 0xba, 0x00, 0x00, 0xff, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00,
            0x14, 0x00, 0x00, 0x11, 0x63, 0x2e, 0x73, 0x2d,
            0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66,
            0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x17, 0x00,
            0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00,
            0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04,
            0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08,
            0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x05, 0x00,
            0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c,
            0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70,
            0x2f, 0x31, 0x2e, 0x31, 0x00, 0x0b, 0x00, 0x02,
            0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08,
            0xaa, 0xaa, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
            0xaa, 0xaa, 0x00, 0x01, 0x00,
        ];
        let domain = sniff_tls(&input).expect("client hello parses");
        assert_eq!(domain, "c.s-microsoft.com");
    }

    #[test]
    fn short_server_name() {
        #[rustfmt::skip]
        let input: Vec<u8> = vec![
            0x16, 0x03, 0x01, 0x00, 0xe6, 0x01, 0x00, 0x00,
            0xe2, 0x03, 0x03, 0x81, 0x47, 0xc1, 0x66, 0xd5,
            0x1b, 0xfa, 0x4b, 0xb5, 0xe0, 0x2a, 0xe1, 0xa7,
            0x87, 0x13, 0x1d, 0x11, 0xaa, 0xc6, 0xce, 0xfc,
            0x7f, 0xab, 0x94, 0xc8, 0x62, 0xad, 0xc8, 0xab,
            0x0c, 0xdd, 0xcb, 0x20, 0x6f, 0x9d, 0x07, 0xf1,
            0x95, 0x3e, 0x99, 0xd8, 0xf3, 0x6d, 0x97, 0xee,
            0x19, 0x0b, 0x06, 0x1b, 0xf4, 0x84, 0x0b, 0xb6,
            0x8f, 0xcc, 0xde, 0xe2, 0xd0, 0x2d, 0x6b, 0x0c,
            0x1f, 0x52, 0x53, 0x13, 0x00, 0x08, 0x13, 0x02,
            0x13, 0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00,
            0x00, 0x91, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a,
            0x00, 0x00, 0x07, 0x64, 0x6f, 0x67, 0x66, 0x69,
            0x73, 0x68, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00,
            0x01, 0x02, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a,
            0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19,
            0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16,
            0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d,
            0x00, 0x1e, 0x00, 0x1c, 0x04, 0x03, 0x05, 0x03,
            0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09,
            0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05,
            0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
            0x00, 0x2b, 0x00, 0x07, 0x06, 0x7f, 0x1c, 0x7f,
            0x1b, 0x7f, 0x1a, 0x00, 0x2d, 0x00, 0x02, 0x01,
            0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00,
            0x1d, 0x00, 0x20, 0x2f, 0x35, 0x0c, 0xb6, 0x90,
            0x0a, 0xb7, 0xd5, 0xc4, 0x1b, 0x2f, 0x60, 0xaa,
            0x56, 0x7b, 0x3f, 0x71, 0xc8, 0x01, 0x7e, 0x86,
            0xd3, 0xb7, 0x0c, 0x29, 0x1a, 0x9e, 0x5b, 0x38,
            0x3f, 0x01, 0x72,
        ];
        let domain = sniff_tls(&input).expect("client hello parses");
        assert_eq!(domain, "dogfish");
    }

    #[test]
    fn ip_server_name() {
        #[rustfmt::skip]
        let input: Vec<u8> = vec![
            0x16, 0x03, 0x01, 0x01, 0x03, 0x01, 0x00, 0x00,
            0xff, 0x03, 0x03, 0x3d, 0x89, 0x52, 0x9e, 0xee,
            0xbe, 0x17, 0x63, 0x75, 0xef, 0x29, 0xbd, 0x14,
            0x6a, 0x49, 0xe0, 0x2c, 0x37, 0x57, 0x71, 0x62,
            0x82, 0x44, 0x94, 0x8f, 0x6e, 0x94, 0x08, 0x45,
            0x7f, 0xdb, 0xc1, 0x00, 0x00, 0x3e, 0xc0, 0x2c,
            0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8,
            0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
            0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23,
            0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14,
            0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33,
            0x00, 0x9d, 0x00, 0x9c, 0x13, 0x02, 0x13, 0x03,
            0x13, 0x01, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35,
            0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x00, 0x98,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00,
            0x0b, 0x31, 0x30, 0x2e, 0x34, 0x32, 0x2e, 0x30,
            0x2e, 0x32, 0x34, 0x33, 0x00, 0x0b, 0x00, 0x04,
            0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x0a,
            0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19,
            0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d,
            0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03,
            0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
            0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03,
            0x02, 0x01, 0x02, 0x02, 0x04, 0x02, 0x05, 0x02,
            0x06, 0x02, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17,
            0x00, 0x00, 0x00, 0x2b, 0x00, 0x09, 0x08, 0x7f,
            0x14, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00,
            0x2d, 0x00, 0x03, 0x02, 0x01, 0x00, 0x00, 0x28,
            0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
            0x13, 0x7c, 0x6e, 0x97, 0xc4, 0xfd, 0x09, 0x2e,
            0x70, 0x2f, 0x73, 0x5a, 0x9b, 0x57, 0x4d, 0x5f,
            0x2b, 0x73, 0x2c, 0xa5, 0x4a, 0x98, 0x40, 0x3d,
            0x75, 0x6e, 0xb4, 0x76, 0xf9, 0x48, 0x8f, 0x36,
        ];
        let domain = sniff_tls(&input).expect("client hello parses");
        assert_eq!(domain, "10.42.0.243");
    }

    #[test]
    fn clicktale_client_hello() {
        #[rustfmt::skip]
        let input: Vec<u8> = vec![
            0x16, 0x03, 0x01, 0x00, 0xee, 0x01, 0x00, 0x00, 0xea, 0x03, 0x03, 0xe7, 0x91, 0x9e, 0x93, 0xca,
            0x78, 0x1b, 0x3c, 0xe0, 0x65, 0x25, 0x58, 0xb5, 0x93, 0xe1, 0x0f, 0x85, 0xec, 0x9a, 0x66, 0x8e,
            0x61, 0x82, 0x88, 0xc8, 0xfc, 0xae, 0x1e, 0xca, 0xd7, 0xa5, 0x63, 0x20, 0xbd, 0x1c, 0x00, 0x00,
            0x8b, 0xee, 0x09, 0xe3, 0x47, 0x6a, 0x0e, 0x74, 0xb0, 0xbc, 0xa3, 0x02, 0xa7, 0x35, 0xe8, 0x85,
            0x70, 0x7c, 0x7a, 0xf0, 0x00, 0xdf, 0x4a, 0xea, 0x87, 0x01, 0x14, 0x91, 0x00, 0x20, 0xea, 0xea,
            0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13,
            0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00,
            0x00, 0x81, 0x9a, 0x9a, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00,
            0x16, 0x00, 0x00, 0x13, 0x77, 0x77, 0x77, 0x30, 0x37, 0x2e, 0x63, 0x6c, 0x69, 0x63, 0x6b, 0x74,
            0x61, 0x6c, 0x65, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
            0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05,
            0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x12, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74,
            0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x75, 0x50, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
            0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x9a, 0x9a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x8a, 0x8a,
            0x00, 0x01, 0x00,
        ];
        let domain = sniff_tls(&input).expect("client hello parses");
        assert_eq!(domain, "www07.clicktale.net");
    }

    #[test]
    fn client_hello_across_records() {
        let generated_hello = make_test_client_hello("example.com", 0);
        let cuts = [1, 2, 3, generated_hello.len() / 2, generated_hello.len() - 3];
        let input = make_test_tls_records(&generated_hello, &cuts);
        let domain = sniff_tls(&input).expect("client hello parses");
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn client_hello_followed_by_handshake_data() {
        let generated_hello = make_test_client_hello("example.com", 0);
        let mut with_trailing = generated_hello;
        with_trailing.extend_from_slice(&[0x02, 0, 0, 0]);
        let input = make_test_tls_records(&with_trailing, &[2]);
        let domain = sniff_tls(&input).expect("client hello parses");
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn server_name_before_client_hello_padding() {
        const PADDING_LEN: usize = 4 * 1024;
        let padded_hello = make_test_client_hello("example.com", PADDING_LEN);
        let padded_prefix_len = padded_hello.len() - (4 + PADDING_LEN);
        let mut padded_record = make_test_tls_records(&padded_hello, &[]);
        padded_record.truncate(TLS_RECORD_HEADER_LEN + padded_prefix_len);
        let domain = sniff_tls(&padded_record).expect("client hello parses");
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn server_name_across_records_before_padding() {
        const PADDING_LEN: usize = 4 * 1024;
        let padded_hello = make_test_client_hello("example.com", PADDING_LEN);
        let padded_prefix_len = padded_hello.len() - (4 + PADDING_LEN);
        let mut fragmented = make_test_tls_records(&padded_hello, &[2]);
        fragmented.truncate(2 * TLS_RECORD_HEADER_LEN + padded_prefix_len);
        let domain = sniff_tls(&fragmented).expect("client hello parses");
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn client_hello_before_incomplete_record_tail() {
        let generated_hello = make_test_client_hello("example.com", 0);
        let mut with_trailing = generated_hello.clone();
        with_trailing.extend_from_slice(&[0x02, 0, 0, 0]);
        let mut incomplete = make_test_tls_records(&with_trailing, &[]);
        incomplete.truncate(TLS_RECORD_HEADER_LEN + generated_hello.len());
        let domain = sniff_tls(&incomplete).expect("client hello parses");
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn fragmented_need_at_least_data() {
        let generated_hello = make_test_client_hello("example.com", 0);
        let fragmented = make_test_tls_records(&generated_hello, &[2, generated_hello.len() / 2]);
        let cases: &[(&str, usize, usize)] = &[
            ("empty input", 0, TLS_RECORD_HEADER_LEN),
            ("one byte record header", 1, TLS_RECORD_HEADER_LEN),
            ("two byte record header", 2, TLS_RECORD_HEADER_LEN),
            ("three byte record header", 3, TLS_RECORD_HEADER_LEN),
            ("four byte record header", 4, TLS_RECORD_HEADER_LEN),
            ("record payload missing", TLS_RECORD_HEADER_LEN, TLS_RECORD_HEADER_LEN + 1),
            ("handshake type only", TLS_RECORD_HEADER_LEN + 1, TLS_RECORD_HEADER_LEN + 2),
            ("next record header missing", TLS_RECORD_HEADER_LEN + 2, 2 * TLS_RECORD_HEADER_LEN + 2),
            ("final record payload incomplete", fragmented.len() - 1, fragmented.len()),
        ];
        for (name, have, need) in cases {
            let err = sniff_tls(&fragmented[..*have]).expect_err(name);
            let need_err = err
                .downcast_ref::<ErrNeedAtLeastData>()
                .unwrap_or_else(|| panic!("{name}: expected ErrNeedAtLeastData"));
            assert_eq!(need_err.length, *need, "{name}");
        }
    }

    #[test]
    fn rejects_oversized_record_before_its_payload() {
        let input = [TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x01, 0x40, 0x01];
        let err = sniff_tls(&input).unwrap_err();
        assert!(err.is::<ErrNotTLS>());
        assert!(err.downcast_ref::<ErrNeedAtLeastData>().is_none());
    }

    #[test]
    fn rejects_another_handshake_type_before_record_completion() {
        let input = [TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x01, 0x40, 0x00, 0x02];
        let err = sniff_tls(&input).unwrap_err();
        assert!(err.is::<ErrNotClientHello>());
        assert!(err.downcast_ref::<ErrNeedAtLeastData>().is_none());
    }

    #[test]
    fn rejects_invalid_client_hello_prefix_before_record_completion() {
        let mut client_hello = vec![0u8; 39];
        client_hello[0] = TLS_HANDSHAKE_TYPE_CLIENT_HELLO;
        client_hello[2] = 0x03;
        client_hello[3] = 0xe8;
        client_hello[38] = 33;
        let mut input = vec![TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x01, 0x03, 0xec];
        input.extend_from_slice(&client_hello);

        let err = sniff_tls(&input).unwrap_err();
        assert!(err.is::<ErrNotClientHello>());
        assert!(err.downcast_ref::<ErrNeedAtLeastData>().is_none());
    }

    #[test]
    fn rejects_absent_server_name_before_final_extension_payload() {
        const PADDING_LEN: usize = 4 * 1024;
        let client_hello = make_test_client_hello("", PADDING_LEN);
        let mut input = make_test_tls_records(&client_hello, &[]);
        input.truncate(TLS_RECORD_HEADER_LEN + client_hello.len() - PADDING_LEN);

        let err = sniff_tls(&input).unwrap_err();
        assert!(err.is::<ErrNotTLS>());
        assert!(err.downcast_ref::<ErrNeedAtLeastData>().is_none());
    }
}
