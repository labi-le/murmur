use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const TLS_RANDOM_SIZE: usize = 32;
pub(crate) const TLS_HEADER_SIZE: usize = 5;
pub(crate) const TLS_SESSION_ID_SIZE: usize = 32;

pub(crate) const CLIENT_HELLO: u8 = 1;
pub(crate) const SERVER_HELLO: u8 = 2;

pub(crate) const CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const ALERT: u8 = 21;
pub(crate) const HANDSHAKE: u8 = 22;
pub(crate) const APPLICATION_DATA: u8 = 23;

pub(crate) const SERVER_RANDOM_INDEX: usize = TLS_HEADER_SIZE + 1 + 3 + 2;
pub(crate) const SESSION_ID_LENGTH_INDEX: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
pub(crate) const HMAC_SIZE: usize = 4;
pub(crate) const TLS_HMAC_HEADER_SIZE: usize = TLS_HEADER_SIZE + HMAC_SIZE;

pub(crate) const MAX_TLS_PLAINTEXT: usize = 16384;

pub(crate) async fn read_frame<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; TLS_HEADER_SIZE];
    reader.read_exact(&mut header).await?;
    let length = usize::from(BigEndian::read_u16(&header[3..]));
    let mut frame = vec![0u8; TLS_HEADER_SIZE + length];
    let (frame_header, frame_body) = frame.split_at_mut(TLS_HEADER_SIZE);
    frame_header.copy_from_slice(&header);
    reader.read_exact(frame_body).await?;
    Ok(frame)
}

pub(crate) async fn copy_until_handshake_finished<W, R>(dst: &mut W, src: &mut R) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
    R: AsyncRead + Unpin + ?Sized,
{
    let mut seen_change_cipher_spec = false;
    loop {
        let frame = read_frame(src).await?;
        dst.write_all(&frame).await?;
        let Some((&record_type, _)) = frame.split_first() else {
            return Err(io::Error::other("shadow-tls: empty TLS record"));
        };
        if record_type != HANDSHAKE {
            if record_type != CHANGE_CIPHER_SPEC {
                return Err(io::Error::other(format!("shadow-tls: unexpected TLS record type: {record_type}")));
            }
            if !seen_change_cipher_spec {
                seen_change_cipher_spec = true;
                continue;
            }
        }
        if seen_change_cipher_spec {
            return Ok(());
        }
    }
}

pub(crate) fn extract_server_name(frame: &[u8]) -> Result<String> {
    if frame.len() < TLS_HEADER_SIZE + 4
        || frame.first() != Some(&HANDSHAKE)
        || frame.get(TLS_HEADER_SIZE) != Some(&CLIENT_HELLO)
    {
        return Err(anyhow!("shadow-tls: invalid ClientHello"));
    }
    let Some(&[length_hi, length_mid, length_lo]) = frame.get(TLS_HEADER_SIZE + 1..TLS_HEADER_SIZE + 4) else {
        return Err(anyhow!("shadow-tls: invalid ClientHello"));
    };
    let hello_length = (usize::from(length_hi) << 16) | (usize::from(length_mid) << 8) | usize::from(length_lo);
    let hello_rest = frame.get(TLS_HEADER_SIZE + 4..).unwrap_or_default();
    if hello_length > hello_rest.len() {
        return Err(anyhow!("unexpected EOF"));
    }
    let (hello, _) = hello_rest.split_at(hello_length);
    if hello.len() < 2 + TLS_RANDOM_SIZE + 1 {
        return Err(anyhow!("unexpected EOF"));
    }
    let mut offset = 2 + TLS_RANDOM_SIZE;
    let Some(&session_id_length) = hello.get(offset) else {
        return Err(anyhow!("unexpected EOF"));
    };
    let session_id_length = usize::from(session_id_length);
    offset += 1;
    if offset + session_id_length + 2 > hello.len() {
        return Err(anyhow!("unexpected EOF"));
    }
    offset += session_id_length;
    let Some(length_bytes) = hello.get(offset..offset + 2) else {
        return Err(anyhow!("unexpected EOF"));
    };
    let cipher_suites_length = usize::from(BigEndian::read_u16(length_bytes));
    offset += 2;
    if offset + cipher_suites_length + 1 > hello.len() {
        return Err(anyhow!("unexpected EOF"));
    }
    offset += cipher_suites_length;
    let Some(&compression_methods_length) = hello.get(offset) else {
        return Err(anyhow!("unexpected EOF"));
    };
    let compression_methods_length = usize::from(compression_methods_length);
    offset += 1;
    if offset + compression_methods_length == hello.len() {
        return Err(anyhow!("shadow-tls: ClientHello has no SNI"));
    }
    if offset + compression_methods_length + 2 > hello.len() {
        return Err(anyhow!("unexpected EOF"));
    }
    offset += compression_methods_length;
    let Some(length_bytes) = hello.get(offset..offset + 2) else {
        return Err(anyhow!("unexpected EOF"));
    };
    let extensions_length = usize::from(BigEndian::read_u16(length_bytes));
    offset += 2;
    if offset + extensions_length > hello.len() {
        return Err(anyhow!("unexpected EOF"));
    }
    let Some(mut extensions) = hello.get(offset..offset + extensions_length) else {
        return Err(anyhow!("unexpected EOF"));
    };
    while extensions.len() >= 4 {
        let extension_type = BigEndian::read_u16(extensions);
        let Some(length_bytes) = extensions.get(2..4) else {
            return Err(anyhow!("unexpected EOF"));
        };
        let ext_len = usize::from(BigEndian::read_u16(length_bytes));
        extensions = extensions.get(4..).unwrap_or_default();
        if ext_len > extensions.len() {
            return Err(anyhow!("unexpected EOF"));
        }
        if extension_type == 0 {
            let Some(extension) = extensions.get(..ext_len) else {
                return Err(anyhow!("unexpected EOF"));
            };
            return parse_server_name_extension(extension);
        }
        extensions = extensions.get(ext_len..).unwrap_or_default();
    }
    Err(anyhow!("shadow-tls: ClientHello has no SNI"))
}

pub(crate) fn extract_server_random(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE
        || frame.first() != Some(&HANDSHAKE)
        || frame.get(TLS_HEADER_SIZE) != Some(&SERVER_HELLO)
    {
        return None;
    }
    Some(frame.get(SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE)?.to_vec())
}

pub(crate) fn is_server_hello_support_tls13(frame: &[u8]) -> bool {
    if frame.len() <= SESSION_ID_LENGTH_INDEX
        || frame.first() != Some(&HANDSHAKE)
        || frame.get(TLS_HEADER_SIZE) != Some(&SERVER_HELLO)
    {
        return false;
    }
    let mut offset = SESSION_ID_LENGTH_INDEX;
    let Some(&session_id_length) = frame.get(offset) else {
        return false;
    };
    let session_id_length = usize::from(session_id_length);
    offset += 1;
    if offset + session_id_length + 3 + 2 > frame.len() {
        return false;
    }
    offset += session_id_length + 3;
    let Some(length_bytes) = frame.get(offset..offset + 2) else {
        return false;
    };
    let extensions_length = usize::from(BigEndian::read_u16(length_bytes));
    offset += 2;
    if offset + extensions_length > frame.len() {
        return false;
    }
    let Some(mut extensions) = frame.get(offset..offset + extensions_length) else {
        return false;
    };
    while extensions.len() >= 4 {
        let extension_type = BigEndian::read_u16(extensions);
        let Some(length_bytes) = extensions.get(2..4) else {
            return false;
        };
        let ext_len = usize::from(BigEndian::read_u16(length_bytes));
        extensions = extensions.get(4..).unwrap_or_default();
        if ext_len > extensions.len() {
            return false;
        }
        if extension_type == 43 {
            return ext_len == 2 && extensions.get(..2).is_some_and(|v| BigEndian::read_u16(v) == 0x0304);
        }
        extensions = extensions.get(ext_len..).unwrap_or_default();
    }
    false
}

pub(crate) fn parse_server_name_extension(extension: &[u8]) -> Result<String> {
    if extension.len() < 2 {
        return Err(anyhow!("unexpected EOF"));
    }
    let list_length = usize::from(BigEndian::read_u16(extension));
    if list_length > extension.len() - 2 {
        return Err(anyhow!("unexpected EOF"));
    }
    let Some(mut list) = extension.get(2..2 + list_length) else {
        return Err(anyhow!("unexpected EOF"));
    };
    while list.len() >= 3 {
        let Some(&[name_type, length_hi, length_lo]) = list.first_chunk::<3>() else {
            break;
        };
        let name_length = usize::from(BigEndian::read_u16(&[length_hi, length_lo]));
        list = list.get(3..).unwrap_or_default();
        if name_length > list.len() {
            return Err(anyhow!("unexpected EOF"));
        }
        if name_type == 0 && name_length > 0 {
            let Some(name_bytes) = list.get(..name_length) else {
                return Err(anyhow!("unexpected EOF"));
            };
            return Ok(String::from_utf8_lossy(name_bytes).into_owned());
        }
        list = list.get(name_length..).unwrap_or_default();
    }
    Err(anyhow!("shadow-tls: ClientHello has no host name"))
}
