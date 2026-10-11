use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::COMMAND_EXTENSION;

/// Private extension opcode for the brutal negotiation: a fixed 6-byte magic
/// prefix followed by extension id 1. The magic is kept verbatim as the wire
/// value a peer expects.
pub(crate) const EXTENSION_OPCODE_BRUTAL: u64 = 0x6d69_686f_6d6f_0001;

pub(crate) const BRUTAL_NEGOTIATION_VERSION: u8 = 1;
/// The header length: version, flags and payload length.
pub(crate) const BRUTAL_NEGOTIATION_HEADER_LEN: usize = 1 + 1 + 2;
/// The minimum payload length of an rx negotiation frame.
pub(crate) const BRUTAL_NEGOTIATION_MIN_PAYLOAD_LEN: usize = 8;
pub(crate) const BRUTAL_NEGOTIATION_MAX_PAYLOAD_LEN: usize = 64;

pub(crate) const BRUTAL_NEGOTIATION_FLAG_RX_AUTO: u8 = 1 << 0;
pub(crate) const BRUTAL_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("shadowquic: invalid brutal negotiation")]
pub struct ErrInvalidBrutalNegotiation;

#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("shadowquic: unsupported brutal negotiation version")]
pub struct ErrUnsupportedBrutalVersion;

///
/// Writes a murmur-only private extension request. JLS already authenticates users; `rx` follows
/// Hysteria2 semantics: the desired receive bandwidth in bytes per second, with 0 meaning
/// unknown/auto.
///
/// The extension body uses a tiny versioned frame:
///
/// `version(1) | flags(1) | payload length(2) | payload`
///
/// Version 1 defines the first 8 payload bytes as rx. Readers deliberately ignore unknown flags
/// and payload bytes after rx so future optional fields can be appended without changing the
/// extension opcode.
pub async fn write_brutal_negotiation_request<W>(w: &mut W, rx: u64) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = [0u8; 1 + 8 + BRUTAL_NEGOTIATION_HEADER_LEN + BRUTAL_NEGOTIATION_MIN_PAYLOAD_LEN];
    buf[0] = COMMAND_EXTENSION;
    buf[1..9].copy_from_slice(&EXTENSION_OPCODE_BRUTAL.to_be_bytes());
    write_brutal_negotiation_frame(&mut buf[9..], 0, rx);
    w.write_all(&buf).await
}

pub async fn read_brutal_negotiation_request<R>(r: &mut R) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let (rx, _flags) = read_brutal_negotiation_frame(r).await?;
    Ok(rx)
}

pub async fn write_brutal_negotiation_response<W>(w: &mut W, rx: u64, rx_auto: bool) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = [0u8; BRUTAL_NEGOTIATION_HEADER_LEN + BRUTAL_NEGOTIATION_MIN_PAYLOAD_LEN];
    let mut flags = 0u8;
    if rx_auto {
        flags |= BRUTAL_NEGOTIATION_FLAG_RX_AUTO;
    }
    write_brutal_negotiation_frame(&mut buf, flags, rx);
    w.write_all(&buf).await
}

pub async fn read_brutal_negotiation_response<R>(r: &mut R) -> anyhow::Result<(u64, bool)>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let (rx, flags) = read_brutal_negotiation_frame(r).await?;
    Ok((rx, flags & BRUTAL_NEGOTIATION_FLAG_RX_AUTO != 0))
}

fn write_brutal_negotiation_frame(buf: &mut [u8], flags: u8, rx: u64) {
    let mut frame = [0u8; BRUTAL_NEGOTIATION_HEADER_LEN + BRUTAL_NEGOTIATION_MIN_PAYLOAD_LEN];
    frame[0] = BRUTAL_NEGOTIATION_VERSION;
    frame[1] = flags;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the frame's payload length field is 16 bits on the wire and the constant is BRUTAL_NEGOTIATION_MIN_PAYLOAD_LEN"
    )]
    let payload_len = BRUTAL_NEGOTIATION_MIN_PAYLOAD_LEN as u16;
    frame[2..4].copy_from_slice(&payload_len.to_be_bytes());
    frame[4..12].copy_from_slice(&rx.to_be_bytes());
    buf.copy_from_slice(&frame);
}

async fn read_brutal_negotiation_frame<R>(r: &mut R) -> anyhow::Result<(u64, u8)>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0u8; BRUTAL_NEGOTIATION_HEADER_LEN];
    r.read_exact(&mut header).await?;
    if header[0] != BRUTAL_NEGOTIATION_VERSION {
        return Err(ErrUnsupportedBrutalVersion.into());
    }
    let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if !(BRUTAL_NEGOTIATION_MIN_PAYLOAD_LEN..=BRUTAL_NEGOTIATION_MAX_PAYLOAD_LEN).contains(&payload_len) {
        return Err(ErrInvalidBrutalNegotiation.into());
    }
    let mut payload = vec![0u8; payload_len];
    r.read_exact(&mut payload).await?;
    let Some(rx_bytes) = payload.get(..8) else {
        return Err(ErrInvalidBrutalNegotiation.into());
    };
    let rx = u64::from_be_bytes(rx_bytes.try_into().map_err(|_| ErrInvalidBrutalNegotiation)?);
    Ok((rx, header[1]))
}
