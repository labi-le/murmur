use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const PROTOCOL_VERSION: u8 = 3;
pub(crate) const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) const CLOSE_ERROR_CODE_GENERIC: u64 = 0;
pub(crate) const CLOSE_ERROR_CODE_PROTOCOL: u64 = 1;
pub(crate) const CLOSE_ERROR_CODE_AUTH: u64 = 2;

/// Reads `N` bytes at `*pos` and advances past them.
fn take<const N: usize>(data: &[u8], pos: &mut usize) -> anyhow::Result<[u8; N]> {
    let end = *pos + N;
    let bytes: [u8; N] =
        data.get(*pos..end).and_then(|bytes| bytes.try_into().ok()).ok_or_else(|| anyhow!("unexpected EOF"))?;
    *pos = end;
    Ok(bytes)
}

fn take_u8(data: &[u8], pos: &mut usize) -> anyhow::Result<u8> {
    let [value] = take::<1>(data, pos)?;
    Ok(value)
}

fn take_u16(data: &[u8], pos: &mut usize) -> anyhow::Result<u16> {
    Ok(u16::from_be_bytes(take::<2>(data, pos)?))
}

fn take_u32(data: &[u8], pos: &mut usize) -> anyhow::Result<u32> {
    Ok(u32::from_be_bytes(take::<4>(data, pos)?))
}

/// The length prefix of every message here is a 16-bit wire field.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the length prefixes are 16-bit protocol fields; the encoder truncates to that width"
)]
const fn wire_len(len: usize) -> u16 {
    len as u16
}

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub send_bps: u64,
    pub recv_bps: u64,
    pub auth: Vec<u8>,
}

pub async fn write_client_hello<W: AsyncWrite + Unpin>(stream: &mut W, hello: &ClientHello) -> anyhow::Result<()> {
    let mut request = Vec::with_capacity(1 + 8 + 8 + 2 + hello.auth.len());
    request.push(PROTOCOL_VERSION);
    request.extend_from_slice(&hello.send_bps.to_be_bytes());
    request.extend_from_slice(&hello.recv_bps.to_be_bytes());
    request.extend_from_slice(&wire_len(hello.auth.len()).to_be_bytes());
    request.extend_from_slice(&hello.auth);
    stream.write_all(&request).await?;
    Ok(())
}

pub async fn read_client_hello<R: AsyncRead + Unpin>(stream: &mut R) -> anyhow::Result<ClientHello> {
    let mut response = [0u8; 1 + 8 + 8 + 2];
    stream.read_exact(&mut response).await?;

    if response.first() != Some(&PROTOCOL_VERSION) {
        return Err(anyhow!("unsupported client version"));
    }
    let mut pos = 1;
    let send_bps = u64::from_be_bytes(take::<8>(&response, &mut pos)?);
    let recv_bps = u64::from_be_bytes(take::<8>(&response, &mut pos)?);
    let auth_len = take_u16(&response, &mut pos)?;

    if send_bps == 0 || recv_bps == 0 {
        return Err(anyhow!("invalid rate from client"));
    }

    let mut auth = vec![0u8; auth_len as usize];
    stream.read_exact(&mut auth).await?;
    Ok(ClientHello { send_bps, recv_bps, auth })
}

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub ok: bool,
    pub send_bps: u64,
    pub recv_bps: u64,
    pub message: String,
}

pub(crate) async fn read_server_hello<R: AsyncRead + Unpin>(stream: &mut R) -> anyhow::Result<ServerHello> {
    let mut response = [0u8; 1 + 8 + 8 + 2];
    stream.read_exact(&mut response).await?;

    let ok = response.first() == Some(&1);
    let mut pos = 1;
    let send_bps = u64::from_be_bytes(take::<8>(&response, &mut pos)?);
    let recv_bps = u64::from_be_bytes(take::<8>(&response, &mut pos)?);
    let message_len = take_u16(&response, &mut pos)?;
    if message_len == 0 {
        return Ok(ServerHello { ok, send_bps, recv_bps, message: String::new() });
    }

    let mut message = vec![0u8; message_len as usize];
    stream.read_exact(&mut message).await?;
    let message = String::from_utf8(message).map_err(|_| anyhow!("invalid message encoding"))?;
    Ok(ServerHello { ok, send_bps, recv_bps, message })
}

pub async fn write_server_hello<W: AsyncWrite + Unpin>(stream: &mut W, hello: &ServerHello) -> anyhow::Result<()> {
    let mut response = Vec::with_capacity(1 + 8 + 8 + 2 + hello.message.len());
    response.push(u8::from(hello.ok));
    response.extend_from_slice(&hello.send_bps.to_be_bytes());
    response.extend_from_slice(&hello.recv_bps.to_be_bytes());
    response.extend_from_slice(&wire_len(hello.message.len()).to_be_bytes());
    response.extend_from_slice(hello.message.as_bytes());
    stream.write_all(&response).await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ClientRequest {
    pub udp: bool,
    pub host: String,
    pub port: u16,
}

pub async fn read_client_request<R: AsyncRead + Unpin>(stream: &mut R) -> anyhow::Result<ClientRequest> {
    let udp = stream.read_u8().await? != 0;
    let host_len = stream.read_u16().await?;
    let mut host = vec![0u8; host_len as usize];
    stream.read_exact(&mut host).await?;
    let host = String::from_utf8(host).map_err(|_| anyhow!("invalid host encoding"))?;
    let port = stream.read_u16().await?;
    Ok(ClientRequest { udp, host, port })
}

pub(crate) async fn write_client_request<W: AsyncWrite + Unpin>(
    stream: &mut W,
    request: &ClientRequest,
) -> anyhow::Result<()> {
    let mut buffer = Vec::with_capacity(1 + 2 + request.host.len() + 2);
    buffer.push(u8::from(request.udp));
    buffer.extend_from_slice(&wire_len(request.host.len()).to_be_bytes());
    buffer.extend_from_slice(request.host.as_bytes());
    buffer.extend_from_slice(&request.port.to_be_bytes());
    stream.write_all(&buffer).await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ServerResponse {
    pub ok: bool,
    pub udp_session_id: u32,
    pub message: String,
}

pub(crate) async fn read_server_response<R: AsyncRead + Unpin>(stream: &mut R) -> anyhow::Result<ServerResponse> {
    let mut response = [0u8; 1 + 4 + 2];
    stream.read_exact(&mut response).await?;

    let ok = response.first() == Some(&1);
    let mut pos = 1;
    let udp_session_id = take_u32(&response, &mut pos)?;
    let message_len = take_u16(&response, &mut pos)?;
    if message_len == 0 {
        return Ok(ServerResponse { ok, udp_session_id, message: String::new() });
    }

    let mut message = vec![0u8; message_len as usize];
    stream.read_exact(&mut message).await?;
    let message = String::from_utf8(message).map_err(|_| anyhow!("invalid message encoding"))?;
    Ok(ServerResponse { ok, udp_session_id, message })
}

pub async fn write_server_response<W: AsyncWrite + Unpin>(
    stream: &mut W,
    response: &ServerResponse,
) -> anyhow::Result<()> {
    let mut buffer = Vec::with_capacity(1 + 4 + 2 + response.message.len());
    buffer.push(u8::from(response.ok));
    buffer.extend_from_slice(&response.udp_session_id.to_be_bytes());
    buffer.extend_from_slice(&wire_len(response.message.len()).to_be_bytes());
    buffer.extend_from_slice(response.message.as_bytes());
    stream.write_all(&buffer).await?;
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UdpMessage {
    pub(crate) session_id: u32,
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Doesn't matter when not fragmented, but must not be 0 when fragmented.
    pub(crate) msg_id: u16,
    /// Doesn't matter when not fragmented, starts at 0 when fragmented.
    pub(crate) frag_id: u8,
    /// Must be 1 when not fragmented.
    pub(crate) frag_count: u8,
    pub(crate) data: Vec<u8>,
}

impl UdpMessage {
    pub(crate) const fn header_size(&self) -> usize {
        4 + 2 + self.host.len() + 2 + 2 + 1 + 1 + 2
    }

    pub(crate) fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    pub(crate) fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.size());
        buffer.extend_from_slice(&self.session_id.to_be_bytes());
        buffer.extend_from_slice(&wire_len(self.host.len()).to_be_bytes());
        buffer.extend_from_slice(self.host.as_bytes());
        buffer.extend_from_slice(&self.port.to_be_bytes());
        buffer.extend_from_slice(&self.msg_id.to_be_bytes());
        buffer.push(self.frag_id);
        buffer.push(self.frag_count);
        buffer.extend_from_slice(&wire_len(self.data.len()).to_be_bytes());
        buffer.extend_from_slice(&self.data);
        buffer
    }

    pub(crate) fn unpack(data: &[u8]) -> anyhow::Result<Self> {
        let mut pos = 0usize;
        let session_id = take_u32(data, &mut pos)?;

        let host_len = usize::from(take_u16(data, &mut pos)?);
        let host_end = pos + host_len;
        let host = String::from_utf8(data.get(pos..host_end).ok_or_else(|| anyhow!("unexpected EOF"))?.to_vec())
            .map_err(|_| anyhow!("invalid host encoding"))?;
        pos = host_end;

        let port = take_u16(data, &mut pos)?;
        let msg_id = take_u16(data, &mut pos)?;
        let frag_id = take_u8(data, &mut pos)?;
        let frag_count = take_u8(data, &mut pos)?;
        let data_len = usize::from(take_u16(data, &mut pos)?);

        if data.len() - pos != data_len {
            return Err(anyhow!("invalid data length"));
        }
        let payload = data.get(pos..).ok_or_else(|| anyhow!("unexpected EOF"))?.to_vec();
        Ok(Self { session_id, host, port, msg_id, frag_id, frag_count, data: payload })
    }
}
