use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;

use super::address::{decode_address, encode_address};
use super::write_chunks::write_all_chunks;
use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{
    old_addr_to_socket_addr, socket_addr_from_udp_addr, udp_addr_from_socket_addr, CancellableStream, Datagram, Stream,
};
use murmur_log::debugln;
use murmur_std_compat::net::{Addr, UdpAddr};
const MAX_UOT_PAYLOAD: usize = 64 * 1024;

/// `WriteDatagram`: sends a single UDP datagram frame over a reliable stream.
pub(crate) async fn write_datagram<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    addr: &str,
    payload: &[u8],
) -> Result<()> {
    let addr_buf = encode_address(addr).map_err(|err| anyhow!("encode address: {err}"))?;

    let addr_len = addr_buf.len();
    if addr_len == 0 || addr_len > MAX_UOT_PAYLOAD {
        return Err(anyhow!("address too long: {addr_len}"));
    }
    if payload.len() > MAX_UOT_PAYLOAD {
        return Err(anyhow!("payload too large: {}", payload.len()));
    }

    let mut header = [0u8; 4];
    let addr_len_u16 = u16::try_from(addr_len).map_err(|_| anyhow!("address too long: {addr_len}"))?;
    let payload_len_u16 = u16::try_from(payload.len()).map_err(|_| anyhow!("payload too large: {}", payload.len()))?;
    BigEndian::write_u16(&mut header[..2], addr_len_u16);
    BigEndian::write_u16(&mut header[2..], payload_len_u16);

    write_all_chunks(w, &[&header[..], &addr_buf, payload]).await.map_err(Into::into)
}

/// `ReadDatagram`: parses a single UDP datagram frame from the reliable stream.
pub async fn read_datagram<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> Result<(String, Vec<u8>)> {
    let (addr, payload_len) = read_datagram_header_and_address(r).await?;
    let mut payload = vec![0u8; payload_len];
    r.read_exact(&mut payload).await?;
    Ok((addr, payload))
}

/// `UoTPacketConn`: adapts a connection carrying the Sudoku `UoT` framing to a datagram
/// interface.
///
/// Deviation: the write lock only guards writes; the underlying conn's reads run unsynchronized.
/// The stream's `poll_read`/`poll_write` need `&mut self`, so both directions share
/// [`SharedConn`]'s single internal mutex (already the crate's convention for a cloneable
/// conn handle, see `murmur_common::shared_conn`).
pub struct UoTPacketConn {
    conn: SharedConn,
    write_mu: AsyncMutex<()>,
}

impl core::fmt::Debug for UoTPacketConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UoTPacketConn").finish_non_exhaustive()
    }
}

impl UoTPacketConn {
    #[must_use]
    pub fn new(conn: Box<dyn Stream>) -> Self {
        Self { conn: SharedConn::new(CancellableStream::new(conn)), write_mu: AsyncMutex::new(()) }
    }
}

#[async_trait::async_trait]
impl Datagram for UoTPacketConn {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        loop {
            let mut conn = self.conn.clone();
            let (addr_str, payload_len) = read_datagram_header_and_address(&mut conn).await.map_err(anyhow_to_io)?;

            let parsed = parse_datagram_udp_addr(&addr_str);
            if payload_len > buf.len() {
                discard_bytes(&mut conn, payload_len).await.map_err(anyhow_to_io)?;
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "short buffer"));
            }
            let udp_addr = match parsed {
                Ok(udp_addr) => udp_addr,
                Err(err) => {
                    discard_bytes(&mut conn, payload_len).await.map_err(anyhow_to_io)?;
                    debugln!("[Sudoku][UoT] discard datagram with invalid address {addr_str}: {err}");
                    continue;
                }
            };
            conn.read_exact(buf.split_at_mut(payload_len).0).await?;
            return Ok((payload_len, socket_addr_from_udp_addr(&udp_addr)));
        }
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        let _guard = self.write_mu.lock().await;
        let mut conn = self.conn.clone();
        let udp_addr = udp_addr_from_socket_addr(addr);
        write_datagram(&mut conn, &udp_addr.string(), buf).await.map_err(anyhow_to_io)?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        old_addr_to_socket_addr(&*self.conn.local_addr()?)
    }

    fn close(&self) -> std::io::Result<()> {
        self.conn.close()
    }
}

fn anyhow_to_io(err: anyhow::Error) -> std::io::Error {
    std::io::Error::other(err)
}

async fn read_datagram_header_and_address<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> Result<(String, usize)> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await?;

    let addr_len = BigEndian::read_u16(&header[..2]) as usize;
    let payload_len = BigEndian::read_u16(&header[2..]) as usize;
    if addr_len == 0 || addr_len > MAX_UOT_PAYLOAD {
        return Err(anyhow!("invalid address length: {addr_len}"));
    }
    if payload_len > MAX_UOT_PAYLOAD {
        return Err(anyhow!("invalid payload length: {payload_len}"));
    }

    let mut addr_buf = vec![0u8; addr_len];
    r.read_exact(&mut addr_buf).await?;

    let addr = decode_address(&mut &addr_buf[..]).await.map_err(|err| anyhow!("decode address: {err}"))?;
    Ok((addr, payload_len))
}

fn parse_datagram_udp_addr(addr: &str) -> Result<UdpAddr> {
    let socket_addr: SocketAddr = addr.parse()?;
    Ok(UdpAddr::from(socket_addr))
}

async fn discard_bytes<R: AsyncRead + Unpin + ?Sized>(r: &mut R, n: usize) -> Result<()> {
    if n == 0 {
        return Ok(());
    }
    let mut remaining = n;
    let mut buf = [0u8; 4096];
    while remaining > 0 {
        let chunk = remaining.min(buf.len());
        r.read_exact(buf.split_at_mut(chunk).0).await?;
        remaining -= chunk;
    }
    Ok(())
}
