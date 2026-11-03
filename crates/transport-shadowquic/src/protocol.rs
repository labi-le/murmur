use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::{Addr, UdpAddr};
use murmur_transport::socks5::socks5;

pub const COMMAND_CONNECT: u8 = 0x01;
pub const COMMAND_BIND: u8 = 0x02;
pub const COMMAND_ASSOCIATE_DATAGRAM: u8 = 0x03;
pub const COMMAND_ASSOCIATE_STREAM: u8 = 0x04;
pub const COMMAND_AUTHENTICATE: u8 = 0x05;
pub const COMMAND_EXTENSION: u8 = 0xff;

pub(crate) const MAX_UDP_PACKET_SIZE: usize = 0xffff;

#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("shadowquic: invalid address")]
pub struct ErrInvalidAddress;

#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("shadowquic: invalid datagram")]
pub struct ErrInvalidDatagram;

#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("shadowquic: packet too large")]
pub struct ErrPacketTooLarge;

pub fn metadata_addr(metadata: &Metadata) -> anyhow::Result<socks5::Addr> {
    socks5::parse_addr(&metadata.remote_address())
        .ok_or_else(|| anyhow::anyhow!("{ErrInvalidAddress}: {}", metadata.remote_address()))
}

#[must_use]
pub fn unspecified_addr() -> socks5::Addr {
    socks5::addr_from_std_addr_port(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
}

pub fn addr_from_net_addr(addr: Option<&dyn Addr>) -> anyhow::Result<socks5::Addr> {
    let Some(addr) = addr else {
        return Err(ErrInvalidAddress.into());
    };
    if let Some(socks_addr) = socks5::parse_addr_to_socks_addr(addr) {
        return Ok(socks_addr);
    }
    socks5::parse_addr(&addr.string()).ok_or_else(|| anyhow::anyhow!("{ErrInvalidAddress}: {}", addr.string()))
}

#[must_use]
pub fn addr_to_net_addr(addr: &socks5::Addr) -> NetAddr {
    if let Some(udp_addr) = addr.udp_addr() {
        return NetAddr::Udp(udp_addr);
    }
    NetAddr::Socks(SocksNetAddr { addr: addr.clone() })
}

pub async fn write_request<W>(w: &mut W, command: u8, addr: &socks5::Addr) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    w.write_all(&[command]).await?;
    w.write_all(addr).await
}

pub async fn read_command<R>(r: &mut R) -> anyhow::Result<u8>
where
    R: AsyncRead + Unpin + ?Sized,
{
    socks5::read_byte(r).await
}

pub async fn read_request_addr<R>(r: &mut R) -> anyhow::Result<socks5::Addr>
where
    R: AsyncRead + Unpin + ?Sized,
{
    socks5::read_addr0(r).await
}

pub async fn read_request<R>(r: &mut R) -> anyhow::Result<(u8, socks5::Addr)>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let command = read_command(r).await?;
    let addr = read_request_addr(r).await?;
    Ok((command, addr))
}

pub async fn write_udp_control<W>(w: &mut W, addr: &socks5::Addr, id: u16) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    w.write_all(addr).await?;
    w.write_all(&id.to_be_bytes()).await?;
    Ok(())
}

// NOT cancel-safe: the address and the id are read with separate exact reads, so a drop in
// between consumes bytes the caller cannot put back; the only caller drops it while closing.
pub async fn read_udp_control<R>(r: &mut R) -> anyhow::Result<(socks5::Addr, u16)>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let addr = socks5::read_addr0(r).await?;
    let id = read_uint16(r).await?;
    Ok((addr, id))
}

pub fn encode_datagram(id: u16, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() > MAX_UDP_PACKET_SIZE {
        return Err(ErrPacketTooLarge.into());
    }
    let mut packet = Vec::with_capacity(2 + payload.len());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub fn decode_datagram(packet: &[u8]) -> anyhow::Result<(u16, &[u8])> {
    let [hi, lo, payload @ ..] = packet else {
        return Err(ErrInvalidDatagram.into());
    };
    Ok((u16::from_be_bytes([*hi, *lo]), payload))
}

pub async fn write_packet_stream_header<W>(w: &mut W, id: u16) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    w.write_all(&id.to_be_bytes()).await
}

pub async fn write_packet_stream_payload<W>(w: &mut W, payload: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if payload.len() > MAX_UDP_PACKET_SIZE {
        return Err(ErrPacketTooLarge.into());
    }
    let len = u16::try_from(payload.len()).map_err(|_| ErrPacketTooLarge)?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    Ok(())
}

pub async fn read_uint16<R>(r: &mut R) -> std::io::Result<u16>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

#[derive(Clone, Debug)]
pub struct SocksNetAddr {
    addr: socks5::Addr,
}

impl Addr for SocksNetAddr {
    fn network(&self) -> &'static str {
        "udp"
    }

    fn string(&self) -> String {
        self.addr.string()
    }
}

/// The two concrete shapes `addr_to_net_addr` produces: a UDP address or a SOCKS address.
#[derive(Clone, Debug)]
pub enum NetAddr {
    Udp(UdpAddr),
    Socks(SocksNetAddr),
}

impl Addr for NetAddr {
    fn network(&self) -> &str {
        match self {
            Self::Udp(addr) => addr.network(),
            Self::Socks(addr) => addr.network(),
        }
    }

    fn string(&self) -> String {
        match self {
            Self::Udp(addr) => addr.string(),
            Self::Socks(addr) => addr.string(),
        }
    }
}
