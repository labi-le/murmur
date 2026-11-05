//! The socks5-shaped address/UDP-associate wire format matches `murmur_transport::socks5::socks5`
//! byte for byte, so this module reuses that crate rather than re-deriving it.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use murmur_transport::socks5::socks5 as socks5codec;

pub const SOCKS5_VERSION: u8 = 5;

#[derive(thiserror::Error, Debug)]
pub enum ModelError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("unrecognized address type {0}")]
    UnrecognizedAddrType(u8),
    #[error("unsupported socks5 version {0}")]
    UnsupportedVersion(u8),
    #[error("socks5 codec error: {0}")]
    Codec(#[from] anyhow::Error),
    #[error("nonzero UDP fragment number is not supported")]
    Fragmented,
}

pub type Result<T, E = ModelError> = std::result::Result<T, E>;

pub const CMD_CONNECT: u8 = 1;
pub const CMD_UDP_ASSOCIATE: u8 = 3;
pub const REPLY_SUCCESS: u8 = 0;

/// An IPv4, IPv6, or FQDN address with a port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddrSpec {
    Ip(IpAddr, u16),
    Fqdn(String, u16),
}

impl AddrSpec {
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(_, port) | Self::Fqdn(_, port) => *port,
        }
    }

    /// The socks5-style `addr_type || address_bytes || port` encoding.
    fn to_socks5(&self) -> socks5codec::Addr {
        match self {
            Self::Ip(IpAddr::V4(ip), port) => {
                socks5codec::addr_from_std_addr_port(std::net::SocketAddr::new(IpAddr::V4(*ip), *port))
            }
            Self::Ip(IpAddr::V6(ip), port) => {
                socks5codec::addr_from_std_addr_port(std::net::SocketAddr::new(IpAddr::V6(*ip), *port))
            }
            Self::Fqdn(host, port) => {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "the socks5 domain-name length field is a single wire byte"
                )]
                let mut buf = vec![socks5codec::ATYP_DOMAIN_NAME, host.len() as u8];
                buf.extend_from_slice(host.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
                socks5codec::Addr(buf)
            }
        }
    }

    fn from_socks5(addr: &socks5codec::Addr) -> Result<Self> {
        let bytes = &addr.0;
        let Some(&atyp) = bytes.first() else {
            return Err(ModelError::UnrecognizedAddrType(0));
        };
        match atyp {
            socks5codec::ATYP_IPV4 => {
                let octets = field::<4>(bytes, 1, atyp)?;
                let port = u16::from_be_bytes(field::<2>(bytes, 5, atyp)?);
                Ok(Self::Ip(IpAddr::V4(Ipv4Addr::from(octets)), port))
            }
            socks5codec::ATYP_IPV6 => {
                let octets = field::<16>(bytes, 1, atyp)?;
                let port = u16::from_be_bytes(field::<2>(bytes, 17, atyp)?);
                Ok(Self::Ip(IpAddr::V6(Ipv6Addr::from(octets)), port))
            }
            socks5codec::ATYP_DOMAIN_NAME => {
                let [host_len] = field::<1>(bytes, 1, atyp)?;
                let host_len = usize::from(host_len);
                let host = bytes.get(2..2 + host_len).ok_or(ModelError::UnrecognizedAddrType(atyp))?;
                let host = String::from_utf8_lossy(host).into_owned();
                let port = u16::from_be_bytes(field::<2>(bytes, 2 + host_len, atyp)?);
                Ok(Self::Fqdn(host, port))
            }
            other => Err(ModelError::UnrecognizedAddrType(other)),
        }
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.to_socks5().0
    }

    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self> {
        let atyp = r.read_u8().await?;
        let mut buf = vec![atyp];
        match atyp {
            socks5codec::ATYP_IPV4 => buf.extend(read_exact_vec(r, 4 + 2).await?),
            socks5codec::ATYP_IPV6 => buf.extend(read_exact_vec(r, 16 + 2).await?),
            socks5codec::ATYP_DOMAIN_NAME => {
                let len = r.read_u8().await?;
                buf.push(len);
                buf.extend(read_exact_vec(r, usize::from(len) + 2).await?);
            }
            other => return Err(ModelError::UnrecognizedAddrType(other)),
        }
        Self::from_socks5(&socks5codec::Addr(buf))
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        w.write_all(&self.encode()).await?;
        Ok(())
    }
}

impl std::fmt::Display for AddrSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip, port) => write!(f, "{ip}:{port}"),
            Self::Fqdn(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

/// Reads the `N`-byte field at `at`; the socks5 codec only builds addresses whose fields fit.
fn field<const N: usize>(bytes: &[u8], at: usize, atyp: u8) -> Result<[u8; N]> {
    let slice = bytes.get(at..at + N).ok_or(ModelError::UnrecognizedAddrType(atyp))?;
    slice.try_into().map_err(|_| ModelError::UnrecognizedAddrType(atyp))
}

async fn read_exact_vec<R: AsyncRead + Unpin>(r: &mut R, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// `version(1B) || command(1B) || reserved(1B) || AddrSpec`, with the version byte 5 and reserved 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub command: u8,
    pub dst_addr: AddrSpec,
}

impl Request {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![SOCKS5_VERSION, self.command, 0];
        buf.extend(self.dst_addr.encode());
        buf
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        w.write_all(&self.encode()).await?;
        Ok(())
    }

    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self> {
        let mut header = [0u8; 3];
        r.read_exact(&mut header).await?;
        if header[0] != SOCKS5_VERSION {
            return Err(ModelError::UnsupportedVersion(header[0]));
        }
        let dst_addr = AddrSpec::read_from(r).await?;
        Ok(Self { command: header[1], dst_addr })
    }
}

/// Same shape as [`Request`], with a reply code instead of a command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub reply_code: u8,
    pub bind_addr: AddrSpec,
}

impl Response {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![SOCKS5_VERSION, self.reply_code, 0];
        buf.extend(self.bind_addr.encode());
        buf
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        w.write_all(&self.encode()).await?;
        Ok(())
    }

    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self> {
        let mut header = [0u8; 3];
        r.read_exact(&mut header).await?;
        if header[0] != SOCKS5_VERSION {
            return Err(ModelError::UnsupportedVersion(header[0]));
        }
        let bind_addr = AddrSpec::read_from(r).await?;
        Ok(Self { reply_code: header[1], bind_addr })
    }

    /// The canned "bind address doesn't matter" response the listener sends.
    #[must_use]
    pub fn success() -> Self {
        Self { reply_code: REPLY_SUCCESS, bind_addr: AddrSpec::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0) }
    }
}

/// `0x00 || len(2B BE) || packet || 0xFF` framing that keeps packet boundaries over an ordered
/// byte stream.
#[derive(Debug)]
pub struct PacketOverStreamTunnel<S> {
    inner: S,
}

impl<S> PacketOverStreamTunnel<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: AsyncWrite + Unpin> PacketOverStreamTunnel<S> {
    pub async fn send_packet(&mut self, data: &[u8]) -> Result<()> {
        let Ok(len) = u16::try_from(data.len()) else {
            return Err(ModelError::Io(io::Error::new(io::ErrorKind::InvalidInput, "packet exceeds 65535 bytes")));
        };
        self.inner.write_u8(0x00).await?;
        self.inner.write_u16(len).await?;
        self.inner.write_all(data).await?;
        self.inner.write_u8(0xFF).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> PacketOverStreamTunnel<S> {
    pub async fn recv_packet(&mut self) -> Result<Vec<u8>> {
        let marker = self.inner.read_u8().await?;
        if marker != 0x00 {
            return Err(ModelError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad packet-over-stream leading marker",
            )));
        }
        let len = self.inner.read_u16().await?;
        let mut data = vec![0u8; usize::from(len)];
        self.inner.read_exact(&mut data).await?;
        let trailer = self.inner.read_u8().await?;
        if trailer != 0xFF {
            return Err(ModelError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad packet-over-stream trailing marker",
            )));
        }
        Ok(data)
    }
}

/// A plain socks5 UDP-relay header (`0x00 0x00 0x00 || AddrSpec || payload`) per packet, layered
/// on [`PacketOverStreamTunnel`].
#[derive(Debug)]
pub struct UdpAssociateWrapper<S> {
    tunnel: PacketOverStreamTunnel<S>,
}

impl<S> UdpAssociateWrapper<S> {
    pub fn new(inner: S) -> Self {
        Self { tunnel: PacketOverStreamTunnel::new(inner) }
    }
}

impl<S: AsyncWrite + Unpin> UdpAssociateWrapper<S> {
    pub async fn send_to(&mut self, payload: &[u8], dest: &AddrSpec) -> Result<()> {
        let socks_addr = dest.to_socks5();
        let packet = socks5codec::encode_udp_packet(&socks_addr, payload)?;
        self.tunnel.send_packet(&packet).await
    }
}

impl<S: AsyncRead + Unpin> UdpAssociateWrapper<S> {
    pub async fn recv_from(&mut self) -> Result<(Vec<u8>, AddrSpec)> {
        let packet = self.tunnel.recv_packet().await?;
        let (addr, payload) = socks5codec::decode_udp_packet(&packet)?;
        let addr_spec = AddrSpec::from_socks5(&addr)?;
        Ok((payload.to_vec(), addr_spec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_round_trips_ipv4_and_fqdn() {
        for req in [
            Request { command: CMD_CONNECT, dst_addr: AddrSpec::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443) },
            Request { command: CMD_UDP_ASSOCIATE, dst_addr: AddrSpec::Fqdn("example.com".to_owned(), 53) },
        ] {
            let mut buf = io::Cursor::new(req.encode());
            let parsed = Request::read_from(&mut buf).await.expect("read_from");
            assert_eq!(parsed, req);
        }
    }

    #[tokio::test]
    async fn response_round_trips() {
        let resp = Response::success();
        let mut buf = io::Cursor::new(resp.encode());
        let parsed = Response::read_from(&mut buf).await.expect("read_from");
        assert_eq!(parsed, resp);
    }

    #[tokio::test]
    async fn packet_over_stream_preserves_boundaries() {
        let (client, server) = tokio::io::duplex(4096);
        let mut writer = PacketOverStreamTunnel::new(client);
        let mut reader = PacketOverStreamTunnel::new(server);
        writer.send_packet(b"first").await.expect("send 1");
        writer.send_packet(b"second-packet").await.expect("send 2");
        assert_eq!(reader.recv_packet().await.expect("recv 1"), b"first");
        assert_eq!(reader.recv_packet().await.expect("recv 2"), b"second-packet");
    }

    #[tokio::test]
    async fn udp_associate_wrapper_round_trips() {
        let (client, server) = tokio::io::duplex(4096);
        let mut writer = UdpAssociateWrapper::new(client);
        let mut reader = UdpAssociateWrapper::new(server);
        let dest = AddrSpec::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 5353);
        writer.send_to(b"dns-query", &dest).await.expect("send_to");
        let (payload, got_dest) = reader.recv_from().await.expect("recv_from");
        assert_eq!(payload, b"dns-query");
        assert_eq!(got_dest, dest);
    }
}
