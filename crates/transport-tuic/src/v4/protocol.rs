use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::AsyncReadExt;

use murmur_component::dialer::bind::join_host_port;
use murmur_constant::metadata::{AddrType, Metadata};
use murmur_quic::ApplicationErrorCode;
use murmur_transport::socks5::socks5;

/// A buffered reader generalized over the readers this
/// crate parses commands from.
///
/// That is any live `AsyncRead` conn or quic stream (a [`BufferedConn`] included) and an in-memory
/// [`SliceReader`] over a datagram/message payload.
pub trait BufferedReader: Send {
    fn read_byte(&mut self) -> impl Future<Output = io::Result<u8>> + Send;
    fn read_full(&mut self, buf: &mut [u8]) -> impl Future<Output = io::Result<()>> + Send;
}

// Every live conn and quic stream parses commands through this bound; sealing it would narrow the
// reader set `read_response` accepts, and the crate is `publish = false`, so nothing can collide.
impl<T: tokio::io::AsyncRead + Unpin + Send + ?Sized> BufferedReader for T {
    async fn read_byte(&mut self) -> io::Result<u8> {
        AsyncReadExt::read_u8(self).await
    }

    async fn read_full(&mut self, buf: &mut [u8]) -> io::Result<()> {
        AsyncReadExt::read_exact(self, buf).await.map(|_| ())
    }
}

/// A reader over an in-memory datagram or message payload.
#[derive(Debug)]
pub struct SliceReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl BufferedReader for SliceReader<'_> {
    async fn read_byte(&mut self) -> io::Result<u8> {
        let Some(&b) = self.data.get(self.pos) else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        };
        self.pos += 1;
        Ok(b)
    }

    async fn read_full(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let Some(src) = self.data.get(self.pos..self.pos + buf.len()) else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        };
        buf.copy_from_slice(src);
        self.pos += buf.len();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandType(pub u8);

impl CommandType {
    pub const AUTHENTICATE_TYPE: Self = Self(0x00);
    pub const CONNECT_TYPE: Self = Self(0x01);
    pub const PACKET_TYPE: Self = Self(0x02);
    pub const DISSOCIATE_TYPE: Self = Self(0x03);
    pub const HEARTBEAT_TYPE: Self = Self(0x04);
    pub const RESPONSE_TYPE: Self = Self(0xff);

    #[must_use]
    pub const fn bytes_len(&self) -> usize {
        1
    }
}

impl fmt::Display for CommandType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            Self::AUTHENTICATE_TYPE => "Authenticate",
            Self::CONNECT_TYPE => "Connect",
            Self::PACKET_TYPE => "Packet",
            Self::DISSOCIATE_TYPE => "Dissociate",
            Self::HEARTBEAT_TYPE => "Heartbeat",
            Self::RESPONSE_TYPE => "Response",
            _ => return write!(f, "UnknowCommand: {:#x}", self.0),
        };
        write!(f, "{s}")
    }
}

pub const VER: u8 = 0x04;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandHead {
    pub ver: u8,
    pub type_: CommandType,
}

#[must_use]
pub const fn new_command_head(type_: CommandType) -> CommandHead {
    CommandHead { ver: VER, type_ }
}

pub async fn read_command_head<R: BufferedReader + ?Sized>(reader: &mut R) -> io::Result<CommandHead> {
    let ver = reader.read_byte().await?;
    read_command_head_after_ver(ver, reader).await
}

/// Reads the command head for a caller that has already read the version byte to pick a handler.
pub async fn read_command_head_after_ver<R: BufferedReader + ?Sized>(
    ver: u8,
    reader: &mut R,
) -> io::Result<CommandHead> {
    let type_ = CommandType(reader.read_byte().await?);
    Ok(CommandHead { ver, type_ })
}

impl CommandHead {
    pub fn write_to(&self, buf: &mut BytesMut) -> io::Result<()> {
        buf.put_u8(self.ver);
        buf.put_u8(self.type_.0);
        Ok(())
    }

    #[must_use]
    pub fn bytes_len(&self) -> usize {
        1 + self.type_.bytes_len()
    }
}

// Every write call site in this crate targets a
// `common::pool` buffer (or one that gets built and flushed in one shot); every `write_to` below
// takes a `BytesMut` directly, so no fallible writer seam is needed.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticate {
    pub command_head: CommandHead,
    pub tkn: [u8; 32],
}

#[must_use]
pub fn new_authenticate(tkn: [u8; 32]) -> Authenticate {
    Authenticate { command_head: new_command_head(CommandType::AUTHENTICATE_TYPE), tkn }
}

pub async fn read_authenticate_with_head<R: BufferedReader + ?Sized>(
    head: CommandHead,
    reader: &mut R,
) -> anyhow::Result<Authenticate> {
    if head.type_ != CommandType::AUTHENTICATE_TYPE {
        return Err(anyhow::anyhow!("error command type: {}", head.type_));
    }
    let mut tkn = [0u8; 32];
    reader.read_full(&mut tkn).await?;
    Ok(Authenticate { command_head: head, tkn })
}

pub async fn read_authenticate<R: BufferedReader + ?Sized>(reader: &mut R) -> anyhow::Result<Authenticate> {
    let head = read_command_head(reader).await?;
    read_authenticate_with_head(head, reader).await
}

#[must_use]
pub fn gen_tkn(token: &str) -> [u8; 32] {
    *blake3::hash(token.as_bytes()).as_bytes()
}

impl Authenticate {
    pub fn write_to(&self, buf: &mut BytesMut) -> io::Result<()> {
        self.command_head.write_to(buf)?;
        buf.put_slice(&self.tkn);
        Ok(())
    }

    #[must_use]
    pub fn bytes_len(&self) -> usize {
        self.command_head.bytes_len() + 32
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connect {
    pub command_head: CommandHead,
    pub addr: Address,
}

#[must_use]
pub fn new_connect(addr: Address) -> Connect {
    Connect { command_head: new_command_head(CommandType::CONNECT_TYPE), addr }
}

pub async fn read_connect_with_head<R: BufferedReader + ?Sized>(
    head: CommandHead,
    reader: &mut R,
) -> anyhow::Result<Connect> {
    if head.type_ != CommandType::CONNECT_TYPE {
        return Err(anyhow::anyhow!("error command type: {}", head.type_));
    }
    let addr = read_address(reader).await?;
    Ok(Connect { command_head: head, addr })
}

pub async fn read_connect<R: BufferedReader + ?Sized>(reader: &mut R) -> anyhow::Result<Connect> {
    let head = read_command_head(reader).await?;
    read_connect_with_head(head, reader).await
}

impl Connect {
    pub fn write_to(&self, buf: &mut BytesMut) -> io::Result<()> {
        self.command_head.write_to(buf)?;
        self.addr.write_to(buf)?;
        Ok(())
    }

    #[must_use]
    pub fn bytes_len(&self) -> usize {
        self.command_head.bytes_len() + self.addr.bytes_len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub command_head: CommandHead,
    pub assoc_id: u32,
    pub len: u16,
    pub addr: Address,
    pub data: Bytes,
}

pub fn new_packet(assoc_id: u32, len: u16, addr: Address, data: Bytes) -> Packet {
    Packet { command_head: new_command_head(CommandType::PACKET_TYPE), assoc_id, len, addr, data }
}

pub async fn read_packet_with_head<R: BufferedReader + ?Sized>(
    head: CommandHead,
    reader: &mut R,
) -> anyhow::Result<Packet> {
    if head.type_ != CommandType::PACKET_TYPE {
        return Err(anyhow::anyhow!("error command type: {}", head.type_));
    }
    let mut assoc_id_buf = [0u8; 4];
    reader.read_full(&mut assoc_id_buf).await?;
    let assoc_id = u32::from_be_bytes(assoc_id_buf);
    let mut len_buf = [0u8; 2];
    reader.read_full(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf);
    let addr = read_address(reader).await?;
    let mut data = vec![0u8; len as usize];
    reader.read_full(&mut data).await?;
    Ok(Packet { command_head: head, assoc_id, len, addr, data: Bytes::from(data) })
}

pub async fn read_packet<R: BufferedReader + ?Sized>(reader: &mut R) -> anyhow::Result<Packet> {
    let head = read_command_head(reader).await?;
    read_packet_with_head(head, reader).await
}

impl Packet {
    pub fn write_to(&self, buf: &mut BytesMut) -> io::Result<()> {
        self.command_head.write_to(buf)?;
        buf.put_u32(self.assoc_id);
        buf.put_u16(self.len);
        self.addr.write_to(buf)?;
        buf.put_slice(&self.data);
        Ok(())
    }

    pub fn bytes_len(&self) -> usize {
        self.command_head.bytes_len() + 4 + 2 + self.addr.bytes_len() + self.data.len()
    }
}

pub static PACKET_OVER_HEAD: LazyLock<usize> = LazyLock::new(|| {
    new_packet(
        0,
        0,
        new_address_addr_port(SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)),
        Bytes::new(),
    )
    .bytes_len()
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dissociate {
    pub command_head: CommandHead,
    pub assoc_id: u32,
}

#[must_use]
pub fn new_dissociate(assoc_id: u32) -> Dissociate {
    Dissociate { command_head: new_command_head(CommandType::DISSOCIATE_TYPE), assoc_id }
}

pub async fn read_dissociate_with_head<R: BufferedReader + ?Sized>(
    head: CommandHead,
    reader: &mut R,
) -> anyhow::Result<Dissociate> {
    if head.type_ != CommandType::DISSOCIATE_TYPE {
        return Err(anyhow::anyhow!("error command type: {}", head.type_));
    }
    let mut assoc_id_buf = [0u8; 4];
    reader.read_full(&mut assoc_id_buf).await?;
    Ok(Dissociate { command_head: head, assoc_id: u32::from_be_bytes(assoc_id_buf) })
}

pub async fn read_dissociate<R: BufferedReader + ?Sized>(reader: &mut R) -> anyhow::Result<Dissociate> {
    let head = read_command_head(reader).await?;
    read_dissociate_with_head(head, reader).await
}

impl Dissociate {
    pub fn write_to(&self, buf: &mut BytesMut) -> io::Result<()> {
        self.command_head.write_to(buf)?;
        buf.put_u32(self.assoc_id);
        Ok(())
    }

    #[must_use]
    pub fn bytes_len(&self) -> usize {
        self.command_head.bytes_len() + 4
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heartbeat {
    pub command_head: CommandHead,
}

#[must_use]
pub fn new_heartbeat() -> Heartbeat {
    Heartbeat { command_head: new_command_head(CommandType::HEARTBEAT_TYPE) }
}

pub fn read_heartbeat_with_head(head: CommandHead) -> anyhow::Result<Heartbeat> {
    if head.type_ != CommandType::HEARTBEAT_TYPE {
        return Err(anyhow::anyhow!("error command type: {}", head.type_));
    }
    Ok(Heartbeat { command_head: head })
}

pub async fn read_heartbeat<R: BufferedReader + ?Sized>(reader: &mut R) -> anyhow::Result<Heartbeat> {
    let head = read_command_head(reader).await?;
    read_heartbeat_with_head(head)
}

impl Heartbeat {
    #[must_use]
    pub fn bytes_len(&self) -> usize {
        self.command_head.bytes_len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    pub command_head: CommandHead,
    pub rep: u8,
}

#[must_use]
pub fn new_response(rep: u8) -> Response {
    Response { command_head: new_command_head(CommandType::RESPONSE_TYPE), rep }
}

#[must_use]
pub fn new_response_succeed() -> Response {
    new_response(0x00)
}

#[must_use]
pub fn new_response_failed() -> Response {
    new_response(0xff)
}

pub async fn read_response_with_head<R: BufferedReader + ?Sized>(
    head: CommandHead,
    reader: &mut R,
) -> anyhow::Result<Response> {
    if head.type_ != CommandType::RESPONSE_TYPE {
        return Err(anyhow::anyhow!("error command type: {}", head.type_));
    }
    let rep = reader.read_byte().await?;
    Ok(Response { command_head: head, rep })
}

pub async fn read_response<R: BufferedReader + ?Sized>(reader: &mut R) -> anyhow::Result<Response> {
    let head = read_command_head(reader).await?;
    read_response_with_head(head, reader).await
}

impl Response {
    pub fn write_to(&self, buf: &mut BytesMut) -> io::Result<()> {
        self.command_head.write_to(buf)?;
        buf.put_u8(self.rep);
        Ok(())
    }

    #[must_use]
    pub const fn is_succeed(&self) -> bool {
        self.rep == 0x00
    }

    #[must_use]
    pub const fn is_failed(&self) -> bool {
        self.rep == 0xff
    }

    #[must_use]
    pub fn bytes_len(&self) -> usize {
        self.command_head.bytes_len() + 1
    }
}

/// the `Addr types` consts.
pub const ATYP_DOMAIN_NAME: u8 = 0;
pub const ATYP_IPV4: u8 = 1;
pub const ATYP_IPV6: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub type_: u8,
    pub addr: Vec<u8>,
    pub port: u16,
}

fn ip_octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn addr_from_slice(b: &[u8]) -> Option<IpAddr> {
    if let Ok(octets) = <[u8; 4]>::try_from(b) {
        return Some(IpAddr::V4(std::net::Ipv4Addr::from(octets)));
    }
    <[u8; 16]>::try_from(b).ok().map(|octets| IpAddr::V6(std::net::Ipv6Addr::from(octets)))
}

#[must_use]
#[expect(
    clippy::expect_used,
    reason = "`addr_type` reports an IP kind only when `dst_ip` is `Some`, so the option is populated on both IP arms"
)]
pub fn new_address(metadata: &Metadata) -> Address {
    let (type_, addr) = match metadata.addr_type() {
        AddrType::ATYP_IPV4 => (ATYP_IPV4, ip_octets(metadata.dst_ip.expect("ATYP_IPV4 implies dst_ip"))),
        AddrType::ATYP_IPV6 => (ATYP_IPV6, ip_octets(metadata.dst_ip.expect("ATYP_IPV6 implies dst_ip"))),
        _ => {
            let mut addr = Vec::with_capacity(metadata.host.len() + 1);
            #[expect(clippy::cast_possible_truncation, reason = "the domain-name length is a single byte on the wire")]
            addr.push(metadata.host.len() as u8);
            addr.extend_from_slice(metadata.host.as_bytes());
            (ATYP_DOMAIN_NAME, addr)
        }
    };
    Address { type_, addr, port: metadata.dst_port }
}

pub fn new_address_addr_port(addr_port: SocketAddr) -> Address {
    let port = addr_port.port();
    let unmapped = match addr_port.ip() {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
    };
    let (type_, addr) = match unmapped {
        IpAddr::V4(ip) => (ATYP_IPV4, ip.octets().to_vec()),
        IpAddr::V6(ip) => (ATYP_IPV6, ip.octets().to_vec()),
    };
    Address { type_, addr, port }
}

pub async fn read_address<R: BufferedReader + ?Sized>(reader: &mut R) -> anyhow::Result<Address> {
    let type_ = reader.read_byte().await?;
    let addr = match type_ {
        ATYP_IPV4 => {
            let mut addr = vec![0u8; 4];
            reader.read_full(&mut addr).await?;
            addr
        }
        ATYP_IPV6 => {
            let mut addr = vec![0u8; 16];
            reader.read_full(&mut addr).await?;
            addr
        }
        ATYP_DOMAIN_NAME => {
            let addr_len = reader.read_byte().await?;
            // The length byte heads the payload; `read_full` overwrites everything after it.
            let mut addr = vec![addr_len; addr_len as usize + 1];
            let (_, host) = addr.split_at_mut(1);
            reader.read_full(host).await?;
            addr
        }
        _ => Vec::new(),
    };
    let mut port_buf = [0u8; 2];
    reader.read_full(&mut port_buf).await?;
    Ok(Address { type_, addr, port: u16::from_be_bytes(port_buf) })
}

impl Address {
    pub fn write_to(&self, buf: &mut BytesMut) -> io::Result<()> {
        buf.put_u8(self.type_);
        buf.put_slice(&self.addr);
        buf.put_u16(self.port);
        Ok(())
    }

    #[must_use]
    pub fn string(&self) -> String {
        if self.type_ == ATYP_DOMAIN_NAME {
            let host = self.addr.get(1..).map(String::from_utf8_lossy).unwrap_or_default();
            join_host_port(&host, self.port)
        } else {
            match addr_from_slice(&self.addr) {
                Some(ip) => SocketAddr::new(ip, self.port).to_string(),
                None => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), self.port).to_string(),
            }
        }
    }

    #[must_use]
    pub fn socks_addr(&self) -> socks5::Addr {
        let atyp = match self.type_ {
            ATYP_IPV4 => socks5::ATYP_IPV4,
            ATYP_IPV6 => socks5::ATYP_IPV6,
            ATYP_DOMAIN_NAME => socks5::ATYP_DOMAIN_NAME,
            _ => 0,
        };
        let mut addr = Vec::with_capacity(1 + self.addr.len() + 2);
        addr.push(atyp);
        addr.extend_from_slice(&self.addr);
        addr.extend_from_slice(&self.port.to_be_bytes());
        socks5::Addr(addr)
    }

    /// Builds a UDP address from the raw IP bytes. Any length is tolerated here by keeping
    /// the bytes as they are; a `std::net::IpAddr` can only be built from 4 or 16 bytes
    /// and falls back to the unspecified address for anything else (in practice, a
    /// domain-name payload, which would be carried unusably too).
    #[must_use]
    pub fn udp_addr(&self) -> murmur_std_compat::net::UdpAddr {
        let ip = addr_from_slice(&self.addr).unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        murmur_std_compat::net::UdpAddr::new(ip, self.port)
    }

    #[must_use]
    pub const fn bytes_len(&self) -> usize {
        1 + self.addr.len() + 2
    }
}

/// The application error codes.
pub const PROTOCOL_ERROR: ApplicationErrorCode = 0xffff_fff0;
pub const AUTHENTICATION_FAILED: ApplicationErrorCode = 0xffff_fff1;
pub const AUTHENTICATION_TIMEOUT: ApplicationErrorCode = 0xffff_fff2;
pub const BAD_COMMAND: ApplicationErrorCode = 0xffff_fff3;
