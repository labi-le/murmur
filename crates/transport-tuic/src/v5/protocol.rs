//! The TUIC v5 command and address codec.
//!
//! The `BufferedReader`/`BufferedWriter` traits are folded into concrete bounds at each call site:
//! reads take `R: AsyncRead + Unpin + ?Sized`
//! (satisfied by a live stream conn as well as a `std::io::Cursor` over an already-received
//! datagram, since tokio implements `AsyncRead` for `Cursor<&[u8]>`), writes take `&mut BytesMut`
//! because every call site in this crate only ever writes into `pool::get_buffer()`'s buffer,
//! never straight to a stream. The two reader/writer interfaces are kept below for API parity but are not
//! used as parameter types.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::LazyLock;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::quic::Conn as QuicConn;
use murmur_component::dialer::bind::join_host_port;
use murmur_component::dialer::bind::unmap_addr;
use murmur_constant::metadata::{AddrType, Metadata};
use murmur_std_compat::net::UdpAddr;
use murmur_transport::socks5::socks5 as socks5_pkg;

// The reader and writer roles are declared as type sets here, so
// these stay as bounds; the crate is `publish = false`, so no downstream impl can collide with them.
pub trait BufferedReader: AsyncRead + Unpin + Send {}
impl<T: AsyncRead + Unpin + Send + ?Sized> BufferedReader for T {}

pub trait BufferedWriter: bytes::BufMut {}
impl<T: bytes::BufMut + ?Sized> BufferedWriter for T {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandType(pub u8);

impl CommandType {
    pub const AUTHENTICATE_TYPE: Self = Self(0x00);
    pub const CONNECT_TYPE: Self = Self(0x01);
    pub const PACKET_TYPE: Self = Self(0x02);
    pub const DISSOCIATE_TYPE: Self = Self(0x03);
    pub const HEARTBEAT_TYPE: Self = Self(0x04);

    #[must_use]
    pub const fn bytes_len(&self) -> usize {
        1
    }
}

impl fmt::Display for CommandType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::AUTHENTICATE_TYPE => write!(f, "Authenticate"),
            Self::CONNECT_TYPE => write!(f, "Connect"),
            Self::PACKET_TYPE => write!(f, "Packet"),
            Self::DISSOCIATE_TYPE => write!(f, "Dissociate"),
            Self::HEARTBEAT_TYPE => write!(f, "Heartbeat"),
            Self(v) => write!(f, "UnknowCommand: {v:#x}"),
        }
    }
}

pub const VER: u8 = 0x05;

#[derive(Clone, Copy, Debug)]
pub struct CommandHead {
    pub ver: u8,
    pub type_: CommandType,
}

#[must_use]
pub const fn new_command_head(type_: CommandType) -> CommandHead {
    CommandHead { ver: VER, type_ }
}

pub async fn read_command_head<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> anyhow::Result<CommandHead> {
    let ver = reader.read_u8().await?;
    let type_ = reader.read_u8().await?;
    Ok(CommandHead { ver, type_: CommandType(type_) })
}

impl CommandHead {
    pub fn write_to(&self, writer: &mut BytesMut) {
        use bytes::BufMut;
        writer.put_u8(self.ver);
        writer.put_u8(self.type_.0);
    }

    #[must_use]
    pub fn bytes_len(&self) -> usize {
        1 + self.type_.bytes_len()
    }
}

#[derive(Clone, Copy)]
pub struct Authenticate {
    pub command_head: CommandHead,
    pub uuid: [u8; 16],
    pub token: [u8; 32],
}

impl fmt::Debug for Authenticate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authenticate")
            .field("command_head", &self.command_head)
            .field("uuid", &"<redacted>")
            .field("token", &"<redacted>")
            .finish()
    }
}

#[must_use]
pub fn new_authenticate(uuid: [u8; 16], token: [u8; 32]) -> Authenticate {
    Authenticate { command_head: new_command_head(CommandType::AUTHENTICATE_TYPE), uuid, token }
}

pub async fn read_authenticate_with_head<R: AsyncRead + Unpin + ?Sized>(
    head: CommandHead,
    reader: &mut R,
) -> anyhow::Result<Authenticate> {
    if head.type_ != CommandType::AUTHENTICATE_TYPE {
        anyhow::bail!("error command type: {}", head.type_);
    }
    let mut uuid = [0u8; 16];
    reader.read_exact(&mut uuid).await?;
    let mut token = [0u8; 32];
    reader.read_exact(&mut token).await?;
    Ok(Authenticate { command_head: head, uuid, token })
}

pub async fn read_authenticate<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> anyhow::Result<Authenticate> {
    let head = read_command_head(reader).await?;
    read_authenticate_with_head(head, reader).await
}

/// Exported keying material, the only part of the connection state this crate reads.
///
/// Takes the owning [`QuicConn`] directly rather than an intermediate connection-state value,
/// which has no other use here.
pub fn gen_token(quic_conn: &dyn QuicConn, uuid: [u8; 16], password: &str) -> anyhow::Result<[u8; 32]> {
    let token_bytes = quic_conn.export_keying_material(&uuid, password.as_bytes(), 32)?;
    let mut token = [0u8; 32];
    let n = token_bytes.len().min(token.len());
    if let (Some(dst), Some(src)) = (token.get_mut(..n), token_bytes.get(..n)) {
        dst.copy_from_slice(src);
    }
    Ok(token)
}

impl Authenticate {
    pub fn write_to(&self, writer: &mut BytesMut) {
        use bytes::BufMut;
        self.command_head.write_to(writer);
        writer.put_slice(&self.uuid);
        writer.put_slice(&self.token);
    }

    #[must_use]
    pub fn bytes_len(&self) -> usize {
        self.command_head.bytes_len() + 16 + 32
    }
}

#[derive(Clone, Debug)]
pub struct Connect {
    pub command_head: CommandHead,
    pub addr: Address,
}

#[must_use]
pub fn new_connect(addr: Address) -> Connect {
    Connect { command_head: new_command_head(CommandType::CONNECT_TYPE), addr }
}

pub async fn read_connect_with_head<R: AsyncRead + Unpin + ?Sized>(
    head: CommandHead,
    reader: &mut R,
) -> anyhow::Result<Connect> {
    if head.type_ != CommandType::CONNECT_TYPE {
        anyhow::bail!("error command type: {}", head.type_);
    }
    let addr = read_address(reader).await?;
    Ok(Connect { command_head: head, addr })
}

pub async fn read_connect<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> anyhow::Result<Connect> {
    let head = read_command_head(reader).await?;
    read_connect_with_head(head, reader).await
}

impl Connect {
    pub fn write_to(&self, writer: &mut BytesMut) {
        self.command_head.write_to(writer);
        self.addr.write_to(writer);
    }

    #[must_use]
    pub fn bytes_len(&self) -> usize {
        self.command_head.bytes_len() + self.addr.bytes_len()
    }
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub command_head: CommandHead,
    pub assoc_id: u16,
    pub pkt_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    pub size: u16,
    pub addr: Address,
    pub data: Bytes,
}

pub fn new_packet(
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    size: u16,
    addr: Address,
    data: Bytes,
) -> Packet {
    Packet {
        command_head: new_command_head(CommandType::PACKET_TYPE),
        assoc_id,
        pkt_id,
        frag_id,
        frag_total,
        size,
        addr,
        data,
    }
}

pub async fn read_packet_with_head<R: AsyncRead + Unpin + ?Sized>(
    head: CommandHead,
    reader: &mut R,
) -> anyhow::Result<Packet> {
    if head.type_ != CommandType::PACKET_TYPE {
        anyhow::bail!("error command type: {}", head.type_);
    }
    let assoc_id = reader.read_u16().await?;
    let pkt_id = reader.read_u16().await?;
    let frag_total = reader.read_u8().await?;
    let frag_id = reader.read_u8().await?;
    let size = reader.read_u16().await?;
    let addr = read_address(reader).await?;
    let mut data = vec![0u8; size as usize];
    reader.read_exact(&mut data).await?;
    Ok(Packet { command_head: head, assoc_id, pkt_id, frag_total, frag_id, size, addr, data: Bytes::from(data) })
}

pub async fn read_packet<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> anyhow::Result<Packet> {
    let head = read_command_head(reader).await?;
    read_packet_with_head(head, reader).await
}

impl Packet {
    pub fn write_to(&self, writer: &mut BytesMut) {
        use bytes::BufMut;
        self.command_head.write_to(writer);
        writer.put_u16(self.assoc_id);
        writer.put_u16(self.pkt_id);
        writer.put_u8(self.frag_total);
        writer.put_u8(self.frag_id);
        writer.put_u16(self.size);
        self.addr.write_to(writer);
        writer.put_slice(&self.data);
    }

    pub fn bytes_len(&self) -> usize {
        self.command_head.bytes_len() + 4 + 2 + self.addr.bytes_len() + self.data.len()
    }
}

pub static PACKET_OVER_HEAD: LazyLock<usize> = LazyLock::new(|| {
    new_packet(
        0,
        0,
        0,
        0,
        0,
        new_address_addr_port(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)),
        Bytes::new(),
    )
    .bytes_len()
});

#[derive(Clone, Copy, Debug)]
pub struct Dissociate {
    pub command_head: CommandHead,
    pub assoc_id: u16,
}

#[must_use]
pub fn new_dissociate(assoc_id: u16) -> Dissociate {
    Dissociate { command_head: new_command_head(CommandType::DISSOCIATE_TYPE), assoc_id }
}

pub async fn read_dissociate_with_head<R: AsyncRead + Unpin + ?Sized>(
    head: CommandHead,
    reader: &mut R,
) -> anyhow::Result<Dissociate> {
    if head.type_ != CommandType::DISSOCIATE_TYPE {
        anyhow::bail!("error command type: {}", head.type_);
    }
    let assoc_id = reader.read_u16().await?;
    Ok(Dissociate { command_head: head, assoc_id })
}

pub async fn read_dissociate<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> anyhow::Result<Dissociate> {
    let head = read_command_head(reader).await?;
    read_dissociate_with_head(head, reader).await
}

impl Dissociate {
    pub fn write_to(&self, writer: &mut BytesMut) {
        use bytes::BufMut;
        self.command_head.write_to(writer);
        writer.put_u16(self.assoc_id);
    }

    #[must_use]
    pub fn bytes_len(&self) -> usize {
        self.command_head.bytes_len() + 4
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Heartbeat {
    pub command_head: CommandHead,
}

#[must_use]
pub fn new_heartbeat() -> Heartbeat {
    Heartbeat { command_head: new_command_head(CommandType::HEARTBEAT_TYPE) }
}

pub fn read_heartbeat_with_head(head: CommandHead) -> anyhow::Result<Heartbeat> {
    if head.type_ != CommandType::HEARTBEAT_TYPE {
        anyhow::bail!("error command type: {}", head.type_);
    }
    Ok(Heartbeat { command_head: head })
}

pub async fn read_heartbeat<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> anyhow::Result<Heartbeat> {
    let head = read_command_head(reader).await?;
    read_heartbeat_with_head(head)
}

impl Heartbeat {
    #[must_use]
    pub fn bytes_len(&self) -> usize {
        self.command_head.bytes_len()
    }
}

/// the `Addr types` const block.
pub const ATYP_DOMAIN_NAME: u8 = 0;
pub const ATYP_IPV4: u8 = 1;
pub const ATYP_IPV6: u8 = 2;
/// Address type None is used in Packet commands that is not the first fragment of a UDP packet.
pub const ATYP_NONE: u8 = 255;

#[derive(Clone, Debug)]
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

#[must_use]
pub fn new_address(metadata: &Metadata) -> Address {
    let mut type_ = 0u8;
    let mut addr = Vec::new();
    match metadata.addr_type() {
        AddrType::ATYP_IPV4 => {
            type_ = ATYP_IPV4;
            if let Some(ip) = metadata.dst_ip {
                addr = ip_octets(ip);
            }
        }
        AddrType::ATYP_IPV6 => {
            type_ = ATYP_IPV6;
            if let Some(ip) = metadata.dst_ip {
                addr = ip_octets(ip);
            }
        }
        AddrType::ATYP_DOMAIN_NAME => {
            type_ = ATYP_DOMAIN_NAME;
            let host = metadata.host.as_bytes();
            addr = Vec::with_capacity(host.len() + 1);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the domain-name length is a single byte on the wire"
            )]
            addr.push(host.len() as u8);
            addr.extend_from_slice(host);
        }
        _ => {}
    }
    Address { type_, addr, port: metadata.dst_port }
}

#[must_use]
pub fn new_address_addr_port(addr_port: SocketAddr) -> Address {
    let port = addr_port.port();
    let ip = unmap_addr(Some(addr_port.ip())).unwrap_or_else(|| addr_port.ip());
    let (type_, addr) = match ip {
        IpAddr::V4(v4) => (ATYP_IPV4, v4.octets().to_vec()),
        IpAddr::V6(v6) => (ATYP_IPV6, v6.octets().to_vec()),
    };
    Address { type_, addr, port }
}

pub async fn read_address<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> anyhow::Result<Address> {
    let type_ = reader.read_u8().await?;
    let mut addr = Vec::new();
    match type_ {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).await?;
            addr = buf.to_vec();
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            reader.read_exact(&mut buf).await?;
            addr = buf.to_vec();
        }
        ATYP_DOMAIN_NAME => {
            let addr_len = reader.read_u8().await?;
            let mut name = vec![0u8; addr_len as usize];
            reader.read_exact(&mut name).await?;
            addr = Vec::with_capacity(addr_len as usize + 1);
            addr.push(addr_len);
            addr.extend_from_slice(&name);
        }
        _ => {}
    }

    if type_ == ATYP_NONE {
        return Ok(Address { type_, addr, port: 0 });
    }
    let port = reader.read_u16().await?;
    Ok(Address { type_, addr, port })
}

impl Address {
    pub fn write_to(&self, writer: &mut BytesMut) {
        use bytes::BufMut;
        writer.put_u8(self.type_);
        if self.type_ == ATYP_NONE {
            return;
        }
        writer.put_slice(&self.addr);
        writer.put_u16(self.port);
    }

    pub fn string(&self) -> String {
        match self.type_ {
            ATYP_DOMAIN_NAME => {
                let host = self.addr.get(1..).map(String::from_utf8_lossy).unwrap_or_default();
                join_host_port(&host, self.port)
            }
            _ => match addr_from_slice(&self.addr) {
                Some(ip) => SocketAddr::new(ip, self.port).to_string(),
                None => "<nil>".to_owned(),
            },
        }
    }

    #[must_use]
    pub fn socks_addr(&self) -> socks5_pkg::Addr {
        let atyp = match self.type_ {
            ATYP_IPV4 => socks5_pkg::ATYP_IPV4,
            ATYP_IPV6 => socks5_pkg::ATYP_IPV6,
            ATYP_DOMAIN_NAME => socks5_pkg::ATYP_DOMAIN_NAME,
            _ => 0,
        };
        let mut addr = Vec::with_capacity(1 + self.addr.len() + 2);
        addr.push(atyp);
        addr.extend_from_slice(&self.addr);
        addr.extend_from_slice(&self.port.to_be_bytes());
        socks5_pkg::Addr(addr)
    }

    #[must_use]
    pub fn udp_addr(&self) -> UdpAddr {
        UdpAddr::new(ip_from_bytes(&self.addr), self.port)
    }

    #[must_use]
    pub const fn bytes_len(&self) -> usize {
        1 + self.addr.len() + 2
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.string())
    }
}

fn addr_from_slice(b: &[u8]) -> Option<IpAddr> {
    if let Ok(octets) = <[u8; 4]>::try_from(b) {
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    <[u8; 16]>::try_from(b).ok().map(|octets| IpAddr::V6(Ipv6Addr::from(octets)))
}

/// Keeps whatever length the address happens to have; a
/// non-4/16 length (the domain-name or none address kinds) has no valid IP reading, so it
/// falls back to the unspecified address rather than constructing an invalid one.
fn ip_from_bytes(b: &[u8]) -> IpAddr {
    addr_from_slice(b).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

pub type ApplicationErrorCode = u64;

pub const PROTOCOL_ERROR: ApplicationErrorCode = 0xffff_fff0;
pub const AUTHENTICATION_FAILED: ApplicationErrorCode = 0xffff_fff1;
pub const AUTHENTICATION_TIMEOUT: ApplicationErrorCode = 0xffff_fff2;
pub const BAD_COMMAND: ApplicationErrorCode = 0xffff_fff3;

pub use crate::quic::DatagramTooLargeError;
