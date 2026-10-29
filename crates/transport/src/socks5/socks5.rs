use std::fmt::{self, Write as _};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::slice::SliceIndex;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use murmur_common_net::io::Stream;
use murmur_component::auth::auth::{Authenticator, ALWAYS_VALID};
use murmur_std_compat::net::UdpAddr;

const IPV4_LEN: usize = 4;
const IPV6_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub u8);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SOCKS error: {}", self.0)
    }
}

impl std::error::Error for Error {}

pub type Command = u8;

pub const VERSION: u8 = 5;

/// SOCKS request commands (RFC 1928 section 4).
pub const CMD_CONNECT: Command = 1;
pub const CMD_BIND: Command = 2;
pub const CMD_UDP_ASSOCIATE: Command = 3;

/// SOCKS address types (RFC 1928 section 5).
pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN_NAME: u8 = 3;
pub const ATYP_IPV6: u8 = 4;

pub const MAX_ADDR_LEN: usize = 1 + 1 + 255 + 2;

/// The maximum size of the user/password field in SOCKS5 auth.
pub const MAX_AUTH_LEN: usize = 255;

/// A SOCKS address (RFC 1928 section 5).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Addr(pub Vec<u8>);

// Deliberate collection delegation: `Addr` is a newtype over the RFC 1928 address encoding, so the
// bytes are what callers read and write.
impl Deref for Addr {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for Addr {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<Vec<u8>> for Addr {
    fn from(b: Vec<u8>) -> Self {
        Self(b)
    }
}

impl From<&[u8]> for Addr {
    fn from(b: &[u8]) -> Self {
        Self(b.to_vec())
    }
}

impl Addr {
    #[must_use]
    pub fn string(&self) -> String {
        let a = &self.0;
        let mut host = String::new();
        let mut port = String::new();

        match a.first().copied() {
            Some(ATYP_DOMAIN_NAME) => {
                let host_len = usize::from(a.get(1).copied().unwrap_or_default());
                if let Some(name) = a.get(2..2 + host_len) {
                    host = String::from_utf8_lossy(name).into_owned();
                }
                port = be_u16_at(a, 2 + host_len).to_string();
            }
            Some(ATYP_IPV4) => {
                host = ip_string(a.get(1..=IPV4_LEN).unwrap_or_default());
                port = be_u16_at(a, 1 + IPV4_LEN).to_string();
            }
            Some(ATYP_IPV6) => {
                host = ip_string(a.get(1..=IPV6_LEN).unwrap_or_default());
                port = be_u16_at(a, 1 + IPV6_LEN).to_string();
            }
            Some(_) | None => {}
        }

        join_host_port(&host, &port)
    }

    #[must_use]
    pub fn udp_addr(&self) -> Option<UdpAddr> {
        let a = &self.0;
        match a.first().copied()? {
            ATYP_IPV4 => {
                let ip: [u8; IPV4_LEN] = a.get(1..=IPV4_LEN)?.try_into().ok()?;
                let port = be_u16_at(a, 1 + IPV4_LEN);
                Some(UdpAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
            }
            ATYP_IPV6 => {
                let ip: [u8; IPV6_LEN] = a.get(1..=IPV6_LEN)?.try_into().ok()?;
                let port = be_u16_at(a, 1 + IPV6_LEN);
                let ip6 = Ipv6Addr::from(ip);
                let ip = match ip6.to_ipv4_mapped() {
                    Some(ip4) => IpAddr::V4(ip4),
                    None => IpAddr::V6(ip6),
                };
                Some(UdpAddr::new(ip, port))
            }
            _ => None,
        }
    }
}

pub const ERR_GENERAL_FAILURE: Error = Error(1);
pub const ERR_CONNECTION_NOT_ALLOWED: Error = Error(2);
pub const ERR_NETWORK_UNREACHABLE: Error = Error(3);
pub const ERR_HOST_UNREACHABLE: Error = Error(4);
pub const ERR_CONNECTION_REFUSED: Error = Error(5);
pub const ERR_TTL_EXPIRED: Error = Error(6);
pub const ERR_COMMAND_NOT_SUPPORTED: Error = Error(7);
pub const ERR_ADDRESS_NOT_SUPPORTED: Error = Error(8);

#[derive(thiserror::Error, Debug)]
#[error("auth failed")]
pub struct ErrAuth;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct User {
    pub username: String,
    pub password: String,
}

/// Fast-tracks SOCKS initialization to get the target address to connect on the server side.
pub async fn server_handshake(
    rw: &mut dyn Stream,
    authenticator: Option<Arc<dyn Authenticator>>,
) -> Result<(Addr, Command, String)> {
    let mut buf = vec![0u8; MAX_ADDR_LEN];

    // VER, NMETHODS, METHODS
    rw.read_exact(slice_at_mut(&mut buf, ..2)?).await?;
    let nmethods = byte_at(&buf, 1)?;
    rw.read_exact(slice_at_mut(&mut buf, ..usize::from(nmethods))?).await?;

    let mut authenticator = authenticator;
    if nmethods == 1 && byte_at(&buf, 0)? == 0x02 && authenticator.is_none() {
        authenticator = Some(ALWAYS_VALID.clone());
    }

    let mut user = String::new();

    if let Some(authenticator) = authenticator.as_ref() {
        rw.write_all(&[5, 2]).await?;
        rw.flush().await?;

        let mut header = [0u8; 2];
        rw.read_exact(&mut header).await?;

        let mut auth_buf = vec![0u8; MAX_AUTH_LEN];
        let user_len = usize::from(header[1]);
        if user_len == 0 {
            let _ = rw.write_all(&[1, 1]).await;
            return Err(ErrAuth.into());
        }
        rw.read_exact(slice_at_mut(&mut auth_buf, ..user_len)?).await?;
        user = String::from_utf8_lossy(slice_at(&auth_buf, ..user_len)?).into_owned();

        let n = rw.read(&mut header[..1]).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        let pass_len = usize::from(header[0]);
        if pass_len == 0 {
            let _ = rw.write_all(&[1, 1]).await;
            return Err(ErrAuth.into());
        }
        rw.read_exact(slice_at_mut(&mut auth_buf, ..pass_len)?).await?;
        let pass = String::from_utf8_lossy(slice_at(&auth_buf, ..pass_len)?).into_owned();

        if !authenticator.verify(&user, &pass) {
            let _ = rw.write_all(&[1, 1]).await;
            return Err(ErrAuth.into());
        }

        rw.write_all(&[1, 0]).await?;
    } else {
        rw.write_all(&[5, 0]).await?;
    }
    rw.flush().await?;

    // VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
    rw.read_exact(slice_at_mut(&mut buf, ..3)?).await?;

    let command = byte_at(&buf, 1)?;
    let addr = read_addr(rw, &mut buf).await?;

    match command {
        CMD_CONNECT | CMD_UDP_ASSOCIATE => {
            let Ok(local_addr) = rw.local_addr() else {
                return Err(ERR_ADDRESS_NOT_SUPPORTED.into());
            };
            let local_addr = addr_from_ip_port(local_addr.ip(), local_addr.port());
            // VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
            let mut reply = Vec::with_capacity(3 + local_addr.0.len());
            reply.extend_from_slice(&[5, 0, 0]);
            reply.extend_from_slice(&local_addr.0);
            rw.write_all(&reply).await?;
            rw.flush().await?;
        }
        _ => return Err(ERR_COMMAND_NOT_SUPPORTED.into()),
    }

    Ok((addr, command, user))
}

/// Fast-tracks SOCKS initialization to get the target address to connect on the client side.
// NOT cancel-safe: the handshake writes its preamble and messages to the socket before it completes, so a dropped call leaves the connection mid-exchange; the arms that await it drop it only when the connection is being torn down.
pub async fn client_handshake<RW>(rw: &mut RW, addr: &Addr, command: Command, user: Option<&User>) -> Result<Addr>
where
    RW: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut buf = vec![0u8; MAX_ADDR_LEN];

    // VER, NMETHODS, METHODS
    if user.is_some() {
        rw.write_all(&[5, 1, 2]).await?;
    } else {
        rw.write_all(&[5, 1, 0]).await?;
    }
    rw.flush().await?;

    // VER, METHOD
    rw.read_exact(slice_at_mut(&mut buf, ..2)?).await?;

    if byte_at(&buf, 0)? != 5 {
        return Err(anyhow!("SOCKS version error"));
    }

    if byte_at(&buf, 1)? == 2 {
        let Some(user) = user else {
            return Err(ErrAuth.into());
        };

        // password protocol version, then the single-byte lengths
        let mut auth_msg = Vec::with_capacity(3 + user.username.len() + user.password.len());
        auth_msg.push(1);
        auth_msg.push(u8::try_from(user.username.len()).map_err(|_| anyhow!("username too long"))?);
        auth_msg.extend_from_slice(user.username.as_bytes());
        auth_msg.push(u8::try_from(user.password.len()).map_err(|_| anyhow!("password too long"))?);
        auth_msg.extend_from_slice(user.password.as_bytes());

        rw.write_all(&auth_msg).await?;
        rw.flush().await?;

        rw.read_exact(slice_at_mut(&mut buf, ..2)?).await?;

        if byte_at(&buf, 1)? != 0 {
            return Err(anyhow!("rejected username/password"));
        }
    } else if byte_at(&buf, 1)? != 0 {
        return Err(anyhow!("SOCKS need auth"));
    }

    // VER, CMD, RSV, ADDR
    let mut request = Vec::with_capacity(3 + addr.0.len());
    request.extend_from_slice(&[5, command, 0]);
    request.extend_from_slice(&addr.0);
    rw.write_all(&request).await?;
    rw.flush().await?;

    // VER, REP, RSV
    rw.read_exact(slice_at_mut(&mut buf, ..3)?).await?;

    read_addr(rw, &mut buf).await
}

pub async fn read_addr<RW>(r: &mut RW, b: &mut [u8]) -> Result<Addr>
where
    RW: AsyncRead + Unpin + ?Sized,
{
    if b.len() < MAX_ADDR_LEN {
        return Err(anyhow!("short buffer"));
    }
    // the first byte is the address type
    r.read_exact(slice_at_mut(b, ..1)?).await?;

    match byte_at(b, 0)? {
        ATYP_DOMAIN_NAME => {
            // the second byte is the domain length
            r.read_exact(slice_at_mut(b, 1..2)?).await?;
            let domain_length = usize::from(byte_at(b, 1)?);
            let len = 1 + 1 + domain_length + 2;
            r.read_exact(slice_at_mut(b, 2..len)?).await?;
            Ok(Addr(slice_at(b, ..len)?.to_vec()))
        }
        ATYP_IPV4 => {
            let len = 1 + IPV4_LEN + 2;
            r.read_exact(slice_at_mut(b, 1..len)?).await?;
            Ok(Addr(slice_at(b, ..len)?.to_vec()))
        }
        ATYP_IPV6 => {
            let len = 1 + IPV6_LEN + 2;
            r.read_exact(slice_at_mut(b, 1..len)?).await?;
            Ok(Addr(slice_at(b, ..len)?.to_vec()))
        }
        _ => Err(ERR_ADDRESS_NOT_SUPPORTED.into()),
    }
}

pub async fn read_addr0<RW>(r: &mut RW) -> Result<Addr>
where
    RW: AsyncRead + Unpin + ?Sized,
{
    // the first byte is the address type
    let a_type = read_byte(r).await?;

    match a_type {
        ATYP_DOMAIN_NAME => {
            // the second byte is the domain length
            let domain_length = read_byte(r).await?;
            let mut b = vec![a_type, domain_length];
            b.resize(1 + 1 + usize::from(domain_length) + 2, 0);
            let len = b.len();
            r.read_exact(slice_at_mut(&mut b, 2..len)?).await?;
            Ok(Addr(b))
        }
        ATYP_IPV4 => {
            let mut b = [0u8; 1 + IPV4_LEN + 2];
            r.read_exact(&mut b[1..]).await?;
            b[0] = a_type;
            Ok(Addr(b.to_vec()))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 1 + IPV6_LEN + 2];
            r.read_exact(&mut b[1..]).await?;
            b[0] = a_type;
            Ok(Addr(b.to_vec()))
        }
        _ => Err(ERR_ADDRESS_NOT_SUPPORTED.into()),
    }
}

pub async fn read_byte<RW>(r: &mut RW) -> Result<u8>
where
    RW: AsyncRead + Unpin + ?Sized,
{
    let mut b = [0u8; 1];
    r.read_exact(&mut b[..]).await?;
    Ok(b[0])
}

/// Slices a SOCKS address from the beginning of `b`. Returns `None` if it fails.
#[must_use]
pub fn split_addr(b: &[u8]) -> Option<Addr> {
    let addr_len = match *b.first()? {
        ATYP_DOMAIN_NAME => {
            if b.len() < 2 {
                return None;
            }
            1 + 1 + usize::from(*b.get(1)?) + 2
        }
        ATYP_IPV4 => 1 + IPV4_LEN + 2,
        ATYP_IPV6 => 1 + IPV6_LEN + 2,
        _ => return None,
    };

    if b.len() < addr_len {
        return None;
    }

    Some(Addr(b.get(..addr_len)?.to_vec()))
}

/// Parses the address in the string `s`. Returns `None` if it fails.
#[must_use]
pub fn parse_addr(s: &str) -> Option<Addr> {
    let (host, port) = split_host_port(s).ok()?;

    let mut addr = if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip4) => ipv4_socks_addr(ip4),
            IpAddr::V6(ip6) => match ip6.to_ipv4_mapped() {
                Some(ip4) => ipv4_socks_addr(ip4),
                None => ipv6_socks_addr(ip6),
            },
        }
    } else {
        let Ok(host_len) = u8::try_from(host.len()) else {
            return None;
        };
        let mut addr = Vec::with_capacity(1 + 1 + host.len() + 2);
        addr.push(ATYP_DOMAIN_NAME);
        addr.push(host_len);
        addr.extend_from_slice(host.as_bytes());
        addr.extend_from_slice(&[0, 0]);
        addr
    };

    set_port(&mut addr, port);

    Some(Addr(addr))
}

/// The ATYP folding: an IPv4-mapped IPv6 address encodes as
/// [`ATYP_IPV4`].
fn addr_from_ip_port(ip: IpAddr, port: u16) -> Addr {
    let ip4 = match ip {
        IpAddr::V4(ip4) => Some(ip4),
        IpAddr::V6(ip6) => ip6.to_ipv4_mapped(),
    };

    let mut parsed = match ip4 {
        Some(ip4) => ipv4_socks_addr(ip4),
        None => match ip {
            IpAddr::V4(ip4) => ipv4_socks_addr(ip4),
            IpAddr::V6(ip6) => ipv6_socks_addr(ip6),
        },
    };

    set_port(&mut parsed, port);

    Addr(parsed)
}

/// Parses a socks addr from a [`murmur_std_compat::net::Addr`], with a fast path over the addr's string form.
pub fn parse_addr_to_socks_addr(addr: &dyn murmur_std_compat::net::Addr) -> Option<Addr> {
    let (hostip, port) = match murmur_std_compat::net::sock_addr_of(addr) {
        Some(murmur_std_compat::net::SockAddr::Udp(udp_addr)) => (Some(udp_addr.ip), udp_addr.port),
        Some(murmur_std_compat::net::SockAddr::Tcp(tcp_addr)) => (Some(tcp_addr.ip), tcp_addr.port),
        None => (None, 0),
    };

    let Some(hostip) = hostip else {
        return parse_addr(&addr.string());
    };

    Some(addr_from_ip_port(hostip, port))
}

#[must_use]
pub fn addr_from_std_addr_port(addr_port: SocketAddr) -> Addr {
    match addr_port {
        SocketAddr::V4(v4) => {
            let ip4 = v4.ip().octets();
            let port = addr_port.port().to_be_bytes();
            Addr(vec![ATYP_IPV4, ip4[0], ip4[1], ip4[2], ip4[3], port[0], port[1]])
        }
        SocketAddr::V6(v6) => {
            let mut buf = socks_addr(ATYP_IPV6, &v6.ip().octets());
            set_port(&mut buf, addr_port.port());
            Addr(buf)
        }
    }
}

/// Splits `packet` into an address and its payload; the payload borrows `packet`.
pub fn decode_udp_packet(packet: &[u8]) -> Result<(Addr, &[u8])> {
    if packet.len() < 5 {
        return Err(anyhow!("insufficient length of packet"));
    }

    // packet[0] and packet[1] are reserved
    if !matches!(slice_at(packet, ..2)?, [0, 0]) {
        return Err(anyhow!("reserved fields should be zero"));
    }

    if byte_at(packet, 2)? != 0 {
        return Err(anyhow!("discarding fragmented payload"));
    }

    let Some(addr) = split_addr(slice_at(packet, 3..)?) else {
        return Err(anyhow!("failed to read UDP header"));
    };

    let payload = slice_at(packet, 3 + addr.0.len()..)?;
    Ok((addr, payload))
}

pub fn encode_udp_packet(addr: &Addr, payload: &[u8]) -> Result<Vec<u8>> {
    if addr.0.is_empty() {
        return Err(anyhow!("address is invalid"));
    }
    let mut packet = Vec::with_capacity(3 + addr.0.len() + payload.len());
    packet.extend_from_slice(&[0, 0, 0]);
    packet.extend_from_slice(&addr.0);
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// A SOCKS address of type `atyp` carrying `body`, with a zero placeholder port.
fn socks_addr(atyp: u8, body: &[u8]) -> Vec<u8> {
    let mut addr = Vec::with_capacity(1 + body.len() + 2);
    addr.push(atyp);
    addr.extend_from_slice(body);
    addr.extend_from_slice(&[0, 0]);
    addr
}

fn ipv4_socks_addr(ip4: Ipv4Addr) -> Vec<u8> {
    socks_addr(ATYP_IPV4, &ip4.octets())
}

fn ipv6_socks_addr(ip6: Ipv6Addr) -> Vec<u8> {
    socks_addr(ATYP_IPV6, &ip6.octets())
}

/// Writes the big-endian `port` into the last two bytes of a SOCKS address.
fn set_port(addr: &mut [u8], port: u16) {
    if let Some(tail) = addr.last_chunk_mut::<2>() {
        *tail = port.to_be_bytes();
    }
}

/// Formats the raw bytes of a SOCKS address as an IP address string.
fn ip_string(ip: &[u8]) -> String {
    if ip.is_empty() {
        return "<nil>".to_owned();
    }
    if let Ok(octets) = <[u8; IPV4_LEN]>::try_from(ip) {
        return Ipv4Addr::from(octets).to_string();
    }
    if let Ok(octets) = <[u8; IPV6_LEN]>::try_from(ip) {
        let ip6 = Ipv6Addr::from(octets);
        return match ip6.to_ipv4_mapped() {
            Some(ip4) => ip4.to_string(),
            None => ip6.to_string(),
        };
    }
    let mut s = String::with_capacity(1 + ip.len() * 2);
    s.push('?');
    for b in ip {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Joins a host and port, bracketing an IPv6 host.
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Splits a host:port string into its host and port.
fn split_host_port(hostport: &str) -> Result<(String, u16)> {
    let (host, port) = split_host_port_parts(hostport)?;
    Ok((host.to_owned(), parse_port(port)?))
}

fn split_host_port_parts(hostport: &str) -> Result<(&str, &str)> {
    let Some(i) = last(hostport, b':') else {
        return Err(anyhow!("address {hostport}: missing port in address"));
    };
    let (host_part, rest) = hostport.split_at(i);
    let Some(port) = rest.strip_prefix(':') else {
        return Err(anyhow!("address {hostport}: missing port in address"));
    };

    let mut host = host_part;
    if let Some(bracketed) = host.strip_prefix('[') {
        let Some(bracketed) = bracketed.strip_suffix(']') else {
            return Err(anyhow!("address {hostport}: missing ']' in address"));
        };
        host = bracketed;
    } else if host.contains(':') {
        return Err(anyhow!("address {hostport}: too many colons in address"));
    }

    Ok((host, port))
}

fn parse_port(port: &str) -> Result<u16> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(anyhow!("invalid port syntax"));
    }
    port.parse::<u16>().map_err(|_| anyhow!("port out of range"))
}

/// The index of the last `b` byte in `s`, if any.
fn last(s: &str, b: u8) -> Option<usize> {
    s.as_bytes().iter().rposition(|c| *c == b)
}

/// Borrows `b[range]`, erroring when `b` is shorter than the range end.
fn slice_at(b: &[u8], range: impl SliceIndex<[u8], Output = [u8]>) -> Result<&[u8]> {
    b.get(range).ok_or_else(|| anyhow!("short buffer"))
}

/// Mutably borrows `b[range]`, erroring when `b` is shorter than the range end.
fn slice_at_mut(b: &mut [u8], range: impl SliceIndex<[u8], Output = [u8]>) -> Result<&mut [u8]> {
    b.get_mut(range).ok_or_else(|| anyhow!("short buffer"))
}

/// The byte at `off`, erroring when `b` is shorter than `off + 1`.
fn byte_at(b: &[u8], off: usize) -> Result<u8> {
    b.get(off).copied().ok_or_else(|| anyhow!("short buffer"))
}

/// The big-endian `u16` at `off`, or 0 when `b` does not cover it.
fn be_u16_at(b: &[u8], off: usize) -> u16 {
    b.get(off..off.saturating_add(2)).and_then(|s| s.first_chunk::<2>()).map_or(0, |c| u16::from_be_bytes(*c))
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::Poll;

    use super::*;
    use murmur_common_net::deadline::pipe_sing::pipe;

    struct FixedLocalAddrConn<C> {
        inner: C,
        local: SocketAddr,
    }

    impl<C: AsyncRead + Unpin> AsyncRead for FixedLocalAddrConn<C> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl<C: AsyncWrite + Unpin> AsyncWrite for FixedLocalAddrConn<C> {
        fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl<C: AsyncRead + AsyncWrite + Send + Sync + Unpin> Stream for FixedLocalAddrConn<C> {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local)
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "test fixture has no real peer address"))
        }
    }

    /// Pins `parse_addr` output for each SOCKS address type.
    #[test]
    fn parse_addr_encodes_each_address_type() {
        let cases = [
            ("example.com:443", "030b6578616d706c652e636f6d01bb"),
            ("192.0.2.1:80", "01c00002010050"),
            ("[::1]:53", "04000000000000000000000000000000010035"),
        ];
        for (input, want_hex) in cases {
            let got = parse_addr(input).unwrap_or_else(|| panic!("parse_addr({input:?}) failed"));
            let want = hex::decode(want_hex).expect("valid hex vector");
            assert_eq!(got.0, want, "parse_addr({input:?}) does not match the pinned bytes");
        }
    }

    /// Pins the UDP header plus payload encoding for `192.0.2.1:80`.
    #[test]
    fn udp_packet_encode_decode_round_trips() {
        let addr = parse_addr("192.0.2.1:80").expect("valid addr");
        let payload = b"dns-query";

        let packet = encode_udp_packet(&addr, payload).expect("encode_udp_packet");
        let want = hex::decode("00000001c00002010050646e732d7175657279").expect("valid hex vector");
        assert_eq!(packet, want, "encode_udp_packet does not match the pinned bytes");

        let (decoded_addr, decoded_payload) = decode_udp_packet(&packet).expect("decode_udp_packet");
        assert_eq!(decoded_addr, addr);
        assert_eq!(decoded_payload, payload);
    }

    /// Pins `client_handshake`'s no-auth greeting and request bytes per ATYP: VLESS numbers
    /// IPv4/domain/IPv6 as 1/2/3, unlike SOCKS's own RFC 1928 values (1/3/4).
    #[tokio::test]
    async fn client_handshake_no_auth_per_atyp() {
        let cases = [
            ("192.0.2.1:80", "05010001c00002010050"),
            ("example.com:80", "050100030b6578616d706c652e636f6d0050"),
            ("[2001:db8::1]:8443", "0501000420010db800000000000000000000000120fb"),
        ];

        for (addr_str, want_request_hex) in cases {
            let (mut client, mut server) = pipe();
            let addr = parse_addr(addr_str).expect("valid addr");
            let addr_for_server = addr.clone();

            let server_task = tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                server.read_exact(&mut greeting).await.expect("read greeting");
                assert_eq!(greeting, [0x05, 0x01, 0x00], "no-auth greeting for {addr_str}");
                server.write_all(&[5, 0]).await.expect("write method reply");

                let mut request = vec![0u8; 3 + addr_for_server.0.len()];
                server.read_exact(&mut request).await.expect("read request");
                let mut probe = [0u8; 1];
                let extra = tokio::time::timeout(std::time::Duration::from_millis(50), server.read(&mut probe)).await;
                assert!(extra.is_err(), "trailing bytes after the request for {addr_str}");
                let mut reply = vec![5, 0, 0];
                reply.extend_from_slice(&addr_for_server);
                server.write_all(&reply).await.expect("write connect reply");
                request
            });

            let got_bound = client_handshake(&mut client, &addr, CMD_CONNECT, None).await.expect("client_handshake");
            assert_eq!(got_bound, addr);

            let got_request = server_task.await.expect("server task");
            let want_request = hex::decode(want_request_hex).expect("valid hex vector");
            assert_eq!(
                got_request, want_request,
                "client_handshake request does not match the pinned bytes for {addr_str}"
            );
        }
    }

    /// Pins `client_handshake`'s username/password sub-negotiation (RFC 1929).
    #[tokio::test]
    async fn client_handshake_with_user_pass() {
        let (mut client, mut server) = pipe();
        let addr = parse_addr("192.0.2.1:80").expect("valid addr");
        let addr_for_server = addr.clone();
        let user = User { username: "alice".to_owned(), password: "secret".to_owned() };

        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.expect("read greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x02]);
            server.write_all(&[5, 2]).await.expect("write method reply");

            let mut auth_msg = [0u8; 14];
            server.read_exact(&mut auth_msg).await.expect("read auth message");
            let want_auth = hex::decode("0105616c69636506736563726574").expect("valid hex vector");
            assert_eq!(auth_msg, want_auth[..], "auth message does not match the pinned bytes");
            server.write_all(&[1, 0]).await.expect("write auth success");

            let mut request = vec![0u8; 3 + addr_for_server.0.len()];
            server.read_exact(&mut request).await.expect("read request");
            let mut probe = [0u8; 1];
            let extra = tokio::time::timeout(std::time::Duration::from_millis(50), server.read(&mut probe)).await;
            assert!(extra.is_err(), "trailing bytes after the request");
            let mut reply = vec![5, 0, 0];
            reply.extend_from_slice(&addr_for_server);
            server.write_all(&reply).await.expect("write connect reply");
            request
        });

        let got_bound = client_handshake(&mut client, &addr, CMD_CONNECT, Some(&user)).await.expect("client_handshake");
        assert_eq!(got_bound, addr);

        let got_request = server_task.await.expect("server task");
        let want_request = hex::decode("05010001c00002010050").expect("valid hex vector");
        assert_eq!(got_request, want_request, "client_handshake request does not match the pinned bytes");
    }

    /// Feeds literal RFC 1928 bytes (a no-auth greeting and a domain CONNECT request) into
    /// the server handshake and pins the parsed address/command/user and the reply bytes it writes.
    #[tokio::test]
    async fn server_handshake_matches_rfc1928_bytes() {
        let (mut client, server) = pipe();
        let mut server =
            FixedLocalAddrConn { inner: server, local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080) };

        let domain_addr = parse_addr("example.com:80").expect("valid addr");
        let domain_addr_for_client = domain_addr.clone();
        let client_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.expect("write greeting");
            let mut method_reply = [0u8; 2];
            client.read_exact(&mut method_reply).await.expect("read method reply");

            let mut request = vec![0x05, 0x01, 0x00];
            request.extend_from_slice(&domain_addr_for_client);
            client.write_all(&request).await.expect("write request");
            let mut connect_reply = vec![0u8; 3 + 7];
            client.read_exact(&mut connect_reply).await.expect("read connect reply");
            (method_reply, connect_reply)
        });

        let (addr, command, user) = server_handshake(&mut server, None).await.expect("server_handshake");
        assert_eq!(command, CMD_CONNECT);
        assert_eq!(user, "");
        assert_eq!(addr, domain_addr);

        let (method_reply, connect_reply) = client_task.await.expect("client task");
        assert_eq!(method_reply, [5, 0]);
        let mut want_connect_reply = vec![5, 0, 0];
        want_connect_reply.extend_from_slice(&parse_addr("127.0.0.1:1080").expect("valid addr"));
        assert_eq!(connect_reply, want_connect_reply);
    }

    /// The server handshake with an [`Authenticator`] runs RFC 1929 username/password
    /// sub-negotiation and reports the verified username.
    #[tokio::test]
    async fn server_handshake_authenticates_user_pass() {
        struct FixedAuth;
        impl Authenticator for FixedAuth {
            fn verify(&self, user: &str, pass: &str) -> bool {
                user == "alice" && pass == "secret"
            }
            fn users(&self) -> Vec<String> {
                vec!["alice".to_owned()]
            }
        }

        let (mut client, server) = pipe();
        let mut server =
            FixedLocalAddrConn { inner: server, local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080) };
        let addr = parse_addr("192.0.2.1:80").expect("valid addr");
        let addr_for_client = addr.clone();

        let client_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x02]).await.expect("write greeting");
            let mut method_reply = [0u8; 2];
            client.read_exact(&mut method_reply).await.expect("read method reply");
            assert_eq!(method_reply, [5, 2]);

            let mut auth_msg = vec![1u8, 5];
            auth_msg.extend_from_slice(b"alice");
            auth_msg.push(6);
            auth_msg.extend_from_slice(b"secret");
            client.write_all(&auth_msg).await.expect("write auth message");
            let mut auth_reply = [0u8; 2];
            client.read_exact(&mut auth_reply).await.expect("read auth reply");
            assert_eq!(auth_reply, [1, 0]);

            let mut request = vec![0x05, 0x01, 0x00];
            request.extend_from_slice(&addr_for_client);
            client.write_all(&request).await.expect("write request");
            let mut connect_reply = vec![0u8; 3 + 7];
            client.read_exact(&mut connect_reply).await.expect("read connect reply");
            connect_reply
        });

        let (got_addr, command, user) =
            server_handshake(&mut server, Some(Arc::new(FixedAuth))).await.expect("server_handshake");
        assert_eq!(command, CMD_CONNECT);
        assert_eq!(user, "alice");
        assert_eq!(got_addr, addr);

        let connect_reply = client_task.await.expect("client task");
        let mut want_connect_reply = vec![5, 0, 0];
        want_connect_reply.extend_from_slice(&parse_addr("127.0.0.1:1080").expect("valid addr"));
        assert_eq!(connect_reply, want_connect_reply);
    }
}
