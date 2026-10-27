use std::io;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt};

use murmur_sing::metadata::{parse_socksaddr_host_port, Socksaddr, SOCKSADDR_SERIALIZER};

pub const PROTOCOL_SMUX: u8 = 0;
pub const PROTOCOL_YAMUX: u8 = 1;
pub const PROTOCOL_H2MUX: u8 = 2;

pub const VERSION_0: u8 = 0;
pub const VERSION_1: u8 = 1;

#[must_use]
pub fn destination() -> Socksaddr {
    Socksaddr::fqdn("sp.mux.sing-box.arpa", 444)
}

#[derive(Clone, Copy, Debug)]
pub struct Request {
    pub version: u8,
    pub protocol: u8,
    pub padding: bool,
}

async fn skip_n<R: AsyncRead + Unpin + ?Sized>(reader: &mut R, mut n: usize) -> io::Result<()> {
    let mut scratch = [0u8; 4096];
    while n > 0 {
        let take = n.min(scratch.len());
        let (chunk, _) = scratch.split_at_mut(take);
        reader.read_exact(chunk).await?;
        n -= take;
    }
    Ok(())
}

pub async fn read_request<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<Request> {
    let mut version = [0u8; 1];
    reader.read_exact(&mut version).await?;
    if version[0] > VERSION_1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported version: {}", version[0])));
    }
    let mut protocol = [0u8; 1];
    reader.read_exact(&mut protocol).await?;
    let mut padding = false;
    if version[0] == VERSION_1 {
        let mut padding_byte = [0u8; 1];
        reader.read_exact(&mut padding_byte).await?;
        padding = padding_byte[0] != 0;
        if padding {
            let mut padding_len = [0u8; 2];
            reader.read_exact(&mut padding_len).await?;
            skip_n(reader, u16::from_be_bytes(padding_len) as usize).await?;
        }
    }
    Ok(Request { version: version[0], protocol: protocol[0], padding })
}

#[must_use]
pub fn encode_request(request: Request, payload: &[u8]) -> Vec<u8> {
    let mut buffer = vec![request.version, request.protocol];
    if request.version == VERSION_1 {
        buffer.push(u8::from(request.padding));
        if request.padding {
            let padding_len: u16 = 256 + rand::rng().random_range(0..512);
            buffer.extend_from_slice(&padding_len.to_be_bytes());
            buffer.resize(buffer.len() + padding_len as usize, 0);
        }
    }
    buffer.extend_from_slice(payload);
    buffer
}

const FLAG_UDP: u16 = 1;
const FLAG_ADDR: u16 = 2;
pub const STATUS_SUCCESS: u8 = 0;
pub const STATUS_ERROR: u8 = 1;

/// The two networks a mux stream request carries: TCP or UDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamNetwork {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
pub struct StreamRequest {
    pub network: StreamNetwork,
    pub destination: Socksaddr,
    pub packet_addr: bool,
}

pub(crate) async fn read_addr_port<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<Socksaddr> {
    let mut family = [0u8; 1];
    reader.read_exact(&mut family).await?;
    let mut addr = match family[0] {
        0x01 => {
            let mut b = [0u8; 4];
            reader.read_exact(&mut b).await?;
            Socksaddr::from_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(b)), 0)
        }
        0x04 => {
            let mut b = [0u8; 16];
            reader.read_exact(&mut b).await?;
            Socksaddr::from_ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(b)), 0).unwrap()
        }
        0x03 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            let mut fqdn = vec![0u8; len[0] as usize];
            reader.read_exact(&mut fqdn).await?;
            parse_socksaddr_host_port(&String::from_utf8_lossy(&fqdn), 0)
        }
        other => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown address family: {other}")));
        }
    };
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await?;
    addr.port = u16::from_be_bytes(port);
    Ok(addr)
}

pub async fn read_stream_request<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<StreamRequest> {
    let mut flags = [0u8; 2];
    reader.read_exact(&mut flags).await?;
    let flags = u16::from_be_bytes(flags);
    let destination = read_addr_port(reader).await?;
    let (network, packet_addr) =
        if flags & FLAG_UDP == 0 { (StreamNetwork::Tcp, false) } else { (StreamNetwork::Udp, flags & FLAG_ADDR != 0) };
    Ok(StreamRequest { network, destination, packet_addr })
}

/// Writes into `buffer` at its current write position; call sites pre-size the buffer via
/// [`stream_request_len`].
pub fn encode_stream_request(request: &StreamRequest, buffer: &mut Vec<u8>) -> io::Result<()> {
    let mut dest = request.destination.clone();
    let mut flags: u16 = 0;
    if request.network == StreamNetwork::Udp {
        flags |= FLAG_UDP;
    }
    if request.packet_addr {
        flags |= FLAG_ADDR;
        if !dest.is_valid() {
            dest = destination();
        }
    }
    buffer.extend_from_slice(&flags.to_be_bytes());
    SOCKSADDR_SERIALIZER.write_addr_port(buffer, &dest)
}

pub fn stream_request_len(request: &StreamRequest) -> usize {
    2 + SOCKSADDR_SERIALIZER.addr_port_len(&request.destination)
}

#[derive(Clone, Debug)]
pub struct StreamResponse {
    pub status: u8,
    pub message: String,
}

async fn read_vstring<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<String> {
    let mut len = [0u8; 1];
    reader.read_exact(&mut len).await?;
    let mut bytes = vec![0u8; len[0] as usize];
    reader.read_exact(&mut bytes).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub async fn read_stream_response<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<StreamResponse> {
    let mut status = [0u8; 1];
    reader.read_exact(&mut status).await?;
    let message = if status[0] == STATUS_ERROR { read_vstring(reader).await? } else { String::new() };
    Ok(StreamResponse { status: status[0], message })
}

/// Writes a length-prefixed string, used by [`crate::brutal`] and the
/// server-side handshake-failure path.
pub fn write_vstring(buffer: &mut Vec<u8>, s: &str) {
    debug_assert!(u8::try_from(s.len()).is_ok(), "sing-mux vstring longer than a byte can address");
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the vstring length is a single byte on the wire; the `debug_assert!` above pins the invariant in debug builds"
    )]
    buffer.push(s.len() as u8);
    buffer.extend_from_slice(s.as_bytes());
}
