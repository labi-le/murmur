//! The IP-level parse and re-encapsulation the TUN device needs.
//!
//! A TUN device is a layer-3 pipe: every read is a whole IP packet and every write is a whole IP
//! packet, so unlike a stream listener there is no framing to carry and no connection to hand to
//! the tunnel. A datagram becomes a per-packet [`murmur_constant::adapters::UDPPacket`] whose
//! `write_back` rebuilds the IP and UDP headers around the reply payload, and the ICMP path
//! answers in the same place.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::Result;
use async_trait::async_trait;

use murmur_constant::adapters::{UDPPacket, WriteBack};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
const IPPROTO_FRAGMENT: u8 = 44;
const IPV6_FRAGMENT_HEADER_LEN: usize = 8;

/// IPv6 extension header walking stops here: with one of these next, the transport header is not at
/// a fixed offset, so the packet is carried as `Other` rather than parsed on a guess.
const IPV6_UNPARSED_NEXT_HEADERS: [u8; 4] = [0, 43, 44, 60];

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_DEST_UNREACH_CODE: u8 = 3;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMPV6_DEST_UNREACH: u8 = 1;
/// ICMPv6 code 4 is "port unreachable"; IPv6 has no separate type for it.
const ICMPV6_PORT_UNREACH_CODE: u8 = 4;

const UDP_HEADER_LEN: usize = 8;

/// RFC 9293's control bits: the second byte of a TCP header after its ports.
const TCP_FLAG_SYN: u8 = 0x02;

/// Where the checksum field ends in any ICMP message, so a truncated one is refused rather than
/// written past.
const ICMP_CHECKSUM_END: usize = 4;

/// Why a packet read off the device could not be turned into a datagram. Each variant is a shape a
/// sender can put on the wire, so they are counted and reported rather than silently dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    Version,
    HeaderLength,
    TotalLength,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooShort => "shorter than its own headers",
            Self::Version => "not an IPv4 or IPv6 packet",
            Self::HeaderLength => "header length field out of range",
            Self::TotalLength => "total length field out of range",
        })
    }
}

impl std::error::Error for ParseError {}

/// The source and destination of one flow, which is what a reply has to be addressed back to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// A TCP or UDP header's ports plus the transport payload after them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramPayload<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// What sits behind the IP header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport<'a> {
    Udp(DatagramPayload<'a>),
    Tcp(DatagramPayload<'a>),
    /// `message` is the ICMP message as it was sent; its first byte is the type named beside it.
    Icmp {
        icmp_type: u8,
        message: &'a [u8],
    },
    /// ICMPv6, carrying the same layout as [`Transport::Icmp`].
    IcmpV6 {
        icmp_type: u8,
        message: &'a [u8],
    },
    /// A protocol this crate has no handler for; answered as unreachable rather than forwarded.
    Other {
        protocol: u8,
    },
}

impl Transport<'_> {
    #[must_use]
    pub fn protocol(&self) -> u8 {
        match *self {
            Self::Udp(_) => IPPROTO_UDP,
            Self::Tcp(_) => IPPROTO_TCP,
            Self::Icmp { .. } => IPPROTO_ICMP,
            Self::IcmpV6 { .. } => IPPROTO_ICMPV6,
            Self::Other { protocol } => protocol,
        }
    }

    /// Whether this is a TCP segment opening a connection, which is the only packet the stack
    /// needs a port armed for before it sees it.
    #[must_use]
    pub fn carries_syn(&self) -> bool {
        match *self {
            Self::Tcp(tcp) => tcp.payload.get(9).is_some_and(|flags| flags & TCP_FLAG_SYN != 0),
            Self::Udp(_) | Self::Icmp { .. } | Self::IcmpV6 { .. } | Self::Other { .. } => false,
        }
    }
}

/// One packet read off the TUN device.
#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub transport: Transport<'a>,
    /// Bytes the IP header occupies, needed to build an ICMP error body that quotes the packet.
    pub header_len: usize,
    /// The length the sender declared, so a quotation stops where the packet it quotes does.
    pub total_len: usize,
}

/// The header parse the listeners perform before a flow reaches the handler.
///
/// Only enough of each header is read to address a reply and name the transport; a transport
/// payload this crate does not understand is kept as `Other` rather than failing the whole packet,
/// because the ICMP error path still has to quote it.
pub fn parse(packet: &[u8]) -> Result<Packet<'_>, ParseError> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => parse_ipv4(packet),
        Some(6) => parse_ipv6(packet),
        _ => Err(ParseError::Version),
    }
}

fn parse_ipv4(packet: &[u8]) -> Result<Packet<'_>, ParseError> {
    let header_len = usize::from(packet.first().ok_or(ParseError::TooShort)? & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return Err(ParseError::HeaderLength);
    }
    let header = packet.first_chunk::<20>().ok_or(ParseError::HeaderLength)?;
    let [_, _, len_hi, len_lo, .., protocol, _, _, s0, s1, s2, s3, d0, d1, d2, d3] = *header;
    let total_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    if total_len < header_len || total_len > packet.len() {
        return Err(ParseError::TotalLength);
    }
    let src = IpAddr::V4(Ipv4Addr::new(s0, s1, s2, s3));
    let dst = IpAddr::V4(Ipv4Addr::new(d0, d1, d2, d3));
    let body = packet.get(header_len..total_len).ok_or(ParseError::TotalLength)?;
    Ok(Packet { src, dst, transport: parse_transport(protocol, body), header_len, total_len })
}

fn parse_ipv6(packet: &[u8]) -> Result<Packet<'_>, ParseError> {
    let Some(header) = packet.first_chunk::<40>() else {
        return Err(ParseError::TooShort);
    };
    let [_, _, _, _, len_hi, len_lo, protocol, _, ..] = *header;
    let total_len = 40 + usize::from(u16::from_be_bytes([len_hi, len_lo]));
    if total_len > packet.len() {
        return Err(ParseError::TotalLength);
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(header.get(8..24).ok_or(ParseError::TooShort)?);
    dst.copy_from_slice(header.get(24..40).ok_or(ParseError::TooShort)?);
    let body = packet.get(40..total_len).ok_or(ParseError::TotalLength)?;
    let transport = if IPV6_UNPARSED_NEXT_HEADERS.contains(&protocol) {
        Transport::Other { protocol }
    } else {
        parse_transport(protocol, body)
    };
    Ok(Packet {
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        transport,
        header_len: 40,
        total_len,
    })
}

fn parse_transport(protocol: u8, body: &[u8]) -> Transport<'_> {
    match protocol {
        IPPROTO_UDP => match parse_udp(body) {
            Ok(payload) => Transport::Udp(payload),
            Err(()) => Transport::Other { protocol },
        },
        IPPROTO_TCP => match parse_ports(body) {
            Some(payload) => Transport::Tcp(payload),
            None => Transport::Other { protocol },
        },
        IPPROTO_ICMP => match body.split_first() {
            Some((icmp_type, _)) => Transport::Icmp { icmp_type: *icmp_type, message: body },
            None => Transport::Other { protocol },
        },
        IPPROTO_ICMPV6 => match body.split_first() {
            Some((icmp_type, _)) => Transport::IcmpV6 { icmp_type: *icmp_type, message: body },
            None => Transport::Other { protocol },
        },
        _ => Transport::Other { protocol },
    }
}

fn parse_ports(body: &[u8]) -> Option<DatagramPayload<'_>> {
    let [src_hi, src_lo, dst_hi, dst_lo, ..] = body else {
        return None;
    };
    Some(DatagramPayload {
        src_port: u16::from_be_bytes([*src_hi, *src_lo]),
        dst_port: u16::from_be_bytes([*dst_hi, *dst_lo]),
        payload: body.get(4..).unwrap_or_default(),
    })
}

fn parse_udp(body: &[u8]) -> Result<DatagramPayload<'_>, ()> {
    let [src, dst, lo, hi, len_lo, len_hi, ..] = body else { return Err(()) };
    let udp_len = usize::from(u16::from_be_bytes([*len_lo, *len_hi]));
    if udp_len < UDP_HEADER_LEN || udp_len > body.len() {
        return Err(());
    }
    let payload = body.get(UDP_HEADER_LEN..udp_len).ok_or(())?;
    Ok(DatagramPayload {
        src_port: u16::from_be_bytes([*src, *dst]),
        dst_port: u16::from_be_bytes([*lo, *hi]),
        payload,
    })
}

/// The Internet checksum of RFC 1071.
pub(crate) fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let mut chunks = part.chunks_exact(2);
        for chunk in &mut chunks {
            let [hi, lo] = chunk else { break };
            sum += u32::from(u16::from_be_bytes([*hi, *lo]));
        }
        if let [last] = chunks.remainder() {
            sum += u32::from(u16::from_be_bytes([*last, 0]));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the fold above leaves the sum below 0x10000, so its low half is the whole value"
    )]
    let folded = sum as u16;
    !folded
}

/// The IPv4 header a reply from `src` to `dst` carries, with the transport checksum already
/// written into `payload`'s own checksum field.
fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload_len: usize) -> Vec<u8> {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the IPv4 total-length field is 16 bits, so the protocol cannot express a longer datagram"
    )]
    let total_len = (20 + payload_len) as u16;
    let src_octets = src.octets();
    let dst_octets = dst.octets();
    let mut header = Vec::with_capacity(20);
    header.extend_from_slice(&[0x45, 0]);
    header.extend_from_slice(&total_len.to_be_bytes());
    header.extend_from_slice(&[0, 0, 0, 0, 64, protocol]);
    let csum = checksum(&[&header, &[0u8, 0], &src_octets, &dst_octets]);
    header.extend_from_slice(&csum.to_be_bytes());
    header.extend_from_slice(&src_octets);
    header.extend_from_slice(&dst_octets);
    header
}

fn build_ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload_len: usize) -> Vec<u8> {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the IPv6 payload-length field is 16 bits, so the protocol cannot express a longer datagram"
    )]
    let payload_len = payload_len as u16;
    let mut header = Vec::with_capacity(40);
    header.extend_from_slice(&[0x60, 0, 0, 0]);
    header.extend_from_slice(&payload_len.to_be_bytes());
    header.extend_from_slice(&[next_header, 64]);
    header.extend_from_slice(&src.octets());
    header.extend_from_slice(&dst.octets());
    header
}

/// The IPv4 or IPv6 pseudo-header, which the transport checksum covers but which is not
/// transmitted.
fn pseudo_header(src: IpAddr, dst: IpAddr, protocol: u8, payload_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            out.push(0);
            out.push(protocol);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the IPv4 pseudo-header length field is 16 bits, so the protocol cannot express a longer datagram"
            )]
            let payload_len = payload_len as u16;
            out.extend_from_slice(&payload_len.to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the IPv6 pseudo-header length field is 32 bits, so the protocol cannot express a longer datagram"
            )]
            let payload_len = payload_len as u32;
            out.extend_from_slice(&payload_len.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0, protocol]);
        }
        _ => return out,
    }
    out
}

/// The checksum an ICMP message carries: the Internet checksum over the message with its own
/// checksum field zeroed, plus the pseudo-header RFC 4443 requires of ICMPv6 and IPv4 has none of.
fn icmp_checksum(message: &mut [u8], src: IpAddr, dst: IpAddr, protocol: u8) -> u16 {
    if let Some(checksum_field) = message.get_mut(2..4) {
        checksum_field.copy_from_slice(&[0, 0]);
    }
    let message: &[u8] = message;
    if protocol == IPPROTO_ICMPV6 {
        checksum(&[&pseudo_header(src, dst, protocol, message.len()), message])
    } else {
        checksum(&[message])
    }
}

/// A full IPv4 or IPv6 datagram carrying `payload` as the UDP body of a reply.
///
/// The reply is addressed from `flow.dst` to `flow.src`, the inverse of the request [`parse`] saw.
/// The checksum is real: the device hands this straight to the kernel's network stack, which drops
/// a bad one.
#[must_use]
pub fn udp_reply(flow: &Flow, payload: &[u8]) -> Vec<u8> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the UDP length field is 16 bits, so the protocol cannot express a longer datagram"
    )]
    let length_field = udp_len as u16;
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&flow.dst_port.to_be_bytes());
    udp.extend_from_slice(&flow.src_port.to_be_bytes());
    udp.extend_from_slice(&length_field.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    // RFC 768's -0 stands in for the checksum field, which means "not computed" on IPv4 and is an
    // illegal value on IPv6, where UDP carries a mandatory one.
    let csum = match checksum(&[&pseudo_header(flow.dst, flow.src, IPPROTO_UDP, udp_len), &udp]) {
        0 => 0xffff,
        csum => csum,
    };
    if let Some(checksum_field) = udp.get_mut(6..8) {
        checksum_field.copy_from_slice(&csum.to_be_bytes());
    }
    encapsulate(flow.dst, flow.src, IPPROTO_UDP, &udp)
}

fn encapsulate(src: IpAddr, dst: IpAddr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => build_ipv4(s, d, protocol, payload.len()),
        (IpAddr::V6(s), IpAddr::V6(d)) => build_ipv6(s, d, protocol, payload.len()),
        _ => return Vec::new(),
    };
    out.extend_from_slice(payload);
    out
}

/// The echo reply the stack synthesises when an ICMP echo is not routed out.
///
/// It is the same message with the type flipped, re-checksummed and sent back from the address
/// that was pinged.
#[must_use]
pub fn icmp_echo_reply(request: &[u8], packet: &Packet<'_>) -> Option<Vec<u8>> {
    let (reply_type, message) = match packet.transport {
        Transport::Icmp { icmp_type: ICMP_ECHO_REQUEST, message } => (ICMP_ECHO_REPLY, message),
        Transport::IcmpV6 { icmp_type: ICMPV6_ECHO_REQUEST, message } => (ICMPV6_ECHO_REPLY, message),
        Transport::Udp(_)
        | Transport::Tcp(_)
        | Transport::Other { .. }
        | Transport::Icmp { .. }
        | Transport::IcmpV6 { .. } => return None,
    };
    // A message with no room for the checksum field is a sender that cannot be answered, not one
    // to be answered badly: the type alone still parses as an echo request.
    let mut icmp = request.get(packet.header_len..packet.header_len + message.len())?.to_vec();
    if icmp.len() < ICMP_CHECKSUM_END {
        return None;
    }
    *icmp.first_mut()? = reply_type;
    let protocol = packet.transport.protocol();
    let csum = icmp_checksum(&mut icmp, packet.dst, packet.src, protocol);
    if let Some(checksum_field) = icmp.get_mut(2..4) {
        checksum_field.copy_from_slice(&csum.to_be_bytes());
    }
    Some(encapsulate(packet.dst, packet.src, protocol, &icmp))
}

/// The ICMP error a host sends for a transport it cannot reach.
///
/// Port-unreachable over IPv4, destination-unreachable over IPv6 (which has no port-unreachable
/// type), quoting the offending IP header and the first 8 octets of its payload.
#[must_use]
pub fn icmp_unreachable(request: &[u8], packet: &Packet<'_>) -> Option<Vec<u8>> {
    let ipv6 = packet.src.is_ipv6();
    let (protocol, icmp_type, code) = if ipv6 {
        (IPPROTO_ICMPV6, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH_CODE)
    } else {
        (IPPROTO_ICMP, ICMP_DEST_UNREACH, ICMP_DEST_UNREACH_CODE)
    };
    let quoted_len = (packet.header_len + 8).min(packet.total_len);
    let mut icmp = vec![icmp_type, code, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(request.get(..quoted_len)?);
    let csum = icmp_checksum(&mut icmp, packet.dst, packet.src, protocol);
    if let Some(checksum_field) = icmp.get_mut(2..4) {
        checksum_field.copy_from_slice(&csum.to_be_bytes());
    }
    Some(encapsulate(packet.dst, packet.src, protocol, &icmp))
}

/// Identifies the IPv6 fragments of one reply; the field only has to differ from other datagrams
/// in flight between the same pair of addresses.
static NEXT_FRAGMENT_ID: AtomicU32 = AtomicU32::new(1);

/// Splits an IPv6 reply into fragments that fit `mtu`.
///
/// A TUN write enters the kernel as an incoming packet on a forwarding path. IPv4 can be
/// fragmented there, but an IPv6 router must send Packet Too Big instead, so a reply larger than
/// the interface MTU has to leave this code already fragmented.
fn ipv6_reply_fragments(packet: &[u8], mtu: u16) -> Option<Vec<Vec<u8>>> {
    let header = packet.first_chunk::<40>()?;
    if header[0] >> 4 != 6 || packet.len() <= usize::from(mtu) {
        return None;
    }
    let chunk = (usize::from(mtu).saturating_sub(40 + IPV6_FRAGMENT_HEADER_LEN)) & !7;
    if chunk < 8 {
        return None;
    }
    let fragmentable = packet.get(40..)?;
    let id = NEXT_FRAGMENT_ID.fetch_add(1, Ordering::Relaxed);
    let mut fragments = Vec::new();
    let mut offset = 0;
    while offset < fragmentable.len() {
        let end = offset.saturating_add(chunk).min(fragmentable.len());
        let more = end < fragmentable.len();
        let payload_len = u16::try_from(IPV6_FRAGMENT_HEADER_LEN + end - offset).ok()?;
        let mut fragment = Vec::with_capacity(40 + usize::from(payload_len));
        let mut header = *header;
        header[4..6].copy_from_slice(&payload_len.to_be_bytes());
        header[6] = IPPROTO_FRAGMENT;
        fragment.extend_from_slice(&header);
        let offset_field = u16::try_from(offset / 8).ok()?.checked_shl(3)? | u16::from(more);
        fragment.extend_from_slice(&[IPPROTO_UDP, 0]);
        fragment.extend_from_slice(&offset_field.to_be_bytes());
        fragment.extend_from_slice(&id.to_be_bytes());
        fragment.extend_from_slice(fragmentable.get(offset..end)?);
        fragments.push(fragment);
        offset = end;
    }
    Some(fragments)
}

/// The write half of the TUN device, split out so a packet can be answered from a NAT worker
/// without owning the reader.
#[async_trait]
pub trait DeviceWriter: Send + Sync {
    async fn write_packet(&self, packet: &[u8]) -> std::io::Result<()>;
}

/// The per-datagram `UDPPacket` one TUN read hands to the tunnel.
///
/// `local_addr` is the destination the sender addressed, which is what the UDP NAT table is keyed
/// on; `in_addr` is the TUN's own address, the interface the packet physically arrived on.
pub struct TunPacket {
    writer: std::sync::Arc<dyn DeviceWriter>,
    flow: Flow,
    payload: Vec<u8>,
    tun_addr: IpAddr,
    mtu: u16,
}

impl std::fmt::Debug for TunPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunPacket")
            .field("flow", &self.flow)
            .field("payload_len", &self.payload.len())
            .field("tun_addr", &self.tun_addr)
            .finish_non_exhaustive()
    }
}

impl TunPacket {
    pub fn new(
        writer: std::sync::Arc<dyn DeviceWriter>,
        flow: Flow,
        payload: Vec<u8>,
        tun_addr: IpAddr,
        mtu: u16,
    ) -> Self {
        Self { writer, flow, payload, tun_addr, mtu }
    }
}

impl UDPPacket for TunPacket {
    fn data(&self) -> &[u8] {
        &self.payload
    }

    /// the `Drop` returns the buffer to sing's pool; the payload here is already a private
    /// `Vec` that the drop frees, so there is nothing to return.
    fn drop_(&self) {}

    fn local_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.flow.dst, self.flow.dst_port)
    }

    fn in_addr(&self) -> Option<std::net::SocketAddr> {
        Some(std::net::SocketAddr::new(self.tun_addr, 0))
    }
}

#[async_trait]
impl WriteBack for TunPacket {
    /// The write-back targets the address the datagram came from; here that means
    /// rebuilding the IP and UDP headers around the payload and handing the packet back to the
    /// device. The `addr` argument carries the reply's real source, which a NAT table may have
    /// rewritten, and only equals the request's destination for an unrewritten session.
    async fn write_back(&self, b: &[u8], addr: Option<std::net::SocketAddr>) -> Result<usize> {
        let (source, source_port) = addr.map_or((self.flow.dst, self.flow.dst_port), |addr| (addr.ip(), addr.port()));
        let reply = udp_reply(&Flow { dst: source, dst_port: source_port, ..self.flow }, b);
        if self.flow.src.is_ipv6() {
            if let Some(fragments) = ipv6_reply_fragments(&reply, self.mtu) {
                for fragment in fragments {
                    self.writer.write_packet(&fragment).await?;
                }
                return Ok(b.len());
            }
        }
        self.writer.write_packet(&reply).await?;
        Ok(b.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn v4_udp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let mut out = build_ipv4(src, dst, IPPROTO_UDP, udp_len);
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        out.extend_from_slice(&(udp_len as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(payload);
        out
    }

    fn v4_icmp(src: Ipv4Addr, dst: Ipv4Addr, icmp_type: u8, body: &[u8]) -> Vec<u8> {
        let mut icmp = vec![icmp_type, 0, 0, 0, 0x12, 0x34, 0, 1];
        icmp.extend_from_slice(body);
        let csum = checksum(&[&icmp]);
        icmp[2..4].copy_from_slice(&csum.to_be_bytes());
        let mut out = build_ipv4(src, dst, IPPROTO_ICMP, icmp.len());
        out.extend_from_slice(&icmp);
        out
    }

    fn v4_tcp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut out = build_ipv4(src, dst, IPPROTO_TCP, 20);
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 2, 0, 0, 0, 0, 0, 0]);
        out
    }

    /// A message carrying the right checksum folds to zero over the whole message, field included,
    /// so this validates the field without recomputing what it should hold.
    fn assert_checksum_valid(parts: &[&[u8]]) {
        assert_eq!(checksum(parts), 0);
    }

    #[test]
    fn parse_reads_an_ipv4_udp_datagram_end_to_end() {
        let raw = v4_udp(v4(10, 0, 0, 2), v4(198, 18, 0, 1), 5353, 53, b"query");
        let parsed = parse(&raw).expect("parse");
        assert_eq!(parsed.src, IpAddr::V4(v4(10, 0, 0, 2)));
        assert_eq!(parsed.dst, IpAddr::V4(v4(198, 18, 0, 1)));
        let Transport::Udp(udp) = parsed.transport else { panic!("expected udp") };
        assert_eq!((udp.src_port, udp.dst_port), (5353, 53));
        assert_eq!(udp.payload, b"query");
    }

    #[test]
    fn parse_reads_an_ipv4_tcp_flow() {
        let raw = v4_tcp(v4(10, 0, 0, 2), v4(198, 18, 0, 1), 1234, 443);
        let parsed = parse(&raw).expect("parse");
        let Transport::Tcp(tcp) = parsed.transport else { panic!("expected tcp") };
        assert_eq!((tcp.src_port, tcp.dst_port), (1234, 443));
    }

    /// A TUN read is one whole packet, but a sender can hand the device fewer bytes than its own
    /// total-length field claims. The trailing bytes must not be mistaken for payload.
    #[test]
    fn parse_ignores_bytes_past_the_ipv4_total_length() {
        let mut raw = v4_udp(v4(10, 0, 0, 2), v4(198, 18, 0, 1), 1, 2, b"ab");
        raw.extend_from_slice(b"trailing");
        let Transport::Udp(udp) = parse(&raw).expect("parse").transport else { panic!("udp") };
        assert_eq!(udp.payload, b"ab");
    }

    #[test]
    fn parse_rejects_lengths_that_do_not_fit_the_packet() {
        let mut raw = v4_udp(v4(10, 0, 0, 2), v4(198, 18, 0, 1), 1, 2, b"ab");
        raw[3] = 0xff;
        assert_eq!(parse(&raw).err(), Some(ParseError::TotalLength));

        let mut raw = v4_udp(v4(10, 0, 0, 2), v4(198, 18, 0, 1), 1, 2, b"ab");
        raw[0] = 0x4f;
        assert_eq!(parse(&raw).err(), Some(ParseError::HeaderLength));

        assert_eq!(parse(&[0x45]).err(), Some(ParseError::HeaderLength));
        assert_eq!(parse(&[0x00; 20]).err(), Some(ParseError::Version));
    }

    /// A UDP length field that overruns its packet would otherwise slice out of bounds; the
    /// transport degrades to `Other` so the packet can still be answered with an ICMP error.
    #[test]
    fn a_udp_length_past_the_packet_degrades_instead_of_slicing() {
        let mut raw = v4_udp(v4(10, 0, 0, 2), v4(198, 18, 0, 1), 1, 2, b"ab");
        raw[24..26].copy_from_slice(&40u16.to_be_bytes());
        assert_eq!(parse(&raw).expect("parse").transport, Transport::Other { protocol: IPPROTO_UDP });
    }

    #[test]
    fn parse_reads_an_ipv6_udp_datagram_end_to_end() {
        let src = "fd00::2".parse::<Ipv6Addr>().unwrap();
        let dst = "fd00::1".parse::<Ipv6Addr>().unwrap();
        let payload = b"six";
        let udp_len = UDP_HEADER_LEN + payload.len();
        let mut raw = build_ipv6(src, dst, IPPROTO_UDP, udp_len);
        raw.extend_from_slice(&5353u16.to_be_bytes());
        raw.extend_from_slice(&53u16.to_be_bytes());
        raw.extend_from_slice(&(udp_len as u16).to_be_bytes());
        raw.extend_from_slice(&[0, 0]);
        raw.extend_from_slice(payload);
        let parsed = parse(&raw).expect("parse");
        assert_eq!(parsed.src, IpAddr::V6(src));
        let Transport::Udp(udp) = parsed.transport else { panic!("expected udp") };
        assert_eq!(udp.payload, payload);
    }

    /// The reply the device hands back to the kernel has to be a valid packet, checksum included,
    /// and has to invert the request's addresses and ports.
    #[test]
    fn udp_reply_is_a_checksum_valid_inverse_datagram() {
        let flow = Flow { src: v4(10, 0, 0, 2).into(), dst: v4(198, 18, 0, 1).into(), src_port: 5353, dst_port: 53 };
        let reply = udp_reply(&flow, b"answer");
        let parsed = parse(&reply).expect("reply parses");
        assert_eq!(parsed.src, flow.dst);
        assert_eq!(parsed.dst, flow.src);
        let Transport::Udp(udp) = parsed.transport else { panic!("expected udp") };
        assert_eq!((udp.src_port, udp.dst_port), (53, 5353));
        assert_eq!(udp.payload, b"answer");

        let udp_len = UDP_HEADER_LEN + b"answer".len();
        assert_checksum_valid(&[&reply[..20]]);
        assert_checksum_valid(&[&pseudo_header(flow.dst, flow.src, IPPROTO_UDP, udp_len), &reply[20..]]);
    }

    #[test]
    fn udp_reply_over_ipv6_carries_the_mandatory_checksum() {
        let flow =
            Flow { src: "fd00::2".parse().unwrap(), dst: "fd00::1".parse().unwrap(), src_port: 5353, dst_port: 53 };
        let reply = udp_reply(&flow, b"six");
        assert_eq!(reply[0] >> 4, 6);
        let Transport::Udp(udp) = parse(&reply).expect("reply parses").transport else { panic!("udp") };
        assert_eq!(udp.payload, b"six");
        let udp_len = UDP_HEADER_LEN + 3;
        assert_ne!(u16::from_be_bytes([reply[46], reply[47]]), 0);
        assert_checksum_valid(&[&pseudo_header(flow.dst, flow.src, IPPROTO_UDP, udp_len), &reply[40..]]);
    }

    /// A ping aimed at the TUN's own range is answered with a synthesised echo reply rather than
    /// forwarded, so the type flips and the identity the client chose survives.
    #[test]
    fn icmp_echo_reply_flips_the_type_and_returns_the_identity() {
        let raw = v4_icmp(v4(198, 18, 0, 1), v4(198, 18, 0, 2), ICMP_ECHO_REQUEST, b"ping");
        let packet = parse(&raw).expect("parse");
        let reply = icmp_echo_reply(&raw, &packet).expect("echo reply");
        let parsed = parse(&reply).expect("reply parses");
        assert_eq!(parsed.src, packet.dst);
        assert_eq!(parsed.dst, packet.src);
        let Transport::Icmp { icmp_type, message } = parsed.transport else { panic!("icmp") };
        assert_eq!(icmp_type, ICMP_ECHO_REPLY);
        assert_eq!(&message[4..8], &[0x12, 0x34, 0, 1]);
        assert_eq!(&message[8..], b"ping");
        assert_checksum_valid(&[&reply[20..]]);
    }

    #[test]
    fn icmp_echo_reply_answers_an_icmpv6_request_under_next_header_58() {
        let mut icmp = vec![ICMPV6_ECHO_REQUEST, 0, 0, 0, 0x12, 0x34, 0, 1];
        icmp.extend_from_slice(b"ping6");
        let mut raw = build_ipv6("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap(), IPPROTO_ICMPV6, icmp.len());
        raw.extend_from_slice(&icmp);
        let packet = parse(&raw).expect("parse");
        let reply = icmp_echo_reply(&raw, &packet).expect("echo reply");
        assert_eq!(reply[6], IPPROTO_ICMPV6);
        let Transport::IcmpV6 { icmp_type, .. } = parse(&reply).expect("parses").transport else { panic!("icmpv6") };
        assert_eq!(icmp_type, ICMPV6_ECHO_REPLY);
        assert_checksum_valid(&[
            &pseudo_header(packet.dst, packet.src, IPPROTO_ICMPV6, reply.len() - 40),
            &reply[40..],
        ]);
    }

    #[test]
    fn icmp_echo_reply_ignores_a_non_echo_request() {
        let raw = v4_icmp(v4(198, 18, 0, 1), v4(198, 18, 0, 2), ICMP_DEST_UNREACH, b"nope");
        let packet = parse(&raw).expect("parse");
        assert!(icmp_echo_reply(&raw, &packet).is_none());
    }

    /// A TCP flow the TUN cannot carry is answered the way a host answers a closed port, so the
    /// client's connect fails fast instead of retransmitting a SYN into a black hole.
    #[test]
    fn icmp_unreachable_reports_port_unreachable_and_quotes_the_request() {
        let request = v4_tcp(v4(10, 0, 0, 2), v4(198, 18, 0, 1), 1234, 443);
        let packet = parse(&request).expect("parse");
        let reply = icmp_unreachable(&request, &packet).expect("unreachable");
        let parsed = parse(&reply).expect("reply parses");
        assert_eq!(parsed.src, packet.dst);
        let Transport::Icmp { icmp_type, message } = parsed.transport else { panic!("icmp") };
        assert_eq!((icmp_type, message[1]), (ICMP_DEST_UNREACH, ICMP_DEST_UNREACH_CODE));
        assert_eq!(&message[8..28], &request[..20]);
        assert_eq!(&message[28..], &request[20..28]);
        assert_checksum_valid(&[&reply[20..]]);
    }

    #[test]
    fn icmp_unreachable_over_ipv6_uses_destination_unreachable_and_next_header_58() {
        let flow =
            Flow { src: "fd00::2".parse().unwrap(), dst: "fd00::1".parse().unwrap(), src_port: 1234, dst_port: 443 };
        let request = udp_reply(&flow, b"payload");
        let packet = parse(&request).expect("parse");
        let reply = icmp_unreachable(&request, &packet).expect("unreachable");
        assert_eq!(reply[6], IPPROTO_ICMPV6);
        let Transport::IcmpV6 { icmp_type, message } = parse(&reply).expect("parses").transport else {
            panic!("icmpv6")
        };
        assert_eq!((icmp_type, message[1]), (ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH_CODE));
        assert_checksum_valid(&[
            &pseudo_header(packet.dst, packet.src, IPPROTO_ICMPV6, reply.len() - 40),
            &reply[40..],
        ]);
    }

    /// The error quotes the request as the sender sent it, so it has to survive a payload shorter
    /// than the 8 octets the quotation asks for.
    #[test]
    fn icmp_unreachable_truncates_the_quotation_to_what_the_packet_holds() {
        let mut request = v4_udp(v4(10, 0, 0, 2), v4(198, 18, 0, 1), 1, 2, b"ab");
        request[2] = 0;
        request[3] = 22;
        let packet = parse(&request).expect("parse");
        let reply = icmp_unreachable(&request, &packet).expect("unreachable");
        let Transport::Icmp { message, .. } = parse(&reply).expect("parses").transport else { panic!("icmp") };
        assert_eq!(message.len(), 8 + 22);
    }

    /// A packet behind an extension header chain is carried whole: the transport header is not at
    /// a fixed offset, so guessing would misread the flow.
    #[test]
    fn ipv6_replies_above_the_mtu_are_fragmented_before_the_device_write() {
        let client = "fd00::2".parse::<Ipv6Addr>().unwrap();
        let server = "fd00:1::2".parse::<Ipv6Addr>().unwrap();
        let flow = Flow { src: client.into(), dst: server.into(), src_port: 51261, dst_port: 18081 };
        let payload = vec![0x5au8; 4000];
        let reply = udp_reply(&flow, &payload);
        let fragments = ipv6_reply_fragments(&reply, 1500).expect("the reply needs fragmentation");
        assert!(fragments.len() > 1);
        let mut assembled = Vec::new();
        let mut next_offset = 0;
        for (index, fragment) in fragments.iter().enumerate() {
            assert!(fragment.len() <= 1500, "fragment {} is {} bytes", index, fragment.len());
            assert_eq!(fragment[0] >> 4, 6);
            assert_eq!(fragment[6], IPPROTO_FRAGMENT);
            assert_eq!(fragment[40], IPPROTO_UDP);
            let field = u16::from_be_bytes([fragment[42], fragment[43]]);
            let offset = usize::from((field >> 3) & 0x1fff) * 8;
            let more = field & 1 != 0;
            assert_eq!(offset, next_offset);
            let data = &fragment[48..];
            if more {
                assert_eq!(data.len() % 8, 0, "a non-last fragment must end on an eight-byte boundary");
            }
            assembled.extend_from_slice(data);
            next_offset += data.len();
        }
        assert_eq!(&assembled[..2], &flow.dst_port.to_be_bytes());
        assert_eq!(&assembled[2..4], &flow.src_port.to_be_bytes());
        assert_eq!(u16::from_be_bytes([assembled[4], assembled[5]]) as usize, 8 + payload.len());
        assert_eq!(&assembled[8..], payload);
        assert!(ipv6_reply_fragments(&reply, 9000).is_none(), "a reply below the MTU stays whole");
    }

    #[test]
    fn ipv6_extension_headers_are_not_guessed_at() {
        let mut raw = build_ipv6("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap(), 44, 8);
        raw.extend_from_slice(&[0; 8]);
        assert_eq!(parse(&raw).expect("parse").transport, Transport::Other { protocol: 44 });
    }
}
