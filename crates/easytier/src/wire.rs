//! Binary wire codecs for the EasyTier WASM ABI.
//!
//! Covers the host-import ABI (`HostSocketAddress`, `SocketContext`, `bind_device`,
//! `TCPConnectOptions`/`UDPBindOptions`/`TCPListenOptions`, `TCPSocketResult`/`BoundSocketResult`,
//! `UdpMetadata`, `DNSQuery` and the DNS result encodings) and the data-plane ABI's IPv4-only
//! socket address (`DataPlaneSocketAddr`) — see `agent://EasyTier.HostAbiMap/markdown_report`
//! §4/§6/§7/§8 and `agent://EasyTier.CoreAbiMap/markdown_report` §2.3. All multi-byte integers
//! are big-endian.
//!
//! `HostSocketAddress` (host-import ABI, §4.1/§8, dual-family) and `DataPlaneSocketAddr`
//! (data-plane ABI, §2.3, IPv4-only) share a length (27 bytes) but not a layout; they are kept as
//! distinct types so neither codec is ever applied to the other's bytes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use anyhow::{anyhow, bail, ensure, Result};

use murmur_component_easytier::platform::platform::{
    DNSQuery, IPVersion, SocketContext, Srv, TCPBindOptions, TCPConnectOptions, TCPConnectPurpose, TCPListenOptions,
    TCPListenPurpose, UDPBindOptions, UDPBindPurpose,
};
use murmur_std_compat::net::{Addr, SockAddr, TcpAddr, UdpAddr};

pub const SOCKET_ADDRESS_LEN: usize = 27;
pub const TCP_SOCKET_RESULT_LEN: usize = 62;
pub const BOUND_SOCKET_RESULT_LEN: usize = 35;
pub const UDP_METADATA_LEN: usize = 48;
/// Same length as [`SOCKET_ADDRESS_LEN`], different layout; see [`DataPlaneSocketAddr`].
pub const DATA_PLANE_SOCKET_ADDR_LEN: usize = 27;

/// The byte at `offset`, or a truncation error.
fn byte_at(bytes: &[u8], offset: usize) -> Result<u8> {
    bytes.get(offset).copied().ok_or_else(|| truncated(offset, 1, bytes.len()))
}

/// The bytes of `bytes` inside `range`, or a truncation error.
fn slice_at(bytes: &[u8], range: Range<usize>) -> Result<&[u8]> {
    bytes.get(range.clone()).ok_or_else(|| truncated(range.start, range.len(), bytes.len()))
}

/// The big-endian `N`-byte field starting at `offset`, or a truncation error.
fn be_field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    Ok(slice_at(bytes, offset..offset + N)?.try_into()?)
}

fn truncated(offset: usize, len: usize, available: usize) -> anyhow::Error {
    anyhow!("wire buffer is too short: {len} bytes needed at offset {offset}, buffer is {available} bytes")
}

/// Decoded host-import socket address (§4.1): family + IP + port + IPv6 scope id. Also the
/// peer-address prefix of [`UdpMetadata`] (§8), whose first 27 bytes are this exact layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostSocketAddress {
    pub ip: IpAddr,
    pub port: u16,
    /// IPv6 zone/interface index; always 0 for IPv4 and for addresses with no zone.
    pub scope_id: u32,
}

fn host_socket_address_bytes(ip: IpAddr, port: u16, scope_id: u32) -> [u8; SOCKET_ADDRESS_LEN] {
    let mut out = [0u8; SOCKET_ADDRESS_LEN];
    match ip {
        IpAddr::V4(v4) => {
            out[0] = 4;
            out[1..5].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out[0] = 6;
            out[1..17].copy_from_slice(&v6.octets());
        }
    }
    out[17..19].copy_from_slice(&port.to_be_bytes());
    out[19..23].copy_from_slice(&0u32.to_be_bytes());
    out[23..27].copy_from_slice(&scope_id.to_be_bytes());
    out
}

/// Encodes a `SocketAddress` (§4.1) from any [`Addr`].
///
/// Only [`TcpAddr`]/[`UdpAddr`] (the two [`SockAddr`] cases) carry a resolvable IP; every other
/// `Addr` implementation encodes to the canonical all-zero absent pattern (family 0), matching
/// what [`decode_socket_address`] accepts with `optional=true`. Callers that must reject
/// unencodable addresses instead of silently producing "absent" (e.g. result encoders in §4.6)
/// go through [`require_encodable_socket_address`].
///
/// **Judgment call**: the assignment fixes this signature as infallible (`-> [u8; 27]`, no
/// `Result`), so an address with no IP (e.g. a hostname-only `Addr`) cannot be reported as an
/// error here; every real call site in this ABI only ever passes a [`TcpAddr`]/[`UdpAddr`]
/// produced by `platform::SocketFactory`/`ConnectorEnvironment`, so this fallback is unreachable
/// in practice.
pub fn encode_socket_address(addr: &dyn Addr) -> [u8; SOCKET_ADDRESS_LEN] {
    let mut out = [0u8; SOCKET_ADDRESS_LEN];
    if let Some(addr_port) = addr.addr_port() {
        if let Some(ip) = addr_port.ip {
            let scope_id = match addr.as_sock_addr() {
                Some(SockAddr::Udp(udp)) => udp.zone.parse::<u32>().unwrap_or(0),
                _ => 0,
            };
            out = host_socket_address_bytes(ip, addr_port.port, scope_id);
        }
    }
    out
}

/// Decodes a `SocketAddress` (§4.1).
///
/// `optional=true` accepts the canonical all-zero "absent" encoding (family byte 0, every other
/// byte zero) as `Ok(None)`; a family-0 encoding with any nonzero byte is rejected as
/// "noncanonical absent socket address", matching socket-address decoding. `optional=false`
/// requires family 4 or 6.
pub fn decode_socket_address(bytes: &[u8], optional: bool) -> Result<Option<HostSocketAddress>> {
    ensure!(
        bytes.len() == SOCKET_ADDRESS_LEN,
        "socket address must be {SOCKET_ADDRESS_LEN} bytes, got {}",
        bytes.len()
    );
    let family = byte_at(bytes, 0)?;
    if optional && family == 0 {
        ensure!(bytes.iter().all(|&b| b == 0), "noncanonical absent socket address");
        return Ok(None);
    }
    let flowinfo = u32::from_be_bytes(be_field::<4>(bytes, 19)?);
    ensure!(flowinfo == 0, "socket address flowinfo must be zero, got {flowinfo}");
    let port = u16::from_be_bytes(be_field::<2>(bytes, 17)?);
    let scope_id = u32::from_be_bytes(be_field::<4>(bytes, 23)?);
    let ip = match family {
        4 => {
            ensure!(slice_at(bytes, 5..17)?.iter().all(|&b| b == 0), "IPv4 socket address must zero-pad bytes 5..17");
            IpAddr::V4(Ipv4Addr::from(be_field::<4>(bytes, 1)?))
        }
        6 => IpAddr::V6(Ipv6Addr::from(be_field::<16>(bytes, 1)?)),
        other => bail!("socket address family must be 4 or 6, got {other}"),
    };
    Ok(Some(HostSocketAddress { ip, port, scope_id }))
}

/// The address encoder's type-switch (§4.6): only [`TcpAddr`]/[`UdpAddr`]-shaped addresses may be
/// reported to the guest as a socket result; anything else is a hard error (the caller then
/// closes the freshly-created handle, mirroring the cleanup-on-encode-failure contract).
fn require_encodable_socket_address(addr: &dyn Addr) -> Result<[u8; SOCKET_ADDRESS_LEN]> {
    if addr.as_sock_addr().is_none() {
        bail!("unsupported socket address {addr:?}: expected a TCP or UDP address");
    }
    Ok(encode_socket_address(addr))
}

/// `TCPSocketResult` (§4.6, 62 bytes): `[handle: u64 BE][local: SocketAddress][peer: SocketAddress]`.
pub fn encode_tcp_socket_result(handle: u64, local: &dyn Addr, peer: &dyn Addr) -> Result<[u8; TCP_SOCKET_RESULT_LEN]> {
    let local_bytes = require_encodable_socket_address(local)?;
    let peer_bytes = require_encodable_socket_address(peer)?;
    let mut out = [0u8; TCP_SOCKET_RESULT_LEN];
    out[0..8].copy_from_slice(&handle.to_be_bytes());
    out[8..35].copy_from_slice(&local_bytes);
    out[35..62].copy_from_slice(&peer_bytes);
    Ok(out)
}

/// `BoundSocketResult` (§4.6, 35 bytes): `[handle: u64 BE][local: SocketAddress]`.
pub fn encode_bound_socket_result(handle: u64, local: &dyn Addr) -> Result<[u8; BOUND_SOCKET_RESULT_LEN]> {
    let local_bytes = require_encodable_socket_address(local)?;
    let mut out = [0u8; BOUND_SOCKET_RESULT_LEN];
    out[0..8].copy_from_slice(&handle.to_be_bytes());
    out[8..35].copy_from_slice(&local_bytes);
    Ok(out)
}

/// `SocketContext` TLV (§4.4): `[ip_version: u8][mark_present: u8][mark: u32 BE][netns_present:
/// u8][netns_len: u32 BE][netns: UTF-8 bytes]`. Returns the encoded bytes; length is
/// `11 + netns.len()`.
pub fn encode_socket_context(context: &SocketContext) -> Vec<u8> {
    let mut out = Vec::with_capacity(11 + context.net_ns.as_ref().map_or(0, String::len));
    out.push(context.ip_version.0);
    match context.socket_mark {
        Some(mark) => {
            out.push(1);
            out.extend_from_slice(&mark.to_be_bytes());
        }
        None => out.extend_from_slice(&[0, 0, 0, 0, 0]),
    }
    match &context.net_ns {
        Some(net_ns) => {
            out.push(1);
            out.extend_from_slice(&u32::try_from(net_ns.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(net_ns.as_bytes());
        }
        None => out.extend_from_slice(&[0, 0, 0, 0, 0]),
    }
    out
}

/// Decodes a `SocketContext` TLV (§4.4) from the head of `bytes`, returning the value and the
/// number of bytes consumed (the caller's remaining slice starts right after).
pub fn decode_socket_context(bytes: &[u8]) -> Result<(SocketContext, usize)> {
    ensure!(bytes.len() >= 11, "socket context must be at least 11 bytes, got {}", bytes.len());
    let ip_version = IPVersion(byte_at(bytes, 0)?);
    ensure!(matches!(ip_version.0, 0..=2), "socket context ip_version must be 0, 1, or 2, got {}", ip_version.0);
    let mark_present = byte_at(bytes, 1)?;
    ensure!(
        matches!(mark_present, 0 | 1),
        "socket context socket_mark present byte must be 0 or 1, got {mark_present}"
    );
    let mark_value = u32::from_be_bytes(be_field::<4>(bytes, 2)?);
    ensure!(
        mark_present == 1 || mark_value == 0,
        "socket context socket_mark value must be zero when absent, got {mark_value}"
    );
    let socket_mark = (mark_present == 1).then_some(mark_value);
    let netns_present = byte_at(bytes, 6)?;
    ensure!(matches!(netns_present, 0 | 1), "socket context netns present byte must be 0 or 1, got {netns_present}");
    let netns_len = u32::from_be_bytes(be_field::<4>(bytes, 7)?) as usize;
    ensure!(
        netns_present == 1 || netns_len == 0,
        "socket context netns length must be zero when absent, got {netns_len}"
    );
    ensure!(11 + netns_len <= bytes.len(), "socket context netns length exceeds remaining buffer");
    let net_ns = if netns_present == 1 {
        let text = std::str::from_utf8(slice_at(bytes, 11..11 + netns_len)?)
            .map_err(|error| anyhow!("socket context netns is not valid UTF-8: {error}"))?;
        Some(text.to_owned())
    } else {
        None
    };
    Ok((SocketContext { ip_version, socket_mark, net_ns }, 11 + netns_len))
}

/// `bind_device` TLV (§4.4): `[present: u8][len: u32 BE][name bytes]`, consuming the *entire*
/// remainder of the passed slice (unlike [`SocketContext`], there is no trailing remainder).
///
/// **Judgment call**: the spec notes the device-name bytes are "not UTF-8 validated" on the wire,
/// but `platform::TCPBindOptions::bind_device`/`platform::UDPBindOptions::bind_device` are typed
/// `Option<String>`; every real bind-device name (an OS interface name) is ASCII, so invalid UTF-8
/// is decoded lossily rather than hard-erroring, unlike every other string field in this module.
pub fn encode_bind_device(device: Option<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + device.map_or(0, str::len));
    match device {
        Some(name) => {
            out.push(1);
            out.extend_from_slice(&u32::try_from(name.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        None => out.extend_from_slice(&[0, 0, 0, 0, 0]),
    }
    out
}

pub fn decode_bind_device(bytes: &[u8]) -> Result<Option<String>> {
    ensure!(bytes.len() >= 5, "bind device must be at least 5 bytes, got {}", bytes.len());
    let present = byte_at(bytes, 0)?;
    ensure!(matches!(present, 0 | 1), "bind device present byte must be 0 or 1, got {present}");
    let len = u32::from_be_bytes(be_field::<4>(bytes, 1)?) as usize;
    ensure!(present == 1 || len == 0, "bind device length must be zero when absent, got {len}");
    ensure!(
        bytes.len() == 5 + len,
        "bind device length must exactly consume the remaining bytes: expected {len}, got {}",
        bytes.len() - 5
    );
    if present == 0 {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(slice_at(bytes, 5..5 + len)?).into_owned()))
}

fn decode_reuse_bool(byte: u8, field: &str) -> Result<bool> {
    ensure!(matches!(byte, 0 | 1), "{field} byte must be 0 or 1, got {byte}");
    Ok(byte == 1)
}

/// `TCPConnectOptions` wire (§4.2, ≥75 bytes). Produces a `platform::TCPConnectOptions` directly.
pub fn decode_tcp_connect_options(bytes: &[u8]) -> Result<TCPConnectOptions> {
    ensure!(bytes.len() >= 75, "tcp connect options must be at least 75 bytes, got {}", bytes.len());
    let version = byte_at(bytes, 0)?;
    ensure!(version == 2, "tcp connect options version must be 2, got {version}");
    let Some(remote) = decode_socket_address(slice_at(bytes, 1..28)?, false)? else {
        bail!("tcp connect options remote socket address must be present");
    };
    let local = decode_socket_address(slice_at(bytes, 28..55)?, true)?;
    let (context, consumed) = decode_socket_context(slice_at(bytes, 55..bytes.len())?)?;
    let pos = 55 + consumed;
    ensure!(bytes.len() >= pos + 4, "tcp connect options missing reuse/purpose fields");
    let reuse_addr = match byte_at(bytes, pos)? {
        0 => None,
        1 => Some(false),
        2 => Some(true),
        other => bail!("tcp connect reuse_addr mode must be 0, 1, or 2, got {other}"),
    };
    let reuse_port = decode_reuse_bool(byte_at(bytes, pos + 1)?, "reuse_port")?;
    let only_v6 = decode_reuse_bool(byte_at(bytes, pos + 2)?, "only_v6")?;
    let purpose = TCPConnectPurpose(byte_at(bytes, pos + 3)?);
    let bind_device = decode_bind_device(slice_at(bytes, pos + 4..bytes.len())?)?;

    Ok(TCPConnectOptions {
        remote_addr: Some(TcpAddr::new(remote.ip, remote.port)),
        bind: TCPBindOptions {
            context,
            local_addr: local.map(|address| TcpAddr::new(address.ip, address.port)),
            bind_device,
            reuse_addr,
            reuse_port,
            only_v6,
        },
        purpose,
    })
}

fn udp_addr_from(address: HostSocketAddress) -> UdpAddr {
    UdpAddr {
        ip: address.ip,
        port: address.port,
        zone: if address.scope_id == 0 { String::new() } else { address.scope_id.to_string() },
    }
}

/// `UDPBindOptions` wire (§4.3, ≥48 bytes). Produces a `platform::UDPBindOptions` directly.
pub fn decode_udp_bind_options(bytes: &[u8]) -> Result<UDPBindOptions> {
    ensure!(bytes.len() >= 48, "udp bind options must be at least 48 bytes, got {}", bytes.len());
    let version = byte_at(bytes, 0)?;
    ensure!(version == 2, "udp bind options version must be 2, got {version}");
    let local = decode_socket_address(slice_at(bytes, 1..28)?, true)?;
    let (context, consumed) = decode_socket_context(slice_at(bytes, 28..bytes.len())?)?;
    let pos = 28 + consumed;
    ensure!(bytes.len() >= pos + 4, "udp bind options missing reuse/purpose fields");
    let reuse_addr = decode_reuse_bool(byte_at(bytes, pos)?, "reuse_addr")?;
    let reuse_port = decode_reuse_bool(byte_at(bytes, pos + 1)?, "reuse_port")?;
    let only_v6 = decode_reuse_bool(byte_at(bytes, pos + 2)?, "only_v6")?;
    let purpose = UDPBindPurpose(byte_at(bytes, pos + 3)?);
    let bind_device = decode_bind_device(slice_at(bytes, pos + 4..bytes.len())?)?;

    Ok(UDPBindOptions {
        context,
        local_addr: local.map(udp_addr_from),
        bind_device,
        reuse_addr,
        reuse_port,
        only_v6,
        purpose,
    })
}

/// `TCPListenOptions` wire (§4.3, ≥48 bytes; listen address is mandatory). Produces a
/// `platform::TCPListenOptions` directly.
pub fn decode_tcp_listen_options(bytes: &[u8]) -> Result<TCPListenOptions> {
    ensure!(bytes.len() >= 48, "tcp listen options must be at least 48 bytes, got {}", bytes.len());
    let version = byte_at(bytes, 0)?;
    ensure!(version == 2, "tcp listen options version must be 2, got {version}");
    let Some(local) = decode_socket_address(slice_at(bytes, 1..28)?, false)? else {
        bail!("tcp listen options local socket address must be present");
    };
    let (context, consumed) = decode_socket_context(slice_at(bytes, 28..bytes.len())?)?;
    let pos = 28 + consumed;
    ensure!(bytes.len() >= pos + 4, "tcp listen options missing reuse/purpose fields");
    let reuse_addr = decode_reuse_bool(byte_at(bytes, pos)?, "reuse_addr")?;
    let reuse_port = decode_reuse_bool(byte_at(bytes, pos + 1)?, "reuse_port")?;
    let only_v6 = decode_reuse_bool(byte_at(bytes, pos + 2)?, "only_v6")?;
    let purpose = TCPListenPurpose(byte_at(bytes, pos + 3)?);
    let bind_device = decode_bind_device(slice_at(bytes, pos + 4..bytes.len())?)?;

    Ok(TCPListenOptions {
        bind: TCPBindOptions {
            context,
            local_addr: Some(TcpAddr::new(local.ip, local.port)),
            bind_device,
            reuse_addr: Some(reuse_addr),
            reuse_port,
            only_v6,
        },
        purpose,
    })
}

/// The optional "secondary IP" slot of [`UdpMetadata`] (§8).
///
/// Currently populated by no caller (always `None` on encode today), reserved for a future
/// `IP_PKTINFO`-style local-destination-address report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecondaryIp {
    pub ip: IpAddr,
    /// Only legal alongside an IPv6 `ip`; IPv4 forbids a nonzero interface index.
    pub if_index: u32,
}

/// `UDPMetadata` (§8, 48 bytes): peer `SocketAddress` (bytes 0..27, delegated to
/// [`encode_socket_address`]/[`decode_socket_address`]) plus an optional secondary IP (bytes
/// 27..48).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpMetadata {
    pub peer: HostSocketAddress,
    pub secondary: Option<SecondaryIp>,
}

const SECONDARY_IP_LEN: usize = 21;

fn secondary_ip_bytes(secondary: Option<SecondaryIp>) -> [u8; SECONDARY_IP_LEN] {
    let mut out = [0u8; SECONDARY_IP_LEN];
    let Some(secondary) = secondary else { return out };
    match secondary.ip {
        IpAddr::V4(v4) => {
            out[0] = 4;
            out[1..5].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out[0] = 6;
            out[1..17].copy_from_slice(&v6.octets());
            out[17..21].copy_from_slice(&secondary.if_index.to_be_bytes());
        }
    }
    out
}

fn decode_secondary_ip(bytes: &[u8]) -> Result<Option<SecondaryIp>> {
    let family = byte_at(bytes, 0)?;
    let if_index = u32::from_be_bytes(be_field::<4>(bytes, 17)?);
    match family {
        0 => {
            ensure!(slice_at(bytes, 1..SECONDARY_IP_LEN)?.iter().all(|&b| b == 0), "noncanonical absent secondary IP");
            Ok(None)
        }
        4 => {
            ensure!(slice_at(bytes, 5..17)?.iter().all(|&b| b == 0), "secondary IPv4 must zero-pad bytes 5..17");
            ensure!(if_index == 0, "secondary IPv4 cannot carry an interface index, got {if_index}");
            Ok(Some(SecondaryIp { ip: IpAddr::V4(Ipv4Addr::from(be_field::<4>(bytes, 1)?)), if_index: 0 }))
        }
        6 => Ok(Some(SecondaryIp { ip: IpAddr::V6(Ipv6Addr::from(be_field::<16>(bytes, 1)?)), if_index })),
        other => bail!("secondary IP family must be 0, 4, or 6, got {other}"),
    }
}

/// Encodes a `UDPMetadata` (§8). `secondary`'s IPv4 case must not carry a nonzero interface index.
///
/// **Judgment call**: §4.1 says socket-address decoding rejects nonzero flowinfo unconditionally,
/// while §8's own field table calls flowinfo "must be 0 everywhere except this raw
/// datagram-metadata struct" — a hint that flowinfo might be legally nonzero for a v6 peer here.
/// The assignment explicitly directs delegating the first 27 bytes to the `SocketAddress` codec
/// rather than duplicating its validation, so this crate enforces flowinfo==0 uniformly (a
/// socket address has no flow-label field to populate it from in the first place, so this is
/// believed unobservable in practice either way).
pub fn encode_udp_metadata(peer: HostSocketAddress, secondary: Option<SecondaryIp>) -> Result<[u8; UDP_METADATA_LEN]> {
    if let Some(secondary) = &secondary {
        if secondary.ip.is_ipv4() {
            ensure!(secondary.if_index == 0, "secondary IPv4 cannot carry an interface index");
        }
    }
    let mut out = [0u8; UDP_METADATA_LEN];
    out[..SOCKET_ADDRESS_LEN].copy_from_slice(&host_socket_address_bytes(peer.ip, peer.port, peer.scope_id));
    out[SOCKET_ADDRESS_LEN..].copy_from_slice(&secondary_ip_bytes(secondary));
    Ok(out)
}

pub fn decode_udp_metadata(bytes: &[u8]) -> Result<UdpMetadata> {
    ensure!(bytes.len() == UDP_METADATA_LEN, "udp metadata must be {UDP_METADATA_LEN} bytes, got {}", bytes.len());
    let Some(peer) = decode_socket_address(slice_at(bytes, 0..SOCKET_ADDRESS_LEN)?, false)? else {
        bail!("udp metadata peer socket address must be present");
    };
    let secondary = decode_secondary_ip(slice_at(bytes, SOCKET_ADDRESS_LEN..UDP_METADATA_LEN)?)?;
    Ok(UdpMetadata { peer, secondary })
}

/// `DNSQuery` wire (≥12 bytes, `dnsWireVersion=1`).
///
/// `ip_version` uses the DNS query's own raw `0/4/6` numbering — deliberately different from
/// the socket context's `0/1/2` — matching `platform::DNSQuery::ip_version`'s bare `u8`
/// field.
pub fn decode_dns_query(bytes: &[u8]) -> Result<DNSQuery> {
    ensure!(bytes.len() >= 12, "dns query must be at least 12 bytes, got {}", bytes.len());
    let version = byte_at(bytes, 0)?;
    ensure!(version == 1, "dns query version must be 1, got {version}");
    let ip_version = byte_at(bytes, 1)?;
    ensure!(matches!(ip_version, 0 | 4 | 6), "dns query ip_version must be 0, 4, or 6, got {ip_version}");
    let mark_present = byte_at(bytes, 2)?;
    ensure!(matches!(mark_present, 0 | 1), "dns query socket_mark present byte must be 0 or 1, got {mark_present}");
    let mark_value = u32::from_be_bytes(be_field::<4>(bytes, 3)?);
    ensure!(
        mark_present == 1 || mark_value == 0,
        "dns query socket_mark value must be zero when absent, got {mark_value}"
    );
    let socket_mark = (mark_present == 1).then_some(mark_value);
    let netns_present = byte_at(bytes, 7)?;
    ensure!(matches!(netns_present, 0 | 1), "dns query netns present byte must be 0 or 1, got {netns_present}");
    let netns_len = u32::from_be_bytes(be_field::<4>(bytes, 8)?) as usize;
    ensure!(netns_present == 1 || netns_len == 0, "dns query netns length must be zero when absent, got {netns_len}");
    ensure!(12 + netns_len <= bytes.len(), "dns query netns length exceeds remaining buffer");
    let net_ns = if netns_present == 1 {
        let text = std::str::from_utf8(slice_at(bytes, 12..12 + netns_len)?)
            .map_err(|error| anyhow!("dns query netns is not valid UTF-8: {error}"))?;
        Some(text.to_owned())
    } else {
        None
    };
    let pos = 12 + netns_len;
    ensure!(bytes.len() >= pos + 4, "dns query missing host length field");
    let host_len = u32::from_be_bytes(be_field::<4>(bytes, pos)?) as usize;
    let host_bytes = slice_at(bytes, pos + 4..bytes.len())?;
    ensure!(
        host_bytes.len() == host_len,
        "dns query host length must exactly consume all remaining bytes: expected {host_len}, got {}",
        host_bytes.len()
    );
    let host = std::str::from_utf8(host_bytes)
        .map_err(|error| anyhow!("dns query host is not valid UTF-8: {error}"))?
        .to_owned();
    Ok(DNSQuery { host, ip_version, socket_mark, net_ns })
}

/// DNS address result (§7): `[count: u32 BE]` then per address `[family: u8][ip: 4 or 16 bytes]`.
#[must_use]
pub fn encode_dns_addresses(addresses: &[IpAddr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + addresses.len() * 17);
    out.extend_from_slice(&u32::try_from(addresses.len()).unwrap_or(u32::MAX).to_be_bytes());
    for address in addresses {
        match address {
            IpAddr::V4(v4) => {
                out.push(4);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(6);
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

/// Test-only mirror of the guest's DNS-address decode, used to verify [`encode_dns_addresses`]
/// round-trips; the host never decodes its own result (only the guest does).
#[cfg(test)]
fn decode_dns_addresses(bytes: &[u8]) -> Result<Vec<IpAddr>> {
    ensure!(bytes.len() >= 4, "dns address list must be at least 4 bytes, got {}", bytes.len());
    let count = u32::from_be_bytes(bytes[0..4].try_into().expect("4-byte slice")) as usize;
    let mut pos = 4;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        ensure!(pos < bytes.len(), "dns address list truncated");
        match bytes[pos] {
            4 => {
                ensure!(pos + 5 <= bytes.len(), "dns address list truncated (IPv4)");
                out.push(IpAddr::V4(Ipv4Addr::new(bytes[pos + 1], bytes[pos + 2], bytes[pos + 3], bytes[pos + 4])));
                pos += 5;
            }
            6 => {
                ensure!(pos + 17 <= bytes.len(), "dns address list truncated (IPv6)");
                out.push(IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&bytes[pos + 1..pos + 17]).expect("16-byte slice"),
                )));
                pos += 17;
            }
            other => bail!("dns address family must be 4 or 6, got {other}"),
        }
    }
    ensure!(pos == bytes.len(), "dns address list has trailing bytes");
    Ok(out)
}

/// DNS TXT result (§7): `[length: u32 BE][text: UTF-8 bytes]`.
#[must_use]
pub fn encode_dns_txt(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + text.len());
    out.extend_from_slice(&u32::try_from(text.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    out
}

/// Test-only mirror of the guest's DNS-TXT decode; see [`decode_dns_addresses`].
#[cfg(test)]
fn decode_dns_txt(bytes: &[u8]) -> Result<String> {
    ensure!(bytes.len() >= 4, "dns txt result must be at least 4 bytes, got {}", bytes.len());
    let len = u32::from_be_bytes(bytes[0..4].try_into().expect("4-byte slice")) as usize;
    ensure!(bytes.len() == 4 + len, "dns txt length must exactly consume the remaining bytes");
    Ok(std::str::from_utf8(&bytes[4..4 + len])?.to_owned())
}

/// DNS SRV result (§7): `[count: u32 BE]` then per record `[priority: u16 BE][weight: u16
/// BE][port: u16 BE][target_len: u32 BE][target: bytes]`.
#[must_use]
pub fn encode_dns_srv(records: &[Srv]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + records.len() * 10);
    out.extend_from_slice(&u32::try_from(records.len()).unwrap_or(u32::MAX).to_be_bytes());
    for record in records {
        out.extend_from_slice(&record.priority.to_be_bytes());
        out.extend_from_slice(&record.weight.to_be_bytes());
        out.extend_from_slice(&record.port.to_be_bytes());
        out.extend_from_slice(&u32::try_from(record.target.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(record.target.as_bytes());
    }
    out
}

/// Test-only mirror of the guest's DNS-SRV decode; see [`decode_dns_addresses`].
#[cfg(test)]
fn decode_dns_srv(bytes: &[u8]) -> Result<Vec<Srv>> {
    ensure!(bytes.len() >= 4, "dns srv result must be at least 4 bytes, got {}", bytes.len());
    let count = u32::from_be_bytes(bytes[0..4].try_into().expect("4-byte slice")) as usize;
    let mut pos = 4;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        ensure!(pos + 10 <= bytes.len(), "dns srv record truncated");
        let priority = u16::from_be_bytes(bytes[pos..pos + 2].try_into().expect("2-byte slice"));
        let weight = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().expect("2-byte slice"));
        let port = u16::from_be_bytes(bytes[pos + 4..pos + 6].try_into().expect("2-byte slice"));
        let target_len = u32::from_be_bytes(bytes[pos + 6..pos + 10].try_into().expect("4-byte slice")) as usize;
        pos += 10;
        ensure!(pos + target_len <= bytes.len(), "dns srv target truncated");
        let target = std::str::from_utf8(&bytes[pos..pos + target_len])?.to_owned();
        pos += target_len;
        out.push(Srv { target, port, priority, weight });
    }
    ensure!(pos == bytes.len(), "dns srv result has trailing bytes");
    Ok(out)
}

/// Data-plane `SocketAddress` (§2.3, 27 bytes, IPv4-ONLY): distinct
/// from [`HostSocketAddress`] despite the identical length — see this module's top-level doc.
///
/// Layout: `[family: u8, MUST be 4][ip: 4 raw bytes][12 zero bytes][port: u16 BE][8 zero bytes]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataPlaneSocketAddr {
    pub ip: Ipv4Addr,
    pub port: u16,
}

#[must_use]
pub fn encode_data_plane_socket_addr(addr: DataPlaneSocketAddr) -> [u8; DATA_PLANE_SOCKET_ADDR_LEN] {
    let mut out = [0u8; DATA_PLANE_SOCKET_ADDR_LEN];
    out[0] = 4;
    out[1..5].copy_from_slice(&addr.ip.octets());
    out[17..19].copy_from_slice(&addr.port.to_be_bytes());
    out
}

pub fn decode_data_plane_socket_addr(bytes: &[u8]) -> Result<DataPlaneSocketAddr> {
    ensure!(
        bytes.len() == DATA_PLANE_SOCKET_ADDR_LEN,
        "data-plane socket address must be {DATA_PLANE_SOCKET_ADDR_LEN} bytes, got {}",
        bytes.len()
    );
    let family = byte_at(bytes, 0)?;
    ensure!(family == 4, "data-plane socket address family must be 4, got {family}");
    ensure!(slice_at(bytes, 5..17)?.iter().all(|&b| b == 0), "data-plane socket address must zero-pad bytes 5..17");
    ensure!(slice_at(bytes, 19..27)?.iter().all(|&b| b == 0), "data-plane socket address must zero-pad bytes 19..27");
    let ip = Ipv4Addr::from(be_field::<4>(bytes, 1)?);
    let port = u16::from_be_bytes(be_field::<2>(bytes, 17)?);
    Ok(DataPlaneSocketAddr { ip, port })
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    #[derive(Debug)]
    struct UnknownAddr;

    impl Addr for UnknownAddr {
        fn network(&self) -> &str {
            "unknown"
        }

        fn string(&self) -> String {
            "unknown".to_owned()
        }
    }

    impl fmt::Display for UnknownAddr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "unknown")
        }
    }

    mod host_socket_address {
        use super::*;

        #[test]
        fn round_trips_ipv4_tcp() {
            let addr = TcpAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 8080);
            let encoded = encode_socket_address(&addr);
            #[rustfmt::skip]
            let expected: [u8; 27] = [
                4, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0x1F, 0x90,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ];
            assert_eq!(encoded, expected);
            let decoded = decode_socket_address(&encoded, false).unwrap().unwrap();
            assert_eq!(decoded, HostSocketAddress { ip: addr.ip, port: addr.port, scope_id: 0 });
        }

        #[test]
        fn round_trips_ipv6_udp_with_scope() {
            let addr =
                UdpAddr { ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), port: 53, zone: "5".to_owned() };
            let encoded = encode_socket_address(&addr);
            #[rustfmt::skip]
            let expected: [u8; 27] = [
                6,
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0x00, 0x35,
                0, 0, 0, 0,
                0, 0, 0, 5,
            ];
            assert_eq!(encoded, expected);
            let decoded = decode_socket_address(&encoded, false).unwrap().unwrap();
            assert_eq!(decoded, HostSocketAddress { ip: addr.ip, port: 53, scope_id: 5 });
        }

        #[test]
        fn encodes_unencodable_addr_as_canonical_absent() {
            let encoded = encode_socket_address(&UnknownAddr);
            assert_eq!(encoded, [0u8; 27]);
        }

        #[test]
        fn decodes_canonical_absent_when_optional() {
            let decoded = decode_socket_address(&[0u8; 27], true).unwrap();
            assert_eq!(decoded, None);
        }

        #[test]
        fn rejects_noncanonical_absent() {
            let mut bytes = [0u8; 27];
            bytes[17] = 1;
            let error = decode_socket_address(&bytes, true).unwrap_err();
            assert!(error.to_string().contains("noncanonical"));
        }

        #[test]
        fn rejects_nonzero_flowinfo() {
            let mut bytes = encode_socket_address(&TcpAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80));
            bytes[19] = 1;
            let error = decode_socket_address(&bytes, false).unwrap_err();
            assert!(error.to_string().contains("flowinfo"));
        }

        #[test]
        fn rejects_family_zero_when_required() {
            let error = decode_socket_address(&[0u8; 27], false).unwrap_err();
            assert!(error.to_string().contains("family"));
        }

        #[test]
        fn rejects_invalid_family() {
            let mut bytes = [0u8; 27];
            bytes[0] = 5;
            let error = decode_socket_address(&bytes, false).unwrap_err();
            assert!(error.to_string().contains("family"));
        }

        #[test]
        fn rejects_ipv4_nonzero_padding() {
            let mut bytes = encode_socket_address(&TcpAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80));
            bytes[10] = 0xFF;
            let error = decode_socket_address(&bytes, false).unwrap_err();
            assert!(error.to_string().contains("zero-pad"));
        }

        #[test]
        fn rejects_wrong_length() {
            let error = decode_socket_address(&[0u8; 26], true).unwrap_err();
            assert!(error.to_string().contains("27 bytes"));
        }
    }

    mod socket_context {
        use super::*;

        #[test]
        fn round_trips_with_mark_and_netns() {
            let context = SocketContext {
                ip_version: IPVersion::IP_VERSION_BOTH,
                socket_mark: Some(1234),
                net_ns: Some("ns0".to_owned()),
            };
            let encoded = encode_socket_context(&context);
            #[rustfmt::skip]
            let expected: Vec<u8> = vec![
                2,
                1, 0x00, 0x00, 0x04, 0xD2,
                1, 0, 0, 0, 3, b'n', b's', b'0',
            ];
            assert_eq!(encoded, expected);
            let (decoded, consumed) = decode_socket_context(&encoded).unwrap();
            assert_eq!(consumed, encoded.len());
            assert_eq!(decoded.ip_version, context.ip_version);
            assert_eq!(decoded.socket_mark, context.socket_mark);
            assert_eq!(decoded.net_ns, context.net_ns);
        }

        #[test]
        fn round_trips_absent_fields() {
            let context = SocketContext { ip_version: IPVersion::IP_VERSION_V4, socket_mark: None, net_ns: None };
            let encoded = encode_socket_context(&context);
            assert_eq!(encoded, vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let (decoded, consumed) = decode_socket_context(&encoded).unwrap();
            assert_eq!(consumed, 11);
            assert_eq!(decoded.socket_mark, None);
            assert_eq!(decoded.net_ns, None);
        }

        #[test]
        fn rejects_mark_value_when_absent() {
            let mut bytes = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            bytes[5] = 1;
            let error = decode_socket_context(&bytes).unwrap_err();
            assert!(error.to_string().contains("socket_mark"));
        }

        #[test]
        fn rejects_invalid_ip_version() {
            let bytes = vec![3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let error = decode_socket_context(&bytes).unwrap_err();
            assert!(error.to_string().contains("ip_version"));
        }

        #[test]
        fn rejects_invalid_netns_utf8() {
            let mut bytes = vec![0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0xFF];
            assert!(decode_socket_context(&bytes).is_err(), "a non-UTF-8 netns token must be rejected");
            bytes[11] = b'x';
            assert!(decode_socket_context(&bytes).is_ok(), "a UTF-8 netns token must be accepted");
        }

        #[test]
        fn rejects_undersized_buffer() {
            let error = decode_socket_context(&[0u8; 10]).unwrap_err();
            assert!(error.to_string().contains("11 bytes"));
        }
    }

    mod bind_device {
        use super::*;

        #[test]
        fn round_trips_present() {
            let encoded = encode_bind_device(Some("eth0"));
            assert_eq!(encoded, vec![1, 0, 0, 0, 4, b'e', b't', b'h', b'0']);
            let decoded = decode_bind_device(&encoded).unwrap();
            assert_eq!(decoded, Some("eth0".to_owned()));
        }

        #[test]
        fn round_trips_absent() {
            let encoded = encode_bind_device(None);
            assert_eq!(encoded, vec![0, 0, 0, 0, 0]);
            let decoded = decode_bind_device(&encoded).unwrap();
            assert_eq!(decoded, None);
        }

        #[test]
        fn rejects_length_not_matching_remaining_bytes() {
            let error = decode_bind_device(&[1, 0, 0, 0, 4, b'e', b't', b'h']).unwrap_err();
            assert!(error.to_string().contains("exactly consume"));
        }

        #[test]
        fn rejects_nonzero_length_when_absent() {
            let error = decode_bind_device(&[0, 0, 0, 0, 1, b'x']).unwrap_err();
            assert!(error.to_string().contains("zero when absent"));
        }
    }

    mod tcp_connect_options {
        use super::*;

        fn minimal_blob(reuse_addr_mode: u8, purpose: u8) -> Vec<u8> {
            let mut out = vec![2];
            out.extend_from_slice(&encode_socket_address(&TcpAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 8080)));
            out.extend_from_slice(&[0u8; 27]);
            out.extend_from_slice(&encode_socket_context(&SocketContext {
                ip_version: IPVersion::IP_VERSION_V4,
                socket_mark: None,
                net_ns: None,
            }));
            out.push(reuse_addr_mode);
            out.push(1);
            out.push(0);
            out.push(purpose);
            out.extend_from_slice(&encode_bind_device(None));
            out
        }

        #[test]
        fn decodes_minimal_blob() {
            let blob = minimal_blob(2, TCPConnectPurpose::TCP_CONNECT_MANUAL.0);
            assert_eq!(blob.len(), 75);
            let options = decode_tcp_connect_options(&blob).unwrap();
            assert_eq!(options.remote_addr, Some(TcpAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 8080)));
            assert_eq!(options.bind.local_addr, None);
            assert_eq!(options.bind.reuse_addr, Some(true));
            assert!(options.bind.reuse_port);
            assert!(!options.bind.only_v6);
            assert_eq!(options.bind.bind_device, None);
            assert_eq!(options.purpose, TCPConnectPurpose::TCP_CONNECT_MANUAL);
        }

        #[test]
        fn rejects_wrong_version() {
            let mut blob = minimal_blob(2, 0);
            blob[0] = 1;
            assert!(decode_tcp_connect_options(&blob).is_err(), "version byte 1 must be rejected");
        }

        #[test]
        fn rejects_undersized_buffer() {
            let error = decode_tcp_connect_options(&[0u8; 74]).unwrap_err();
            assert!(error.to_string().contains("75 bytes"));
        }

        #[test]
        fn rejects_invalid_reuse_addr_mode() {
            assert!(decode_tcp_connect_options(&minimal_blob(3, 0)).is_err(), "reuse_addr mode 3 must be rejected");
            assert!(decode_tcp_connect_options(&minimal_blob(2, 0)).is_ok(), "reuse_addr mode 2 must be accepted");
        }
    }

    mod udp_bind_options {
        use super::*;

        #[test]
        fn decodes_blob_with_local_addr_and_bind_device() {
            let mut blob = vec![2];
            blob.extend_from_slice(&encode_socket_address(&UdpAddr {
                ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                port: 53,
                zone: "5".to_owned(),
            }));
            blob.extend_from_slice(&encode_socket_context(&SocketContext {
                ip_version: IPVersion::IP_VERSION_V6,
                socket_mark: None,
                net_ns: None,
            }));
            blob.push(1);
            blob.push(0);
            blob.push(1);
            blob.push(UDPBindPurpose::UDP_BIND_DIRECT.0);
            blob.extend_from_slice(&encode_bind_device(Some("wg0")));

            let options = decode_udp_bind_options(&blob).unwrap();
            assert_eq!(
                options.local_addr,
                Some(UdpAddr {
                    ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                    port: 53,
                    zone: "5".to_owned()
                })
            );
            assert_eq!(options.bind_device, Some("wg0".to_owned()));
            assert!(options.reuse_addr);
            assert!(!options.reuse_port);
            assert!(options.only_v6);
            assert_eq!(options.purpose, UDPBindPurpose::UDP_BIND_DIRECT);
        }

        #[test]
        fn rejects_wrong_version() {
            let mut blob = vec![9];
            blob.extend_from_slice(&[0u8; 27]);
            blob.extend_from_slice(&encode_socket_context(&SocketContext::default()));
            blob.extend_from_slice(&[0, 0, 0, 0]);
            blob.extend_from_slice(&encode_bind_device(None));
            assert!(decode_udp_bind_options(&blob).is_err(), "version byte 9 must be rejected");
            blob[0] = 2;
            assert!(decode_udp_bind_options(&blob).is_ok(), "version byte 2 must be accepted");
        }
    }

    mod tcp_listen_options {
        use super::*;

        #[test]
        fn decodes_minimal_blob() {
            let mut blob = vec![2];
            blob.extend_from_slice(&encode_socket_address(&TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000)));
            blob.extend_from_slice(&encode_socket_context(&SocketContext::default()));
            blob.push(1);
            blob.push(1);
            blob.push(0);
            blob.push(TCPListenPurpose::TCP_LISTEN_HOLE_PUNCH.0);
            blob.extend_from_slice(&encode_bind_device(None));
            assert_eq!(blob.len(), 48);

            let options = decode_tcp_listen_options(&blob).unwrap();
            assert_eq!(options.bind.local_addr, Some(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000)));
            assert_eq!(options.bind.reuse_addr, Some(true));
            assert!(options.bind.reuse_port);
            assert!(!options.bind.only_v6);
            assert_eq!(options.purpose, TCPListenPurpose::TCP_LISTEN_HOLE_PUNCH);
        }

        #[test]
        fn rejects_absent_required_addr() {
            let mut blob = vec![2];
            blob.extend_from_slice(&[0u8; 27]);
            blob.extend_from_slice(&encode_socket_context(&SocketContext::default()));
            blob.extend_from_slice(&[0, 0, 0, 0]);
            blob.extend_from_slice(&encode_bind_device(None));
            assert!(decode_tcp_listen_options(&blob).is_err(), "a listen address must be present");
        }
    }

    mod socket_results {
        use super::*;

        #[test]
        fn encodes_tcp_socket_result() {
            let local = TcpAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234);
            let peer = TcpAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5678);
            let encoded = encode_tcp_socket_result(0x0001_0203_0405_0607, &local, &peer).unwrap();
            #[rustfmt::skip]
            let expected: [u8; 62] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                4, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0xD2, 0, 0, 0, 0, 0, 0, 0, 0,
                4, 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16, 0x2E, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            assert_eq!(encoded, expected);
        }

        #[test]
        fn encodes_bound_socket_result() {
            let local = UdpAddr { ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), port: 4000, zone: String::new() };
            let encoded = encode_bound_socket_result(0x1122_3344_5566_7788, &local).unwrap();
            #[rustfmt::skip]
            let expected: [u8; 35] = [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                4, 172, 16, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0F, 0xA0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            assert_eq!(encoded, expected);
        }

        #[test]
        fn rejects_unsupported_addr_kind() {
            let local = TcpAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1);
            let error = encode_tcp_socket_result(1, &local, &UnknownAddr).unwrap_err();
            assert!(error.to_string().contains("unsupported socket address"));
        }
    }

    mod udp_metadata {
        use super::*;

        #[test]
        fn round_trips_without_secondary() {
            let peer = HostSocketAddress { ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), port: 9000, scope_id: 0 };
            let encoded = encode_udp_metadata(peer, None).unwrap();
            #[rustfmt::skip]
            let expected: [u8; 48] = [
                4, 10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x23, 0x28, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            assert_eq!(encoded, expected);
            let decoded = decode_udp_metadata(&encoded).unwrap();
            assert_eq!(decoded, UdpMetadata { peer, secondary: None });
        }

        #[test]
        fn round_trips_with_secondary_ipv6() {
            let peer = HostSocketAddress { ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), port: 9000, scope_id: 0 };
            let secondary = SecondaryIp { ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)), if_index: 7 };
            let encoded = encode_udp_metadata(peer, Some(secondary)).unwrap();
            let decoded = decode_udp_metadata(&encoded).unwrap();
            assert_eq!(decoded, UdpMetadata { peer, secondary: Some(secondary) });
        }

        #[test]
        fn rejects_secondary_ipv4_with_ifindex() {
            let peer = HostSocketAddress { ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), port: 1, scope_id: 0 };
            let secondary = SecondaryIp { ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), if_index: 1 };
            let error = encode_udp_metadata(peer, Some(secondary)).unwrap_err();
            assert!(error.to_string().contains("interface index"));
        }

        #[test]
        fn rejects_wrong_length() {
            let error = decode_udp_metadata(&[0u8; 47]).unwrap_err();
            assert!(error.to_string().contains("48 bytes"));
        }

        #[test]
        fn rejects_secondary_ipv4_noncanonical_padding() {
            let peer = HostSocketAddress { ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), port: 1, scope_id: 0 };
            let mut encoded = encode_udp_metadata(peer, None).unwrap();
            encoded[27] = 4;
            encoded[27 + 5] = 0xFF;
            let error = decode_udp_metadata(&encoded).unwrap_err();
            assert!(error.to_string().contains("zero-pad"));
        }
    }

    mod dns_query {
        use super::*;

        fn blob(ip_version: u8, host: &str) -> Vec<u8> {
            let mut out = vec![1, ip_version, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            out.extend_from_slice(&u32::try_from(host.len()).unwrap().to_be_bytes());
            out.extend_from_slice(host.as_bytes());
            out
        }

        #[test]
        fn decodes_minimal_query() {
            let bytes = blob(4, "example.com");
            let query = decode_dns_query(&bytes).unwrap();
            assert_eq!(query.host, "example.com");
            assert_eq!(query.ip_version, 4);
            assert_eq!(query.socket_mark, None);
            assert_eq!(query.net_ns, None);
        }

        #[test]
        fn decodes_query_with_mark_and_netns() {
            let mut bytes = vec![1, 6, 1, 0, 0, 0, 42, 1, 0, 0, 0, 3, b'n', b's', b'1'];
            bytes.extend_from_slice(&8u32.to_be_bytes());
            bytes.extend_from_slice(b"host.tld");
            let query = decode_dns_query(&bytes).unwrap();
            assert_eq!(query.ip_version, 6);
            assert_eq!(query.socket_mark, Some(42));
            assert_eq!(query.net_ns, Some("ns1".to_owned()));
            assert_eq!(query.host, "host.tld");
        }

        #[test]
        fn rejects_wrong_version() {
            let mut bytes = blob(0, "x");
            bytes[0] = 2;
            let error = decode_dns_query(&bytes).unwrap_err();
            assert!(error.to_string().contains("version"));
        }

        #[test]
        fn rejects_invalid_ip_version() {
            let bytes = blob(5, "x");
            let error = decode_dns_query(&bytes).unwrap_err();
            assert!(error.to_string().contains("ip_version"));
        }

        #[test]
        fn rejects_host_length_mismatch() {
            const HOST: &str = "example.com";
            let mut bytes = blob(0, HOST);
            let length_at = 12;
            bytes[length_at..length_at + 4].copy_from_slice(&(HOST.len() as u32 + 1).to_be_bytes());
            assert!(decode_dns_query(&bytes).is_err(), "a host length that leaves trailing bytes must be rejected");
            bytes[length_at..length_at + 4].copy_from_slice(&(HOST.len() as u32).to_be_bytes());
            assert!(decode_dns_query(&bytes).is_ok(), "an exact host length must be accepted");
        }
    }

    mod dns_results {
        use super::*;

        #[test]
        fn round_trips_addresses() {
            let addresses =
                vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))];
            let encoded = encode_dns_addresses(&addresses);
            assert_eq!(&encoded[0..4], &2u32.to_be_bytes());
            let decoded = decode_dns_addresses(&encoded).unwrap();
            assert_eq!(decoded, addresses);
        }

        #[test]
        fn round_trips_txt() {
            let encoded = encode_dns_txt("v=spf1 -all");
            let decoded = decode_dns_txt(&encoded).unwrap();
            assert_eq!(decoded, "v=spf1 -all");
        }

        #[test]
        fn round_trips_srv() {
            let records = vec![Srv { target: "sip.example.com".to_owned(), port: 5060, priority: 10, weight: 20 }];
            let encoded = encode_dns_srv(&records);
            let decoded = decode_dns_srv(&encoded).unwrap();
            assert_eq!(decoded, records);
        }

        #[test]
        fn rejects_truncated_address_list() {
            let error = decode_dns_addresses(&[0, 0, 0, 1]).unwrap_err();
            assert!(error.to_string().contains("truncated"));
        }
    }

    mod data_plane_socket_addr {
        use super::*;

        #[test]
        fn round_trips() {
            let addr = DataPlaneSocketAddr { ip: Ipv4Addr::new(198, 51, 100, 7), port: 443 };
            let encoded = encode_data_plane_socket_addr(addr);
            #[rustfmt::skip]
            let expected: [u8; 27] = [
                4, 198, 51, 100, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            assert_eq!(encoded, expected);
            let decoded = decode_data_plane_socket_addr(&encoded).unwrap();
            assert_eq!(decoded, addr);
        }

        #[test]
        fn rejects_non_ipv4_family() {
            let mut bytes =
                encode_data_plane_socket_addr(DataPlaneSocketAddr { ip: Ipv4Addr::new(1, 2, 3, 4), port: 1 });
            bytes[0] = 6;
            let error = decode_data_plane_socket_addr(&bytes).unwrap_err();
            assert!(error.to_string().contains("family"));
        }

        #[test]
        fn rejects_nonzero_padding_low() {
            let mut bytes =
                encode_data_plane_socket_addr(DataPlaneSocketAddr { ip: Ipv4Addr::new(1, 2, 3, 4), port: 1 });
            bytes[10] = 1;
            let error = decode_data_plane_socket_addr(&bytes).unwrap_err();
            assert!(error.to_string().contains("5..17"));
        }

        #[test]
        fn rejects_nonzero_padding_high() {
            let mut bytes =
                encode_data_plane_socket_addr(DataPlaneSocketAddr { ip: Ipv4Addr::new(1, 2, 3, 4), port: 1 });
            bytes[20] = 1;
            let error = decode_data_plane_socket_addr(&bytes).unwrap_err();
            assert!(error.to_string().contains("19..27"));
        }

        #[test]
        fn rejects_wrong_length() {
            let error = decode_data_plane_socket_addr(&[0u8; 28]).unwrap_err();
            assert!(error.to_string().contains("27 bytes"));
        }
    }
}
