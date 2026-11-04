//! A port-then-address serializer with family bytes `0x01`=IPv4, `0x03`=IPv6, `0x02`=FQDN —
//! distinct from `murmur_sing::metadata::SOCKSADDR_SERIALIZER`'s address-then-port SOCKS layout
//! and byte values, so it is not shared with that module.

use std::io;
use std::net::IpAddr;

use murmur_sing::metadata::{write_socks_string, Socksaddr};

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_FQDN: u8 = 0x02;
const FAMILY_IPV6: u8 = 0x03;

fn address_len(addr: &Socksaddr) -> usize {
    if !addr.is_valid() {
        1
    } else if addr.is_ipv4() {
        5
    } else if addr.is_ipv6() {
        17
    } else {
        2 + addr.fqdn.len()
    }
}

pub(crate) fn addr_port_len(dst: &Socksaddr) -> usize {
    if dst.is_valid() {
        address_len(dst) + 2
    } else {
        address_len(dst)
    }
}

fn write_address(buffer: &mut Vec<u8>, addr: &Socksaddr) -> io::Result<()> {
    if !addr.is_valid() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported address"));
    }
    if addr.is_ipv4() {
        buffer.push(FAMILY_IPV4);
        let Some(IpAddr::V4(v4)) = addr.addr else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported address"));
        };
        buffer.extend_from_slice(&v4.octets());
    } else if addr.is_ipv6() {
        buffer.push(FAMILY_IPV6);
        let Some(IpAddr::V6(v6)) = addr.addr else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported address"));
        };
        buffer.extend_from_slice(&v6.octets());
    } else {
        buffer.push(FAMILY_FQDN);
        write_socks_string(buffer, &addr.fqdn)?;
    }
    Ok(())
}

/// Writes an address and port in port-then-address order.
pub(crate) fn write_addr_port(buffer: &mut Vec<u8>, dst: &Socksaddr) -> io::Result<()> {
    buffer.extend_from_slice(&dst.port.to_be_bytes());
    write_address(buffer, dst)
}

/// Reads an address and port from a byte cursor: every caller already holds the whole decrypted
/// header in memory.
pub(crate) fn read_addr_port(cursor: &mut &[u8]) -> io::Result<Socksaddr> {
    let bytes: &[u8] = cursor;
    let [port_hi, port_lo, rest @ ..] = bytes else {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    };
    let port = u16::from_be_bytes([*port_hi, *port_lo]);

    let [family, rest @ ..] = rest else {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    };

    let mut addr = match *family {
        FAMILY_IPV4 => {
            let Some((octets, rest)) = rest.split_first_chunk::<4>() else {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            };
            *cursor = rest;
            Socksaddr::from_ip(IpAddr::from(*octets), 0)
        }
        FAMILY_IPV6 => {
            let Some((octets, rest)) = rest.split_first_chunk::<16>() else {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            };
            *cursor = rest;
            Socksaddr::from_ip(IpAddr::from(*octets), 0)
        }
        FAMILY_FQDN => {
            let [len, rest @ ..] = rest else {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            };
            let Some((fqdn, rest)) = rest.split_at_checked(usize::from(*len)) else {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            };
            *cursor = rest;
            Socksaddr::fqdn(String::from_utf8_lossy(fqdn).into_owned(), 0)
        }
        other => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown address family: {other}"))),
    };
    addr.port = port;
    Ok(addr.unwrap())
}
