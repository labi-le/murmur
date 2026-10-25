use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use murmur_component::dialer::bind::join_host_port;
use murmur_component::resolver::host::unmap_addr;
use murmur_constant::metadata::Metadata;
use murmur_transport::socks5::socks5;

use super::connect_authority;

pub(crate) fn parse_socks_addr(target: &socks5::Addr) -> Metadata {
    let target = &target.0;
    let mut metadata = Metadata::default();

    match target.first().copied() {
        Some(socks5::ATYP_DOMAIN_NAME) => {
            let length = usize::from(target.get(1).copied().unwrap_or_default());
            if let Some(host) = target.get(2..2 + length) {
                String::from_utf8_lossy(host).trim_end_matches('.').clone_into(&mut metadata.host);
            }
            metadata.dst_port = be_u16_at(target, 2 + length);
        }
        Some(socks5::ATYP_IPV4) => {
            metadata.dst_ip = address_from_slice(target.get(1..=4).unwrap_or_default());
            metadata.dst_port = be_u16_at(target, 1 + 4);
        }
        Some(socks5::ATYP_IPV6) => {
            metadata.dst_ip = address_from_slice(target.get(1..=16).unwrap_or_default());
            metadata.dst_port = be_u16_at(target, 1 + 16);
        }
        Some(_) | None => {}
    }
    metadata.dst_ip = metadata.dst_ip.map(unmap_addr);

    metadata
}

/// The big-endian port two bytes into `b` at `off`; zero when they are not there.
fn be_u16_at(b: &[u8], off: usize) -> u16 {
    b.get(off..off.saturating_add(2)).and_then(|s| s.first_chunk::<2>()).map_or(0, |c| u16::from_be_bytes(*c))
}

/// A 4- or 16-byte slice as an address; any other length is rejected.
fn address_from_slice(slice: &[u8]) -> Option<IpAddr> {
    match slice.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(slice).ok()?))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(slice).ok()?))),
        _ => None,
    }
}

/// Parses an HTTP address. A CONNECT authority's userinfo, brackets and `%XX` escapes are stripped,
/// and the host is never lowercased (see `connect_authority.rs`'s module doc). By the time this
/// runs, `authority` has already been accepted by the request reader's own call to the same parser, so
/// a failure should not occur in practice; falling back to the raw authority text on one keeps
/// this function infallible for its one caller (`https.rs::new_https`).
pub(crate) fn parse_http_addr(authority: &str) -> Metadata {
    let (host, port) = match connect_authority::parse_connect_authority(authority) {
        Ok((host, port)) => (host, port.unwrap_or_else(|| "80".to_owned())),
        Err(_) => (authority.to_owned(), "80".to_owned()),
    };

    let host = host.trim_end_matches('.').to_owned();

    let mut metadata = Metadata::default();
    let _ = metadata.set_remote_address(&join_host_port(&host, &port));
    metadata
}

/// Whether any prefix contains `addr`; `None` (an unparsed address) is rejected.
pub(crate) fn prefixes_contains(prefixes: &[IpNet], addr: Option<IpAddr>) -> bool {
    if prefixes.is_empty() {
        return false;
    }
    let Some(addr) = addr else {
        return false;
    };
    let addr = unmap_addr(addr);
    prefixes.iter().any(|prefix| prefix.contains(&addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_authority_userinfo_is_never_routed_as_host() {
        // P2-connect-raw-authority-userinfo: routing on the raw authority let a
        // `user@example.com:443`-shaped target reach rule matching with host
        // `user@example.com`, so a `DOMAIN-SUFFIX` rule for the real host never matched and the
        // userinfo-stripped authority still got dialled by the outbound anyway. The hostname
        // semantics (userinfo stripped, case preserved) must be what rules and the dial layer
        // both see.
        let metadata = parse_http_addr("user@example.com:443");
        assert_eq!(metadata.host, "example.com");
        assert_eq!(metadata.dst_port, 443);
    }

    #[test]
    fn host_case_is_preserved() {
        let metadata = parse_http_addr("EXAMPLE.com:443");
        assert_eq!(metadata.host, "EXAMPLE.com");
    }

    #[test]
    fn ipv6_literal_host() {
        // `Metadata::set_remote_address` routes a parseable IP literal into `dst_ip`, leaving
        // `host` empty (mirroring `host` staying unset for a raw-IP destination) —
        // so the address round trip, not `host`, is what proves the brackets and case survived.
        let metadata = parse_http_addr("[::1]:443");
        assert_eq!(metadata.dst_ip, Some(Ipv6Addr::LOCALHOST.into()));
        assert_eq!(metadata.dst_port, 443);
    }

    #[test]
    fn missing_port_defaults_to_80() {
        let metadata = parse_http_addr("example.com");
        assert_eq!(metadata.host, "example.com");
        assert_eq!(metadata.dst_port, 80);
    }
}
