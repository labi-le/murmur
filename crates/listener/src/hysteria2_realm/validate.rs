use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use anyhow::{anyhow, Result};

pub const MAX_ADDRESSES: usize = 8;
pub const NONCE_HEX_LENGTH: usize = 32;
pub const OBFS_HEX_LENGTH: usize = 64;

pub const ERR_BAD_REQUEST: &str = "bad_request";
pub const ERR_INVALID_TOKEN: &str = "invalid_token";
pub const ERR_REALM_TAKEN: &str = "realm_taken";
pub const ERR_REALM_LIMIT: &str = "realm_limit_reached";
pub const ERR_IP_LIMIT: &str = "ip_limit_reached";
pub const ERR_REALM_NOT_FOUND: &str = "realm_not_found";
pub const ERR_ATTEMPT_NOT_FOUND: &str = "attempt_not_found";
pub const ERR_RATE_LIMITED: &str = "rate_limited";
pub const ERR_NOT_FOUND: &str = "not_found";

/// `writeErr`'s payload: `{"error": code, "message": msg}`.
#[must_use]
pub fn error_body(code: &str, message: &str) -> String {
    serde_json::json!({ "error": code, "message": message }).to_string()
}

/// Host/port splitting, restricted to the shapes a request address can take.
fn split_host_port(hostport: &str) -> Option<(String, String)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        return Some((host.to_owned(), port.to_owned()));
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host.to_owned(), port.to_owned())),
        _ => None,
    }
}

/// Parses an address and renders it unmapped: an IPv4-mapped IPv6 address becomes its IPv4 form.
fn parse_addr_unmapped(v: &str) -> Option<String> {
    let (addr_part, zone) = match v.split_once('%') {
        Some((addr, zone)) => (addr, Some(zone)),
        None => (v, None),
    };
    let addr = IpAddr::from_str(addr_part).ok()?;
    let addr = match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 @ IpAddr::V4(_) => v4,
    };
    let mut s = addr.to_string();
    if let Some(zone) = zone {
        s.push('%');
        s.push_str(zone);
    }
    Some(s)
}

/// The client IP from the request address, honouring a configured header.
#[must_use]
pub fn client_ip(remote_addr: &str, header: &str, header_value: &str) -> String {
    if !header.is_empty() && !header_value.is_empty() {
        let first = match header_value.split_once(',') {
            Some((first, _)) => first,
            None => header_value,
        };
        let first = first.trim();
        let host = match split_host_port(first) {
            Some((host, _)) => host,
            None => first.to_owned(),
        };
        if let Some(addr) = parse_addr_unmapped(&host) {
            return addr;
        }
    }
    let host = match split_host_port(remote_addr) {
        Some((h, _)) => h,
        None => remote_addr.to_owned(),
    };
    parse_addr_unmapped(&host).unwrap_or(host)
}

/// Extracts the bearer token from the `Authorization` header value.
#[must_use]
pub fn bearer(authorization: &str) -> String {
    match authorization.strip_prefix("Bearer ") {
        Some(token) => token.to_owned(),
        None => String::new(),
    }
}

pub fn validate_addresses(addrs: &[String]) -> Result<()> {
    if addrs.is_empty() {
        return Err(anyhow!("at least one address required"));
    }
    if addrs.len() > MAX_ADDRESSES {
        return Err(anyhow!("too many addresses (max {MAX_ADDRESSES})"));
    }
    for a in addrs {
        if SocketAddr::from_str(a).is_err() {
            return Err(anyhow!("invalid address: {a}"));
        }
    }
    Ok(())
}

pub fn validate_hex_field(name: &str, value: &str, length: usize) -> Result<()> {
    if value.len() != length {
        return Err(anyhow!("{name} must be {length} hex characters"));
    }
    if hex::decode(value).is_err() {
        return Err(anyhow!("{name} must be valid hex"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_addresses_accepts_up_to_eight_addrports() {
        let addrs: Vec<String> = (0..MAX_ADDRESSES).map(|i| format!("192.0.2.1:{}", 1000 + i)).collect();
        assert!(validate_addresses(&addrs).is_ok());
        let v6 = vec!["[2001:db8::1]:443".to_owned()];
        assert!(validate_addresses(&v6).is_ok());
    }

    #[test]
    fn validate_addresses_rejects_empty_overflow_and_malformed() {
        assert_eq!(validate_addresses(&[]).unwrap_err().to_string(), "at least one address required");
        let too_many: Vec<String> = (0..MAX_ADDRESSES + 1).map(|i| format!("192.0.2.1:{}", 1000 + i)).collect();
        assert_eq!(
            validate_addresses(&too_many).unwrap_err().to_string(),
            format!("too many addresses (max {MAX_ADDRESSES})")
        );
        for bad in ["192.0.2.1", "192.0.2.1:99999", "not-an-address", "2001:db8::1:443"] {
            assert_eq!(
                validate_addresses(&[bad.to_owned()]).unwrap_err().to_string(),
                format!("invalid address: {bad}")
            );
        }
    }

    #[test]
    fn validate_hex_field_checks_length_then_hex() {
        assert!(validate_hex_field("nonce", &"ab".repeat(16), NONCE_HEX_LENGTH).is_ok());
        assert_eq!(
            validate_hex_field("nonce", "abcd", NONCE_HEX_LENGTH).unwrap_err().to_string(),
            "nonce must be 32 hex characters"
        );
        assert_eq!(
            validate_hex_field("obfs", &"zz".repeat(32), OBFS_HEX_LENGTH).unwrap_err().to_string(),
            "obfs must be valid hex"
        );
    }

    #[test]
    fn bearer_requires_the_exact_prefix() {
        assert_eq!(bearer("Bearer abc"), "abc");
        assert_eq!(bearer("bearer abc"), "");
        assert_eq!(bearer("abc"), "");
        assert_eq!(bearer(""), "");
    }

    #[test]
    fn client_ip_prefers_the_configured_header() {
        assert_eq!(client_ip("10.0.0.1:5555", "X-Real-IP", "203.0.113.7"), "203.0.113.7");
        assert_eq!(client_ip("10.0.0.1:5555", "X-Real-IP", "203.0.113.7, 10.0.0.2"), "203.0.113.7");
        assert_eq!(client_ip("10.0.0.1:5555", "X-Real-IP", "203.0.113.7:9999"), "203.0.113.7");
        assert_eq!(client_ip("10.0.0.1:5555", "", "203.0.113.7"), "10.0.0.1");
        assert_eq!(client_ip("[2001:db8::1]:5555", "", ""), "2001:db8::1");
        assert_eq!(client_ip("10.0.0.1:5555", "X-Real-IP", "not-an-ip"), "10.0.0.1");
        assert_eq!(client_ip("10.0.0.1", "", ""), "10.0.0.1");
    }

    #[test]
    fn client_ip_unmaps_v4_mapped_v6_and_keeps_zones() {
        assert_eq!(client_ip("10.0.0.1:5555", "X-Real-IP", "::ffff:203.0.113.7"), "203.0.113.7");
        assert_eq!(client_ip("[fe80::1%eth0]:5555", "", ""), "fe80::1%eth0");
    }
}
