use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use murmur_component::dialer::bind::{join_host_port, parse_address_port, unmap_addr};
use murmur_std_compat::net::{Addr, UdpAddr};

use super::dns::DNSMode;
use super::version::PROJECT_NAME;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddrType(pub u8);

impl AddrType {
    pub const ATYP_IPV4: Self = Self(1);
    pub const ATYP_DOMAIN_NAME: Self = Self(3);
    pub const ATYP_IPV6: Self = Self(4);

    #[must_use]
    pub fn string(&self) -> String {
        match *self {
            Self::ATYP_IPV4 => "IPv4",
            Self::ATYP_DOMAIN_NAME => "DomainName",
            Self::ATYP_IPV6 => "IPv6",
            _ => "Unknown",
        }
        .to_owned()
    }
}

impl fmt::Display for AddrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetWork(pub i32);

impl NetWork {
    pub const TCP: Self = Self(0);
    pub const UDP: Self = Self(1);
    pub const ALL_NET: Self = Self(2);
    pub const INVALID_NET: Self = Self(0xff);

    #[must_use]
    pub fn string(&self) -> String {
        match *self {
            Self::TCP => "tcp",
            Self::UDP => "udp",
            Self::ALL_NET => "all",
            _ => "invalid",
        }
        .to_owned()
    }
}

impl fmt::Display for NetWork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

impl Serialize for NetWork {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.string())
    }
}

impl<'de> Deserialize<'de> for NetWork {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NetWorkVisitor;

        impl Visitor<'_> for NetWorkVisitor {
            type Value = NetWork;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a network name or number")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<NetWork, E> {
                match value {
                    "tcp" => Ok(NetWork::TCP),
                    "udp" => Ok(NetWork::UDP),
                    "all" => Ok(NetWork::ALL_NET),
                    "invalid" => Ok(NetWork::INVALID_NET),
                    _ => Err(E::custom(format!("invalid network: {value}"))),
                }
            }

            #[expect(
                clippy::cast_possible_truncation,
                reason = "the network id is stored in this 32-bit field; a wider JSON number truncates into it"
            )]
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<NetWork, E> {
                Ok(NetWork(value as i32))
            }

            #[expect(
                clippy::cast_possible_truncation,
                reason = "the network id is stored in this 32-bit field; a wider JSON number truncates into it"
            )]
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<NetWork, E> {
                Ok(NetWork(value as i32))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<NetWork, E> {
                Ok(NetWork::default())
            }
        }

        deserializer.deserialize_any(NetWorkVisitor)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Type(pub i32);

impl Type {
    pub const HTTP: Self = Self(0);
    pub const HTTPS: Self = Self(1);
    pub const SOCKS4: Self = Self(2);
    pub const SOCKS5: Self = Self(3);
    pub const SHADOWSOCKS: Self = Self(4);
    pub const SNELL: Self = Self(5);
    pub const VMESS: Self = Self(6);
    pub const VLESS: Self = Self(7);
    pub const REDIR: Self = Self(8);
    pub const TPROXY: Self = Self(9);
    pub const TROJAN: Self = Self(10);
    pub const TUNNEL: Self = Self(11);
    pub const TUN: Self = Self(12);
    pub const TUIC: Self = Self(13);
    pub const HYSTERIA2: Self = Self(14);
    pub const ANYTLS: Self = Self(15);
    pub const MIERU: Self = Self(16);
    pub const SUDOKU: Self = Self(17);
    pub const TRUSTTUNNEL: Self = Self(18);
    pub const SHADOWQUIC: Self = Self(19);
    pub const INNER: Self = Self(20);

    #[must_use]
    pub fn string(&self) -> String {
        match *self {
            Self::HTTP => "HTTP",
            Self::HTTPS => "HTTPS",
            Self::SOCKS4 => "Socks4",
            Self::SOCKS5 => "Socks5",
            Self::SHADOWSOCKS => "ShadowSocks",
            Self::SNELL => "Snell",
            Self::VMESS => "Vmess",
            Self::VLESS => "Vless",
            Self::REDIR => "Redir",
            Self::TPROXY => "TProxy",
            Self::TROJAN => "Trojan",
            Self::TUNNEL => "Tunnel",
            Self::TUN => "Tun",
            Self::TUIC => "Tuic",
            Self::HYSTERIA2 => "Hysteria2",
            Self::ANYTLS => "AnyTLS",
            Self::MIERU => "Mieru",
            Self::SUDOKU => "Sudoku",
            Self::TRUSTTUNNEL => "TrustTunnel",
            Self::SHADOWQUIC => "ShadowQuic",
            Self::INNER => "Inner",
            _ => "Unknown",
        }
        .to_owned()
    }
}

pub fn parse_type(t: &str) -> Result<Type> {
    match t {
        "HTTP" => Ok(Type::HTTP),
        "HTTPS" => Ok(Type::HTTPS),
        "SOCKS4" => Ok(Type::SOCKS4),
        "SOCKS5" => Ok(Type::SOCKS5),
        "SHADOWSOCKS" => Ok(Type::SHADOWSOCKS),
        "SNELL" => Ok(Type::SNELL),
        "VMESS" => Ok(Type::VMESS),
        "VLESS" => Ok(Type::VLESS),
        "REDIR" => Ok(Type::REDIR),
        "TPROXY" => Ok(Type::TPROXY),
        "TROJAN" => Ok(Type::TROJAN),
        "TUNNEL" => Ok(Type::TUNNEL),
        "TUN" => Ok(Type::TUN),
        "TUIC" => Ok(Type::TUIC),
        "HYSTERIA2" => Ok(Type::HYSTERIA2),
        "ANYTLS" => Ok(Type::ANYTLS),
        "MIERU" => Ok(Type::MIERU),
        "SUDOKU" => Ok(Type::SUDOKU),
        "TRUSTTUNNEL" => Ok(Type::TRUSTTUNNEL),
        "SHADOWQUIC" => Ok(Type::SHADOWQUIC),
        "INNER" => Ok(Type::INNER),
        _ => Err(anyhow::anyhow!("unknown type: {t}")),
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

impl Serialize for Type {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.string())
    }
}

impl<'de> Deserialize<'de> for Type {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TypeVisitor;

        impl Visitor<'_> for TypeVisitor {
            type Value = Type;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a type name or number")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Type, E> {
                parse_type(value).map_err(E::custom)
            }

            #[expect(
                clippy::cast_possible_truncation,
                reason = "the type id is stored in this 32-bit field; a wider JSON number truncates into it"
            )]
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Type, E> {
                Ok(Type(value as i32))
            }

            #[expect(
                clippy::cast_possible_truncation,
                reason = "the type id is stored in this 32-bit field; a wider JSON number truncates into it"
            )]
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Type, E> {
                Ok(Type(value as i32))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Type, E> {
                Ok(Type::default())
            }
        }

        deserializer.deserialize_any(TypeVisitor)
    }
}

/// An address has no crate mirror; `None` is its invalid zero value, as in the dialer.
fn netip_string(ip: Option<&IpAddr>) -> String {
    match ip {
        Some(ip) => ip.to_string(),
        None => "invalid IP".to_owned(),
    }
}

/// Parses an address, accepting a zone that `IpAddr` cannot hold.
fn parse_netip_addr(host: &str) -> Option<IpAddr> {
    let host = host.split('%').next().unwrap_or(host);
    host.parse().ok()
}

/// Parses a signed decimal integer, keeping the value it produces on error too, since call sites
/// use it unconditionally.
///
/// Accepts an optional leading `+`/`-`. A magnitude that overflows `u64` clamps to
/// `i64::MAX`/`i64::MIN` by sign as soon as it overflows, before any later byte is looked at; any
/// other non-digit byte yields `0`; the `i64` range is applied only after the whole string parsed.
#[must_use]
pub fn parse_int(s: &str) -> i64 {
    const CUTOFF: u64 = 1u64 << 63;

    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if digits.is_empty() {
        return 0;
    }
    let mut n: u64 = 0;
    for b in digits.bytes() {
        if !b.is_ascii_digit() {
            return 0;
        }
        n = match n.checked_mul(10).and_then(|v| v.checked_add(u64::from(b - b'0'))) {
            Some(v) => v,
            None => return if neg { i64::MIN } else { i64::MAX },
        };
    }
    if neg {
        if n > CUTOFF {
            i64::MIN
        } else {
            n.cast_signed().wrapping_neg()
        }
    } else if n >= CUTOFF {
        i64::MAX
    } else {
        n.cast_signed()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Metadata {
    pub network: NetWork,
    #[serde(rename = "type")]
    pub type_: Type,
    #[serde(rename = "sourceIP", with = "netip_addr_json")]
    pub src_ip: Option<IpAddr>,
    #[serde(rename = "destinationIP", with = "netip_addr_json")]
    pub dst_ip: Option<IpAddr>,
    /// The geo cache: `None` means never queried (`null` on the wire), `Some(vec![])` is a lookup
    /// that found nothing, which the later rules must not repeat.
    #[serde(rename = "sourceGeoIP")]
    pub src_geo_ip: Option<Vec<String>>,
    #[serde(rename = "destinationGeoIP")]
    pub dst_geo_ip: Option<Vec<String>>,
    #[serde(rename = "sourceIPASN")]
    pub src_ipasn: String,
    #[serde(rename = "destinationIPASN")]
    pub dst_ipasn: String,
    #[serde(rename = "sourcePort", with = "port_string")]
    pub src_port: u16,
    #[serde(rename = "destinationPort", with = "port_string")]
    pub dst_port: u16,
    #[serde(rename = "inboundIP", with = "netip_addr_json")]
    pub in_ip: Option<IpAddr>,
    #[serde(rename = "inboundPort", with = "port_string")]
    pub in_port: u16,
    #[serde(rename = "inboundName")]
    pub in_name: String,
    #[serde(rename = "inboundUser")]
    pub in_user: String,
    #[serde(rename = "rematchName")]
    pub rematch_name: String,
    pub host: String,
    #[serde(rename = "dnsMode")]
    pub dns_mode: DNSMode,
    pub uid: u32,
    pub process: String,
    #[serde(rename = "processPath")]
    pub process_path: String,
    #[serde(rename = "specialProxy")]
    pub special_proxy: String,
    #[serde(rename = "specialRules")]
    pub special_rules: String,
    #[serde(rename = "remoteDestination")]
    pub remote_dst: String,
    pub dscp: u8,
    /// Held by shared reference, so every copy of the metadata sees the same values.
    #[serde(skip)]
    pub raw_src_addr: Option<Arc<dyn Addr>>,
    #[serde(skip)]
    pub raw_dst_addr: Option<Arc<dyn Addr>>,
    #[serde(rename = "sniffHost")]
    pub sniff_host: String,
}
/// The port fields serialize as a JSON string holding the number.
mod port_string {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    #[expect(clippy::trivially_copy_pass_by_ref, reason = "serde's `with` module receives the field as `&u16`")]
    pub(super) fn serialize<S: Serializer>(port: &u16, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&port.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse::<u16>().map_err(D::Error::custom)
    }
}

/// An address marshals as text, and its zero value marshals as the empty string.
mod netip_addr_json {
    use std::net::IpAddr;

    use serde::{Deserialize, Deserializer, Serializer};

    use super::parse_netip_addr;

    #[expect(clippy::ref_option, reason = "serde's `with` module receives the field as `&Option<T>`")]
    pub(super) fn serialize<S: Serializer>(addr: &Option<IpAddr>, serializer: S) -> Result<S::Ok, S::Error> {
        match addr {
            Some(addr) => serializer.serialize_str(&addr.to_string()),
            None => serializer.serialize_str(""),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<IpAddr>, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty() {
            return Ok(None);
        }
        parse_netip_addr(&text).map(Some).ok_or_else(|| serde::de::Error::custom("invalid IP address"))
    }
}

impl Metadata {
    #[must_use]
    pub fn remote_address(&self) -> String {
        join_host_port(&self.string(), self.dst_port)
    }

    #[must_use]
    pub fn source_address(&self) -> String {
        join_host_port(&netip_string(self.src_ip.as_ref()), self.src_port)
    }

    #[must_use]
    pub fn source_addr_port(&self) -> Option<SocketAddr> {
        unmap_addr(self.src_ip).map(|ip| SocketAddr::new(ip, self.src_port))
    }

    #[must_use]
    pub fn source_detail(&self) -> String {
        if self.type_ == Type::INNER {
            return PROJECT_NAME.to_owned();
        }

        match (self.process.is_empty(), self.uid) {
            (false, uid) if uid != 0 => format!("{}({}, uid={})", self.source_address(), self.process, self.uid),
            (_, uid) if uid != 0 => format!("{}(uid={})", self.source_address(), self.uid),
            (false, _) => format!("{}({})", self.source_address(), self.process),
            _ => self.source_address(),
        }
    }

    #[must_use]
    pub const fn source_valid(&self) -> bool {
        self.src_port != 0 && self.src_ip.is_some()
    }

    #[must_use]
    pub const fn addr_type(&self) -> AddrType {
        if !self.host.is_empty() || self.dst_ip.is_none() {
            AddrType::ATYP_DOMAIN_NAME
        } else if matches!(self.dst_ip, Some(IpAddr::V4(_))) {
            AddrType::ATYP_IPV4
        } else {
            AddrType::ATYP_IPV6
        }
    }

    #[must_use]
    pub const fn resolved(&self) -> bool {
        self.dst_ip.is_some()
    }

    #[must_use]
    pub fn rule_host(&self) -> &str {
        if self.sniff_host.is_empty() {
            &self.host
        } else {
            &self.sniff_host
        }
    }

    /// Returns the receiver itself when it is already pure; here a clone is answered in both
    /// cases.
    #[must_use]
    pub fn pure(&self) -> Self {
        if (self.dns_mode == DNSMode::DNS_MAPPING || self.dns_mode == DNSMode::DNS_HOSTS) && self.dst_ip.is_some() {
            let mut copy = self.clone();
            copy.host = String::new();
            return copy;
        }

        self.clone()
    }

    #[must_use]
    pub fn addr_port(&self) -> Option<SocketAddr> {
        unmap_addr(self.dst_ip).map(|ip| SocketAddr::new(ip, self.dst_port))
    }

    #[must_use]
    pub fn udp_addr(&self) -> Option<UdpAddr> {
        if self.network != NetWork::UDP || self.dst_ip.is_none() {
            return None;
        }
        unmap_addr(self.dst_ip).map(|ip| UdpAddr::new(ip, self.dst_port))
    }

    #[must_use]
    pub fn string(&self) -> String {
        if !self.host.is_empty() {
            self.host.clone()
        } else if self.dst_ip.is_some() {
            netip_string(self.dst_ip.as_ref())
        } else {
            "<nil>".to_owned()
        }
    }

    #[must_use]
    pub const fn valid(&self) -> bool {
        !self.host.is_empty() || self.dst_ip.is_some()
    }

    pub fn set_remote_addr(&mut self, addr: Option<&dyn Addr>) -> Result<()> {
        let Some(addr) = addr else {
            return Ok(());
        };
        if let Some(raw_addr) = addr.raw_addr() {
            if self.set_remote_addr(Some(raw_addr)).is_ok() {
                return Ok(());
            }
        }
        if let Some(addr_port) = addr.addr_port() {
            if addr_port.port != 0 {
                self.dst_port = addr_port.port;
                if let Some(ip) = addr_port.ip {
                    self.dst_ip = unmap_addr(Some(ip));
                    return Ok(());
                }
                if let Some(fqdn) = addr_port.fqdn {
                    self.host = fqdn;
                    return Ok(());
                }
            }
        }
        self.set_remote_address(&addr.string())
    }

    pub fn set_remote_address(&mut self, raw_address: &str) -> Result<()> {
        let (host, port) = murmur_common::net_addr::split_host_port(raw_address)?;

        let uint16_port: u16 = parse_address_port(&port);

        if let Some(ip) = parse_netip_addr(&host) {
            self.host = String::new();
            self.dst_ip = unmap_addr(Some(ip));
        } else {
            self.host = host;
            self.dst_ip = None;
        }
        self.dst_port = uint16_port;

        Ok(())
    }

    pub const fn swap_src_dst(&mut self) {
        std::mem::swap(&mut self.src_ip, &mut self.dst_ip);
        std::mem::swap(&mut self.src_port, &mut self.dst_port);
        std::mem::swap(&mut self.src_ipasn, &mut self.dst_ipasn);
        std::mem::swap(&mut self.src_geo_ip, &mut self.dst_geo_ip);
    }
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A geo slice stays absent until a lookup runs, and a lookup that finds nothing leaves an
    /// empty slice behind; the wire form and later rules distinguish the two.
    #[test]
    fn geo_ip_caches_serialize_absent_and_empty_slices() {
        let untouched = serde_json::to_value(Metadata::default()).expect("metadata serializes");
        assert!(untouched["sourceGeoIP"].is_null(), "{untouched}");
        assert!(untouched["destinationGeoIP"].is_null(), "{untouched}");

        let queried =
            Metadata { src_geo_ip: Some(Vec::new()), dst_geo_ip: Some(vec!["US".to_owned()]), ..Metadata::default() };
        let queried = serde_json::to_value(queried).expect("metadata serializes");
        assert_eq!(queried["sourceGeoIP"], serde_json::json!([]));
        assert_eq!(queried["destinationGeoIP"], serde_json::json!(["US"]));
    }

    #[test]
    fn set_remote_address_rejects_leading_plus_in_port() {
        let mut m = Metadata::default();
        m.set_remote_address("example.com:+80").unwrap();
        assert_eq!(m.dst_port, 0, "port parsing rejects a leading '+' and leaves the port at 0");

        m.set_remote_address("example.com:80").unwrap();
        assert_eq!(m.dst_port, 80);
    }

    /// Expected values match the signed-decimal rules this function implements. Cast to `u16`
    /// where the old `s.parse::<u16>().unwrap_or(0)` this function replaced at its call sites would
    /// have given a different answer, so a regression to that old behaviour fails these assertions.
    #[test]
    fn parse_int_matches_its_documented_semantics() {
        assert_eq!(parse_int("+80") as u16, 80);
        assert_eq!(parse_int("-0") as u16, 0);
        assert_eq!(parse_int("080") as u16, 80);
        assert_eq!(parse_int(" 80") as u16, 0);
        assert_eq!(parse_int("") as u16, 0);
        assert_eq!(parse_int("65536"), 65536);
        assert_eq!(parse_int("70000") as u16, 4464, "uint16(70000) wraps, unlike u16::from_str");
        assert_eq!(parse_int("-80") as u16, 65456, "a leading '-' is accepted, unlike an unsigned parse");
        assert_eq!(parse_int("-65456") as u16, 80);
        assert_eq!(parse_int("9223372036854775808"), i64::MAX, "a positive overflow clamps to MaxInt64");
        assert_eq!(parse_int("-9223372036854775809"), i64::MIN, "a negative overflow clamps to MinInt64");

        // Overflow clamps as soon as the digits so far exceed i64, before the trailing garbage
        // byte is looked at.
        assert_eq!(parse_int("99999999999999999999x"), i64::MAX);
        assert_eq!(parse_int("-99999999999999999999x"), i64::MIN);
        // Past i64 but within u64, then junk: the unsigned parse reports a syntax error, so the
        // result is 0.
        assert_eq!(parse_int("9223372036854775808x"), 0);
        assert_eq!(parse_int("-9999999999999999999x"), 0);
        assert_eq!(parse_int("9223372036854775808"), i64::MAX);
        assert_eq!(parse_int("-9223372036854775809"), i64::MIN);

        assert_eq!(
            murmur_sing::metadata::parse_socksaddr("1.2.3.4:70000").port,
            4464,
            "an out-of-range port wraps the same way"
        );
    }

    /// A sniffed name replaces the connection host for rule matching, so routing must follow the
    /// sniff while it is set and fall back to the host once it is cleared.
    #[test]
    fn rule_host_prefers_a_sniffed_host_over_the_connection_host() {
        let mut metadata = Metadata {
            host: "host.example.com".to_owned(),
            sniff_host: "sniff.example.com".to_owned(),
            ..Metadata::default()
        };
        assert_eq!(metadata.rule_host(), "sniff.example.com");

        metadata.sniff_host = String::new();
        assert_eq!(metadata.rule_host(), "host.example.com");
    }
}
