//! The Shadowsocks `ss://` URL splitter and the UDP packet backing store.
//!
//! DEVIATION: `Drop` cannot null the backing storage through the trait's
//! `&self` receiver (`constant::adapters::UDPPacket::drop_`), so the payload's readable length is
//! tracked in a separate atomic counter that `Drop` zeroes instead, mirroring
//! `listener::socks::utils::Packet`.
//!
//! DEVIATION: a multi-host-capable fork of the standard URL parser is needed
//! because the standard parser and the `url` crate both reject a comma-separated host such as
//! `ss://…@host1,host2,host3`. Only the host and
//! the userinfo are read off the parsed value, so this is a small purpose-built
//! scheme/userinfo/comma-separated-host splitter rather than a full RFC 3986 URL parser.

#[cfg(feature = "extra-protocols")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "extra-protocols")]
use std::sync::Arc;

use anyhow::{anyhow, Result};
#[cfg(feature = "extra-protocols")]
use async_trait::async_trait;
#[cfg(feature = "extra-protocols")]
use parking_lot::Mutex;

#[cfg(feature = "extra-protocols")]
use murmur_constant::adapters::{UDPPacket, WriteBack};
#[cfg(feature = "extra-protocols")]
use murmur_std_compat::net::PacketConn;
#[cfg(feature = "extra-protocols")]
use murmur_transport::socks5::socks5;

#[cfg(feature = "extra-protocols")]
pub(crate) struct Packet {
    pc: Arc<dyn PacketConn>,
    r_addr: std::net::SocketAddr,
    payload: Vec<u8>,
    len: AtomicUsize,
    put: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[cfg(feature = "extra-protocols")]
impl Packet {
    pub(crate) fn new(
        pc: Arc<dyn PacketConn>,
        r_addr: std::net::SocketAddr,
        payload: Vec<u8>,
        put: Option<Box<dyn FnOnce() + Send>>,
    ) -> Self {
        let len = AtomicUsize::new(payload.len());
        Self { pc, r_addr, payload, len, put: Mutex::new(put) }
    }
}

#[cfg(feature = "extra-protocols")]
#[async_trait]
impl WriteBack for Packet {
    /// Writes a UDP packet with source `(ip, port)` = `addr`.
    async fn write_back(&self, b: &[u8], addr: Option<std::net::SocketAddr>) -> Result<usize> {
        let addr = addr.ok_or_else(|| anyhow!("address is invalid"))?;
        let addr = murmur_common_net::io::udp_addr_from_socket_addr(addr);
        let socks_addr = socks5::parse_addr_to_socks_addr(&addr).ok_or_else(|| anyhow!("address is invalid"))?;
        let packet = encode_ss_udp_packet(&socks_addr, b);
        let r_addr = murmur_common_net::io::udp_addr_from_socket_addr(self.r_addr);
        Ok(self.pc.write_to(&packet, &r_addr).await?)
    }
}

/// Shadowsocks carries the target address and payload with no SOCKS5 RSV/FRAG preface; the
/// three zero bytes `socks5::encode_udp_packet` writes are SOCKS5 UDP framing, not SS framing.
/// Reusing that encoder here made every inbound SS UDP reply unparseable to a real client.
#[cfg(feature = "extra-protocols")]
fn encode_ss_udp_packet(addr: &socks5::Addr, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(addr.0.len() + payload.len());
    packet.extend_from_slice(&addr.0);
    packet.extend_from_slice(payload);
    packet
}

#[cfg(feature = "extra-protocols")]
impl UDPPacket for Packet {
    fn data(&self) -> &[u8] {
        self.payload.get(..self.len.load(Ordering::Acquire).min(self.payload.len())).unwrap_or_default()
    }

    fn drop_(&self) {
        let put = self.put.lock().take();
        if let Some(put) = put {
            put();
        }
        self.len.store(0, Ordering::Release);
    }

    /// The source IP/port of the UDP packet.
    fn local_addr(&self) -> std::net::SocketAddr {
        self.r_addr
    }

    fn in_addr(&self) -> Option<std::net::SocketAddr> {
        Some(
            self.pc
                .local_addr()
                .ok()
                .and_then(|a| murmur_common_net::io::old_addr_to_socket_addr(a.as_ref()).ok())
                .unwrap_or(self.r_addr),
        )
    }
}

/// The `ss://` URL parser. See the module-level DEVIATION note about the URL stand-in.
pub fn parse_ss_url(s: &str) -> Result<(String, String, String)> {
    let (_, rest) = s.split_once("://").ok_or_else(|| anyhow!("missing protocol scheme"))?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end).unwrap_or_default();

    let (userinfo, host_part) = match authority.rfind('@') {
        Some(i) => (authority.get(..i), authority.get(i + 1..).unwrap_or_default()),
        None => (None, authority),
    };

    let mut hosts = Vec::new();
    for host in host_part.split(',') {
        hosts.push(percent_decode(host)?);
    }
    let addr = hosts.join(",");

    let (cipher, password) = match userinfo {
        Some(info) => match info.split_once(':') {
            Some((user, pass)) => (percent_decode(user)?, percent_decode(pass)?),
            None => (percent_decode(info)?, String::new()),
        },
        None => (String::new(), String::new()),
    };

    Ok((addr, cipher, password))
}

/// `unescape`: query-style `%XX` decoding, the subset the URL parsers' host/userinfo parsing
/// needs. Shared by [`parse_ss_url`] and `sing_vmess::server::parse_vmess_url`.
pub(crate) fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hi = bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16));
            let lo = bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16));
            let (Some(hi), Some(lo)) = (hi, lo) else {
                let end = (i + 3).min(bytes.len());
                let escape = bytes.get(i..end).unwrap_or_default();
                return Err(anyhow!("invalid URL escape {:?}", String::from_utf8_lossy(escape)));
            };
            let hi = u8::try_from(hi).map_err(|err| anyhow!("invalid URL escape at byte {i}: {err}"))?;
            let lo = u8::try_from(lo).map_err(|err| anyhow!("invalid URL escape at byte {i}: {err}"))?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

#[cfg(test)]
mod tests {
    use super::{encode_ss_udp_packet, parse_ss_url};

    /// The bad escape's bytes are quoted with `String::from_utf8_lossy` + `Debug`, never sliced
    /// as a `&str` directly — the raw bytes around a bad escape have no char-boundary
    /// guarantee. The equivalent Rust `&str` slice panicked on a non-char-boundary byte index
    /// whenever the invalid escape sat next to a multi-byte UTF-8 character, which is exactly
    /// what `%€` does here.
    #[test]
    fn parse_ss_url_rejects_malformed_percent_encoding_without_panicking() {
        let err = parse_ss_url("ss://a:b@%€:1000").unwrap_err();
        assert_eq!(err.to_string(), "invalid URL escape \"%\u{fffd}\"");
    }

    #[test]
    fn test_parse_ss_url() {
        for (method, passwd, hosts) in [
            ("aes-256-gcm", "password", ":1000,:2000,:3000"),
            ("aes-256-gcm", "password", "127.0.0.1:1000,127.0.0.1:2000,127.0.0.1:3000"),
            ("aes-256-gcm", "password", "[::1]:1000,[::1]:2000,[::1]:3000"),
        ] {
            let (addr, cipher, password) = parse_ss_url(&format!("ss://{method}:{passwd}@{hosts}")).unwrap();
            assert_eq!(addr, hosts);
            assert_eq!(cipher, method);
            assert_eq!(password, passwd);
        }
    }

    #[cfg(feature = "extra-protocols")]
    #[test]
    fn shadowsocks_udp_reply_has_no_socks5_rsv_frag_preface() {
        let addr = murmur_transport::socks5::socks5::addr_from_std_addr_port("127.0.0.1:53".parse().unwrap());
        let packet = encode_ss_udp_packet(&addr, b"payload");
        assert_eq!(packet, [1, 127, 0, 0, 1, 0, 53, b'p', b'a', b'y', b'l', b'o', b'a', b'd']);
    }
}
