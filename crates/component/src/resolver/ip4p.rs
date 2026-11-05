use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use murmur_log::debugln;

static IP4P_ENABLE: AtomicBool = AtomicBool::new(false);

pub fn get_ip4p_enable() -> bool {
    IP4P_ENABLE.load(Ordering::Relaxed)
}

pub fn set_ip4p_enable(enable_ip4p_convert: bool) {
    IP4P_ENABLE.store(enable_ip4p_convert, Ordering::Relaxed);
}

/// The address as bytes: 4 for IPv4, 16 for IPv6.
fn addr_as_slice(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// An IPv4-embedded address yields the IPv4 address and port it encodes.
#[must_use]
pub fn lookup_ip4p(addr: IpAddr, port: &str) -> (IpAddr, String) {
    if get_ip4p_enable() {
        let ip = addr_as_slice(addr);
        if let [0x20, 0x01, 0x00, 0x00, _, _, _, _, _, _, port_hi, port_lo, a, b, c, d] = ip.as_slice() {
            let addr = IpAddr::from([*a, *b, *c, *d]);
            let port = u16::from_be_bytes([*port_hi, *port_lo]).to_string();
            debugln!(
                "Convert IP4P address {} to {}",
                String::from_utf8_lossy(&ip),
                join_host_port(&addr.to_string(), &port)
            );
            return (addr, port);
        }
    }
    (addr, port.to_owned())
}
