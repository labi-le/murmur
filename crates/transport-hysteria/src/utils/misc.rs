use std::net::IpAddr;

use anyhow::anyhow;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::{Addr, PacketConn};

pub fn split_host_port(hostport: &str) -> anyhow::Result<(String, u16)> {
    let (host, port) = split_host_port_parts(hostport)?;
    Ok((host.to_owned(), parse_port(port)?))
}

#[must_use]
pub fn parse_ip_zone(s: &str) -> (Option<IpAddr>, String) {
    let (host, zone) = split_host_zone(s);
    (host.parse::<IpAddr>().ok(), zone.to_owned())
}

#[async_trait]
pub trait PacketDialer: Send + Sync {
    async fn listen_packet(&self, r_addr: &dyn Addr) -> anyhow::Result<Box<dyn PacketConn>>;
    fn context(&self) -> CancellationToken;
    async fn remote_addr(&self, host: &str) -> anyhow::Result<Box<dyn Addr>>;
}

fn split_host_port_parts(hostport: &str) -> anyhow::Result<(&str, &str)> {
    let Some((host, port)) = hostport.rsplit_once(':') else {
        return Err(anyhow!("address {hostport}: missing port in address"));
    };
    let mut host = host;

    if let Some(unbracketed) = host.strip_prefix('[') {
        let Some(inner) = unbracketed.strip_suffix(']') else {
            return Err(anyhow!("address {hostport}: missing ']' in address"));
        };
        host = inner;
    } else if host.contains(':') {
        return Err(anyhow!("address {hostport}: too many colons in address"));
    }

    Ok((host, port))
}

fn parse_port(port: &str) -> anyhow::Result<u16> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(anyhow!("invalid port syntax"));
    }
    port.parse::<u16>().map_err(|_| anyhow!("port out of range"))
}

fn split_host_zone(s: &str) -> (&str, &str) {
    match s.rsplit_once('%') {
        Some((host, zone)) if !host.is_empty() => (host, zone),
        _ => (s, ""),
    }
}
