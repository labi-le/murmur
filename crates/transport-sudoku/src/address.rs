use std::net::IpAddr;

use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use tokio::io::{AsyncRead, AsyncReadExt};

use murmur_component::dialer::bind::join_host_port;

pub fn encode_address(raw_addr: &str) -> Result<Vec<u8>> {
    let (host, port_str) = split_host_port(raw_addr)?;

    let port_int: u16 = port_str.parse().map_err(|err| anyhow!("invalid port {port_str:?}: {err}"))?;

    let mut buf = Vec::new();
    let host = match host.find('%') {
        Some(i) => host.split_at(i).0,
        None => host.as_str(),
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip4) => {
                buf.push(0x01);
                buf.extend_from_slice(&ip4.octets());
            }
            IpAddr::V6(ip6) => {
                buf.push(0x04);
                buf.extend_from_slice(&ip6.octets());
            }
        }
    } else {
        let host_len = u8::try_from(host.len()).map_err(|_| anyhow!("domain too long"))?;
        buf.push(0x03);
        buf.push(host_len);
        buf.extend_from_slice(host.as_bytes());
    }

    let mut port_bytes = [0u8; 2];
    BigEndian::write_u16(&mut port_bytes, port_int);
    buf.extend_from_slice(&port_bytes);
    Ok(buf)
}

/// Splits a `host:port` pair, restricted to what `EncodeAddress` needs.
fn split_host_port(raw_addr: &str) -> Result<(String, String)> {
    let idx = raw_addr.rfind(':').ok_or_else(|| anyhow!("address {raw_addr:?}: missing port in address"))?;
    let (host_part, port_part) = raw_addr.split_at(idx);
    let port =
        port_part.strip_prefix(':').ok_or_else(|| anyhow!("address {raw_addr:?}: missing port in address"))?.to_owned();
    let mut host = host_part.to_owned();
    if let Some(unbracketed) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        host = unbracketed.to_owned();
    }
    Ok((host, port))
}

pub(crate) async fn decode_address<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> Result<String> {
    let mut atyp = [0u8; 1];
    r.read_exact(&mut atyp).await?;

    match atyp[0] {
        0x01 => {
            let mut ip_buf = [0u8; 4];
            r.read_exact(&mut ip_buf).await?;
            let mut port_buf = [0u8; 2];
            r.read_exact(&mut port_buf).await?;
            let ip = IpAddr::from(ip_buf);
            Ok(join_host_port(&ip.to_string(), BigEndian::read_u16(&port_buf)))
        }
        0x04 => {
            let mut ip_buf = [0u8; 16];
            r.read_exact(&mut ip_buf).await?;
            let mut port_buf = [0u8; 2];
            r.read_exact(&mut port_buf).await?;
            let ip = IpAddr::from(ip_buf);
            Ok(join_host_port(&ip.to_string(), BigEndian::read_u16(&port_buf)))
        }
        0x03 => {
            let mut length_buf = [0u8; 1];
            r.read_exact(&mut length_buf).await?;
            let l = length_buf[0] as usize;
            let mut host_buf = vec![0u8; l];
            r.read_exact(&mut host_buf).await?;
            let mut port_buf = [0u8; 2];
            r.read_exact(&mut port_buf).await?;
            let host = String::from_utf8_lossy(&host_buf).into_owned();
            Ok(join_host_port(&host, BigEndian::read_u16(&port_buf)))
        }
        other => Err(anyhow!("unknown address type: {other}")),
    }
}
