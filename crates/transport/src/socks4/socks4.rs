use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use ipnet::Ipv4Net;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use murmur_component::auth::auth::Authenticator;

pub const VERSION: u8 = 0x04;

pub type Command = u8;

pub const CMD_CONNECT: Command = 0x01;
pub const CMD_BIND: Command = 0x02;

pub type Code = u8;

pub const REQUEST_GRANTED: Code = 90;
pub const REQUEST_REJECTED: Code = 91;
pub const REQUEST_IDENTD_FAILED: Code = 92;
pub const REQUEST_IDENTD_MISMATCHED: Code = 93;

#[derive(thiserror::Error, Debug)]
#[error("version code mismatched")]
pub(crate) struct ErrVersionMismatched;

#[derive(thiserror::Error, Debug)]
#[error("command not supported")]
pub(crate) struct ErrCommandNotSupported;

#[derive(thiserror::Error, Debug)]
#[error("IPv6 not supported")]
pub(crate) struct ErrIPv6NotSupported;

#[derive(thiserror::Error, Debug)]
#[error("request rejected or failed")]
pub struct ErrRequestRejected;

#[derive(thiserror::Error, Debug)]
#[error("request rejected because SOCKS server cannot connect to identd on the client")]
pub struct ErrRequestIdentdFailed;

#[derive(thiserror::Error, Debug)]
#[error("request rejected because the client program and identd report different user-ids")]
pub struct ErrRequestIdentdMismatched;

#[derive(thiserror::Error, Debug)]
#[error("request failed with unknown code")]
pub struct ErrRequestUnknownCode;

pub(crate) static SUBNET: LazyLock<Ipv4Net> = LazyLock::new(|| Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 24));

pub async fn server_handshake<RW>(
    rw: &mut RW,
    authenticator: Option<Arc<dyn Authenticator>>,
) -> Result<(String, Command, String)>
where
    RW: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut req = [0u8; 8];
    rw.read_exact(&mut req).await?;

    if req[0] != VERSION {
        return Err(ErrVersionMismatched.into());
    }

    let command = req[1];
    if command != CMD_CONNECT {
        return Err(ErrCommandNotSupported.into());
    }

    let dst_ip = Ipv4Addr::from([req[4], req[5], req[6], req[7]]);
    let dst_port = [req[2], req[3]];

    let user_id = read_until_null(rw).await?;
    let user = String::from_utf8_lossy(&user_id).into_owned();

    let host = if is_reserved_ip(IpAddr::V4(dst_ip)) {
        let target = read_until_null(rw).await?;
        String::from_utf8_lossy(&target).into_owned()
    } else {
        String::new()
    };

    let port = u16::from_be_bytes(dst_port).to_string();
    let addr = if host.is_empty() { join_host_port(&dst_ip.to_string(), &port) } else { join_host_port(&host, &port) };

    // SOCKS4 only support USERID auth.
    let mut err: Option<anyhow::Error> = None;
    let code = if authenticator.as_ref().is_none_or(|authenticator| authenticator.verify(&user, "")) {
        REQUEST_GRANTED
    } else {
        err = Some(ErrRequestIdentdMismatched.into());
        REQUEST_IDENTD_MISMATCHED
    };

    let mut reply = [0u8; 8];
    reply[0] = 0x00; // reply code
    reply[1] = code; // result code
    reply[4..8].copy_from_slice(&dst_ip.octets());
    reply[2..4].copy_from_slice(&dst_port);

    let mut w_err = rw.write_all(&reply).await.err();
    if w_err.is_none() {
        w_err = rw.flush().await.err();
    }
    if err.is_none() {
        err = w_err.map(Into::into);
    }

    match err {
        Some(err) => Err(err),
        None => Ok((addr, command, user)),
    }
}

// NOT cancel-safe: the handshake writes its preamble and messages to the socket before it completes, so a dropped call leaves the connection mid-exchange; the arms that await it drop it only when the connection is being torn down.
pub async fn client_handshake<RW>(rw: &mut RW, addr: &str, command: Command, user_id: &str) -> Result<()>
where
    RW: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (host, port) = split_host_port(addr)?;

    let dst_ip = match parse_addr(&host) {
        Some(IpAddr::V6(_)) => return Err(ErrIPv6NotSupported.into()),
        Some(IpAddr::V4(v4)) => v4,
        None => Ipv4Addr::from([0, 0, 0, 1]),
    };

    let mut req = Vec::new();
    req.push(VERSION);
    req.push(command);
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&dst_ip.octets());
    req.extend_from_slice(user_id.as_bytes());
    req.push(0); // NULL

    // SOCKS4A
    if is_reserved_ip(IpAddr::V4(dst_ip)) {
        req.extend_from_slice(host.as_bytes());
        req.push(0); // NULL
    }

    rw.write_all(&req).await?;

    let mut resp = [0u8; 8];
    rw.read_exact(&mut resp).await?;

    if resp[0] != 0x00 {
        return Err(ErrVersionMismatched.into());
    }

    match resp[1] {
        REQUEST_GRANTED => Ok(()),
        REQUEST_REJECTED => Err(ErrRequestRejected.into()),
        REQUEST_IDENTD_FAILED => Err(ErrRequestIdentdFailed.into()),
        REQUEST_IDENTD_MISMATCHED => Err(ErrRequestIdentdMismatched.into()),
        _ => Err(ErrRequestUnknownCode.into()),
    }
}

/// A SOCKS4A client that cannot resolve the destination host sets DSTIP to `0.0.0.x` (x non-zero),
/// an address IANA deems inadmissible as a destination, so such an address means the host name
/// follows the USERID.
pub(crate) fn is_reserved_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && match ip {
            IpAddr::V4(v4) => SUBNET.contains(&v4),
            IpAddr::V6(_) => false,
        }
}

async fn read_until_null<RW>(r: &mut RW) -> Result<Vec<u8>>
where
    RW: AsyncRead + Unpin + ?Sized,
{
    const MAX_LEN: usize = 256;

    let mut buf = Vec::new();
    let mut data = [0u8; 1];

    loop {
        r.read_exact(&mut data).await?;
        if data[0] == 0 {
            return Ok(buf);
        }
        if buf.len() >= MAX_LEN {
            return Err(anyhow!("readUntilNull: data too long"));
        }
        buf.push(data[0]);
    }
}

/// A zone suffix is accepted only on an IPv6 address.
fn parse_addr(host: &str) -> Option<IpAddr> {
    let first_delimiter = host.bytes().find(|b| *b == b'.' || *b == b':');
    if first_delimiter == Some(b':') {
        if let Some((addr, zone)) = host.split_once('%') {
            if zone.is_empty() {
                return None;
            }
            return match addr.parse::<IpAddr>() {
                Ok(ip @ IpAddr::V6(_)) => Some(ip),
                _ => None,
            };
        }
    }
    host.parse::<IpAddr>().ok()
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn split_host_port(hostport: &str) -> Result<(String, u16)> {
    let (host, port) = split_host_port_parts(hostport)?;
    Ok((host.to_owned(), parse_port(port)?))
}

fn split_host_port_parts(hostport: &str) -> Result<(&str, &str)> {
    let Some((mut host, port)) = hostport.rsplit_once(':') else {
        return Err(anyhow!("address {hostport}: missing port in address"));
    };

    if let Some(bracketed) = host.strip_prefix('[') {
        let Some(bracketed) = bracketed.strip_suffix(']') else {
            return Err(anyhow!("address {hostport}: missing ']' in address"));
        };
        host = bracketed;
    } else if host.contains(':') {
        return Err(anyhow!("address {hostport}: too many colons in address"));
    }

    Ok((host, port))
}

fn parse_port(port: &str) -> Result<u16> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(anyhow!("invalid port syntax"));
    }
    port.parse::<u16>().map_err(|_| anyhow!("port out of range"))
}
