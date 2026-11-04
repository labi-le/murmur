#![cfg(target_os = "linux")]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};

use anyhow::Result;
use tokio::net::TcpStream;

use murmur_transport::socks5::socks5;

#[cfg(target_arch = "x86")]
use super::tcp_linux_386::{socketcall, GETSOCKOPT};
#[cfg(not(target_arch = "x86"))]
use super::tcp_linux_other::{socketcall, GETSOCKOPT};

/// `SO_ORIGINAL_DST`, from `linux/include/uapi/linux/netfilter_ipv4.h`.
const SO_ORIGINAL_DST: i32 = 80;
/// `IP6T_SO_ORIGINAL_DST`, from `linux/include/uapi/linux/netfilter_ipv6/ip6_tables.h`.
const IP6T_SO_ORIGINAL_DST: i32 = 80;

const fn is_ipv4(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
    }
}

pub(crate) fn parser_packet(conn: &TcpStream) -> Result<socks5::Addr> {
    let fd = conn.as_raw_fd();
    let local_ip = conn.local_addr()?.ip();

    let addr = if is_ipv4(local_ip) { get_orig_dst(fd)? } else { get_orig_dst6(fd)? };
    Ok(socks5::addr_from_std_addr_port(addr))
}

/// Reads the original destination through `SO_ORIGINAL_DST`, whose kernel handler lives in
/// `linux/net/ipv4/netfilter/nf_conntrack_l3proto_ipv4.c`.
fn get_orig_dst(fd: RawFd) -> io::Result<std::net::SocketAddr> {
    let fd = usize::try_from(fd).map_err(|_| io::Error::other("negative file descriptor"))?;
    let mut addr =
        libc::sockaddr_in { sin_family: 0, sin_port: 0, sin_addr: libc::in_addr { s_addr: 0 }, sin_zero: [0; 8] };
    let mut len =
        u32::try_from(size_of::<libc::sockaddr_in>()).map_err(|_| io::Error::other("sockaddr length exceeds u32"))?;
    socketcall(
        GETSOCKOPT,
        fd,
        libc::IPPROTO_IP as usize,
        SO_ORIGINAL_DST as usize,
        std::ptr::addr_of_mut!(addr) as usize,
        std::ptr::addr_of_mut!(len) as usize,
        0,
    )?;
    let port = u16::from_be(addr.sin_port);
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    Ok(std::net::SocketAddr::new(IpAddr::V4(ip), port))
}

fn get_orig_dst6(fd: RawFd) -> io::Result<std::net::SocketAddr> {
    let fd = usize::try_from(fd).map_err(|_| io::Error::other("negative file descriptor"))?;
    let mut addr = libc::sockaddr_in6 {
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
        sin6_scope_id: 0,
    };
    let mut len =
        u32::try_from(size_of::<libc::sockaddr_in6>()).map_err(|_| io::Error::other("sockaddr length exceeds u32"))?;
    socketcall(
        GETSOCKOPT,
        fd,
        libc::IPPROTO_IPV6 as usize,
        IP6T_SO_ORIGINAL_DST as usize,
        std::ptr::addr_of_mut!(addr) as usize,
        std::ptr::addr_of_mut!(len) as usize,
        0,
    )?;
    let port = u16::from_be(addr.sin6_port);
    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
    Ok(std::net::SocketAddr::new(IpAddr::V6(ip), port))
}
