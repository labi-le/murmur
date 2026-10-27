//! DEVIATION: the crate already links `libc` for every other FFI call, so `getsockopt` goes
//! through `libc::getsockopt` rather than a raw `syscall`. Both reach the identical kernel entry
//! point with identical arguments.

#![cfg(target_os = "freebsd")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};

use anyhow::Result;
use tokio::net::TcpStream;

use murmur_transport::socks5::socks5;

/// `SO_ORIGINAL_DST`, from `linux/include/uapi/linux/netfilter_ipv4.h`.
const SO_ORIGINAL_DST: libc::c_int = 80;
/// `IP6T_SO_ORIGINAL_DST`, from `linux/include/uapi/linux/netfilter_ipv6/ip6_tables.h`.
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

fn is_ipv4(ip: IpAddr) -> bool {
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
#[expect(unsafe_code, reason = "zeroed sockaddr_in handed to getsockopt(SO_ORIGINAL_DST)")]
fn get_orig_dst(fd: RawFd) -> std::io::Result<std::net::SocketAddr> {
    // Safety: `libc::sockaddr_in` is plain-old-data; zero-initializing it is valid, and
    // `getsockopt` fills it in place, staying within the buffer described by `len`.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_IP,
            SO_ORIGINAL_DST,
            std::ptr::addr_of_mut!(addr).cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let port = u16::from_be(addr.sin_port);
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    Ok(std::net::SocketAddr::new(IpAddr::V4(ip), port))
}

#[expect(unsafe_code, reason = "zeroed sockaddr_in6 handed to getsockopt(IP6T_SO_ORIGINAL_DST)")]
fn get_orig_dst6(fd: RawFd) -> std::io::Result<std::net::SocketAddr> {
    // Safety: `libc::sockaddr_in6` is plain-old-data; zero-initializing it is valid, and
    // `getsockopt` fills it in place, staying within the buffer described by `len`.
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IP6T_SO_ORIGINAL_DST,
            std::ptr::addr_of_mut!(addr).cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let port = u16::from_be(addr.sin6_port);
    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
    Ok(std::net::SocketAddr::new(IpAddr::V6(ip), port))
}
