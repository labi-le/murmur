use std::net::IpAddr;
use std::os::fd::RawFd;

use anyhow::Result;

use super::udp_linux::IPV6_RECVORIGDSTADDR;

/// Splits a `host:port`/`:port` string closely enough for the forms this package ever sees.
fn split_host(addr: &str) -> &str {
    match addr.rsplit_once(':') {
        Some((host, _)) => host.trim_start_matches('[').trim_end_matches(']'),
        None => addr,
    }
}

#[expect(unsafe_code, reason = "setsockopt on a descriptor open for the call")]
fn set_int_opt(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> std::io::Result<()> {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a `socklen_t` describes a length in bytes and is never narrower than the `int` above it"
    )]
    // SAFETY: `fd` is a valid, open socket for the lifetime of this call; `value` is passed as a
    // plain `c_int` matching `setsockopt`'s documented `SOL_SOCKET`/`SOL_IP`/`SOL_IPV6` usage.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(&value).cast::<libc::c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Applies the transparent-proxy options a TPROXY socket needs. Takes the socket itself
/// rather than its descriptor so the options `socket2` names do not need an unsafe wrapper.
pub fn setsockopt<S: std::os::fd::AsFd + std::os::fd::AsRawFd>(socket: &S, addr: &str) -> Result<()> {
    let mut is_ipv6 = true;
    let host = split_host(addr);
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_ipv4() {
            is_ipv6 = false;
        }
        if let IpAddr::V6(v6) = ip {
            if v6.to_ipv4_mapped().is_some() {
                is_ipv6 = false;
            }
        }
    }

    let fd = socket.as_raw_fd();
    let socket = socket2::SockRef::from(socket);
    socket.set_reuse_address(true)?;
    socket.set_ip_transparent_v4(true)?;
    if is_ipv6 {
        socket.set_ip_transparent_v6(true)?;
    }
    set_int_opt(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1)?;
    if is_ipv6 {
        set_int_opt(fd, libc::SOL_IPV6, IPV6_RECVORIGDSTADDR, 1)?;
    }
    let _ = set_dscp_sockopt(fd, is_ipv6);

    Ok(())
}

fn set_dscp_sockopt(fd: RawFd, is_ipv6: bool) -> Result<()> {
    set_int_opt(fd, libc::SOL_IP, libc::IP_RECVTOS, 1)?;
    if is_ipv6 {
        set_int_opt(fd, libc::SOL_IPV6, libc::IPV6_RECVTCLASS, 1)?;
    }
    Ok(())
}
