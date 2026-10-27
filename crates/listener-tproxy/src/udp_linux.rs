use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;

use anyhow::Result;
use socket2::{Domain, Socket, Type as SockType};
use tokio::net::UdpSocket;

/// `IPV6_RECVORIGDSTADDR`; equals Linux's `IPV6_ORIGDSTADDR`, the same constant used both to
/// enable and to report the ancillary message.
pub(crate) const IPV6_RECVORIGDSTADDR: libc::c_int = 0x4a;

/// Binds to a non-local address (`lAddr`) for transparent proxy replies.
pub async fn dial_udp(network: &str, l_addr: SocketAddr, r_addr: SocketAddr) -> Result<UdpSocket> {
    let domain = udp_addr_family(network, l_addr, r_addr);
    let socket = Socket::new(domain, SockType::DGRAM, None)?;
    socket.set_reuse_address(true)?;
    socket.set_ip_transparent_v4(true)?;
    socket.bind(&l_addr.into())?;
    socket.connect(&r_addr.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_socket)?)
}

const fn udp_addr_family(network: &str, l_addr: SocketAddr, r_addr: SocketAddr) -> Domain {
    match network.as_bytes().last() {
        Some(b'4') => return Domain::IPV4,
        Some(b'6') => return Domain::IPV6,
        _ => {}
    }
    if l_addr.is_ipv4() && r_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    }
}

/// Reads a datagram with its source address over `UdpSocket::try_io` + raw `recvmsg`, because
/// tokio exposes no ancillary-data read.
///
/// NEEDED SHIM ITEM: none; this is a self-contained, package-local seam.
#[expect(unsafe_code, reason = "recvmsg over live stack buffers")]
pub async fn recv_msg_udp(
    socket: &UdpSocket,
    buf: &mut [u8],
    oob: &mut [u8],
) -> io::Result<(usize, usize, SocketAddr)> {
    loop {
        socket.readable().await?;
        let fd = socket.as_raw_fd();
        let mut src: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = std::ptr::addr_of_mut!(src).cast();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "sockaddr_storage is 128 bytes, far below the u32 `msg_namelen` bound"
        )]
        let namelen = size_of::<libc::sockaddr_storage>() as u32;
        msg.msg_namelen = namelen;
        msg.msg_iov = std::ptr::addr_of_mut!(iov);
        msg.msg_iovlen = 1;
        msg.msg_control = oob.as_mut_ptr().cast();
        #[expect(
            clippy::useless_conversion,
            reason = "msg_controllen is usize on linux, so the checked conversion is a no-op"
        )]
        let controllen =
            oob.len().try_into().map_err(|_| io::Error::other("oob control buffer exceeds msg_controllen capacity"))?;
        msg.msg_controllen = controllen;

        // SAFETY: `fd` stays valid and readable (checked above); `msg` points at live, correctly
        // sized stack buffers for the duration of this syscall only.
        let result = socket.try_io(tokio::io::Interest::READABLE, || {
            let n = unsafe { libc::recvmsg(fd, std::ptr::addr_of_mut!(msg), 0) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n.cast_unsigned())
            }
        });

        match result {
            Ok(n) => {
                #[expect(
                    clippy::useless_conversion,
                    reason = "msg_controllen is usize on linux, so the checked conversion is a no-op"
                )]
                let oobn: usize =
                    msg.msg_controllen.try_into().map_err(|_| io::Error::other("msg_controllen exceeds usize"))?;
                let addr = sockaddr_storage_to_socket_addr(&src)?;
                return Ok((n, oobn, addr));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
}

#[expect(unsafe_code, reason = "reads the sockaddr variant the family tag selects")]
fn sockaddr_storage_to_socket_addr(storage: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: `ss_family == AF_INET` guarantees `storage` was populated as `sockaddr_in`.
            let sa: libc::sockaddr_in = unsafe { std::ptr::read_unaligned(std::ptr::from_ref(storage).cast()) };
            let port = u16::from_be(sa.sin_port);
            let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            // SAFETY: `ss_family == AF_INET6` guarantees `storage` was populated as `sockaddr_in6`.
            let sa: libc::sockaddr_in6 = unsafe { std::ptr::read_unaligned(std::ptr::from_ref(storage).cast()) };
            let port = u16::from_be(sa.sin6_port);
            let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        family => Err(io::Error::other(format!("unsupported address family: {family}"))),
    }
}

struct CmsgIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for CmsgIter<'a> {
    type Item = (libc::c_int, libc::c_int, &'a [u8]);

    #[expect(unsafe_code, reason = "reads a cmsghdr from the length-checked prefix")]
    fn next(&mut self) -> Option<Self::Item> {
        let all = self.data;
        let hdr_len = size_of::<libc::cmsghdr>();
        if all.len() < hdr_len {
            return None;
        }
        // SAFETY: `all` was just checked to hold at least one `cmsghdr`-sized prefix.
        let hdr: libc::cmsghdr = unsafe { std::ptr::read_unaligned(all.as_ptr().cast()) };
        #[expect(
            clippy::useless_conversion,
            reason = "cmsg_len is usize on linux, so the checked conversion is a no-op"
        )]
        let cmsg_len: usize = hdr.cmsg_len.try_into().ok()?;
        if cmsg_len < hdr_len || cmsg_len > all.len() {
            return None;
        }
        let data = all.get(hdr_len..cmsg_len)?;
        let aligned = cmsg_align(cmsg_len);
        self.data = all.get(aligned..).unwrap_or_default();
        Some((hdr.cmsg_level, hdr.cmsg_type, data))
    }
}

const fn cmsg_align(len: usize) -> usize {
    let align = size_of::<usize>();
    (len + align - 1) & !(align - 1)
}

pub fn get_orig_dst(oob: &[u8]) -> Result<SocketAddr> {
    for (level, cmsg_type, data) in (CmsgIter { data: oob }) {
        if let Some(addr) = parse_orig_dst(level, cmsg_type, data) {
            return Ok(addr);
        }
    }
    Err(anyhow::anyhow!("retrieve destination: unsupported address type"))
}

#[expect(unsafe_code, reason = "reads the sockaddr variant the level and type select")]
fn parse_orig_dst(level: libc::c_int, cmsg_type: libc::c_int, data: &[u8]) -> Option<SocketAddr> {
    if level == libc::SOL_IP && cmsg_type == libc::IP_ORIGDSTADDR && data.len() >= size_of::<libc::sockaddr_in>() {
        // SAFETY: length was just checked against `sockaddr_in`.
        let sa: libc::sockaddr_in = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
        let port = u16::from_be(sa.sin_port);
        let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
        Some(SocketAddr::new(IpAddr::V4(ip), port))
    } else if level == libc::SOL_IPV6
        && cmsg_type == IPV6_RECVORIGDSTADDR
        && data.len() >= size_of::<libc::sockaddr_in6>()
    {
        // SAFETY: length was just checked against `sockaddr_in6`.
        let sa: libc::sockaddr_in6 = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
        let port = u16::from_be(sa.sin6_port);
        let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
        Some(SocketAddr::new(IpAddr::V6(ip), port))
    } else {
        None
    }
}

/// The DSCP parser never returns an error (its default arm also returns nothing), so the
/// loop always breaks on the first control message; that observable quirk is kept.
pub fn get_dscp(oob: &[u8]) -> Result<u8> {
    match (CmsgIter { data: oob }).next() {
        Some((level, cmsg_type, data)) => Ok(parse_dscp(level, cmsg_type, data)),
        None => Ok(0),
    }
}

#[expect(
    clippy::if_same_then_else,
    reason = "the IP and IPV6 TOS arms read the same first byte, matching the original"
)]
fn parse_dscp(level: libc::c_int, cmsg_type: libc::c_int, data: &[u8]) -> u8 {
    let Some(&tos) = data.first() else { return 0 };
    if level == libc::SOL_IP && cmsg_type == libc::IP_TOS {
        tos >> 2
    } else if level == libc::SOL_IPV6 && cmsg_type == libc::IPV6_TCLASS {
        tos >> 2
    } else {
        0
    }
}
