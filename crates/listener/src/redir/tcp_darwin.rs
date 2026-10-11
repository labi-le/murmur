#![cfg(target_os = "macos")]

use std::net::IpAddr;

use anyhow::Result;
use tokio::net::TcpStream;

use murmur_transport::socks5::socks5;

const PF_OUT: u8 = 2;
const IOC_OUT: u32 = 0x4000_0000;
const IOC_IN: u32 = 0x8000_0000;
const IOC_INOUT: u32 = IOC_IN | IOC_OUT;
const IOC_PARM_MASK: u32 = 0x1FFF;

/// the anonymous `struct pfioc_natlook` literal.
#[repr(C)]
#[derive(Clone, Copy)]
struct PfiocNatlook {
    saddr: [u8; 16],
    daddr: [u8; 16],
    rsaddr: [u8; 16],
    rdaddr: [u8; 16],
    sxport: [u8; 4],
    dxport: [u8; 4],
    rsxport: [u8; 4],
    rdxport: [u8; 4],
    af: u8,
    proto: u8,
    proto_variant: u8,
    direction: u8,
}

const LEN: u32 = std::mem::size_of::<PfiocNatlook>() as u32;

const DIOCNATLOOK: u64 = (IOC_INOUT | ((LEN & IOC_PARM_MASK) << 16) | (('D' as u32) << 8) | 23) as u64;

#[expect(unsafe_code, reason = "libc::open plus an ioctl on a repr(C) buffer")]
pub(crate) fn parser_packet(c: &TcpStream) -> Result<socks5::Addr> {
    // Safety: `/dev/pf` is opened read-only, the fd is closed before returning on every path, and
    // the ioctl buffer's size matches `PfiocNatlook`'s `#[repr(C)]` layout exactly.
    unsafe {
        let fd = libc::open(c"/dev/pf".as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let result = (|| -> Result<socks5::Addr> {
            let mut nl: PfiocNatlook = std::mem::zeroed();
            nl.af = libc::AF_INET as u8;
            nl.proto = libc::IPPROTO_TCP as u8;
            nl.direction = PF_OUT;

            let saddr = c.peer_addr()?;
            let daddr = c.local_addr()?;
            copy_addr(&mut nl.saddr, saddr.ip());
            copy_addr(&mut nl.daddr, daddr.ip());
            let sport = saddr.port();
            let dport = daddr.port();
            nl.sxport[0] = (sport >> 8) as u8;
            nl.sxport[1] = sport as u8;
            nl.dxport[0] = (dport >> 8) as u8;
            nl.dxport[1] = dport as u8;

            let rc = libc::ioctl(fd, DIOCNATLOOK as libc::c_ulong, std::ptr::addr_of_mut!(nl));
            if rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            let mut addr = vec![0u8; 1 + 4 + 2];
            addr[0] = socks5::ATYP_IPV4;
            addr[1..5].copy_from_slice(&nl.rdaddr[..4]);
            addr[5..7].copy_from_slice(&nl.rdxport[..2]);
            Ok(socks5::Addr(addr))
        })();

        libc::close(fd);
        result
    }
}

fn copy_addr(dst: &mut [u8; 16], ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => dst[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => dst.copy_from_slice(&v6.octets()),
    }
}
