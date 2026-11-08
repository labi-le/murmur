//! The Linux TUN device: the device-creation half, reduced to what a device owns, without the
//! network stack built on top of it.
//!
//! `TUNSETIFF` creates the interface, `SIOCSIFMTU` and `SIOCSIFFLAGS` shape it, netlink gives it
//! the configured addresses, and the descriptor is then a packet pipe the reader task drains and
//! the NAT workers answer on. Routes are installed separately, so a caller can postpone them.
//! Adopting an already-open `file-descriptor` skips all of that configuration and only asks
//! `TUNGETIFF` for the name, the way a name-only lookup does.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use anyhow::{Context, Result};
use ipnet::IpNet;
use tokio::io::unix::AsyncFd;

use super::{Cleanup, Device, TunAddresses};

/// `linux/if_tun.h`. `IFF_NO_PI` is what makes a read a bare IP packet rather than one behind a
/// four-byte flags header every packet would then have to be stripped of.
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

// libc's SIOC constants use c_ulong, but ioctl takes c_int on musl.
const SIOCGIFFLAGS: libc::Ioctl = 0x8913;
const SIOCSIFFLAGS: libc::Ioctl = 0x8914;
const SIOCSIFMTU: libc::Ioctl = 0x8922;
const IFF_UP: libc::c_short = 0x1;
const IFF_RUNNING: libc::c_short = 0x40;

pub(super) struct Inner {
    fd: AsyncFd<std::fs::File>,
}

pub(super) fn open(device: &str, file_descriptor: i32, addresses: &TunAddresses) -> Result<(Arc<Device>, Cleanup)> {
    let (device, mut cleanup) = if file_descriptor == 0 { create(device)? } else { adopt(file_descriptor)? };
    if file_descriptor == 0 {
        let socket = control_socket()?;
        set_mtu(socket.as_fd(), device.name(), addresses.mtu)?;
        for prefix in &addresses.addresses {
            super::super::netlink_linux::add_address(device.index(), &prefix.addr(), prefix.prefix_len())
                .with_context(|| format!("add address {prefix} to {}", device.name()))?;
            cleanup.record_address(device.index(), prefix.addr(), prefix.prefix_len());
        }
        set_up(socket.as_fd(), device.name())?;
    }
    Ok((Arc::new(device), cleanup))
}

pub(super) fn add_route(dst: IpNet, index: u32) -> Result<()> {
    super::super::netlink_linux::add_route(&dst, index).with_context(|| format!("add route {dst}"))
}

pub(super) fn delete_address(index: u32, addr: &IpAddr, prefix_len: u8) -> Result<()> {
    super::super::netlink_linux::del_address(index, addr, prefix_len)
}

pub(super) fn delete_route(dst: &IpNet, index: u32) -> Result<()> {
    super::super::netlink_linux::del_route(dst, index)
}

impl Inner {
    pub(super) async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| read_once(inner.get_ref().as_fd(), buf)) {
                Ok(result) => return result,
                Err(_would_block) => {}
            }
        }
    }

    pub(super) async fn write(&self, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| write_once(inner.get_ref().as_fd(), packet)) {
                Ok(result) => return result,
                Err(_would_block) => {}
            }
        }
    }
}

/// Builds the device value the two constructors share. The `File` owns the descriptor, so
/// dropping the device closes it; the cleanup list starts empty, which is what an adopted device
/// keeps, because none of what it carries was added by this process.
#[expect(unsafe_code, reason = "AsyncFd registration requires a stable owned descriptor")]
fn from_file(name: String, index: u32, file: std::fs::File) -> Result<(Device, Cleanup)> {
    set_nonblocking(&file)?;
    // Safety: AsyncFd exclusively owns this File; its descriptor is never replaced or closed early.
    let fd = unsafe { AsyncFd::register(file) }?;
    Ok((Device { name, index, inner: Inner { fd } }, Cleanup::default()))
}

fn create(requested: &str) -> Result<(Device, Cleanup)> {
    let owned = rustix::fs::open(
        c"/dev/net/tun",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)
    .context("open /dev/net/tun")?;
    let name = tun_set_iff(owned.as_fd(), requested)?;
    let index = ifindex(&name)?;
    from_file(name, index, std::fs::File::from(owned))
}

#[expect(unsafe_code, reason = "libc::dup, whose descriptor is adopted by an OwnedFd")]
fn adopt(file_descriptor: i32) -> Result<(Device, Cleanup)> {
    anyhow::ensure!(file_descriptor >= 0, "file-descriptor must be non-negative, got {file_descriptor}");
    // The descriptor belongs to the caller, so the device takes a dup and leaves the original
    // open: closing it here would take away a descriptor this crate did not open.
    // Safety: `dup` returns a fresh descriptor owned here, recorded by `OwnedFd`.
    unsafe {
        let dup = libc::dup(file_descriptor);
        if dup < 0 {
            return Err(io::Error::last_os_error()).context("dup file-descriptor");
        }
        let owned = OwnedFd::from_raw_fd(dup);
        let name = tun_name(owned.as_fd())?;
        let index = ifindex(&name)?;
        from_file(name, index, std::fs::File::from(owned))
    }
}

fn set_nonblocking(file: &std::fs::File) -> io::Result<()> {
    rustix::io::ioctl_fionbio(file, true).map_err(io::Error::from)
}

fn read_once(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    rustix::io::read(fd, buf).map_err(io::Error::from)
}

fn write_once(fd: BorrowedFd<'_>, packet: &[u8]) -> io::Result<()> {
    let n = rustix::io::write(fd, packet).map_err(io::Error::from)?;
    // A short write on a packet device is not a recoverable state: what the client is waiting for
    // is already truncated on the wire.
    if n != packet.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, format!("tun wrote {n} of {} bytes", packet.len())));
    }
    Ok(())
}

#[expect(unsafe_code, reason = "TUNSETIFF on a live, zeroed ifreq local")]
fn tun_set_iff(fd: BorrowedFd<'_>, requested: &str) -> io::Result<String> {
    // Safety: the `ifreq` is a live local; the kernel reads `ifr_name` and `ifr_flags` and writes
    // the interface it actually created back into `ifr_name`, still inside it.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        write_ifreq_name(&mut ifr, requested)?;
        ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
        if libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &raw mut ifr) < 0 {
            return Err(io::Error::last_os_error());
        }
        read_ifreq_name(&ifr)
    }
}

#[expect(unsafe_code, reason = "TUNGETIFF on a live, zeroed ifreq local")]
fn tun_name(fd: BorrowedFd<'_>) -> io::Result<String> {
    // Safety: the kernel writes the interface name into `ifr_name` of a live local `ifreq`.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        if libc::ioctl(fd.as_raw_fd(), libc::TUNGETIFF, &raw mut ifr) < 0 {
            return Err(io::Error::last_os_error());
        }
        read_ifreq_name(&ifr)
    }
}

fn read_ifreq_name(ifr: &libc::ifreq) -> io::Result<String> {
    let name = ifr.ifr_name.map(|c| u8::from_ne_bytes(c.to_ne_bytes()));
    let name = name.split(|b| *b == 0).next().unwrap_or(&[]);
    let name = std::str::from_utf8(name).map(str::to_owned);
    match name {
        Ok(name) if !name.is_empty() => Ok(name),
        Ok(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "tun descriptor has an empty interface name")),
        Err(err) => Err(io::Error::new(io::ErrorKind::InvalidData, format!("tun interface name is not utf-8: {err}"))),
    }
}

#[expect(unsafe_code, reason = "libc::socket, whose descriptor is adopted by a File")]
fn control_socket() -> Result<std::fs::File> {
    // Safety: opening an IPv4 datagram socket purely as a handle for the `SIOC*IF*` ioctls, which
    // need a socket descriptor; the returned `File` owns it.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("socket(AF_INET) for interface ioctls");
        }
        Ok(<std::fs::File as FromRawFd>::from_raw_fd(fd))
    }
}

#[expect(unsafe_code, reason = "SIOCSIFMTU on a live ifreq local")]
fn set_mtu(socket: BorrowedFd<'_>, name: &str, mtu: u32) -> io::Result<()> {
    // Safety: the `ifreq` is a live local whose name is NUL-terminated within `IF_NAMESIZE`, and
    // `ifr_mtu` is written before the ioctl reads it.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        write_ifreq_name(&mut ifr, name)?;
        ifr.ifr_ifru.ifru_mtu = mtu.cast_signed();
        if libc::ioctl(socket.as_raw_fd(), SIOCSIFMTU, &raw mut ifr) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[expect(unsafe_code, reason = "SIOCGIFFLAGS/SIOCSIFFLAGS on a live ifreq local")]
fn set_up(socket: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    // Safety: as `set_mtu`, reading the current flags back first so the bits this crate does not
    // manage survive the update.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        write_ifreq_name(&mut ifr, name)?;
        if libc::ioctl(socket.as_raw_fd(), SIOCGIFFLAGS, &raw mut ifr) < 0 {
            return Err(io::Error::last_os_error());
        }
        ifr.ifr_ifru.ifru_flags |= IFF_UP | IFF_RUNNING;
        if libc::ioctl(socket.as_raw_fd(), SIOCSIFFLAGS, &raw mut ifr) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn write_ifreq_name(ifr: &mut libc::ifreq, name: &str) -> io::Result<()> {
    if name.len() >= libc::IF_NAMESIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("interface name {name} is too long")));
    }
    ifr.ifr_name.iter_mut().zip(name.as_bytes()).for_each(|(dst, &src)| *dst = libc::c_char::from_ne_bytes([src]));
    Ok(())
}

fn ifindex(name: &str) -> Result<u32> {
    let socket = rustix::net::socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(io::Error::from)
    .context("socket for if_nametoindex")?;
    rustix::net::netdevice::name_to_index(&socket, name)
        .map_err(io::Error::from)
        .with_context(|| format!("if_nametoindex {name}"))
}

#[cfg(test)]
#[allow(unsafe_code, reason = "tests seed a live kernel request struct the same way the production ioctl paths do")]
mod tests {
    use super::{ifindex, read_ifreq_name, write_ifreq_name};

    fn zeroed_ifreq() -> libc::ifreq {
        unsafe { std::mem::zeroed() }
    }

    #[test]
    fn name_round_trips_through_the_ifreq_field() {
        for name in ["murmur0", "tun%d", "eth"] {
            let mut ifr = zeroed_ifreq();
            write_ifreq_name(&mut ifr, name).expect("write name");
            assert_eq!(read_ifreq_name(&ifr).expect("read name"), name);
        }
    }

    #[test]
    fn high_bit_bytes_survive_the_round_trip() {
        let name = "tun\u{80}\u{ff}";
        let mut ifr = zeroed_ifreq();
        write_ifreq_name(&mut ifr, name).expect("write name");
        assert_eq!(read_ifreq_name(&ifr).expect("read name"), name);
    }

    #[test]
    fn write_touches_only_the_name() {
        let mut ifr = zeroed_ifreq();
        ifr.ifr_name = [libc::c_char::from_ne_bytes([0xff]); libc::IF_NAMESIZE];
        write_ifreq_name(&mut ifr, "tun0").expect("write name");
        assert_eq!(ifr.ifr_name[..4], b"tun0".map(|b| libc::c_char::from_ne_bytes([b])));
        assert!(
            ifr.ifr_name[4..].iter().all(|&b| b == libc::c_char::from_ne_bytes([0xff])),
            "the write must not reach past the name"
        );
    }

    #[test]
    fn read_stops_at_the_nul_even_over_a_dirty_field() {
        let mut ifr = zeroed_ifreq();
        write_ifreq_name(&mut ifr, "eth1").expect("write name");
        ifr.ifr_name[10] = libc::c_char::from_ne_bytes([0xff]);
        ifr.ifr_name[11] = libc::c_char::from_ne_bytes([0xff]);
        assert_eq!(read_ifreq_name(&ifr).expect("read name"), "eth1");
    }

    #[test]
    fn read_rejects_an_empty_and_a_blanked_field() {
        assert!(read_ifreq_name(&zeroed_ifreq()).is_err(), "an all-NUL name is rejected");

        let mut ifr = zeroed_ifreq();
        write_ifreq_name(&mut ifr, "x").expect("write name");
        ifr.ifr_name[0] = 0;
        assert!(read_ifreq_name(&ifr).is_err());
    }

    #[test]
    fn write_rejects_a_name_that_cannot_fit() {
        let long = "n".repeat(libc::IF_NAMESIZE);
        let mut ifr = zeroed_ifreq();
        assert!(write_ifreq_name(&mut ifr, &long).is_err(), "IF_NAMESIZE bytes cannot fit");

        let exactly = "n".repeat(libc::IF_NAMESIZE - 1);
        assert!(write_ifreq_name(&mut ifr, &exactly).is_ok(), "one byte under the limit fits");
    }

    /// The syscall reads a C string, so a `&str` view whose allocation continues past it must
    /// still resolve to the name in the view rather than to the longer byte run behind it.
    #[test]
    fn ifindex_hands_the_syscall_a_terminated_name() {
        let padded = format!("lo{}", "n".repeat(16));
        assert_eq!(ifindex(&padded[..2]).expect("the view names an interface"), ifindex("lo").expect("lo"));
    }
}
