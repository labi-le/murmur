//! The pieces of the network interface API the transport code needs.
//!
//! The types the signatures mention (`Interface`, `Flags`, `HardwareAddr`, `IPMask`, `IPNet`,
//! `IPAddr` and `OpError`) live here, alongside the `pub mod` lines of the submodules.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::resolver::host::unmap_addr;
use murmur_std_compat::net::Addr;

pub mod anet;
pub mod doc;
#[cfg(not(target_os = "android"))]
pub mod interface;
#[cfg(target_os = "android")]
pub mod interface_android;
#[cfg(target_os = "android")]
pub mod netlink_android;

bitflags::bitflags! {
    /// Interface flags, as the platform reports them.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Flags: u32 {
        const FLAG_UP = 1 << 0;
        const FLAG_BROADCAST = 1 << 1;
        const FLAG_LOOPBACK = 1 << 2;
        const FLAG_POINT_TO_POINT = 1 << 3;
        const FLAG_MULTICAST = 1 << 4;
        const FLAG_RUNNING = 1 << 5;
    }
}

/// A link-layer address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HardwareAddr(pub Vec<u8>);

impl fmt::Display for HardwareAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A network interface and its attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub index: i32,
    pub mtu: i32,
    pub name: String,
    pub hardware_addr: HardwareAddr,
    pub flags: Flags,
}

/// An IP network mask.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IPMask(pub Vec<u8>);

impl IPMask {
    #[must_use]
    pub fn size(&self) -> (usize, usize) {
        let mut ones = 0usize;
        let mut bits = 0usize;
        for b in &self.0 {
            ones += b.count_ones() as usize;
            bits += 8;
        }
        (ones, bits)
    }
}

/// The hex form, and `<nil>` for the empty mask.
impl fmt::Display for IPMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("<nil>");
        }
        f.write_str(&hex::encode(&self.0))
    }
}

/// `None` for an out-of-range `ones`/`bits` pair.
#[must_use]
pub fn cidr_mask(ones: usize, bits: usize) -> Option<IPMask> {
    if bits != 8 * 4 && bits != 8 * 16 {
        return None;
    }
    if ones > bits {
        return None;
    }
    let l = bits / 8;
    let mut m = vec![0u8; l];
    let mut n = ones;
    for b in &mut m {
        if n >= 8 {
            *b = 0xff;
            n -= 8;
        } else {
            *b = !(0xffu8 >> n);
            n = 0;
        }
    }
    Some(IPMask(m))
}

/// An IP network: an address and its mask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IPNet {
    pub ip: IpAddr,
    pub mask: IPMask,
}

impl IPNet {
    /// The address and the mask reconciled to one family, of which the
    /// network address and, per the mask, the simple prefix length follow.
    fn network_number_and_mask(&self) -> Option<(IpAddr, IPMask)> {
        match (self.ip, self.mask.0.len()) {
            (IpAddr::V4(_), 4) | (IpAddr::V6(_), 16) => Some((self.ip, self.mask.clone())),
            (IpAddr::V4(_), 16) => Some((self.ip, IPMask(self.mask.0.get(12..).unwrap_or_default().to_vec()))),
            _ => None,
        }
    }

    /// `None` stands for the `-1`.
    fn simple_mask_length(mask: &IPMask) -> Option<usize> {
        let mut n = 0usize;
        let mut seen_zero = false;
        for b in &mask.0 {
            if seen_zero {
                if *b != 0 {
                    return None;
                }
                continue;
            }
            if *b == 0xff {
                n += 8;
                continue;
            }
            let mut v = *b;
            while v & 0x80 != 0 {
                n += 1;
                v <<= 1;
            }
            if v != 0 {
                return None;
            }
            seen_zero = true;
        }
        Some(n)
    }
}

impl fmt::Display for IPNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some((ip, mask)) = self.network_number_and_mask() else {
            return f.write_str("<nil>");
        };
        let masked = match ip {
            IpAddr::V4(v4) => {
                let b = v4.octets();
                let mut out = [0u8; 4];
                for (o, (&bi, &mi)) in out.iter_mut().zip(b.iter().zip(&mask.0)) {
                    *o = bi & mi;
                }
                IpAddr::V4(Ipv4Addr::from(out))
            }
            IpAddr::V6(v6) => {
                let b = v6.octets();
                let mut out = [0u8; 16];
                for (o, (&bi, &mi)) in out.iter_mut().zip(b.iter().zip(&mask.0)) {
                    *o = bi & mi;
                }
                IpAddr::V6(Ipv6Addr::from(out))
            }
        };
        match Self::simple_mask_length(&mask) {
            Some(l) => write!(f, "{masked}/{l}"),
            None => write!(f, "{masked}/{mask}"),
        }
    }
}

impl Addr for IPNet {
    fn network(&self) -> &'static str {
        "ip+net"
    }

    fn string(&self) -> String {
        self.to_string()
    }

    fn as_iface_prefix(&self) -> Option<IpNet> {
        let (ones, bits) = self.mask.size();
        let ip = if bits == 32 { unmap_addr(self.ip) } else { self.ip };
        IpNet::new(ip, u8::try_from(ones).ok()?).ok()
    }
}

/// An IP address with an optional zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IPAddr {
    pub ip: IpAddr,
    pub zone: String,
}

impl fmt::Display for IPAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.zone.is_empty() {
            write!(f, "{}", self.ip)
        } else {
            write!(f, "{}%{}", self.ip, self.zone)
        }
    }
}

impl Addr for IPAddr {
    fn network(&self) -> &'static str {
        "ip"
    }

    fn string(&self) -> String {
        self.to_string()
    }

    fn as_iface_prefix(&self) -> Option<IpNet> {
        let ip = unmap_addr(self.ip);
        let ones = if ip.is_ipv4() { 32 } else { 128 };
        IpNet::new(ip, ones).ok()
    }
}

/// A network operation error. The call sites never set a source or address, so those fields are
/// not carried.
#[derive(Debug)]
pub struct OpError {
    pub op: String,
    pub net: String,
    pub err: anyhow::Error,
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.op, self.net, self.err)
    }
}

impl std::error::Error for OpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.err.as_ref())
    }
}

/// `EINVAL`, the error the ioctl and netlink code reports for malformed data.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
pub(crate) fn einval() -> anyhow::Error {
    anyhow::anyhow!(std::io::Error::from_raw_os_error(libc::EINVAL))
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn last_os_error() -> anyhow::Error {
    anyhow::anyhow!(std::io::Error::last_os_error())
}

/// Closes the descriptor when dropped.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
pub(crate) struct FdGuard(pub(crate) i32);

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
impl Drop for FdGuard {
    #[expect(unsafe_code, reason = "`libc::close` on an owned descriptor has no safe wrapper in std")]
    fn drop(&mut self) {
        // SAFETY: the descriptor is owned by this guard and closed exactly once.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// `IFNAMSIZ` for the name field, plus the 24-byte union the request struct is fixed at.
#[cfg(any(target_os = "linux", target_os = "android"))]
const IF_REQ_SIZE: usize = 40;
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
pub(crate) const IFNAMSIZ: usize = 16;

/// `SIOCGIFNAME`, used only by the netlink interface table.
#[cfg(target_os = "android")]
const SIOCGIFNAME: libc::Ioctl = 0x8910;
#[cfg(any(target_os = "linux", target_os = "android"))]
const SIOCGIFMTU: libc::Ioctl = 0x8921;
#[cfg(any(target_os = "linux", target_os = "android"))]
const SIOCGIFFLAGS: libc::Ioctl = 0x8913;
#[cfg(any(target_os = "linux", target_os = "android"))]
const SIOCGIFHWADDR: libc::Ioctl = 0x8927;

#[cfg(any(target_os = "linux", target_os = "android"))]
const IFF_UP: u32 = 0x1;
#[cfg(any(target_os = "linux", target_os = "android"))]
const IFF_BROADCAST: u32 = 0x2;
#[cfg(any(target_os = "linux", target_os = "android"))]
const IFF_LOOPBACK: u32 = 0x8;
#[cfg(any(target_os = "linux", target_os = "android"))]
const IFF_POINTOPOINT: u32 = 0x10;
#[cfg(any(target_os = "linux", target_os = "android"))]
const IFF_RUNNING: u32 = 0x40;
#[cfg(any(target_os = "linux", target_os = "android"))]
const IFF_MULTICAST: u32 = 0x1000;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[expect(unsafe_code, reason = "`socket` is a raw syscall with no safe wrapper in std")]
fn ioctl_socket() -> anyhow::Result<i32> {
    // SAFETY: a plain socket(2) call, no pointers handed over.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(last_os_error());
    }
    Ok(fd)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[expect(unsafe_code, reason = "`ioctl` is a raw syscall; the SAFETY comment below states the buffer invariant")]
fn ioctl(fd: i32, req: libc::Ioctl, arg: *mut u8) -> anyhow::Result<()> {
    // SAFETY: `arg` points at the live `ifreq` buffer the caller owns for the call.
    let rc = unsafe { libc::ioctl(fd, req, arg.cast::<libc::c_void>()) };
    if rc != 0 {
        return Err(last_os_error());
    }
    Ok(())
}

/// `IFNAMSIZ` for the name field, plus the 16-byte union the request struct fixes its payload at
/// on Darwin (a bare `sockaddr`/`ifkpi`, half the 24-byte union Linux's larger `sockaddr`
/// variants need); checked against Apple's `bsd/net/if.h`.
#[cfg(target_os = "macos")]
const IF_REQ_SIZE_MACOS: usize = 32;

/// `SIOCGIFMTU`/`SIOCGIFFLAGS` on Darwin: `_IOWR('i', 51|17, struct ifreq)`, which do not
/// match the Linux request numbers `anet.rs` otherwise uses. Values extracted from Apple's `xnu`
/// `bsd/sys/sockio.h` (`_IOWR` encodes as `0xC0000000 | (sizeof(struct ifreq) << 16) | ('i' << 8)
/// | num`, `sizeof(struct ifreq) == 32` on Darwin) and cross-checked against
/// github.com/rust-lang/libc#3626, which reports the same `SIOCGIFFLAGS` value from a live macOS
/// header dump. Not runnable on this host; the derivation above is the verification available.
#[cfg(target_os = "macos")]
const SIOCGIFMTU_MACOS: libc::c_ulong = 0xc020_6933;
#[cfg(target_os = "macos")]
const SIOCGIFFLAGS_MACOS: libc::c_ulong = 0xc020_6911;

#[cfg(any(target_os = "linux", target_os = "android"))]
/// `ifru_hwaddr` is a `sockaddr`, so the address sits past its 2-byte family field.
const MAC_ADDR_OFFSET: usize = IFNAMSIZ + 2;
#[cfg(any(target_os = "linux", target_os = "android"))]
const MAC_ADDR_LEN: usize = 6;

/// The `IFF_*` flag values on Darwin (`bsd/net/if.h`); `IFF_MULTICAST` in particular is `0x8000` here, not
/// Linux's `0x1000` — the two platforms assign this bit differently.
#[cfg(target_os = "macos")]
const IFF_UP_MACOS: u32 = 0x1;
#[cfg(target_os = "macos")]
const IFF_BROADCAST_MACOS: u32 = 0x2;
#[cfg(target_os = "macos")]
const IFF_LOOPBACK_MACOS: u32 = 0x8;
#[cfg(target_os = "macos")]
const IFF_POINTOPOINT_MACOS: u32 = 0x10;
#[cfg(target_os = "macos")]
const IFF_RUNNING_MACOS: u32 = 0x40;
#[cfg(target_os = "macos")]
const IFF_MULTICAST_MACOS: u32 = 0x8000;

#[cfg(target_os = "macos")]
#[expect(unsafe_code, reason = "`socket` and `fcntl` are raw syscalls with no safe wrapper in std")]
fn ioctl_socket_macos() -> anyhow::Result<i32> {
    // SAFETY: a plain socket(2) call, no pointers handed over.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(last_os_error());
    }
    // SAFETY: `fd` is the descriptor just created above and still owned by this function; a
    // failed `fcntl` is reported and the descriptor closed by the caller's `FdGuard`.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    if rc < 0 {
        let err = last_os_error();
        // SAFETY: `fd` is still owned here; no `FdGuard` has been constructed yet.
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    Ok(fd)
}

#[cfg(target_os = "macos")]
#[expect(unsafe_code, reason = "`ioctl` is a raw syscall; the SAFETY comment below states the buffer invariant")]
fn ioctl_macos(fd: i32, req: libc::c_ulong, arg: *mut u8) -> anyhow::Result<()> {
    // SAFETY: `arg` points at the live `ifreq` buffer the caller owns for the call.
    let rc = unsafe { libc::ioctl(fd, req, arg.cast::<libc::c_void>()) };
    if rc != 0 {
        return Err(last_os_error());
    }
    Ok(())
}

/// `SIOCGIFNAME`: the interface name of a link index.
#[cfg(target_os = "android")]
pub(crate) fn index_to_name(index: u32) -> anyhow::Result<String> {
    let fd = ioctl_socket()?;
    let _guard = FdGuard(fd);

    let mut ifr = [0u8; IF_REQ_SIZE];
    ifr[IFNAMSIZ..IFNAMSIZ + 4].copy_from_slice(&index.to_ne_bytes());
    ioctl(fd, SIOCGIFNAME, ifr.as_mut_ptr())?;

    Ok(String::from_utf8_lossy(trim_nul(&ifr[..IFNAMSIZ])).into_owned())
}

/// `SIOCGIFMTU`: the link MTU of an interface, which `if-addrs` does not report.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn name_to_mtu(name: &str) -> anyhow::Result<i32> {
    // Leave room for terminating NULL byte.
    if name.len() >= IFNAMSIZ {
        return Err(einval());
    }

    let fd = ioctl_socket()?;
    let _guard = FdGuard(fd);

    let mut ifr = [0u8; IF_REQ_SIZE];
    let (name_field, _) = ifr.split_at_mut(name.len());
    name_field.copy_from_slice(name.as_bytes());
    ioctl(fd, SIOCGIFMTU, ifr.as_mut_ptr())?;

    Ok(i32::from_ne_bytes([ifr[IFNAMSIZ], ifr[IFNAMSIZ + 1], ifr[IFNAMSIZ + 2], ifr[IFNAMSIZ + 3]]))
}

/// `SIOCGIFFLAGS`: the interface flags, which `if-addrs` only approximates.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn name_to_flags(name: &str) -> anyhow::Result<Flags> {
    // Leave room for terminating NULL byte.
    if name.len() >= IFNAMSIZ {
        return Err(einval());
    }

    let fd = ioctl_socket()?;
    let _guard = FdGuard(fd);

    let mut ifr = [0u8; IF_REQ_SIZE];
    let (name_field, _) = ifr.split_at_mut(name.len());
    name_field.copy_from_slice(name.as_bytes());
    ioctl(fd, SIOCGIFFLAGS, ifr.as_mut_ptr())?;

    Ok(link_flags(u32::from_ne_bytes([ifr[IFNAMSIZ], ifr[IFNAMSIZ + 1], ifr[IFNAMSIZ + 2], ifr[IFNAMSIZ + 3]])))
}

/// `SIOCGIFHWADDR`: the link-layer address the interface listing reports, which
/// `if-addrs` does not carry at all. `component/dhcp` puts this in the `chaddr` of its
/// DISCOVER, so leaving it empty makes every DHCP server drop the request.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn name_to_hardware_addr(name: &str) -> anyhow::Result<HardwareAddr> {
    if name.len() >= IFNAMSIZ {
        return Err(einval());
    }

    let fd = ioctl_socket()?;
    let _guard = FdGuard(fd);

    let mut ifr = [0u8; IF_REQ_SIZE];
    let (name_field, _) = ifr.split_at_mut(name.len());
    name_field.copy_from_slice(name.as_bytes());
    ioctl(fd, SIOCGIFHWADDR, ifr.as_mut_ptr())?;

    // only a non-zero address is kept, which is what a device with no link-layer
    // address (a WireGuard or loopback interface) reports here.
    let addr = &ifr[MAC_ADDR_OFFSET..MAC_ADDR_OFFSET + MAC_ADDR_LEN];
    Ok(if addr.iter().any(|&b| b != 0) { HardwareAddr(addr.to_vec()) } else { HardwareAddr::default() })
}

/// `SIOCGIFMTU` on Darwin: the link MTU of an interface, which `if-addrs` does not report. A real
/// ioctl rather than a stub, because the interface list reports an accurate MTU on Darwin too; a
/// fail-closed stub here would be a genuine behaviour gap, not just an unimplemented edge case.
#[cfg(target_os = "macos")]
pub(crate) fn name_to_mtu(name: &str) -> anyhow::Result<i32> {
    // Leave room for terminating NULL byte.
    if name.len() >= IFNAMSIZ {
        return Err(einval());
    }

    let fd = ioctl_socket_macos()?;
    let _guard = FdGuard(fd);

    let mut ifr = [0u8; IF_REQ_SIZE_MACOS];
    ifr[..name.len()].copy_from_slice(name.as_bytes());
    ioctl_macos(fd, SIOCGIFMTU_MACOS, ifr.as_mut_ptr())?;

    Ok(i32::from_ne_bytes([ifr[IFNAMSIZ], ifr[IFNAMSIZ + 1], ifr[IFNAMSIZ + 2], ifr[IFNAMSIZ + 3]]))
}

/// `SIOCGIFFLAGS` on Darwin: the interface flags, which `if-addrs` only
/// approximates.
#[cfg(target_os = "macos")]
pub(crate) fn name_to_flags(name: &str) -> anyhow::Result<Flags> {
    // Leave room for terminating NULL byte.
    if name.len() >= IFNAMSIZ {
        return Err(einval());
    }

    let fd = ioctl_socket_macos()?;
    let _guard = FdGuard(fd);

    let mut ifr = [0u8; IF_REQ_SIZE_MACOS];
    ifr[..name.len()].copy_from_slice(name.as_bytes());
    ioctl_macos(fd, SIOCGIFFLAGS_MACOS, ifr.as_mut_ptr())?;

    Ok(link_flags_macos(u32::from_ne_bytes([ifr[IFNAMSIZ], ifr[IFNAMSIZ + 1], ifr[IFNAMSIZ + 2], ifr[IFNAMSIZ + 3]])))
}

/// `NEEDED CRATE: windows-sys` (`Win32_NetworkManagement_IpHelper`) would let this call
/// `GetAdaptersAddresses` for a real MTU/flags read, matching what the interface listing does on
/// Windows. Without it, both queries fail closed here; `net_interfaces` below already treats a
/// failed `name_to_mtu` as MTU 0 and a failed `name_to_flags` as the `if-addrs`-derived
/// approximation, the same fallback the ioctl path uses when it fails on Linux/Android.
#[cfg(windows)]
pub(crate) fn name_to_mtu(_name: &str) -> anyhow::Result<i32> {
    Err(anyhow::anyhow!("interface MTU query not supported on this platform"))
}

#[cfg(windows)]
pub(crate) fn name_to_flags(_name: &str) -> anyhow::Result<Flags> {
    Err(anyhow::anyhow!("interface flags query not supported on this platform"))
}

/// Windows needs the same `NEEDED CRATE: windows-sys` (`GetAdaptersAddresses`) as the two
/// queries above. Darwin and the BSDs are not in the `NEEDED CRATE` category: no macOS SDK on
/// any build host carries the `SIOCGIFHWADDR` request number or the kernel's `struct ifreq`, so
/// unlike the MTU and flags numbers above there is no derivation to cross-check here, and an
/// unverified request number is worse than a documented gap.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn name_to_hardware_addr(_name: &str) -> anyhow::Result<HardwareAddr> {
    Err(anyhow::anyhow!("interface hardware address query not supported on this platform"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn link_flags(raw_flags: u32) -> Flags {
    let mut f = Flags::empty();
    if raw_flags & IFF_UP != 0 {
        f |= Flags::FLAG_UP;
    }
    if raw_flags & IFF_RUNNING != 0 {
        f |= Flags::FLAG_RUNNING;
    }
    if raw_flags & IFF_BROADCAST != 0 {
        f |= Flags::FLAG_BROADCAST;
    }
    if raw_flags & IFF_LOOPBACK != 0 {
        f |= Flags::FLAG_LOOPBACK;
    }
    if raw_flags & IFF_POINTOPOINT != 0 {
        f |= Flags::FLAG_POINT_TO_POINT;
    }
    if raw_flags & IFF_MULTICAST != 0 {
        f |= Flags::FLAG_MULTICAST;
    }
    f
}

#[cfg(target_os = "macos")]
fn link_flags_macos(raw_flags: u32) -> Flags {
    let mut f = Flags::empty();
    if raw_flags & IFF_UP_MACOS != 0 {
        f |= Flags::FLAG_UP;
    }
    if raw_flags & IFF_RUNNING_MACOS != 0 {
        f |= Flags::FLAG_RUNNING;
    }
    if raw_flags & IFF_BROADCAST_MACOS != 0 {
        f |= Flags::FLAG_BROADCAST;
    }
    if raw_flags & IFF_LOOPBACK_MACOS != 0 {
        f |= Flags::FLAG_LOOPBACK;
    }
    if raw_flags & IFF_POINTOPOINT_MACOS != 0 {
        f |= Flags::FLAG_POINT_TO_POINT;
    }
    if raw_flags & IFF_MULTICAST_MACOS != 0 {
        f |= Flags::FLAG_MULTICAST;
    }
    f
}

/// Trims leading and trailing NUL bytes.
#[cfg(target_os = "android")]
fn trim_nul(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&c| c != 0).unwrap_or(b.len());
    let end = b.iter().rposition(|&c| c != 0).map_or(start, |i| i + 1);
    &b[start..end]
}

fn if_addrs_flags(ifa: &if_addrs::Interface) -> Flags {
    let mut flags = Flags::empty();
    if ifa.is_loopback() {
        flags |= Flags::FLAG_LOOPBACK;
    }
    if ifa.is_oper_up() {
        flags |= Flags::FLAG_UP | Flags::FLAG_RUNNING;
    }
    if ifa.is_p2p {
        flags |= Flags::FLAG_POINT_TO_POINT;
    }
    flags
}

/// The kernel's link table, which lists every interface including the ones with no address. Linux
/// and Android expose it as `/sys/class/net`; the platforms without a readable equivalent return
/// nothing, so the union below is left with the address-shaped entries `if-addrs` provides.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn net_link_interfaces() -> anyhow::Result<Vec<Interface>> {
    let mut ift: Vec<Interface> = Vec::new();
    for entry in std::fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
        let index = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
            .ok()
            .and_then(|raw| raw.trim().parse::<i32>().ok())
            .unwrap_or(0);
        let mtu = name_to_mtu(&name).unwrap_or(0);
        let flags = name_to_flags(&name).unwrap_or_else(|_| Flags::empty());
        let hardware_addr = name_to_hardware_addr(&name).unwrap_or_default();
        ift.push(Interface { index, mtu, name, hardware_addr, flags });
    }
    Ok(ift)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn net_link_interfaces() -> anyhow::Result<Vec<Interface>> {
    Ok(Vec::new())
}

/// Stand-in for the interface listing, of which there is no std equivalent. The kernel's link
/// table comes first so address-less interfaces are listed; `if-addrs`, which enumerates addresses
/// rather than interfaces, fills in whatever the link table could not report.
pub(crate) fn net_interfaces() -> anyhow::Result<Vec<Interface>> {
    let mut ift = net_link_interfaces()?;
    let addrs = if_addrs::get_if_addrs()?;
    for ifa in addrs {
        if ift.iter().any(|i| i.name == ifa.name) {
            continue;
        }
        let mtu = name_to_mtu(&ifa.name).unwrap_or(0);
        let flags = name_to_flags(&ifa.name).unwrap_or_else(|_| if_addrs_flags(&ifa));
        let hardware_addr = name_to_hardware_addr(&ifa.name).unwrap_or_default();
        #[expect(
            clippy::cast_possible_wrap,
            reason = "an interface index is a small positive number, as the OS reports it"
        )]
        let index = ifa.index.unwrap_or(0) as i32;
        ift.push(Interface { index, mtu, name: ifa.name, hardware_addr, flags });
    }
    Ok(ift)
}

/// The interface addresses.
pub(crate) fn net_interface_addrs() -> anyhow::Result<Vec<Box<dyn Addr>>> {
    let addrs = if_addrs::get_if_addrs()?;
    let mut ifat: Vec<Box<dyn Addr>> = Vec::new();
    for ifa in addrs {
        ifat.push(net_addr_of(&ifa));
    }
    Ok(ifat)
}

/// The addresses of one interface.
pub(crate) fn net_interface_addrs_of(ifi: &Interface) -> anyhow::Result<Vec<Box<dyn Addr>>> {
    let addrs = if_addrs::get_if_addrs()?;
    let mut ifat: Vec<Box<dyn Addr>> = Vec::new();
    for ifa in addrs {
        if ifa.name != ifi.name {
            continue;
        }
        ifat.push(net_addr_of(&ifa));
    }
    Ok(ifat)
}

/// Looks an interface up by index.
#[cfg(target_os = "android")]
pub(crate) fn net_interface_by_index(index: i32) -> anyhow::Result<Interface> {
    net_interfaces()?.into_iter().find(|i| i.index == index).ok_or_else(|| anyhow::anyhow!("no such network interface"))
}

/// Looks an interface up by name.
#[cfg(target_os = "android")]
pub(crate) fn net_interface_by_name(name: &str) -> anyhow::Result<Interface> {
    net_interfaces()?.into_iter().find(|i| i.name == name).ok_or_else(|| anyhow::anyhow!("no such network interface"))
}

/// An address is reported as a network when it carries a mask, and bare otherwise.
fn net_addr_of(ifa: &if_addrs::Interface) -> Box<dyn Addr> {
    match &ifa.addr {
        if_addrs::IfAddr::V4(v4) => {
            let ip = IpAddr::V4(v4.ip);
            match cidr_mask(v4.prefixlen as usize, 32) {
                Some(mask) => Box::new(IPNet { ip, mask }),
                None => Box::new(IPAddr { ip, zone: String::new() }),
            }
        }
        if_addrs::IfAddr::V6(v6) => {
            let ip = IpAddr::V6(v6.ip);
            match cidr_mask(v6.prefixlen as usize, 128) {
                Some(mask) => Box::new(IPNet { ip, mask }),
                None => Box::new(IPAddr { ip, zone: String::new() }),
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{name_to_hardware_addr, net_interfaces};

    /// The kernel's own per-interface view, which is what the netlink dump
    /// reports, reduced by the rule that an all-zero address counts as no address.
    fn expected_hardware_addr(name: &str) -> Option<Vec<u8>> {
        let raw = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
        let bytes: Vec<u8> = raw.trim().split(':').filter_map(|b| u8::from_str_radix(b, 16).ok()).collect();
        (!bytes.is_empty() && bytes.iter().any(|&b| b != 0)).then_some(bytes)
    }

    /// `component/dhcp` builds its DISCOVER from `Interface::hardware_addr`, and leaving that
    /// field empty on every platform sent the request out with an all-zero `chaddr` that no DHCP
    /// server answers. `net_interfaces` must report what the kernel has.
    #[test]
    fn reported_hardware_addresses_match_sysfs() {
        let mut compared = 0usize;
        for iface in net_interfaces().expect("interfaces") {
            let Some(expected) = expected_hardware_addr(&iface.name) else { continue };
            assert_eq!(iface.hardware_addr.0, expected, "{} hardware address", iface.name);
            assert_eq!(name_to_hardware_addr(&iface.name).expect("SIOCGIFHWADDR").0, expected);
            compared += 1;
        }
        assert!(compared > 0, "no interface could be cross-checked against /sys/class/net");
    }

    /// An interface with no address is still an interface. `if-addrs` enumerates addresses, so an
    /// address-less link (a powered-down wifi device, a dummy, a bridge) is dropped before any
    /// lookup can see it; the listing must cover the kernel's link table instead.
    #[test]
    fn network_interfaces_include_links_with_no_address() {
        let listed: std::collections::HashSet<String> =
            net_interfaces().expect("interfaces").into_iter().map(|i| i.name).collect();
        let mut missing = Vec::new();
        for entry in std::fs::read_dir("/sys/class/net").expect("kernel link table") {
            let name = entry.expect("entry").file_name().to_string_lossy().into_owned();
            if !listed.contains(&name) {
                missing.push(name);
            }
        }
        assert!(missing.is_empty(), "interfaces in the kernel's link table are missing: {missing:?}");
    }
}
