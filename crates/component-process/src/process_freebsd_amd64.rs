use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::{Arc, Once};

use anyhow::anyhow;
use parking_lot::RwLock;

use super::process::{ProcessError, TCP, UDP};

/// Stores the process name for when dealing with multiple PROCESS-NAME rules.
static DEFAULT_SEARCHER: RwLock<Option<Arc<Searcher>>> = RwLock::new(None);

static ONCE: Once = Once::new();

pub(crate) fn find_process_name(network: &str, ip: Option<IpAddr>, src_port: i32) -> anyhow::Result<(u32, String)> {
    ONCE.call_once(|| {
        if let Err(err) = init_searcher() {
            murmur_log::errorln!("Initialize PROCESS-NAME failed: {}", err);
            murmur_log::warnln!("All PROCESS-NAME rules will be skipped");
        }
    });

    let Some(searcher) = DEFAULT_SEARCHER.read().clone() else {
        return Err(ProcessError::PlatformNotSupport.into());
    };

    let is_tcp = network == TCP;
    let spath = match network {
        TCP => "net.inet.tcp.pcblist",
        UDP => "net.inet.udp.pcblist",
        _ => return Err(ProcessError::InvalidNetwork.into()),
    };

    let buf = sysctl_bytes(spath)?;
    let pid = searcher.search(&buf, ip, src_port as u16, is_tcp)?;

    let pp = get_exec_path_from_pid(pid);
    Ok((0, pp?))
}

pub(crate) fn get_exec_path_from_pid(pid: u32) -> anyhow::Result<String> {
    let mut buf = vec![0u8; 2048];
    let mut size = buf.len() as libc::size_t;
    // CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid
    let mib: [libc::c_int; 4] = [1, 14, 12, pid as libc::c_int];

    // SAFETY: `mib` holds four valid names, `buf` and `size` describe one live buffer, and no new
    // value is written.
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast(),
            ptr::addr_of_mut!(size),
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if size == 0 {
        return Err(std::io::Error::from_raw_os_error(0).into());
    }

    Ok(String::from_utf8_lossy(&buf[..size - 1]).into_owned())
}

pub(crate) fn read_native_u32(b: &[u8]) -> u32 {
    u32::from_ne_bytes([b[0], b[1], b[2], b[3]])
}

pub(crate) struct Searcher {
    /// Size of the `xinpgen` header block.
    pub head_size: usize,
    /// Size of an `xtcpcb` entry.
    pub tcp_item_size: usize,
    /// Size of an `xinpcb` entry.
    pub udp_item_size: usize,
    pub udp_inp_offset: usize,
    pub port: usize,
    pub ip: usize,
    pub vflag: usize,
    pub socket: usize,

    /// Size of an `xfile` entry.
    pub file_item_size: usize,
    pub data: usize,
    pub pid: usize,
}

impl Searcher {
    pub(crate) fn search(&self, buf: &[u8], ip: Option<IpAddr>, port: u16, is_tcp: bool) -> anyhow::Result<u32> {
        let (item_size, inp_offset) = if is_tcp {
            // struct xtcpcb
            (self.tcp_item_size, 8)
        } else {
            // struct xinpcb
            (self.udp_item_size, self.udp_inp_offset)
        };

        let is_ipv4 = matches!(ip, Some(IpAddr::V4(_)));
        // skip the first xinpgen block
        for i in (self.head_size..).step_by(item_size) {
            if i + item_size > buf.len() {
                break;
            }
            let inp = i + inp_offset;

            let src_port = u16::from_be_bytes([buf[inp + self.port], buf[inp + self.port + 1]]);

            if port != src_port {
                continue;
            }

            // xinpcb.inp_vflag
            let flag = buf[inp + self.vflag];

            let src_ip = if flag & 0x1 > 0 && is_ipv4 {
                // ipv4
                let ip = Ipv4Addr::new(
                    buf[inp + self.ip],
                    buf[inp + self.ip + 1],
                    buf[inp + self.ip + 2],
                    buf[inp + self.ip + 3],
                );
                Some(IpAddr::V4(ip))
            } else if flag & 0x2 > 0 && !is_ipv4 {
                // ipv6
                let mut a = [0u8; 16];
                a.copy_from_slice(&buf[inp + self.ip - 12..inp + self.ip + 4]);
                Some(IpAddr::V6(Ipv6Addr::from(a)))
            } else {
                continue;
            };
            let src_ip = src_ip.map(unmap);

            if ip != src_ip {
                continue;
            }

            // xsocket.xso_so, interpreted as big endian anyway since it's only used for comparison
            let mut a = [0u8; 8];
            a.copy_from_slice(&buf[inp + self.socket..inp + self.socket + 8]);
            let socket = u64::from_be_bytes(a);
            return self.search_socket_pid(socket);
        }
        Err(ProcessError::NotFound.into())
    }

    pub(crate) fn search_socket_pid(&self, socket: u64) -> anyhow::Result<u32> {
        let buf = sysctl_bytes("kern.file")?;

        // struct xfile
        let item_size = self.file_item_size;
        for i in (0..).step_by(item_size) {
            if i + item_size > buf.len() {
                break;
            }
            // xfile.xf_data
            let mut a = [0u8; 8];
            a.copy_from_slice(&buf[i + self.data..i + self.data + 8]);
            let data = u64::from_be_bytes(a);
            if data == socket {
                // xfile.xf_pid
                let pid = read_native_u32(&buf[i + self.pid..i + self.pid + 4]);
                return Ok(pid);
            }
        }
        Err(ProcessError::NotFound.into())
    }
}

pub(crate) fn new_searcher(major: i32) -> Option<Searcher> {
    match major {
        11 => Some(Searcher {
            head_size: 32,
            tcp_item_size: 1304,
            udp_item_size: 632,
            port: 198,
            ip: 228,
            vflag: 116,
            socket: 88,
            file_item_size: 80,
            data: 56,
            pid: 8,
            udp_inp_offset: 8,
        }),
        12 | 13 | 14 | 15 => Some(Searcher {
            head_size: 64,
            tcp_item_size: 744,
            udp_item_size: 400,
            port: 254,
            ip: 284,
            vflag: 392,
            socket: 16,
            file_item_size: 128,
            data: 56,
            pid: 8,
            // the udp input offset stays at its zero value for these versions.
            udp_inp_offset: 0,
        }),
        _ => None,
    }
}

pub(crate) fn init_searcher() -> anyhow::Result<()> {
    let os_release = sysctl_text("kern.osrelease")?;

    let dot = os_release.find('.');
    let os_release = match dot {
        Some(dot) => &os_release[..dot],
        None => &os_release[..],
    };
    let major: i32 = os_release.parse()?;
    let searcher = new_searcher(major);
    *DEFAULT_SEARCHER.write() = searcher.map(Arc::new);
    if DEFAULT_SEARCHER.read().is_none() {
        return Err(anyhow!("unsupported freebsd version {major}"));
    }
    Ok(())
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        ip => ip,
    }
}

/// The kernel's bytes as they are, minus at most one trailing NUL. The
/// `pcblist` and `kern.file` payloads are binary and contain NUL bytes of their own.
#[allow(unsafe_code)]
fn sysctl_bytes(name: &str) -> anyhow::Result<Vec<u8>> {
    let name = CString::new(name)?;
    let mut length: libc::size_t = 0;
    // SAFETY: a null `oldp` makes the kernel report the needed length only.
    let ret =
        unsafe { libc::sysctlbyname(name.as_ptr(), ptr::null_mut(), ptr::addr_of_mut!(length), ptr::null_mut(), 0) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let mut buf = vec![0u8; length];
    // SAFETY: `buf` holds exactly the length the kernel asked for above.
    let ret = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            ptr::addr_of_mut!(length),
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    buf.truncate(length);
    if buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(buf)
}

/// The sysctl where the value is text, as `kern.osrelease` is.
fn sysctl_text(name: &str) -> anyhow::Result<String> {
    let value = sysctl_bytes(name)?;
    Ok(String::from_utf8_lossy(&value).into_owned())
}
