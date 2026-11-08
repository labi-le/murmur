use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::LazyLock;

use super::process::{ProcessError, TCP, UDP};

const PROCPIDPATHINFO: libc::c_int = 0xb;
const PROCPIDPATHINFOSIZE: usize = 1024;

/// Computed once from `kern.osrelease`.
static STRUCT_SIZE: LazyLock<usize> = LazyLock::new(|| {
    let value = sysctl_string("kern.osrelease").unwrap_or_default();
    let major = value.split('.').next().unwrap_or_default();
    let n = major.parse::<i64>().unwrap_or_default();
    if n >= 22 {
        408
    } else {
        // from darwin-xnu/bsd/netinet/in_pcblist.c:get_pcblist_n
        // size/offset are round up (aligned) to 8 bytes in darwin
        // rup8(sizeof(xinpcb_n)) + rup8(sizeof(xsocket_n)) +
        // 2 * rup8(sizeof(xsockbuf_n)) + rup8(sizeof(xsockstat_n))
        384
    }
});

pub(crate) fn find_process_name(network: &str, ip: Option<IpAddr>, port: i32) -> anyhow::Result<(u32, String)> {
    let spath = match network {
        TCP => "net.inet.tcp.pcblist_n",
        UDP => "net.inet.udp.pcblist_n",
        _ => return Err(ProcessError::InvalidNetwork.into()),
    };

    let is_ipv4 = matches!(ip, Some(IpAddr::V4(_)));

    let buf = sysctl_raw(spath)?;

    let mut item_size = *STRUCT_SIZE;
    if network == TCP {
        // rup8(sizeof(xtcpcb_n))
        item_size += 208;
    }

    let mut fallback_udp_process = String::new();
    // skip the first xinpgen(24 bytes) block
    for i in (24..).step_by(item_size) {
        if i + item_size > buf.len() {
            break;
        }
        // offset of xinpcb_n and xsocket_n
        let (inp, so) = (i, i + 104);

        let src_port = u16::from_be_bytes([buf[inp + 18], buf[inp + 19]]);
        if port as u16 != src_port {
            continue;
        }

        // xinpcb_n.inp_vflag
        let flag = buf[inp + 44];

        let (src_ip, src_is_ipv4) = if flag & 0x1 > 0 && is_ipv4 {
            // ipv4
            let ip = Ipv4Addr::new(buf[inp + 76], buf[inp + 77], buf[inp + 78], buf[inp + 79]);
            (Some(IpAddr::V4(ip)), true)
        } else if flag & 0x2 > 0 && !is_ipv4 {
            // ipv6
            let mut a = [0u8; 16];
            a.copy_from_slice(&buf[inp + 64..inp + 80]);
            (Some(IpAddr::V6(Ipv6Addr::from(a))), false)
        } else {
            continue;
        };
        let src_ip = src_ip.map(unmap);

        if ip == src_ip {
            // xsocket_n.so_last_pid
            let pid = read_native_u32(&buf, so + 68);
            let pp = get_exec_path_from_pid(pid);
            return Ok((0, pp?));
        }

        // udp packet connection may be not equal with srcIP
        if network == UDP && src_ip.is_some_and(|ip| ip.is_unspecified()) && is_ipv4 == src_is_ipv4 {
            fallback_udp_process = get_exec_path_from_pid(read_native_u32(&buf, so + 68)).unwrap_or_default();
        }
    }

    if network == UDP && !fallback_udp_process.is_empty() {
        return Ok((0, fallback_udp_process));
    }

    Err(ProcessError::NotFound.into())
}

#[allow(unsafe_code)]
pub(crate) fn get_exec_path_from_pid(pid: u32) -> anyhow::Result<String> {
    let mut buf = vec![0u8; PROCPIDPATHINFOSIZE];

    // SAFETY: `buf` is a live buffer of the size passed as `buffersize`, and the call only writes
    // within it.
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            PROCPIDPATHINFO,
            0,
            buf.as_mut_ptr().cast(),
            PROCPIDPATHINFOSIZE as libc::c_int,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(byte_slice_to_string(&buf))
}

pub(crate) fn read_native_u32(b: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]])
}

fn byte_slice_to_string(b: &[u8]) -> String {
    let end = b.iter().position(|b| *b == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        ip => ip,
    }
}

/// The kernel reports the size first, then the bytes are read.
#[allow(unsafe_code)]
fn sysctl_raw(name: &str) -> anyhow::Result<Vec<u8>> {
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

    Ok(buf)
}

/// The sysctl, which drops the trailing NUL.
fn sysctl_string(name: &str) -> anyhow::Result<String> {
    let value = sysctl_raw(name)?;
    Ok(byte_slice_to_string(&value))
}
