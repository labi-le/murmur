use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use anyhow::anyhow;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, GetExtendedUdpTable};
use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW};

use super::process::{ProcessError, TCP, UDP};

const AF_INET: i32 = 2;
const AF_INET6: i32 = 23;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const MAX_LONG_PATH: usize = 32767;
const TCP_TABLE_PID_CONN: i32 = 4;
const UDP_TABLE_PID: i32 = 1;

pub(crate) fn find_process_name(network: &str, ip: Option<IpAddr>, src_port: i32) -> anyhow::Result<(u32, String)> {
    let family = if matches!(ip, Some(IpAddr::V6(_))) { AF_INET6 } else { AF_INET };

    let (is_tcp, class) = match network {
        TCP => (true, TCP_TABLE_PID_CONN),
        UDP => (false, UDP_TABLE_PID),
        _ => return Err(ProcessError::InvalidNetwork.into()),
    };

    let buf = get_transport_table(is_tcp, family, class)?;

    let s = new_searcher(family == AF_INET, network == TCP);

    let pid = s.search(&buf, ip, u16::try_from(src_port)?)?;
    let pp = get_exec_path_from_pid(pid);
    Ok((0, pp?))
}

pub(crate) struct Searcher {
    pub item_size: usize,
    pub port: usize,
    pub ip: usize,
    pub ip_size: usize,
    pub pid: usize,
    pub tcp_state: i32,
}

impl Searcher {
    pub(crate) fn search(&self, b: &[u8], ip: Option<IpAddr>, port: u16) -> anyhow::Result<u32> {
        let n = read_native_u32(b) as usize;
        let item_size = self.item_size;
        let tcp_state = usize::try_from(self.tcp_state).unwrap_or(0);
        for i in 0..n {
            let Some(row) = b.get(4 + item_size * i..4 + item_size * (i + 1)) else {
                continue;
            };

            if self.tcp_state >= 0 {
                let tcp_state = read_native_u32(row.get(tcp_state..).unwrap_or_default());
                // MIB_TCP_STATE_ESTAB, only check established connections for TCP
                if tcp_state != 5 {
                    continue;
                }
            }

            // according to MSDN, only the lower 16 bits of dwLocalPort are used and the port number
            // is in network endian. This field depends on the machine's endianness:
            //     little endian: [ MSB LSB  0   0  ]   native u32 is ((LSB<<8)|MSB)
            //       big  endian: [  0   0  MSB LSB ]   native u32 is ((MSB<<8)|LSB)
            // so the lower 16 bits need a byte swap after being read as a native u32.
            let src_port = ntohs(
                u16::try_from(read_native_u32(row.get(self.port..).unwrap_or_default()) & 0xffff).unwrap_or_default(),
            );
            if src_port != port {
                continue;
            }

            let Some(src) = row.get(self.ip..self.ip + self.ip_size) else {
                continue;
            };
            let src_ip = if self.ip_size == 4 {
                let bytes: [u8; 4] = src.get(..4).and_then(|s| s.try_into().ok()).unwrap_or_default();
                Some(IpAddr::V4(Ipv4Addr::from(bytes)))
            } else {
                let mut a = [0u8; 16];
                if src.len() >= 16 {
                    a.copy_from_slice(src.get(..16).unwrap_or_default());
                }
                Some(IpAddr::V6(Ipv6Addr::from(a)))
            };
            let src_ip = src_ip.map(unmap);
            // windows binds an unbound udp socket to 0.0.0.0/[::] while first sendto
            if ip != src_ip && (!src_ip.is_some_and(|ip| ip.is_unspecified()) || self.tcp_state != -1) {
                continue;
            }

            let pid = read_native_u32(row.get(self.pid..).unwrap_or_default());
            return Ok(pid);
        }
        Err(ProcessError::NotFound.into())
    }
}

pub(crate) fn new_searcher(is_v4: bool, is_tcp: bool) -> Searcher {
    let (item_size, port, ip, ip_size, pid, tcp_state) = match (is_v4, is_tcp) {
        // struct MIB_TCPROW_OWNER_PID
        (true, true) => (24, 8, 4, 4, 20, 0),
        // struct MIB_UDPROW_OWNER_PID
        (true, false) => (12, 4, 0, 4, 8, -1),
        // struct MIB_TCP6ROW_OWNER_PID
        (false, true) => (56, 20, 0, 16, 52, 48),
        // struct MIB_UDP6ROW_OWNER_PID
        (false, false) => (28, 20, 0, 16, 24, -1),
    };

    Searcher { item_size, port, ip, ip_size, pid, tcp_state }
}

#[allow(unsafe_code)]
pub(crate) fn get_transport_table(is_tcp: bool, family: i32, class: i32) -> anyhow::Result<Vec<u8>> {
    let mut size: u32 = 8;
    let mut buf = vec![0u8; 8];
    loop {
        // SAFETY: `buf` and `size` describe the same live buffer that `GetExtendedTcpTable`/
        // `GetExtendedUdpTable` fills, per the documented six-argument signature:
        // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
        // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable
        let err = unsafe {
            if is_tcp {
                GetExtendedTcpTable(
                    buf.as_mut_ptr().cast(),
                    ptr::addr_of_mut!(size),
                    0,
                    family.cast_unsigned(),
                    class,
                    0,
                )
            } else {
                GetExtendedUdpTable(
                    buf.as_mut_ptr().cast(),
                    ptr::addr_of_mut!(size),
                    0,
                    family.cast_unsigned(),
                    class,
                    0,
                )
            }
        };

        match err {
            0 => return Ok(buf),
            ERROR_INSUFFICIENT_BUFFER => buf = vec![0u8; size as usize],
            err => return Err(anyhow!("syscall error: {err}")),
        }
    }
}

pub(crate) fn read_native_u32(b: &[u8]) -> u32 {
    b.get(..4).and_then(|b| b.try_into().ok()).map_or(0, u32::from_ne_bytes)
}

#[allow(unsafe_code)]
pub(crate) fn get_exec_path_from_pid(pid: u32) -> anyhow::Result<String> {
    // kernel process starts with a colon in order to distinguish with normal processes
    match pid {
        // reserved pid for system idle process
        0 => return Ok(":System Idle Process".to_owned()),
        // reserved pid for windows kernel image
        4 => return Ok(":System".to_owned()),
        _ => {}
    }

    let h = open_process(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;

    let mut buf = vec![0u16; MAX_LONG_PATH];
    let mut size = u32::try_from(buf.len()).unwrap_or(u32::MAX);

    // SAFETY: windows-sys `QueryFullProcessImageNameW(HANDLE, PROCESS_NAME_FORMAT, PWSTR, *mut u32) -> BOOL`;
    // `h` is an open handle with PROCESS_QUERY_LIMITED_INFORMATION; `buf` is live for the call and
    // `size` is its length in u16 characters, rewritten on success to the characters written
    // excluding the NUL (<= buf.len()).
    let r1 = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), ptr::addr_of_mut!(size)) };
    let result = if r1 == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(String::from_utf16_lossy(buf.get(..size as usize).unwrap_or_default()))
    };

    close_handle(h);
    result
}

#[allow(unsafe_code)]
fn open_process(access: u32, inherit: bool, pid: u32) -> anyhow::Result<*mut c_void> {
    // SAFETY: the arguments are the documented `OpenProcess` values.
    let h = unsafe { OpenProcess(access, i32::from(inherit), pid) };
    if h.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(h)
}

#[allow(unsafe_code)]
fn close_handle(handle: *mut c_void) {
    // SAFETY: `handle` comes from `OpenProcess` and is closed exactly once.
    unsafe {
        CloseHandle(handle);
    }
}

fn ntohs(v: u16) -> u16 {
    v.to_be()
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}
