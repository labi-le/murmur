use std::ffi::CString;
use std::mem::size_of;
use std::ptr;

use super::memory::MemoryInfoStat;

#[cfg(target_arch = "x86")]
use super::memory_freebsd_386::{KinfoProc, SIZE_OF_KINFO_PROC};
#[cfg(target_arch = "x86_64")]
use super::memory_freebsd_amd64::{KinfoProc, SIZE_OF_KINFO_PROC};
#[cfg(target_arch = "arm")]
use super::memory_freebsd_arm::{KinfoProc, SIZE_OF_KINFO_PROC};
#[cfg(target_arch = "aarch64")]
use super::memory_freebsd_arm64::{KinfoProc, SIZE_OF_KINFO_PROC};

fn kinfo_proc_size() -> anyhow::Result<u64> {
    if SIZE_OF_KINFO_PROC != size_of::<KinfoProc>() {
        return Err(anyhow::anyhow!("KinfoProc size constant disagrees with the packed struct size"));
    }
    u64::try_from(SIZE_OF_KINFO_PROC).map_err(|_| anyhow::anyhow!("KinfoProc size does not fit u64"))
}

pub const CTL_KERN: i32 = 1;
pub const KERN_PROC: i32 = 14;
pub const KERN_PROC_PID: i32 = 1;

#[allow(unsafe_code)]
pub fn call_syscall(mib: &[i32]) -> anyhow::Result<(Vec<u8>, u64)> {
    let mut length: libc::size_t = 0;
    // SAFETY: a null `oldp` makes the kernel report the needed length only.
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            u32::try_from(mib.len()).unwrap_or(u32::MAX),
            ptr::null_mut(),
            ptr::addr_of_mut!(length),
            ptr::null(),
            0,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if length == 0 {
        return Ok((Vec::new(), 0));
    }
    let mut buf = vec![0u8; length];
    // SAFETY: `buf` holds exactly the length the kernel asked for above.
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            u32::try_from(mib.len()).unwrap_or(u32::MAX),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            ptr::addr_of_mut!(length),
            ptr::null(),
            0,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok((buf, u64::try_from(length).map_err(|_| anyhow::anyhow!("sysctl length does not fit u64"))?))
}

#[allow(unsafe_code)]
pub(crate) fn parse_kinfo_proc(buf: &[u8]) -> anyhow::Result<KinfoProc> {
    if buf.len() < size_of::<KinfoProc>() {
        return Err(anyhow::anyhow!("unexpected EOF"));
    }
    // SAFETY: `KinfoProc` is repr(C) plain data and `buf` is at least that large.
    Ok(unsafe { ptr::read_unaligned(buf.as_ptr().cast::<KinfoProc>()) })
}

pub(crate) fn get_k_proc(pid: i32) -> anyhow::Result<KinfoProc> {
    let mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid];

    let (buf, length) = call_syscall(&mib)?;
    if length != kinfo_proc_size()? {
        return Err(anyhow::anyhow!("unexpected size of KinfoProc"));
    }

    parse_kinfo_proc(&buf)
}

#[allow(unsafe_code)]
fn sysctl_raw(name: &str) -> anyhow::Result<Vec<u8>> {
    let name = CString::new(name)?;
    let mut length: libc::size_t = 0;
    // SAFETY: a null `oldp` makes the kernel report the needed length only.
    let ret = unsafe { libc::sysctlbyname(name.as_ptr(), ptr::null_mut(), ptr::addr_of_mut!(length), ptr::null(), 0) };
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
            ptr::null(),
            0,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(buf)
}

pub async fn get_memory_info(pid: i32) -> anyhow::Result<MemoryInfoStat> {
    let k = get_k_proc(pid)?;
    let v = sysctl_raw("vm.stats.vm.v_page_size")?;
    if v.len() < size_of::<u16>() {
        return Err(anyhow::anyhow!("unexpected EOF"));
    }
    let page_size = u16::from_le_bytes([v[0], v[1]]);

    let rss = u64::try_from(k.rssize).map_err(|_| anyhow::anyhow!("KinfoProc rssize is negative"))?;
    let vms = u64::try_from(k.size).map_err(|_| anyhow::anyhow!("KinfoProc size does not fit u64"))?;

    Ok(MemoryInfoStat { rss: rss * u64::from(page_size), vms })
}
