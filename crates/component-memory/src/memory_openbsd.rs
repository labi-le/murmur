use std::mem::size_of;
use std::ptr;

use super::memory::MemoryInfoStat;

#[cfg(target_arch = "x86")]
use super::memory_openbsd_386::{KinfoProc, SIZE_OF_KINFO_PROC};
#[cfg(target_arch = "x86_64")]
use super::memory_openbsd_amd64::{KinfoProc, SIZE_OF_KINFO_PROC};
#[cfg(target_arch = "arm")]
use super::memory_openbsd_arm::{KinfoProc, SIZE_OF_KINFO_PROC};
#[cfg(target_arch = "aarch64")]
use super::memory_openbsd_arm64::{KinfoProc, SIZE_OF_KINFO_PROC};
#[cfg(target_arch = "riscv64")]
use super::memory_openbsd_riscv64::{KinfoProc, SIZE_OF_KINFO_PROC};

fn kinfo_proc_size() -> anyhow::Result<u64> {
    if SIZE_OF_KINFO_PROC != size_of::<KinfoProc>() {
        return Err(anyhow::anyhow!("KinfoProc size constant disagrees with the packed struct size"));
    }
    u64::try_from(SIZE_OF_KINFO_PROC).map_err(|_| anyhow::anyhow!("KinfoProc size does not fit u64"))
}

fn kinfo_proc_size_i32() -> anyhow::Result<i32> {
    let size = kinfo_proc_size()?;
    i32::try_from(size).map_err(|_| anyhow::anyhow!("KinfoProc size does not fit the MIB int field"))
}

pub const CTL_KERN: i32 = 1;
pub const KERN_PROC: i32 = 14;
pub const KERN_PROC_PID: i32 = 1;

const CTL_VM: i32 = 2;
const VM_UVMEXP: i32 = 4;
const SIZE_OF_UVMEXP: u64 = 0x158;

#[allow(unsafe_code)]
pub(crate) fn call_kern_proc_syscall(op: i32, arg: i32) -> anyhow::Result<(Vec<u8>, u64)> {
    let mut mib = [CTL_KERN, KERN_PROC, op, arg, kinfo_proc_size_i32()?, 0];
    let mut length: libc::size_t = 0;
    // SAFETY: a null `oldp` makes the kernel report the needed length only.
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            u32::try_from(mib.len()).unwrap_or(u32::MAX),
            ptr::null_mut(),
            ptr::addr_of_mut!(length),
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let count = i32::try_from(length / SIZE_OF_KINFO_PROC)
        .map_err(|_| anyhow::anyhow!("process count reported by the kernel does not fit an int"))?;
    mib = [CTL_KERN, KERN_PROC, op, arg, kinfo_proc_size_i32()?, count];
    let mut buf = vec![0u8; length];
    // SAFETY: `buf` holds exactly the length the kernel asked for above.
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            u32::try_from(mib.len()).unwrap_or(u32::MAX),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            ptr::addr_of_mut!(length),
            ptr::null_mut(),
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
    let (buf, length) = call_kern_proc_syscall(KERN_PROC_PID, pid)?;
    if length != kinfo_proc_size()? {
        return Err(anyhow::anyhow!("unexpected size of KinfoProc"));
    }

    parse_kinfo_proc(&buf)
}

#[allow(unsafe_code)]
fn uvmexp_pagesize() -> anyhow::Result<i32> {
    let mib = [CTL_VM, VM_UVMEXP];
    let mut length: libc::size_t = 0;
    // SAFETY: a null `oldp` makes the kernel report the needed length only.
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            u32::try_from(mib.len()).unwrap_or(u32::MAX),
            ptr::null_mut(),
            ptr::addr_of_mut!(length),
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let mut buf = vec![0u8; length];
    // SAFETY: `buf` holds exactly the length the kernel asked for above.
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            u32::try_from(mib.len()).unwrap_or(u32::MAX),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            ptr::addr_of_mut!(length),
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if u64::try_from(length).map_err(|_| anyhow::anyhow!("uvmexp length does not fit u64"))? != SIZE_OF_UVMEXP {
        return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
    }
    if buf.len() < size_of::<i32>() {
        return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
    }

    Ok(i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

pub async fn get_memory_info(pid: i32) -> anyhow::Result<MemoryInfoStat> {
    let k = get_k_proc(pid)?;
    let page_size = uvmexp_pagesize()?;

    let rss = u64::try_from(k.vm_rssize).map_err(|_| anyhow::anyhow!("KinfoProc vm_rssize is negative"))?;
    let vms = u64::try_from(k.vm_tsize).map_err(|_| anyhow::anyhow!("KinfoProc vm_tsize is negative"))?
        + u64::try_from(k.vm_dsize).map_err(|_| anyhow::anyhow!("KinfoProc vm_dsize is negative"))?
        + u64::try_from(k.vm_ssize).map_err(|_| anyhow::anyhow!("KinfoProc vm_ssize is negative"))?;
    let page_size_u64 = u64::try_from(page_size).map_err(|_| anyhow::anyhow!("negative page size from uvmexp"))?;

    Ok(MemoryInfoStat { rss: rss * page_size_u64, vms })
}
