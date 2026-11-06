use std::ffi::c_void;
use std::mem::size_of;

use super::memory::MemoryInfoStat;

type Handle = *mut c_void;

#[link(name = "psapi")]
extern "system" {
    fn GetProcessMemoryInfo(process: Handle, ppsmem_counters: *mut ProcessMemoryCounters, cb: u32) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(dw_desired_access: u32, b_inherit_handle: i32, dw_process_id: u32) -> Handle;
    fn CloseHandle(h_object: Handle) -> i32;
}

pub(crate) const PROCESS_QUERY_INFORMATION: u32 = 0x1000;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessMemoryCounters {
    pub cb: u32,
    pub page_fault_count: u32,
    pub peak_working_set_size: u64,
    pub working_set_size: u64,
    pub quota_peak_paged_pool_usage: u64,
    pub quota_paged_pool_usage: u64,
    pub quota_peak_non_paged_pool_usage: u64,
    pub quota_non_paged_pool_usage: u64,
    pub pagefile_usage: u64,
    pub peak_pagefile_usage: u64,
}

#[allow(unsafe_code)]
fn get_process_memory_info(h: Handle, mem: &mut ProcessMemoryCounters) -> anyhow::Result<()> {
    // SAFETY: `mem` outlives the call and its size is passed alongside it.
    let r1 =
        unsafe { GetProcessMemoryInfo(h, mem, u32::try_from(size_of::<ProcessMemoryCounters>()).unwrap_or(u32::MAX)) };
    if r1 == 0 {
        let e1 = std::io::Error::last_os_error();
        if e1.raw_os_error().unwrap_or(0) != 0 {
            return Err(e1.into());
        }
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL).into());
    }
    Ok(())
}

/// Queries the process memory counters.
#[allow(unsafe_code)]
fn query_process_memory_counters(pid: i32) -> anyhow::Result<ProcessMemoryCounters> {
    let mut mem = ProcessMemoryCounters::default();
    // SAFETY: plain FFI call, the returned handle is checked for null before use.
    let c = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid.cast_unsigned()) };
    if c.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let res = get_process_memory_info(c, &mut mem);
    let _ = unsafe { CloseHandle(c) };
    res?;

    Ok(mem)
}

pub async fn get_memory_info(pid: i32) -> anyhow::Result<MemoryInfoStat> {
    let mem = query_process_memory_counters(pid)?;
    Ok(MemoryInfoStat { rss: mem.working_set_size, vms: mem.pagefile_usage })
}
