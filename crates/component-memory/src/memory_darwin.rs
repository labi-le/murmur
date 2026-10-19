use std::mem::size_of;
use std::ptr;

use super::memory::MemoryInfoStat;

pub const PROC_PIDTASKINFO: i32 = 4;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcTaskInfo {
    pub virtual_size: u64,
    pub resident_size: u64,
    pub total_user: u64,
    pub total_system: u64,
    pub threads_user: u64,
    pub threads_system: u64,
    pub policy: i32,
    pub faults: i32,
    pub pageins: i32,
    pub cow_faults: i32,
    pub messages_sent: i32,
    pub messages_received: i32,
    pub syscalls_mach: i32,
    pub syscalls_unix: i32,
    pub csw: i32,
    pub threadnum: i32,
    pub numrunning: i32,
    pub priority: i32,
}

#[allow(unsafe_code)]
pub async fn get_memory_info(pid: i32) -> anyhow::Result<MemoryInfoStat> {
    let mut ti = ProcTaskInfo::default();
    // SAFETY: `ti` outlives the call and the size passed is exactly its size.
    let ret = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDTASKINFO,
            0,
            ptr::addr_of_mut!(ti).cast::<libc::c_void>(),
            size_of::<ProcTaskInfo>() as i32,
        )
    };
    if ret <= 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(MemoryInfoStat { rss: ti.resident_size, vms: ti.virtual_size })
}
