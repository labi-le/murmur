use std::path::PathBuf;
use std::sync::LazyLock;

use super::memory::MemoryInfoStat;

pub(crate) static PAGE_SIZE: LazyLock<u64> = LazyLock::new(getpagesize);

#[allow(unsafe_code)]
fn getpagesize() -> u64 {
    // SAFETY: reads a kernel constant, no preconditions.
    let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    // `sysconf` signals failure with -1; a zero page size reports zero sizes
    // instead of wrapping them into garbage.
    u64::try_from(pagesize).unwrap_or_default()
}

pub async fn get_memory_info(pid: i32) -> anyhow::Result<MemoryInfoStat> {
    let proc = match std::env::var("HOST_PROC") {
        Ok(proc) if !proc.is_empty() => proc,
        _ => "/proc".to_owned(),
    };
    let mem_path = PathBuf::from(proc).join(pid.to_string()).join("statm");
    let contents = tokio::fs::read(mem_path).await?;
    let contents = String::from_utf8_lossy(&contents);
    let fields: Vec<&str> = contents.split(' ').collect();

    let vms: u64 = fields.first().ok_or_else(|| anyhow::anyhow!("statm: missing vms field"))?.parse()?;
    let rss: u64 = fields.get(1).ok_or_else(|| anyhow::anyhow!("statm: missing rss field"))?.parse()?;
    Ok(MemoryInfoStat { rss: rss * *PAGE_SIZE, vms: vms * *PAGE_SIZE })
}
