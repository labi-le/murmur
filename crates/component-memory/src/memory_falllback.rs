use super::memory::{ErrNotImplementedError, MemoryInfoStat};

pub async fn get_memory_info(_pid: i32) -> anyhow::Result<MemoryInfoStat> {
    Err(ErrNotImplementedError.into())
}
