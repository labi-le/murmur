use std::net::IpAddr;

use super::process::ProcessError;

pub(crate) fn find_process_name(_network: &str, _ip: Option<IpAddr>, _src_port: i32) -> anyhow::Result<(u32, String)> {
    Err(ProcessError::PlatformNotSupport.into())
}
