use serde::{Deserialize, Serialize};

/// The sentinel error for memory statistics this platform does not implement.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
#[error("not implemented yet")]
pub struct ErrNotImplementedError;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryInfoStat {
    /// bytes
    #[serde(rename = "rss")]
    pub rss: u64,
    /// bytes
    #[serde(rename = "vms")]
    pub vms: u64,
}

/// Converts a size in bytes to bytes, kilobytes, megabytes, gigabytes and terabytes.
/// <https://gist.github.com/anikitenko/b41206a49727b83a530142c76b1cb82d?permalink_comment_id=4467913#gistcomment-4467913>
#[must_use]
pub fn pretty_byte_size(b: u64) -> String {
    // the conversion to `f64` rounds the same way; sizes are only ever displayed.
    #[allow(
        clippy::cast_precision_loss,
        reason = "the conversion to f64 loses precision the same way and the value is only displayed"
    )]
    let mut bf = b as f64;
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"] {
        if bf.abs() < 1024.0 {
            return format!("{bf:3.1}{unit}B");
        }
        bf /= 1024.0;
    }
    format!("{bf:.1}YiB")
}

#[cfg(target_os = "macos")]
pub use super::memory_darwin::get_memory_info;
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "windows"
)))]
pub use super::memory_falllback::get_memory_info;
#[cfg(target_os = "freebsd")]
pub use super::memory_freebsd::get_memory_info;
#[cfg(target_os = "linux")]
pub use super::memory_linux::get_memory_info;
#[cfg(target_os = "openbsd")]
pub use super::memory_openbsd::get_memory_info;
#[cfg(target_os = "windows")]
pub use super::memory_windows::get_memory_info;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_info() {
        let v = match get_memory_info(i32::try_from(std::process::id()).expect("current pid fits in i32")).await {
            Ok(v) => v,
            Err(err) => {
                if err.is::<ErrNotImplementedError>() {
                    println!("not implemented");
                    return;
                }
                panic!("getting memory info error {err}");
            }
        };
        let empty = MemoryInfoStat::default();
        if v == empty {
            panic!("could not get memory info {v:?}");
        } else {
            println!("memory info {{RSS:{}, VMS:{}}}", pretty_byte_size(v.rss), pretty_byte_size(v.vms));
        }
    }
}
