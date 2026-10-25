use std::net::IpAddr;

use parking_lot::RwLock;

use murmur_constant::metadata::Metadata;

#[cfg(target_os = "macos")]
use super::process_darwin as platform;
#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
use super::process_freebsd_amd64 as platform;
#[cfg(any(target_os = "linux", target_os = "android"))]
use super::process_linux as platform;
#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    all(target_os = "freebsd", target_arch = "x86_64")
)))]
use super::process_other as platform;
#[cfg(target_os = "windows")]
use super::process_windows as platform;

/// The package's sentinel errors.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    #[error("invalid network")]
    InvalidNetwork,
    #[error("not support on this platform")]
    PlatformNotSupport,
    #[error("process not found")]
    NotFound,
}

pub const TCP: &str = "tcp";
pub const UDP: &str = "udp";

/// The `None` case stands for an invalid zero address.
pub fn find_process_name(network: &str, src_ip: Option<IpAddr>, src_port: i32) -> anyhow::Result<(u32, String)> {
    platform::find_process_name(network, src_ip, src_port)
}

/// the `PackageNameResolver`; never change its shape because it is used in CMFA.
pub type PackageNameResolver = fn(&Metadata) -> anyhow::Result<String>;

pub static DEFAULT_PACKAGE_NAME_RESOLVER: RwLock<Option<PackageNameResolver>> = RwLock::new(None);

pub fn find_package_name(metadata: &Metadata) -> anyhow::Result<String> {
    let resolver = *DEFAULT_PACKAGE_NAME_RESOLVER.read();
    if let Some(resolver) = resolver {
        return resolver(metadata);
    }
    Err(ProcessError::PlatformNotSupport.into())
}
