//! Every platform but Linux. `open` is the whole point of this file: there is no device to create
//! and no weaker thing to fall back to, so it fails with the platform named rather than handing
//! back a value that looks like a working TUN.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{bail, Result};
use ipnet::IpNet;

use super::{Cleanup, Device, TunAddresses};

pub(super) struct Inner;

pub(super) fn open(_device: &str, _file_descriptor: i32, _addresses: &TunAddresses) -> Result<(Arc<Device>, Cleanup)> {
    bail!("tun is not supported on {}: only the Linux TUN device has a Rust implementation", std::env::consts::OS);
}

pub(super) fn add_route(_dst: IpNet, _index: u32) -> Result<()> {
    bail!(
        "tun routes are not supported on {}: only the Linux TUN device has a Rust implementation",
        std::env::consts::OS
    )
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the shared device code calls this on every platform and Linux answers with a result"
)]
pub(super) fn delete_address(_index: u32, _addr: &IpAddr, _prefix_len: u8) -> Result<()> {
    Ok(())
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the shared device code calls this on every platform and Linux answers with a result"
)]
pub(super) fn delete_route(_dst: &IpNet, _index: u32) -> Result<()> {
    Ok(())
}

impl Inner {
    #[expect(
        clippy::unused_async,
        reason = "the shared device code awaits this on Linux as well, so the stub keeps the same shape"
    )]
    pub(super) async fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    #[expect(
        clippy::unused_async,
        reason = "the shared device code awaits this on Linux as well, so the stub keeps the same shape"
    )]
    pub(super) async fn write(&self, _packet: &[u8]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
