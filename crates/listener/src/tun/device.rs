//! The TUN device itself, split per platform: only Linux has one this crate can open.
//!
//! `open` is the whole of what a device owns — create or adopt the
//! interface, give it the configured addresses and bring it up — and [`Device::install_routes`]
//! adds the configured routes once the caller decides they are due. [`Cleanup::revert`] is the
//! mirror image, removing exactly what was added. Every platform
//! that cannot do that says so by name instead of returning a device that carries nothing.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use ipnet::IpNet;

#[cfg(target_os = "linux")]
#[path = "device/linux.rs"]
mod platform;

#[cfg(not(target_os = "linux"))]
#[path = "device/other.rs"]
mod platform;

/// A device carries at most one IPv6 header plus payload, which the 16-bit total-length field
/// caps at 65535 bytes; the slack covers a read racing a writer.
pub const MAX_PACKET_SIZE: usize = 65536;

/// The addresses and routes a device is configured with, already split by family.
#[derive(Clone, Debug, Default)]
pub struct TunAddresses {
    pub mtu: u32,
    pub addresses: Vec<IpNet>,
    pub routes: Vec<IpNet>,
}

pub struct Device {
    name: String,
    index: u32,
    inner: platform::Inner,
}

impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Device").field("name", &self.name).field("index", &self.index).finish_non_exhaustive()
    }
}

/// Everything the device added to the host, so closing leaves the routing table as it was.
///
/// An address or route left behind after a restart black-holes traffic with nothing pointing at the
/// TUN, so a failure to undo one is reported rather than swallowed.
#[derive(Debug, Default)]
pub struct Cleanup {
    addresses: Vec<(u32, IpAddr, u8)>,
    routes: Vec<(u32, IpNet)>,
}

impl Cleanup {
    #[cfg(target_os = "linux")]
    pub(super) fn record_address(&mut self, index: u32, addr: IpAddr, prefix_len: u8) {
        self.addresses.push((index, addr, prefix_len));
    }

    #[cfg(target_os = "linux")]
    pub(super) fn record_route(&mut self, index: u32, dst: IpNet) {
        self.routes.push((index, dst));
    }

    /// Drops a route that was added and then removed by the caller, so `revert` does not try to
    /// delete it a second time.
    pub(super) fn forget_route(&mut self, index: u32, dst: &IpNet) {
        self.routes.retain(|(recorded_index, recorded)| *recorded_index != index || recorded != dst);
    }

    pub fn revert(&mut self) -> Vec<anyhow::Error> {
        let mut errs = Vec::new();
        for (index, dst) in std::mem::take(&mut self.routes) {
            if let Err(err) = platform::delete_route(&dst, index) {
                errs.push(err);
            }
        }
        for (index, addr, prefix_len) in std::mem::take(&mut self.addresses) {
            if let Err(err) = platform::delete_address(index, &addr, prefix_len) {
                errs.push(err);
            }
        }
        errs
    }
}

/// A layer-3 packet pipe: one whole IP packet per read and per write, the surface the listener
/// drives for reads and writes; the tests drive the same path over a fake.
#[async_trait]
pub trait PacketDevice: Send + Sync {
    async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    async fn write(&self, packet: &[u8]) -> std::io::Result<()>;
}

impl Device {
    /// `device` is the requested interface name; the kernel settles any collision and the
    /// settled name is what `name` returns. A non-zero `file_descriptor` adopts an existing device
    /// instead and configures nothing, because that device belongs to whoever created it.
    pub fn open(device: &str, file_descriptor: i32, addresses: &TunAddresses) -> Result<(Arc<Self>, Cleanup)> {
        platform::open(device, file_descriptor, addresses)
    }

    /// The name the kernel settled on, which for an adopted device is the only thing `TUNGETIFF`
    /// can be asked and may disagree with the config's own `device`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Installs `routes` on the device's interface, recording each success in `cleanup` and
    /// returning the failures instead of stopping at the first: one route the host refuses must
    /// not hide the others.
    pub fn install_routes(&self, routes: &[IpNet], cleanup: &mut Cleanup) -> Vec<(IpNet, anyhow::Error)> {
        let mut failures = Vec::new();
        for dst in routes {
            match platform::add_route(*dst, self.index) {
                Ok(()) => cleanup.record_route(self.index, *dst),
                Err(err) => failures.push((*dst, err)),
            }
        }
        failures
    }

    /// Removes one route this device installed, for undoing a partially applied set.
    pub fn remove_route(&self, dst: &IpNet) -> Result<()> {
        platform::delete_route(dst, self.index)
    }
}

#[async_trait]
impl PacketDevice for Device {
    /// one whole IP packet per call.
    async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf).await
    }

    /// one whole IP packet per call.
    async fn write(&self, packet: &[u8]) -> std::io::Result<()> {
        self.inner.write(packet).await
    }
}
