use std::any::Any;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use anyhow::Result;
use parking_lot::RwLock;

/// A shared `Enhancer`, the Rust form of the interface value.
pub type SharedEnhancer = Arc<dyn Enhancer + Send + Sync>;

/// Bound on `Enhancer` itself, not on `Any`.
///
/// `Arc<dyn Enhancer>` does not itself implement `Enhancer`, so it never matches the blanket below
/// and `as_any` on a [`SharedEnhancer`] always dispatches through the `Arc` to the concrete mapper
/// instead of answering for the `Arc`.
///
/// The blanket impl below stays deliberately: every member of this workspace is
/// `publish = false`, so no downstream crate can write an `impl AsAny` for it to collide with,
/// and sealing the trait would change a public shape for no gain.
pub trait AsAny: Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Enhancer + 'static> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait Enhancer: AsAny + Send + Sync {
    fn fake_ip_enabled(&self) -> bool;
    fn mapping_enabled(&self) -> bool;
    fn is_fake_ip(&self, ip: IpAddr) -> bool;
    fn is_fake_broadcast_ip(&self, ip: IpAddr) -> bool;
    fn is_exist_fake_ip(&self, ip: IpAddr) -> bool;
    /// The host name and a found flag; `None` is `("", false)`.
    fn find_host_by_ip(&self, ip: IpAddr) -> Option<String>;
    fn flush_fake_ip(&self) -> Result<()>;
    fn insert_host_by_ip(&self, ip: IpAddr, host: &str);
    fn store_fake_pool_state(&self);
}

static DEFAULT_HOST_MAPPER: LazyLock<RwLock<Option<SharedEnhancer>>> = LazyLock::new(|| RwLock::new(None));

pub fn default_host_mapper() -> Option<SharedEnhancer> {
    DEFAULT_HOST_MAPPER.read().clone()
}

pub fn set_default_host_mapper(mapper: Option<SharedEnhancer>) {
    *DEFAULT_HOST_MAPPER.write() = mapper;
}

#[must_use]
pub fn fake_ip_enabled() -> bool {
    default_host_mapper().is_some_and(|mapper| mapper.fake_ip_enabled())
}

#[must_use]
pub fn mapping_enabled() -> bool {
    default_host_mapper().is_some_and(|mapper| mapper.mapping_enabled())
}

#[must_use]
pub fn is_fake_ip(ip: IpAddr) -> bool {
    default_host_mapper().is_some_and(|mapper| mapper.is_fake_ip(ip))
}

#[must_use]
pub fn is_fake_broadcast_ip(ip: IpAddr) -> bool {
    default_host_mapper().is_some_and(|mapper| mapper.is_fake_broadcast_ip(ip))
}

#[must_use]
pub fn is_exist_fake_ip(ip: IpAddr) -> bool {
    default_host_mapper().is_some_and(|mapper| mapper.is_exist_fake_ip(ip))
}

pub fn insert_host_by_ip(ip: IpAddr, host: &str) {
    if let Some(mapper) = default_host_mapper() {
        mapper.insert_host_by_ip(ip, host);
    }
}

#[must_use]
pub fn find_host_by_ip(ip: IpAddr) -> Option<String> {
    default_host_mapper().and_then(|mapper| mapper.find_host_by_ip(ip))
}

pub fn flush_fake_ip() -> Result<()> {
    default_host_mapper().map_or(Ok(()), |mapper| mapper.flush_fake_ip())
}

pub fn store_fake_pool_state() {
    if let Some(mapper) = default_host_mapper() {
        mapper.store_fake_pool_state();
    }
}
