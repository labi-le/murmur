use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_common::utils::ranges::IntRanges;
use murmur_constant::adapters::{Conn as CConn, Proxy, ProxyAdapter};
use murmur_constant::provider::interface::ProxyProvider;

use super::fallback::Fallback;
use super::loadbalance::LoadBalance;
use super::selector::Selector;
use super::urltest::URLTest;

#[async_trait]
pub trait ProxyGroup: ProxyAdapter {
    fn providers(&self) -> Vec<Arc<dyn ProxyProvider>>;

    fn proxies(&self) -> Vec<Arc<dyn Proxy>>;

    fn now(&self) -> String;

    fn touch(&self);

    fn hidden(&self) -> bool;

    fn icon(&self) -> String;

    async fn url_test(
        &self,
        ctx: &CancellationToken,
        url: &str,
        expected_status: IntRanges<u16>,
    ) -> anyhow::Result<HashMap<String, u16>>;
}

/// A group whose active member can be set by name. `set` is async because `Fallback::set` awaits a
/// `URLTest` probe; `force_set` blocks the caller the same way.
#[async_trait]
pub trait SelectAble: Send + Sync {
    async fn set(&self, name: &str) -> anyhow::Result<()>;

    fn force_set(&self, name: &str);
}

/// Downcasts an adapter to a [`ProxyGroup`].
///
/// The closed set of concrete types this package ever hands back is exactly the four group
/// implementors, so the downcast tries each in turn instead of needing an open-ended registry.
pub fn as_proxy_group(adapter: &dyn ProxyAdapter) -> Option<&dyn ProxyGroup> {
    let any = adapter.as_any();
    if let Some(v) = any.downcast_ref::<Selector>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<Fallback>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<URLTest>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<LoadBalance>() {
        return Some(v);
    }
    None
}

/// Downcasts the adapter to `SelectAble`; `LoadBalance` does not implement it.
pub fn as_select_able(adapter: &dyn ProxyAdapter) -> Option<&dyn SelectAble> {
    let any = adapter.as_any();
    if let Some(v) = any.downcast_ref::<Selector>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<Fallback>() {
        return Some(v);
    }
    if let Some(v) = any.downcast_ref::<URLTest>() {
        return Some(v);
    }
    None
}

/// The early-conn boundary: `constant::adapters::Conn` deliberately carries no
/// `as_any`, so a generic `Box<dyn CConn>` cannot be tested for the
/// sing early-conn chain, the same limitation `adapter::outbound::shadowsocks` and
/// `tunnel::tunnel` already record for the same reason.
pub(crate) fn need_handshake(_conn: &dyn CConn) -> bool {
    false
}
