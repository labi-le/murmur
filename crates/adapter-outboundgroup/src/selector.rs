use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
    DEFAULT_TEST_URL,
};
use murmur_constant::metadata::Metadata;
use murmur_constant::provider::interface::ProxyProvider;

use super::groupbase::{GroupBase, GroupBaseOption};
use super::parser::GroupCommonOption;
use super::util::{ProxyGroup, SelectAble};

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct SelectorOption {
    #[serde(rename = "default-selected", default)]
    pub default_selected: String,
}

/// The last resolved selection, keyed by the member snapshot it came from and the selected name.
///
/// Keeping `snapshot` here holds that allocation alive, so a later snapshot cannot be allocated
/// at the same address and mistaken for this one; `Arc::ptr_eq` is therefore a valid generation
/// key without a separate counter.
struct ResolvedSelection {
    snapshot: Arc<[Arc<dyn Proxy>]>,
    name: String,
    proxy: Arc<dyn Proxy>,
}

pub struct Selector {
    self_weak: Weak<Self>,
    group_base: GroupBase,
    disable_udp: bool,
    selected: Mutex<String>,
    resolved: Mutex<Option<ResolvedSelection>>,
    test_url: String,
}

impl core::fmt::Debug for Selector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Selector")
            .field("group_base", &self.group_base)
            .field("disable_udp", &self.disable_udp)
            .field("selected", &self.selected)
            .field("test_url", &self.test_url)
            .finish_non_exhaustive()
    }
}

impl Selector {
    pub fn new(
        option: GroupCommonOption,
        selector_option: SelectorOption,
        empty_fallback: Arc<dyn Proxy>,
        providers: Vec<Arc<dyn ProxyProvider>>,
    ) -> Result<Arc<Self>> {
        let group_base = GroupBase::new(GroupBaseOption {
            name: option.name,
            type_: AdapterType::SELECTOR,
            hidden: option.hidden,
            icon: option.icon,
            filter: option.filter,
            exclude_filter: option.exclude_filter,
            exclude_type: option.exclude_type,
            test_timeout: option.test_timeout,
            max_failed_times: option.max_failed_times,
            empty_fallback,
            providers,
        });

        Ok(Arc::new_cyclic(|self_weak| Self {
            self_weak: Weak::clone(self_weak),
            group_base,
            disable_udp: option.disable_udp,
            selected: Mutex::new(selector_option.default_selected),
            resolved: Mutex::new(None),
            test_url: option.url,
        }))
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("Selector adapter dropped while still in use"))
    }

    fn selected_proxy(&self, touch: bool) -> Arc<dyn Proxy> {
        let proxies = self.group_base.get_proxies_shared(touch);
        let selected = self.selected.lock();
        let mut resolved = self.resolved.lock();

        if let Some(entry) = resolved.as_ref() {
            if entry.name == *selected && Arc::ptr_eq(&entry.snapshot, &proxies) {
                return Arc::clone(&entry.proxy);
            }
        }

        let proxy = proxies
            .iter()
            .find(|proxy| proxy.name() == *selected)
            .map(Arc::clone)
            .or_else(|| proxies.first().map(Arc::clone))
            .unwrap_or_else(|| self.group_base.empty_fallback());

        *resolved = Some(ResolvedSelection {
            snapshot: Arc::clone(&proxies),
            name: selected.clone(),
            proxy: Arc::clone(&proxy),
        });

        proxy
    }
}

#[async_trait]
impl CProxyAdapter for Selector {
    fn name(&self) -> String {
        self.group_base.base.name()
    }

    fn type_(&self) -> AdapterType {
        self.group_base.base.type_()
    }

    fn addr(&self) -> String {
        self.group_base.base.addr()
    }

    fn support_udp(&self) -> bool {
        if self.disable_udp {
            return false;
        }

        self.selected_proxy(false).support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        self.group_base.base.proxy_info()
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        let all: Vec<String> = self.group_base.get_proxies(false).iter().map(|p| p.name()).collect();
        let url = if self.test_url == DEFAULT_TEST_URL { String::new() } else { self.test_url.clone() };

        Ok(serde_json::to_vec(&serde_json::json!({
            "type": self.type_().string(),
            "now": self.selected_proxy(false).name(),
            "all": all,
            "testUrl": url,
            "hidden": self.group_base.hidden(),
            "icon": self.group_base.icon(),
            "emptyFallback": self.group_base.empty_fallback().name(),
        }))?)
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let c = self.selected_proxy(true).dial_context(ctx, metadata).await?;
        c.append_to_chains(self.self_arc()?);
        Ok(c)
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        let pc = self.selected_proxy(true).listen_packet_context(ctx, metadata).await?;
        pc.append_to_chains(self.self_arc()?);
        Ok(pc)
    }

    fn support_uot(&self) -> bool {
        self.group_base.base.support_uot()
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.selected_proxy(false).is_l3_protocol(metadata)
    }

    fn unwrap(&self, _metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        Some(self.selected_proxy(touch))
    }

    fn close(&self) -> Result<()> {
        self.group_base.base.close()
    }
}

#[async_trait]
impl ProxyGroup for Selector {
    fn providers(&self) -> Vec<Arc<dyn ProxyProvider>> {
        self.group_base.providers.clone()
    }

    fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.group_base.get_proxies(false)
    }

    fn now(&self) -> String {
        self.selected_proxy(false).name()
    }

    fn touch(&self) {
        self.group_base.touch();
    }

    fn hidden(&self) -> bool {
        self.group_base.hidden()
    }

    fn icon(&self) -> String {
        self.group_base.icon()
    }

    async fn url_test(
        &self,
        ctx: &CancellationToken,
        url: &str,
        expected_status: murmur_common::utils::ranges::IntRanges<u16>,
    ) -> Result<std::collections::HashMap<String, u16>> {
        self.group_base.url_test(ctx, url, expected_status).await
    }
}

#[async_trait]
impl SelectAble for Selector {
    async fn set(&self, name: &str) -> Result<()> {
        let proxies = self.group_base.get_proxies_shared(false);
        for proxy in proxies.iter() {
            if proxy.name() == name {
                name.clone_into(&mut self.selected.lock());
                return Ok(());
            }
        }

        Err(anyhow!("proxy not exist"))
    }

    fn force_set(&self, name: &str) {
        name.clone_into(&mut self.selected.lock());
    }
}
