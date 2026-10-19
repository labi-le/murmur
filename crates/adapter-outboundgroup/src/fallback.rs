use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use murmur_common::utils::ranges::{new_unsigned_ranges, IntRanges};
use murmur_common_callback::callback::new_first_write_call_back_conn;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_constant::provider::interface::ProxyProvider;

use super::groupbase::{GroupBase, GroupBaseOption};
use super::parser::GroupCommonOption;
use super::util::{need_handshake, ProxyGroup, SelectAble};

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct FallbackOption {}

pub struct Fallback {
    self_weak: Weak<Self>,
    group_base: GroupBase,
    disable_udp: bool,
    test_url: String,
    selected: Mutex<String>,
    expected_status: String,
}

impl core::fmt::Debug for Fallback {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fallback")
            .field("group_base", &self.group_base)
            .field("disable_udp", &self.disable_udp)
            .field("test_url", &self.test_url)
            .field("selected", &self.selected)
            .field("expected_status", &self.expected_status)
            .finish_non_exhaustive()
    }
}

/// A child token cancelled after `dur`, matching the same idiom in `adapter::outbound::openvpn`.
fn with_timeout_token(parent: &CancellationToken, dur: Duration) -> CancellationToken {
    let child = parent.child_token();
    let sleeper = child.clone();
    tokio::spawn(async move {
        tokio::select! {
            () = tokio::time::sleep(dur) => sleeper.cancel(),
            () = sleeper.cancelled() => {}
        }
    });
    child
}

impl Fallback {
    pub fn new(
        option: GroupCommonOption,
        _fallback_option: FallbackOption,
        empty_fallback: Arc<dyn Proxy>,
        providers: Vec<Arc<dyn ProxyProvider>>,
    ) -> Result<Arc<Self>> {
        let group_base = GroupBase::new(GroupBaseOption {
            name: option.name,
            type_: AdapterType::FALLBACK,
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
            test_url: option.url,
            selected: Mutex::new(String::new()),
            expected_status: option.expected_status,
        }))
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("Fallback adapter dropped while still in use"))
    }

    fn health_check_closure(&self) -> impl Fn() + Send + Sync + 'static {
        let weak = Weak::clone(&self.self_weak);
        move || {
            let weak = Weak::clone(&weak);
            tokio::spawn(async move {
                if let Some(this) = weak.upgrade() {
                    this.group_base.health_check().await;
                }
            });
        }
    }

    fn find_alive_proxy(&self, touch: bool) -> Arc<dyn Proxy> {
        let proxies = self.group_base.get_proxies(touch);
        let mut selected = self.selected.lock();
        for proxy in &proxies {
            if selected.is_empty() {
                if proxy.alive_for_test_url(&self.test_url) {
                    return Arc::clone(proxy);
                }
            } else if proxy.name() == *selected {
                if proxy.alive_for_test_url(&self.test_url) {
                    return Arc::clone(proxy);
                }
                selected.clear();
            }
        }
        drop(selected);

        proxies.first().map_or_else(|| self.group_base.empty_fallback(), Arc::clone)
    }
}

#[async_trait]
impl CProxyAdapter for Fallback {
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

        self.find_alive_proxy(false).support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        self.group_base.base.proxy_info()
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        let all: Vec<String> = self.group_base.get_proxies(false).iter().map(|p| p.name()).collect();
        Ok(serde_json::to_vec(&serde_json::json!({
            "type": self.type_().string(),
            "now": self.now(),
            "all": all,
            "testUrl": self.test_url,
            "expectedStatus": self.expected_status,
            "fixed": *self.selected.lock(),
            "hidden": self.group_base.hidden(),
            "icon": self.group_base.icon(),
            "emptyFallback": self.group_base.empty_fallback().name(),
        }))?)
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let proxy = self.find_alive_proxy(true);
        let dial_type = proxy.type_();
        let mut c = match proxy.dial_context(ctx, metadata).await {
            Ok(conn) => conn,
            Err(err) => {
                self.group_base.on_dial_failed(dial_type, &err, self.health_check_closure());
                return Err(err);
            }
        };
        c.append_to_chains(self.self_arc()?);

        if need_handshake(&*c) {
            let weak = Weak::clone(&self.self_weak);
            c = new_first_write_call_back_conn(
                c,
                Box::new(move |err: Option<anyhow::Error>| {
                    let Some(this) = weak.upgrade() else { return };
                    match err {
                        None => this.group_base.on_dial_success(),
                        Some(err) => this.group_base.on_dial_failed(dial_type, &err, this.health_check_closure()),
                    }
                }),
            );
        }

        Ok(c)
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        let proxy = self.find_alive_proxy(true);
        let pc = proxy.listen_packet_context(ctx, metadata).await?;
        pc.append_to_chains(self.self_arc()?);
        Ok(pc)
    }

    fn support_uot(&self) -> bool {
        self.group_base.base.support_uot()
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.find_alive_proxy(false).is_l3_protocol(metadata)
    }

    fn unwrap(&self, _metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        Some(self.find_alive_proxy(touch))
    }

    fn close(&self) -> Result<()> {
        self.group_base.base.close()
    }
}

#[async_trait]
impl ProxyGroup for Fallback {
    fn providers(&self) -> Vec<Arc<dyn ProxyProvider>> {
        self.group_base.providers.clone()
    }

    fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.group_base.get_proxies(false)
    }

    fn now(&self) -> String {
        self.find_alive_proxy(false).name()
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
        expected_status: IntRanges<u16>,
    ) -> Result<std::collections::HashMap<String, u16>> {
        self.group_base.url_test(ctx, url, expected_status).await
    }
}

#[async_trait]
impl SelectAble for Fallback {
    async fn set(&self, name: &str) -> Result<()> {
        let mut found: Option<Arc<dyn Proxy>> = None;
        for proxy in self.group_base.get_proxies(false) {
            if proxy.name() == name {
                found = Some(proxy);
                break;
            }
        }
        let p = found.ok_or_else(|| anyhow!("proxy not exist"))?;

        name.clone_into(&mut self.selected.lock());
        if !p.alive_for_test_url(&self.test_url) {
            let ctx = with_timeout_token(&CancellationToken::new(), Duration::from_millis(5000));
            let expected_status = new_unsigned_ranges::<u16>(&self.expected_status)
                .map_err(|e| anyhow!("{name}: expected-status: {e}"))?;
            let _ = p.url_test(&ctx, &self.test_url, expected_status).await;
        }

        Ok(())
    }

    fn force_set(&self, name: &str) {
        name.clone_into(&mut self.selected.lock());
    }
}
