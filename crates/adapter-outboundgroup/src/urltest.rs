use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use murmur_common::singledo::singledo::{new_single, Single};
use murmur_common::utils::ranges::IntRanges;
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
pub struct URLTestOption {
    #[serde(rename = "tolerance", default)]
    pub tolerance: u16,
}

pub struct URLTest {
    self_weak: Weak<Self>,
    group_base: GroupBase,
    selected: Mutex<String>,
    test_url: String,
    expected_status: String,
    tolerance: u16,
    disable_udp: bool,
    fast_node: Mutex<Option<Arc<dyn Proxy>>>,
    fast_single: Single<Arc<dyn Proxy>>,
}

impl core::fmt::Debug for URLTest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("URLTest")
            .field("group_base", &self.group_base)
            .field("selected", &self.selected)
            .field("test_url", &self.test_url)
            .field("expected_status", &self.expected_status)
            .field("tolerance", &self.tolerance)
            .field("disable_udp", &self.disable_udp)
            .finish_non_exhaustive()
    }
}

impl URLTest {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "public constructor: the deserialized option is taken by value like the sibling group constructors"
    )]
    pub fn new(
        option: GroupCommonOption,
        url_test_option: URLTestOption,
        empty_fallback: Option<Arc<dyn Proxy>>,
        providers: Vec<Arc<dyn ProxyProvider>>,
    ) -> Result<Arc<Self>> {
        let Some(empty_fallback) = empty_fallback else {
            return Err(anyhow!("empty fallback proxy not exist"));
        };

        let group_base = GroupBase::new(GroupBaseOption {
            name: option.name,
            type_: AdapterType::URL_TEST,
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
            selected: Mutex::new(String::new()),
            test_url: option.url,
            expected_status: option.expected_status,
            tolerance: url_test_option.tolerance,
            disable_udp: option.disable_udp,
            fast_node: Mutex::new(None),
            fast_single: new_single(Duration::from_secs(10)),
        }))
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("URLTest adapter dropped while still in use"))
    }

    fn health_check_closure(&self) -> impl Fn() + Send + Sync + 'static {
        let weak = Weak::clone(&self.self_weak);
        move || {
            let weak = Weak::clone(&weak);
            tokio::spawn(async move {
                if let Some(this) = weak.upgrade() {
                    this.health_check().await;
                }
            });
        }
    }

    async fn health_check(&self) {
        self.fast_single.reset();
        self.group_base.health_check().await;
        self.fast_single.reset();
    }

    fn on_proxy_dial_failed(&self, proxy: &Arc<dyn Proxy>, dial_type: AdapterType, err: &anyhow::Error) {
        if !matches!(
            dial_type,
            AdapterType::DIRECT
                | AdapterType::COMPATIBLE
                | AdapterType::REJECT
                | AdapterType::PASS
                | AdapterType::REJECT_DROP
        ) && !murmur_common::errors::error_is::<murmur_constant::adapters::ErrNotSupport>(err)
        {
            proxy.mark_dead(&self.test_url);
            self.fast_single.reset();
        }
        self.group_base.on_dial_failed(dial_type, err, self.health_check_closure());
    }

    /// `singledo::Single::do_` is `async` (it awaits a `watch` channel when a call is already in
    /// flight), so the synchronous path is bridged with `tokio::task::block_in_place` +
    /// `Handle::current().block_on`, the same idiom `adapter::outbound`'s synchronous `close`
    /// methods already use in this crate, since `fast` is called from both sync (`now`,
    /// `support_udp`, `is_l3_protocol`) and async (`dial_context`) call sites.
    #[expect(
        clippy::expect_used,
        reason = "the single-flight closure cannot fail: group construction always installs an `empty_fallback`, so the proxy set is never empty"
    )]
    fn fast(&self, touch: bool) -> Arc<dyn Proxy> {
        let (result, shared) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.fast_single.do_(|| async {
                let proxies = self.group_base.get_proxies(touch);
                let selected = self.selected.lock().clone();
                if !selected.is_empty() {
                    for proxy in &proxies {
                        if !proxy.alive_for_test_url(&self.test_url) {
                            continue;
                        }
                        if proxy.name() == selected {
                            *self.fast_node.lock() = Some(Arc::clone(proxy));
                            return Ok(Arc::clone(proxy));
                        }
                    }
                }

                let Some((first, rest)) = proxies.split_first() else {
                    return Err(anyhow!("URLTest.fast: proxies are never empty"));
                };
                let mut fast = Arc::clone(first);
                let mut min_delay = fast.last_delay_for_test_url(&self.test_url);
                let mut fast_not_exist = true;

                for proxy in rest {
                    let current_fast_node = self.fast_node.lock().clone();
                    if let Some(fast_node) = current_fast_node {
                        if proxy.name() == fast_node.name() {
                            fast_not_exist = false;
                        }
                    }

                    if !proxy.alive_for_test_url(&self.test_url) {
                        continue;
                    }

                    let delay = proxy.last_delay_for_test_url(&self.test_url);
                    if !fast.alive_for_test_url(&self.test_url) || delay < min_delay {
                        fast = Arc::clone(proxy);
                        min_delay = delay;
                    }
                }

                let fast_node_snapshot = self.fast_node.lock().clone();
                let should_replace = match &fast_node_snapshot {
                    None => true,
                    Some(fast_node) => {
                        fast_not_exist
                            || !fast_node.alive_for_test_url(&self.test_url)
                            || fast_node.last_delay_for_test_url(&self.test_url)
                                > fast.last_delay_for_test_url(&self.test_url).wrapping_add(self.tolerance)
                    }
                };
                if should_replace {
                    *self.fast_node.lock() = Some(Arc::clone(&fast));
                }

                self.fast_node.lock().clone().ok_or_else(|| anyhow!("fast_node was just set above"))
            }))
        });

        if shared && touch {
            self.group_base.touch();
        }

        result.expect("URLTest.fast: proxies are never empty, so the closure always returns Ok")
    }
}

#[async_trait]
impl CProxyAdapter for URLTest {
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
        self.fast(false).support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        self.group_base.base.proxy_info()
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        let all: Vec<String> = self.group_base.get_proxies(false).iter().map(|p| p.name()).collect();
        Ok(serde_json::to_vec(&serde_json::json!({
            "type": self.type_().string(),
            "now": self.fast(false).name(),
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
        let proxy = self.fast(true);
        let dial_type = proxy.type_();
        let mut c = match proxy.dial_context(ctx, metadata).await {
            Ok(conn) => conn,
            Err(err) => {
                self.on_proxy_dial_failed(&proxy, dial_type, &err);
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
                        Some(err) => this.on_proxy_dial_failed(&proxy, dial_type, &err),
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
        let proxy = self.fast(true);
        let dial_type = proxy.type_();
        match proxy.listen_packet_context(ctx, metadata).await {
            Ok(pc) => {
                pc.append_to_chains(self.self_arc()?);
                Ok(pc)
            }
            Err(err) => {
                self.on_proxy_dial_failed(&proxy, dial_type, &err);
                Err(err)
            }
        }
    }

    fn support_uot(&self) -> bool {
        self.group_base.base.support_uot()
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.fast(false).is_l3_protocol(metadata)
    }

    fn unwrap(&self, _metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        Some(self.fast(touch))
    }

    fn close(&self) -> Result<()> {
        self.group_base.base.close()
    }
}

#[async_trait]
impl ProxyGroup for URLTest {
    fn providers(&self) -> Vec<Arc<dyn ProxyProvider>> {
        self.group_base.providers.clone()
    }

    fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.group_base.get_proxies(false)
    }

    fn now(&self) -> String {
        self.fast(false).name()
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

    /// Ignores the caller's `url` in favour of the group's own `test_url`.
    async fn url_test(
        &self,
        ctx: &CancellationToken,
        _url: &str,
        expected_status: IntRanges<u16>,
    ) -> Result<std::collections::HashMap<String, u16>> {
        self.group_base.url_test(ctx, &self.test_url, expected_status).await
    }
}

#[async_trait]
impl SelectAble for URLTest {
    async fn set(&self, name: &str) -> Result<()> {
        let mut found = false;
        for proxy in self.group_base.get_proxies(false) {
            if proxy.name() == name {
                found = true;
                break;
            }
        }
        if !found {
            return Err(anyhow!("proxy not exist"));
        }

        self.force_set(name);
        Ok(())
    }

    fn force_set(&self, name: &str) {
        name.clone_into(&mut self.selected.lock());
        self.fast_single.reset();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::anyhow;
    use async_trait::async_trait;
    use tokio_util::sync::CancellationToken;

    use super::{URLTest, URLTestOption};
    use crate::parser::GroupCommonOption;
    use crate::util::ProxyGroup;
    use murmur_adapter::adapter::Proxy;
    use murmur_adapter_outbound::reject::new_reject;
    use murmur_common::utils::ranges::IntRanges;
    use murmur_constant::adapters::{AdapterType, Conn, PacketConn, Proxy as CProxy, ProxyAdapter, ProxyInfo};
    use murmur_constant::metadata::Metadata;
    use murmur_constant::provider::interface::{Provider, ProviderType, ProxyProvider, VehicleType};

    struct FailingAdapter {
        name: String,
    }

    #[async_trait]
    impl ProxyAdapter for FailingAdapter {
        fn name(&self) -> String {
            self.name.clone()
        }
        fn type_(&self) -> AdapterType {
            AdapterType::VLESS
        }
        fn addr(&self) -> String {
            String::new()
        }
        fn support_udp(&self) -> bool {
            true
        }
        fn proxy_info(&self) -> ProxyInfo {
            ProxyInfo::default()
        }
        fn marshal_json(&self) -> anyhow::Result<Vec<u8>> {
            Ok(br#"{"type":"Vless"}"#.to_vec())
        }
        async fn dial_context(
            &self,
            _ctx: &CancellationToken,
            _metadata: &mut Metadata,
        ) -> anyhow::Result<Box<dyn Conn>> {
            Err(anyhow!("REALITY handshake cancelled"))
        }
        async fn listen_packet_context(
            &self,
            _ctx: &CancellationToken,
            _metadata: &mut Metadata,
        ) -> anyhow::Result<Arc<dyn PacketConn>> {
            Err(anyhow!("REALITY handshake cancelled"))
        }
        fn support_uot(&self) -> bool {
            false
        }
        fn is_l3_protocol(&self, _metadata: &Metadata) -> bool {
            false
        }
        fn unwrap(&self, _metadata: &Metadata, _touch: bool) -> Option<Arc<dyn CProxy>> {
            None
        }
        fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct StaticProvider(Vec<Arc<dyn CProxy>>);

    #[async_trait]
    impl Provider for StaticProvider {
        fn name(&self) -> String {
            "static".to_owned()
        }
        fn vehicle_type(&self) -> VehicleType {
            VehicleType::FILE
        }
        fn type_(&self) -> ProviderType {
            ProviderType::PROXY
        }
        async fn initial(&self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn update(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn marshal_json(&self) -> anyhow::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl ProxyProvider for StaticProvider {
        fn proxies(&self) -> Vec<Arc<dyn CProxy>> {
            self.0.clone()
        }
        fn count(&self) -> i32 {
            i32::try_from(self.0.len()).unwrap_or(i32::MAX)
        }
        fn touch(&self) {}
        async fn health_check(&self) {}
        fn version(&self) -> u32 {
            0
        }
        fn register_health_check_task(
            &self,
            _url: &str,
            _expected_status: IntRanges<u16>,
            _filter: &str,
            _interval: u32,
        ) {
        }
        fn health_check_url(&self) -> String {
            String::new()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dial_failure_immediately_demotes_the_active_node_to_the_next_alive_peer() {
        let dead_node = Proxy::new(Arc::new(FailingAdapter { name: "node-a".to_owned() }));
        let live_node = Proxy::new(Arc::new(FailingAdapter { name: "node-b".to_owned() }));
        let provider: Arc<dyn ProxyProvider> = Arc::new(StaticProvider(vec![dead_node, live_node]));

        let group = URLTest::new(
            GroupCommonOption {
                name: "auto".to_owned(),
                url: "https://example.com".to_owned(),
                max_failed_times: 1,
                ..GroupCommonOption::default()
            },
            URLTestOption { tolerance: 150 },
            Some(Proxy::new(new_reject())),
            vec![provider],
        )
        .expect("urltest construction");

        assert_eq!(group.now(), "node-a");
        let mut metadata = Metadata::default();
        let _ = group.dial_context(&CancellationToken::new(), &mut metadata).await;
        assert_eq!(group.now(), "node-b", "a failed dial must immediately switch off the dead node");
    }
}
