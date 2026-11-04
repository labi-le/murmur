//! The finalizer callback becomes `Drop`, and the captured `pd` pointer becomes a `Weak`
//! self-reference built with `Arc::new_cyclic` instead of a strong `Arc`.
//!
//! A strong `Arc` would instead leak a reference cycle that a garbage collector would collect but
//! Rust's `Arc` cannot. `Arc::new_cyclic` is this crate's established convention, see
//! `adapter/outbound/direct.rs`.

use std::collections::HashSet;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use fancy_regex::Regex;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use yaml_serde::{Mapping, Value};

use murmur_adapter::parser::{parse_proxy, with_provider_name, with_tunnel_for_api};
use murmur_common::time::zero_time;
use murmur_common::utils::ranges::IntRanges;
use murmur_common::yaml::yaml::{marshal as yaml_marshal, unmarshal as yaml_unmarshal};
use murmur_common_convert::converter::converts_v2ray;
use murmur_component::age::age::{decrypt_bytes, verity_secret_keys};
use murmur_component_profile::cachefile::cache::cache;
use murmur_component_resource::fetcher::{new_fetcher, Fetcher, Parser as ResourceParser};
use murmur_constant::adapters::Proxy;
use murmur_constant::provider::interface::{Provider, ProviderType, ProxyProvider, Vehicle, VehicleType};
use murmur_constant::tunnel::Tunnel;
use murmur_tunnel::statistic::manager::DEFAULT_MANAGER;

use super::healthcheck::HealthCheck;
use super::override_::OverrideSchema;
use super::subscription_info::SubscriptionInfo;

pub const RESERVED_NAME: &str = "default";

fn equal_fold(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right) || left.to_lowercase() == right.to_lowercase()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProxySchema {
    #[serde(rename = "proxies", default)]
    pub proxies: Option<Vec<Mapping>>,
}

struct ProviderForApi<'a> {
    name: String,
    type_: String,
    vehicle_type: String,
    proxies: &'a [Arc<dyn Proxy>],
    test_url: String,
    expected_status: String,
    updated_at: DateTime<Utc>,
    subscription_info: Option<SubscriptionInfo>,
}

impl ProviderForApi<'_> {
    /// The `Proxies` field holds each proxy's own `marshal_json` bytes, so they are embedded
    /// verbatim; a `serde_json::Value` round trip would sort the `history`/`extra` objects nested
    /// inside them out of their declaration order.
    fn marshal_json(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        write_field(&mut body, "name", &self.name)?;
        write_field(&mut body, "type", &self.type_)?;
        write_field(&mut body, "vehicleType", &self.vehicle_type)?;
        write_proxies(&mut body, self.proxies)?;
        write_field(&mut body, "testUrl", &self.test_url)?;
        write_field(&mut body, "expectedStatus", &self.expected_status)?;
        write_field(&mut body, "updatedAt", &murmur_common::time_rfc3339::to_wire_string(&self.updated_at))?;
        if let Some(subscription_info) = &self.subscription_info {
            write_field(&mut body, "subscriptionInfo", subscription_info)?;
        }

        let mut out = Vec::with_capacity(body.len() + 2);
        out.push(b'{');
        out.extend_from_slice(&body);
        out.push(b'}');
        Ok(out)
    }
}

fn write_field<T: Serialize>(out: &mut Vec<u8>, name: &str, value: &T) -> Result<()> {
    if !out.is_empty() {
        out.push(b',');
    }
    serde_json::to_writer(&mut *out, name)?;
    out.push(b':');
    Ok(serde_json::to_writer(&mut *out, value)?)
}

fn write_proxies(out: &mut Vec<u8>, proxies: &[Arc<dyn Proxy>]) -> Result<()> {
    if !out.is_empty() {
        out.push(b',');
    }
    out.extend_from_slice(b"\"proxies\":[");
    for (index, proxy) in proxies.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&proxy.marshal_json()?);
    }
    out.push(b']');
    Ok(())
}

struct BaseProviderState {
    proxies: Vec<Arc<dyn Proxy>>,
    version: u32,
}

struct BaseProvider {
    name: String,
    state: RwLock<BaseProviderState>,
    health_check: Arc<HealthCheck>,
}

impl BaseProvider {
    fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>, health_check: Arc<HealthCheck>) -> Self {
        Self { name: name.to_owned(), state: RwLock::new(BaseProviderState { proxies, version: 0 }), health_check }
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn version(&self) -> u32 {
        self.state.read().version
    }

    fn initial(&self) {
        if self.health_check.auto() {
            let hc = Arc::clone(&self.health_check);
            tokio::spawn(hc.process());
        }
    }

    async fn health_check(&self) {
        self.health_check.check().await;
    }

    const fn type_() -> ProviderType {
        ProviderType::PROXY
    }

    fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.state.read().proxies.clone()
    }

    fn count(&self) -> i32 {
        i32::try_from(self.state.read().proxies.len()).unwrap_or(i32::MAX)
    }

    fn touch(&self) {
        self.health_check.touch();
    }

    fn health_check_url(&self) -> String {
        self.health_check.url.clone()
    }

    fn register_health_check_task(&self, url: &str, expected_status: IntRanges<u16>, filter: &str, interval: u32) {
        self.health_check.register_health_check_task(url, expected_status, filter, interval);
    }

    fn set_proxies(&self, proxies: Vec<Arc<dyn Proxy>>) {
        {
            let mut state = self.state.write();
            proxies.clone_into(&mut state.proxies);
            state.version += 1;
        }
        self.health_check.set_proxies(proxies);
        if self.health_check.auto() {
            let hc = Arc::clone(&self.health_check);
            tokio::spawn(async move { hc.check().await });
        }
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "the three provider wrappers keep one `close` shape so they can delegate unchanged"
    )]
    fn close(&self) -> Result<()> {
        self.health_check.close();
        Ok(())
    }
}

struct ProxySetProviderInner {
    base: BaseProvider,
    fetcher: Arc<Fetcher<Vec<Arc<dyn Proxy>>>>,
    subscription_info: Mutex<Option<SubscriptionInfo>>,
}

impl ProxySetProviderInner {
    fn close(&self) -> Result<()> {
        let _ = self.base.close();
        self.fetcher.close()
    }
}

/// `ProxySetProvider` ("for auto gc").
pub struct ProxySetProvider(Arc<ProxySetProviderInner>);

impl std::fmt::Debug for ProxySetProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxySetProvider").finish_non_exhaustive()
    }
}

impl ProxySetProvider {
    pub fn marshal_json(&self) -> Result<Vec<u8>> {
        let proxies = self.proxies();
        let api = ProviderForApi {
            name: self.name(),
            type_: self.type_().to_string(),
            vehicle_type: self.vehicle_type().to_string(),
            proxies: &proxies,
            test_url: self.0.base.health_check.url.clone(),
            expected_status: self.0.base.health_check.expected_status.to_string(),
            updated_at: self.0.fetcher.updated_at(),
            subscription_info: *self.0.subscription_info.lock(),
        };
        api.marshal_json()
    }

    fn close_all_connections(&self) {
        let name = self.name();
        DEFAULT_MANAGER.range(|c| {
            for chain in &c.provider_chains().0 {
                if *chain == name {
                    let _ = c.close();
                    break;
                }
            }
            true
        });
    }

    pub fn close(&self) -> Result<()> {
        self.0.close()
    }

    pub(crate) fn new(
        name: &str,
        interval: Duration,
        payload: Vec<Mapping>,
        parser: ResourceParser<Vec<Arc<dyn Proxy>>>,
        vehicle: Arc<dyn Vehicle>,
        hc: Arc<HealthCheck>,
    ) -> Result<Self> {
        let mut initial_proxies: Vec<Arc<dyn Proxy>> = Vec::new();
        if !payload.is_empty() {
            // Using as fallback proxies.
            let schema = ProxySchema { proxies: Some(payload) };
            let buf = yaml_marshal(&schema)?;
            let proxies = parser(&buf)?;
            proxies.clone_into(&mut initial_proxies);
            // Directly call setProxies on hc to avoid starting a health check process immediately, it
            // should be done by Initial().
            hc.set_proxies(proxies);
        }

        let name = name.to_owned();
        let inner = Arc::new_cyclic(move |weak: &Weak<ProxySetProviderInner>| {
            if let Some(http_vehicle) = vehicle.as_subscription_read_callback() {
                let weak = Weak::clone(weak);
                let name = name.clone();
                http_vehicle.set_in_read(Arc::new(move |resp: &hyper::Response<hyper::body::Incoming>| {
                    let Some(subscription_info) =
                        resp.headers().get("subscription-userinfo").and_then(|v| v.to_str().ok())
                    else {
                        return;
                    };
                    if subscription_info.is_empty() {
                        return;
                    }
                    cache().set_subscription_info(&name, subscription_info);
                    if let Some(inner) = weak.upgrade() {
                        *inner.subscription_info.lock() = Some(SubscriptionInfo::new(subscription_info));
                    }
                }));
            }

            let weak_for_update = Weak::clone(weak);
            let on_update: Arc<dyn Fn(Vec<Arc<dyn Proxy>>) + Send + Sync> = Arc::new(move |proxies| {
                if let Some(inner) = weak_for_update.upgrade() {
                    inner.base.set_proxies(proxies);
                }
            });

            let fetcher = new_fetcher(&name, interval, vehicle, None, parser, Some(on_update));

            ProxySetProviderInner {
                base: BaseProvider::new(&name, initial_proxies, hc),
                fetcher,
                subscription_info: Mutex::new(None),
            }
        });

        Ok(Self(inner))
    }
}

impl Drop for ProxySetProvider {
    fn drop(&mut self) {
        let _ = self.0.close();
    }
}

#[async_trait]
impl Provider for ProxySetProvider {
    /// Shadows the promoted name of the base provider.
    fn name(&self) -> String {
        self.0.fetcher.name()
    }

    fn vehicle_type(&self) -> VehicleType {
        self.0.fetcher.vehicle_type()
    }

    fn type_(&self) -> ProviderType {
        BaseProvider::type_()
    }

    async fn initial(&self) -> Result<()> {
        self.0.base.initial();
        self.0.fetcher.initial().await?;
        let subscription_info = cache().get_subscription_info(&self.name());
        if !subscription_info.is_empty() {
            *self.0.subscription_info.lock() = Some(SubscriptionInfo::new(&subscription_info));
        }
        self.close_all_connections();
        Ok(())
    }

    async fn update(&self) -> Result<()> {
        self.0.fetcher.update().await?;
        Ok(())
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.marshal_json()
    }
}

#[async_trait]
impl ProxyProvider for ProxySetProvider {
    fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.0.base.proxies()
    }

    fn count(&self) -> i32 {
        self.0.base.count()
    }

    fn touch(&self) {
        self.0.base.touch();
    }

    async fn health_check(&self) {
        self.0.base.health_check().await;
    }

    fn version(&self) -> u32 {
        self.0.base.version()
    }

    fn register_health_check_task(&self, url: &str, expected_status: IntRanges<u16>, filter: &str, interval: u32) {
        self.0.base.register_health_check_task(url, expected_status, filter, interval);
    }

    fn health_check_url(&self) -> String {
        self.0.base.health_check_url()
    }
}

struct InlineProviderInner {
    base: BaseProvider,
    update_at: Mutex<DateTime<Utc>>,
}

/// `InlineProvider` ("for auto gc").
pub struct InlineProvider(Arc<InlineProviderInner>);

impl std::fmt::Debug for InlineProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineProvider").finish_non_exhaustive()
    }
}

impl InlineProvider {
    pub fn marshal_json(&self) -> Result<Vec<u8>> {
        let proxies = self.proxies();
        let api = ProviderForApi {
            name: self.name(),
            type_: self.type_().to_string(),
            vehicle_type: self.vehicle_type().to_string(),
            proxies: &proxies,
            test_url: self.0.base.health_check.url.clone(),
            expected_status: self.0.base.health_check.expected_status.to_string(),
            updated_at: *self.0.update_at.lock(),
            subscription_info: None,
        };
        api.marshal_json()
    }

    pub fn close(&self) -> Result<()> {
        self.0.base.close()
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "the private constructor keeps the parser-by-value signature of ProxySetProvider::new"
    )]
    pub(crate) fn new(
        name: &str,
        payload: Vec<Mapping>,
        parser: ResourceParser<Vec<Arc<dyn Proxy>>>,
        hc: Arc<HealthCheck>,
    ) -> Result<Self> {
        let schema = ProxySchema { proxies: Some(payload) };
        let buf = yaml_marshal(&schema)?;
        let proxies = parser(&buf)?;
        // Directly call setProxies on hc to avoid starting a health check process immediately, it
        // should be done by Initial().
        hc.set_proxies(proxies.clone());

        let inner =
            InlineProviderInner { base: BaseProvider::new(name, proxies, hc), update_at: Mutex::new(Utc::now()) };
        let wrapper = Self(Arc::new(inner));
        Ok(wrapper)
    }
}

impl Drop for InlineProvider {
    fn drop(&mut self) {
        let _ = self.0.base.close();
    }
}

#[async_trait]
impl Provider for InlineProvider {
    fn name(&self) -> String {
        self.0.base.name()
    }

    fn vehicle_type(&self) -> VehicleType {
        VehicleType::INLINE
    }

    fn type_(&self) -> ProviderType {
        BaseProvider::type_()
    }

    async fn initial(&self) -> Result<()> {
        self.0.base.initial();
        Ok(())
    }

    /// makes API update happy.
    async fn update(&self) -> Result<()> {
        *self.0.update_at.lock() = Utc::now();
        Ok(())
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.marshal_json()
    }
}

#[async_trait]
impl ProxyProvider for InlineProvider {
    fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.0.base.proxies()
    }

    fn count(&self) -> i32 {
        self.0.base.count()
    }

    fn touch(&self) {
        self.0.base.touch();
    }

    async fn health_check(&self) {
        self.0.base.health_check().await;
    }

    fn version(&self) -> u32 {
        self.0.base.version()
    }

    fn register_health_check_task(&self, url: &str, expected_status: IntRanges<u16>, filter: &str, interval: u32) {
        self.0.base.register_health_check_task(url, expected_status, filter, interval);
    }

    fn health_check_url(&self) -> String {
        self.0.base.health_check_url()
    }
}

/// `CompatibleProvider` ("for auto gc").
pub struct CompatibleProvider(Arc<BaseProvider>);

impl std::fmt::Debug for CompatibleProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompatibleProvider").finish_non_exhaustive()
    }
}

impl CompatibleProvider {
    pub fn marshal_json(&self) -> Result<Vec<u8>> {
        let proxies = self.proxies();
        let api = ProviderForApi {
            name: self.name(),
            type_: self.type_().to_string(),
            vehicle_type: self.vehicle_type().to_string(),
            proxies: &proxies,
            test_url: self.0.health_check.url.clone(),
            expected_status: self.0.health_check.expected_status.to_string(),
            updated_at: zero_time(),
            subscription_info: None,
        };
        api.marshal_json()
    }

    pub fn close(&self) -> Result<()> {
        self.0.close()
    }
}

impl Drop for CompatibleProvider {
    fn drop(&mut self) {
        let _ = self.0.close();
    }
}

#[async_trait]
impl Provider for CompatibleProvider {
    fn name(&self) -> String {
        self.0.name()
    }

    fn vehicle_type(&self) -> VehicleType {
        VehicleType::COMPATIBLE
    }

    fn type_(&self) -> ProviderType {
        BaseProvider::type_()
    }

    async fn initial(&self) -> Result<()> {
        self.0.initial();
        Ok(())
    }

    async fn update(&self) -> Result<()> {
        Ok(())
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.marshal_json()
    }
}

#[async_trait]
impl ProxyProvider for CompatibleProvider {
    fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.0.proxies()
    }

    fn count(&self) -> i32 {
        self.0.count()
    }

    fn touch(&self) {
        self.0.touch();
    }

    async fn health_check(&self) {
        self.0.health_check().await;
    }

    fn version(&self) -> u32 {
        self.0.version()
    }

    fn register_health_check_task(&self, url: &str, expected_status: IntRanges<u16>, filter: &str, interval: u32) {
        self.0.register_health_check_task(url, expected_status, filter, interval);
    }

    fn health_check_url(&self) -> String {
        self.0.health_check_url()
    }
}

pub fn new_compatible_provider(
    name: &str,
    proxies: Vec<Arc<dyn Proxy>>,
    hc: Arc<HealthCheck>,
) -> Result<CompatibleProvider> {
    if proxies.is_empty() {
        return Err(anyhow!("provider need one proxy at least"));
    }

    let wrapper = CompatibleProvider(Arc::new(BaseProvider::new(name, proxies, hc)));
    Ok(wrapper)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the constructor takes the eight configuration inputs the parser needs; a params struct would only relocate them"
)]
pub(crate) fn new_proxies_parser(
    pd_name: &str,
    tunnel: Arc<dyn Tunnel>,
    filter: &str,
    exclude_filter: &str,
    exclude_type: &str,
    dialer_proxy: &str,
    override_: OverrideSchema,
    age_secret_key: &str,
) -> Result<ResourceParser<Vec<Arc<dyn Proxy>>>> {
    let exclude_type_array: Vec<String> =
        if exclude_type.is_empty() { Vec::new() } else { exclude_type.split('|').map(str::to_owned).collect() };

    let mut exclude_filter_regs: Vec<Regex> = Vec::new();
    if !exclude_filter.is_empty() {
        for part in exclude_filter.split('`') {
            let reg = Regex::new(part).map_err(|err| anyhow!("invalid excludeFilter regex: {err}"))?;
            exclude_filter_regs.push(reg);
        }
    }

    let mut filter_regs: Vec<Regex> = Vec::new();
    for part in filter.split('`') {
        let reg = Regex::new(part).map_err(|err| anyhow!("invalid filter regex: {err}"))?;
        filter_regs.push(reg);
    }

    if !age_secret_key.is_empty() {
        verity_secret_keys(std::slice::from_ref(&age_secret_key.to_owned())).context("invalid age-secret-key")?;
    }

    let pd_name = pd_name.to_owned();
    let filter = filter.to_owned();
    let dialer_proxy = dialer_proxy.to_owned();
    let age_secret_key = age_secret_key.to_owned();

    let parser: ResourceParser<Vec<Arc<dyn Proxy>>> = Arc::new(move |buf: &[u8]| -> Result<Vec<Arc<dyn Proxy>>> {
        let mut schema = ProxySchema::default();

        // Decrypt config.
        let buf = decrypt_bytes(buf, std::slice::from_ref(&age_secret_key)).context("decrypt config error")?;

        let unmarshal_err = yaml_unmarshal(&buf, &mut schema).err();
        if let Some(unmarshal_err) = &unmarshal_err {
            match converts_v2ray(&buf) {
                Ok(proxies) => {
                    let converted: Vec<Mapping> = proxies
                        .into_iter()
                        .map(|proxy| yaml_serde::from_value(yaml_serde::to_value(proxy)?))
                        .collect::<std::result::Result<Vec<Mapping>, yaml_serde::Error>>()?;
                    schema.proxies = Some(converted);
                }
                Err(err1) => return Err(anyhow!("{unmarshal_err}, {err1}")),
            }
        }

        let Some(mut proxy_mappings) = schema.proxies else {
            return Err(anyhow!("file must have a `proxies` field"));
        };

        let mut proxies: Vec<Arc<dyn Proxy>> = Vec::new();
        let mut proxies_set: HashSet<String> = HashSet::new();

        for filter_reg in &filter_regs {
            'loop1: for (idx, mapping) in proxy_mappings.iter_mut().enumerate() {
                if !exclude_type_array.is_empty() {
                    let Some(Value::String(p_type)) = mapping.get("type") else {
                        continue;
                    };
                    for excluded in &exclude_type_array {
                        if equal_fold(p_type, excluded) {
                            continue 'loop1;
                        }
                    }
                }

                let Some(Value::String(name)) = mapping.get("name").cloned() else {
                    continue;
                };

                if !exclude_filter_regs.is_empty() {
                    for exclude_filter_reg in &exclude_filter_regs {
                        if exclude_filter_reg.is_match(&name).unwrap_or(false) {
                            continue 'loop1;
                        }
                    }
                }

                if !filter.is_empty() && !filter_reg.is_match(&name).unwrap_or(false) {
                    continue;
                }

                if proxies_set.contains(&name) {
                    continue;
                }

                if !dialer_proxy.is_empty() {
                    mapping.insert(Value::String("dialer-proxy".to_owned()), Value::String(dialer_proxy.clone()));
                }

                override_.apply(mapping).with_context(|| format!("proxy {idx} override error"))?;

                let proxy = parse_proxy(
                    mapping,
                    &[with_tunnel_for_api(Arc::clone(&tunnel)), with_provider_name(pd_name.clone())],
                )
                .with_context(|| format!("proxy {idx} error"))?;

                proxies_set.insert(name);
                proxies.push(proxy);
            }
        }

        if proxies.is_empty() {
            if !filter.is_empty() {
                return Err(anyhow!("doesn't match any proxy, please check your filter"));
            }
            return Err(anyhow!("file doesn't have any proxy"));
        }

        Ok(proxies)
    });

    Ok(parser)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "extra-protocols"))]
    #[test]
    fn a_removed_protocol_rejects_the_whole_provider_payload() {
        let parser = new_proxies_parser(
            "mixed",
            Arc::new(murmur_tunnel::tunnel::Tunnel),
            "",
            "",
            "",
            "",
            OverrideSchema::default(),
            "",
        )
        .expect("parser");
        let error = parser(b"proxies:\n  - {name: retained, type: direct}\n  - {name: removed, type: ss}\n")
            .err()
            .expect("a provider cannot silently drop an unavailable protocol");
        let message = format!("{error:#}");
        assert!(message.contains("proxy 1"), "{message}");
        assert!(message.contains("extra-protocols"), "{message}");
    }

    #[cfg(not(feature = "extra-protocols"))]
    #[tokio::test]
    async fn a_removed_protocol_update_keeps_active_provider_proxies() {
        let path = std::env::temp_dir().join(format!("murmur-vvt-provider-{}", std::process::id()));
        let parser = new_proxies_parser(
            "vvt-update",
            Arc::new(murmur_tunnel::tunnel::Tunnel),
            "",
            "",
            "",
            "",
            OverrideSchema::default(),
            "",
        )
        .expect("parser");
        let hc = crate::healthcheck::new_health_check(Vec::new(), "", 0, 0, false, IntRanges::default());
        let provider = ProxySetProvider::new(
            "vvt-update",
            Duration::ZERO,
            Vec::new(),
            parser,
            Arc::new(murmur_component_resource::vehicle::FileVehicle::new(path.to_str().expect("temporary path"))),
            hc,
        )
        .expect("provider");
        std::fs::write(&path, b"proxies:\n  - {name: retained, type: direct}\n").expect("write good provider");
        provider.update().await.expect("load retained provider");
        let original = provider.proxies();
        let version = provider.version();
        assert_eq!(original.len(), 1);
        std::fs::write(&path, b"proxies:\n  - {name: removed, type: ss}\n").expect("write unsupported provider");
        let error = provider.update().await.expect_err("unavailable protocol update fails");
        assert!(format!("{error:#}").contains("extra-protocols"));
        let current = provider.proxies();
        assert_eq!(current.len(), 1);
        assert!(Arc::ptr_eq(&current[0], &original[0]));
        assert_eq!(provider.version(), version);
        provider.close().expect("close provider");
        std::fs::remove_file(path).expect("remove provider fixture");
    }
    use murmur_adapter::adapter;
    use murmur_constant::adapters::{AdapterType, Conn, PacketConn, ProxyAdapter, ProxyInfo};
    use murmur_constant::metadata::Metadata;
    use tokio_util::sync::CancellationToken;

    struct StubAdapter;

    #[async_trait]
    impl ProxyAdapter for StubAdapter {
        fn name(&self) -> String {
            "STUB".to_owned()
        }

        fn type_(&self) -> AdapterType {
            AdapterType::DIRECT
        }

        fn addr(&self) -> String {
            String::new()
        }

        fn support_udp(&self) -> bool {
            false
        }

        fn proxy_info(&self) -> ProxyInfo {
            ProxyInfo::default()
        }

        fn marshal_json(&self) -> Result<Vec<u8>> {
            Ok(br#"{"type":"Stub"}"#.to_vec())
        }

        async fn dial_context(&self, _ctx: &CancellationToken, _metadata: &mut Metadata) -> Result<Box<dyn Conn>> {
            Err(anyhow!("the stub adapter never dials"))
        }

        async fn listen_packet_context(
            &self,
            _ctx: &CancellationToken,
            _metadata: &mut Metadata,
        ) -> Result<Arc<dyn PacketConn>> {
            Err(anyhow!("the stub adapter never listens"))
        }

        fn support_uot(&self) -> bool {
            false
        }

        fn is_l3_protocol(&self, _metadata: &Metadata) -> bool {
            false
        }

        fn unwrap(&self, _metadata: &Metadata, _touch: bool) -> Option<Arc<dyn Proxy>> {
            None
        }

        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    /// The failed dial still records a `DelayHistory`, which is what makes the nested order
    /// observable: the wrapper embeds the proxy's own bytes, so `{"time":…,"delay":…}` must survive.
    #[tokio::test]
    async fn provider_proxies_keep_the_proxy_byte_order() {
        let proxy = adapter::Proxy::new(Arc::new(StubAdapter));
        let _ = proxy.url_test(&CancellationToken::new(), "http://192.0.2.1/", IntRanges::default()).await;

        let proxies: Vec<Arc<dyn Proxy>> = vec![proxy];
        let api = ProviderForApi {
            name: "default".to_owned(),
            type_: "Proxy".to_owned(),
            vehicle_type: "Compatible".to_owned(),
            proxies: &proxies,
            test_url: "http://192.0.2.1/".to_owned(),
            expected_status: String::new(),
            updated_at: zero_time(),
            subscription_info: None,
        };
        let body = String::from_utf8(api.marshal_json().expect("marshal")).expect("JSON is UTF-8");

        assert!(
            body.starts_with(r#"{"name":"default","type":"Proxy","vehicleType":"Compatible","proxies":["#),
            "{body}"
        );
        assert!(re_search(r#""history":\[\{"time":"[^"]+","delay":0\}\]"#, &body), "{body}");
        assert!(
            re_search(
                r#""extra":\{"http://192\.0\.2\.1/":\{"alive":false,"history":\[\{"time":"[^"]+","delay":0\}\]\}\}"#,
                &body
            ),
            "{body}"
        );
        assert!(body.ends_with(r#""updatedAt":"0001-01-01T00:00:00Z"}"#), "{body}");
    }

    fn re_search(pattern: &str, text: &str) -> bool {
        Regex::new(pattern).expect("valid pattern").is_match(text).unwrap_or(false)
    }

    /// An encryption-only Vision entry is a supported configuration, so a mixed provider must
    /// parse both entries instead of losing the whole payload at construction.
    #[tokio::test]
    async fn an_encryption_only_vision_entry_does_not_abort_a_mixed_provider() {
        let (_, client, _) = murmur_transport_vless::encryption::key::gen_mlkem768("").expect("gen_mlkem768");
        let (_, password, _) = murmur_transport_vless::encryption::key::gen_x25519("").expect("gen_x25519");
        let yaml = format!(
            r#"
proxies:
  - name: ordinary
    type: trojan
    server: 192.0.2.1
    port: 443
    password: example
  - name: vision-encrypted
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    flow: xtls-rprx-vision
    tls: false
    encryption: mlkem768x25519plus.native.0rtt.{password}.{client}
"#
        );
        let parser = new_proxies_parser(
            "mixed",
            Arc::new(murmur_tunnel::tunnel::Tunnel),
            "",
            "",
            "",
            "",
            OverrideSchema::default(),
            "",
        )
        .expect("parser");

        let proxies = parser(yaml.as_bytes()).expect("the mixed provider parses");
        let names: Vec<String> = proxies.iter().map(|proxy| proxy.name()).collect();
        assert_eq!(names, ["ordinary", "vision-encrypted"]);
    }
}
