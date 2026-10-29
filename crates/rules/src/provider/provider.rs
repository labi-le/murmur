use std::io::{Read, Write};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_component::cidr::ipcidr_set::IpCidrSet;
use murmur_component_resource::fetcher::{new_fetcher, BundleFile, Fetcher, Parser};
use murmur_constant::metadata::Metadata;
use murmur_constant::provider::interface::{
    Provider, ProviderType, RuleBehavior, RuleFormat, RuleProvider, Tunnel, Vehicle, VehicleType,
};
use murmur_constant::rule::RuleMatchHelper;
use murmur_rules_common::base::ParseRuleFunc;

use super::classical_strategy::new_classical_strategy;
use super::domain_strategy::new_domain_strategy;
use super::ipcidr_strategy::new_ip_cidr_strategy;
use super::mrs_reader::rules_mrs_parse;

static TUNNEL: RwLock<Option<Arc<dyn Tunnel>>> = RwLock::new(None);

pub fn set_tunnel(t: Arc<dyn Tunnel>) {
    *TUNNEL.write() = Some(t);
}

pub(crate) fn tunnel() -> Option<Arc<dyn Tunnel>> {
    TUNNEL.read().clone()
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct RulePayload {
    #[serde(rename = "payload", default)]
    pub(crate) payload: Vec<String>,
    #[serde(rename = "rules", default)]
    pub(crate) rules: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProviderForApi {
    pub(crate) behavior: String,
    pub(crate) format: String,
    pub(crate) name: String,
    #[serde(rename = "ruleCount")]
    pub(crate) rule_count: i32,
    #[serde(rename = "type")]
    pub(crate) type_: String,
    #[serde(rename = "vehicleType")]
    pub(crate) vehicle_type: String,
    #[serde(rename = "updatedAt", with = "murmur_common::time_rfc3339")]
    pub(crate) updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) payload: Vec<String>,
}

pub(crate) trait RuleStrategy: Send + Sync {
    fn behavior(&self) -> RuleBehavior;
    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> bool;
    fn count(&self) -> i32;
    fn reset(&mut self);
    fn insert(&mut self, rule: &str);
    fn finish_insert(&mut self);

    /// the `strategy.(mrsRuleStrategy)` interface-to-interface type assertion.
    fn as_mrs(&self) -> Option<&dyn MrsRuleStrategy> {
        None
    }
    fn as_mrs_mut(&mut self) -> Option<&mut dyn MrsRuleStrategy> {
        None
    }

    /// Returns the underlying rule set when this strategy is IP-CIDR backed.
    fn to_ip_cidr(&self) -> Option<&IpCidrSet> {
        None
    }
}

pub(crate) trait MrsRuleStrategy: RuleStrategy {
    fn load_mrs(&mut self, r: &mut dyn Read, count: i32) -> Result<()>;
    fn write_mrs(&self, w: &mut dyn Write) -> Result<()>;
    fn dump_mrs(&self, f: &mut dyn FnMut(&str) -> bool);
}

/// Bridges the synchronous `Read`/`Write` streams `mrs_reader.rs`/`mrs_converter.rs` use (a
/// `zstd` decoder/encoder over an in-memory buffer, never a real blocking I/O source) to the
/// `tokio::io::AsyncRead`/`AsyncWrite` APIs `component::trie`/`component::cidr` already expose;
/// `futures::executor::block_on` resolves the resulting future inline since `poll_read`/
/// `poll_write` below never return `Poll::Pending`.
pub(crate) struct SyncAsyncReader<'a>(pub(crate) &'a mut dyn Read);

impl AsyncRead for SyncAsyncReader<'_> {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let n = this.0.read(buf.initialize_unfilled())?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct SyncAsyncWriter<'a>(pub(crate) &'a mut dyn Write);

impl AsyncWrite for SyncAsyncWriter<'_> {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Poll::Ready(self.get_mut().0.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(self.get_mut().0.flush())
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct BaseProvider {
    behavior: RuleBehavior,
    strategy: RwLock<Option<Arc<dyn RuleStrategy>>>,
}

impl BaseProvider {
    pub(crate) fn new(behavior: RuleBehavior, strategy: Option<Arc<dyn RuleStrategy>>) -> Self {
        Self { behavior, strategy: RwLock::new(strategy) }
    }

    pub(crate) const fn type_() -> ProviderType {
        ProviderType::RULE
    }

    pub(crate) const fn behavior(&self) -> RuleBehavior {
        self.behavior
    }

    pub(crate) fn count(&self) -> i32 {
        self.strategy.read().as_ref().map_or(0, |s| s.count())
    }

    pub(crate) fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> bool {
        self.strategy.read().as_ref().is_some_and(|strategy| strategy.match_(metadata, helper))
    }

    pub(crate) fn to_ip_cidr(&self) -> Option<IpCidrSet> {
        self.strategy.read().as_ref().and_then(|s| s.to_ip_cidr().cloned())
    }

    pub(crate) fn set_strategy(&self, strategy: Arc<dyn RuleStrategy>) {
        *self.strategy.write() = Some(strategy);
    }
}

pub struct RuleSetProvider {
    base: BaseProvider,
    fetcher: Arc<Fetcher<Option<Arc<dyn RuleStrategy>>>>,
    format: RuleFormat,
}

impl std::fmt::Debug for RuleSetProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSetProvider")
            .field("behavior", &self.base.behavior())
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Provider for RuleSetProvider {
    fn name(&self) -> String {
        self.fetcher.name()
    }

    fn vehicle_type(&self) -> VehicleType {
        self.fetcher.vehicle_type()
    }

    fn type_(&self) -> ProviderType {
        BaseProvider::type_()
    }

    async fn initial(&self) -> Result<()> {
        self.fetcher.initial().await.map(|_| ())
    }

    async fn update(&self) -> Result<()> {
        self.fetcher.update().await.map(|_| ())
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.marshal_json()
    }
}

#[async_trait]
impl RuleProvider for RuleSetProvider {
    fn behavior(&self) -> RuleBehavior {
        self.base.behavior()
    }

    fn count(&self) -> i32 {
        self.base.count()
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> bool {
        self.base.match_(metadata, helper)
    }

    fn to_ip_cidr(&self) -> Option<IpCidrSet> {
        self.base.to_ip_cidr()
    }
}

impl RuleSetProvider {
    pub fn marshal_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&ProviderForApi {
            behavior: self.base.behavior().to_string(),
            format: self.format.to_string(),
            name: self.fetcher.name(),
            rule_count: self.base.count(),
            type_: BaseProvider::type_().to_string(),
            vehicle_type: self.fetcher.vehicle_type().to_string(),
            updated_at: self.fetcher.updated_at(),
            payload: Vec::new(),
        })?)
    }

    pub fn close(&self) -> Result<()> {
        self.fetcher.close()
    }
}

impl Drop for RuleSetProvider {
    fn drop(&mut self) {
        let _ = self.fetcher.close();
    }
}

pub fn new_rule_set_provider(
    name: &str,
    behavior: RuleBehavior,
    format: RuleFormat,
    interval: Duration,
    vehicle: Arc<dyn Vehicle>,
    payload: &[String],
    bundle_file: Option<BundleFile>,
    parse: &ParseRuleFunc,
) -> Arc<dyn RuleProvider> {
    let initial_strategy: Arc<dyn RuleStrategy> = {
        #[expect(
            clippy::expect_used,
            reason = "`parse_behavior` only yields DOMAIN/IPCIDR/CLASSICAL, so `None` is unreachable"
        )]
        let strategy = new_strategy(behavior, Some(Arc::clone(parse))).expect("unsupported rule behavior");
        let strategy = if payload.is_empty() { strategy } else { rules_parse_inline(payload, strategy) };
        Arc::from(strategy)
    };

    let name = name.to_owned();
    let rp: Arc<RuleSetProvider> = Arc::new_cyclic(|weak: &Weak<RuleSetProvider>| {
        let weak_self = Weak::clone(weak);
        let on_update: Arc<dyn Fn(Option<Arc<dyn RuleStrategy>>) + Send + Sync> = Arc::new(move |v| {
            let Some(rp) = weak_self.upgrade() else {
                return;
            };
            if let Some(strategy) = v {
                rp.base.set_strategy(strategy);
            }
            if let Some(tunnel) = tunnel() {
                tunnel.rule_update_callback().emit(rp);
            }
        });

        let parse_for_parser = Arc::clone(parse);
        let parser: Parser<Option<Arc<dyn RuleStrategy>>> = Arc::new(move |buf: &[u8]| {
            #[expect(
                clippy::expect_used,
                reason = "`parse_behavior` only yields DOMAIN/IPCIDR/CLASSICAL, so `None` is unreachable"
            )]
            let strategy =
                new_strategy(behavior, Some(Arc::clone(&parse_for_parser))).expect("unsupported rule behavior");
            let strategy = rules_parse(buf, strategy, format)?;
            Ok(Some(Arc::from(strategy)))
        });

        let fetcher = new_fetcher(&name, interval, vehicle, bundle_file, parser, Some(on_update));

        RuleSetProvider { base: BaseProvider::new(behavior, Some(initial_strategy)), fetcher, format }
    });

    rp
}

pub(crate) fn new_strategy(behavior: RuleBehavior, parse: Option<ParseRuleFunc>) -> Option<Box<dyn RuleStrategy>> {
    match behavior {
        RuleBehavior::DOMAIN => Some(new_domain_strategy()),
        RuleBehavior::IPCIDR => Some(new_ip_cidr_strategy()),
        RuleBehavior::CLASSICAL => Some(new_classical_strategy(parse)),
        _ => None,
    }
}

pub(crate) fn err_no_payload() -> anyhow::Error {
    anyhow!("file must have a `payload` field")
}

pub(crate) fn err_invalid_format() -> anyhow::Error {
    anyhow!("invalid format")
}

pub(crate) fn rules_parse(
    buf: &[u8],
    mut strategy: Box<dyn RuleStrategy>,
    format: RuleFormat,
) -> Result<Box<dyn RuleStrategy>> {
    strategy.reset();
    if format == RuleFormat::MRS_RULE {
        return rules_mrs_parse(buf, strategy);
    }

    let mut schema = RulePayload::default();
    let mut first_line_buffer = murmur_common_pool::get_buffer();

    let parse_result = (|| -> Result<()> {
        let mut first_line_length = 0usize;
        for line in buf.split_inclusive(|&b| b == b'\n') {
            if !line.ends_with(b"\n") && first_line_length == 0 && format == RuleFormat::YAML_RULE {
                return Err(err_no_payload());
            }

            let str_: String;
            match format {
                RuleFormat::TEXT_RULE => {
                    let trimmed = String::from_utf8_lossy(line);
                    let trimmed = trimmed.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if trimmed.starts_with('#') {
                        continue;
                    }
                    if trimmed.starts_with("//") {
                        continue;
                    }
                    str_ = trimmed.to_owned();
                }
                RuleFormat::YAML_RULE => {
                    let trim_line = line.trim_ascii();
                    if trim_line.is_empty() {
                        continue;
                    }
                    if trim_line.first() == Some(&b'#') {
                        continue;
                    }
                    first_line_buffer.extend_from_slice(line);
                    if first_line_length == 0 {
                        first_line_length = first_line_buffer.len();
                        first_line_buffer.extend_from_slice(b"  - ''");

                        let unmarshal_result = murmur_common::yaml::yaml::unmarshal(&first_line_buffer, &mut schema);
                        first_line_buffer.truncate(first_line_length);
                        if unmarshal_result.is_ok() && (!schema.rules.is_empty() || !schema.payload.is_empty()) {
                            continue;
                        }

                        first_line_buffer.clear();
                        first_line_length = 0;
                        continue;
                    }

                    let unmarshal_result = murmur_common::yaml::yaml::unmarshal(&first_line_buffer, &mut schema);
                    first_line_buffer.truncate(first_line_length);
                    if unmarshal_result.is_err() {
                        continue;
                    }

                    let mut computed = String::new();
                    if let Some(rule) = schema.rules.first() {
                        computed.clone_from(rule);
                    }
                    if let Some(payload) = schema.payload.first() {
                        computed.clone_from(payload);
                    }
                    str_ = computed;
                }
                _ => return Err(err_invalid_format()),
            }

            if str_.is_empty() {
                continue;
            }

            strategy.insert(&str_);
        }
        Ok(())
    })();

    murmur_common_pool::put_buffer(first_line_buffer);
    parse_result?;

    strategy.finish_insert();
    Ok(strategy)
}

pub(crate) fn rules_parse_inline(rs: &[String], mut strategy: Box<dyn RuleStrategy>) -> Box<dyn RuleStrategy> {
    strategy.reset();
    for r in rs {
        if !r.is_empty() {
            strategy.insert(r);
        }
    }
    strategy.finish_insert();
    strategy
}

pub struct InlineProvider {
    base: BaseProvider,
    name: String,
    update_at: RwLock<DateTime<Utc>>,
    payload: Vec<String>,
}

impl std::fmt::Debug for InlineProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineProvider")
            .field("behavior", &self.base.behavior())
            .field("name", &self.name)
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Provider for InlineProvider {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn vehicle_type(&self) -> VehicleType {
        VehicleType::INLINE
    }

    fn type_(&self) -> ProviderType {
        BaseProvider::type_()
    }

    async fn initial(&self) -> Result<()> {
        Ok(())
    }

    async fn update(&self) -> Result<()> {
        *self.update_at.write() = Utc::now();
        Ok(())
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.marshal_json()
    }
}

#[async_trait]
impl RuleProvider for InlineProvider {
    fn behavior(&self) -> RuleBehavior {
        self.base.behavior()
    }

    fn count(&self) -> i32 {
        self.base.count()
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> bool {
        self.base.match_(metadata, helper)
    }

    fn to_ip_cidr(&self) -> Option<IpCidrSet> {
        self.base.to_ip_cidr()
    }
}

impl InlineProvider {
    pub fn marshal_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&ProviderForApi {
            behavior: self.base.behavior().to_string(),
            format: String::new(),
            name: self.name.clone(),
            rule_count: self.base.count(),
            type_: BaseProvider::type_().to_string(),
            vehicle_type: VehicleType::INLINE.to_string(),
            updated_at: *self.update_at.read(),
            payload: self.payload.clone(),
        })?)
    }
}

pub fn new_inline_provider(
    name: &str,
    behavior: RuleBehavior,
    payload: &[String],
    parse: ParseRuleFunc,
) -> Arc<dyn RuleProvider> {
    #[expect(
        clippy::expect_used,
        reason = "`parse_behavior` only yields DOMAIN/IPCIDR/CLASSICAL, so `None` is unreachable"
    )]
    let strategy = new_strategy(behavior, Some(parse)).expect("unsupported rule behavior");
    let strategy = rules_parse_inline(payload, strategy);

    Arc::new(InlineProvider {
        base: BaseProvider::new(behavior, Some(Arc::from(strategy))),
        name: name.to_owned(),
        update_at: RwLock::new(Utc::now()),
        payload: payload.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    use std::collections::HashMap;
    use std::net::IpAddr;

    use async_trait::async_trait;
    use murmur_common::utils::callback::Callback;
    use murmur_constant::provider::interface::ProxyProvider;
    use murmur_constant::rule::Rule;

    use crate::logic::logic::Logic;
    use crate::parser::parse_rule;
    use crate::provider::rule_set::RuleSet;

    #[derive(Default)]
    struct RecordingStrategy {
        inserted: Arc<Mutex<Vec<String>>>,
        finished: Arc<Mutex<bool>>,
    }

    impl RuleStrategy for RecordingStrategy {
        fn behavior(&self) -> RuleBehavior {
            RuleBehavior::CLASSICAL
        }

        fn match_(&self, _metadata: &mut Metadata, _helper: &RuleMatchHelper) -> bool {
            false
        }

        fn count(&self) -> i32 {
            i32::try_from(self.inserted.lock().len()).expect("inserted rule count fits in i32")
        }

        fn reset(&mut self) {
            self.inserted.lock().clear();
            *self.finished.lock() = false;
        }

        fn insert(&mut self, rule: &str) {
            self.inserted.lock().push(rule.to_owned());
        }

        fn finish_insert(&mut self) {
            *self.finished.lock() = true;
        }
    }

    fn run_parse(buf: &[u8], format: RuleFormat) -> Result<Vec<String>> {
        let strategy = RecordingStrategy::default();
        let inserted = Arc::clone(&strategy.inserted);
        let finished = Arc::clone(&strategy.finished);
        rules_parse(buf, Box::new(strategy), format)?;
        assert!(*finished.lock(), "finish_insert must run once parsing succeeds");
        let result = inserted.lock().clone();
        Ok(result)
    }

    fn parse_text(buf: &[u8]) -> Result<Vec<String>> {
        run_parse(buf, RuleFormat::TEXT_RULE)
    }

    fn parse_yaml(buf: &[u8]) -> Result<Vec<String>> {
        run_parse(buf, RuleFormat::YAML_RULE)
    }

    #[test]
    fn text_rule_skips_comments_and_blanks_with_trailing_newline() {
        let buf = b"DOMAIN,a.com,DIRECT\n# comment\n\n// slash comment\nDOMAIN,b.com,DIRECT\n";
        let got = parse_text(buf).unwrap();
        assert_eq!(got, vec!["DOMAIN,a.com,DIRECT".to_owned(), "DOMAIN,b.com,DIRECT".to_owned()]);
    }

    #[test]
    fn text_rule_last_line_without_trailing_newline_is_included() {
        let buf = b"DOMAIN,a.com,DIRECT\nDOMAIN,b.com,DIRECT";
        let got = parse_text(buf).unwrap();
        assert_eq!(got, vec!["DOMAIN,a.com,DIRECT".to_owned(), "DOMAIN,b.com,DIRECT".to_owned()]);
    }

    #[test]
    fn text_rule_empty_buffer_yields_no_rules() {
        let got = parse_text(b"").unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn yaml_rule_under_payload_key() {
        let buf = b"payload:\n  - 'DOMAIN,a.com,DIRECT'\n  - 'DOMAIN,b.com,DIRECT'\n";
        let got = parse_yaml(buf).unwrap();
        assert_eq!(got, vec!["DOMAIN,a.com,DIRECT".to_owned(), "DOMAIN,b.com,DIRECT".to_owned()]);
    }

    #[test]
    fn yaml_rule_without_trailing_newline_still_parses_last_entry() {
        let buf = b"payload:\n  - 'DOMAIN,a.com,DIRECT'\n  - 'DOMAIN,b.com,DIRECT'";
        let got = parse_yaml(buf).unwrap();
        assert_eq!(got, vec!["DOMAIN,a.com,DIRECT".to_owned(), "DOMAIN,b.com,DIRECT".to_owned()]);
    }

    #[test]
    fn yaml_rule_missing_payload_key_on_single_line_without_newline_errors() {
        let buf = b"not a payload key";
        let err = parse_yaml(buf).unwrap_err();
        assert_eq!(err.to_string(), err_no_payload().to_string());
    }

    #[test]
    fn yaml_rule_skips_comment_and_blank_lines() {
        let buf = b"# leading comment\n\npayload:\n  - 'DOMAIN,a.com,DIRECT'\n";
        let got = parse_yaml(buf).unwrap();
        assert_eq!(got, vec!["DOMAIN,a.com,DIRECT".to_owned()]);
    }

    struct RuleBackedProvider {
        inner: Arc<dyn Rule>,
    }

    #[async_trait]
    impl Provider for RuleBackedProvider {
        fn name(&self) -> String {
            "delegate".to_owned()
        }

        fn vehicle_type(&self) -> VehicleType {
            VehicleType::INLINE
        }

        fn type_(&self) -> ProviderType {
            ProviderType::RULE
        }

        async fn initial(&self) -> Result<()> {
            Ok(())
        }

        async fn update(&self) -> Result<()> {
            Ok(())
        }

        fn marshal_json(&self) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl RuleProvider for RuleBackedProvider {
        fn behavior(&self) -> RuleBehavior {
            RuleBehavior::IPCIDR
        }

        fn count(&self) -> i32 {
            1
        }

        fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> bool {
            self.inner.match_(metadata, helper).0
        }

        fn to_ip_cidr(&self) -> Option<IpCidrSet> {
            None
        }
    }

    struct RuleTunnel {
        rule_providers: HashMap<String, Arc<dyn RuleProvider>>,
        rule_update_callback: Callback<Arc<dyn RuleProvider>>,
    }

    impl Tunnel for RuleTunnel {
        fn providers(&self) -> HashMap<String, Arc<dyn ProxyProvider>> {
            HashMap::new()
        }

        fn rule_providers(&self) -> HashMap<String, Arc<dyn RuleProvider>> {
            self.rule_providers.clone()
        }

        fn rule_update_callback(&self) -> &Callback<Arc<dyn RuleProvider>> {
            &self.rule_update_callback
        }
    }

    struct TunnelReset(Option<Arc<dyn Tunnel>>);

    impl Drop for TunnelReset {
        fn drop(&mut self) {
            *TUNNEL.write() = self.0.take();
        }
    }

    fn parse_fn() -> ParseRuleFunc {
        Arc::new(parse_rule)
    }

    #[test]
    fn rule_set_no_resolve_masking_stays_local_to_the_nested_rule_set() {
        let provider_rule = parse_rule("IP-CIDR", "10.0.0.0/8", "PROVIDER", &[], &HashMap::new()).unwrap();
        let mut providers: HashMap<String, Arc<dyn RuleProvider>> = HashMap::new();
        providers.insert("DELEGATE".to_owned(), Arc::new(RuleBackedProvider { inner: provider_rule }));

        let mock_tunnel: Arc<dyn Tunnel> =
            Arc::new(RuleTunnel { rule_providers: providers, rule_update_callback: Callback::default() });
        let _reset = TunnelReset(TUNNEL.write().replace(mock_tunnel));

        let masked: Arc<dyn Rule> = Arc::new(RuleSet::new("DELEGATE", "MASKED-SET", false, true).unwrap());
        let sibling = parse_rule("IP-CIDR", "10.0.0.0/8", "SIBLING", &[], &HashMap::new()).unwrap();

        let mut sub_rules: HashMap<String, Vec<Arc<dyn Rule>>> = HashMap::new();
        sub_rules.insert("NESTED".to_owned(), vec![masked, sibling]);
        let logic = Logic::sub_rule("(DOMAIN,trigger.example.com,DIRECT)", "NESTED", sub_rules, &parse_fn()).unwrap();

        let resolved: IpAddr = "10.1.2.3".parse().unwrap();
        let helper = RuleMatchHelper {
            resolve_ip: Some(Arc::new(move |metadata: &mut Metadata| metadata.dst_ip = Some(resolved))),
            ..Default::default()
        };

        let mut metadata = Metadata { host: "trigger.example.com".to_owned(), ..Default::default() };
        let (matched, adapter) = logic.match_(&mut metadata, &helper);

        assert!(matched, "the sibling IP-CIDR must match after it resolves the destination");
        assert_eq!(adapter.as_ref(), "SIBLING", "the masked set must not pre-empt the sibling");
        assert_eq!(metadata.dst_ip, Some(resolved), "the sibling must have set the destination");
    }
}
