//! A regex decoded through a text unmarshaler maps to `fancy_regex::Regex` compiled with no flags.
//!
//! That matches the mapping `murmur_rules_common::domain_regex` uses for the case-insensitive
//! case. A `.Replace` with .NET-style `$1`/`${name}` group references can fail on a malformed
//! replacement; `fancy_regex::Regex::replace_all` accepts the same `$1`/`${name}` syntax but never
//! fails, silently dropping an unknown group reference instead — DEVIATION, see the wave report.

use std::fmt;

use anyhow::{anyhow, Context, Result};
use fancy_regex::Regex;
use serde::de::{Deserializer, Visitor};
use serde::Deserialize;
use serde_yaml::{Mapping, Number, Value};

use murmur_common::structure::structure::TEXT_UNMARSHALER;

use super::override_expr::OverrideExpr;

#[derive(Clone, Debug)]
pub(crate) struct OverrideNamePattern(pub(crate) Regex);

impl<'de> Deserialize<'de> for OverrideNamePattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct PatternVisitor;

        impl Visitor<'_> for PatternVisitor {
            type Value = OverrideNamePattern;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a regular expression")
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> std::result::Result<OverrideNamePattern, E> {
                Regex::new(text).map(OverrideNamePattern).map_err(E::custom)
            }
        }

        deserializer.deserialize_newtype_struct(TEXT_UNMARSHALER, PatternVisitor)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct OverrideProxyNameSchema {
    /// Matching expression for regex replacement.
    #[serde(rename = "pattern")]
    pub(crate) pattern: OverrideNamePattern,
    /// The new content after regex matching.
    #[serde(rename = "target")]
    pub(crate) target: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct OverrideSchema {
    #[serde(rename = "tfo", default)]
    pub(crate) tfo: Option<bool>,
    #[serde(rename = "mptcp", default)]
    pub(crate) mptcp: Option<bool>,
    #[serde(rename = "udp", default)]
    pub(crate) udp: Option<bool>,
    #[serde(rename = "udp-over-tcp", default)]
    pub(crate) udp_over_tcp: Option<bool>,
    #[serde(rename = "up", default)]
    pub(crate) up: Option<String>,
    #[serde(rename = "down", default)]
    pub(crate) down: Option<String>,
    #[serde(rename = "dialer-proxy", default)]
    pub(crate) dialer_proxy: Option<String>,
    #[serde(rename = "skip-cert-verify", default)]
    pub(crate) skip_cert_verify: Option<bool>,
    #[serde(rename = "name-cert-verify", default)]
    pub(crate) name_cert_verify: Option<String>,
    #[serde(rename = "interface-name", default)]
    pub(crate) interface: Option<String>,
    #[serde(rename = "routing-mark", default)]
    pub(crate) routing_mark: Option<i64>,
    #[serde(rename = "ip-version", default)]
    pub(crate) ip_version: Option<String>,

    #[serde(rename = "additional-prefix", default)]
    pub(crate) additional_prefix: Option<String>,
    #[serde(rename = "additional-suffix", default)]
    pub(crate) additional_suffix: Option<String>,
    #[serde(rename = "proxy-name", default)]
    pub(crate) proxy_name: Vec<OverrideProxyNameSchema>,
    #[serde(rename = "override-expr", default)]
    pub(crate) override_expr: Vec<OverrideExpr>,
}

impl OverrideSchema {
    pub(crate) fn apply(&self, mapping: &mut Mapping) -> Result<()> {
        if let Some(tfo) = self.tfo {
            mapping.insert(Value::String("tfo".to_owned()), Value::Bool(tfo));
        }
        if let Some(mptcp) = self.mptcp {
            mapping.insert(Value::String("mptcp".to_owned()), Value::Bool(mptcp));
        }
        if let Some(udp) = self.udp {
            mapping.insert(Value::String("udp".to_owned()), Value::Bool(udp));
        }
        if let Some(udp_over_tcp) = self.udp_over_tcp {
            mapping.insert(Value::String("udp-over-tcp".to_owned()), Value::Bool(udp_over_tcp));
        }
        if let Some(up) = &self.up {
            mapping.insert(Value::String("up".to_owned()), Value::String(up.clone()));
        }
        if let Some(down) = &self.down {
            mapping.insert(Value::String("down".to_owned()), Value::String(down.clone()));
        }
        if let Some(dialer_proxy) = &self.dialer_proxy {
            mapping.insert(Value::String("dialer-proxy".to_owned()), Value::String(dialer_proxy.clone()));
        }
        if let Some(skip_cert_verify) = self.skip_cert_verify {
            mapping.insert(Value::String("skip-cert-verify".to_owned()), Value::Bool(skip_cert_verify));
        }
        if let Some(name_cert_verify) = &self.name_cert_verify {
            mapping.insert(Value::String("name-cert-verify".to_owned()), Value::String(name_cert_verify.clone()));
        }
        if let Some(interface) = &self.interface {
            mapping.insert(Value::String("interface-name".to_owned()), Value::String(interface.clone()));
        }
        if let Some(routing_mark) = self.routing_mark {
            mapping.insert(Value::String("routing-mark".to_owned()), Value::Number(Number::from(routing_mark)));
        }
        if let Some(ip_version) = &self.ip_version {
            mapping.insert(Value::String("ip-version".to_owned()), Value::String(ip_version.clone()));
        }

        for expr in &self.proxy_name {
            let name = mapping_name(mapping)?;
            let new_name = expr.pattern.0.replace_all(&name, expr.target.as_str()).into_owned();
            mapping.insert(Value::String("name".to_owned()), Value::String(new_name));
        }
        if let Some(prefix) = &self.additional_prefix {
            let name = mapping_name(mapping)?;
            mapping.insert(Value::String("name".to_owned()), Value::String(format!("{prefix}{name}")));
        }
        if let Some(suffix) = &self.additional_suffix {
            let name = mapping_name(mapping)?;
            mapping.insert(Value::String("name".to_owned()), Value::String(format!("{name}{suffix}")));
        }
        for (idx, expr) in self.override_expr.iter().enumerate() {
            expr.apply(mapping).with_context(|| format!("override-expr[{idx}] {:?}: ", expr.to_string()))?;
        }

        Ok(())
    }
}

fn mapping_name(mapping: &Mapping) -> Result<String> {
    mapping
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("proxy mapping must already carry a string \"name\" by the time overrides apply"))
}
