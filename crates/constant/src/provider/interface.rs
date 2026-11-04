use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::adapters::Proxy;
use crate::metadata::Metadata;
use crate::rule::RuleMatchHelper;
use murmur_common::utils::callback::Callback;
use murmur_common::utils::hash::HashType;
use murmur_common::utils::ranges::IntRanges;
use murmur_component::cidr::ipcidr_set::IpCidrSet;

/// the `VehicleType`, keeping the `int` representation so unknown values still render.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VehicleType(pub i32);

impl VehicleType {
    pub const FILE: Self = Self(0);
    pub const HTTP: Self = Self(1);
    pub const COMPATIBLE: Self = Self(2);
    pub const INLINE: Self = Self(3);
}

impl fmt::Display for VehicleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::FILE => "File",
            Self::HTTP => "HTTP",
            Self::COMPATIBLE => "Compatible",
            Self::INLINE => "Inline",
            _ => "Unknown",
        };
        f.write_str(name)
    }
}

/// `HTTPVehicle`'s callback capability, used by `adapter::provider::provider` to capture the
/// `subscription-userinfo` header.
///
/// Only `HTTPVehicle` has it, so this is a capability method with a default, overridden by the
/// implementor that has the capability (this project's usual replacement for a single-implementor
/// downcast).
pub trait SubscriptionReadCallback: Send + Sync {
    fn set_in_read(&self, f: Arc<dyn Fn(&hyper::Response<hyper::body::Incoming>) + Send + Sync>);
}

/// the `Vehicle` interface.
#[async_trait]
pub trait Vehicle: Send + Sync {
    async fn read(&self, ctx: &CancellationToken, old_hash: HashType) -> anyhow::Result<(Vec<u8>, HashType)>;
    fn write(&self, buf: &[u8]) -> anyhow::Result<()>;
    fn path(&self) -> String;
    fn url(&self) -> String;
    fn proxy(&self) -> String;
    fn type_(&self) -> VehicleType;

    fn as_subscription_read_callback(&self) -> Option<&dyn SubscriptionReadCallback> {
        None
    }
}

/// the `ProviderType`, keeping the `int` representation so unknown values still render.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderType(pub i32);

impl ProviderType {
    pub const PROXY: Self = Self(0);
    pub const RULE: Self = Self(1);
}

impl fmt::Display for ProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::PROXY => "Proxy",
            Self::RULE => "Rule",
            _ => "Unknown",
        };
        f.write_str(name)
    }
}

/// the `Provider` interface.
///
/// Serializing a map of providers would otherwise need runtime reflection to find each concrete
/// provider's serializer; `marshal_json` is a required trait method instead, forwarding to each
/// concrete provider's inherent `marshal_json`.
#[async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> String;
    fn vehicle_type(&self) -> VehicleType;
    fn type_(&self) -> ProviderType;
    async fn initial(&self) -> anyhow::Result<()>;
    async fn update(&self) -> anyhow::Result<()>;
    fn marshal_json(&self) -> anyhow::Result<Vec<u8>>;
}

/// the `ProxyProvider` interface.
#[async_trait]
pub trait ProxyProvider: Provider {
    fn proxies(&self) -> Vec<Arc<dyn Proxy>>;
    fn count(&self) -> i32;
    /// Informs the provider that the proxy is actually being used while getting the list of
    /// proxies, as in `DialContext` and `DialPacketConn`.
    fn touch(&self);
    async fn health_check(&self);
    fn version(&self) -> u32;
    fn register_health_check_task(&self, url: &str, expected_status: IntRanges<u16>, filter: &str, interval: u32);
    fn health_check_url(&self) -> String;
}

/// the `RuleProvider` interface. The strategy is narrowed to the one capability any caller
/// downcasts to (an ipcidr set); `None` covers both "not an ipcidr strategy" and an unset
/// `IpSet`.
#[async_trait]
pub trait RuleProvider: Provider {
    fn behavior(&self) -> RuleBehavior;
    fn count(&self) -> i32;
    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> bool;
    fn to_ip_cidr(&self) -> Option<IpCidrSet>;
}

/// the `RuleBehavior`, keeping the `int` representation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleBehavior(pub i32);

impl RuleBehavior {
    pub const DOMAIN: Self = Self(0);
    pub const IPCIDR: Self = Self(1);
    pub const CLASSICAL: Self = Self(2);

    #[must_use]
    pub const fn byte(&self) -> u8 {
        match *self {
            Self::DOMAIN => 0,
            Self::IPCIDR => 1,
            Self::CLASSICAL => 2,
            _ => 255,
        }
    }
}

impl fmt::Display for RuleBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::DOMAIN => "Domain",
            Self::IPCIDR => "IPCIDR",
            Self::CLASSICAL => "Classical",
            _ => "Unknown",
        };
        f.write_str(name)
    }
}

pub fn parse_behavior(s: &str) -> anyhow::Result<RuleBehavior> {
    let behavior = match s {
        "domain" => RuleBehavior::DOMAIN,
        "ipcidr" => RuleBehavior::IPCIDR,
        "classical" => RuleBehavior::CLASSICAL,
        _ => return Err(anyhow!("unsupported behavior type: {s}")),
    };
    Ok(behavior)
}

/// the `RuleFormat`, keeping the `int` representation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleFormat(pub i32);

impl RuleFormat {
    pub const YAML_RULE: Self = Self(0);
    pub const TEXT_RULE: Self = Self(1);
    pub const MRS_RULE: Self = Self(2);
}

impl fmt::Display for RuleFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::YAML_RULE => "YamlRule",
            Self::TEXT_RULE => "TextRule",
            Self::MRS_RULE => "MrsRule",
            _ => "Unknown",
        };
        f.write_str(name)
    }
}

pub fn parse_rule_format(s: &str) -> anyhow::Result<RuleFormat> {
    let format = match s {
        "" | "yaml" => RuleFormat::YAML_RULE,
        "text" => RuleFormat::TEXT_RULE,
        "mrs" => RuleFormat::MRS_RULE,
        _ => return Err(anyhow!("unsupported format type: {s}")),
    };
    Ok(format)
}

/// the `Tunnel` interface.
pub trait Tunnel: Send + Sync {
    fn providers(&self) -> HashMap<String, Arc<dyn ProxyProvider>>;
    fn rule_providers(&self) -> HashMap<String, Arc<dyn RuleProvider>>;
    fn rule_update_callback(&self) -> &Callback<Arc<dyn RuleProvider>>;
}
