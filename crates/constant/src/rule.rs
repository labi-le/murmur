use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::metadata::Metadata;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleType(pub i32);

impl RuleType {
    pub const DOMAIN: Self = Self(0);
    pub const DOMAIN_SUFFIX: Self = Self(1);
    pub const DOMAIN_KEYWORD: Self = Self(2);
    pub const DOMAIN_REGEX: Self = Self(3);
    pub const DOMAIN_WILDCARD: Self = Self(4);
    pub const GEOSITE: Self = Self(5);
    pub const GEOIP: Self = Self(6);
    pub const SRC_GEOIP: Self = Self(7);
    pub const IPASN: Self = Self(8);
    pub const SRC_IPASN: Self = Self(9);
    pub const IPCIDR: Self = Self(10);
    pub const SRC_IPCIDR: Self = Self(11);
    pub const IP_SUFFIX: Self = Self(12);
    pub const SRC_IP_SUFFIX: Self = Self(13);
    pub const SRC_PORT: Self = Self(14);
    pub const DST_PORT: Self = Self(15);
    pub const IN_PORT: Self = Self(16);
    pub const DSCP: Self = Self(17);
    pub const IN_USER: Self = Self(18);
    pub const IN_NAME: Self = Self(19);
    pub const IN_TYPE: Self = Self(20);
    pub const PROCESS_NAME: Self = Self(21);
    pub const PROCESS_PATH: Self = Self(22);
    pub const PROCESS_NAME_REGEX: Self = Self(23);
    pub const PROCESS_PATH_REGEX: Self = Self(24);
    pub const PROCESS_NAME_WILDCARD: Self = Self(25);
    pub const PROCESS_PATH_WILDCARD: Self = Self(26);
    pub const REMATCH_NAME: Self = Self(27);
    pub const RULE_SET: Self = Self(28);
    pub const NETWORK: Self = Self(29);
    pub const UID: Self = Self(30);
    pub const SUB_RULES: Self = Self(31);
    pub const MATCH: Self = Self(32);
    pub const AND: Self = Self(33);
    pub const OR: Self = Self(34);
    pub const NOT: Self = Self(35);

    #[must_use]
    pub fn string(&self) -> String {
        match *self {
            Self::DOMAIN => "Domain",
            Self::DOMAIN_SUFFIX => "DomainSuffix",
            Self::DOMAIN_KEYWORD => "DomainKeyword",
            Self::DOMAIN_REGEX => "DomainRegex",
            Self::DOMAIN_WILDCARD => "DomainWildcard",
            Self::GEOSITE => "GeoSite",
            Self::GEOIP => "GeoIP",
            Self::SRC_GEOIP => "SrcGeoIP",
            Self::IPASN => "IPASN",
            Self::SRC_IPASN => "SrcIPASN",
            Self::IPCIDR => "IPCIDR",
            Self::SRC_IPCIDR => "SrcIPCIDR",
            Self::IP_SUFFIX => "IPSuffix",
            Self::SRC_IP_SUFFIX => "SrcIPSuffix",
            Self::SRC_PORT => "SrcPort",
            Self::DST_PORT => "DstPort",
            Self::IN_PORT => "InPort",
            Self::IN_USER => "InUser",
            Self::IN_NAME => "InName",
            Self::IN_TYPE => "InType",
            Self::PROCESS_NAME => "ProcessName",
            Self::PROCESS_PATH => "ProcessPath",
            Self::PROCESS_NAME_REGEX => "ProcessNameRegex",
            Self::PROCESS_PATH_REGEX => "ProcessPathRegex",
            Self::PROCESS_NAME_WILDCARD => "ProcessNameWildcard",
            Self::PROCESS_PATH_WILDCARD => "ProcessPathWildcard",
            Self::REMATCH_NAME => "RematchName",
            Self::MATCH => "Match",
            Self::RULE_SET => "RuleSet",
            Self::NETWORK => "Network",
            Self::DSCP => "DSCP",
            Self::UID => "Uid",
            Self::SUB_RULES => "SubRules",
            Self::AND => "AND",
            Self::OR => "OR",
            Self::NOT => "NOT",
            _ => "Unknown",
        }
        .to_owned()
    }
}

impl fmt::Display for RuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

pub trait Rule: Send + Sync {
    fn rule_type(&self) -> RuleType;

    /// The helper is borrowed for the call; a nested rule set that must not resolve builds its own
    /// masked copy. The returned adapter borrows the rule.
    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>);

    fn adapter(&self) -> String;

    fn payload(&self) -> String;

    fn provider_names(&self) -> Vec<String>;

    fn as_rule_wrapper(&self) -> Option<&dyn RuleWrapper> {
        None
    }

    fn as_rule_group(&self) -> Option<&dyn RuleGroup> {
        None
    }
}

pub trait RuleWrapper: Rule {
    fn set_disabled(&self, v: bool);

    fn is_disabled(&self) -> bool;

    fn hit_count(&self) -> u64;

    fn hit_at(&self) -> DateTime<Utc>;

    fn miss_count(&self) -> u64;

    fn miss_at(&self) -> DateTime<Utc>;

    fn unwrap(&self) -> Arc<dyn Rule>;
}

/// the `CheckPassRule` field type: a predicate over an adapter name.
///
/// It takes the caller's already-held `&Metadata` explicitly rather than capturing a pointer, so
/// the aliasing is visible at every call site.
pub type CheckPassRuleFn = Arc<dyn Fn(&Metadata, &str) -> bool + Send + Sync>;

/// `RuleMatchHelper`. A hook left unset is `None`.
///
/// The closures capture the metadata they mutate, which is also the exact `metadata` a
/// `Rule::match_` call already holds `&mut` over. That borrow cannot be aliased through a captured
/// pointer, so `resolve_ip`/`find_process` take the caller's `&mut Metadata` as an explicit
/// parameter — the same object, passed safely.
#[derive(Clone, Default)]
pub struct RuleMatchHelper {
    pub resolve_ip: Option<Arc<dyn Fn(&mut Metadata) + Send + Sync>>,
    pub find_process: Option<Arc<dyn Fn(&mut Metadata) + Send + Sync>>,
    pub check_pass_rule: Option<CheckPassRuleFn>,
}

impl fmt::Debug for RuleMatchHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleMatchHelper").finish_non_exhaustive()
    }
}

pub trait RuleGroup: Rule {
    fn get_recode_size(&self) -> i32;
}
