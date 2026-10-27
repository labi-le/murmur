//! The messages are declared as `prost` messages with the same tags; the protobuf reflection
//! tables and the message-type reset methods are not reproduced here.

use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

/// Type of domain value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    /// The value is used as is.
    Plain = 0,
    /// The value is used as a regular expression.
    Regex = 1,
    /// The value is a root domain.
    Domain = 2,
    /// The value is a domain.
    Full = 3,
}

pub static DOMAIN_TYPE_NAME: LazyLock<HashMap<i32, &'static str>> =
    LazyLock::new(|| HashMap::from([(0, "Plain"), (1, "Regex"), (2, "Domain"), (3, "Full")]));

pub static DOMAIN_TYPE_VALUE: LazyLock<HashMap<&'static str, i32>> =
    LazyLock::new(|| HashMap::from([("Plain", 0), ("Regex", 1), ("Domain", 2), ("Full", 3)]));

impl DomainType {
    /// The string name of a known value.
    #[must_use]
    pub const fn as_str_name(&self) -> &'static str {
        match self {
            Self::Plain => "Plain",
            Self::Regex => "Regex",
            Self::Domain => "Domain",
            Self::Full => "Full",
        }
    }

    /// The reverse lookup from a name to its value.
    #[must_use]
    pub fn from_str_name(value: &str) -> Option<Self> {
        match value {
            "Plain" => Some(Self::Plain),
            "Regex" => Some(Self::Regex),
            "Domain" => Some(Self::Domain),
            "Full" => Some(Self::Full),
            _ => None,
        }
    }
}

impl fmt::Display for DomainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str_name())
    }
}

/// Domain for routing decision.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct Domain {
    /// Domain matching type.
    #[prost(enumeration = "DomainType", tag = "1")]
    pub r#type: i32,
    /// Domain value.
    #[prost(string, tag = "2")]
    pub value: String,
    /// Attributes of this domain. May be used for filtering.
    #[prost(message, repeated, tag = "3")]
    pub attribute: Vec<DomainAttribute>,
}

impl Domain {
    /// Returns the raw protobuf value.
    #[must_use]
    pub const fn get_type(&self) -> i32 {
        self.r#type
    }

    #[must_use]
    pub fn get_value(&self) -> &str {
        &self.value
    }

    #[must_use]
    pub fn get_attribute(&self) -> &[DomainAttribute] {
        &self.attribute
    }
}

/// IP for routing decision, in CIDR form.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct Cidr {
    /// IP address, should be either 4 or 16 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub ip: Vec<u8>,
    /// Number of leading ones in the network mask.
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}

impl Cidr {
    #[must_use]
    pub fn get_ip(&self) -> &[u8] {
        &self.ip
    }

    #[must_use]
    pub const fn get_prefix(&self) -> u32 {
        self.prefix
    }
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct GeoIp {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    pub reverse_match: bool,
}

impl GeoIp {
    #[must_use]
    pub fn get_country_code(&self) -> &str {
        &self.country_code
    }

    #[must_use]
    pub fn get_cidr(&self) -> &[Cidr] {
        &self.cidr
    }

    #[must_use]
    pub const fn get_reverse_match(&self) -> bool {
        self.reverse_match
    }
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoIp>,
}

impl GeoIpList {
    #[must_use]
    pub fn get_entry(&self) -> &[GeoIp] {
        &self.entry
    }
}

/// `GeoSite`.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct GeoSite {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
}

impl GeoSite {
    #[must_use]
    pub fn get_country_code(&self) -> &str {
        &self.country_code
    }

    #[must_use]
    pub fn get_domain(&self) -> &[Domain] {
        &self.domain
    }
}

/// `GeoSiteList`.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoSite>,
}

impl GeoSiteList {
    #[must_use]
    pub fn get_entry(&self) -> &[GeoSite] {
        &self.entry
    }
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct DomainAttribute {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(oneof = "domain_attribute::TypedValue", tags = "2, 3")]
    pub typed_value: Option<domain_attribute::TypedValue>,
}

pub mod domain_attribute {
    #[derive(Clone, PartialEq, Eq, prost::Oneof)]
    pub enum TypedValue {
        #[prost(bool, tag = "2")]
        BoolValue(bool),
        #[prost(int64, tag = "3")]
        IntValue(i64),
    }
}

impl DomainAttribute {
    #[must_use]
    pub fn get_key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub const fn get_typed_value(&self) -> Option<&domain_attribute::TypedValue> {
        self.typed_value.as_ref()
    }

    #[must_use]
    pub const fn get_bool_value(&self) -> bool {
        match &self.typed_value {
            Some(domain_attribute::TypedValue::BoolValue(value)) => *value,
            _ => false,
        }
    }

    #[must_use]
    pub const fn get_int_value(&self) -> i64 {
        match &self.typed_value {
            Some(domain_attribute::TypedValue::IntValue(value)) => *value,
            _ => 0,
        }
    }
}
