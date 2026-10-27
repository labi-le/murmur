use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use anyhow::{anyhow, Result};
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub static DNS_MODE_MAPPING: LazyLock<HashMap<&'static str, DNSMode>> = LazyLock::new(|| {
    HashMap::from([
        ("normal", DNSMode::DNS_NORMAL),
        ("fake-ip", DNSMode::DNS_FAKE_IP),
        ("redir-host", DNSMode::DNS_MAPPING),
    ])
});

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSMode(pub i32);

impl DNSMode {
    pub const DNS_NORMAL: Self = Self(0);
    pub const DNS_FAKE_IP: Self = Self(1);
    pub const DNS_MAPPING: Self = Self(2);
    pub const DNS_HOSTS: Self = Self(3);

    pub fn unmarshal_text(&mut self, data: &[u8]) -> Result<()> {
        let text = String::from_utf8_lossy(data).to_lowercase();
        let mode = DNS_MODE_MAPPING.get(text.as_str()).ok_or_else(|| anyhow!("invalid mode"))?;
        *self = *mode;
        Ok(())
    }

    pub fn marshal_text(&self) -> Result<Vec<u8>> {
        Ok(self.string().into_bytes())
    }

    #[must_use]
    pub fn string(&self) -> String {
        match *self {
            Self::DNS_NORMAL => "normal",
            Self::DNS_FAKE_IP => "fake-ip",
            Self::DNS_MAPPING => "redir-host",
            Self::DNS_HOSTS => "hosts",
            _ => "unknown",
        }
        .to_owned()
    }
}

impl fmt::Display for DNSMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

impl Serialize for DNSMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.string())
    }
}

impl<'de> Deserialize<'de> for DNSMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DNSModeVisitor;

        impl Visitor<'_> for DNSModeVisitor {
            type Value = DNSMode;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a dns mode string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<DNSMode, E> {
                let mut mode = DNSMode::default();
                mode.unmarshal_text(value.as_bytes()).map_err(E::custom)?;
                Ok(mode)
            }
        }

        deserializer.deserialize_str(DNSModeVisitor)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSPrefer(pub i32);

impl DNSPrefer {
    pub const DUAL_STACK: Self = Self(0);
    pub const IPV4_ONLY: Self = Self(1);
    pub const IPV6_ONLY: Self = Self(2);
    pub const IPV4_PREFER: Self = Self(3);
    pub const IPV6_PREFER: Self = Self(4);

    #[must_use]
    pub fn string(&self) -> String {
        match *self {
            Self::IPV4_ONLY => "ipv4",
            Self::IPV6_ONLY => "ipv6",
            Self::IPV4_PREFER => "ipv4-prefer",
            Self::IPV6_PREFER => "ipv6-prefer",
            _ => "dual",
        }
        .to_owned()
    }

    pub fn marshal_text(&self) -> Result<Vec<u8>> {
        Ok(self.string().into_bytes())
    }

    /// Falls back to `DualStack` on an unknown name.
    pub fn unmarshal_text(&mut self, data: &[u8]) -> Result<()> {
        let text = String::from_utf8_lossy(data).to_lowercase();
        *self = DNS_PREFER_MAP.get(text.as_str()).copied().unwrap_or(Self::DUAL_STACK);
        Ok(())
    }
}

static DNS_PREFER_MAP: LazyLock<HashMap<&'static str, DNSPrefer>> = LazyLock::new(|| {
    HashMap::from([
        ("dual", DNSPrefer::DUAL_STACK),
        ("ipv4", DNSPrefer::IPV4_ONLY),
        ("ipv6", DNSPrefer::IPV6_ONLY),
        ("ipv4-prefer", DNSPrefer::IPV4_PREFER),
        ("ipv6-prefer", DNSPrefer::IPV6_PREFER),
    ])
});

impl fmt::Display for DNSPrefer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

impl Serialize for DNSPrefer {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.string())
    }
}

impl<'de> Deserialize<'de> for DNSPrefer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DNSPreferVisitor;

        impl Visitor<'_> for DNSPreferVisitor {
            type Value = DNSPrefer;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a dns prefer string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<DNSPrefer, E> {
                let mut prefer = DNSPrefer::default();
                prefer.unmarshal_text(value.as_bytes()).map_err(E::custom)?;
                Ok(prefer)
            }
        }

        deserializer.deserialize_str(DNSPreferVisitor)
    }
}

pub static FILTER_MODE_MAPPING: LazyLock<HashMap<&'static str, FilterMode>> = LazyLock::new(|| {
    HashMap::from([
        ("blacklist", FilterMode::FILTER_BLACK_LIST),
        ("whitelist", FilterMode::FILTER_WHITE_LIST),
        ("rule", FilterMode::FILTER_RULE),
    ])
});

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilterMode(pub i32);

impl FilterMode {
    pub const FILTER_BLACK_LIST: Self = Self(0);
    pub const FILTER_WHITE_LIST: Self = Self(1);
    pub const FILTER_RULE: Self = Self(2);

    #[must_use]
    pub fn string(&self) -> String {
        match *self {
            Self::FILTER_BLACK_LIST => "blacklist",
            Self::FILTER_WHITE_LIST => "whitelist",
            Self::FILTER_RULE => "rule",
            _ => "unknown",
        }
        .to_owned()
    }

    pub fn marshal_text(&self) -> Result<Vec<u8>> {
        Ok(self.string().into_bytes())
    }

    pub fn unmarshal_text(&mut self, data: &[u8]) -> Result<()> {
        let text = String::from_utf8_lossy(data).to_lowercase();
        let mode = FILTER_MODE_MAPPING.get(text.as_str()).ok_or_else(|| anyhow!("invalid mode"))?;
        *self = *mode;
        Ok(())
    }
}

impl fmt::Display for FilterMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

impl Serialize for FilterMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.string())
    }
}

impl<'de> Deserialize<'de> for FilterMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FilterModeVisitor;

        impl Visitor<'_> for FilterModeVisitor {
            type Value = FilterMode;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a filter mode string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<FilterMode, E> {
                let mut mode = FilterMode::default();
                mode.unmarshal_text(value.as_bytes()).map_err(E::custom)?;
                Ok(mode)
            }
        }

        deserializer.deserialize_str(FilterModeVisitor)
    }
}

/// `HTTPVersion`. Only three constants exist, kept as `&'static str` values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HTTPVersion(pub &'static str);

impl HTTPVersion {
    pub const HTTP_VERSION11: Self = Self("http/1.1");
    pub const HTTP_VERSION2: Self = Self("h2");
    pub const HTTP_VERSION3: Self = Self("h3");
}

impl fmt::Display for HTTPVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
