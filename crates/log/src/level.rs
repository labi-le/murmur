use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use anyhow::anyhow;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// `LogLevel`; the `i32` representation is kept so out-of-range levels still render as `unknown`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogLevel(pub i32);

impl LogLevel {
    pub const DEBUG: Self = Self(0);
    pub const INFO: Self = Self(1);
    pub const WARNING: Self = Self(2);
    pub const ERROR: Self = Self(3);
    pub const SILENT: Self = Self(4);

    pub fn unmarshal_text(data: &[u8]) -> anyhow::Result<Self> {
        let text = String::from_utf8_lossy(data);
        LOG_LEVEL_MAPPING
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&text))
            .map(|(_, level)| *level)
            .ok_or_else(|| anyhow!("invalid log-level"))
    }

    pub fn marshal_text(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_string().into_bytes())
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::INFO => "info",
            Self::WARNING => "warning",
            Self::ERROR => "error",
            Self::DEBUG => "debug",
            Self::SILENT => "silent",
            _ => "unknown",
        };
        f.write_str(name)
    }
}

impl Serialize for LogLevel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for LogLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct LogLevelVisitor;

        impl Visitor<'_> for LogLevelVisitor {
            type Value = LogLevel;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a log-level string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<LogLevel, E> {
                LogLevel::unmarshal_text(value.as_bytes()).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(LogLevelVisitor)
    }
}

pub static LOG_LEVEL_MAPPING: LazyLock<HashMap<&'static str, LogLevel>> = LazyLock::new(|| {
    HashMap::from([
        ("error", LogLevel::ERROR),
        ("warning", LogLevel::WARNING),
        ("info", LogLevel::INFO),
        ("debug", LogLevel::DEBUG),
        ("silent", LogLevel::SILENT),
    ])
});
