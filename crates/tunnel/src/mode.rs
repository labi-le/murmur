use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use anyhow::{anyhow, Result};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TunnelMode(pub i32);

impl TunnelMode {
    pub const GLOBAL: Self = Self(0);
    pub const RULE: Self = Self(1);
    pub const DIRECT: Self = Self(2);

    pub fn unmarshal_text(&mut self, data: &[u8]) -> Result<()> {
        let text = String::from_utf8_lossy(data).to_lowercase();
        let mode = MODE_MAPPING.get(text.as_str()).ok_or_else(|| anyhow!("invalid mode"))?;
        *self = *mode;
        Ok(())
    }

    pub fn marshal_text(&self) -> Result<Vec<u8>> {
        Ok(self.string().into_bytes())
    }

    #[must_use]
    pub fn string(&self) -> String {
        match *self {
            Self::GLOBAL => "global",
            Self::RULE => "rule",
            Self::DIRECT => "direct",
            _ => "Unknown",
        }
        .to_owned()
    }
}

impl fmt::Display for TunnelMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

impl serde::Serialize for TunnelMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.string())
    }
}

impl<'de> serde::Deserialize<'de> for TunnelMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct TunnelModeVisitor;

        impl serde::de::Visitor<'_> for TunnelModeVisitor {
            type Value = TunnelMode;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a tunnel mode string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<TunnelMode, E> {
                let mut mode = TunnelMode::default();
                mode.unmarshal_text(value.as_bytes()).map_err(E::custom)?;
                Ok(mode)
            }
        }

        deserializer.deserialize_str(TunnelModeVisitor)
    }
}

/// Bridges `TunnelMode` into `common::atomic::enum_::Int32Enum`.
impl From<i32> for TunnelMode {
    fn from(v: i32) -> Self {
        Self(v)
    }
}

impl From<TunnelMode> for i32 {
    fn from(mode: TunnelMode) -> Self {
        mode.0
    }
}

pub static MODE_MAPPING: LazyLock<HashMap<&'static str, TunnelMode>> = LazyLock::new(|| {
    HashMap::from([("global", TunnelMode::GLOBAL), ("rule", TunnelMode::RULE), ("direct", TunnelMode::DIRECT)])
});
