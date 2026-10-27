use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use anyhow::anyhow;
use murmur_common::atomic::enum_::Int32EnumValue;

/// `FindProcessMode`; the `i32` representation is kept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FindProcessMode(pub i32);

/// `common::atomic::enum_`'s blanket impl needs `From<i32>`/`Into<i32>`, which this type does
/// not implement (only a bare tuple field); crate split moved this impl out of `tunnel` (which
/// owned neither `Int32EnumValue` nor `FindProcessMode` before the split) into the crate that
/// owns the type.
impl Int32EnumValue for FindProcessMode {
    fn from_i32(v: i32) -> Self {
        Self(v)
    }

    fn into_i32(self) -> i32 {
        self.0
    }
}

impl FindProcessMode {
    pub const FIND_PROCESS_STRICT: Self = Self(0);
    pub const FIND_PROCESS_ALWAYS: Self = Self(1);
    pub const FIND_PROCESS_OFF: Self = Self(2);

    pub fn unmarshal_text(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.set(&String::from_utf8_lossy(data))
    }

    pub fn set(&mut self, value: &str) -> anyhow::Result<()> {
        let Some(mode) = VALID_MODES.get(&value.to_lowercase()) else {
            return Err(anyhow!("invalid find process mode"));
        };
        *self = *mode;
        Ok(())
    }

    pub fn marshal_text(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_string().into_bytes())
    }
}

impl fmt::Display for FindProcessMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::FIND_PROCESS_ALWAYS => "always",
            Self::FIND_PROCESS_OFF => "off",
            _ => "strict",
        };
        f.write_str(name)
    }
}

impl serde::Serialize for FindProcessMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for FindProcessMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FindProcessModeVisitor;

        impl serde::de::Visitor<'_> for FindProcessModeVisitor {
            type Value = FindProcessMode;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a find-process mode string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<FindProcessMode, E> {
                let mut mode = FindProcessMode::default();
                mode.unmarshal_text(value.as_bytes()).map_err(E::custom)?;
                Ok(mode)
            }
        }

        deserializer.deserialize_str(FindProcessModeVisitor)
    }
}

pub(crate) static VALID_MODES: LazyLock<HashMap<String, FindProcessMode>> = LazyLock::new(|| {
    HashMap::from([
        (FindProcessMode::FIND_PROCESS_STRICT.to_string(), FindProcessMode::FIND_PROCESS_STRICT),
        (FindProcessMode::FIND_PROCESS_ALWAYS.to_string(), FindProcessMode::FIND_PROCESS_ALWAYS),
        (FindProcessMode::FIND_PROCESS_OFF.to_string(), FindProcessMode::FIND_PROCESS_OFF),
    ])
});
