use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The prefix used when the config names no `device`, which is why a default Linux device is
/// called `Meta`.
pub const INTERFACE_NAME: &str = "Meta";

/// The fallback MTU for an unset `mtu`.
pub const DEFAULT_MTU: u32 = 9000;

/// The fallback GSO max size for an unset `gso-max-size`.
pub const DEFAULT_GSO_MAX_SIZE: u32 = 65536;

/// The lowercased stack name, the key a stack is looked up with.
#[must_use]
pub fn stack_name(stack: TunStack) -> &'static str {
    match stack {
        TunStack::Gvisor => "gvisor",
        TunStack::System => "system",
        TunStack::Mixed => "mixed",
        TunStack::Mips => "mips",
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TunStack {
    #[default]
    Gvisor,
    System,
    Mixed,
    Mips,
}

impl fmt::Display for TunStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Gvisor => "gVisor",
            Self::System => "System",
            Self::Mixed => "Mixed",
            Self::Mips => "Mips",
        })
    }
}

impl Serialize for TunStack {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TunStack {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.to_lowercase().as_str() {
            "gvisor" => Ok(Self::Gvisor),
            "system" => Ok(Self::System),
            "mixed" => Ok(Self::Mixed),
            "mips" => Ok(Self::Mips),
            _ => Err(serde::de::Error::custom("invalid tun stack")),
        }
    }
}
