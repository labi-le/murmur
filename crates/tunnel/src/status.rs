use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

use anyhow::{anyhow, Result};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TunnelStatus(pub i32);

impl TunnelStatus {
    pub const SUSPEND: Self = Self(0);
    pub const INNER: Self = Self(1);
    pub const RUNNING: Self = Self(2);

    pub fn unmarshal_text(&mut self, data: &[u8]) -> Result<()> {
        let text = String::from_utf8_lossy(data).to_lowercase();
        let status = STATUS_MAPPING.get(text.as_str()).ok_or_else(|| anyhow!("invalid status"))?;
        *self = *status;
        Ok(())
    }

    pub fn marshal_text(&self) -> Result<Vec<u8>> {
        Ok(self.string().into_bytes())
    }

    #[must_use]
    pub fn string(&self) -> String {
        match *self {
            Self::SUSPEND => "suspend",
            Self::INNER => "inner",
            Self::RUNNING => "running",
            _ => "Unknown",
        }
        .to_owned()
    }
}

impl fmt::Display for TunnelStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

/// Bridges `TunnelStatus` into `common::atomic::enum_::Int32Enum`.
impl From<i32> for TunnelStatus {
    fn from(v: i32) -> Self {
        Self(v)
    }
}

impl From<TunnelStatus> for i32 {
    fn from(status: TunnelStatus) -> Self {
        status.0
    }
}

pub static STATUS_MAPPING: LazyLock<HashMap<&'static str, TunnelStatus>> = LazyLock::new(|| {
    HashMap::from([
        ("suspend", TunnelStatus::SUSPEND),
        ("inner", TunnelStatus::INNER),
        ("running", TunnelStatus::RUNNING),
    ])
});
