use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use super::base::{Base, BasicOption};

pub struct Tailscale {
    #[allow(dead_code, reason = "kept for structural fidelity with the real adapter")]
    base: Base,
}

impl std::fmt::Debug for Tailscale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tailscale").finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TailscaleOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "hostname", default)]
    pub hostname: String,
    #[serde(rename = "auth-key", default)]
    pub auth_key: String,
    #[serde(rename = "control-url", default)]
    pub control_url: String,
    #[serde(rename = "state-dir", default)]
    pub state_dir: String,
    #[serde(rename = "ephemeral", default)]
    pub ephemeral: bool,
    #[serde(rename = "udp", default)]
    pub udp: bool,

    #[serde(rename = "accept-routes", default)]
    pub accept_routes: Option<bool>,
    #[serde(rename = "exit-node", default)]
    pub exit_node: String,
    #[serde(rename = "exit-node-allow-lan-access", default)]
    pub exit_node_allow_lan_access: Option<bool>,
}

impl std::fmt::Debug for TailscaleOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TailscaleOption")
            .field("name", &self.name)
            .field("hostname", &self.hostname)
            .field("auth_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Tailscale {
    pub fn new(_option: TailscaleOption) -> anyhow::Result<Self> {
        Err(anyhow!(
            "tailscale support is disabled by \"no_tailscale\" build tag or not include \"with_gvisor\" build tag"
        ))
    }
}
