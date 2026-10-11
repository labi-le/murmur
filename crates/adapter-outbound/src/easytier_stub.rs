use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use super::base::{Base, BasicOption};

pub struct EasyTier {
    #[allow(dead_code, reason = "kept for structural fidelity with the real adapter")]
    base: Base,
}

impl std::fmt::Debug for EasyTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EasyTier").finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct EasyTierOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "network-name", default)]
    pub network_name: String,
    #[serde(rename = "network-secret", default)]
    pub network_secret: String,
    #[serde(rename = "hostname", default)]
    pub hostname: String,
    #[serde(rename = "ipv4", default)]
    pub ipv4: String,
    #[serde(rename = "dhcp", default)]
    pub dhcp: bool,
    #[serde(rename = "peers", default)]
    pub peers: Vec<String>,
    #[serde(rename = "listeners", default)]
    pub listeners: Vec<String>,
    #[serde(rename = "no-listener", default)]
    pub no_listener: Option<bool>,
    #[serde(rename = "mapped-listeners", default)]
    pub mapped_listeners: Vec<String>,
    #[serde(rename = "exit-nodes", default)]
    pub exit_nodes: Vec<String>,
    #[serde(rename = "proxy-networks", default)]
    pub proxy_networks: Vec<String>,
    #[serde(rename = "instance-name", default)]
    pub instance_name: String,
    #[serde(rename = "state-dir", default)]
    pub state_dir: String,
    #[serde(rename = "udp", default)]
    pub udp: bool,
    #[serde(rename = "accept-dns", default)]
    pub accept_dns: Option<bool>,
    #[serde(rename = "enable-exit-node", default)]
    pub enable_exit_node: Option<bool>,
    #[serde(rename = "enable-encryption", default)]
    pub enable_encryption: Option<bool>,
    #[serde(rename = "encryption-algorithm", default)]
    pub encryption_algorithm: String,
    #[serde(rename = "private-mode", default)]
    pub private_mode: Option<bool>,
    #[serde(rename = "latency-first", default)]
    pub latency_first: Option<bool>,
    #[serde(rename = "disable-p2p", default)]
    pub disable_p2p: Option<bool>,
    #[serde(rename = "enable-kcp-proxy", default)]
    pub enable_kcp_proxy: Option<bool>,
    #[serde(rename = "disable-kcp-input", default)]
    pub disable_kcp_input: Option<bool>,
    #[serde(rename = "enable-quic-proxy", default)]
    pub enable_quic_proxy: Option<bool>,
    #[serde(rename = "disable-quic-input", default)]
    pub disable_quic_input: Option<bool>,
    #[serde(rename = "mtu", default)]
    pub mtu: i32,
    #[serde(rename = "tld-dns-zone", default)]
    pub tld_dns_zone: String,
    #[serde(rename = "secure-mode", default)]
    pub secure_mode: Option<bool>,
    #[serde(rename = "local-private-key", default)]
    pub local_private_key: String,
    #[serde(rename = "local-public-key", default)]
    pub local_public_key: String,
}

impl std::fmt::Debug for EasyTierOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EasyTierOption")
            .field("name", &self.name)
            .field("hostname", &self.hostname)
            .field("network_secret", &"<redacted>")
            .field("local_private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EasyTier {
    pub fn new(_option: EasyTierOption) -> anyhow::Result<Self> {
        Err(anyhow!("EasyTier support is disabled by \"no_easytier\" build tag"))
    }
}
