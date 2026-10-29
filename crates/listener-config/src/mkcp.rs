use serde::{Deserialize, Serialize};

use murmur_transport_mkcp::config::Config as MkcpConfig;

fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MKCPConfig {
    #[serde(rename = "enable", default, skip_serializing_if = "is_zero")]
    pub enable: bool,
    #[serde(rename = "mtu", default, skip_serializing_if = "is_zero")]
    pub mtu: u32,
    #[serde(rename = "tti", default, skip_serializing_if = "is_zero")]
    pub tti: u32,
    #[serde(rename = "uplink-capacity", default, skip_serializing_if = "is_zero")]
    pub uplink_capacity: u32,
    #[serde(rename = "downlink-capacity", default, skip_serializing_if = "is_zero")]
    pub downlink_capacity: u32,
    #[serde(rename = "congestion", default, skip_serializing_if = "is_zero")]
    pub congestion: bool,
    #[serde(rename = "write-buffer", default, skip_serializing_if = "is_zero")]
    pub write_buffer: u32,
    #[serde(rename = "read-buffer", default, skip_serializing_if = "is_zero")]
    pub read_buffer: u32,
    #[serde(rename = "seed", default, skip_serializing_if = "String::is_empty")]
    pub seed: String,
    #[serde(rename = "header", default, skip_serializing_if = "String::is_empty")]
    pub header: String,
}

impl MKCPConfig {
    #[must_use]
    pub fn build(&self) -> MkcpConfig {
        MkcpConfig {
            mtu: self.mtu,
            tti: self.tti,
            uplink_capacity: self.uplink_capacity,
            downlink_capacity: self.downlink_capacity,
            congestion: self.congestion,
            write_buffer: self.write_buffer,
            read_buffer: self.read_buffer,
            seed: self.seed.clone(),
            header: self.header.clone(),
        }
    }
}
