use serde::{Deserialize, Serialize};

use crate::mkcp::MKCPConfig;
use murmur_transport_mekya::config::Config as MekyaTransportConfig;

fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MekyaConfig {
    #[serde(rename = "enable", default, skip_serializing_if = "is_zero")]
    pub enable: bool,
    #[serde(rename = "url", default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    #[serde(rename = "h2-pool-size", default, skip_serializing_if = "is_zero")]
    pub h2_pool_size: i32,
    #[serde(rename = "max-write-delay", default, skip_serializing_if = "is_zero")]
    pub max_write_delay: i32,
    #[serde(rename = "max-request-size", default, skip_serializing_if = "is_zero")]
    pub max_request_size: i32,
    #[serde(rename = "polling-interval-initial", default, skip_serializing_if = "is_zero")]
    pub polling_interval_initial: i32,
    #[serde(rename = "max-write-size", default, skip_serializing_if = "is_zero")]
    pub max_write_size: i32,
    #[serde(rename = "max-write-duration-ms", default, skip_serializing_if = "is_zero")]
    pub max_write_duration_ms: i32,
    #[serde(rename = "max-simultaneous-write-connection", default, skip_serializing_if = "is_zero")]
    pub max_simultaneous_write_connection: i32,
    #[serde(rename = "packet-writing-buffer", default, skip_serializing_if = "is_zero")]
    pub packet_writing_buffer: i32,
    #[serde(rename = "kcp", default)]
    pub kcp: MKCPConfig,
}

impl MekyaConfig {
    #[must_use]
    pub fn build(&self) -> MekyaTransportConfig {
        MekyaTransportConfig {
            kcp: self.kcp.build(),
            url: self.url.clone(),
            h2_pool_size: i64::from(self.h2_pool_size),
            max_write_delay: i64::from(self.max_write_delay),
            max_request_size: i64::from(self.max_request_size),
            polling_interval_initial: i64::from(self.polling_interval_initial),
            max_write_size: i64::from(self.max_write_size),
            max_write_duration_ms: i64::from(self.max_write_duration_ms),
            max_simultaneous_write_connection: i64::from(self.max_simultaneous_write_connection),
            packet_writing_buffer: i64::from(self.packet_writing_buffer),
        }
    }
}
