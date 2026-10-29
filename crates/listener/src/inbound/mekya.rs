use crate::inbound::mkcp::MKCPConfig;
use murmur_listener_config::mekya as lc_mekya;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct MekyaConfig {
    pub enable: bool,
    pub url: String,
    pub h2_pool_size: i32,
    pub max_write_delay: i32,
    pub max_request_size: i32,
    pub polling_interval_initial: i32,
    pub max_write_size: i32,
    pub max_write_duration_ms: i32,
    pub max_simultaneous_write_connection: i32,
    pub packet_writing_buffer: i32,
    pub kcp: MKCPConfig,
}

impl MekyaConfig {
    #[must_use]
    pub fn build(&self) -> lc_mekya::MekyaConfig {
        lc_mekya::MekyaConfig {
            enable: self.enable,
            url: self.url.clone(),
            h2_pool_size: self.h2_pool_size,
            max_write_delay: self.max_write_delay,
            max_request_size: self.max_request_size,
            polling_interval_initial: self.polling_interval_initial,
            max_write_size: self.max_write_size,
            max_write_duration_ms: self.max_write_duration_ms,
            max_simultaneous_write_connection: self.max_simultaneous_write_connection,
            packet_writing_buffer: self.packet_writing_buffer,
            kcp: self.kcp.build(),
        }
    }
}
