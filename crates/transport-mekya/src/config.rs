use murmur_transport_mkcp::config::Config as KcpConfig;

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub kcp: KcpConfig,
    pub url: String,
    pub h2_pool_size: i64,
    pub max_write_delay: i64,
    pub max_request_size: i64,
    pub polling_interval_initial: i64,
    pub max_write_size: i64,
    pub max_write_duration_ms: i64,
    pub max_simultaneous_write_connection: i64,
    pub packet_writing_buffer: i64,
}
