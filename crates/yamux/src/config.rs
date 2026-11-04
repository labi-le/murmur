use std::io;
use std::time::Duration;

use crate::frame::{INITIAL_STREAM_WINDOW, MAX_STREAM_WINDOW};

/// Configuration for a session.
///
/// Does not carry `LogOutput`, `ReadBufSize` or `WriteCoalesceDelay`: there is no log sink,
/// buffering is delegated to the tokio runtime, and writes are never coalesced.
/// `stream_close_timeout`/`stream_open_timeout` are omitted rather than invented.
#[derive(Clone, Debug)]
pub struct Config {
    pub accept_backlog: usize,
    pub ping_backlog: usize,
    pub enable_keepalive: bool,
    pub keep_alive_interval: Duration,
    pub measure_rtt_interval: Duration,
    pub connection_write_timeout: Duration,
    pub max_incoming_streams: u32,
    pub initial_stream_window_size: u32,
    pub max_stream_window_size: u32,
    pub max_message_size: u32,
}

#[must_use]
pub const fn default_config() -> Config {
    Config {
        accept_backlog: 256,
        ping_backlog: 32,
        enable_keepalive: true,
        keep_alive_interval: Duration::from_secs(30),
        measure_rtt_interval: Duration::from_secs(30),
        connection_write_timeout: Duration::from_secs(10),
        max_incoming_streams: 1000,
        initial_stream_window_size: INITIAL_STREAM_WINDOW,
        max_stream_window_size: MAX_STREAM_WINDOW,
        max_message_size: 64 * 1024,
    }
}

pub fn verify_config(config: &Config) -> io::Result<()> {
    if config.accept_backlog == 0 {
        return Err(io::Error::other("backlog must be positive"));
    }
    if config.enable_keepalive && config.keep_alive_interval.is_zero() {
        return Err(io::Error::other("keep-alive interval must be positive"));
    }
    if config.measure_rtt_interval.is_zero() {
        return Err(io::Error::other("measure-rtt interval must be positive"));
    }
    if config.initial_stream_window_size < INITIAL_STREAM_WINDOW {
        return Err(io::Error::other("InitialStreamWindowSize must be larger or equal 256 kB"));
    }
    if config.max_stream_window_size < config.initial_stream_window_size {
        return Err(io::Error::other("MaxStreamWindowSize must be larger than the InitialStreamWindowSize"));
    }
    if config.max_message_size < 1024 {
        return Err(io::Error::other("MaxMessageSize must be greater than a kilobyte"));
    }
    if config.ping_backlog == 0 {
        return Err(io::Error::other("PingBacklog must be > 0"));
    }
    Ok(())
}
