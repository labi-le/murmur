use crate::quic::{CongestionOption, Profile};

pub const DEFAULT_STREAM_RECEIVE_WINDOW: i32 = 15_728_640; // 15 MB/s
pub const DEFAULT_CONNECTION_RECEIVE_WINDOW: i32 = 67_108_864; // 64 MB/s

///
/// The controller belongs on a live QUIC connection, but quinn binds one when the endpoint is
/// built, so the choice travels to endpoint construction as a [`CongestionOption`].
#[must_use]
pub fn congestion_option(cc: &str, cwnd: i32, profile: &str) -> CongestionOption {
    CongestionOption { name: cc.to_owned(), cwnd, profile: Profile::from(profile) }
}
