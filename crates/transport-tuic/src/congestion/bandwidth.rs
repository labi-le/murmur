use std::time::Duration;

use murmur_quic::congestion;

pub(crate) const INF_BANDWIDTH: Bandwidth = u64::MAX;

/// Bandwidth of a connection
pub type Bandwidth = u64;

/// One bit per second.
pub const BITS_PER_SECOND: Bandwidth = 1;
/// One byte per second.
pub const BYTES_PER_SECOND: Bandwidth = 8 * BITS_PER_SECOND;

/// The bandwidth implied by a number of bytes over a time delta.
#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    reason = "the one-second nanosecond factor and a realistic delta both fit the bandwidth's width"
)]
pub const fn bandwidth_from_delta(bytes: congestion::ByteCount, delta: Duration) -> Bandwidth {
    (bytes.cast_unsigned())
        .wrapping_mul(Duration::from_secs(1).as_nanos() as Bandwidth)
        .wrapping_div(delta.as_nanos() as Bandwidth)
        .wrapping_mul(BYTES_PER_SECOND)
}
