use std::time::Duration;

use murmur_quic::congestion::ByteCount;

pub(crate) const INF_BANDWIDTH: Bandwidth = u64::MAX;

/// Bandwidth of a connection, in bits per second.
pub type Bandwidth = u64;

pub const BITS_PER_SECOND: Bandwidth = 1;
pub const BYTES_PER_SECOND: Bandwidth = 8 * BITS_PER_SECOND;

/// Calculates the bandwidth from a number of bytes and a time delta
#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    reason = "the one-second nanosecond factor and a realistic delta both fit the bandwidth's width"
)]
pub const fn bandwidth_from_delta(bytes: ByteCount, delta: Duration) -> Bandwidth {
    (bytes.cast_unsigned()) * (Duration::from_secs(1).as_nanos() as Bandwidth) / (delta.as_nanos() as Bandwidth)
        * BYTES_PER_SECOND
}
