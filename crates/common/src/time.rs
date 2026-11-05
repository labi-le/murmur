//! Signed-nanosecond duration and zero-time-relative timestamp helpers this crate depends on.
//!
//! A duration is a signed nanosecond count and callers throughout the crate rely on that
//! sign: openvpn's `transition_window`/`ping_interval` reject negative values only at the YAML
//! boundary and must still hold a transiently negative value before that check runs
//! (`transport::openvpn::client` tests this directly); `component::resource::fetcher`'s pull-loop
//! interval and `ntp::time`'s clock offset are differences that go negative in the ordinary case
//! (a stale file, a local clock ahead of the server); `component::keepalive`'s dialer `keep_alive`
//! field follows the dialer convention where negative means "disabled" and zero
//! means "use the OS default"; and the tuic congestion estimators (`transport::tuic::congestion`)
//! and the `monotime` quic arithmetic that saturates through zero in both
//! directions. `std::time::Duration` is unsigned and cannot represent any of this, so `TimeDuration`
//! keeps the signed representation; `Duration` is used only where a value is already known
//! non-negative (e.g. after `duration_from_nanos` clamps it).

use std::time::Duration;

pub type TimeDuration = i64;

pub const NANOSECOND: TimeDuration = 1;
pub const MICROSECOND: TimeDuration = 1_000;
pub const MILLISECOND: TimeDuration = 1_000_000;
pub const SECOND: TimeDuration = 1_000_000_000;
pub const MINUTE: TimeDuration = 60 * SECOND;
pub const HOUR: TimeDuration = 60 * MINUTE;

#[must_use]
pub const fn duration_from_nanos(nanos: TimeDuration) -> Duration {
    if nanos <= 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(nanos.cast_unsigned())
    }
}

#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    reason = "`TimeDuration` is a signed nanosecond count, so a `std::time::Duration` above `i64::MAX` nanoseconds (292 years) has no representable value and truncates instead of saturating"
)]
pub const fn duration_to_nanos(d: Duration) -> TimeDuration {
    d.as_nanos() as TimeDuration
}

pub const ZERO_TIME_TIMESTAMP: i64 = -62_135_596_800;

/// The zero time is 0001-01-01T00:00:00Z, not the Unix epoch.
///
/// `Option<DateTime<Utc>>` replaced this sentinel everywhere the "unset" state was internal to a
/// Rust type. It survives here only where a wire format is pinned to the literal zero time:
/// the cachefile msgpack decoder's legacy null-time fallback, the clash API's `updatedAt` field on
/// a provider with no fetcher (`CompatibleProvider`), and a fetcher's public accessor when nothing
/// has been fetched yet.
#[must_use]
pub fn zero_time() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(ZERO_TIME_TIMESTAMP, 0).unwrap_or_default()
}
