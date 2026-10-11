use chrono::{DateTime, Utc};

use murmur_common::time::TimeDuration;

pub use std::cmp::{max, min};

/// A duration of infinite length.
pub const INF_DURATION: TimeDuration = i64::MAX;

/// The minimum duration that is not zero.
#[must_use]
pub fn min_non_zero_duration(a: TimeDuration, b: TimeDuration) -> TimeDuration {
    if a == 0 {
        return b;
    }
    if b == 0 {
        return a;
    }
    min(a, b)
}

/// The absolute value of a time duration.
#[must_use]
pub const fn abs_duration(d: TimeDuration) -> TimeDuration {
    if d >= 0 {
        return d;
    }
    d.wrapping_neg()
}

/// The earlier of two times.
#[must_use]
pub fn min_time(a: DateTime<Utc>, b: DateTime<Utc>) -> DateTime<Utc> {
    if a > b {
        return b;
    }
    a
}

/// The earlier of two possibly-unset times.
#[must_use]
pub fn min_non_zero_time(a: Option<DateTime<Utc>>, b: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    match (a, b) {
        (None, other) | (other, None) => other,
        (Some(a), Some(b)) => Some(min_time(a, b)),
    }
}

/// The later of two times.
#[must_use]
pub fn max_time(a: DateTime<Utc>, b: DateTime<Utc>) -> DateTime<Utc> {
    if a > b {
        return a;
    }
    b
}
