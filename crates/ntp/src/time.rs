//! Offset-corrected wall clock.
//!
//! [`now`] returns `Utc::now()` shifted by the offset the NTP service last measured.
//!
//! Kept dependency-light on purpose: other project crates must not be imported here.

use portable_atomic::AtomicI64;
use std::sync::atomic::Ordering;

use chrono::{DateTime, TimeDelta, Utc};

use murmur_common::time::TimeDuration;

/// Clock offset in nanoseconds, as measured by the NTP service.
///
/// The offset is signed and `std::time::Duration` cannot represent a negative value, so the count
/// is kept as `TimeDuration`.
static OFFSET: AtomicI64 = AtomicI64::new(0);

pub fn set_offset(offset: TimeDuration) {
    OFFSET.store(offset, Ordering::SeqCst);
}

pub fn get_offset() -> TimeDuration {
    OFFSET.load(Ordering::SeqCst)
}

#[must_use]
pub fn now() -> DateTime<Utc> {
    let now = Utc::now();
    let offset = get_offset();
    if offset != 0 {
        return now + TimeDelta::nanoseconds(offset);
    }
    now
}
