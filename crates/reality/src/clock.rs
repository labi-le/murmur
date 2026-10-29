//! The system clock plus the NTP offset. Both REALITY halves read it: the client stamps the
//! spliced session id with the current Unix second, and the server compares that stamp against
//! `max-time-difference`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use murmur_ntp::time::now as ntp_now;

pub(crate) fn now_unix_secs() -> u64 {
    u64::try_from(ntp_now().timestamp()).unwrap_or_default()
}

pub(crate) fn now() -> SystemTime {
    let Some(nanos) = ntp_now().timestamp_nanos_opt() else {
        return SystemTime::now();
    };
    let offset = Duration::from_nanos(nanos.unsigned_abs());
    if nanos >= 0 {
        UNIX_EPOCH + offset
    } else {
        UNIX_EPOCH - offset
    }
}
