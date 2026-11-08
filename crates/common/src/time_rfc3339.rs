//! The JSON wire form of a timestamp, shared by every field that carries one.
//!
//! The value is written in its own zone, so the offset on the wire is whatever the value's
//! location says. Every producer in this tree uses the current local time, so the offset is
//! `Local`'s. The zero time is the exception: its absent location is written as UTC.

use chrono::{DateTime, FixedOffset, Local, TimeZone, Utc};
use serde::{Deserialize, Deserializer, Serializer};

/// `#[serde(with = "murmur_common::time_rfc3339")]`.
pub fn serialize<S: Serializer>(time: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&to_wire_string(time))
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<DateTime<Utc>, D::Error> {
    let text = String::deserialize(deserializer)?;
    DateTime::parse_from_rfc3339(&text).map(|time| time.with_timezone(&Utc)).map_err(serde::de::Error::custom)
}

/// Formats the value in the RFC 3339 wire form, where the zero time keeps its absent location.
#[must_use]
pub fn to_wire_string(time: &DateTime<Utc>) -> String {
    if *time == crate::time::zero_time() {
        return rfc3339_nano(&time.fixed_offset());
    }
    to_wire(time, &Local)
}

/// Converts into `tz` before formatting; its own function so a test can pin a fixed offset that is
/// not the host's zone, which a `Z`-equivalent local zone would hide.
fn to_wire<Tz: TimeZone>(time: &DateTime<Utc>, tz: &Tz) -> String {
    rfc3339_nano(&time.with_timezone(tz).fixed_offset())
}

/// Nine fractional digits with the trailing zeros removed, none when the value
/// is a whole second, and `Z` in place of a zero offset.
fn rfc3339_nano(time: &DateTime<FixedOffset>) -> String {
    let base = time.format("%Y-%m-%dT%H:%M:%S");
    let sub_nanos = time.timestamp_subsec_nanos();
    let mut text = if sub_nanos == 0 {
        base.to_string()
    } else {
        let fraction = format!("{sub_nanos:09}");
        format!("{base}.{}", fraction.trim_end_matches('0'))
    };
    let offset_secs = time.offset().local_minus_utc();
    if offset_secs == 0 {
        text.push('Z');
    } else {
        let minutes = offset_secs / 60;
        let sign = if minutes < 0 { '-' } else { '+' };
        let m = minutes.unsigned_abs();
        text = format!("{text}{sign}{:02}:{:02}", m / 60, m % 60);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct Wrapper {
        #[serde(with = "super")]
        time: DateTime<Utc>,
    }

    #[test]
    fn whole_second_has_no_fraction() {
        let offset = FixedOffset::east_opt(3 * 3600).unwrap();
        let time = offset.with_ymd_and_hms(2026, 9, 24, 13, 0, 0).unwrap();
        assert_eq!(rfc3339_nano(&time), "2026-09-24T13:00:00+03:00");
    }

    #[test]
    fn fractional_second_trims_trailing_zeros() {
        let offset = FixedOffset::east_opt(3 * 3600).unwrap();
        let time = offset.with_ymd_and_hms(2026, 9, 24, 13, 0, 1).unwrap() + chrono::Duration::milliseconds(500);
        assert_eq!(rfc3339_nano(&time), "2026-09-24T13:00:01.5+03:00");
    }

    #[test]
    fn negative_offset_uses_minus_sign() {
        let offset = FixedOffset::west_opt(5 * 3600).unwrap();
        let time = offset.with_ymd_and_hms(2026, 9, 24, 13, 0, 0).unwrap();
        assert_eq!(rfc3339_nano(&time), "2026-09-24T13:00:00-05:00");
    }

    #[test]
    fn sub_minute_negative_offset_rounds_the_sign_from_whole_minutes() {
        // the appendFormatRFC3339 takes the sign from `offset / 60`, so an offset under a minute
        // in magnitude (reachable only through a historical LMT-era zone) prints `+`.
        let offset = FixedOffset::west_opt(30).unwrap();
        let time = offset.with_ymd_and_hms(2026, 9, 24, 13, 0, 0).unwrap();
        assert_eq!(rfc3339_nano(&time), "2026-09-24T13:00:00+00:00");
    }

    #[test]
    fn zero_offset_uses_z() {
        let time = FixedOffset::east_opt(0).unwrap().with_ymd_and_hms(2026, 9, 24, 13, 0, 0).unwrap();
        assert_eq!(rfc3339_nano(&time), "2026-09-24T13:00:00Z");
    }

    #[test]
    fn to_wire_converts_into_the_given_zone_not_utc() {
        let time: DateTime<Utc> = Utc.with_ymd_and_hms(2026, 9, 24, 13, 0, 0).unwrap();
        let tz = FixedOffset::east_opt(9 * 3600).unwrap();
        assert_eq!(to_wire(&time, &tz), "2026-09-24T22:00:00+09:00");
    }

    #[test]
    fn serialize_carries_the_local_offset_not_utc() {
        let time: DateTime<Utc> = Utc.with_ymd_and_hms(2026, 9, 24, 13, 0, 0).unwrap();
        let json = serde_json::to_string(&Wrapper { time }).unwrap();
        let expected = to_wire(&time, &Local);
        assert_eq!(json, format!(r#"{{"time":"{expected}"}}"#));
    }

    #[test]
    fn the_zero_time_keeps_zero_values_zulu_form() {
        let json = serde_json::to_string(&Wrapper { time: crate::time::zero_time() }).unwrap();
        assert_eq!(json, r#"{"time":"0001-01-01T00:00:00Z"}"#);
    }

    #[test]
    fn round_trips_through_deserialize() {
        let original = Utc.with_ymd_and_hms(2026, 9, 24, 10, 0, 0).unwrap();
        let json = serde_json::to_string(&Wrapper { time: original }).unwrap();
        let back: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(back.time, original);
    }
}
