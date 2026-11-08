use std::sync::LazyLock;

use regex::Regex;

/// `\s` is spelled out because the Rust regex crate's `\s` is Unicode-aware.
#[expect(
    clippy::expect_used,
    reason = "the pattern is a fixed literal, so a failure here can only be a source-level mistake, and a `LazyLock` initializer has no error channel"
)]
static RATE_STRING_REGEXP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([0-9]+)[ \t\n\f\r]*([KMGT]?)([Bb])ps$").expect("rate string regexp is valid"));

pub fn string_to_bps(s: &str) -> u64 {
    if s.is_empty() {
        return 0;
    }

    // when have not unit, use Mbps
    if let Ok(v) = s.parse::<i64>() {
        return string_to_bps(&format!("{v} Mbps"));
    }

    let Some(m) = RATE_STRING_REGEXP.captures(s) else {
        return 0;
    };
    let unit = &m[2];
    let mut n: u64 = 1;
    // A unit falls through into every smaller one.
    if matches!(unit, "T" | "G" | "M" | "K") {
        n = n.wrapping_mul(1000);
    }
    if matches!(unit, "T" | "G" | "M") {
        n = n.wrapping_mul(1000);
    }
    if matches!(unit, "T" | "G") {
        n = n.wrapping_mul(1000);
    }
    if unit == "T" {
        n = n.wrapping_mul(1000);
    }
    let v: u64 = m[1].parse().unwrap_or(0);
    n = n.wrapping_mul(v);
    if &m[3] == "b" {
        // Bits, need to convert to bytes
        n /= 8;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_to_bps() {
        assert_eq!(string_to_bps(""), 0);
        assert_eq!(string_to_bps("Mbps"), 0);
        assert_eq!(string_to_bps("1.5"), 0);
        assert_eq!(string_to_bps("1000"), 125_000_000);
        assert_eq!(string_to_bps("100 Mbps"), 12_500_000);
        assert_eq!(string_to_bps("1 Kbps"), 125);
        assert_eq!(string_to_bps("1 KBps"), 1000);
        assert_eq!(string_to_bps("1 Mbps"), 125_000);
        assert_eq!(string_to_bps("1 Gbps"), 125_000_000);
        assert_eq!(string_to_bps("1 Tbps"), 125_000_000_000);
    }
}
