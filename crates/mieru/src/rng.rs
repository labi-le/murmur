//! Two families live here.
//!
//! The `fixed_*` ones are deterministic functions of a hint string, which is what makes a traffic
//! pattern's implicit options reproducible: the same seed must always produce the same pattern,
//! on any host. The rest are ordinary random draws, shaped so that padding lengths and fragment
//! sizes keep mieru's shape (a bias toward small values) rather than being uniform.

use rand::Rng;
use sha2::{Digest, Sha256};

/// `FixedInt`: `sha256(hint)`, top bit cleared, first four bytes big-endian, modulo `n`.
#[must_use]
pub fn fixed_int(n: i32, hint: &str) -> i32 {
    if n <= 0 {
        return 0;
    }
    fixed_value(hint) % n
}

/// `FixedIntV`: as [`fixed_int`], but the hint is salted with the app version so that a release
/// bump reshuffles the derived values.
#[must_use]
pub fn fixed_int_v(n: i32, hint: &str) -> i32 {
    if n <= 0 {
        return 0;
    }
    fixed_value(&format!("{hint} {APP_VERSION}")) % n
}

/// `FixedIntVH`: [`fixed_int_v`] keyed on the host, so every process on a machine agrees on
/// values that are stable for that machine but need not match anyone else's.
#[must_use]
pub fn fixed_int_vh(n: i32) -> i32 {
    fixed_int_v(n, &host_hint())
}

const APP_VERSION: &str = "3.37.0";

fn fixed_value(hint: &str) -> i32 {
    let digest: [u8; 32] = Sha256::digest(hint.as_bytes()).into();
    let [mut first, second, third, fourth, ..] = digest;
    first &= 0b0111_1111;
    i32::from_be_bytes([first, second, third, fourth])
}

/// The host identity [`fixed_int_vh`] keys on. The OS hostname is read directly; falling back to a
/// fixed string keeps the function total, at the cost of two hosts that happen to be unnamed
/// agreeing.
#[must_use]
pub fn host_hint() -> String {
    hostname().unwrap_or_else(|| "mieru".to_owned())
}

fn hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
}

/// A draw from `[0, n]` scaled down by `sqrt(u^3)`, so results cluster toward the low
/// end.
///
/// Padding lengths and inter-fragment gaps both use this shape; a uniform draw would make small
/// padding conspicuously rare.
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "`n` is a padding length far below 2^53, where f64 loses integer precision"
)]
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the product of a non-negative draw and a factor in `[0, 1)` stays within `[0, draw]`"
)]
pub fn intn(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let draw = rand::rng().random_range(0..=n) as f64;
    (draw * scale_down()) as usize
}

/// A uniform value in the half-open range `[m, n)`.
#[must_use]
pub fn int_range(m: usize, n: usize) -> usize {
    m + intn(n.saturating_sub(m))
}

fn scale_down() -> f64 {
    let base = rand::rng().random::<f64>();
    (base * base * base).sqrt()
}

/// A `u32` with exactly `n` set bits.
#[must_use]
pub fn uint32_with_bits(n: u32) -> u32 {
    let mut positions: Vec<u32> = (0..32).collect();
    let mut result = 0u32;
    let mut rng = rand::rng();
    for i in 0..n.min(32) as usize {
        let j = i + rng.random_range(0..positions.len() - i);
        positions.swap(i, j);
        if let Some(&position) = positions.get(i) {
            result |= 1 << position;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_values_depend_only_on_the_hint() {
        assert_eq!(fixed_int(100, "42:nonce.type"), fixed_int(100, "42:nonce.type"));
        assert_ne!(fixed_int(100, "42:nonce.type"), fixed_int(100, "43:nonce.type"));
    }

    #[test]
    fn fixed_values_stay_in_range_and_clear_the_sign_bit() {
        for n in 1..64 {
            let value = fixed_int(n, "0:probe");
            assert!((0..n).contains(&value), "n {n} produced {value}");
            assert!(value >= 0);
        }
        assert_eq!(fixed_int(0, "x"), 0);
        assert_eq!(fixed_int(-5, "x"), 0);
    }

    #[test]
    fn versioned_and_host_variants_differ_from_the_plain_one() {
        assert_ne!(fixed_int(1000, "probe"), fixed_int_v(1000, "probe"));
        assert_eq!(fixed_int_vh(1000), fixed_int_vh(1000));
    }

    #[test]
    fn intn_stays_in_range_and_favors_small_values() {
        let mut histogram = [0usize; 5];
        for _ in 0..20_000 {
            let value = intn(4);
            assert!((0..=4).contains(&value), "{value}");
            histogram[value] += 1;
        }
        assert!(histogram[0] > histogram[4], "scaling failed, histogram {histogram:?}");
    }

    #[test]
    fn int_range_shifts_the_draw() {
        for _ in 0..1000 {
            let value = int_range(10, 14);
            assert!((10..=14).contains(&value), "{value}");
        }
    }

    #[test]
    fn uint32_with_bits_sets_exactly_the_requested_count() {
        for n in 0..=32 {
            let value = uint32_with_bits(n);
            assert_eq!(value.count_ones(), n, "n {n} produced {value:#x}");
        }
    }
}
