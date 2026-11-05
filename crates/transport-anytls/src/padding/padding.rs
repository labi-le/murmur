use std::sync::Arc;

use arc_swap::ArcSwapOption;
use md5::{Digest, Md5};
use rand::Rng;

use crate::util::string_map::{string_map_from_bytes, StringMap};

pub const CHECK_MARK: i32 = -1;

pub static DEFAULT_PADDING_SCHEME: &[u8] = br"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

#[derive(Debug)]
pub struct PaddingFactory {
    pub(crate) scheme: StringMap,
    pub raw_scheme: Vec<u8>,
    pub stop: u32,
    pub md5: String,
}

pub fn update_padding_scheme(raw_scheme: &[u8], to: &ArcSwapOption<PaddingFactory>) -> bool {
    let Some(p) = new_padding_factory(raw_scheme) else {
        return false;
    };
    to.store(Some(Arc::new(p)));
    true
}

/// Builds a `PaddingFactory` from a raw scheme, returning `None` when the scheme is invalid.
pub fn new_padding_factory(raw_scheme: &[u8]) -> Option<PaddingFactory> {
    let mut p = PaddingFactory {
        scheme: StringMap::new(),
        raw_scheme: raw_scheme.to_vec(),
        stop: 0,
        md5: hex::encode(Md5::digest(raw_scheme)),
    };
    let scheme = string_map_from_bytes(raw_scheme);
    if scheme.is_empty() {
        return None;
    }
    match scheme.get("stop").map_or("", String::as_str).parse::<i32>() {
        Ok(stop) => p.stop = stop.cast_unsigned(),
        Err(_) => return None,
    }
    p.scheme = scheme;
    Some(p)
}

impl PaddingFactory {
    #[must_use]
    pub fn generate_record_payload_sizes(&self, pkt: u32) -> Vec<i32> {
        let mut pkt_sizes: Vec<i32> = Vec::new();
        if let Some(s) = self.scheme.get(&pkt.to_string()) {
            let s_ranges = s.split(',');
            for s_range in s_ranges {
                let mut parts = s_range.split('-');
                let (Some(min), Some(max), None) = (parts.next(), parts.next(), parts.next()) else {
                    if s_range == "c" {
                        pkt_sizes.push(CHECK_MARK);
                    }
                    continue;
                };
                let Ok(mut min) = min.parse::<i64>() else {
                    continue;
                };
                let Ok(mut max) = max.parse::<i64>() else {
                    continue;
                };
                if min > max {
                    std::mem::swap(&mut min, &mut max);
                }
                if min <= 0 || max <= 0 {
                    continue;
                }
                let (Ok(min), Ok(max)) = (i32::try_from(min), i32::try_from(max)) else {
                    continue;
                };
                if min == max {
                    pkt_sizes.push(min);
                } else {
                    let i = rand::rng().random_range(0..(max - min));
                    pkt_sizes.push(i + min);
                }
            }
        }
        pkt_sizes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the P2 finding: a malicious server's `CMD_UPDATE_PADDING_SCHEME`
    /// range like `4294967294-4294967294` used to survive the `min <= 0 || max <= 0` guard (it
    /// runs on the parsed `i64`) and then wrap to a negative `i32` (`-2`) via `as i32`, which the
    /// client later fed into `waste_frame`'s length arithmetic and panicked/OOM'd on. Values that
    /// do not fit in `i32` must be skipped instead of silently truncated.
    #[test]
    fn generate_record_payload_sizes_rejects_ranges_outside_i32() {
        let raw = b"stop=8\n1=4294967294-4294967294,4294967296-4294967297";
        let factory = new_padding_factory(raw).expect("valid scheme header");
        let sizes = factory.generate_record_payload_sizes(1);
        assert!(sizes.is_empty(), "out-of-i32-range entries must be skipped, not wrapped into a negative or huge size");
    }

    #[test]
    fn generate_record_payload_sizes_keeps_valid_i32_ranges() {
        let raw = b"stop=8\n1=100-100";
        let factory = new_padding_factory(raw).expect("valid scheme header");
        let sizes = factory.generate_record_payload_sizes(1);
        assert_eq!(sizes, vec![100]);
    }
}
