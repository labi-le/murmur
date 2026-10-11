use std::collections::HashMap;

use anyhow::Result;
use regex::Regex;

use super::ac_automaton_matcher::{new_ac_automaton, ACAutomaton};
use super::matchers::RegexMatcher;
use super::strmatcher::{IndexMatcher, MatcherEntry, Type};

/// `PrimeRK` is the prime base used in Rabin-Karp algorithm.
pub const PRIME_RK: u32 = 16777619;

/// `RollingHash` calculates the rolling hash of given string.
#[must_use]
pub fn rolling_hash(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut h: u32 = 0;
    for &byte in bytes.iter().rev() {
        h = h.wrapping_mul(PRIME_RK).wrapping_add(u32::from(byte));
    }
    h
}

/// A `MphMatcherGroup` is divided into three parts:
/// 1. `full` and `domain` patterns are matched by Rabin-Karp algorithm and minimal perfect hash table;
/// 2. `substr` patterns are matched by ac automaton;
/// 3. `regex` patterns are matched with the regex library.
#[derive(Debug)]
pub struct MphMatcherGroup {
    pub(crate) ac: Option<ACAutomaton>,
    pub(crate) other_matchers: Vec<MatcherEntry>,
    pub(crate) rules: Vec<String>,
    pub(crate) level0: Vec<u32>,
    pub(crate) level0_mask: usize,
    pub(crate) level1: Vec<u32>,
    pub(crate) level1_mask: usize,
    pub(crate) count: u32,
    pub(crate) rule_map: Option<HashMap<String, u32>>,
}

impl MphMatcherGroup {
    #[expect(
        clippy::panic,
        reason = "the rule map is present until `build` takes it, so adding a pattern afterwards is \
                  a caller bug that must abort instead of dropping the rule"
    )]
    pub fn add_full_or_domain_pattern(&mut self, pattern: &str, t: Type) {
        let h = rolling_hash(pattern);
        if t != Type::Domain && t != Type::Full {
            return;
        }
        let Some(rule_map) = self.rule_map.as_mut() else {
            panic!("assignment to entry in nil map");
        };
        if t == Type::Domain {
            rule_map.insert(format!(".{pattern}"), h.wrapping_mul(PRIME_RK).wrapping_add(u32::from(b'.')));
        }
        rule_map.insert(pattern.to_owned(), h);
    }

    #[must_use]
    pub fn new_mph_matcher_group() -> Self {
        Self {
            ac: None,
            other_matchers: Vec::new(),
            rules: Vec::new(),
            level0: Vec::new(),
            level0_mask: 0,
            level1: Vec::new(),
            level1_mask: 0,
            count: 1,
            rule_map: Some(HashMap::new()),
        }
    }

    /// Adds a pattern to the group.
    pub fn add_pattern(&mut self, pattern: &str, t: Type) -> Result<u32> {
        match t {
            Type::Substr => {
                let ac = self.ac.get_or_insert_with(new_ac_automaton);
                ac.add(pattern, t);
            }
            Type::Full | Type::Domain => {
                let pattern = pattern.to_lowercase();
                self.add_full_or_domain_pattern(&pattern, t);
            }
            Type::Regex => {
                let r = Regex::new(pattern)?;
                self.other_matchers.push(MatcherEntry { m: Box::new(RegexMatcher { pattern: r }), id: self.count });
            }
        }
        Ok(self.count)
    }

    /// Builds a minimal perfect hash table and ac automaton from insert rules.
    #[expect(
        clippy::panic,
        reason = "`build` takes the rule map, so a second build is a caller bug that must abort \
                  instead of publishing an empty table"
    )]
    #[expect(
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        reason = "the masks are `len - 1` over power-of-two tables that supply every slot index, and \
                  the hash and rule id are truncated to the table's 32-bit cell width by design"
    )]
    pub fn build(&mut self) {
        if let Some(ac) = self.ac.as_mut() {
            ac.build();
        }
        let Some(mut rule_map) = self.rule_map.take() else {
            panic!("invalid memory address or nil pointer dereference");
        };
        let mut key_len = rule_map.len();
        if key_len == 0 {
            key_len = 1;
            rule_map.insert("empty___".to_owned(), rolling_hash("empty___"));
        }
        self.level0 = vec![0u32; next_pow2(key_len / 4)];
        self.level0_mask = self.level0.len() - 1;
        self.level1 = vec![0u32; next_pow2(key_len)];
        self.level1_mask = self.level1.len() - 1;
        let mut sparse_buckets: Vec<Vec<usize>> = vec![Vec::new(); self.level0.len()];
        for (rule_idx, (rule, hash)) in rule_map.iter().enumerate() {
            let n = (*hash as usize) & self.level0_mask;
            self.rules.push(rule.clone());
            sparse_buckets[n].push(rule_idx);
        }

        let mut buckets: Vec<IndexBucket> = Vec::new();
        for (n, vals) in sparse_buckets.into_iter().enumerate() {
            if !vals.is_empty() {
                buckets.push(IndexBucket { n, vals });
            }
        }
        buckets.sort_by_key(|b| std::cmp::Reverse(b.vals.len()));

        let mut occ = vec![false; self.level1.len()];
        let mut tmp_occ: Vec<usize> = Vec::new();
        for bucket in buckets {
            let mut seed: u32 = 0;
            loop {
                let mut find_seed = true;
                tmp_occ.clear();
                for &i in &bucket.vals {
                    let n = (strhash_fallback(&self.rules[i], u64::from(seed)) as usize) & self.level1_mask;
                    if occ[n] {
                        for &n in &tmp_occ {
                            occ[n] = false;
                        }
                        seed = seed.wrapping_add(1);
                        find_seed = false;
                        break;
                    }
                    occ[n] = true;
                    tmp_occ.push(n);
                    self.level1[n] = i as u32;
                }
                if find_seed {
                    self.level0[bucket.n] = seed;
                    break;
                }
            }
        }
    }

    /// `Lookup` searches for `s` in `t` and returns whether it was found.
    #[must_use]
    #[expect(
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        reason = "`i0` and `i1` are masked with their own table's `len - 1` mask, `n` is a slot \
                  `build` filled, and the hash is truncated to the table's cell width by design"
    )]
    pub fn lookup(&self, h: u32, s: &str) -> bool {
        let i0 = (h as usize) & self.level0_mask;
        let seed = self.level0[i0];
        let i1 = (strhash_fallback(s, u64::from(seed)) as usize) & self.level1_mask;
        let n = self.level1[i1];
        s == self.rules[n as usize]
    }

    /// Implements `IndexMatcher`.
    #[must_use]
    pub fn match_(&self, pattern: &str) -> Vec<u32> {
        let mut result: Vec<u32> = Vec::new();
        let mut hash: u32 = 0;
        let bytes = pattern.as_bytes();
        for (i, &byte) in bytes.iter().enumerate().rev() {
            hash = hash.wrapping_mul(PRIME_RK).wrapping_add(u32::from(byte));
            if byte == b'.' && pattern.get(i..).is_some_and(|rest| self.lookup(hash, rest)) {
                result.push(1);
                return result;
            }
        }
        if self.lookup(hash, pattern) {
            result.push(1);
            return result;
        }
        if let Some(ac) = self.ac.as_ref() {
            if ac.match_(pattern) {
                result.push(1);
                return result;
            }
        }
        for e in &self.other_matchers {
            if e.m.match_(pattern) {
                result.push(e.id);
                return result;
            }
        }
        Vec::new()
    }
}

impl IndexMatcher for MphMatcherGroup {
    fn match_(&self, input: &str) -> Vec<u32> {
        Self::match_(self, input)
    }
}

struct IndexBucket {
    n: usize,
    vals: Vec<usize>,
}

const fn next_pow2(v: usize) -> usize {
    if v <= 1 {
        1
    } else {
        (v + 1).next_power_of_two()
    }
}

/// Hashes the bytes the argument refers to, so the length and the contents are all this needs.
fn strhash_fallback(s: &str, h: u64) -> u64 {
    memhash_fallback(s.as_bytes(), h, s.len())
}

const M1: u64 = 16877499708836156737;
const M2: u64 = 2820277070424839065;
const M3: u64 = 9497967016996688599;
const M4: u64 = 15839092249703872147;

/// A 64-bit key on every supported target.
const HASHKEY: [u64; 4] = [1, 1, 1, 1];

/// Hashes `p`'s bytes under `seed`.
#[expect(
    clippy::indexing_slicing,
    reason = "`off` and `n` track the unread remainder of `p`, so every read of a short tail stays \
              inside the slice"
)]
fn memhash_fallback(p: &[u8], seed: u64, s: usize) -> u64 {
    let mut h = seed.wrapping_add((s as u64).wrapping_mul(HASHKEY[0]));
    let mut n = s;
    let mut off = 0usize;
    loop {
        if n == 0 {
            break;
        }
        if n < 4 {
            h ^= u64::from(p[off]);
            h ^= u64::from(p[off + (n >> 1)]) << 8;
            h ^= u64::from(p[off + n - 1]) << 16;
            h = h.wrapping_mul(M1).rotate_left(31).wrapping_mul(M2);
            break;
        }
        if n <= 8 {
            h ^= u64::from(read_unaligned32(p, off));
            h ^= u64::from(read_unaligned32(p, off + n - 4)) << 32;
            h = h.wrapping_mul(M1).rotate_left(31).wrapping_mul(M2);
            break;
        }
        if n <= 16 {
            h ^= read_unaligned64(p, off);
            h = h.wrapping_mul(M1).rotate_left(31).wrapping_mul(M2);
            h ^= read_unaligned64(p, off + n - 8);
            h = h.wrapping_mul(M1).rotate_left(31).wrapping_mul(M2);
            break;
        }
        if n <= 32 {
            h ^= read_unaligned64(p, off);
            h = h.wrapping_mul(M1).rotate_left(31).wrapping_mul(M2);
            h ^= read_unaligned64(p, off + 8);
            h = h.wrapping_mul(M1).rotate_left(31).wrapping_mul(M2);
            h ^= read_unaligned64(p, off + n - 16);
            h = h.wrapping_mul(M1).rotate_left(31).wrapping_mul(M2);
            h ^= read_unaligned64(p, off + n - 8);
            h = h.wrapping_mul(M1).rotate_left(31).wrapping_mul(M2);
            break;
        }
        let mut v1 = h;
        let mut v2 = seed.wrapping_mul(HASHKEY[1]);
        let mut v3 = seed.wrapping_mul(HASHKEY[2]);
        let mut v4 = seed.wrapping_mul(HASHKEY[3]);
        while n >= 32 {
            v1 ^= read_unaligned64(p, off);
            v1 = v1.wrapping_mul(M1).rotate_left(31).wrapping_mul(M2);
            off += 8;
            v2 ^= read_unaligned64(p, off);
            v2 = v2.wrapping_mul(M2).rotate_left(31).wrapping_mul(M3);
            off += 8;
            v3 ^= read_unaligned64(p, off);
            v3 = v3.wrapping_mul(M3).rotate_left(31).wrapping_mul(M4);
            off += 8;
            v4 ^= read_unaligned64(p, off);
            v4 = v4.wrapping_mul(M4).rotate_left(31).wrapping_mul(M1);
            off += 8;
            n -= 32;
        }
        h = v1 ^ v2 ^ v3 ^ v4;
    }

    h ^= h >> 29;
    h = h.wrapping_mul(M3);
    h ^= h >> 32;
    h
}

#[expect(
    clippy::indexing_slicing,
    reason = "the callers bound `off` and the field width against `p.len()` before every read"
)]
fn read_unaligned32(p: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([p[off], p[off + 1], p[off + 2], p[off + 3]])
}

#[expect(
    clippy::indexing_slicing,
    reason = "the callers bound `off` and the field width against `p.len()` before every read"
)]
fn read_unaligned64(p: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([p[off], p[off + 1], p[off + 2], p[off + 3], p[off + 4], p[off + 5], p[off + 6], p[off + 7]])
}
