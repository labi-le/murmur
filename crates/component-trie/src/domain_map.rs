use std::collections::HashMap;

use anyhow::Result;

use super::domain::{COMPLEX_WILDCARD, DOMAIN_STEP_CHAR, WILDCARD};
use super::domain_set::{
    bitmap, build_domain_set, byte_reverse, get_bit, index_of, rev_lower_at, select_ith_one, DomainSet,
    DomainSetBuilder, COMPLEX_WILDCARD_BYTE, DOMAIN_STEP_BYTE, WILDCARD_BYTE,
};
use murmur_common::utils::strings::reverse;

pub(crate) const DOMAIN_MAP_SELECT_OVERFLOW: u8 = u8::MAX;

/// `DomainMap` is an immutable domain-pattern index with values.
///
/// Lookup prefers exact labels, then single-label wildcards, then suffix wildcards. An empty map
/// behaves the same as the zero value.
#[derive(Debug)]
pub struct DomainMap<T> {
    pub(crate) index: DomainMapIndex,
    pub(crate) leaf_ranks: Vec<i32>,
    pub(crate) values: Vec<T>,
}

#[derive(Debug, Default)]
pub(crate) struct DomainMapIndex {
    pub(crate) domain_set: Option<DomainSet>,
    pub(crate) select_deltas: Vec<u8>,
}

/// `DomainMapBuilder` collects patterns and values. Its zero value is ready to use.
/// Insert and Build must not run concurrently on the same builder.
#[derive(Debug)]
pub struct DomainMapBuilder<T> {
    pub(crate) set: DomainSetBuilder,
    pub(crate) value_keys: HashMap<String, T>,
}

impl<T> Default for DomainMapBuilder<T> {
    fn default() -> Self {
        Self { set: DomainSetBuilder::default(), value_keys: HashMap::new() }
    }
}

impl<T: Clone> DomainMapBuilder<T> {
    /// Insert accepts the same patterns as [`crate::domain::DomainTrie::insert`]. The last insertion wins
    /// for each expanded terminal; +.domain assigns both the exact and suffix values.
    pub fn insert(&mut self, domain: &str, value: T) -> Result<()> {
        let begin = self.set.keys.len();
        self.set.insert(domain)?;
        for key in self.set.keys.iter().skip(begin) {
            self.value_keys.insert(key.clone(), value.clone());
        }
        Ok(())
    }
}

impl<T> DomainMapBuilder<T> {
    /// `IsEmpty` reports whether the builder has any domain paths.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Reset discards pending patterns and values without changing previously built maps.
    pub fn reset(&mut self) {
        self.set.reset();
        self.value_keys.clear();
    }

    /// Build consumes the builder's inputs and creates an immutable map. It returns None
    /// for an empty builder. The builder can be reused without changing earlier maps.
    pub fn build(&mut self) -> Option<DomainMap<T>> {
        let keys = std::mem::take(&mut self.set.keys);
        let mut value_keys = std::mem::take(&mut self.value_keys);
        if keys.is_empty() {
            return None;
        }
        let mut values: Vec<T> = Vec::with_capacity(value_keys.len());
        let set = {
            let on_terminal: &mut dyn FnMut(&str) = &mut |key: &str| {
                if let Some(value) = value_keys.remove(key) {
                    values.push(value);
                }
            };
            build_domain_set(keys, Some(on_terminal))
        };
        let mut mapping = DomainMap {
            index: DomainMapIndex { domain_set: set, select_deltas: Vec::new() },
            leaf_ranks: Vec::new(),
            values,
        };
        mapping.init();
        Some(mapping)
    }
}

impl<T> Default for DomainMap<T> {
    fn default() -> Self {
        Self { index: DomainMapIndex::default(), leaf_ranks: Vec::new(), values: Vec::new() }
    }
}

impl<T> DomainMap<T> {
    /// `IsEmpty` reports whether the map contains any values.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// `DomainSet` returns the underlying domain set without copying it.
    /// The returned set is read-only. An empty map returns None.
    #[must_use]
    pub const fn domain_set(&self) -> Option<&DomainSet> {
        self.index.domain_set.as_ref()
    }

    /// Lookup returns the most specific matching value. Like [`DomainSet::has`], Lookup
    /// matches names without validating query syntax.
    #[must_use]
    pub fn lookup(&self, domain: &str) -> Option<&T> {
        if self.is_empty() {
            return None;
        }
        let lowered: std::borrow::Cow<'_, str> = if domain.bytes().any(|b| !b.is_ascii()) {
            std::borrow::Cow::Owned(domain.to_lowercase())
        } else {
            std::borrow::Cow::Borrowed(domain)
        };
        let node_id = self.index.match_(0, &lowered);
        if node_id < 0 {
            return None;
        }
        let set = self.index.set();
        let (rank, _) = bitmap::rank_64(&set.leaves, &self.leaf_ranks, node_id);
        self.values.get(index_of(rank))
    }

    /// Foreach iterates over the stored domain patterns and their associated values
    /// in unspecified order. Returning false stops iteration.
    pub fn foreach<F>(&self, mut f: F)
    where
        F: FnMut(&str, &T) -> bool,
    {
        if self.is_empty() {
            return;
        }
        let set = self.index.set();
        set.keys(|key, node_id| {
            let (rank, _) = bitmap::rank_64(&set.leaves, &self.leaf_ranks, node_id);
            let key = String::from_utf8_lossy(key);
            let trimmed: &str = match key.strip_suffix(COMPLEX_WILDCARD) {
                Some(trimmed) => trimmed,
                None => &key,
            };
            self.values.get(index_of(rank)).is_none_or(|value| f(&reverse(trimmed), value))
        });
    }

    /// Builds the pre-calculated cache that speeds up ranking and selection.
    pub(crate) fn init(&mut self) {
        let set = self.index.set();
        self.leaf_ranks = bitmap::index_rank_64(&set.leaves, false);
        self.index.init_select_deltas();
    }
}

impl DomainMapIndex {
    /// The domain set, or the empty set for an index whose map has no patterns.
    pub(crate) fn set(&self) -> &DomainSet {
        static EMPTY: DomainSet = DomainSet {
            leaves: Vec::new(),
            label_bitmap: Vec::new(),
            labels: Vec::new(),
            ranks: Vec::new(),
            selects: Vec::new(),
        };
        self.domain_set.as_ref().unwrap_or(&EMPTY)
    }

    /// The cached select delta at `index`, or the sentinel for an index outside the cache.
    fn delta_at(&self, index: i32) -> u8 {
        self.select_deltas.get(index_of(index)).copied().unwrap_or(DOMAIN_MAP_SELECT_OVERFLOW)
    }

    fn init_select_deltas(&mut self) {
        let set = self.set();
        let mut select_deltas = vec![0u8; set.labels.len()];
        for (ordinal, select_delta) in select_deltas.iter_mut().enumerate() {
            let Ok(ordinal) = i32::try_from(ordinal) else {
                continue;
            };
            let position = select_ith_one(&set.label_bitmap, &set.ranks, &set.selects, ordinal);
            let Some(base) = set.selects.get(index_of(ordinal >> 5)) else {
                continue;
            };
            let delta = position - base;
            *select_delta = if delta < 0 || delta >= i32::from(DOMAIN_MAP_SELECT_OVERFLOW) {
                DOMAIN_MAP_SELECT_OVERFLOW
            } else {
                u8::try_from(delta).unwrap_or(DOMAIN_MAP_SELECT_OVERFLOW)
            };
        }
        self.select_deltas = select_deltas;
    }

    fn child_start(&self, ordinal: i32, delta: u8) -> i32 {
        if delta == DOMAIN_MAP_SELECT_OVERFLOW {
            return self.uncached_child_start(ordinal);
        }
        let Some(base) = self.set().selects.get(index_of(ordinal >> 5)).copied() else {
            return self.uncached_child_start(ordinal);
        };
        base + i32::from(delta) + 1
    }

    fn uncached_child_start(&self, ordinal: i32) -> i32 {
        let set = self.set();
        select_ith_one(&set.label_bitmap, &set.ranks, &set.selects, ordinal) + 1
    }

    /// match consumes one domain label per recursive step, like `DomainTrie::search_node`.
    /// Each branch gets its own remaining prefix, so failed matches cannot consume it.
    fn match_(&self, mut node_id: i32, domain: &str) -> i32 {
        let set = self.set();
        if domain.is_empty() {
            if get_bit(&set.leaves, node_id) != 0 {
                return node_id;
            }
            return -1;
        }
        let mut bitmap_index: i32 = 0;
        if node_id > 0 {
            bitmap_index = self.child_start(node_id - 1, self.delta_at(node_id - 1));
            while get_bit(&set.label_bitmap, bitmap_index) == 0
                && set.label_at(bitmap_index - node_id).is_some_and(|at| at < DOMAIN_STEP_BYTE)
            {
                bitmap_index += 1;
            }
            if get_bit(&set.label_bitmap, bitmap_index) != 0
                || set.label_at(bitmap_index - node_id) != Some(DOMAIN_STEP_BYTE)
            {
                return -1;
            }
            node_id = bitmap_index - node_id + 1;
            bitmap_index = self.child_start(node_id - 1, self.delta_at(node_id - 1));
        }
        let (remaining, part) = domain.rsplit_once(DOMAIN_STEP_CHAR).unwrap_or(("", domain));
        let part_cow: std::borrow::Cow<'_, [u8]> = if part.is_ascii() {
            std::borrow::Cow::Borrowed(part.as_bytes())
        } else {
            std::borrow::Cow::Owned(byte_reverse(reverse(part).as_bytes()))
        };
        let part: &[u8] = &part_cow;
        let mut static_node = node_id;
        let mut static_index = bitmap_index;
        for offset in 0..part.len() {
            let label = rev_lower_at(part, offset);
            while get_bit(&set.label_bitmap, static_index) == 0
                && set.label_at(static_index - static_node).is_some_and(|at| at < label)
            {
                static_index += 1;
            }
            if get_bit(&set.label_bitmap, static_index) != 0
                || set.label_at(static_index - static_node) != Some(label)
                || label == COMPLEX_WILDCARD_BYTE
            {
                static_node = -1;
                break;
            }
            static_node = static_index - static_node + 1;
            if offset + 1 < part.len() {
                static_index = self.child_start(static_node - 1, self.delta_at(static_node - 1));
            }
        }
        if static_node >= 0 {
            let terminal = self.match_(static_node, remaining);
            if terminal >= 0 {
                return terminal;
            }
        }
        while get_bit(&set.label_bitmap, bitmap_index) == 0 {
            let Some(label) = set.label_at(bitmap_index - node_id) else {
                return -1;
            };
            let child_id = bitmap_index - node_id + 1;
            if label == WILDCARD_BYTE {
                if part != WILDCARD.as_bytes() {
                    let terminal = self.match_(child_id, remaining);
                    if terminal >= 0 {
                        return terminal;
                    }
                }
            } else if label == COMPLEX_WILDCARD_BYTE {
                return child_id;
            }
            if label > COMPLEX_WILDCARD_BYTE {
                break;
            }
            bitmap_index += 1;
        }
        -1
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::domain_map_bin::read_domain_map_bin;

    fn check_domain_map_lookup<'a, T>(mapping: &'a DomainMap<T>, query: &str) -> Option<&'a T> {
        let found = mapping.lookup(query);
        assert_eq!(found.is_some(), mapping.domain_set().is_some_and(|set| set.has(query)), "{query}");
        found
    }

    async fn test_domain_map_bin_i32(mapping: &DomainMap<i32>) -> DomainMap<i32> {
        let mut buffer: Vec<u8> = Vec::new();
        mapping
            .write_bin(&mut buffer, |value, out| {
                out.extend_from_slice(&value.to_be_bytes());
                Ok(())
            })
            .await
            .expect("write bin");
        let mut reader: &[u8] = &buffer;
        let restored = read_domain_map_bin(&mut reader, |bin| {
            if bin.len() < 4 {
                return Ok(None);
            }
            Ok(Some((i32::from_be_bytes([bin[0], bin[1], bin[2], bin[3]]), 4)))
        })
        .await
        .expect("read bin");

        let mut values: HashMap<String, i32> = HashMap::new();
        mapping.foreach(|domain, value| {
            values.insert(domain.to_owned(), *value);
            true
        });
        let mut restored_values: HashMap<String, i32> = HashMap::new();
        restored.foreach(|domain, value| {
            restored_values.insert(domain.to_owned(), *value);
            true
        });
        assert_eq!(values, restored_values);
        restored
    }

    async fn test_domain_map_bin_vec_i32(mapping: &DomainMap<Vec<i32>>) -> DomainMap<Vec<i32>> {
        let mut buffer: Vec<u8> = Vec::new();
        mapping
            .write_bin(&mut buffer, |value, out| {
                out.extend_from_slice(&(value.len() as u16).to_be_bytes());
                for item in value {
                    out.extend_from_slice(&item.to_be_bytes());
                }
                Ok(())
            })
            .await
            .expect("write bin");
        let mut reader: &[u8] = &buffer;
        let restored = read_domain_map_bin(&mut reader, |bin| {
            if bin.len() < 2 {
                return Ok(None);
            }
            let count = usize::from(u16::from_be_bytes([bin[0], bin[1]]));
            if bin.len() < 2 + count * 4 {
                return Ok(None);
            }
            let mut value = Vec::with_capacity(count);
            for index in 0..count {
                let start = 2 + index * 4;
                value.push(i32::from_be_bytes([bin[start], bin[start + 1], bin[start + 2], bin[start + 3]]));
            }
            Ok(Some((value, 2 + count * 4)))
        })
        .await
        .expect("read bin");

        let mut values: HashMap<String, Vec<i32>> = HashMap::new();
        mapping.foreach(|domain, value| {
            values.insert(domain.to_owned(), value.clone());
            true
        });
        let mut restored_values: HashMap<String, Vec<i32>> = HashMap::new();
        restored.foreach(|domain, value| {
            restored_values.insert(domain.to_owned(), value.clone());
            true
        });
        assert_eq!(values, restored_values);
        restored
    }

    async fn test_domain_map_bin_string(mapping: &DomainMap<String>) -> DomainMap<String> {
        let mut buffer: Vec<u8> = Vec::new();
        mapping
            .write_bin(&mut buffer, |value, out| {
                out.extend_from_slice(&(value.len() as u16).to_be_bytes());
                out.extend_from_slice(value.as_bytes());
                Ok(())
            })
            .await
            .expect("write bin");
        let mut reader: &[u8] = &buffer;
        let restored = read_domain_map_bin(&mut reader, |bin| {
            if bin.len() < 2 {
                return Ok(None);
            }
            let len = usize::from(u16::from_be_bytes([bin[0], bin[1]]));
            if bin.len() < 2 + len {
                return Ok(None);
            }
            let value = String::from_utf8_lossy(&bin[2..2 + len]).into_owned();
            Ok(Some((value, 2 + len)))
        })
        .await
        .expect("read bin");

        let mut values: HashMap<String, String> = HashMap::new();
        mapping.foreach(|domain, value| {
            values.insert(domain.to_owned(), value.clone());
            true
        });
        let mut restored_values: HashMap<String, String> = HashMap::new();
        restored.foreach(|domain, value| {
            restored_values.insert(domain.to_owned(), value.clone());
            true
        });
        assert_eq!(values, restored_values);
        restored
    }

    async fn test_domain_map_bin_unit(mapping: &DomainMap<()>) -> DomainMap<()> {
        let mut buffer: Vec<u8> = Vec::new();
        mapping.write_bin(&mut buffer, |_, _| Ok(())).await.expect("write bin");
        let mut reader: &[u8] = &buffer;
        let restored = read_domain_map_bin(&mut reader, |_| Ok(Some(((), 0)))).await.expect("read bin");

        let mut domains: Vec<String> = Vec::new();
        mapping.foreach(|domain, _| {
            domains.push(domain.to_owned());
            true
        });
        let mut restored_domains: Vec<String> = Vec::new();
        restored.foreach(|domain, _| {
            restored_domains.push(domain.to_owned());
            true
        });
        domains.sort();
        restored_domains.sort();
        assert_eq!(domains, restored_domains);
        restored
    }

    fn check_domain_map_queries(mapping: &DomainMap<i32>, queries: &[(&str, i32)]) {
        for &(query, expected) in queries {
            let found = check_domain_map_lookup(mapping, query);
            assert_eq!(found.is_some(), expected != 0, "{query}");
            assert_eq!(found.copied().unwrap_or(0), expected, "{query}");
        }
    }

    #[tokio::test]
    async fn test_domain_map_lifecycle() {
        let mut nil_builder = DomainMapBuilder::<i32>::default();
        assert!(nil_builder.is_empty());
        assert!(nil_builder.build().is_none());

        let empty_map = DomainMap::<i32>::default();
        for mapping in [&empty_map] {
            assert!(mapping.is_empty());
            assert!(mapping.domain_set().is_none());
            let found = check_domain_map_lookup(mapping, "example.com");
            assert!(found.is_none());
            let mut calls = 0;
            mapping.foreach(|_, _| {
                calls += 1;
                true
            });
            assert_eq!(calls, 0);
            let mut buffer: Vec<u8> = Vec::new();
            let called = std::cell::Cell::new(false);
            let result = mapping
                .write_bin(&mut buffer, |_, _| {
                    called.set(true);
                    Ok(())
                })
                .await;
            assert!(result.is_err());
            assert!(!called.get());
            assert!(buffer.is_empty());
        }

        let mut builder = DomainMapBuilder::<i32>::default();
        assert!(builder.is_empty());
        assert!(builder.build().is_none());
        for domain in [
            "",
            ".",
            "..dev",
            "example.com.",
            " example.com",
            "example.com ",
            "invalid..example",
            "stun.+",
            "a.+.b",
            "a.+",
            "+",
            "+.+.com",
            "a+b.com",
            "a*b.com",
            "*a.com",
            "a*.com",
        ] {
            let err = builder.insert(domain, 1).expect_err("invalid domain");
            assert!(err.downcast_ref::<crate::domain::InvalidDomainError>().is_some(), "{domain}");
            assert!(builder.is_empty(), "{domain}");
        }

        assert!(builder.insert("+.example.com", 1).is_ok());
        assert!(builder.insert("example.com", 2).is_ok());
        assert!(builder.insert(".example.com", 3).is_ok());
        assert!(!builder.is_empty());
        let mapping = builder.build().expect("mapping");
        assert!(!mapping.is_empty());
        assert!(builder.is_empty());
        assert!(builder.build().is_none());
        for (query, expected) in [("example.com", 2), ("www.example.com", 3), ("a.b.example.com", 3)] {
            let value = check_domain_map_lookup(&mapping, query).expect(query);
            assert_eq!(*value, expected, "{query}");
        }

        assert!(builder.insert("+.other.example", 0).is_ok());
        let next = builder.build().expect("mapping");
        assert!(builder.insert("reset.example", 4).is_ok());
        builder.reset();
        assert!(builder.is_empty());
        assert!(builder.build().is_none());
        assert!(builder.insert("fresh.example", 5).is_ok());
        let fresh = builder.build().expect("mapping");
        let value = check_domain_map_lookup(&fresh, "fresh.example").expect("found");
        assert_eq!(*value, 5);
        let found = check_domain_map_lookup(&fresh, "reset.example");
        assert!(found.is_none());

        let value = check_domain_map_lookup(&mapping, "www.example.com").expect("found");
        assert_eq!(*value, 3);
        assert!(check_domain_map_lookup(&mapping, "www.other.example").is_none());
        assert!(check_domain_map_lookup(&mapping, "fresh.example").is_none());
        let found = check_domain_map_lookup(&next, "www.example.com");
        assert!(found.is_none());
        let value = check_domain_map_lookup(&next, "www.other.example").expect("found");
        assert_eq!(*value, 0);
    }

    #[tokio::test]
    async fn test_domain_map_values() {
        let mut builder = DomainMapBuilder::<Vec<i32>>::default();
        assert!(builder.insert("+.example.com", vec![1]).is_ok());
        assert!(builder.insert("+.EXAMPLE.COM", vec![2]).is_ok());
        assert!(builder.insert("nil.example.com", Vec::new()).is_ok());
        let mapping = builder.build().expect("mapping");
        let restored = test_domain_map_bin_vec_i32(&mapping).await;
        for mapping in [&mapping, &restored] {
            for query in ["example.com", "www.example.com", "WwW.ExAmPlE.CoM"] {
                let value = check_domain_map_lookup(mapping, query).expect(query);
                assert_eq!(*value, vec![2], "{query}");
            }
            let value = check_domain_map_lookup(mapping, "nil.example.com").expect("found");
            assert!(value.is_empty());
            let found = check_domain_map_lookup(mapping, "missing.example");
            assert!(found.is_none());
            let mut values: HashMap<String, Vec<i32>> = HashMap::new();
            mapping.foreach(|domain, value| {
                values.insert(domain.to_owned(), value.clone());
                true
            });
            let expected: HashMap<String, Vec<i32>> =
                [("example.com", vec![2]), (".example.com", vec![2]), ("nil.example.com", Vec::new())]
                    .into_iter()
                    .map(|(domain, value)| (domain.to_owned(), value))
                    .collect();
            assert_eq!(values, expected);
        }

        let mut empty_builder = DomainMapBuilder::<()>::default();
        assert!(empty_builder.insert("+.example.com", ()).is_ok());
        let empty = empty_builder.build().expect("mapping");
        let empty_restored = test_domain_map_bin_unit(&empty).await;
        for empty in [&empty, &empty_restored] {
            for (query, expected) in
                [("example.com", true), ("www.example.com", true), ("a.b.example.com", true), ("example.net", false)]
            {
                assert_eq!(check_domain_map_lookup(empty, query).is_some(), expected, "{query}");
            }
        }
    }

    #[tokio::test]
    async fn test_domain_map_lookup() {
        let rules = [
            (".example.com", "suffix"),
            ("*.example.com", "single-label"),
            ("api.example.com", "api"),
            ("internal.*.example.com", "internal-service"),
            ("dead.a.example.com", "dead"),
            ("+.example.net", "net"),
            (".example.org", "org"),
            ("例子.测试", "unicode"),
            ("xn--fsqu00a.xn--0zwm56d", "punycode"),
            ("bücher.example", "books"),
            ("+.测试.cn", "unicode-suffix"),
            ("Mijia Cloud", "device"),
            ("_acme-challenge.example.com", "acme"),
            ("router", "local"),
        ];
        let mut builder = DomainMapBuilder::<String>::default();
        for (domain, value) in rules {
            assert!(builder.insert(domain, value.to_owned()).is_ok());
        }
        let mapping = builder.build().expect("mapping");
        let restored = test_domain_map_bin_string(&mapping).await;
        for mapping in [&mapping, &restored] {
            for (query, expected) in [
                ("", ""),
                ("api.example.com", "api"),
                ("API.EXAMPLE.COM", "api"),
                ("www.example.com", "single-label"),
                ("a.example.com", "single-label"),
                ("dead.a.example.com", "dead"),
                ("internal.service.example.com", "internal-service"),
                ("other.service.example.com", "suffix"),
                ("internal.other.service.example.com", "suffix"),
                ("example.com", ""),
                ("example.net", "net"),
                ("www.example.net", "net"),
                ("a.b.example.net", "net"),
                ("example.org", ""),
                ("www.example.org", "org"),
                ("example.test", ""),
                ("例子.测试", "unicode"),
                ("XN--FSQU00A.XN--0ZWM56D", "punycode"),
                ("BÜCHER.EXAMPLE", "books"),
                ("测试.cn", "unicode-suffix"),
                ("www.测试.cn", "unicode-suffix"),
                ("日本語.测试", ""),
                ("Mijia Cloud", "device"),
                ("MIJIA CLOUD", "device"),
                ("_acme-challenge.example.com", "acme"),
                ("ROUTER", "local"),
            ] {
                let value = check_domain_map_lookup(mapping, query);
                assert_eq!(value.is_some(), !expected.is_empty(), "{query}");
                assert_eq!(value.map(String::as_str).unwrap_or(""), expected, "{query}");
            }
        }
    }

    #[tokio::test]
    async fn test_domain_map_length_changing_case_fold() {
        use super::super::domain::DomainTrie;

        let mut tree = DomainTrie::<&str>::new();
        let mut builder = DomainMapBuilder::<&str>::default();
        for (domain, value) in [("i\u{307}.tr", "dotted-i"), ("ασ.gr", "sigma"), ("ας", "final-sigma")] {
            assert!(tree.insert(domain, value).is_ok());
            assert!(builder.insert(domain, value).is_ok());
        }
        let mapping = builder.build().expect("mapping");
        for (query, expected) in [("İ.tr", "dotted-i"), ("ΑΣ.gr", "sigma"), ("ΑΣ", "final-sigma")] {
            assert_eq!(tree.search(query).map(|node| *node.data()), Some(expected), "{query}");
            assert_eq!(check_domain_map_lookup(&mapping, query).copied(), Some(expected), "{query}");
        }
    }

    #[test]
    fn test_domain_map_unicode_wildcard_lookup() {
        let rules = [
            ("www.例子.测试", "exact"),
            ("*.例子.测试", "single-label"),
            (".例子.测试", "suffix"),
            ("+.🦀.测试", "astral-suffix"),
            ("a🦀b.example", "astral-exact"),
        ];
        let mut builder = DomainMapBuilder::<&str>::default();
        for (domain, value) in rules {
            assert!(builder.insert(domain, value).is_ok(), "{domain}");
        }
        let mapping = builder.build().expect("mapping");
        for (query, expected) in [
            ("www.例子.测试", "exact"),
            ("WWW.例子.测试", "exact"),
            ("a.例子.测试", "single-label"),
            ("b.a.例子.测试", "suffix"),
            ("例子.测试", ""),
            ("a🦀b.example", "astral-exact"),
            ("A🦀B.EXAMPLE", "astral-exact"),
            ("a🦀c.example", ""),
            ("🦀.测试", "astral-suffix"),
            ("x.🦀.测试", "astral-suffix"),
            ("y.x.🦀.测试", "astral-suffix"),
            ("测试", ""),
        ] {
            let found = check_domain_map_lookup(&mapping, query);
            assert_eq!(found.copied().unwrap_or(""), expected, "{query}");
        }
    }

    #[tokio::test]
    async fn test_domain_map_wildcard() {
        let tests: [(&[&str], &[(&str, i32)]); 4] = [
            (
                &["*.*.*.baidu.com", "www.baidu.*", "stun.*.*", "*.*.qq.com", "test.*.baidu.com", "*.apple.com"],
                &[
                    ("a.b.c.baidu.com", 1),
                    ("www.baidu.com", 2),
                    ("www.baidu.net", 2),
                    ("stun.ab.cd", 3),
                    ("test.test.qq.com", 4),
                    ("test.test.baidu.com", 5),
                    ("www.apple.com", 6),
                    ("test.baidu.com", 0),
                    ("a.b.baidu.com", 0),
                    ("d.a.b.c.baidu.com", 0),
                    ("stun.l.google.com", 0),
                    ("www.google.com", 0),
                    ("a.www.google.com", 0),
                    ("test.qq.com", 0),
                    ("test.test.test.qq.com", 0),
                    ("apple.com", 0),
                    ("a.www.apple.com", 0),
                ],
            ),
            (
                &["*.dev", ".org", ".apple.*"],
                &[
                    ("example.dev", 1),
                    ("test.org", 2),
                    ("a.b.org", 2),
                    ("test.apple.com", 3),
                    ("test.apple.net", 3),
                    ("a.b.apple.com", 3),
                    ("dev", 0),
                    ("foo.example.dev", 0),
                    ("org", 0),
                    ("apple.com", 0),
                    ("test.orange.com", 0),
                ],
            ),
            (&["*"], &[("router", 1), ("com", 1), ("example.com", 0), ("", 0)]),
            (&["a.*", "*.a"], &[("a.com", 1), ("b.a", 2), ("a.a", 2), ("a", 0), ("com", 0), ("www.a.com", 0)]),
        ];
        for (domains, queries) in tests {
            let mut builder = DomainMapBuilder::<i32>::default();
            for (index, domain) in domains.iter().enumerate() {
                assert!(builder.insert(domain, index as i32 + 1).is_ok());
            }
            let mapping = builder.build().expect("mapping");
            let restored = test_domain_map_bin_i32(&mapping).await;
            for mapping in [&mapping, &restored] {
                check_domain_map_queries(mapping, queries);
            }
        }
    }

    #[tokio::test]
    async fn test_domain_map_complex_wildcard() {
        let tests: [(&[&str], &[(&str, i32)]); 4] = [
            (&["+.example.com", "example.com"], &[("example.com", 2), ("www.example.com", 1)]),
            (
                &["+.baidu.com", "+.a.baidu.com", "www.baidu.com", "+.bb.baidu.com"],
                &[
                    ("baidu.com", 1),
                    ("test.test.baidu.com", 1),
                    ("a.baidu.com", 2),
                    ("www.a.baidu.com", 2),
                    ("www.baidu.com", 3),
                    ("bb.baidu.com", 4),
                    ("www.bb.baidu.com", 4),
                    ("google.com", 0),
                ],
            ),
            (
                &["+.stun.*.*", "+.stun.*.*.*", "+.stun.*.*.*.*", "stun.l.google.com"],
                &[
                    ("stun.website.com", 1),
                    ("global.stun.website.com", 1),
                    ("region.global.stun.website.com", 1),
                    ("global.stun.l.google.com", 2),
                    ("stun.a.b.example.com", 3),
                    ("global.stun.a.b.example.com", 3),
                    ("stun.l.google.com", 4),
                    ("stun.com", 0),
                    ("stun.a.b.c.example.com", 0),
                    ("global.turn.website.com", 0),
                ],
            ),
            (
                &["+.*", "stun.*.*.*"],
                &[
                    ("router", 1),
                    ("example.com", 1),
                    ("stun.l.google.com", 2),
                    ("global.stun.l.google.com", 1),
                    ("", 0),
                ],
            ),
        ];
        for (domains, queries) in tests {
            let mut builder = DomainMapBuilder::<i32>::default();
            for (index, domain) in domains.iter().enumerate() {
                assert!(builder.insert(domain, index as i32 + 1).is_ok());
            }
            let mapping = builder.build().expect("mapping");
            let restored = test_domain_map_bin_i32(&mapping).await;
            for mapping in [&mapping, &restored] {
                check_domain_map_queries(mapping, queries);
            }
        }
    }

    #[tokio::test]
    async fn test_domain_map_wildcard_shadow() {
        let tests: [(&[&str], &[(&str, i32)]); 3] = [
            (
                &["*.example.com", "dead.a.example.com"],
                &[("a.example.com", 1), ("b.a.example.com", 0), ("dead.a.example.com", 2)],
            ),
            (
                &["*.*.example.com", "dead.*.a.example.com", "dead.b.a.example.com"],
                &[
                    ("b.a.example.com", 1),
                    ("a.example.com", 0),
                    ("dead.c.a.example.com", 2),
                    ("dead.b.a.example.com", 3),
                    ("other.c.a.example.com", 0),
                ],
            ),
            (
                &["*.*.*.example.com", "*.a.example.com"],
                &[("b.c.a.example.com", 1), ("d.b.c.a.example.com", 0), ("c.a.example.com", 2), ("a.example.com", 0)],
            ),
        ];
        for (domains, queries) in tests {
            let mut builder = DomainMapBuilder::<i32>::default();
            for (index, domain) in domains.iter().enumerate() {
                assert!(builder.insert(domain, index as i32 + 1).is_ok());
            }
            let mapping = builder.build().expect("mapping");
            let restored = test_domain_map_bin_i32(&mapping).await;
            for mapping in [&mapping, &restored] {
                check_domain_map_queries(mapping, queries);
            }
        }
    }

    #[tokio::test]
    async fn test_domain_map_long_domain() {
        let prefix = "label.".repeat(32);
        let mut builder = DomainMapBuilder::<i32>::default();
        assert!(builder.insert("+.example.com", 1).is_ok());
        assert!(builder.insert(&format!("{prefix}example.com"), 2).is_ok());
        let mapping = builder.build().expect("mapping");
        let restored = test_domain_map_bin_i32(&mapping).await;
        for mapping in [&mapping, &restored] {
            for (query, expected) in [
                (format!("{prefix}example.com"), 2),
                (format!("www.{prefix}example.com"), 1),
                (format!("{prefix}example.net"), 0),
            ] {
                let found = check_domain_map_lookup(mapping, &query);
                assert_eq!(found.is_some(), expected != 0, "{query}");
                assert_eq!(found.copied().unwrap_or(0), expected, "{query}");
            }
        }
    }

    #[tokio::test]
    async fn test_domain_map_many_domains() {
        let domains: Vec<String> = (0..2000).map(|index| format!("host{index}.example.com")).collect();
        let mut builder = DomainMapBuilder::<i32>::default();
        for (index, domain) in domains.iter().enumerate() {
            assert!(builder.insert(domain, index as i32 + 1).is_ok());
        }
        let mapping = builder.build().expect("mapping");
        let restored = test_domain_map_bin_i32(&mapping).await;
        for mapping in [&mapping, &restored] {
            for (index, domain) in domains.iter().enumerate() {
                let value = check_domain_map_lookup(mapping, domain).expect(domain);
                assert_eq!(*value, index as i32 + 1, "{domain}");
                let query = format!("www.{domain}");
                let found = check_domain_map_lookup(mapping, &query);
                assert!(found.is_none(), "{query}");
            }
            let found = check_domain_map_lookup(mapping, "missing.example.com");
            assert!(found.is_none());
        }
    }

    #[tokio::test]
    async fn test_domain_map_foreach() {
        let domains = [
            "google.com",
            "stun.*.*.*",
            "test.*.google.com",
            "+.baidu.com",
            "*.baidu.com",
            "*.*.baidu.com",
            "BAIDU.COM",
            ".baidu.com",
            ".example.org",
            "+.测试.cn",
            "bücher.example",
            "BÜCHER.EXAMPLE",
        ];
        let mut builder = DomainMapBuilder::<i32>::default();
        for (index, domain) in domains.iter().enumerate() {
            assert!(builder.insert(domain, index as i32).is_ok());
        }
        let mapping = builder.build().expect("mapping");
        let restored = test_domain_map_bin_i32(&mapping).await;
        for mapping in [&mapping, &restored] {
            for limit in [1, 3] {
                let mut calls = 0;
                mapping.foreach(|_, _| {
                    calls += 1;
                    calls < limit
                });
                assert_eq!(calls, limit);
            }

            let mut rebuilt = DomainMapBuilder::<i32>::default();
            let mut map_domains: Vec<String> = Vec::new();
            let mut values: HashMap<String, i32> = HashMap::new();
            mapping.foreach(|domain, value| {
                assert!(!values.contains_key(domain));
                map_domains.push(domain.to_owned());
                values.insert(domain.to_owned(), *value);
                assert!(rebuilt.insert(domain, *value).is_ok());
                true
            });
            let expected: HashMap<String, i32> = [
                ("google.com", 0),
                ("stun.*.*.*", 1),
                ("test.*.google.com", 2),
                ("baidu.com", 6),
                (".baidu.com", 7),
                ("*.baidu.com", 4),
                ("*.*.baidu.com", 5),
                (".example.org", 8),
                ("测试.cn", 9),
                (".测试.cn", 9),
                ("bücher.example", 11),
            ]
            .into_iter()
            .map(|(domain, value)| (domain.to_owned(), value))
            .collect();
            assert_eq!(values, expected);

            let mut set_domains: Vec<String> = Vec::new();
            mapping.domain_set().expect("set").foreach(|domain| {
                set_domains.push(domain.to_owned());
                true
            });
            map_domains.sort();
            set_domains.sort();
            assert_eq!(map_domains, set_domains);

            let rebuilt = rebuilt.build().expect("mapping");
            for mapping in [mapping, &rebuilt] {
                for (domain, expected) in
                    [("google.com", 0), ("baidu.com", 6), ("a.b.c.baidu.com", 7), ("www.example.org", 8)]
                {
                    let value = check_domain_map_lookup(mapping, domain).expect(domain);
                    assert_eq!(*value, expected, "{domain}");
                }
                let found = check_domain_map_lookup(mapping, "example.org");
                assert!(found.is_none());
            }
        }
    }
}
