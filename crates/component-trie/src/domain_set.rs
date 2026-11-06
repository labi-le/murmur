use anyhow::Result;

use super::domain::{join_domain, valid_and_split_domain, COMPLEX_WILDCARD, DOMAIN_STEP_CHAR, DOT_WILDCARD};
use murmur_common::utils::strings::reverse;

pub(crate) const COMPLEX_WILDCARD_BYTE: u8 = b'+';
pub(crate) const WILDCARD_BYTE: u8 = b'*';
pub(crate) const DOMAIN_STEP_BYTE: u8 = b'.';

/// A succinct set of domain patterns, modified from <https://github.com/openacid/succinct>.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainSet {
    pub(crate) leaves: Vec<u64>,
    pub(crate) label_bitmap: Vec<u64>,
    pub(crate) labels: Vec<u8>,
    pub(crate) ranks: Vec<i32>,
    pub(crate) selects: Vec<i32>,
}

#[derive(Debug, Clone, Copy)]
struct QElt {
    s: usize,
    e: usize,
}

/// `DomainSetBuilder` incrementally collects domain patterns for a `DomainSet`.
/// Its zero value is ready to use.
#[derive(Debug, Default)]
pub struct DomainSetBuilder {
    pub(crate) keys: Vec<String>,
}

impl DomainSetBuilder {
    /// Insert validates and adds a domain pattern to the builder. It accepts the
    /// same domain syntax as [`crate::domain::DomainTrie::insert`].
    pub fn insert(&mut self, domain: &str) -> Result<()> {
        let lowered = valid_and_split_domain(domain)?;
        let mut parts: Vec<&str> = lowered.split(DOMAIN_STEP_CHAR).collect();

        if let Some((first, rest)) = parts.split_first_mut() {
            if *first == COMPLEX_WILDCARD {
                self.insert_parts(rest);
            }
        }
        self.insert_parts(&mut parts);
        Ok(())
    }

    fn insert_parts(&mut self, parts: &mut [&str]) {
        if let Some(first) = parts.first_mut() {
            if *first == DOT_WILDCARD {
                *first = COMPLEX_WILDCARD;
            }
        }
        self.keys.push(reverse(&join_domain(parts)));
    }

    /// `IsEmpty` reports whether the builder contains any domain paths.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Reset discards all domains accumulated by the builder.
    pub fn reset(&mut self) {
        self.keys.clear();
    }

    /// Build consumes the accumulated domains and creates an immutable `DomainSet`.
    /// The builder can be reused after Build returns.
    pub fn build(&mut self) -> Option<DomainSet> {
        let keys = std::mem::take(&mut self.keys);
        build_domain_set(keys, None)
    }
}

impl<T> super::domain::DomainTrie<T> {
    /// Creates a new [`DomainSet`] from a `DomainTrie`.
    pub fn new_domain_set(&self) -> Option<DomainSet> {
        let mut keys: Vec<String> = Vec::new();
        self.foreach(|domain, _| {
            if domain.starts_with(DOMAIN_STEP_CHAR) {
                keys.push(reverse(&format!("{COMPLEX_WILDCARD}{domain}")));
            } else {
                keys.push(reverse(domain));
            }
            true
        });
        build_domain_set(keys, None)
    }
}

pub(crate) fn build_domain_set(
    mut keys: Vec<String>,
    mut on_terminal: Option<&mut dyn FnMut(&str)>,
) -> Option<DomainSet> {
    if keys.is_empty() {
        return None;
    }
    keys.sort();
    keys.dedup();

    let mut ss = DomainSet::default();
    let mut l_idx: i32 = 0;

    let mut node_id: i32 = 0;
    let mut queue: Vec<QElt> = Vec::with_capacity(1);
    queue.push(QElt { s: 0, e: keys.len() });
    let mut next: Vec<QElt> = Vec::with_capacity(keys.len());
    let mut col: usize = 0;
    while !queue.is_empty() {
        for mut elt in queue.iter().copied() {
            let terminal = keys.get(elt.s);
            if terminal.is_some_and(|key| key.len() == col) {
                if let (Some(key), Some(on_terminal)) = (terminal, on_terminal.as_deref_mut()) {
                    on_terminal(key);
                }
                elt.s += 1;
                set_bit(&mut ss.leaves, node_id, 1);
            }

            let mut j = elt.s;
            while j < elt.e {
                let frm = j;
                let frm_byte = keys.get(frm).and_then(|key| key.as_bytes().get(col)).copied();
                while j < elt.e && keys.get(j).and_then(|key| key.as_bytes().get(col)).copied() == frm_byte {
                    j += 1;
                }
                next.push(QElt { s: frm, e: j });
                if let Some(label) = frm_byte {
                    ss.labels.push(label);
                }
                set_bit(&mut ss.label_bitmap, l_idx, 0);
                l_idx += 1;
            }
            set_bit(&mut ss.label_bitmap, l_idx, 1);
            l_idx += 1;
            node_id += 1;
        }
        std::mem::swap(&mut queue, &mut next);
        next.clear();
        col += 1;
    }

    ss.init();
    Some(ss)
}

impl DomainSet {
    /// Has query for a key and return whether it presents in the `DomainSet`.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        let key_cow: std::borrow::Cow<'_, [u8]> = if key.is_ascii() {
            std::borrow::Cow::Borrowed(key.as_bytes())
        } else {
            std::borrow::Cow::Owned(byte_reverse(reverse(&key.to_lowercase()).as_bytes()))
        };
        let key: &[u8] = &key_cow;

        let mut node_id: i32 = 0;
        let mut bm_idx: i32 = 0;
        let mut stack: Vec<WildcardCursor> = Vec::new();
        let mut i: usize = 0;
        while i < key.len() {
            'restart: loop {
                let c = rev_lower_at(key, i);
                loop {
                    if get_bit(&self.label_bitmap, bm_idx) != 0 {
                        while let Some(cursor) = stack.pop() {
                            let next_node_id = count_zeros(&self.label_bitmap, &self.ranks, cursor.bm_idx + 1);
                            let mut j = cursor.index;
                            while j < key.len() && rev_lower_at(key, j) != DOMAIN_STEP_BYTE {
                                j += 1;
                            }
                            if j == key.len() {
                                if get_bit(&self.leaves, next_node_id) != 0 {
                                    return true;
                                }
                                continue;
                            }
                            let mut next_bm_idx =
                                select_ith_one(&self.label_bitmap, &self.ranks, &self.selects, next_node_id - 1) + 1;
                            while get_bit(&self.label_bitmap, next_bm_idx) == 0 {
                                let Some(label) = self.label_at(next_bm_idx - next_node_id) else {
                                    return false;
                                };
                                if label == DOMAIN_STEP_BYTE {
                                    bm_idx = next_bm_idx;
                                    node_id = next_node_id;
                                    i = j;
                                    continue 'restart;
                                }
                                next_bm_idx += 1;
                            }
                        }
                        return false;
                    }
                    let Some(label) = self.label_at(bm_idx - node_id) else {
                        return false;
                    };
                    if label == COMPLEX_WILDCARD_BYTE {
                        return true;
                    } else if label == WILDCARD_BYTE {
                        stack.push(WildcardCursor { bm_idx, index: i });
                    } else if label == c {
                        break;
                    }
                    bm_idx += 1;
                }
                node_id = bm_idx - node_id + 1;
                if i == key.len() - 1 {
                    if get_bit(&self.leaves, node_id) != 0 {
                        return true;
                    }
                    if stack.is_empty() {
                        return false;
                    }
                    bm_idx = select_ith_one(&self.label_bitmap, &self.ranks, &self.selects, node_id);
                    continue 'restart;
                }
                bm_idx = select_ith_one(&self.label_bitmap, &self.ranks, &self.selects, node_id - 1) + 1;
                break 'restart;
            }
            i += 1;
        }

        get_bit(&self.leaves, node_id) != 0
    }

    pub(crate) fn keys<F>(&self, mut f: F)
    where
        F: FnMut(&[u8], i32) -> bool,
    {
        let mut current_key: Vec<u8> = Vec::new();
        traverse(self, 0, 0, &mut current_key, &mut f);
    }

    /// Foreach iterates over the stored domain patterns in unspecified order.
    /// Returning false stops iteration.
    pub fn foreach<F>(&self, mut f: F)
    where
        F: FnMut(&str) -> bool,
    {
        self.keys(|key, _| {
            let key = String::from_utf8_lossy(key);
            let trimmed: &str = match key.strip_suffix(COMPLEX_WILDCARD) {
                Some(trimmed) => trimmed,
                None => &key,
            };
            f(&reverse(trimmed))
        });
    }

    /// Implements the domain matcher.
    #[must_use]
    pub fn match_domain(&self, domain: &str) -> bool {
        self.has(domain)
    }

    /// Builds the pre-calculated cache that speeds up ranking and selection.
    pub(crate) fn init(&mut self) {
        let (selects, ranks) = bitmap::index_select_32_r64(&self.label_bitmap);
        self.selects = selects;
        self.ranks = ranks;
    }

    /// The label byte at a bitmap offset, or `None` when the offset is not a label index.
    pub(crate) fn label_at(&self, offset: i32) -> Option<u8> {
        self.labels.get(index_of(offset)).copied()
    }
}

#[derive(Debug, Clone, Copy)]
struct WildcardCursor {
    bm_idx: i32,
    index: usize,
}

fn traverse<F>(set: &DomainSet, node_id: i32, bm_idx: i32, current_key: &mut Vec<u8>, f: &mut F) -> bool
where
    F: FnMut(&[u8], i32) -> bool,
{
    if get_bit(&set.leaves, node_id) != 0 && !f(current_key, node_id) {
        return false;
    }

    let mut bm_idx = bm_idx;
    loop {
        if get_bit(&set.label_bitmap, bm_idx) != 0 {
            return true;
        }
        let Some(next_label) = set.label_at(bm_idx - node_id) else {
            return true;
        };
        current_key.push(next_label);
        let next_node_id = bm_idx - node_id + 1;
        let next_bm_idx = select_ith_one(&set.label_bitmap, &set.ranks, &set.selects, next_node_id - 1) + 1;
        if !traverse(set, next_node_id, next_bm_idx, current_key, f) {
            return false;
        }
        current_key.pop();
        bm_idx += 1;
    }
}

/// Returns the i-th byte of key read back to front, ASCII-lowercased.
pub(crate) fn rev_lower_at(key: &[u8], i: usize) -> u8 {
    let mut c = key.len().checked_sub(i + 1).and_then(|back| key.get(back)).copied().unwrap_or_default();
    if c.is_ascii_uppercase() {
        c += b'a' - b'A';
    }
    c
}

pub(crate) fn byte_reverse(s: &[u8]) -> Vec<u8> {
    s.iter().rev().copied().collect()
}

/// The `usize` view of a signed bitmap offset; offsets are non-negative by construction.
pub(crate) fn index_of(i: i32) -> usize {
    usize::try_from(i).unwrap_or(usize::MAX)
}

fn set_bit(bm: &mut Vec<u64>, i: i32, v: u64) {
    let Ok(word) = usize::try_from(i >> 6) else {
        return;
    };
    if bm.len() <= word {
        bm.resize(word + 1, 0);
    }
    if let Some(slot) = bm.get_mut(word) {
        *slot |= v << (i & 63);
    }
}

pub(crate) fn get_bit(bm: &[u64], i: i32) -> u64 {
    bm.get(index_of(i >> 6)).copied().unwrap_or(0) & (1u64 << (i & 63))
}

/// Counts the zeros in a bitmap before the i-th bit, excluding the i-th bit.
pub(crate) fn count_zeros(bm: &[u64], ranks: &[i32], i: i32) -> i32 {
    let (a, _) = bitmap::rank_64(bm, ranks, i);
    i - a
}

/// Returns the index of the i-th set bit in a bitmap.
pub(crate) fn select_ith_one(bm: &[u64], ranks: &[i32], selects: &[i32], i: i32) -> i32 {
    let (a, _) = bitmap::select_32_r64(bm, selects, ranks, i);
    a
}

/// Local mirror of the subset of `github.com/openacid/low/bitmap` this package uses.
pub(crate) mod bitmap {
    use super::index_of;

    /// rank(i) is defined as number of "1" up to position i, excluding i; an entry per 64-bit word.
    pub(crate) fn index_rank_64(words: &[u64], trailing: bool) -> Vec<i32> {
        let len = if trailing { words.len() + 1 } else { words.len() };
        let mut idx = vec![0i32; len];
        let mut n: i32 = 0;
        for (entry, word) in idx.iter_mut().zip(words) {
            *entry = n;
            n += word.count_ones().cast_signed();
        }
        if trailing {
            if let Some(entry) = idx.last_mut() {
                *entry = n;
            }
        }
        idx
    }

    /// Indexes for the "select" operation over 64-bit words, plus the Rank64 index.
    pub(crate) fn index_select_32_r64(words: &[u64]) -> (Vec<i32>, Vec<i32>) {
        let len = words.len() << 6;
        let mut select_index: Vec<i32> = Vec::with_capacity(words.len());

        let mut ith: i32 = -1;
        for i in 0..len {
            if words.get(i >> 6).copied().unwrap_or(0) & (1u64 << (i & 63)) != 0 {
                ith += 1;
                if ith.trailing_zeros() >= 5 {
                    select_index.push(i32::try_from(i).unwrap_or(i32::MAX));
                }
            }
        }

        (select_index, index_rank_64(words, true))
    }

    /// The count of 1 up to i excluding i and the bit value at i, with a 64-bit index.
    pub(crate) fn rank_64(words: &[u64], rindex: &[i32], i: i32) -> (i32, i32) {
        let word_i = index_of(i >> 6);
        let j = (i & 63).cast_unsigned();

        let n = rindex.get(word_i).copied().unwrap_or(0);
        let w = words.get(word_i).copied().unwrap_or(0);

        let c1 = n + (w & mask(j)).count_ones().cast_signed();
        (c1, i32::from(((w >> j) & 1) != 0))
    }

    /// The indexes of the i-th "1" and the (i+1)-th "1", using a Rank64 and a Select32 index.
    pub(crate) fn select_32_r64(words: &[u64], select_index: &[i32], rank_index: &[i32], i: i32) -> (i32, i32) {
        let mut a: i32;

        let l = i32::try_from(words.len()).unwrap_or(i32::MAX);

        let mut word_i = select_index.get(index_of(i >> 5)).copied().unwrap_or(0) >> 6;
        while rank_index.get(index_of(word_i + 1)).copied().unwrap_or(i32::MAX) <= i {
            word_i += 1;
        }

        let w = words.get(index_of(word_i)).copied().unwrap_or(0);
        let mut ww = w;
        let base = word_i << 6;
        let mut find_ith: i32 = i - rank_index.get(index_of(word_i)).copied().unwrap_or(0);

        let mut offset: i32 = 0;

        let ones = (ww & u64::from(u32::MAX)).count_ones().cast_signed();
        if ones <= find_ith {
            find_ith -= ones;
            offset |= 32;
            ww >>= 32;
        }

        let ones = (ww & u64::from(u16::MAX)).count_ones().cast_signed();
        if ones <= find_ith {
            find_ith -= ones;
            offset |= 16;
            ww >>= 16;
        }

        let ones = (ww & u64::from(u8::MAX)).count_ones().cast_signed();
        if ones <= find_ith {
            a = i32::from(select8_lookup(((ww >> 8) & 0xff) as u8, find_ith - ones)) + offset + 8;
        } else {
            a = i32::from(select8_lookup((ww & 0xff) as u8, find_ith)) + offset;
        }

        a += base;

        let mut w = w & !mask_upto((a & 63).cast_unsigned());

        if w != 0 {
            return (a, base + w.trailing_zeros().cast_signed());
        }

        let mut word_i = word_i + 1;
        while word_i < l {
            w = words.get(index_of(word_i)).copied().unwrap_or(0);
            if w != 0 {
                return (a, (word_i << 6) + w.trailing_zeros().cast_signed());
            }
            word_i += 1;
        }
        (a, l << 6)
    }

    const fn mask(i: u32) -> u64 {
        if i >= 64 {
            u64::MAX
        } else {
            (1u64 << i) - 1
        }
    }

    const fn mask_upto(i: u32) -> u64 {
        if i >= 63 {
            u64::MAX
        } else {
            (1u64 << (i + 1)) - 1
        }
    }

    fn select8_lookup(w: u8, ith: i32) -> u8 {
        let mut w = w;
        let mut x = 8u8;
        for _ in 0..=ith {
            x = u8::try_from(w.trailing_zeros()).unwrap_or(8);
            w &= w.wrapping_sub(1);
        }
        x
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::{DomainTrie, DOMAIN_STEP};

    use super::*;

    fn test_dump(tree: &DomainTrie<()>, set: &DomainSet) {
        let mut data_src: Vec<String> = Vec::new();
        tree.foreach(|domain, _| {
            data_src.push(domain.to_owned());
            true
        });
        data_src.sort();
        let mut data_set: Vec<String> = Vec::new();
        set.foreach(|key| {
            data_set.push(key.to_owned());
            true
        });
        data_set.sort();
        assert_eq!(data_src, data_set);
    }

    #[test]
    fn test_domain_set() {
        let mut tree = DomainTrie::<()>::new();
        let mut builder = DomainSetBuilder::default();
        let domain_set =
            ["baidu.com", "google.com", "www.google.com", "test.a.net", "test.a.oc", "Mijia Cloud", ".qq.com", "+.cn"];

        for domain in domain_set {
            assert!(tree.insert(domain, ()).is_ok());
            assert!(builder.insert(domain).is_ok());
        }
        assert!(!builder.is_empty());
        let set = builder.build().expect("set");
        assert_eq!(tree.new_domain_set().as_ref(), Some(&set));
        assert!(set.has("test.cn"));
        assert!(set.has("cn"));
        assert!(set.has("Mijia Cloud"));
        assert!(set.has("test.a.net"));
        assert!(set.has("www.qq.com"));
        assert!(set.has("google.com"));
        assert!(!set.has("qq.com"));
        assert!(!set.has("www.baidu.com"));
        test_dump(&tree, &set);
    }

    #[test]
    fn test_domain_set_has_non_ascii_and_uppercase() {
        let mut builder = DomainSetBuilder::default();
        for domain in ["例え.jp", "+.пример.рф"] {
            assert!(builder.insert(domain).is_ok());
        }
        let set = builder.build().expect("set");
        assert!(set.has("例え.jp"));
        assert!(set.has("ПРИМЕР.рф"));
        assert!(set.has("sub.пример.рф"));
        assert!(!set.has("例え.com"));
        assert!(!set.has("рф"));
    }

    #[test]
    fn converting_a_trie_to_a_domain_set_round_trips_the_patterns() {
        let patterns = [
            "www.example.com",
            "*.example.com",
            "subdomain.*.example.com",
            ".example.com",
            "+.example.com",
            "测试.cn",
            "+.тест.рф",
            "i\u{307}.tr",
            "ΑΣ",
            "ǅ.com",
            "Mijia Cloud",
        ];

        let mut tree = DomainTrie::<()>::new();
        for pattern in patterns {
            assert!(tree.insert(pattern, ()).is_ok(), "{pattern}");
        }

        let mut visited: Vec<String> = Vec::new();
        tree.foreach(|domain, _| {
            visited.push(domain.to_owned());
            true
        });
        let suffix_only = visited.iter().filter(|domain| domain.starts_with(DOMAIN_STEP)).count();
        assert!(suffix_only > 0, "a suffix-only pattern is required");
        assert!(visited.iter().all(|domain| !domain.is_empty()));

        let set = tree.new_domain_set().expect("set");
        let mut keys: Vec<String> = Vec::new();
        set.foreach(|key| {
            keys.push(key.to_owned());
            true
        });

        let mut from_trie = visited.clone();
        let mut from_set = keys.clone();
        from_trie.sort();
        from_set.sort();
        assert_eq!(from_trie, from_set);

        let mut rebuilt = DomainTrie::<()>::new();
        for key in &keys {
            assert!(rebuilt.insert(key, ()).is_ok(), "{key}");
        }
        assert_eq!(rebuilt.new_domain_set().as_ref(), Some(&set));
    }

    #[test]
    fn domain_set_foreach_keys_reinsert_into_an_equal_trie() {
        let patterns = ["中文.example", "+.测试.cn", "i\u{307}.tr", "ασ.gr", "ας", "*.例え.jp"];
        let mut tree = DomainTrie::<()>::new();
        for pattern in patterns {
            assert!(tree.insert(pattern, ()).is_ok(), "{pattern}");
        }
        let set = tree.new_domain_set().expect("set");

        let mut keys: Vec<String> = Vec::new();
        set.foreach(|key| {
            keys.push(key.to_owned());
            true
        });
        keys.sort();

        let mut rebuilt = DomainTrie::<()>::new();
        for key in &keys {
            assert!(rebuilt.insert(key, ()).is_ok(), "{key}");
        }
        assert_eq!(rebuilt.new_domain_set().as_ref(), Some(&set));
        for (domain, expected) in [
            ("中文.example", true),
            ("www.测试.cn", true),
            ("测试.cn", true),
            ("İ.tr", true),
            ("ΑΣ", true),
            ("ΑΣ.gr", true),
            ("a.例え.jp", true),
            ("日本語.example", false),
        ] {
            assert_eq!(set.has(domain), expected, "{domain}");
        }
    }

    #[test]
    fn test_domain_set_foreach() {
        let mut builder = DomainSetBuilder::default();
        for domain in [".example.com", "+.example.org", "example.net"] {
            assert!(builder.insert(domain).is_ok());
        }
        let set = builder.build().expect("set");
        let mut keys: Vec<String> = Vec::new();
        set.foreach(|key| {
            keys.push(key.to_owned());
            assert!(builder.insert(key).is_ok());
            true
        });
        let mut expected = vec![
            ".example.com".to_owned(),
            ".example.org".to_owned(),
            "example.org".to_owned(),
            "example.net".to_owned(),
        ];
        expected.sort();
        keys.sort();
        assert_eq!(keys, expected);
        let rebuilt = builder.build().expect("set");
        for set in [&set, &rebuilt] {
            for (domain, expected) in [
                ("example.com", false),
                ("www.example.com", true),
                ("example.org", true),
                ("www.example.org", true),
                ("example.net", true),
                ("www.example.net", false),
            ] {
                assert_eq!(set.has(domain), expected, "{domain}");
            }
        }
    }

    #[test]
    fn test_domain_set_builder_lifecycle() {
        let mut builder = DomainSetBuilder::default();
        assert!(builder.is_empty());
        assert!(builder.insert("invalid..example").is_err());
        assert!(builder.is_empty());
        assert!(builder.build().is_none());

        for domain in ["+.example.com", "example.com", "+.example.com"] {
            assert!(builder.insert(domain).is_ok());
        }
        let set = builder.build().expect("set");
        assert!(builder.is_empty());
        assert!(set.has("example.com"));
        assert!(set.has("www.example.com"));

        let mut keys: Vec<String> = Vec::new();
        set.foreach(|key| {
            keys.push(key.to_owned());
            true
        });
        keys.sort();
        assert_eq!(keys, vec![".example.com".to_owned(), "example.com".to_owned()]);

        assert!(builder.insert("other.example").is_ok());
        let set = builder.build().expect("set");
        assert!(set.has("other.example"));
        assert!(!set.has("example.com"));

        assert!(builder.insert("discard.example").is_ok());
        builder.reset();
        assert!(builder.is_empty());
        assert!(builder.build().is_none());
    }

    #[test]
    fn test_domain_set_complex_wildcard() {
        let mut tree = DomainTrie::<()>::new();
        let mut builder = DomainSetBuilder::default();
        let domain_set = [
            "+.baidu.com",
            "+.a.baidu.com",
            "www.baidu.com",
            "+.bb.baidu.com",
            "test.a.net",
            "test.a.oc",
            "www.qq.com",
        ];

        for domain in domain_set {
            assert!(tree.insert(domain, ()).is_ok());
            assert!(builder.insert(domain).is_ok());
        }
        assert!(!builder.is_empty());
        let set = builder.build().expect("set");
        assert_eq!(tree.new_domain_set().as_ref(), Some(&set));
        assert!(!set.has("google.com"));
        assert!(set.has("www.baidu.com"));
        assert!(set.has("test.test.baidu.com"));
        test_dump(&tree, &set);
    }

    #[test]
    fn test_domain_set_wildcard() {
        let mut tree = DomainTrie::<()>::new();
        let mut builder = DomainSetBuilder::default();
        let domain_set =
            ["*.*.*.baidu.com", "www.baidu.*", "stun.*.*", "*.*.qq.com", "test.*.baidu.com", "*.apple.com"];

        for domain in domain_set {
            assert!(tree.insert(domain, ()).is_ok());
            assert!(builder.insert(domain).is_ok());
        }
        assert!(!builder.is_empty());
        let set = builder.build().expect("set");
        assert_eq!(tree.new_domain_set().as_ref(), Some(&set));
        assert!(set.has("www.baidu.com"));
        assert!(set.has("test.test.baidu.com"));
        assert!(set.has("test.test.qq.com"));
        assert!(set.has("stun.ab.cd"));
        assert!(!set.has("test.baidu.com"));
        assert!(!set.has("www.google.com"));
        assert!(!set.has("a.www.google.com"));
        assert!(!set.has("test.qq.com"));
        assert!(!set.has("test.test.test.qq.com"));
        test_dump(&tree, &set);
    }

    #[test]
    fn test_domain_set_wildcard_shadow() {
        let tests: [(&[&str], &str, &str); 3] = [
            (&["*.example.com", "dead.a.example.com"], "a.example.com", "b.a.example.com"),
            (&["*.*.example.com", "dead.*.a.example.com", "dead.b.a.example.com"], "b.a.example.com", "a.example.com"),
            (&["*.*.*.example.com", "*.a.example.com"], "b.c.a.example.com", "d.b.c.a.example.com"),
        ];
        for (domains, match_, not_match) in tests {
            let mut tree = DomainTrie::<()>::new();
            let mut builder = DomainSetBuilder::default();
            for domain in domains {
                assert!(tree.insert(domain, ()).is_ok());
                assert!(builder.insert(domain).is_ok());
            }
            let set = builder.build().expect("set");
            assert_eq!(tree.new_domain_set().as_ref(), Some(&set));
            assert!(set.has(match_), "{match_}");
            assert!(!set.has(not_match), "{not_match}");
            test_dump(&tree, &set);
        }
    }

    #[test]
    fn test_domain_set_case() {
        let mut tree = DomainTrie::<()>::new();
        let mut builder = DomainSetBuilder::default();
        for domain in ["example.com", "EXAMPLE.COM", "+.mixed.example.org"] {
            assert!(tree.insert(domain, ()).is_ok());
            assert!(builder.insert(domain).is_ok());
        }
        let set = builder.build().expect("set");
        assert_eq!(tree.new_domain_set().as_ref(), Some(&set));
        assert!(set.has("EXAMPLE.COM"));
        assert!(set.has("ExAmPlE.cOm"));
        assert!(set.has("WWW.MIXED.EXAMPLE.ORG"));
        assert!(!set.has("EXAMPLE.NET"));
    }

    #[test]
    fn test_domain_set_unicode() {
        let mut tree = DomainTrie::<()>::new();
        let mut builder = DomainSetBuilder::default();
        for domain in ["中文.example", "+.测试.cn"] {
            assert!(tree.insert(domain, ()).is_ok());
            assert!(builder.insert(domain).is_ok());
        }
        let set = builder.build().expect("set");
        assert_eq!(tree.new_domain_set().as_ref(), Some(&set));
        assert!(set.has("中文.example"));
        assert!(set.has("www.测试.cn"));
        assert!(!set.has("日本語.example"));
    }

    #[test]
    fn test_domain_set_length_changing_case_fold() {
        let mut tree = DomainTrie::<()>::new();
        let mut builder = DomainSetBuilder::default();
        for domain in ["i\u{307}.tr", "ασ.gr", "ας"] {
            assert!(tree.insert(domain, ()).is_ok());
            assert!(builder.insert(domain).is_ok());
        }
        let set = builder.build().expect("set");
        assert_eq!(tree.new_domain_set().as_ref(), Some(&set));
        assert!(tree.search("İ.tr").is_some());
        assert!(set.has("İ.tr"));
        assert!(tree.search("ΑΣ.gr").is_some());
        assert!(set.has("ΑΣ.gr"));
        assert!(tree.search("ΑΣ").is_some());
        assert!(set.has("ΑΣ"));
    }
    #[test]
    fn test_domain_set_oversized_key() {
        let mut tree = DomainTrie::<()>::new();
        let mut builder = DomainSetBuilder::default();
        let domain = "+.example.com";
        assert!(tree.insert(domain, ()).is_ok());
        assert!(builder.insert(domain).is_ok());
        let set = builder.build().expect("set");
        assert_eq!(tree.new_domain_set().as_ref(), Some(&set));

        let mut key = String::new();
        while key.len() < 300 {
            key.push_str("label.");
        }
        assert!(set.has(&format!("{key}example.com")));
        assert!(!set.has(&format!("{key}example.net")));
    }
}
