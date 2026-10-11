use std::fmt;
use std::ops::{Deref, DerefMut};

use thiserror::Error;

use super::range::{new_int_range, parse_signed, parse_unsigned, Integer, Range, Signed, Unsigned};

#[derive(Debug, Clone, Copy, Error)]
pub enum IntRangesError {
    #[error("intRanges error")]
    IntRanges,
    #[error("intRanges error, too many ranges to use, maximum support 28 ranges")]
    TooManyRanges,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntRanges<T>(pub Vec<Range<T>>);

// Delegation to the collection this newtype wraps, not the inheritance pattern to avoid.
impl<T> Deref for IntRanges<T> {
    type Target = [Range<T>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for IntRanges<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> From<Vec<Range<T>>> for IntRanges<T> {
    fn from(ranges: Vec<Range<T>>) -> Self {
        Self(ranges)
    }
}

impl<T> FromIterator<Range<T>> for IntRanges<T> {
    fn from_iter<I: IntoIterator<Item = Range<T>>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<T> IntoIterator for IntRanges<T> {
    type Item = Range<T>;
    type IntoIter = std::vec::IntoIter<Range<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a IntRanges<T> {
    type Item = &'a Range<T>;
    type IntoIter = std::slice::Iter<'a, Range<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

pub(crate) fn new_int_ranges<T: Integer>(
    expected: &str,
    parse_fn: fn(&str) -> anyhow::Result<T>,
) -> anyhow::Result<IntRanges<T>> {
    // example: 200 or 200/302 or 200-400 or 200/204/401-429/501-503
    let expected = expected.trim();
    if expected.is_empty() || expected == "*" {
        return Ok(IntRanges(Vec::new()));
    }

    // support: 200,302 or 200,204,401-429,501-503
    let expected = expected.replace(',', "/");
    let list: Vec<&str> = expected.split('/').collect();
    if list.len() > 28 {
        return Err(IntRangesError::TooManyRanges.into());
    }

    new_int_ranges_from_list(&list, parse_fn)
}

pub(crate) fn new_int_ranges_from_list<S: AsRef<str>, T: Integer>(
    list: &[S],
    parse_fn: fn(&str) -> anyhow::Result<T>,
) -> anyhow::Result<IntRanges<T>> {
    list.iter()
        .map(AsRef::as_ref)
        .filter(|s| !s.is_empty())
        .map(|s| new_int_range(s, parse_fn))
        .collect::<anyhow::Result<Vec<_>>>()
        .map(IntRanges)
}

pub fn new_unsigned_ranges<T: Unsigned>(expected: &str) -> anyhow::Result<IntRanges<T>> {
    new_int_ranges(expected, parse_unsigned::<T>)
}

pub fn new_unsigned_ranges_from_list<S: AsRef<str>, T: Unsigned>(list: &[S]) -> anyhow::Result<IntRanges<T>> {
    new_int_ranges_from_list(list, parse_unsigned::<T>)
}

pub fn new_signed_ranges<T: Signed>(expected: &str) -> anyhow::Result<IntRanges<T>> {
    new_int_ranges(expected, parse_signed::<T>)
}

pub fn new_signed_ranges_from_list<S: AsRef<str>, T: Signed>(list: &[S]) -> anyhow::Result<IntRanges<T>> {
    new_int_ranges_from_list(list, parse_signed::<T>)
}

impl<T: Integer> IntRanges<T> {
    pub fn check(&self, status: T) -> bool {
        self.0.is_empty() || self.0.iter().any(|segment| segment.contains(status))
    }

    pub fn range(&self, mut f: impl FnMut(T) -> bool) {
        if self.0.is_empty() {
            return;
        }

        for r in &self.0 {
            let mut i = r.start();
            while i <= r.end() && i >= r.start() {
                if !f(i) {
                    return;
                }
                if i.wrapping_inc() < i {
                    // integer overflow
                    break;
                }
                i = i.wrapping_inc();
            }
        }
    }

    #[must_use]
    pub fn merge(&self) -> Self {
        if self.0.is_empty() {
            return Self(Vec::new());
        }
        let mut ranges = self.0.clone();
        ranges.sort_by_key(Range::start);

        let mut merged: Vec<Range<T>> = Vec::with_capacity(ranges.len());
        let mut rest = ranges.iter();
        let Some(first) = rest.next().copied() else {
            return Self(merged);
        };
        merged.push(first);
        for r in rest {
            let Some(last) = merged.last() else {
                return Self(merged);
            };
            let end = last.end();
            if end.wrapping_inc() > end && r.start() > end.wrapping_inc() {
                // integer overflow
                merged.push(*r);
            } else if r.end() > end {
                if let Some(last) = merged.last_mut() {
                    last.end = r.end();
                }
            }
        }
        Self(merged)
    }
}

impl<T: Integer + fmt::Display> IntRanges<T> {
    #[must_use]
    pub fn string(&self) -> String {
        self.to_string()
    }
}

impl<T: Integer + fmt::Display> fmt::Display for IntRanges<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("*");
        }

        let terms: Vec<String> = self.0.iter().map(Range::string).collect();
        f.write_str(&terms.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::range::new_range;

    type TestRanges = Vec<(Vec<Range<u16>>, Vec<Range<u16>>)>;

    #[test]
    fn test_merge_ranges() {
        let test_ranges: TestRanges = vec![
            (vec![new_range(0, 1), new_range(1, 2)], vec![new_range(0, 2)]),
            (
                vec![new_range(0, 3), new_range(5, 7), new_range(8, 9), new_range(10, 10)],
                vec![new_range(0, 3), new_range(5, 10)],
            ),
            (
                vec![new_range(1, 3), new_range(2, 6), new_range(8, 10), new_range(15, 18)],
                vec![new_range(1, 6), new_range(8, 10), new_range(15, 18)],
            ),
            (vec![new_range(1, 3), new_range(2, 7), new_range(2, 6)], vec![new_range(1, 7)]),
            (vec![new_range(1, 3), new_range(2, 6), new_range(2, 7)], vec![new_range(1, 7)]),
            (vec![new_range(1, 3), new_range(2, 65535), new_range(2, 7), new_range(3, 16)], vec![new_range(1, 65535)]),
        ];
        for (ranges, expected) in test_ranges {
            assert_eq!(IntRanges(ranges).merge(), IntRanges(expected));
        }
    }
}
