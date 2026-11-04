use anyhow::Result;
use regex::Regex;

use super::matchers::{DomainMatcher, FullMatcher, RegexMatcher, SubstrMatcher};

/// `Matcher` determines whether a string matches a pattern.
pub trait Matcher: Send + Sync + std::fmt::Debug {
    /// Returns true if the given string matches a predefined pattern.
    fn match_(&self, s: &str) -> bool;

    fn string(&self) -> String;
}

/// `Type` is the type of the matcher.
///
/// A Rust enum cannot hold out-of-range byte values, so the constructor has no unknown-type arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Type {
    /// The input string must exactly equal to the pattern.
    Full,
    /// The input string must contain the pattern as a sub-string.
    Substr,
    /// The input string must be a sub-domain or itself of the pattern.
    Domain,
    /// The input string must match the regular-expression pattern.
    Regex,
}

impl Type {
    /// Creates a new `Matcher` from the given pattern; named `new_matcher` because a method
    /// called `new` is expected to return `Self`.
    pub fn new_matcher(self, pattern: &str) -> Result<Box<dyn Matcher>> {
        match self {
            // regex matching is case-sensitive
            Self::Full => Ok(Box::new(FullMatcher(pattern.to_owned()))),
            Self::Substr => Ok(Box::new(SubstrMatcher(pattern.to_owned()))),
            Self::Domain => Ok(Box::new(DomainMatcher(pattern.to_owned()))),
            Self::Regex => {
                let r = Regex::new(pattern)?;
                Ok(Box::new(RegexMatcher { pattern: r }))
            }
        }
    }
}

/// `IndexMatcher` matches against a group of matchers.
pub trait IndexMatcher: Send + Sync + std::fmt::Debug {
    /// Returns the index of a matcher that matches the input, or an empty array if none does.
    fn match_(&self, input: &str) -> Vec<u32>;
}

#[derive(Debug)]
pub(crate) struct MatcherEntry {
    pub(crate) m: Box<dyn Matcher>,
    pub(crate) id: u32,
}
