use regex::Regex;

use super::strmatcher::Matcher;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullMatcher(pub(crate) String);

impl Matcher for FullMatcher {
    fn match_(&self, s: &str) -> bool {
        self.0 == s
    }

    fn string(&self) -> String {
        format!("full:{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrMatcher(pub(crate) String);

impl Matcher for SubstrMatcher {
    fn match_(&self, s: &str) -> bool {
        s.contains(self.0.as_str())
    }

    fn string(&self) -> String {
        format!("keyword:{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainMatcher(pub(crate) String);

impl Matcher for DomainMatcher {
    fn match_(&self, s: &str) -> bool {
        let pattern = self.0.as_str();
        if !s.ends_with(pattern) {
            return false;
        }
        s.len() == pattern.len() || s.as_bytes().get(s.len() - pattern.len() - 1) == Some(&b'.')
    }

    fn string(&self) -> String {
        format!("domain:{}", self.0)
    }
}

#[derive(Clone, Debug)]
pub struct RegexMatcher {
    pub(crate) pattern: Regex,
}

impl Matcher for RegexMatcher {
    fn match_(&self, s: &str) -> bool {
        self.pattern.is_match(s)
    }

    fn string(&self) -> String {
        format!("regexp:{}", self.pattern.as_str())
    }
}
