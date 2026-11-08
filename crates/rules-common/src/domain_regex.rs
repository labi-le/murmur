//! Patterns are compiled case-insensitively with `fancy_regex::RegexBuilder`, which provides the
//! .NET-style lookaround/backreference support these patterns rely on.
//!
//! An engine failure (e.g. backtrack-limit exhaustion) evaluates to `false`.

use std::borrow::Cow;

use fancy_regex::{Regex, RegexBuilder};

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct DomainRegex {
    base: Base,
    regex: Regex,
    adapter: String,
}

impl Rule for DomainRegex {
    fn rule_type(&self) -> RuleType {
        RuleType::DOMAIN_REGEX
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let domain = metadata.rule_host();
        let matched = self.regex.is_match(domain).unwrap_or(false);
        // DEVIATION: the rule returns the adapter unconditionally; no
        // caller reads it on a miss, so we skip the allocation and return an empty string.
        (matched, if matched { Cow::Borrowed(self.adapter.as_str()) } else { Cow::Borrowed("") })
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.regex.as_str().to_owned()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}

impl DomainRegex {
    pub fn new(regex: &str, adapter: &str) -> anyhow::Result<Self> {
        let r = RegexBuilder::new(regex).case_insensitive(true).build()?;
        Ok(Self { base: Base, regex: r, adapter: adapter.to_owned() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookahead_pattern_matches() {
        let rule = DomainRegex::new(r"^(?=.*example)(?=.*\.com$).+$", "DIRECT").unwrap();
        let metadata = Metadata { host: "example.com".to_owned(), ..Default::default() };
        assert!(rule.regex.is_match(metadata.rule_host()).unwrap());

        let miss = Metadata { host: "example.org".to_owned(), ..Default::default() };
        assert!(!rule.regex.is_match(miss.rule_host()).unwrap());
    }

    #[test]
    fn plain_pattern_matches_case_insensitively() {
        let rule = DomainRegex::new(r"^sub\.example\.com$", "DIRECT").unwrap();
        let metadata = Metadata { host: "SUB.EXAMPLE.COM".to_owned(), ..Default::default() };
        assert!(rule.regex.is_match(metadata.rule_host()).unwrap());

        let miss = Metadata { host: "other.example.com".to_owned(), ..Default::default() };
        assert!(!rule.regex.is_match(miss.rule_host()).unwrap());
    }
}
