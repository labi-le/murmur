use std::borrow::Cow;

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct DomainSuffix {
    base: Base,
    suffix: String,
    adapter: String,
}

impl Rule for DomainSuffix {
    fn rule_type(&self) -> RuleType {
        RuleType::DOMAIN_SUFFIX
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let domain = metadata.rule_host();
        let suffix = self.suffix.as_str();
        let matched = domain == suffix
            || (domain.len() > suffix.len()
                && domain.ends_with(suffix)
                && domain.as_bytes().get(domain.len() - suffix.len() - 1) == Some(&b'.'));
        // DEVIATION: the rule returns the adapter unconditionally; no
        // caller reads it on a miss, so we skip the allocation and return an empty string.
        (matched, if matched { Cow::Borrowed(self.adapter.as_str()) } else { Cow::Borrowed("") })
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.suffix.clone()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}

impl DomainSuffix {
    #[must_use]
    pub fn new(suffix: &str, adapter: &str) -> Self {
        Self { base: Base, suffix: suffix.to_lowercase(), adapter: adapter.to_owned() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched(rule: &DomainSuffix, host: &str) -> (bool, String) {
        let mut metadata = Metadata { host: host.to_owned(), ..Default::default() };
        let (matched, adapter) = rule.match_(&mut metadata, &RuleMatchHelper::default());
        (matched, adapter.into_owned())
    }

    #[test]
    fn suffix_matches_require_a_label_boundary() {
        let rule = DomainSuffix::new("example.com", "DIRECT");
        assert_eq!(matched(&rule, "www.example.com"), (true, "DIRECT".to_owned()));
        assert_eq!(matched(&rule, "example.com"), (true, "DIRECT".to_owned()));
        assert!(!matched(&rule, "notexample.com").0);
        assert!(!matched(&rule, "example.com.evil.org").0);
    }

    #[test]
    fn suffix_match_is_case_sensitive_on_the_host() {
        let rule = DomainSuffix::new("EXAMPLE.com", "DIRECT");
        assert_eq!(matched(&rule, "www.example.com"), (true, "DIRECT".to_owned()));
        assert!(!matched(&rule, "www.EXAMPLE.com").0);
    }

    #[test]
    fn suffix_match_handles_non_ascii_hosts() {
        let rule = DomainSuffix::new("例え.jp", "DIRECT");
        assert_eq!(matched(&rule, "www.例え.jp"), (true, "DIRECT".to_owned()));
        assert!(!matched(&rule, "www.例え.com").0);
    }
}
