use std::borrow::Cow;

use murmur_component::wildcard::wildcard::match_ as wildcard_match;
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct DomainWildcard {
    base: Base,
    pattern: String,
    adapter: String,
}

impl Rule for DomainWildcard {
    fn rule_type(&self) -> RuleType {
        RuleType::DOMAIN_WILDCARD
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let matched = wildcard_match(&self.pattern, metadata.rule_host());
        // DEVIATION: the rule returns the adapter unconditionally; no
        // caller reads it on a miss, so we skip the allocation and return an empty string.
        (matched, if matched { Cow::Borrowed(self.adapter.as_str()) } else { Cow::Borrowed("") })
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.pattern.clone()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}

impl DomainWildcard {
    pub fn new(pattern: &str, adapter: &str) -> anyhow::Result<Self> {
        Ok(Self { base: Base, pattern: pattern.to_lowercase(), adapter: adapter.to_owned() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched(rule: &DomainWildcard, host: &str) -> (bool, String) {
        let mut metadata = Metadata { host: host.to_owned(), ..Default::default() };
        let (matched, adapter) = rule.match_(&mut metadata, &RuleMatchHelper::default());
        (matched, adapter.into_owned())
    }

    #[test]
    fn wildcard_match_is_case_sensitive_on_the_host() {
        let rule = DomainWildcard::new("*.EXAMPLE.com", "DIRECT").unwrap();
        assert_eq!(matched(&rule, "www.example.com"), (true, "DIRECT".to_owned()));
        assert!(!matched(&rule, "www.EXAMPLE.com").0);
    }

    #[test]
    fn wildcard_match_handles_non_ascii_hosts() {
        let rule = DomainWildcard::new("*.例え.jp", "DIRECT").unwrap();
        assert_eq!(matched(&rule, "www.例え.jp"), (true, "DIRECT".to_owned()));
        assert!(!matched(&rule, "www.例え.com").0);
    }
}
