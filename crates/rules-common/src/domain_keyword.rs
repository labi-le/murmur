use std::borrow::Cow;

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct DomainKeyword {
    base: Base,
    keyword: String,
    adapter: String,
}

impl Rule for DomainKeyword {
    fn rule_type(&self) -> RuleType {
        RuleType::DOMAIN_KEYWORD
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let domain = metadata.rule_host();
        let matched = domain.contains(&self.keyword);
        // DEVIATION: the rule returns the adapter unconditionally; no
        // caller reads it on a miss, so we skip the allocation and return an empty string.
        (matched, if matched { Cow::Borrowed(self.adapter.as_str()) } else { Cow::Borrowed("") })
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.keyword.clone()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}

impl DomainKeyword {
    #[must_use]
    pub fn new(keyword: &str, adapter: &str) -> Self {
        Self { base: Base, keyword: keyword.to_lowercase(), adapter: adapter.to_owned() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched(rule: &DomainKeyword, host: &str) -> (bool, String) {
        let mut metadata = Metadata { host: host.to_owned(), ..Default::default() };
        let (matched, adapter) = rule.match_(&mut metadata, &RuleMatchHelper::default());
        (matched, adapter.into_owned())
    }

    #[test]
    fn keyword_match_is_case_sensitive_on_the_host() {
        let rule = DomainKeyword::new("EXAMPLE", "DIRECT");
        assert_eq!(matched(&rule, "www.example.com"), (true, "DIRECT".to_owned()));
        assert!(!matched(&rule, "www.EXAMPLE.com").0);
    }

    #[test]
    fn keyword_match_handles_non_ascii_hosts() {
        let rule = DomainKeyword::new("例え", "DIRECT");
        assert_eq!(matched(&rule, "www.例え.jp"), (true, "DIRECT".to_owned()));
        assert!(!matched(&rule, "www.other.jp").0);
    }
}
