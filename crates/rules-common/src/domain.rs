use std::borrow::Cow;

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct Domain {
    base: Base,
    host: String,
    adapter: String,
}

impl Rule for Domain {
    fn rule_type(&self) -> RuleType {
        RuleType::DOMAIN
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let matched = metadata.rule_host() == self.host;
        // DEVIATION: the rule returns the adapter unconditionally; no caller
        // reads it on a miss, so we skip the allocation and return an empty string instead.
        (matched, if matched { Cow::Borrowed(self.adapter.as_str()) } else { Cow::Borrowed("") })
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.host.clone()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}

impl Domain {
    #[must_use]
    pub fn new(domain: &str, adapter: &str) -> Self {
        Self { base: Base, host: domain.to_lowercase(), adapter: adapter.to_owned() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched(rule: &Domain, host: &str) -> (bool, String) {
        let mut metadata = Metadata { host: host.to_owned(), ..Default::default() };
        let (matched, adapter) = rule.match_(&mut metadata, &RuleMatchHelper::default());
        (matched, adapter.into_owned())
    }

    #[test]
    fn exact_match_is_case_sensitive_on_the_host() {
        let rule = Domain::new("EXAMPLE.com", "DIRECT");
        assert_eq!(matched(&rule, "example.com"), (true, "DIRECT".to_owned()));
        assert!(!matched(&rule, "EXAMPLE.com").0);
        assert!(!matched(&rule, "www.example.com").0);
    }

    #[test]
    fn exact_match_handles_non_ascii_hosts() {
        let rule = Domain::new("例え.jp", "DIRECT");
        assert_eq!(matched(&rule, "例え.jp"), (true, "DIRECT".to_owned()));
        assert!(!matched(&rule, "例え.jp.").0);
    }

    /// A rule matches the sniffed name, not the connection host, while a sniff is set, and falls
    /// back to the host once the sniff is cleared.
    #[test]
    fn sniffed_host_takes_precedence_over_the_connection_host() {
        let rule = Domain::new("sniff.example.com", "DIRECT");
        let mut metadata = Metadata {
            host: "host.example.com".to_owned(),
            sniff_host: "sniff.example.com".to_owned(),
            ..Default::default()
        };
        let (matched, adapter) = rule.match_(&mut metadata, &RuleMatchHelper::default());
        assert_eq!((matched, adapter.as_ref()), (true, "DIRECT"));

        metadata.sniff_host = String::new();
        let (matched, adapter) = rule.match_(&mut metadata, &RuleMatchHelper::default());
        assert_eq!((matched, adapter.as_ref()), (false, ""));
    }
}
