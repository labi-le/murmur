use std::borrow::Cow;

use memchr::memmem::Finder;
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct DomainKeyword {
    base: Base,
    /// The needle search is fixed to the lowered keyword, so it is built once here rather than
    /// on every match. `Finder` owns its needle and keeps no interior mutability, which keeps the
    /// rule `Send + Sync` and avoids the self-referential borrow a borrowed `Finder` would need.
    /// It is the only retained copy of the keyword; `payload()` reconstructs the string from it.
    finder: Finder<'static>,
    adapter: String,
}

impl Rule for DomainKeyword {
    fn rule_type(&self) -> RuleType {
        RuleType::DOMAIN_KEYWORD
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let domain = metadata.rule_host();
        // Byte search over the host is equivalent to `str::contains` here: the needle is valid
        // UTF-8 and its first byte is never a continuation byte, so it can only match at a
        // scalar boundary. `Finder` reports an empty needle as a match at offset 0, matching the
        // `contains("")` behaviour the rule had before.
        let matched = self.finder.find(domain.as_bytes()).is_some();
        // DEVIATION: the rule returns the adapter unconditionally; no
        // caller reads it on a miss, so we skip the allocation and return an empty string.
        (matched, if matched { Cow::Borrowed(self.adapter.as_str()) } else { Cow::Borrowed("") })
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        // The finder was built from the bytes of a lowered `String`, so its needle is the lowered
        // keyword and always valid UTF-8. The lossy path is therefore never taken; this avoids a
        // second permanent keyword allocation and only allocates when the payload is requested.
        String::from_utf8_lossy(self.finder.needle()).into_owned()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}

impl DomainKeyword {
    #[must_use]
    pub fn new(keyword: &str, adapter: &str) -> Self {
        let keyword = keyword.to_lowercase();
        let finder = Finder::new(keyword.as_bytes()).into_owned();
        Self { base: Base, finder, adapter: adapter.to_owned() }
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

    #[test]
    fn empty_keyword_matches_every_host_including_an_empty_one() {
        let rule = DomainKeyword::new("", "DIRECT");
        assert_eq!(matched(&rule, "example.com"), (true, "DIRECT".to_owned()));
        assert_eq!(matched(&rule, ""), (true, "DIRECT".to_owned()));
    }

    #[test]
    fn keyword_is_matched_after_lowercase_expansion() {
        // U+0130 lowers to "i" plus U+0307, two scalars, so the needle is longer than the input.
        let rule = DomainKeyword::new("\u{0130}", "DIRECT");
        assert_eq!(matched(&rule, "i\u{0307}.example"), (true, "DIRECT".to_owned()));
        assert!(!matched(&rule, "\u{0130}.example").0);
    }

    #[test]
    fn a_keyword_miss_on_a_shared_prefix_does_not_match() {
        let rule = DomainKeyword::new("kwmid12", "DIRECT");
        assert!(matched(&rule, "kwmid12.example").0);
        assert!(!matched(&rule, "kwmid13.example").0);
    }

    #[test]
    fn payload_is_the_lowered_keyword() {
        let rule = DomainKeyword::new("EXAMPLE", "DIRECT");
        assert_eq!(rule.payload(), "example");
    }
}
