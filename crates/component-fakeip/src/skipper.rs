use std::sync::Arc;

use murmur_constant::dns::FilterMode;
use murmur_constant::matcher::DomainMatcher;
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper};

pub const USE_FAKE_IP: &str = "fake-ip";
pub const USE_REAL_IP: &str = "real-ip";

pub struct Skipper {
    pub rules: Vec<Arc<dyn Rule>>,
    pub host: Vec<Arc<dyn DomainMatcher>>,
    pub mode: FilterMode,
}

impl std::fmt::Debug for Skipper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Skipper")
            .field("rules", &self.rules.len())
            .field("host", &self.host.len())
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl Skipper {
    #[must_use]
    pub fn should_skipped(&self, domain: &str) -> bool {
        if !self.rules.is_empty() {
            let mut metadata = Metadata { host: domain.to_owned(), ..Metadata::default() };
            let helper = RuleMatchHelper::default();
            for rule in &self.rules {
                let (matched, action) = rule.match_(&mut metadata, &helper);
                if matched {
                    return action == USE_REAL_IP;
                }
            }
            return false;
        }

        let should = self.should_skipped_(domain);
        if self.mode == FilterMode::FILTER_WHITE_LIST {
            return !should;
        }
        should
    }

    /// Renamed with a trailing underscore because the exported `ShouldSkipped` already claims the
    /// `should_skipped` spelling under Rust's casing rules.
    fn should_skipped_(&self, domain: &str) -> bool {
        self.host.iter().any(|matcher| matcher.match_domain(domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use murmur_component_trie::domain_set::{DomainSet, DomainSetBuilder};

    /// `component/trie` (a separate crate) only gives `DomainSet` an inherent
    /// `match_domain`; this test needs it behind `constant::matcher::DomainMatcher` to build a
    /// `Skipper.host` entry. Neither crate depends on the other, so `impl DomainMatcher for
    /// DomainSet` would be an orphan impl; wrap it in a local newtype instead.
    struct TestDomainSet(DomainSet);

    impl DomainMatcher for TestDomainSet {
        fn match_domain(&self, domain: &str) -> bool {
            self.0.match_domain(domain)
        }
    }

    #[test]
    fn test_skipper_black_list() {
        let mut builder = DomainSetBuilder::default();
        builder.insert("example.com").unwrap();
        assert!(!builder.is_empty());
        let skipper = Skipper {
            rules: Vec::new(),
            host: vec![Arc::new(TestDomainSet(builder.build().unwrap()))],
            mode: FilterMode::default(),
        };
        assert!(skipper.should_skipped("example.com"));
        assert!(!skipper.should_skipped("foo.com"));
        assert!(!skipper.should_skipped_("baz.com"));
    }

    #[test]
    fn test_skipper_white_list() {
        let mut builder = DomainSetBuilder::default();
        builder.insert("example.com").unwrap();
        assert!(!builder.is_empty());
        let skipper = Skipper {
            rules: Vec::new(),
            host: vec![Arc::new(TestDomainSet(builder.build().unwrap()))],
            mode: FilterMode::FILTER_WHITE_LIST,
        };
        assert!(!skipper.should_skipped("example.com"));
        assert!(skipper.should_skipped("foo.com"));
        assert!(skipper.should_skipped("baz.com"));
    }
}
