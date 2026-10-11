use std::io::{Read, Write};

use anyhow::{anyhow, Result};

use murmur_component_trie::domain_set::{DomainSet, DomainSetBuilder};
use murmur_component_trie::domain_set_bin::read_domain_set_bin;
use murmur_constant::metadata::Metadata;
use murmur_constant::provider::interface::RuleBehavior;
use murmur_constant::rule::RuleMatchHelper;
use murmur_log::warnln;

use super::provider::{MrsRuleStrategy, RuleStrategy, SyncAsyncReader, SyncAsyncWriter};

#[derive(Debug, Default)]
pub(crate) struct DomainStrategy {
    count: i32,
    domain_set_builder: DomainSetBuilder,
    domain_set: Option<DomainSet>,
}

impl RuleStrategy for DomainStrategy {
    fn behavior(&self) -> RuleBehavior {
        RuleBehavior::DOMAIN
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> bool {
        self.domain_set.as_ref().is_some_and(|set| set.has(metadata.rule_host()))
    }

    fn count(&self) -> i32 {
        self.count
    }

    fn reset(&mut self) {
        self.domain_set_builder.reset();
        self.domain_set = None;
        self.count = 0;
    }

    fn insert(&mut self, rule: &str) {
        if rule.contains('/') {
            warnln!("skip invalid domain from rule provider: invalid domain {rule:?}: slash is not allowed");
            return;
        }
        match self.domain_set_builder.insert(rule) {
            Ok(()) => self.count += 1,
            Err(err) => warnln!("skip invalid domain from rule provider: {err}"),
        }
    }

    fn finish_insert(&mut self) {
        self.domain_set = self.domain_set_builder.build();
    }

    fn as_mrs(&self) -> Option<&dyn MrsRuleStrategy> {
        Some(self)
    }

    fn as_mrs_mut(&mut self) -> Option<&mut dyn MrsRuleStrategy> {
        Some(self)
    }
}

impl MrsRuleStrategy for DomainStrategy {
    fn load_mrs(&mut self, r: &mut dyn Read, count: i32) -> Result<()> {
        let mut reader = SyncAsyncReader(r);
        let domain_set = futures::executor::block_on(read_domain_set_bin(&mut reader))?;
        self.count = count;
        self.domain_set = Some(domain_set);
        Ok(())
    }

    fn write_mrs(&self, w: &mut dyn Write) -> Result<()> {
        let Some(domain_set) = self.domain_set.as_ref() else {
            return Err(anyhow!("nil domainSet"));
        };
        let mut writer = SyncAsyncWriter(w);
        futures::executor::block_on(domain_set.write_bin(&mut writer))
    }

    /// Emits a compact domain rule list in lexicographical order: a "domain" entry and a ".domain"
    /// entry collapse to one "+.domain" rule, while either entry alone is emitted unchanged.
    /// Returning `false` from `f` stops iteration.
    fn dump_mrs(&self, f: &mut dyn FnMut(&str) -> bool) {
        let Some(domain_set) = self.domain_set.as_ref() else {
            return;
        };

        let mut keys: Vec<String> = Vec::new();
        domain_set.foreach(|key| {
            keys.push(key.to_owned());
            true
        });

        keys.sort_by(|left, right| left.trim_start_matches('.').cmp(right.trim_start_matches('.')));

        let mut merged: Vec<String> = Vec::with_capacity(keys.len());
        let mut iter = keys.into_iter().peekable();
        while let Some(key) = iter.next() {
            let domain = key.trim_start_matches('.').to_owned();
            if iter.peek().is_some_and(|next| next.trim_start_matches('.') == domain) {
                iter.next();
                merged.push(format!("+.{domain}"));
            } else {
                merged.push(key);
            }
        }
        let mut keys = merged;
        keys.sort();

        for key in &keys {
            if !f(key) {
                return;
            }
        }
    }
}

pub(crate) fn new_domain_strategy() -> Box<DomainStrategy> {
    Box::default()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use murmur_constant::metadata::Metadata;
    use murmur_constant::rule::RuleMatchHelper;

    use super::super::provider::{MrsRuleStrategy, RuleStrategy};
    use super::new_domain_strategy;

    #[test]
    fn test_domain_strategy_dump_mrs() {
        struct TestCase {
            name: &'static str,
            domains: &'static [&'static str],
            expected: &'static [&'static str],
            queries: &'static [(&'static str, bool)],
        }

        let tests: &[TestCase] = &[
            TestCase {
                name: "suffix-only",
                domains: &[".example.com"],
                expected: &[".example.com"],
                queries: &[("example.com", false), ("www.example.com", true)],
            },
            TestCase {
                name: "exact-only",
                domains: &["example.com"],
                expected: &["example.com"],
                queries: &[("example.com", true), ("www.example.com", false)],
            },
            TestCase {
                name: "merge-terminals",
                domains: &["example.com", ".example.com"],
                expected: &["+.example.com"],
                queries: &[("example.com", true), ("www.example.com", true)],
            },
            TestCase {
                name: "deduplicate",
                domains: &["+.example.com", "+.example.com", "example.com", ".example.com"],
                expected: &["+.example.com"],
                queries: &[("example.com", true), ("www.example.com", true)],
            },
            TestCase {
                name: "mixed",
                domains: &[".example.com", "example.net", "example.org", ".example.org"],
                expected: &["+.example.org", ".example.com", "example.net"],
                queries: &[
                    ("example.com", false),
                    ("www.example.com", true),
                    ("example.net", true),
                    ("www.example.net", false),
                    ("example.org", true),
                    ("www.example.org", true),
                ],
            },
            TestCase {
                name: "wildcards",
                domains: &["*.example.com", "+.example.org", "test.*.google.com", ".test.*.google.com", ".example.net"],
                expected: &["*.example.com", "+.example.org", "+.test.*.google.com", ".example.net"],
                queries: &[
                    ("example.com", false),
                    ("www.example.com", true),
                    ("example.org", true),
                    ("www.example.org", true),
                    ("test.www.google.com", true),
                    ("www.test.www.google.com", true),
                    ("example.net", false),
                    ("www.example.net", true),
                ],
            },
        ];

        for test_case in tests {
            let mut strategy = new_domain_strategy();
            for domain in test_case.domains {
                strategy.insert(domain);
            }
            strategy.finish_insert();

            let mut rebuilt = new_domain_strategy();
            let mut domains: Vec<String> = Vec::new();
            strategy.dump_mrs(&mut |domain: &str| {
                domains.push(domain.to_owned());
                rebuilt.insert(domain);
                true
            });
            rebuilt.finish_insert();

            let expected: Vec<String> = test_case.expected.iter().map(|s| (*s).to_owned()).collect();
            assert_eq!(domains, expected, "{}", test_case.name);

            let queries: HashMap<&str, bool> = test_case.queries.iter().copied().collect();
            for (domain, expected) in queries {
                let mut metadata = Metadata { host: domain.to_owned(), ..Default::default() };
                assert_eq!(strategy.match_(&mut metadata, &RuleMatchHelper::default()), expected, "{domain}");
                assert_eq!(rebuilt.match_(&mut metadata, &RuleMatchHelper::default()), expected, "{domain}");
            }
        }
    }
}
