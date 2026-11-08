//! Patterns are compiled case-insensitively (see `domain_regex.rs`), and an engine failure
//! evaluates to `false` via `is_match(&target).unwrap_or(false)` below. Case folding uses
//! `str::to_lowercase`.

use std::borrow::Cow;

use fancy_regex::{Regex, RegexBuilder};

use murmur_component::wildcard::wildcard::match_ as wildcard_match;
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct Process {
    base: Base,
    pattern: String,
    adapter: String,
    rule_type: RuleType,
    regexp: Option<Regex>,
}

impl Rule for Process {
    fn rule_type(&self) -> RuleType {
        self.rule_type
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        if let Some(f) = &helper.find_process {
            f(metadata);
        }

        let target = match self.rule_type {
            RuleType::PROCESS_NAME | RuleType::PROCESS_NAME_REGEX | RuleType::PROCESS_NAME_WILDCARD => {
                metadata.process.clone()
            }
            _ => metadata.process_path.clone(),
        };

        match self.rule_type {
            RuleType::PROCESS_NAME_REGEX | RuleType::PROCESS_PATH_REGEX => (
                self.regexp.as_ref().is_some_and(|regexp| regexp.is_match(&target).unwrap_or(false)),
                Cow::Borrowed(self.adapter.as_str()),
            ),
            RuleType::PROCESS_NAME_WILDCARD | RuleType::PROCESS_PATH_WILDCARD => (
                wildcard_match(&self.pattern.to_lowercase(), &target.to_lowercase()),
                Cow::Borrowed(self.adapter.as_str()),
            ),
            _ => (target.to_lowercase() == self.pattern.to_lowercase(), Cow::Borrowed(self.adapter.as_str())),
        }
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

impl Process {
    pub fn new(pattern: &str, adapter: &str, rule_type: RuleType) -> anyhow::Result<Self> {
        let mut ps =
            Self { base: Base, pattern: pattern.to_owned(), adapter: adapter.to_owned(), rule_type, regexp: None };

        if matches!(rule_type, RuleType::PROCESS_NAME_REGEX | RuleType::PROCESS_PATH_REGEX) {
            let r = RegexBuilder::new(pattern).case_insensitive(true).build()?;
            ps.regexp = Some(r);
        }

        Ok(ps)
    }
}
