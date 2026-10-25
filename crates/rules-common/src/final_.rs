use std::borrow::Cow;

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct Match {
    base: Base,
    adapter: String,
}

impl Rule for Match {
    fn rule_type(&self) -> RuleType {
        RuleType::MATCH
    }

    fn match_(&self, _metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        (true, Cow::Borrowed(self.adapter.as_str()))
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        String::new()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}

impl Match {
    #[must_use]
    pub fn new(adapter: &str) -> Self {
        Self { base: Base, adapter: adapter.to_owned() }
    }
}
