use std::borrow::Cow;

use anyhow::{anyhow, Result};

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct InName {
    base: Base,
    names: Vec<String>,
    adapter: String,
    payload: String,
}

impl Rule for InName {
    fn rule_type(&self) -> RuleType {
        RuleType::IN_NAME
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let matched = self.names.contains(&metadata.in_name);
        (matched, if matched { Cow::Borrowed(self.adapter.as_str()) } else { Cow::Borrowed("") })
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.payload.clone()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}

impl InName {
    pub fn new(i_names: &str, adapter: &str) -> Result<Self> {
        let mut names: Vec<String> = i_names.split('/').map(str::to_owned).collect();
        for name in &mut names {
            let trimmed = name.trim().to_owned();
            if trimmed.is_empty() {
                return Err(anyhow!("in name couldn't be empty"));
            }
            *name = trimmed;
        }

        Ok(Self { base: Base, names, adapter: adapter.to_owned(), payload: i_names.to_owned() })
    }
}
