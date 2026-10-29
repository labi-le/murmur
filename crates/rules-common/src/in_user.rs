use std::borrow::Cow;

use anyhow::{anyhow, Result};

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct InUser {
    base: Base,
    users: Vec<String>,
    adapter: String,
    payload: String,
}

impl Rule for InUser {
    fn rule_type(&self) -> RuleType {
        RuleType::IN_USER
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let matched = self.users.contains(&metadata.in_user);
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

impl InUser {
    pub fn new(i_users: &str, adapter: &str) -> Result<Self> {
        let mut users: Vec<String> = i_users.split('/').map(str::to_owned).collect();
        for user in &mut users {
            let trimmed = user.trim().to_owned();
            if trimmed.is_empty() {
                return Err(anyhow!("in user couldn't be empty"));
            }
            *user = trimmed;
        }

        Ok(Self { base: Base, users, adapter: adapter.to_owned(), payload: i_users.to_owned() })
    }
}
