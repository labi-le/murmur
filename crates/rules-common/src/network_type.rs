use std::borrow::Cow;

use anyhow::{anyhow, Result};

use murmur_constant::metadata::{Metadata, NetWork};
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct NetworkType {
    base: Base,
    network: NetWork,
    adapter: String,
}

impl NetworkType {
    pub fn new(network: &str, adapter: &str) -> Result<Self> {
        let mut nt_type = Self { base: Base, network: NetWork::default(), adapter: adapter.to_owned() };

        match network.to_uppercase().as_str() {
            "TCP" => nt_type.network = NetWork::TCP,
            "UDP" => nt_type.network = NetWork::UDP,
            _ => return Err(anyhow!("unsupported network type, only TCP/UDP")),
        }

        Ok(nt_type)
    }
}

impl Rule for NetworkType {
    fn rule_type(&self) -> RuleType {
        RuleType::NETWORK
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let matched = self.network == metadata.network;
        // DEVIATION: the rule returns the adapter unconditionally; no
        // caller reads it on a miss, so we skip the allocation and return an empty string.
        (matched, if matched { Cow::Borrowed(self.adapter.as_str()) } else { Cow::Borrowed("") })
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.network.string()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}
