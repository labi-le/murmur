use std::borrow::Cow;

use anyhow::{anyhow, Result};

use murmur_common::utils::ranges::{new_unsigned_ranges, IntRanges};
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::{err_payload, Base, ERR_PAYLOAD};

#[derive(Debug)]
pub struct Port {
    base: Base,
    adapter: String,
    payload: String,
    rule_type: RuleType,
    ranges: IntRanges<u16>,
}

impl Rule for Port {
    fn rule_type(&self) -> RuleType {
        self.rule_type
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let target_port = match self.rule_type {
            RuleType::IN_PORT => metadata.in_port,
            RuleType::SRC_PORT => metadata.src_port,
            _ => metadata.dst_port,
        };
        (self.ranges.check(target_port), Cow::Borrowed(self.adapter.as_str()))
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

impl Port {
    pub fn new(port: &str, adapter: &str, rule_type: RuleType) -> Result<Self> {
        let port_ranges = new_unsigned_ranges::<u16>(port).map_err(|err| anyhow!("{ERR_PAYLOAD}, {err}"))?;

        if port_ranges.is_empty() {
            return Err(err_payload());
        }

        Ok(Self { base: Base, adapter: adapter.to_owned(), payload: port.to_owned(), rule_type, ranges: port_ranges })
    }
}
