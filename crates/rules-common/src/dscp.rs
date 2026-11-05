use std::borrow::Cow;

use anyhow::anyhow;

use murmur_common::utils::ranges::{new_unsigned_ranges, IntRanges};
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct DSCP {
    base: Base,
    ranges: IntRanges<u8>,
    payload: String,
    adapter: String,
}

impl Rule for DSCP {
    fn rule_type(&self) -> RuleType {
        RuleType::DSCP
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let matched = self.ranges.check(metadata.dscp);
        // DEVIATION: the rule returns the adapter unconditionally; no caller
        // reads it on a miss, so we skip the allocation and return an empty string.
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

impl DSCP {
    pub fn new(dscp: &str, adapter: &str) -> anyhow::Result<Self> {
        let ranges = new_unsigned_ranges::<u8>(dscp).map_err(|err| anyhow!("parse DSCP rule fail: {err}"))?;
        for r in &ranges {
            if r.end() > 63 {
                return Err(anyhow!("DSCP couldn't be negative or exceed 63"));
            }
        }
        Ok(Self { base: Base, payload: dscp.to_owned(), ranges, adapter: adapter.to_owned() })
    }
}
