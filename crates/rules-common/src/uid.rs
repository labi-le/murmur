use std::borrow::Cow;

use anyhow::{anyhow, Result};

use murmur_common::utils::ranges::{new_unsigned_ranges, IntRanges};
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};
use murmur_log::warnln;

use super::base::{err_payload, Base, ERR_PAYLOAD};

#[derive(Debug)]
pub struct Uid {
    base: Base,
    uids: IntRanges<u32>,
    payload: String,
    adapter: String,
}

impl Rule for Uid {
    fn rule_type(&self) -> RuleType {
        RuleType::UID
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        if let Some(f) = &helper.find_process {
            f(metadata);
        }
        if metadata.uid != 0 && self.uids.check(metadata.uid) {
            return (true, Cow::Borrowed(self.adapter.as_str()));
        }
        warnln!("[UID] could not get uid from {}", metadata);
        (false, Cow::Borrowed(""))
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

impl Uid {
    pub fn new(o_uid: &str, adapter: &str) -> Result<Self> {
        if !(cfg!(target_os = "linux") || cfg!(target_os = "android")) {
            return Err(anyhow!("uid rule not support this platform"));
        }

        let uid_range = new_unsigned_ranges::<u32>(o_uid).map_err(|err| anyhow!("{ERR_PAYLOAD}, {err}"))?;

        if uid_range.is_empty() {
            return Err(err_payload());
        }

        Ok(Self { base: Base, adapter: adapter.to_owned(), payload: o_uid.to_owned(), uids: uid_range })
    }
}
