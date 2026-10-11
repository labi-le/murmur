use std::io::{Read, Write};

use anyhow::{anyhow, Result};

use murmur_component::cidr::ipcidr_set::IpCidrSet;
use murmur_component::cidr::ipcidr_set_bin::read_ip_cidr_set;
use murmur_constant::metadata::Metadata;
use murmur_constant::provider::interface::RuleBehavior;
use murmur_constant::rule::RuleMatchHelper;
use murmur_log::warnln;

use super::provider::{MrsRuleStrategy, RuleStrategy, SyncAsyncReader, SyncAsyncWriter};

#[derive(Debug, Default)]
pub(crate) struct IpcidrStrategy {
    count: i32,
    cidr_set: Option<IpCidrSet>,
}

impl RuleStrategy for IpcidrStrategy {
    fn behavior(&self) -> RuleBehavior {
        RuleBehavior::IPCIDR
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> bool {
        if let Some(resolve_ip) = helper.resolve_ip.as_ref() {
            resolve_ip(metadata);
        }
        self.cidr_set.as_ref().is_some_and(|set| metadata.dst_ip.is_some_and(|ip| set.is_contain(ip)))
    }

    fn count(&self) -> i32 {
        self.count
    }

    fn reset(&mut self) {
        self.cidr_set = Some(IpCidrSet::new_ip_cidr_set());
        self.count = 0;
    }

    fn insert(&mut self, rule: &str) {
        let Some(cidr_set) = self.cidr_set.as_mut() else {
            return;
        };
        match cidr_set.add_ip_cidr_for_string(rule) {
            Ok(()) => self.count += 1,
            Err(_) => warnln!("invalid Ipcidr:[{rule}]"),
        }
    }

    fn finish_insert(&mut self) {
        if let Some(cidr_set) = self.cidr_set.as_mut() {
            let _ = cidr_set.merge();
        }
    }

    fn as_mrs(&self) -> Option<&dyn MrsRuleStrategy> {
        Some(self)
    }

    fn as_mrs_mut(&mut self) -> Option<&mut dyn MrsRuleStrategy> {
        Some(self)
    }

    fn to_ip_cidr(&self) -> Option<&IpCidrSet> {
        self.cidr_set.as_ref()
    }
}

impl MrsRuleStrategy for IpcidrStrategy {
    fn load_mrs(&mut self, r: &mut dyn Read, count: i32) -> Result<()> {
        let mut reader = SyncAsyncReader(r);
        let cidr_set = futures::executor::block_on(read_ip_cidr_set(&mut reader))?;
        self.count = count;
        self.cidr_set = Some(cidr_set);
        Ok(())
    }

    fn write_mrs(&self, w: &mut dyn Write) -> Result<()> {
        let Some(cidr_set) = self.cidr_set.as_ref() else {
            return Err(anyhow!("nil cidrSet"));
        };
        let mut writer = SyncAsyncWriter(w);
        futures::executor::block_on(cidr_set.write_bin(&mut writer))
    }

    fn dump_mrs(&self, f: &mut dyn FnMut(&str) -> bool) {
        let Some(cidr_set) = self.cidr_set.as_ref() else {
            return;
        };
        cidr_set.foreach(|prefix| f(&prefix.to_string()));
    }
}

pub(crate) fn new_ip_cidr_strategy() -> Box<dyn RuleStrategy> {
    Box::<IpcidrStrategy>::default()
}
