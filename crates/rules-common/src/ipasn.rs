use std::borrow::Cow;
use std::future::Future;

use anyhow::Result;

use murmur_component_geodata::init;
use murmur_component_mmdb as mmdb;
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};
use murmur_log::errorln;

use super::base::Base;

fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

#[derive(Debug)]
pub struct ASN {
    base: Base,
    asn: String,
    adapter: String,
    no_resolve_ip: bool,
    is_source_ip: bool,
}

impl Rule for ASN {
    fn rule_type(&self) -> RuleType {
        if self.is_source_ip {
            RuleType::SRC_IPASN
        } else {
            RuleType::IPASN
        }
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        if !self.no_resolve_ip && !self.is_source_ip {
            if let Some(f) = &helper.resolve_ip {
                f(metadata);
            }
        }

        let ip = if self.is_source_ip { metadata.src_ip } else { metadata.dst_ip };
        let Some(ip) = ip else {
            return (false, Cow::Borrowed(""));
        };

        let (asn, aso) = mmdb::asn_instance().lookup_asn(&ip);
        if self.is_source_ip {
            metadata.src_ipasn = format!("{asn} {aso}");
        } else {
            metadata.dst_ipasn = format!("{asn} {aso}");
        }

        (self.asn == asn, Cow::Borrowed(self.adapter.as_str()))
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.asn.clone()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}

impl ASN {
    pub fn new(asn: &str, adapter: &str, is_src: bool, no_resolve_ip: bool) -> Result<Self> {
        if let Err(err) = block_on(init::init_asn()) {
            errorln!("can't initial ASN: {err}");
            return Err(err);
        }

        Ok(Self { base: Base, asn: asn.to_owned(), adapter: adapter.to_owned(), no_resolve_ip, is_source_ip: is_src })
    }
}
