use std::borrow::Cow;

use anyhow::Result;
use ipnet::IpNet;

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::{err_payload, Base};

/// The function type accepts closures that capture state, so this is a boxed `Fn` rather than a
/// bare `fn` pointer.
pub type IPCIDROption = Box<dyn Fn(&mut IPCIDR)>;

#[must_use]
pub fn with_ipcidr_source_ip(b: bool) -> IPCIDROption {
    Box::new(move |i: &mut IPCIDR| {
        i.is_source_ip = b;
    })
}

#[must_use]
pub fn with_ipcidr_no_resolve(no_resolve: bool) -> IPCIDROption {
    Box::new(move |i: &mut IPCIDR| {
        i.no_resolve_ip = no_resolve;
    })
}

#[derive(Debug)]
pub struct IPCIDR {
    base: Base,
    ipnet: IpNet,
    adapter: String,
    is_source_ip: bool,
    no_resolve_ip: bool,
}

impl Rule for IPCIDR {
    fn rule_type(&self) -> RuleType {
        if self.is_source_ip {
            RuleType::SRC_IPCIDR
        } else {
            RuleType::IPCIDR
        }
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        if !self.no_resolve_ip && !self.is_source_ip {
            if let Some(f) = &helper.resolve_ip {
                f(metadata);
            }
        }

        let ip = if self.is_source_ip { metadata.src_ip } else { metadata.dst_ip };
        (ip.is_some_and(|ip| self.ipnet.contains(&ip)), Cow::Borrowed(self.adapter.as_str()))
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.ipnet.to_string()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}

impl IPCIDR {
    pub fn new(s: &str, adapter: &str, opts: &[IPCIDROption]) -> Result<Self> {
        let ipnet: IpNet = s.parse().map_err(|_| err_payload())?;

        let mut ipcidr =
            Self { base: Base, ipnet, adapter: adapter.to_owned(), is_source_ip: false, no_resolve_ip: false };

        for o in opts {
            o(&mut ipcidr);
        }

        Ok(ipcidr)
    }
}
