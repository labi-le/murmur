use std::borrow::Cow;
use std::net::IpAddr;

use anyhow::Result;

use murmur_constant::matcher::{DomainMatcher, IpMatcher};
use murmur_constant::metadata::Metadata;
use murmur_constant::provider::interface::RuleProvider;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::provider::tunnel;

#[derive(Debug)]
pub struct RuleSet {
    rule_provider_name: String,
    adapter: String,
    is_src: bool,
    no_resolve_ip: bool,
}

impl Rule for RuleSet {
    fn rule_type(&self) -> RuleType {
        RuleType::RULE_SET
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let Some(provider) = self.get_provider() else {
            return (false, Cow::Borrowed(""));
        };

        let matched = if self.is_src || self.no_resolve_ip {
            let masked = RuleMatchHelper {
                resolve_ip: None,
                find_process: helper.find_process.clone(),
                check_pass_rule: helper.check_pass_rule.clone(),
            };
            if self.is_src {
                metadata.swap_src_dst();
            }
            let matched = provider.match_(metadata, &masked);
            if self.is_src {
                metadata.swap_src_dst();
            }
            matched
        } else {
            provider.match_(metadata, helper)
        };

        (matched, Cow::Borrowed(self.adapter.as_str()))
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.rule_provider_name.clone()
    }

    fn provider_names(&self) -> Vec<String> {
        vec![self.rule_provider_name.clone()]
    }
}

impl DomainMatcher for RuleSet {
    fn match_domain(&self, domain: &str) -> bool {
        let Metadata {
            network,
            type_,
            src_ip,
            dst_ip,
            src_geo_ip,
            dst_geo_ip,
            src_ipasn,
            dst_ipasn,
            src_port,
            dst_port,
            in_ip,
            in_port,
            in_name,
            in_user,
            rematch_name,
            dns_mode,
            uid,
            process,
            process_path,
            special_proxy,
            special_rules,
            remote_dst,
            dscp,
            raw_src_addr,
            raw_dst_addr,
            sniff_host,
            ..
        } = Metadata::default();
        let mut metadata = Metadata {
            network,
            type_,
            src_ip,
            dst_ip,
            src_geo_ip,
            dst_geo_ip,
            src_ipasn,
            dst_ipasn,
            src_port,
            dst_port,
            in_ip,
            in_port,
            in_name,
            in_user,
            rematch_name,
            host: domain.to_owned(),
            dns_mode,
            uid,
            process,
            process_path,
            special_proxy,
            special_rules,
            remote_dst,
            dscp,
            raw_src_addr,
            raw_dst_addr,
            sniff_host,
        };
        self.match_(&mut metadata, &RuleMatchHelper::default()).0
    }
}

impl IpMatcher for RuleSet {
    fn match_ip(&self, ip: IpAddr) -> bool {
        let Metadata {
            network,
            type_,
            src_ip,
            src_geo_ip,
            dst_geo_ip,
            src_ipasn,
            dst_ipasn,
            src_port,
            dst_port,
            in_ip,
            in_port,
            in_name,
            in_user,
            rematch_name,
            host,
            dns_mode,
            uid,
            process,
            process_path,
            special_proxy,
            special_rules,
            remote_dst,
            dscp,
            raw_src_addr,
            raw_dst_addr,
            sniff_host,
            ..
        } = Metadata::default();
        let mut metadata = Metadata {
            network,
            type_,
            src_ip,
            dst_ip: Some(ip),
            src_geo_ip,
            dst_geo_ip,
            src_ipasn,
            dst_ipasn,
            src_port,
            dst_port,
            in_ip,
            in_port,
            in_name,
            in_user,
            rematch_name,
            host,
            dns_mode,
            uid,
            process,
            process_path,
            special_proxy,
            special_rules,
            remote_dst,
            dscp,
            raw_src_addr,
            raw_dst_addr,
            sniff_host,
        };
        self.match_(&mut metadata, &RuleMatchHelper::default()).0
    }
}

impl RuleSet {
    fn get_provider(&self) -> Option<std::sync::Arc<dyn RuleProvider>> {
        let t = tunnel()?;
        t.rule_providers().get(&self.rule_provider_name).cloned()
    }
}

impl RuleSet {
    pub fn new(rule_provider_name: &str, adapter: &str, is_src: bool, no_resolve_ip: bool) -> Result<Self> {
        Ok(Self {
            rule_provider_name: rule_provider_name.to_owned(),
            adapter: adapter.to_owned(),
            is_src,
            no_resolve_ip,
        })
    }
}
