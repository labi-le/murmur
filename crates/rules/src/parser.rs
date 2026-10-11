use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::logic::logic::Logic;
use crate::provider::rule_set::RuleSet;
use murmur_constant::rule::{Rule, RuleType};
use murmur_rules_common::base::{parse_params, ParseRuleFunc};
use murmur_rules_common::domain::Domain;
use murmur_rules_common::domain_keyword::DomainKeyword;
use murmur_rules_common::domain_regex::DomainRegex;
use murmur_rules_common::domain_suffix::DomainSuffix;
use murmur_rules_common::domain_wildcard::DomainWildcard;
use murmur_rules_common::dscp::DSCP;
use murmur_rules_common::final_::Match;
use murmur_rules_common::geoip::GEOIP;
use murmur_rules_common::geosite::GEOSITE;
use murmur_rules_common::in_name::InName;
use murmur_rules_common::in_type::InType;
use murmur_rules_common::in_user::InUser;
use murmur_rules_common::ipasn::ASN;
use murmur_rules_common::ipcidr::{with_ipcidr_no_resolve, with_ipcidr_source_ip, IPCIDR};
use murmur_rules_common::ipsuffix::IPSuffix;
use murmur_rules_common::network_type::NetworkType;
use murmur_rules_common::port::Port;
use murmur_rules_common::process::Process;
use murmur_rules_common::rematch_name::RematchName;
use murmur_rules_common::uid::Uid;

#[expect(
    clippy::implicit_hasher,
    reason = "`parse_rule` is the published signature: callers build `sub_rules` with the default hasher"
)]
pub fn parse_rule(
    tp: &str,
    payload: &str,
    target: &str,
    params: &[String],
    sub_rules: &HashMap<String, Vec<Arc<dyn Rule>>>,
) -> Result<Arc<dyn Rule>> {
    // only MATCH allowed doesn't contain payload
    if tp != "MATCH" && payload.is_empty() {
        return Err(anyhow!("missing subsequent parameters: {tp}"));
    }

    let parse_rule_fn: ParseRuleFunc = Arc::new(parse_rule);

    let parsed: Arc<dyn Rule> = match tp {
        "DOMAIN" => Arc::new(Domain::new(payload, target)),
        "DOMAIN-SUFFIX" => Arc::new(DomainSuffix::new(payload, target)),
        "DOMAIN-KEYWORD" => Arc::new(DomainKeyword::new(payload, target)),
        "DOMAIN-REGEX" => Arc::new(DomainRegex::new(payload, target)?),
        "DOMAIN-WILDCARD" => Arc::new(DomainWildcard::new(payload, target)?),
        "GEOSITE" => Arc::new(GEOSITE::new(payload, target)?),
        "GEOIP" => {
            let (is_src, no_resolve) = parse_params(params);
            Arc::new(GEOIP::new(payload, target, is_src, no_resolve)?)
        }
        "SRC-GEOIP" => Arc::new(GEOIP::new(payload, target, true, true)?),
        "IP-ASN" => {
            let (is_src, no_resolve) = parse_params(params);
            Arc::new(ASN::new(payload, target, is_src, no_resolve)?)
        }
        "SRC-IP-ASN" => Arc::new(ASN::new(payload, target, true, true)?),
        "IP-CIDR" | "IP-CIDR6" => {
            let (is_src, no_resolve) = parse_params(params);
            Arc::new(IPCIDR::new(
                payload,
                target,
                &[with_ipcidr_source_ip(is_src), with_ipcidr_no_resolve(no_resolve)],
            )?)
        }
        "SRC-IP-CIDR" => {
            Arc::new(IPCIDR::new(payload, target, &[with_ipcidr_source_ip(true), with_ipcidr_no_resolve(true)])?)
        }
        "IP-SUFFIX" => {
            let (is_src, no_resolve) = parse_params(params);
            Arc::new(IPSuffix::new(payload, target, is_src, no_resolve)?)
        }
        "SRC-IP-SUFFIX" => Arc::new(IPSuffix::new(payload, target, true, true)?),
        "SRC-PORT" => Arc::new(Port::new(payload, target, RuleType::SRC_PORT)?),
        "DST-PORT" => Arc::new(Port::new(payload, target, RuleType::DST_PORT)?),
        "IN-PORT" => Arc::new(Port::new(payload, target, RuleType::IN_PORT)?),
        "DSCP" => Arc::new(DSCP::new(payload, target)?),
        "PROCESS-NAME" => Arc::new(Process::new(payload, target, RuleType::PROCESS_NAME)?),
        "PROCESS-PATH" => Arc::new(Process::new(payload, target, RuleType::PROCESS_PATH)?),
        "PROCESS-NAME-REGEX" => Arc::new(Process::new(payload, target, RuleType::PROCESS_NAME_REGEX)?),
        "PROCESS-PATH-REGEX" => Arc::new(Process::new(payload, target, RuleType::PROCESS_PATH_REGEX)?),
        "PROCESS-NAME-WILDCARD" => Arc::new(Process::new(payload, target, RuleType::PROCESS_NAME_WILDCARD)?),
        "PROCESS-PATH-WILDCARD" => Arc::new(Process::new(payload, target, RuleType::PROCESS_PATH_WILDCARD)?),
        "NETWORK" => Arc::new(NetworkType::new(payload, target)?),
        "UID" => Arc::new(Uid::new(payload, target)?),
        "IN-TYPE" => Arc::new(InType::new(payload, target)?),
        "IN-USER" => Arc::new(InUser::new(payload, target)?),
        "IN-NAME" => Arc::new(InName::new(payload, target)?),
        "REMATCH-NAME" => Arc::new(RematchName::new(payload, target)?),
        "SUB-RULE" => Arc::new(Logic::sub_rule(payload, target, sub_rules.clone(), &parse_rule_fn)?),
        "AND" => Arc::new(Logic::and(payload, target, &parse_rule_fn)?),
        "OR" => Arc::new(Logic::or(payload, target, &parse_rule_fn)?),
        "NOT" => Arc::new(Logic::not(payload, target, &parse_rule_fn)?),
        "RULE-SET" => {
            let (is_src, no_resolve) = parse_params(params);
            Arc::new(RuleSet::new(payload, target, is_src, no_resolve)?)
        }
        "MATCH" => Arc::new(Match::new(target)),
        _ => return Err(anyhow!("unsupported rule type: {tp}")),
    };

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;
    use murmur_constant::metadata::Metadata;
    use murmur_constant::rule::RuleMatchHelper;

    fn empty_sub_rules() -> HashMap<String, Vec<Arc<dyn Rule>>> {
        HashMap::new()
    }

    #[test]
    fn match_needs_no_payload() {
        let rule = parse_rule("MATCH", "", "DIRECT", &[], &empty_sub_rules()).unwrap();
        assert_eq!(rule.rule_type(), RuleType::MATCH);
        assert_eq!(rule.adapter(), "DIRECT");
    }

    #[test]
    fn missing_payload_on_a_non_match_type_is_an_error() {
        let err = parse_rule("DOMAIN", "", "P", &[], &empty_sub_rules()).map(|_| ()).unwrap_err();
        assert_eq!(err.to_string(), "missing subsequent parameters: DOMAIN");
    }

    #[test]
    fn unknown_type_is_an_error() {
        let err = parse_rule("NOT-A-RULE-TYPE", "x", "P", &[], &empty_sub_rules()).map(|_| ()).unwrap_err();
        assert_eq!(err.to_string(), "unsupported rule type: NOT-A-RULE-TYPE");
    }

    #[test]
    fn ip_cidr_no_resolve_param_skips_the_resolver_hook() {
        let rule = parse_rule("IP-CIDR", "1.0.0.0/8", "P", &["no-resolve".to_owned()], &empty_sub_rules()).unwrap();
        assert_eq!(rule.rule_type(), RuleType::IPCIDR);

        let called = Arc::new(AtomicBool::new(false));
        let called_in_closure = Arc::clone(&called);
        let helper = RuleMatchHelper {
            resolve_ip: Some(Arc::new(move |_metadata| called_in_closure.store(true, Ordering::SeqCst))),
            ..Default::default()
        };
        let mut metadata = Metadata::default();
        rule.match_(&mut metadata, &helper);
        assert!(!called.load(Ordering::SeqCst), "no-resolve must skip the resolver hook");
    }

    #[test]
    fn ip_cidr_without_no_resolve_calls_the_resolver_hook() {
        let rule = parse_rule("IP-CIDR", "1.0.0.0/8", "P", &[], &empty_sub_rules()).unwrap();

        let called = Arc::new(AtomicBool::new(false));
        let called_in_closure = Arc::clone(&called);
        let helper = RuleMatchHelper {
            resolve_ip: Some(Arc::new(move |_metadata| called_in_closure.store(true, Ordering::SeqCst))),
            ..Default::default()
        };
        let mut metadata = Metadata::default();
        rule.match_(&mut metadata, &helper);
        assert!(called.load(Ordering::SeqCst), "a resolvable IP-CIDR without no-resolve must call the resolver hook");
    }

    #[test]
    fn ip_cidr_src_param_matches_against_the_source_ip_not_the_destination() {
        let rule = parse_rule("IP-CIDR", "1.0.0.0/8", "P", &["src".to_owned()], &empty_sub_rules()).unwrap();
        assert_eq!(rule.rule_type(), RuleType::SRC_IPCIDR);

        let mut metadata = Metadata {
            src_ip: Some(IpAddr::from([1, 2, 3, 4])),
            dst_ip: Some(IpAddr::from([9, 9, 9, 9])),
            ..Default::default()
        };
        let (matched, adapter) = rule.match_(&mut metadata, &RuleMatchHelper::default());
        assert!(matched, "1.2.3.4 is inside 1.0.0.0/8 and must match on the source IP");
        assert_eq!(adapter, "P");
    }
}
