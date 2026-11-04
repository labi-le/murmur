use std::sync::Arc;

use anyhow::{anyhow, Result};

use murmur_constant::metadata::Metadata;
use murmur_constant::provider::interface::RuleBehavior;
use murmur_constant::rule::{Rule, RuleMatchHelper};
use murmur_log::warnln;
use murmur_rules_common::base::{parse_rule_payload, ParseRuleFunc};

use super::provider::RuleStrategy;

pub(crate) struct ClassicalStrategy {
    rules: Vec<Arc<dyn Rule>>,
    count: i32,
    parse: Option<ParseRuleFunc>,
}

impl RuleStrategy for ClassicalStrategy {
    fn behavior(&self) -> RuleBehavior {
        RuleBehavior::CLASSICAL
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> bool {
        self.rules.iter().any(|rule| rule.match_(metadata, helper).0)
    }

    fn count(&self) -> i32 {
        self.count
    }

    fn reset(&mut self) {
        self.rules = Vec::new();
        self.count = 0;
    }

    fn insert(&mut self, rule: &str) {
        match self.payload_to_rule(rule) {
            Ok(r) => {
                self.rules.push(r);
                self.count += 1;
            }
            Err(err) => warnln!("parse classical rule [{rule}] error: {err}"),
        }
    }

    fn finish_insert(&mut self) {}
}

impl ClassicalStrategy {
    fn payload_to_rule(&self, rule: &str) -> Result<Arc<dyn Rule>> {
        let (tp, payload, target, params) = parse_rule_payload(rule, false);
        match tp.as_str() {
            "MATCH" | "RULE-SET" | "SUB-RULE" => {
                return Err(anyhow!("unsupported rule type on classical rule-set: {tp}"));
            }
            _ => {}
        }
        let Some(parse) = self.parse.as_ref() else {
            return Err(anyhow!("classical strategy has no parse function"));
        };
        parse(&tp, &payload, &target, &params, &std::collections::HashMap::new())
    }
}

pub(crate) fn new_classical_strategy(parse: Option<ParseRuleFunc>) -> Box<dyn RuleStrategy> {
    Box::new(ClassicalStrategy { rules: Vec::new(), count: 0, parse })
}
