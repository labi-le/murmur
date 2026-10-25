use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};
use murmur_rules_common::base::{parse_rule_payload, ParseRuleFunc};

pub struct Logic {
    initial_payload: String,
    payload_cache: OnceLock<String>,
    adapter: String,
    rule_type: RuleType,
    rules: Vec<Arc<dyn Rule>>,
    sub_rules: HashMap<String, Vec<Arc<dyn Rule>>>,
}

impl std::fmt::Debug for Logic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Logic")
            .field("adapter", &self.adapter)
            .field("rule_type", &self.rule_type)
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}

impl Logic {
    fn empty(
        rule_type: RuleType,
        payload: &str,
        adapter: &str,
        sub_rules: HashMap<String, Vec<Arc<dyn Rule>>>,
    ) -> Self {
        Self {
            initial_payload: payload.to_owned(),
            payload_cache: OnceLock::new(),
            adapter: adapter.to_owned(),
            rule_type,
            rules: Vec::new(),
            sub_rules,
        }
    }
}

impl Logic {
    pub fn sub_rule(
        payload: &str,
        adapter: &str,
        sub_rules: HashMap<String, Vec<Arc<dyn Rule>>>,
        parse_rule: &ParseRuleFunc,
    ) -> Result<Self> {
        let mut logic = Self::empty(RuleType::SUB_RULES, payload, adapter, sub_rules);
        logic.parse_payload(&format!("({payload})"), parse_rule)?;

        if logic.rules.len() != 1 {
            return Err(anyhow!("Sub-Rule rule must contain one rule"));
        }
        Ok(logic)
    }

    pub fn not(payload: &str, adapter: &str, parse_rule: &ParseRuleFunc) -> Result<Self> {
        let mut logic = Self::empty(RuleType::NOT, payload, adapter, HashMap::new());
        logic.parse_payload(payload, parse_rule)?;

        if logic.rules.len() != 1 {
            return Err(anyhow!("not rule must contain one rule"));
        }
        Ok(logic)
    }

    pub fn or(payload: &str, adapter: &str, parse_rule: &ParseRuleFunc) -> Result<Self> {
        let mut logic = Self::empty(RuleType::OR, payload, adapter, HashMap::new());
        logic.parse_payload(payload, parse_rule)?;
        Ok(logic)
    }

    pub fn and(payload: &str, adapter: &str, parse_rule: &ParseRuleFunc) -> Result<Self> {
        let mut logic = Self::empty(RuleType::AND, payload, adapter, HashMap::new());
        logic.parse_payload(payload, parse_rule)?;
        Ok(logic)
    }
}

#[derive(Clone, Copy, Debug)]
struct RangeSpan {
    start: usize,
    end: usize,
}

impl RangeSpan {
    const fn contain_range(&self, pre_start: usize, pre_end: usize) -> bool {
        pre_start < self.start && pre_end > self.end
    }
}

impl Logic {
    fn payload_to_rule(sub_payload: &str, parse_rule: &ParseRuleFunc) -> Result<Arc<dyn Rule>> {
        let (tp, payload, target, params) = parse_rule_payload(sub_payload, false);
        match tp.as_str() {
            "MATCH" | "SUB-RULE" => return Err(anyhow!("unsupported rule type [{tp}] on logic rule")),
            "" => return Err(anyhow!("[{sub_payload}] format is error")),
            _ => {}
        }
        parse_rule(&tp, &payload, &target, &params, &HashMap::new())
    }

    fn format(payload: &str) -> Result<Vec<RangeSpan>> {
        let mut stack: Vec<usize> = Vec::new();
        let mut sub_ranges: Vec<RangeSpan> = Vec::new();
        for (i, c) in payload.char_indices() {
            if c == '(' {
                stack.push(i);
            } else if c == ')' {
                let Some(start) = stack.pop() else {
                    return Err(anyhow!("missing '('"));
                };
                sub_ranges.push(RangeSpan { start, end: i });
            }
        }

        if !stack.is_empty() {
            return Err(anyhow!("format error is missing )"));
        }

        sub_ranges.sort_by_key(|r| r.start);

        Ok(sub_ranges)
    }

    fn find_sub_rule_range(payload: &str, rule_ranges: &[RangeSpan]) -> Vec<RangeSpan> {
        let payload_len = payload.len();
        let mut sub_rule_range: Vec<RangeSpan> = Vec::new();
        for rr in rule_ranges {
            if rr.start == 0 && rr.end == payload_len - 1 {
                continue;
            }

            let contain_in_sub = sub_rule_range.iter().any(|r| rr.contain_range(r.start, r.end));

            if !contain_in_sub {
                sub_rule_range.push(*rr);
            }
        }

        sub_rule_range
    }

    fn parse_payload(&mut self, payload: &str, parse_rule: &ParseRuleFunc) -> Result<()> {
        if !payload.starts_with('(') || !payload.ends_with(')') {
            return Err(anyhow!("payload format error"));
        }

        let sub_all_ranges = Self::format(payload)?;

        let mut rules: Vec<Arc<dyn Rule>> = Vec::with_capacity(sub_all_ranges.len());

        let sub_ranges = Self::find_sub_rule_range(payload, &sub_all_ranges);
        for sub_range in sub_ranges {
            let Some(sub_payload) = payload.get(sub_range.start + 1..sub_range.end) else {
                return Err(anyhow!("payload format error"));
            };

            let rule = Self::payload_to_rule(sub_payload, parse_rule)?;

            rules.push(rule);
        }

        self.rules = rules;

        Ok(())
    }
}

fn match_sub_rules<'a>(
    metadata: &mut Metadata,
    name: &str,
    sub_rules: &'a HashMap<String, Vec<Arc<dyn Rule>>>,
    helper: &RuleMatchHelper,
) -> (bool, Cow<'a, str>) {
    let Some(rules) = sub_rules.get(name) else {
        return (false, Cow::Borrowed(""));
    };
    for rule in rules {
        let (mut m, mut a) = rule.match_(metadata, helper);
        if m {
            if rule.rule_type() == RuleType::SUB_RULES {
                (m, a) = match_sub_rules(metadata, &rule.adapter(), sub_rules, helper);
            }
            if m && (a == "PASS-RULE" || helper.check_pass_rule.as_ref().is_some_and(|f| f(metadata, &a))) {
                continue;
            }
            return (m, a);
        }
    }
    (false, Cow::Borrowed(""))
}

impl Rule for Logic {
    fn rule_type(&self) -> RuleType {
        self.rule_type
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        match self.rule_type {
            RuleType::SUB_RULES => {
                let Some(rule) = self.rules.first() else {
                    return (false, Cow::Borrowed(""));
                };
                let (m, _) = rule.match_(metadata, helper);
                if m {
                    match_sub_rules(metadata, &self.adapter, &self.sub_rules, helper)
                } else {
                    (false, Cow::Borrowed(""))
                }
            }
            RuleType::NOT => {
                let Some(rule) = self.rules.first() else {
                    return (false, Cow::Borrowed(""));
                };
                let (m, _) = rule.match_(metadata, helper);
                if m {
                    (false, Cow::Borrowed(""))
                } else {
                    (true, Cow::Borrowed(self.adapter.as_str()))
                }
            }
            RuleType::OR => {
                for rule in &self.rules {
                    let (m, _) = rule.match_(metadata, helper);
                    if m {
                        return (true, Cow::Borrowed(self.adapter.as_str()));
                    }
                }
                (false, Cow::Borrowed(""))
            }
            RuleType::AND => {
                for rule in &self.rules {
                    let (m, _) = rule.match_(metadata, helper);
                    if !m {
                        return (false, Cow::Borrowed(self.adapter.as_str()));
                    }
                }
                (true, Cow::Borrowed(self.adapter.as_str()))
            }
            _ => (false, Cow::Borrowed("")),
        }
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.payload_cache
            .get_or_init(|| match self.rule_type {
                RuleType::NOT => match self.rules.first() {
                    Some(rule) => format!("(!({},{}))", rule.rule_type(), rule.payload()),
                    None => self.initial_payload.clone(),
                },
                RuleType::OR => {
                    let payloads: Vec<String> =
                        self.rules.iter().map(|rule| format!("({},{})", rule.rule_type(), rule.payload())).collect();
                    format!("({})", payloads.join(" || "))
                }
                RuleType::AND => {
                    let payloads: Vec<String> =
                        self.rules.iter().map(|rule| format!("({},{})", rule.rule_type(), rule.payload())).collect();
                    format!("({})", payloads.join(" && "))
                }
                _ => self.initial_payload.clone(),
            })
            .clone()
    }

    fn provider_names(&self) -> Vec<String> {
        self.rules.iter().flat_map(|rule| rule.provider_names()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_rule;

    fn parse_fn() -> ParseRuleFunc {
        Arc::new(parse_rule)
    }

    #[test]
    fn and_or_not_parse_and_match() {
        let and = Logic::and("(DOMAIN,a.com,DIRECT),(DOMAIN,b.com,DIRECT)", "OUT", &parse_fn()).unwrap();
        let mut hit = Metadata { host: "a.com".to_owned(), ..Default::default() };
        let (matched, adapter) = and.match_(&mut hit, &RuleMatchHelper::default());
        assert_eq!((matched, adapter.as_ref()), (false, "OUT"));

        let or = Logic::or("(DOMAIN,a.com,DIRECT),(DOMAIN,b.com,DIRECT)", "OUT", &parse_fn()).unwrap();
        let (matched, adapter) = or.match_(&mut hit, &RuleMatchHelper::default());
        assert_eq!((matched, adapter.as_ref()), (true, "OUT"));

        let not = Logic::not("((DOMAIN,a.com,DIRECT))", "OUT", &parse_fn()).unwrap();
        let mut miss = Metadata { host: "b.com".to_owned(), ..Default::default() };
        let (matched, adapter) = not.match_(&mut miss, &RuleMatchHelper::default());
        assert_eq!((matched, adapter.as_ref()), (true, "OUT"));
        let (matched, adapter) = not.match_(&mut hit, &RuleMatchHelper::default());
        assert_eq!((matched, adapter.as_ref()), (false, ""));
    }

    #[test]
    fn payload_must_be_parenthesized() {
        let err = Logic::or("DOMAIN,a.com,DIRECT", "OUT", &parse_fn()).err().unwrap();
        assert_eq!(err.to_string(), "payload format error");
    }

    #[test]
    fn unbalanced_missing_close_paren_is_rejected() {
        let err = Logic::or("(DOMAIN,a.com,DIRECT", "OUT", &parse_fn()).err().unwrap();
        assert_eq!(err.to_string(), "payload format error");
    }

    #[test]
    fn unbalanced_extra_close_paren_is_rejected() {
        let err = Logic::or("(DOMAIN,a.com,DIRECT))", "OUT", &parse_fn()).err().unwrap();
        assert_eq!(err.to_string(), "missing '('");
    }

    #[test]
    fn empty_sub_payload_is_rejected() {
        let err = Logic::or("(())", "OUT", &parse_fn()).err().unwrap();
        assert_eq!(err.to_string(), "[] format is error");
    }

    #[test]
    fn match_and_sub_rule_are_unsupported_inside_logic() {
        let err = Logic::or("(MATCH,DIRECT),(DOMAIN,a.com,DIRECT)", "OUT", &parse_fn()).err().unwrap();
        assert_eq!(err.to_string(), "unsupported rule type [MATCH] on logic rule");
    }

    #[test]
    fn not_rule_rejects_anything_but_exactly_one_rule() {
        let err = Logic::not("(DOMAIN,a.com,DIRECT),(DOMAIN,b.com,DIRECT)", "OUT", &parse_fn()).err().unwrap();
        assert_eq!(err.to_string(), "not rule must contain one rule");
    }

    #[test]
    fn sub_rule_rejects_anything_but_exactly_one_rule() {
        let err = Logic::sub_rule("(DOMAIN,a.com,DIRECT),(DOMAIN,b.com,DIRECT)", "OUT", HashMap::new(), &parse_fn())
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "Sub-Rule rule must contain one rule");
    }
}
