use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;

use murmur_constant::rule::Rule;

pub(crate) const ERR_PAYLOAD: &str = "payloadRule error";

pub(crate) fn err_payload() -> anyhow::Error {
    anyhow!(ERR_PAYLOAD)
}

pub const NO_RESOLVE: &str = "no-resolve";
pub const SRC: &str = "src";

#[derive(Clone, Copy, Debug, Default)]
pub struct Base;

impl Base {
    #[must_use]
    pub const fn provider_names(&self) -> Vec<String> {
        Vec::new()
    }
}

#[must_use]
pub fn parse_params(params: &[String]) -> (bool, bool) {
    let is_src = params.iter().any(|p| p == SRC);
    let no_resolve = if is_src { true } else { params.iter().any(|p| p == NO_RESOLVE) };
    (is_src, no_resolve)
}

pub(crate) fn trim_arr(arr: &[String]) -> Vec<String> {
    arr.iter().map(|e| e.trim_matches(' ').to_owned()).collect()
}

/// `ParseRulePayload`, which parses a rule formatted as `tp,payload,target(,params...)` or
/// `tp,payload(,params...)`; `need_target` controls whether the format contains `target`.
pub fn parse_rule_payload(rule_raw: &str, need_target: bool) -> (String, String, String, Vec<String>) {
    let mut item = trim_arr(&rule_raw.split(',').map(str::to_owned).collect::<Vec<_>>());
    let mut payload = String::new();
    let mut target = String::new();
    let mut params: Vec<String> = Vec::new();

    let Some(tp) = item.first().map(|tp| tp.to_uppercase()) else {
        return (String::new(), payload, target, params);
    };

    if item.len() > 1 {
        match tp.as_str() {
            "MATCH" => {
                if let Some(v) = item.get(1) {
                    target.clone_from(v);
                }
            }
            "NOT" | "OR" | "AND" | "SUB-RULE" | "DOMAIN-REGEX" | "PROCESS-NAME-REGEX" | "PROCESS-PATH-REGEX" => {
                if need_target {
                    if let Some(v) = item.last() {
                        target.clone_from(v);
                    }
                    item.truncate(item.len() - 1);
                }
                payload = item.get(1..).map_or_else(String::new, |rest| rest.join(","));
            }
            _ => {
                if let Some(v) = item.get(1) {
                    payload.clone_from(v);
                }
                if item.len() > 2 {
                    if need_target {
                        if let Some(v) = item.get(2) {
                            target.clone_from(v);
                        }
                        if let Some(rest) = item.get(3..) {
                            params = rest.to_vec();
                        }
                    } else if let Some(rest) = item.get(2..) {
                        params = rest.to_vec();
                    }
                }
            }
        }
    }

    (tp, payload, target, params)
}

/// The named function type accepts any function value, including closures that capture state;
/// this keeps that flexibility with a boxed `Fn` rather than a bare `fn` pointer.
pub type ParseRuleFunc = Arc<
    dyn Fn(&str, &str, &str, &[String], &HashMap<String, Vec<Arc<dyn Rule>>>) -> anyhow::Result<Arc<dyn Rule>>
        + Send
        + Sync,
>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_type_with_target() {
        assert_eq!(
            parse_rule_payload("DOMAIN,a.com,P", true),
            ("DOMAIN".to_owned(), "a.com".to_owned(), "P".to_owned(), Vec::<String>::new())
        );
    }

    #[test]
    fn params_after_target_are_collected() {
        let (tp, payload, target, params) = parse_rule_payload("IP-CIDR,1.0.0.0/8,P,no-resolve", true);
        assert_eq!((tp.as_str(), payload.as_str(), target.as_str()), ("IP-CIDR", "1.0.0.0/8", "P"));
        assert_eq!(params, vec!["no-resolve".to_owned()]);
    }

    #[test]
    fn src_param_is_collected_like_any_other() {
        let (.., params) = parse_rule_payload("IP-CIDR,1.0.0.0/8,P,src", true);
        assert_eq!(params, vec!["src".to_owned()]);
    }

    #[test]
    fn comma_bearing_payload_keeps_its_commas_and_target_is_the_last_field() {
        assert_eq!(
            parse_rule_payload("AND,((DOMAIN,a.com),(NETWORK,UDP)),P", true),
            ("AND".to_owned(), "((DOMAIN,a.com),(NETWORK,UDP))".to_owned(), "P".to_owned(), Vec::<String>::new())
        );
        assert_eq!(
            parse_rule_payload("DOMAIN-REGEX,^a,b$,P", true),
            ("DOMAIN-REGEX".to_owned(), "^a,b$".to_owned(), "P".to_owned(), Vec::<String>::new())
        );
    }

    #[test]
    fn match_takes_target_from_field_one_and_has_no_payload() {
        assert_eq!(
            parse_rule_payload("MATCH,P", true),
            ("MATCH".to_owned(), String::new(), "P".to_owned(), Vec::<String>::new())
        );
    }

    #[test]
    fn extra_trailing_comma_becomes_an_empty_param() {
        let (.., params) = parse_rule_payload("DOMAIN,a.com,P,", true);
        assert_eq!(params, vec![String::new()]);
    }

    #[test]
    fn need_target_false_leaves_target_empty_and_shifts_params_left() {
        assert_eq!(
            parse_rule_payload("DOMAIN,a.com", false),
            ("DOMAIN".to_owned(), "a.com".to_owned(), String::new(), Vec::<String>::new())
        );
        let (.., target, params) = parse_rule_payload("IP-CIDR,1.0.0.0/8,no-resolve", false);
        assert_eq!(target, "");
        assert_eq!(params, vec!["no-resolve".to_owned()]);
    }

    #[test]
    fn type_only_line_has_no_payload_or_target() {
        assert_eq!(
            parse_rule_payload("DOMAIN", true),
            ("DOMAIN".to_owned(), String::new(), String::new(), Vec::<String>::new())
        );
    }

    #[test]
    fn whitespace_around_fields_is_trimmed() {
        assert_eq!(
            parse_rule_payload("DOMAIN, a.com , P ", true),
            ("DOMAIN".to_owned(), "a.com".to_owned(), "P".to_owned(), Vec::<String>::new())
        );
    }

    #[test]
    fn type_is_uppercased() {
        let (tp, ..) = parse_rule_payload("domain,a.com,P", true);
        assert_eq!(tp, "DOMAIN");
    }

    #[test]
    fn src_forces_no_resolve() {
        assert_eq!(parse_params(&["src".to_owned()]), (true, true));
    }

    #[test]
    fn no_resolve_without_src() {
        assert_eq!(parse_params(&["no-resolve".to_owned()]), (false, true));
    }

    #[test]
    fn src_and_no_resolve_together() {
        assert_eq!(parse_params(&["src".to_owned(), "no-resolve".to_owned()]), (true, true));
    }

    #[test]
    fn no_params_means_neither_flag() {
        assert_eq!(parse_params(&[]), (false, false));
    }

    #[test]
    fn param_matching_is_case_sensitive() {
        assert_eq!(parse_params(&["NO-RESOLVE".to_owned()]), (false, false));
    }
}
