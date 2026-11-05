use std::borrow::Cow;

use anyhow::{anyhow, Result};

use murmur_constant::metadata::{parse_type, Metadata, Type};
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::Base;

#[derive(Debug)]
pub struct InType {
    base: Base,
    types: Vec<Type>,
    adapter: String,
    payload: String,
}

impl Rule for InType {
    fn rule_type(&self) -> RuleType {
        RuleType::IN_TYPE
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let matched = self.types.contains(&metadata.type_);
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

impl InType {
    pub fn new(i_types: &str, adapter: &str) -> Result<Self> {
        let mut types: Vec<String> = i_types.split('/').map(str::to_owned).collect();
        for tp in &mut types {
            let trimmed = tp.trim().to_owned();
            if trimmed.is_empty() {
                return Err(anyhow!("in type couldn't be empty"));
            }
            *tp = trimmed;
        }

        let tps = parse_in_types(&types)?;

        Ok(Self { base: Base, types: tps, adapter: adapter.to_owned(), payload: i_types.to_uppercase() })
    }
}

fn parse_in_types(tps: &[String]) -> Result<Vec<Type>> {
    let mut res = Vec::with_capacity(tps.len());
    for tp in tps {
        let utp = tp.to_uppercase();
        if utp == "SOCKS" {
            res.push(parse_type("SOCKS4")?);
            res.push(parse_type("SOCKS5")?);
        } else {
            res.push(parse_type(&utp)?);
        }
    }
    Ok(res)
}
