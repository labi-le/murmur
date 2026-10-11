use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::Deserialize;

use murmur_common::structure::structure::{new_decoder, Option as StructureOption};
use murmur_component_resource::fetcher::BundleFile;
use murmur_component_resource::vehicle::{FileVehicle, HTTPVehicle, DEFAULT_HTTP_TIMEOUT};
use murmur_constant::path::PATH;
use murmur_constant::provider::interface::{parse_behavior, parse_rule_format, RuleProvider, Vehicle};
use murmur_rules_common::base::ParseRuleFunc;

use super::provider::{new_inline_provider, new_rule_set_provider};

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RuleProviderSchema {
    #[serde(rename = "type")]
    type_: String,
    #[serde(rename = "behavior")]
    behavior: String,
    #[serde(rename = "path", default)]
    path: String,
    #[serde(rename = "url", default)]
    url: String,
    #[serde(rename = "proxy", default)]
    proxy: String,
    #[serde(rename = "format", default)]
    format: String,
    #[serde(rename = "interval", default)]
    interval: i64,
    #[serde(rename = "size-limit", default)]
    size_limit: i64,
    #[serde(rename = "payload", default)]
    payload: Vec<String>,
    #[serde(rename = "header", default)]
    header: HashMap<String, Vec<String>>,
    #[serde(rename = "path-in-bundle", default)]
    path_in_bundle: String,
}

pub fn parse_rule_provider(
    name: &str,
    mapping: &serde_yaml::Mapping,
    parse: ParseRuleFunc,
    make_bundle_file: &dyn Fn(&str) -> Option<BundleFile>,
) -> Result<Arc<dyn RuleProvider>> {
    let decoder =
        new_decoder(StructureOption { tag_name: "provider".to_owned(), weakly_typed_input: true, key_replacer: None });
    let schema: RuleProviderSchema = decoder.decode(mapping)?;

    let behavior = parse_behavior(&schema.behavior)?;
    let format = parse_rule_format(&schema.format)?;

    let vehicle: Arc<dyn Vehicle> = match schema.type_.as_str() {
        "file" => {
            let path = PATH.resolve(&schema.path);
            if !PATH.is_safe_path(&path) {
                return Err(PATH.err_not_safe_path(&path).into());
            }
            Arc::new(FileVehicle::new(&path))
        }
        "http" => {
            let mut path = PATH.get_path_by_hash("rules", &schema.url);
            if !schema.path.is_empty() {
                path = PATH.resolve(&schema.path);
                if !PATH.is_safe_path(&path) {
                    return Err(PATH.err_not_safe_path(&path).into());
                }
            }
            Arc::new(HTTPVehicle::new(
                &schema.url,
                &path,
                &schema.proxy,
                schema.header.clone(),
                DEFAULT_HTTP_TIMEOUT,
                schema.size_limit,
            ))
        }
        "inline" => {
            return Ok(new_inline_provider(name, behavior, &schema.payload, parse));
        }
        other => return Err(anyhow!("unsupported vehicle type: {other}")),
    };

    let interval = Duration::from_secs(schema.interval.cast_unsigned());

    Ok(new_rule_set_provider(
        name,
        behavior,
        format,
        interval,
        vehicle,
        &schema.payload,
        make_bundle_file(&schema.path_in_bundle),
        &parse,
    ))
}
