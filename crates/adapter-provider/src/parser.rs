use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use yaml_serde::Mapping;

use murmur_common::structure::structure::{new_decoder, Decoder as StructureDecoder, Option as StructureOption};
use murmur_common::utils::ranges::new_unsigned_ranges;
use murmur_component_resource::vehicle::{FileVehicle, HTTPVehicle, DEFAULT_HTTP_TIMEOUT};
use murmur_constant::path::PATH;
use murmur_constant::provider::interface::{ProxyProvider, Vehicle};
use murmur_constant::tunnel::Tunnel;

use super::healthcheck::new_health_check;
use super::override_::OverrideSchema;
use super::provider::{new_proxies_parser, InlineProvider, ProxySetProvider};

const ERR_VEHICLE_TYPE: &str = "unsupport vehicle type";

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct HealthCheckSchema {
    #[serde(rename = "enable")]
    enable: bool,
    #[serde(rename = "url", default)]
    url: String,
    #[serde(rename = "interval", default)]
    interval: i64,
    #[serde(rename = "timeout", default)]
    test_timeout: i64,
    #[serde(rename = "lazy", default = "default_lazy")]
    lazy: bool,
    #[serde(rename = "expected-status", default)]
    expected_status: String,
}

const fn default_lazy() -> bool {
    true
}

impl Default for HealthCheckSchema {
    fn default() -> Self {
        Self {
            enable: false,
            url: String::new(),
            interval: 0,
            test_timeout: 0,
            lazy: true,
            expected_status: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct ProxyProviderSchema {
    #[serde(rename = "type")]
    type_: String,
    #[serde(rename = "path", default)]
    path: String,
    #[serde(rename = "url", default)]
    url: String,
    #[serde(rename = "proxy", default)]
    proxy: String,
    #[serde(rename = "interval", default)]
    interval: i64,
    #[serde(rename = "filter", default)]
    filter: String,
    #[serde(rename = "exclude-filter", default)]
    exclude_filter: String,
    #[serde(rename = "exclude-type", default)]
    exclude_type: String,
    #[serde(rename = "dialer-proxy", default)]
    dialer_proxy: String,
    #[serde(rename = "size-limit", default)]
    size_limit: i64,
    #[serde(rename = "payload", default)]
    payload: Vec<Mapping>,
    #[serde(rename = "age-secret-key", default)]
    age_secret_key: String,

    #[serde(rename = "health-check", default)]
    health_check: HealthCheckSchema,
    #[serde(rename = "override", default)]
    override_: OverrideSchema,
    #[serde(rename = "header", default)]
    header: HashMap<String, Vec<String>>,
}

pub fn parse_proxy_provider(name: &str, mapping: &Mapping, tunnel: Arc<dyn Tunnel>) -> Result<Arc<dyn ProxyProvider>> {
    let decoder: StructureDecoder =
        new_decoder(StructureOption { tag_name: "provider".to_owned(), weakly_typed_input: true, key_replacer: None });

    let mut schema: ProxyProviderSchema = decoder.decode(mapping)?;

    let expected_status = new_unsigned_ranges::<u16>(&schema.health_check.expected_status)?;

    let hc_interval = if schema.health_check.enable {
        if schema.health_check.interval == 0 {
            schema.health_check.interval = 300;
        }
        u32::try_from(schema.health_check.interval)
            .map_err(|_| anyhow!("health-check interval out of range: {}", schema.health_check.interval))?
    } else {
        0
    };
    let hc = new_health_check(
        Vec::new(),
        &schema.health_check.url,
        u32::try_from(schema.health_check.test_timeout)
            .map_err(|_| anyhow!("health-check timeout out of range: {}", schema.health_check.test_timeout))?,
        hc_interval,
        schema.health_check.lazy,
        expected_status,
    );

    let parser = new_proxies_parser(
        name,
        tunnel,
        &schema.filter,
        &schema.exclude_filter,
        &schema.exclude_type,
        &schema.dialer_proxy,
        schema.override_.clone(),
        &schema.age_secret_key,
    )?;

    let vehicle: Arc<dyn Vehicle> = match schema.type_.as_str() {
        "file" => {
            let path = PATH.resolve(&schema.path);
            if !PATH.is_safe_path(&path) {
                return Err(PATH.err_not_safe_path(&path).into());
            }
            Arc::new(FileVehicle::new(&path))
        }
        "http" => {
            let mut path = PATH.get_path_by_hash("proxies", &schema.url);
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
            let inline = InlineProvider::new(name, schema.payload, parser, hc)?;
            return Ok(Arc::new(inline));
        }
        other => return Err(anyhow!("{ERR_VEHICLE_TYPE}: {other}")),
    };

    let interval = Duration::from_secs(schema.interval.max(0).cast_unsigned());

    let provider = ProxySetProvider::new(name, interval, schema.payload, parser, vehicle, hc)?;
    Ok(Arc::new(provider))
}
