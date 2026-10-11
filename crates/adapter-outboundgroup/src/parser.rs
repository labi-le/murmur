use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use fancy_regex::Regex;
use serde::Deserialize;
use serde_yaml::Mapping;

use murmur_adapter_provider::healthcheck::new_health_check;
use murmur_adapter_provider::provider::new_compatible_provider;
use murmur_common::structure::structure::{new_decoder, Option as StructureOption};
use murmur_common::utils::ranges::{new_unsigned_ranges, IntRanges};
use murmur_constant::adapters::{Proxy, DEFAULT_TEST_URL};
use murmur_constant::provider::interface::{ProxyProvider, VehicleType};
use murmur_log::errorln;

use super::fallback::{Fallback, FallbackOption};
use super::groupbase::must_compile_regexp2;
use super::loadbalance::{LoadBalance, LoadBalanceOption};
use super::selector::{Selector, SelectorOption};
use super::urltest::{URLTest, URLTestOption};
use super::util::{as_proxy_group, ProxyGroup};

const fn default_lazy() -> bool {
    true
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "deserialized group configuration: each bool mirrors one YAML key and cannot be grouped without changing the accepted config format"
)]
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct GroupCommonOption {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "proxies", default)]
    pub proxies: Vec<String>,
    #[serde(rename = "use", default)]
    pub use_: Vec<String>,
    #[serde(rename = "url", default)]
    pub url: String,
    #[serde(rename = "interval", default)]
    pub interval: i32,
    #[serde(rename = "timeout", default)]
    pub test_timeout: i32,
    #[serde(rename = "max-failed-times", default)]
    pub max_failed_times: i32,
    #[serde(rename = "empty-fallback", default)]
    pub empty_fallback: String,
    #[serde(rename = "lazy", default = "default_lazy")]
    pub lazy: bool,
    #[serde(rename = "disable-udp", default)]
    pub disable_udp: bool,
    #[serde(rename = "filter", default)]
    pub filter: String,
    #[serde(rename = "exclude-filter", default)]
    pub exclude_filter: String,
    #[serde(rename = "exclude-type", default)]
    pub exclude_type: String,
    #[serde(rename = "expected-status", default)]
    pub expected_status: String,
    #[serde(rename = "include-all", default)]
    pub include_all: bool,
    #[serde(rename = "include-all-proxies", default)]
    pub include_all_proxies: bool,
    #[serde(rename = "include-all-providers", default)]
    pub include_all_providers: bool,
    #[serde(rename = "hidden", default)]
    pub hidden: bool,
    #[serde(rename = "icon", default)]
    pub icon: String,
}

#[expect(
    clippy::implicit_hasher,
    reason = "public entry point: the map parameters are part of the crate API, so the hasher cannot be generalized"
)]
pub fn parse_proxy_group(
    config: &Mapping,
    proxy_map: &HashMap<String, Arc<dyn Proxy>>,
    providers_map: &mut HashMap<String, Arc<dyn ProxyProvider>>,
    all_proxies: &[String],
    all_providers: &[String],
) -> Result<Arc<dyn ProxyGroup>> {
    let decoder =
        new_decoder(StructureOption { tag_name: "group".to_owned(), weakly_typed_input: true, key_replacer: None });

    let mut group_option: GroupCommonOption = decoder.decode(config).map_err(|_| anyhow!("format error"))?;

    if group_option.type_.is_empty() || group_option.name.is_empty() {
        return Err(anyhow!("format error"));
    }

    warn_deprecated_group_fields(config, &group_option.name);

    let group_name = group_option.name.clone();

    let empty_fallback = resolve_empty_fallback(&group_name, &mut group_option, proxy_map)?;

    let mut providers: Vec<Arc<dyn ProxyProvider>> = Vec::new();

    apply_include_all(&mut group_option, all_proxies, all_providers);

    if group_option.proxies.is_empty() && group_option.use_.is_empty() {
        return Err(anyhow!("{group_name}: `use` or `proxies` missing"));
    }

    let expected_status =
        new_unsigned_ranges::<u16>(&group_option.expected_status).map_err(|e| anyhow!("{group_name}: {e}"))?;

    let status = group_option.expected_status.trim();
    group_option.expected_status = if status.is_empty() { "*".to_owned() } else { status.to_owned() };

    if !group_option.use_.is_empty() {
        let pds = get_providers(providers_map, &group_option.use_).map_err(|e| anyhow!("{group_name}: {e}"))?;

        if group_option.url.is_empty() {
            for pd in &pds {
                let health_check_url = pd.health_check_url();
                if !health_check_url.is_empty() {
                    group_option.url = health_check_url;
                    break;
                }
            }
            if group_option.url.is_empty() {
                DEFAULT_TEST_URL.clone_into(&mut group_option.url);
            }
        } else {
            add_test_url_to_providers(
                &pds,
                &group_option.url,
                &expected_status,
                &group_option.filter,
                group_option.interval.cast_unsigned(),
            );
        }
        providers.extend(pds);
    }

    if !group_option.proxies.is_empty() {
        let ps = get_proxies(proxy_map, &group_option.proxies).map_err(|e| anyhow!("{group_name}: {e}"))?;

        if providers_map.contains_key(&group_name) {
            return Err(anyhow!("{group_name}: duplicate provider name"));
        }

        if group_option.url.is_empty() {
            DEFAULT_TEST_URL.clone_into(&mut group_option.url);
        }

        if group_option.type_ != "select" && group_option.type_ != "relay" && group_option.interval == 0 {
            group_option.interval = 300;
        }

        let hc = new_health_check(
            ps.clone(),
            &group_option.url,
            group_option.test_timeout.cast_unsigned(),
            group_option.interval.cast_unsigned(),
            group_option.lazy,
            expected_status,
        );

        let pd: Arc<dyn ProxyProvider> =
            Arc::new(new_compatible_provider(&group_name, ps, hc).map_err(|e| anyhow!("{group_name}: {e}"))?);

        providers = std::iter::once(Arc::clone(&pd)).chain(providers).collect();
        providers_map.insert(group_name.clone(), pd);
    }

    match group_option.type_.as_str() {
        "url-test" => {
            let opt: URLTestOption = decoder.decode(config)?;
            Ok(URLTest::new(group_option, opt, Some(empty_fallback), providers)?)
        }
        "select" => {
            let opt: SelectorOption = decoder.decode(config)?;
            Ok(Selector::new(group_option, opt, empty_fallback, providers)?)
        }
        "fallback" => {
            let opt: FallbackOption = decoder.decode(config)?;
            Ok(Fallback::new(group_option, opt, empty_fallback, providers)?)
        }
        "load-balance" => {
            let opt: LoadBalanceOption = decoder.decode(config)?;
            Ok(LoadBalance::new(group_option, opt, empty_fallback, providers)?)
        }
        "relay" => Err(anyhow!(
            "unsupported type: The group [{group_name}] with relay type was removed, please using dialer-proxy instead"
        )),
        other => Err(anyhow!("unsupported type: {other}")),
    }
}

fn get_proxies(mapping: &HashMap<String, Arc<dyn Proxy>>, list: &[String]) -> Result<Vec<Arc<dyn Proxy>>> {
    let mut ps = Vec::with_capacity(list.len());
    for name in list {
        let p = mapping.get(name).ok_or_else(|| anyhow!("'{name}' not found"))?;
        ps.push(Arc::clone(p));
    }
    Ok(ps)
}

fn get_providers(
    mapping: &HashMap<String, Arc<dyn ProxyProvider>>,
    list: &[String],
) -> Result<Vec<Arc<dyn ProxyProvider>>> {
    let mut ps = Vec::with_capacity(list.len());
    for name in list {
        let p = mapping.get(name).ok_or_else(|| anyhow!("'{name}' not found"))?;
        if p.vehicle_type() == VehicleType::COMPATIBLE {
            return Err(anyhow!("proxy group {name} can't contains in `use`"));
        }
        ps.push(Arc::clone(p));
    }
    Ok(ps)
}

fn add_test_url_to_providers(
    providers: &[Arc<dyn ProxyProvider>],
    url: &str,
    expected_status: &IntRanges<u16>,
    filter: &str,
    interval: u32,
) {
    if providers.is_empty() || url.is_empty() {
        return;
    }

    for pd in providers {
        pd.register_health_check_task(url, expected_status.clone(), filter, interval);
    }
}

fn warn_deprecated_group_fields(config: &Mapping, group_name: &str) {
    if config.get("routing-mark").is_some() {
        errorln!(
            "The group [{}] with routing-mark configuration was removed, please set it directly on the proxy instead",
            group_name
        );
    }
    if config.get("interface-name").is_some() {
        errorln!(
            "The group [{}] with interface-name configuration was removed, please set it directly on the proxy instead",
            group_name
        );
    }
    if config.get("dialer-proxy").is_some() {
        errorln!(
            "The group [{}] with dialer-proxy configuration is not allowed, please set it directly on the proxy instead",
            group_name
        );
    }
}

fn resolve_empty_fallback(
    group_name: &str,
    option: &mut GroupCommonOption,
    proxy_map: &HashMap<String, Arc<dyn Proxy>>,
) -> Result<Arc<dyn Proxy>> {
    if option.empty_fallback.is_empty() {
        "COMPATIBLE".clone_into(&mut option.empty_fallback);
    }
    let Some(empty_fallback) = proxy_map.get(&option.empty_fallback).cloned() else {
        return Err(anyhow!("{group_name}: empty fallback proxy '{}' not found", option.empty_fallback));
    };
    if as_proxy_group(&*empty_fallback.adapter()).is_some() {
        return Err(anyhow!("{group_name}: empty fallback proxy '{}' not found", option.empty_fallback));
    }
    Ok(empty_fallback)
}

fn apply_include_all(option: &mut GroupCommonOption, all_proxies: &[String], all_providers: &[String]) {
    if option.include_all {
        option.include_all_providers = true;
        option.include_all_proxies = true;
    }

    if option.include_all_providers {
        option.use_ = all_providers.to_vec();
    }
    if option.include_all_proxies {
        if option.filter.is_empty() {
            option.proxies.extend(all_proxies.iter().cloned());
        } else {
            let filter_regs: Vec<Regex> = option.filter.split('`').map(must_compile_regexp2).collect();
            for p in all_proxies {
                for filter_reg in &filter_regs {
                    if filter_reg.is_match(p).unwrap_or(false) {
                        option.proxies.push(p.clone());
                    }
                }
            }
        }
        if option.proxies.is_empty() && option.use_.is_empty() {
            option.proxies = vec![option.empty_fallback.clone()];
        }
    }
}
