//! The geoip matcher load and init are `async` in this crate (their `singleflight`
//! and downloader dependencies are).
//!
//! While `constant::rule::Rule::match_` and `constant::matcher::IpMatcher::match_ip` stay
//! synchronous, matching the tunnel's hot-path call site (`tunnel::tunnel`), this bridges the
//! sync/async boundary the same way `tunnel::tunnel` already bridges its own synchronous DNS
//! resolution: `tokio::task::block_in_place` + `Handle::current().block_on`.

use std::borrow::Cow;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use murmur_component_geodata::router::condition::IPMatcher;
use murmur_component_geodata::{init, utils};
use murmur_component_mmdb as mmdb;
use murmur_constant::matcher::IpMatcher;
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleGroup, RuleMatchHelper, RuleType};
use murmur_log::{errorln, infoln};

use super::base::Base;

fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

/// Private, unspecified, loopback, multicast and link-local addresses, combined.
const fn is_lan(ip: IpAddr) -> bool {
    let is_private = match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    };
    let is_link_local_unicast = match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    };
    is_private || ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || is_link_local_unicast
}

#[derive(Debug)]
pub struct GEOIP {
    base: Base,
    country: String,
    adapter: String,
    no_resolve_ip: bool,
    is_source_ip: bool,
}

impl Rule for GEOIP {
    fn rule_type(&self) -> RuleType {
        if self.is_source_ip {
            RuleType::SRC_GEOIP
        } else {
            RuleType::GEOIP
        }
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        if !self.no_resolve_ip && !self.is_source_ip {
            if let Some(f) = &helper.resolve_ip {
                f(metadata);
            }
        }

        let ip = if self.is_source_ip { metadata.src_ip } else { metadata.dst_ip };
        let Some(ip) = ip else {
            return (false, Cow::Borrowed(""));
        };

        if self.country == "lan" {
            return (is_lan(ip), Cow::Borrowed(self.adapter.as_str()));
        }

        if utils::geodata_mode() {
            if self.is_source_ip {
                if metadata.src_geo_ip.as_ref().is_some_and(|codes| codes.contains(&self.country)) {
                    return (true, Cow::Borrowed(self.adapter.as_str()));
                }
            } else if metadata.dst_geo_ip.as_ref().is_some_and(|codes| codes.contains(&self.country)) {
                return (true, Cow::Borrowed(self.adapter.as_str()));
            }
            let Ok(ip_matcher) = self.load_ip_matcher() else {
                return (false, Cow::Borrowed(""));
            };
            let matched = ip_matcher.match_(ip);
            if matched {
                if self.is_source_ip {
                    metadata.src_geo_ip.get_or_insert_with(Vec::new).push(self.country.clone());
                } else {
                    metadata.dst_geo_ip.get_or_insert_with(Vec::new).push(self.country.clone());
                }
            }
            return (matched, Cow::Borrowed(self.adapter.as_str()));
        }

        if self.is_source_ip {
            if let Some(codes) = &metadata.src_geo_ip {
                return (codes.contains(&self.country), Cow::Borrowed(self.adapter.as_str()));
            }
        } else if let Some(codes) = &metadata.dst_geo_ip {
            return (codes.contains(&self.country), Cow::Borrowed(self.adapter.as_str()));
        }
        let codes = mmdb::ip_instance().lookup_code(&ip);
        if self.is_source_ip {
            metadata.src_geo_ip = Some(codes.clone());
        } else {
            metadata.dst_geo_ip = Some(codes.clone());
        }
        if codes.contains(&self.country) {
            return (true, Cow::Borrowed(self.adapter.as_str()));
        }
        (false, Cow::Borrowed(""))
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.country.clone()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }

    fn as_rule_group(&self) -> Option<&dyn RuleGroup> {
        Some(self)
    }
}

impl RuleGroup for GEOIP {
    fn get_recode_size(&self) -> i32 {
        self.get_recode_size()
    }
}

impl IpMatcher for GEOIP {
    fn match_ip(&self, ip: IpAddr) -> bool {
        if self.country == "lan" {
            return is_lan(ip);
        }

        if utils::geodata_mode() {
            let Ok(matcher) = self.load_ip_matcher() else {
                return false;
            };
            return matcher.match_(ip);
        }

        let codes = mmdb::ip_instance().lookup_code(&ip);
        codes.contains(&self.country)
    }
}

/// Embeds the geoip set; the same instance is shared via `Arc`.
#[derive(Debug)]
pub struct DnsFallbackFilter {
    geoip: Arc<GEOIP>,
}

impl IpMatcher for DnsFallbackFilter {
    fn match_ip(&self, ip: IpAddr) -> bool {
        if is_lan(ip) {
            // compatible with original behavior
            return false;
        }

        if self.geoip.country == "lan" {
            return !is_lan(ip);
        }

        if utils::geodata_mode() {
            let Ok(matcher) = self.geoip.load_ip_matcher() else {
                return false;
            };
            return !matcher.match_(ip);
        }

        let codes = mmdb::ip_instance().lookup_code(&ip);
        !codes.contains(&self.geoip.country)
    }
}

impl GEOIP {
    /// The matcher for `dns.fallback-filter.geoip`.
    #[must_use]
    pub fn dns_fallback_filter(self: &Arc<Self>) -> Arc<dyn IpMatcher> {
        Arc::new(DnsFallbackFilter { geoip: Arc::clone(self) })
    }

    #[must_use]
    pub fn adapter(&self) -> String {
        self.adapter.clone()
    }

    #[must_use]
    pub fn payload(&self) -> String {
        self.country.clone()
    }

    pub fn get_ip_matcher(&self) -> Result<Arc<dyn IPMatcher>> {
        if utils::geodata_mode() {
            self.load_ip_matcher()
        } else {
            Err(anyhow!("not geodata mode"))
        }
    }

    /// Renamed to avoid colliding with the public `get_ip_matcher` once the case-only distinction
    /// collapses under `snake_case`.
    fn load_ip_matcher(&self) -> Result<Arc<dyn IPMatcher>> {
        block_on(utils::load_geo_ip_matcher(&self.country)).map_err(|err| anyhow!("[GeoIP] {err}"))
    }

    #[must_use]
    pub fn get_recode_size(&self) -> i32 {
        // skip pseudorule lan
        if self.country == "lan" {
            return 0;
        }

        self.get_ip_matcher().map_or(0, |matcher| matcher.count().try_into().unwrap_or(i32::MAX))
    }

    pub fn new(country: &str, adapter: &str, is_src: bool, no_resolve_ip: bool) -> Result<Self> {
        let country = country.to_lowercase();

        let geoip = Self {
            base: Base,
            country: country.clone(),
            adapter: adapter.to_owned(),
            no_resolve_ip,
            is_source_ip: is_src,
        };

        if country == "lan" {
            return Ok(geoip);
        }

        if let Err(err) = block_on(init::init_geo_ip()) {
            errorln!("can't initial GeoIP: {err}");
            return Err(err);
        }

        if utils::geodata_mode() {
            let geo_ip_matcher = geoip.load_ip_matcher()?; // test load
            infoln!("Finished initial GeoIP rule {} => {}, records: {}", country, adapter, geo_ip_matcher.count());
        }

        Ok(geoip)
    }
}
