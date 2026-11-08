//! The geosite matcher load and init are `async` in this crate; see `geoip.rs` for
//! the sync/async bridging rationale shared by every rule in this package that touches geodata.

use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use murmur_component_geodata::router::condition::DomainMatcher as GeoDomainMatcher;
use murmur_component_geodata::{init, utils};
use murmur_constant::matcher::DomainMatcher;
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleGroup, RuleMatchHelper, RuleType};
use murmur_log::{errorln, infoln};

use super::base::Base;

fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

#[derive(Debug)]
pub struct GEOSITE {
    base: Base,
    country: String,
    adapter: String,
}

impl Rule for GEOSITE {
    fn rule_type(&self) -> RuleType {
        RuleType::GEOSITE
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        let matched = self.match_domain(metadata.rule_host());
        // DEVIATION: the rule returns the adapter unconditionally; no caller
        // reads it on a miss, so we skip the allocation and return an empty string.
        (matched, if matched { Cow::Borrowed(self.adapter.as_str()) } else { Cow::Borrowed("") })
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

impl RuleGroup for GEOSITE {
    fn get_recode_size(&self) -> i32 {
        self.get_recode_size()
    }
}

impl DomainMatcher for GEOSITE {
    fn match_domain(&self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }
        let Ok(matcher) = self.get_domain_matcher() else {
            return false;
        };
        matcher.apply_domain(domain)
    }
}

impl GEOSITE {
    #[must_use]
    pub fn adapter(&self) -> String {
        self.adapter.clone()
    }

    #[must_use]
    pub fn payload(&self) -> String {
        self.country.clone()
    }

    pub fn get_domain_matcher(&self) -> Result<Arc<dyn GeoDomainMatcher>> {
        block_on(utils::load_geo_site_matcher(&self.country)).map_err(|err| anyhow!("load GeoSite data error, {err}"))
    }

    #[must_use]
    pub fn get_recode_size(&self) -> i32 {
        match self.get_domain_matcher() {
            Ok(matcher) => matcher.count().try_into().unwrap_or(i32::MAX),
            Err(_) => 0,
        }
    }

    pub fn new(country: &str, adapter: &str) -> Result<Self> {
        if let Err(err) = block_on(init::init_geo_site()) {
            errorln!("can't initial GeoSite: {err}");
            return Err(err);
        }

        let geo_site = Self { base: Base, country: country.to_owned(), adapter: adapter.to_owned() };

        let matcher = geo_site.get_domain_matcher()?; // test load

        infoln!("Finished initial GeoSite rule {} => {}, records: {}", country, adapter, matcher.count());

        Ok(geo_site)
    }
}
