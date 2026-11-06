use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use parking_lot::RwLock;

use murmur_common::singleflight::singleflight::Group;
use murmur_constant::path::{GEOIP_NAME, GEOSITE_NAME};
use murmur_log::{infoln, warnln};

use super::attr::parse_attrs;
use super::geodata::get_geo_data_loader;
use super::router::condition::{
    new_geo_ip_matcher, new_mph_matcher_group, new_not_domain_matcher_group, new_not_ip_matcher_group,
    new_succinct_matcher_group, DomainMatcher, IPMatcher,
};
use super::router::config_pb::Domain;

static GEO_MODE: RwLock<bool> = RwLock::new(false);
static GEO_LOADER_NAME: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new("memconservative".to_owned()));
static GEO_SITE_MATCHER: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new("succinct".to_owned()));

pub fn geodata_mode() -> bool {
    *GEO_MODE.read()
}

pub fn loader_name() -> String {
    GEO_LOADER_NAME.read().clone()
}

pub fn site_matcher_name() -> String {
    GEO_SITE_MATCHER.read().clone()
}

pub fn set_geodata_mode(new_geodata_mode: bool) {
    *GEO_MODE.write() = new_geodata_mode;
}

pub fn set_loader(new_loader: &str) {
    let new_loader = if new_loader == "memc" { "memconservative" } else { new_loader };
    new_loader.clone_into(&mut GEO_LOADER_NAME.write());
}

pub fn set_site_matcher(new_matcher: &str) {
    let new_matcher = match new_matcher {
        "mph" | "hybrid" => "mph",
        _ => "succinct",
    };
    new_matcher.clone_into(&mut GEO_SITE_MATCHER.write());
}

pub async fn verify(name: &str) -> Result<()> {
    if name == GEOSITE_NAME.read().as_str() {
        load_geo_site_matcher("CN").await?;
        Ok(())
    } else if name == GEOIP_NAME.read().as_str() {
        load_geo_ip_matcher("CN").await?;
        Ok(())
    } else {
        Err(anyhow!("not support name"))
    }
}

static LOAD_GEO_SITE_MATCHER_LIST_SF: LazyLock<Group<Vec<Domain>>> = LazyLock::new(|| {
    let Group { mu, .. } = Group::default();
    Group { mu, store_result: true }
});
static LOAD_GEO_SITE_MATCHER_SF: LazyLock<Group<Arc<dyn DomainMatcher>>> = LazyLock::new(|| {
    let Group { mu, .. } = Group::default();
    Group { mu, store_result: true }
});

pub async fn load_geo_site_matcher(country_code: &str) -> Result<Arc<dyn DomainMatcher>> {
    if country_code.is_empty() {
        return Err(anyhow!("country code could not be empty"));
    }

    let mut not = false;
    let mut country_code = country_code.to_owned();
    if let Some(rest) = country_code.strip_prefix('!') {
        not = true;
        country_code = rest.to_owned();
        if country_code.is_empty() {
            return Err(anyhow!("country code could not be empty"));
        }
    }
    let country_code = country_code.to_lowercase();

    let mut parts = country_code.split('@');
    let list_name = parts.next().unwrap_or_default().trim().to_owned();
    let attr_val: Vec<String> = parts.map(str::to_owned).collect();
    let attrs = parse_attrs(&attr_val);

    if list_name.is_empty() {
        return Err(anyhow!("empty listname in rule: {country_code}"));
    }

    let mut matcher_name = list_name.clone();
    if !attrs.is_empty() {
        matcher_name = format!("{matcher_name}@{attrs}");
    }

    let (result, shared) = LOAD_GEO_SITE_MATCHER_SF
        .do_(&matcher_name, || async {
            infoln!("Load GeoSite rule: {matcher_name}");

            let (domains_result, list_shared) = LOAD_GEO_SITE_MATCHER_LIST_SF
                .do_(&list_name, || async {
                    let geo_loader = get_geo_data_loader(&loader_name())?;
                    geo_loader.load_geo_site(&list_name)
                })
                .await;

            let mut domains = match domains_result {
                Ok(domains) => domains,
                Err(err) => {
                    if !list_shared {
                        LOAD_GEO_SITE_MATCHER_LIST_SF.forget(&list_name);
                    }
                    return Err(err);
                }
            };

            if attrs.is_empty() {
                if country_code.contains('@') {
                    warnln!("empty attribute list: {country_code}");
                }
            } else {
                let mut filtered_domains = Vec::with_capacity(domains.len());
                let mut has_attr_matched = false;
                for domain in &domains {
                    if attrs.match_(domain) {
                        has_attr_matched = true;
                        filtered_domains.push(domain.clone());
                    }
                }
                if !has_attr_matched {
                    warnln!("attribute match no rule: geosite: {country_code}");
                }
                domains = filtered_domains;
            }

            let matcher: Box<dyn DomainMatcher> = if site_matcher_name() == "mph" {
                new_mph_matcher_group(&domains)?
            } else {
                new_succinct_matcher_group(&domains)?
            };
            Ok(Arc::<dyn DomainMatcher>::from(matcher))
        })
        .await;

    let matcher = match result {
        Ok(matcher) => matcher,
        Err(err) => {
            if !shared {
                LOAD_GEO_SITE_MATCHER_SF.forget(&matcher_name);
            }
            return Err(err);
        }
    };

    let matcher = if not {
        Arc::<dyn DomainMatcher>::from(new_not_domain_matcher_group(matcher_to_box(&matcher)))
    } else {
        matcher
    };

    Ok(matcher)
}

/// The singleflight-cached matcher stays an `Arc` so future duplicate callers keep seeing the
/// un-negated value, and this adapter lets that same `Arc` also satisfy
/// `new_not_domain_matcher_group`'s `Box<dyn DomainMatcher>` parameter.
fn matcher_to_box(matcher: &Arc<dyn DomainMatcher>) -> Box<dyn DomainMatcher> {
    Box::new(ArcDomainMatcher(Arc::clone(matcher)))
}

#[derive(Debug)]
struct ArcDomainMatcher(Arc<dyn DomainMatcher>);

impl DomainMatcher for ArcDomainMatcher {
    fn apply_domain(&self, domain: &str) -> bool {
        self.0.apply_domain(domain)
    }

    fn count(&self) -> usize {
        self.0.count()
    }
}

static LOAD_GEO_IP_MATCHER_SF: LazyLock<Group<Arc<dyn IPMatcher>>> = LazyLock::new(|| {
    let Group { mu, .. } = Group::default();
    Group { mu, store_result: true }
});

pub async fn load_geo_ip_matcher(country: &str) -> Result<Arc<dyn IPMatcher>> {
    if country.is_empty() {
        return Err(anyhow!("country code could not be empty"));
    }

    let mut not = false;
    let mut country = country.to_owned();
    if let Some(rest) = country.strip_prefix('!') {
        not = true;
        country = rest.to_owned();
    }
    let country = country.to_lowercase();

    let (result, shared) = LOAD_GEO_IP_MATCHER_SF
        .do_(&country, || async {
            infoln!("Load GeoIP rule: {country}");
            let geo_loader = get_geo_data_loader(&loader_name())?;
            let cidr_list = geo_loader.load_geo_ip(&country)?;
            let matcher = new_geo_ip_matcher(&cidr_list)?;
            Ok(Arc::<dyn IPMatcher>::from(matcher))
        })
        .await;

    let matcher = match result {
        Ok(matcher) => matcher,
        Err(err) => {
            if !shared {
                LOAD_GEO_IP_MATCHER_SF.forget(&country);
                warnln!("Load GeoIP rule: {country}");
            }
            return Err(err);
        }
    };

    let matcher =
        if not { Arc::<dyn IPMatcher>::from(new_not_ip_matcher_group(matcher_to_box_ip(&matcher))) } else { matcher };

    Ok(matcher)
}

/// See [`matcher_to_box`]; the IP-matcher counterpart of the same `Arc`-to-`Box` adapter.
fn matcher_to_box_ip(matcher: &Arc<dyn IPMatcher>) -> Box<dyn IPMatcher> {
    Box::new(ArcIpMatcher(Arc::clone(matcher)))
}

#[derive(Debug)]
struct ArcIpMatcher(Arc<dyn IPMatcher>);

impl IPMatcher for ArcIpMatcher {
    fn match_(&self, ip: std::net::IpAddr) -> bool {
        self.0.match_(ip)
    }

    fn count(&self) -> usize {
        self.0.count()
    }
}

pub fn clear_geo_site_cache() {
    LOAD_GEO_SITE_MATCHER_LIST_SF.reset();
    LOAD_GEO_SITE_MATCHER_SF.reset();
}

pub fn clear_geo_ip_cache() {
    LOAD_GEO_IP_MATCHER_SF.reset();
}
