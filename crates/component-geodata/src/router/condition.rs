use std::net::IpAddr;

use anyhow::{anyhow, Result};
use ipnet::IpNet;

use crate::strmatcher::mph_matcher::MphMatcherGroup;
use crate::strmatcher::strmatcher::{Matcher, Type as MatcherType};
use murmur_component::cidr::ipcidr_set::IpCidrSet;
use murmur_component_trie::domain_set::{DomainSet, DomainSetBuilder};

use super::config_pb::{Cidr, Domain, DomainType};

/// Maps every domain type.
const fn matcher_type_map(domain_type: DomainType) -> MatcherType {
    match domain_type {
        DomainType::Plain => MatcherType::Substr,
        DomainType::Regex => MatcherType::Regex,
        DomainType::Domain => MatcherType::Domain,
        DomainType::Full => MatcherType::Full,
    }
}

/// The domain type when the wire value is known, absent otherwise.
fn domain_type(domain: &Domain) -> Option<DomainType> {
    DomainType::try_from(domain.r#type).ok()
}

pub trait DomainMatcher: Send + Sync + std::fmt::Debug {
    fn apply_domain(&self, domain: &str) -> bool;
    fn count(&self) -> usize;
}

#[derive(Debug)]
pub struct SuccinctDomainMatcher {
    set: Option<DomainSet>,
    other_matchers: Vec<Box<dyn Matcher>>,
    count: usize,
}

impl DomainMatcher for SuccinctDomainMatcher {
    fn apply_domain(&self, domain: &str) -> bool {
        let mut is_matched = self.set.as_ref().is_some_and(|set| set.has(domain));
        if !is_matched {
            for matcher in &self.other_matchers {
                is_matched = matcher.match_(domain);
                if is_matched {
                    break;
                }
            }
        }
        is_matched
    }

    fn count(&self) -> usize {
        self.count
    }
}

pub fn new_succinct_matcher_group(domains: &[Domain]) -> Result<Box<dyn DomainMatcher>> {
    let mut builder = DomainSetBuilder::default();
    let mut m = SuccinctDomainMatcher { set: None, other_matchers: Vec::new(), count: domains.len() };
    for d in domains {
        let Some(domain_type) = domain_type(d) else {
            continue;
        };
        match domain_type {
            DomainType::Plain | DomainType::Regex => {
                let matcher = matcher_type_map(domain_type).new_matcher(&d.value)?;
                m.other_matchers.push(matcher);
            }
            DomainType::Domain => {
                builder.insert(&format!("+.{value}", value = d.value))?;
            }
            DomainType::Full => {
                builder.insert(&d.value)?;
            }
        }
    }
    m.set = builder.build();
    Ok(Box::new(m))
}

#[derive(Debug)]
pub struct V2rayDomainMatcher {
    matchers: MphMatcherGroup,
    count: usize,
}

pub fn new_mph_matcher_group(domains: &[Domain]) -> Result<Box<dyn DomainMatcher>> {
    let mut g = MphMatcherGroup::new_mph_matcher_group();
    for d in domains {
        let Some(matcher_type) = domain_type(d).map(matcher_type_map) else {
            return Err(anyhow!("unsupported domain type {}", d.r#type));
        };
        g.add_pattern(&d.value, matcher_type)?;
    }
    g.build();
    Ok(Box::new(V2rayDomainMatcher { matchers: g, count: domains.len() }))
}

impl DomainMatcher for V2rayDomainMatcher {
    fn apply_domain(&self, domain: &str) -> bool {
        !self.matchers.match_(&domain.to_lowercase()).is_empty()
    }

    fn count(&self) -> usize {
        self.count
    }
}

/// Forwards `count` to the matcher it negates.
#[derive(Debug)]
pub struct NotDomainMatcher {
    domain_matcher: Box<dyn DomainMatcher>,
}

impl DomainMatcher for NotDomainMatcher {
    fn apply_domain(&self, domain: &str) -> bool {
        !self.domain_matcher.apply_domain(domain)
    }

    fn count(&self) -> usize {
        self.domain_matcher.count()
    }
}

#[must_use]
pub fn new_not_domain_matcher_group(matcher: Box<dyn DomainMatcher>) -> Box<dyn DomainMatcher> {
    Box::new(NotDomainMatcher { domain_matcher: matcher })
}

pub trait IPMatcher: Send + Sync + std::fmt::Debug {
    fn match_(&self, ip: IpAddr) -> bool;
    fn count(&self) -> usize;
}

#[derive(Debug)]
pub struct GeoIpMatcher {
    cidr_set: IpCidrSet,
    count: usize,
}

impl IPMatcher for GeoIpMatcher {
    /// Returns true if the given ip is included by the geoip set.
    fn match_(&self, ip: IpAddr) -> bool {
        self.cidr_set.is_contain(ip)
    }

    fn count(&self) -> usize {
        self.count
    }
}

/// Builds an address from a 4- or 16-byte slice; `None` for any other length.
fn addr_from_slice(slice: &[u8]) -> Option<IpAddr> {
    match <[u8; 4]>::try_from(slice) {
        Ok(octets) => Some(IpAddr::from(octets)),
        Err(_) => <[u8; 16]>::try_from(slice).ok().map(IpAddr::from),
    }
}

pub fn new_geo_ip_matcher(cidr_list: &[Cidr]) -> Result<Box<dyn IPMatcher>> {
    let mut m = GeoIpMatcher { cidr_set: IpCidrSet::new_ip_cidr_set(), count: cidr_list.len() };
    for cidr in cidr_list {
        let Some(addr) = addr_from_slice(&cidr.ip) else {
            return Err(anyhow!("error when loading GeoIP: invalid IP: {}", String::from_utf8_lossy(&cidr.ip)));
        };
        let Some(prefix) = u8::try_from(cidr.prefix).ok().and_then(|bits| IpNet::new(addr, bits).ok()) else {
            return Err(anyhow!("error when loading GeoIP: not valid ipcidr range: invalid Prefix"));
        };
        m.cidr_set.add_ip_cidr(prefix).map_err(|err| anyhow!("error when loading GeoIP: {err}"))?;
    }
    m.cidr_set.merge()?;

    Ok(Box::new(m))
}

/// Forwards `count` to the matcher it negates.
#[derive(Debug)]
pub struct NotIpMatcher {
    ip_matcher: Box<dyn IPMatcher>,
}

impl IPMatcher for NotIpMatcher {
    fn match_(&self, ip: IpAddr) -> bool {
        !self.ip_matcher.match_(ip)
    }

    fn count(&self) -> usize {
        self.ip_matcher.count()
    }
}

#[must_use]
pub fn new_not_ip_matcher_group(matcher: Box<dyn IPMatcher>) -> Box<dyn IPMatcher> {
    Box::new(NotIpMatcher { ip_matcher: matcher })
}
