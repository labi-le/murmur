//! Rust has no import-time side effects, so [`init`] is exported instead: callers must invoke it
//! once at startup, before the first `geodata::get_geo_data_loader` call, to register this loader.

use anyhow::{anyhow, Result};

use crate::geodata::register_geo_data_loader_implementation_creator;
use crate::geodataproto::LoaderImplementation;
use crate::router::config_pb::{Cidr, Domain};

use super::cache::{GeoIpCache, GeoSiteCache};

struct MemConservativeLoader {
    geoipcache: GeoIpCache,
    geositecache: GeoSiteCache,
}

impl LoaderImplementation for MemConservativeLoader {
    /// An explicit collection after loading has no Rust equivalent (the allocator is not manually
    /// collected) and is dropped.
    fn load_ip_by_path(&self, filename: &str, country: &str) -> Result<Vec<Cidr>> {
        let geoip = self
            .geoipcache
            .unmarshal(filename, country)
            .map_err(|err| anyhow!("failed to decode geodata file: {filename}, base error: {err}"))?;
        Ok(geoip.cidr.clone())
    }

    fn load_ip_by_bytes(&self, _geoip_bytes: &[u8], _country: &str) -> Result<Vec<Cidr>> {
        Err(anyhow!("memConservative do not support LoadIPByBytes"))
    }

    fn load_site_by_path(&self, filename: &str, list: &str) -> Result<Vec<Domain>> {
        let geosite = self
            .geositecache
            .unmarshal(filename, list)
            .map_err(|err| anyhow!("failed to decode geodata file: {filename}, base error: {err}"))?;
        Ok(geosite.domain.clone())
    }

    fn load_site_by_bytes(&self, _geosite_bytes: &[u8], _list: &str) -> Result<Vec<Domain>> {
        Err(anyhow!("memConservative do not support LoadSiteByBytes"))
    }
}

fn new_mem_conservative_loader() -> Box<dyn LoaderImplementation> {
    Box::new(MemConservativeLoader { geoipcache: GeoIpCache::new(), geositecache: GeoSiteCache::new() })
}

pub fn init() {
    register_geo_data_loader_implementation_creator("memconservative", Box::new(new_mem_conservative_loader));
}
