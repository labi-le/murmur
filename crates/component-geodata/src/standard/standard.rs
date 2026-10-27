//! Registering this loader requires an explicit [`init`] call; see the module doc of
//! [`crate::memconservative::memc`] for why.

use anyhow::{anyhow, Result};

use crate::geodata::register_geo_data_loader_implementation_creator;
use crate::geodataproto::LoaderImplementation;
use crate::router::config_pb::{Cidr, Domain, GeoIpList, GeoSiteList};
use murmur_constant::path::PATH;

pub fn read_file(path: &str) -> Result<Vec<u8>> {
    Ok(std::fs::read(path)?)
}

pub fn read_asset(file: &str) -> Result<Vec<u8>> {
    read_file(&PATH.get_asset_location(file))
}

fn load_ip(geoip_bytes: &[u8], country: &str) -> Result<Vec<Cidr>> {
    let geoip_list: GeoIpList = prost::Message::decode(geoip_bytes)?;

    for geoip in geoip_list.get_entry() {
        if country.eq_ignore_ascii_case(geoip.get_country_code()) {
            return Ok(geoip.get_cidr().to_vec());
        }
    }

    Err(anyhow!("country {country} not found"))
}

fn load_site(geosite_bytes: &[u8], list: &str) -> Result<Vec<Domain>> {
    let geosite_list: GeoSiteList = prost::Message::decode(geosite_bytes)?;

    for site in geosite_list.get_entry() {
        if list.eq_ignore_ascii_case(site.get_country_code()) {
            return Ok(site.get_domain().to_vec());
        }
    }

    Err(anyhow!("list {list} not found"))
}

struct StandardLoader;

impl LoaderImplementation for StandardLoader {
    fn load_site_by_path(&self, filename: &str, list: &str) -> Result<Vec<Domain>> {
        let geosite_bytes =
            read_asset(filename).map_err(|err| anyhow!("failed to open file: {filename}, base error: {err}"))?;
        load_site(&geosite_bytes, list)
    }

    fn load_site_by_bytes(&self, geosite_bytes: &[u8], list: &str) -> Result<Vec<Domain>> {
        load_site(geosite_bytes, list)
    }

    fn load_ip_by_path(&self, filename: &str, country: &str) -> Result<Vec<Cidr>> {
        let geoip_bytes =
            read_asset(filename).map_err(|err| anyhow!("failed to open file: {filename}, base error: {err}"))?;
        load_ip(&geoip_bytes, country)
    }

    fn load_ip_by_bytes(&self, geoip_bytes: &[u8], country: &str) -> Result<Vec<Cidr>> {
        load_ip(geoip_bytes, country)
    }
}

pub fn init() {
    register_geo_data_loader_implementation_creator("standard", Box::new(|| Box::new(StandardLoader)));
}
