use anyhow::Result;

use super::router::config_pb::{Cidr, Domain};

pub trait LoaderImplementation: Send + Sync {
    fn load_site_by_path(&self, filename: &str, list: &str) -> Result<Vec<Domain>>;
    fn load_site_by_bytes(&self, geosite_bytes: &[u8], list: &str) -> Result<Vec<Domain>>;
    fn load_ip_by_path(&self, filename: &str, country: &str) -> Result<Vec<Cidr>>;
    fn load_ip_by_bytes(&self, geoip_bytes: &[u8], country: &str) -> Result<Vec<Cidr>>;
}

pub trait Loader: LoaderImplementation {
    fn load_geo_site(&self, list: &str) -> Result<Vec<Domain>>;
    fn load_geo_ip(&self, country: &str) -> Result<Vec<Cidr>>;
}
