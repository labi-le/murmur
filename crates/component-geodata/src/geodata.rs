//! The `loaders` registry holds one factory per name, and it is mutated only while registering,
//! before any concurrent use; a `Mutex` keeps that sound under Rust's aliasing rules.
//!
//! The private `loader` struct and the public `Loader` trait both case-fold to `Loader`; the
//! trait keeps that name and the struct import-aliases it as `LoaderTrait` to avoid a same-file
//! collision.

use std::collections::HashMap;
use std::sync::LazyLock;

use anyhow::{anyhow, Result};
use parking_lot::Mutex;

use murmur_constant::path::{GEOIP_NAME, GEOSITE_NAME};

use super::geodataproto::{Loader as LoaderTrait, LoaderImplementation};
use super::router::config_pb::{Cidr, Domain};

pub(crate) struct Loader {
    implementation: Box<dyn LoaderImplementation>,
}

impl LoaderImplementation for Loader {
    fn load_site_by_path(&self, filename: &str, list: &str) -> Result<Vec<Domain>> {
        self.implementation.load_site_by_path(filename, list)
    }

    fn load_site_by_bytes(&self, geosite_bytes: &[u8], list: &str) -> Result<Vec<Domain>> {
        self.implementation.load_site_by_bytes(geosite_bytes, list)
    }

    fn load_ip_by_path(&self, filename: &str, country: &str) -> Result<Vec<Cidr>> {
        self.implementation.load_ip_by_path(filename, country)
    }

    fn load_ip_by_bytes(&self, geoip_bytes: &[u8], country: &str) -> Result<Vec<Cidr>> {
        self.implementation.load_ip_by_bytes(geoip_bytes, country)
    }
}

impl LoaderTrait for Loader {
    fn load_geo_site(&self, list: &str) -> Result<Vec<Domain>> {
        self.load_site_by_path(&GEOSITE_NAME.read(), list)
    }

    fn load_geo_ip(&self, country: &str) -> Result<Vec<Cidr>> {
        self.load_ip_by_path(&GEOIP_NAME.read(), country)
    }
}

pub type LoaderCreator = Box<dyn Fn() -> Box<dyn LoaderImplementation> + Send + Sync>;

static LOADERS: LazyLock<Mutex<HashMap<String, LoaderCreator>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn register_geo_data_loader_implementation_creator(name: &str, loader: LoaderCreator) {
    LOADERS.lock().insert(name.to_owned(), loader);
}

fn get_geo_data_loader_implementation(name: &str) -> Result<Box<dyn LoaderImplementation>> {
    match LOADERS.lock().get(name) {
        Some(geo_loader) => Ok(geo_loader()),
        None => Err(anyhow!("unable to locate GeoData loader {name}")),
    }
}

pub fn get_geo_data_loader(name: &str) -> Result<Box<dyn LoaderTrait>> {
    let load_impl = get_geo_data_loader_implementation(name)?;
    Ok(Box::new(Loader { implementation: load_impl }))
}
