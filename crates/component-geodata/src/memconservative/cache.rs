//! The caches hold a plain map guarded by a `Mutex`, so entries can be mutated from the `&self`
//! `LoaderImplementation` methods, the way [`crate::geodata`] guards its own loader registry.
//!
//! Every cache is built with an already-initialized map, so there is no uninitialized-map quirk to
//! keep.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use parking_lot::Mutex;

use crate::router::config_pb::{GeoIp, GeoIpList, GeoSite, GeoSiteList};
use murmur_constant::path::PATH;
use murmur_log::warnln;

use super::decode::{decode, DecodeError};

#[derive(Debug, Default)]
pub struct GeoIpCache(Mutex<HashMap<String, Arc<GeoIp>>>);

impl GeoIpCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn get(&self, key: &str) -> Option<Arc<GeoIp>> {
        self.0.lock().get(key).cloned()
    }

    pub fn set(&self, key: &str, value: Arc<GeoIp>) {
        self.0.lock().insert(key.to_owned(), value);
    }

    pub fn unmarshal(&self, filename: &str, code: &str) -> Result<Arc<GeoIp>> {
        let asset = PATH.get_asset_location(filename);
        let idx = format!("{asset}:{code}").to_lowercase();
        if let Some(cached) = self.get(&idx) {
            return Ok(cached);
        }

        match decode(&asset, code) {
            Ok(geoip_bytes) => {
                let geoip: GeoIp = prost::Message::decode(geoip_bytes.as_slice())?;
                let geoip = Arc::new(geoip);
                self.set(&idx, Arc::clone(&geoip));
                Ok(geoip)
            }
            Err(DecodeError::CodeNotFound) => Err(anyhow!("country code {code} not found in {filename}")),
            Err(
                DecodeError::FailedToReadBytes
                | DecodeError::FailedToReadExpectedLenBytes
                | DecodeError::InvalidGeodataFile
                | DecodeError::InvalidGeodataVarintLength,
            ) => {
                warnln!("failed to decode geoip file: {filename}, fallback to the original ReadFile method");
                let geoip_bytes = std::fs::read(&asset)?;
                let geoip_list: GeoIpList = prost::Message::decode(geoip_bytes.as_slice())?;
                for geoip in geoip_list.get_entry() {
                    if code.eq_ignore_ascii_case(geoip.get_country_code()) {
                        let geoip = Arc::new(geoip.clone());
                        self.set(&idx, Arc::clone(&geoip));
                        return Ok(geoip);
                    }
                }
                Err(anyhow!("country code {code} not found in {filename}"))
            }
            Err(err) => Err(err.into()),
        }
    }
}

#[derive(Debug, Default)]
pub struct GeoSiteCache(Mutex<HashMap<String, Arc<GeoSite>>>);

impl GeoSiteCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn get(&self, key: &str) -> Option<Arc<GeoSite>> {
        self.0.lock().get(key).cloned()
    }

    pub fn set(&self, key: &str, value: Arc<GeoSite>) {
        self.0.lock().insert(key.to_owned(), value);
    }

    pub fn unmarshal(&self, filename: &str, code: &str) -> Result<Arc<GeoSite>> {
        let asset = PATH.get_asset_location(filename);
        let idx = format!("{asset}:{code}").to_lowercase();
        if let Some(cached) = self.get(&idx) {
            return Ok(cached);
        }

        match decode(&asset, code) {
            Ok(geosite_bytes) => {
                let geosite: GeoSite = prost::Message::decode(geosite_bytes.as_slice())?;
                let geosite = Arc::new(geosite);
                self.set(&idx, Arc::clone(&geosite));
                Ok(geosite)
            }
            Err(DecodeError::CodeNotFound) => Err(anyhow!("list {code} not found in {filename}")),
            Err(
                DecodeError::FailedToReadBytes
                | DecodeError::FailedToReadExpectedLenBytes
                | DecodeError::InvalidGeodataFile
                | DecodeError::InvalidGeodataVarintLength,
            ) => {
                warnln!("failed to decode geosite file: {filename}, fallback to the original ReadFile method");
                let geosite_bytes = std::fs::read(&asset)?;
                let geosite_list: GeoSiteList = prost::Message::decode(geosite_bytes.as_slice())?;
                for geosite in geosite_list.get_entry() {
                    if code.eq_ignore_ascii_case(geosite.get_country_code()) {
                        let geosite = Arc::new(geosite.clone());
                        self.set(&idx, Arc::clone(&geosite));
                        return Ok(geosite);
                    }
                }
                Err(anyhow!("list {code} not found in {filename}"))
            }
            Err(err) => Err(err.into()),
        }
    }
}
