use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Result};
use http_body_util::BodyExt;
use parking_lot::RwLock;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use murmur_common::atomic::type_::{new_bool, Bool};
use murmur_component_http::http as murmur_http;
use murmur_component_mmdb as mmdb;
use murmur_constant::path::PATH;
use murmur_log::{infoln, warnln};

use super::utils::verify;

static INIT_GEO_SITE: Mutex<bool> = Mutex::const_new(false);
static INIT_GEO_IP: Mutex<i32> = Mutex::const_new(0);
static INIT_ASN: Mutex<bool> = Mutex::const_new(false);

static GEO_IP_ENABLE: Bool = new_bool(false);
static GEO_SITE_ENABLE: Bool = new_bool(false);
static ASN_ENABLE: Bool = new_bool(false);

static GEO_IP_URL: RwLock<String> = RwLock::new(String::new());
static MMDB_URL: RwLock<String> = RwLock::new(String::new());
static GEO_SITE_URL: RwLock<String> = RwLock::new(String::new());
static ASN_URL: RwLock<String> = RwLock::new(String::new());

pub fn geo_ip_url() -> String {
    GEO_IP_URL.read().clone()
}

pub fn set_geo_ip_url(url: &str) {
    url.clone_into(&mut GEO_IP_URL.write());
}

pub fn mmdb_url() -> String {
    MMDB_URL.read().clone()
}

pub fn set_mmdb_url(url: &str) {
    url.clone_into(&mut MMDB_URL.write());
}

pub fn geo_site_url() -> String {
    GEO_SITE_URL.read().clone()
}

pub fn set_geo_site_url(url: &str) {
    url.clone_into(&mut GEO_SITE_URL.write());
}

pub fn asn_url() -> String {
    ASN_URL.read().clone()
}

pub fn set_asn_url(url: &str) {
    url.clone_into(&mut ASN_URL.write());
}

async fn download_to_path(url: &str, path: &str) -> Result<()> {
    let ctx = CancellationToken::new();
    let timeout_ctx = ctx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(90)).await;
        timeout_ctx.cancel();
    });

    let resp = murmur_http::http_request(&ctx, url, "GET", &HashMap::new(), None, &[]).await?;

    let mut options = tokio::fs::OpenOptions::new();
    options.create(true).write(true);
    set_unix_mode(&mut options);
    let mut file = options.open(path).await?;
    let body = resp.into_body().collect().await?.to_bytes();
    file.write_all(&body).await?;

    Ok(())
}

#[cfg(unix)]
fn set_unix_mode(options: &mut tokio::fs::OpenOptions) {
    options.mode(0o644);
}

#[cfg(not(unix))]
fn set_unix_mode(_options: &mut tokio::fs::OpenOptions) {}

/// Whether a metadata lookup reports the path as missing.
async fn path_missing(path: &str) -> bool {
    matches!(tokio::fs::metadata(path).await, Err(err) if err.kind() == std::io::ErrorKind::NotFound)
}

pub async fn init_geo_site() -> Result<()> {
    GEO_SITE_ENABLE.store(true);
    let mut init_geo_site = INIT_GEO_SITE.lock().await;

    if path_missing(&PATH.geo_site()).await {
        infoln!("Can't find GeoSite.dat, start download");
        if let Err(err) = download_to_path(&geo_site_url(), &PATH.geo_site()).await {
            return Err(anyhow!("can't download GeoSite.dat: {err}"));
        }
        infoln!("Download GeoSite.dat finish");
        *init_geo_site = false;
    }
    if !*init_geo_site {
        let geosite_name = murmur_constant::path::GEOSITE_NAME.read().clone();
        if let Err(err) = verify(&geosite_name).await {
            warnln!("GeoSite.dat invalid, remove and download: {err}");
            if let Err(err) = tokio::fs::remove_file(&PATH.geo_site()).await {
                return Err(anyhow!("can't remove invalid GeoSite.dat: {err}"));
            }
            if let Err(err) = download_to_path(&geo_site_url(), &PATH.geo_site()).await {
                return Err(anyhow!("can't download GeoSite.dat: {err}"));
            }
        }
        *init_geo_site = true;
    }
    drop(init_geo_site);
    Ok(())
}

pub async fn init_geo_ip() -> Result<()> {
    GEO_IP_ENABLE.store(true);
    let mut init_geo_ip = INIT_GEO_IP.lock().await;

    if super::utils::geodata_mode() {
        if path_missing(&PATH.geo_ip()).await {
            infoln!("Can't find GeoIP.dat, start download");
            if let Err(err) = download_to_path(&geo_ip_url(), &PATH.geo_ip()).await {
                return Err(anyhow!("can't download GeoIP.dat: {err}"));
            }
            infoln!("Download GeoIP.dat finish");
            *init_geo_ip = 0;
        }

        if *init_geo_ip != 1 {
            let geoip_name = murmur_constant::path::GEOIP_NAME.read().clone();
            if let Err(err) = verify(&geoip_name).await {
                warnln!("GeoIP.dat invalid, remove and download: {err}");
                if let Err(err) = tokio::fs::remove_file(&PATH.geo_ip()).await {
                    return Err(anyhow!("can't remove invalid GeoIP.dat: {err}"));
                }
                if let Err(err) = download_to_path(&geo_ip_url(), &PATH.geo_ip()).await {
                    return Err(anyhow!("can't download GeoIP.dat: {err}"));
                }
            }
            *init_geo_ip = 1;
        }
        return Ok(());
    }

    if path_missing(&PATH.mmdb()).await {
        infoln!("Can't find MMDB, start download");
        if let Err(err) = download_to_path(&mmdb_url(), &PATH.mmdb()).await {
            return Err(anyhow!("can't download MMDB: {err}"));
        }
    }

    if *init_geo_ip != 2 {
        if !mmdb::verify(&PATH.mmdb()) {
            warnln!("MMDB invalid, remove and download");
            if let Err(err) = tokio::fs::remove_file(&PATH.mmdb()).await {
                return Err(anyhow!("can't remove invalid MMDB: {err}"));
            }
            if let Err(err) = download_to_path(&mmdb_url(), &PATH.mmdb()).await {
                return Err(anyhow!("can't download MMDB: {err}"));
            }
        }
        *init_geo_ip = 2;
    }
    drop(init_geo_ip);
    Ok(())
}

pub async fn init_asn() -> Result<()> {
    ASN_ENABLE.store(true);
    let mut init_asn = INIT_ASN.lock().await;

    if path_missing(&PATH.asn()).await {
        infoln!("Can't find ASN.mmdb, start download");
        if let Err(err) = download_to_path(&asn_url(), &PATH.asn()).await {
            return Err(anyhow!("can't download ASN.mmdb: {err}"));
        }
        infoln!("Download ASN.mmdb finish");
        *init_asn = false;
    }
    if !*init_asn {
        if !mmdb::verify(&PATH.asn()) {
            warnln!("ASN invalid, remove and download");
            if let Err(err) = tokio::fs::remove_file(&PATH.asn()).await {
                return Err(anyhow!("can't remove invalid ASN: {err}"));
            }
            if let Err(err) = download_to_path(&asn_url(), &PATH.asn()).await {
                return Err(anyhow!("can't download ASN: {err}"));
            }
        }
        *init_asn = true;
    }
    drop(init_asn);
    Ok(())
}

pub fn geo_ip_enable() -> bool {
    GEO_IP_ENABLE.load()
}

pub fn geo_site_enable() -> bool {
    GEO_SITE_ENABLE.load()
}

pub fn asn_enable() -> bool {
    ASN_ENABLE.load()
}
