//! The "standard" geodata loader implementation registers itself at startup.
//!
//! There is no automatic side-effecting import, so `ensure_standard_loader_registered` calls
//! `geodata::standard::standard::init()` once before any lookup; the lookup that follows reports a
//! missing registration as an error rather than panicking.
//!
//! The concurrent updates run on a `tokio::task::JoinSet`, which returns the first error after all
//! of them finish.
//! Closing an mmap before overwriting the database file on disk is unnecessary here:
//! `maxminddb::Reader<Vec<u8>>` already holds its bytes in memory rather than mmap-ing the file,
//! so there is no handle to close and that step is dropped.

use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use murmur_common::atomic::type_::{new_bool, Bool};
use murmur_common::utils::hash::make_hash;
use murmur_component_geodata::geodata::get_geo_data_loader;
use murmur_component_geodata::init as geodata_init;
use murmur_component_geodata::standard::standard as geodata_standard;
use murmur_component_geodata::utils as geodata_utils;
use murmur_component_mmdb as mmdb;
use murmur_component_resource::vehicle::HTTPVehicle;
use murmur_constant::path::PATH;
use murmur_constant::provider::interface::Vehicle as _;
use murmur_log::{errorln, infoln};

use super::utils::DEFAULT_HTTP_TIMEOUT;

static AUTO_UPDATE: parking_lot::RwLock<bool> = parking_lot::RwLock::new(false);
static UPDATE_INTERVAL: parking_lot::RwLock<i32> = parking_lot::RwLock::new(0);

static UPDATING_GEO: Bool = new_bool(false);

static STANDARD_LOADER_INIT: LazyLock<()> = LazyLock::new(geodata_standard::init);

fn ensure_standard_loader_registered() {
    LazyLock::force(&STANDARD_LOADER_INIT);
}

pub fn geo_auto_update() -> bool {
    *AUTO_UPDATE.read()
}

pub fn geo_update_interval() -> i32 {
    *UPDATE_INTERVAL.read()
}

pub fn set_geo_auto_update(new_auto_update: bool) {
    *AUTO_UPDATE.write() = new_auto_update;
}

pub fn set_geo_update_interval(new_geo_update_interval: i32) {
    *UPDATE_INTERVAL.write() = new_geo_update_interval;
}

// NOT cancel-safe: an abort after the in-memory install but before the save leaves memory
// holding the new database while the file on disk keeps the old one.
pub async fn update_mmdb() -> Result<()> {
    let vehicle = HTTPVehicle::new(
        &geodata_init::mmdb_url(),
        &PATH.mmdb(),
        "",
        std::collections::HashMap::new(),
        DEFAULT_HTTP_TIMEOUT,
        0,
    );
    let old_hash = tokio::fs::read(vehicle.path()).await.map(|buf| make_hash(&buf)).unwrap_or_default();

    let (data, hash) = vehicle
        .read(&CancellationToken::new(), old_hash)
        .await
        .map_err(|err| anyhow!("can't download MMDB database file: {err}"))?;
    if old_hash.equal(hash) {
        return Ok(());
    }
    if data.is_empty() {
        return Err(anyhow!("can't download MMDB database file: no data"));
    }

    maxminddb::Reader::from_source(data.clone()).map_err(|err| anyhow!("invalid MMDB database file: {err}"))?;
    mmdb::reload_ip();
    let save = tokio::task::spawn_blocking(move || vehicle.write(&data)).await?;
    save.map_err(|err| anyhow!("can't save MMDB database file: {err}"))?;
    Ok(())
}

// NOT cancel-safe: an abort after the in-memory install but before the save leaves memory
// holding the new database while the file on disk keeps the old one.
pub async fn update_asn() -> Result<()> {
    let vehicle = HTTPVehicle::new(
        &geodata_init::asn_url(),
        &PATH.asn(),
        "",
        std::collections::HashMap::new(),
        DEFAULT_HTTP_TIMEOUT,
        0,
    );
    let old_hash = tokio::fs::read(vehicle.path()).await.map(|buf| make_hash(&buf)).unwrap_or_default();

    let (data, hash) = vehicle
        .read(&CancellationToken::new(), old_hash)
        .await
        .map_err(|err| anyhow!("can't download ASN database file: {err}"))?;
    if old_hash.equal(hash) {
        return Ok(());
    }
    if data.is_empty() {
        return Err(anyhow!("can't download ASN database file: no data"));
    }

    maxminddb::Reader::from_source(data.clone()).map_err(|err| anyhow!("invalid ASN database file: {err}"))?;
    mmdb::reload_asn();
    let save = tokio::task::spawn_blocking(move || vehicle.write(&data)).await?;
    save.map_err(|err| anyhow!("can't save ASN database file: {err}"))?;
    Ok(())
}

// NOT cancel-safe: an abort after the in-memory install but before the save leaves memory
// holding the new database while the file on disk keeps the old one.
pub async fn update_geo_ip() -> Result<()> {
    ensure_standard_loader_registered();
    let geo_loader = get_geo_data_loader("standard").ok();

    let vehicle = HTTPVehicle::new(
        &geodata_init::geo_ip_url(),
        &PATH.geo_ip(),
        "",
        std::collections::HashMap::new(),
        DEFAULT_HTTP_TIMEOUT,
        0,
    );
    let old_hash = tokio::fs::read(vehicle.path()).await.map(|buf| make_hash(&buf)).unwrap_or_default();

    let (data, hash) = vehicle
        .read(&CancellationToken::new(), old_hash)
        .await
        .map_err(|err| anyhow!("can't download GeoIP database file: {err}"))?;
    if old_hash.equal(hash) {
        return Ok(());
    }
    if data.is_empty() {
        return Err(anyhow!("can't download GeoIP database file: no data"));
    }

    geo_loader
        .ok_or_else(|| anyhow!("\"standard\" GeoData loader must be registered"))?
        .load_ip_by_bytes(&data, "cn")
        .map_err(|err| anyhow!("invalid GeoIP database file: {err}"))?;

    geodata_utils::clear_geo_ip_cache();
    let save = tokio::task::spawn_blocking(move || vehicle.write(&data)).await?;
    save.map_err(|err| anyhow!("can't save GeoIP database file: {err}"))?;
    Ok(())
}

// NOT cancel-safe: an abort after the in-memory install but before the save leaves memory
// holding the new database while the file on disk keeps the old one.
pub async fn update_geo_site() -> Result<()> {
    ensure_standard_loader_registered();
    let geo_loader = get_geo_data_loader("standard").ok();

    let vehicle = HTTPVehicle::new(
        &geodata_init::geo_site_url(),
        &PATH.geo_site(),
        "",
        std::collections::HashMap::new(),
        DEFAULT_HTTP_TIMEOUT,
        0,
    );
    let old_hash = tokio::fs::read(vehicle.path()).await.map(|buf| make_hash(&buf)).unwrap_or_default();

    let (data, hash) = vehicle
        .read(&CancellationToken::new(), old_hash)
        .await
        .map_err(|err| anyhow!("can't download GeoSite database file: {err}"))?;
    if old_hash.equal(hash) {
        return Ok(());
    }
    if data.is_empty() {
        return Err(anyhow!("can't download GeoSite database file: no data"));
    }

    geo_loader
        .ok_or_else(|| anyhow!("\"standard\" GeoData loader must be registered"))?
        .load_site_by_bytes(&data, "cn")
        .map_err(|err| anyhow!("invalid GeoSite database file: {err}"))?;

    geodata_utils::clear_geo_site_cache();
    let save = tokio::task::spawn_blocking(move || vehicle.write(&data)).await?;
    save.map_err(|err| anyhow!("can't save GeoSite database file: {err}"))?;
    Ok(())
}

// NOT cancel-safe: dropping it aborts the spawned updates, which can leave memory holding a
// database the file on disk never received.
async fn update_geo_databases() -> Result<()> {
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();

    if geodata_init::geo_ip_enable() {
        if geodata_utils::geodata_mode() {
            tasks.spawn(update_geo_ip());
        } else {
            tasks.spawn(update_mmdb());
        }
    }

    if geodata_init::asn_enable() {
        tasks.spawn(update_asn());
    }

    if geodata_init::geo_site_enable() {
        tasks.spawn(update_geo_site());
    }

    let mut first_error = None;
    while let Some(result) = tasks.join_next().await {
        let result = result.map_err(|err| anyhow!("task join error: {err}"))?;
        if let Err(err) = result {
            if first_error.is_none() {
                first_error = Some(err);
            }
        }
    }

    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

#[derive(Debug, Error)]
#[error("GEO database is updating, skip")]
pub struct ErrGetDatabaseUpdateSkip;

/// The public and private spellings both case-fold to `update_geo_databases`; this keeps the
/// private name and renames the public wrapper to `update_geo_databases_guarded` to avoid the
/// collision.
// NOT cancel-safe: a drop between the two `UPDATING_GEO` stores leaves the flag set, so every
// later update reports that one is already running until the process restarts.
pub async fn update_geo_databases_guarded() -> Result<()> {
    infoln!("[GEO] Start updating GEO database");

    if UPDATING_GEO.load() {
        return Err(ErrGetDatabaseUpdateSkip.into());
    }

    UPDATING_GEO.store(true);
    infoln!("[GEO] Updating GEO database");

    let result = update_geo_databases().await;
    if let Err(err) = &result {
        errorln!("[GEO] update GEO database error: {err}");
    }
    UPDATING_GEO.store(false);
    result
}

async fn get_update_time() -> Result<DateTime<Utc>> {
    let files_to_check = [PATH.geo_ip(), PATH.mmdb(), PATH.asn(), PATH.geo_site()];

    let mut last_err = None;
    for file in files_to_check {
        match tokio::fs::metadata(&file).await {
            Ok(metadata) => return Ok(DateTime::<Utc>::from(metadata.modified()?)),
            Err(err) => last_err = Some(err),
        }
    }

    match last_err {
        Some(err) => Err(err.into()),
        None => Err(anyhow!("no GEO database file to check")),
    }
}

pub fn register_geo_updater() {
    let update_interval = geo_update_interval();
    if update_interval <= 0 {
        errorln!("[GEO] Invalid update interval: {update_interval}");
        return;
    }

    tokio::spawn(async move {
        let Ok(interval_hours) = u64::try_from(update_interval) else {
            return;
        };
        let mut interval = tokio::time::interval(Duration::from_secs(interval_hours * 3600));
        interval.tick().await;

        let last_update = match get_update_time().await {
            Ok(time) => time,
            Err(err) => {
                errorln!("[GEO] Get GEO database update time error: {err}");
                return;
            }
        };

        infoln!("[GEO] last update time {last_update}");
        let refresh_after = last_update + chrono::Duration::hours(i64::from(update_interval));
        if refresh_after < Utc::now() {
            infoln!("[GEO] Database has not been updated for {update_interval}h, update now");
            if let Err(err) = update_geo_databases_guarded().await {
                errorln!("[GEO] Failed to update GEO database: {err}");
                return;
            }
        }

        loop {
            interval.tick().await;
            infoln!("[GEO] updating database every {update_interval} hours");
            if let Err(err) = update_geo_databases_guarded().await {
                errorln!("[GEO] Failed to update GEO database: {err}");
            }
        }
    });
}
