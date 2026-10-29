use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use crate::STORE_SELECTED;
use murmur_constant::path::PATH;
use murmur_log::{infoln, warnln};

use super::bolt::{Db, Error, Options};

pub(crate) const FILE_MODE: u32 = 0o666;

pub(crate) static BUCKET_SELECTED: &[u8] = b"selected";
pub(crate) static BUCKET_FAKEIP: &[u8] = b"fakeip";
pub(crate) static BUCKET_FAKEIP6: &[u8] = b"fakeip6";
pub(crate) static BUCKET_ETAG: &[u8] = b"etag";
pub(crate) static BUCKET_SUBSCRIPTION_INFO: &[u8] = b"subscriptioninfo";
pub(crate) static BUCKET_STORAGE: &[u8] = b"storage";

/// Created by the first `cache` call.
static DEFAULT_CACHE: LazyLock<Arc<CacheFile>> = LazyLock::new(|| Arc::new(init_cache()));

/// Stores and updates the cache file.
pub struct CacheFile {
    pub db: Option<Db>,
}

impl core::fmt::Debug for CacheFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CacheFile").field("db", &self.db.is_some()).finish()
    }
}

impl CacheFile {
    pub fn set_selected(&self, group: &str, selected: &str) {
        if !STORE_SELECTED.load() || self.db.is_none() {
            return;
        }
        let Some(db) = self.db.as_ref() else { return };

        let result = db.batch(|t| {
            let mut bucket = t.create_bucket_if_not_exists(BUCKET_SELECTED)?;
            bucket.put(group.as_bytes(), selected.as_bytes())?;
            Ok(())
        });
        if let Err(err) = result {
            warnln!("[CacheFile] write cache to {} failed: {}", db.path(), err);
        }
    }

    pub fn selected_map(&self) -> HashMap<String, String> {
        let mut mapping = HashMap::new();
        if !STORE_SELECTED.load() || self.db.is_none() {
            return mapping;
        }
        let Some(db) = self.db.as_ref() else { return mapping };

        let _ = db.view(|t| {
            let Some(bucket) = t.bucket(BUCKET_SELECTED) else { return Ok(()) };

            let mut c = bucket.cursor();
            let mut item = c.first();
            while let Some((k, v)) = item {
                mapping.insert(String::from_utf8_lossy(k).into_owned(), String::from_utf8_lossy(v).into_owned());
                item = c.next();
            }
            Ok(())
        });
        mapping
    }

    pub fn close(&self) -> anyhow::Result<()> {
        match &self.db {
            Some(db) => Ok(db.close()?),
            None => Err(Error::DatabaseNotOpen.into()),
        }
    }
}

fn init_cache() -> CacheFile {
    let options = Options { timeout: Some(Duration::from_secs(1)), no_statistics: true };
    let mut db = Db::open(&PATH.cache(), FILE_MODE, &options);
    let mut err = db.as_ref().err().map(ToString::to_string);

    if matches!(db.as_ref().err(), Some(Error::Invalid | Error::Checksum | Error::VersionMismatch)) {
        if let Err(remove_err) = fs::remove_file(PATH.cache()) {
            warnln!("[CacheFile] remove invalid cache file error: {}", remove_err);
            // `err` is reused, so the warning below reports the remove failure.
            err = Some(remove_err.to_string());
        } else {
            infoln!("[CacheFile] remove invalid cache file and create new one");
            db = Db::open(&PATH.cache(), FILE_MODE, &options);
            err = db.as_ref().err().map(ToString::to_string);
        }
    }
    if let Some(err) = err {
        warnln!("[CacheFile] can't open cache file: {}", err);
    }

    CacheFile { db: db.ok() }
}

/// The singleton `CacheFile` instance.
pub fn cache() -> Arc<CacheFile> {
    DEFAULT_CACHE.clone()
}
