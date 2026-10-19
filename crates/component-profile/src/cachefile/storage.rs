use std::collections::HashMap;

use chrono::{DateTime, Utc};

use murmur_common::time::zero_time;
use murmur_log::{infoln, warnln};

use super::cache::{CacheFile, BUCKET_STORAGE};
use super::msgpack;

pub(crate) const STORAGE_SIZE_LIMIT: usize = 1024 * 1024;
pub(crate) const STORAGE_KEY_SIZE_LIMIT: usize = 64;
pub(crate) const MAX_STORAGE_ENTRIES: usize = STORAGE_SIZE_LIMIT / STORAGE_KEY_SIZE_LIMIT;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageData {
    pub data: Vec<u8>,
    pub time: DateTime<Utc>,
}

impl Default for StorageData {
    fn default() -> Self {
        Self { data: Vec::new(), time: zero_time() }
    }
}

/// Declared inside the write transaction.
struct StorageEntry {
    key: String,
    data: StorageData,
}

impl CacheFile {
    pub fn get_storage(&self, key: &str) -> Option<Vec<u8>> {
        let db = self.db.as_ref()?;

        let mut data = None;
        let mut decode_failed = false;
        let result = db.view(|t| {
            let Some(bucket) = t.bucket(BUCKET_STORAGE) else { return Ok(()) };
            let Some(v) = bucket.get(key.as_bytes()) else { return Ok(()) };

            match msgpack::decode_storage_data(v) {
                Ok(storage) => {
                    data = Some(storage.data);
                    Ok(())
                }
                Err(err) => {
                    decode_failed = true;
                    Err(err)
                }
            }
        });
        if let Err(err) = result {
            warnln!("[CacheFile] read cache for key {} failed: {}", key, err);
            if decode_failed {
                self.delete_storage(key);
            }
            return None;
        }
        data
    }

    pub fn set_storage(&self, key: &str, data: &[u8]) {
        let Some(db) = self.db.as_ref() else { return };

        if key.len() > STORAGE_KEY_SIZE_LIMIT {
            warnln!("[CacheFile] skip storage for key {}: key exceeds {} bytes", key, STORAGE_KEY_SIZE_LIMIT);
            return;
        }
        if data.len() > STORAGE_SIZE_LIMIT {
            warnln!("[CacheFile] skip storage for key {}: payload exceeds {} bytes", key, STORAGE_SIZE_LIMIT);
            return;
        }
        let key_bytes = key.as_bytes();
        let payload = msgpack::encode_storage_data(data, &Utc::now());

        let result = db.batch(|t| {
            let mut bucket = t.create_bucket_if_not_exists(BUCKET_STORAGE)?;

            let mut entries: HashMap<String, StorageData> = HashMap::new();
            let mut used_size = 0;
            let mut entry_count = 0;
            let mut corrupted_keys: Vec<Vec<u8>> = Vec::new();
            let mut c = bucket.cursor();
            let mut item = c.first();
            while let Some((k, v)) = item {
                match msgpack::decode_storage_data(v) {
                    Ok(storage) => {
                        let entry_key = String::from_utf8_lossy(k).into_owned();
                        let size = storage.data.len();
                        let is_target = entry_key == key;
                        entries.insert(entry_key, storage);
                        if !is_target {
                            used_size += size;
                            entry_count += 1;
                        }
                    }
                    Err(err) => {
                        warnln!("[CacheFile] drop corrupted storage entry {}: {}", String::from_utf8_lossy(k), err);
                        corrupted_keys.push(k.to_vec());
                    }
                }
                item = c.next();
            }
            for k in corrupted_keys {
                bucket.delete(&k)?;
            }

            let mut eviction_queue: Vec<StorageEntry> = Vec::with_capacity(entries.len());
            for (entry_key, storage) in entries {
                if entry_key == key {
                    continue;
                }
                eviction_queue.push(StorageEntry { key: entry_key, data: storage });
            }
            eviction_queue.sort_by(|left, right| {
                if left.data.time == right.data.time {
                    return left.key.cmp(&right.key);
                }
                left.data.time.cmp(&right.data.time)
            });

            for entry in &eviction_queue {
                if used_size + data.len() <= STORAGE_SIZE_LIMIT && entry_count < MAX_STORAGE_ENTRIES {
                    break;
                }
                bucket.delete(entry.key.as_bytes())?;
                infoln!("[CacheFile] evict storage entry {} to make room for {}", entry.key, key);
                used_size -= entry.data.data.len();
                entry_count -= 1;
            }
            bucket.put(key_bytes, &payload)?;
            Ok(())
        });
        if let Err(err) = result {
            warnln!("[CacheFile] write cache to {} failed: {}", db.path(), err);
        }
    }

    pub fn delete_storage(&self, key: &str) {
        let Some(db) = self.db.as_ref() else { return };

        let result = db.batch(|t| {
            let Some(mut bucket) = t.bucket(BUCKET_STORAGE) else { return Ok(()) };
            bucket.delete(key.as_bytes())?;
            Ok(())
        });
        if let Err(err) = result {
            warnln!("[CacheFile] delete cache from {} failed: {}", db.path(), err);
        }
    }
}
