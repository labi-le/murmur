use chrono::{DateTime, Utc};

use murmur_common::time::zero_time;
use murmur_common::utils::hash::HashType;
use murmur_log::warnln;

use super::cache::{CacheFile, BUCKET_ETAG};
use super::msgpack;

/// The `EtagWithHash` struct; its msgpack map keys are the field names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtagWithHash {
    pub hash: HashType,
    pub etag: String,
    pub time: DateTime<Utc>,
}

impl Default for EtagWithHash {
    fn default() -> Self {
        Self { hash: HashType::default(), etag: String::new(), time: zero_time() }
    }
}

impl CacheFile {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the published cache API takes the value by ownership; the msgpack encoder only borrows it"
    )]
    pub fn set_etag_with_hash(&self, url: &str, etag_with_hash: EtagWithHash) {
        let Some(db) = self.db.as_ref() else { return };

        let data = msgpack::encode_etag_with_hash(&etag_with_hash);

        let result = db.batch(|t| {
            let mut bucket = t.create_bucket_if_not_exists(BUCKET_ETAG)?;
            bucket.put(url.as_bytes(), &data)?;
            Ok(())
        });
        if let Err(err) = result {
            warnln!("[CacheFile] write cache to {} failed: {}", db.path(), err);
        }
    }

    pub fn get_etag_with_hash(&self, key: &str) -> EtagWithHash {
        let mut etag_with_hash = EtagWithHash::default();
        let Some(db) = self.db.as_ref() else { return etag_with_hash };

        let _ = db.view(|t| {
            let Some(bucket) = t.bucket(BUCKET_ETAG) else { return Ok(()) };
            let Some(v) = bucket.get(key.as_bytes()) else { return Ok(()) };
            etag_with_hash = msgpack::decode_etag_with_hash(v)?;
            Ok(())
        });

        etag_with_hash
    }
}
