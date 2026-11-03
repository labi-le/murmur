use murmur_log::warnln;

use super::cache::{CacheFile, BUCKET_SUBSCRIPTION_INFO};

impl CacheFile {
    pub fn set_subscription_info(&self, name: &str, user_info: &str) {
        let Some(db) = self.db.as_ref() else { return };

        let result = db.batch(|t| {
            let mut bucket = t.create_bucket_if_not_exists(BUCKET_SUBSCRIPTION_INFO)?;
            bucket.put(name.as_bytes(), user_info.as_bytes())?;
            Ok(())
        });
        if let Err(err) = result {
            warnln!("[CacheFile] write cache to {} failed: {}", db.path(), err);
        }
    }

    pub fn get_subscription_info(&self, name: &str) -> String {
        let mut user_info = String::new();
        let Some(db) = self.db.as_ref() else { return user_info };

        let _ = db.view(|t| {
            let Some(bucket) = t.bucket(BUCKET_SUBSCRIPTION_INFO) else { return Ok(()) };
            let Some(v) = bucket.get(name.as_bytes()) else { return Ok(()) };
            user_info = String::from_utf8_lossy(v).into_owned();
            Ok(())
        });

        user_info
    }
}
