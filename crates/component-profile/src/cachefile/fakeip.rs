use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use murmur_log::warnln;

use super::bolt::Error;
use super::cache::{CacheFile, BUCKET_FAKEIP, BUCKET_FAKEIP6};

#[derive(Debug)]
pub struct FakeIpStore {
    pub(crate) cache_file: Arc<CacheFile>,
    pub(crate) bucket_name: &'static [u8],
}

impl CacheFile {
    pub fn fake_ip_store(self: &Arc<Self>) -> FakeIpStore {
        FakeIpStore { cache_file: Arc::clone(self), bucket_name: BUCKET_FAKEIP }
    }

    pub fn fake_ip_store6(self: &Arc<Self>) -> FakeIpStore {
        FakeIpStore { cache_file: Arc::clone(self), bucket_name: BUCKET_FAKEIP6 }
    }
}

impl FakeIpStore {
    #[must_use]
    pub fn by_host(&self, host: &str) -> Option<IpAddr> {
        let mut ip = None;
        let Some(db) = self.cache_file.db.as_ref() else { return ip };

        let _ = db.view(|t| {
            let Some(bucket) = t.bucket(self.bucket_name) else { return Ok(()) };
            let Some(v) = bucket.get(host.as_bytes()) else { return Ok(()) };
            ip = addr_from_slice(v);
            Ok(())
        });
        ip
    }

    pub fn put_by_host(&self, host: &str, ip: IpAddr) {
        let Some(db) = self.cache_file.db.as_ref() else { return };

        let result = db.batch(|t| {
            let mut bucket = t.create_bucket_if_not_exists(self.bucket_name)?;
            bucket.put(host.as_bytes(), &as_slice(ip))?;
            Ok(())
        });
        if let Err(err) = result {
            warnln!("[CacheFile] write cache to {} failed: {}", db.path(), err);
        }
    }

    #[must_use]
    pub fn by_ip(&self, ip: IpAddr) -> Option<String> {
        let mut host = None;
        let Some(db) = self.cache_file.db.as_ref() else { return host };

        let _ = db.view(|t| {
            let Some(bucket) = t.bucket(self.bucket_name) else { return Ok(()) };
            let Some(v) = bucket.get(&as_slice(ip)) else { return Ok(()) };
            host = Some(String::from_utf8_lossy(v).into_owned());
            Ok(())
        });
        host
    }

    pub fn put_by_ip(&self, ip: IpAddr, host: &str) {
        let Some(db) = self.cache_file.db.as_ref() else { return };

        let result = db.batch(|t| {
            let mut bucket = t.create_bucket_if_not_exists(self.bucket_name)?;
            bucket.put(&as_slice(ip), host.as_bytes())?;
            Ok(())
        });
        if let Err(err) = result {
            warnln!("[CacheFile] write cache to {} failed: {}", db.path(), err);
        }
    }

    pub fn del_by_ip(&self, ip: IpAddr) {
        let Some(db) = self.cache_file.db.as_ref() else { return };

        let addr = as_slice(ip);
        let result = db.batch(|t| {
            let mut bucket = t.create_bucket_if_not_exists(self.bucket_name)?;
            let host = bucket.get(&addr).map(<[u8]>::to_vec);
            let mut err = bucket.delete(&addr);
            if let Some(host) = host {
                if !host.is_empty() {
                    err = bucket.delete(&host);
                }
            }
            err?;
            Ok(())
        });
        if let Err(err) = result {
            warnln!("[CacheFile] write cache to {} failed: {}", db.path(), err);
        }
    }

    pub fn flush_fake_ip(&self) -> anyhow::Result<()> {
        let Some(db) = self.cache_file.db.as_ref() else {
            return Err(Error::DatabaseNotOpen.into());
        };

        db.batch(|t| {
            if t.bucket(self.bucket_name).is_none() {
                return Ok(());
            }
            t.delete_bucket(self.bucket_name)?;
            Ok(())
        })
    }
}

/// Accepts four or sixteen bytes.
fn addr_from_slice(slice: &[u8]) -> Option<IpAddr> {
    if let Ok(octets) = <[u8; 4]>::try_from(slice) {
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    let octets = <[u8; 16]>::try_from(slice).ok()?;
    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}

fn as_slice(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}
