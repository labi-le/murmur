use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use murmur_component_profile::cachefile::cache::CacheFile;
use murmur_component_profile::cachefile::fakeip::FakeIpStore;

pub(crate) struct CachefileStore {
    cache: FakeIpStore,
}

impl CachefileStore {
    pub(crate) fn by_host(&self, host: &str) -> Option<IpAddr> {
        self.cache.by_host(host)
    }

    pub(crate) fn put_by_host(&self, host: &str, ip: IpAddr) {
        self.cache.put_by_host(host, ip);
    }

    pub(crate) fn by_ip(&self, ip: IpAddr) -> Option<String> {
        self.cache.by_ip(ip)
    }

    pub(crate) fn put_by_ip(&self, ip: IpAddr, host: &str) {
        self.cache.put_by_ip(ip, host);
    }

    pub(crate) fn del_by_ip(&self, ip: IpAddr) {
        self.cache.del_by_ip(ip);
    }

    pub(crate) fn exist(&self, ip: IpAddr) -> bool {
        self.by_ip(ip).is_some()
    }

    pub(crate) fn flush_fake_ip(&self) -> anyhow::Result<()> {
        self.cache.flush_fake_ip()
    }
}

pub(crate) fn new_cachefile_store(cache: &Arc<CacheFile>, prefix: IpNet) -> CachefileStore {
    if prefix.addr().is_ipv6() {
        CachefileStore { cache: cache.fake_ip_store6() }
    } else {
        CachefileStore { cache: cache.fake_ip_store() }
    }
}
