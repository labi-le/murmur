use std::net::IpAddr;
use std::sync::Arc;

use murmur_common::lru;
use murmur_common::lru::LruCache;

/// The in-memory store. Both indexes hold the same `Arc<str>` handle for a hostname, so one
/// insertion pair allocates the hostname once. The cached IP's value is `Option<IpAddr>` (always
/// `Some`) because `LruCache::get` requires `V: Default`, which `IpAddr` does not implement; the
/// reverse cache stores `Arc<str>`, whose `Default` is the empty string but is never written.
pub(crate) struct MemoryStore {
    cache_ip: LruCache<Arc<str>, Option<IpAddr>>,
    cache_host: LruCache<IpAddr, Arc<str>>,
}

impl MemoryStore {
    pub(crate) fn by_host(&self, host: &str) -> Option<IpAddr> {
        let (ip, exist) = self.cache_ip.get(host);
        if !exist {
            return None;
        }
        #[expect(
            clippy::expect_used,
            reason = "`cache_ip` is written only through `put_pair`, which always stores `Some`, so the entry is present here"
        )]
        let ip = ip.expect("memoryStore.cache_ip always stores Some(ip)");
        self.cache_host.touch(&ip);
        Some(ip)
    }

    /// Stores both directions with one hostname allocation shared by the forward key, its LRU
    /// entry key and the reverse value.
    pub(crate) fn put_pair(&self, host: Arc<str>, ip: IpAddr) {
        self.cache_ip.set(Arc::clone(&host), Some(ip));
        self.cache_host.set(ip, host);
    }

    pub(crate) fn by_ip(&self, ip: IpAddr) -> Option<String> {
        let (host, exist) = self.cache_host.get(&ip);
        if !exist {
            return None;
        }
        let host = String::from(&*host);
        self.cache_ip.touch(host.as_str());
        Some(host)
    }

    pub(crate) fn del_by_ip(&self, ip: IpAddr) {
        let (host, exist) = self.cache_host.get(&ip);
        if exist {
            self.cache_ip.delete(host);
        }
        self.cache_host.delete(ip);
    }

    pub(crate) fn exist(&self, ip: IpAddr) -> bool {
        self.cache_host.exist(ip)
    }

    pub(crate) fn clone_to(&self, dst: &Self) {
        self.cache_ip.clone_to(&dst.cache_ip);
        self.cache_host.clone_to(&dst.cache_host);
    }

    pub(crate) fn flush_fake_ip(&self) {
        self.cache_ip.clear();
        self.cache_host.clear();
    }
}

pub(crate) fn new_memory_store(size: usize) -> MemoryStore {
    MemoryStore { cache_ip: lru::new(vec![lru::with_size(size)]), cache_host: lru::new(vec![lru::with_size(size)]) }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn put_pair(store: &MemoryStore, host: &str, ip: IpAddr) {
        store.put_pair(Arc::from(host), ip);
    }

    #[test]
    fn by_host_touches_reverse_entry() {
        let store = new_memory_store(2);
        put_pair(&store, "a.example", test_ip(1));
        put_pair(&store, "b.example", test_ip(2));

        assert_eq!(store.by_host("a.example"), Some(test_ip(1)));

        put_pair(&store, "c.example", test_ip(3));

        assert_eq!(store.by_ip(test_ip(1)).as_deref(), Some("a.example"));
        assert_eq!(store.by_ip(test_ip(2)), None);
    }

    #[test]
    fn by_ip_touches_forward_entry() {
        let store = new_memory_store(2);
        put_pair(&store, "a.example", test_ip(1));
        put_pair(&store, "b.example", test_ip(2));

        assert_eq!(store.by_ip(test_ip(1)).as_deref(), Some("a.example"));

        put_pair(&store, "c.example", test_ip(3));

        assert_eq!(store.by_host("a.example"), Some(test_ip(1)));
        assert_eq!(store.by_host("b.example"), None);
    }

    #[test]
    fn del_by_ip_removes_both_directions() {
        let store = new_memory_store(4);
        put_pair(&store, "a.example", test_ip(1));

        store.del_by_ip(test_ip(1));

        assert_eq!(store.by_host("a.example"), None);
        assert_eq!(store.by_ip(test_ip(1)), None);
    }
}
