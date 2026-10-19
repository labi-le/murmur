//!
//! DEVIATION: a `parking_lot::Mutex` cannot be bypassed, so every accessor locks the same
//! `PoolState`.
//!
//! This is strictly safer and behaves identically for the single-threaded call patterns `Pool` is
//! used with.
//!
//! Address next/previous return an invalid zero value on overflow; no fake-ip subnet realistically
//! exhausts the address space, so the arithmetic wraps instead of modelling that invalid value,
//! keeping `Pool`'s fields plain `IpAddr`.
//!
//! A zero prefix is invalid, which the constructor rejects; `ipnet::IpNet`
//! has no such invalid representation (a constructed value is always valid), so that guard reduces
//! to the `first < last` range check the same test suite already covers.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};
use ipnet::IpNet;
use parking_lot::Mutex;

use murmur_component_profile::cachefile::cache::cache as profile_cachefile_cache;

use super::cachefile::{new_cachefile_store, CachefileStore};
use super::memory::{new_memory_store, MemoryStore};

const OFFSET_KEY: &str = "key-offset-fake-ip";
const CYCLE_KEY: &str = "key-cycle-fake-ip";

// Reloaded pools share cachefile buckets but not their per-pool state mutex.
static PERSISTENT_ALLOCATION: Mutex<()> = Mutex::new(());

/// A closed enum, not a trait object: `Pool` only ever holds one of these two concrete backends,
/// and every call site already matches on which one it needs.
pub(crate) enum Store {
    Memory(Box<MemoryStore>),
    Cachefile(CachefileStore),
}

impl Store {
    fn by_host(&self, host: &str) -> Option<IpAddr> {
        match self {
            Self::Memory(s) => s.by_host(host),
            Self::Cachefile(s) => s.by_host(host),
        }
    }

    fn put_by_host(&self, host: &str, ip: IpAddr) {
        match self {
            Self::Memory(s) => s.put_by_host(host, ip),
            Self::Cachefile(s) => s.put_by_host(host, ip),
        }
    }

    fn by_ip(&self, ip: IpAddr) -> Option<String> {
        match self {
            Self::Memory(s) => s.by_ip(ip),
            Self::Cachefile(s) => s.by_ip(ip),
        }
    }

    fn put_by_ip(&self, ip: IpAddr, host: &str) {
        match self {
            Self::Memory(s) => s.put_by_ip(ip, host),
            Self::Cachefile(s) => s.put_by_ip(ip, host),
        }
    }

    fn del_by_ip(&self, ip: IpAddr) {
        match self {
            Self::Memory(s) => s.del_by_ip(ip),
            Self::Cachefile(s) => s.del_by_ip(ip),
        }
    }

    fn exist(&self, ip: IpAddr) -> bool {
        match self {
            Self::Memory(s) => s.exist(ip),
            Self::Cachefile(s) => s.exist(ip),
        }
    }

    /// A no-op unless both sides are the in-memory store (a cachefile-backed store is already
    /// persistent, and the same bail applies when either side is cachefile-backed).
    fn clone_to(&self, dst: &Self) {
        if let (Self::Memory(src), Self::Memory(dst)) = (self, dst) {
            src.clone_to(dst);
        }
    }

    fn flush_fake_ip(&self) -> Result<()> {
        match self {
            Self::Memory(s) => {
                s.flush_fake_ip();
                Ok(())
            }
            Self::Cachefile(s) => s.flush_fake_ip(),
        }
    }
}

/// The mutable half of `Pool`'s fields, all reachable only through `Pool::state`.
struct PoolState {
    offset: IpAddr,
    cycle: bool,
    store: Store,
}

/// `Pool`: an implementation about fake ip generator without storage.
pub struct Pool {
    gateway: IpAddr,
    first: IpAddr,
    last: IpAddr,
    ipnet: IpNet,
    state: Mutex<PoolState>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("gateway", &self.gateway)
            .field("first", &self.first)
            .field("last", &self.last)
            .field("ipnet", &self.ipnet)
            .finish_non_exhaustive()
    }
}

impl Pool {
    /// return a fake ip with host.
    pub fn lookup(&self, host: &str) -> IpAddr {
        let mut state = self.state.lock();

        // RFC4343: DNS Case Insensitive, we SHOULD return result with all cases.
        let host = lower_host(host);
        if let Some(ip) = state.store.by_host(&host) {
            return ip;
        }

        let _persistent_allocation = if matches!(&state.store, Store::Cachefile(_)) {
            let guard = PERSISTENT_ALLOCATION.lock();
            if let Some(ip) = state.store.by_host(&host) {
                return ip;
            }
            Some(guard)
        } else {
            None
        };

        let ip = get_locked(&mut state, self.first, self.last, &host);
        state.store.put_by_host(&host, ip);
        ip
    }

    /// return host with the fake ip.
    pub fn look_back(&self, ip: IpAddr) -> Option<String> {
        self.state.lock().store.by_ip(ip)
    }

    /// returns if given ip exists in fake-ip pool.
    pub fn exist(&self, ip: IpAddr) -> bool {
        self.state.lock().store.exist(ip)
    }

    /// return gateway ip.
    pub const fn gateway(&self) -> IpAddr {
        self.gateway
    }

    /// return the last ip.
    pub const fn broadcast(&self) -> IpAddr {
        self.last
    }

    /// return raw ipnet.
    pub const fn ip_net(&self) -> IpNet {
        self.ipnet
    }

    /// Clone mappings and the allocation cursor from an old pool with the same prefix.
    pub fn clone_from(&self, o: &Self) {
        if std::ptr::eq(self, o) || self.first != o.first || self.last != o.last {
            return;
        }

        // Opposite-direction clones must acquire the pool locks in the same order.
        let (mut p_state, o_state) = if std::ptr::from_ref(self) < std::ptr::from_ref(o) {
            (self.state.lock(), o.state.lock())
        } else {
            let o_state = o.state.lock();
            (self.state.lock(), o_state)
        };
        o_state.store.clone_to(&p_state.store);
        p_state.offset = o_state.offset;
        p_state.cycle = o_state.cycle;
    }

    pub fn flush_fake_ip(&self) -> Result<()> {
        let mut state = self.state.lock();
        let persistent_allocation = matches!(&state.store, Store::Cachefile(_)).then(|| PERSISTENT_ALLOCATION.lock());
        let result = flush_fake_ip_locked(&mut state, self.first);
        drop(persistent_allocation);
        drop(state);
        result
    }

    pub fn store_state(&self) {
        let state = self.state.lock();
        if let Store::Cachefile(s) = &state.store {
            let _persistent_allocation = PERSISTENT_ALLOCATION.lock();
            s.put_by_host(OFFSET_KEY, state.offset);
            if state.cycle {
                s.put_by_host(CYCLE_KEY, state.offset);
            }
        }
    }
}

/// RFC4343 lowercasing, borrowing the input when it is already ASCII lowercase.
fn lower_host(host: &str) -> Cow<'_, str> {
    if host.is_ascii() {
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        }
    } else {
        Cow::Owned(host.to_lowercase())
    }
}

fn get_locked(state: &mut PoolState, first: IpAddr, last: IpAddr, host: &str) -> IpAddr {
    loop {
        state.offset = addr_next(state.offset);

        if !addr_less(state.offset, last) {
            state.cycle = true;
            state.offset = first;
        }

        // Persistent mappings can be newer than a restored or copied cursor.
        if state.cycle || !state.store.exist(state.offset) {
            break;
        }
    }

    if state.cycle {
        state.store.del_by_ip(state.offset);
    }

    state.store.put_by_ip(state.offset, host);
    state.offset
}

/// Shared with `restore_state`, which runs before `Pool.state` exists.
fn flush_fake_ip_locked(state: &mut PoolState, first: IpAddr) -> Result<()> {
    state.store.flush_fake_ip()?;
    state.cycle = false;
    state.offset = addr_prev(first);
    Ok(())
}

/// Called from the constructor before the state is behind a lock.
fn restore_state(ipnet: &IpNet, first: IpAddr, state: &mut PoolState) {
    let Store::Cachefile(store) = &state.store else {
        return;
    };
    let _persistent_allocation = PERSISTENT_ALLOCATION.lock();
    let has_cycle = store.by_host(CYCLE_KEY).is_some();
    let offset_entry = store.by_host(OFFSET_KEY);

    if has_cycle {
        state.cycle = true;
    }

    match offset_entry {
        Some(offset) if ipnet.contains(&offset) => state.offset = offset,
        Some(_) => {
            let _ = flush_fake_ip_locked(state, first);
        }
        // A live pool may have written mappings without saving its shutdown cursor yet.
        None => {}
    }
}

/// Overflow wraps instead of producing an invalid zero address.
fn addr_next(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4).wrapping_add(1))),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(v6.octets()).wrapping_add(1).to_be_bytes())),
    }
}

/// Underflow wraps instead of producing an invalid zero address.
fn addr_prev(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4).wrapping_sub(1))),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(v6.octets()).wrapping_sub(1).to_be_bytes())),
    }
}

/// Restricted to same-family comparisons (`Pool` never mixes them).
fn addr_less(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => u32::from(a) < u32::from(b),
        (IpAddr::V6(a), IpAddr::V6(b)) => u128::from_be_bytes(a.octets()) < u128::from_be_bytes(b.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => true,
        (IpAddr::V6(_), IpAddr::V4(_)) => false,
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub ip_net: IpNet,

    /// Size sets the maximum number of entries in memory and does not work if `persistence` is
    /// `true`.
    pub size: i32,

    /// Persistence will save the data to disk. `size` will not work and record will be fully
    /// stored.
    pub persistence: bool,
}

/// Creates a Pool instance. The gateway is the network address plus one; the pool's first
/// usable address skips three more addresses past the gateway, matching the default fake-ip
/// layout.
pub fn new(options: Options) -> Result<Pool> {
    let host_addr = options.ip_net.network();
    let gateway = addr_next(host_addr);
    let first = addr_next(addr_next(addr_next(gateway)));
    let last = options.ip_net.broadcast();

    if !addr_less(first, last) {
        return Err(anyhow!("ipnet don't have valid ip"));
    }

    let store = if options.persistence {
        Store::Cachefile(new_cachefile_store(&profile_cachefile_cache(), options.ip_net))
    } else {
        Store::Memory(Box::new(new_memory_store(usize::try_from(options.size.max(0)).unwrap_or(0))))
    };

    let mut state = PoolState { offset: addr_prev(first), cycle: false, store };
    restore_state(&options.ip_net, first, &mut state);

    Ok(Pool { gateway, first, last, ipnet: options.ip_net, state: Mutex::new(state) })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use murmur_common::utils::uuid::new_uuid_v4;
    use murmur_component_profile::cachefile::bolt::{Db, Options as BoltOptions};
    use murmur_component_profile::cachefile::cache::CacheFile;

    use super::*;

    struct TempFileGuard(PathBuf);

    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn temp_file_path() -> PathBuf {
        std::env::temp_dir().join(format!("murmur-{}", new_uuid_v4()))
    }

    fn create_pools(options: Options) -> Result<(Vec<Pool>, PathBuf)> {
        let pool = new(options)?;
        let (file_pool, _, tempfile) = create_cachefile_store(options)?;
        Ok((vec![pool, file_pool], tempfile))
    }

    fn create_cachefile_store(options: Options) -> Result<(Pool, Arc<CacheFile>, PathBuf)> {
        let pool = new(options)?;
        let path = temp_file_path();

        let db = Db::open(
            &path.to_string_lossy(),
            0o666,
            &BoltOptions { timeout: Some(std::time::Duration::from_secs(1)), no_statistics: true },
        )?;

        let cache = Arc::new(CacheFile { db: Some(db) });
        pool.state.lock().store = Store::Cachefile(new_cachefile_store(&cache, options.ip_net));
        Ok((pool, cache, path))
    }

    #[test]
    fn test_pool_basic() {
        let ipnet: IpNet = "192.168.0.0/28".parse().unwrap();
        let (pools, tempfile) = create_pools(Options { ip_net: ipnet, size: 10, persistence: false }).unwrap();
        let _guard = TempFileGuard(tempfile);

        for pool in &pools {
            let first = pool.lookup("foo.com");
            let last = pool.lookup("bar.com");
            let bar = pool.look_back(last);

            assert_eq!(first, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 4)));
            assert_eq!(pool.lookup("foo.com"), IpAddr::V4(Ipv4Addr::new(192, 168, 0, 4)));
            assert_eq!(last, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 5)));
            assert_eq!(bar.as_deref(), Some("bar.com"));
            assert_eq!(pool.gateway(), IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
            assert_eq!(pool.broadcast(), IpAddr::V4(Ipv4Addr::new(192, 168, 0, 15)));
            assert_eq!(pool.ip_net().to_string(), ipnet.to_string());
            assert!(pool.exist(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 5))));
            assert!(!pool.exist(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 6))));
            assert!(!pool.exist("::1".parse().unwrap()));
        }
    }

    #[test]
    fn test_pool_basic_v6() {
        let ipnet: IpNet = "2001:4860:4860::8888/118".parse().unwrap();
        let (pools, tempfile) = create_pools(Options { ip_net: ipnet, size: 10, persistence: false }).unwrap();
        let _guard = TempFileGuard(tempfile);

        for pool in &pools {
            let first = pool.lookup("foo.com");
            let last = pool.lookup("bar.com");
            let bar = pool.look_back(last);

            assert_eq!(first, "2001:4860:4860:0000:0000:0000:0000:8804".parse::<IpAddr>().unwrap());
            assert_eq!(pool.lookup("foo.com"), "2001:4860:4860:0000:0000:0000:0000:8804".parse::<IpAddr>().unwrap());
            assert_eq!(last, "2001:4860:4860:0000:0000:0000:0000:8805".parse::<IpAddr>().unwrap());
            assert_eq!(bar.as_deref(), Some("bar.com"));
            assert_eq!(pool.gateway(), "2001:4860:4860:0000:0000:0000:0000:8801".parse::<IpAddr>().unwrap());
            assert_eq!(pool.broadcast(), "2001:4860:4860:0000:0000:0000:0000:8bff".parse::<IpAddr>().unwrap());
            assert_eq!(pool.ip_net().to_string(), ipnet.to_string());
            assert!(pool.exist("2001:4860:4860:0000:0000:0000:0000:8805".parse().unwrap()));
            assert!(!pool.exist("2001:4860:4860:0000:0000:0000:0000:8806".parse().unwrap()));
            assert!(!pool.exist("127.0.0.1".parse().unwrap()));
        }
    }

    #[test]
    fn test_pool_case_insensitive() {
        let ipnet: IpNet = "192.168.0.1/29".parse().unwrap();
        let (pools, tempfile) = create_pools(Options { ip_net: ipnet, size: 10, persistence: false }).unwrap();
        let _guard = TempFileGuard(tempfile);

        for pool in &pools {
            let first = pool.lookup("foo.com");
            let last = pool.lookup("Foo.Com");
            let foo = pool.look_back(last);

            assert_eq!(first, pool.lookup("Foo.Com"));
            assert_eq!(pool.lookup("fOo.cOM"), first);
            assert_eq!(foo.as_deref(), Some("foo.com"));
        }
    }

    #[test]
    fn test_pool_cycle_used() {
        let ipnet: IpNet = "192.168.0.16/28".parse().unwrap();
        let (pools, tempfile) = create_pools(Options { ip_net: ipnet, size: 10, persistence: false }).unwrap();
        let _guard = TempFileGuard(tempfile);

        for pool in &pools {
            let foo = pool.lookup("foo.com");
            let bar = pool.lookup("bar.com");
            for i in 0..9 {
                pool.lookup(&format!("{i}.com"));
            }
            let baz = pool.lookup("baz.com");
            let next = pool.lookup("foo.com");
            assert_eq!(foo, baz);
            assert_eq!(next, bar);
        }
    }

    #[test]
    fn test_pool_max_cache_size() {
        let ipnet: IpNet = "192.168.0.1/24".parse().unwrap();
        let pool = new(Options { ip_net: ipnet, size: 2, persistence: false }).unwrap();

        let first = pool.lookup("foo.com");
        pool.lookup("bar.com");
        pool.lookup("baz.com");
        let next = pool.lookup("foo.com");

        assert_ne!(first, next);
    }

    #[test]
    fn test_pool_double_mapping() {
        let ipnet: IpNet = "192.168.0.1/24".parse().unwrap();
        let pool = new(Options { ip_net: ipnet, size: 2, persistence: false }).unwrap();

        let foo_ip = pool.lookup("foo.com");
        let baz_ip = pool.lookup("baz.com");

        pool.lookup("foo.com");

        let bar_ip = pool.lookup("bar.com");

        let foo_exist = pool.look_back(foo_ip).is_some();
        let baz_exist = pool.look_back(baz_ip).is_some();
        let bar_exist = pool.look_back(bar_ip).is_some();

        let new_baz_ip = pool.lookup("baz.com");

        assert!(foo_exist);
        assert!(!baz_exist);
        assert!(bar_exist);

        assert_ne!(baz_ip, new_baz_ip);
    }

    #[test]
    fn test_pool_clone() {
        let ipnet: IpNet = "192.168.0.1/24".parse().unwrap();
        let pool = new(Options { ip_net: ipnet, size: 2, persistence: false }).unwrap();

        let first = pool.lookup("foo.com");
        let last = pool.lookup("bar.com");
        assert_eq!(first, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 4)));
        assert_eq!(last, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 5)));

        let new_pool = new(Options { ip_net: ipnet, size: 2, persistence: false }).unwrap();
        new_pool.clone_from(&pool);
        assert!(new_pool.look_back(first).is_some());
        assert!(new_pool.look_back(last).is_some());
    }

    #[test]
    fn cloned_pool_preserves_active_destinations_when_allocating_new_hosts() {
        let options = Options { ip_net: "192.0.2.0/24".parse().unwrap(), size: 64, persistence: false };
        let pool = new(options).unwrap();
        let hosts = ["one.example", "two.example", "three.example", "four.example"];
        let addresses = hosts.map(|host| pool.lookup(host));

        let reloaded = new(options).unwrap();
        reloaded.clone_from(&pool);
        for _ in 0..32 {
            for (host, ip) in hosts.iter().zip(addresses) {
                assert_eq!(reloaded.lookup(host), ip);
            }
        }

        for host in ["new.example", "another.example"] {
            let ip = reloaded.lookup(host);
            assert!(!addresses.contains(&ip));
            assert_eq!(reloaded.look_back(ip).as_deref(), Some(host));
        }
        for (host, ip) in hosts.iter().zip(addresses) {
            assert_eq!(reloaded.lookup(host), ip);
            assert_eq!(reloaded.look_back(ip).as_deref(), Some(*host));
        }
    }

    #[test]
    fn cloned_pool_continues_fifo_eviction_after_wrapping() {
        let options = Options { ip_net: "192.0.2.0/29".parse().unwrap(), size: 64, persistence: false };
        let pool = new(options).unwrap();
        let first = pool.lookup("one.example");
        let second = pool.lookup("two.example");
        let third = pool.lookup("three.example");
        assert_eq!(pool.lookup("four.example"), first);

        let reloaded = new(options).unwrap();
        reloaded.clone_from(&pool);
        assert_eq!(reloaded.lookup("five.example"), second);
        assert_eq!(reloaded.look_back(first).as_deref(), Some("four.example"));
        assert_eq!(reloaded.look_back(second).as_deref(), Some("five.example"));
        assert_eq!(reloaded.look_back(third).as_deref(), Some("three.example"));
        assert_eq!(reloaded.lookup("four.example"), first);
    }

    #[test]
    fn cloning_a_pool_into_itself_preserves_mappings() {
        let pool = new(Options { ip_net: "192.0.2.0/24".parse().unwrap(), size: 64, persistence: false }).unwrap();
        let ip = pool.lookup("active.example");
        pool.clone_from(&pool);
        assert_eq!(pool.lookup("active.example"), ip);
        assert_eq!(pool.look_back(ip).as_deref(), Some("active.example"));
        assert_ne!(pool.lookup("new.example"), ip);
    }

    #[test]
    fn persistent_reload_preserves_destinations_with_missing_or_stale_cursor() {
        let options = Options { ip_net: "192.0.2.0/24".parse().unwrap(), size: 64, persistence: false };
        for save_stale_cursor in [false, true] {
            let (pool, cache, tempfile) = create_cachefile_store(options).unwrap();
            let _guard = TempFileGuard(tempfile);
            let first = pool.lookup("one.example");
            if save_stale_cursor {
                pool.store_state();
            }
            let second = pool.lookup("two.example");
            let third = pool.lookup("three.example");
            let active = [("one.example", first), ("two.example", second), ("three.example", third)];

            // Reconstruct against the same cache, as config parsing does before patch_from.
            let reloaded = new(options).unwrap();
            let mut state = reloaded.state.lock();
            state.store = Store::Cachefile(new_cachefile_store(&cache, options.ip_net));
            restore_state(&options.ip_net, reloaded.first, &mut state);
            drop(state);

            for (host, ip) in active {
                assert_eq!(pool.look_back(ip).as_deref(), Some(host));
            }
            // A restart has no live pool to clone, so allocation must tolerate stale metadata.
            let restart_ip = reloaded.lookup("restart.example");
            assert!(!active.iter().any(|(_, ip)| *ip == restart_ip));
            assert_eq!(reloaded.look_back(restart_ip).as_deref(), Some("restart.example"));

            reloaded.clone_from(&pool);
            // An in-flight old DNS request may allocate after the cursor snapshot was copied.
            let late_ip = pool.lookup("late.example");
            let new_ip = reloaded.lookup("four.example");
            assert_ne!(new_ip, late_ip);
            assert_ne!(new_ip, restart_ip);
            assert_eq!(reloaded.look_back(late_ip).as_deref(), Some("late.example"));
            assert_eq!(reloaded.look_back(new_ip).as_deref(), Some("four.example"));
            for _ in 0..32 {
                for (host, ip) in active {
                    assert_eq!(reloaded.lookup(host), ip);
                    assert_eq!(reloaded.look_back(ip).as_deref(), Some(host));
                }
            }
        }
    }

    #[test]
    fn concurrent_persistent_pools_keep_both_mapping_directions() {
        let options = Options { ip_net: "192.0.2.0/24".parse().unwrap(), size: 64, persistence: false };
        let (pool, cache, tempfile) = create_cachefile_store(options).unwrap();
        let _guard = TempFileGuard(tempfile);
        let reloaded = new(options).unwrap();
        reloaded.state.lock().store = Store::Cachefile(new_cachefile_store(&cache, options.ip_net));
        reloaded.clone_from(&pool);
        let barrier = std::sync::Barrier::new(2);

        let (old_addresses, new_addresses) = std::thread::scope(|scope| {
            let old = scope.spawn(|| {
                (0..16)
                    .map(|i| {
                        barrier.wait();
                        pool.lookup(&format!("old-{i}.example"))
                    })
                    .collect::<Vec<_>>()
            });
            let new = scope.spawn(|| {
                (0..16)
                    .map(|i| {
                        barrier.wait();
                        reloaded.lookup(&format!("new-{i}.example"))
                    })
                    .collect::<Vec<_>>()
            });
            (old.join().unwrap(), new.join().unwrap())
        });

        for (prefix, addresses) in [("old", old_addresses), ("new", new_addresses)] {
            for (i, ip) in addresses.into_iter().enumerate() {
                let host = format!("{prefix}-{i}.example");
                assert_eq!(pool.lookup(&host), ip);
                assert_eq!(reloaded.lookup(&host), ip);
                assert_eq!(pool.look_back(ip).as_deref(), Some(host.as_str()));
                assert_eq!(reloaded.look_back(ip).as_deref(), Some(host.as_str()));
            }
        }
    }

    #[test]
    fn opposite_direction_clones_do_not_deadlock() {
        let options = Options { ip_net: "192.0.2.0/24".parse().unwrap(), size: 64, persistence: false };
        let a = new(options).unwrap();
        let b = new(options).unwrap();
        let ip = a.lookup("active.example");
        assert_eq!(b.lookup("active.example"), ip);
        let barrier = std::sync::Barrier::new(2);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                for _ in 0..100 {
                    a.clone_from(&b);
                }
            });
            scope.spawn(|| {
                barrier.wait();
                for _ in 0..100 {
                    b.clone_from(&a);
                }
            });
        });

        for pool in [&a, &b] {
            assert_eq!(pool.lookup("active.example"), ip);
            assert_eq!(pool.look_back(ip).as_deref(), Some("active.example"));
            assert_ne!(pool.lookup("new.example"), ip);
        }
    }

    #[test]
    fn test_pool_error() {
        let ipnet: IpNet = "192.168.0.1/31".parse().unwrap();
        assert!(new(Options { ip_net: ipnet, size: 10, persistence: false }).is_err());
    }

    #[test]
    fn test_pool_flush_file_cache() {
        let ipnet: IpNet = "192.168.0.1/28".parse().unwrap();
        let (pools, tempfile) = create_pools(Options { ip_net: ipnet, size: 10, persistence: false }).unwrap();
        let _guard = TempFileGuard(tempfile);

        for pool in &pools {
            let foo = pool.lookup("foo.com");
            let bar = pool.lookup("baz.com");
            let bax = pool.lookup("baz.com");
            let fox = pool.lookup("foo.com");

            pool.flush_fake_ip().unwrap();

            let next = pool.lookup("baz.com");
            let baz = pool.lookup("foo.com");
            let nero = pool.lookup("foo.com");

            assert_eq!(foo, fox);
            assert_eq!(foo, next);
            assert_ne!(foo, baz);
            assert_eq!(bar, bax);
            assert_eq!(bar, baz);
            assert_ne!(bar, next);
            assert_eq!(baz, nero);
        }
    }

    #[test]
    fn test_pool_flush_memory_cache() {
        let ipnet: IpNet = "192.168.0.1/28".parse().unwrap();
        let pool = new(Options { ip_net: ipnet, size: 10, persistence: false }).unwrap();

        let foo = pool.lookup("foo.com");
        let bar = pool.lookup("baz.com");
        let bax = pool.lookup("baz.com");
        let fox = pool.lookup("foo.com");

        pool.flush_fake_ip().unwrap();

        let next = pool.lookup("baz.com");
        let baz = pool.lookup("foo.com");
        let nero = pool.lookup("foo.com");

        assert_eq!(foo, fox);
        assert_eq!(foo, next);
        assert_ne!(foo, baz);
        assert_eq!(bar, bax);
        assert_eq!(bar, baz);
        assert_ne!(bar, next);
        assert_eq!(baz, nero);
    }

    #[test]
    fn test_pool_unicode_lowercase() {
        let ipnet: IpNet = "192.168.0.1/24".parse().unwrap();
        let pool = new(Options { ip_net: ipnet, size: 10, persistence: false }).unwrap();

        let lower = "ünïcödé.exämple";
        let upper = "ÜNÏCÖDÉ.EXÄMPLE";

        let from_upper = pool.lookup(upper);
        assert_eq!(pool.lookup(lower), from_upper);
        assert_eq!(pool.look_back(from_upper).as_deref(), Some(lower));
    }

    #[test]
    fn test_pool_unicode_expansion() {
        let ipnet: IpNet = "192.168.0.1/24".parse().unwrap();
        let pool = new(Options { ip_net: ipnet, size: 10, persistence: false }).unwrap();

        let expanded = "i\u{307}.example";
        let ip = pool.lookup("İ.example");
        assert_eq!(pool.lookup(expanded), ip);
        assert_eq!(pool.look_back(ip).as_deref(), Some(expanded));
    }
}
