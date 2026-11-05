use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;

use murmur_common::lru::{new as new_lru, with_size, LruCache};
use murmur_component::resolver::enhancer::Enhancer;
use murmur_component_fakeip::pool::Pool;
use murmur_component_fakeip::skipper::Skipper;
use murmur_constant::dns::DNSMode;

pub struct ResolverEnhancer {
    pub(crate) ipv6: bool,
    pub(crate) mode: DNSMode,
    pub(crate) fake_ip_pool: Option<Arc<Pool>>,
    pub(crate) fake_ip_pool6: Option<Arc<Pool>>,
    pub(crate) fake_ip_skipper: Option<Arc<Skipper>>,
    pub(crate) fake_ip_ttl: i32,
    pub(crate) mapping: Option<Arc<LruCache<IpAddr, String>>>,
    pub(crate) use_hosts: bool,
}

impl std::fmt::Debug for ResolverEnhancer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolverEnhancer")
            .field("mode", &self.mode)
            .field("ipv6", &self.ipv6)
            .field("use_hosts", &self.use_hosts)
            .field("fake_ip_ttl", &self.fake_ip_ttl)
            .finish_non_exhaustive()
    }
}

impl ResolverEnhancer {
    #[must_use]
    pub fn fake_ip_enabled(&self) -> bool {
        self.mode == DNSMode::DNS_FAKE_IP
    }

    pub(crate) fn mapping_enabled(&self) -> bool {
        self.mode == DNSMode::DNS_FAKE_IP || self.mode == DNSMode::DNS_MAPPING
    }

    #[must_use]
    pub fn is_exist_fake_ip(&self, ip: IpAddr) -> bool {
        if !self.fake_ip_enabled() {
            return false;
        }

        if let Some(pool) = &self.fake_ip_pool {
            if pool.exist(ip) {
                return true;
            }
        }

        if let Some(pool6) = &self.fake_ip_pool6 {
            if pool6.exist(ip) {
                return true;
            }
        }

        false
    }

    #[must_use]
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        if !self.fake_ip_enabled() {
            return false;
        }

        if let Some(pool) = &self.fake_ip_pool {
            if pool.ip_net().contains(&ip) && ip != pool.gateway() && ip != pool.broadcast() {
                return true;
            }
        }

        if let Some(pool6) = &self.fake_ip_pool6 {
            if pool6.ip_net().contains(&ip) && ip != pool6.gateway() && ip != pool6.broadcast() {
                return true;
            }
        }

        false
    }

    #[must_use]
    pub fn is_fake_broadcast_ip(&self, ip: IpAddr) -> bool {
        if !self.fake_ip_enabled() {
            return false;
        }

        if let Some(pool) = &self.fake_ip_pool {
            if pool.broadcast() == ip {
                return true;
            }
        }

        if let Some(pool6) = &self.fake_ip_pool6 {
            if pool6.broadcast() == ip {
                return true;
            }
        }

        false
    }

    #[must_use]
    pub fn find_host_by_ip(&self, ip: IpAddr) -> Option<String> {
        if let Some(pool) = &self.fake_ip_pool {
            if let Some(host) = pool.look_back(ip) {
                return Some(host);
            }
        }

        if let Some(pool6) = &self.fake_ip_pool6 {
            if let Some(host) = pool6.look_back(ip) {
                return Some(host);
            }
        }

        if let Some(mapping) = &self.mapping {
            let (host, existed) = mapping.get(&ip);
            if existed {
                return Some(host);
            }
        }

        None
    }

    pub fn insert_host_by_ip(&self, ip: IpAddr, host: &str) {
        if let Some(mapping) = &self.mapping {
            mapping.set(ip, host.to_owned());
        }
    }

    pub fn flush_fake_ip(&self) -> Result<()> {
        let mut errs = Vec::new();
        if let Some(pool) = &self.fake_ip_pool {
            if let Err(err) = pool.flush_fake_ip() {
                errs.push(err);
            }
        }
        if let Some(pool6) = &self.fake_ip_pool6 {
            if let Err(err) = pool6.flush_fake_ip() {
                errs.push(err);
            }
        }
        if !errs.is_empty() {
            return Err(anyhow::anyhow!(errs.into_iter().map(|err| err.to_string()).collect::<Vec<_>>().join("\n")));
        }
        Ok(())
    }

    pub fn patch_from(&self, o: &Self) {
        if let (Some(mapping), Some(o_mapping)) = (&self.mapping, &o.mapping) {
            o_mapping.clone_to(mapping.as_ref());
        }

        if let (Some(pool), Some(o_pool)) = (&self.fake_ip_pool, &o.fake_ip_pool) {
            Pool::clone_from(pool, o_pool);
        }

        if let (Some(pool6), Some(o_pool6)) = (&self.fake_ip_pool6, &o.fake_ip_pool6) {
            Pool::clone_from(pool6, o_pool6);
        }
    }

    pub fn store_fake_pool_state(&self) {
        if let Some(pool) = &self.fake_ip_pool {
            pool.store_state();
        }
        if let Some(pool6) = &self.fake_ip_pool6 {
            pool6.store_state();
        }
    }
}

impl Enhancer for ResolverEnhancer {
    fn fake_ip_enabled(&self) -> bool {
        Self::fake_ip_enabled(self)
    }

    fn mapping_enabled(&self) -> bool {
        Self::mapping_enabled(self)
    }

    fn is_fake_ip(&self, ip: IpAddr) -> bool {
        Self::is_fake_ip(self, ip)
    }

    fn is_fake_broadcast_ip(&self, ip: IpAddr) -> bool {
        Self::is_fake_broadcast_ip(self, ip)
    }

    fn is_exist_fake_ip(&self, ip: IpAddr) -> bool {
        Self::is_exist_fake_ip(self, ip)
    }

    fn find_host_by_ip(&self, ip: IpAddr) -> Option<String> {
        Self::find_host_by_ip(self, ip)
    }

    fn flush_fake_ip(&self) -> Result<()> {
        Self::flush_fake_ip(self)
    }

    fn insert_host_by_ip(&self, ip: IpAddr, host: &str) {
        Self::insert_host_by_ip(self, ip, host);
    }

    fn store_fake_pool_state(&self) {
        Self::store_fake_pool_state(self);
    }
}

#[derive(Default)]
pub struct EnhancerConfig {
    pub ipv6: bool,
    pub enhanced_mode: DNSMode,
    pub fake_ip_pool: Option<Arc<Pool>>,
    pub fake_ip_pool6: Option<Arc<Pool>>,
    pub fake_ip_skipper: Option<Arc<Skipper>>,
    pub fake_ip_ttl: i32,
    pub use_hosts: bool,
}

impl std::fmt::Debug for EnhancerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnhancerConfig")
            .field("enhanced_mode", &self.enhanced_mode)
            .field("ipv6", &self.ipv6)
            .field("use_hosts", &self.use_hosts)
            .field("fake_ip_ttl", &self.fake_ip_ttl)
            .finish_non_exhaustive()
    }
}

impl ResolverEnhancer {
    #[must_use]
    pub fn new(cfg: EnhancerConfig) -> Self {
        let mut e = Self {
            ipv6: cfg.ipv6,
            mode: cfg.enhanced_mode,
            fake_ip_pool: None,
            fake_ip_pool6: None,
            fake_ip_skipper: None,
            fake_ip_ttl: 0,
            mapping: None,
            use_hosts: cfg.use_hosts,
        };

        if cfg.enhanced_mode != DNSMode::DNS_NORMAL {
            e.fake_ip_pool = cfg.fake_ip_pool;
            if cfg.ipv6 {
                e.fake_ip_pool6 = cfg.fake_ip_pool6;
            }
            e.fake_ip_skipper = cfg.fake_ip_skipper;
            e.fake_ip_ttl = cfg.fake_ip_ttl.max(1);
            e.mapping = Some(Arc::new(new_lru(vec![with_size(4096)])));
        }

        e
    }
}
