use std::net::IpAddr;

pub trait DomainMatcher: Send + Sync {
    fn match_domain(&self, domain: &str) -> bool;
}

/// `IpMatcher`. An address has no crate mirror type, so it is a `std::net::IpAddr`.
pub trait IpMatcher: Send + Sync {
    fn match_ip(&self, ip: IpAddr) -> bool;
}
