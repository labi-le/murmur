//! Exports functions from the tunnel module.

use murmur_tunnel::dns_dialer;

pub const RESPECT_RULES: &str = dns_dialer::DNS_RESPECT_RULES;

pub(crate) type DnsDialer = dns_dialer::DNSDialer;
