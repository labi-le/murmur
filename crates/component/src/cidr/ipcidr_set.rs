//! An address-range set with no crate equivalent, implemented inline here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};
use ipnet::IpNet;

/// An inclusive range of addresses of a single family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpRange {
    pub(crate) from: IpAddr,
    pub(crate) to: IpAddr,
}

/// Builds an inclusive address range.
#[must_use]
pub const fn ip_range_from(from: IpAddr, to: IpAddr) -> IpRange {
    IpRange { from, to }
}

/// The address range covered by a prefix.
#[must_use]
pub fn range_of_prefix(p: &IpNet) -> IpRange {
    ip_range_from(p.network(), p.broadcast())
}

fn bit_len(ip: IpAddr) -> u32 {
    match unmap_addr(ip) {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Unmaps a 4-in-6 address to its IPv4 form.
pub(crate) use crate::resolver::host::unmap_addr;

/// The address as 16 bytes, IPv4 mapped into IPv6.
pub(crate) const fn addr_as16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Builds an address from 16 bytes, unmapping a 4-in-6 form.
pub(crate) fn addr_from16_unmap(a16: [u8; 16]) -> IpAddr {
    unmap_addr(IpAddr::V6(Ipv6Addr::from(a16)))
}

/// Parses an address, dropping any zone suffix.
fn parse_addr(s: &str) -> Result<IpAddr, std::net::AddrParseError> {
    let addr = match s.split_once('%') {
        Some((addr, _)) => addr,
        None => s,
    };
    addr.parse::<IpAddr>()
}

/// The next address; `None` on overflow.
fn addr_next(ip: IpAddr) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(v4) => u32::from(v4).checked_add(1).map(|n| IpAddr::V4(Ipv4Addr::from(n))),
        IpAddr::V6(v6) => {
            u128::from_be_bytes(v6.octets()).checked_add(1).map(|n| IpAddr::V6(Ipv6Addr::from(n.to_be_bytes())))
        }
    }
}

impl IpRange {
    #[must_use]
    pub const fn from(&self) -> IpAddr {
        self.from
    }

    #[must_use]
    pub const fn to(&self) -> IpAddr {
        self.to
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        bit_len(self.from) == bit_len(self.to) && (self.to >= self.from)
    }

    /// No address zones exist here, so only the validity check and the range check remain.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.is_valid() && self.contains_unchecked(addr)
    }

    /// Unchecked range containment, so named because the public `contains` maps to the same
    /// snake-case spelling. Address comparison unmaps IPv4-mapped IPv6 addresses.
    fn contains_unchecked(&self, addr: IpAddr) -> bool {
        let addr = unmap_addr(addr);
        self.from <= addr && self.to >= addr
    }

    fn less(&self, other: &Self) -> bool {
        match self.from.cmp(&other.from) {
            std::cmp::Ordering::Equal => other.to < self.to,
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
        }
    }

    #[must_use]
    pub fn prefixes(&self) -> Vec<IpNet> {
        if !self.is_valid() {
            return Vec::new();
        }
        let mut dst = Vec::new();
        let is_v4 = self.from.is_ipv4();
        append_range_prefixes(
            &mut dst,
            is_v4,
            u128::from_be_bytes(addr_as16(self.from)),
            u128::from_be_bytes(addr_as16(self.to)),
        );
        dst
    }
}

/// The topmost `n` bits of a 128-bit number.
const fn mask6(n: u8) -> u128 {
    if n == 0 {
        0
    } else if n >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - n)
    }
}

/// Appends the prefixes covering `a`..`b`; `is_v4` selects the 32-bit form.
fn append_range_prefixes(dst: &mut Vec<IpNet>, is_v4: bool, a: u128, b: u128) {
    let (common, whole_range) = compare_prefixes(a, b);
    if whole_range {
        dst.push(prefix_from_128_and_bits(is_v4, a, common));
        return;
    }
    append_range_prefixes(dst, is_v4, a, a | !mask6(common + 1));
    append_range_prefixes(dst, is_v4, b & mask6(common + 1), b);
}

/// The shared prefix length of `a` and `b`, and whether `a` ends in zero bits and `b` in one bits
/// right after it.
fn compare_prefixes(a: u128, b: u128) -> (u8, bool) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "`leading_zeros` of a `u128` is at most 128, which fits in a byte"
    )]
    let common = (a ^ b).leading_zeros() as u8;
    if common == 128 {
        return (common, true);
    }
    let m = mask6(common);
    (common, (a ^ (a & m)) == 0 && (b | m) == u128::MAX)
}

/// Builds a prefix from a 128-bit base and a bit length; a v4 range carries the 96-bit
/// IPv6-mapped prefix already subtracted by the caller.
fn prefix_from_128_and_bits(is_v4: bool, a: u128, bits: u8) -> IpNet {
    if is_v4 {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a v4 prefix carries the address in the low 32 bits, the 96-bit mapped prefix being already subtracted"
        )]
        let v4 = Ipv4Addr::from(a as u32);
        IpNet::new_assert(IpAddr::V4(v4), bits - 12 * 8)
    } else {
        IpNet::new_assert(IpAddr::V6(Ipv6Addr::from(a)), bits)
    }
}

/// Whether two ranges, one ending at `a_to` and the next starting at `b_from`, overlap or are
/// adjacent, and therefore cover one contiguous range.
fn ranges_touch(a_to: IpAddr, b_from: IpAddr) -> bool {
    match addr_next(a_to) {
        Some(next) => b_from <= next,
        None => b_from <= a_to,
    }
}

/// Sorts `rr` in place and yields the minimal sorted set of ranges, or
/// `None` when an invalid range is met.
pub(crate) fn merge_ip_ranges(rr: &mut [IpRange]) -> Option<Vec<IpRange>> {
    if rr.is_empty() {
        return Some(Vec::new());
    }

    rr.sort_by(|a, b| {
        if a.less(b) {
            std::cmp::Ordering::Less
        } else if b.less(a) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
    let mut out: Vec<IpRange> = Vec::with_capacity(rr.len());
    let mut ranges = rr.iter();
    let Some(first) = ranges.next() else {
        return Some(Vec::new());
    };
    let mut current = *first;
    for r in ranges {
        if !r.is_valid() {
            return None;
        }
        if addr_next(current.to) == Some(r.from) {
            current.to = r.to;
        } else if current.to < r.from {
            out.push(current);
            current = *r;
        } else if current.to < r.to {
            current.to = r.to;
        }
    }
    out.push(current);
    Some(out)
}

/// `IpSet` and `IpCidrSet` are the same type here, since their layouts are identical.
pub type IpSet = IpCidrSet;

#[derive(Clone, Debug)]
pub struct IpCidrSet {
    /// The ranges, kept sorted and disjoint.
    pub(crate) rr: Vec<IpRange>,
}

impl IpCidrSet {
    #[must_use]
    pub const fn new_ip_cidr_set() -> Self {
        Self { rr: Vec::new() }
    }

    pub fn add_ip_cidr_for_string(&mut self, ip_cidr: &str) -> Result<()> {
        let prefix = ip_cidr.parse::<IpNet>()?;
        self.add_ip_cidr(prefix)
    }

    pub fn add_ip_cidr(&mut self, ip_cidr: IpNet) -> Result<()> {
        let r = range_of_prefix(&ip_cidr);
        if r.is_valid() {
            self.insert_range(r);
            Ok(())
        } else {
            Err(anyhow!("not valid ipcidr range: {ip_cidr}"))
        }
    }

    /// Inserts `r` in sorted position, absorbing every range it touches, so `rr` keeps the shape
    /// `contains` binary-searches.
    fn insert_range(&mut self, r: IpRange) {
        let mut from = r.from;
        let mut to = r.to;
        let pos = self.rr.partition_point(|existing| existing.from < r.from);
        let mut start = pos;
        while start > 0 {
            let Some(prev) = self.rr.get(start - 1) else {
                break;
            };
            if !ranges_touch(prev.to, from) {
                break;
            }
            from = prev.from;
            to = to.max(prev.to);
            start -= 1;
        }
        let mut end = pos;
        while end < self.rr.len() {
            let Some(next) = self.rr.get(end) else {
                break;
            };
            if !ranges_touch(to, next.from) {
                break;
            }
            to = to.max(next.to);
            end += 1;
        }
        self.rr.drain(start..end);
        self.rr.insert(start, ip_range_from(from, to));
    }

    #[must_use]
    pub fn is_contain_for_string(&self, ip_string: &str) -> bool {
        match parse_addr(ip_string) {
            Ok(ip) => self.is_contain(ip),
            Err(_) => false,
        }
    }

    /// Address zones do not participate: the comparison is on the bare address.
    #[must_use]
    pub fn is_contain(&self, ip: IpAddr) -> bool {
        self.to_ip_set().contains(ip)
    }

    #[must_use]
    pub fn match_ip(&self, ip: IpAddr) -> bool {
        if self.is_empty() {
            return false;
        }
        self.is_contain(ip)
    }

    pub fn merge(&mut self) -> Result<()> {
        let mut b = IpSetBuilder::new();
        b.add_set(self.to_ip_set());
        let i = b.ip_set()?;
        *self = Self::from_ip_set(i);
        Ok(())
    }

    /// An absent receiver has no Rust counterpart here, so there is nothing else to check.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rr.is_empty()
    }

    pub fn foreach<F: FnMut(IpNet) -> bool>(&self, mut f: F) {
        for r in &self.rr {
            for prefix in r.prefixes() {
                if !f(prefix) {
                    return;
                }
            }
        }
    }

    /// The cast is the identity here.
    #[must_use]
    pub const fn to_ip_set(&self) -> &Self {
        self
    }

    /// Replaces the receiver's contents; the caller assigns the value.
    const fn from_ip_set(i: Self) -> Self {
        i
    }

    /// Whether the set contains the address.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = unmap_addr(ip);
        let mut lo = 0usize;
        let mut hi = self.rr.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let Some(range) = self.rr.get(mid) else {
                return false;
            };
            if ip < range.from {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        if lo == 0 {
            return false;
        }
        let Some(range) = self.rr.get(lo - 1) else {
            return false;
        };
        range.contains_unchecked(ip)
    }
}

/// The subset of the range-set builder that `IpCidrSet::merge` reaches.
struct IpSetBuilder {
    in_: Vec<IpRange>,
    errs: Vec<String>,
}

impl IpSetBuilder {
    const fn new() -> Self {
        Self { in_: Vec::new(), errs: Vec::new() }
    }

    fn add_set(&mut self, b: &IpSet) {
        for r in &b.rr {
            self.add_range(*r);
        }
    }

    fn add_range(&mut self, r: IpRange) {
        if r.is_valid() {
            self.in_.push(r);
        } else {
            self.errs.push(format!("AddRange({}-{})", r.from(), r.to()));
        }
    }

    fn ip_set(&mut self) -> Result<IpSet> {
        self.normalize();
        let ret = IpCidrSet { rr: self.in_.clone() };
        if self.errs.is_empty() {
            Ok(ret)
        } else {
            let errs = std::mem::take(&mut self.errs);
            Err(anyhow!("{}", errs.join("; ")))
        }
    }

    fn normalize(&mut self) {
        if let Some(merged) = merge_ip_ranges(&mut self.in_) {
            self.in_ = merged;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4() {
        let tests = [
            ("Test Case 1", "149.154.160.0/20", "149.154.160.0", true),
            ("Test Case 2", "192.168.0.0/16", "10.0.0.1", false),
        ];

        for (name, ip_cidr, ip, expected) in tests {
            let mut set = IpCidrSet::new_ip_cidr_set();
            let _ = set.add_ip_cidr_for_string(ip_cidr);

            assert_eq!(set.is_contain_for_string(ip), expected, "{name}");
        }
    }

    #[test]
    fn test_ipv6() {
        let tests = [
            ("Test Case 1", "2409:8000::/20", "2409:8087:1e03:21::27", true),
            ("Test Case 2", "240e::/16", "240e:964:ea02:100:1800::71", true),
        ];

        for (name, ip_cidr, ip, expected) in tests {
            let mut set = IpCidrSet::new_ip_cidr_set();
            let _ = set.add_ip_cidr_for_string(ip_cidr);

            assert_eq!(set.is_contain_for_string(ip), expected, "{name}");
        }
    }

    #[test]
    fn test_merge() {
        let tests = [("Test Case 1", "2409:8000::/20", "2409:8000::/21", "2409:8000::/48", 1)];

        for (name, ip_cidr1, ip_cidr2, _ip_cidr3, expected_len) in tests {
            let mut set = IpCidrSet::new_ip_cidr_set();
            let _ = set.add_ip_cidr_for_string(ip_cidr1);
            let _ = set.add_ip_cidr_for_string(ip_cidr2);
            let _ = set.merge();

            assert_eq!(set.rr.len(), expected_len, "{name}");
        }
    }

    #[test]
    fn ranges_added_in_descending_order_still_contain_their_addresses() {
        let mut set = IpCidrSet::new_ip_cidr_set();
        set.add_ip_cidr_for_string("192.168.0.0/16").expect("valid cidr");
        set.add_ip_cidr_for_string("10.0.0.0/8").expect("valid cidr");

        assert!(set.is_contain_for_string("192.168.1.1"));
        assert!(set.is_contain_for_string("10.1.2.3"));
        assert!(!set.is_contain_for_string("172.16.0.1"));
    }

    #[test]
    fn a_contained_prefix_leaves_the_whole_of_the_larger_range_matching() {
        let mut set = IpCidrSet::new_ip_cidr_set();
        set.add_ip_cidr_for_string("10.0.0.0/23").expect("valid cidr");
        set.add_ip_cidr_for_string("10.0.0.128/25").expect("valid cidr");

        assert!(set.is_contain_for_string("10.0.1.0"));
        assert!(set.is_contain_for_string("10.0.0.200"));
        assert!(!set.is_contain_for_string("10.0.2.0"));
    }

    #[test]
    fn ranges_stay_sorted_and_disjoint_across_families_and_addresses() {
        let mut set = IpCidrSet::new_ip_cidr_set();
        set.add_ip_cidr_for_string("2001:db8::/32").expect("valid cidr");
        set.add_ip_cidr_for_string("10.0.0.0/8").expect("valid cidr");
        set.add_ip_cidr_for_string("2409:8000::/20").expect("valid cidr");
        set.add_ip_cidr_for_string("192.168.0.0/16").expect("valid cidr");
        set.add_ip_cidr_for_string("10.128.0.0/9").expect("valid cidr");

        assert!(set.is_contain_for_string("10.1.2.3"));
        assert!(set.is_contain_for_string("10.200.0.1"));
        assert!(set.is_contain_for_string("192.168.255.255"));
        assert!(set.is_contain_for_string("2001:db8::1"));
        assert!(set.is_contain_for_string("2409:8087:1e03:21::27"));
        assert!(!set.is_contain_for_string("11.0.0.1"));
        assert!(!set.is_contain_for_string("2001:db9::1"));

        assert!(set.rr.iter().all(IpRange::is_valid));
        assert!(set.rr.windows(2).all(|w| w[0].to < w[1].from));
    }
}
