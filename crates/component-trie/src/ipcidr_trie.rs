use std::net::IpAddr;

use anyhow::Result;
use ipnet::IpNet;

use super::ipcidr_node::{clean_child, IpCidrNode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ipv6(pub bool);

pub(crate) const IPV4_GROUP_MAX_VALUE: u32 = 0xFF;
pub(crate) const IPV6_GROUP_MAX_VALUE: u32 = 0xFFFF;

#[derive(Debug)]
pub struct IpCidrTrie {
    ipv4_trie: IpCidrNode,
    ipv6_trie: IpCidrNode,
}

impl IpCidrTrie {
    #[must_use]
    pub fn new_ip_cidr_trie() -> Self {
        Self {
            ipv4_trie: IpCidrNode::new_ip_cidr_node(false, IPV4_GROUP_MAX_VALUE),
            ipv6_trie: IpCidrNode::new_ip_cidr_node(false, IPV6_GROUP_MAX_VALUE),
        }
    }

    pub fn add_ip_cidr(&mut self, ip_cidr: &IpNet) -> Result<()> {
        let (sub_ip_cidr, sub_cidr, is_ipv4) = ip_cidr_to_sub_ip_cidr(ip_cidr);

        for sub in &sub_ip_cidr {
            add_ip_cidr(self, is_ipv4, sub, sub_cidr / 8);
        }

        Ok(())
    }

    pub fn add_ip_cidr_for_string(&mut self, ip_cidr: &str) -> Result<()> {
        let ip_net: IpNet = ip_cidr.parse()?;

        self.add_ip_cidr(&ip_net)
    }

    #[must_use]
    pub fn is_contain(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let group_values = ipv4.octets().map(u32::from);
                search(&self.ipv4_trie, &group_values).is_some()
            }
            IpAddr::V6(ipv6) => {
                let group_values = ipv6.segments().map(u32::from);
                search(&self.ipv6_trie, &group_values).is_some()
            }
        }
    }

    #[must_use]
    pub fn is_contain_for_string(&self, ip_string: &str) -> bool {
        let Ok(ip) = ip_string.parse::<IpAddr>() else {
            return false;
        };
        let actual_ip = match ip {
            IpAddr::V6(ipv6) => match ipv6.to_ipv4_mapped() {
                Some(ipv4) => IpAddr::V4(ipv4),
                None => ip,
            },
            IpAddr::V4(_) => ip,
        };
        self.is_contain(&actual_ip)
    }
}

fn ip_cidr_to_sub_ip_cidr(ip_net: &IpNet) -> (Vec<Vec<u8>>, usize, bool) {
    let mask_size = ip_net.prefix_len() as usize;
    let is_ipv4 = matches!(ip_net, IpNet::V4(_));
    let ip: Vec<u8> = match ip_net.network() {
        IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
        IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
    };
    let (ip_list, new_mask_size) = sub_ip_cidr(&ip, mask_size, is_ipv4);

    (ip_list, new_mask_size, is_ipv4)
}

fn sub_ip_cidr(ip: &[u8], mask_size: usize, is_ipv4: bool) -> (Vec<Vec<u8>>, usize) {
    let mut sub_ip_cidr_list: Vec<Vec<u8>> = Vec::new();
    let group_size = if is_ipv4 { 8 } else { 16 };

    if mask_size.is_multiple_of(group_size) {
        sub_ip_cidr_list.push(ip.to_vec());
        return (sub_ip_cidr_list, mask_size);
    }

    let last_byte_mask_size = mask_size % 8;
    let last_byte_mask_index = mask_size / 8;
    let sub_ip_cidr_num = u8::try_from(0xFFu16 >> last_byte_mask_size).unwrap_or(u8::MAX);
    for i in 0..=sub_ip_cidr_num {
        let mut sub_ip_cidr = ip.to_vec();
        if let Some(byte) = sub_ip_cidr.get_mut(last_byte_mask_index) {
            *byte = byte.wrapping_add(i);
        }
        sub_ip_cidr_list.push(sub_ip_cidr);
    }

    let new_mask_size = if is_ipv4 { (last_byte_mask_index + 1) * 8 } else { (last_byte_mask_index / 2 + 1) * 16 };

    (sub_ip_cidr_list, new_mask_size)
}

fn add_ip_cidr(trie: &mut IpCidrTrie, is_ipv4: bool, ip: &[u8], group_size: usize) {
    if is_ipv4 {
        add_ipv4_cidr(trie, ip, group_size);
    } else {
        add_ipv6_cidr(trie, ip, group_size);
    }
}

fn add_ipv4_cidr(trie: &mut IpCidrTrie, ip: &[u8], group_size: usize) {
    let Some(&first_byte) = ip.first() else {
        return;
    };
    let first_group = u32::from(first_byte);
    if trie.ipv4_trie.get_child(first_group).is_none() && trie.ipv4_trie.add_child(first_group).is_err() {
        return;
    }
    let Some(mut node) = trie.ipv4_trie.get_child_mut(first_group) else {
        return;
    };

    for i in 1..group_size {
        if node.mark {
            return;
        }

        let Some(&byte) = ip.get(i) else {
            return;
        };
        let group_value = u32::from(byte);
        if !node.has_child(group_value) {
            if let Err(err) = node.add_child(group_value) {
                murmur_log::errorln!("{err}");
            }
        }

        let Some(&previous_byte) = ip.get(i - 1) else {
            return;
        };
        let previous_group = u32::from(previous_byte);
        let child = if node.get_child(group_value).is_some() {
            group_value
        } else {
            if node.add_child(previous_group).is_err() {
                return;
            }

            previous_group
        };
        let Some(next) = node.get_child_mut(child) else {
            return;
        };
        node = next;
    }

    node.mark = true;
    clean_child(node);
}

fn add_ipv6_cidr(trie: &mut IpCidrTrie, ip: &[u8], group_size: usize) {
    let (Some(&high), Some(&low)) = (ip.first(), ip.get(1)) else {
        return;
    };
    let first_group = get_ipv6_group_value(high, low);
    if trie.ipv6_trie.get_child(first_group).is_none() && trie.ipv6_trie.add_child(first_group).is_err() {
        return;
    }
    let Some(mut node) = trie.ipv6_trie.get_child_mut(first_group) else {
        return;
    };

    let mut i = 2;
    while i < group_size {
        let (Some(&high), Some(&low)) = (ip.get(i), ip.get(i + 1)) else {
            return;
        };
        if high == 0 && low == 0 {
            node.mark = true;
        }

        if node.mark {
            return;
        }

        let group_value = get_ipv6_group_value(high, low);
        if !node.has_child(group_value) {
            if let Err(err) = node.add_child(group_value) {
                murmur_log::errorln!("{err}");
            }
        }

        let (Some(&previous_high), Some(&previous_low)) = (ip.get(i - 2), ip.get(i - 1)) else {
            return;
        };
        let previous_group = get_ipv6_group_value(previous_high, previous_low);
        let child = if node.get_child(group_value).is_some() {
            group_value
        } else {
            if node.add_child(previous_group).is_err() {
                return;
            }

            previous_group
        };
        let Some(next) = node.get_child_mut(child) else {
            return;
        };
        node = next;
        i += 2;
    }

    node.mark = true;
    clean_child(node);
}

pub(crate) fn get_ipv6_group_value(high: u8, low: u8) -> u32 {
    (u32::from(high) << 8) | u32::from(low)
}

fn search<'a>(root: &'a IpCidrNode, group_values: &[u32]) -> Option<&'a IpCidrNode> {
    let (first, rest) = group_values.split_first()?;
    let mut node = root.get_child(*first)?;
    if node.mark {
        return Some(node);
    }

    for value in rest {
        node = node.get_child(*value)?;

        if node.mark {
            return Some(node);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use ipnet::AddrParseError;

    use super::*;

    #[test]
    fn test_ipv4_add_success() {
        let mut trie = IpCidrTrie::new_ip_cidr_trie();
        assert!(trie.add_ip_cidr_for_string("10.0.0.2/16").is_ok());
    }

    #[test]
    fn test_ipv4_add_fail() {
        let mut trie = IpCidrTrie::new_ip_cidr_trie();
        let err = trie.add_ip_cidr_for_string("333.00.23.2/23").expect_err("parse error");
        assert!(err.downcast_ref::<AddrParseError>().is_some());

        let err = trie.add_ip_cidr_for_string("22.3.34.2/222").expect_err("parse error");
        assert!(err.downcast_ref::<AddrParseError>().is_some());

        let err = trie.add_ip_cidr_for_string("2.2.2.2").expect_err("parse error");
        assert!(err.downcast_ref::<AddrParseError>().is_some());
    }

    #[test]
    fn test_ipv4_search() {
        let mut trie = IpCidrTrie::new_ip_cidr_trie();
        assert!(trie.add_ip_cidr_for_string("149.154.160.0/20").is_ok());
        assert!(trie.is_contain_for_string("149.154.160.0"));
        assert!(trie.is_contain_for_string("149.154.175.255"));
        assert!(!trie.is_contain_for_string("149.154.176.0"));
        assert!(!trie.is_contain_for_string("149.154.159.255"));

        assert!(trie.add_ip_cidr_for_string("129.2.36.0/16").is_ok());
        assert!(trie.add_ip_cidr_for_string("10.2.36.0/18").is_ok());
        assert!(trie.add_ip_cidr_for_string("16.2.23.0/24").is_ok());
        assert!(trie.add_ip_cidr_for_string("11.2.13.2/26").is_ok());
        assert!(trie.add_ip_cidr_for_string("55.5.6.3/8").is_ok());
        assert!(trie.add_ip_cidr_for_string("66.23.25.4/6").is_ok());

        assert!(trie.is_contain_for_string("129.2.3.65"));
        assert!(!trie.is_contain_for_string("15.2.3.1"));
        assert!(trie.is_contain_for_string("11.2.13.1"));
        assert!(trie.is_contain_for_string("55.0.0.0"));
        assert!(trie.is_contain_for_string("64.0.0.0"));
        assert!(!trie.is_contain_for_string("128.0.0.0"));

        assert!(!trie.is_contain_for_string("22"));
        assert!(!trie.is_contain_for_string(""));
    }

    #[test]
    fn test_ipv6_add_success() {
        let mut trie = IpCidrTrie::new_ip_cidr_trie();
        assert!(trie.add_ip_cidr_for_string("2001:0db8:02de:0000:0000:0000:0000:0e13/32").is_ok());

        assert!(trie.add_ip_cidr_for_string("2001:1db8:f2de::0e13/18").is_ok());
    }

    #[test]
    fn test_ipv6_add_fail() {
        let mut trie = IpCidrTrie::new_ip_cidr_trie();
        let err = trie.add_ip_cidr_for_string("2001::25de::cade/23").expect_err("parse error");
        assert!(err.downcast_ref::<AddrParseError>().is_some());

        let err = trie.add_ip_cidr_for_string("2001:0fa3:25de::cade/222").expect_err("parse error");
        assert!(err.downcast_ref::<AddrParseError>().is_some());

        let err = trie.add_ip_cidr_for_string("2001:0fa3:25de::cade").expect_err("parse error");
        assert!(err.downcast_ref::<AddrParseError>().is_some());
    }

    #[test]
    fn test_ipv6_search_sub() {
        let mut trie = IpCidrTrie::new_ip_cidr_trie();
        assert!(trie.add_ip_cidr_for_string("240e::/18").is_ok());

        assert!(trie.is_contain_for_string("240e:964:ea02:100:1800::71"));
    }

    #[test]
    fn test_ipv6_search() {
        let mut trie = IpCidrTrie::new_ip_cidr_trie();

        assert!(trie.add_ip_cidr_for_string("2a0a:f280::/32").is_ok());
        assert!(trie.is_contain_for_string("2a0a:f280:0000:0000:0000:0000:0000:0000"));
        assert!(trie.is_contain_for_string("2a0a:f280:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert!(!trie.is_contain_for_string("2a0a:f279:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert!(!trie.is_contain_for_string("2a0a:f281:0000:0000:0000:0000:0000:0000"));

        assert!(trie.add_ip_cidr_for_string("2001:b28:f23d:f001::e/128").is_ok());
        assert!(trie.add_ip_cidr_for_string("2001:67c:4e8:f002::e/12").is_ok());
        assert!(trie.add_ip_cidr_for_string("2001:b28:f23d:f003::e/96").is_ok());
        assert!(trie.add_ip_cidr_for_string("2001:67c:4e8:f002::a/32").is_ok());
        assert!(trie.add_ip_cidr_for_string("2001:67c:4e8:f004::a/60").is_ok());
        assert!(trie.add_ip_cidr_for_string("2001:b28:f23f:f005::a/64").is_ok());

        assert!(trie.is_contain_for_string("2001:b28:f23d:f001::e"));
        assert!(!trie.is_contain_for_string("2222::fff2"));
        assert!(trie.is_contain_for_string("2000::ffa0"));
        assert!(trie.is_contain_for_string("2001:b28:f23f:f005:5662::"));
        assert!(trie.is_contain_for_string("2001:67c:4e8:9666::1213"));

        assert!(!trie.is_contain_for_string("22233:22"));
    }

    #[test]
    fn test_ipv4_in_ipv6() {
        let mut trie = IpCidrTrie::new_ip_cidr_trie();

        // An IPv4-mapped IPv6 CIDR parses as an IPv6 network (stored in the IPv6 trie), while
        // `is_contain_for_string` normalizes an IPv4-mapped IPv6 query to plain IPv4 and searches
        // the IPv4 trie instead. Neither ever crosses to the other trie; the `IpCidrTrie` has the
        // same split.
        assert!(trie.add_ip_cidr_for_string("::ffff:198.18.5.138/128").is_ok());
        assert!(!trie.is_contain_for_string("::ffff:198.18.5.138"));
        assert!(!trie.is_contain_for_string("198.18.5.138"));

        // A CIDR added in plain IPv4 form is found by an IPv4-mapped IPv6 query.
        assert!(trie.add_ip_cidr_for_string("198.18.5.0/24").is_ok());
        assert!(trie.is_contain_for_string("::ffff:198.18.5.138"));
        assert!(!trie.is_contain_for_string("::ffff:198.19.5.138"));

        // True only because of the zero-hextet early mark: the /128 insert above marked the
        // first-hextet-0 node terminal, so any unmapped ::x query is
        // contained. This still kills the `to_ipv4()` mutant: that mutant would map this address
        // to plain IPv4 and search the v4 trie instead, which does not contain it, and return
        // false.
        assert!(trie.is_contain_for_string("::192.0.2.5"));
    }

    #[test]
    fn test_ipv4_full_group_search() {
        let mut trie = IpCidrTrie::new_ip_cidr_trie();
        assert!(trie.add_ip_cidr_for_string("192.0.2.7/32").is_ok());
        let hit: IpAddr = "192.0.2.7".parse().expect("valid ipv4");
        let last_octet_miss: IpAddr = "192.0.2.8".parse().expect("valid ipv4");
        let third_octet_miss: IpAddr = "192.0.3.7".parse().expect("valid ipv4");
        let first_octet_miss: IpAddr = "193.0.2.7".parse().expect("valid ipv4");
        assert!(trie.is_contain(&hit));
        assert!(!trie.is_contain(&last_octet_miss));
        assert!(!trie.is_contain(&third_octet_miss));
        assert!(!trie.is_contain(&first_octet_miss));

        assert!(trie.add_ip_cidr_for_string("10.0.0.0/8").is_ok());
        assert!(trie.add_ip_cidr_for_string("10.1.0.0/16").is_ok());
        let narrow_prefix_hit: IpAddr = "10.1.2.3".parse().expect("valid ipv4");
        let wide_prefix_hit: IpAddr = "10.2.3.4".parse().expect("valid ipv4");
        let above_prefix_miss: IpAddr = "11.0.0.0".parse().expect("valid ipv4");
        let below_prefix_miss: IpAddr = "9.255.255.255".parse().expect("valid ipv4");
        assert!(trie.is_contain(&narrow_prefix_hit));
        assert!(trie.is_contain(&wide_prefix_hit));
        assert!(!trie.is_contain(&above_prefix_miss));
        assert!(!trie.is_contain(&below_prefix_miss));
    }

    #[test]
    fn test_ipv6_full_group_search() {
        let mut trie = IpCidrTrie::new_ip_cidr_trie();
        assert!(trie.add_ip_cidr_for_string("2001:db8:1:2:3:4:5:6/128").is_ok());
        assert!(trie.add_ip_cidr_for_string("2001:db8:1:2:3:4:5:7/128").is_ok());
        let hit: IpAddr = "2001:db8:1:2:3:4:5:6".parse().expect("valid ipv6");
        let sibling_hit: IpAddr = "2001:db8:1:2:3:4:5:7".parse().expect("valid ipv6");
        let eighth_group_miss: IpAddr = "2001:db8:1:2:3:4:5:8".parse().expect("valid ipv6");
        let seventh_group_miss: IpAddr = "2001:db8:1:2:3:4:6:6".parse().expect("valid ipv6");
        let fifth_group_miss: IpAddr = "2001:db8:1:2:9:4:5:6".parse().expect("valid ipv6");
        let first_group_miss: IpAddr = "2002:db8:1:2:3:4:5:6".parse().expect("valid ipv6");
        let unspecified_miss: IpAddr = "::".parse().expect("valid ipv6");
        assert!(trie.is_contain(&hit));
        assert!(trie.is_contain(&sibling_hit));
        assert!(!trie.is_contain(&eighth_group_miss));
        assert!(!trie.is_contain(&seventh_group_miss));
        assert!(!trie.is_contain(&fifth_group_miss));
        assert!(!trie.is_contain(&first_group_miss));
        assert!(!trie.is_contain(&unspecified_miss));
    }

    #[test]
    fn test_ipv6_prefix_group_search() {
        let mut trie = IpCidrTrie::new_ip_cidr_trie();
        assert!(trie.add_ip_cidr_for_string("2001:db8:1:2::/64").is_ok());
        let hit: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().expect("valid ipv6");
        let fourth_group_miss: IpAddr = "2001:db8:1:3::1".parse().expect("valid ipv6");
        let second_group_miss: IpAddr = "2001:db9:1:2::1".parse().expect("valid ipv6");
        assert!(trie.is_contain(&hit));
        assert!(!trie.is_contain(&fourth_group_miss));
        assert!(!trie.is_contain(&second_group_miss));
    }
}
