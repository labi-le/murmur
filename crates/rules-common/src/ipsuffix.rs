use std::borrow::Cow;
use std::net::IpAddr;

use anyhow::Result;
use ipnet::IpNet;

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

use super::base::{err_payload, Base};

fn ip_as_slice(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

#[derive(Debug)]
pub struct IPSuffix {
    base: Base,
    ip_bytes: Vec<u8>,
    bits: usize,
    payload: String,
    adapter: String,
    is_source_ip: bool,
    no_resolve_ip: bool,
}

impl Rule for IPSuffix {
    fn rule_type(&self) -> RuleType {
        if self.is_source_ip {
            RuleType::SRC_IP_SUFFIX
        } else {
            RuleType::IP_SUFFIX
        }
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        if !self.no_resolve_ip && !self.is_source_ip {
            if let Some(f) = &helper.resolve_ip {
                f(metadata);
            }
        }

        let ip = if self.is_source_ip { metadata.src_ip } else { metadata.dst_ip };
        let m_ip_bytes = ip.map(ip_as_slice).unwrap_or_default();
        if self.ip_bytes.len() != m_ip_bytes.len() {
            return (false, Cow::Borrowed(""));
        }

        let size = m_ip_bytes.len();
        let bits = self.bits;

        let full_bytes = bits / 8;
        let keep = size - full_bytes;
        let (Some(rule_tail), Some(dst_tail)) = (self.ip_bytes.get(keep..), m_ip_bytes.get(keep..)) else {
            return (false, Cow::Borrowed(""));
        };
        if rule_tail != dst_tail {
            return (false, Cow::Borrowed(""));
        }

        if !bits.is_multiple_of(8) {
            let idx = keep - 1;
            let shift = 8 - bits % 8;
            let (Some(&rule_byte), Some(&dst_byte)) = (self.ip_bytes.get(idx), m_ip_bytes.get(idx)) else {
                return (false, Cow::Borrowed(""));
            };
            if (rule_byte << shift) != (dst_byte << shift) {
                return (false, Cow::Borrowed(""));
            }
        }

        (true, Cow::Borrowed(self.adapter.as_str()))
    }

    fn adapter(&self) -> String {
        self.adapter.clone()
    }

    fn payload(&self) -> String {
        self.payload.clone()
    }

    fn provider_names(&self) -> Vec<String> {
        self.base.provider_names()
    }
}

impl IPSuffix {
    pub fn new(payload: &str, adapter: &str, is_src: bool, no_resolve_ip: bool) -> Result<Self> {
        let ipnet: IpNet = payload.parse().map_err(|_| err_payload())?;

        Ok(Self {
            base: Base,
            payload: payload.to_owned(),
            ip_bytes: ip_as_slice(ipnet.addr()),
            bits: usize::from(ipnet.prefix_len()),
            adapter: adapter.to_owned(),
            is_source_ip: is_src,
            no_resolve_ip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(cidr: &str, dst: &str) -> bool {
        let rule = IPSuffix::new(cidr, "OUT", false, true).unwrap();
        let mut metadata = Metadata { dst_ip: Some(dst.parse().unwrap()), ..Default::default() };
        rule.match_(&mut metadata, &RuleMatchHelper::default()).0
    }

    #[test]
    fn whole_byte_suffix_matches_last_byte_only() {
        assert!(matches("0.0.0.4/8", "1.2.3.4"));
        assert!(!matches("0.0.0.4/8", "1.2.3.5"));
    }

    #[test]
    fn partial_byte_suffix_matches_low_bits_of_leading_byte() {
        // 30 bits: the full last three bytes plus the low 6 bits of the first byte.
        assert!(matches("0.0.0.4/30", "64.0.0.4"));
        assert!(!matches("0.0.0.4/30", "65.0.0.4"));
        assert!(!matches("0.0.0.4/30", "64.0.0.5"));
    }

    #[test]
    fn zero_bit_suffix_always_matches_same_family() {
        assert!(matches("0.0.0.0/0", "255.255.255.255"));
    }

    #[test]
    fn mismatched_address_family_never_matches() {
        assert!(!matches("0.0.0.4/8", "::1"));
    }
}
