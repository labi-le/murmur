use std::io::Read;

use anyhow::{anyhow, Result};

use super::provider::{err_invalid_format, RuleStrategy};

/// `MrsMagicBytes` (`MRSv1`).
pub const MRS_MAGIC_BYTES: [u8; 4] = [b'M', b'R', b'S', 1];

pub(crate) fn rules_mrs_parse(buf: &[u8], mut strategy: Box<dyn RuleStrategy>) -> Result<Box<dyn RuleStrategy>> {
    if strategy.as_mrs_mut().is_none() {
        return Err(err_invalid_format());
    }

    let mut reader = zstd::Decoder::new(buf)?;

    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    if header != MRS_MAGIC_BYTES {
        return Err(anyhow!("invalid MrsMagic bytes"));
    }

    let mut behavior_byte = [0u8; 1];
    reader.read_exact(&mut behavior_byte)?;
    if behavior_byte[0] != strategy.behavior().byte() {
        return Err(anyhow!("invalid behavior"));
    }

    let mut count_bytes = [0u8; 8];
    reader.read_exact(&mut count_bytes)?;
    let count = i32::try_from(i64::from_be_bytes(count_bytes)).map_err(|_| anyhow!("count is invalid"))?;

    let mut length_bytes = [0u8; 8];
    reader.read_exact(&mut length_bytes)?;
    let extra_len = u64::try_from(i64::from_be_bytes(length_bytes)).map_err(|_| anyhow!("length is invalid"))?;
    if extra_len > 0 {
        let copied = std::io::copy(&mut reader.by_ref().take(extra_len), &mut std::io::sink())?;
        if copied != extra_len {
            return Err(anyhow!("extra is truncated"));
        }
    }

    let Some(mrs) = strategy.as_mrs_mut() else {
        return Err(err_invalid_format());
    };
    mrs.load_mrs(&mut reader, count)?;
    Ok(strategy)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use murmur_constant::provider::interface::RuleBehavior;

    use super::*;
    use crate::provider::provider::new_strategy;

    /// One range in the body of an `ipcidr` payload.
    fn ipcidr_body() -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.push(1);
        body.extend_from_slice(&1i64.to_be_bytes());
        for addr in [Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)] {
            body.extend_from_slice(&addr.to_ipv6_mapped().octets());
        }
        body
    }

    /// `MRSv1 | behavior | count | extra_len | extra | body`; `extra_len` may disagree with `extra`,
    /// which is how a malformed payload declares a field it does not carry.
    fn mrs_payload_with_body(count: i64, extra_len: i64, extra: &[u8], body: &[u8]) -> Vec<u8> {
        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(&MRS_MAGIC_BYTES);
        raw.push(RuleBehavior::IPCIDR.byte());
        raw.extend_from_slice(&count.to_be_bytes());
        raw.extend_from_slice(&extra_len.to_be_bytes());
        raw.extend_from_slice(extra);
        raw.extend_from_slice(body);
        zstd::encode_all(raw.as_slice(), 0).expect("zstd encode")
    }

    fn mrs_payload(count: i64, extra_len: i64, extra: &[u8]) -> Vec<u8> {
        mrs_payload_with_body(count, extra_len, extra, &ipcidr_body())
    }

    fn parse(payload: &[u8]) -> Result<Box<dyn RuleStrategy>> {
        let strategy = new_strategy(RuleBehavior::IPCIDR, None).expect("ipcidr strategy");
        rules_mrs_parse(payload, strategy)
    }

    #[test]
    fn a_well_formed_payload_loads_its_rule_set() {
        let strategy = parse(&mrs_payload(1, 0, &[])).expect("valid payload");

        assert_eq!(strategy.count(), 1);
        assert!(strategy.to_ip_cidr().is_some_and(|set| set.is_contain_for_string("10.0.0.7")));
    }

    #[test]
    fn a_declared_extra_field_is_skipped_before_the_rule_set() {
        let strategy = parse(&mrs_payload(1, 4, b"note")).expect("valid payload");

        assert_eq!(strategy.count(), 1);
        assert!(strategy.to_ip_cidr().is_some_and(|set| set.is_contain_for_string("10.0.0.7")));
    }

    #[test]
    fn an_extra_length_past_the_stream_is_rejected() {
        let payload = mrs_payload(1, 1i64 << 40, &[]);

        let err = parse(&payload).err().expect("extra past the stream");

        assert!(err.to_string().contains("extra is truncated"), "{err}");
    }

    #[test]
    fn a_rule_count_past_the_i32_range_is_rejected() {
        let payload = mrs_payload(i64::from(i32::MAX) + 1, 0, &[]);

        let err = parse(&payload).err().expect("rule count past the i32 range");

        assert!(err.to_string().contains("count is invalid"), "{err}");
    }

    #[test]
    fn a_payload_whose_rule_set_declares_no_range_is_rejected() {
        let mut body: Vec<u8> = Vec::new();
        body.push(1);
        body.extend_from_slice(&0i64.to_be_bytes());

        let err = parse(&mrs_payload_with_body(1, 0, &[], &body)).err().expect("empty range set");

        assert!(err.to_string().contains("length is invalid"), "{err}");
    }
}
