//! Capabilities: a signed delegation chain that grants its final custodian a
//! rule set beyond the network's own rules.

use crate::address::{controller, Address, ADDRESS_SIZE};
use crate::identity::{Identity, SIGNATURE_SIZE};
use crate::rules::NetworkRule;

/// The protocol limit for capabilities in one network configuration.
pub const MAX_NETWORK_CAPABILITIES: usize = 128;
/// The maximum number of rules in one capability.
pub const MAX_CAPABILITY_RULES: usize = 64;
/// The maximum supported custody-chain length.
pub const MAX_CAPABILITY_CUSTODY: u8 = 7;

/// Reports a malformed or unverifiable capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ZeroTier capability")]
pub struct InvalidCapability;

/// One signed delegation link in a capability chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityCustody {
    pub to: Address,
    pub from: Address,
    pub signature: [u8; SIGNATURE_SIZE],
}

/// Grants its final custodian a signed set of network rules.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capability {
    pub network_id: u64,
    pub timestamp: u64,
    pub id: u32,
    pub rules: Vec<NetworkRule>,
    pub max_custody_chain_length: u8,
    pub custody: Vec<CapabilityCustody>,
    /// The exact bytes this capability was decoded from.
    raw: Vec<u8>,
}

impl Capability {
    /// Decodes one capability, reporting bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), InvalidCapability> {
        if data.len() < 23 {
            return Err(InvalidCapability);
        }
        let network_id = read_u64(data, 0);
        let timestamp = read_u64(data, 8);
        let id = u32::from_be_bytes(read_array::<4>(data, 16)?);
        let rule_count = usize::from(u16::from_be_bytes(read_array::<2>(data, 20)?));
        if rule_count > MAX_CAPABILITY_RULES {
            return Err(InvalidCapability);
        }
        let mut rules = Vec::with_capacity(rule_count);
        let mut pos = 22;
        for _ in 0..rule_count {
            if data.len() - pos < 2 {
                return Err(InvalidCapability);
            }
            let [rule_type, field_length] = read_array::<2>(data, pos)?;
            let field_length = usize::from(field_length);
            if data.len() - pos - 2 < field_length {
                return Err(InvalidCapability);
            }
            let value = data.get(pos + 2..pos + 2 + field_length).ok_or(InvalidCapability)?.to_vec();
            rules.push(NetworkRule { rule_type, value });
            pos += 2 + field_length;
        }
        if data.len() - pos < 1 {
            return Err(InvalidCapability);
        }
        let max_custody_chain_length = *data.get(pos).ok_or(InvalidCapability)?;
        pos += 1;
        if !(1..=MAX_CAPABILITY_CUSTODY).contains(&max_custody_chain_length) {
            return Err(InvalidCapability);
        }
        let mut custody = Vec::new();
        // The chain is terminated by a zero `to` address rather than by a count.
        loop {
            if data.len() - pos < ADDRESS_SIZE {
                return Err(InvalidCapability);
            }
            let to = Address::from_bytes(&read_array::<ADDRESS_SIZE>(data, pos)?).map_err(|_| InvalidCapability)?;
            pos += ADDRESS_SIZE;
            if to.is_zero() {
                break;
            }
            if custody.len() >= usize::from(max_custody_chain_length)
                || data.len() - pos < ADDRESS_SIZE + 3 + SIGNATURE_SIZE
            {
                return Err(InvalidCapability);
            }
            let from = Address::from_bytes(&read_array::<ADDRESS_SIZE>(data, pos)?).map_err(|_| InvalidCapability)?;
            if from.is_zero() {
                return Err(InvalidCapability);
            }
            pos += ADDRESS_SIZE;
            let [tag, length_high, length_low] = read_array::<3>(data, pos)?;
            if tag != 1 || usize::from(u16::from_be_bytes([length_high, length_low])) != SIGNATURE_SIZE {
                return Err(InvalidCapability);
            }
            pos += 3;
            let mut signature = [0u8; SIGNATURE_SIZE];
            signature.copy_from_slice(&read_array::<SIGNATURE_SIZE>(data, pos)?);
            pos += SIGNATURE_SIZE;
            custody.push(CapabilityCustody { to, from, signature });
        }
        if data.len() - pos < 2 {
            return Err(InvalidCapability);
        }
        let extension_length = usize::from(u16::from_be_bytes(read_array::<2>(data, pos)?));
        pos += 2;
        if data.len() - pos < extension_length {
            return Err(InvalidCapability);
        }
        pos += extension_length;
        Ok((
            Self {
                network_id,
                timestamp,
                id,
                rules,
                max_custody_chain_length,
                custody,
                raw: data.get(..pos).ok_or(InvalidCapability)?.to_vec(),
            },
            pos,
        ))
    }

    /// The final custodian, or the zero address for an empty chain.
    #[must_use]
    pub fn issued_to(&self) -> Address {
        self.custody.last().map_or_else(|| Address::new(0), |custody| custody.to)
    }

    /// Authenticates the complete custody chain with `identity_for`.
    pub fn verify(&self, identity_for: impl Fn(Address) -> Option<Identity>) -> bool {
        self.verify_chain(identity_for).1
    }

    /// Authenticates custody and reports the first missing signer identity.
    pub fn verify_chain(&self, identity_for: impl Fn(Address) -> Option<Identity>) -> (Address, bool) {
        if self.max_custody_chain_length < 1
            || self.max_custody_chain_length > MAX_CAPABILITY_CUSTODY
            || self.custody.is_empty()
            || self.custody.len() > usize::from(self.max_custody_chain_length)
        {
            return (Address::new(0), false);
        }
        let Ok(signed_data) = self.signed_data() else {
            return (Address::new(0), false);
        };
        for (index, custody) in self.custody.iter().enumerate() {
            let expected_from = if index == 0 {
                controller(self.network_id)
            } else {
                let Some(previous) = self.custody.get(index - 1) else {
                    return (Address::new(0), false);
                };
                previous.to
            };
            if custody.from != expected_from {
                return (Address::new(0), false);
            }
            let Some(identity) = identity_for(custody.from) else {
                return (custody.from, false);
            };
            if !identity.verify(&signed_data, &custody.signature) {
                return (Address::new(0), false);
            }
        }
        (Address::new(0), true)
    }

    /// The protocol bytes authenticated by each custodian.
    pub fn signed_data(&self) -> Result<Vec<u8>, InvalidCapability> {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&0x7f7f_7f7f_7f7f_7f7fu64.to_be_bytes());
        data = append_capability_base(data, self)?;
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0x7f7f_7f7f_7f7f_7f7fu64.to_be_bytes());
        Ok(data)
    }

    /// Appends the complete wire encoding of this capability to `data`.
    pub fn append_binary(&self, mut data: Vec<u8>) -> Result<Vec<u8>, InvalidCapability> {
        if !self.raw.is_empty() {
            data.extend_from_slice(&self.raw);
            return Ok(data);
        }
        data = append_capability_base(data, self)?;
        let signature_length = u16::try_from(SIGNATURE_SIZE).map_err(|_| InvalidCapability)?;
        for custody in &self.custody {
            data.extend_from_slice(&custody.to.bytes());
            data.extend_from_slice(&custody.from.bytes());
            data.push(1);
            data.extend_from_slice(&signature_length.to_be_bytes());
            data.extend_from_slice(&custody.signature);
        }
        data.extend_from_slice(&[0u8; ADDRESS_SIZE]);
        data.extend_from_slice(&0u16.to_be_bytes());
        Ok(data)
    }

    /// The capability's own wire encoding, as decoded.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
}

/// Serializes the unsigned fixed fields and rule list.
fn append_capability_base(mut data: Vec<u8>, capability: &Capability) -> Result<Vec<u8>, InvalidCapability> {
    if capability.rules.len() > MAX_CAPABILITY_RULES {
        return Err(InvalidCapability);
    }
    let rule_count = u16::try_from(capability.rules.len()).map_err(|_| InvalidCapability)?;
    data.extend_from_slice(&capability.network_id.to_be_bytes());
    data.extend_from_slice(&capability.timestamp.to_be_bytes());
    data.extend_from_slice(&capability.id.to_be_bytes());
    data.extend_from_slice(&rule_count.to_be_bytes());
    for rule in &capability.rules {
        data.push(rule.rule_type);
        data.push(u8::try_from(rule.value.len()).map_err(|_| InvalidCapability)?);
        data.extend_from_slice(&rule.value);
    }
    data.push(capability.max_custody_chain_length);
    Ok(data)
}

fn read_array<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], InvalidCapability> {
    data.get(offset..offset + N).ok_or(InvalidCapability)?.try_into().map_err(|_| InvalidCapability)
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    read_array::<8>(data, offset).map_or(0, u64::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::{append_dictionary_entry, append_dictionary_uint};
    use crate::network_config::parse_network_config;
    use crate::rules::{RULE_ACTION_ACCEPT, RULE_MATCH_IP_PROTOCOL};

    /// Builds the two-link chain a controller issues through a holder, the way
    /// both signers authenticate the same capability bytes.
    fn chain(controller_identity: &Identity, holder: &Identity, recipient: &Identity, network_id: u64) -> Capability {
        let mut capability = Capability {
            network_id,
            timestamp: 1000,
            id: 5,
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_IP_PROTOCOL, value: vec![6] },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
            ],
            max_custody_chain_length: 2,
            custody: Vec::new(),
            raw: Vec::new(),
        };
        let signed = capability.signed_data().expect("the capability encodes");
        capability.custody = vec![
            CapabilityCustody {
                from: controller_identity.address(),
                to: holder.address(),
                signature: controller_identity.sign(&signed).expect("controller signs"),
            },
            CapabilityCustody {
                from: holder.address(),
                to: recipient.address(),
                signature: holder.sign(&signed).expect("holder signs"),
            },
        ];
        capability
    }

    #[test]
    fn custody_chain_round_trips_and_verifies() {
        let controller_identity = Identity::generate();
        let holder = Identity::generate();
        let recipient = Identity::generate();
        let network_id = controller_identity.address().uint64() << 24 | 0x1234;
        let capability = chain(&controller_identity, &holder, &recipient, network_id);

        let encoded = capability.append_binary(Vec::new()).expect("the capability encodes");
        let (parsed, consumed) = Capability::parse(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        let identities =
            [(controller_identity.address(), controller_identity.clone()), (holder.address(), holder.clone())];
        let identity_for = |address: Address| {
            identities.iter().find(|(known, _)| *known == address).map(|(_, identity)| identity.clone())
        };
        assert_eq!(parsed.issued_to(), recipient.address());
        assert!(parsed.verify(identity_for));
        assert_eq!(parsed.bytes(), &encoded[..]);

        let mut broken = parsed.clone();
        broken.custody[1].from = controller_identity.address();
        assert!(!broken.verify(identity_for));
    }

    #[test]
    fn a_missing_signer_is_reported_without_accepting_the_chain() {
        let controller_identity = Identity::generate();
        let holder = Identity::generate();
        let recipient = Identity::generate();
        let network_id = controller_identity.address().uint64() << 24 | 0x1234;
        let mut capability = chain(&controller_identity, &holder, &recipient, network_id);
        capability.raw.clear();
        let (parsed, _) =
            Capability::parse(&capability.append_binary(Vec::new()).expect("the capability encodes")).unwrap();

        let identity_for =
            |address: Address| (address == controller_identity.address()).then(|| controller_identity.clone());
        assert_eq!(parsed.verify_chain(identity_for), (holder.address(), false));
    }

    #[test]
    fn a_chain_whose_first_custodian_is_not_the_controller_fails() {
        let controller_identity = Identity::generate();
        let impostor = Identity::generate();
        let recipient = Identity::generate();
        let network_id = controller_identity.address().uint64() << 24 | 0x1234;
        let mut capability = chain(&controller_identity, &impostor, &recipient, network_id);
        // Re-sign the first link, which only moves the failure to the network's
        // controller address rather than the signature.
        capability.custody[0].from = impostor.address();
        let signed = capability.signed_data().expect("the capability encodes");
        capability.custody[0].signature = impostor.sign(&signed).expect("impostor signs");

        let (parsed, _) =
            Capability::parse(&capability.append_binary(Vec::new()).expect("the capability encodes")).unwrap();
        let identities = [(impostor.address(), impostor.clone()), (recipient.address(), recipient.clone())];
        let identity_for = |address: Address| {
            identities.iter().find(|(known, _)| *known == address).map(|(_, identity)| identity.clone())
        };
        assert!(!parsed.verify(identity_for));
    }

    #[test]
    fn rejects_malformed_structures() {
        assert_eq!(Capability::parse(&[]), Err(InvalidCapability));
        assert_eq!(Capability::parse(&[0u8; 22]), Err(InvalidCapability));

        let controller_identity = Identity::generate();
        let network_id = controller_identity.address().uint64() << 24 | 0x1234;
        let encoded = chain(&controller_identity, &Identity::generate(), &Identity::generate(), network_id)
            .append_binary(Vec::new())
            .expect("the capability encodes");

        let mut too_many_rules = encoded.clone();
        too_many_rules[20..22].copy_from_slice(&((MAX_CAPABILITY_RULES + 1) as u16).to_be_bytes());
        assert_eq!(Capability::parse(&too_many_rules), Err(InvalidCapability));

        // The rule list is 22 fixed bytes plus 3 and 2 bytes of fixture rules.
        const CUSTODY_LIMIT_OFFSET: usize = 27;
        let mut zero_custody_limit = encoded.clone();
        zero_custody_limit[CUSTODY_LIMIT_OFFSET] = 0;
        assert_eq!(Capability::parse(&zero_custody_limit), Err(InvalidCapability));

        let mut long_custody_limit = encoded.clone();
        long_custody_limit[CUSTODY_LIMIT_OFFSET] = MAX_CAPABILITY_CUSTODY + 1;
        assert_eq!(Capability::parse(&long_custody_limit), Err(InvalidCapability));

        let mut custody_over_limit = encoded.clone();
        custody_over_limit[CUSTODY_LIMIT_OFFSET] = 1;
        assert_eq!(Capability::parse(&custody_over_limit), Err(InvalidCapability));

        let mut truncated = encoded.clone();
        truncated.truncate(encoded.len() - 1);
        assert_eq!(Capability::parse(&truncated), Err(InvalidCapability));
    }

    /// A rule value the length byte cannot carry must be refused, not truncated.
    #[test]
    fn a_rule_value_longer_than_a_u8_is_refused_by_the_encoder() {
        let capability = Capability {
            max_custody_chain_length: 1,
            rules: vec![NetworkRule { rule_type: RULE_MATCH_IP_PROTOCOL, value: vec![0u8; 256] }],
            ..Default::default()
        };

        assert_eq!(capability.append_binary(Vec::new()), Err(InvalidCapability));
    }

    /// A rule count beyond the protocol's limit must be refused too.
    #[test]
    fn more_rules_than_the_protocol_allows_are_refused_by_the_encoder() {
        let capability = Capability {
            max_custody_chain_length: 1,
            rules: vec![NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() }; MAX_CAPABILITY_RULES + 1],
            ..Default::default()
        };

        assert_eq!(capability.append_binary(Vec::new()), Err(InvalidCapability));
    }

    #[test]
    fn a_network_config_retains_and_verifies_its_capability() {
        let controller_identity = Identity::generate();
        let holder = Identity::generate();
        let recipient = Identity::generate();
        let network_id = controller_identity.address().uint64() << 24 | 0x1234;
        let capability = chain(&controller_identity, &holder, &recipient, network_id);
        let encoded = capability.append_binary(Vec::new()).expect("the capability encodes");

        let dictionary = append_dictionary_uint(Vec::new(), "nwid", network_id).unwrap();
        let dictionary = append_dictionary_uint(dictionary, "v", 7).unwrap();
        let dictionary = append_dictionary_uint(dictionary, "id", recipient.address().uint64()).unwrap();
        let dictionary = append_dictionary_uint(dictionary, "t", 1).unwrap();
        let dictionary = append_dictionary_entry(dictionary, "CAP", &encoded).unwrap();

        let config = parse_network_config(&dictionary).unwrap();
        let identities =
            [(controller_identity.address(), controller_identity.clone()), (holder.address(), holder.clone())];
        let identity_for = |address: Address| {
            identities.iter().find(|(known, _)| *known == address).map(|(_, identity)| identity.clone())
        };
        assert_eq!(config.capabilities.len(), 1);
        assert!(config.capabilities[0].verify(identity_for));
    }
}
