//! Network rules: the ordered match-and-action stream a controller installs on
//! a network, plus the capability-scoped rules a member may be granted.
//!
//! [`NetworkConfigData::filter_frame`] is the engine that turns a frame plus the
//! peer credentials gathered by the node into a forwarding decision; the
//! ordering rules around BREAK, TEE/WATCH/REDIRECT, the guarded DROP and the
//! NOT/OR flags are all observable protocol behaviour.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rand::RngCore;

use crate::address::{Address, ADDRESS_SIZE};
use crate::capability::Capability;
use crate::frame::{Frame, ETHER_TYPE_ARP, ETHER_TYPE_IPV4, ETHER_TYPE_IPV6};
use crate::mac::Mac;
use crate::network_config::NetworkConfigData;
use crate::ownership::CertificateOfOwnership;
use crate::tag::Tag;

/// The protocol limit for rules in one network configuration.
pub const MAX_NETWORK_RULES: usize = 1024;

/// Rejects the frame when the current rule set matches.
pub const RULE_ACTION_DROP: u8 = 0;
/// Permits the frame when the current rule set matches.
pub const RULE_ACTION_ACCEPT: u8 = 1;
/// Copies the frame to another network member.
pub const RULE_ACTION_TEE: u8 = 2;
/// Copies the frame without changing its destination.
pub const RULE_ACTION_WATCH: u8 = 3;
/// Replaces the frame's ZeroTier destination.
pub const RULE_ACTION_REDIRECT: u8 = 4;
/// Ends the current rule set without a final decision.
pub const RULE_ACTION_BREAK: u8 = 5;
/// Assigns a QoS bucket to the frame.
pub const RULE_ACTION_PRIORITY: u8 = 6;
/// The highest type code reserved for rule actions.
pub const RULE_ACTION_MAX: u8 = 15;

/// Matches the source ZeroTier address.
pub const RULE_MATCH_SOURCE_ZT_ADDRESS: u8 = 24;
/// Matches the destination ZeroTier address.
pub const RULE_MATCH_DEST_ZT_ADDRESS: u8 = 25;
/// Matches the frame's VLAN identifier.
pub const RULE_MATCH_VLAN_ID: u8 = 26;
/// Matches the frame's VLAN priority code point.
pub const RULE_MATCH_VLAN_PCP: u8 = 27;
/// Matches the frame's VLAN drop-eligible indicator.
pub const RULE_MATCH_VLAN_DEI: u8 = 28;
/// Matches the source virtual MAC address.
pub const RULE_MATCH_MAC_SOURCE: u8 = 29;
/// Matches the destination virtual MAC address.
pub const RULE_MATCH_MAC_DEST: u8 = 30;
/// Matches the source IPv4 prefix.
pub const RULE_MATCH_IPV4_SOURCE: u8 = 31;
/// Matches the destination IPv4 prefix.
pub const RULE_MATCH_IPV4_DEST: u8 = 32;
/// Matches the source IPv6 prefix.
pub const RULE_MATCH_IPV6_SOURCE: u8 = 33;
/// Matches the destination IPv6 prefix.
pub const RULE_MATCH_IPV6_DEST: u8 = 34;
/// Matches an IP traffic-class or type-of-service value.
pub const RULE_MATCH_IP_TOS: u8 = 35;
/// Matches an IP protocol or next-header value.
pub const RULE_MATCH_IP_PROTOCOL: u8 = 36;
/// Matches an Ethernet protocol type.
pub const RULE_MATCH_ETHER_TYPE: u8 = 37;
/// Matches an ICMP type, code, and flags tuple.
pub const RULE_MATCH_ICMP: u8 = 38;
/// Matches a transport source-port range.
pub const RULE_MATCH_IP_SOURCE_PORT: u8 = 39;
/// Matches a transport destination-port range.
pub const RULE_MATCH_IP_DEST_PORT: u8 = 40;
/// Matches frame characteristic flags.
pub const RULE_MATCH_CHARACTERISTICS: u8 = 41;
/// Matches the serialized frame-size range.
pub const RULE_MATCH_FRAME_SIZE: u8 = 42;
/// Applies a probabilistic match threshold.
pub const RULE_MATCH_RANDOM: u8 = 43;
/// Compares the absolute difference of tag values.
pub const RULE_MATCH_TAGS_DIFFERENCE: u8 = 44;
/// Compares the bitwise AND of tag values.
pub const RULE_MATCH_TAGS_BITWISE_AND: u8 = 45;
/// Compares the bitwise OR of tag values.
pub const RULE_MATCH_TAGS_BITWISE_OR: u8 = 46;
/// Compares the bitwise XOR of tag values.
pub const RULE_MATCH_TAGS_BITWISE_XOR: u8 = 47;
/// Matches when both the sender's and the receiver's tag values equal the rule's value.
pub const RULE_MATCH_TAGS_EQUAL: u8 = 48;
/// Compares the sender's tag value with a fixed value.
pub const RULE_MATCH_TAG_SENDER: u8 = 49;
/// Compares the receiver's tag value with a fixed value.
pub const RULE_MATCH_TAG_RECEIVER: u8 = 50;
/// Compares a tag value with an inclusive range.
pub const RULE_MATCH_INTEGER_RANGE: u8 = 51;

/// Joins a match to the following match as an alternative.
pub const RULE_FLAG_OR: u8 = 0x40;
/// Inverts a match result.
pub const RULE_FLAG_NOT: u8 = 0x80;

/// Marks a frame received from another member.
pub const CHARACTERISTIC_INBOUND: u64 = 0x8000_0000_0000_0000;
/// Marks a multicast destination.
pub const CHARACTERISTIC_MULTICAST: u64 = 0x4000_0000_0000_0000;
/// Marks the Ethernet broadcast destination.
pub const CHARACTERISTIC_BROADCAST: u64 = 0x2000_0000_0000_0000;
/// Marks a frame whose IP ownership is authenticated.
pub const CHARACTERISTIC_IP_AUTH: u64 = 0x1000_0000_0000_0000;
/// Marks a frame whose MAC ownership is authenticated.
pub const CHARACTERISTIC_MAC_AUTH: u64 = 0x0800_0000_0000_0000;

/// Reports a malformed network rule stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ZeroTier network rule stream")]
pub struct InvalidRule;

/// One action or match entry in a network rule stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRule {
    pub rule_type: u8,
    pub value: Vec<u8>,
}

/// The peer credentials and direction supplied to rule evaluation.
///
/// `super_accept` is scratch state: evaluation raises it for the duration of one
/// rule sequence once an inbound rule addresses the local member, and later
/// rules in that sequence observe it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameRuleContext {
    pub inbound: bool,
    pub trace_rules: bool,
    pub source_zt: Address,
    pub destination_zt: Address,
    pub ownership: Vec<CertificateOfOwnership>,
    pub local_tags: Vec<Tag>,
    pub remote_tags: Vec<Tag>,
    pub capabilities: Vec<Capability>,
    pub super_accept: bool,
}

/// The terminal decision produced by a rule set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RuleResult {
    /// Evaluation continues in a following rule set or default policy.
    #[default]
    NoMatch,
    /// The frame is rejected.
    Drop,
    /// The frame is permitted.
    Accept,
}

/// One additional tee or watch destination selected by a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTeeDecision {
    pub target: Address,
    pub length: usize,
    pub watch: bool,
}

/// The terminal and side-effect results accumulated from rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRuleDecision {
    pub result: RuleResult,
    pub super_accept: bool,
    pub tee: Address,
    pub tee_length: usize,
    pub watch: bool,
    pub additional_tee: Vec<RuleTeeDecision>,
    pub redirect: Address,
    /// Parsed for wire parity. ZeroTier One's `Network::qosEnabled` returns
    /// false, so its AQM scheduler never consumes this value.
    pub qos_bucket: u8,
    pub rule_log: Vec<u8>,
    pub capability_rule_log: Vec<u8>,
    pub matching_capability_id: u32,
    pub matching_capability: bool,
}
impl Default for FrameRuleDecision {
    /// Every field at its reference zero value. Written out rather than derived so that adding a
    /// field to `FrameRuleDecision` cannot default silently: this impl stops compiling until the new field is
    /// named here (RUST_GUIDELINES.md section 3, functional-update struct literals).
    fn default() -> Self {
        Self {
            result: <RuleResult as Default>::default(),
            super_accept: <bool as Default>::default(),
            tee: <Address as Default>::default(),
            tee_length: <usize as Default>::default(),
            watch: <bool as Default>::default(),
            additional_tee: <Vec<RuleTeeDecision> as Default>::default(),
            redirect: <Address as Default>::default(),
            qos_bucket: <u8 as Default>::default(),
            rule_log: <Vec<u8> as Default>::default(),
            capability_rule_log: <Vec<u8> as Default>::default(),
            matching_capability_id: <u32 as Default>::default(),
            matching_capability: <bool as Default>::default(),
        }
    }
}

/// Copies the leading `N` bytes of a rule operand; short operands read as zero.
fn fixed_bytes<const N: usize>(bytes: &[u8]) -> [u8; N] {
    // `[u8; N]` has no `Default` impl, so the zeroed fallback is written out.
    bytes.get(..N).and_then(|head| head.try_into().ok()).unwrap_or([0u8; N])
}

/// Mutable state threaded through one rule sequence.
struct RuleSetState {
    set_matches: bool,
    skip_drop: bool,
    decision: FrameRuleDecision,
}

/// Decodes the length-prefixed network rule stream.
pub fn parse_network_rules(data: &[u8]) -> Result<Vec<NetworkRule>, InvalidRule> {
    let mut rules = Vec::with_capacity(16);
    let mut pos = 0;
    while pos < data.len() {
        if rules.len() >= MAX_NETWORK_RULES {
            break;
        }
        let window = data.get(pos..).ok_or(InvalidRule)?;
        let [rule_type, field_length, rest @ ..] = window else {
            return Err(InvalidRule);
        };
        let field_length = usize::from(*field_length);
        let value = rest.get(..field_length).ok_or(InvalidRule)?;
        rules.push(NetworkRule { rule_type: *rule_type, value: value.to_vec() });
        pos += 2 + field_length;
    }
    Ok(rules)
}

/// Decodes a tee, watch, or redirect action operand into its target and length.
#[must_use]
pub fn parse_rule_forward(value: &[u8]) -> Option<(Address, usize)> {
    if value.len() != 14 {
        return None;
    }
    let [address @ .., _, _, _, _, low, high] = value else {
        return None;
    };
    let target = Address::new(u64::from_be_bytes(address.try_into().ok()?));
    if target.is_reserved() {
        return None;
    }
    Some((target, usize::from(u16::from_be_bytes([*low, *high]))))
}

/// The `EXT_FRAME` flags a rule-generated copy of a frame carries.
#[must_use]
pub fn rule_forward_flags(inbound: bool, watch: bool) -> u8 {
    match (inbound, watch) {
        (false, false) => 0x02,
        (true, false) => 0x08,
        (false, true) => 0x16,
        (true, true) => 0x1c,
    }
}

/// The `EXT_FRAME` flags a rule-generated redirect carries.
#[must_use]
pub fn rule_redirect_flags(inbound: bool) -> u8 {
    if inbound {
        0x0a
    } else {
        0x04
    }
}

/// Serializes the `EXT_FRAME` body a tee, watch, or redirect emits.
///
/// A rule length of zero, or one past the end of the payload, forwards the whole
/// payload. A redirect ignores the length operand and passes zero.
#[must_use]
pub fn rule_forward_payload(frame: &Frame, flags: u8, payload_length: usize) -> Vec<u8> {
    let length =
        if payload_length == 0 || payload_length > frame.payload.len() { frame.payload.len() } else { payload_length };
    let mut out = Vec::with_capacity(23 + length);
    out.extend_from_slice(&frame.network_id.to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&frame.destination.bytes());
    out.extend_from_slice(&frame.source.bytes());
    out.extend_from_slice(&frame.ether_type.to_be_bytes());
    out.extend_from_slice(frame.payload.get(..length).unwrap_or_default());
    out
}

/// Evaluates one binary integer operand against the frame payload.
///
/// The format byte carries the bit width in its low six bits and the byte order
/// in its top bit; the big-endian form (bit 7 clear) right-aligns the window in
/// the eight bytes after the index, the little-endian form reads it at the index.
#[must_use]
pub fn match_integer_range(value: &[u8], payload: &[u8]) -> bool {
    if value.len() != 19 {
        return false;
    }
    let Some((start_bytes, rest)) = value.split_at_checked(8) else {
        return false;
    };
    let Some((end_bytes, rest)) = rest.split_at_checked(8) else {
        return false;
    };
    let Some((index_bytes, format_byte)) = rest.split_at_checked(2) else {
        return false;
    };
    let [index_high, index_low] = index_bytes else {
        return false;
    };
    let Some(&format) = format_byte.first() else {
        return false;
    };
    let start = u64::from_be_bytes(start_bytes.try_into().unwrap_or_default());
    let end_operand = u64::from_be_bytes(end_bytes.try_into().unwrap_or_default());
    let span = end_operand.wrapping_sub(start) & 0xffff_ffff;
    let end = start.wrapping_add(span);
    let bits = usize::from(format & 63) + 1;
    let bytes = bits.div_ceil(8);
    let mut index = usize::from(u16::from_be_bytes([*index_high, *index_low]));
    if format & 0x80 == 0 {
        index += 8 - bytes;
    }
    let mut integer = 0u64;
    if let Some(window) = payload.get(index..index + bytes) {
        if format & 0x80 == 0 {
            for byte in window {
                integer = (integer << 8) | u64::from(*byte);
            }
        } else {
            for byte in window.iter().rev() {
                integer = (integer << 8) | u64::from(*byte);
            }
        }
    }
    if bits < 64 {
        integer &= (1u64 << bits) - 1;
    }
    integer >= start && integer <= end
}

/// Whether the frame carries an ICMPv6 neighbor solicitation.
#[must_use]
pub fn ipv6_neighbor_solicitation(frame: &Frame) -> bool {
    frame.ether_type == ETHER_TYPE_IPV6
        && frame.payload.len() >= 64
        && frame.payload.get(6) == Some(&58)
        && frame.payload.get(40) == Some(&135)
}

impl NetworkConfigData {
    /// Reports the terminal result of network and capability rules.
    #[must_use]
    pub fn allows_frame(&self, frame: &Frame, context: FrameRuleContext) -> bool {
        self.filter_frame(frame, context).result == RuleResult::Accept
    }

    /// Applies the network's own rules before any delegated capability rules.
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "crate API: the rule context is a caller-owned value, as the reference's matcher takes it"
    )]
    pub fn filter_frame(&self, frame: &Frame, mut context: FrameRuleContext) -> FrameRuleDecision {
        // Evaluation only mutates `super_accept`, so one context serves every rule set; the
        // capability list moves out because the loop needs it borrowed while the context is mutable.
        let capabilities = std::mem::take(&mut context.capabilities);
        let super_accept = context.super_accept;
        let mut decision = self.evaluate_rules(&self.rules, frame, &mut context);
        if decision.result != RuleResult::NoMatch {
            return decision;
        }
        for capability in &capabilities {
            if context.inbound
                && absolute_difference(capability.timestamp, self.timestamp) > self.credential_time_max_delta
            {
                continue;
            }
            context.super_accept = super_accept;
            let mut capability_decision = self.evaluate_rules(&capability.rules, frame, &mut context);
            if capability_decision.result == RuleResult::Accept {
                capability_decision.capability_rule_log = std::mem::take(&mut capability_decision.rule_log);
                capability_decision.rule_log = std::mem::take(&mut decision.rule_log);
                capability_decision.matching_capability_id = capability.id;
                capability_decision.matching_capability = true;
                if !decision.tee.is_zero() {
                    if !capability_decision.tee.is_zero() {
                        capability_decision.additional_tee.push(RuleTeeDecision {
                            target: capability_decision.tee,
                            length: capability_decision.tee_length,
                            watch: capability_decision.watch,
                        });
                    }
                    capability_decision.tee = decision.tee;
                    capability_decision.tee_length = decision.tee_length;
                    capability_decision.watch = decision.watch;
                }
                let mut additional = std::mem::take(&mut decision.additional_tee);
                additional.append(&mut capability_decision.additional_tee);
                capability_decision.additional_tee = additional;
                return capability_decision;
            }
        }
        FrameRuleDecision { result: RuleResult::Drop, rule_log: decision.rule_log, ..Default::default() }
    }

    /// Evaluates one rule sequence, accumulating its terminal and side effects.
    fn evaluate_rules(
        &self,
        rules: &[NetworkRule],
        frame: &Frame,
        context: &mut FrameRuleContext,
    ) -> FrameRuleDecision {
        let mut state = RuleSetState { set_matches: true, skip_drop: false, decision: FrameRuleDecision::default() };
        if context.trace_rules {
            state.decision.rule_log = vec![0u8; MAX_NETWORK_RULES / 2];
        }
        let local_address = if context.inbound { context.destination_zt } else { context.source_zt };
        for (rule_index, rule) in rules.iter().enumerate() {
            let rule_type = rule.rule_type & 0x3f;
            if rule_type <= RULE_ACTION_MAX {
                if Self::apply_action_rule(rule, rule_type, local_address, context, &mut state) {
                    return state.decision;
                }
                continue;
            }
            if !state.set_matches && rule.rule_type & RULE_FLAG_OR == 0 {
                log_skipped_rule(&mut state.decision.rule_log, rule_index, state.set_matches);
                continue;
            }
            let mut matched = self.rule_matches(rule, frame, context);
            log_evaluated_rule(&mut state.decision.rule_log, rule_index, matched, state.set_matches);
            if rule.rule_type & RULE_FLAG_NOT != 0 {
                matched = !matched;
            }
            if rule.rule_type & RULE_FLAG_OR != 0 {
                state.set_matches = state.set_matches || matched;
            } else {
                state.set_matches = state.set_matches && matched;
            }
            if matched && self.rule_match_skips_drop(rule, context) {
                state.skip_drop = true;
            }
        }
        state.decision
    }

    /// Applies one action rule, reporting whether the rule set terminates.
    fn apply_action_rule(
        rule: &NetworkRule,
        rule_type: u8,
        local_address: Address,
        context: &mut FrameRuleContext,
        state: &mut RuleSetState,
    ) -> bool {
        if !state.set_matches {
            let forwards =
                rule_type == RULE_ACTION_TEE || rule_type == RULE_ACTION_WATCH || rule_type == RULE_ACTION_REDIRECT;
            if context.inbound && forwards {
                if let Some((target, _)) = parse_rule_forward(&rule.value) {
                    if target == local_address {
                        state.decision.super_accept = true;
                        context.super_accept = true;
                    }
                }
            }
            state.set_matches = true;
            return false;
        }
        match rule_type {
            RULE_ACTION_DROP => {
                if state.skip_drop {
                    state.skip_drop = false;
                    return false;
                }
                state.decision.result = RuleResult::Drop;
                true
            }
            RULE_ACTION_BREAK => {
                state.decision.result = RuleResult::NoMatch;
                true
            }
            RULE_ACTION_ACCEPT => {
                state.decision.result = RuleResult::Accept;
                true
            }
            RULE_ACTION_PRIORITY => {
                if let Some(bucket) = rule.value.first().copied().filter(|bucket| *bucket <= 8) {
                    state.decision.qos_bucket = bucket;
                }
                state.decision.result = RuleResult::Accept;
                true
            }
            RULE_ACTION_TEE | RULE_ACTION_WATCH | RULE_ACTION_REDIRECT => {
                let Some((target, length)) = parse_rule_forward(&rule.value) else {
                    return false;
                };
                if target == context.source_zt {
                    return false;
                }
                if target == local_address {
                    if context.inbound {
                        state.decision.super_accept = true;
                        context.super_accept = true;
                        state.decision.result = RuleResult::Accept;
                        return true;
                    }
                    return false;
                }
                if target == context.destination_zt {
                    return false;
                }
                if rule_type == RULE_ACTION_REDIRECT {
                    state.decision.redirect = target;
                    state.decision.result = RuleResult::Accept;
                    return true;
                }
                state.decision.tee = target;
                state.decision.tee_length = length;
                state.decision.watch = rule_type == RULE_ACTION_WATCH;
                false
            }
            _ => false,
        }
    }

    /// Whether a matched rule preserves outbound compatibility for a tag the
    /// remote member has not published yet, instead of arming the next DROP.
    fn rule_match_skips_drop(&self, rule: &NetworkRule, context: &FrameRuleContext) -> bool {
        let rule_type = rule.rule_type & 0x3f;
        if context.super_accept {
            return (RULE_MATCH_TAGS_DIFFERENCE..=RULE_MATCH_TAG_RECEIVER).contains(&rule_type);
        }
        if rule.value.len() != 8 {
            return false;
        }
        let id = u32::from_be_bytes(fixed_bytes::<4>(&rule.value));
        match rule_type {
            RULE_MATCH_TAGS_DIFFERENCE
            | RULE_MATCH_TAGS_BITWISE_AND
            | RULE_MATCH_TAGS_BITWISE_OR
            | RULE_MATCH_TAGS_BITWISE_XOR
            | RULE_MATCH_TAGS_EQUAL => {
                let local_known = find_tag(&context.local_tags, id, self, false).is_some();
                let remote_known = find_tag(&context.remote_tags, id, self, true).is_some();
                local_known && !remote_known && !context.inbound
            }
            RULE_MATCH_TAG_RECEIVER => {
                let remote_known = find_tag(&context.remote_tags, id, self, true).is_some();
                !context.inbound && !remote_known
            }
            _ => false,
        }
    }

    /// Evaluates one match rule against the frame and context.
    ///
    /// A rule that does not apply returns the NOT flag's value, which is why a
    /// "hard yes" branch can disagree with the surrounding flag handling.
    fn rule_matches(&self, rule: &NetworkRule, frame: &Frame, context: &FrameRuleContext) -> bool {
        let rule_type = rule.rule_type & 0x3f;
        let not = rule.rule_type & RULE_FLAG_NOT != 0;
        let not_applicable = not;
        let value = &rule.value;
        let payload = &frame.payload;
        match rule_type {
            RULE_MATCH_SOURCE_ZT_ADDRESS | RULE_MATCH_DEST_ZT_ADDRESS => {
                Self::match_zt_address(rule_type, value, context, not_applicable)
            }
            RULE_MATCH_VLAN_ID => value.len() == 2 && fixed_bytes::<2>(value) == [0u8; 2],
            RULE_MATCH_VLAN_PCP | RULE_MATCH_VLAN_DEI => value.len() == 1 && value.first() == Some(&0),
            RULE_MATCH_MAC_SOURCE | RULE_MATCH_MAC_DEST => {
                Self::match_mac_address(rule_type, value, frame, not_applicable)
            }
            RULE_MATCH_IPV4_SOURCE | RULE_MATCH_IPV4_DEST => {
                Self::match_ipv4_prefix(rule_type, value, frame, payload, not_applicable)
            }
            RULE_MATCH_IPV6_SOURCE | RULE_MATCH_IPV6_DEST => {
                Self::match_ipv6_prefix(rule_type, value, frame, payload, not_applicable)
            }
            RULE_MATCH_IP_TOS => Self::match_ip_tos(value, frame, payload, not_applicable),
            RULE_MATCH_IP_PROTOCOL => Self::match_ip_protocol(value, frame, payload, not_applicable),
            RULE_MATCH_ETHER_TYPE => {
                value.len() == 2 && u16::from_be_bytes(fixed_bytes::<2>(value)) == frame.ether_type
            }
            RULE_MATCH_ICMP => Self::match_icmp(value, frame, payload, not, not_applicable),
            RULE_MATCH_IP_SOURCE_PORT | RULE_MATCH_IP_DEST_PORT => {
                Self::match_ports(value, rule_type, frame, payload, not_applicable)
            }
            RULE_MATCH_CHARACTERISTICS => self.match_characteristics(value, frame, context, not_applicable),
            RULE_MATCH_FRAME_SIZE => value.len() == 4 && Self::match_frame_size(value, payload),
            RULE_MATCH_RANDOM => Self::match_random(value, not_applicable),
            RULE_MATCH_TAGS_DIFFERENCE
            | RULE_MATCH_TAGS_BITWISE_AND
            | RULE_MATCH_TAGS_BITWISE_OR
            | RULE_MATCH_TAGS_BITWISE_XOR
            | RULE_MATCH_TAGS_EQUAL => self.match_tag_pair(rule_type, value, context, not, not_applicable),
            RULE_MATCH_TAG_SENDER | RULE_MATCH_TAG_RECEIVER => {
                self.match_tag_direction(rule_type, value, context, not, not_applicable)
            }
            RULE_MATCH_INTEGER_RANGE => match_integer_range(value, payload),
            _ => self.flags & 0x08 != 0,
        }
    }

    fn match_zt_address(rule_type: u8, value: &[u8], context: &FrameRuleContext, not_applicable: bool) -> bool {
        if value.len() != ADDRESS_SIZE {
            return not_applicable;
        }
        let Ok(address) = Address::from_bytes(value) else {
            return not_applicable;
        };
        if address.is_reserved() {
            return not_applicable;
        }
        if rule_type == RULE_MATCH_SOURCE_ZT_ADDRESS {
            address == context.source_zt
        } else {
            address == context.destination_zt
        }
    }

    fn match_mac_address(rule_type: u8, value: &[u8], frame: &Frame, not_applicable: bool) -> bool {
        let Ok(mac) = Mac::from_bytes(value) else {
            return not_applicable;
        };
        if rule_type == RULE_MATCH_MAC_SOURCE {
            mac == frame.source
        } else {
            mac == frame.destination
        }
    }

    fn match_ipv4_prefix(rule_type: u8, value: &[u8], frame: &Frame, payload: &[u8], not_applicable: bool) -> bool {
        if value.len() != 5 || frame.ether_type != ETHER_TYPE_IPV4 || payload.len() < 20 {
            return not_applicable;
        }
        let [_, _, _, _, bits] = fixed_bytes::<5>(value);
        if bits > 32 {
            return not_applicable;
        }
        let pos = if rule_type == RULE_MATCH_IPV4_DEST { 16 } else { 12 };
        let Some(address) = payload.get(pos..pos + 4) else {
            return not_applicable;
        };
        prefix_contains_v4(fixed_bytes::<4>(value), bits, fixed_bytes::<4>(address))
    }

    fn match_ipv6_prefix(rule_type: u8, value: &[u8], frame: &Frame, payload: &[u8], not_applicable: bool) -> bool {
        if value.len() != 17 || frame.ether_type != ETHER_TYPE_IPV6 || payload.len() < 40 {
            return not_applicable;
        }
        let prefix = fixed_bytes::<16>(value);
        let Some(&bits) = value.get(16) else {
            return not_applicable;
        };
        if bits > 128 {
            return not_applicable;
        }
        let pos = if rule_type == RULE_MATCH_IPV6_DEST { 24 } else { 8 };
        let Some(address) = payload.get(pos..pos + 16) else {
            return not_applicable;
        };
        prefix_contains_v6(prefix, bits, fixed_bytes::<16>(address))
    }

    fn match_ip_tos(value: &[u8], frame: &Frame, payload: &[u8], not_applicable: bool) -> bool {
        if value.len() != 3 {
            return not_applicable;
        }
        let mut tos = if frame.ether_type == ETHER_TYPE_IPV4 && payload.len() >= 20 {
            let Some(tos) = payload.get(1).copied() else {
                return not_applicable;
            };
            tos
        } else if frame.ether_type == ETHER_TYPE_IPV6 && payload.len() >= 40 {
            let (Some(&high), Some(&low)) = (payload.first(), payload.get(1)) else {
                return not_applicable;
            };
            (high << 4) | (low >> 4)
        } else {
            return not_applicable;
        };
        let [mask, minimum, maximum] = fixed_bytes::<3>(value);
        tos &= mask;
        tos >= minimum && tos <= maximum
    }

    fn match_ip_protocol(value: &[u8], frame: &Frame, payload: &[u8], not_applicable: bool) -> bool {
        if value.len() != 1 {
            return not_applicable;
        }
        let [protocol] = fixed_bytes::<1>(value);
        if frame.ether_type == ETHER_TYPE_IPV4 {
            return payload.len() >= 20 && payload.get(9) == Some(&protocol);
        }
        match ip_payload(frame.ether_type, payload) {
            Some((_, found)) => found == protocol,
            None => false,
        }
    }

    fn match_icmp(value: &[u8], frame: &Frame, payload: &[u8], not: bool, not_applicable: bool) -> bool {
        if value.len() != 3 {
            return not_applicable;
        }
        let Some((pos, protocol)) = ip_payload(frame.ether_type, payload) else {
            return not_applicable;
        };
        let [icmp_type, icmp_code, flags] = fixed_bytes::<3>(value);
        if (protocol != 1 && protocol != 58) || payload.len() - pos < 2 || payload.get(pos) != Some(&icmp_type) {
            return not_applicable;
        }
        if flags & 1 == 0 {
            return !not;
        }
        payload.get(pos + 1) == Some(&icmp_code)
    }

    fn match_ports(value: &[u8], rule_type: u8, frame: &Frame, payload: &[u8], not_applicable: bool) -> bool {
        if value.len() != 4 {
            return not_applicable;
        }
        let Some((mut pos, protocol)) = ip_payload(frame.ether_type, payload) else {
            return not_applicable;
        };
        if protocol != 6 && protocol != 17 && protocol != 132 && protocol != 136 {
            return not_applicable;
        }
        if payload.len() - pos <= 4 {
            return not_applicable;
        }
        if rule_type == RULE_MATCH_IP_DEST_PORT {
            pos += 2;
        }
        let (Some(&port_high), Some(&port_low)) = (payload.get(pos), payload.get(pos + 1)) else {
            return not_applicable;
        };
        let port = u16::from_be_bytes([port_high, port_low]);
        if frame.ether_type == ETHER_TYPE_IPV6 && port == 0 {
            return false;
        }
        let lower = u16::from_be_bytes(fixed_bytes::<2>(value));
        let upper = u16::from_be_bytes(fixed_bytes::<2>(value.get(2..).unwrap_or_default()));
        port >= lower && port <= upper
    }

    fn match_frame_size(value: &[u8], payload: &[u8]) -> bool {
        let lower = usize::from(u16::from_be_bytes(fixed_bytes::<2>(value)));
        let upper = usize::from(u16::from_be_bytes(fixed_bytes::<2>(value.get(2..).unwrap_or_default())));
        payload.len() >= lower && payload.len() <= upper
    }

    fn match_random(value: &[u8], not_applicable: bool) -> bool {
        if value.len() != 4 {
            return not_applicable;
        }
        let mut random = [0u8; 4];
        rand::rng().fill_bytes(&mut random);
        u32::from_be_bytes(random) <= u32::from_be_bytes(fixed_bytes::<4>(value))
    }

    fn match_characteristics(
        &self,
        value: &[u8],
        frame: &Frame,
        context: &FrameRuleContext,
        not_applicable: bool,
    ) -> bool {
        if value.len() != 8 {
            return not_applicable;
        }
        let requested = u64::from_be_bytes(fixed_bytes::<8>(value));
        let mut characteristics = 0u64;
        if context.inbound {
            characteristics |= CHARACTERISTIC_INBOUND;
        }
        if frame.destination.is_multicast() {
            characteristics |= CHARACTERISTIC_MULTICAST;
        }
        if frame.destination.is_broadcast() {
            characteristics |= CHARACTERISTIC_BROADCAST;
        }
        characteristics |= self.ownership_characteristics(frame, context, requested);
        if let Some((pos, protocol)) = ip_payload(frame.ether_type, &frame.payload) {
            if protocol == 6 && frame.payload.len() - pos > 13 {
                if let Some(&tcp_flags) = frame.payload.get(pos + 13) {
                    characteristics |= u64::from(tcp_flags);
                }
                // Bits 8..11 carry the data-offset byte's low (reserved) nibble, which is what the
                // reference computes; the header length in its high nibble is not a characteristic.
                if let Some(&reserved) = frame.payload.get(pos + 12) {
                    characteristics |= u64::from(reserved & 0x0f) << 8;
                }
            }
        }
        characteristics & requested != 0
    }

    fn ownership_characteristics(&self, frame: &Frame, context: &FrameRuleContext, requested: u64) -> u64 {
        if requested & (CHARACTERISTIC_IP_AUTH | CHARACTERISTIC_MAC_AUTH) == 0 {
            return 0;
        }
        let mut characteristics = 0u64;
        if requested & CHARACTERISTIC_IP_AUTH != 0 && ipv6_neighbor_solicitation(frame) {
            characteristics |= CHARACTERISTIC_IP_AUTH;
        }
        for certificate in &context.ownership {
            if context.inbound
                && absolute_difference(certificate.timestamp, self.timestamp) > self.credential_time_max_delta
            {
                continue;
            }
            if characteristics & CHARACTERISTIC_MAC_AUTH == 0 && certificate.owns_mac(frame.source) {
                characteristics |= CHARACTERISTIC_MAC_AUTH;
            }
            if characteristics & CHARACTERISTIC_IP_AUTH == 0 {
                if let Some(source_ip) = frame_source_ip(frame) {
                    if certificate.owns_ip(source_ip) {
                        characteristics |= CHARACTERISTIC_IP_AUTH;
                    }
                }
            }
        }
        characteristics
    }

    fn match_tag_pair(
        &self,
        rule_type: u8,
        value: &[u8],
        context: &FrameRuleContext,
        not: bool,
        not_applicable: bool,
    ) -> bool {
        if value.len() != 8 {
            return not_applicable;
        }
        let id = u32::from_be_bytes(fixed_bytes::<4>(value));
        let expected = u32::from_be_bytes(fixed_bytes::<4>(value.get(4..).unwrap_or_default()));
        let Some(local_tag) = find_tag(&context.local_tags, id, self, false).map(|tag| tag.value) else {
            return not_applicable;
        };
        let Some(remote_tag) = find_tag(&context.remote_tags, id, self, true).map(|tag| tag.value) else {
            if context.super_accept || !context.inbound {
                return !not;
            }
            return not_applicable;
        };
        match rule_type {
            RULE_MATCH_TAGS_DIFFERENCE => local_tag.abs_diff(remote_tag) <= expected,
            RULE_MATCH_TAGS_BITWISE_AND => local_tag & remote_tag == expected,
            RULE_MATCH_TAGS_BITWISE_OR => local_tag | remote_tag == expected,
            RULE_MATCH_TAGS_BITWISE_XOR => local_tag ^ remote_tag == expected,
            RULE_MATCH_TAGS_EQUAL => local_tag == expected && remote_tag == expected,
            // The caller dispatches only the five tag-pair types; the reference's own fallback for
            // anything else is `hardNo`, i.e. the NOT flag's value.
            _ => not_applicable,
        }
    }

    fn match_tag_direction(
        &self,
        rule_type: u8,
        value: &[u8],
        context: &FrameRuleContext,
        not: bool,
        not_applicable: bool,
    ) -> bool {
        if value.len() != 8 {
            return not_applicable;
        }
        let id = u32::from_be_bytes(fixed_bytes::<4>(value));
        let expected = u32::from_be_bytes(fixed_bytes::<4>(value.get(4..).unwrap_or_default()));
        if context.super_accept {
            return !not;
        }
        let use_remote = (rule_type == RULE_MATCH_TAG_SENDER && context.inbound)
            || (rule_type == RULE_MATCH_TAG_RECEIVER && !context.inbound);
        if use_remote {
            let Some(tag) = find_tag(&context.remote_tags, id, self, true) else {
                if !context.inbound && rule_type == RULE_MATCH_TAG_RECEIVER {
                    return !not;
                }
                return not_applicable;
            };
            tag.value == expected
        } else {
            match find_tag(&context.local_tags, id, self, false) {
                Some(tag) => tag.value == expected,
                None => not_applicable,
            }
        }
    }
}

/// Locates a tag. The remote table mirrors the reference's id -> tag map, whose entry is the newest
/// record for the id; the local table is read from the front, as its lower bound does.
fn find_tag<'a>(tags: &'a [Tag], id: u32, config: &NetworkConfigData, remote: bool) -> Option<&'a Tag> {
    let tag = if remote {
        tags.iter().filter(|tag| tag.id == id).max_by_key(|tag| tag.timestamp)?
    } else {
        tags.iter().find(|tag| tag.id == id)?
    };
    if remote && absolute_difference(tag.timestamp, config.timestamp) > config.credential_time_max_delta {
        return None;
    }
    Some(tag)
}

/// Extracts the asserted source IP from IPv4, IPv6, NDP, or ARP.
fn frame_source_ip(frame: &Frame) -> Option<IpAddr> {
    match frame.ether_type {
        ETHER_TYPE_IPV4 => {
            if frame.payload.len() >= 20 {
                let octets = frame.payload.get(12..).unwrap_or_default();
                return Some(IpAddr::V4(Ipv4Addr::from(fixed_bytes::<4>(octets))));
            }
        }
        ETHER_TYPE_IPV6 => {
            if frame.payload.len() >= 40 {
                let offset = if frame.payload.len() >= 64
                    && frame.payload.get(6) == Some(&58)
                    && frame.payload.get(40) == Some(&136)
                {
                    48
                } else {
                    8
                };
                let octets = frame.payload.get(offset..offset + 16).unwrap_or_default();
                return Some(IpAddr::V6(Ipv6Addr::from(fixed_bytes::<16>(octets))));
            }
        }
        ETHER_TYPE_ARP if frame.payload.len() >= 28 => {
            let octets = frame.payload.get(14..).unwrap_or_default();
            return Some(IpAddr::V4(Ipv4Addr::from(fixed_bytes::<4>(octets))));
        }
        _ => {}
    }
    None
}

/// Locates the transport payload after an IPv4 or supported IPv6 header chain.
fn ip_payload(ether_type: u16, packet: &[u8]) -> Option<(usize, u8)> {
    if ether_type == ETHER_TYPE_IPV4 {
        if packet.len() < 20 {
            return None;
        }
        let version = packet.first().copied()?;
        let protocol = packet.get(9).copied()?;
        let pos = usize::from(version & 0x0f) * 4;
        return (pos <= packet.len()).then_some((pos, protocol));
    }
    if ether_type != ETHER_TYPE_IPV6 || packet.len() < 40 {
        return None;
    }
    let mut pos = 40usize;
    let mut protocol = packet.get(6).copied()?;
    while pos <= packet.len() {
        match protocol {
            0 | 43 | 60 | 135 => {
                if packet.len() - pos < 8 {
                    return None;
                }
                let window = packet.get(pos..pos + 2)?;
                let [next_protocol, length] = window else {
                    return None;
                };
                protocol = *next_protocol;
                pos += usize::from(*length) * 8 + 8;
            }
            _ => return Some((pos, protocol)),
        }
    }
    None
}

fn log_evaluated_rule(log: &mut [u8], index: usize, matched: bool, set_matches: bool) {
    let Some(entry) = log.get_mut(index / 2) else {
        return;
    };
    let mut value = 0x05u8;
    if matched {
        value += 0x04;
    }
    if set_matches {
        value += 1;
    }
    *entry |= value << (u32::try_from(index & 1).unwrap_or_default() * 4);
}

fn log_skipped_rule(log: &mut [u8], index: usize, set_matches: bool) {
    let Some(entry) = log.get_mut(index / 2) else {
        return;
    };
    let mut value = 1u8;
    if set_matches {
        value += 1;
    }
    *entry |= value << (u32::try_from(index & 1).unwrap_or_default() * 4);
}

fn absolute_difference(left: u64, right: u64) -> u64 {
    left.abs_diff(right)
}

fn prefix_contains_v4(prefix: [u8; 4], bits: u8, address: [u8; 4]) -> bool {
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - u32::from(bits)) };
    (u32::from_be_bytes(prefix) & mask) == (u32::from_be_bytes(address) & mask)
}

fn prefix_contains_v6(prefix: [u8; 16], bits: u8, address: [u8; 16]) -> bool {
    let bits = u32::from(bits);
    let high = mask64(bits.min(64));
    let low = mask64(bits.saturating_sub(64));
    let prefix_high = u64::from_be_bytes(prefix[..8].try_into().unwrap_or_default());
    let prefix_low = u64::from_be_bytes(prefix[8..].try_into().unwrap_or_default());
    let address_high = u64::from_be_bytes(address[..8].try_into().unwrap_or_default());
    let address_low = u64::from_be_bytes(address[8..].try_into().unwrap_or_default());
    (prefix_high & high) == (address_high & high) && (prefix_low & low) == (address_low & low)
}

fn mask64(bits: u32) -> u64 {
    match bits {
        0 => 0,
        bits if bits >= 64 => u64::MAX,
        bits => u64::MAX << (64 - bits),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SIGNATURE_SIZE;

    fn frame(ether_type: u16, payload_len: usize) -> Frame {
        Frame {
            network_id: 0,
            source: Mac::default(),
            destination: Mac::default(),
            ether_type,
            payload: vec![0u8; payload_len],
        }
    }

    fn context() -> FrameRuleContext {
        FrameRuleContext { source_zt: Address::new(1), destination_zt: Address::new(2), ..Default::default() }
    }

    /// A tag as the controller wire format carries it; rule evaluation reads
    /// only the identifier, value, and timestamp.
    fn tag(id: u32, value: u32, timestamp: u64) -> Tag {
        let mut raw = Vec::new();
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.extend_from_slice(&timestamp.to_be_bytes());
        raw.extend_from_slice(&id.to_be_bytes());
        raw.extend_from_slice(&value.to_be_bytes());
        raw.extend_from_slice(&[0u8; ADDRESS_SIZE * 2]);
        raw.push(1);
        raw.extend_from_slice(&(SIGNATURE_SIZE as u16).to_be_bytes());
        raw.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
        raw.extend_from_slice(&0u16.to_be_bytes());
        Tag::parse(&raw).expect("parses").0
    }

    /// An ownership certificate carrying one MAC and one IPv4 claim.
    fn ownership(mac: Mac, ip: Ipv4Addr) -> CertificateOfOwnership {
        use crate::ownership::OwnershipThingType;

        let mut raw = Vec::new();
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.extend_from_slice(&0u32.to_be_bytes());
        raw.extend_from_slice(&2u16.to_be_bytes());
        let mut mac_claim = [0u8; 16];
        mac_claim[..6].copy_from_slice(&mac.bytes());
        raw.push(OwnershipThingType::Mac.bits());
        raw.extend_from_slice(&mac_claim);
        let mut ip_claim = [0u8; 16];
        ip_claim[..4].copy_from_slice(&ip.octets());
        raw.push(OwnershipThingType::Ipv4.bits());
        raw.extend_from_slice(&ip_claim);
        raw.extend_from_slice(&[0u8; ADDRESS_SIZE * 2]);
        raw.push(1);
        raw.extend_from_slice(&(SIGNATURE_SIZE as u16).to_be_bytes());
        raw.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
        raw.extend_from_slice(&0u16.to_be_bytes());
        CertificateOfOwnership::parse(&raw).expect("parses").0
    }

    fn forward_rule_value(target: Address, length: u16) -> Vec<u8> {
        let mut value = vec![0u8; 14];
        value[..8].copy_from_slice(&target.uint64().to_be_bytes());
        value[12..14].copy_from_slice(&length.to_be_bytes());
        value
    }

    #[test]
    fn allows_the_ether_types_of_the_official_configuration() {
        let raw = hex::decode("a5020800a5020806a50286dd00000100").unwrap();
        let config = NetworkConfigData { rules: parse_network_rules(&raw).unwrap(), ..Default::default() };
        for ether_type in [ETHER_TYPE_IPV4, ETHER_TYPE_ARP, ETHER_TYPE_IPV6] {
            assert!(config.allows_frame(&frame(ether_type, 40), context()));
        }
        assert!(!config.allows_frame(&frame(0x88cc, 40), context()));
    }

    #[test]
    fn reports_tee_watch_redirect_and_inbound_super_accept() {
        let frame = frame(ETHER_TYPE_IPV4, 20);
        let tee_target = Address::new(3);
        let mut config = NetworkConfigData {
            rules: vec![
                NetworkRule { rule_type: RULE_ACTION_TEE, value: forward_rule_value(tee_target, 12) },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
            ],
            ..Default::default()
        };
        let decision = config.filter_frame(&frame, context());
        assert_eq!(decision.result, RuleResult::Accept);
        assert_eq!(decision.tee, tee_target);
        assert_eq!(decision.tee_length, 12);
        assert!(!decision.watch);
        assert!(decision.redirect.is_zero());

        let redirect_target = Address::new(4);
        config.rules =
            vec![NetworkRule { rule_type: RULE_ACTION_REDIRECT, value: forward_rule_value(redirect_target, 0) }];
        let decision = config.filter_frame(&frame, context());
        assert_eq!(decision.result, RuleResult::Accept);
        assert_eq!(decision.redirect, redirect_target);

        let local = Address::new(5);
        config.rules = vec![
            NetworkRule { rule_type: RULE_MATCH_SOURCE_ZT_ADDRESS, value: Address::new(99).bytes().to_vec() },
            NetworkRule { rule_type: RULE_ACTION_WATCH, value: forward_rule_value(local, 0) },
            NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
        ];
        let inbound =
            FrameRuleContext { inbound: true, source_zt: Address::new(6), destination_zt: local, ..Default::default() };
        let decision = config.filter_frame(&frame, inbound);
        assert_eq!(decision.result, RuleResult::Accept);
        assert!(decision.super_accept);

        config.rules = vec![NetworkRule { rule_type: RULE_ACTION_WATCH, value: forward_rule_value(local, 0) }];
        let decision = config.filter_frame(
            &frame,
            FrameRuleContext { inbound: true, source_zt: Address::new(6), destination_zt: local, ..Default::default() },
        );
        assert_eq!(decision.result, RuleResult::Accept);
        assert!(decision.super_accept);
    }

    #[test]
    fn an_unknown_outbound_receiver_tag_skips_one_guarded_drop() {
        let value = vec![0, 0, 0, 7, 0, 0, 0, 42];
        let config = NetworkConfigData {
            tags: vec![tag(7, 42, 0)],
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_TAG_RECEIVER, value },
                NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
            ],
            ..Default::default()
        };
        let mut context = context();
        context.local_tags = config.tags.clone();
        assert!(config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), context));
    }

    #[test]
    fn hard_matches_stay_true_under_not() {
        let value = vec![0, 0, 0, 7, 0, 0, 0, 42];
        let tags = vec![tag(7, 42, 0)];
        let mut frame = frame(ETHER_TYPE_IPV4, 28);
        frame.payload[0] = 0x45;
        frame.payload[9] = 1;
        frame.payload[20] = 8;

        for (rule_type, rule_value) in [
            (RULE_MATCH_ICMP, vec![8, 0, 0]),
            (RULE_MATCH_TAGS_EQUAL, value.clone()),
            (RULE_MATCH_TAG_RECEIVER, value.clone()),
        ] {
            let config = NetworkConfigData {
                tags: tags.clone(),
                rules: vec![
                    NetworkRule { rule_type: rule_type | RULE_FLAG_NOT, value: rule_value },
                    NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
                ],
                ..Default::default()
            };
            let mut context = context();
            context.local_tags = tags.clone();
            assert!(config.allows_frame(&frame, context), "hard match {rule_type} was inverted by NOT");
        }
    }

    #[test]
    fn integer_range_uses_the_slot_relative_big_endian_index() {
        let mut value = vec![0u8; 19];
        value[..8].copy_from_slice(&5u64.to_be_bytes());
        value[8..16].copy_from_slice(&5u64.to_be_bytes());
        value[18] = 7;
        let mut payload = vec![0u8; 8];
        payload[7] = 5;
        assert!(match_integer_range(&value, &payload));
    }

    #[test]
    fn integer_range_truncates_to_the_official_uint32_span() {
        let mut value = vec![0u8; 19];
        value[..8].copy_from_slice(&1u64.to_be_bytes());
        value[8..16].copy_from_slice(&(1 + (1u64 << 32) + 1).to_be_bytes());
        value[18] = 7;
        let mut payload = vec![0u8; 8];
        payload[7] = 3;
        assert!(!match_integer_range(&value, &payload));
    }

    #[test]
    fn integer_range_out_of_bounds_compares_the_official_zero_value() {
        let mut value = vec![0u8; 19];
        value[16..18].copy_from_slice(&32u16.to_be_bytes());
        value[18] = 7;
        assert!(match_integer_range(&value, &[]));
        value[..8].copy_from_slice(&1u64.to_be_bytes());
        value[8..16].copy_from_slice(&1u64.to_be_bytes());
        assert!(!match_integer_range(&value, &[]));
    }

    #[test]
    fn empty_rules_fail_closed() {
        assert!(!NetworkConfigData::default().allows_frame(&frame(ETHER_TYPE_IPV4, 20), context()));
    }

    #[test]
    fn ipv4_protocol_match_ignores_the_ihl() {
        let mut frame = frame(ETHER_TYPE_IPV4, 20);
        frame.payload[0] = 0x4f;
        frame.payload[9] = 17;
        let config = NetworkConfigData {
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_IP_PROTOCOL, value: vec![17] },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
            ],
            ..Default::default()
        };
        assert!(config.allows_frame(&frame, FrameRuleContext::default()));
    }

    /// Every rule set starts from the caller's `super_accept`, not from what the network rule set or
    /// a previous capability left behind.
    #[test]
    fn each_rule_set_starts_from_the_callers_super_accept() {
        let local = Address::new(2);
        let mut raises_super_accept = Capability::default();
        raises_super_accept.rules = vec![
            NetworkRule { rule_type: RULE_MATCH_ETHER_TYPE, value: 0x1234u16.to_be_bytes().to_vec() },
            NetworkRule { rule_type: RULE_ACTION_TEE, value: forward_rule_value(local, 0) },
            NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
        ];
        let mut reads_super_accept = Capability::default();
        reads_super_accept.rules = vec![
            NetworkRule { rule_type: RULE_MATCH_TAG_SENDER, value: vec![0, 0, 0, 7, 0, 0, 0, 1] },
            NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
        ];
        let config =
            NetworkConfigData { capabilities: vec![raises_super_accept, reads_super_accept], ..Default::default() };
        let context =
            FrameRuleContext { inbound: true, source_zt: Address::new(1), destination_zt: local, ..Default::default() };

        assert!(
            !config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), context),
            "the second capability must not inherit the first one's super_accept"
        );
    }

    #[test]
    fn capability_accept_preserves_both_base_and_capability_tee() {
        let base_target = Address::new(3);
        let capability_target = Address::new(4);
        let config = NetworkConfigData {
            rules: vec![
                NetworkRule { rule_type: RULE_ACTION_TEE, value: forward_rule_value(base_target, 10) },
                NetworkRule { rule_type: RULE_ACTION_BREAK, value: Vec::new() },
            ],
            ..Default::default()
        };
        let mut capability = Capability::default();
        capability.rules = vec![
            NetworkRule { rule_type: RULE_ACTION_WATCH, value: forward_rule_value(capability_target, 12) },
            NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
        ];
        let decision = config.filter_frame(
            &frame(ETHER_TYPE_IPV4, 20),
            FrameRuleContext { capabilities: vec![capability], ..Default::default() },
        );
        assert_eq!(decision.result, RuleResult::Accept);
        assert_eq!(decision.tee, base_target);
        assert_eq!(decision.additional_tee.len(), 1);
        let additional = &decision.additional_tee[0];
        assert_eq!(additional.target, capability_target);
        assert_eq!(additional.length, 12);
        assert!(additional.watch);
    }

    #[test]
    fn tag_rules_require_fresh_remote_credentials() {
        let local = tag(7, 42, 1000);
        let remote = tag(7, 42, 1005);
        let config = NetworkConfigData {
            timestamp: 1000,
            credential_time_max_delta: 10,
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_TAGS_EQUAL, value: vec![0, 0, 0, 7, 0, 0, 0, 42] },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
                NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
            ],
            ..Default::default()
        };
        let inbound = |remote_tags: Vec<Tag>| FrameRuleContext {
            inbound: true,
            source_zt: Address::new(1),
            destination_zt: Address::new(2),
            local_tags: vec![local.clone()],
            remote_tags,
            ..Default::default()
        };
        assert!(config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), inbound(vec![remote.clone()])));
        let mut expired = remote;
        expired.timestamp = 1011;
        assert!(!config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), inbound(vec![expired])));
        let mut outbound = context();
        outbound.local_tags = vec![local];
        assert!(config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), outbound));
    }

    /// The reference requires both tag values to equal the operand, so tags that agree with each
    /// other but not with the operand do not match.
    #[test]
    fn tags_equal_requires_both_tag_values_to_equal_the_operand() {
        let config = NetworkConfigData {
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_TAGS_EQUAL, value: vec![0, 0, 0, 7, 0, 0, 0, 42] },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
                NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
            ],
            ..Default::default()
        };
        let agreeing =
            FrameRuleContext { local_tags: vec![tag(7, 7, 0)], remote_tags: vec![tag(7, 7, 0)], ..context() };
        assert!(
            !config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), agreeing),
            "the operand is part of the comparison, so agreeing tags that differ from it do not match"
        );

        let matching =
            FrameRuleContext { local_tags: vec![tag(7, 42, 0)], remote_tags: vec![tag(7, 42, 0)], ..context() };
        assert!(config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), matching));
    }

    /// A NOT-flagged tag rule does not apply to a tag the network never issued.
    #[test]
    fn a_not_flagged_tag_rule_does_not_apply_to_an_absent_local_tag() {
        let config = NetworkConfigData {
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_TAG_SENDER | RULE_FLAG_NOT, value: vec![0, 0, 0, 9, 0, 0, 0, 42] },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
                NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
            ],
            ..Default::default()
        };
        let mut context = context();
        context.local_tags = vec![tag(7, 42, 0)];

        assert!(
            !config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), context),
            "an unissued tag leaves the rule inapplicable, so the NOT flag must not make it match"
        );
    }

    /// The same rule with the tag present compares the value in both directions.
    #[test]
    fn a_not_flagged_tag_rule_compares_a_present_local_tag() {
        let config = NetworkConfigData {
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_TAG_SENDER | RULE_FLAG_NOT, value: vec![0, 0, 0, 7, 0, 0, 0, 42] },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
                NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
            ],
            ..Default::default()
        };
        let mut equal = context();
        equal.local_tags = vec![tag(7, 42, 0)];
        assert!(
            !config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), equal),
            "the value matches, so the NOT rule does not"
        );

        let mut different = context();
        different.local_tags = vec![tag(7, 7, 0)];
        assert!(
            config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), different),
            "the value differs, so the NOT rule matches"
        );
    }

    /// A plain tag rule matches a present tag and leaves an absent one inapplicable.
    #[test]
    fn a_plain_tag_rule_matches_only_a_present_local_tag() {
        let config = NetworkConfigData {
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_TAG_SENDER, value: vec![0, 0, 0, 7, 0, 0, 0, 42] },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
                NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
            ],
            ..Default::default()
        };
        let mut present = context();
        present.local_tags = vec![tag(7, 42, 0)];
        assert!(config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), present));

        assert!(!config.allows_frame(&frame(ETHER_TYPE_IPV4, 20), context()));
    }

    /// The reference keeps remote credentials in an id -> tag map whose entry is the newest
    /// accepted record, so the freshness check applies to that record alone.
    #[test]
    fn a_fresh_remote_tag_behind_a_stale_one_is_still_found() {
        let config = NetworkConfigData { timestamp: 10, credential_time_max_delta: 1, ..Default::default() };
        let remote = vec![tag(7, 1, 0), tag(7, 2, 10)];
        assert_eq!(find_tag(&remote, 7, &config, true).map(|tag| tag.value), Some(2));
    }

    /// An older record never displaces a newer one, whatever order the wire carried them in.
    #[test]
    fn an_older_remote_tag_does_not_displace_a_newer_one() {
        let config = NetworkConfigData { timestamp: 10, credential_time_max_delta: 1, ..Default::default() };
        let remote = vec![tag(7, 2, 10), tag(7, 1, 0)];
        assert_eq!(find_tag(&remote, 7, &config, true).map(|tag| tag.value), Some(2));
    }

    /// The local table is the configuration's list, which the reference reads with a lower bound.
    #[test]
    fn the_local_tag_table_reads_the_first_record_for_an_id() {
        let config = NetworkConfigData::default();
        let local = vec![tag(7, 1, 0), tag(7, 2, 0)];
        assert_eq!(find_tag(&local, 7, &config, false).map(|tag| tag.value), Some(1));
    }

    /// Bits 8..11 carry the low nibble of the TCP data-offset byte, as ZeroTier One's matcher does.
    #[test]
    fn characteristics_bits_8_to_11_hold_the_tcp_reserved_nibble() {
        let mut frame = frame(ETHER_TYPE_IPV4, 40);
        frame.payload[0] = 0x45;
        frame.payload[9] = 6;
        frame.payload[32] = 0x51;
        let config = NetworkConfigData {
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_CHARACTERISTICS, value: 0x0100u64.to_be_bytes().to_vec() },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
            ],
            ..Default::default()
        };
        assert!(config.allows_frame(&frame, FrameRuleContext::default()));

        frame.payload[32] = 0x50;
        assert!(!config.allows_frame(&frame, FrameRuleContext::default()));
    }

    #[test]
    fn ownership_characteristics_authenticate_the_claimed_addresses() {
        let mac = Mac::new(0x7a11_2233_4455);
        let ip = Ipv4Addr::new(192, 0, 2, 10);
        let mut frame = Frame {
            network_id: 0,
            source: mac,
            destination: Mac::default(),
            ether_type: ETHER_TYPE_IPV4,
            payload: vec![0u8; 20],
        };
        frame.payload[12..16].copy_from_slice(&ip.octets());
        let config = NetworkConfigData {
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_CHARACTERISTICS, value: vec![0x18, 0, 0, 0, 0, 0, 0, 0] },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
                NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
            ],
            ..Default::default()
        };
        let mut proven = context();
        proven.ownership = vec![ownership(mac, ip)];
        assert!(config.allows_frame(&frame, proven));
        assert!(!config.allows_frame(&frame, context()));
    }

    #[test]
    fn capabilities_are_a_fallback_only() {
        let frame = frame(ETHER_TYPE_IPV4, 20);
        let mut capability = Capability::default();
        capability.rules = vec![
            NetworkRule { rule_type: RULE_MATCH_ETHER_TYPE, value: vec![0x08, 0x00] },
            NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
        ];
        let mut config = NetworkConfigData {
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_ETHER_TYPE, value: vec![0x08, 0x06] },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
            ],
            ..Default::default()
        };
        let context = FrameRuleContext { capabilities: vec![capability], ..Default::default() };
        assert!(config.allows_frame(&frame, context.clone()));
        config.rules = vec![NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() }];
        assert!(!config.allows_frame(&frame, context));
    }

    #[test]
    fn rule_forward_flags_cover_every_direction() {
        assert_eq!(rule_forward_flags(false, false), 0x02);
        assert_eq!(rule_forward_flags(true, false), 0x08);
        assert_eq!(rule_forward_flags(false, true), 0x16);
        assert_eq!(rule_forward_flags(true, true), 0x1c);
        assert_eq!(rule_redirect_flags(false), 0x04);
        assert_eq!(rule_redirect_flags(true), 0x0a);
    }

    #[test]
    fn rule_forward_payload_truncates_to_the_rule_length() {
        let frame = Frame {
            network_id: 0x0102_0304_0506_0708,
            source: Mac::new(0x1122_3344_5566),
            destination: Mac::new(0xaabb_ccdd_eeff),
            ether_type: ETHER_TYPE_IPV4,
            payload: vec![1, 2, 3, 4],
        };
        let expected_prefix = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x08, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x08, 0x00,
        ];
        let truncated = rule_forward_payload(&frame, 0x08, 2);
        assert_eq!(&truncated[..expected_prefix.len()], expected_prefix.as_slice());
        assert_eq!(&truncated[expected_prefix.len()..], &[1, 2]);
        assert_eq!(rule_forward_payload(&frame, 0x08, 0).len(), 23 + 4);
        assert_eq!(rule_forward_payload(&frame, 0x08, 9).len(), 23 + 4);
    }

    #[test]
    fn a_forward_target_must_be_a_real_node_and_operand_length() {
        assert_eq!(parse_rule_forward(&[0u8; 14]), None);
        assert_eq!(parse_rule_forward(&forward_rule_value(Address::new(3), 7)), Some((Address::new(3), 7)));
        let mut reserved = forward_rule_value(Address::new(3), 7);
        reserved[..8].copy_from_slice(&0x0000_00ff_1234_5678u64.to_be_bytes());
        assert_eq!(parse_rule_forward(&reserved), None);
    }

    #[test]
    fn trace_log_records_evaluated_and_skipped_rules() {
        let config = NetworkConfigData {
            rules: vec![
                NetworkRule { rule_type: RULE_MATCH_ETHER_TYPE, value: vec![0x08, 0x06] },
                NetworkRule { rule_type: RULE_MATCH_ETHER_TYPE, value: vec![0x08, 0x00] },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
            ],
            ..Default::default()
        };
        let frame = frame(ETHER_TYPE_IPV4, 20);
        let context = FrameRuleContext { trace_rules: true, ..Default::default() };
        let decision = config.filter_frame(&frame, context);
        assert_eq!(decision.result, RuleResult::Drop);
        assert_eq!(decision.rule_log.len(), MAX_NETWORK_RULES / 2);
        // Rule 0 was evaluated without matching (nibble 6) and rule 1 was
        // skipped (nibble 1); the action at index 2 is never logged.
        assert_eq!(decision.rule_log[0], 0x16);
        assert!(decision.rule_log[1..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn parses_length_prefixed_rules() {
        let data = [RULE_MATCH_IP_PROTOCOL, 1, 6, RULE_ACTION_ACCEPT, 0];
        let rules = parse_network_rules(&data).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].rule_type, RULE_MATCH_IP_PROTOCOL);
        assert_eq!(rules[0].value, vec![6]);
        assert_eq!(rules[1].rule_type, RULE_ACTION_ACCEPT);
        assert!(rules[1].value.is_empty());
    }

    #[test]
    fn parse_keeps_the_rule_type_flags() {
        let data = [RULE_MATCH_ETHER_TYPE | RULE_FLAG_NOT, 2, 0x86, 0xdd, RULE_ACTION_ACCEPT, 0];
        let rules = parse_network_rules(&data).unwrap();
        assert_eq!(rules[0].rule_type, RULE_MATCH_ETHER_TYPE | RULE_FLAG_NOT);
    }

    #[test]
    fn rejects_a_truncated_rule_stream() {
        assert_eq!(parse_network_rules(&[RULE_ACTION_ACCEPT]), Err(InvalidRule));
        assert_eq!(parse_network_rules(&[RULE_MATCH_ETHER_TYPE, 2, 0x08]), Err(InvalidRule));
    }

    #[test]
    fn truncates_at_the_advertised_maximum() {
        let raw = vec![0u8; (MAX_NETWORK_RULES + 1) * 2];
        assert_eq!(parse_network_rules(&raw).unwrap().len(), MAX_NETWORK_RULES);
    }

    #[test]
    fn ipv6_prefixes_take_their_length_from_the_operand_tail() {
        let mut value = vec![0u8; 17];
        value[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        value[16] = 32;
        let mut frame = frame(ETHER_TYPE_IPV6, 40);
        frame.payload[8..12].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        assert!(NetworkConfigData::match_ipv6_prefix(RULE_MATCH_IPV6_SOURCE, &value, &frame, &frame.payload, false));
        frame.payload[8..12].copy_from_slice(&[0x30, 0x01, 0x00, 0x00]);
        assert!(!NetworkConfigData::match_ipv6_prefix(RULE_MATCH_IPV6_SOURCE, &value, &frame, &frame.payload, false));
    }
}
