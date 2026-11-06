//! Virtual Ethernet frames and their two wire encodings.
//!
//! A native `FRAME` carries only a network ID and EtherType: both MAC addresses
//! are implied by the ZeroTier node addresses on the packet, which is why it is
//! cheap. An `EXT_FRAME` carries explicit MACs and can therefore bridge a
//! non-ZeroTier device, at the cost of a certificate and more header bytes.

use crate::address::Address;
use crate::mac::{address_for_mac, first_mac_octet, mac_for_address, Mac, ETHERNET_MAC_SIZE};
use crate::membership::CertificateOfMembership;
use crate::packet::{Packet, PacketError, Verb, MAX_PACKET_SIZE};

/// An IPv4 payload inside a virtual Ethernet frame.
pub const ETHER_TYPE_IPV4: u16 = 0x0800;
/// An ARP payload inside a virtual Ethernet frame.
pub const ETHER_TYPE_ARP: u16 = 0x0806;
/// An IPv6 payload inside a virtual Ethernet frame.
pub const ETHER_TYPE_IPV6: u16 = 0x86dd;

/// Reports a frame that cannot be decoded or is not deliverable on this network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("invalid ZeroTier packet")]
    InvalidPacket,
    #[error("unsupported ZeroTier Ethernet destination")]
    UnsupportedEthernet,
}

/// An Ethernet payload exchanged over a virtual ZeroTier network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub network_id: u64,
    pub source: Mac,
    pub destination: Mac,
    pub ether_type: u16,
    pub payload: Vec<u8>,
}

/// A decoded `EXT_FRAME`: the frame or bare receipt request it carried, plus
/// the membership certificate a bridged sender attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedFrame {
    /// The Ethernet frame, absent when the payload was a bare receipt request.
    pub frame: Option<Frame>,
    pub flags: u8,
    pub certificate: Option<CertificateOfMembership>,
}

/// An Ethernet group address plus the additional identifier that separates the
/// 256 ARP groups sharing one broadcast MAC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MulticastGroup {
    pub mac: Mac,
    pub adi: u32,
}

impl MulticastGroup {
    #[must_use]
    pub const fn new(mac: Mac, adi: u32) -> Self {
        Self { mac, adi }
    }
}

/// What a destination MAC means for a network, which decides how a frame must
/// be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDestination {
    /// A ZeroTier node on this network, reachable at that address.
    Node(Address),
    /// An Ethernet group address, replicated rather than unicast.
    Multicast,
    /// A device behind an active bridge on this network.
    Bridged,
}

impl Frame {
    /// Classifies `mac` on `network_id`.
    ///
    /// A MAC whose first octet is the network's locally administered octet is a
    /// ZeroTier node; anything else on the virtual segment is bridged. A
    /// multicast or broadcast destination is always replicated.
    #[must_use]
    pub fn classify_destination(mac: Mac, network_id: u64) -> FrameDestination {
        if mac.is_broadcast() || mac.is_multicast() {
            return FrameDestination::Multicast;
        }
        if first_mac_octet(network_id) == mac.uint64().to_be_bytes()[2] {
            FrameDestination::Node(address_for_mac(mac, network_id))
        } else {
            FrameDestination::Bridged
        }
    }

    /// Encodes a native `FRAME` payload: network ID, EtherType, payload.
    ///
    /// A native frame's MACs are implied by the packet's node addresses, so
    /// [`Packet::source`] and [`Packet::destination`] supply them on decode.
    pub fn encode_native(&self) -> Result<Vec<u8>, FrameError> {
        if self.payload.is_empty() {
            return Err(FrameError::InvalidPacket);
        }
        let mut out = Vec::with_capacity(10 + self.payload.len());
        out.extend_from_slice(&self.network_id.to_be_bytes());
        out.extend_from_slice(&self.ether_type.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decodes a native `FRAME` payload received from `source` toward `local`.
    ///
    /// Returns `Ok(None)` for a payload of exactly the 8-byte network ID probe
    /// with no frame body, which ZeroTier uses to test membership only.
    pub fn decode_native(
        payload: &[u8],
        network_local_address: Address,
        source: Address,
    ) -> Result<Option<Self>, FrameError> {
        let network_id = read_network_id(payload)?;
        if payload.len() <= 10 {
            return Ok(None);
        }
        let ether_type = u16::from_be_bytes(read_array(payload, 8)?);
        Ok(Some(Self {
            network_id,
            source: mac_for_address(source, network_id),
            destination: mac_for_address(network_local_address, network_id),
            ether_type,
            payload: payload.get(10..).ok_or(FrameError::InvalidPacket)?.to_vec(),
        }))
    }

    /// Encodes an `EXT_FRAME` payload, which carries explicit MAC addresses.
    ///
    /// `acknowledged` requests a receipt, and a certificate of membership is
    /// prepended when the network requires one for bridged peers.
    pub fn encode_extended(&self, flags: u8, certificate: &[u8]) -> Result<Vec<u8>, FrameError> {
        if self.payload.is_empty() {
            return Err(FrameError::InvalidPacket);
        }
        if flags & 0x01 != 0 && certificate.is_empty() {
            return Err(FrameError::InvalidPacket);
        }
        let mut out = Vec::with_capacity(23 + certificate.len() + self.payload.len());
        out.extend_from_slice(&self.network_id.to_be_bytes());
        out.push(flags);
        out.extend_from_slice(certificate);
        out.extend_from_slice(&self.destination.bytes());
        out.extend_from_slice(&self.source.bytes());
        out.extend_from_slice(&self.ether_type.to_be_bytes());
        out.extend_from_slice(&self.payload);
        if out.len() > MAX_PACKET_SIZE {
            return Err(FrameError::InvalidPacket);
        }
        Ok(out)
    }

    /// Decodes an `EXT_FRAME` payload, reporting the flags and certificate it
    /// carried.
    ///
    /// A body of exactly 14 header bytes with no payload is a bare receipt
    /// request rather than a frame, reported with no frame so the caller can
    /// answer it. A certificate of membership, present when the low flag bit is
    /// set, is decoded and returned so the caller can admit the bridged sender.
    pub fn decode_extended(payload: &[u8]) -> Result<ExtendedFrame, FrameError> {
        let network_id = read_network_id(payload)?;
        if payload.len() < 9 {
            return Err(FrameError::InvalidPacket);
        }
        let flags = payload.get(8).copied().ok_or(FrameError::InvalidPacket)?;
        let mut pos = 9;
        let mut certificate = None;
        if flags & 0x01 != 0 {
            let encoded = payload.get(pos..).ok_or(FrameError::InvalidPacket)?;
            let (parsed, consumed) = CertificateOfMembership::parse(encoded).map_err(|_| FrameError::InvalidPacket)?;
            certificate = Some(parsed);
            pos += consumed;
        }
        let body = payload.get(pos..).ok_or(FrameError::InvalidPacket)?;
        if body.len() < 14 {
            return Err(FrameError::InvalidPacket);
        }
        if body.len() == 14 {
            return Ok(ExtendedFrame { frame: None, flags, certificate });
        }
        let destination =
            Mac::from_bytes(&read_array::<ETHERNET_MAC_SIZE>(body, 0)?).map_err(|_| FrameError::InvalidPacket)?;
        let source = Mac::from_bytes(&read_array::<ETHERNET_MAC_SIZE>(body, ETHERNET_MAC_SIZE)?)
            .map_err(|_| FrameError::InvalidPacket)?;
        let ether_type = u16::from_be_bytes(read_array(body, 12)?);
        let frame_payload = body.get(14..).ok_or(FrameError::InvalidPacket)?;
        Ok(ExtendedFrame {
            frame: Some(Self { network_id, source, destination, ether_type, payload: frame_payload.to_vec() }),
            flags,
            certificate,
        })
    }

    /// Rejects a bridged frame that cannot have come from a real peer.
    ///
    /// An all-zero or multicast source, or one claiming to be this node, is
    /// either corruption or a loop, and is never delivered.
    #[must_use]
    pub fn is_deliverable(&self, local: Address, network_id: u64) -> bool {
        self.source.uint64() != 0 && !self.source.is_multicast() && self.source != mac_for_address(local, network_id)
    }
}

/// Builds the native `FRAME` packet for `destination` on `network_id`.
pub fn build_native_packet(frame: &Frame, destination: Address, local: Address) -> Result<Packet, PacketError> {
    let payload = frame.encode_native().map_err(|_| PacketError::Invalid)?;
    let mut packet = Packet::with_payload_capacity(destination, local, Verb::Frame, payload.len())?;
    packet.append(&payload)?;
    Ok(packet)
}

/// Builds the `EXT_FRAME` packet for a bridged or acknowledged frame.
pub fn build_extended_packet(
    frame: &Frame,
    destination: Address,
    local: Address,
    flags: u8,
    certificate: &[u8],
) -> Result<Packet, PacketError> {
    let payload = frame.encode_extended(flags, certificate).map_err(|_| PacketError::Invalid)?;
    let mut packet = Packet::with_payload_capacity(destination, local, Verb::ExtFrame, payload.len())?;
    packet.append(&payload)?;
    Ok(packet)
}

/// Reads the `N` bytes at `offset`, or reports a truncated packet.
fn read_array<const N: usize>(payload: &[u8], offset: usize) -> Result<[u8; N], FrameError> {
    payload.get(offset..offset + N).ok_or(FrameError::InvalidPacket)?.try_into().map_err(|_| FrameError::InvalidPacket)
}

fn read_network_id(payload: &[u8]) -> Result<u64, FrameError> {
    Ok(u64::from_be_bytes(read_array(payload, 0)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Identity, SIGNATURE_SIZE};
    use crate::membership::{QUALIFIER_MEMBER, QUALIFIER_NETWORK, QUALIFIER_TIMESTAMP};

    const NETWORK: u64 = 0x8056_c2e2_1c00_0001;

    /// A structurally valid certificate of membership, the way a controller
    /// attaches one to a bridged frame.
    fn membership_certificate() -> CertificateOfMembership {
        let controller = Identity::generate();
        let qualifiers = [
            (QUALIFIER_TIMESTAMP, 1_700_000_000u64, 0u64),
            (QUALIFIER_NETWORK, controller.address().uint64() << 24, 0),
            (QUALIFIER_MEMBER, 0x8e4d_f28b72, 0),
        ];
        let mut raw = vec![1u8, 0, qualifiers.len() as u8];
        for (id, value, max_delta) in qualifiers {
            raw.extend_from_slice(&id.to_be_bytes());
            raw.extend_from_slice(&value.to_be_bytes());
            raw.extend_from_slice(&max_delta.to_be_bytes());
        }
        raw.extend_from_slice(&controller.address().bytes());
        raw.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
        CertificateOfMembership::parse(&raw).expect("fixture certificate parses").0
    }

    fn sample() -> Frame {
        Frame {
            network_id: NETWORK,
            source: mac_for_address(Address::new(0x8e4d_f28b72), NETWORK),
            destination: mac_for_address(Address::new(0x0123_4567), NETWORK),
            ether_type: ETHER_TYPE_IPV4,
            payload: vec![0x45, 0x00, 0x00, 0x14],
        }
    }

    /// A native frame carries no MACs on the wire, so the decoded destination
    /// is the receiving node's own MAC rather than the sender's intended one.
    #[test]
    fn native_round_trip_preserves_content_and_readdresses_to_the_receiver() {
        let frame = sample();
        let encoded = frame.encode_native().unwrap();
        assert_eq!(encoded.len(), 10 + frame.payload.len());

        let local = Address::new(0x0000_0abc_def0);
        let decoded =
            Frame::decode_native(&encoded, local, frame_source(&frame)).unwrap().expect("a full native frame decodes");

        assert_eq!(decoded.network_id, frame.network_id);
        assert_eq!(decoded.ether_type, frame.ether_type);
        assert_eq!(decoded.payload, frame.payload);
        assert_eq!(decoded.source, frame.source);
        assert_eq!(decoded.destination, mac_for_address(local, NETWORK));
        assert_ne!(decoded.destination, frame.destination);
    }

    #[test]
    fn a_bare_network_probe_yields_no_frame() {
        let probe = NETWORK.to_be_bytes();
        assert_eq!(Frame::decode_native(&probe, Address::new(1), Address::new(2)).unwrap(), None);

        let too_short = [0u8; 10];
        assert_eq!(Frame::decode_native(&too_short, Address::new(1), Address::new(2)).unwrap(), None);
    }

    #[test]
    fn rejects_truncated_frame_payloads() {
        assert_eq!(Frame::decode_native(&[0u8; 7], Address::new(1), Address::new(2)), Err(FrameError::InvalidPacket));
        assert_eq!(Frame::decode_extended(&[0u8; 8]), Err(FrameError::InvalidPacket));
        assert_eq!(Frame::decode_extended(&[0u8; 9]), Err(FrameError::InvalidPacket));
    }

    #[test]
    fn extended_frame_round_trips_with_explicit_macs() {
        let frame = sample();
        let encoded = frame.encode_extended(0x04, &[]).unwrap();
        let decoded = Frame::decode_extended(&encoded).unwrap();
        assert_eq!(decoded.frame, Some(frame));
        assert_eq!(decoded.flags, 0x04);
        assert_eq!(decoded.certificate, None);
    }

    #[test]
    fn extended_frame_reports_a_bare_receipt_request() {
        let frame = sample();
        let mut encoded = frame.encode_extended(0x10, &[]).unwrap();
        encoded.truncate(9 + 14);
        let decoded = Frame::decode_extended(&encoded).unwrap();
        assert_eq!(decoded.frame, None);
        assert_eq!(decoded.flags, 0x10);
    }

    #[test]
    fn extended_frame_carries_a_membership_certificate() {
        let frame = sample();
        let certificate = membership_certificate();
        assert_eq!(frame.encode_extended(0x01, &[]), Err(FrameError::InvalidPacket));

        let mut encoded = frame.encode_extended(0x01, certificate.bytes()).unwrap();
        let decoded = Frame::decode_extended(&encoded).unwrap();
        assert_eq!(decoded.frame, Some(frame));
        assert_eq!(decoded.flags, 0x01);
        assert_eq!(decoded.certificate, Some(certificate.clone()));

        // A receipt request can carry one too, with no frame behind it.
        encoded.truncate(9 + certificate.bytes().len() + 14);
        let decoded = Frame::decode_extended(&encoded).unwrap();
        assert_eq!(decoded.frame, None);
        assert_eq!(decoded.certificate, Some(certificate));

        let mut truncated = encoded.clone();
        truncated.truncate(12);
        assert_eq!(Frame::decode_extended(&truncated), Err(FrameError::InvalidPacket));
    }

    #[test]
    fn classifies_node_multicast_and_bridged_destinations() {
        let node_mac = mac_for_address(Address::new(0x8e4d_f28b72), NETWORK);
        assert_eq!(Frame::classify_destination(node_mac, NETWORK), FrameDestination::Node(Address::new(0x8e4d_f28b72)));

        assert_eq!(Frame::classify_destination(Mac::new(0x0100_0000_0001), NETWORK), FrameDestination::Multicast);
        assert_eq!(Frame::classify_destination(Mac::new(0xffff_ffff_ffff), NETWORK), FrameDestination::Multicast);

        // A first octet other than the network's marks a bridged device.
        let bridged = Mac::new(0xaabb_ccdd_eeff);
        assert_eq!(Frame::classify_destination(bridged, NETWORK), FrameDestination::Bridged);
    }

    #[test]
    fn rejects_undeliverable_bridged_sources() {
        let local = Address::new(0x0000_0abc_def0);
        let mut frame = sample();
        assert!(frame.is_deliverable(local, NETWORK));

        frame.source = Mac::new(0);
        assert!(!frame.is_deliverable(local, NETWORK));

        frame.source = Mac::new(0x0100_0000_0001);
        assert!(!frame.is_deliverable(local, NETWORK));

        frame.source = mac_for_address(local, NETWORK);
        assert!(!frame.is_deliverable(local, NETWORK));
    }

    #[test]
    fn empty_payloads_are_rejected() {
        let mut frame = sample();
        frame.payload.clear();
        assert_eq!(frame.encode_native(), Err(FrameError::InvalidPacket));
        assert_eq!(frame.encode_extended(0x04, &[]), Err(FrameError::InvalidPacket));
    }

    #[test]
    fn frame_packets_carry_the_expected_verb() {
        let frame = sample();
        let destination = Address::new(0x8e4d_f28b72);
        let local = Address::new(0x0000_0abc_def0);

        let native = build_native_packet(&frame, destination, local).unwrap();
        assert_eq!(native.verb(), Some(Verb::Frame));
        assert_eq!(native.source(), local);
        assert_eq!(native.destination(), destination);

        let extended = build_extended_packet(&frame, destination, local, 0x04, &[]).unwrap();
        assert_eq!(extended.verb(), Some(Verb::ExtFrame));
    }

    fn frame_source(frame: &Frame) -> Address {
        address_for_mac(frame.source, NETWORK)
    }
}
