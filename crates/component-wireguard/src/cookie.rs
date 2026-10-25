//! The `MessageCookieReply` message (type 3) and the two halves that handle it.
//!
//! A responder that is under load answers a handshake whose `mac2` it cannot verify with a
//! cookie reply instead of dropping it, and the sender repeats the handshake with a `mac2`
//! derived from that cookie; calculating the cookie costs the responder one hash per source
//! address rather than a full Diffie-Hellman exchange.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305};
use subtle::ConstantTimeEq;

use crate::crypto::{mac, mac1_key, mac2_key, HASH_SIZE, MAC_SIZE};
use crate::handshake::TYPE_COOKIE_REPLY;

pub const MESSAGE_COOKIE_REPLY_SIZE: usize = 64;
pub const COOKIE_NONCE_SIZE: usize = 24;
/// The sealed cookie as it appears on the wire.
pub const COOKIE_REPLY_COOKIE_SIZE: usize = MAC_SIZE + 16;
/// After this, a cookie secret or a held cookie is stale.
pub const COOKIE_REFRESH_TIME: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageCookieReply {
    /// `Receiver`: the sender index of the handshake being answered.
    pub receiver: u32,
    /// `Nonce`: the XChaCha20 nonce the cookie was sealed under.
    pub nonce: [u8; COOKIE_NONCE_SIZE],
    /// The cookie: a 16-byte keyed hash plus a Poly1305 tag.
    pub cookie: [u8; COOKIE_REPLY_COOKIE_SIZE],
}

impl MessageCookieReply {
    pub fn unmarshal(packet: &[u8]) -> Result<Self> {
        let packet: &[u8; MESSAGE_COOKIE_REPLY_SIZE] =
            packet.try_into().map_err(|_| anyhow!("message length mismatch"))?;
        Ok(Self {
            receiver: u32::from_le_bytes(packet[4..8].try_into().unwrap_or_default()),
            nonce: packet[8..8 + COOKIE_NONCE_SIZE].try_into().map_err(|_| anyhow!("message length mismatch"))?,
            cookie: packet[8 + COOKIE_NONCE_SIZE..].try_into().map_err(|_| anyhow!("message length mismatch"))?,
        })
    }

    #[must_use]
    pub fn marshal(&self) -> [u8; MESSAGE_COOKIE_REPLY_SIZE] {
        let mut packet = [0u8; MESSAGE_COOKIE_REPLY_SIZE];
        packet[0..4].copy_from_slice(&TYPE_COOKIE_REPLY.to_le_bytes());
        packet[4..8].copy_from_slice(&self.receiver.to_le_bytes());
        packet[8..8 + COOKIE_NONCE_SIZE].copy_from_slice(&self.nonce);
        packet[8 + COOKIE_NONCE_SIZE..].copy_from_slice(&self.cookie);
        packet
    }
}

/// the source address as the cookie's key input, in
/// its 4-byte form when IPv4-mapped, so an IPv4-mapped IPv6 peer and an IPv4 peer share a cookie.
#[must_use]
pub fn address_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => {
            address.to_ipv4_mapped().map_or_else(|| address.octets().to_vec(), |address| address.octets().to_vec())
        }
    }
}

/// A MAC mismatch must not be observable byte by byte, and a length mismatch fails closed.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// The responder's half. Its keys derive from the responder's own
/// static public key, which is the key the initiator uses to build `mac1` and `mac2`.
pub struct CookieChecker {
    mac1_key: [u8; HASH_SIZE],
    secret: [u8; HASH_SIZE],
    secret_set: Option<Instant>,
    encryption_key: [u8; HASH_SIZE],
}

impl core::fmt::Debug for CookieChecker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CookieChecker").field("secret_set", &self.secret_set).finish_non_exhaustive()
    }
}

impl CookieChecker {
    #[must_use]
    pub fn new(static_public: &[u8; HASH_SIZE]) -> Self {
        Self {
            mac1_key: mac1_key(static_public),
            secret: [0u8; HASH_SIZE],
            secret_set: None,
            encryption_key: mac2_key(static_public),
        }
    }

    #[must_use]
    pub fn check_mac1(&self, msg: &[u8]) -> bool {
        if msg.len() < 2 * MAC_SIZE {
            return false;
        }
        let (body, macs) = msg.split_at(msg.len() - 2 * MAC_SIZE);
        let Ok(expected) = mac(&self.mac1_key, body) else {
            return false;
        };
        macs.get(..MAC_SIZE).is_some_and(|mac1| constant_time_eq(mac1, &expected))
    }

    /// Verifies `mac2`. Without a secret younger than `COOKIE_REFRESH_TIME`
    /// there is no cookie any `mac2` could have been derived from.
    #[must_use]
    pub fn check_mac2(&self, msg: &[u8], src: &[u8]) -> bool {
        if self.secret_set.is_none_or(|set| set.elapsed() > COOKIE_REFRESH_TIME) || msg.len() < MAC_SIZE {
            return false;
        }
        let Ok(cookie) = mac(&self.secret, src) else {
            return false;
        };
        let (body, mac2) = msg.split_at(msg.len() - MAC_SIZE);
        let Ok(expected) = mac(&cookie, body) else {
            return false;
        };
        constant_time_eq(mac2, &expected)
    }

    /// Builds a cookie reply, including its lazy secret rotation.
    pub fn create_reply(&mut self, msg: &[u8], receiver: u32, src: &[u8]) -> Result<MessageCookieReply> {
        if self.secret_set.is_none_or(|set| set.elapsed() > COOKIE_REFRESH_TIME) {
            self.secret = rand::random();
            self.secret_set = Some(Instant::now());
        }
        if msg.len() < 2 * MAC_SIZE {
            bail!("message length mismatch");
        }
        let cookie = mac(&self.secret, src)?;

        let mac2_offset = msg.len() - MAC_SIZE;
        let mac1_offset = mac2_offset - MAC_SIZE;
        let nonce: [u8; COOKIE_NONCE_SIZE] = rand::random();
        let cipher = XChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|_| anyhow!("cookie encryption key is not {HASH_SIZE} bytes"))?;
        let cookie = cipher
            .encrypt(
                (&nonce).into(),
                Payload { msg: &cookie, aad: msg.get(mac1_offset..mac2_offset).unwrap_or_default() },
            )
            .map_err(|_| anyhow!("sealing failed"))?;
        Ok(MessageCookieReply {
            receiver,
            nonce,
            cookie: cookie.try_into().map_err(|_| anyhow!("sealed cookie must be {COOKIE_REPLY_COOKIE_SIZE} bytes"))?,
        })
    }
}

/// The sender's half. Its keys derive from the *peer's* static
/// public key, so the peer's checker — which derives them from its own — agrees.
pub struct CookieGenerator {
    mac1_key: [u8; HASH_SIZE],
    encryption_key: [u8; HASH_SIZE],
    cookie: [u8; MAC_SIZE],
    cookie_set: Option<Instant>,
    has_last_mac1: bool,
    last_mac1: [u8; MAC_SIZE],
}

impl core::fmt::Debug for CookieGenerator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CookieGenerator")
            .field("has_last_mac1", &self.has_last_mac1)
            .field("cookie_set", &self.cookie_set)
            .finish_non_exhaustive()
    }
}

impl CookieGenerator {
    #[must_use]
    pub fn new(peer_public: &[u8; HASH_SIZE]) -> Self {
        Self {
            mac1_key: mac1_key(peer_public),
            encryption_key: mac2_key(peer_public),
            cookie: [0u8; MAC_SIZE],
            cookie_set: None,
            has_last_mac1: false,
            last_mac1: [0u8; MAC_SIZE],
        }
    }

    /// `mac1` always, `mac2` only while a cookie is held.
    pub fn add_macs(&mut self, msg: &mut [u8]) {
        if msg.len() < 2 * MAC_SIZE {
            return;
        }
        let mac2_offset = msg.len() - MAC_SIZE;
        let mac1_offset = mac2_offset - MAC_SIZE;
        let Ok(mac1) = mac(&self.mac1_key, msg.get(..mac1_offset).unwrap_or_default()) else {
            return;
        };
        if let Some(mac1_slot) = msg.get_mut(mac1_offset..mac2_offset) {
            mac1_slot.copy_from_slice(&mac1);
        }
        self.last_mac1 = mac1;
        self.has_last_mac1 = true;

        if self.cookie_set.is_none_or(|set| set.elapsed() > COOKIE_REFRESH_TIME) {
            return;
        }
        let Ok(mac2) = mac(&self.cookie, msg.get(..mac2_offset).unwrap_or_default()) else {
            return;
        };
        if let Some(mac2_slot) = msg.get_mut(mac2_offset..) {
            mac2_slot.copy_from_slice(&mac2);
        }
    }

    /// Consumes a cookie reply; the reply is authenticated with the `mac1` of
    /// the last message this generator stamped.
    pub fn consume_reply(&mut self, reply: &MessageCookieReply) -> bool {
        if !self.has_last_mac1 {
            return false;
        }
        let Ok(cipher) = XChaCha20Poly1305::new_from_slice(&self.encryption_key) else {
            return false;
        };
        match cipher.decrypt((&reply.nonce).into(), Payload { msg: &reply.cookie, aad: &self.last_mac1 }) {
            Ok(cookie) if cookie.len() == MAC_SIZE => {
                self.cookie.copy_from_slice(&cookie);
                self.cookie_set = Some(Instant::now());
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::StaticKey;

    /// The source address a reply is bound to, as a real UDP source would supply it.
    const SRC: [u8; 4] = [192, 0, 2, 1];

    fn handshake_packet(sender: u32) -> Vec<u8> {
        let mut packet = vec![0u8; 148];
        packet[0..4].copy_from_slice(&1u32.to_le_bytes());
        packet[4..8].copy_from_slice(&sender.to_le_bytes());
        packet
    }

    fn hex(input: &str) -> Vec<u8> {
        (0..input.len()).step_by(2).map(|i| u8::from_str_radix(&input[i..i + 2], 16).expect("hex literal")).collect()
    }

    fn pair() -> (CookieChecker, CookieGenerator) {
        let responder = StaticKey::from_bytes([0x22; 32]);
        (CookieChecker::new(responder.public_key().as_bytes()), CookieGenerator::new(responder.public_key().as_bytes()))
    }

    /// draft-irtf-cfrg-xchacha-03 A.3, the construction a cookie reply seals with.
    #[test]
    fn xchacha20_poly1305_matches_the_draft_vector() {
        let key: [u8; 32] = (0x80u8..0xa0).collect::<Vec<u8>>().try_into().expect("32 bytes");
        let nonce: [u8; COOKIE_NONCE_SIZE] = (0x40u8..0x58).collect::<Vec<u8>>().try_into().expect("24 bytes");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
        let sealed = cipher.encrypt((&nonce).into(), Payload { msg: plaintext, aad: &aad }).expect("seal");
        assert_eq!(
            sealed,
            hex(concat!(
                "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
                "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
                "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
                "21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780a",
                "cf49"
            ))
        );
    }

    #[test]
    fn a_cookie_reply_lets_the_sender_use_mac2() {
        let (mut checker, mut generator) = pair();
        let mut initiation = handshake_packet(7);
        generator.add_macs(&mut initiation);
        assert!(checker.check_mac1(&initiation));
        assert_eq!(&initiation[132..], &[0u8; MAC_SIZE], "mac2 stays zero until a cookie arrives");
        assert!(!checker.check_mac2(&initiation, &SRC), "no cookie has been handed out yet");

        let reply = checker.create_reply(&initiation, 7, &SRC).expect("cookie reply");
        assert_eq!(reply.receiver, 7);
        assert_eq!(&reply.marshal()[0..4], &TYPE_COOKIE_REPLY.to_le_bytes());
        assert_eq!(MessageCookieReply::unmarshal(&reply.marshal()).expect("round trip"), reply);
        assert!(generator.consume_reply(&reply));

        let mut retry = handshake_packet(8);
        generator.add_macs(&mut retry);
        assert!(checker.check_mac1(&retry));
        assert!(checker.check_mac2(&retry, &SRC), "the retry must carry a cookie-derived mac2");
        assert_ne!(&retry[132..], &[0u8; MAC_SIZE]);
    }

    #[test]
    fn mac1_is_rejected_whatever_byte_differs() {
        let (checker, mut generator) = pair();
        let mut initiation = handshake_packet(7);
        generator.add_macs(&mut initiation);
        assert!(checker.check_mac1(&initiation));

        let first = initiation.len() - 2 * MAC_SIZE;
        for byte in first..first + MAC_SIZE {
            let mut tampered = initiation.clone();
            tampered[byte] ^= 1;
            assert!(!checker.check_mac1(&tampered), "a mac1 wrong in byte {byte} must not verify");
        }
    }

    #[test]
    fn mac2_is_rejected_whatever_byte_differs() {
        let (mut checker, mut generator) = pair();
        let mut initiation = handshake_packet(7);
        generator.add_macs(&mut initiation);
        let reply = checker.create_reply(&initiation, 7, &SRC).expect("cookie reply");
        assert!(generator.consume_reply(&reply));

        let mut retry = handshake_packet(8);
        generator.add_macs(&mut retry);
        assert!(checker.check_mac2(&retry, &SRC));

        for byte in retry.len() - MAC_SIZE..retry.len() {
            let mut tampered = retry.clone();
            tampered[byte] ^= 1;
            assert!(!checker.check_mac2(&tampered, &SRC), "a mac2 wrong in byte {byte} must not verify");
        }
    }

    #[test]
    fn a_mac_comparison_fails_closed_on_a_length_mismatch() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[2, 2, 3], &[1, 2, 3]));

        let (checker, mut generator) = pair();
        let mut initiation = handshake_packet(7);
        generator.add_macs(&mut initiation);
        assert!(!checker.check_mac1(&initiation[..2 * MAC_SIZE - 1]), "a message too short for its macs must fail");
        assert!(!checker.check_mac2(&initiation[..MAC_SIZE - 1], &SRC), "a message too short for a mac2 must fail");
    }

    #[test]
    fn a_cookie_is_bound_to_the_source_address() {
        let (mut checker, mut generator) = pair();
        let mut initiation = handshake_packet(7);
        generator.add_macs(&mut initiation);
        let reply = checker.create_reply(&initiation, 7, &SRC).expect("cookie reply");
        assert!(generator.consume_reply(&reply));

        let mut retry = handshake_packet(8);
        generator.add_macs(&mut retry);
        assert!(checker.check_mac2(&retry, &SRC));
        assert!(!checker.check_mac2(&retry, &[198, 51, 100, 2]), "another source address derives another cookie");
    }

    #[test]
    fn a_tampered_cookie_reply_is_rejected() {
        let (mut checker, mut generator) = pair();
        let mut initiation = handshake_packet(7);
        generator.add_macs(&mut initiation);

        let mut reply = checker.create_reply(&initiation, 7, &SRC).expect("cookie reply");
        reply.cookie[0] ^= 1;
        assert!(!generator.consume_reply(&reply), "the ciphertext must authenticate");

        let mut reply = checker.create_reply(&initiation, 7, &SRC).expect("cookie reply");
        reply.nonce[0] ^= 1;
        assert!(!generator.consume_reply(&reply), "the nonce must match too");
    }

    #[test]
    fn a_cookie_reply_is_useless_without_a_mac1_to_authenticate_it() {
        let (mut checker, _) = pair();
        let mut sender = handshake_packet(7);
        sender[132..].copy_from_slice(&[0x7f; MAC_SIZE]);
        let reply = checker.create_reply(&sender, 7, &SRC).expect("cookie reply");
        let mut fresh = CookieGenerator::new(StaticKey::from_bytes([0x22; 32]).public_key().as_bytes());
        assert!(
            !fresh.consume_reply(&reply),
            "a generator that never stamped a message has no mac1 to open the reply with"
        );
    }

    #[test]
    fn address_bytes_collapses_ipv4_mapped_addresses() {
        assert_eq!(address_bytes("192.0.2.1".parse().expect("ipv4")), vec![192, 0, 2, 1]);
        assert_eq!(address_bytes("::ffff:192.0.2.1".parse().expect("mapped")), vec![192, 0, 2, 1]);
        assert_eq!(address_bytes("2001:db8::1".parse().expect("ipv6")).len(), 16);
    }
}
