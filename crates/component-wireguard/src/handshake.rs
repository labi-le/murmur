//! The initiation and response messages and the noise handshake. This project's own
//! configuration only ever initiates, but a device with a listening bind answers too.
//!
//! The message constructors leave `mac1`/`mac2` zero; `cookie::CookieGenerator` stamps them once
//! the peer sends the packet.

use anyhow::{anyhow, bail, Result};

use crate::crypto::{self, initial_chain_key, initial_hash, kdf2, kdf3, mix_hash, mix_key, Aead, HASH_SIZE};
use crate::keys::{PresharedKey, PublicKey, StaticKey};

pub const MESSAGE_INITIATION_SIZE: usize = 148;
pub const MESSAGE_RESPONSE_SIZE: usize = 92;
pub const MESSAGE_TRANSPORT_HEADER_SIZE: usize = 16;
/// The transport message size.
pub const MESSAGE_TRANSPORT_SIZE: usize = MESSAGE_TRANSPORT_HEADER_SIZE + crypto::TAG_SIZE;
pub const MESSAGE_MIN_SIZE: usize = MESSAGE_TRANSPORT_SIZE;
pub const MESSAGE_MAX_SIZE: usize = u16::MAX as usize;
pub const MESSAGE_CONTENT_MAX_SIZE: usize = MESSAGE_MAX_SIZE - MESSAGE_TRANSPORT_SIZE;
pub const TRANSPORT_OFFSET_RECEIVER: usize = 4;
pub const TRANSPORT_OFFSET_COUNTER: usize = 8;
pub const TRANSPORT_OFFSET_CONTENT: usize = 16;
pub const TYPE_INITIATION: u32 = 1;
pub const TYPE_RESPONSE: u32 = 2;
pub const TYPE_COOKIE_REPLY: u32 = 3;
pub const TYPE_TRANSPORT: u32 = 4;

const ZERO_NONCE: [u8; crypto::NONCE_SIZE] = [0u8; crypto::NONCE_SIZE];

/// The fixed-width wire field at `range`; a message that stops short of a field it must carry is
/// rejected rather than read as zeroes.
fn field<const N: usize>(packet: &[u8], range: core::ops::Range<usize>) -> Result<[u8; N]> {
    packet.get(range).and_then(|bytes| bytes.try_into().ok()).ok_or_else(|| anyhow!("message length mismatch"))
}

/// The output of a symmetric-session handoff: the two transport keys plus the peer's index.
pub struct Session {
    pub send_key: [u8; crypto::KEY_SIZE],
    pub recv_key: [u8; crypto::KEY_SIZE],
    pub remote_index: u32,
    pub local_index: u32,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("remote_index", &self.remote_index)
            .field("local_index", &self.local_index)
            .finish_non_exhaustive()
    }
}

/// The initiator state, kept between sending an initiation and
/// receiving the matching response.
pub struct Initiator {
    hash: [u8; HASH_SIZE],
    chain_key: [u8; HASH_SIZE],
    ephemeral: StaticKey,
    local_index: u32,
}

impl core::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Initiator").field("local_index", &self.local_index).finish_non_exhaustive()
    }
}

impl Initiator {
    pub fn create_message_initiation(
        static_key: &StaticKey,
        remote_static: &PublicKey,
        local_index: u32,
    ) -> Result<(Self, [u8; MESSAGE_INITIATION_SIZE])> {
        let mut hash = mix_hash(&initial_hash(), remote_static.as_bytes());
        let mut chain_key = initial_chain_key();

        let ephemeral = StaticKey::random();
        let ephemeral_public = ephemeral.public_key();
        chain_key = mix_key(&chain_key, ephemeral_public.as_bytes());
        hash = mix_hash(&hash, ephemeral_public.as_bytes());

        let (next_chain_key, key) = kdf2(&chain_key, &ephemeral.diffie_hellman(remote_static)?);
        chain_key = next_chain_key;
        let encrypted_static = Aead::new(&key).seal(&ZERO_NONCE, &hash, static_key.public_key().as_bytes())?;
        if encrypted_static.len() != 48 {
            bail!("encrypted static key must be 48 bytes, got {}", encrypted_static.len());
        }
        hash = mix_hash(&hash, &encrypted_static);
        let timestamp = crypto::tai64n_now(std::time::SystemTime::now());
        let (chain_key, key) = kdf2(&chain_key, &static_key.diffie_hellman(remote_static)?);
        let encrypted_timestamp = Aead::new(&key).seal(&ZERO_NONCE, &hash, &timestamp)?;

        if encrypted_timestamp.len() != 28 {
            bail!("encrypted timestamp must be 28 bytes, got {}", encrypted_timestamp.len());
        }
        hash = mix_hash(&hash, &encrypted_timestamp);

        let mut packet = [0u8; MESSAGE_INITIATION_SIZE];
        packet[0..4].copy_from_slice(&TYPE_INITIATION.to_le_bytes());
        packet[4..8].copy_from_slice(&local_index.to_le_bytes());
        packet[8..40].copy_from_slice(ephemeral_public.as_bytes());
        packet[40..88].copy_from_slice(&encrypted_static);
        packet[88..116].copy_from_slice(&encrypted_timestamp);

        Ok((Self { hash, chain_key, ephemeral, local_index }, packet))
    }

    /// Consumes a handshake response and derives the session.
    pub fn consume_message_response(
        &self,
        static_key: &StaticKey,
        preshared_key: &PresharedKey,
        packet: &[u8],
    ) -> Result<Session> {
        if packet.len() != MESSAGE_RESPONSE_SIZE {
            bail!("message length mismatch");
        }
        let message_type = u32::from_le_bytes(field::<4>(packet, 0..4)?);
        if message_type != TYPE_RESPONSE {
            bail!("unexpected message type {message_type}");
        }

        let remote_ephemeral = PublicKey::from_bytes(field::<32>(packet, 12..44)?);
        let hash = mix_hash(&self.hash, remote_ephemeral.as_bytes());
        let mut chain_key = mix_key(&self.chain_key, remote_ephemeral.as_bytes());
        chain_key = mix_key(&chain_key, &self.ephemeral.diffie_hellman(&remote_ephemeral)?);
        chain_key = mix_key(&chain_key, &static_key.diffie_hellman(&remote_ephemeral)?);

        let (chain_key, tau, key) = kdf3(&chain_key, preshared_key.as_bytes());
        let hash = mix_hash(&hash, &tau);
        Aead::new(&key).open(&ZERO_NONCE, &hash, &field::<16>(packet, 44..60)?)?;

        let (send_key, recv_key) = kdf2(&chain_key, &[]);
        Ok(Session {
            send_key,
            recv_key,
            remote_index: u32::from_le_bytes(field::<4>(packet, 4..8)?),
            local_index: self.local_index,
        })
    }
}

/// Consumes an initiation and builds the response. This crate's own configuration
/// only ever initiates, but a device with a listening bind can be initiated at.
pub mod responder {
    use super::{
        anyhow, bail, field, initial_chain_key, initial_hash, kdf2, kdf3, mix_hash, mix_key, Aead, PresharedKey,
        PublicKey, Result, Session, StaticKey, HASH_SIZE, MESSAGE_INITIATION_SIZE, MESSAGE_RESPONSE_SIZE,
        TYPE_RESPONSE, ZERO_NONCE,
    };

    /// The responder half of `Noise_IKpsk2`.
    pub struct Responder {
        hash: [u8; HASH_SIZE],
        chain_key: [u8; HASH_SIZE],
        remote_static: PublicKey,
        remote_ephemeral: PublicKey,
        remote_index: u32,
        preshared_key: PresharedKey,
        /// The last TAI64N stamp seen; a repeated or older one is a replay.
        last_timestamp: [u8; 12],
    }

    impl core::fmt::Debug for Responder {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Responder").field("remote_index", &self.remote_index).finish_non_exhaustive()
        }
    }

    impl Responder {
        /// The zero value of a responder, awaiting the first initiation.
        #[must_use]
        pub fn new() -> Self {
            Self {
                hash: [0; HASH_SIZE],
                chain_key: [0; HASH_SIZE],
                remote_static: PublicKey::from_bytes([0u8; 32]),
                remote_ephemeral: PublicKey::from_bytes([0u8; 32]),
                remote_index: 0,
                preshared_key: PresharedKey::zeroed(),
                last_timestamp: [0; 12],
            }
        }

        /// Message-initiation consumption up to the peer lookup: the decrypted static key is
        /// what names the peer, and the peer's pre-shared key is what the rest of the
        /// transcript needs.
        pub fn consume_static(&mut self, static_key: &StaticKey, packet: &[u8]) -> Result<PublicKey> {
            if packet.len() != MESSAGE_INITIATION_SIZE {
                bail!("message length mismatch");
            }
            let initiator_ephemeral = PublicKey::from_bytes(field::<32>(packet, 8..40)?);

            let mut hash = mix_hash(&initial_hash(), static_key.public_key().as_bytes());
            let mut chain_key = initial_chain_key();
            hash = mix_hash(&hash, initiator_ephemeral.as_bytes());
            chain_key = mix_key(&chain_key, initiator_ephemeral.as_bytes());

            let (next_chain_key, key) = kdf2(&chain_key, &static_key.diffie_hellman(&initiator_ephemeral)?);
            chain_key = next_chain_key;
            let remote_static = Aead::new(&key).open(&ZERO_NONCE, &hash, &field::<48>(packet, 40..88)?)?;
            let remote_static: [u8; 32] =
                remote_static.try_into().map_err(|_| anyhow!("decrypted static key is not 32 bytes"))?;
            hash = mix_hash(&hash, &field::<48>(packet, 40..88)?);

            self.hash = hash;
            self.chain_key = chain_key;
            self.remote_static = PublicKey::from_bytes(remote_static);
            self.remote_ephemeral = initiator_ephemeral;
            self.remote_index = u32::from_le_bytes(field::<4>(packet, 4..8)?);
            Ok(self.remote_static)
        }

        /// The hash and chain key are recomputed from every initiation, but one handshake is kept
        /// per peer, so the replay stamp is the only state that survives a message:
        /// `consume_static` rebuilds the transcript on a fresh instance and this carries the stamp
        /// from the peer's previous one.
        pub fn carry_replay_stamp(&mut self, previous: Option<&Self>) {
            if let Some(previous) = previous {
                self.last_timestamp = previous.last_timestamp;
            }
        }

        /// The timestamp half of message-initiation consumption, which needs the peer's
        /// pre-shared key and rejects a stamp that is not strictly newer than the last
        /// accepted one.
        pub fn consume_timestamp(
            &mut self,
            static_key: &StaticKey,
            preshared_key: &PresharedKey,
            packet: &[u8],
        ) -> Result<()> {
            let (next_chain_key, key) = kdf2(&self.chain_key, &static_key.diffie_hellman(&self.remote_static)?);
            let timestamp = Aead::new(&key).open(&ZERO_NONCE, &self.hash, &field::<28>(packet, 88..116)?)?;
            if timestamp.as_slice() <= self.last_timestamp.as_slice() {
                bail!("handshake rejected: no recent enough timestamp");
            }
            self.last_timestamp.copy_from_slice(&timestamp);
            self.chain_key = next_chain_key;
            self.hash = mix_hash(&self.hash, &field::<28>(packet, 88..116)?);
            self.preshared_key = *preshared_key;
            Ok(())
        }

        pub fn create_message_response(&self, local_index: u32) -> Result<([u8; MESSAGE_RESPONSE_SIZE], Session)> {
            let local_ephemeral = StaticKey::random();
            let ephemeral_public = local_ephemeral.public_key();

            let hash = mix_hash(&self.hash, ephemeral_public.as_bytes());
            let mut chain_key = mix_key(&self.chain_key, ephemeral_public.as_bytes());
            chain_key = mix_key(&chain_key, &local_ephemeral.diffie_hellman(&self.remote_ephemeral)?);
            chain_key = mix_key(&chain_key, &local_ephemeral.diffie_hellman(&self.remote_static)?);

            let (chain_key, tau, key) = kdf3(&chain_key, self.preshared_key.as_bytes());
            let hash = mix_hash(&hash, &tau);
            let empty = Aead::new(&key).seal(&ZERO_NONCE, &hash, &[])?;
            if empty.len() != 16 {
                bail!("encrypted nothing must be 16 bytes, got {}", empty.len());
            }

            let mut packet = [0u8; MESSAGE_RESPONSE_SIZE];
            packet[0..4].copy_from_slice(&TYPE_RESPONSE.to_le_bytes());
            packet[4..8].copy_from_slice(&local_index.to_le_bytes());
            packet[8..12].copy_from_slice(&self.remote_index.to_le_bytes());
            packet[12..44].copy_from_slice(ephemeral_public.as_bytes());
            packet[44..60].copy_from_slice(&empty);

            let (recv_key, send_key) = kdf2(&chain_key, &[]);
            Ok((packet, Session { send_key, recv_key, remote_index: self.remote_index, local_index }))
        }
    }

    impl Default for Responder {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::responder::Responder;
    use super::*;
    use crate::cookie::{CookieChecker, CookieGenerator};

    /// Drives one full exchange and returns both sides' state for the assertions to poke at.
    /// The MACs come from each side's cookie generator, added when the initiation and the
    /// response are sent.
    fn exchange(
        psk: &PresharedKey,
    ) -> (StaticKey, StaticKey, [u8; MESSAGE_INITIATION_SIZE], Initiator, [u8; MESSAGE_RESPONSE_SIZE], Session) {
        let initiator_static = StaticKey::from_bytes([1u8; 32]);
        let responder_static = StaticKey::from_bytes([2u8; 32]);
        let (initiator, mut initiation) =
            Initiator::create_message_initiation(&initiator_static, &responder_static.public_key(), 7)
                .expect("initiation");
        CookieGenerator::new(responder_static.public_key().as_bytes()).add_macs(&mut initiation);
        let mut responder = Responder::new();
        assert_eq!(
            responder.consume_static(&responder_static, &initiation).expect("consume static"),
            initiator_static.public_key()
        );
        responder.consume_timestamp(&responder_static, psk, &initiation).expect("consume timestamp");
        let (mut response, responder_session) = responder.create_message_response(9).expect("response");
        CookieGenerator::new(initiator_static.public_key().as_bytes()).add_macs(&mut response);
        (initiator_static, responder_static, initiation, initiator, response, responder_session)
    }

    #[test]
    fn handshake_completes_and_both_sides_derive_the_same_keys() {
        for psk in [PresharedKey::zeroed(), PresharedKey::from_bytes([0x5a; 32])] {
            let (initiator_static, responder_static, initiation, initiator, response, responder_session) =
                exchange(&psk);
            assert!(CookieChecker::new(responder_static.public_key().as_bytes()).check_mac1(&initiation));
            assert!(CookieChecker::new(initiator_static.public_key().as_bytes()).check_mac1(&response));

            let initiator_session =
                initiator.consume_message_response(&initiator_static, &psk, &response).expect("consume response");
            assert_eq!(initiator_session.send_key, responder_session.recv_key);
            assert_eq!(initiator_session.recv_key, responder_session.send_key);
            assert_ne!(initiator_session.send_key, initiator_session.recv_key);
            assert_eq!(initiator_session.remote_index, 9);
            assert_eq!(responder_session.remote_index, 7);
        }
    }

    #[test]
    fn a_tampered_response_fails_authentication() {
        let psk = PresharedKey::zeroed();
        let (initiator_static, _, _, initiator, mut response, _) = exchange(&psk);
        response[12] ^= 1;
        assert!(initiator.consume_message_response(&initiator_static, &psk, &response).is_err());
    }

    #[test]
    fn a_mismatched_preshared_key_fails_authentication() {
        let psk = PresharedKey::from_bytes([0x11; 32]);
        let (initiator_static, responder_static, initiation, initiator, _, _) = exchange(&psk);
        let mut responder = Responder::new();
        responder.consume_static(&responder_static, &initiation).expect("consume static");
        responder.consume_timestamp(&responder_static, &psk, &initiation).expect("consume timestamp");
        let (response, _) = responder.create_message_response(9).expect("response");
        assert!(initiator.consume_message_response(&initiator_static, &PresharedKey::zeroed(), &response).is_err());
    }

    #[test]
    fn a_replayed_initiation_is_rejected() {
        let responder_static = StaticKey::from_bytes([2u8; 32]);
        let psk = PresharedKey::zeroed();
        let (_, _, initiation, _, _, _) = exchange(&psk);

        let mut responder = Responder::new();
        for attempt in 0..2 {
            responder.consume_static(&responder_static, &initiation).expect("consume static");
            let accepted = responder.consume_timestamp(&responder_static, &psk, &initiation).is_ok();
            assert_eq!(accepted, attempt == 0, "attempt {attempt}");
        }
    }

    #[test]
    fn the_macs_reject_a_tampered_handshake() {
        let initiator_static = StaticKey::from_bytes([3u8; 32]);
        let responder_static = StaticKey::from_bytes([4u8; 32]);
        let (_, mut initiation) =
            Initiator::create_message_initiation(&initiator_static, &responder_static.public_key(), 1)
                .expect("initiation");
        let checker = CookieChecker::new(responder_static.public_key().as_bytes());
        assert_eq!(&initiation[132..], &[0u8; 16], "a message leaves with mac1 only");

        let mut generator = CookieGenerator::new(responder_static.public_key().as_bytes());
        generator.add_macs(&mut initiation);
        assert!(checker.check_mac1(&initiation));
        initiation[50] ^= 1;
        assert!(!checker.check_mac1(&initiation));
    }
}
