//! ZeroTier wire packets: the common header, the Salsa20/Poly1305 and
//! AES-GMAC-SIV armor suites, and the protocol-13 extended armor.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes256;
use poly1305::Poly1305;
use rand::RngCore;

use crate::address::Address;
use crate::identity::{agree_ephemeral, Identity, PUBLIC_KEY_SIZE};
use crate::ztcrypto::gmac_siv::GmacSivKeys;
use crate::ztcrypto::salsa::xor_key_stream_in_place;

pub const MIN_PHYSICAL_MTU: usize = 510;
pub const DEFAULT_PHYSICAL_MTU: usize = 1432;
pub const MAX_PHYSICAL_MTU: usize = 10_324;

pub const IV_OFFSET: usize = 0;
pub const DEST_OFFSET: usize = 8;
pub const SOURCE_OFFSET: usize = 13;
pub const FLAGS_OFFSET: usize = 18;
pub const MAC_OFFSET: usize = 19;
pub const VERB_OFFSET: usize = 27;
pub const PAYLOAD_OFFSET: usize = 28;
pub const MIN_PACKET_SIZE: usize = PAYLOAD_OFFSET;
pub const MAX_PACKET_SIZE: usize = 7 * DEFAULT_PHYSICAL_MTU;
/// Length of the ephemeral public key appended by protocol-13 armor.
pub const EXTENDED_ARMOR_KEY_SIZE: usize = 32;

pub const FLAG_EXTENDED_ARMOR: u8 = 0x80;
pub const FLAG_FRAGMENTED: u8 = 0x40;
pub const VERB_COMPRESSED: u8 = 0x80;

/// Reports malformed, truncated, or oversized packet data, and packet ciphers
/// outside the implemented wire protocol suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("invalid ZeroTier packet")]
    Invalid,
    #[error("unsupported ZeroTier cipher")]
    UnsupportedCipher,
}

/// The armor or encryption scheme encoded in a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// Cleartext payload authenticated with the legacy agreement key.
    C25519Poly1305None,
    /// Payload encrypted with Salsa20/12 and authenticated with Poly1305.
    C25519Poly1305Salsa2012,
    /// A configured trusted physical path in place of ordinary armor.
    TrustedPath,
    /// Payload protected by the protocol-12 AES-GMAC-SIV construction.
    AesGmacSiv,
}

impl Cipher {
    fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::C25519Poly1305None),
            1 => Some(Self::C25519Poly1305Salsa2012),
            2 => Some(Self::TrustedPath),
            3 => Some(Self::AesGmacSiv),
            _ => None,
        }
    }

    fn bits(self) -> u8 {
        match self {
            Self::C25519Poly1305None => 0,
            Self::C25519Poly1305Salsa2012 => 1,
            Self::TrustedPath => 2,
            Self::AesGmacSiv => 3,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::C25519Poly1305None => "c25519-poly1305-none",
            Self::C25519Poly1305Salsa2012 => "c25519-poly1305-salsa20-12",
            Self::TrustedPath => "trusted-path",
            Self::AesGmacSiv => "aes-gmac-siv",
        }
    }
}

/// The operation a packet carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Nop,
    Hello,
    Error,
    Ok,
    Whois,
    Rendezvous,
    Frame,
    ExtFrame,
    Echo,
    MulticastLike,
    NetworkCredentials,
    NetworkConfigRequest,
    NetworkConfig,
    MulticastGather,
    MulticastFrame,
    PushDirectPaths,
    Ack,
    QosMeasurement,
    UserMessage,
    RemoteTrace,
    PathNegotiation,
}

impl Verb {
    fn from_bits(bits: u8) -> Option<Self> {
        Some(match bits {
            0x00 => Self::Nop,
            0x01 => Self::Hello,
            0x02 => Self::Error,
            0x03 => Self::Ok,
            0x04 => Self::Whois,
            0x05 => Self::Rendezvous,
            0x06 => Self::Frame,
            0x07 => Self::ExtFrame,
            0x08 => Self::Echo,
            0x09 => Self::MulticastLike,
            0x0a => Self::NetworkCredentials,
            0x0b => Self::NetworkConfigRequest,
            0x0c => Self::NetworkConfig,
            0x0d => Self::MulticastGather,
            0x0e => Self::MulticastFrame,
            0x10 => Self::PushDirectPaths,
            0x12 => Self::Ack,
            0x13 => Self::QosMeasurement,
            0x14 => Self::UserMessage,
            0x15 => Self::RemoteTrace,
            0x16 => Self::PathNegotiation,
            _ => return None,
        })
    }

    #[must_use]
    pub fn bits(self) -> u8 {
        match self {
            Self::Nop => 0x00,
            Self::Hello => 0x01,
            Self::Error => 0x02,
            Self::Ok => 0x03,
            Self::Whois => 0x04,
            Self::Rendezvous => 0x05,
            Self::Frame => 0x06,
            Self::ExtFrame => 0x07,
            Self::Echo => 0x08,
            Self::MulticastLike => 0x09,
            Self::NetworkCredentials => 0x0a,
            Self::NetworkConfigRequest => 0x0b,
            Self::NetworkConfig => 0x0c,
            Self::MulticastGather => 0x0d,
            Self::MulticastFrame => 0x0e,
            Self::PushDirectPaths => 0x10,
            Self::Ack => 0x12,
            Self::QosMeasurement => 0x13,
            Self::UserMessage => 0x14,
            Self::RemoteTrace => 0x15,
            Self::PathNegotiation => 0x16,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Nop => "nop",
            Self::Hello => "hello",
            Self::Error => "error",
            Self::Ok => "ok",
            Self::Whois => "whois",
            Self::Rendezvous => "rendezvous",
            Self::Frame => "frame",
            Self::ExtFrame => "ext-frame",
            Self::Echo => "echo",
            Self::MulticastLike => "multicast-like",
            Self::NetworkCredentials => "network-credentials",
            Self::NetworkConfigRequest => "network-config-request",
            Self::NetworkConfig => "network-config",
            Self::MulticastGather => "multicast-gather",
            Self::MulticastFrame => "multicast-frame",
            Self::PushDirectPaths => "push-direct-paths",
            Self::Ack => "ack",
            Self::QosMeasurement => "qos-measurement",
            Self::UserMessage => "user-message",
            Self::RemoteTrace => "remote-trace",
            Self::PathNegotiation => "path-negotiation",
        }
    }
}

/// A ZeroTier wire packet. Multi-byte verb fields are big endian; the IV and
/// MAC fields are opaque bytes owned by the armor suites.
#[derive(Debug, Clone)]
pub struct Packet {
    data: Vec<u8>,
    /// Retained after the wire buffer is handed to a transport, so a request's
    /// ID survives for deduplication bookkeeping.
    sent_packet_id: u64,
    /// Append errors are sticky so a caller cannot ignore one and then transmit
    /// a truncated packet.
    err: bool,
}

impl Packet {
    /// Creates an unarmored packet with a random IV.
    pub fn new(destination: Address, source: Address, verb: Verb) -> Result<Self, PacketError> {
        Self::with_payload_capacity(destination, source, verb, 0)
    }

    /// Creates a packet with exact append storage for a known verb payload.
    pub fn with_payload_capacity(
        destination: Address,
        source: Address,
        verb: Verb,
        payload_capacity: usize,
    ) -> Result<Self, PacketError> {
        if payload_capacity > MAX_PACKET_SIZE - MIN_PACKET_SIZE {
            return Err(PacketError::Invalid);
        }
        let mut data = Vec::with_capacity(MIN_PACKET_SIZE + payload_capacity);
        data.resize(MIN_PACKET_SIZE, 0);
        rand::rng().fill_bytes(field_mut(&mut data, IV_OFFSET, DEST_OFFSET));
        field_mut(&mut data, DEST_OFFSET, SOURCE_OFFSET).copy_from_slice(&destination.bytes());
        field_mut(&mut data, SOURCE_OFFSET, FLAGS_OFFSET).copy_from_slice(&source.bytes());
        set_byte_at(&mut data, VERB_OFFSET, verb.bits());
        Ok(Self { data, sent_packet_id: 0, err: false })
    }

    /// Copies and validates the common bounds of one wire packet.
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < MIN_PACKET_SIZE || data.len() > MAX_PACKET_SIZE {
            return Err(PacketError::Invalid);
        }
        Ok(Self { data: data.to_vec(), sent_packet_id: 0, err: false })
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Whether a previous append or armor step failed.
    #[must_use]
    pub fn err(&self) -> bool {
        self.err
    }

    fn fail(&mut self) -> PacketError {
        self.err = true;
        PacketError::Invalid
    }

    /// Extends the packet, recording an oversized-packet failure.
    pub fn append(&mut self, data: &[u8]) -> Result<(), PacketError> {
        if self.err {
            return Err(PacketError::Invalid);
        }
        if self.data.len() + data.len() > MAX_PACKET_SIZE {
            return Err(self.fail());
        }
        self.data.extend_from_slice(data);
        Ok(())
    }

    pub fn append_u8(&mut self, value: u8) -> Result<(), PacketError> {
        self.append(&[value])
    }

    pub fn append_u16(&mut self, value: u16) -> Result<(), PacketError> {
        self.append(&value.to_be_bytes())
    }

    pub fn append_u32(&mut self, value: u32) -> Result<(), PacketError> {
        self.append(&value.to_be_bytes())
    }

    pub fn append_u64(&mut self, value: u64) -> Result<(), PacketError> {
        self.append(&value.to_be_bytes())
    }

    #[must_use]
    pub fn destination(&self) -> Address {
        Address::from_bytes(field(&self.data, DEST_OFFSET, SOURCE_OFFSET)).unwrap_or_default()
    }

    #[must_use]
    pub fn source(&self) -> Address {
        Address::from_bytes(field(&self.data, SOURCE_OFFSET, FLAGS_OFFSET)).unwrap_or_default()
    }

    #[must_use]
    pub fn cipher(&self) -> Option<Cipher> {
        Cipher::from_bits((byte_at(&self.data, FLAGS_OFFSET) & 0x38) >> 3)
    }

    pub fn set_cipher(&mut self, cipher: Cipher) {
        let flags = byte_at(&self.data, FLAGS_OFFSET);
        set_byte_at(&mut self.data, FLAGS_OFFSET, (flags & 0xc7) | ((cipher.bits() << 3) & 0x38));
    }

    /// The physical trusted-path identifier in the MAC field, meaningful only
    /// when [`Packet::cipher`] is [`Cipher::TrustedPath`].
    #[must_use]
    pub fn trusted_path_id(&self) -> u64 {
        u64::from_be_bytes(field(&self.data, MAC_OFFSET, VERB_OFFSET).try_into().unwrap_or_default())
    }

    /// Marks the packet as authenticated by a configured physical path. Such
    /// packets are deliberately neither encrypted nor cryptographically
    /// authenticated, so a receiver must verify both the source prefix and the
    /// configured ID.
    pub fn set_trusted(&mut self, id: u64) {
        self.set_cipher(Cipher::TrustedPath);
        field_mut(&mut self.data, MAC_OFFSET, VERB_OFFSET).copy_from_slice(&id.to_be_bytes());
    }

    #[must_use]
    pub fn extended_armor(&self) -> bool {
        byte_at(&self.data, FLAGS_OFFSET) & FLAG_EXTENDED_ARMOR != 0
    }

    #[must_use]
    pub fn hops(&self) -> u8 {
        byte_at(&self.data, FLAGS_OFFSET) & 0x07
    }

    pub fn set_hops(&mut self, hops: u8) {
        let flags = byte_at(&self.data, FLAGS_OFFSET);
        set_byte_at(&mut self.data, FLAGS_OFFSET, (flags & 0xf8) | (hops & 0x07));
    }

    #[must_use]
    pub fn fragmented(&self) -> bool {
        byte_at(&self.data, FLAGS_OFFSET) & FLAG_FRAGMENTED != 0
    }

    pub fn set_fragmented(&mut self, fragmented: bool) {
        let flags = byte_at(&self.data, FLAGS_OFFSET);
        let updated = if fragmented { flags | FLAG_FRAGMENTED } else { flags & !FLAG_FRAGMENTED };
        set_byte_at(&mut self.data, FLAGS_OFFSET, updated);
    }

    #[must_use]
    pub fn verb(&self) -> Option<Verb> {
        Verb::from_bits(byte_at(&self.data, VERB_OFFSET) & 0x1f)
    }

    /// Whether the verb payload is LZ4-compressed.
    #[must_use]
    pub fn compressed(&self) -> bool {
        byte_at(&self.data, VERB_OFFSET) & VERB_COMPRESSED != 0
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.data.get(PAYLOAD_OFFSET..).unwrap_or_default()
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.data.get_mut(PAYLOAD_OFFSET..).unwrap_or_default()
    }

    /// Expands a raw LZ4-compressed verb payload in place.
    ///
    /// The wire format carries a bare LZ4 block with no frame header and no
    /// size prefix, so the output length comes from the block itself and is
    /// bounded by the maximum packet size.
    pub fn uncompress(&mut self) -> Result<(), PacketError> {
        if self.err {
            return Err(PacketError::Invalid);
        }
        if !self.compressed() {
            return Ok(());
        }
        let destination = lz4_flex::block::decompress(self.payload(), MAX_PACKET_SIZE - PAYLOAD_OFFSET)
            .map_err(|_| PacketError::Invalid)?;
        if destination.is_empty() || PAYLOAD_OFFSET + destination.len() > MAX_PACKET_SIZE {
            return Err(PacketError::Invalid);
        }
        self.data.truncate(PAYLOAD_OFFSET);
        self.data.extend_from_slice(&destination);
        let verb = byte_at(&self.data, VERB_OFFSET);
        set_byte_at(&mut self.data, VERB_OFFSET, verb & !VERB_COMPRESSED);
        Ok(())
    }

    /// Replaces the verb payload with a raw LZ4 block when that makes the
    /// packet smaller. An empty or incompressible payload is left alone, so the
    /// compressed flag is never set on a packet that grew.
    pub fn compress(&mut self) -> Result<(), PacketError> {
        if self.err {
            return Err(PacketError::Invalid);
        }
        if self.compressed() || self.data.len() < PAYLOAD_OFFSET {
            return Err(PacketError::Invalid);
        }
        let payload = self.payload().to_vec();
        if payload.is_empty() {
            return Ok(());
        }
        let mut buffer = vec![0u8; lz4_flex::block::get_maximum_output_size(payload.len())];
        let written = lz4_flex::block::compress_into(&payload, &mut buffer).map_err(|_| PacketError::Invalid)?;
        if written == 0 || written >= payload.len() {
            return Ok(());
        }
        buffer.truncate(written);
        self.data.truncate(PAYLOAD_OFFSET);
        self.data.extend_from_slice(&buffer);
        let verb = byte_at(&self.data, VERB_OFFSET);
        set_byte_at(&mut self.data, VERB_OFFSET, verb | VERB_COMPRESSED);
        Ok(())
    }

    /// The packet IV read as a network-order identifier.
    #[must_use]
    pub fn packet_id(&self) -> u64 {
        if self.data.len() >= DEST_OFFSET {
            return u64::from_be_bytes(field(&self.data, IV_OFFSET, DEST_OFFSET).try_into().unwrap_or_default());
        }
        self.sent_packet_id
    }

    /// Authenticates the packet and, when `encrypt` is set, encrypts its verb
    /// and payload with the legacy Salsa20/Poly1305 suite.
    pub fn armor(&mut self, key: &[u8], encrypt: bool) -> Result<(), PacketError> {
        if self.err || key.len() < 32 || self.data.len() < MIN_PACKET_SIZE {
            return Err(PacketError::Invalid);
        }
        self.set_cipher(if encrypt { Cipher::C25519Poly1305Salsa2012 } else { Cipher::C25519Poly1305None });

        let mangled = self.mangle_key(field(key, 0, 32));
        let nonce = array::<8>(field(&self.data, IV_OFFSET, DEST_OFFSET))?;
        let payload_len = self.data.len() - VERB_OFFSET;
        let mut stream = vec![0u8; 64 + payload_len];
        xor_key_stream_in_place(&mut stream, &salsa_state(&nonce), &mangled, 12);

        if encrypt {
            let end = self.data.len();
            xor_bytes(field_mut(&mut self.data, VERB_OFFSET, end), field(&stream, 64, stream.len()));
        }
        let tag = poly1305_tag(field(&stream, 0, 32), field(&self.data, VERB_OFFSET, self.data.len()))?;
        field_mut(&mut self.data, MAC_OFFSET, VERB_OFFSET).copy_from_slice(field(&tag, 0, 8));
        Ok(())
    }

    /// Authenticates and encrypts the verb and payload with the protocol-12
    /// AES-GMAC-SIV suite.
    pub fn armor_aes(&mut self, key: &[u8]) -> Result<(), PacketError> {
        let mut keys = GmacSivKeys::new(key).map_err(|_| PacketError::Invalid)?;
        self.armor_aes_with(&mut keys)
    }

    /// [`Packet::armor_aes`] reusing a peer's cached key schedule.
    pub fn armor_aes_with(&mut self, keys: &mut GmacSivKeys) -> Result<(), PacketError> {
        if self.err || self.data.len() < MIN_PACKET_SIZE {
            return Err(PacketError::Invalid);
        }
        self.set_cipher(Cipher::AesGmacSiv);
        let iv = array::<8>(field(&self.data, IV_OFFSET, DEST_OFFSET))?;
        let aad = field(&self.data, DEST_OFFSET, MAC_OFFSET).to_vec();
        let end = self.data.len();
        let payload = field(&self.data, VERB_OFFSET, end).to_vec();
        let (opaque, ciphertext) = keys.seal(&iv, &payload, &aad).map_err(|_| PacketError::Invalid)?;
        field_mut(&mut self.data, VERB_OFFSET, end).copy_from_slice(&ciphertext);
        field_mut(&mut self.data, IV_OFFSET, DEST_OFFSET).copy_from_slice(field(&opaque, 0, 8));
        field_mut(&mut self.data, MAC_OFFSET, VERB_OFFSET).copy_from_slice(field(&opaque, 8, opaque.len()));
        Ok(())
    }

    /// Applies protocol-13 ephemeral armor to a cleartext HELLO after its
    /// normal Salsa20/Poly1305 authentication.
    pub fn armor_extended(&mut self, key: &[u8], peer_public: &[u8; PUBLIC_KEY_SIZE]) -> Result<(), PacketError> {
        if self.err || self.data.len() + EXTENDED_ARMOR_KEY_SIZE > MAX_PACKET_SIZE {
            return Err(PacketError::Invalid);
        }
        let flags = byte_at(&self.data, FLAGS_OFFSET);
        set_byte_at(&mut self.data, FLAGS_OFFSET, flags | FLAG_EXTENDED_ARMOR);
        self.armor(key, false)?;
        let mut ephemeral_private = [0u8; 32];
        rand::rng().fill_bytes(&mut ephemeral_private);
        let ephemeral_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(ephemeral_private)).to_bytes();
        let ephemeral_key =
            agree_ephemeral(&ephemeral_private, field(peer_public, 0, 32)).map_err(|_| PacketError::Invalid)?;
        let mut iv_prefix = [0u8; 12];
        iv_prefix.copy_from_slice(field(&self.data, 0, 12));
        let end = self.data.len();
        aes_ctr_in_place(&ephemeral_key, &iv_prefix, field_mut(&mut self.data, MAC_OFFSET, end));
        self.data.extend_from_slice(&ephemeral_public);
        Ok(())
    }

    /// Hands the wire buffer to a transport without copying it.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Verifies the packet and decrypts its verb and payload when required.
    pub fn dearmor(&mut self, key: &[u8]) -> Result<(), PacketError> {
        self.dearmor_with(key, None, None)
    }

    /// [`Packet::dearmor`] with the local identity needed to unwrap
    /// protocol-13 extended armor, and cached AES keys for protocol-12 armor.
    pub fn dearmor_with(
        &mut self,
        key: &[u8],
        aes_keys: Option<&mut GmacSivKeys>,
        identity: Option<&Identity>,
    ) -> Result<(), PacketError> {
        if self.err || key.len() < 32 || self.data.len() < MIN_PACKET_SIZE {
            return Err(PacketError::Invalid);
        }
        let Some(suite) = self.cipher() else {
            return Err(PacketError::Invalid);
        };

        if self.extended_armor() && suite == Cipher::C25519Poly1305None {
            if self.data.len() < MIN_PACKET_SIZE + EXTENDED_ARMOR_KEY_SIZE {
                return Err(PacketError::Invalid);
            }
            let ephemeral_at = self.data.len() - EXTENDED_ARMOR_KEY_SIZE;
            let identity = identity.ok_or(PacketError::Invalid)?;
            let seed = identity.dh_seed().ok_or(PacketError::Invalid)?;
            let ephemeral_key = agree_ephemeral(&seed, field(&self.data, ephemeral_at, self.data.len()))
                .map_err(|_| PacketError::Invalid)?;
            let (header, body) = self.data.split_at_mut(MAC_OFFSET);
            aes_ctr_in_place(&ephemeral_key, field(header, 0, 12), field_mut(body, 0, ephemeral_at - MAC_OFFSET));
            self.data.truncate(ephemeral_at);
        }

        if suite == Cipher::AesGmacSiv {
            if key.len() < crate::identity::SYMMETRIC_KEY_SIZE {
                return Err(PacketError::Invalid);
            }
            let mut owned;
            let keys = if let Some(keys) = aes_keys {
                keys
            } else {
                owned = GmacSivKeys::new(field(key, 0, crate::identity::SYMMETRIC_KEY_SIZE))
                    .map_err(|_| PacketError::Invalid)?;
                &mut owned
            };
            let opaque_size = crate::ztcrypto::gmac_siv::OPAQUE_SIZE;
            let mut opaque = [0u8; crate::ztcrypto::gmac_siv::OPAQUE_SIZE];
            field_mut(&mut opaque, 0, 8).copy_from_slice(field(&self.data, IV_OFFSET, DEST_OFFSET));
            field_mut(&mut opaque, 8, opaque_size).copy_from_slice(field(&self.data, MAC_OFFSET, VERB_OFFSET));
            // The AAD covers the destination and source addresses only; the
            // cipher and hop bits were folded into the opaque value itself.
            let aad = field(&self.data, DEST_OFFSET, MAC_OFFSET).to_vec();
            let end = self.data.len();
            let payload = field(&self.data, VERB_OFFSET, end).to_vec();
            let plaintext = keys.open(&opaque, &payload, &aad).map_err(|_| PacketError::Invalid)?;
            self.data.truncate(VERB_OFFSET);
            self.data.extend_from_slice(&plaintext);
            return Ok(());
        }

        if suite != Cipher::C25519Poly1305None && suite != Cipher::C25519Poly1305Salsa2012 {
            return Err(PacketError::UnsupportedCipher);
        }

        let mangled = self.mangle_key(field(key, 0, 32));
        let nonce = array::<8>(field(&self.data, IV_OFFSET, DEST_OFFSET))?;
        let payload_len = self.data.len() - VERB_OFFSET;
        let mut stream = vec![0u8; 64 + payload_len];
        xor_key_stream_in_place(&mut stream, &salsa_state(&nonce), &mangled, 12);

        let tag = poly1305_tag(field(&stream, 0, 32), field(&self.data, VERB_OFFSET, self.data.len()))?;
        let mut mismatch = 0u8;
        for (received, expected) in field(&self.data, MAC_OFFSET, VERB_OFFSET).iter().zip(field(&tag, 0, 8)) {
            mismatch |= received ^ expected;
        }
        if mismatch != 0 {
            return Err(PacketError::Invalid);
        }
        if suite == Cipher::C25519Poly1305Salsa2012 {
            let end = self.data.len();
            xor_bytes(field_mut(&mut self.data, VERB_OFFSET, end), field(&stream, 64, stream.len()));
        }
        Ok(())
    }

    /// Applies the secondary HELLO field protection stream.
    pub fn crypt_field(&mut self, key: &[u8], start: usize, length: usize) -> Result<(), PacketError> {
        if self.err || key.len() < 32 || start + length > self.data.len() {
            return Err(PacketError::Invalid);
        }
        let mut nonce = array::<8>(field(&self.data, IV_OFFSET, DEST_OFFSET))?;
        if let Some(last) = nonce.get_mut(7) {
            *last &= 0xf8;
        }
        let stream_key: [u8; 32] = array(field(key, 0, 32))?;
        let end = start + length;
        let encrypted = field_mut(&mut self.data, start, end);
        xor_key_stream_in_place(encrypted, &salsa_state(&nonce), &stream_key, 12);
        Ok(())
    }

    /// Binds the legacy armor key to the immutable header fields so a packet
    /// cannot be replayed with a different destination, source, or length.
    fn mangle_key(&self, key: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(field(key, 0, 32));
        xor_bytes(&mut out, field(&self.data, 0, 18));
        if let Some(cipher) = out.get_mut(18) {
            *cipher ^= byte_at(&self.data, FLAGS_OFFSET) & 0xf8;
        }
        let length = self.data.len();
        if let Some(low) = out.get_mut(19) {
            *low ^= u8::try_from(length & 0xff).unwrap_or_default();
        }
        if let Some(high) = out.get_mut(20) {
            *high ^= u8::try_from((length >> 8) & 0xff).unwrap_or_default();
        }
        out
    }
}

/// Copies a fixed-width protocol field. A wrong-width slice is malformed input,
/// never a value to silently zero-fill.
fn array<const N: usize>(slice: &[u8]) -> Result<[u8; N], PacketError> {
    <[u8; N]>::try_from(slice).map_err(|_| PacketError::Invalid)
}

fn byte_at(data: &[u8], offset: usize) -> u8 {
    data.get(offset).copied().unwrap_or_default()
}

fn set_byte_at(data: &mut [u8], offset: usize, value: u8) {
    if let Some(slot) = data.get_mut(offset) {
        *slot = value;
    }
}

fn field(data: &[u8], start: usize, end: usize) -> &[u8] {
    data.get(start..end).unwrap_or_default()
}

fn field_mut(data: &mut [u8], start: usize, end: usize) -> &mut [u8] {
    data.get_mut(start..end).unwrap_or_default()
}

fn xor_bytes(target: &mut [u8], mask: &[u8]) {
    for (byte, key) in target.iter_mut().zip(mask) {
        *byte ^= key;
    }
}

/// The Salsa20/12 input state ZeroTier uses for packet armor: the eight-byte
/// packet IV as the nonce, with the block counter starting at zero.
fn salsa_state(nonce: &[u8]) -> [u8; 16] {
    let mut state = [0u8; 16];
    let len = nonce.len().min(8);
    field_mut(&mut state, 0, len).copy_from_slice(field(nonce, 0, len));
    state
}

fn poly1305_tag(key: &[u8], message: &[u8]) -> Result<[u8; 16], PacketError> {
    let mut tag = [0u8; 16];
    let poly = Poly1305::new_from_slice(key).map_err(|_| PacketError::Invalid)?;
    tag.copy_from_slice(poly.compute_unpadded(message).as_slice());
    Ok(tag)
}

/// AES-256-CTR over the full big-endian 128-bit counter, seeded from the
/// packet's first twelve bytes; a 16-byte counter, so no counter block is ever
/// treated as a nonce.
fn aes_ctr_in_place(key: &[u8; 32], iv_prefix: &[u8], data: &mut [u8]) {
    let mut counter = [0u8; 16];
    let prefix_len = iv_prefix.len().min(12);
    field_mut(&mut counter, 0, prefix_len).copy_from_slice(field(iv_prefix, 0, prefix_len));
    let cipher = Aes256::new(key.into());
    let mut keystream = [0u8; 16];
    for chunk in data.chunks_mut(16) {
        let mut block = counter;
        cipher.encrypt_block((&mut block).into());
        keystream.copy_from_slice(&block);
        xor_bytes(chunk, &keystream);
        for byte in counter.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Identity {
        Identity::generate()
    }

    fn key48() -> [u8; 48] {
        let mut key = [0u8; 48];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        key
    }

    fn hello(source: Address, payload: &[u8]) -> Packet {
        let mut packet =
            Packet::with_payload_capacity(Address::new(0x8e4d_f28b72), source, Verb::Hello, payload.len()).unwrap();
        packet.append(payload).unwrap();
        packet
    }

    /// A compression test payload: 1024 bytes of `i % 7`, which is highly
    /// compressible.
    fn compressible_payload() -> Vec<u8> {
        (0..1024u32).map(|index| (index % 7) as u8).collect()
    }

    #[test]
    fn compressible_payload_round_trips() {
        let payload = compressible_payload();
        let mut packet = hello(Address::new(0x0000_0000_0001), &payload);

        packet.compress().unwrap();
        assert!(packet.compressed());
        assert!(packet.payload().len() < payload.len());
        assert_eq!(packet.verb(), Some(Verb::Hello));

        packet.uncompress().unwrap();
        assert!(!packet.compressed());
        assert_eq!(packet.payload(), payload.as_slice());
        assert_eq!(packet.verb(), Some(Verb::Hello));
    }

    #[test]
    fn incompressible_payload_is_left_alone() {
        let mut rng = rand::rng();
        let mut payload = vec![0u8; 1024];
        rng.fill_bytes(&mut payload);
        let mut packet = hello(Address::new(0x0000_0000_0001), &payload);

        packet.compress().unwrap();
        if !packet.compressed() {
            assert_eq!(packet.payload(), payload.as_slice());
        } else {
            packet.uncompress().unwrap();
            assert_eq!(packet.payload(), payload.as_slice());
        }
    }

    #[test]
    fn compression_survives_the_wire_and_armor() {
        let key = key48();
        let payload = compressible_payload();
        let mut sent = hello(Address::new(0xabcd_ef01), &payload);
        sent.compress().unwrap();
        sent.armor(&key, true).unwrap();

        let wire = sent.bytes().to_vec();
        let mut received = Packet::parse(&wire).unwrap();
        received.dearmor(&key).unwrap();
        assert!(received.compressed());
        received.uncompress().unwrap();
        assert_eq!(received.payload(), payload.as_slice());
    }

    #[test]
    fn uncompress_is_idempotent_and_compress_rejects_double_compression() {
        let payload = compressible_payload();
        let mut packet = hello(Address::new(0x0000_0000_0001), &payload);

        packet.uncompress().unwrap();
        assert_eq!(packet.payload(), payload.as_slice());

        packet.compress().unwrap();
        assert!(packet.compress().is_err());
    }

    #[test]
    fn header_round_trips_addresses_and_verb() {
        let source = Address::new(0x0001_2345_6789);
        let packet = hello(source, b"payload");
        assert_eq!(packet.source(), source);
        assert_eq!(packet.destination(), Address::new(0x008e_4df2_8b72));
        assert_eq!(packet.verb(), Some(Verb::Hello));
        assert_eq!(packet.payload(), b"payload");
        assert_eq!(packet.bytes().len(), MIN_PACKET_SIZE + 7);
    }

    #[test]
    fn legacy_armor_round_trips_both_modes() {
        let source = Address::new(0xabcd_ef01);
        for encrypt in [false, true] {
            let key = key48();
            let mut sent = hello(source, b"the quick brown fox jumps over");
            sent.armor(&key, encrypt).unwrap();
            assert_eq!(
                sent.cipher(),
                Some(if encrypt { Cipher::C25519Poly1305Salsa2012 } else { Cipher::C25519Poly1305None })
            );
            if encrypt {
                assert_ne!(sent.payload(), b"the quick brown fox jumps over");
            }

            let wire = sent.bytes().to_vec();
            let mut received = Packet::parse(&wire).unwrap();
            received.dearmor(&key).unwrap();
            assert_eq!(received.verb(), Some(Verb::Hello));
            assert_eq!(received.payload(), b"the quick brown fox jumps over");
        }
    }

    #[test]
    fn legacy_armor_rejects_wrong_key_and_tampering() {
        let key = key48();
        let mut wrong = key;
        wrong[0] ^= 1;
        let mut other = key;
        other[31] ^= 1;

        let mut sent = hello(Address::new(0xabcd_ef01), b"authenticated payload");
        sent.armor(&key, true).unwrap();
        let mut wire = sent.bytes().to_vec();
        assert!(Packet::parse(&wire).unwrap().dearmor(&wrong).is_err());
        assert!(Packet::parse(&wire).unwrap().dearmor(&other).is_err());

        let last = wire.len() - 1;
        wire[last] ^= 1;
        assert!(Packet::parse(&wire).unwrap().dearmor(&key).is_err());

        wire = sent.bytes().to_vec();
        wire[SOURCE_OFFSET] ^= 1;
        assert!(Packet::parse(&wire).unwrap().dearmor(&key).is_err());
    }

    #[test]
    fn aes_gmac_siv_armor_round_trips() {
        let key = key48();
        let mut sent = hello(Address::new(0xabcd_ef01), b"protocol twelve payload");
        sent.armor_aes(&key).unwrap();
        assert_eq!(sent.cipher(), Some(Cipher::AesGmacSiv));

        let wire = sent.bytes().to_vec();
        let mut received = Packet::parse(&wire).unwrap();
        received.dearmor(&key).unwrap();
        assert_eq!(received.verb(), Some(Verb::Hello));
        assert_eq!(received.payload(), b"protocol twelve payload");

        let mut tampered = wire;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(Packet::parse(&tampered).unwrap().dearmor(&key).is_err());
    }

    #[test]
    fn crypt_field_is_reversible_and_position_bound() {
        let key = key48();
        let mut packet = hello(Address::new(0xabcd_ef01), &[0u8; 16]);
        let before: Vec<u8> = packet.payload().to_vec();

        packet.crypt_field(&key, VERB_OFFSET, 8).unwrap();
        assert_ne!(&packet.payload()[..8], &before[..8]);
        packet.crypt_field(&key, VERB_OFFSET, 8).unwrap();
        assert_eq!(packet.payload(), before.as_slice());

        assert!(packet.crypt_field(&key, MIN_PACKET_SIZE, 8).is_ok());
        assert!(packet.crypt_field(&key, packet.bytes().len(), 1).is_err());
    }

    #[test]
    fn trusted_path_uses_the_mac_field() {
        let mut packet = hello(Address::new(0xabcd_ef01), b"trusted");
        packet.set_trusted(0x0123_4567_89ab_cdef);
        assert_eq!(packet.cipher(), Some(Cipher::TrustedPath));
        assert_eq!(packet.trusted_path_id(), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn rejects_truncated_and_oversized_packets() {
        assert!(Packet::parse(&[0u8; MIN_PACKET_SIZE - 1]).is_err());
        assert!(Packet::parse(&[0u8; MAX_PACKET_SIZE + 1]).is_err());
        assert!(Packet::parse(&[0u8; MIN_PACKET_SIZE]).is_ok());
    }

    #[test]
    fn append_overflow_is_sticky() {
        let mut packet = Packet::new(Address::new(1), Address::new(2), Verb::Nop).unwrap();
        let oversized = vec![0u8; MAX_PACKET_SIZE];
        assert!(packet.append(&oversized).is_err());
        assert!(packet.err());
        assert!(packet.append(b"late").is_err());
    }

    #[test]
    fn flags_round_trip_without_disturbing_the_cipher() {
        let mut packet = hello(Address::new(0xabcd_ef01), b"x");
        packet.set_hops(5);
        packet.set_fragmented(true);
        assert_eq!(packet.hops(), 5);
        assert!(packet.fragmented());
        assert_eq!(packet.cipher(), Some(Cipher::C25519Poly1305None));
        packet.set_fragmented(false);
        assert!(!packet.fragmented());
        assert_eq!(packet.hops(), 5);
    }

    #[test]
    fn identities_are_still_generated_with_a_real_peer_key() {
        let identity = secret();
        assert!(identity.has_private());
    }
}
