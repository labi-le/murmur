//! The control packet format: opcodes, key ids, session ids and the reliability-layer header.

use std::fmt;
use std::ops::Deref;

use anyhow::{bail, Result};
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use tokio::time::Instant;

use super::control::RELIABLE_ACK_SIZE;
use super::tlscrypt::{be_u32, clone_bytes, TLS_CRYPT_HEADER_SIZE};

pub trait ControlCryptor: Send + Sync {
    fn wrap(&self, header: &[u8], packet_id: u32, unix_time: u32, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn unwrap(&self, packet: &[u8]) -> Result<(Vec<u8>, u32, u32, Vec<u8>)>;

    /// `Some` only for a tls-crypt-v2 cryptor, carrying the client key wrapped for the V3
    /// hard-reset packet.
    fn wrapped_client_key(&self) -> Option<Vec<u8>> {
        None
    }
}

pub const KEY_ID_MASK: u8 = 0x07;
pub const OPCODE_SHIFT: u8 = 3;

pub const P_CONTROL_HARD_RESET_CLIENT_V1: Opcode = Opcode(1);
pub const P_CONTROL_HARD_RESET_SERVER_V1: Opcode = Opcode(2);
pub const P_CONTROL_SOFT_RESET_V1: Opcode = Opcode(3);
pub const P_CONTROL_V1: Opcode = Opcode(4);
pub const P_ACK_V1: Opcode = Opcode(5);
pub const P_DATA_V1: Opcode = Opcode(6);
pub const P_CONTROL_HARD_RESET_CLIENT_V2: Opcode = Opcode(7);
pub const P_CONTROL_HARD_RESET_SERVER_V2: Opcode = Opcode(8);
pub const P_DATA_V2: Opcode = Opcode(9);
pub const P_CONTROL_HARD_RESET_CLIENT_V3: Opcode = Opcode(10);
pub const P_CONTROL_WKC_V1: Opcode = Opcode(11);

pub const SESSION_ID_SIZE: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Opcode(pub u8);

impl Opcode {
    #[must_use]
    pub const fn is_control(self) -> bool {
        matches!(
            self,
            P_CONTROL_HARD_RESET_CLIENT_V1
                | P_CONTROL_HARD_RESET_SERVER_V1
                | P_CONTROL_SOFT_RESET_V1
                | P_CONTROL_V1
                | P_ACK_V1
                | P_CONTROL_HARD_RESET_CLIENT_V2
                | P_CONTROL_HARD_RESET_SERVER_V2
                | P_CONTROL_HARD_RESET_CLIENT_V3
                | P_CONTROL_WKC_V1
        )
    }

    #[must_use]
    pub fn has_message_id(self) -> bool {
        self.is_control() && self != P_ACK_V1
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            P_CONTROL_HARD_RESET_CLIENT_V1 => "P_CONTROL_HARD_RESET_CLIENT_V1",
            P_CONTROL_HARD_RESET_SERVER_V1 => "P_CONTROL_HARD_RESET_SERVER_V1",
            P_CONTROL_SOFT_RESET_V1 => "P_CONTROL_SOFT_RESET_V1",
            P_CONTROL_V1 => "P_CONTROL_V1",
            P_ACK_V1 => "P_ACK_V1",
            P_DATA_V1 => "P_DATA_V1",
            P_CONTROL_HARD_RESET_CLIENT_V2 => "P_CONTROL_HARD_RESET_CLIENT_V2",
            P_CONTROL_HARD_RESET_SERVER_V2 => "P_CONTROL_HARD_RESET_SERVER_V2",
            P_DATA_V2 => "P_DATA_V2",
            P_CONTROL_HARD_RESET_CLIENT_V3 => "P_CONTROL_HARD_RESET_CLIENT_V3",
            P_CONTROL_WKC_V1 => "P_CONTROL_WKC_V1",
            _ => "P_UNKNOWN",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SessionID(pub [u8; SESSION_ID_SIZE]);

// Deliberate newtype delegation to the fixed-size wire field, not OO inheritance.
impl Deref for SessionID {
    type Target = [u8; SESSION_ID_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for SessionID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub fn new_session_id() -> Result<SessionID> {
    let mut id = SessionID::default();
    OsRng.try_fill_bytes(&mut id.0)?;
    Ok(id)
}

#[derive(Clone, Debug, Default)]
pub struct ControlPacket {
    pub opcode: Opcode,
    pub key_id: u8,
    pub local_session: SessionID,

    pub ack_ids: Vec<u32>,
    pub ack_remote_session: SessionID,

    pub message_id: u32,
    pub payload: Vec<u8>,
    /// Local-only timestamp of when a valid soft reset was accepted. It is
    /// never serialized; `None` is the zero instant.
    pub(crate) received_at: Option<Instant>,
}

#[must_use]
pub const fn opcode_key_id(opcode: Opcode, key_id: u8) -> u8 {
    opcode.0 << OPCODE_SHIFT | (key_id & KEY_ID_MASK)
}

#[must_use]
pub const fn parse_opcode_key_id(b: u8) -> (Opcode, u8) {
    (Opcode(b >> OPCODE_SHIFT), b & KEY_ID_MASK)
}

impl ControlPacket {
    pub fn encode_plain(&self) -> Result<Vec<u8>> {
        if !self.opcode.is_control() {
            bail!("opcode {} is not a control opcode", self.opcode);
        }
        if self.ack_ids.len() > RELIABLE_ACK_SIZE {
            bail!("too many ack ids: {}", self.ack_ids.len());
        }

        let mut size = 1 + self.ack_ids.len() * 4;
        if !self.ack_ids.is_empty() {
            size += SESSION_ID_SIZE;
        }
        if self.opcode.has_message_id() {
            size += 4 + self.payload.len();
        }
        let mut out = Vec::with_capacity(size);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the ack count was checked against `RELIABLE_ACK_SIZE` (8) above and the wire field is one byte"
        )]
        out.push(self.ack_ids.len() as u8);
        for id in &self.ack_ids {
            out.extend_from_slice(&id.to_be_bytes());
        }
        if !self.ack_ids.is_empty() {
            out.extend_from_slice(&self.ack_remote_session.0);
        }
        if self.opcode.has_message_id() {
            out.extend_from_slice(&self.message_id.to_be_bytes());
            out.extend_from_slice(&self.payload);
        }
        Ok(out)
    }
}

pub(crate) fn decode_control_plain(opcode: Opcode, plain: &[u8]) -> Result<(Vec<u32>, SessionID, u32, Vec<u8>)> {
    let Some(&ack_count) = plain.first() else {
        bail!("control payload too short");
    };
    let ack_len = usize::from(ack_count);
    if ack_len > RELIABLE_ACK_SIZE {
        bail!("control ack array exceeds {RELIABLE_ACK_SIZE} entries");
    }
    let mut offset = 1;
    if plain.len() < offset + ack_len * 4 {
        bail!("control ack array truncated");
    }
    let mut ack_ids = Vec::with_capacity(ack_len);
    for _ in 0..ack_len {
        ack_ids.push(be_u32(plain, offset));
        offset += 4;
    }
    let mut ack_remote = SessionID::default();
    if ack_len > 0 {
        let Some(remote) = plain.get(offset..offset + SESSION_ID_SIZE) else {
            bail!("control ack remote session truncated");
        };
        ack_remote.0.copy_from_slice(remote);
        offset += SESSION_ID_SIZE;
    }
    let mut message_id = 0;
    let mut payload = Vec::new();
    if opcode.has_message_id() {
        let Some(message) = plain.get(offset..) else {
            bail!("control message id truncated");
        };
        let Some((id, rest)) = message.split_at_checked(4) else {
            bail!("control message id truncated");
        };
        message_id = be_u32(id, 0);
        payload = clone_bytes(rest);
    } else if plain.len() != offset {
        bail!("ack packet has trailing payload");
    }
    Ok((ack_ids, ack_remote, message_id, payload))
}

impl ControlPacket {
    pub fn encode(&self, crypt: Option<&dyn ControlCryptor>, packet_id: u32, unix_time: u32) -> Result<Vec<u8>> {
        let plain = self.encode_plain()?;

        let mut header = vec![opcode_key_id(self.opcode, self.key_id)];
        header.extend_from_slice(&self.local_session.0);

        let Some(crypt) = crypt else {
            let mut out = Vec::with_capacity(header.len() + plain.len());
            out.extend_from_slice(&header);
            out.extend_from_slice(&plain);
            return Ok(out);
        };
        crypt.wrap(&header, packet_id, unix_time, &plain)
    }
}

pub fn decode_control_packet(crypt: Option<&dyn ControlCryptor>, packet: &[u8]) -> Result<(ControlPacket, u32, u32)> {
    let Some(crypt) = crypt else {
        let Some((first, rest)) = packet.split_first() else {
            bail!("control packet too short");
        };
        let (opcode, key_id) = parse_opcode_key_id(*first);
        if !opcode.is_control() {
            bail!("opcode {opcode} is not a control opcode");
        }
        let Some((session, plain)) = rest.split_at_checked(SESSION_ID_SIZE) else {
            bail!("control packet too short");
        };
        if plain.is_empty() {
            bail!("control packet too short");
        }
        let mut local_session = SessionID::default();
        local_session.0.copy_from_slice(session);
        let (ack_ids, ack_remote_session, message_id, payload) = decode_control_plain(opcode, plain)?;
        return Ok((
            ControlPacket {
                opcode,
                key_id,
                local_session,
                ack_ids,
                ack_remote_session,
                message_id,
                payload,
                received_at: None,
            },
            0,
            0,
        ));
    };

    let (header, packet_id, unix_time, plain) = crypt.unwrap(packet)?;
    if header.len() != TLS_CRYPT_HEADER_SIZE {
        bail!("invalid control header length {}", header.len());
    }
    let Some((first, session)) = header.split_first() else {
        bail!("invalid control header length {}", header.len());
    };
    let (opcode, key_id) = parse_opcode_key_id(*first);
    if !opcode.is_control() {
        bail!("opcode {opcode} is not a control opcode");
    }
    let mut local_session = SessionID::default();
    local_session.0.copy_from_slice(session);

    let (ack_ids, ack_remote_session, message_id, payload) = decode_control_plain(opcode, &plain)?;
    Ok((
        ControlPacket {
            opcode,
            key_id,
            local_session,
            ack_ids,
            ack_remote_session,
            message_id,
            payload,
            received_at: None,
        },
        packet_id,
        unix_time,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AUTH_SHA1;
    use crate::control::RELIABLE_ACK_SIZE;
    use crate::tlsauth::new_tls_auth;
    use crate::tlscrypt::new_tls_crypt;

    fn test_static_key() -> Vec<u8> {
        (0..=255u8).collect()
    }

    #[test]
    fn control_packet_encode_decode_with_tls_crypt() {
        let crypt_client = new_tls_crypt(&test_static_key(), true).expect("new tls-crypt client");
        let crypt_server = new_tls_crypt(&test_static_key(), false).expect("new tls-crypt server");

        let mut local = SessionID::default();
        local.0.copy_from_slice(b"client01");
        let mut remote = SessionID::default();
        remote.0.copy_from_slice(b"server01");

        let sent = ControlPacket {
            opcode: P_CONTROL_V1,
            key_id: 0,
            local_session: local,
            ack_ids: vec![3, 4],
            ack_remote_session: remote,
            message_id: 9,
            payload: b"tls ciphertext".to_vec(),
            ..Default::default()
        };
        let encoded = sent.encode(Some(&crypt_client), 77, 1_714_567_890).expect("encode");
        assert_eq!(
            hex::encode(&encoded),
            "20636c69656e7430310000004d66323ad2658f217d26c01c73745422011d51cb94027af3c622322309bea3c7\
dca626d73beb5008bec110b2af05c44491854e772f53a9a9f1e3f93502e58fb86eda09519472f897",
        );

        let (decoded, packet_id, unix_time) = decode_control_packet(Some(&crypt_server), &encoded).expect("decode");
        assert!(
            packet_id == 77 && unix_time == 1_714_567_890,
            "unexpected tls-crypt packet id/time: {packet_id}/{unix_time}"
        );
        assert!(
            decoded.opcode == sent.opcode && decoded.key_id == sent.key_id,
            "unexpected opcode/key-id: {}/{}",
            decoded.opcode,
            decoded.key_id
        );
        assert_eq!(decoded.local_session, local);
        assert_eq!(decoded.payload, sent.payload);
        assert_eq!(decoded.ack_ids, [3, 4]);
        assert_eq!(decoded.ack_remote_session, remote);
    }

    #[test]
    fn control_packet_encode_decode_with_tls_auth() {
        let crypt_client = new_tls_auth(&test_static_key(), "1", AUTH_SHA1).expect("new tls-auth client");
        let crypt_server = new_tls_auth(&test_static_key(), "0", AUTH_SHA1).expect("new tls-auth server");

        let mut local = SessionID::default();
        local.0.copy_from_slice(b"client01");
        let mut remote = SessionID::default();
        remote.0.copy_from_slice(b"server01");

        let sent = ControlPacket {
            opcode: P_CONTROL_V1,
            key_id: 0,
            local_session: local,
            ack_ids: vec![3, 4],
            ack_remote_session: remote,
            message_id: 9,
            payload: b"tls auth".to_vec(),
            ..Default::default()
        };
        let encoded = sent.encode(Some(&crypt_client), 77, 1_714_567_890).expect("encode");
        assert_eq!(
            hex::encode(&encoded),
            "20636c69656e74303196a5cadfe49c2466756924995446839ddc4500fc0000004d66323ad2020000000300000\
004736572766572303100000009746c732061757468",
        );

        let (decoded, packet_id, unix_time) = decode_control_packet(Some(&crypt_server), &encoded).expect("decode");
        assert!(
            packet_id == 77 && unix_time == 1_714_567_890,
            "unexpected tls-auth packet id/time: {packet_id}/{unix_time}"
        );
        assert!(
            decoded.opcode == sent.opcode && decoded.key_id == sent.key_id,
            "unexpected opcode/key-id: {}/{}",
            decoded.opcode,
            decoded.key_id
        );
        assert_eq!(decoded.local_session, local);
        assert_eq!(decoded.payload, sent.payload);
    }

    #[test]
    fn control_packet_encode_decode_plain() {
        let mut local = SessionID::default();
        local.0.copy_from_slice(b"client01");
        let mut remote = SessionID::default();
        remote.0.copy_from_slice(b"server01");

        let sent = ControlPacket {
            opcode: P_CONTROL_V1,
            key_id: 1,
            local_session: local,
            ack_ids: vec![11],
            ack_remote_session: remote,
            message_id: 12,
            payload: b"plain control".to_vec(),
            ..Default::default()
        };
        let encoded = sent.encode(None, 0, 0).expect("encode");
        assert_eq!(
            hex::encode(&encoded),
            "21636c69656e743031010000000b73657276657230310000000c706c61696e20636f6e74726f6c",
        );

        let (decoded, packet_id, unix_time) = decode_control_packet(None, &encoded).expect("decode");
        assert!(packet_id == 0 && unix_time == 0, "unexpected plain packet id/time: {packet_id}/{unix_time}");
        assert!(
            decoded.opcode == sent.opcode && decoded.key_id == sent.key_id,
            "unexpected opcode/key-id: {}/{}",
            decoded.opcode,
            decoded.key_id
        );
        assert_eq!(decoded.local_session, local);
        assert_eq!(decoded.message_id, sent.message_id);
        assert_eq!(decoded.payload, sent.payload);
        assert_eq!(decoded.ack_ids, [11]);
        assert_eq!(decoded.ack_remote_session, remote);
    }

    #[test]
    fn ack_packet_rejects_trailing_payload() {
        assert!(decode_control_plain(P_ACK_V1, &[0, 1]).is_err(), "expected trailing payload error");
    }

    #[test]
    fn control_packet_rejects_oversized_ack_array() {
        let sent = ControlPacket { opcode: P_ACK_V1, ack_ids: vec![0u32; RELIABLE_ACK_SIZE + 1], ..Default::default() };
        assert!(sent.encode_plain().is_err(), "oversized ACK array encoded");

        let mut plain = vec![0u8; 1 + (RELIABLE_ACK_SIZE + 1) * 4 + SESSION_ID_SIZE];
        plain[0] = (RELIABLE_ACK_SIZE + 1) as u8;
        assert!(decode_control_plain(P_ACK_V1, &plain).is_err(), "oversized ACK array decoded");
    }
}
