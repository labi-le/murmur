//! The `tls-auth` control-channel authenticator: an HMAC over control packets under a static
//! key.

use std::fmt;

use anyhow::{bail, Result};
use subtle::ConstantTimeEq;

use super::config::normalize_auth;
use super::data::{new_data_channel_auth, AuthHash};
use super::packet::ControlCryptor;
use super::tlscrypt::{be_u32, clone_bytes, KEY_SLOT_SIZE, STATIC_KEY_SIZE, TLS_CRYPT_HEADER_SIZE};

pub const TLS_AUTH_PID_SIZE: usize = 4 + 4;

/// Where the HMAC key material starts inside a 128-byte key slot: `OpenVPN`'s
/// `struct key` is 64 bytes of cipher key followed by 64 bytes of HMAC key, and
/// `--tls-auth` uses the first digest-size bytes of the HMAC half.
pub(crate) const TLS_AUTH_HMAC_KEY_OFFSET: usize = 64;

pub struct TLSAuth {
    auth_hash: AuthHash,
    tag_size: usize,
    encrypt_hmac_key: Vec<u8>,
    decrypt_hmac_key: Vec<u8>,
}

impl fmt::Debug for TLSAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TLSAuth").field("tag_size", &self.tag_size).finish_non_exhaustive()
    }
}

/// Builds the `--tls-auth` control channel wrapper.
///
/// `auth_name` selects the HMAC digest exactly as the `--auth` option does:
/// the tag length and the amount of key material taken from the static key both
/// follow that digest, so a peer running "auth SHA256" or "auth SHA512" sees the
/// tag size it expects.
pub fn new_tls_auth(static_key: &[u8], key_direction: &str, auth_name: &str) -> Result<TLSAuth> {
    if static_key.len() != STATIC_KEY_SIZE {
        bail!("invalid tls-auth static key length {}, expected {}", static_key.len(), STATIC_KEY_SIZE);
    }
    if key_direction != "0" && key_direction != "1" && !key_direction.is_empty() {
        bail!("invalid tls-auth key-direction {key_direction:?}, expected '0', '1', or ''");
    }
    let (auth_hash, tag_size) =
        new_data_channel_auth(&normalize_auth(auth_name)).map_err(|err| anyhow::anyhow!("tls-auth: {err}"))?;

    let (key0, key1) = static_key.split_at(KEY_SLOT_SIZE);

    let (encrypt, decrypt) = match key_direction {
        "1" => (key1, key0),
        "0" => (key0, key1),
        _ => (key0, key0),
    };

    #[expect(
        clippy::indexing_slicing,
        reason = "a slot is `KEY_SLOT_SIZE` bytes and `tag_size` is at most the 64-byte SHA-512 digest, so the HMAC key range stays inside it"
    )]
    let (encrypt_hmac_key, decrypt_hmac_key) = (
        clone_bytes(&encrypt[TLS_AUTH_HMAC_KEY_OFFSET..TLS_AUTH_HMAC_KEY_OFFSET + tag_size]),
        clone_bytes(&decrypt[TLS_AUTH_HMAC_KEY_OFFSET..TLS_AUTH_HMAC_KEY_OFFSET + tag_size]),
    );

    Ok(TLSAuth { auth_hash, tag_size, encrypt_hmac_key, decrypt_hmac_key })
}

impl TLSAuth {
    /// The length of the HMAC tag that follows the packet header.
    #[must_use]
    pub const fn tag_size(&self) -> usize {
        self.tag_size
    }

    fn hmac(&self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        self.auth_hash.hmac(key, parts)
    }
}

impl ControlCryptor for TLSAuth {
    fn wrap(&self, header: &[u8], packet_id: u32, unix_time: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        if header.len() != TLS_CRYPT_HEADER_SIZE {
            bail!("invalid tls-auth header length {}, expected {}", header.len(), TLS_CRYPT_HEADER_SIZE);
        }

        let mut pid = [0u8; TLS_AUTH_PID_SIZE];
        pid[..4].copy_from_slice(&packet_id.to_be_bytes());
        pid[4..].copy_from_slice(&unix_time.to_be_bytes());
        let tag = self.hmac(&self.encrypt_hmac_key, &[&pid, header, plaintext]);

        let mut out = Vec::with_capacity(header.len() + tag.len() + pid.len() + plaintext.len());
        out.extend_from_slice(header);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&pid);
        out.extend_from_slice(plaintext);
        Ok(out)
    }

    fn unwrap(&self, packet: &[u8]) -> Result<(Vec<u8>, u32, u32, Vec<u8>)> {
        let Some((header, rest)) = packet.split_at_checked(TLS_CRYPT_HEADER_SIZE) else {
            bail!("tls-auth packet too short");
        };
        let Some((tag, rest)) = rest.split_at_checked(self.tag_size) else {
            bail!("tls-auth packet too short");
        };
        let Some((pid, plaintext)) = rest.split_at_checked(TLS_AUTH_PID_SIZE) else {
            bail!("tls-auth packet too short");
        };
        if plaintext.is_empty() {
            bail!("tls-auth packet too short");
        }

        let header = clone_bytes(header);
        let tag_check = self.hmac(&self.decrypt_hmac_key, &[pid, &header, plaintext]);
        if tag.ct_eq(&tag_check).unwrap_u8() != 1 {
            bail!("tls-auth authentication failed");
        }

        let packet_id = be_u32(pid, 0);
        let unix_time = be_u32(pid, 4);
        Ok((header, packet_id, unix_time, clone_bytes(plaintext)))
    }
}
