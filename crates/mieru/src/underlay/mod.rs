//! Server-side user discovery: a linear scan over the configured users replaces a source-IP
//! authentication cache.

pub mod packet;
pub mod stream;

use std::collections::HashMap;

use crate::cipher::{self, BlockCipher};
use crate::wire;

pub use packet::PacketUnderlay;
pub use stream::StreamUnderlay;

/// The default MTU; the `MieruOption` inbound never overrides it.
pub const DEFAULT_MTU: usize = 1400;

/// `packetOverhead = NonceSize + MetadataLength + Overhead*2`.
pub const PACKET_OVERHEAD: usize = cipher::DEFAULT_NONCE_SIZE + wire::METADATA_LENGTH + cipher::DEFAULT_OVERHEAD * 2;

#[derive(thiserror::Error, Debug)]
pub enum UnderlayError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("wire error: {0}")]
    Wire(#[from] wire::WireError),
    #[error("no configured user's key could decrypt the first segment")]
    NoMatchingUser,
    #[error("underlay is closed")]
    Closed,
}

pub type Result<T, E = UnderlayError> = std::result::Result<T, E>;

/// A server's configured users, pre-hashed into AEAD key material:
/// `sha256(password || 0x00 || name)`, per the credential builder.
#[derive(Clone)]
pub struct ServerUsers {
    entries: Vec<(String, [u8; 32])>,
    hint_mandatory: bool,
}

impl core::fmt::Debug for ServerUsers {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerUsers")
            .field("user_count", &self.entries.len())
            .field("hint_mandatory", &self.hint_mandatory)
            .finish_non_exhaustive()
    }
}

impl ServerUsers {
    #[must_use]
    pub fn new(users: &HashMap<String, String>, hint_mandatory: bool) -> Self {
        let entries = users
            .iter()
            .map(|(name, password)| (name.clone(), cipher::hash_password(password.as_bytes(), name.as_bytes())))
            .collect();
        Self { entries, hint_mandatory }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// `Registry::discover`: hint-matching users first, then — unless the hint is mandatory — every
/// user unconditionally (each tried across all 3 clock-skew epochs), first successful decrypt wins.
#[must_use]
pub fn discover(data: &[u8], users: &ServerUsers, stateless: bool) -> Option<(String, BlockCipher, Vec<u8>)> {
    let hint_nonce = data.get(..cipher::DEFAULT_NONCE_SIZE);

    if let Some(nonce) = hint_nonce {
        for (name, credential) in &users.entries {
            if !BlockCipher::check_user_from_hint(name, nonce) {
                continue;
            }
            if let Some(found) = try_user(data, name, credential, stateless) {
                return Some(found);
            }
        }
    }
    if users.hint_mandatory {
        return None;
    }
    for (name, credential) in &users.entries {
        if let Some(found) = try_user(data, name, credential, stateless) {
            return Some(found);
        }
    }
    None
}

fn try_user(data: &[u8], name: &str, credential: &[u8; 32], stateless: bool) -> Option<(String, BlockCipher, Vec<u8>)> {
    let blocks = cipher::block_cipher_list_from_password(credential, stateless).ok()?;
    for block in blocks {
        if let Ok(plaintext) = block.decrypt(data) {
            block.set_user_name(Some(name.to_owned()));
            return Some((name.to_owned(), block, plaintext));
        }
    }
    None
}

/// `session.mtu - packetOverhead` (packet transport) or `MAX_PDU` (stream transport), i.e. the
/// per-fragment payload cap a [`crate::session::Session`] chunks writes into.
#[must_use]
pub fn fragment_size(transport: crate::session::Transport, mtu: usize) -> usize {
    match transport {
        crate::session::Transport::Stream => wire::MAX_PDU,
        crate::session::Transport::Packet => mtu.saturating_sub(PACKET_OVERHEAD).max(1),
    }
}
