//! Running SHA-256 transcript hash over every handshake message, in both
//! directions, in wire order -- RFC 8446 §4.4.1.

use sha2::{Digest, Sha256};

#[derive(Clone)]
pub(crate) struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    pub(crate) fn new() -> Self {
        Self { hasher: Sha256::new() }
    }

    /// Feeds one complete handshake message (header + body) into the running
    /// hash. Must be called exactly once per message, in the order it was
    /// sent or received on the wire.
    pub(crate) fn update(&mut self, message: &[u8]) {
        self.hasher.update(message);
    }

    /// Snapshot of the hash over every message fed in so far, without
    /// consuming the running state.
    pub(crate) fn hash(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}
