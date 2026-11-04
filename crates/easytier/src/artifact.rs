//! The embedded bytes are an exact copy of `easytier_core.wasm` at the version pinned
//! here (`v0.0.0-20260910071355-3d0c9c3ca5e2`).
//!
//! The checksum below is compared against those bytes by [`verify`], so a corrupted or
//! mismatched copy fails fast instead of producing silently-wrong wire behavior.

pub const CORE_WASM: &[u8] = include_bytes!("artifact/easytier_core.wasm");

/// The EasyTier core commit this WASM build was produced from.
pub const COMMIT: &str = "63519db2b5f2a6a1b9b7f20905f036dab54eb829";

pub const SHA256: &str = "8b82f37d62fba2ffe8e256386096fddf448d4261d51c495d5bd97cd11bbb24a0";

/// Hash of the `.proto` IDL set at [`COMMIT`] (schema, not wasm bytes).
pub const PROTO_SCHEMA_SHA256: &str = "4fc7f40eac5d3803ed8afe707f2be1db121a022547f91568955c369212875064";

/// Embedded EasyTier core version string reported by the guest (`CoreInfo`).
pub const CORE_VERSION: &str = "2.6.4";

#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError {
    #[error("easytier_core.wasm checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
}

/// Verifies [`CORE_WASM`] against [`SHA256`].
///
/// Call once at process startup (or rely on the `provenance_matches` test) rather than
/// per-instantiation: hashing 6.85 MiB on every `Host::new` would be wasted work once the
/// binary is known good.
pub fn verify() -> Result<(), ProvenanceError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(CORE_WASM);
    let actual = hex::encode(hasher.finalize());
    if actual == SHA256 {
        Ok(())
    } else {
        Err(ProvenanceError::ChecksumMismatch { expected: SHA256.to_owned(), actual })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_matches() {
        verify().expect("checked-in easytier_core.wasm must match its recorded provenance");
    }

    #[test]
    fn artifact_size_is_the_pinned_module_size() {
        assert_eq!(CORE_WASM.len(), 6_850_909);
    }
}
