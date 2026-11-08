use std::sync::Arc;

use anyhow::Result;
use curve25519_dalek::EdwardsPoint;

use crate::crypto::ed25519;
use crate::obfs::sudoku::table::Table;

#[allow(
    dead_code,
    reason = "reachable only from httpmask_tunnel.rs's #[cfg(test)] module, not from any production caller"
)]
#[expect(
    clippy::panic,
    reason = "table construction for an explicit user-supplied table type is a fatal configuration error; the caller-free signature returns Arc<Table>"
)]
pub(crate) fn new_table(key: &str, table_type: &str) -> Arc<Table> {
    match new_table_with_custom(key, table_type, "") {
        Ok(table) => table,
        Err(err) => panic!("[Sudoku] failed to init tables: {err}"),
    }
}

pub(crate) fn new_table_with_custom(key: &str, table_type: &str, custom_table: &str) -> Result<Arc<Table>> {
    crate::obfs::sudoku::table::new_table_with_custom(key, table_type, custom_table)
}

/// `ClientAEADSeed`: returns a canonical "seed" that is stable between client private key
/// material and server public key.
#[must_use]
pub fn client_aead_seed(key: &str) -> String {
    let key = key.trim();
    if key.is_empty() {
        return String::new();
    }

    let Ok(b) = hex::decode(key) else {
        return key.to_owned();
    };

    // Client-side key material can be:
    //   - public key: 32 bytes hex compressed point
    //   - split private key: 64 bytes hex (r||k)
    //   - master private scalar: 32 bytes hex (x)
    //   - PSK string: non-hex
    //
    // 32-byte hex is ambiguous: it can be either a compressed public key or a
    // master private scalar. Official Sudoku runtime accepts public keys directly,
    // so when the bytes already decode as a point, preserve that point verbatim.
    if b.len() == 32 {
        if let Some(p) = decode_edwards_point(&b) {
            return hex::encode(p.compress().to_bytes());
        }
    }
    if b.len() != 64 && b.len() != 32 {
        return key.to_owned();
    }
    if let Ok(recovered) = ed25519::recover_public_key(key) {
        return ed25519::encode_point(&recovered);
    }
    key.to_owned()
}

/// `ServerAEADSeed`: returns a canonical seed for server-side configuration.
///
/// When key is a public key (32-byte compressed point, hex), it returns the canonical point
/// encoding. When key is private key material (split/master scalar), it derives and returns the
/// public key.
#[must_use]
pub fn server_aead_seed(key: &str) -> String {
    let key = key.trim();
    if key.is_empty() {
        return String::new();
    }

    let Ok(b) = hex::decode(key) else {
        return key.to_owned();
    };

    // Prefer interpreting 32-byte hex as a public key point, to avoid accidental scalar parsing.
    if b.len() == 32 {
        if let Some(p) = decode_edwards_point(&b) {
            return hex::encode(p.compress().to_bytes());
        }
    }

    // Fall back to client-side rules for private key materials / other formats.
    client_aead_seed(key)
}

fn decode_edwards_point(b: &[u8]) -> Option<EdwardsPoint> {
    let bytes: [u8; 32] = b.try_into().ok()?;
    curve25519_dalek::edwards::CompressedEdwardsY(bytes).decompress()
}

/// `GenKeyPair`: generates a client "available private key" and the corresponding server
/// public key.
pub fn gen_key_pair() -> Result<(String, String)> {
    let pair = ed25519::generate_master_key()?;
    let available_private_key = ed25519::split_private_key(&pair.private)?;
    Ok((available_private_key, ed25519::encode_point(&pair.public)))
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::Scalar;
    use rand::rngs::OsRng;
    use rand::TryRngCore;

    use super::*;

    #[test]
    fn client_aead_seed_is_stable_for_priv_and_pub() {
        for _ in 0..64 {
            let (priv_key, pub_key) = gen_key_pair().expect("gen key pair");
            assert_eq!(pub_key, client_aead_seed(&priv_key));
            assert_eq!(pub_key, client_aead_seed(&pub_key));
            assert_eq!(pub_key, server_aead_seed(&pub_key));
            assert_eq!(pub_key, server_aead_seed(&priv_key));
        }
    }

    #[test]
    fn client_aead_seed_supports_32_byte_master_scalar() {
        for _ in 0..256 {
            let mut seed = [0u8; 64];
            OsRng.try_fill_bytes(&mut seed).expect("random seed");
            let s = Scalar::from_bytes_mod_order_wide(&seed);
            let key_hex = hex::encode(s.as_bytes());
            assert_eq!(key_hex.len(), 64);

            // 32-byte hex is ambiguous: it can be either a master scalar or an
            // already-compressed public key. Public-key encoding wins when both parse.
            if decode_edwards_point(s.as_bytes()).is_some() {
                continue;
            }

            assert_ne!(key_hex, client_aead_seed(&key_hex));
            assert_eq!(client_aead_seed(&key_hex), server_aead_seed(&client_aead_seed(&key_hex)));
            return;
        }

        panic!("failed to generate an unambiguous 32-byte master scalar");
    }

    #[test]
    fn server_aead_seed_leaves_public_key_as_is() {
        for _ in 0..64 {
            let (priv_key, pub_key) = gen_key_pair().expect("gen key pair");
            assert_eq!(pub_key, server_aead_seed(&pub_key));
            assert_eq!(pub_key, server_aead_seed(&priv_key));
        }
    }
}
