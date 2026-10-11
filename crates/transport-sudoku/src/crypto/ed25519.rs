use anyhow::{anyhow, Result};
use curve25519_dalek::{EdwardsPoint, Scalar};
use rand::rngs::OsRng;
use rand::TryRngCore;

/// `KeyPair` holds the scalar private key and point public key
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private: Scalar,
    pub public: EdwardsPoint,
}

/// `GenerateMasterKey` generates a random master private key (scalar) and its public key (point)
pub fn generate_master_key() -> Result<KeyPair> {
    let mut seed = [0u8; 64];
    OsRng.try_fill_bytes(&mut seed)?;

    let x = Scalar::from_bytes_mod_order_wide(&seed);
    let p = EdwardsPoint::mul_base(&x);

    Ok(KeyPair { private: x, public: p })
}

/// `SplitPrivateKey` takes a master private key x and returns a new random split key (r, k)
/// such that x = r + k (mod L).
/// Returns hex encoded string of r || k (64 bytes)
pub fn split_private_key(x: &Scalar) -> Result<String> {
    let mut seed = [0u8; 64];
    OsRng.try_fill_bytes(&mut seed)?;
    let r = Scalar::from_bytes_mod_order_wide(&seed);

    let k = x - r;

    let mut full = [0u8; 64];
    full[..32].copy_from_slice(r.as_bytes());
    full[32..].copy_from_slice(k.as_bytes());

    Ok(hex::encode(full))
}

/// `RecoverPublicKey` takes a split private key (r, k) or a master private key (x)
/// and returns the public key P.
/// Input can be:
/// - 32 bytes hex (Master Scalar x)
/// - 64 bytes hex (Split Key r || k)
pub fn recover_public_key(key_hex: &str) -> Result<EdwardsPoint> {
    let key_bytes = hex::decode(key_hex).map_err(|err| anyhow!("invalid hex: {err}"))?;

    if key_bytes.len() == 32 {
        let x = decode_scalar(&key_bytes).ok_or_else(|| anyhow!("invalid scalar: invalid scalar encoding"))?;
        return Ok(EdwardsPoint::mul_base(&x));
    }
    if key_bytes.len() == 64 {
        let (r_bytes, k_bytes) = key_bytes.split_at(32);
        let r = decode_scalar(r_bytes).ok_or_else(|| anyhow!("invalid scalar r: invalid scalar encoding"))?;
        let k = decode_scalar(k_bytes).ok_or_else(|| anyhow!("invalid scalar k: invalid scalar encoding"))?;

        let sum = r + k;

        return Ok(EdwardsPoint::mul_base(&sum));
    }

    Err(anyhow!("invalid key length: must be 32 bytes (Master) or 64 bytes (Split)"))
}

fn decode_scalar(bytes: &[u8]) -> Option<Scalar> {
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
}

/// `EncodePoint` returns the hex string of the compressed point
#[must_use]
pub fn encode_point(p: &EdwardsPoint) -> String {
    hex::encode(p.compress().to_bytes())
}

/// `EncodeScalar` returns the hex string of the scalar
#[must_use]
pub fn encode_scalar(s: &Scalar) -> String {
    hex::encode(s.as_bytes())
}
