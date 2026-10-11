use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use super::kip::KIP_HELLO_NONCE_SIZE;

#[expect(clippy::expect_used, reason = "expanding 32 bytes from HKDF-SHA256 cannot fail")]
pub(crate) fn derive_psk_directional_bases(psk: &str) -> (Vec<u8>, Vec<u8>) {
    let sum = Sha256::digest(psk.as_bytes());
    let mut c2s_key = vec![0u8; 32];
    let mut s2c_key = vec![0u8; 32];
    let hk = Hkdf::<Sha256>::from_prk(&sum).expect("sudoku: hkdf expand failed");
    hk.expand(b"sudoku-psk-c2s", &mut c2s_key).expect("sudoku: hkdf expand failed");
    let hk = Hkdf::<Sha256>::from_prk(&sum).expect("sudoku: hkdf expand failed");
    hk.expand(b"sudoku-psk-s2c", &mut s2c_key).expect("sudoku: hkdf expand failed");
    (c2s_key, s2c_key)
}

pub(crate) fn derive_session_directional_bases(
    psk: &str,
    shared: &[u8],
    nonce: &[u8; KIP_HELLO_NONCE_SIZE],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let sum = Sha256::digest(psk.as_bytes());
    let mut ikm = Vec::with_capacity(shared.len() + nonce.len());
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(nonce);

    let (_, hk) = Hkdf::<Sha256>::extract(Some(&sum), &ikm);

    let mut c2s_key = vec![0u8; 32];
    let mut s2c_key = vec![0u8; 32];
    hk.expand(b"sudoku-session-c2s", &mut c2s_key).map_err(|err| anyhow!("hkdf expand c2s: {err}"))?;
    hk.expand(b"sudoku-session-s2c", &mut s2c_key).map_err(|err| anyhow!("hkdf expand s2c: {err}"))?;
    Ok((c2s_key, s2c_key))
}

pub(crate) fn generate_x25519_ephemeral() -> Result<StaticSecret> {
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes)?;
    Ok(StaticSecret::from(bytes))
}

pub(crate) fn x25519_shared_secret(priv_key: &StaticSecret, peer_pub: &[u8]) -> Result<Vec<u8>> {
    let pk: [u8; 32] = peer_pub.try_into().map_err(|_| anyhow!("parse peer pub: invalid public key"))?;
    let shared = priv_key.diffie_hellman(&PublicKey::from(pk));
    if !shared.was_contributory() {
        return Err(anyhow!("ecdh: bad X25519 remote ECDH input: low order point"));
    }
    Ok(shared.to_bytes().to_vec())
}
