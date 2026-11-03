//! XChaCha20 is ChaCha20 with a 24-byte nonce.
//!
//! `nonce[0..8]` feeds HChaCha20 for the subkey and `nonce[8..24]` is the substream nonce from
//! counter 0, which is exactly what `chacha20::XChaCha20` (the workspace's `xchacha` feature)
//! builds from the same 32-byte key and 24-byte nonce.

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce as GcmNonce};
use anyhow::{anyhow, Result};
use chacha20::cipher::KeyIvInit;
use chacha20::XChaCha20;
use hkdf::Hkdf;
use sha2::Sha256;

struct XorNonceAead {
    nonce_mask: [u8; 12],
    aead: Aes128Gcm,
}

fn new_xor_nonce_aead(key: &[u8], nonce_mask: &[u8]) -> Result<XorNonceAead> {
    if nonce_mask.len() != 12 {
        return Err(anyhow!("tlsmirror: invalid nonce mask size"));
    }
    let aead = Aes128Gcm::new_from_slice(key).map_err(|err| anyhow!("invalid AES key: {err}"))?;
    let mut mask = [0u8; 12];
    mask.copy_from_slice(nonce_mask);
    Ok(XorNonceAead { nonce_mask: mask, aead })
}

impl XorNonceAead {
    const NONCE_SIZE: usize = 8;
    const OVERHEAD: usize = 16;

    fn masked_nonce(&self, nonce: &[u8]) -> [u8; 12] {
        let mut mask = self.nonce_mask;
        for (slot, byte) in mask.iter_mut().skip(4).zip(nonce) {
            *slot ^= byte;
        }
        mask
    }

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<()> {
        let mask = self.masked_nonce(nonce);
        let ciphertext = self
            .aead
            .encrypt(&GcmNonce::<U12>::from(mask), Payload { msg: plaintext, aad: additional_data })
            .map_err(|err| anyhow!("message authentication failed: {err}"))?;
        dst.extend_from_slice(&ciphertext);
        Ok(())
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>> {
        let mask = self.masked_nonce(nonce);
        self.aead
            .decrypt(&GcmNonce::<U12>::from(mask), Payload { msg: ciphertext, aad: additional_data })
            .map_err(|err| anyhow!("message authentication failed: {err}"))
    }
}

pub(crate) fn derive_encryption_key(
    primary_key: &[u8],
    client_random: [u8; 32],
    server_random: [u8; 32],
    tag: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if primary_key.len() != 32 {
        return Err(anyhow!("tlsmirror: invalid primary key size"));
    }
    let mut combined = Vec::with_capacity(96);
    combined.extend_from_slice(primary_key);
    combined.extend_from_slice(&client_random);
    combined.extend_from_slice(&server_random);

    let hkdf = Hkdf::<Sha256>::from_prk(&combined).map_err(|err| anyhow!("hkdf: invalid prk: {err}"))?;
    let mut encryption_key = vec![0u8; 16];
    hkdf.expand(format!("v2ray-sp76YMKM-EkGrFUNL-rTJRJMkU:tlsmirror-encryption{tag}").as_bytes(), &mut encryption_key)
        .map_err(|err| anyhow!("hkdf: expand failed: {err}"))?;
    let mut nonce_mask = vec![0u8; 12];
    hkdf.expand(format!("v2ray-sp76YMKM-EkGrFUNL-rTJRJMkU:tlsmirror-noncemask{tag}").as_bytes(), &mut nonce_mask)
        .map_err(|err| anyhow!("hkdf: expand failed: {err}"))?;
    Ok((encryption_key, nonce_mask))
}

pub(crate) fn derive_sequence_watermarking_key(
    primary_key: &[u8],
    client_random: [u8; 32],
    server_random: [u8; 32],
    tag: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if primary_key.len() != 32 {
        return Err(anyhow!("tlsmirror: invalid primary key size"));
    }
    let mut combined = Vec::with_capacity(96);
    combined.extend_from_slice(primary_key);
    combined.extend_from_slice(&client_random);
    combined.extend_from_slice(&server_random);

    let hkdf = Hkdf::<Sha256>::from_prk(&combined).map_err(|err| anyhow!("hkdf: invalid prk: {err}"))?;
    let mut encryption_key = vec![0u8; 32];
    hkdf.expand(
        format!("v2ray-xv64FXUU-GxMn8UYz-bTy6UDeE:tlsmirror-sequence-watermark-encryption{tag}").as_bytes(),
        &mut encryption_key,
    )
    .map_err(|err| anyhow!("hkdf: expand failed: {err}"))?;
    let mut nonce = vec![0u8; 24];
    hkdf.expand(
        format!("v2ray-xv64FXUU-GxMn8UYz-bTy6UDeE:tlsmirror-sequence-watermark-noncemask{tag}").as_bytes(),
        &mut nonce,
    )
    .map_err(|err| anyhow!("hkdf: expand failed: {err}"))?;
    Ok((encryption_key, nonce))
}

pub(crate) fn new_sequence_watermark(
    primary_key: &[u8],
    client_random: [u8; 32],
    server_random: [u8; 32],
    tag: &str,
) -> Result<XChaCha20> {
    let (key, nonce) = derive_sequence_watermarking_key(primary_key, client_random, server_random, tag)?;
    XChaCha20::new_from_slices(&key, &nonce).map_err(|err| anyhow!("chacha20: {err}"))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NonceGenerator {
    next: [u8; 8],
}

pub(crate) const fn new_nonce_generator() -> NonceGenerator {
    NonceGenerator { next: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff] }
}

impl NonceGenerator {
    pub(crate) fn next(&mut self) -> [u8; 8] {
        for b in &mut self.next {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        self.next
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ExplicitNonceGenerator {
    next: [u8; 8],
}

impl ExplicitNonceGenerator {
    pub(crate) fn next(&mut self) -> [u8; 8] {
        for byte in self.next.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        self.next
    }
}

pub(crate) struct Encryptor {
    nonce: NonceGenerator,
    aead: XorNonceAead,
}

pub(crate) fn new_encryptor(key: &[u8], mask: &[u8]) -> Result<Encryptor> {
    let aead = new_xor_nonce_aead(key, mask)?;
    Ok(Encryptor { nonce: new_nonce_generator(), aead })
}

impl Encryptor {
    pub(crate) fn seal(&mut self, dst: &mut Vec<u8>, src: &[u8]) -> Result<()> {
        let nonce = self.nonce.next();
        self.aead.seal(dst, &nonce, src, &[])
    }

    #[expect(
        clippy::unused_self,
        reason = "the AEAD overhead is constant, but callers read it through the live encryptor handle"
    )]
    pub(crate) fn overhead(&self) -> usize {
        XorNonceAead::OVERHEAD
    }
}

pub(crate) struct Decryptor {
    nonce: NonceGenerator,
    aead: XorNonceAead,
    next_nonce: Option<[u8; 8]>,
}

pub(crate) fn new_decryptor(key: &[u8], mask: &[u8]) -> Result<Decryptor> {
    let aead = new_xor_nonce_aead(key, mask)?;
    Ok(Decryptor { nonce: new_nonce_generator(), aead, next_nonce: None })
}

impl Decryptor {
    pub(crate) fn open(&mut self, src: &[u8]) -> Result<Vec<u8>> {
        let nonce = *self.next_nonce.get_or_insert_with(|| self.nonce.next());
        let out = self.aead.open(&nonce, src, &[])?;
        self.next_nonce = None;
        Ok(out)
    }

    #[expect(
        clippy::unused_self,
        reason = "the AEAD nonce size is constant, but callers read it through the live decryptor handle"
    )]
    pub(crate) fn nonce_size(&self) -> usize {
        XorNonceAead::NONCE_SIZE
    }
}
