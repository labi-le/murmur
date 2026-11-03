use std::sync::Arc;

use aes_gcm::aead::{Aead as _, Key, Nonce, Payload};
use aes_gcm::{Aes128Gcm, KeyInit as _};
use anyhow::{anyhow, Result};

pub(crate) trait Aead: Send + Sync + std::fmt::Debug {
    fn nonce_size(&self) -> usize;

    fn overhead(&self) -> usize;

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plain: &[u8], extra: &[u8]) -> Result<()>;

    fn open(&self, dst: &mut Vec<u8>, nonce: &[u8], ciphertext: &[u8], extra: &[u8]) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SimpleAuthenticator {}

pub(crate) fn new_simple_authenticator() -> Arc<dyn Aead> {
    Arc::new(SimpleAuthenticator {})
}

impl Aead for SimpleAuthenticator {
    fn nonce_size(&self) -> usize {
        0
    }

    fn overhead(&self) -> usize {
        6
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the length field is 16 bits by protocol; a frame past it is truncated onto the \
                  wire"
    )]
    fn seal(&self, dst: &mut Vec<u8>, _nonce: &[u8], plain: &[u8], _extra: &[u8]) -> Result<()> {
        let start = dst.len();
        dst.extend_from_slice(&[0u8; 6]);
        dst.extend_from_slice(plain);

        let (_, body) = dst.split_at_mut(start);
        let (hash_out, rest) = body.split_at_mut(4);
        let (len_out, plain_out) = rest.split_at_mut(2);
        plain_out.copy_from_slice(plain);
        let len = plain.len() as u16;
        len_out.copy_from_slice(&len.to_be_bytes());
        hash_out.copy_from_slice(&fnv32a(rest).to_be_bytes());

        let dst_len = dst.len();
        let extra = 4 - dst_len % 4;
        if extra != 4 {
            dst.extend(std::iter::repeat_n(0u8, extra));
        }
        xorfwd(dst.split_at_mut(start).1);
        dst.truncate(dst_len);
        Ok(())
    }

    fn open(&self, dst: &mut Vec<u8>, _nonce: &[u8], ciphertext: &[u8], _extra: &[u8]) -> Result<()> {
        let start = dst.len();
        dst.extend_from_slice(ciphertext);
        let dst_len = dst.len();
        let extra = 4 - dst_len % 4;
        if extra != 4 {
            dst.extend(std::iter::repeat_n(0u8, extra));
        }
        xorbkd(dst.split_at_mut(start).1);
        dst.truncate(dst_len);

        let (_, body) = dst.split_at(start);
        let [h0, h1, h2, h3, rest @ ..] = body else {
            return Err(anyhow!("mkcp: invalid auth"));
        };
        let [l0, l1, payload @ ..] = rest else {
            return Err(anyhow!("mkcp: invalid auth"));
        };
        if u32::from_be_bytes([*h0, *h1, *h2, *h3]) != fnv32a(rest) {
            return Err(anyhow!("mkcp: invalid auth"));
        }
        let length = usize::from(u16::from_be_bytes([*l0, *l1]));
        if payload.len() != length {
            return Err(anyhow!("mkcp: invalid auth"));
        }
        dst.drain(start..start + 6);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GcmAead {
    cipher: Aes128Gcm,
}

impl GcmAead {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        let key =
            Key::<Aes128Gcm>::try_from(key).map_err(|_| anyhow!("invalid aes-128-gcm key length: {}", key.len()))?;
        Ok(Self { cipher: Aes128Gcm::new(&key) })
    }
}

impl Aead for GcmAead {
    fn nonce_size(&self) -> usize {
        12
    }

    fn overhead(&self) -> usize {
        16
    }

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plain: &[u8], extra: &[u8]) -> Result<()> {
        let nonce =
            Nonce::<Aes128Gcm>::try_from(nonce).map_err(|_| anyhow!("mkcp: invalid nonce size: {}", nonce.len()))?;
        let sealed = self
            .cipher
            .encrypt(&nonce, Payload { msg: plain, aad: extra })
            .map_err(|_| anyhow!("mkcp: seal failed"))?;
        dst.extend_from_slice(&sealed);
        Ok(())
    }

    fn open(&self, dst: &mut Vec<u8>, nonce: &[u8], ciphertext: &[u8], extra: &[u8]) -> Result<()> {
        let nonce =
            Nonce::<Aes128Gcm>::try_from(nonce).map_err(|_| anyhow!("mkcp: invalid nonce size: {}", nonce.len()))?;
        let plain = self
            .cipher
            .decrypt(&nonce, Payload { msg: ciphertext, aad: extra })
            .map_err(|_| anyhow!("mkcp: invalid auth"))?;
        dst.extend_from_slice(&plain);
        Ok(())
    }
}

fn fnv32a(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in data {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn xorfwd(x: &mut [u8]) {
    for i in 4..x.len() {
        let (low, high) = x.split_at_mut(i);
        let Some(source) = low.get(i - 4) else { continue };
        let Some(target) = high.first_mut() else { continue };
        *target ^= *source;
    }
}

fn xorbkd(x: &mut [u8]) {
    for i in (4..x.len()).rev() {
        let (low, high) = x.split_at_mut(i);
        let Some(source) = low.get(i - 4) else { continue };
        let Some(target) = high.first_mut() else { continue };
        *target ^= *source;
    }
}
