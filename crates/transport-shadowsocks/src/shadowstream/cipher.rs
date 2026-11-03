use std::fmt;

use aes::cipher::array::Array;
use aes::cipher::consts::U16;
use aes::cipher::{BlockCipherEncrypt, InOutBuf, InnerIvInit as _, KeyInit, StreamCipher, StreamCipherError};
use aes::{Aes128, Aes192, Aes256};
use cfb_mode::{BufDecryptor, BufEncryptor};
use ctr::flavors::Ctr128BE as Ctr128BeFlavor;
use ctr::{Ctr128BE, CtrCore};
use md5::{Digest, Md5};

pub trait Cipher: Send + Sync + fmt::Debug {
    fn iv_size(&self) -> usize;

    fn encrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync>;

    fn decrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync>;
}

/// `KeySizeError`, whose message names the size the cipher needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("key size error: need {0} bytes")]
pub struct KeySizeError(pub i32);

fn aes_key_size_error(size: usize) -> anyhow::Error {
    anyhow::anyhow!("invalid AES key size {size}")
}

/// Picks the AES variant from the key length.
fn new_aes_block<C: KeyInit>(key: &[u8]) -> anyhow::Result<C> {
    C::new_from_slice(key).map_err(|_| aes_key_size_error(key.len()))
}

/// The shared IV check for CTR and CFB, which panics.
#[expect(
    clippy::panic,
    reason = "`Cipher::encrypter` and `Cipher::decrypter` return a stream rather than an error, so a wrong-length IV can only abort"
)]
fn new_block_iv(iv: &[u8], panic_message: &str) -> Array<u8, U16> {
    let Ok(iv) = <[u8; 16]>::try_from(iv) else {
        panic!("{panic_message}");
    };
    Array::from(iv)
}

/// CTR mode over the block cipher the cipher keeps.
pub(crate) struct CtrStream<C> {
    block: C,
}

impl<C> CtrStream<C> {
    const fn new(block: C) -> Self {
        Self { block }
    }
}

impl<C> fmt::Debug for CtrStream<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtrStream").finish_non_exhaustive()
    }
}

impl<C> Cipher for CtrStream<C>
where
    C: BlockCipherEncrypt<BlockSize = U16> + KeyInit + Clone + Send + Sync + 'static,
{
    fn iv_size(&self) -> usize {
        C::block_size()
    }

    fn encrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        let iv = new_block_iv(iv, "cipher.NewCTR: IV length must equal block size");
        let core = CtrCore::<C, Ctr128BeFlavor>::inner_iv_init(self.block.clone(), &iv);
        Box::new(Ctr128BE::<C>::from_core(core))
    }

    fn decrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        self.encrypter(iv)
    }
}

pub fn aesctr(key: &[u8]) -> anyhow::Result<Box<dyn Cipher>> {
    match key.len() {
        16 => Ok(Box::new(CtrStream::new(new_aes_block::<Aes128>(key)?))),
        24 => Ok(Box::new(CtrStream::new(new_aes_block::<Aes192>(key)?))),
        32 => Ok(Box::new(CtrStream::new(new_aes_block::<Aes256>(key)?))),
        size => Err(aes_key_size_error(size)),
    }
}

/// CFB mode over the block cipher the cipher keeps.
pub(crate) struct CfbStream<C> {
    block: C,
}

impl<C> CfbStream<C> {
    const fn new(block: C) -> Self {
        Self { block }
    }
}

impl<C> fmt::Debug for CfbStream<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CfbStream").finish_non_exhaustive()
    }
}

impl<C> Cipher for CfbStream<C>
where
    C: BlockCipherEncrypt<BlockSize = U16> + KeyInit + Clone + Send + Sync + 'static,
{
    fn iv_size(&self) -> usize {
        C::block_size()
    }

    fn encrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        let iv = new_block_iv(iv, "cipher.newCFB: IV length must equal block size");
        let cipher = BufEncryptor::<C>::inner_iv_init(self.block.clone(), &iv);
        Box::new(CfbEncryptor { cipher })
    }

    fn decrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        let iv = new_block_iv(iv, "cipher.newCFB: IV length must equal block size");
        let cipher = BufDecryptor::<C>::inner_iv_init(self.block.clone(), &iv);
        Box::new(CfbDecryptor { cipher })
    }
}

/// The CFB-128 encrypting stream, whose byte-wise state persists across calls.
struct CfbEncryptor<C: BlockCipherEncrypt> {
    cipher: BufEncryptor<C>,
}

impl<C> StreamCipher for CfbEncryptor<C>
where
    C: BlockCipherEncrypt<BlockSize = U16> + Send + Sync + 'static,
{
    fn check_remaining(&self, _data_len: usize) -> Result<(), StreamCipherError> {
        Ok(())
    }

    fn unchecked_apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>) {
        self.cipher.encrypt(buf.into_out_with_copied_in());
    }

    fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
        buf.fill(0);
        self.unchecked_apply_keystream(buf);
    }
}

/// The CFB-128 decrypting stream, whose byte-wise state persists across calls.
struct CfbDecryptor<C: BlockCipherEncrypt> {
    cipher: BufDecryptor<C>,
}

impl<C> StreamCipher for CfbDecryptor<C>
where
    C: BlockCipherEncrypt<BlockSize = U16> + Send + Sync + 'static,
{
    fn check_remaining(&self, _data_len: usize) -> Result<(), StreamCipherError> {
        Ok(())
    }

    fn unchecked_apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>) {
        self.cipher.decrypt(buf.into_out_with_copied_in());
    }

    fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
        buf.fill(0);
        self.unchecked_apply_keystream(buf);
    }
}

pub fn aescfb(key: &[u8]) -> anyhow::Result<Box<dyn Cipher>> {
    match key.len() {
        16 => Ok(Box::new(CfbStream::new(new_aes_block::<Aes128>(key)?))),
        24 => Ok(Box::new(CfbStream::new(new_aes_block::<Aes192>(key)?))),
        32 => Ok(Box::new(CfbStream::new(new_aes_block::<Aes256>(key)?))),
        size => Err(aes_key_size_error(size)),
    }
}

pub(crate) struct Rc4Md5Key {
    key: Vec<u8>,
}

impl Rc4Md5Key {
    fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl fmt::Debug for Rc4Md5Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc4Md5Key").finish_non_exhaustive()
    }
}

impl Cipher for Rc4Md5Key {
    /// Hard-coded to 16 for this cipher rather than derived from the block size.
    fn iv_size(&self) -> usize {
        16
    }

    fn encrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        let mut h = Md5::new();
        h.update(&self.key);
        h.update(iv);
        let rc4_key: [u8; 16] = h.finalize().into();
        Box::new(Rc4::new(&rc4_key))
    }

    fn decrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        self.encrypter(iv)
    }
}

/// The RC4-MD5 cipher, which never reports a key-size error.
pub fn rc4md5(key: &[u8]) -> anyhow::Result<Box<dyn Cipher>> {
    Ok(Box::new(Rc4Md5Key::new(key)))
}

/// The RC4 stream cipher, written out here because no RC4 crate is pinned.
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// RC4; `Rc4Md5Key` always hands it the 16-byte MD5 digest, so the key-size error
    /// it discards cannot be reached.
    #[expect(
        clippy::indexing_slicing,
        reason = "the `take(256)` loop keeps `i` inside the 256-entry state the loop just filled"
    )]
    fn new(key: &[u8]) -> Self {
        let k = key.len();
        assert!((1..=256).contains(&k), "invalid RC4 key size {k}");
        let mut s = [0u8; 256];
        for (v, i) in s.iter_mut().zip(0u8..=u8::MAX) {
            *v = i;
        }
        let mut j: u8 = 0;
        for (i, k) in key.iter().cycle().take(256).enumerate() {
            j = j.wrapping_add(s[i]).wrapping_add(*k);
            s.swap(i, usize::from(j));
        }
        Self { s, i: 0, j: 0 }
    }
}

impl StreamCipher for Rc4 {
    fn check_remaining(&self, _data_len: usize) -> Result<(), StreamCipherError> {
        Ok(())
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "`i`, `j` and the XOR key are all bytes, so they always index the 256-entry state, and `StreamCipher` has no error channel for a miss"
    )]
    fn unchecked_apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>) {
        for v in buf.into_out_with_copied_in() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
            *v ^= self.s[k as usize];
        }
    }

    fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
        buf.fill(0);
        self.unchecked_apply_keystream(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6229 §2.1, key `0102030405`: the KSA must fill the state with `0..=255` — the byte-at-a-time
    /// spelling of that fill used to panic on overflow at `255u8`, so every RC4-MD5 conn failed to build.
    #[test]
    fn rc4_matches_rfc_6229_vector() {
        let mut c = Rc4::new(&[0x01, 0x02, 0x03, 0x04, 0x05]);
        let mut buf = [0u8; 16];
        c.apply_keystream(&mut buf);
        assert_eq!(
            buf,
            [0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8]
        );
    }

    #[test]
    fn rc4md5_round_trips_and_uses_the_iv() {
        let key = rc4md5(b"secret").expect("RC4MD5 never fails");
        assert_eq!(key.iv_size(), 16);

        let iv = [7u8; 16];
        let plaintext = b"the quick brown fox".to_vec();
        let mut sealed = plaintext.clone();
        key.encrypter(&iv).apply_keystream(&mut sealed);
        assert_ne!(sealed, plaintext);

        let mut opened = sealed.clone();
        key.decrypter(&iv).apply_keystream(&mut opened);
        assert_eq!(opened, plaintext);

        let mut other_iv = plaintext.clone();
        key.encrypter(&[8u8; 16]).apply_keystream(&mut other_iv);
        assert_ne!(other_iv, sealed);
    }
}
