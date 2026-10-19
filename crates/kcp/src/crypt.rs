//! The cipher suite and the block/stream cipher interfaces.
//!
//! Relocated verbatim from `transport-kcptun/src/common.rs`'s local `pub mod kcp` (same
//! semantics, same trait shapes): that module was a stand-in for this crate before it existed.
//! `transport-kcptun` keeps its own copy for now; a separate integration pass repoints it to
//! re-export from here.

use std::marker::PhantomData;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, KeyIvInit as _};
use aes_gcm::aead::{AeadInOut as _, Key, Nonce, Tag};
use aes_gcm::Aes128Gcm;
use anyhow::{anyhow, Result};
use cfb_mode::{Decryptor, Encryptor};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha1::Sha1;

/// The fixed IV used by the CFB ciphers.
pub(crate) const INITIAL_VECTOR: [u8; 16] = [167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107];

/// The salt XOR'd into the SimpleXor key.
pub(crate) const SALT_XOR: &str = "sH3CIVoF#rWLtJo6";

/// The maximum packet size accepted on the wire.
pub const MTU_LIMIT: usize = 1500;

/// PBKDF2 key derivation with HMAC-SHA1 as the PRF, used by [`SimpleXorCrypt::new`].
#[expect(
    clippy::expect_used,
    reason = "HMAC accepts a key of any length, so PBKDF2 cannot reject this key; ignoring the error would silently emit an all-zero key stream"
)]
fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::<Hmac<Sha1>>(password, salt, iterations, out).expect("HMAC can be initialized with any key length");
}

pub trait BlockCrypt: Send + Sync {
    fn encrypt(&self, dst: &mut [u8], src: &[u8]);

    fn decrypt(&self, dst: &mut [u8], src: &[u8]);

    /// Capability query: `AesGcmCrypt` overrides this to return `Some(self)`; every other cipher
    /// keeps the default `None`, so `session.rs`'s framing code can pick AEAD vs. nonce+crc
    /// framing without downcasting a `&dyn BlockCrypt`.
    fn as_aead(&self) -> Option<&dyn AeadCrypt> {
        None
    }
}

/// The AEAD cipher surface, used to pick AEAD framing.
pub trait AeadCrypt: BlockCrypt {
    fn seal<'a>(&self, dst: &'a mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> &'a [u8];

    fn open<'a>(
        &self,
        dst: &'a mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<&'a [u8]>;

    fn nonce_size(&self) -> usize;

    fn overhead(&self) -> usize;
}

fn xor_bytes(dst: &mut [u8], x: &[u8], y: &[u8]) {
    for ((d, a), b) in dst.iter_mut().zip(x.iter()).zip(y.iter()) {
        *d = a ^ b;
    }
}

/// Big-endian `u32` from the first four bytes of `b`, or zero if `b` is shorter.
fn read_u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.first_chunk::<4>().copied().unwrap_or_default())
}

/// Little-endian `u32` from the first four bytes of `b`, or zero if `b` is shorter.
fn read_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.first_chunk::<4>().copied().unwrap_or_default())
}

fn write_u32_be(b: &mut [u8], v: u32) {
    if let Some(word) = b.first_chunk_mut::<4>() {
        *word = v.to_be_bytes();
    }
}

pub struct SimpleXorCrypt {
    xortbl: Vec<u8>,
}

impl core::fmt::Debug for SimpleXorCrypt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SimpleXorCrypt").field("xortbl", &"<redacted>").finish()
    }
}

impl SimpleXorCrypt {
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut xortbl = vec![0u8; MTU_LIMIT];
        pbkdf2_sha1(key, SALT_XOR.as_bytes(), 32, &mut xortbl);
        Self { xortbl }
    }
}

impl BlockCrypt for SimpleXorCrypt {
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        xor_bytes(dst, src, &self.xortbl);
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        xor_bytes(dst, src, &self.xortbl);
    }
}

#[derive(Debug)]
pub struct NoneCrypt;

impl NoneCrypt {
    /// Builds a no-op crypt, which ignores its key.
    #[must_use]
    pub const fn new(_key: &[u8]) -> Self {
        Self
    }
}

impl BlockCrypt for NoneCrypt {
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        let n = dst.len().min(src.len());
        if let (Some(d), Some(s)) = (dst.get_mut(..n), src.get(..n)) {
            d.copy_from_slice(s);
        }
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        let n = dst.len().min(src.len());
        if let (Some(d), Some(s)) = (dst.get_mut(..n), src.get(..n)) {
            d.copy_from_slice(s);
        }
    }
}

/// CFB over a 16-byte block cipher, with the fixed [`INITIAL_VECTOR`].
pub struct AesCfbCrypt<C> {
    key: Vec<u8>,
    _cipher: PhantomData<C>,
}

impl<C> core::fmt::Debug for AesCfbCrypt<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesCfbCrypt").field("key", &"<redacted>").finish_non_exhaustive()
    }
}

impl<C> AesCfbCrypt<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + KeyInit + Send + Sync,
{
    pub fn new(key: &[u8]) -> Result<Self> {
        C::new_from_slice(key).map_err(|_| anyhow!("invalid AES key size {}", key.len()))?;
        Ok(Self { key: key.to_vec(), _cipher: PhantomData })
    }
}

impl<C> BlockCrypt for AesCfbCrypt<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + KeyInit + Send + Sync,
{
    #[expect(
        clippy::expect_used,
        reason = "`new` validated the key against `C` and the trait contract hands over equal-length buffers; `BlockCrypt::encrypt` has no error channel"
    )]
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        Encryptor::<C>::new_from_slices(&self.key, &INITIAL_VECTOR)
            .expect("AesCfbCrypt::new validated the key size")
            .encrypt_b2b(src, dst)
            .expect("equal buffer lengths");
    }

    #[expect(
        clippy::expect_used,
        reason = "`new` validated the key against `C` and the trait contract hands over equal-length buffers; `BlockCrypt::decrypt` has no error channel"
    )]
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        Decryptor::<C>::new_from_slices(&self.key, &INITIAL_VECTOR)
            .expect("AesCfbCrypt::new validated the key size")
            .decrypt_b2b(src, dst)
            .expect("equal buffer lengths");
    }
}

/// An AEAD crypt over AES-GCM.
pub struct AesGcmCrypt {
    cipher: Aes128Gcm,
}

impl core::fmt::Debug for AesGcmCrypt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AesGcmCrypt { cipher: <redacted> }")
    }
}

impl AesGcmCrypt {
    pub fn new(key: &[u8]) -> Result<Self> {
        let key = Key::<Aes128Gcm>::try_from(key).map_err(|_| anyhow!("invalid AES key size {}", key.len()))?;
        Ok(Self { cipher: Aes128Gcm::new(&key) })
    }
}

impl BlockCrypt for AesGcmCrypt {
    #[expect(
        clippy::panic,
        reason = "an AEAD cipher is only reached through `as_aead`; framing that ends up here must fail loudly instead of sending the payload in the clear"
    )]
    fn encrypt(&self, _dst: &mut [u8], _src: &[u8]) {
        panic!("called Encrypt on AEAD crypt");
    }

    #[expect(
        clippy::panic,
        reason = "an AEAD cipher is only reached through `as_aead`; framing that ends up here must fail loudly instead of emitting an undecryptable packet"
    )]
    fn decrypt(&self, _dst: &mut [u8], _src: &[u8]) {
        panic!("called Decrypt on AEAD crypt");
    }

    fn as_aead(&self) -> Option<&dyn AeadCrypt> {
        Some(self)
    }
}

impl AeadCrypt for AesGcmCrypt {
    #[expect(
        clippy::expect_used,
        reason = "`seal` returns the sealed slice and has no error channel; the nonce length and the reserved capacity come from this crate's own framing code"
    )]
    fn seal<'a>(&self, dst: &'a mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> &'a [u8] {
        assert!(
            dst.capacity() >= dst.len() + plaintext.len() + self.overhead(),
            "AEAD Seal allocated new slice, please increase MTU size"
        );
        let nonce = Nonce::<Aes128Gcm>::try_from(nonce).expect("incorrect nonce length for GCM");
        let start = dst.len();
        dst.extend_from_slice(plaintext);
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce, additional_data, dst.get_mut(start..).unwrap_or_default().into())
            .expect("message too large for GCM");
        dst.extend_from_slice(&tag);
        dst.get(start..).unwrap_or_default()
    }

    fn open<'a>(
        &self,
        dst: &'a mut Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<&'a [u8]> {
        let nonce = Nonce::<Aes128Gcm>::try_from(nonce).map_err(|_| anyhow!("incorrect nonce length for GCM"))?;
        if ciphertext.len() < self.overhead() {
            return Err(anyhow!("ciphertext too short"));
        }
        let start = dst.len();
        dst.extend_from_slice(ciphertext);
        let split = dst.len() - self.overhead();
        let result = {
            let (body, tag) = dst.get_mut(start..).unwrap_or_default().split_at_mut(split - start);
            Tag::<Aes128Gcm>::try_from(&*tag).map_err(|_| anyhow!("incorrect tag length")).and_then(|tag| {
                self.cipher
                    .decrypt_inout_detached(&nonce, additional_data, body.into(), &tag)
                    .map_err(|_| anyhow!("message authentication failed"))
            })
        };
        if result.is_err() {
            dst.truncate(start);
        }
        result?;
        Ok(dst.get(start..).unwrap_or_default())
    }

    fn nonce_size(&self) -> usize {
        12
    }

    fn overhead(&self) -> usize {
        16
    }
}

/// A block cipher with an 8-byte block: TEA and XTEA.
pub trait Block8: Send + Sync {
    fn block_encrypt(&self, dst: &mut [u8], src: &[u8]);
    fn block_decrypt(&self, dst: &mut [u8], src: &[u8]);
}

/// A crypt over an 8-byte block cipher.
pub struct BlockCrypt8<B: Block8> {
    block: B,
}

impl<B: Block8> core::fmt::Debug for BlockCrypt8<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BlockCrypt8 { block: <redacted> }")
    }
}

impl<B: Block8> BlockCrypt8<B> {
    pub const fn new(block: B) -> Self {
        Self { block }
    }
}

impl<B: Block8> BlockCrypt for BlockCrypt8<B> {
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        encrypt8(&self.block, dst, src);
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        decrypt8(&self.block, dst, src);
    }
}

fn encrypt8<B: Block8>(block: &B, dst: &mut [u8], src: &[u8]) {
    let mut tbl = [0u8; 8];
    block.block_encrypt(&mut tbl, &INITIAL_VECTOR[..8]);
    let n = src.len() / 8;
    let mut rest_src = src;
    let mut rest_dst = dst;
    for _ in 0..n {
        let (s_chunk, s_tail) = rest_src.split_at(8);
        let (d_chunk, d_tail) = rest_dst.split_at_mut(8);
        let mut c = [0u8; 8];
        for ((c_byte, s), t) in c.iter_mut().zip(s_chunk).zip(tbl.iter()) {
            *c_byte = *s ^ *t;
        }
        d_chunk.copy_from_slice(&c);
        block.block_encrypt(&mut tbl, &c);
        rest_src = s_tail;
        rest_dst = d_tail;
    }
    for ((out, s), t) in rest_dst.iter_mut().zip(rest_src).zip(tbl.iter()) {
        *out = *s ^ *t;
    }
}

fn decrypt8<B: Block8>(block: &B, dst: &mut [u8], src: &[u8]) {
    let mut tbl = [0u8; 8];
    block.block_encrypt(&mut tbl, &INITIAL_VECTOR[..8]);
    let n = src.len() / 8;
    let mut rest_src = src;
    let mut rest_dst = dst;
    for _ in 0..n {
        let (c, s_tail) = rest_src.split_at(8);
        let (d_chunk, d_tail) = rest_dst.split_at_mut(8);
        for ((out, src_byte), t) in d_chunk.iter_mut().zip(c).zip(tbl.iter()) {
            *out = *src_byte ^ *t;
        }
        block.block_encrypt(&mut tbl, c);
        rest_src = s_tail;
        rest_dst = d_tail;
    }
    for ((out, s), t) in rest_dst.iter_mut().zip(rest_src).zip(tbl.iter()) {
        *out = *s ^ *t;
    }
}

/// TEA.
pub struct Tea {
    key: [u8; 16],
    rounds: i32,
}

impl core::fmt::Debug for Tea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tea").field("key", &"<redacted>").field("rounds", &self.rounds).finish()
    }
}

impl Tea {
    pub fn new_with_rounds(key: &[u8], rounds: i32) -> Result<Self> {
        if key.len() != 16 {
            return Err(anyhow!("incorrect TEA key size"));
        }
        if rounds & 1 != 0 {
            return Err(anyhow!("odd number of TEA rounds specified"));
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        Ok(Self { key: k, rounds })
    }
}

impl Block8 for Tea {
    fn block_encrypt(&self, dst: &mut [u8], src: &[u8]) {
        let (s0, rest) = src.split_at(4);
        let (s1, _) = rest.split_at(4);
        let (mut v0, mut v1) = (read_u32_be(s0), read_u32_be(s1));
        let k0 = read_u32_be(&self.key[..4]);
        let k1 = read_u32_be(&self.key[4..8]);
        let k2 = read_u32_be(&self.key[8..12]);
        let k3 = read_u32_be(&self.key[12..16]);
        let delta: u32 = 0x9e37_79b9;
        let mut sum: u32 = 0;
        for _ in 0..self.rounds / 2 {
            sum = sum.wrapping_add(delta);
            v0 = v0.wrapping_add(((v1 << 4).wrapping_add(k0)) ^ (v1.wrapping_add(sum)) ^ ((v1 >> 5).wrapping_add(k1)));
            v1 = v1.wrapping_add(((v0 << 4).wrapping_add(k2)) ^ (v0.wrapping_add(sum)) ^ ((v0 >> 5).wrapping_add(k3)));
        }
        let (d0, rest) = dst.split_at_mut(4);
        let (d1, _) = rest.split_at_mut(4);
        write_u32_be(d0, v0);
        write_u32_be(d1, v1);
    }

    fn block_decrypt(&self, dst: &mut [u8], src: &[u8]) {
        let (s0, rest) = src.split_at(4);
        let (s1, _) = rest.split_at(4);
        let (mut v0, mut v1) = (read_u32_be(s0), read_u32_be(s1));
        let k0 = read_u32_be(&self.key[..4]);
        let k1 = read_u32_be(&self.key[4..8]);
        let k2 = read_u32_be(&self.key[8..12]);
        let k3 = read_u32_be(&self.key[12..16]);
        let delta: u32 = 0x9e37_79b9;
        let mut sum = delta.wrapping_mul((self.rounds / 2).cast_unsigned());
        for _ in 0..self.rounds / 2 {
            v1 = v1.wrapping_sub(((v0 << 4).wrapping_add(k2)) ^ (v0.wrapping_add(sum)) ^ ((v0 >> 5).wrapping_add(k3)));
            v0 = v0.wrapping_sub(((v1 << 4).wrapping_add(k0)) ^ (v1.wrapping_add(sum)) ^ ((v1 >> 5).wrapping_add(k1)));
            sum = sum.wrapping_sub(delta);
        }
        let (d0, rest) = dst.split_at_mut(4);
        let (d1, _) = rest.split_at_mut(4);
        write_u32_be(d0, v0);
        write_u32_be(d1, v1);
    }
}

/// XTEA.
pub struct Xtea {
    table: [u32; 64],
}

impl core::fmt::Debug for Xtea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Xtea { table: <redacted> }")
    }
}

impl Xtea {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(anyhow!("invalid XTEA key size {}", key.len()));
        }
        let mut k = [0u32; 4];
        for (ki, word) in k.iter_mut().zip(key.chunks_exact(4)) {
            *ki = read_u32_be(word);
        }
        let mut table = [0u32; 64];
        let delta: u32 = 0x9E37_79B9;
        let mut sum: u32 = 0;
        for pair in table.chunks_mut(2) {
            let Some([even, odd]) = pair.first_chunk_mut::<2>() else {
                break;
            };
            *even = sum.wrapping_add(k.get((sum & 3) as usize).copied().unwrap_or_default());
            sum = sum.wrapping_add(delta);
            *odd = sum.wrapping_add(k.get(((sum >> 11) & 3) as usize).copied().unwrap_or_default());
        }
        Ok(Self { table })
    }
}

impl Block8 for Xtea {
    fn block_encrypt(&self, dst: &mut [u8], src: &[u8]) {
        let (s0, rest) = src.split_at(4);
        let (s1, _) = rest.split_at(4);
        let (mut v0, mut v1) = (read_u32_be(s0), read_u32_be(s1));
        for pair in self.table.chunks_exact(2) {
            let Some([a, b]) = pair.first_chunk::<2>() else {
                break;
            };
            v0 = v0.wrapping_add(((v1 << 4 ^ v1 >> 5).wrapping_add(v1)) ^ *a);
            v1 = v1.wrapping_add(((v0 << 4 ^ v0 >> 5).wrapping_add(v0)) ^ *b);
        }
        let (d0, rest) = dst.split_at_mut(4);
        let (d1, _) = rest.split_at_mut(4);
        write_u32_be(d0, v0);
        write_u32_be(d1, v1);
    }

    fn block_decrypt(&self, dst: &mut [u8], src: &[u8]) {
        let (s0, rest) = src.split_at(4);
        let (s1, _) = rest.split_at(4);
        let (mut v0, mut v1) = (read_u32_be(s0), read_u32_be(s1));
        for pair in self.table.chunks_exact(2).rev() {
            let Some([a, b]) = pair.first_chunk::<2>() else {
                break;
            };
            v1 = v1.wrapping_sub(((v0 << 4 ^ v0 >> 5).wrapping_add(v0)) ^ *b);
            v0 = v0.wrapping_sub(((v1 << 4 ^ v1 >> 5).wrapping_add(v1)) ^ *a);
        }
        let (d0, rest) = dst.split_at_mut(4);
        let (d1, _) = rest.split_at_mut(4);
        write_u32_be(d0, v0);
        write_u32_be(d1, v1);
    }
}

/// Salsa20 core.
const SIGMA: [u8; 16] = *b"expand 32-byte k";

fn salsa20_core(out: &mut [u8; 64], input: &[u8; 16], key: &[u8; 32], c: &[u8; 16]) {
    let mut j = [0u32; 16];
    j[0] = read_u32_le(c);
    for (w, chunk) in j[1..5].iter_mut().zip(key.chunks_exact(4)) {
        *w = read_u32_le(chunk);
    }
    j[5] = read_u32_le(&c[4..]);
    for (w, chunk) in j[6..10].iter_mut().zip(input.chunks_exact(4)) {
        *w = read_u32_le(chunk);
    }
    j[10] = read_u32_le(&c[8..]);
    for (w, chunk) in j[11..15].iter_mut().zip(key[16..].chunks_exact(4)) {
        *w = read_u32_le(chunk);
    }
    j[15] = read_u32_le(&c[12..]);

    let mut x = j;
    for _ in 0..10 {
        x[4] ^= x[0].wrapping_add(x[12]).rotate_left(7);
        x[8] ^= x[4].wrapping_add(x[0]).rotate_left(9);
        x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
        x[0] ^= x[12].wrapping_add(x[8]).rotate_left(18);

        x[9] ^= x[5].wrapping_add(x[1]).rotate_left(7);
        x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
        x[1] ^= x[13].wrapping_add(x[9]).rotate_left(13);
        x[5] ^= x[1].wrapping_add(x[13]).rotate_left(18);

        x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
        x[2] ^= x[14].wrapping_add(x[10]).rotate_left(9);
        x[6] ^= x[2].wrapping_add(x[14]).rotate_left(13);
        x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);

        x[3] ^= x[15].wrapping_add(x[11]).rotate_left(7);
        x[7] ^= x[3].wrapping_add(x[15]).rotate_left(9);
        x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
        x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);

        x[1] ^= x[0].wrapping_add(x[3]).rotate_left(7);
        x[2] ^= x[1].wrapping_add(x[0]).rotate_left(9);
        x[3] ^= x[2].wrapping_add(x[1]).rotate_left(13);
        x[0] ^= x[3].wrapping_add(x[2]).rotate_left(18);

        x[6] ^= x[5].wrapping_add(x[4]).rotate_left(7);
        x[7] ^= x[6].wrapping_add(x[5]).rotate_left(9);
        x[4] ^= x[7].wrapping_add(x[6]).rotate_left(13);
        x[5] ^= x[4].wrapping_add(x[7]).rotate_left(18);

        x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
        x[8] ^= x[11].wrapping_add(x[10]).rotate_left(9);
        x[9] ^= x[8].wrapping_add(x[11]).rotate_left(13);
        x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);

        x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
        x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
        x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
        x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
    }
    for (v, k) in x.iter_mut().zip(j) {
        *v = v.wrapping_add(k);
    }
    for (chunk, v) in out.chunks_exact_mut(4).zip(x.iter()) {
        chunk.copy_from_slice(&v.to_le_bytes());
    }
}

fn salsa20_xor_key_stream(out: &mut [u8], input: &[u8], counter: &[u8; 16], key: &[u8; 32]) {
    let mut block = [0u8; 64];
    let mut counter_copy = *counter;
    let mut rest_out = out;
    let mut rest_in = input;
    while rest_in.len() >= 64 {
        salsa20_core(&mut block, &counter_copy, key, &SIGMA);
        let (in_chunk, in_tail) = rest_in.split_at(64);
        let (out_chunk, out_tail) = rest_out.split_at_mut(rest_out.len().min(64));
        for ((o, s), b) in out_chunk.iter_mut().zip(in_chunk).zip(block.iter()) {
            *o = *s ^ *b;
        }
        let mut u: u32 = 1;
        for byte in &mut counter_copy[8..16] {
            u = u.wrapping_add(u32::from(*byte));
            *byte = u.to_le_bytes()[0];
            u >>= 8;
        }
        rest_out = out_tail;
        rest_in = in_tail;
    }
    if !rest_in.is_empty() {
        salsa20_core(&mut block, &counter_copy, key, &SIGMA);
        for ((o, s), b) in rest_out.iter_mut().zip(rest_in).zip(block.iter()) {
            *o = *s ^ *b;
        }
    }
}

pub struct Salsa20Crypt {
    key: [u8; 32],
}

impl core::fmt::Debug for Salsa20Crypt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Salsa20Crypt").field("key", &"<redacted>").finish()
    }
}

impl Salsa20Crypt {
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 32];
        for (slot, byte) in k.iter_mut().zip(key) {
            *slot = *byte;
        }
        Self { key: k }
    }

    fn xor_key_stream(&self, dst: &mut [u8], src: &[u8]) {
        let (iv, body) = src.split_at(8);
        let (dst_iv, dst_body) = dst.split_at_mut(8);
        let mut counter = [0u8; 16];
        if let Some(head) = counter.first_chunk_mut::<8>() {
            head.copy_from_slice(iv);
        }
        salsa20_xor_key_stream(dst_body, body, &counter, &self.key);
        dst_iv.copy_from_slice(iv);
    }
}

impl BlockCrypt for Salsa20Crypt {
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        self.xor_key_stream(dst, src);
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        self.xor_key_stream(dst, src);
    }
}

/// Whether a `dyn BlockCrypt` is actually AEAD, and if so its per-packet costs.
///
/// A trait object cannot be downcast here, so callers that construct an AEAD cipher must also hand
/// back an [`AeadCrypt`] reference alongside the [`BlockCrypt`] one (see `session::CryptoMode`).
pub enum CryptoMode<'a> {
    None,
    Aead(&'a dyn AeadCrypt),
    Block(&'a dyn BlockCrypt),
}

impl core::fmt::Debug for CryptoMode<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Aead(_) => f.write_str("Aead"),
            Self::Block(_) => f.write_str("Block"),
        }
    }
}

/// Size of the per-packet nonce for non-AEAD ciphers.
pub const NONCE_SIZE: usize = 16;
/// Size of the packet checksum.
pub const CRC_SIZE: usize = 4;
/// Overall crypto header size for non-AEAD ciphers.
pub const CRYPT_HEADER_SIZE: usize = NONCE_SIZE + CRC_SIZE;

/// Fills `p` with CSPRNG output for a packet nonce.
///
/// A thread-local OS-seeded CSPRNG is used rather than a hand-rolled AES/ChaCha8 reseeding scheme:
/// the latter is a performance optimization over the OS entropy source with no wire-visible
/// effect, since a nonce only needs to be unpredictable.
pub fn fill_rand(p: &mut [u8]) {
    use rand::RngCore as _;
    rand::rng().fill_bytes(p);
}

/// The per-packet encrypt step, given a buffer laid out as
/// `[crypto header reservation][payload]`.
///
/// The crypto header reservation is exactly [`CryptoMode`]'s header size for this mode. Encrypts
/// `buf` in place (for AEAD, in place plus an appended tag) and returns nothing since `buf` itself
/// becomes the wire packet.
pub fn seal_packet(mode: &CryptoMode<'_>, buf: &mut Vec<u8>) {
    match mode {
        CryptoMode::None => {}
        CryptoMode::Aead(aead) => {
            let nonce_size = aead.nonce_size();
            let plaintext = buf.split_off(nonce_size);
            fill_rand(buf);
            let nonce = buf.clone();
            buf.reserve(plaintext.len() + aead.overhead());
            aead.seal(buf, &nonce, &plaintext, &[]);
        }
        CryptoMode::Block(block) => {
            if let Some(nonce) = buf.get_mut(..NONCE_SIZE) {
                fill_rand(nonce);
            }
            let checksum = crc32fast::hash(buf.get(CRYPT_HEADER_SIZE..).unwrap_or_default());
            if let Some(slot) = buf.get_mut(NONCE_SIZE..CRYPT_HEADER_SIZE) {
                slot.copy_from_slice(&checksum.to_le_bytes());
            }
            let src = buf.clone();
            block.encrypt(buf, &src);
        }
    }
}

/// Decrypts a packet and verifies its CRC. Returns the payload with the crypto header stripped,
/// or `None` if the packet is malformed or fails authentication, in which case it is dropped.
#[must_use]
pub fn open_packet(mode: &CryptoMode<'_>, data: Vec<u8>) -> Option<Vec<u8>> {
    match mode {
        CryptoMode::None => Some(data),
        CryptoMode::Aead(aead) => {
            let nonce_size = aead.nonce_size();
            if data.len() < nonce_size + aead.overhead() {
                return None;
            }
            let nonce = data.get(..nonce_size)?.to_vec();
            let ciphertext = data.get(nonce_size..)?;
            let mut dst = Vec::with_capacity(ciphertext.len());
            aead.open(&mut dst, &nonce, ciphertext, &[]).ok()?;
            Some(dst)
        }
        CryptoMode::Block(block) => {
            if data.len() < CRYPT_HEADER_SIZE {
                return None;
            }
            let mut decrypted = vec![0u8; data.len()];
            block.decrypt(&mut decrypted, &data);
            let checksum = u32::from_le_bytes(decrypted.get(NONCE_SIZE..CRYPT_HEADER_SIZE)?.try_into().ok()?);
            if crc32fast::hash(decrypted.get(CRYPT_HEADER_SIZE..)?) != checksum {
                return None;
            }
            Some(decrypted.get(CRYPT_HEADER_SIZE..)?.to_vec())
        }
    }
}

/// Header bytes reserved at the front of every outgoing wire packet for this crypto mode: `0`,
/// the AEAD nonce size, or [`CRYPT_HEADER_SIZE`].
#[must_use]
pub fn header_size(mode: &CryptoMode<'_>) -> usize {
    match mode {
        CryptoMode::None => 0,
        CryptoMode::Aead(aead) => aead.nonce_size(),
        CryptoMode::Block(_) => CRYPT_HEADER_SIZE,
    }
}

/// AEAD per-packet framing overhead (tag), subtracted from the MTU.
#[must_use]
pub fn aead_overhead(mode: &CryptoMode<'_>) -> usize {
    match mode {
        CryptoMode::Aead(aead) => aead.overhead(),
        CryptoMode::None | CryptoMode::Block(_) => 0,
    }
}
