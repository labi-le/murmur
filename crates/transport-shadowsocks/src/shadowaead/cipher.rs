use std::fmt;

use aes::cipher::{BlockCipherEncrypt, KeyInit as _};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{AeadInOut, Nonce, Tag};
use aes_gcm::{Aes128Gcm, Aes256Gcm};

/// The 192-bit AES-GCM type: the `aes-gcm` crate aliases only 128 and 256, so 192 is spelled out.
type Aes192Gcm = aes_gcm::AesGcm<Aes192, aes_gcm::aead::consts::U12>;
use anyhow::{anyhow, Result};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha8, Key};
use hkdf::Hkdf;
use poly1305::universal_hash::UniversalHash as _;
use poly1305::Poly1305;
use sha1::Sha1;
use subtle::ConstantTimeEq;

pub trait Aead: Send + Sync + fmt::Debug {
    fn nonce_size(&self) -> usize;

    fn overhead(&self) -> usize;

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<()>;

    fn open(&self, nonce: &[u8], ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>>;

    /// Decrypts `buf` in place and returns the plaintext prefix. The default falls back to
    /// [`Aead::open`] and copies the result back over `buf`; [`GcmAead`] and [`ChaChaAead`]
    /// override it to decrypt directly with no extra allocation.
    fn open_in_place<'a>(&self, nonce: &[u8], buf: &'a mut [u8], additional_data: &[u8]) -> Result<&'a mut [u8]> {
        let plaintext = self.open(nonce, buf, additional_data)?;
        let n = plaintext.len();
        let (head, _) = buf.split_at_mut(n);
        head.copy_from_slice(&plaintext);
        Ok(head)
    }
}

pub trait Cipher: Send + Sync + fmt::Debug {
    fn key_size(&self) -> usize;
    fn salt_size(&self) -> usize;
    fn encrypter(&self, salt: &[u8]) -> Result<Box<dyn Aead>>;
    fn decrypter(&self, salt: &[u8]) -> Result<Box<dyn Aead>>;
}

#[derive(Debug, Clone, Copy)]
pub struct KeySizeError(pub i32);

impl fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key size error: need {} bytes", self.0)
    }
}

impl std::error::Error for KeySizeError {}

fn hkdf_sha1(secret: &[u8], salt: &[u8], info: &[u8], out_key: &mut [u8]) -> Result<()> {
    let hkdf = Hkdf::<Sha1>::new(Some(salt), secret);
    hkdf.expand(info, out_key).map_err(|_| anyhow!("hkdf: output larger than 255 * hash length"))?;
    Ok(())
}

type MakeAead = fn(&[u8]) -> Result<Box<dyn Aead>>;

#[derive(Debug)]
pub(crate) struct MetaCipher {
    psk: Vec<u8>,
    make_aead: MakeAead,
}

impl Cipher for MetaCipher {
    fn key_size(&self) -> usize {
        self.psk.len()
    }

    fn salt_size(&self) -> usize {
        let key_size = self.key_size();
        if key_size > 16 {
            key_size
        } else {
            16
        }
    }

    fn encrypter(&self, salt: &[u8]) -> Result<Box<dyn Aead>> {
        let mut subkey = vec![0u8; self.key_size()];
        hkdf_sha1(&self.psk, salt, b"ss-subkey", &mut subkey)?;
        (self.make_aead)(&subkey)
    }

    fn decrypter(&self, salt: &[u8]) -> Result<Box<dyn Aead>> {
        let mut subkey = vec![0u8; self.key_size()];
        hkdf_sha1(&self.psk, salt, b"ss-subkey", &mut subkey)?;
        (self.make_aead)(&subkey)
    }
}

/// The key-size error the AEADs report for an unknown key length.
fn aes_key_size_error(size: usize) -> anyhow::Error {
    anyhow!("invalid AES key size {size}")
}

/// The key-size error the chacha ciphers report, whose only legal size is `CHACHA_KEY_SIZE`.
fn chacha_key_size_error() -> anyhow::Error {
    match i32::try_from(CHACHA_KEY_SIZE) {
        Ok(need) => KeySizeError(need).into(),
        Err(_) => anyhow!("chacha20poly1305: bad key length"),
    }
}

/// `chacha20poly1305`'s 16-byte Poly1305 tag, which every AEAD here carries.
const TAG_SIZE: usize = 16;

/// The GCM nonce size.
const GCM_NONCE_SIZE: usize = 12;

const CHACHA_NONCE_SIZE: usize = 12;

const XCHACHA_NONCE_SIZE: usize = 24;

/// The ChaCha20-Poly1305 key size.
const CHACHA_KEY_SIZE: usize = 32;

/// One ChaCha block, skipped before the payload (the counter starts at 1).
const CHACHA_BLOCK_SIZE: usize = 64;

/// The AES-GCM construction: the pinned `aes-gcm` appends its tag after the ciphertext.
#[derive(Debug)]
struct GcmAead<C> {
    cipher: C,
}

/// The ChaCha20-Poly1305 construction, or its XChaCha variant.
#[derive(Debug)]
struct ChaChaAead<C> {
    cipher: C,
    nonce_size: usize,
}

fn tagged_seal<C>(
    cipher: &C,
    dst: &mut Vec<u8>,
    nonce: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
    nonce_error: &str,
    too_large_error: &str,
) -> Result<()>
where
    C: AeadInOut<TagSize = U16>,
{
    let nonce = Nonce::<C>::try_from(nonce).map_err(|_| anyhow!("{nonce_error}"))?;
    let start = dst.len();
    dst.extend_from_slice(plaintext);
    let (_, appended) = dst.split_at_mut(start);
    let tag = cipher
        .encrypt_inout_detached(&nonce, additional_data, (&mut *appended).into())
        .map_err(|_| anyhow!("{too_large_error}"))?;
    dst.extend_from_slice(&tag);
    Ok(())
}

fn tagged_open<C>(
    cipher: &C,
    nonce: &[u8],
    ciphertext: &[u8],
    additional_data: &[u8],
    nonce_error: &str,
    auth_error: &str,
) -> Result<Vec<u8>>
where
    C: AeadInOut<TagSize = U16>,
{
    let nonce = Nonce::<C>::try_from(nonce).map_err(|_| anyhow!("{nonce_error}"))?;
    if ciphertext.len() < TAG_SIZE {
        return Err(anyhow!("{auth_error}"));
    }
    let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);
    let tag = Tag::<C>::try_from(tag).map_err(|_| anyhow!("{auth_error}"))?;
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_inout_detached(&nonce, additional_data, (&mut plaintext[..]).into(), &tag)
        .map_err(|_| anyhow!("{auth_error}"))?;
    Ok(plaintext)
}

fn tagged_open_in_place<'a, C>(
    cipher: &C,
    nonce: &[u8],
    buf: &'a mut [u8],
    additional_data: &[u8],
    nonce_error: &str,
    auth_error: &str,
) -> Result<&'a mut [u8]>
where
    C: AeadInOut<TagSize = U16>,
{
    let nonce = Nonce::<C>::try_from(nonce).map_err(|_| anyhow!("{nonce_error}"))?;
    if buf.len() < TAG_SIZE {
        return Err(anyhow!("{auth_error}"));
    }
    let plain_len = buf.len() - TAG_SIZE;
    let (ciphertext, tag) = buf.split_at_mut(plain_len);
    let tag = Tag::<C>::try_from(&tag[..]).map_err(|_| anyhow!("{auth_error}"))?;
    cipher
        .decrypt_inout_detached(&nonce, additional_data, (&mut *ciphertext).into(), &tag)
        .map_err(|_| anyhow!("{auth_error}"))?;
    Ok(ciphertext)
}

impl<C> Aead for GcmAead<C>
where
    C: AeadInOut<TagSize = U16> + Send + Sync + fmt::Debug,
{
    fn nonce_size(&self) -> usize {
        GCM_NONCE_SIZE
    }

    fn overhead(&self) -> usize {
        TAG_SIZE
    }

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<()> {
        tagged_seal(
            &self.cipher,
            dst,
            nonce,
            plaintext,
            additional_data,
            "incorrect nonce length for GCM",
            "cipher: message too large for GCM",
        )
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>> {
        tagged_open(
            &self.cipher,
            nonce,
            ciphertext,
            additional_data,
            "incorrect nonce length for GCM",
            "cipher: message authentication failed",
        )
    }

    fn open_in_place<'a>(&self, nonce: &[u8], buf: &'a mut [u8], additional_data: &[u8]) -> Result<&'a mut [u8]> {
        tagged_open_in_place(
            &self.cipher,
            nonce,
            buf,
            additional_data,
            "incorrect nonce length for GCM",
            "cipher: message authentication failed",
        )
    }
}

impl<C> Aead for ChaChaAead<C>
where
    C: AeadInOut<TagSize = U16> + Send + Sync + fmt::Debug,
{
    fn nonce_size(&self) -> usize {
        self.nonce_size
    }

    fn overhead(&self) -> usize {
        TAG_SIZE
    }

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<()> {
        tagged_seal(
            &self.cipher,
            dst,
            nonce,
            plaintext,
            additional_data,
            "chacha20poly1305: bad nonce length passed to Seal",
            "chacha20poly1305: plaintext too large",
        )
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>> {
        tagged_open(
            &self.cipher,
            nonce,
            ciphertext,
            additional_data,
            "chacha20poly1305: bad nonce length passed to Open",
            "cipher: message authentication failed",
        )
    }

    fn open_in_place<'a>(&self, nonce: &[u8], buf: &'a mut [u8], additional_data: &[u8]) -> Result<&'a mut [u8]> {
        tagged_open_in_place(
            &self.cipher,
            nonce,
            buf,
            additional_data,
            "chacha20poly1305: bad nonce length passed to Open",
            "cipher: message authentication failed",
        )
    }
}

/// The 8-round ChaCha20-Poly1305 construction, which the pinned `chacha20poly1305` only offers
/// behind its unused `reduced-round` feature.
struct ChaCha8Aead {
    key: [u8; CHACHA_KEY_SIZE],
}

impl fmt::Debug for ChaCha8Aead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChaCha8Aead").finish_non_exhaustive()
    }
}

impl ChaCha8Aead {
    fn stream(&self, nonce: &[u8], error: &str) -> Result<ChaCha8> {
        let key = Key::from(self.key);
        let nonce = chacha20::Nonce::try_from(nonce).map_err(|_| anyhow!("{error}"))?;
        Ok(ChaCha8::new(&key, &nonce))
    }
}

/// The ChaCha20-Poly1305 lengths block: LE64 of the aad length, then LE64 of the payload's.
fn length_block(additional_data_len: usize, payload_len: usize) -> poly1305::Block {
    let mut block = poly1305::Block::default();
    let (aad_len, payload_bytes) = block.split_at_mut(8);
    aad_len.copy_from_slice(&(additional_data_len as u64).to_le_bytes());
    payload_bytes.copy_from_slice(&(payload_len as u64).to_le_bytes());
    block
}

/// The ChaCha20-Poly1305 seal: the Poly1305 key is the first 32 keystream bytes at counter 0, the
/// payload is encrypted from block 1 on, and the tag covers `aad || pad || ct || pad || lengths`.
pub(crate) fn chacha_seal<C>(cipher: &mut C, dst: &mut Vec<u8>, plaintext: &[u8], additional_data: &[u8]) -> Result<()>
where
    C: StreamCipher + StreamCipherSeek,
{
    let mut mac_key = poly1305::Key::default();
    cipher.apply_keystream(&mut mac_key);
    let mut mac = Poly1305::new(&mac_key);
    cipher.try_seek(CHACHA_BLOCK_SIZE as u64).map_err(|_| anyhow!("chacha20poly1305: position overflow"))?;

    let start = dst.len();
    dst.resize(start + plaintext.len() + TAG_SIZE, 0);
    let (_, sealed) = dst.split_at_mut(start);
    let (ciphertext, tag_out) = sealed.split_at_mut(plaintext.len());
    cipher.apply_keystream_b2b(plaintext, ciphertext);

    mac.update_padded(additional_data);
    mac.update_padded(ciphertext);
    mac.update(&[length_block(additional_data.len(), plaintext.len())]);
    let tag = mac.finalize();
    tag_out.copy_from_slice(&tag);
    Ok(())
}

/// The ChaCha20-Poly1305 open: the tag is checked in constant time before anything is decrypted.
pub(crate) fn chacha_open<C>(cipher: &mut C, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>>
where
    C: StreamCipher + StreamCipherSeek,
{
    if ciphertext.len() < TAG_SIZE {
        return Err(anyhow!("cipher: message authentication failed"));
    }
    let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);

    let mut mac_key = poly1305::Key::default();
    cipher.apply_keystream(&mut mac_key);
    let mut mac = Poly1305::new(&mac_key);
    cipher.try_seek(CHACHA_BLOCK_SIZE as u64).map_err(|_| anyhow!("chacha20poly1305: position overflow"))?;

    mac.update_padded(additional_data);
    mac.update_padded(ciphertext);
    mac.update(&[length_block(additional_data.len(), ciphertext.len())]);
    let expected = mac.finalize();

    let tag = poly1305::Tag::try_from(tag).map_err(|_| anyhow!("cipher: message authentication failed"))?;
    if !bool::from(expected.ct_eq(&tag)) {
        return Err(anyhow!("cipher: message authentication failed"));
    }
    let mut plaintext = ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext);
    Ok(plaintext)
}

impl Aead for ChaCha8Aead {
    fn nonce_size(&self) -> usize {
        CHACHA_NONCE_SIZE
    }

    fn overhead(&self) -> usize {
        TAG_SIZE
    }

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<()> {
        let mut cipher = self.stream(nonce, "chacha20poly1305: bad nonce length passed to Seal")?;
        chacha_seal(&mut cipher, dst, plaintext, additional_data)
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>> {
        let mut cipher = self.stream(nonce, "chacha20poly1305: bad nonce length passed to Open")?;
        chacha_open(&mut cipher, ciphertext, additional_data)
    }
}

/// AES in counter-with-CBC-MAC mode, standard 12-byte nonce and 16-byte tag, which no pinned
/// crate provides.
#[derive(Debug)]
struct CcmAead<C> {
    cipher: C,
}

const CCM_BLOCK_SIZE: usize = 16;

const CCM_TAG_SIZE: usize = 16;

const CCM_STANDARD_NONCE_SIZE: usize = 12;

/// The CCM length field `L`, `15 - nonceSize`.
const CCM_L: usize = CCM_BLOCK_SIZE - 1 - CCM_STANDARD_NONCE_SIZE;

/// The maximum message length for `L = 3`.
const CCM_MAX_LENGTH: usize = (1usize << (8 * CCM_L)) - 1;

/// Copies the nonce into the IV tail, as much as both sides hold.
fn copy_min(dst: &mut [u8], src: &[u8]) {
    let n = core::cmp::min(dst.len(), src.len());
    let (target, _) = dst.split_at_mut(n);
    let (source, _) = src.split_at(n);
    target.copy_from_slice(source);
}

/// The block encryption, named through the `aes` crate's block type.
fn encrypt_block<C: BlockCipherEncrypt>(block_cipher: &C, block: &mut [u8; CCM_BLOCK_SIZE]) {
    #[expect(
        clippy::expect_used,
        reason = "`CCM_BLOCK_SIZE` is the block size of every cipher this CCM wrapper is built with"
    )]
    let mut array = cipher::Block::<C>::try_from(block.as_slice()).expect("fixed-size block");
    block_cipher.encrypt_block(&mut array);
    block.copy_from_slice(array.as_slice());
}

/// The AES-CTR keystream over the CCM counter block, which counts big-endian over all 16 bytes.
fn ctr_xor<C: BlockCipherEncrypt>(cipher: &C, iv: &mut [u8; CCM_BLOCK_SIZE], data: &mut [u8]) {
    for chunk in data.chunks_mut(CCM_BLOCK_SIZE) {
        let mut stream = *iv;
        encrypt_block(cipher, &mut stream);
        for (byte, key) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= key;
        }
        for byte in iv.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
}

impl<C> CcmAead<C>
where
    C: BlockCipherEncrypt,
{
    fn cbc_round(&self, mac: &mut [u8; CCM_BLOCK_SIZE], data: &[u8]) {
        for (m, d) in mac.iter_mut().zip(data) {
            *m ^= *d;
        }
        encrypt_block(&self.cipher, mac);
    }

    fn cbc_data(&self, mac: &mut [u8; CCM_BLOCK_SIZE], mut data: &[u8]) {
        while let Some((head, rest)) = data.split_at_checked(CCM_BLOCK_SIZE) {
            self.cbc_round(mac, head);
            data = rest;
        }
        if !data.is_empty() {
            let mut block = [0u8; CCM_BLOCK_SIZE];
            let (head, _) = block.split_at_mut(data.len());
            head.copy_from_slice(data);
            self.cbc_round(mac, &block);
        }
    }

    fn tag(&self, nonce: &[u8], plaintext: &[u8], adata: &[u8]) -> Result<[u8; CCM_BLOCK_SIZE]> {
        let mut mac = [0u8; CCM_BLOCK_SIZE];

        if !adata.is_empty() {
            mac[0] |= 1 << 6;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "`CCM_TAG_SIZE` (16) and `CCM_L` (3) are the byte-sized CCM layout constants"
        )]
        let flag_tail = (((CCM_TAG_SIZE - 2) << 2) | (CCM_L - 1)) as u8;
        mac[0] |= flag_tail;
        if nonce.len() != CCM_STANDARD_NONCE_SIZE {
            return Err(anyhow!("ccm: invalid nonce size"));
        }
        if plaintext.len() > CCM_MAX_LENGTH {
            return Err(anyhow!("ccm: plaintext too large"));
        }
        mac[CCM_BLOCK_SIZE - 8..].copy_from_slice(&(plaintext.len() as u64).to_be_bytes());
        mac[1..CCM_BLOCK_SIZE - CCM_L].copy_from_slice(nonce);
        encrypt_block(&self.cipher, &mut mac);

        let mut block = [0u8; CCM_BLOCK_SIZE];
        let adata_len = adata.len() as u64;
        if adata_len > 0 {
            let mut i = 2;
            if adata_len <= 0xfeff {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "the `adata_len <= 0xfeff` guard bounds the length to two bytes"
                )]
                let len = (adata_len as u16).to_be_bytes();
                let (prefix, _) = block.split_at_mut(i);
                prefix.copy_from_slice(&len);
            } else {
                block[0] = 0xfe;
                block[1] = 0xff;
                if adata_len < 1 << 32 {
                    i = 2 + 4;
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "the `adata_len < 1 << 32` guard bounds the length to four bytes"
                    )]
                    let len = (adata_len as u32).to_be_bytes();
                    let (_, tail) = block.split_at_mut(2);
                    let (prefix, _) = tail.split_at_mut(i - 2);
                    prefix.copy_from_slice(&len);
                } else {
                    i = 2 + 8;
                    let (_, tail) = block.split_at_mut(2);
                    let (prefix, _) = tail.split_at_mut(i - 2);
                    prefix.copy_from_slice(&adata_len.to_be_bytes());
                }
            }
            let copied = core::cmp::min(CCM_BLOCK_SIZE - i, adata.len());
            let (_, tail) = block.split_at_mut(i);
            let (target, _) = tail.split_at_mut(copied);
            let (source, _) = adata.split_at(copied);
            target.copy_from_slice(source);
            i += copied;
            self.cbc_round(&mut mac, &block);
            let (_, rest) = adata.split_at(i);
            self.cbc_data(&mut mac, rest);
        }

        if !plaintext.is_empty() {
            self.cbc_data(&mut mac, plaintext);
        }

        Ok(mac)
    }

    /// The CCM counter block: the IV the tag is computed with and encryption starts from.
    fn counter_block(&self, nonce: &[u8]) -> ([u8; CCM_BLOCK_SIZE], [u8; CCM_BLOCK_SIZE]) {
        let mut iv = [0u8; CCM_BLOCK_SIZE];
        #[expect(clippy::cast_possible_truncation, reason = "`CCM_L` (3) is a byte-sized CCM layout constant")]
        let counter_flag = (CCM_L - 1) as u8;
        iv[0] = counter_flag;
        copy_min(&mut iv[1..CCM_BLOCK_SIZE - CCM_L], nonce);
        let mut s0 = iv;
        encrypt_block(&self.cipher, &mut s0);
        iv[CCM_BLOCK_SIZE - 1] |= 1;
        (iv, s0)
    }
}

impl<C> Aead for CcmAead<C>
where
    C: BlockCipherEncrypt + Send + Sync + fmt::Debug,
{
    fn nonce_size(&self) -> usize {
        CCM_STANDARD_NONCE_SIZE
    }

    fn overhead(&self) -> usize {
        CCM_TAG_SIZE
    }

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<()> {
        let mut tag = self.tag(nonce, plaintext, additional_data)?;

        let (mut iv, s0) = self.counter_block(nonce);
        for (t, s) in tag.iter_mut().zip(s0) {
            *t ^= s;
        }

        let start = dst.len();
        dst.extend_from_slice(plaintext);
        let (_, sealed) = dst.split_at_mut(start);
        ctr_xor(&self.cipher, &mut iv, sealed);
        dst.extend_from_slice(&tag);
        Ok(())
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < CCM_TAG_SIZE {
            return Err(anyhow!("ccm: ciphertext too short"));
        }
        if ciphertext.len() > CCM_MAX_LENGTH + CCM_TAG_SIZE {
            return Err(anyhow!("ccm: ciphertext too long"));
        }

        let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - CCM_TAG_SIZE);
        let mut expected = [0u8; CCM_TAG_SIZE];
        expected.copy_from_slice(tag);

        let (mut iv, s0) = self.counter_block(nonce);
        for (e, s) in expected.iter_mut().zip(s0) {
            *e ^= s;
        }

        let mut plaintext = ciphertext.to_vec();
        ctr_xor(&self.cipher, &mut iv, &mut plaintext);
        let computed = self.tag(nonce, &plaintext, additional_data)?;

        if !bool::from(computed.ct_eq(&expected)) {
            return Err(anyhow!("ccm: message authentication failed"));
        }
        Ok(plaintext)
    }
}

pub(crate) fn aes_gcm(key: &[u8]) -> Result<Box<dyn Aead>> {
    let aead: Box<dyn Aead> = match key.len() {
        16 => Box::new(GcmAead { cipher: Aes128Gcm::new_from_slice(key).map_err(|_| aes_key_size_error(key.len()))? }),
        24 => Box::new(GcmAead { cipher: Aes192Gcm::new_from_slice(key).map_err(|_| aes_key_size_error(key.len()))? }),
        32 => Box::new(GcmAead { cipher: Aes256Gcm::new_from_slice(key).map_err(|_| aes_key_size_error(key.len()))? }),
        l => return Err(aes_key_size_error(l)),
    };
    Ok(aead)
}

/// Creates a new AES-GCM [`Cipher`] with a pre-shared key. `psk.len()` must be one of
/// 16, 24 or 32 to select AES-128/196/256-GCM.
pub fn aesgcm(psk: &[u8]) -> Result<Box<dyn Cipher>> {
    match psk.len() {
        // AES 128/196/256
        16 | 24 | 32 => {}
        l => return Err(aes_key_size_error(l)),
    }
    Ok(Box::new(MetaCipher { psk: psk.to_vec(), make_aead: aes_gcm }))
}

pub(crate) fn aes_ccm(key: &[u8]) -> Result<Box<dyn Aead>> {
    let aead: Box<dyn Aead> = match key.len() {
        16 => Box::new(CcmAead { cipher: Aes128::new_from_slice(key).map_err(|_| aes_key_size_error(key.len()))? }),
        24 => Box::new(CcmAead { cipher: Aes192::new_from_slice(key).map_err(|_| aes_key_size_error(key.len()))? }),
        32 => Box::new(CcmAead { cipher: Aes256::new_from_slice(key).map_err(|_| aes_key_size_error(key.len()))? }),
        l => return Err(aes_key_size_error(l)),
    };
    Ok(aead)
}

/// Creates a new AES-CCM [`Cipher`] with a pre-shared key. `psk.len()` must be one of
/// 16, 24 or 32 to select AES-128/196/256-CCM.
pub fn aesccm(psk: &[u8]) -> Result<Box<dyn Cipher>> {
    match psk.len() {
        // AES 128/196/256
        16 | 24 | 32 => {}
        l => return Err(aes_key_size_error(l)),
    }
    Ok(Box::new(MetaCipher { psk: psk.to_vec(), make_aead: aes_ccm }))
}

pub(crate) fn chacha20_poly1305(key: &[u8]) -> Result<Box<dyn Aead>> {
    let key = chacha20poly1305::Key::try_from(key).map_err(|_| anyhow!("chacha20poly1305: bad key length"))?;
    Ok(Box::new(ChaChaAead { cipher: chacha20poly1305::ChaCha20Poly1305::new(&key), nonce_size: CHACHA_NONCE_SIZE }))
}

/// Creates a new ChaCha20-Poly1305 [`Cipher`] with a pre-shared key. `psk.len()` must be 32.
pub fn chacha20poly1305(psk: &[u8]) -> Result<Box<dyn Cipher>> {
    if psk.len() != CHACHA_KEY_SIZE {
        return Err(chacha_key_size_error());
    }
    Ok(Box::new(MetaCipher { psk: psk.to_vec(), make_aead: chacha20_poly1305 }))
}

pub(crate) fn xchacha20_poly1305(key: &[u8]) -> Result<Box<dyn Aead>> {
    let key = chacha20poly1305::Key::try_from(key).map_err(|_| anyhow!("chacha20poly1305: bad key length"))?;
    Ok(Box::new(ChaChaAead { cipher: chacha20poly1305::XChaCha20Poly1305::new(&key), nonce_size: XCHACHA_NONCE_SIZE }))
}

/// Creates a new XChaCha20-Poly1305 [`Cipher`] with a pre-shared key. `psk.len()` must be 32.
pub fn xchacha20poly1305(psk: &[u8]) -> Result<Box<dyn Cipher>> {
    if psk.len() != CHACHA_KEY_SIZE {
        return Err(chacha_key_size_error());
    }
    Ok(Box::new(MetaCipher { psk: psk.to_vec(), make_aead: xchacha20_poly1305 }))
}

pub(crate) fn chacha8_poly1305(key: &[u8]) -> Result<Box<dyn Aead>> {
    let key: [u8; CHACHA_KEY_SIZE] = key.try_into().map_err(|_| anyhow!("chacha20poly1305: bad key length"))?;
    Ok(Box::new(ChaCha8Aead { key }))
}

/// Creates a new ChaCha8-Poly1305 [`Cipher`] with a pre-shared key. `psk.len()` must be 32.
pub fn chacha8poly1305(psk: &[u8]) -> Result<Box<dyn Cipher>> {
    if psk.len() != CHACHA_KEY_SIZE {
        return Err(chacha_key_size_error());
    }
    Ok(Box::new(MetaCipher { psk: psk.to_vec(), make_aead: chacha8_poly1305 }))
}

/// Creates a new XChaCha8-Poly1305 [`Cipher`] with a pre-shared key. `psk.len()` must be 32.
///
/// The name maps to a full 20-round XChaCha20-Poly1305, so the 24-byte nonce is XChaCha20's
/// rather than the 8-round construction the name suggests.
pub fn xchacha8poly1305(psk: &[u8]) -> Result<Box<dyn Cipher>> {
    if psk.len() != CHACHA_KEY_SIZE {
        return Err(chacha_key_size_error());
    }
    Ok(Box::new(MetaCipher { psk: psk.to_vec(), make_aead: xchacha20_poly1305 }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
    }

    /// NIST GCM spec (McGrew & Viega), Appendix B, Test Case 2: AES-128-GCM, all-zero 16-byte
    /// key, all-zero 12-byte IV, 16 zero plaintext bytes, no AAD.
    #[test]
    fn gcm_aead_open_in_place_matches_nist_test_case_2() {
        let key = hex(&"0".repeat(32));
        let nonce = hex(&"0".repeat(24));
        let plaintext = hex(&"0".repeat(32));
        let want_ciphertext = hex("0388dace60b6a392f328c2b971b2fe78");
        let want_tag = hex("ab6e47d42cec13bdf53a67b21257bddf");

        let aead = GcmAead { cipher: Aes128Gcm::new_from_slice(&key).expect("aes-128 key") };

        let mut sealed = Vec::new();
        aead.seal(&mut sealed, &nonce, &plaintext, &[]).expect("seal");
        assert_eq!(&sealed[..want_ciphertext.len()], &want_ciphertext[..], "ciphertext must match NIST vector");
        assert_eq!(&sealed[want_ciphertext.len()..], &want_tag[..], "tag must match NIST vector");

        let mut buf = sealed.clone();
        let opened = aead.open_in_place(&nonce, &mut buf, &[]).expect("open_in_place").to_vec();
        assert_eq!(opened, plaintext, "open_in_place must recover the exact plaintext");
    }

    /// RFC 8439 section 2.8.2: AEAD_CHACHA20_POLY1305 example and test vector.
    #[test]
    fn chacha_aead_open_in_place_matches_rfc8439() {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex("070000004041424344454647");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        let want_ciphertext = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let want_tag = hex("1ae10b594f09e26a7e902ecbd0600691");

        let aead = ChaChaAead {
            cipher: chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key).expect("key"),
            nonce_size: CHACHA_NONCE_SIZE,
        };

        let mut sealed = Vec::new();
        aead.seal(&mut sealed, &nonce, &plaintext, &aad).expect("seal");
        assert_eq!(&sealed[..want_ciphertext.len()], &want_ciphertext[..], "ciphertext must match RFC 8439 vector");
        assert_eq!(&sealed[want_ciphertext.len()..], &want_tag[..], "tag must match RFC 8439 vector");

        let mut buf = sealed.clone();
        let opened = aead.open_in_place(&nonce, &mut buf, &aad).expect("open_in_place").to_vec();
        assert_eq!(opened, plaintext, "open_in_place must recover the exact plaintext");
    }
}
