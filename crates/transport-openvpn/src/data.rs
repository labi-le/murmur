//! The data channel: encrypting and decrypting tunnel packets under the negotiated cipher.

use std::fmt;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as _};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::{Aead, Key, Nonce, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};

/// `aes-gcm` 0.11 only aliases the 128- and 256-bit GCM ciphers; `OpenVPN`'s AES-192-GCM is the same
/// generic cipher over a 192-bit AES block key.
type Aes192Gcm = AesGcm<Aes192, cipher::consts::U12>;
use anyhow::anyhow;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac as _};
use md5::Md5;
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq as _;

use crate::config::{
    AUTH_MD5, AUTH_SHA1, AUTH_SHA256, AUTH_SHA384, AUTH_SHA512, CIPHER_AES_128_CBC, CIPHER_AES_128_GCM,
    CIPHER_AES_192_CBC, CIPHER_AES_192_GCM, CIPHER_AES_256_CBC, CIPHER_AES_256_GCM, CIPHER_AES_CBC,
    CIPHER_CHACHA20_POLY1305,
};
use crate::keymethod::KeyMaterial;
use crate::packet::{opcode_key_id, parse_opcode_key_id, KEY_ID_MASK, P_DATA_V1, P_DATA_V2};
use crate::push::split_push_options;
use crate::tlscrypt::be_u32;

const AES_BLOCK_SIZE: usize = 16;

pub const DATA_CHANNEL_TAG_SIZE: usize = 16;
pub const DATA_CHANNEL_IV_SIZE: usize = 12;
pub const DATA_CHANNEL_CBC_IV_SIZE: usize = AES_BLOCK_SIZE;
const DATA_CHANNEL_IV_RAND_BUF: usize = 32 * 1024;
pub(crate) const DATA_CHANNEL_REPLAY_WINDOW: usize = 64;

pub const PEER_ID_UNSET: u32 = 0xffffff;

/// The data-channel ping payload.
pub(crate) static OPEN_VPN_PING_PACKET: [u8; 16] =
    [0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48];

#[must_use]
pub fn is_ping_packet(packet: &[u8]) -> bool {
    packet == OPEN_VPN_PING_PACKET.as_slice()
}

/// The hash an HMAC data-channel cipher uses for its auth digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthHash {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl AuthHash {
    pub(crate) const fn tag_size(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// HMAC keyed with `key`, then every part written in order.
    #[expect(clippy::expect_used, reason = "HMAC accepts a key of any length, so `new_from_slice` cannot fail")]
    pub(crate) fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        match self {
            Self::Md5 => {
                let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC accepts keys of any length");
                for part in parts {
                    mac.update(part);
                }
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts keys of any length");
                for part in parts {
                    mac.update(part);
                }
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
                for part in parts {
                    mac.update(part);
                }
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key).expect("HMAC accepts keys of any length");
                for part in parts {
                    mac.update(part);
                }
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts keys of any length");
                for part in parts {
                    mac.update(part);
                }
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}

enum AeadCipher {
    Aes128Gcm(Aes128Gcm),
    Aes192Gcm(Aes192Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl AeadCipher {
    /// Seals the plaintext: the tag is appended to the ciphertext.
    fn seal(&self, nonce: &[u8], plaintext: &[u8], ad: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm(cipher) => seal_gcm(cipher, nonce, plaintext, ad),
            Self::Aes192Gcm(cipher) => seal_gcm(cipher, nonce, plaintext, ad),
            Self::Aes256Gcm(cipher) => seal_gcm(cipher, nonce, plaintext, ad),
            Self::ChaCha20Poly1305(cipher) => {
                let nonce = chacha20poly1305::Nonce::try_from(nonce)
                    .map_err(|_| anyhow!("unexpected chacha nonce size: {}", nonce.len()))?;
                cipher
                    .encrypt(&nonce, Payload { msg: plaintext, aad: ad })
                    .map_err(|_| anyhow!("chacha20poly1305: message authentication failed"))
            }
        }
    }

    fn open(&self, nonce: &[u8], combined: &[u8], ad: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm(cipher) => open_gcm(cipher, nonce, combined, ad),
            Self::Aes192Gcm(cipher) => open_gcm(cipher, nonce, combined, ad),
            Self::Aes256Gcm(cipher) => open_gcm(cipher, nonce, combined, ad),
            Self::ChaCha20Poly1305(cipher) => {
                let nonce = chacha20poly1305::Nonce::try_from(nonce)
                    .map_err(|_| anyhow!("unexpected chacha nonce size: {}", nonce.len()))?;
                cipher
                    .decrypt(&nonce, Payload { msg: combined, aad: ad })
                    .map_err(|_| anyhow!("chacha20poly1305: message authentication failed"))
            }
        }
    }
}

fn seal_gcm<C>(cipher: &C, nonce: &[u8], plaintext: &[u8], ad: &[u8]) -> anyhow::Result<Vec<u8>>
where
    C: Aead,
{
    let nonce = Nonce::<C>::try_from(nonce).map_err(|_| anyhow!("unexpected gcm nonce size: {}", nonce.len()))?;
    cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad: ad })
        .map_err(|_| anyhow!("cipher: message authentication failed"))
}

fn open_gcm<C>(cipher: &C, nonce: &[u8], combined: &[u8], ad: &[u8]) -> anyhow::Result<Vec<u8>>
where
    C: Aead,
{
    let nonce = Nonce::<C>::try_from(nonce).map_err(|_| anyhow!("unexpected gcm nonce size: {}", nonce.len()))?;
    cipher
        .decrypt(&nonce, Payload { msg: combined, aad: ad })
        .map_err(|_| anyhow!("cipher: message authentication failed"))
}

enum BlockCipher {
    Aes128(Box<Aes128>),
    Aes192(Box<Aes192>),
    Aes256(Box<Aes256>),
}

impl BlockCipher {
    #[expect(clippy::unused_self, reason = "the CBC paths read the block size off a cipher")]
    const fn block_size(&self) -> usize {
        AES_BLOCK_SIZE
    }

    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        match self {
            Self::Aes128(cipher) => {
                let mut array = aes::Block::from(*block);
                cipher.encrypt_block(&mut array);
                block.copy_from_slice(array.as_slice());
            }
            Self::Aes192(cipher) => {
                let mut array = aes::Block::from(*block);
                cipher.encrypt_block(&mut array);
                block.copy_from_slice(array.as_slice());
            }
            Self::Aes256(cipher) => {
                let mut array = aes::Block::from(*block);
                cipher.encrypt_block(&mut array);
                block.copy_from_slice(array.as_slice());
            }
        }
    }

    fn decrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        match self {
            Self::Aes128(cipher) => {
                let mut array = aes::Block::from(*block);
                cipher.decrypt_block(&mut array);
                block.copy_from_slice(array.as_slice());
            }
            Self::Aes192(cipher) => {
                let mut array = aes::Block::from(*block);
                cipher.decrypt_block(&mut array);
                block.copy_from_slice(array.as_slice());
            }
            Self::Aes256(cipher) => {
                let mut array = aes::Block::from(*block);
                cipher.decrypt_block(&mut array);
                block.copy_from_slice(array.as_slice());
            }
        }
    }
}

fn cbc_encrypt(block: &BlockCipher, iv: &[u8; AES_BLOCK_SIZE], data: &mut [u8]) {
    let mut prev = *iv;
    for chunk in data.chunks_exact_mut(AES_BLOCK_SIZE) {
        let mut buf = [0u8; AES_BLOCK_SIZE];
        for ((out, input), previous) in buf.iter_mut().zip(chunk.iter()).zip(prev.iter()) {
            *out = *input ^ *previous;
        }
        block.encrypt_block(&mut buf);
        chunk.copy_from_slice(&buf);
        prev = buf;
    }
}

fn cbc_decrypt(block: &BlockCipher, iv: &[u8; AES_BLOCK_SIZE], data: &mut [u8]) {
    let mut prev = *iv;
    for chunk in data.chunks_exact_mut(AES_BLOCK_SIZE) {
        let mut buf = [0u8; AES_BLOCK_SIZE];
        buf.copy_from_slice(chunk);
        let mut plain = buf;
        block.decrypt_block(&mut plain);
        for ((out, plain_byte), previous) in chunk.iter_mut().zip(plain.iter()).zip(prev.iter()) {
            *out = *plain_byte ^ *previous;
        }
        prev = buf;
    }
}

#[derive(Default)]
#[expect(
    clippy::struct_field_names,
    reason = "every field describes the receive half of the replay window, as OpenVPN names it"
)]
pub(crate) struct DataChannelReplay {
    pub(crate) recv_evidence: bool,
    pub(crate) recv_highest: u32,
    pub(crate) recv_window: u64,
    pub(crate) recv_seen: bool,
}

#[derive(Default)]
pub(crate) struct DataChannelState {
    pub(crate) send_packet_id: u32,
    pub(crate) replay: DataChannelReplay,
}

#[derive(Default)]
struct RandState {
    buf: Vec<u8>,
    offset: usize,
}

pub struct DataChannel {
    send_aead: Option<AeadCipher>,
    recv_aead: Option<AeadCipher>,

    send_block: Option<BlockCipher>,
    recv_block: Option<BlockCipher>,
    send_hmac_key: Vec<u8>,
    recv_hmac_key: Vec<u8>,
    auth_hash: Option<AuthHash>,
    auth_size: usize,

    send_implicit_iv: [u8; DATA_CHANNEL_IV_SIZE],
    recv_implicit_iv: [u8; DATA_CHANNEL_IV_SIZE],

    pub(crate) key_id: u8,
    header: Vec<u8>,

    state: Mutex<DataChannelState>,

    rand_state: Mutex<RandState>,
}

impl fmt::Debug for DataChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataChannel").field("key_id", &self.key_id).finish_non_exhaustive()
    }
}

pub fn new_data_channel(
    keys: &KeyMaterial,
    cipher_name: &str,
    auth_name: &str,
    peer_id: u32,
    key_id: u8,
) -> anyhow::Result<DataChannel> {
    if is_data_channel_aead(cipher_name) {
        let send = new_data_channel_aead(cipher_name, &keys.send_cipher_key)
            .map_err(|err| anyhow!("create send cipher: {err}"))?;
        let recv = new_data_channel_aead(cipher_name, &keys.recv_cipher_key)
            .map_err(|err| anyhow!("create recv cipher: {err}"))?;
        let (Some(send_iv_key), Some(recv_iv_key)) =
            (keys.send_hmac_key.get(..DATA_CHANNEL_IV_SIZE - 4), keys.recv_hmac_key.get(..DATA_CHANNEL_IV_SIZE - 4))
        else {
            return Err(anyhow!("openvpn implicit IV keys are too short"));
        };
        let mut send_implicit_iv = [0u8; DATA_CHANNEL_IV_SIZE];
        let mut recv_implicit_iv = [0u8; DATA_CHANNEL_IV_SIZE];
        send_implicit_iv[4..].copy_from_slice(send_iv_key);
        recv_implicit_iv[4..].copy_from_slice(recv_iv_key);
        return Ok(DataChannel {
            send_aead: Some(send),
            recv_aead: Some(recv),
            send_block: None,
            recv_block: None,
            send_hmac_key: Vec::new(),
            recv_hmac_key: Vec::new(),
            auth_hash: None,
            auth_size: 0,
            send_implicit_iv,
            recv_implicit_iv,
            key_id: key_id & KEY_ID_MASK,
            header: data_header(peer_id, key_id),
            state: Mutex::new(DataChannelState::default()),
            rand_state: Mutex::new(RandState::default()),
        });
    }

    let send =
        new_data_channel_cbc(cipher_name, &keys.send_cipher_key).map_err(|err| anyhow!("create send cipher: {err}"))?;
    let recv =
        new_data_channel_cbc(cipher_name, &keys.recv_cipher_key).map_err(|err| anyhow!("create recv cipher: {err}"))?;
    let (auth_hash, auth_size) = new_data_channel_auth(auth_name)?;
    let (Some(send_hmac_key), Some(recv_hmac_key)) =
        (keys.send_hmac_key.get(..auth_size), keys.recv_hmac_key.get(..auth_size))
    else {
        return Err(anyhow!("openvpn HMAC keys are too short"));
    };
    Ok(DataChannel {
        send_aead: None,
        recv_aead: None,
        send_block: Some(send),
        recv_block: Some(recv),
        send_hmac_key: send_hmac_key.to_vec(),
        recv_hmac_key: recv_hmac_key.to_vec(),
        auth_hash: Some(auth_hash),
        auth_size,
        send_implicit_iv: [0u8; DATA_CHANNEL_IV_SIZE],
        recv_implicit_iv: [0u8; DATA_CHANNEL_IV_SIZE],
        key_id: key_id & KEY_ID_MASK,
        header: data_header(peer_id, key_id),
        state: Mutex::new(DataChannelState::default()),
        rand_state: Mutex::new(RandState::default()),
    })
}

/// Build a zero-value `DataChannel` for one key id; the fields are private outside this module,
/// so tests go through this helper.
#[allow(dead_code, reason = "only called from #[cfg(test)] tests")]
pub(crate) fn data_channel_with_key_id(key_id: u8) -> DataChannel {
    DataChannel {
        send_aead: None,
        recv_aead: None,
        send_block: None,
        recv_block: None,
        send_hmac_key: Vec::new(),
        recv_hmac_key: Vec::new(),
        auth_hash: None,
        auth_size: 0,
        send_implicit_iv: [0u8; DATA_CHANNEL_IV_SIZE],
        recv_implicit_iv: [0u8; DATA_CHANNEL_IV_SIZE],
        key_id: key_id & KEY_ID_MASK,
        header: data_header(PEER_ID_UNSET, key_id),
        state: Mutex::new(DataChannelState::default()),
        rand_state: Mutex::new(RandState::default()),
    }
}

fn is_data_channel_aead(cipher_name: &str) -> bool {
    matches!(cipher_name, CIPHER_AES_128_GCM | CIPHER_AES_192_GCM | CIPHER_AES_256_GCM | CIPHER_CHACHA20_POLY1305)
}

fn new_data_channel_aead(cipher_name: &str, key: &[u8]) -> anyhow::Result<AeadCipher> {
    match cipher_name {
        CIPHER_AES_128_GCM | CIPHER_AES_192_GCM | CIPHER_AES_256_GCM => match key.len() {
            16 => {
                let key = Key::<Aes128Gcm>::try_from(key).map_err(|_| invalid_aes_key_size(key))?;
                Ok(AeadCipher::Aes128Gcm(Aes128Gcm::new(&key)))
            }
            24 => {
                let key = Key::<Aes192Gcm>::try_from(key).map_err(|_| invalid_aes_key_size(key))?;
                Ok(AeadCipher::Aes192Gcm(Aes192Gcm::new(&key)))
            }
            32 => {
                let key = Key::<Aes256Gcm>::try_from(key).map_err(|_| invalid_aes_key_size(key))?;
                Ok(AeadCipher::Aes256Gcm(Aes256Gcm::new(&key)))
            }
            _ => Err(invalid_aes_key_size(key)),
        },
        CIPHER_CHACHA20_POLY1305 => {
            let key = chacha20poly1305::Key::try_from(key)
                .map_err(|_| anyhow!("chacha20poly1305: bad key length {}", key.len()))?;
            Ok(AeadCipher::ChaCha20Poly1305(ChaCha20Poly1305::new(&key)))
        }
        _ => Err(anyhow!("unsupported openvpn cipher {cipher_name:?}")),
    }
}

fn invalid_aes_key_size(key: &[u8]) -> anyhow::Error {
    anyhow!("invalid key size {}", key.len())
}

fn new_data_channel_cbc(cipher_name: &str, key: &[u8]) -> anyhow::Result<BlockCipher> {
    match cipher_name {
        CIPHER_AES_CBC | CIPHER_AES_128_CBC | CIPHER_AES_192_CBC | CIPHER_AES_256_CBC => new_aes_cipher(key),
        _ => Err(anyhow!("unsupported openvpn cipher {cipher_name:?}")),
    }
}

fn new_aes_cipher(key: &[u8]) -> anyhow::Result<BlockCipher> {
    let cipher = match key.len() {
        16 => BlockCipher::Aes128(Box::new(Aes128::new_from_slice(key).map_err(|_| invalid_aes_key_size(key))?)),
        24 => BlockCipher::Aes192(Box::new(Aes192::new_from_slice(key).map_err(|_| invalid_aes_key_size(key))?)),
        32 => BlockCipher::Aes256(Box::new(Aes256::new_from_slice(key).map_err(|_| invalid_aes_key_size(key))?)),
        _ => return Err(invalid_aes_key_size(key)),
    };
    Ok(cipher)
}

pub(crate) fn new_data_channel_auth(auth_name: &str) -> anyhow::Result<(AuthHash, usize)> {
    match auth_name {
        AUTH_MD5 => Ok((AuthHash::Md5, AuthHash::Md5.tag_size())),
        AUTH_SHA1 => Ok((AuthHash::Sha1, AuthHash::Sha1.tag_size())),
        AUTH_SHA256 => Ok((AuthHash::Sha256, AuthHash::Sha256.tag_size())),
        AUTH_SHA384 => Ok((AuthHash::Sha384, AuthHash::Sha384.tag_size())),
        AUTH_SHA512 => Ok((AuthHash::Sha512, AuthHash::Sha512.tag_size())),
        _ => Err(anyhow!("unsupported openvpn auth {auth_name:?}")),
    }
}

impl DataChannel {
    pub fn new(
        keys: &KeyMaterial,
        cipher_name: &str,
        auth_name: &str,
        peer_id: u32,
        key_id: u8,
    ) -> anyhow::Result<Self> {
        new_data_channel(keys, cipher_name, auth_name, peer_id, key_id)
    }

    pub fn encrypt(&self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        let packet_id = self.next_packet_id()?;
        if let Some(send_aead) = &self.send_aead {
            return self.encrypt_aead(send_aead, packet, packet_id);
        }
        self.encrypt_cbc(packet, packet_id)
    }

    fn encrypt_aead(&self, aead: &AeadCipher, packet: &[u8], packet_id: u32) -> anyhow::Result<Vec<u8>> {
        let header = &self.header;
        let packet_id_bytes = packet_id.to_be_bytes();
        let nonce = data_nonce(packet_id, self.send_implicit_iv);
        let mut ad = Vec::with_capacity(header.len() + packet_id_bytes.len());
        ad.extend_from_slice(header);
        ad.extend_from_slice(&packet_id_bytes);
        let sealed = aead.seal(&nonce, packet, &ad)?;
        let (ciphertext, tag) = sealed.split_at(sealed.len() - DATA_CHANNEL_TAG_SIZE);

        let mut out = Vec::with_capacity(header.len() + 4 + DATA_CHANNEL_TAG_SIZE + packet.len());
        out.extend_from_slice(header);
        out.extend_from_slice(&packet_id_bytes);
        out.extend_from_slice(tag);
        out.extend_from_slice(ciphertext);
        Ok(out)
    }

    fn encrypt_cbc(&self, packet: &[u8], packet_id: u32) -> anyhow::Result<Vec<u8>> {
        let Some(send_block) = &self.send_block else {
            return Err(anyhow!("nil openvpn data channel cipher"));
        };
        let header = &self.header;
        let block_size = send_block.block_size();
        let plain_len = 4 + packet.len();
        let mut padding = block_size - plain_len % block_size;
        if padding == 0 {
            padding = block_size;
        }
        let authenticated_start = header.len() + self.auth_size;
        let mut out = vec![0u8; authenticated_start + DATA_CHANNEL_CBC_IV_SIZE + plain_len + padding];

        let mut iv = [0u8; DATA_CHANNEL_CBC_IV_SIZE];
        self.fill_cbc_iv(&mut iv)?;

        {
            let (header_out, rest) = out.split_at_mut(header.len());
            header_out.copy_from_slice(header);
            let (_tag_out, rest) = rest.split_at_mut(self.auth_size);
            let (iv_out, ciphertext_out) = rest.split_at_mut(DATA_CHANNEL_CBC_IV_SIZE);
            iv_out.copy_from_slice(&iv);

            let (packet_id_out, rest) = ciphertext_out.split_at_mut(4);
            packet_id_out.copy_from_slice(&packet_id.to_be_bytes());
            let (payload_out, padding_out) = rest.split_at_mut(packet.len());
            payload_out.copy_from_slice(packet);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "`padding` is one cipher block at most, well inside a byte"
            )]
            padding_out.fill(padding as u8);

            cbc_encrypt(send_block, &iv, ciphertext_out);
        }

        let authenticated = out.split_at(authenticated_start).1;
        let tag = self.hmac_sum(true, authenticated);
        let n = tag.len().min(self.auth_size);
        let (_, tag_and_rest) = out.split_at_mut(header.len());
        let (tag_out, _) = tag_and_rest.split_at_mut(n);
        tag_out.copy_from_slice(tag.split_at(n).0);
        Ok(out)
    }

    pub fn decrypt(&self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        let header_size = data_packet_header_size(packet)?;
        if let Some(recv_aead) = &self.recv_aead {
            return self.decrypt_aead(recv_aead, packet, header_size);
        }
        self.decrypt_cbc(packet, header_size)
    }

    fn decrypt_aead(&self, aead: &AeadCipher, packet: &[u8], header_size: usize) -> anyhow::Result<Vec<u8>> {
        if packet.is_empty() {
            return Err(anyhow!("empty openvpn data packet"));
        }
        let Some((header, rest)) = packet.split_at_checked(header_size) else {
            return Err(anyhow!("openvpn data packet too short"));
        };
        let Some((packet_id_bytes, rest)) = rest.split_at_checked(4) else {
            return Err(anyhow!("openvpn data packet too short"));
        };
        let Some((tag, ciphertext)) = rest.split_at_checked(DATA_CHANNEL_TAG_SIZE) else {
            return Err(anyhow!("openvpn data packet too short"));
        };
        if ciphertext.is_empty() {
            return Err(anyhow!("openvpn data packet too short"));
        }
        let packet_id = be_u32(packet_id_bytes, 0);
        let mut combined = Vec::with_capacity(ciphertext.len() + DATA_CHANNEL_TAG_SIZE);
        combined.extend_from_slice(ciphertext);
        combined.extend_from_slice(tag);
        let mut ad = Vec::with_capacity(header.len() + packet_id_bytes.len());
        ad.extend_from_slice(header);
        ad.extend_from_slice(packet_id_bytes);

        let nonce = data_nonce(packet_id, self.recv_implicit_iv);
        let plain = aead.open(&nonce, &combined, &ad)?;
        self.accept_packet_id(packet_id)?;
        Ok(plain)
    }

    fn decrypt_cbc(&self, packet: &[u8], header_size: usize) -> anyhow::Result<Vec<u8>> {
        let Some(recv_block) = &self.recv_block else {
            return Err(anyhow!("nil openvpn data channel cipher"));
        };
        let block_size = recv_block.block_size();
        let min_packet_len = header_size + self.auth_size + block_size + block_size;
        if packet.len() < min_packet_len {
            return Err(anyhow!("openvpn CBC data packet too short"));
        }

        let (_, body) = packet.split_at(header_size);
        let (tag, authenticated) = body.split_at(self.auth_size);
        let expected = self.hmac_sum(false, authenticated);
        if !bool::from(tag.ct_eq(&expected)) {
            return Err(anyhow!("openvpn CBC data packet HMAC authentication failed"));
        }

        let (iv_bytes, ciphertext) = authenticated.split_at(block_size);
        let Ok(iv) = <[u8; AES_BLOCK_SIZE]>::try_from(iv_bytes) else {
            return Err(anyhow!("invalid openvpn CBC ciphertext length"));
        };
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(block_size) {
            return Err(anyhow!("invalid openvpn CBC ciphertext length"));
        }
        let mut plain = ciphertext.to_vec();
        cbc_decrypt(recv_block, &iv, &mut plain);
        let mut plain = pkcs7_unpad(plain, block_size)?;
        if plain.len() < 4 {
            return Err(anyhow!("openvpn CBC plaintext missing packet id"));
        }

        let packet_id = be_u32(&plain, 0);
        self.accept_packet_id(packet_id)?;
        plain.drain(..4);
        Ok(plain)
    }

    /// Holds the epoch state lock, for a test that blocks on it.
    #[allow(dead_code, reason = "exercised only by #[cfg(test)] tests")]
    pub(crate) fn lock_state(&self) -> parking_lot::MutexGuard<'_, DataChannelState> {
        self.state.lock()
    }

    #[allow(dead_code, reason = "exercised only by #[cfg(test)] tests")]
    pub(crate) fn send_packet_id(&self) -> u32 {
        self.state.lock().send_packet_id
    }

    #[allow(dead_code, reason = "exercised only by #[cfg(test)] tests")]
    pub(crate) fn set_send_packet_id(&self, packet_id: u32) {
        self.state.lock().send_packet_id = packet_id;
    }

    fn next_packet_id(&self) -> anyhow::Result<u32> {
        let mut state = self.state.lock();
        // OpenVPN starts a soft reset once `packet_id_close_to_wrapping` reaches this threshold.
        // This client cannot initiate that reset yet, so surface the condition and let the adapter
        // reconnect instead of silently blackholing packets or approaching nonce reuse.
        if state.send_packet_id >= DATA_PACKET_ID_REKEY_THRESHOLD {
            return Err(anyhow::Error::new(ErrDataPacketIDExhausted));
        }
        state.send_packet_id += 1;
        Ok(state.send_packet_id)
    }

    /// Records that a packet labeled with this key ID decrypted successfully, i.e. the peer has
    /// activated this epoch.
    pub fn mark_peer_active(&self) {
        self.state.lock().replay.recv_evidence = true;
    }

    /// Reports whether the peer has activated this epoch.
    pub fn peer_active(&self) -> bool {
        self.state.lock().replay.recv_evidence
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the replay window must be read and updated under one epoch lock, including the replay-rejection returns"
    )]
    fn accept_packet_id(&self, packet_id: u32) -> anyhow::Result<()> {
        #[expect(clippy::cast_possible_truncation, reason = "`DATA_CHANNEL_REPLAY_WINDOW` is 64, which fits a `u32`")]
        let window = DATA_CHANNEL_REPLAY_WINDOW as u32;
        let mut state = self.state.lock();
        let replay = &mut state.replay;

        if !replay.recv_seen {
            replay.recv_highest = packet_id;
            replay.recv_window = 1;
            replay.recv_seen = true;
            return Ok(());
        }

        if packet_id > replay.recv_highest {
            let shift = packet_id - replay.recv_highest;
            if shift >= window {
                replay.recv_window = 1;
            } else {
                replay.recv_window = replay.recv_window << shift | 1;
            }
            replay.recv_highest = packet_id;
            return Ok(());
        }

        let diff = replay.recv_highest - packet_id;
        if diff >= window {
            return Err(anyhow!("openvpn replayed data packet id {packet_id}"));
        }
        let mask = 1u64 << diff;
        if replay.recv_window & mask != 0 {
            return Err(anyhow!("openvpn replayed data packet id {packet_id}"));
        }
        replay.recv_window |= mask;
        Ok(())
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the random buffer is refilled and consumed across loop iterations, so the RNG lock spans the whole fill"
    )]
    fn fill_cbc_iv(&self, iv: &mut [u8]) -> anyhow::Result<()> {
        let mut rand = self.rand_state.lock();
        let mut iv = iv;

        while !iv.is_empty() {
            if rand.offset == rand.buf.len() {
                if rand.buf.is_empty() {
                    rand.buf = vec![0u8; DATA_CHANNEL_IV_RAND_BUF];
                }
                OsRng.try_fill_bytes(&mut rand.buf).map_err(|err| anyhow!("{err}"))?;
                rand.offset = 0;
            }
            let n = iv.len().min(rand.buf.len() - rand.offset);
            let (filled, rest) = iv.split_at_mut(n);
            let (_, buffered) = rand.buf.split_at(rand.offset);
            let (source, _) = buffered.split_at(n);
            filled.copy_from_slice(source);
            rand.offset += n;
            iv = rest;
        }
        Ok(())
    }

    fn hmac_sum(&self, send: bool, data: &[u8]) -> Vec<u8> {
        let Some(auth_hash) = self.auth_hash else {
            return Vec::new();
        };
        let key = if send { &self.send_hmac_key } else { &self.recv_hmac_key };
        auth_hash.hmac(key, &[data])
    }
}

/// The AEAD nonce: the implicit IV with its leading word XORed by the packet id.
fn data_nonce(packet_id: u32, implicit: [u8; DATA_CHANNEL_IV_SIZE]) -> [u8; DATA_CHANNEL_IV_SIZE] {
    let mut nonce = implicit;
    let first = u32::from_be_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]) ^ packet_id;
    nonce[..4].copy_from_slice(&first.to_be_bytes());
    nonce
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("openvpn data packet id reached rekey threshold")]
pub struct ErrDataPacketIDExhausted;

pub(crate) const DATA_PACKET_ID_REKEY_THRESHOLD: u32 = 0xFF00_0000;

fn data_packet_header_size(packet: &[u8]) -> anyhow::Result<usize> {
    let Some(&first) = packet.first() else {
        return Err(anyhow!("empty openvpn data packet"));
    };
    let (opcode, _) = parse_opcode_key_id(first);
    match opcode {
        P_DATA_V1 => Ok(1),
        P_DATA_V2 => {
            if packet.len() < 4 {
                return Err(anyhow!("openvpn P_DATA_V2 packet missing peer id"));
            }
            Ok(4)
        }
        _ => Err(anyhow!("not an openvpn data packet: {opcode}")),
    }
}

fn data_header(peer_id: u32, key_id: u8) -> Vec<u8> {
    if peer_id == PEER_ID_UNSET {
        return vec![opcode_key_id(P_DATA_V1, key_id)];
    }
    let mut header = vec![opcode_key_id(P_DATA_V2, key_id)];
    let [_, first, second, third] = peer_id.to_be_bytes();
    header.extend_from_slice(&[first, second, third]);
    header
}

fn pkcs7_unpad(mut padded: Vec<u8>, block_size: usize) -> anyhow::Result<Vec<u8>> {
    if padded.is_empty() || !padded.len().is_multiple_of(block_size) {
        return Err(anyhow!("invalid openvpn CBC padding length"));
    }
    let padding = usize::from(padded.last().copied().unwrap_or(0));
    if padding == 0 || padding > block_size || padding > padded.len() {
        return Err(anyhow!("invalid openvpn CBC padding"));
    }
    let keep = padded.len() - padding;
    if padded.split_at(keep).1.iter().any(|byte| usize::from(*byte) != padding) {
        return Err(anyhow!("invalid openvpn CBC padding"));
    }
    padded.truncate(keep);
    Ok(padded)
}

#[must_use]
pub fn parse_peer_id(options: &str) -> u32 {
    const PREFIX: &str = "peer-id ";
    for field in split_push_options(options) {
        if let Some(id) = field.strip_prefix(PREFIX).and_then(parse_scan_uint) {
            if id <= PEER_ID_UNSET {
                return id;
            }
        }
    }
    PEER_ID_UNSET
}

/// Scans an unsigned 32-bit value out of the field: leading
/// spaces are skipped, an optional sign is accepted and digits are consumed up to the first
/// non-digit.
fn parse_scan_uint(field: &str) -> Option<u32> {
    let rest = field.trim_start_matches(' ');
    let (negative, digits) = match rest.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => match rest.strip_prefix('+') {
            Some(digits) => (false, digits),
            None => (false, rest),
        },
    };
    let end = digits.find(|ch: char| !ch.is_ascii_digit()).unwrap_or(digits.len());
    if end == 0 || negative {
        return None;
    }
    digits.get(..end).and_then(|digits| digits.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_encrypt_matches_known_answer_vector() {
        let client_keys = KeyMaterial {
            send_cipher_key: vec![0x11; 16],
            send_hmac_key: vec![0x22; 64],
            recv_cipher_key: vec![0x33; 16],
            recv_hmac_key: vec![0x44; 64],
        };
        let client =
            DataChannel::new(&client_keys, CIPHER_AES_128_GCM, AUTH_SHA256, 7, 0).expect("create data channel");

        let ip_packet = vec![0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1];
        let encrypted = client.encrypt(&ip_packet).expect("encrypt packet");
        assert_eq!(
            hex::encode(&encrypted),
            "48000007000000010d91b1910bbe2321ff7e7360b4183ff17e794e64a8909482fedb857c6fdb756550120eb7"
        );
    }
}
