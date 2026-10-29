use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Error, Result};
use md5::{Digest, Md5};

use crate::shadowaead::{cipher as aead_cipher, packet as aead_packet, stream as aead_stream};
use crate::shadowstream::{
    chacha20 as stream_chacha20, cipher as stream_cipher, packet as stream_packet, stream as stream_stream,
};
use murmur_common_net::io::{OldConnAsStream, Stream as NetStream, StreamAsOldConn};
use murmur_common_net::EnhancePacketConn;
use murmur_std_compat::net::Conn as NetConn;

pub trait StreamConnCipher: Send + Sync {
    /// Returns a `Result` because a boxed cipher cannot be shared as one value: the wrapper
    /// rebuilds the cipher from its key, the one place where the single object is observable and
    /// the only one that can fail.
    fn stream_conn(&self, c: Box<dyn NetConn>) -> Result<Box<dyn NetConn>>;
}

pub trait PacketConnCipher: Send + Sync {
    fn packet_conn(&self, c: Arc<dyn EnhancePacketConn>) -> Result<Arc<dyn EnhancePacketConn>>;
}

pub trait Cipher: StreamConnCipher + PacketConnCipher {}

impl<T: StreamConnCipher + PacketConnCipher> Cipher for T {}

#[must_use]
pub fn err_cipher_not_supported() -> Error {
    anyhow!("cipher not supported")
}

pub const AEAD_AES_128_GCM: &str = "AEAD_AES_128_GCM";
pub const AEAD_AES_192_GCM: &str = "AEAD_AES_192_GCM";
pub const AEAD_AES_256_GCM: &str = "AEAD_AES_256_GCM";
pub const AEAD_CHACHA20_POLY1305: &str = "AEAD_CHACHA20_POLY1305";
pub const AEAD_XCHACHA20_POLY1305: &str = "AEAD_XCHACHA20_POLY1305";
pub const AEAD_CHACHA8_POLY1305: &str = "AEAD_CHACHA8_POLY1305";
pub const AEAD_XCHACHA8_POLY1305: &str = "AEAD_XCHACHA8_POLY1305";
pub const AEAD_AES_128_CCM: &str = "AEAD_AES_128_CCM";
pub const AEAD_AES_192_CCM: &str = "AEAD_AES_192_CCM";
pub const AEAD_AES_256_CCM: &str = "AEAD_AES_256_CCM";

type AeadNew = fn(&[u8]) -> Result<Box<dyn aead_cipher::Cipher>>;
type StreamNew = fn(&[u8]) -> Result<Box<dyn stream_cipher::Cipher>>;

/// The value type of the AEAD cipher list.
#[derive(Debug)]
pub struct AeadChoice {
    pub key_size: usize,
    pub new: AeadNew,
}

/// The value type of the stream cipher list.
#[derive(Debug)]
pub struct StreamChoice {
    pub key_size: usize,
    pub new: StreamNew,
}

pub static AEAD_LIST: LazyLock<HashMap<&'static str, AeadChoice>> = LazyLock::new(|| {
    HashMap::from([
        (AEAD_AES_128_GCM, AeadChoice { key_size: 16, new: aead_cipher::aesgcm }),
        (AEAD_AES_192_GCM, AeadChoice { key_size: 24, new: aead_cipher::aesgcm }),
        (AEAD_AES_256_GCM, AeadChoice { key_size: 32, new: aead_cipher::aesgcm }),
        (AEAD_CHACHA20_POLY1305, AeadChoice { key_size: 32, new: aead_cipher::chacha20poly1305 }),
        (AEAD_XCHACHA20_POLY1305, AeadChoice { key_size: 32, new: aead_cipher::xchacha20poly1305 }),
        (AEAD_CHACHA8_POLY1305, AeadChoice { key_size: 32, new: aead_cipher::chacha8poly1305 }),
        (AEAD_XCHACHA8_POLY1305, AeadChoice { key_size: 32, new: aead_cipher::xchacha8poly1305 }),
        (AEAD_AES_128_CCM, AeadChoice { key_size: 16, new: aead_cipher::aesccm }),
        (AEAD_AES_192_CCM, AeadChoice { key_size: 24, new: aead_cipher::aesccm }),
        (AEAD_AES_256_CCM, AeadChoice { key_size: 32, new: aead_cipher::aesccm }),
    ])
});

pub static STREAM_LIST: LazyLock<HashMap<&'static str, StreamChoice>> = LazyLock::new(|| {
    HashMap::from([
        ("RC4-MD5", StreamChoice { key_size: 16, new: stream_cipher::rc4md5 }),
        ("AES-128-CTR", StreamChoice { key_size: 16, new: stream_cipher::aesctr }),
        ("AES-192-CTR", StreamChoice { key_size: 24, new: stream_cipher::aesctr }),
        ("AES-256-CTR", StreamChoice { key_size: 32, new: stream_cipher::aesctr }),
        ("AES-128-CFB", StreamChoice { key_size: 16, new: stream_cipher::aescfb }),
        ("AES-192-CFB", StreamChoice { key_size: 24, new: stream_cipher::aescfb }),
        ("AES-256-CFB", StreamChoice { key_size: 32, new: stream_cipher::aescfb }),
        ("CHACHA20", StreamChoice { key_size: 32, new: stream_chacha20::chacha20 }),
        ("CHACHA20-IETF", StreamChoice { key_size: 32, new: stream_chacha20::chacha20ietf }),
        ("XCHACHA20", StreamChoice { key_size: 32, new: stream_chacha20::xchacha20 }),
    ])
});

pub fn list_cipher() -> Vec<String> {
    let mut l: Vec<String> = AEAD_LIST.keys().chain(STREAM_LIST.keys()).map(|k| (*k).to_owned()).collect();
    l.sort();
    l
}

pub fn pick_cipher(name: &str, key: Option<&[u8]>, password: &str) -> Result<Box<dyn Cipher>> {
    let mut name = name.to_uppercase();

    match name.as_str() {
        "DUMMY" => return Ok(Box::new(Dummy {})),
        "CHACHA20-IETF-POLY1305" => AEAD_CHACHA20_POLY1305.clone_into(&mut name),
        "XCHACHA20-IETF-POLY1305" => AEAD_XCHACHA20_POLY1305.clone_into(&mut name),
        "AES-128-GCM" => AEAD_AES_128_GCM.clone_into(&mut name),
        "AES-192-GCM" => AEAD_AES_192_GCM.clone_into(&mut name),
        "AES-256-GCM" => AEAD_AES_256_GCM.clone_into(&mut name),
        "CHACHA8-IETF-POLY1305" => AEAD_CHACHA8_POLY1305.clone_into(&mut name),
        "XCHACHA8-IETF-POLY1305" => AEAD_XCHACHA8_POLY1305.clone_into(&mut name),
        "AES-128-CCM" => AEAD_AES_128_CCM.clone_into(&mut name),
        "AES-192-CCM" => AEAD_AES_192_CCM.clone_into(&mut name),
        "AES-256-CCM" => AEAD_AES_256_CCM.clone_into(&mut name),
        _ => {}
    }

    if let Some(choice) = AEAD_LIST.get(name.as_str()) {
        let key = match key {
            Some(key) if !key.is_empty() => key.to_vec(),
            _ => kdf(password, choice.key_size),
        };
        if key.len() != choice.key_size {
            let need = i32::try_from(choice.key_size).map_err(|_| err_cipher_not_supported())?;
            return Err(Error::new(aead_cipher::KeySizeError(need)));
        }
        let _ = (choice.new)(&key)?;
        return Ok(Box::new(AeadCipher { make: choice.new, key }));
    }

    if let Some(choice) = STREAM_LIST.get(name.as_str()) {
        let key = match key {
            Some(key) if !key.is_empty() => key.to_vec(),
            _ => kdf(password, choice.key_size),
        };
        if key.len() != choice.key_size {
            let need = i32::try_from(choice.key_size).map_err(|_| err_cipher_not_supported())?;
            return Err(Error::new(stream_cipher::KeySizeError(need)));
        }
        let _ = (choice.new)(&key)?;
        return Ok(Box::new(StreamCipher { make: choice.new, key }));
    }

    Err(err_cipher_not_supported())
}

pub struct AeadCipher {
    make: AeadNew,
    pub key: Vec<u8>,
}

impl fmt::Debug for AeadCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadCipher").finish_non_exhaustive()
    }
}

impl StreamConnCipher for AeadCipher {
    fn stream_conn(&self, c: Box<dyn NetConn>) -> Result<Box<dyn NetConn>> {
        let stream: Box<dyn NetStream> = Box::new(OldConnAsStream(c));
        let conn = aead_stream::new_conn(stream, (self.make)(&self.key)?);
        Ok(Box::new(StreamAsOldConn::new(conn)))
    }
}

impl PacketConnCipher for AeadCipher {
    fn packet_conn(&self, c: Arc<dyn EnhancePacketConn>) -> Result<Arc<dyn EnhancePacketConn>> {
        Ok(Arc::new(aead_packet::new_packet_conn(c, (self.make)(&self.key)?)))
    }
}

pub struct StreamCipher {
    make: StreamNew,
    pub key: Vec<u8>,
}

impl fmt::Debug for StreamCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamCipher").finish_non_exhaustive()
    }
}

impl StreamConnCipher for StreamCipher {
    fn stream_conn(&self, c: Box<dyn NetConn>) -> Result<Box<dyn NetConn>> {
        let stream: Box<dyn NetStream> = Box::new(OldConnAsStream(c));
        let conn = stream_stream::new_conn(stream, (self.make)(&self.key)?);
        Ok(Box::new(StreamAsOldConn::new(conn)))
    }
}

impl PacketConnCipher for StreamCipher {
    fn packet_conn(&self, c: Arc<dyn EnhancePacketConn>) -> Result<Arc<dyn EnhancePacketConn>> {
        Ok(Arc::new(stream_packet::new_packet_conn(c, (self.make)(&self.key)?)))
    }
}

/// The cipher that does not encrypt.
#[derive(Debug)]
pub struct Dummy {}

impl StreamConnCipher for Dummy {
    fn stream_conn(&self, c: Box<dyn NetConn>) -> Result<Box<dyn NetConn>> {
        Ok(c)
    }
}

impl PacketConnCipher for Dummy {
    fn packet_conn(&self, c: Arc<dyn EnhancePacketConn>) -> Result<Arc<dyn EnhancePacketConn>> {
        Ok(c)
    }
}

/// The key-derivation function: MD5 chained over the password.
#[must_use]
pub fn kdf(password: &str, key_len: usize) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    while b.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password.as_bytes());
        let sum = h.finalize();
        let start = sum.len().saturating_sub(16);
        prev = sum.get(start..).unwrap_or_default().to_vec();
        b.extend_from_slice(&sum);
    }
    b.truncate(key_len);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_matches_the_reference_derivation() {
        // MD5 chained derivation: md5(md5(pw) || pw) prefix for a 16-byte key.
        let key = kdf("password", 16);
        let first = Md5::digest(b"password");
        assert_eq!(key, first.to_vec());

        let key32 = kdf("password", 32);
        let mut h = Md5::new();
        h.update(&first[..]);
        h.update(b"password");
        let second = h.finalize();
        assert_eq!(key32, [first.to_vec(), second.to_vec()].concat());
    }

    #[test]
    fn list_cipher_is_sorted_and_complete() {
        let list = list_cipher();
        assert!(list.windows(2).all(|w| w[0] < w[1]));
        assert!(list.contains(&"AEAD_AES_128_GCM".to_owned()));
        assert!(list.contains(&"AEAD_CHACHA20_POLY1305".to_owned()));
        assert_eq!(list.len(), AEAD_LIST.len() + STREAM_LIST.len());
    }

    #[test]
    fn pick_cipher_accepts_aliases_and_rejects_unknown_names() {
        assert!(pick_cipher("dummy", None, "").is_ok());
        assert!(pick_cipher("chacha20-ietf-poly1305", None, "pw").is_ok());
        assert!(pick_cipher("aead_aes_256_gcm", None, "pw").is_ok());
        assert!(pick_cipher("aes-256-cfb", None, "pw").is_ok());
        assert!(pick_cipher("not-a-cipher", None, "pw").is_err());

        let short = match pick_cipher("aes-256-gcm", Some(&[0u8; 16]), "") {
            Ok(_) => panic!("expected a key size error"),
            Err(err) => err,
        };
        assert!(short.to_string().contains("key size error: need 32 bytes"));
    }
}
