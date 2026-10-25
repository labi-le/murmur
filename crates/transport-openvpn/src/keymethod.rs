//! The OpenVPN key-method 2 exchange: building the client record, parsing the server's, and
//! deriving the data-channel key material.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

use anyhow::{anyhow, Result};
use hmac::{Hmac, KeyInit as _, Mac as _};
use md5::Md5;
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use sha1::Sha1;

use super::config::{
    normalize_cipher, CIPHER_AES_256_CBC, CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305, COMP_LZO_YES, PROTO_TCP,
};
use super::packet::SessionID;
use super::tlscrypt::clone_bytes;

pub const KEY_METHOD_2: u8 = 2;

pub(crate) const KEY_SOURCE_PRE_MASTER_SIZE: usize = 48;
pub(crate) const KEY_SOURCE_RANDOM_SIZE: usize = 32;

pub(crate) const MAX_CIPHER_KEY_LENGTH: usize = 64;
pub(crate) const MAX_HMAC_KEY_LENGTH: usize = 64;
pub(crate) const KEY_BLOCK_SIZE: usize = 2 * (MAX_CIPHER_KEY_LENGTH + MAX_HMAC_KEY_LENGTH);

pub(crate) const KEY_EXPANSION_ID: &str = "OpenVPN";

/// DATA_V2 (bit 1), REQUEST_PUSH (bit 2) and AUTH_PENDING keyword support (bit 4); the
/// AUTH_PENDING,timeout N parser depends on the advertised capability.
const IV_PROTO: u32 = (1 << 1) | (1 << 2) | (1 << 4);

/// Stands in place of the hash-factory argument, which the PRF only ever
/// instantiates with MD5 or SHA-1.
#[derive(Clone, Copy)]
pub(crate) enum PrfHash {
    Md5,
    Sha1,
}

impl PrfHash {
    #[expect(clippy::expect_used, reason = "HMAC accepts a key of any length, so `new_from_slice` cannot fail")]
    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => {
                let mut mac = Hmac::<Md5>::new_from_slice(key).expect("hmac accepts any key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("hmac accepts any key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct KeySource {
    pub pre_master: [u8; KEY_SOURCE_PRE_MASTER_SIZE],
    pub random_1: [u8; KEY_SOURCE_RANDOM_SIZE],
    pub random_2: [u8; KEY_SOURCE_RANDOM_SIZE],
}

impl Default for KeySource {
    fn default() -> Self {
        Self {
            pre_master: [0u8; KEY_SOURCE_PRE_MASTER_SIZE],
            random_1: [0u8; KEY_SOURCE_RANDOM_SIZE],
            random_2: [0u8; KEY_SOURCE_RANDOM_SIZE],
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KeySource2 {
    pub client: KeySource,
    pub server: KeySource,
}

#[derive(Clone, Debug, Default)]
pub struct KeyMaterial {
    pub send_cipher_key: Vec<u8>,
    pub send_hmac_key: Vec<u8>,
    pub recv_cipher_key: Vec<u8>,
    pub recv_hmac_key: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct KeyMethod2Record {
    pub sources: KeySource2,
    pub options: String,
    pub username: String,
    pub password: String,
    pub peer_info: String,
}

pub fn new_client_key_method2_record(
    options: &str,
    peer_info: &str,
    username: &str,
    password: &str,
) -> Result<KeyMethod2Record> {
    let mut record = KeyMethod2Record::default();
    OsRng.try_fill_bytes(&mut record.sources.client.pre_master)?;
    OsRng.try_fill_bytes(&mut record.sources.client.random_1)?;
    OsRng.try_fill_bytes(&mut record.sources.client.random_2)?;
    options.clone_into(&mut record.options);
    peer_info.clone_into(&mut record.peer_info);
    username.clone_into(&mut record.username);
    password.clone_into(&mut record.password);
    Ok(record)
}

impl KeyMethod2Record {
    pub fn marshal_client(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(
            4 + 1 + KEY_SOURCE_PRE_MASTER_SIZE + KEY_SOURCE_RANDOM_SIZE * 2 + self.options.len() + 16,
        );
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(KEY_METHOD_2);
        out.extend_from_slice(&self.sources.client.pre_master);
        out.extend_from_slice(&self.sources.client.random_1);
        out.extend_from_slice(&self.sources.client.random_2);
        append_openvpn_string(&mut out, &self.options);
        append_openvpn_string(&mut out, &self.username);
        append_openvpn_string(&mut out, &self.password);
        append_openvpn_string(&mut out, &self.peer_info);
        Ok(out)
    }
}

/// The packet-too-short sentinel, matched by type.
#[derive(Debug, thiserror::Error)]
#[error("key method 2 packet too short")]
pub(crate) struct ErrKeyMethodPacketTooShort;

/// The string-EOF sentinel.
#[derive(Debug, thiserror::Error)]
#[error("openvpn string truncated")]
pub(crate) struct IoStringEOF;

pub(crate) fn is_io_string_eof(err: &anyhow::Error) -> bool {
    err.chain().any(<dyn std::error::Error + 'static>::is::<IoStringEOF>)
}

/// Error with context: renders the cause and keeps it reachable
/// through the error chain.
#[derive(Debug)]
struct ReadOptionsError(anyhow::Error);

impl fmt::Display for ReadOptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "read options: {}", self.0)
    }
}

impl std::error::Error for ReadOptionsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[expect(clippy::indexing_slicing, reason = "callers pass a slice they have already bounds-checked against the packet")]
fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[expect(clippy::indexing_slicing, reason = "callers pass a slice they have already bounds-checked against the packet")]
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

pub fn parse_server_key_method2_record(packet: &[u8]) -> Result<KeyMethod2Record> {
    let (record, _) = parse_server_key_method2_record_consumed(packet)?;
    Ok(record)
}

/// Parses a server key-method-2 record and reports how many bytes were consumed so
/// following TLS control data (`PUSH_REPLY` / `AUTH_FAILED`) can be preserved.
///
/// `OpenVPN` 2.6 may omit the optional username, password and peer-info strings after the
/// mandatory options string.
pub fn parse_server_key_method2_record_consumed(packet: &[u8]) -> Result<(KeyMethod2Record, usize)> {
    if packet.len() < 4 + 1 + KEY_SOURCE_RANDOM_SIZE * 2 {
        return Err(anyhow::Error::new(ErrKeyMethodPacketTooShort));
    }
    let (prefix, rest) = packet.split_at(4);
    if be_u32(prefix) != 0 {
        return Err(anyhow!("invalid key method 2 prefix"));
    }
    let Some((&key_method, rest)) = rest.split_first() else {
        return Err(anyhow::Error::new(ErrKeyMethodPacketTooShort));
    };
    if key_method & 0x0f != KEY_METHOD_2 {
        return Err(anyhow!("unsupported key method {key_method}"));
    }
    let (random_1, rest) = rest.split_at(KEY_SOURCE_RANDOM_SIZE);
    let (random_2, _) = rest.split_at(KEY_SOURCE_RANDOM_SIZE);
    let mut offset = 5 + KEY_SOURCE_RANDOM_SIZE * 2;
    let mut record = KeyMethod2Record::default();
    record.sources.server.random_1.copy_from_slice(random_1);
    record.sources.server.random_2.copy_from_slice(random_2);

    let (options, next) =
        read_openvpn_string(packet, offset).map_err(|err| anyhow::Error::new(ReadOptionsError(err)))?;
    record.options = options;
    offset = next;

    // OpenVPN 2.6 writes the trailing strings even when empty, so only a following TLS control
    // message ends the record early; a truncated string means the caller must keep reading.
    let (username, next) = read_km2_trailing_string(packet, offset)?;
    record.username = username;
    offset = next;
    let (password, next) = read_km2_trailing_string(packet, offset)?;
    record.password = password;
    offset = next;
    let (peer_info, next) = read_km2_trailing_string(packet, offset)?;
    record.peer_info = peer_info;
    offset = next;
    Ok((record, offset))
}

pub(crate) fn read_km2_trailing_string(packet: &[u8], offset: usize) -> Result<(String, usize)> {
    match read_openvpn_string(packet, offset) {
        Ok((s, next)) => Ok((s, next)),
        Err(err) => {
            if is_io_string_eof(&err) && packet.get(offset..).is_some_and(looks_like_following_tls_control) {
                Ok((String::new(), offset))
            } else {
                Err(err)
            }
        }
    }
}

/// Reports whether a full key-method-2 server record is present, and returns the consumed
/// offset.
///
/// It requires all four strings (`OpenVPN` 2.6 writes them even when empty) so a standard
/// record fragmented across TLS reads is not accepted prematurely.
#[must_use]
pub fn record_complete(packet: &[u8]) -> (bool, usize) {
    if packet.len() < 4 + 1 + KEY_SOURCE_RANDOM_SIZE * 2 {
        return (false, 0);
    }
    if be_u32(packet.split_at(4).0) != 0 {
        return (false, 0);
    }
    if packet.split_at(4).1.first().is_none_or(|byte| byte & 0x0f != KEY_METHOD_2) {
        return (false, 0);
    }
    let mut offset = 5 + KEY_SOURCE_RANDOM_SIZE * 2;
    for _ in 0..4 {
        if !km2_str_complete(packet, offset) {
            return (false, 0);
        }
        let Some(size) = km2_str_len(packet, offset) else {
            return (false, 0);
        };
        offset += 2 + size;
    }
    (true, offset)
}

/// The two-byte length prefix of one key-method-2 string, `None` when it is not present.
fn km2_str_len(packet: &[u8], offset: usize) -> Option<usize> {
    packet.get(offset..offset + 2).map(|prefix| usize::from(be_u16(prefix)))
}

pub(crate) fn km2_str_complete(packet: &[u8], offset: usize) -> bool {
    km2_str_len(packet, offset).is_some_and(|size| size == 0 || offset + 2 + size <= packet.len())
}

pub(crate) fn looks_like_following_tls_control(mut b: &[u8]) -> bool {
    while let Some((&0, rest)) = b.split_first() {
        b = rest;
    }
    if b.is_empty() {
        return false;
    }
    b.starts_with(b"PUSH_REPLY")
        || b.starts_with(b"AUTH_FAILED")
        || b.starts_with(b"PUSH_REQUEST")
        || b.starts_with(b"AUTH_PENDING")
        || b.starts_with(b"INFO_PRE")
        || b.starts_with(b"INFO")
        || b.starts_with(b"RESTART")
        || b.starts_with(b"HALT")
        || b.starts_with(b"EXIT")
        || b.starts_with(b"CR_RESPONSE")
}

pub fn derive_client_key_material(
    sources: KeySource2,
    client_session: SessionID,
    server_session: SessionID,
    cipher_key_len: usize,
) -> Result<KeyMaterial> {
    if cipher_key_len != 16 && cipher_key_len != 24 && cipher_key_len != 32 {
        return Err(anyhow!("unsupported data cipher key length {cipher_key_len}"));
    }
    let mut master = [0u8; KEY_SOURCE_PRE_MASTER_SIZE];
    openvpn_prf(
        &sources.client.pre_master,
        &format!("{KEY_EXPANSION_ID} master secret"),
        &sources.client.random_1,
        &sources.server.random_1,
        &[],
        &[],
        &mut master,
    )?;

    let mut key_block = vec![0u8; KEY_BLOCK_SIZE];
    openvpn_prf(
        &master,
        &format!("{KEY_EXPANSION_ID} key expansion"),
        &sources.client.random_2,
        &sources.server.random_2,
        &client_session[..],
        &server_session[..],
        &mut key_block,
    )?;

    let (client_to_server, server_to_client) = key_block.split_at(MAX_CIPHER_KEY_LENGTH + MAX_HMAC_KEY_LENGTH);
    let (send_cipher_key, _) = client_to_server.split_at(cipher_key_len);
    let (_, send_hmac_key) = client_to_server.split_at(MAX_CIPHER_KEY_LENGTH);
    let (recv_cipher_key, _) = server_to_client.split_at(cipher_key_len);
    let (_, recv_hmac_key) = server_to_client.split_at(MAX_CIPHER_KEY_LENGTH);
    Ok(KeyMaterial {
        send_cipher_key: clone_bytes(send_cipher_key),
        send_hmac_key: clone_bytes(send_hmac_key),
        recv_cipher_key: clone_bytes(recv_cipher_key),
        recv_hmac_key: clone_bytes(recv_hmac_key),
    })
}

#[must_use]
pub fn install_script_options_string(proto: &str, cipher: &str, auth: &str, comp_lzo: &str) -> String {
    let proto_name = if proto == PROTO_TCP { "TCPv4_CLIENT" } else { "UDPv4" };
    let keysize = if cipher == CIPHER_AES_256_GCM || cipher == CIPHER_AES_256_CBC || cipher == CIPHER_CHACHA20_POLY1305
    {
        "256"
    } else {
        "128"
    };
    let (mtu, comp) = if comp_lzo == COMP_LZO_YES { ("1544", "comp-lzo,") } else { ("1550", "") };
    format!("V4,dev-type tun,link-mtu {mtu},tun-mtu 1500,proto {proto_name},{comp}cipher {cipher},auth {auth},keysize {keysize},key-method 2,tls-client")
}

#[expect(
    clippy::implicit_hasher,
    reason = "the peer-info map is built and passed by crate-internal callers with the default hasher"
)]
#[must_use]
pub fn install_script_peer_info(
    cipher: &str,
    data_ciphers: &[String],
    comp_lzo: &str,
    peer_info: &HashMap<String, String>,
) -> String {
    let iv_ver = peer_info.get("IV_VER").map_or("murmur-openvpn", String::as_str);
    let lzo = if comp_lzo == COMP_LZO_YES { "IV_LZO=1\n" } else { "" };
    let iv_ciphers = if data_ciphers.is_empty() {
        cipher.to_owned()
    } else {
        data_ciphers.iter().map(|c| normalize_cipher(c)).collect::<Vec<String>>().join(":")
    };
    let mut info = format!("IV_VER={iv_ver}\nIV_PROTO={IV_PROTO}\n{lzo}IV_CIPHERS={iv_ciphers}\n");
    // Sorted so the peer-info string is deterministic.
    let mut keys: Vec<&String> = Vec::with_capacity(peer_info.len());
    for key in peer_info.keys() {
        match key.as_str() {
            "IV_VER" | "IV_PROTO" | "IV_CIPHERS" => continue,
            "IV_LZO" if !lzo.is_empty() => {
                continue;
            }
            _ => {}
        }
        keys.push(key);
    }
    keys.sort();
    for key in keys {
        let _ = writeln!(info, "{key}={}", peer_info[key]);
    }
    info
}

pub(crate) fn append_openvpn_string(out: &mut Vec<u8>, s: &str) {
    if s.is_empty() {
        out.extend_from_slice(&0u16.to_be_bytes());
        return;
    }
    let bytes = s.as_bytes();
    let bytes = if bytes.len() + 1 > 0xffff { bytes.split_at(0xfffe).0 } else { bytes };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "`bytes` was clamped to 0xfffe above, so the prefix fits a `u16`"
    )]
    let length = (bytes.len() + 1) as u16;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    out.push(0);
}

pub(crate) fn read_openvpn_string(packet: &[u8], offset: usize) -> Result<(String, usize)> {
    let Some(prefix) = packet.get(offset..offset + 2) else {
        return Err(anyhow::Error::new(IoStringEOF));
    };
    let size = usize::from(be_u16(prefix));
    if size == 0 {
        return Ok((String::new(), offset + 2));
    }
    let Some(raw) = packet.get(offset + 2..offset + 2 + size) else {
        // The length prefix is left unconsumed: the leftover bytes may be PUSH_REPLY.
        return Err(anyhow::Error::new(IoStringEOF));
    };
    let raw = raw.strip_suffix(&[0]).unwrap_or(raw);
    Ok((String::from_utf8_lossy(raw).into_owned(), offset + 2 + size))
}

#[expect(clippy::unnecessary_wraps, reason = "every key-derivation caller propagates the `Result` signature with `?`")]
pub(crate) fn openvpn_prf(
    secret: &[u8],
    label: &str,
    client_seed: &[u8],
    server_seed: &[u8],
    client_session: &[u8],
    server_session: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let mut seed = Vec::with_capacity(
        label.len() + client_seed.len() + server_seed.len() + client_session.len() + server_session.len(),
    );
    seed.extend_from_slice(label.as_bytes());
    seed.extend_from_slice(client_seed);
    seed.extend_from_slice(server_seed);
    seed.extend_from_slice(client_session);
    seed.extend_from_slice(server_session);

    let split = secret.len().div_ceil(2);
    let (s1, _) = secret.split_at(split);
    let (_, s2) = secret.split_at(secret.len() - split);

    let md5_out = p_hash(PrfHash::Md5, s1, &seed, out.len());
    let sha1_out = p_hash(PrfHash::Sha1, s2, &seed, out.len());
    for (byte, (md5, sha1)) in out.iter_mut().zip(md5_out.iter().zip(&sha1_out)) {
        *byte = md5 ^ sha1;
    }
    Ok(())
}

pub(crate) fn p_hash(hash: PrfHash, secret: &[u8], seed: &[u8], size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    let mut a = hmac_sum(hash, secret, seed);
    while out.len() < size {
        let mut chunk_input = Vec::with_capacity(a.len() + seed.len());
        chunk_input.extend_from_slice(&a);
        chunk_input.extend_from_slice(seed);
        out.extend_from_slice(&hmac_sum(hash, secret, &chunk_input));
        a = hmac_sum(hash, secret, &a);
    }
    out.truncate(size);
    out
}

pub(crate) fn hmac_sum(hash: PrfHash, key: &[u8], data: &[u8]) -> Vec<u8> {
    hash.hmac(key, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AUTH_SHA1, AUTH_SHA256, CIPHER_AES_128_GCM, PROTO_UDP};

    fn sample_record(cipher: &str) -> KeyMethod2Record {
        let mut record = KeyMethod2Record {
            options: install_script_options_string(PROTO_UDP, cipher, AUTH_SHA256, ""),
            peer_info: install_script_peer_info(cipher, &[], "", &HashMap::new()),
            ..Default::default()
        };
        for i in 0..KEY_SOURCE_PRE_MASTER_SIZE {
            record.sources.client.pre_master[i] = (i + 1) as u8;
        }
        for i in 0..KEY_SOURCE_RANDOM_SIZE {
            record.sources.client.random_1[i] = (i + 2) as u8;
            record.sources.client.random_2[i] = (i + 3) as u8;
            record.sources.server.random_1[i] = (i + 4) as u8;
            record.sources.server.random_2[i] = (i + 5) as u8;
        }
        record
    }

    fn session_id(bytes: &[u8]) -> SessionID {
        let mut id = SessionID::default();
        id.0[..bytes.len()].copy_from_slice(bytes);
        id
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Client marshal and derive round trip.
    #[test]
    fn key_method2_client_marshal_and_derive() {
        let record = sample_record(CIPHER_AES_128_GCM);
        let encoded = record.marshal_client().unwrap();
        assert_eq!(u32::from_be_bytes(encoded[..4].try_into().unwrap()), 0);
        assert_eq!(encoded[4], KEY_METHOD_2);
        assert!(encoded.windows(record.options.len()).any(|w| w == record.options.as_bytes()));

        let client_id = session_id(b"client01");
        let server_id = session_id(b"server01");
        let keys = derive_client_key_material(record.sources, client_id, server_id, 16).unwrap();
        assert_eq!(keys.send_cipher_key.len(), 16);
        assert_eq!(keys.recv_cipher_key.len(), 16);
        assert_eq!(keys.send_hmac_key.len(), MAX_HMAC_KEY_LENGTH);
        assert_eq!(keys.recv_hmac_key.len(), MAX_HMAC_KEY_LENGTH);
        assert_ne!(keys.send_cipher_key, keys.recv_cipher_key);
    }

    /// The four hex strings are the derived client key material's send cipher key, send HMAC
    /// key, recv cipher key and recv HMAC key for the fixture below.
    #[test]
    fn key_method2_derive_aes256_known_answer() {
        let record = sample_record(CIPHER_AES_256_GCM);
        let client_id = session_id(b"client01");
        let server_id = session_id(b"server01");
        let keys = derive_client_key_material(record.sources, client_id, server_id, 32).unwrap();
        assert_eq!(keys.send_cipher_key.len(), 32);
        assert_eq!(keys.recv_cipher_key.len(), 32);
        assert_eq!(keys.send_hmac_key.len(), MAX_HMAC_KEY_LENGTH);
        assert_eq!(keys.recv_hmac_key.len(), MAX_HMAC_KEY_LENGTH);
        assert_ne!(keys.send_cipher_key, keys.recv_cipher_key);

        assert_eq!(hex(&keys.send_cipher_key), "398bb7e7f3e55b4ec9b663bc44d04696d29d61d207598f396b2f56c74e06e1ba");
        assert_eq!(
            hex(&keys.send_hmac_key),
            "cf5ddca2c0f9b86d98363c83c7c3a372e0c4a62b6f06239d8446c6ddfa6a903da4d2df1c1014ac3a1bf8932fd439b19b558ab3653be3eabeabb9ea548fb0c784"
        );
        assert_eq!(hex(&keys.recv_cipher_key), "81693cfb38abb5f88039763eb4c9450b0ec614b45bf8dfe52ebce363e7accd1a");
        assert_eq!(
            hex(&keys.recv_hmac_key),
            "317dab8cd211fe399a685370e996026b167d3a084fabd4f549b61e059d1fac57e4280885640e9f79b03b37756739f8798e418c24eb2883021e67864a4066186b"
        );
    }

    /// Install-script options for CBC/SHA1.
    #[test]
    fn install_script_options_cbc_sha1() {
        let options = install_script_options_string(PROTO_TCP, CIPHER_AES_256_CBC, AUTH_SHA1, "");
        for want in ["proto TCPv4_CLIENT", "cipher AES-256-CBC", "auth SHA1", "keysize 256"] {
            assert!(options.contains(want), "options missing {want:?}: {options}");
        }
    }

    /// Install-script peer info: sorted merge and IV_VER override.
    #[test]
    fn install_script_peer_info_sorted_merge_and_iv_ver_override() {
        let base = install_script_peer_info(CIPHER_AES_128_GCM, &[], "", &HashMap::new());
        assert_eq!(base, "IV_VER=murmur-openvpn\nIV_PROTO=22\nIV_CIPHERS=AES-128-GCM\n");

        let mut extra = HashMap::new();
        extra.insert("UV_DEVICE_ID".to_owned(), "laptop-001".to_owned());
        extra.insert("IV_HWADDR".to_owned(), "52:54:00:ff:72:87".to_owned());
        let info = install_script_peer_info(CIPHER_AES_128_GCM, &[], "", &extra);
        assert_eq!(info, format!("{base}IV_HWADDR=52:54:00:ff:72:87\nUV_DEVICE_ID=laptop-001\n"));

        let mut overrides = HashMap::new();
        overrides.insert("IV_VER".to_owned(), "custom-client/1.0".to_owned());
        overrides.insert("IV_PROTO".to_owned(), "999".to_owned());
        overrides.insert("IV_LZO".to_owned(), "0".to_owned());
        overrides.insert("IV_CIPHERS".to_owned(), "AES-256-CBC".to_owned());
        let overridden = install_script_peer_info(CIPHER_AES_128_GCM, &[], COMP_LZO_YES, &overrides);
        assert_eq!(overridden, "IV_VER=custom-client/1.0\nIV_PROTO=22\nIV_LZO=1\nIV_CIPHERS=AES-128-GCM\n");
    }

    /// Parses a basic server key-method-2 record.
    #[test]
    fn parse_server_key_method2_record_basic() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.push(KEY_METHOD_2);
        packet.extend(vec![1u8; KEY_SOURCE_RANDOM_SIZE]);
        packet.extend(vec![2u8; KEY_SOURCE_RANDOM_SIZE]);
        append_openvpn_string(&mut packet, "server-options");
        append_openvpn_string(&mut packet, "");
        append_openvpn_string(&mut packet, "");
        append_openvpn_string(&mut packet, "IV_VER=server\n");

        let record = parse_server_key_method2_record(&packet).unwrap();
        assert_eq!(record.options, "server-options");
        assert_eq!(record.peer_info, "IV_VER=server\n");
        assert_eq!(record.sources.server.random_1[0], 1);
        assert_eq!(record.sources.server.random_2[0], 2);
    }

    /// A shortened server key-method-2 record preserves its tail.
    #[test]
    fn parse_server_key_method2_record_shortened_preserves_tail() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.push(KEY_METHOD_2);
        packet.extend(vec![1u8; KEY_SOURCE_RANDOM_SIZE]);
        packet.extend(vec![2u8; KEY_SOURCE_RANDOM_SIZE]);
        append_openvpn_string(&mut packet, "server-options");
        packet.extend_from_slice(b"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00");

        let (record, consumed) = parse_server_key_method2_record_consumed(&packet).unwrap();
        assert_eq!(record.options, "server-options");
        assert_eq!(record.username, "");
        assert_eq!(record.password, "");
        assert_eq!(record.peer_info, "");
        assert!(packet[consumed..].starts_with(b"PUSH_REPLY"));
    }
}
