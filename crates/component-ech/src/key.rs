use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::Engine as _;
use notify::{RecursiveMode, Watcher};
use parking_lot::RwLock;

use murmur_component_tls::utls::{generate_x25519, Config as TlsConfig, EncryptedClientHelloKey};
use murmur_constant::path::PATH;

pub const AEAD_AES_128_GCM: u16 = 0x0001;
pub const AEAD_AES_256_GCM: u16 = 0x0002;
pub const AEAD_CHACHA20_POLY1305: u16 = 0x0003;

const EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

pub const DHKEM_X25519_HKDF_SHA256: u16 = 0x0020;
pub const KDF_HKDF_SHA256: u16 = 0x0001;

static SORTED_SUPPORTED_AEADS: [u16; 3] = [AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305];

const PEM_LINE_LENGTH: usize = 64;
const PEM_BEGIN: &[u8] = b"-----BEGIN ";
const PEM_END: &[u8] = b"-----END ";
const PEM_DASHES: &[u8] = b"-----";

/// Minimal big-endian byte builder covering the write calls this file makes.
#[derive(Default)]
struct CryptobyteBuilder {
    b: Vec<u8>,
}

impl CryptobyteBuilder {
    fn add_uint8(&mut self, v: u8) {
        self.b.push(v);
    }

    fn add_uint16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }

    fn add_bytes(&mut self, v: &[u8]) {
        self.b.extend_from_slice(v);
    }

    fn add_uint8_length_prefixed(&mut self, f: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let mut inner = Self::default();
        f(&mut inner)?;
        let length = u8::try_from(inner.b.len())
            .map_err(|_| anyhow!("ECH config field of {} bytes does not fit a uint8 length prefix", inner.b.len()))?;
        self.b.push(length);
        self.b.extend_from_slice(&inner.b);
        Ok(())
    }

    fn add_uint16_length_prefixed(&mut self, f: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let mut inner = Self::default();
        f(&mut inner)?;
        let length = u16::try_from(inner.b.len())
            .map_err(|_| anyhow!("ECH config field of {} bytes does not fit a uint16 length prefix", inner.b.len()))?;
        self.b.extend_from_slice(&length.to_be_bytes());
        self.b.extend_from_slice(&inner.b);
        Ok(())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.b
    }
}

/// Cursor over a byte slice covering the read calls this file makes.
struct CryptobyteString<'a> {
    s: &'a [u8],
}

impl<'a> CryptobyteString<'a> {
    const fn new(s: &'a [u8]) -> Self {
        Self { s }
    }

    const fn empty(&self) -> bool {
        self.s.is_empty()
    }

    const fn rest(&self) -> &'a [u8] {
        self.s
    }

    fn read_uint16_length_prefixed(&mut self) -> Option<Self> {
        let (&first, rest) = self.s.split_first()?;
        let (&second, rest) = rest.split_first()?;
        let length = usize::from(u16::from_be_bytes([first, second]));
        if length > rest.len() {
            return None;
        }
        let (out, rest) = rest.split_at(length);
        self.s = rest;
        Some(CryptobyteString::new(out))
    }
}

fn marshal_ech_config(id: u8, pub_key: &[u8], public_name: &str, max_name_len: u8) -> Result<Vec<u8>> {
    let mut builder = CryptobyteBuilder::default();

    builder.add_uint16(EXTENSION_ENCRYPTED_CLIENT_HELLO);
    builder.add_uint16_length_prefixed(|builder| {
        builder.add_uint8(id);

        builder.add_uint16(DHKEM_X25519_HKDF_SHA256);
        builder.add_uint16_length_prefixed(|builder| {
            builder.add_bytes(pub_key);
            Ok(())
        })?;
        builder.add_uint16_length_prefixed(|builder| {
            for aead_id in SORTED_SUPPORTED_AEADS {
                builder.add_uint16(KDF_HKDF_SHA256);
                builder.add_uint16(aead_id);
            }
            Ok(())
        })?;
        builder.add_uint8(max_name_len);
        builder.add_uint8_length_prefixed(|builder| {
            builder.add_bytes(public_name.as_bytes());
            Ok(())
        })?;
        builder.add_uint16(0);
        Ok(())
    })?;

    Ok(builder.into_bytes())
}

pub fn gen_ech_config(public_name: &str) -> Result<(String, String)> {
    let ech_key = generate_x25519()?;
    let public_key = x25519_dalek::PublicKey::from(&ech_key).to_bytes();

    let ech_config = marshal_ech_config(0, &public_key, public_name, 0)?;

    let mut builder = CryptobyteBuilder::default();
    builder.add_uint16_length_prefixed(|builder| {
        builder.add_bytes(&ech_config);
        Ok(())
    })?;
    let ech_config_list = builder.into_bytes();

    let mut builder2 = CryptobyteBuilder::default();
    builder2.add_uint16_length_prefixed(|builder| {
        builder.add_bytes(&ech_key.to_bytes());
        Ok(())
    })?;
    builder2.add_uint16_length_prefixed(|builder| {
        builder.add_bytes(&ech_config);
        Ok(())
    })?;
    let ech_config_keys = builder2.into_bytes();

    let config_base64 = base64::engine::general_purpose::STANDARD.encode(&ech_config_list);
    let key_pem = String::from_utf8(pem_encode_to_memory("ECH KEYS", &ech_config_keys))
        .map_err(|_| anyhow!("ECH keys PEM is not valid UTF-8"))?;
    Ok((config_base64, key_pem))
}

pub fn unmarshal_ech_keys(raw: &[u8]) -> Result<Vec<EncryptedClientHelloKey>> {
    let mut keys = Vec::new();
    let mut raw_string = CryptobyteString::new(raw);
    while !raw_string.empty() {
        let Some(private_key) = raw_string.read_uint16_length_prefixed() else {
            return Err(anyhow!("error parsing private key"));
        };
        let Some(config) = raw_string.read_uint16_length_prefixed() else {
            return Err(anyhow!("error parsing config"));
        };
        keys.push(EncryptedClientHelloKey {
            private_key: private_key.rest().to_vec(),
            config: config.rest().to_vec(),
            send_as_retry: false,
        });
    }
    if keys.is_empty() {
        return Err(anyhow!("empty ECH keys"));
    }
    Ok(keys)
}

pub fn load_ech_key(key: &str, tls_config: &mut TlsConfig) -> Result<()> {
    if key.is_empty() {
        return Ok(());
    }
    let pain_text_err = match load_ech_key_bytes(key.as_bytes()) {
        Ok(ech_keys) => {
            tls_config.get_encrypted_client_hello_keys = Some(Arc::new(move |_info| Ok(ech_keys.clone())));
            return Ok(());
        }
        Err(err) => err,
    };
    let key = PATH.resolve(key);
    let load: Result<Vec<EncryptedClientHelloKey>> = if PATH.is_safe_path(&key) {
        match std::fs::read(&key) {
            Ok(bytes) => load_ech_key_bytes(&bytes),
            Err(load_err) => Err(load_err.into()),
        }
    } else {
        Err(PATH.err_not_safe_path(&key).into())
    };
    let ech_keys = load.map_err(|load_err| {
        anyhow!("parse ECH keys failed, maybe format error:{pain_text_err}, or path error: {load_err}")
    })?;

    // Holding the watcher in the closure returned to the caller keeps the watch running for the
    // loader's lifetime (see `ca::keypair::new_tls_key_pair_loader`).
    let ech_keys = Arc::new(RwLock::new(ech_keys));
    let updated = Arc::clone(&ech_keys);
    let watched_key = key.clone();
    let watcher = notify::recommended_watcher(move |_event: notify::Result<notify::Event>| {
        if let Ok(new_keys) =
            std::fs::read(&watched_key).map_err(anyhow::Error::from).and_then(|bytes| load_ech_key_bytes(&bytes))
        {
            *updated.write() = new_keys;
        }
    })
    .ok()
    .and_then(|mut watcher| watcher.watch(Path::new(&key), RecursiveMode::NonRecursive).ok().map(|()| watcher));

    tls_config.get_encrypted_client_hello_keys = Some(Arc::new(move |_info| {
        let _keep_alive = &watcher;
        Ok(ech_keys.read().clone())
    }));
    Ok(())
}

fn load_ech_key_bytes(ech_key: &[u8]) -> Result<Vec<EncryptedClientHelloKey>> {
    let Some((block_type, block_bytes, rest)) = pem_decode(ech_key) else {
        return Err(anyhow!("invalid ECH keys pem"));
    };
    if block_type != "ECH KEYS" || !rest.is_empty() {
        return Err(anyhow!("invalid ECH keys pem"));
    }
    let ech_keys = unmarshal_ech_keys(&block_bytes).map_err(|err| anyhow!("parse ECH keys: {err}"))?;
    Ok(ech_keys)
}

fn pem_encode_to_memory(block_type: &str, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = writeln!(out, "-----BEGIN {block_type}-----");
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    for chunk in encoded.as_bytes().chunks(PEM_LINE_LENGTH) {
        out.extend_from_slice(chunk);
        out.push(b'\n');
    }
    let _ = writeln!(out, "-----END {block_type}-----");
    out
}

/// Decodes a single unheadered PEM block, the way the ECH key loader reads one: the block type,
/// the block bytes, and the input after the block.
fn pem_decode(data: &[u8]) -> Option<(String, Vec<u8>, Vec<u8>)> {
    let begin = find_bytes(data, PEM_BEGIN, 0)?;
    if begin > 0 && data.get(begin - 1) != Some(&b'\n') {
        return None;
    }
    let type_start = begin + PEM_BEGIN.len();
    let type_end = find_bytes(data, PEM_DASHES, type_start)?;
    let block_type = std::str::from_utf8(data.get(type_start..type_end)?).ok()?.to_owned();

    let mut body = Vec::new();
    let (_, mut pos) = next_line(data, type_end);
    loop {
        let (line_end, next) = next_line(data, pos);
        let mut line = data.get(pos..line_end)?;
        if line.last() == Some(&b'\r') {
            line = line.get(..line.len() - 1)?;
        }
        if line.starts_with(PEM_END) && line.ends_with(PEM_DASHES) {
            let label = line.get(PEM_END.len()..line.len() - PEM_DASHES.len())?;
            if label != block_type.as_bytes() {
                return None;
            }
            let bytes = base64::engine::general_purpose::STANDARD.decode(&body).ok()?;
            return Some((block_type, bytes, data.get(next..)?.to_vec()));
        }
        body.extend(line.iter().copied().filter(|b| *b != b' ' && *b != b'\t'));
        if next >= data.len() {
            return None;
        }
        pos = next;
    }
}

/// The end of the current line, and the start of the next one.
fn next_line(data: &[u8], from: usize) -> (usize, usize) {
    match data.get(from..).and_then(|rest| rest.iter().position(|b| *b == b'\n')) {
        Some(offset) => (from + offset, from + offset + 1),
        None => (data.len(), data.len()),
    }
}

fn find_bytes(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?.windows(needle.len()).position(|window| window == needle).map(|at| at + from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use murmur_component_tls::utls::ClientHelloInfo;

    #[test]
    fn test_gen_ech_config() {
        let domain = "www.example.com";
        let (config_base64, _) = gen_ech_config(domain).expect("gen ech config");
        let ech_config_list = base64::engine::general_purpose::STANDARD.decode(config_base64).expect("base64 decode");
        let ech_configs =
            crate::echparser::echparser::parse_ech_config_list(&ech_config_list).expect("parse ech config list");
        assert!(!ech_configs.is_empty(), "no ech config");
        let public_name = String::from_utf8(ech_configs[0].public_name.clone()).expect("public name is utf-8");
        assert_eq!(public_name, domain, "ech config domain error");
    }

    #[test]
    fn test_load_ech_key_reloads_on_file_change() {
        let (_, key_pem_a) = gen_ech_config("a.example.com").expect("gen ech config a");
        let (_, key_pem_b) = gen_ech_config("b.example.com").expect("gen ech config b");
        let keys_a = load_ech_key_bytes(key_pem_a.as_bytes()).expect("parse key a");
        let keys_b = load_ech_key_bytes(key_pem_b.as_bytes()).expect("parse key b");

        let dir = std::path::PathBuf::from(PATH.home_dir()).join(format!("ech-reload-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("ech.key");
        std::fs::write(&path, &key_pem_a).expect("write initial key");

        let mut tls_config = TlsConfig::default();
        load_ech_key(path.to_str().expect("utf-8 path"), &mut tls_config).expect("load ech key");
        let hook = tls_config.get_encrypted_client_hello_keys.clone().expect("hook installed");
        assert_eq!(hook(&ClientHelloInfo::default()).expect("call hook"), keys_a);

        std::fs::write(&path, &key_pem_b).expect("rewrite key file");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if hook(&ClientHelloInfo::default()).expect("call hook") == keys_b {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "reload watcher never picked up the new key file");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}
