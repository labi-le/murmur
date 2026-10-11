//! The age v1 format (header, stanzas, payload stream), armor, bech32, the HKDF/AEAD primitives and
//! the X25519 identity/recipient.
//!
//! No crate mirrors those parts, so what this wrapper uses is implemented here.
//!
//! The `mlkem768x25519` (post-quantum) recipient needs ML-KEM-768, which no
//! pinned crate provides: its keys parse and print, but wrapping and unwrapping a
//! file key return an error.

use std::fmt;
use std::io::{Read, Write};
use std::sync::LazyLock;

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use rand::Rng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

pub const FILE_HEADER: &str = ARMOR_HEADER;

static GLOBAL_SECRET_KEYS: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));

fn parse_identities(secret_key: &str) -> Result<Vec<Identity>> {
    const PRIVATE_KEY_SIZE_LIMIT: usize = 1 << 24; // 16 MiB
    let bytes = secret_key.as_bytes();
    let limited = bytes.get(..PRIVATE_KEY_SIZE_LIMIT).unwrap_or(bytes);
    let mut ids: Vec<Identity> = Vec::new();
    for (i, line) in limited.split(|b| *b == b'\n').enumerate() {
        let n = i + 1;
        let line = strip_cr(line);
        if line.starts_with(b"#") || line.is_empty() {
            continue;
        }
        let line = std::str::from_utf8(line).map_err(|_| anyhow!("identities file is not valid UTF-8"))?;
        let identity = parse_identity(line).map_err(|err| anyhow!("error at line {n}: {err}"))?;
        ids.push(identity);
    }
    if ids.is_empty() {
        bail!("no identities found");
    }
    Ok(ids)
}

fn parse_identity(arg: &str) -> Result<Identity> {
    if arg.starts_with("AGE-SECRET-KEY-1") {
        return Ok(Identity::X25519(parse_x25519_identity(arg)?));
    }
    if arg.starts_with("AGE-SECRET-KEY-PQ-1") {
        return Ok(Identity::Hybrid(parse_hybrid_identity(arg)?));
    }
    Err(anyhow!("unknown identity type: {arg:?}"))
}

fn parse_recipients(public_key: &str) -> Result<Vec<Box<dyn Recipient>>> {
    const RECIPIENT_FILE_SIZE_LIMIT: usize = 1 << 24; // 16 MiB
    let bytes = public_key.as_bytes();
    let limited = bytes.get(..RECIPIENT_FILE_SIZE_LIMIT).unwrap_or(bytes);
    let mut recs: Vec<Box<dyn Recipient>> = Vec::new();
    for (i, line) in limited.split(|b| *b == b'\n').enumerate() {
        let n = i + 1;
        let line = strip_cr(line);
        if line.starts_with(b"#") || line.is_empty() {
            continue;
        }
        let line = std::str::from_utf8(line).map_err(|_| anyhow!("recipients file is not valid UTF-8"))?;
        let recipient = parse_recipient(line).map_err(|err| anyhow!("error at line {n}: {err}"))?;
        recs.push(recipient);
    }
    if recs.is_empty() {
        bail!("no recipients found");
    }
    Ok(recs)
}

fn parse_recipient(arg: &str) -> Result<Box<dyn Recipient>> {
    if arg.starts_with("age1pq1") {
        return Ok(Box::new(parse_hybrid_recipient(arg)?));
    }
    if arg.starts_with("age1") {
        return Ok(Box::new(parse_x25519_recipient(arg)?));
    }
    Err(anyhow!("unknown recipient type: {arg:?}"))
}

fn convert_to_recipient(identity: &Identity) -> Result<Box<dyn Recipient>> {
    match identity {
        Identity::X25519(identity) => Ok(Box::new(identity.recipient())),
        Identity::Hybrid(identity) => Ok(Box::new(identity.recipient()?)),
    }
}

pub fn to_public_keys(secret_keys: &[String]) -> Result<Vec<String>> {
    let mut public_keys = Vec::new();
    for secret_key in secret_keys {
        let identities = parse_identities(secret_key)?;
        for identity in identities {
            let recipient = convert_to_recipient(&identity)?;
            public_keys.push(recipient.string());
        }
    }
    Ok(public_keys)
}

pub fn set_global_secret_keys(secret_keys: &[String]) {
    let mut global_secret_keys = GLOBAL_SECRET_KEYS.write();
    global_secret_keys.clear();
    global_secret_keys.extend_from_slice(secret_keys);
}

pub fn verity_secret_keys(secret_keys: &[String]) -> Result<()> {
    for secret_key in secret_keys {
        parse_identities(secret_key)?;
    }
    Ok(())
}

pub fn verity_public_keys(public_keys: &[String]) -> Result<()> {
    for public_key in public_keys {
        parse_recipients(public_key)?;
    }
    Ok(())
}

pub fn decrypt_bytes(data: &[u8], secret_keys: &[String]) -> Result<Vec<u8>> {
    if !data.starts_with(FILE_HEADER.as_bytes()) {
        // not age armor format
        return Ok(data.to_vec());
    }
    let mut identities: Vec<Identity> = Vec::new();
    for secret_key in secret_keys {
        identities.extend(parse_identities(secret_key)?);
    }
    for secret_key in GLOBAL_SECRET_KEYS.read().iter() {
        identities.extend(parse_identities(secret_key)?);
    }

    decrypt(&armor_decode(data)?, &identities)
}

pub fn encrypt_bytes(data: &[u8], public_keys: &[String]) -> Result<Vec<u8>> {
    let mut recipients: Vec<Box<dyn Recipient>> = Vec::new();
    for public_key in public_keys {
        recipients.extend(parse_recipients(public_key)?);
    }
    Ok(armor_encode(&encrypt(data, &recipients)?))
}

pub fn gen_x25519_key_pair() -> Result<(String, String)> {
    let identity = generate_x25519_identity();
    Ok((identity.string(), identity.recipient().string()))
}

pub fn gen_hybrid_key_pair() -> Result<(String, String)> {
    let identity = generate_hybrid_identity()?;
    Ok((identity.string(), identity.recipient()?.string()))
}

#[expect(clippy::panic, reason = "a CLI entry point has no caller to report a usage or I/O failure to")]
#[expect(clippy::print_stdout, reason = "CLI output on the process stdout, not a log line")]
pub fn main(args: &[String]) {
    let Some(command) = args.first() else {
        panic!("Using: age keygen/keygen-pq/convert/decrypt/encrypt");
    };
    match command.as_str() {
        "keygen" => {
            let (secret_key, public_key) = gen_x25519_key_pair().unwrap_or_else(|err| panic!("{err}"));
            println!("# created: {}", created_at());
            println!("# public key: {public_key}");
            println!("{secret_key}");
        }
        "keygen-pq" => {
            let (secret_key, public_key) = gen_hybrid_key_pair().unwrap_or_else(|err| panic!("{err}"));
            println!("# created: {}", created_at());
            println!("# public key: {public_key}");
            println!("{secret_key}");
        }
        "convert" => {
            let Some(secret_key) = args.get(1) else {
                panic!("Using: age convert <secret_key>");
            };
            let public_keys = to_public_keys(std::slice::from_ref(secret_key)).unwrap_or_else(|err| panic!("{err}"));
            assert!(!public_keys.is_empty(), "no public keys found in the input");
            for public_key in public_keys {
                println!("{public_key}");
            }
        }
        "decrypt" => {
            let [_, secret_key, source, target, ..] = args else {
                panic!("Using: age decrypt <secret_key> <source_file> <target_file>");
            };
            let data = read_source(source).unwrap_or_else(|err| panic!("{err}"));
            let result = decrypt_bytes(&data, std::slice::from_ref(secret_key)).unwrap_or_else(|err| panic!("{err}"));
            write_target(target, &result).unwrap_or_else(|err| panic!("{err}"));
        }
        "encrypt" => {
            let [_, public_key, source, target, ..] = args else {
                panic!("Using: age encrypt <public_key> <source_file> <target_file>");
            };
            let data = read_source(source).unwrap_or_else(|err| panic!("{err}"));
            let result = encrypt_bytes(&data, std::slice::from_ref(public_key)).unwrap_or_else(|err| panic!("{err}"));
            write_target(target, &result).unwrap_or_else(|err| panic!("{err}"));
        }
        _ => {}
    }
}

fn created_at() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn read_source(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut data = Vec::new();
        std::io::stdin().read_to_end(&mut data)?;
        return Ok(data);
    }
    Ok(std::fs::read(path)?)
}

fn write_target(path: &str, data: &[u8]) -> Result<()> {
    if path == "-" {
        std::io::stdout().write_all(data)?;
        return Ok(());
    }
    std::fs::write(path, data)?;
    Ok(())
}

// ---------- age core ----------

const FILE_KEY_SIZE: usize = 16;
const STREAM_NONCE_SIZE: usize = 16;
const AEAD_NONCE_SIZE: usize = 12;
const AEAD_KEY_SIZE: usize = 32;
const AEAD_OVERHEAD: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024;
const ENC_CHUNK_SIZE: usize = CHUNK_SIZE + AEAD_OVERHEAD;
const LAST_CHUNK_FLAG: u8 = 0x01;
const X25519_LABEL: &str = "age-encryption.org/v1/X25519";
const HYBRID_LABEL: &str = "age-encryption.org/mlkem768x25519";
/// The ML-KEM encapsulation key size plus the curve point size.
const HYBRID_PUBLIC_KEY_SIZE: usize = 1184 + 32;
/// The private key takes a 32-byte seed.
const HYBRID_SECRET_KEY_SIZE: usize = 32;

const INTRO: &str = "age-encryption.org/v1\n";
const STANZA_PREFIX: &str = "->";
const FOOTER_PREFIX: &str = "---";
const COLUMNS_PER_LINE: usize = 64;
const BYTES_PER_LINE: usize = COLUMNS_PER_LINE / 4 * 3;

#[derive(Debug, Clone, Copy, Error)]
pub enum AgeError {
    #[error("incorrect identity for recipient block")]
    IncorrectIdentity,
}

/// `decrypt_header` and `multi_unwrap` branch on "this identity does not match this recipient
/// stanza, try the next one" versus every other failure, which aborts decryption outright;
/// replaces the `downcast_ref::<AgeError>()` at both call sites with a `match`.
#[derive(Debug, Error)]
pub(crate) enum UnwrapError {
    #[error("incorrect identity for recipient block")]
    IncorrectIdentity,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// `X25519Identity::unwrap_stanza` branches on "ciphertext has the wrong length" (a real, distinct
/// failure) versus every other AEAD failure (treated as "wrong identity"); replaces the
/// `downcast_ref::<AeadError>()` at that call site with a `match`.
#[derive(Debug, Error)]
pub(crate) enum AeadDecryptError {
    #[error("encrypted value has unexpected length")]
    IncorrectCiphertextSize,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// A closed enum, not a trait object: this crate implements exactly the two identity kinds age v1
/// defines (`X25519Identity`, `HybridIdentity`).
///
/// The downcast-by-concrete-type therefore becomes an exhaustive match instead of a runtime type
/// test with an "unexpected identity type" fallback that could never actually be reached.
pub enum Identity {
    X25519(X25519Identity),
    Hybrid(HybridIdentity),
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X25519(identity) => f.debug_tuple("X25519").field(identity).finish(),
            Self::Hybrid(identity) => f.debug_tuple("Hybrid").field(identity).finish(),
        }
    }
}

impl Identity {
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<Vec<u8>, UnwrapError> {
        match self {
            Self::X25519(identity) => identity.unwrap(stanzas),
            Self::Hybrid(_) => Err(hybrid_unavailable().into()),
        }
    }
}

pub trait Recipient: Send + Sync {
    fn wrap(&self, file_key: &[u8]) -> Result<Vec<Stanza>>;

    /// The optional recipient labels returned alongside the wrapped key.
    fn wrap_with_labels(&self, file_key: &[u8]) -> Result<(Vec<Stanza>, Vec<String>)> {
        Ok((self.wrap(file_key)?, Vec::new()))
    }

    fn string(&self) -> String;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stanza {
    pub type_: String,
    pub args: Vec<String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Header {
    pub recipients: Vec<Stanza>,
    pub mac: Vec<u8>,
}

#[derive(Debug)]
pub struct NoIdentityMatchError {
    pub errors: Vec<anyhow::Error>,
    pub stanza_types: Vec<String>,
}

impl fmt::Display for NoIdentityMatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let [error] = self.errors.as_slice() {
            return write!(f, "identity did not match any of the recipients: {error}");
        }
        f.write_str("no identity matched any of the recipients")
    }
}

impl std::error::Error for NoIdentityMatchError {}

fn decrypt(data: &[u8], identities: &[Identity]) -> Result<Vec<u8>> {
    let (header, payload) = parse(data).map_err(|err| anyhow!("failed to read header: {err}"))?;

    let file_key = decrypt_header(&header, identities)?;

    if payload.len() < STREAM_NONCE_SIZE {
        let eof = if payload.is_empty() { "EOF" } else { "unexpected EOF" };
        bail!("failed to read nonce: {eof}");
    }
    let (nonce, payload) = payload.split_at(STREAM_NONCE_SIZE);
    let stream_key = stream_key(&file_key, nonce)?;

    decrypt_payload(&stream_key, payload)
}

fn encrypt(data: &[u8], recipients: &[Box<dyn Recipient>]) -> Result<Vec<u8>> {
    let mut file_key = [0u8; FILE_KEY_SIZE];
    rand::rng().fill(&mut file_key[..]);

    let header = encrypt_header(&file_key, recipients)?;
    let mut out = marshal_header(&header);
    out.extend_from_slice(&encrypt_payload(&file_key, data)?);
    Ok(out)
}

fn encrypt_header(file_key: &[u8], recipients: &[Box<dyn Recipient>]) -> Result<Header> {
    if recipients.is_empty() {
        bail!("no recipients specified");
    }

    let mut header = Header::default();
    let mut labels: Vec<String> = Vec::new();
    for (i, recipient) in recipients.iter().enumerate() {
        let (stanzas, mut recipient_labels) = recipient
            .wrap_with_labels(file_key)
            .map_err(|err| anyhow!("failed to wrap key for recipient #{i}: {err}"))?;
        recipient_labels.sort();
        if i == 0 {
            labels = recipient_labels;
        } else if labels != recipient_labels {
            return Err(incompatible_labels_error(&labels, &recipient_labels));
        }
        header.recipients.extend(stanzas);
    }
    header.mac = header_mac(file_key, &header).map_err(|err| anyhow!("failed to compute header MAC: {err}"))?;
    Ok(header)
}

fn incompatible_labels_error(labels1: &[String], labels2: &[String]) -> anyhow::Error {
    let has_pq1 = labels1.iter().any(|label| label == "postquantum");
    let has_pq2 = labels2.iter().any(|label| label == "postquantum");
    if has_pq1 != has_pq2 {
        return anyhow!("incompatible recipients: can't mix post-quantum and classic recipients, or the file would be vulnerable to quantum computers");
    }
    anyhow!("incompatible recipients: {} and {} can't be mixed", quoted_list(labels1), quoted_list(labels2))
}

fn quoted_list(labels: &[String]) -> String {
    let quoted: Vec<String> = labels.iter().map(|label| format!("{label:?}")).collect();
    format!("[{}]", quoted.join(" "))
}

fn decrypt_header(header: &Header, identities: &[Identity]) -> Result<Vec<u8>> {
    if identities.is_empty() {
        bail!("no identities specified");
    }

    let mut err_no_match = NoIdentityMatchError {
        errors: Vec::new(),
        stanza_types: header.recipients.iter().map(|stanza| stanza.type_.clone()).collect(),
    };
    let mut file_key: Option<Vec<u8>> = None;
    for identity in identities {
        match identity.unwrap(&header.recipients) {
            Ok(key) => {
                file_key = Some(key);
                break;
            }
            Err(UnwrapError::IncorrectIdentity) => {
                err_no_match.errors.push(AgeError::IncorrectIdentity.into());
            }
            Err(UnwrapError::Other(err)) => return Err(err),
        }
    }
    let Some(file_key) = file_key else {
        return Err(err_no_match.into());
    };

    let mac = header_mac(&file_key, header).map_err(|err| anyhow!("failed to compute header MAC: {err}"))?;
    if mac.ct_eq(&header.mac).unwrap_u8() != 1 {
        bail!("bad header MAC");
    }

    Ok(file_key)
}

fn multi_unwrap(
    unwrap: &dyn Fn(&Stanza) -> Result<Vec<u8>, UnwrapError>,
    stanzas: &[Stanza],
) -> Result<Vec<u8>, UnwrapError> {
    for stanza in stanzas {
        match unwrap(stanza) {
            Ok(file_key) => return Ok(file_key),
            Err(UnwrapError::IncorrectIdentity) => {}
            Err(other) => return Err(other),
        }
    }
    Err(UnwrapError::IncorrectIdentity)
}

fn aead_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let aead = ChaCha20Poly1305::new_from_slice(key).map_err(|err| anyhow!("{err}"))?;
    // The nonce is fixed because each key is only used once.
    let nonce = Nonce::from([0u8; AEAD_NONCE_SIZE]);
    aead.encrypt(&nonce, plaintext).map_err(|err| anyhow!("{err}"))
}

fn aead_decrypt(key: &[u8], size: usize, ciphertext: &[u8]) -> Result<Vec<u8>, AeadDecryptError> {
    let aead = ChaCha20Poly1305::new_from_slice(key).map_err(|err| anyhow!("{err}"))?;
    if ciphertext.len() != size + AEAD_OVERHEAD {
        return Err(AeadDecryptError::IncorrectCiphertextSize);
    }
    let nonce = Nonce::from([0u8; AEAD_NONCE_SIZE]);
    Ok(aead.decrypt(&nonce, ciphertext).map_err(|err| anyhow!("{err}"))?)
}

fn header_mac(file_key: &[u8], header: &Header) -> Result<Vec<u8>> {
    let hmac_key = hkdf_sha256(file_key, None, b"header", 32)?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(&hmac_key).map_err(|err| anyhow!("{err}"))?;
    hmac.update(&marshal_header_without_mac(header));
    Ok(hmac.finalize().into_bytes().to_vec())
}

fn stream_key(file_key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    hkdf_sha256(file_key, Some(nonce), b"payload", AEAD_KEY_SIZE)
}

fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut okm = vec![0u8; length];
    Hkdf::<Sha256>::new(salt, ikm).expand(info, &mut okm).map_err(|err| anyhow!("{err}"))?;
    Ok(okm)
}

fn encrypt_payload(file_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; STREAM_NONCE_SIZE];
    rand::rng().fill(&mut nonce[..]);
    let key = stream_key(file_key, &nonce)?;
    let aead = ChaCha20Poly1305::new_from_slice(&key).map_err(|err| anyhow!("{err}"))?;

    let mut out = Vec::with_capacity(STREAM_NONCE_SIZE + plaintext.len() + ENC_CHUNK_SIZE);
    out.extend_from_slice(&nonce);

    let mut chunk_nonce = [0u8; AEAD_NONCE_SIZE];
    let mut rest = plaintext;
    loop {
        let last = rest.len() <= CHUNK_SIZE;
        let (chunk, tail) = rest.split_at(rest.len().min(CHUNK_SIZE));
        if last {
            set_last_chunk_flag(&mut chunk_nonce);
        }
        let ciphertext = aead.encrypt(&Nonce::from(chunk_nonce), chunk).map_err(|err| anyhow!("{err}"))?;
        out.extend_from_slice(&ciphertext);
        if last {
            break;
        }
        inc_nonce(&mut chunk_nonce)?;
        rest = tail;
    }
    Ok(out)
}

fn decrypt_payload(key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let aead = ChaCha20Poly1305::new_from_slice(key).map_err(|err| anyhow!("{err}"))?;
    let mut out: Vec<u8> = Vec::new();
    let mut nonce = [0u8; AEAD_NONCE_SIZE];
    let mut rest = payload;
    loop {
        if rest.is_empty() {
            // A message can't end without a marked chunk.
            bail!("unexpected EOF");
        }
        let n = rest.len().min(ENC_CHUNK_SIZE);
        let (chunk, tail) = rest.split_at(n);
        let mut last = n < ENC_CHUNK_SIZE;
        if last && !nonce_is_zero(&nonce) && n == AEAD_OVERHEAD {
            bail!("last chunk is empty, try age v1.0.0, and please consider reporting this");
        }
        if last {
            set_last_chunk_flag(&mut nonce);
        }
        let plaintext = if let Ok(plaintext) = aead.decrypt(&Nonce::from(nonce), chunk) {
            plaintext
        } else {
            if last {
                bail!("failed to decrypt and authenticate payload chunk, file may be corrupted or tampered with");
            }
            // This was a full-length final chunk.
            last = true;
            set_last_chunk_flag(&mut nonce);
            match aead.decrypt(&Nonce::from(nonce), chunk) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    bail!("failed to decrypt and authenticate payload chunk, file may be corrupted or tampered with")
                }
            }
        };
        inc_nonce(&mut nonce)?;
        out.extend_from_slice(&plaintext);
        if last {
            if !tail.is_empty() {
                bail!("trailing data after end of encrypted file");
            }
            return Ok(out);
        }
        rest = tail;
    }
}

fn inc_nonce(nonce: &mut [u8; AEAD_NONCE_SIZE]) -> Result<()> {
    // The last byte carries the last-chunk flag, not the counter.
    let (counter, _flag) = nonce.split_at_mut(AEAD_NONCE_SIZE - 1);
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return Ok(());
        }
    }
    // An 88-bit counter cannot wrap around.
    bail!("stream: chunk counter wrapped around")
}

const fn set_last_chunk_flag(nonce: &mut [u8; AEAD_NONCE_SIZE]) {
    nonce[AEAD_NONCE_SIZE - 1] = LAST_CHUNK_FLAG;
}

fn nonce_is_zero(nonce: &[u8; AEAD_NONCE_SIZE]) -> bool {
    *nonce == [0u8; AEAD_NONCE_SIZE]
}

fn encode_string(data: &[u8]) -> String {
    STANDARD_NO_PAD.encode(data)
}

fn decode_string(s: &str) -> Result<Vec<u8>> {
    // CR and LF are ignored by DecodeString, but we don't want any malleability.
    if s.contains(['\n', '\r']) {
        bail!("unexpected newline character");
    }
    Ok(STANDARD_NO_PAD.decode(s)?)
}

fn wrap_base64(encoded: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(encoded.len() + encoded.len() / COLUMNS_PER_LINE + 1);
    let mut written = 0;
    for byte in encoded {
        out.push(*byte);
        written += 1;
        if written % COLUMNS_PER_LINE == 0 {
            out.push(b'\n');
        }
    }
    (out, written % COLUMNS_PER_LINE == 0)
}

fn marshal_stanza(stanza: &Stanza, out: &mut Vec<u8>) {
    out.extend_from_slice(STANZA_PREFIX.as_bytes());
    out.push(b' ');
    out.extend_from_slice(stanza.type_.as_bytes());
    for arg in &stanza.args {
        out.push(b' ');
        out.extend_from_slice(arg.as_bytes());
    }
    out.push(b'\n');
    let (wrapped, _) = wrap_base64(encode_string(&stanza.body).as_bytes());
    out.extend_from_slice(&wrapped);
    out.push(b'\n');
}

fn marshal_header_without_mac(header: &Header) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(INTRO.as_bytes());
    for recipient in &header.recipients {
        marshal_stanza(recipient, &mut out);
    }
    out.extend_from_slice(FOOTER_PREFIX.as_bytes());
    out
}

fn marshal_header(header: &Header) -> Vec<u8> {
    let mut out = marshal_header_without_mac(header);
    out.push(b' ');
    out.extend_from_slice(encode_string(&header.mac).as_bytes());
    out.push(b'\n');
    out
}

struct LineReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> LineReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        LineReader { data, offset: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        let data: &'a [u8] = self.data;
        data.get(self.offset..).unwrap_or_default()
    }

    /// Reads up to and including the newline; the flag reports whether the input was exhausted
    /// without one.
    fn read_until_newline(&mut self) -> (Vec<u8>, bool) {
        if let Some(i) = self.remaining().iter().position(|b| *b == b'\n') {
            let (line, _) = self.remaining().split_at(i + 1);
            self.offset += i + 1;
            (line.to_vec(), false)
        } else {
            let line = self.remaining().to_vec();
            self.offset = self.data.len();
            (line, true)
        }
    }
}

fn parse(data: &[u8]) -> Result<(Header, &[u8])> {
    let mut reader = LineReader::new(data);

    let (line, eof) = reader.read_until_newline();
    if eof {
        return Err(parse_error("file is empty"));
    }
    if line != INTRO.as_bytes() {
        return Err(parse_error(&format!("unexpected intro: {:?}", String::from_utf8_lossy(&line))));
    }

    let mut header = Header::default();
    loop {
        if reader.remaining().len() < FOOTER_PREFIX.len() {
            bail!("failed to read header: EOF");
        }
        if reader.remaining().starts_with(FOOTER_PREFIX.as_bytes()) {
            let (line, _) = reader.read_until_newline();
            let (prefix, args) = split_args(&line);
            if prefix != FOOTER_PREFIX {
                return Err(parse_error(&format!("malformed closing line: {:?}", String::from_utf8_lossy(&line))));
            }
            let [arg] = args.as_slice() else {
                return Err(parse_error(&format!("malformed closing line: {:?}", String::from_utf8_lossy(&line))));
            };
            let mac = decode_string(arg);
            match mac {
                Ok(mac) if mac.len() == 32 => header.mac = mac,
                Ok(_) => {
                    return Err(parse_error(&format!(
                        "malformed closing line {:?}: <nil>",
                        String::from_utf8_lossy(&line)
                    )))
                }
                Err(err) => {
                    return Err(parse_error(&format!(
                        "malformed closing line {:?}: {err}",
                        String::from_utf8_lossy(&line)
                    )))
                }
            }
            break;
        }

        let stanza = read_stanza(&mut reader).map_err(|err| anyhow!("failed to parse header: {err}"))?;
        header.recipients.push(stanza);
    }

    Ok((header, reader.remaining()))
}

fn read_stanza(reader: &mut LineReader<'_>) -> Result<Stanza> {
    let (line, _) = reader.read_until_newline();
    if !line.starts_with(STANZA_PREFIX.as_bytes()) {
        return Err(parse_error(&format!("malformed stanza opening line: {:?}", String::from_utf8_lossy(&line))));
    }
    let (prefix, args) = split_args(&line);
    if prefix != STANZA_PREFIX {
        return Err(parse_error(&format!("malformed stanza: {:?}", String::from_utf8_lossy(&line))));
    }
    let Some((stanza_type, rest)) = args.split_first() else {
        return Err(parse_error(&format!("malformed stanza: {:?}", String::from_utf8_lossy(&line))));
    };
    for arg in &args {
        if !is_valid_string(arg) {
            return Err(parse_error(&format!("malformed stanza: {:?}", String::from_utf8_lossy(&line))));
        }
    }

    let mut stanza = Stanza { type_: stanza_type.clone(), args: rest.to_vec(), body: Vec::new() };
    loop {
        let (line, _) = reader.read_until_newline();
        let body_line = strip_suffix_newline(&line);
        match decode_string(&String::from_utf8_lossy(body_line)) {
            Ok(body) => {
                if body.len() > BYTES_PER_LINE {
                    return Err(parse_error(&format!(
                        "malformed body line {:?}: too long",
                        String::from_utf8_lossy(&line)
                    )));
                }
                stanza.body.extend_from_slice(&body);
                if body.len() < BYTES_PER_LINE {
                    // A stanza body always ends with a short line.
                    return Ok(stanza);
                }
            }
            Err(err) => {
                if line.starts_with(FOOTER_PREFIX.as_bytes()) || line.starts_with(STANZA_PREFIX.as_bytes()) {
                    return Err(parse_error(&format!(
                        "malformed body line {:?}: stanza ended without a short line\nnote: this might be a file encrypted with an old beta version of age or rage; use age v1.0.0-beta6 or rage to decrypt it",
                        String::from_utf8_lossy(&line)
                    )));
                }
                return Err(parse_error(&format!("malformed body line {:?}: {err}", String::from_utf8_lossy(&line))));
            }
        }
    }
}

fn parse_error(msg: &str) -> anyhow::Error {
    anyhow!("parsing age header: {msg}")
}

fn split_args(line: &[u8]) -> (String, Vec<String>) {
    let line = String::from_utf8_lossy(strip_suffix_newline(line)).into_owned();
    let mut parts = line.split(' ');
    let prefix = parts.next().unwrap_or_default().to_owned();
    (prefix, parts.map(str::to_owned).collect())
}

fn is_valid_string(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.chars().all(|c| ('!'..='~').contains(&c))
}

const fn strip_suffix_newline(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\n', rest)) => rest,
        _ => line,
    }
}

const fn strip_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\r', rest)) => rest,
        _ => line,
    }
}

// ---------- x25519 ----------

impl fmt::Debug for X25519Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519Identity").finish_non_exhaustive()
    }
}

pub struct X25519Identity {
    secret_key: [u8; 32],
    our_public_key: [u8; 32],
}

impl X25519Identity {
    fn new_from_scalar(secret_key: [u8; 32]) -> Self {
        let our_public_key = x25519(secret_key, X25519_BASEPOINT_BYTES);
        Self { secret_key, our_public_key }
    }

    #[must_use]
    pub const fn recipient(&self) -> X25519Recipient {
        X25519Recipient { their_public_key: self.our_public_key }
    }

    #[must_use]
    pub fn string(&self) -> String {
        bech32_encode("AGE-SECRET-KEY-", &self.secret_key).unwrap_or_default().to_uppercase()
    }

    fn unwrap_stanza(&self, block: &Stanza) -> Result<Vec<u8>, UnwrapError> {
        if block.type_ != "X25519" {
            return Err(UnwrapError::IncorrectIdentity);
        }
        let [arg] = block.args.as_slice() else {
            return Err(anyhow!("invalid X25519 recipient block").into());
        };
        let public_key = decode_string(arg).map_err(|err| anyhow!("failed to parse X25519 recipient: {err}"))?;
        let public_key: [u8; 32] =
            public_key.as_slice().try_into().map_err(|_| anyhow!("invalid X25519 recipient block"))?;

        let shared_secret =
            x25519_shared(&self.secret_key, &public_key).map_err(|err| anyhow!("invalid X25519 recipient: {err}"))?;

        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(&public_key);
        salt.extend_from_slice(&self.our_public_key);
        let wrapping_key = hkdf_sha256(&shared_secret, Some(&salt), X25519_LABEL.as_bytes(), 32)?;

        match aead_decrypt(&wrapping_key, FILE_KEY_SIZE, &block.body) {
            Ok(file_key) => Ok(file_key),
            Err(AeadDecryptError::IncorrectCiphertextSize) => {
                Err(anyhow!("invalid X25519 recipient block: incorrect file key size").into())
            }
            Err(AeadDecryptError::Other(_)) => Err(UnwrapError::IncorrectIdentity),
        }
    }
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<Vec<u8>, UnwrapError> {
        multi_unwrap(&|block| self.unwrap_stanza(block), stanzas)
    }
}

impl fmt::Display for X25519Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

#[must_use]
pub fn generate_x25519_identity() -> X25519Identity {
    let mut secret_key = [0u8; 32];
    rand::rng().fill(&mut secret_key[..]);
    X25519Identity::new_from_scalar(secret_key)
}

pub fn parse_x25519_identity(s: &str) -> Result<X25519Identity> {
    let (t, k) = bech32_decode(s).map_err(|err| anyhow!("malformed secret key: {err}"))?;
    if t != "AGE-SECRET-KEY-" {
        bail!("malformed secret key: unknown type {t:?}");
    }
    if k.len() != 32 {
        bail!("malformed secret key: invalid X25519 secret key");
    }
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&k);
    Ok(X25519Identity::new_from_scalar(secret_key))
}

#[derive(Debug)]
pub struct X25519Recipient {
    their_public_key: [u8; 32],
}

impl X25519Recipient {
    const fn new_from_point(public_key: [u8; 32]) -> Self {
        Self { their_public_key: public_key }
    }

    #[must_use]
    pub fn string(&self) -> String {
        bech32_encode("age", &self.their_public_key).unwrap_or_default()
    }

    fn wrap_stanzas(&self, file_key: &[u8]) -> Result<Vec<Stanza>> {
        let mut ephemeral = [0u8; 32];
        rand::rng().fill(&mut ephemeral[..]);
        let our_public_key = x25519_shared(&ephemeral, &X25519_BASEPOINT_BYTES)?;
        let shared_secret = x25519_shared(&ephemeral, &self.their_public_key)?;

        let mut stanza =
            Stanza { type_: "X25519".to_owned(), args: vec![encode_string(&our_public_key)], body: Vec::new() };

        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(&our_public_key);
        salt.extend_from_slice(&self.their_public_key);
        let wrapping_key = hkdf_sha256(&shared_secret, Some(&salt), X25519_LABEL.as_bytes(), 32)?;

        stanza.body = aead_encrypt(&wrapping_key, file_key)?;
        Ok(vec![stanza])
    }
}

impl Recipient for X25519Recipient {
    fn wrap(&self, file_key: &[u8]) -> Result<Vec<Stanza>> {
        self.wrap_stanzas(file_key)
    }

    fn string(&self) -> String {
        Self::string(self)
    }
}

impl fmt::Display for X25519Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&Self::string(self))
    }
}

pub fn parse_x25519_recipient(s: &str) -> Result<X25519Recipient> {
    let (t, k) = bech32_decode(s).map_err(|err| anyhow!("malformed recipient {s:?}: {err}"))?;
    if t != "age" {
        bail!("malformed recipient {s:?}: invalid type {t:?}");
    }
    if k.len() != 32 {
        bail!("malformed recipient {s:?}: invalid X25519 public key");
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&k);
    Ok(X25519Recipient::new_from_point(public_key))
}

fn x25519_shared(scalar: &[u8; 32], point: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = x25519(*scalar, *point);
    if shared.iter().all(|byte| *byte == 0) {
        bail!("bad X25519 remote ECDH input: low order point");
    }
    Ok(shared)
}

// ---------- ML-KEM hybrid ----------

impl fmt::Debug for HybridIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridIdentity").finish_non_exhaustive()
    }
}

pub struct HybridIdentity {
    secret_key: Vec<u8>,
}

impl HybridIdentity {
    pub fn recipient(&self) -> Result<HybridRecipient> {
        Err(hybrid_unavailable())
    }

    #[must_use]
    pub fn string(&self) -> String {
        bech32_encode("AGE-SECRET-KEY-PQ-", &self.secret_key).unwrap_or_default().to_uppercase()
    }
}

impl fmt::Display for HybridIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

pub fn generate_hybrid_identity() -> Result<HybridIdentity> {
    // Unimplemented: a hybrid identity would expand a random 32-byte seed with ML-KEM-768 and
    // X25519.
    Err(hybrid_unavailable())
}

pub fn parse_hybrid_identity(s: &str) -> Result<HybridIdentity> {
    let (t, k) = bech32_decode(s).map_err(|err| anyhow!("malformed secret key: {err}"))?;
    if t != "AGE-SECRET-KEY-PQ-" {
        bail!("malformed secret key: unknown type {t:?}");
    }
    if k.len() != HYBRID_SECRET_KEY_SIZE {
        bail!("malformed secret key: invalid MLKEM768-X25519 secret key");
    }
    Ok(HybridIdentity { secret_key: k })
}

#[derive(Debug)]
pub struct HybridRecipient {
    public_key: Vec<u8>,
}

impl HybridRecipient {
    #[must_use]
    pub fn string(&self) -> String {
        bech32_encode("age1pq", &self.public_key).unwrap_or_default()
    }
}

impl Recipient for HybridRecipient {
    fn wrap(&self, _file_key: &[u8]) -> Result<Vec<Stanza>> {
        Err(hybrid_unavailable())
    }

    fn wrap_with_labels(&self, _file_key: &[u8]) -> Result<(Vec<Stanza>, Vec<String>)> {
        Err(hybrid_unavailable())
    }

    fn string(&self) -> String {
        Self::string(self)
    }
}

impl fmt::Display for HybridRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&Self::string(self))
    }
}

pub fn parse_hybrid_recipient(s: &str) -> Result<HybridRecipient> {
    let (t, k) = bech32_decode(s).map_err(|err| anyhow!("malformed recipient {s:?}: {err}"))?;
    if t != "age1pq" {
        bail!("malformed recipient {s:?}: invalid type {t:?}");
    }
    if k.len() != HYBRID_PUBLIC_KEY_SIZE {
        bail!("malformed recipient {s:?}: invalid MLKEM768-X25519 public key");
    }
    Ok(HybridRecipient { public_key: k })
}

fn hybrid_unavailable() -> anyhow::Error {
    anyhow!(
        "mlkem768x25519 ({HYBRID_LABEL}) needs an ML-KEM-768 implementation, which the pinned dependencies do not provide"
    )
}

// ---------- bech32 ----------

const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ u32::from(*v);
        for (i, generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let h = hrp.to_lowercase().into_bytes();
    let mut ret = Vec::with_capacity(h.len() * 2 + 1);
    for c in &h {
        ret.push(c >> 5);
    }
    ret.push(0);
    for c in &h {
        ret.push(c & 31);
    }
    ret
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == 1
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "a bech32 checksum symbol is 5 bits by definition; the mask bounds the value"
)]
fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let mod_ = polymod(&values) ^ 1;
    let mut ret = [0u8; 6];
    for (p, out) in ret.iter_mut().enumerate() {
        let shift = 5 * (5 - p);
        *out = (mod_ >> shift) as u8 & 31;
    }
    ret
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "a bech32 group is at most 8 bits by definition; the mask bounds the value"
)]
fn convert_bits(data: &[u8], from_bits: u8, to_bits: u8, pad: bool) -> Result<Vec<u8>> {
    let mut ret = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    let maxv: u8 = ((1u32 << to_bits) - 1) as u8;
    for (idx, value) in data.iter().enumerate() {
        if u32::from(*value) >> from_bits != 0 {
            bail!("invalid data range: data[{idx}]={value} (frombits={from_bits})");
        }
        acc = acc << from_bits | u32::from(*value);
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push((acc >> bits) as u8 & maxv);
        }
    }
    if pad {
        if bits > 0 {
            ret.push((acc << (to_bits - bits)) as u8 & maxv);
        }
    } else if bits >= from_bits {
        bail!("illegal zero padding");
    } else if (acc << (to_bits - bits)) as u8 & maxv != 0 {
        bail!("non-zero padding");
    }
    Ok(ret)
}

fn charset_char(value: u8) -> Result<char> {
    let Some(c) = CHARSET.as_bytes().get(usize::from(value)) else {
        bail!("invalid data value: {value}");
    };
    Ok(*c as char)
}

fn bech32_encode(hrp: &str, data: &[u8]) -> Result<String> {
    let values = convert_bits(data, 8, 5, true)?;
    if hrp.is_empty() {
        bail!("invalid HRP: {hrp:?}");
    }
    for (p, c) in hrp.char_indices() {
        if !('!'..='~').contains(&c) {
            bail!("invalid HRP character: hrp[{p}]={}", c as u32);
        }
    }
    if hrp.to_uppercase() != hrp && hrp.to_lowercase() != hrp {
        bail!("mixed case HRP: {hrp:?}");
    }
    let lower = hrp.to_lowercase() == hrp;
    let hrp = hrp.to_lowercase();
    let checksum = create_checksum(&hrp, &values);
    let mut ret = String::new();
    ret.push_str(&hrp);
    ret.push('1');
    for value in values.iter().copied().chain(checksum) {
        ret.push(charset_char(value)?);
    }
    if lower {
        return Ok(ret);
    }
    Ok(ret.to_uppercase())
}

fn bech32_decode(s: &str) -> Result<(String, Vec<u8>)> {
    if s.to_lowercase() != s && s.to_uppercase() != s {
        bail!("mixed case");
    }
    let pos = s.rfind('1').unwrap_or(0);
    if pos < 1 || pos + 7 > s.len() {
        bail!("separator '1' at invalid position: pos={pos}, len={}", s.len());
    }
    let Some(hrp) = s.get(..pos) else {
        bail!("separator '1' at invalid position: pos={pos}, len={}", s.len());
    };
    for (p, c) in hrp.char_indices() {
        if !('!'..='~').contains(&c) {
            bail!("invalid character human-readable part: s[{p}]={}", c as u32);
        }
    }
    let lower = s.to_lowercase();
    let Some(data_part) = lower.get(pos + 1..) else {
        bail!("separator '1' at invalid position: pos={pos}, len={}", lower.len());
    };
    let mut data = Vec::new();
    for (p, c) in data_part.char_indices() {
        let Some(d) = CHARSET.find(c) else {
            bail!("invalid character data part: s[{p}]={c}");
        };
        #[expect(clippy::cast_possible_truncation, reason = "the bech32 alphabet has 32 entries")]
        data.push(d as u8);
    }
    if !verify_checksum(hrp, &data) {
        bail!("invalid checksum");
    }
    let Some(data_len) = data.len().checked_sub(6) else {
        bail!("invalid checksum");
    };
    let (data, _checksum) = data.split_at(data_len);
    let data = convert_bits(data, 5, 8, false)?;
    Ok((hrp.to_owned(), data))
}

// ---------- armor ----------

const ARMOR_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const ARMOR_FOOTER: &str = "-----END AGE ENCRYPTED FILE-----";
const MAX_WHITESPACE: usize = 1024;

fn armor_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ARMOR_HEADER.as_bytes());
    out.push(b'\n');
    let (wrapped, last_line_empty) = wrap_base64(STANDARD.encode(data).as_bytes());
    out.extend_from_slice(&wrapped);
    if !last_line_empty {
        out.push(b'\n');
    }
    out.extend_from_slice(ARMOR_FOOTER.as_bytes());
    out.push(b'\n');
    out
}

fn armor_decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut lines = ArmorLines { data, offset: 0 };

    let mut removed_whitespace = 0;
    loop {
        let line = lines.get_line()?;
        // Ignore leading whitespace.
        if line.iter().all(|byte| is_space(*byte)) {
            removed_whitespace += line.len() + 1;
            if removed_whitespace > MAX_WHITESPACE {
                bail!("invalid armor: too much leading whitespace");
            }
            continue;
        }
        if line != ARMOR_HEADER.as_bytes() {
            bail!("invalid armor: invalid first line: {:?}", String::from_utf8_lossy(&line));
        }
        break;
    }

    let mut decoded = Vec::new();
    let mut line = lines.get_line()?;
    loop {
        if line == ARMOR_FOOTER.as_bytes() {
            lines.drain_trailing()?;
            return Ok(decoded);
        }
        if line.is_empty() {
            bail!("invalid armor: empty line in armored data");
        }
        if line.len() > COLUMNS_PER_LINE {
            bail!("invalid armor: column limit exceeded");
        }
        let chunk = STANDARD.decode(&line).map_err(|err| anyhow!("invalid armor: {err}"))?;
        decoded.extend_from_slice(&chunk);
        if chunk.len() < BYTES_PER_LINE {
            let line = lines.get_line()?;
            if line != ARMOR_FOOTER.as_bytes() {
                bail!("invalid armor: invalid closing line: {:?}", String::from_utf8_lossy(&line));
            }
            lines.drain_trailing()?;
            return Ok(decoded);
        }
        line = lines.get_line()?;
    }
}

struct ArmorLines<'a> {
    data: &'a [u8],
    offset: usize,
}

impl ArmorLines<'_> {
    fn get_line(&mut self) -> Result<Vec<u8>> {
        if self.offset >= self.data.len() {
            bail!("invalid armor: unexpected EOF");
        }
        let rest = self.data.get(self.offset..).unwrap_or_default();
        let mut line = if let Some(i) = rest.iter().position(|b| *b == b'\n') {
            self.offset += i + 1;
            let (line, _) = rest.split_at(i);
            line.to_vec()
        } else {
            self.offset = self.data.len();
            rest.to_vec()
        };
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(line)
    }

    fn drain_trailing(&mut self) -> Result<()> {
        let rest = self.data.get(self.offset..).unwrap_or_default();
        let buf = rest.get(..MAX_WHITESPACE).unwrap_or(rest);
        self.offset += buf.len();
        if buf.iter().any(|byte| !is_space(*byte)) {
            bail!("invalid armor: trailing data after armored file");
        }
        if buf.len() == MAX_WHITESPACE {
            bail!("invalid armor: too much trailing whitespace");
        }
        Ok(())
    }
}

/// Whether the byte is ASCII whitespace.
const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | b'\x0c' | b'\r')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_age() {
        let (secret_key, public_key) = gen_x25519_key_pair().unwrap();
        let public_keys = to_public_keys(std::slice::from_ref(&secret_key)).unwrap();
        assert_eq!(public_keys.len(), 1);
        assert_eq!(public_keys[0], public_key);

        let raw_data = b"hello world";
        let encrypt_data = encrypt_bytes(raw_data, &[public_key]).unwrap();
        let decrypt_data = decrypt_bytes(&encrypt_data, std::slice::from_ref(&secret_key)).unwrap();
        assert_eq!(decrypt_data, raw_data);
    }

    /// `testdata/example.age` of the age repository with its `example_keys.txt` secret key.
    #[test]
    fn test_age_cli_vector() {
        const EXAMPLE_AGE: &str = concat!(
            "6167652d656e6372797074696f6e2e6f72672f76310a2d3e20583235353139203868726c4d2b5a424733446434664632",
            "2b613538337a64544957446b382f5234316b43595a7376775457340a794f345059646c4d57444a2b437867554e527159",
            "355a30542f6d2b6733464368356a4978474c62435658630a2d2d2d20492f696d65765a7a79383132304a537a6d4a6e6d",
            "6e2f4b4d6b3370354131315638334e6b34316d394e50450a70c5e53624a1520753f92c5ad10ecab273ba4d6117807713",
            "e83820417a1df2ca08182272c8f85c857734a1311a3b75e98d0eaf"
        );
        const SECRET_KEY: &str = "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU";

        let data = hex::decode(EXAMPLE_AGE).unwrap();
        let identities: Vec<Identity> = vec![Identity::X25519(parse_x25519_identity(SECRET_KEY).unwrap())];
        assert_eq!(decrypt(&data, &identities).unwrap(), b"Black lives matter.");

        let armored = armor_encode(&data);
        assert_eq!(decrypt_bytes(&armored, &[SECRET_KEY.to_owned()]).unwrap(), b"Black lives matter.");
    }

    #[test]
    fn test_age_payload_chunks() {
        let (secret_key, public_key) = gen_x25519_key_pair().unwrap();
        for len in [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, CHUNK_SIZE * 2, CHUNK_SIZE * 3 + 5] {
            let raw_data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let encrypted = encrypt_bytes(&raw_data, std::slice::from_ref(&public_key)).unwrap();
            let decrypted = decrypt_bytes(&encrypted, std::slice::from_ref(&secret_key)).unwrap();
            assert_eq!(decrypted, raw_data, "plaintext length {len}");

            let (other_secret_key, _) = gen_x25519_key_pair().unwrap();
            assert!(decrypt_bytes(&encrypted, &[other_secret_key]).is_err());
        }
    }

    #[test]
    fn test_age_armor_and_plain_passthrough() {
        let (secret_key, public_key) = gen_x25519_key_pair().unwrap();
        let encrypted = encrypt_bytes(b"armored", &[public_key]).unwrap();
        assert!(encrypted.starts_with(FILE_HEADER.as_bytes()));
        assert_eq!(decrypt_bytes(&encrypted, &[secret_key]).unwrap(), b"armored".to_vec());

        let not_armored = b"age-secret-key: plain config";
        assert_eq!(decrypt_bytes(not_armored, &[]).unwrap(), not_armored.to_vec());
    }

    #[test]
    fn test_key_pair_round_trip() {
        let (secret_key, public_key) = gen_x25519_key_pair().unwrap();
        verity_secret_keys(std::slice::from_ref(&secret_key)).unwrap();
        verity_public_keys(std::slice::from_ref(&public_key)).unwrap();
        assert_eq!(to_public_keys(&[secret_key]).unwrap(), vec![public_key]);

        let secret_keys = vec!["AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU".to_owned()];
        assert_eq!(
            to_public_keys(&secret_keys).unwrap(),
            vec!["age1cy0su9fwf3gf9mw868g5yut09p6nytfmmnktexz2ya5uqg9vl9sss4euqm".to_owned()]
        );
    }

    #[test]
    fn test_bech32() {
        let (secret_key, public_key) = gen_x25519_key_pair().unwrap();
        assert_eq!(parse_x25519_identity(&secret_key).unwrap().string(), secret_key);
        assert_eq!(parse_x25519_recipient(&public_key).unwrap().string(), public_key);

        let hybrid_secret_key = gen_hybrid_key_pair();
        assert!(hybrid_secret_key.is_err());
    }
}
