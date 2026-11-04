//! The cursor methods this file uses have no crate equivalent in this workspace and are
//! implemented inline as `CryptobyteString`.

use anyhow::{anyhow, Result};

const EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ECHCipher {
    pub kdf_id: u16,
    pub aead_id: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ECHExtension {
    pub type_: u16,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ECHConfig {
    pub(crate) raw: Vec<u8>,

    pub version: u16,
    pub length: u16,

    pub config_id: u8,
    pub kem_id: u16,
    pub public_key: Vec<u8>,
    pub symmetric_cipher_suite: Vec<ECHCipher>,

    pub max_name_length: u8,
    pub public_name: Vec<u8>,
    pub extensions: Vec<ECHExtension>,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("tls: malformed ECHConfigList")]
pub struct ErrMalformedECHConfigList;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EchConfigErr {
    pub(crate) field: String,
}

impl EchConfigErr {
    fn new(field: &str) -> Self {
        Self { field: field.to_owned() }
    }
}

impl std::fmt::Display for EchConfigErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.field.is_empty() {
            return write!(f, "tls: malformed ECHConfig");
        }
        write!(f, "tls: malformed ECHConfig, invalid {} field", self.field)
    }
}

impl std::error::Error for EchConfigErr {}

struct CryptobyteString<'a> {
    s: &'a [u8],
}

impl<'a> CryptobyteString<'a> {
    const fn new(s: &'a [u8]) -> Self {
        CryptobyteString { s }
    }

    const fn empty(&self) -> bool {
        self.s.is_empty()
    }

    const fn rest(&self) -> &'a [u8] {
        self.s
    }

    fn skip(&mut self, n: usize) -> bool {
        let Some(rest) = self.s.get(n..) else {
            return false;
        };
        self.s = rest;
        true
    }

    fn read_uint8(&mut self) -> Option<u8> {
        let (&first, rest) = self.s.split_first()?;
        self.s = rest;
        Some(first)
    }

    fn read_uint16(&mut self) -> Option<u16> {
        let (&first, rest) = self.s.split_first()?;
        let (&second, rest) = rest.split_first()?;
        self.s = rest;
        Some(u16::from_be_bytes([first, second]))
    }

    fn read_uint8_length_prefixed(&mut self) -> Option<Self> {
        let length = self.read_uint8()? as usize;
        self.read_length_prefixed(length)
    }

    fn read_uint16_length_prefixed(&mut self) -> Option<Self> {
        let length = self.read_uint16()? as usize;
        self.read_length_prefixed(length)
    }

    fn read_length_prefixed(&mut self, length: usize) -> Option<Self> {
        if length > self.s.len() {
            return None;
        }
        let (out, rest) = self.s.split_at(length);
        self.s = rest;
        Some(CryptobyteString::new(out))
    }
}

pub fn parse_ech_config(enc: &[u8]) -> Result<(bool, ECHConfig)> {
    let mut s = CryptobyteString::new(enc);
    let mut ec = ECHConfig {
        raw: enc.to_vec(),
        version: 0,
        length: 0,
        config_id: 0,
        kem_id: 0,
        public_key: Vec::new(),
        symmetric_cipher_suite: Vec::new(),
        max_name_length: 0,
        public_name: Vec::new(),
        extensions: Vec::new(),
    };
    let Some(version) = s.read_uint16() else {
        return Err(EchConfigErr::new("version").into());
    };
    ec.version = version;
    let Some(length) = s.read_uint16() else {
        return Err(EchConfigErr::new("length").into());
    };
    ec.length = length;
    if ec.raw.len() < ec.length as usize + 4 {
        return Err(EchConfigErr::new("length").into());
    }
    ec.raw.truncate(ec.length as usize + 4);
    if ec.version != EXTENSION_ENCRYPTED_CLIENT_HELLO {
        s.skip(ec.length as usize);
        return Ok((true, ECHConfig::default()));
    }
    let Some(config_id) = s.read_uint8() else {
        return Err(EchConfigErr::new("config_id").into());
    };
    ec.config_id = config_id;
    let Some(kem_id) = s.read_uint16() else {
        return Err(EchConfigErr::new("kem_id").into());
    };
    ec.kem_id = kem_id;
    let Some(public_key) = s.read_uint16_length_prefixed() else {
        return Err(EchConfigErr::new("public_key").into());
    };
    ec.public_key = public_key.rest().to_vec();
    let Some(mut cipher_suites) = s.read_uint16_length_prefixed() else {
        return Err(EchConfigErr::new("cipher_suites").into());
    };
    while !cipher_suites.empty() {
        let Some(kdf_id) = cipher_suites.read_uint16() else {
            return Err(EchConfigErr::new("cipher_suites kdf_id").into());
        };
        let Some(aead_id) = cipher_suites.read_uint16() else {
            return Err(EchConfigErr::new("cipher_suites aead_id").into());
        };
        ec.symmetric_cipher_suite.push(ECHCipher { kdf_id, aead_id });
    }
    let Some(max_name_length) = s.read_uint8() else {
        return Err(EchConfigErr::new("maximum_name_length").into());
    };
    ec.max_name_length = max_name_length;
    let Some(public_name) = s.read_uint8_length_prefixed() else {
        return Err(EchConfigErr::new("public_name").into());
    };
    ec.public_name = public_name.rest().to_vec();
    let Some(mut extensions) = s.read_uint16_length_prefixed() else {
        return Err(EchConfigErr::new("extensions").into());
    };
    while !extensions.empty() {
        let Some(type_) = extensions.read_uint16() else {
            return Err(EchConfigErr::new("extensions type").into());
        };
        let Some(data) = extensions.read_uint16_length_prefixed() else {
            return Err(EchConfigErr::new("extensions data").into());
        };
        ec.extensions.push(ECHExtension { type_, data: data.rest().to_vec() });
    }

    Ok((false, ec))
}

/// Parses a draft-ietf-tls-esni-18 `ECHConfigList`, returning the parsed configs in the same
/// order they were parsed, or an error when the list is malformed.
pub fn parse_ech_config_list(data: &[u8]) -> Result<Vec<ECHConfig>> {
    let mut s = CryptobyteString::new(data);
    let Some(length) = s.read_uint16() else {
        return Err(ErrMalformedECHConfigList.into());
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the length is narrowed the same way, so a buffer past 64 KiB truncates instead of erroring"
    )]
    let expected = (data.len() - 2) as u16;
    if length != expected {
        return Err(ErrMalformedECHConfigList.into());
    }
    let mut configs: Vec<ECHConfig> = Vec::new();
    while !s.empty() {
        let [_, _, len_hi, len_lo, ..] = *s.rest() else {
            return Err(anyhow!("tls: malformed ECHConfig"));
        };
        let config_len = u16::from_be_bytes([len_hi, len_lo]);
        let (skip, ec) = parse_ech_config(s.rest())?;
        s.skip(config_len as usize + 4);
        if !skip {
            configs.push(ec);
        }
    }
    Ok(configs)
}
