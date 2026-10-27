use std::fmt;
use std::str::FromStr;

use anyhow::anyhow;
use md5::{Digest, Md5};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const MD5_SIZE: usize = 16;

/// Wraps the hash array inside the struct, so the algorithm can be swapped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HashType {
    md5: [u8; MD5_SIZE],
}

#[must_use]
pub fn make_hash(data: &[u8]) -> HashType {
    let mut md5 = [0u8; MD5_SIZE];
    md5.copy_from_slice(&Md5::digest(data));
    HashType { md5 }
}

impl HashType {
    #[must_use]
    pub fn equal(&self, hash: Self) -> bool {
        self.md5 == hash.md5
    }

    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        &self.md5
    }

    #[must_use]
    pub fn string(&self) -> String {
        hex::encode(self.md5)
    }

    pub fn marshal_text(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.string().into_bytes())
    }

    pub fn unmarshal_text(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.len() / 2 != MD5_SIZE {
            return Err(anyhow!("invalid hash length"));
        }
        hex::decode_to_slice(data, &mut self.md5)?;
        Ok(())
    }

    pub fn marshal_binary(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.md5.to_vec())
    }

    pub fn unmarshal_binary(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.len() != MD5_SIZE {
            return Err(anyhow!("invalid hash length"));
        }
        self.md5.copy_from_slice(data);
        Ok(())
    }

    #[allow(clippy::len_without_is_empty, reason = "the HashType has no IsEmpty; the length is the fixed MD5 size")]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.md5.len()
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        *self != Self::default()
    }
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

impl FromStr for HashType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut hash = Self::default();
        hash.unmarshal_text(s.as_bytes())?;
        Ok(hash)
    }
}

impl Serialize for HashType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.string())
    }
}

impl<'de> Deserialize<'de> for HashType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let mut hash = Self::default();
        hash.unmarshal_text(s.as_bytes()).map_err(serde::de::Error::custom)?;
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_type() {
        let hash = make_hash(b"hello");
        assert_eq!(hash.string(), "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(hash.len(), MD5_SIZE);
        assert!(hash.is_valid());
        assert!(!HashType::default().is_valid());

        let parsed: HashType = hash.string().parse().unwrap();
        assert!(parsed.equal(hash));
        assert_eq!(parsed.bytes(), hash.bytes());
        assert!(HashType::default().unmarshal_text(b"5d41402a").is_err());
        assert!(HashType::default().unmarshal_text(b"zzzzzzzz").is_err());

        assert_eq!(serde_json::to_string(&hash).unwrap(), "\"5d41402abc4b2a76b9719d911017c592\"");
        assert_eq!(serde_json::from_str::<HashType>("\"5d41402abc4b2a76b9719d911017c592\"").unwrap(), hash);
    }
}
