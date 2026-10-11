use md5::{Digest, Md5};
use rand::Rng;
use sha1::Sha1;
use uuid::{Builder, Uuid};

/// Returns a UUID based on the MD5 hash of the namespace UUID and name.
#[must_use]
pub fn new_uuid_v3(ns: Uuid, name: &str) -> Uuid {
    let mut h = Md5::new();
    h.update(ns.as_bytes());
    h.update(name.as_bytes());
    let digest: [u8; 16] = h.finalize().into();
    Builder::from_md5_bytes(digest).into_uuid()
}

/// Returns a new version 4 UUID, containing 122 bits of random data.
#[must_use]
pub fn new_uuid_v4() -> Uuid {
    let mut u = [0u8; 16];
    rand::rng().fill(&mut u);
    Builder::from_random_bytes(u).into_uuid()
}

/// Returns a UUID based on the SHA-1 hash of the namespace UUID and name.
#[must_use]
pub fn new_uuid_v5(ns: Uuid, name: &str) -> Uuid {
    let mut h = Sha1::new();
    h.update(ns.as_bytes());
    h.update(name.as_bytes());
    let digest = h.finalize();
    let u: [u8; 16] = digest.as_slice().first_chunk::<16>().copied().unwrap_or_default();
    Builder::from_sha1_bytes(u).into_uuid()
}

#[must_use]
pub fn uuid_map(str: &str) -> Uuid {
    Uuid::parse_str(str).unwrap_or_else(|_| new_uuid_v5(Uuid::nil(), str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_map() {
        let tests = [
            ("82410302-039e-41b6-98b0-d964084b4170", "82410302-039e-41b6-98b0-d964084b4170"),
            ("88c502e6-d7eb-4c8e-8259-94cb13d83c77", "88c502e6-d7eb-4c8e-8259-94cb13d83c77"),
            ("123456", "f8598425-92f2-5508-a071-4fc67f9040ac"),
            ("a9dk23bz0", "c91481b6-fc0f-5d9e-b166-5ddf07b9c3c5"),
            ("中文123", "145c544c-2229-59e5-8dbb-3f33b7610d26"),
        ];
        for (str, want) in tests {
            let got = uuid_map(str);
            assert_eq!(got, Uuid::parse_str(want).unwrap(), "UUIDMap({str})");
        }
    }
}
