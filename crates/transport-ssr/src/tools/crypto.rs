use hmac::{Hmac, KeyInit as _, Mac as _};
use md5::{Digest, Md5};
use sha1::Sha1;

/// The HMAC-SHA1 truncation length.
pub const HMAC_SHA1_LEN: usize = 10;

#[must_use]
#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length, so `new_from_slice` cannot fail")]
pub fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[must_use]
#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length, so `new_from_slice` cannot fail")]
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[must_use]
pub fn md5_sum(b: &[u8]) -> Vec<u8> {
    let mut h = Md5::new();
    h.update(b);
    h.finalize().to_vec()
}

#[must_use]
pub fn sha1_sum(b: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(b);
    h.finalize().to_vec()
}
