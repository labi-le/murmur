use std::sync::Arc;

use crate::tools::crypto::{hmac_md5, md5_sum};

use super::auth_aes128_sha1::{new_auth_aes128, AuthAES128Function};
use super::base::{AuthData, Base, UserData};
use super::protocol::{register, Protocol, ProtocolList};

/// the `init` registering `auth_aes128_md5`.
pub(crate) fn init(list: &mut ProtocolList) {
    register(list, "auth_aes128_md5", new_auth_aes128_md5, 9);
}

pub(crate) fn new_auth_aes128_md5(b: &Base) -> Box<dyn Protocol> {
    Box::new(new_auth_aes128(
        b,
        AuthData::default(),
        Arc::new(AuthAES128Function { salt: "auth_aes128_md5", hmac: hmac_md5, hash_digest: md5_sum }),
        UserData::default(),
    ))
}
