use std::collections::HashMap;
use std::sync::LazyLock;

use anyhow::{anyhow, Result};
use bytes::BytesMut;

use murmur_common_net::io::Stream;
use murmur_common_net::EnhancePacketConn;

use super::base::Base;
pub(crate) fn err_auth_sha1_v4_crc32_error() -> anyhow::Error {
    anyhow!("auth_sha1_v4 decode data wrong crc32")
}
pub(crate) fn err_auth_sha1_v4_length_error() -> anyhow::Error {
    anyhow!("auth_sha1_v4 decode data wrong length")
}
pub(crate) fn err_auth_sha1_v4_adler32_error() -> anyhow::Error {
    anyhow!("auth_sha1_v4 decode data wrong adler32")
}
pub(crate) fn err_auth_aes128_mac_error() -> anyhow::Error {
    anyhow!("auth_aes128 decode data wrong mac")
}
pub(crate) fn err_auth_aes128_length_error() -> anyhow::Error {
    anyhow!("auth_aes128 decode data wrong length")
}
pub(crate) fn err_auth_aes128_chksum_error() -> anyhow::Error {
    anyhow!("auth_aes128 decode data wrong checksum")
}
pub(crate) fn err_auth_chain_length_error() -> anyhow::Error {
    anyhow!("auth_chain decode data wrong length")
}
pub(crate) fn err_auth_chain_chksum_error() -> anyhow::Error {
    anyhow!("auth_chain decode data wrong checksum")
}

/// the `"ssr crashing blocked"` error, the workaround both `auth_chain` decoders share.
pub(crate) fn err_ssr_crashing_blocked() -> anyhow::Error {
    anyhow!("ssr crashing blocked")
}
pub trait Protocol: Send + Sync {
    fn stream_conn(&self, c: Box<dyn Stream>, iv: &[u8]) -> Box<dyn Stream>;

    fn packet_conn(&self, c: std::sync::Arc<dyn EnhancePacketConn>) -> std::sync::Arc<dyn EnhancePacketConn>;

    /// Decodes a packet: `src`'s read position and `dst`'s write position both advance.
    ///
    /// The `Protocol` value owns its decoder state (the raw transport buffer, the rolling hashes, the
    /// cipher streams), so the codec half takes `&mut self`; `stream_conn`/`packet_conn` stay
    /// `&self` because they only read the prototype.
    fn decode(&mut self, dst: &mut BytesMut, src: &mut BytesMut) -> Result<()>;

    fn encode(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()>;

    fn decode_packet(&mut self, b: &[u8]) -> Result<Vec<u8>>;

    fn encode_packet(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()>;
}
pub(crate) type ProtocolCreator = fn(&Base) -> Box<dyn Protocol>;

/// The registry entry for one protocol: its overhead and its constructor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProtocolEntry {
    pub(crate) overhead: i32,
    pub(crate) new: ProtocolCreator,
}

/// The map type of the protocol registry.
pub(crate) type ProtocolList = HashMap<String, ProtocolEntry>;

/// The protocol registry, filled by each module's `init`.
static PROTOCOL_LIST: LazyLock<ProtocolList> = LazyLock::new(|| {
    let mut list = ProtocolList::new();
    super::auth_aes128_md5::init(&mut list);
    super::auth_aes128_sha1::init(&mut list);
    super::auth_chain_a::init(&mut list);
    super::auth_chain_b::init(&mut list);
    super::auth_sha1_v4::init(&mut list);
    super::origin::init(&mut list);
    list
});

/// `register`; the registry is passed in rather than reached through a global.
pub(crate) fn register(list: &mut ProtocolList, name: &str, c: ProtocolCreator, o: i32) {
    list.insert(name.to_owned(), ProtocolEntry { overhead: o, new: c });
}

///
/// The overhead is folded into a copy of the `Base`, since the only caller builds that `Base` as a
/// temporary and never looks at it again.
///
/// # Errors
/// Returns an error when no protocol is registered under `name`.
pub fn pick_protocol(name: &str, b: &Base) -> Result<Box<dyn Protocol>> {
    let choice = PROTOCOL_LIST.get(name).copied();
    match choice {
        Some(choice) => {
            let mut base = b.clone();
            base.overhead += choice.overhead;
            Ok((choice.new)(&base))
        }
        None => Err(anyhow!("protocol {name} not supported")),
    }
}

pub(crate) fn get_head_size(b: &[u8], default_value: i32) -> i32 {
    let [head, next, ..] = b else {
        return default_value;
    };
    match head & 7 {
        1 => 7,
        4 => 19,
        3 => 4 + i32::from(*next),
        _ => default_value,
    }
}

pub(crate) fn get_data_length(b: &[u8]) -> i32 {
    let data_length = get_head_size(b, 30) + rand::random_range(0..32);
    let Ok(data_length_usize) = usize::try_from(data_length) else {
        return data_length;
    };
    if b.len() < data_length_usize {
        return i32::try_from(b.len()).unwrap_or(i32::MAX);
    }
    data_length
}
