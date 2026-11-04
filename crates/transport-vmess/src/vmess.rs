use std::collections::HashMap;
use std::sync::LazyLock;

use murmur_common::shared_conn::SharedConn as VmessSharedConn;
use murmur_common::utils::uuid::uuid_map;
use murmur_common_net::io::{OldConnAsStream, Stream, StreamAsOldConn};
use murmur_std_compat::net::Conn as NetConn;

use super::conn::new_conn;
use super::user::{new_alter_ids, new_id, Id};

pub const VERSION: u8 = 1;

/// The request option bits.
pub const OPTION_CHUNK_STREAM: u8 = 1;
pub const OPTION_CHUNK_MASKING: u8 = 4;

pub type Security = u8;

/// The cipher types.
pub const SECURITY_AES128GCM: Security = 3;
pub const SECURITY_CHACHA20POLY1305: Security = 4;
pub const SECURITY_NONE: Security = 5;

pub static CIPHER_MAPPING: LazyLock<HashMap<&'static str, u8>> = LazyLock::new(|| {
    HashMap::from([
        ("none", SECURITY_NONE),
        ("aes-128-gcm", SECURITY_AES128GCM),
        ("chacha20-poly1305", SECURITY_CHACHA20POLY1305),
    ])
});

/// The command types.
pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 2;

/// The address types.
pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN_NAME: u8 = 2;
pub const ATYP_IPV6: u8 = 3;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DstAddr {
    pub udp: bool,
    pub addr_type: u8,
    pub addr: Vec<u8>,
    pub port: u32,
}

#[derive(Debug, Clone)]
pub struct Client {
    pub(crate) user: Vec<Id>,
    pub(crate) security: Security,
    pub(crate) is_aead: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub uuid: String,
    pub alter_id: u16,
    pub security: String,
    pub port: String,
    pub host_name: String,
    pub is_aead: bool,
}

impl Client {
    pub async fn stream_conn(&self, conn: Box<dyn NetConn>, dst: DstAddr) -> anyhow::Result<Box<dyn NetConn>> {
        let r = rand::Rng::random_range(&mut rand::rng(), 0..self.user.len());
        let user = self.user.get(r).ok_or_else(|| anyhow::anyhow!("user index out of range"))?.clone();
        let close_handle = VmessSharedConn::from_boxed(conn);
        let stream: Box<dyn Stream> = Box::new(OldConnAsStream(close_handle.clone()));
        let out = new_conn(stream, close_handle, user, dst, self.security, self.is_aead).await?;
        Ok(Box::new(StreamAsOldConn::new(out)))
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "`new_client` is part of the crate's public API, so its by-value `Config` parameter stays as published"
)]
pub fn new_client(config: Config) -> anyhow::Result<Client> {
    let uid = uuid_map(&config.uuid);

    let security = match config.security.as_str() {
        "aes-128-gcm" => SECURITY_AES128GCM,
        "chacha20-poly1305" => SECURITY_CHACHA20POLY1305,
        "none" => SECURITY_NONE,
        "auto" => match std::env::consts::ARCH {
            "x86_64" | "s390x" | "aarch64" => SECURITY_AES128GCM,
            _ => SECURITY_CHACHA20POLY1305,
        },
        other => return Err(anyhow::anyhow!("unknown security type: {other}")),
    };

    Ok(Client { user: new_alter_ids(&new_id(&uid), config.alter_id), security, is_aead: config.is_aead })
}
