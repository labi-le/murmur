//! The KCP and smux layers this crate is built on are workspace crates, re-exported here as
//! [`kcp`] (`murmur-kcp`) and [`smux`] (`murmur-smux`).

use std::sync::Arc;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use serde::{Deserialize, Serialize};
use sha1::Sha1;

use murmur_log::{errorln, warnln};

/// `SALT` is use for pbkdf2 key expansion.
pub const SALT: &str = "kcp-go";

/// maximum supported smux version
pub(crate) const MAX_SMUX_VER: i32 = 2;

/// scavenger check period, in seconds
pub(crate) const SCAVENGE_PERIOD: u64 = 5;

/// PBKDF2 key derivation with HMAC-SHA1 as the PRF.
#[expect(
    clippy::expect_used,
    reason = "PBKDF2 only rejects an output past (2^32 - 1) HMAC-SHA1 blocks; the derived key is 32 bytes"
)]
pub(crate) fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::<Hmac<Sha1>>(password, salt, iterations, out).expect("HMAC can be initialized with any key length");
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "crypt")]
    pub crypt: String,
    #[serde(rename = "mode")]
    pub mode: String,
    #[serde(rename = "conn")]
    pub conn: i32,
    #[serde(rename = "autoexpire")]
    pub auto_expire: i32,
    #[serde(rename = "scavengettl")]
    pub scavenge_ttl: i32,
    #[serde(rename = "mtu")]
    pub mtu: i32,
    #[serde(rename = "ratelimit")]
    pub rate_limit: i32,
    #[serde(rename = "sndwnd")]
    pub snd_wnd: i32,
    #[serde(rename = "rcvwnd")]
    pub rcv_wnd: i32,
    #[serde(rename = "datashard")]
    pub data_shard: i32,
    #[serde(rename = "parityshard")]
    pub parity_shard: i32,
    #[serde(rename = "dscp")]
    pub dscp: i32,
    #[serde(rename = "nocomp")]
    pub no_comp: bool,
    #[serde(rename = "acknodelay")]
    pub ack_nodelay: bool,
    #[serde(rename = "nodelay")]
    pub no_delay: i32,
    #[serde(rename = "interval")]
    pub interval: i32,
    #[serde(rename = "resend")]
    pub resend: i32,
    #[serde(rename = "nc")]
    pub no_congestion: i32,
    #[serde(rename = "sockbuf")]
    pub sock_buf: i32,
    #[serde(rename = "smuxver")]
    pub smux_ver: i32,
    #[serde(rename = "smuxbuf")]
    pub smux_buf: i32,
    #[serde(rename = "framesize")]
    pub frame_size: i32,
    #[serde(rename = "streambuf")]
    pub stream_buf: i32,
    #[serde(rename = "keepalive")]
    pub keep_alive: i32,
}

impl Config {
    pub fn fill_defaults(&mut self) {
        if self.key.is_empty() {
            "it's a secrect".clone_into(&mut self.key);
        }
        if self.crypt.is_empty() {
            "aes".clone_into(&mut self.crypt);
        }
        if self.mode.is_empty() {
            "fast".clone_into(&mut self.mode);
        }
        if self.conn == 0 {
            self.conn = 1;
        }
        if self.scavenge_ttl == 0 {
            self.scavenge_ttl = 600;
        }
        if self.mtu == 0 {
            self.mtu = 1350;
        }
        if self.snd_wnd == 0 {
            self.snd_wnd = 128;
        }
        if self.rcv_wnd == 0 {
            self.rcv_wnd = 512;
        }
        if self.data_shard == 0 {
            self.data_shard = 10;
        }
        if self.parity_shard == 0 {
            self.parity_shard = 3;
        }
        if self.interval == 0 {
            self.interval = 50;
        }
        if self.sock_buf == 0 {
            self.sock_buf = 4194304;
        }
        if self.smux_ver == 0 {
            self.smux_ver = 1;
        }
        if self.smux_buf == 0 {
            self.smux_buf = 4194304;
        }
        if self.frame_size == 0 {
            self.frame_size = 8192;
        }
        if self.stream_buf == 0 {
            self.stream_buf = 2097152;
        }
        if self.keep_alive == 0 {
            self.keep_alive = 10;
        }
        match self.mode.as_str() {
            "normal" => {
                (self.no_delay, self.interval, self.resend, self.no_congestion) = (0, 40, 2, 1);
            }
            "fast" => {
                (self.no_delay, self.interval, self.resend, self.no_congestion) = (0, 30, 2, 1);
            }
            "fast2" => {
                (self.no_delay, self.interval, self.resend, self.no_congestion) = (1, 20, 2, 1);
            }
            "fast3" => {
                (self.no_delay, self.interval, self.resend, self.no_congestion) = (1, 10, 2, 1);
            }
            _ => {}
        }

        if self.smux_ver > MAX_SMUX_VER {
            let version = self.smux_ver;
            warnln!("unsupported smux version: {version}");
            self.smux_ver = MAX_SMUX_VER;
        }

        if self.auto_expire != 0 && self.scavenge_ttl > self.auto_expire {
            warnln!("WARNING: scavengettl is bigger than autoexpire, connections may race hard to use bandwidth.");
            warnln!("Try limiting scavengettl to a smaller value.");
        }
    }

    pub fn new_block(&mut self) -> Option<Arc<dyn kcp::BlockCrypt>> {
        let mut pass = [0u8; 32];
        pbkdf2_sha1(self.key.as_bytes(), SALT.as_bytes(), 4096, &mut pass);
        match self.crypt.as_str() {
            "null" => None,
            "tea" => kcp::Tea::new_with_rounds(&pass[..16], 16)
                .ok()
                .map(|tea| -> Arc<dyn kcp::BlockCrypt> { Arc::new(kcp::BlockCrypt8::new(tea)) }),
            "xor" => Some(Arc::new(kcp::SimpleXorCrypt::new(&pass))),
            "none" => Some(Arc::new(kcp::NoneCrypt::new(&pass))),
            "aes-128" => kcp::AesCfbCrypt::<aes::Aes128>::new(&pass[..16])
                .ok()
                .map(|c| -> Arc<dyn kcp::BlockCrypt> { Arc::new(c) }),
            "aes-192" => kcp::AesCfbCrypt::<aes::Aes192>::new(&pass[..24])
                .ok()
                .map(|c| -> Arc<dyn kcp::BlockCrypt> { Arc::new(c) }),
            "blowfish" => {
                errorln!("kcptun: crypt \"blowfish\" is unavailable: crate blowfish is not a dependency, no encryption is used");
                None
            }
            "twofish" => {
                errorln!("kcptun: crypt \"twofish\" is unavailable: crate twofish is not a dependency, no encryption is used");
                None
            }
            "cast5" => {
                errorln!(
                    "kcptun: crypt \"cast5\" is unavailable: crate cast5 is not a dependency, no encryption is used"
                );
                None
            }
            "3des" => {
                errorln!("kcptun: crypt \"3des\" is unavailable: crate des is not a dependency, no encryption is used");
                None
            }
            "xtea" => kcp::Xtea::new(&pass[..16])
                .ok()
                .map(|xtea| -> Arc<dyn kcp::BlockCrypt> { Arc::new(kcp::BlockCrypt8::new(xtea)) }),
            "salsa20" => Some(Arc::new(kcp::Salsa20Crypt::new(&pass))),
            "aes-128-gcm" => {
                kcp::AesGcmCrypt::new(&pass[..16]).ok().map(|c| -> Arc<dyn kcp::BlockCrypt> { Arc::new(c) })
            }
            _ => {
                "aes".clone_into(&mut self.crypt);
                kcp::AesCfbCrypt::<aes::Aes256>::new(&pass).ok().map(|c| -> Arc<dyn kcp::BlockCrypt> { Arc::new(c) })
            }
        }
    }
}

/// The KCP transport, re-exported from `murmur-kcp`.
pub use murmur_kcp as kcp;

/// The smux session multiplexer, re-exported from `murmur-smux`.
pub use murmur_smux as smux;
