//! Reality configuration, merging the yaml-facing shape and the runtime `Config` into one struct.
//!
//! Every field is fully decoded (`PrivateKey` is `[u8; 32]`, `ShortID` a `HashSet<[u8; 8]>`),
//! since the decode happens once at config-parse time (`listener::parse::build_reality_config`)
//! rather than being deferred to listen-time.
//!
//! `limit-fallback-upload`/`limit-fallback-download` are carried here as
//! [`RealityLimitFallback`] and applied to the fallback relay by `murmur-reality`.

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The REALITY config, pre-decoded (see module doc).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RealityConfig {
    pub dest: String,
    pub private_key: [u8; 32],
    pub server_names: HashSet<String>,
    pub short_ids: HashSet<[u8; 8]>,
    pub max_time_diff: Option<Duration>,
    pub proxy: String,
    #[serde(default)]
    pub limit_fallback_upload: RealityLimitFallback,
    #[serde(default)]
    pub limit_fallback_download: RealityLimitFallback,
}

/// The fallback rate limit: the first `after_bytes` of a fallback relay are free.
///
/// The rest are metered at `bytes_per_sec` with a `burst_bytes_per_sec` allowance. A zero rate
/// disables the limit.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct RealityLimitFallback {
    pub after_bytes: u64,
    pub bytes_per_sec: u64,
    pub burst_bytes_per_sec: u64,
}
