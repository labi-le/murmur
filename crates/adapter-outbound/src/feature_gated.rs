//! A node this build cannot construct because the Cargo feature that carries it is off.
//!
//! The provider layer separates this failure from every other parse error: a `file`/`http`
//! provider skips such a node and reports the skipped types once per pull, while a malformed
//! node or an unknown `type:` stays fatal. One typed error keeps that decision off the message
//! text.

use std::fmt;

/// The running build lacks `extra-protocols` for a `proxy:` type or a Shadowsocks plugin.
#[derive(Debug)]
pub struct FeatureGated {
    detail: String,
}

impl FeatureGated {
    /// A `proxy: <type>` the dispatch table rejects when `extra-protocols` is off.
    #[must_use]
    pub fn protocol(proxy_type: &str) -> Self {
        Self { detail: format!("outbound protocol {proxy_type}") }
    }

    /// A Shadowsocks plugin whose transport crate is only built with `extra-protocols`.
    #[must_use]
    pub fn plugin(plugin: &str) -> Self {
        Self { detail: format!("shadowsocks plugin {plugin}") }
    }
}

impl fmt::Display for FeatureGated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} requires feature extra-protocols", self.detail)
    }
}

impl std::error::Error for FeatureGated {}
