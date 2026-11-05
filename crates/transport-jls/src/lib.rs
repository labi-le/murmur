//! JLS is a TLS 1.3 camouflage transport: the peer's credentials are sealed
//! into the `ClientHello`/`ServerHello` random field, so a probe that cannot
//! decrypt it sees 32 bytes of noise, and a client that presents no valid
//! JLS `ClientHello` is relayed to an ordinary TLS site instead.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::pedantic,
        clippy::nursery
    )
)]

pub mod camouflage;
pub mod client;
pub mod server;

use anyhow::{anyhow, Result};
use murmur_jls_tls::JlsUser;

/// The peer credentials a JLS handshake is sealed with.
#[derive(Clone, Debug)]
pub struct Config {
    pub user: JlsUser,
}

pub fn new_config(username: &str, password: &str) -> Result<Config> {
    if username.is_empty() {
        return Err(anyhow!("jls: username is required"));
    }
    if password.is_empty() {
        return Err(anyhow!("jls: password is required"));
    }
    Ok(Config { user: JlsUser { username: username.to_owned(), password: password.to_owned() } })
}

impl Config {
    /// the `&jls.ClientConfig{Config: *cfg, ServerName: ..., ALPN: ...}` literal. A `None` ALPN
    /// is nil slice, which `NewClient` turns into [`server::DEFAULT_ALPN`].
    #[must_use]
    pub fn client_config(&self, server_name: &str, alpn: Option<Vec<String>>) -> client::ClientConfig {
        client::ClientConfig { server_name: server_name.to_owned(), user: self.user.clone(), alpn }
    }
}

pub mod cert;
mod ratelimit;
pub use cert::{new_self_signed_cert, SelfSignedCert};
pub use ratelimit::{new_rate_limited_conn, BitRateLimiter};
