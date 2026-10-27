//! Restls: a TLS-mimicking transport. The handshake is relayed verbatim to a real disguise
//! target, and once the peer is authenticated from public wire bytes the application records
//! switch to the HMAC-authenticated, mask-XORed Restls framing.
//!
//! TLS 1.2 and TLS 1.3 handshake paths use version-pinned, hand-built ClientHello messages.
//! Browser-specific extension order/content remains absent: `component-tls::utls` currently
//! provides no supported-versions clamp on its fingerprint-built ClientHello, which Restls's
//! exact-version auth requires. Outbound `force_tls12` maps to `version-hint: tls12`, not an
//! independent version clamp. TLS 1.2 client key agreement supports only X25519.
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

pub mod client;
pub mod config;
pub mod consts;
pub mod crypto;
pub mod framing;
pub mod messages;
pub mod script;
pub mod server;
pub mod sigverify;
pub mod wire;

pub use client::new_restls;
pub use config::{new_restls_config, Config, ServerConfig};
pub use server::{restls_server, DialFn};
