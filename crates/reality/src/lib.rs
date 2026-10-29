//! REALITY: a client-splices-its-own-`ClientHello` TLS trick for disguising proxy traffic as a
//! real TLS connection to an innocuous `dest` site, without needing that site's private key.
//!
//! Each module's doc comment states its exact scope decisions. The authentication protocol
//! (`RealityConfig`/session-id splice for the client and the server-side authentication) is
//! implemented directly, along with the thin client and server wrappers that compose it.
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

mod cert;
mod client;
mod clock;
mod handshake;
mod record;
mod server;
mod stream;
mod suite;
mod wire;

pub use client::{connect_reality_client, RealityClientConfig, MAX_SHORT_ID_LEN};
pub use server::{
    reality_server_accept, AsyncReadWriteUnpinSend, BoxedStream, DialDest, FallbackLimit, RealityServerConfig,
};
pub use stream::{RealityCloser, RealityConnAddrs, RealityStream};

#[cfg(test)]
mod keys_tests;
#[cfg(test)]
mod tests;
