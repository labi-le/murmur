//! A minimal, from-scratch TLS 1.3 handshake engine (client and server)
//! carrying the JLS authentication mechanism.
//!
//! Scope is deliberately narrow: TLS 1.3 only, exactly
//! `TLS_AES_128_GCM_SHA256` / X25519 / `ecdsa_secp256r1_sha256`, session
//! resumption with 0-RTT, no client certificates, no `HelloRetryRequest`.
//! See the individual modules for the exact wire format and key schedule this
//! implements.
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

use std::sync::Arc;

use rustls::RootCertStore;

mod client;
mod cursor;
mod der;
mod error;
pub mod jls;
mod keys;
#[cfg(test)]
mod keys_tests;
mod messages;
pub mod quic;
#[cfg(test)]
mod quic_tests;
mod record;
mod server;
mod stream;
mod tee;
#[cfg(test)]
mod tests;
mod ticket;
mod transcript;
mod x509;

pub use client::client_handshake;
pub use error::{ServerHandshakeError, TlsError};
pub use jls::JlsUser;
pub use keys::{quic_initial_secrets, quic_keys, resumption_psk, QuicKeys, QuicVersion};
pub use messages::{MAX_EARLY_DATA_SIZE_QUIC, MAX_SESSION_TICKET_LIFETIME_SECS};
pub use quic::{
    ClientSessionTicket, EncryptionLevel, QuicClient, QuicClientConfig, QuicEvent, QuicServer, QuicServerOptions,
};
pub use server::server_handshake;
pub use stream::JlsStream;
pub use x509::TimeFn;

/// Client-side configuration for [`client_handshake`].
pub struct ClientConfig {
    pub server_name: String,
    pub alpn: Vec<String>,
    pub user: JlsUser,
    /// The trust anchors a peer's certificate chain is verified against. Ignored when the peer is
    /// JLS-authenticated, whose camouflage certificate is self-signed by construction.
    pub root_certs: Arc<RootCertStore>,
    /// The instant the peer's chain is checked at.
    pub time: Option<TimeFn>,
}

impl core::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("server_name", &self.server_name)
            .field("alpn", &self.alpn)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

/// Server-side configuration for [`server_handshake`].
#[derive(Debug)]
pub struct ServerConfig {
    pub users: Vec<JlsUser>,
    /// Empty string accepts any client-presented SNI.
    pub server_name: String,
    pub alpn: Vec<String>,
    /// Self-signed P-256 leaf certificate, DER-encoded, no chain.
    pub cert_der: Vec<u8>,
    pub key: p256::ecdsa::SigningKey,
}

/// JLS authentication outcome for a connection.
///
/// `Disabled` is unreachable from this crate's own entry points (JLS is always
/// enabled when [`client_handshake`] / [`server_handshake`] are called); it exists
/// only so callers that also model plain (non-JLS) connections can use one enum
/// uniformly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JlsStatus {
    Disabled,
    Unauthenticated,
    Authenticated,
}

/// JLS authentication state and negotiated parameters for a finished
/// connection.
#[derive(Clone, Debug)]
pub struct JlsConnectionState {
    pub status: JlsStatus,
    pub negotiated_alpn: Option<String>,
    pub user: String,
}
