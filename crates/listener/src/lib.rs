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

pub mod anytls;
pub mod auth;
pub mod http;
pub mod hysteria2_realm;
pub mod inbound;
pub mod jls;
pub mod mieru;
pub mod mixed;
pub mod reality;
pub mod redir;
pub mod shadowquic;
pub mod shadowsocks;
pub mod shadowtls;
pub mod sing_shadowsocks;
pub mod sing_vless;
pub mod sing_vmess;
pub mod snell;
pub mod socks;
pub mod sudoku;
pub mod tlsmirror;
pub mod trojan;
pub mod trusttunnel;
pub mod tuic;
pub mod tun;
pub mod tunnel;

pub mod listener;
pub mod parse;

use murmur_component_tls::utls::{Config as TlsConfig, TimeFn};

/// A server TLS config on `now`, with every remaining field named so a field added to
/// [`TlsConfig`] fails the build instead of silently taking its default.
#[must_use]
#[expect(
    clippy::unneeded_field_pattern,
    reason = "naming every field makes a field added to TlsConfig fail the build instead of silently taking its default"
)]
pub(crate) fn tls_server_config(now: TimeFn) -> TlsConfig {
    let TlsConfig {
        rand,
        time: _,
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        next_protos,
        server_name,
        client_auth,
        client_cas,
        insecure_skip_verify,
        cipher_suites,
        session_tickets_disabled,
        min_version,
        max_version,
        curve_preferences,
        renegotiation,
        key_log_writer,
        encrypted_client_hello_config_list,
        encrypted_client_hello_rejection_verify,
        encrypted_client_hello_keys,
        get_encrypted_client_hello_keys,
        session_id_generator,
    } = TlsConfig::default();
    TlsConfig {
        rand,
        time: Some(now),
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        next_protos,
        server_name,
        client_auth,
        client_cas,
        insecure_skip_verify,
        cipher_suites,
        session_tickets_disabled,
        min_version,
        max_version,
        curve_preferences,
        renegotiation,
        key_log_writer,
        encrypted_client_hello_config_list,
        encrypted_client_hello_rejection_verify,
        encrypted_client_hello_keys,
        get_encrypted_client_hello_keys,
        session_id_generator,
    }
}
