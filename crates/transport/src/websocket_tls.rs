//! Client TLS config shared by the WebSocket-based obfuscation layers.

use murmur_component_tls::utls as tls_c;

/// Every `utls::Config` field is spelled out so one added upstream cannot silently take its
/// default on the WebSocket dial path; both callers speak the upgrade over HTTP/1.1.
pub(crate) fn http_upgrade_tls_config(host: &str, skip_cert_verify: bool) -> tls_c::Config {
    let tls_c::Config {
        rand,
        time,
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        client_auth,
        client_cas,
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
        ..
    } = tls_c::Config::default();
    tls_c::Config {
        rand,
        time,
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        next_protos: vec!["http/1.1".to_owned()],
        server_name: host.to_owned(),
        client_auth,
        client_cas,
        insecure_skip_verify: skip_cert_verify,
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
