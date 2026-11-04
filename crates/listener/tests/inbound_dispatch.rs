//! Config-level dispatch smoke tests for the inbound registry: one registry maps every listener
//! type, and an unknown type is refused by name.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![allow(
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
)]

use std::sync::Arc;

use murmur_constant::listener::InboundListener;
use murmur_listener::parse::parse_listener;
use yaml_serde::Mapping;

/// Every `type` string the registry accepts.
const LISTENER_TYPES: &[&str] = &[
    "socks",
    "http",
    "tproxy",
    "redir",
    "mixed",
    "tunnel",
    "tun",
    "shadowsocks",
    "snell",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "hysteria2-realm",
    "tuic",
    "shadowquic",
    "anytls",
    "mieru",
    "sudoku",
    "trusttunnel",
];

fn parse_yaml(yaml: &str) -> Result<Arc<dyn InboundListener>, String> {
    let mapping: Mapping = yaml_serde::from_str(yaml).expect("listener mapping");
    parse_listener(&mapping).map_err(|err| err.to_string())
}

fn minimal_yaml(listener_type: &str) -> String {
    format!("name: probe\ntype: {listener_type}\nport: 18801\n")
}

fn option_json(listener_type: &str, extra_fields: &str) -> String {
    let yaml = format!("{}{}", minimal_yaml(listener_type), extra_fields);
    let listener = parse_yaml(&yaml).unwrap_or_else(|err| panic!("type {listener_type} should parse: {err}"));
    listener.config().option_to_string()
}

#[test]
fn every_listener_type_avoids_the_generic_refusal() {
    for listener_type in LISTENER_TYPES {
        match parse_yaml(&minimal_yaml(listener_type)) {
            Ok(listener) => assert_eq!(listener.name(), "probe", "type {listener_type}"),
            Err(err) => {
                assert!(!err.contains("unsupport proxy type"), "type {listener_type} has no arm of its own: {err}")
            }
        }
    }
}

#[test]
fn unregistered_listener_type_keeps_the_generic_refusal() {
    for listener_type in ["zerotier", "not-a-listener-type"] {
        match parse_yaml(&minimal_yaml(listener_type)) {
            Ok(_) => panic!("type {listener_type} must not dispatch"),
            Err(err) => assert!(err.contains("unsupport proxy type"), "type {listener_type}: {err}"),
        }
    }
}

#[test]
fn each_type_builds_its_own_option() {
    let cases: &[(&str, &str, &[&str])] = &[
        ("socks", "", &["\"udp\":true"]),
        ("http", "", &["\"reality_config\":", "\"certificate\":"]),
        ("tproxy", "", &["\"udp\":true"]),
        ("redir", "", &[]),
        ("mixed", "", &["\"udp\":true"]),
        (
            "tunnel",
            "network:\n  - tcp\ntarget: 127.0.0.1:18802\n",
            &["\"network\":[\"tcp\"]", "\"target\":\"127.0.0.1:18802\""],
        ),
        ("tun", "", &["\"device\":", "\"route_address\":"]),
        #[cfg(feature = "extra-protocols")]
        (
            "shadowsocks",
            "cipher: aes-128-gcm\npassword: probe-password\n",
            &["\"cipher\":\"aes-128-gcm\"", "\"simple_obfs\":"],
        ),
        #[cfg(feature = "extra-protocols")]
        ("snell", "psk: probe-psk\n", &["\"psk\":\"probe-psk\"", "\"obfs_opts\":"]),
        (
            "vmess",
            "users:\n  - uuid: 11111111-1111-1111-1111-111111111111\n",
            &["\"mekya_config\":", "\"mkcp_config\":"],
        ),
        (
            "vless",
            "users:\n  - uuid: 11111111-1111-1111-1111-111111111111\n",
            &["\"decryption\":", "\"xhttp_config\":"],
        ),
        ("trojan", "users:\n  - password: probe-password\n", &["\"ss_option\":", "\"grpc_service_name\":"]),
        #[cfg(feature = "extra-protocols")]
        (
            "hysteria2",
            "certificate: probe-cert\nprivate-key: probe-key\n",
            &["\"obfs_password\":", "\"realm_opts\":", "\"masquerade\":"],
        ),
        #[cfg(feature = "extra-protocols")]
        ("hysteria2-realm", "token: probe-token\n", &["\"max_realms\":", "\"realm_name_pattern\":"]),
        #[cfg(feature = "extra-protocols")]
        (
            "tuic",
            "certificate: probe-cert\nprivate-key: probe-key\n",
            &["\"max_idle_time\":15000", "\"authentication_timeout\":1000"],
        ),
        #[cfg(feature = "extra-protocols")]
        ("shadowquic", "jls-upstream:\n  addr: 127.0.0.1:443\n", &["\"jls_upstream\":", "\"max_idle_time\":30000"]),
        #[cfg(feature = "extra-protocols")]
        ("anytls", "", &["\"padding_scheme\":", "\"allow_insecure\":"]),
        #[cfg(feature = "extra-protocols")]
        (
            "mieru",
            "transport: TCP\nusers:\n  probe-user: probe-password\n",
            &["\"transport\":\"TCP\"", "\"traffic_pattern\":"],
        ),
        #[cfg(feature = "extra-protocols")]
        ("sudoku", "key: probe-key\n", &["\"aead_method\":", "\"http_mask_options\":"]),
        #[cfg(feature = "extra-protocols")]
        ("trusttunnel", "certificate: probe-cert\nprivate-key: probe-key\n", &["\"network\":", "\"bbr_profile\":"]),
    ];

    for (listener_type, extra_fields, fragments) in cases {
        let json = option_json(listener_type, extra_fields);
        assert!(json.contains("\"name_str\":\"probe\""), "type {listener_type}: {json}");
        for fragment in *fragments {
            assert!(json.contains(fragment), "type {listener_type} lacks {fragment} in {json}");
        }
    }
}
