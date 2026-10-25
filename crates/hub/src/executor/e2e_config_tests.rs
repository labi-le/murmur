//! End-to-end config-parsing coverage driven through the same entry point `main.rs`'s `-t` flag
//! and the real API config reload both use (`hub::executor::executor::parse_with_bytes`), not a
//! test-only shortcut into `config::config::parse`.
//!
//! The fixture at `testdata/e2e_supported.yaml` lives under `rust/src/config/` rather than
//! depending on the repository-root `docs/config.yaml`: this crate owns it, so a change to the
//! supported surface is a change to a file this crate's own commits can update, instead of a live
//! dependency on a file excluded from runtime use. It is not a
//! byte-for-byte copy of `docs/config.yaml`'s 39 sections; it is a curated real-world-shaped
//! config exercising one proxy of each currently-supported family plus the general/dns/sniffer/tun
//! sections, using RFC 5737/6890 documentation addresses and obvious placeholder credentials in
//! place of anything real.

#[cfg(feature = "extra-protocols")]
#[tokio::test(flavor = "multi_thread")]
async fn parses_real_world_supported_config() {
    let yaml = include_bytes!("testdata/e2e_supported.yaml");
    let cfg = crate::executor::executor::parse_with_bytes(yaml)
        .await
        .expect("a config using only currently-supported protocols and sections must parse");

    let proxy_names = [
        "socks-in",
        "http-in",
        "ss-in",
        "vmess-in",
        "vless-in",
        "trojan-in",
        "hysteria-in",
        "tuic-in",
        "ssh-in",
        "snell-in",
        "anytls-in",
        "gost-relay-in",
        "mieru-in",
    ];
    for name in proxy_names {
        assert!(cfg.proxies.contains_key(name), "expected proxy `{name}` to be present in the parsed config");
    }
    assert!(cfg.proxies.contains_key("PROXY"), "expected the PROXY selector group to be present");
}

#[tokio::test]
async fn retained_protocols_and_router_sections_parse_in_every_build() {
    let config = br#"
mixed-port: 0
redir-port: 0
tproxy-port: 0
external-controller: 127.0.0.1:0
dns:
  enable: true
  nameserver: [192.0.2.53]
tun:
  enable: false
  stack: system
proxies:
  - {name: vless, type: vless, server: 192.0.2.1, port: 443, uuid: 11111111-1111-1111-1111-111111111111}
  - {name: vmess, type: vmess, server: 192.0.2.1, port: 443, uuid: 11111111-1111-1111-1111-111111111111, alterId: 0, cipher: auto}
  - {name: trojan, type: trojan, server: 192.0.2.1, port: 443, password: example}
proxy-groups:
  - {name: PROXY, type: select, proxies: [vless, vmess, trojan, DIRECT]}
rules:
  - MATCH,PROXY
"#;
    let cfg = crate::executor::executor::parse_with_bytes(config).await.expect("retained config parses");
    for name in ["vless", "vmess", "trojan", "PROXY", "DIRECT"] {
        assert!(cfg.proxies.contains_key(name), "missing {name}");
    }
    assert!(cfg.dns.enable);
    assert!(!cfg.general.inbound.tun.enable);
}

/// `restls-opts` and `shadow-tls-opts` are TLS options on the four dialers that carry them, so a
/// config naming either parses once `tls: true` says the mode has a TLS layer to wrap. Restls'
/// engine is implemented (`crates/restls`, with adapter-level round trips in
/// `adapter-outbound/tests/restls_e2e.rs`), and shadow-tls v3's client-side gate is the dial path
/// (`crates/transport-shadowtls/src/client.rs`, `check_version`), not the option block, so only a
/// v3 *dial* names the missing rustls `legacy_session_id` hook.
#[tokio::test(flavor = "multi_thread")]
async fn restls_and_shadow_tls_options_parse_on_a_vless_proxy() {
    for option in ["restls-opts", "shadow-tls-opts"] {
        let block = match option {
            "restls-opts" => "    restls-opts:\n      password: placeholder\n      version-hint: tls13\n",
            _ => "    shadow-tls-opts:\n      password: placeholder\n      version: 3\n",
        };
        let config = format!(
            "proxies:\n  - name: p\n    type: vless\n    server: 203.0.113.37\n    port: 443\n    \
             uuid: 00000000-0000-0000-0000-000000000005\n    network: tcp\n    tls: true\n    \
             servername: internal.example\n{block}"
        );
        let cfg = crate::executor::executor::parse_with_bytes(config.as_bytes())
            .await
            .unwrap_or_else(|err| panic!("{option} must not be rejected at parse time: {err}"));
        assert!(cfg.proxies.contains_key("p"), "{option}: the proxy must be built");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn zerotier_configuration_follows_engine_availability() {
    let config = concat!("proxies:\n", "  - name: p\n", "    type: zerotier\n", "    network: \"0123456789abcdef\"\n",);
    let result = crate::executor::executor::parse_with_bytes(config.as_bytes()).await;
    if cfg!(all(feature = "zerotier", not(feature = "no_zerotier"))) {
        let cfg = result.expect("an enabled zerotier adapter must parse");
        assert!(cfg.proxies.contains_key("p"), "the proxy must be built");
    } else {
        let err = result.expect_err("a disabled zerotier adapter must reject configuration");
        assert!(err.to_string().contains("zerotier support is disabled"), "unexpected error: {err}");
    }
}

/// A `tun:` section parses whether enabled or not, and every sub-field reaches `general.tun` the
/// way the config parser's `parse_tun` maps it. `inet4-address` is the one field the config never
/// names: it is computed from `dns.fake-ip-range` re-prefixed to a `/30`, which is why
/// `enable: true` alone still yields `198.18.0.1/30` here.
#[tokio::test(flavor = "multi_thread")]
async fn tun_section_maps_every_option_whether_enabled_or_not() {
    let config = concat!(
        "tun:\n",
        "  enable: true\n",
        "  stack: gvisor\n",
        "  device: utun9\n",
        "  dns-hijack: [\"any:53\"]\n",
        "  auto-route: false\n",
        "  auto-detect-interface: false\n",
        "  mtu: 9000\n",
        "  disable-icmp-forwarding: true\n",
        "  udp-timeout: 60\n",
        "  file-descriptor: 7\n",
        "  inet6-route-address: [\"2001:db8::/32\"]\n",
    );
    let cfg = crate::executor::executor::parse_with_bytes(config.as_bytes())
        .await
        .expect("an enabled tun: section must parse");

    let tun = &cfg.general.inbound.tun;
    assert!(tun.enable);
    assert_eq!(tun.device, "utun9");
    assert_eq!(tun.stack, murmur_constant::tun::TunStack::Gvisor);
    assert_eq!(tun.dns_hijack, Some(vec!["any:53".to_owned()]));
    assert!(!tun.auto_route);
    assert!(!tun.auto_detect_interface);
    assert_eq!(tun.mtu, 9000);
    assert!(tun.disable_icmp_forwarding);
    assert_eq!(tun.udp_timeout, 60);
    assert_eq!(tun.file_descriptor, 7);
    assert_eq!(tun.inet6_route_address, vec!["2001:db8::/32".parse().unwrap()]);
    assert_eq!(tun.inet4_address, vec!["198.18.0.1/30".parse().unwrap()]);

    let disabled = crate::executor::executor::parse_with_bytes(
        "tun:\n  enable: false\n  stack: system\n  device: utun9\n  dns-hijack: [\"any:53\"]\n  mtu: 9000\n".as_bytes(),
    )
    .await
    .expect("a disabled tun: section with named sub-fields must parse");
    assert!(!disabled.general.inbound.tun.enable);
    assert_eq!(disabled.general.inbound.tun.device, "utun9");
    assert_eq!(disabled.general.inbound.tun.stack, murmur_constant::tun::TunStack::System);
    assert_eq!(disabled.general.inbound.tun.dns_hijack, Some(vec!["any:53".to_owned()]));
    assert_eq!(disabled.general.inbound.tun.mtu, 9000);
}

/// `inet4-address` follows the fake-IP range it is derived from, and - as for every other `tun:`
/// field - a config that turns `ipv6` off loses `inet6-address` before `parse_tun` runs.
#[tokio::test(flavor = "multi_thread")]
async fn tun_inet4_address_follows_the_fake_ip_range() {
    let config = concat!(
        "ipv6: false\n",
        "tun:\n",
        "  enable: true\n",
        "  inet6-address: [\"fdfe:dcba:9876::1/126\"]\n",
        "dns:\n",
        "  fake-ip-range: 10.20.0.0/16\n",
    );
    let cfg = crate::executor::executor::parse_with_bytes(config.as_bytes()).await.expect("config parses");
    assert_eq!(cfg.general.inbound.tun.inet4_address, vec!["10.20.0.0/30".parse().unwrap()]);
    assert!(cfg.general.inbound.tun.inet6_address.is_empty());
    assert!(cfg.general.inbound.tun.device.is_empty(), "no device means the listener names one, as sing_tun does");
}

/// An unknown `stack` is rejected while the config is read, so the error names the field rather
/// than surfacing later as a startup log line.
#[tokio::test(flavor = "multi_thread")]
async fn tun_unknown_stack_is_rejected_at_parse_time() {
    let result = crate::executor::executor::parse_with_bytes(b"tun:\n  enable: true\n  stack: bogus\n").await;
    let err = match result {
        Ok(_) => panic!("an unknown stack must not parse"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("invalid tun stack"), "unexpected error: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn easytier_and_tailscale_configuration_follows_engine_availability() {
    let easytier = concat!(
        "proxies:\n",
        "  - name: p\n",
        "    type: easytier\n",
        "    server: 203.0.113.39\n",
        "    port: 443\n",
        "    network-name: placeholder-network\n",
        "    peers:\n",
        "      - tcp://203.0.113.39:11010\n",
    );
    let result = crate::executor::executor::parse_with_bytes(easytier.as_bytes()).await;
    if cfg!(all(feature = "easytier", not(feature = "no_easytier"))) {
        result.expect("an enabled EasyTier adapter must parse");
    } else {
        let err = result.expect_err("a disabled EasyTier adapter must reject configuration");
        assert!(err.to_string().contains("easytier support is disabled"), "unexpected error: {err}");
    }

    let tailscale = "proxies:\n  - name: p\n    type: tailscale\n";
    let result = crate::executor::executor::parse_with_bytes(tailscale.as_bytes()).await;
    if cfg!(all(feature = "tailscale", feature = "with_gvisor", not(feature = "no_tailscale"))) {
        result.expect("an enabled Tailscale adapter must parse");
    } else {
        let err = result.expect_err("a disabled Tailscale adapter must reject configuration");
        assert!(err.to_string().contains("tailscale support is disabled"), "unexpected error: {err}");
    }
}
