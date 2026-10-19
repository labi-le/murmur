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

/// ZeroTier was the last row of `rust/README.md`'s "Rejected at configuration-parse time" table:
/// its adapter parses, and the data-plane gap surfaces at dial time instead.
#[tokio::test(flavor = "multi_thread")]
async fn zerotier_parses_like_the_other_outbounds() {
    let config = concat!("proxies:\n", "  - name: p\n", "    type: zerotier\n", "    network: \"0123456789abcdef\"\n",);
    let cfg = crate::executor::executor::parse_with_bytes(config.as_bytes())
        .await
        .expect("a zerotier proxy must parse; the data-plane gap surfaces at dial time");
    assert!(cfg.proxies.contains_key("p"), "the proxy must be built");
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

/// `EasyTier` and Tailscale are two "no Rust implementation" table entries whose adapters are
/// still compiled by default (`no_easytier`/`no_tailscale` are opt-out features, both off by
/// default) and therefore still parse under the crate's default feature set. This test documents
/// that as a known, deliberate exception; if a future change compiles them out by default too, the
/// `Ok` branches below are what gain a rejection expectation.
///
/// `cargo test --all-features` (`make test`, `make test-windows`) turns `no_easytier` and
/// `no_tailscale` on, which is the opposite of "default features"; asserting `Ok` unconditionally
/// here made the test fail under that invocation on every platform, not just Windows. The
/// assertions below follow whichever build actually ran: the stub constructors' own
/// "disabled by ... build tag" wording, not this test's assumption about which features are on.
#[tokio::test(flavor = "multi_thread")]
async fn easytier_and_tailscale_still_parse_under_default_features() {
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
    if cfg!(feature = "no_easytier") {
        let err = result.expect_err("\"no_easytier\" routes to the stub constructor, which always fails");
        assert!(err.to_string().contains("no_easytier"), "expected the stub's build-tag message, got: {err}");
    } else {
        result.expect("EasyTier's real adapter is compiled by default and should still parse a config naming it");
    }

    let tailscale = "proxies:\n  - name: p\n    type: tailscale\n";
    let result = crate::executor::executor::parse_with_bytes(tailscale.as_bytes()).await;
    if cfg!(feature = "with_gvisor") && !cfg!(feature = "no_tailscale") {
        result.expect("Tailscale's real adapter is compiled by default and should still parse a config naming it");
    } else {
        let err = result.expect_err(
            "tailscale routes to the stub constructor without with_gvisor, or with no_tailscale, which always fails",
        );
        assert!(err.to_string().contains("build tag"), "expected the stub's build-tag message, got: {err}");
    }
}
