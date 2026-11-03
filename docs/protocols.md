# Protocol status and known limitations

## Protocols

### Rejected at configuration-parse time

Nothing is refused by name at configuration-parse time any more. ZeroTier, the last entry to leave
that list, now has an adapter that parses and an overlay data plane behind it
(`crates/adapter-outbound/src/zerotier.rs` plus `crates/adapter-outbound/src/zerotier_link.rs`), so
a `type: zerotier` proxy runs; what an engine cannot do yet is recorded per option and in
"Compiled by default, but engine gaps surface at dial time". What remains are per-option refusals
inside a configuration that does parse (mieru's `low-entropy`, a Restls `version-hint`, shadow-tls
v3's dial, TUN's unsupported fields, ZeroTier's `planet`/`physical-mtu`/`low-bandwidth`/
`encrypted-hello`/`remote-trace-target`, and `hysteria2`'s realm-plus-port-hopping combination), and
each one names the piece that is still missing rather than ignoring it.

`hysteria2` is implemented: `crates/listener/src/inbound/hysteria2.rs` builds the inbound on
`murmur-transport-hysteria2`'s `Service`. The option block maps every field, including the
`realm-opts` block, `mux-option` and the two `initial-*` QUIC receive windows, which quinn
advertises in the handshake; the TLS layer is built from
`certificate`/`private-key`/`client-auth-*`/`ech-key`/`alpn` (ALPN defaulting to `h3`), obfs
accepts `salamander` and `gecko` and rejects an unknown type or a missing password with the
reference's messages, `masquerade` accepts `file://` and `http(s)://` and rejects an unknown scheme,
and the listener binds every comma-separated address with `SO_REUSEADDR`. The tests cover the option
mapping and its zero-value defaults, those four rejections, the file and reverse-proxy masquerade
variants, and a loopback round trip that authenticates a real transport client and carries a stream
payload, a datagram (attributed back to the dialled destination) and a wrong-password dial that
carries no traffic. The outbound half is real as well: `crates/adapter-outbound/src/hysteria2.rs` is
registered in `crates/adapter/src/parser.rs`. What is not implemented: `bbr-profile` is accepted
but not applied, because quinn binds its congestion controller when the connection is created
(`crates/transport-hysteria2/src/quic.rs`); the two `max-*` receive windows are accepted but not
applied either, because quinn's flow-control window is fixed at the value it advertises in the
handshake and only its connection window can be raised later, through
`quinn::Connection::set_receive_window` (`crates/transport-hysteria2/src/quic.rs`); everything else
the option block carries now runs, including `realm-opts`, whose dial half is described next.

`hysteria2-realm` is implemented: `crates/listener/src/hysteria2_realm` carries the realm
rendezvous service, the `hysteria2-realm` inbound type parses with a required `token` (the schema
makes it required), and the tests cover the option defaults, the
register/heartbeat/deregister/events/connect/connects codecs with their error codes, and a loopback
round trip that registers a realm, reads the punch event off `GET /v1/{id}/events` and waits for a
`POST /v1/{id}/connects/{nonce}` to reach the blocked `POST /v1/{id}/connect`, over both plain HTTP
and TLS. The client half is implemented as well: `crates/adapter-outbound/src/hysteria2_realm.rs` carries
the full `realm-opts` block (all 12 fields, including the realm HTTP TLS block), the STUN discovery
and UDP hole-punch behind the offer-new-realm step, and the exchange equivalent to the reference's
control-client connect that hands the punched socket to the QUIC session. The filter
`cargo test -p murmur-adapter-outbound hysteria2` reports 26 passed (16 `hysteria2` + 10
`hysteria2_realm`). Two deviations remain from the reference: the punch runs once per adapter client
build rather than once per QUIC connection attempt, because `murmur-transport-hysteria2`'s
`ClientOptions` takes a bound packet conn and a fixed server address (the reference re-runs the
offer inside every attempt), and a realm combined with `server-ports` is refused, as the reference
also does. Two requirements fail closed at load rather than reaching the network: a
`hysteria2-realm` listener without a `token` does not parse, and a realm client without
`realm-opts.server-url` fails with "create control client: control server URL is required".

What is not proven here is a run against a third-party hysteria realm client: the realm only brokers
the rendezvous, and the payload then flows between the two peers, so nothing about the peer-to-peer
path is exercised by the realm's own tests. The one behavioural deviation is that `connect` does not
return early when the requesting client disconnects (hyper exposes no per-request cancellation
signal here); it waits out the same 10s response timeout instead.

shadow-tls v3 is refused at the dial: the `shadow-tls-opts` block parses, and it is the v3 *dial*
that refuses, naming the rustls `legacy_session_id` hook v3's per-connection HMAC needs
([rustls/rustls#1932](https://github.com/rustls/rustls/issues/1932)); v1 and v2 dial.

TUN parses. A `tun:` section is parsed, mapped onto the runtime's TUN config and handed to
`listener::listener::re_create_tun`: a conf the device cannot honour is logged, stored with
`enable: false` and does not stop the rest of the config from loading. The options this build cannot
honour are refused by name at that point — `stack: system`/`mixed`, a `disable-icmp-forwarding`
that is not `true`, `dns-hijack`, `auto-redirect`, `auto-detect-interface`, `gso`, `strict-route`,
`endpoint-independent-nat`, `udp-timeout`, `icmp-timeout`, the UID/UID-range, interface, port-range,
android-user, package and MAC filters, `route-address-set`, `route-exclude-address-set`,
`route-exclude-address`, the family-specific route-exclude lists, `loopback-address`, the
`iproute2-*` indices and the auto-redirect marks. `inet4-address` gets the same treatment one
layer earlier: the address comes from `dns.fake-ip-range` re-prefixed to a `/30`, which is also
what the reference does, so a config that names the key is warned about and has TUN stored disabled
instead of being silently given the derived value. One refusal
lists every offending option, not just the first. With `auto-route` on, startup logs the default
routes already in the main table, because the metric-less routes it installs outrank them and that
line is the only warning before connectivity moves. `auto-route-delay: <seconds>` postpones that
installation by the given number of seconds; it is an extension over the reference, which installs
immediately, and the delay is a window for the operator, not proof that the tunnel carries traffic.
Opening a device needs the privileges
`/dev/net/tun` requires. TCP is carried: the listener drives `murmur-component-wireguard`'s smoltcp
stack — the engine both `stack: mips` and `stack: gvisor` name here, because this build has no
gVisor crate — from the device's own packets, and hands each connection it terminates to the
tunnel; UDP datagrams and the synthesised ICMP echo reply stay on the listener's direct path.
IPv4 and IPv6 fragments are reassembled before that parse: at most 64 datagrams are in flight, an
unfinished datagram expires after 30 seconds, and a conflicting overlap drops the whole datagram
rather than picking a byte. An IPv6 UDP reply larger than the interface MTU is fragmented before
the device write, because the kernel will not fragment a forwarded IPv6 packet; IPv4 keeps relying
on the kernel's fragmentation.
The packet-device tests complete a TCP handshake through the listener's own stack
against a second smoltcp peer. Linux automatic device creation also passed a real
namespace smoke check: the binary configures its address and route, answers an ICMP
echo through `/dev/net/tun` and removes the interface on shutdown. Netlink requests
target kernel port zero, include the complete attribute length and supply both
`IFA_LOCAL` and `IFA_ADDRESS` without requesting IPv6 home-address semantics.

The kernel address/route regression test checks IPv4 and IPv6 creation, duplicate
handling, deletion and errors in a disposable user/network namespace. It requires
`unshare`, `timeout`, iproute2, IPv6 and permission to create those namespaces:

```sh
timeout 900 tools/cargo-slot cargo test -p murmur-listener \
  tun::netlink_linux::tests::kernel_address_and_route_lifecycle_in_isolated_namespace \
  -- --exact --ignored --nocapture
```

JLS is implemented: `crates/jls-tls` (the TLS 1.3 engine, in both its TCP and its QUIC transports)
and `crates/transport-jls` (the transport, including the camouflage-forwarding rate limiters), so
`jls-config` builds a real listener on the shadowsocks (both implementations), Snell, Trojan,
VLESS, VMess and AnyTLS inbounds, and the `jls` plugin / obfs mode dials from the shadowsocks and
Snell outbounds. The same engine also dials from a `jls-opts` block on the VLESS, Trojan, VMess and
AnyTLS outbounds, as a TLS wrapper rather than an obfs plugin. ShadowQuic and JLS-over-QUIC are
implemented in `crates/transport-shadowquic`, which builds the QUIC session on `quinn`, over the
QUIC-mode handshake and key derivation in `crates/jls-tls`. Session resumption is real:
`crates/jls-tls` derives the RFC 8446 §7.1 early secret, the resumption binder and the client early
traffic secret, seals and validates `NewSessionTicket`s, and `crates/transport-shadowquic` offers
the early flight through quinn's `into_0rtt` — a resumed client rides the 0-RTT flight and the
server reads the payload off it, with a client that has no ticket as the negative control. The
engine's ALPN handling matches the reference on both transports: the TCP server negotiates (and a
disjoint list is an error, which is exactly what triggers the camouflage relay instead of
tunnelling) and the client checks the server's selection against what it offered, so a client
offering an unserved protocol is relayed to the camouflage destination. The listener-level
end-to-end tests are `crates/listener/src/shadowquic/server.rs`'s six (a relayed JLS client stream,
streams past quinn's default, and the unknown-ALPN, wrong-password and unoffered version fail-closed
cases) plus `inbound::shadowquic`'s two, which drive the real `OutShadowQuic` against the inbound
for QUIC v1 and v2 and require that no packet reaches the JLS upstream. The engine is 39 tests and
the transport 19 after those changes. What no test here does is dial with a third-party ShadowQuic
client, and `Transport::dial_early` is reached only by review: the `Conn` trait exposes no 0-RTT
accessor, so the loopback test uses quinn's `Connecting::into_0rtt` directly.

Restls is implemented. The engine in `crates/restls` drives the `restls` obfs mode from the
shadowsocks and Snell outbounds, and a `restls-opts` block dials from the VLESS, Trojan, VMess and
AnyTLS outbounds: `crates/adapter-outbound/tests/restls_e2e.rs` carries eight adapter-level round
trips over those four dialers (TLS 1.3 and TLS 1.2 each), including a camouflage check that parses
the client's byte stream as TLS records and requires the ClientHello's SNI to match the configured
name. The TLS 1.3 master-secret salt defect that made the engine's TLS 1.3 records undecryptable was
fixed — RFC 8446 §7.1 derives the master secret from the *handshake* secret's `derived` value —
leaving `murmur-restls` at 66 lib tests plus its interop tests green. The superseded
`trojan::restls_stream_tests` module was deleted.

Mieru is implemented: `crates/mieru` (the chacha20poly1305-authenticated multiplexed TCP/UDP engine)
drives both the `mieru` proxy outbound and the `mieru` inbound, on both the `TCP` and `UDP`
transports. `traffic-pattern` (nonce shaping, padding, TCP fragmentation) is parsed and applied
rather than rejected: the crate is 67 tests green with a forced clean rebuild, and the pass-through
is verified on both sides — `inbound::mieru`'s five listener tests relay TCP and UDP with and
without a configured pattern and refuse a listener with no port, and the adapter's own tests
exercise the pattern glue. Fixing that turned up a second defect: four of the crate's sweeps used
`tokio::time::interval`, whose first tick fires immediately where a ticker waiting a full interval
does not, so the client underlay cleaner could close an underlay between its publish and its session
registration and the first write failed about half the time; they now use `interval_at`. The one
part still refused rather than silently ignored is `low-entropy` payload coding, which fails closed
with an error naming `lowEntropy` — a documented limitation rather than a missing validation.

sing-mux is implemented: `crates/sing-mux` (the smux / yamux / h2mux framing, the
`sp.mux.sing-box.arpa` padding scheme, and the TCP Brutal bandwidth exchange) drives both sides of
the feature: the `smux:` option on any outbound proxy, and the `mux-option` (padding and brutal)
block the sing-based listeners accept. `protocol` selects `h2mux` (the default), `smux` or `yamux`.

### Config parses, but the end-to-end path is not yet proven

These protocols are not rejected at parse time. Their option structs, TLS setup, authentication and
the transport that carries traffic are all implemented, and each has at least an in-crate loopback
proof; what is still missing is the stronger end-to-end proof named in the third column, so this
section should not yet be read as "these work against a third-party peer".

| Protocol | Implemented | Still unproven |
| --- | --- | --- |
| Hysteria (v1) | `crates/transport-hysteria`'s quinn session — a real loopback handshake, a stream, and a fragmented datagram round trip, 7/7 — plus the adapter-level end-to-end test in `crates/adapter-outbound/tests/hysteria_e2e.rs` (4 tests: a stream, a datagram, a wrong password and a wrong ALPN, each against a loopback server) | a third-party Hysteria client: every dial here is this build's client against this build's server |
| ShadowQuic | the JLS-over-QUIC session, 19 tests including a resumed client riding the 0-RTT early flight, plus the listener-level tests: `crates/listener/src/shadowquic/server.rs`'s six and `inbound::shadowquic`'s two drive the real `OutShadowQuic` against the inbound for QUIC v1 and v2 | a third-party ShadowQuic client, and `Transport::dial_early` end to end — the `Conn` trait exposes no 0-RTT accessor, so only review covers that path |
| TUIC | the transport and the adapter's real dial — `tuic::tests::dial_context_completes_against_a_real_server` completes a loopback v5 authentication and a payload round trip both ways — and the inbound's three tests: a v4 and a v5 authentication and payload round trip through the listener, and a wrong-password fail-closed | a third-party TUIC client: the round trips put this build's client on both ends |
| VMess (client and server, AEAD-2) | `crates/transport-vmess`'s AEAD-2 client and server, exercised by the crate's 55 tests, and the adapter dials through its real AEAD-2 client; the native stability suite drives VMess over TCP, WS and gRPC with UDP associations | a third-party VMess client or server: every round trip is this build against itself |

REALITY is implemented on both halves in `crates/reality`: the client splices its own `ClientHello`,
the server authenticates real `utls` clients, and the record layer reads the content type as the
last non-zero octet — which is what a REALITY server's zero-padded records require, and what the
reference's `utls` implementation does. The client advertises ECDSA P384/SHA384 so a mirrored
target using a P384 certificate can negotiate before REALITY substitutes its Ed25519 authentication
certificate; REALITY authentication still verifies Ed25519. This is not browser fingerprint
emulation. An in-memory regression rejects a ClientHello without the target's required P384 offer,
then completes the authenticated REALITY handshake and application-data exchange when it is present.
Live third-party dials remain outside the automated suite.

### Compiled by default, but engine gaps surface at dial time

EasyTier, Tailscale and ZeroTier were listed in an earlier draft of this table as removed, which was
wrong: their adapters are compiled into the default build (`no_easytier`, `no_zerotier` and
`no_tailscale` are opt-out Cargo features, all off by default) and a config naming any of them
parses successfully. What an engine cannot do yet — or cannot do the way the reference does —
therefore fails at dial time, not at parse time, and that distinction matters to anyone checking a
config file before deploying it:

- **EasyTier:** the engine is in `crates/easytier` and `crates/component-easytier`. The in-process
  `ring://` listener test that would prove the guest ABI end to end is still in flight.
- **ZeroTier:** the adapter is in (`crates/adapter-outbound/src/zerotier.rs`, registered in
  `crates/adapter/src/parser.rs`) and both halves of the engine are implemented. `crates/zerotier`
  carries identity, packet/armor/frame, world, membership, ownership, tag, revocation, capability
  and bonding, plus the multicast plane (`src/node/multicast.rs`: the locked send's
  LIKE/GATHER/FRAME replication with the pending/gather machinery, the multicast subscribe and
  unsubscribe calls, the inbound verb handlers and the `0x08` error path).
  `crates/adapter-outbound/src/zerotier_link.rs` is the `iplink` data plane:
  `apply_network_config`, `write_packet`, `handle_frame`, `validate_destination`, ARP/NDP with the
  neighbour DELAY/PROBE state machine and its queue bounds, route selection, managed IPv6 MACs (/88
  RFC4193 and /40 6plane) and the IGMP/MLD multicast filter. The adapter builds the userspace stack
  (`NetworkStack`), installs the device, and dials/listens through it (`ZeroTierNetDialer`,
  `ValidatedDatagram`), so a virtual network carries traffic: tests cross a real UDP wire between
  two nodes, answer a peer's ARP request from the runtime's link, and install the stack for an
  ad-hoc network. Runtime shutdown also joins its stack-packet readers after their async drivers
  stop; lifecycle tests cover an abandoned start, normal close, runtime unwind, bind failure and
  a fresh stack after retry, without using OS thread names as an ownership oracle.
  What is not proven here is a stack-to-stack round trip against a third-party controller or peer
  — none is available in this environment — and `planet`, `physical-mtu`, `low-bandwidth`,
  `encrypted-hello` and `remote-trace-target` are refused in `ZeroTier::new` rather than run without them.
- **Tailscale:** the engine is in. `crates/adapter-outbound/src/tailscale.rs` drives
  `geiserx_tailscale` 0.57.7 (`tsnet` feature) - `tsnet::Server` for the node lifecycle and the
  crate's `Device` for the client calls the module needs — and the module doc maps each step onto
  the call it became. Adopting it is the one reason the workspace floor is 1.94 rather than 1.89:
  the crate declares `rust-version = "1.94.1"` and `edition = "2024"`. What the engine has no
  counterpart for is recorded there as deviations — the system dialer, the system packet listener,
  the lookup hook, extra root CAs, the logging hooks, and the host-info and interface-monitor hooks
  — so `interface`, `routing-mark` and `dialer-proxy` cannot carry the node's control, DERP or
  underlay traffic; `Tailscale::new` warns when one is configured rather than dropping it silently.
  `exit-node: auto:*` fails closed in `apply_prefs` with the missing pref named, and the engine
  refuses to build a `Device` unless `TS_RS_EXPERIMENT=this_is_unstable_software` is in the
  environment, which `init` and `Tailscale::new` set.

Everything else the configuration format supports — the shadowsocks family, Trojan, VMess (both
directions), VLESS, AnyTLS, Snell, ShadowsocksR, SOCKS5, HTTP, sudoku, gost-relay, MASQUE, OpenVPN,
WireGuard, SSH (via the `russh` crate), shadow-tls v1/v2, JLS, REALITY (see the caveat above), and
Restls both as an obfs mode on the shadowsocks and Snell outbounds and as a `restls-opts` block on
the VLESS, Trojan, VMess and AnyTLS dialers — has a real implementation and is exercised by the
test suite.

AnyTLS UDP uses the UOT v2 request's SOCKS address families (`1/4/3` for IPv4/IPv6/domain),
distinct from the subsequent datagram families (`0/1/2`). Independent byte fixtures in
`crates/sing/src/lib.rs` cover encoding and decoding both mappings against sing v0.5.7,
including both request connect flags. An isolated ARM router smoke with the full 171-node
configuration verified the previously failing AnyTLS node returned valid UDP DNS and an exact
65,536-byte HTTPS body; this is evidence for that exercised node, not every provider.

## Known limitations

These are cases where this build intentionally or knowingly differs from the reference:

- **Windows path cleaning:** `clean_path_windows` keeps all separators as `/` rather than
  canonicalizing them to `\` mid-algorithm, so for a pathological relative input with a colon after
  a dotdot, such as the relative path between `ab:/` and `ab:/x`, the platform's own rules yield `..\ab:\x` and this
  build yields `x`. Colons are illegal in Windows relative path components, so this is unreachable
  in practice.
- **Windows path cleaning:** `rel_path` exits its cursor loop when both cursors reach the end, where
  the straightforward algorithm loops forever for a share root compared with its trailing-slash form
  (the relative path between `//nas/share` and `//nas/share/`). This is deliberate: this build refuses rather than hangs.
- **`common/sockopt` `udp_reuseaddr` on Windows:** Sets SO_REUSEADDR on Windows UDP listeners
  (commit db7f73e9). Before that commit nothing was set on Windows.
- **`component/age` hybrid identity unwrap:** A hybrid identity that fails to unwrap returns a
  hard error, so decryption stops before trying later X25519 identities rather than continuing
  through them. Pre-existing limitation of the crate used.
- **`component::power` is uncalled.** The package (`crates/component/src/power`) is an
  embedder-facing library API and nothing in this tree calls it: no module outside it references it.
  The binary registers no suspend/resume listener. `make clippy-windows` builds the Windows half
  (`x86_64-pc-windows-gnu`), but no test exercises it: registering the notification and taking the
  callback needs a real Windows host, so the unregistration path is compile-verified only.
- **`component-memory` BSD files:** eleven of the crate's seventeen source files sit behind
  `#[cfg(target_os = ...)]` and `#[cfg(target_arch = ...)]` gates that nothing in this repository
  selects: all nine BSD arch tables, both BSD backends, and the non-Linux/macOS/BSD fallback stub.
  No CI job, no release job, no flake devshell and no Make target names a BSD target, and adding one
  from here fails because the nixpkgs cross `clippy` derivation cannot link against the build
  platform's LLVM. Changes to that code are therefore review-only: never compiled, never linted,
  never tested here.
- **QUIC incoming streams:** the configured ceiling is `1<<60` for trusttunnel's h3,
  `(1<<32)-1` for TUIC, and the same shape of value for ShadowQuic and Hysteria2. `quinn`
  materialises one stream-table entry per admitted stream id
  (`quinn-proto-0.11.18/src/streams/state.rs`), so `1<<60` would hang the server while `VarInt::MAX`
  exceeds `quinn_proto::MAX_STREAM_COUNT` and is rejected by the peer. All four servers instead
  clamp the admitted ceiling to `1<<12` at the quinn boundary
  (`crates/transport-trusttunnel/src/quic.rs`, `crates/transport-tuic/src/quic.rs`,
  `crates/transport-shadowquic/src/quic/conn.rs`, `crates/transport-hysteria2/src/service.rs`), so
  more than 4096 concurrent incoming streams on one of those inbounds is refused rather than
  hanging.
- **`/debug/pprof` is partial.** `cmdline`, `profile` (a live SIGPROF profile through the `pprof`
  crate, gzipped pprof protobuf), `symbol` and the index are served with the reference's shapes,
  plus the reference's exact 404 for an unknown name; `trace`, the six runtime profiles (`allocs`,
  `block`, `goroutine`, `heap`, `mutex`, `threadcreate`) and `/debug/vars` answer **501 with the
  missing thing named**, because the Rust runtime exposes no trace stream, no runtime profile
  registries and no process-wide variable registry (`crates/hub/src/route/pprof.rs`). The index
  also lists only the routes that answer here, the CPU profile drops libc/libgcc/pthread/vdso leaf
  frames, `seconds` is read from the query string only (the reference's form lookup would read a
  POST body too), and Windows answers 501 for `profile` and `num_symbols: 0` for `symbol` instead
  of a fake profile.
- **`/ui` (mounted when `ext-ui` names a directory) is a static file server minus five details.**
  Content-Type comes from the extension table alone (no content sniffing, so an unknown extension
  is `application/octet-stream`); a multi-range request returns the whole file (200) instead of
  `multipart/byteranges`; date parsing accepts only the HTTP date format (no RFC 850/ANSI C); a
  directory without an `index.html` answers 404 instead of the reference's directory listing; and
  `/ui` and `/ui/*` answer HEAD where the reference's GET-only routes return 405.
- **`hysteria2-realm` requires a `token`, and a realm client requires `realm-opts.server-url`.**
  Neither has a default, so both fail closed at load — "has unset fields: token" and "create control
  client: control server URL is required" — rather than starting with an empty credential. The
  schema makes the inbound token required as well; they are recorded here because such a config
  simply does not load.
- **TUN `stack: gvisor` and `stack: mips` name the same smoltcp engine.** This build has no gVisor
  crate, so both drive `murmur-component-wireguard`'s smoltcp stack, while `system` and `mixed` are
  refused. At most 1024 TCP ports can be armed at once (the in-flight forwarder's bound), and a SYN
  past that is dropped and counted instead of being answered with an ICMP error.
- **`-v` says `with rustc <version> <time>`.** The line is
  `murmur <VERSION> <os> <arch> with rustc <RUSTC_VERSION> <BUILD_TIME>`, using `RUSTC_VERSION`
  from `crates/murmur/build.rs`; the reference prints its own runtime version there. `META`,
  `VERSION`, `BUILD_TIME` and `PROJECT_NAME` live in `crates/constant/src/version.rs`, and the
  header of `crates/murmur/src/main.rs` documents the line.
- **A hijacked websocket upgrade carries hyper's `Date` header.** The reference writes the 101 by
  hand, so `/connections`, `/logs`, `/traffic` and `/memory` answer it without a date. Everything
  else about those six endpoints matches byte for byte, re-compared as described below.
- **A failing nameserver query reports the resolver library's error text.** With
  `nameserver: [127.0.0.1:1]` and a query, the reference answers 500 with `read udp
  127.0.0.1:…->127.0.0.1:1: connection refused`, this build with hickory's wording (`context
  canceled or deadline exceeded`, or `i/o timeout`). Statuses and the decision to fail agree; only
  the message text differs. The `[DNS] <ips> <type>` log line itself is `[1.2.3.4 5.6.7.8] A`, a
  space-separated bracketed slice, pinned by a unit test in `crates/dns/src/util.rs`.
- **`transport-kcptun` rewrites an unrecognised `crypt` name to `aes`.** The `match` over the
  configured name has a final wildcard arm
  (`crates/transport-kcptun/src/common.rs:208-211`) that sets the name to `aes` and builds an
  AES-256-CFB cipher. An operator who
  misspells `crypt`, or configures a cipher this build does not know, gets a tunnel running under a
  cipher they did not ask for, and the config reported to the controller names `aes` as though that
  were what was configured.
- **`IpCidrTrie` has no production consumer.** `crates/component-trie/src/ipcidr_trie.rs` and
  `ipcidr_node.rs` are reached only from the Criterion benches
  (`crates/component-trie/benches/domain_match.rs:280` and
  `crates/transport-vless/benches/support/metric_fixture.rs:95`); production IP-CIDR matching goes
  through `murmur_component::cidr::ipcidr_set::IpCidrSet`, an interval set rather than a trie.
  `publish = false` in the workspace manifest, so removing the two modules is not a semver break.
- **Dead `pub` items inside `pub` modules are invisible to this gate.** `Ipv6` at
  `crates/component-trie/src/ipcidr_trie.rs:9` is the worked example: it has exactly one occurrence in
  the crate and no user, yet `unreachable_pub` (warn, `Cargo.toml:203`) cannot flag it, because the
  lint measures whether a `pub` item is reachable *outside its crate*, not whether it is used. The
  usage lint that would catch it, `dead_code_pub_in_binary`, is off by design at `Cargo.toml:214`
  because every crate here but `murmur` is a library. So a `pub` type reached only through a `pub mod`
  is dead code no configured lint reports.
- **`put_buffer` retention is real, and shrinking it is measurably the wrong trade.**
  `crates/common-pool/src/buffer.rs:18` calls `clear()`, which zeroes `len` but keeps `capacity`, and
  one pool of 64 slots serves every caller of it. Measured in `buffer_pool`: after a single 64 KiB
  buffer is handed back, **8 of 8** subsequent small `get_buffer()` calls return a 65536-byte buffer,
  where an untouched 64-byte buffer would have sufficed; in an 8-slot ring with one slot poisoned,
  **8 of 8** gets come back large. So one oversized write raises what every later small caller pays
  in memory.
  It does not raise what it pays in time: staying pooled measures **21.5 ns** against **373-377 ns**
  to reallocate 64 KiB back to 64 B across two runs, so a shrink threshold would cost about **17x**
  on every crossing. The ceiling at `buffer.rs:21` means a buffer above 64 KiB is dropped rather than
  pooled, so this is retention inside the pool, not unbounded pinning. The reference differs
  structurally: it puts into a pool the garbage collector can drain, whereas this pool is a `Vec`
  that holds its slots until the process exits. Fixing the retention means shrinking,
  and the measurement says the fix costs more than the retention does; leaving it is deliberate, not
  an oversight.
- **`rev_lower_at` was never quadratic.** Commit `5b6cc87` replaced
  `key.iter().rev().nth(i)` with direct indexing in
  `crates/component-trie/src/domain_set.rs:307` under the claim that the old form was a quadratic
  walk. That claim was wrong. `Iterator::nth` on a slice-backed `DoubleEndedIterator` is random
  access, so the old code was O(1) per call as well. Measured in the pinned toolchain at 5M
  iterations on a 26-byte key: `nth` 60 ns, direct indexing 30 ns — the direct form is about 2x
  faster per call but **constant**, not quadratic. End to end, Criterion puts every delta in
  `domain_match` inside a 0.17% noise floor, at key lengths of 64 B and 1039 B as well as the
  original short keys. The rewrite is kept because it is simpler and marginally cheaper; the
  performance rationale for it was wrong.
- **`put` did not wipe pooled blocks, so one connection could read another's bytes.** Fixed in
  `52bf316`. `crates/common-pool/src/alloc.rs` zeroed a returning block with
  `buf.resize(capacity, 0)`, and `Vec::resize` writes only the tail past the current `len`. A block
  handed back with `len < capacity` therefore kept its contents, and the next `get` returned them to
  an unrelated caller. On the crate's own test shape, a 1024-byte block truncated to 1023 left **1023
  of 1024 bytes** non-zero; with `len == capacity` the resize was a no-op and nothing was zeroed at
  all. The struct's own doc claimed the pool was "optimized to prevent overwriting after zeroing",
  which was false for every short block. The fix clears the length before resizing, so the wipe
  covers the whole block. This was a real information-disclosure path between connections, not a
  performance tweak; the reference does not zero at all, and its comment carries a
  a suppression directive for the same unchecked pattern, so this guarantee had to be established here.

