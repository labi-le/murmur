# murmur

murmur is a Rust proxy core. It reads the Clash-compatible YAML configuration format and exposes
the matching HTTP control API, so configs and controller clients written for that interface drive it
unchanged: the same `proxies` / `proxy-groups` / `rules` sections, the same `mixed-port` and
`external-controller` keys, the same `/proxies`, `/configs`, `/rules`, `/connections` and `/logs`
endpoints. That compatibility is deliberate — it is what lets this binary run side by side with
another implementation of the same interface against real proxy servers, and be checked against it,
rather than only against its own test suite. Where this document needs a baseline for a
compatibility claim it says **the reference**: another implementation of that interface, which
`tools/diff_sweep.py` (see [Verification](#verification)) can start and probe beside this binary,
and `tools/e2e_vm.py` drives both through a fixed set of controlled scenarios in a disposable
QEMU guest.

Internally the design is idiomatic Rust: closed enums where a dynamic dispatch would otherwise be
needed, `Option` for absence instead of a zero value, typed errors instead of stringly-typed ones,
and `unsafe` denied outside a handful of justified, audited exceptions. Code paths that were carried
but never reached were deleted rather than kept.

## Building and running

```
nix develop .        # rustc/cargo/clippy/rustfmt + cargo-deny/audit/machete/nextest/typos/sccache
cargo check --all-targets
cargo test --workspace
cargo build --bin murmur --release
./target/release/murmur -f /path/to/config.yaml
```

On the shared development hosts, compile only on `pc`: from `rust/`, run
`tools/cargo-slot cargo check -j 2 --all-targets` (or substitute `test`/`build`).
The wrapper holds a shared remote build slot, enters this project's Nix shell on
`pc`, and uses its sccache configuration. Build artifacts live in the remote
Cargo target directory, not the local `./target` shown above. Direct SSH Cargo
commands bypass the slot limit.

The workspace floor is `[workspace.package] rust-version = "1.94"` with
`edition = "2021"`, inherited by every crate. It moved from 1.89 to 1.94 for one
reason: the Tailscale engine is `geiserx_tailscale` 0.57.7 (`tsnet` feature), whose
own manifest declares `rust-version = "1.94.1"` and `edition = "2024"`. The dev
shell that actually compiles the workspace — the toolchain `flake.lock` pins — is
`rustc 1.97.1` / `cargo 1.97.0`, so an API stabilised after 1.94 but at or before
1.97.1 compiles here and still breaks the declared floor. `RUST_GUIDELINES.md`
Section 12 carries the allowed/blocked list; there is no `rust-toolchain.toml` pin.

The binary is `murmur`. `-f` names the config file, `-d` the working directory, and `-t` parses and
validates a config, then exits without starting the proxy — `crates/hub/src/executor/testdata/`
carries the `e2e_supported.yaml` fixture that exercises every supported protocol family in that
mode. `-v` prints version and build metadata.

`--watch-config` reloads the main configuration file automatically. It is off by default, so the
configuration a process already applied stays in force until a `SIGHUP` or a `PUT /configs` call,
exactly as before. With the flag set, the path `-f` resolved at startup (a relative name joined
onto the working directory, then canonicalized) is watched for the life of the process, and every
change that settles reloads it through the same entry point a `SIGHUP` takes: the file is parsed
again, the startup CLI overrides are reapplied and the external controller is reconfigured.
`-f -` (stdin) and `--config` (base64) keep the configuration in the process arguments, and watch
mode is refused for them with an error instead of falling back to a default path.

The watcher follows the parent directory of that canonical path and filters events down to the
file itself, so atomic replacement by an editor or a configuration generator, a burst of writes
and a file deleted then recreated all reload, while sibling files, reads and opens do not. The
bytes the process applied at startup count as applied, so saving that same file again is skipped
instead of reapplying it over a runtime change made through the API. A truncated, malformed or
unreadable file is not applied and leaves that cache of applied content alone: nothing ran, so the
running configuration still matches it and a later save of those same bytes is still skipped. A
configuration that parsed but whose listeners or external controller could not bind is also not
applied, but it clears the cache, because the failed apply may already have closed or replaced
listeners; restoring the last good file therefore reapplies it. In both cases the specific error is
logged, and saving the bytes again retries them once the cause is gone. A completed reload means the
file parsed and every part it named applied; the apply steps that can
report a failure (inbound listeners, tunnels and the controller transports) report it to the
caller, while a `tun` section the device refuses stays the documented degradation that clears
`enable` in the stored conf. Because the watcher follows the canonical path, replacing the symlink itself is
not observed; replace the target file.

Every parse-and-apply, watched or not, holds one process-wide lock (`hub::lock_config_operation`)
that the API updates take as well. During parsing, only the candidate geodata settings are
published temporarily for rule construction and restored on return; live routing mode, resolver
and dialer settings stay unchanged until apply. The lock prevents another configuration operation
from interleaving with that temporary state. A malformed nonempty `ss-config` or `vmess-config`
fails apply instead of disabling its existing listener; an empty value disables it explicitly.
While watch mode is on, `PUT /configs` with
a `path` or a `payload` still applies to the running process and does not move the watcher, so the
next real file change replaces those API-only settings. `--watch-config` together with `-f -` or
`--config` is refused before the configuration is read, so it never waits for stdin. Rule and
log-level changes keep the PID and leave existing listeners and established flows in place; a
changed listener, TUN or tunnel address may have to recreate its socket.

### ARM64 OpenWrt builds

The `aarch64-musl` shell supplies the cross compiler and target standard library for
64-bit ARM routers. On the shared hosts, keep compilation inside a remote slot:

```bash
CARGO_TARGET_DIR=openwrt-aarch64-musl \
CARGO_PROFILE_RELEASE_STRIP=symbols \
tools/cargo-slot bash -c 'nix develop .#aarch64-musl --command cargo build -j 2 --locked --release -p murmur --bin murmur --target aarch64-unknown-linux-musl'
```

The artifact is on `pc` at
`/home/labile/.cache/cargo-pc/openwrt-aarch64-musl/aarch64-unknown-linux-musl/release/murmur`.
Check it with `file` and `readelf -l -d` before installing: a portable static build
must not require a `/nix/store` interpreter or shared libraries. The shell sets
`RUSTFLAGS` explicitly because an inherited empty value overrides Cargo's
target-specific static-link flags.

OpenWrt integration needs separate firewall and service configuration. Keep
`iptables.enable: false` when fw4/nftables owns interception, install the
`kmod-nft-tproxy` kernel package and configure both the capture fwmark's policy
route and a different outbound `routing-mark`. Forward dnsmasq to murmur's DNS
listener with caching disabled for fake-IP answers. Seed every rule provider
before exposing DNS; file providers can carry the same entries in `payload` to
make their rules available before asynchronous file loading. Bind the controller
to loopback and restrict proxy/DNS ports to the intended client network. An
IPv4-only policy also needs an explicit IPv6 forwarding policy.

Health checks send HEAD requests to the configured origin, with an origin-form
path/query and a `Host` header carrying its authority, including a nondefault
port or bracketed IPv6 literal. An HTTP response outside `expected-status` can
still produce a measured delay, but its per-URL health state is unhealthy; use
that state rather than a nonzero delay alone to validate node availability.

File-provider watchers schedule updates on their owning Tokio runtime, not on
notify's OS thread. They watch the provider's parent directory and filter by
path, so successive atomic replacements keep working. Read/open events do not
trigger refreshes; content changes and write-close events do. Dropping the
provider releases its watcher without requiring a separate close call.

Fake-IP reloads preserve the allocator cursor alongside mappings. A persistent
pool skips occupied addresses when its saved cursor is stale or absent, and
serializes misses across old and new pools that share a cachefile. Existing
destinations remain assigned to their original names until normal pool reuse.

The common recipes are `make` targets: `check`, `fmt`, `fmt-check`, `clippy`,
`test`, `nextest`, `test-heavy`, `gate` (`fmt-check nextest clippy hygiene`), `gate-full`,
`hygiene`, `deny`, `machete`, `audit`, `typos`, `lint`, `act-test`, `test-windows`,
`clippy-windows` and `all`. The `Makefile` documents each one inline, including why `hygiene` is
non-blocking.

## Workspace layout

`rust/Cargo.toml` is a virtual workspace: 89 member crates under `crates/`, every inter-crate
dependency a path dependency, and shared `[workspace.package]` and `[workspace.lints]` settings
inherited by all of them. There is exactly one binary crate (`crates/murmur`); the other 88 are
libraries.

The crates group as follows.

| Group | Crates |
| --- | --- |
| Entry point | `murmur` — the binary: CLI, config-test mode, signal handling, shutdown |
| Configuration | `config`, `listener-config` |
| Controller API | `hub` — the Clash-compatible HTTP/websocket controller |
| Proxies | `adapter`, `adapter-inbound`, `adapter-outbound`, `adapter-outboundgroup`, `adapter-provider` |
| Inbound listeners | `listener`, `listener-inner`, `listener-sing`, `listener-tproxy` |
| Wire protocols | `transport`, plus one `transport-*` crate per protocol (anytls, hysteria, hysteria2, jls, kcptun, masque, mekya, mkcp, openvpn, shadowquic, shadowsocks, shadowtls, simple-obfs, snell, ssr, sudoku, tlsmirror, trusttunnel, tuic, vless, vmess, xhttp) |
| Protocol engines | `jls-tls`, `reality`, `restls`, `mieru`, `zerotier`, `easytier`, `quic`, `kcp`, `smux`, `sing-mux`, `sing`, `yamux` |
| Rules and DNS | `rules`, `rules-common`, `dns` |
| Shared services | `component` and the `component-*` crates (tls, wireguard, ca, geodata, fakeip, sniffer, nat, mmdb, process, profile, updater, resource, trie, memory, http, generator, ech, loopback, proxydialer) |
| Infrastructure | `common` and the `common-*` crates (`common-net`, `common-pool`, `common-httputils`, `common-convert`, `common-callback`), `std-compat`, `compat`, `constant`, `constant-features`, `context`, `log`, `ntp`, `ws` |
| Test support | `testsupport`, `testsupport-probe` |

## Architecture

A run starts in `crates/murmur`: it parses the command line, resolves the working directory, reads
`config.yaml` through `crates/config` (which owns the schema for everything the format can express),
and builds the shared runtime state in `crates/context`. From there:

- **Inbound.** The `listener*` crates bind what the config names: the mixed port (SOCKS5, HTTP
  CONNECT and HTTP proxy on one port), the dedicated SOCKS/HTTP/redirect/tproxy ports, the
  per-protocol inbounds in `crates/listener/src/inbound`, and the TUN device
  (`crates/listener/src/tun.rs`). Each accepted connection becomes a stream and is handed to the
  tunnel.
- **Selection.** `crates/rules` matches the connection against the `rules` list and resolves the
  chosen `proxy-groups` member, which `adapter-outboundgroup` and `adapter-provider` keep current.
- **Outbound.** `crates/adapter-outbound` holds one adapter per proxy type; each dials through a
  crate in `crates/transport*` or the protocol engine it needs, with TLS supplied by
  `crates/component-tls`.
- **Control.** `crates/hub` serves the controller API, the websocket/log endpoints and the HTTP
  executor that applies `PUT /configs` and `PATCH /configs` at runtime.
- **Support.** `crates/dns` (resolution, hosts, fake-IP), the `component-*` crates (geodata, mmdb,
  sniffer, nat, resource) and `common*` / `std-compat` (buffers, connection wrappers, socket
  options) sit underneath those.

## Correctness invariants

These hold everywhere in the tree, not just in the newest code, and a change that needs to violate
one of them needs a different design instead:

- **No `unsafe`.** `unsafe_code` is denied crate-wide, including via a local
  `#[allow(unsafe_code)]`. The few syscall-level exceptions that exist are isolated in one small
  function each, with a safety comment justifying the exact invariant the surrounding code
  maintains.
- **Never hold a `parking_lot` guard across an `.await`.** This includes a guard held indirectly
  through a helper that then awaits, and a guard held across an `.await` inside a `select!`
  branch. A `parking_lot::Mutex` guard is not `Send`-safe to hold across a suspension point the
  way a `tokio::sync::Mutex` guard is, and doing so anyway either fails to compile or deadlocks.
- **No new `.unwrap()` / `.expect()` on a fallible runtime path** — I/O, config, network input,
  anything an attacker or a misconfigured user controls. `expect()` is reserved for invariants
  that genuinely cannot fail, with a message naming which invariant.
- **No silent degradation.** A code path that cannot do what it claims — a missing dependency, a
  downcast that was supposed to succeed, a handshake that was supposed to authenticate — fails
  closed with an error naming the reason. It does not fall back to a weaker but working-looking
  behaviour. This is why the protocols listed below fail with a named reason instead of silently
  running unencrypted or unauthenticated.
- **No weakening a test to make it pass.** If a change makes a test fail, the test found a real
  behaviour change. A test that only pinned an incidental detail — a specific wording, an
  implementation artifact rather than a contract — is deleted outright rather than kept and
  re-pinned to new text.

## Hazards found under load

Six kinds of bug have shown up repeatedly in this tree, each costing real debugging time before its
root cause was understood. Each is a case where code compiled, type-checked, and passed under light
load, and then broke under a load shape it did not preserve.

1. **A lost guarantee.** `tokio_rustls`'s `TlsStream` behaves like a buffered writer: `poll_write`
   can report the plaintext as consumed while the ciphertext is still sitting in an internal
   buffer, and only `poll_flush` guarantees it reaches the peer. A `write_all(...).await` with no
   following flush strands a fraction of requests in the TLS buffer forever under concurrency. This
   was found once in the VMess WebSocket client, then found six more times elsewhere in the tree by
   an audit for the same shape (write, then await a reply, over a TLS-wrapped connection).
2. **Lost cardinality.** Where the model has a slice, a map, or an explicit pool, an
   implementation that collapses it to a single instance is wrong even when every test passes. The xhttp
   transport's HTTP/1.1 client pinned exactly one physical connection because that was the natural
   way to model "the thing a round trip uses"; a real HTTP client transport is a connection pool
   that dials as many physical connections as concurrently in-flight requests need. HTTP/2 hid the
   bug entirely — one real multiplexed connection is genuinely enough for concurrent requests — so
   every test using an HTTP/2-shaped mode passed. The first HTTP/1.1 xhttp mode needing two
   concurrent requests on "one" transport deadlocked. The fix added a small on-demand connection
   pool rather than a single connection.
   A later sustained-transfer gate exposed a related completion hazard: stream-up and packet-up
   pre-polled their download request to claim a pooled connection, then unconditionally awaited
   it again in a spawned task. If that first poll returned `Ready`, the second poll panicked and
   stranded the download reader. The handoff now delivers a captured ready result exactly once
   and awaits only a pending request. The 30 XHTTP tests and a standalone real-TCP smoke with
   distinct 2 MiB upload/download bodies in all three modes verify the corrected path.
3. **A double bind.** The trusttunnel HTTP/3 server took an already-bound UDP socket from its
   caller, then called `quinn::Endpoint::server(server_config, local_addr)` — which binds its own,
   second socket at that address — and closed the original as unused. Two sockets existed where the
   caller had passed one value along. The fix converts the already-bound socket into a raw
   `std::net::UdpSocket` and hands it directly to `quinn::Endpoint::new`, so only one bind ever
   happens.
4. **Cancel-unsafety.** `h3::client::RequestStream::recv_data` is an `async fn`; a `poll_read` that
   boxes a fresh call to it on every poll and drops that boxed future whenever polling returns
   `Pending` is not cancel-safe. Dropping a `recv_data` call mid-flight discards bytes it already
   pulled off the QUIC stream without ever delivering them to the caller, which desynchronizes
   every HTTP/3 DATA frame boundary after the first short read. The fix keeps the same future alive
   across polls instead of rebuilding it, and holds back any leftover bytes from a chunk larger
   than the caller's buffer rather than dropping them.
5. **Indistinguishable states.** A header lookup that returns `""` for a missing header cannot tell
   "the caller supplied no Host header" from "the caller supplied an empty one" — and the config
   schema lets a user write an empty `Host:` line by omission (a zero-valued struct field) as
   easily as on purpose. An `is_empty()` check on the decoded header value carried that ambiguity
   forward and then resolved it the wrong way in one case: an explicitly configured but empty
   WebSocket `Host` header was treated as "present but empty" and sent as-is instead of being
   replaced with the randomized default host, changing observable behaviour. The fix treats an
   empty `Host` value as absent, which is what the call sites actually intended.
6. **A carrier the target library throws away.** `hyper`'s h2 client keeps a CONNECT request's body
   for the response's upgrade and never polls it, and its h2 server swaps a CONNECT's request body
   for an empty one, discarding whatever the peer already sent. The trusttunnel client puts the
   tunnel's bytes in the CONNECT request's `Body` and reads the reply from the response body, so
   that code wrote into a stream nothing ever read, and the tunnel broke as soon as the staging
   buffer in front of it filled — the tunnel case failed on its very first plain-HTTP
   round trip with a broken pipe while writing the POST body, with the handshake, the
   authentication and the relay all looking healthy. The fix moves both halves onto
   `hyper::upgrade::on`, the one path where `hyper` hands back a real duplex handle for a CONNECT
   on the client and on the server, and the framing a peer already reads the same way.

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
`iproute2-*` indices and the auto-redirect marks. Opening a device needs the privileges
`/dev/net/tun` requires. TCP is carried: the listener drives `murmur-component-wireguard`'s smoltcp
stack — the engine both `stack: mips` and `stack: gvisor` name here, because this build has no
gVisor crate — from the device's own packets, and hands each connection it terminates to the
tunnel; UDP datagrams and the synthesised ICMP echo reply stay on the listener's direct path. The
`tun::` tests are 28 and the TCP one completes a real handshake through the listener's own stack
against a second smoltcp peer behind a fake device, so the path is proven without root or a real
`/dev/net/tun`.

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
leaving `murmur-restls` at 59 lib tests plus its interop tests green. The superseded
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
| VMess (client and server, AEAD-2) | `crates/transport-vmess`'s AEAD-2 client and server, exercised by the crate's 42 tests, and the adapter dials through its real AEAD-2 client | a third-party VMess client or server: every round trip is this build against itself |

REALITY is implemented on both halves in `crates/reality`: the client splices its own `ClientHello`,
the server authenticates real `utls` clients, and the record layer reads the content type as the
last non-zero octet — which is what a REALITY server's zero-padded records require, and what the
reference's `utls` implementation does. A live dial against a third-party peer is not part of this
tree's automated checks, so the client's evidence in the suite is a replay of the reference's exact
wire shape.

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
  ad-hoc network. What is not proven here is a stack-to-stack round trip against a third-party
  controller or peer — none is available in this environment — and `planet`, `physical-mtu`,
  `low-bandwidth`, `encrypted-hello` and `remote-trace-target` are refused in `ZeroTier::new`
  rather than run without them.
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

## Component benchmarks

Eight crate-local [Criterion](https://criterion-rs.github.io/book/) targets exercise production
APIs without changing the proxy's public interfaces:

| Target | Workloads |
| --- | --- |
| `vless` | IPv4/domain/IPv6/UDP/MUX first-write request framing; established memory-stream writes; Vision padding encode/decode/roundtrip at 64 B, 1 KiB and 16 KiB; VLESS AES-256-GCM and ChaCha20-Poly1305 seal/open/roundtrip |
| `domain_match` | DomainSet/DomainMap/DomainTrie lookup over 10,000 generated patterns plus boundary cases; builds at 100/10,000 patterns; IPv4/IPv6 CIDR hit/miss |
| `fakeip` | In-memory lookup hit and bounded eviction/miss, reverse lookup and existence; the miss workload rotates 8,192 hosts through a 256-entry pool across measurement batches |
| `rule_match` | Ordered mixed-rule scans with 16/256/1,024 rules, matching first/last or missing; no DNS or network resolution |
| `buffer_pool` | Buffer get/put, fill, and cold allocation/free at 64 B through 128 KiB, including an unpooled size above the 64 KiB ceiling; BytesMut recycling |
| `rule_wrapper` | A bare rule chain against the same chain inside the production `RuleWrapper`, at 16/256/1,024 rules, on a full-chain miss and on a steady all-hit streak. The miss case pays a clock reading per rule because the streak gate is cold; the hit case pays it once per 256 matches |
| `udp_path` | The per-datagram metadata path the UDP entry point walks |

Three further targets are not Criterion and are not part of `make bench`:

| Target | Output |
| --- | --- |
| `alloc_census` (`make bench-alloc`) | Heap allocations per operation from `dhat` as the global allocator: `Metadata::clone`, `DomainSet::has` and `DomainMap::lookup` in ASCII and upper-case, and rule-chain scans at 16/256/1,024 rules on a first-rule hit and a full-chain miss. Prints the measured figure beside the hand count for `Metadata::clone` so a disagreement between arithmetic and measurement is visible |
| `dialer_alloc_census` | The same shape for the dialer and resolver: option application, the address helpers each attempt runs, the hosts-table search each lookup starts with, and the literal-IP short circuit. Every connect path is reported as unmeasured, because each ends in a real connect; the upstream DNS leg is reported as unmeasured too, because a bench can only supply a trait stub whose own allocations would be inside every figure |
| the metrics pair | Documented under [Measurement](measurement) |
| `unsafe_removal_parity` | The descriptor open and close the `anet` ioctl paths perform today, as the cost a socket2 replacement would carry: TCP stream, datagram and raw netlink opens, an owned-descriptor close, an open-then-close pair, and bind-plus-listen for scale. The current implementations cannot appear in the bench at all, because the workspace denies unsafe code and a benchmark target inherits that lint, so every figure is a socket2 formulation; the two TCP fastopen option sites are reported as not removable rather than given a fabricated ratio |

Run from the workspace root; compilation and measurements happen on `pc`, not locally:

```bash
CARGO_TARGET_DIR=bench-vless-core tools/cargo-slot make bench-smoke
CARGO_TARGET_DIR=bench-vless-core tools/cargo-slot make bench

# A single target, or a named baseline for later comparisons:
CARGO_TARGET_DIR=bench-vless-core tools/cargo-slot cargo bench -j 2 \
  -p murmur-transport-vless --bench vless -- --save-baseline before
CARGO_TARGET_DIR=bench-vless-core tools/cargo-slot cargo bench -j 2 \
  -p murmur-transport-vless --bench vless -- --baseline before
```

`bench-smoke` executes each workload once, including its untimed correctness checks.
`bench` collects timing statistics; `BENCH_ARGS` forwards Criterion options such as
`--warm-up-time 1 --measurement-time 2 --sample-size 30`. Fixtures, keys, runtimes and lookup
tables are prepared outside timing; domain-build cases deliberately measure insertion and
construction. Criterion stores estimates and baselines under the remote target directory's
`criterion/` subtree (`/home/labile/.cache/cargo-pc/bench-vless-core/criterion/` above).
Compare only runs on the same machine with the same build options and similar competing load.

These are CPU/component microbenchmarks, not TCP/TLS/REALITY handshake latency or real-network
bandwidth. Vision uses fresh framing state over memory transports, not a TLS direct-handoff
session. Throughput counts useful input bytes (or operations), not padding/wire overhead.
Criterion measures timing/throughput only; the separate measurement suite below adds allocation
and benchmark-process memory metrics, not the running proxy's RSS.
VLESS/Vision cases include the memory transport and per-iteration connection/buffer teardown;
they are not isolated codec instruction timings.
The rule suite includes both the original empty-helper groups and
`rule_chain_populated/{16,256,1024}/{first,last,miss}` with populated cached-resolution hooks.
The suite currently declares **49 `bench_function` sites** across the eight Criterion targets; several
sit inside loops, so the number of workloads Criterion actually runs is higher than that. The
populated groups still exclude DNS and OS process I/O.

Initial baseline measured on 2026-10-04: Ryzen 7 9800X3D, rustc 1.97.1, default optimized
bench profile, 1 s warmup, 2 s target measurement and 30 samples per case, saved as `initial`.
That baseline was recorded against an earlier tree and does not cover the targets added since; its
figures below are kept as the historical record they are, not as a current measurement. Selected
Criterion point estimates (not deployment guarantees):

| Workload | Time |
| --- | --- |
| VLESS IPv4 first-write framing and peer drain | 1.223 µs |
| Vision padding encode, 1 KiB | 957 ns |
| AES-256-GCM seal, 16 KiB | 3.644 µs (4.19 GiB/s useful input) |
| DomainMap exact lookup, 10,000-pattern fixture | 89.1 ns |
| Fake-IP lookup hit / bounded miss | 99.1 ns / 204.4 ns |
| Last-rule match in a 1,024-rule chain | 14.50 µs |
| Pooled 16 KiB buffer get/put, without payload fill | 22.05 ns |

### Additional measurement suite

`tools/bench_metrics.py` runs 24 isolated workloads through two optimized, `harness = false`
targets: `metrics_cpu` uses the normal allocator, while `metrics_heap` installs
[dhat](https://docs.rs/dhat/latest/dhat/) only in that benchmark executable. These two targets
are built by `make bench-metrics`, not by `make bench` or `make bench-smoke`; the Criterion
target list in `Makefile` deliberately omits them because this runner needs to harvest
executable paths itself and to keep the `dhat` allocator confined to `metrics_heap`. Production
binaries and Criterion targets do not use its allocator. The suite covers VLESS first/established
writes, fresh Vision encode/decode, AEAD, domain/IP lookup, fake-IP forward hits, reverse hits and
eviction at 256- and 1,000-entry capacities, rule scans and buffer reuse, plus a zero-work control
and a separately named stateful pipe diagnostic.
`rule_chain_256_miss_populated` complements the original empty-helper miss without changing it.

```bash
# The script owns its remote build slot; run this target without another cargo-slot wrapper.
make bench-metrics
make bench-metrics METRICS_ARGS="--smoke --workdir /tmp/murmur-metrics-smoke"
python3 tools/bench_metrics.py --case domain_map_lookup_exact \
  --case rule_chain_256_miss --iterations 1000000 --heap-iterations 2000

# Symbolized CPU samples and allocation stacks for selected cases:
python3 tools/bench_metrics.py --hotspots vision_encode_16384 \
  --workdir /tmp/murmur-metrics-profile
```

Compilation and execution happen on `pc`; each case and allocator mode runs in a separate
process. The runner reads executable paths from Cargo's JSON artifacts, forces `LC_ALL=C` for
perf output, writes a private `0700` result directory, and fetches artifacts back when `/tmp`
is not shared. A missing mandatory CPU counter or invalid workload fails the run with an
error artifact; unsupported optional events are explicitly unavailable, never zero.

`results.json` and per-case logs contain:

- Measured-loop allocation calls and bytes per operation, from heap snapshots after setup
  and warmup; live bytes/blocks before and after distinguish churn from retained growth.
  Reallocation counts include the full new block size, not only its incremental growth.
- Heap high-water bytes from setup through the measured loop, before report emission;
  the accompanying block count is the number of blocks at that byte peak, not an independent
  block-count maximum. This is not a per-operation peak.
- Clean amortized batch elapsed time, with no per-operation clock or payload-sized hash;
  RSS before/after and lifetime HWM describe the benchmark process, not the full proxy.
- Perf task-clock, cycles, instructions, branch/cache events and scheduling/page-fault counters,
  including event modifiers and multiplexing percentages. These cover the **whole process**,
  including startup/setup/warmup; counter/operation ratios are amortized process totals.
- For `--hotspots`, `perf.data`, a text CPU report and DHAT allocation stacks. Small sample
  counts or startup-dominated profiles need a larger iteration count before drawing conclusions.

The counting allocator's instrumentation is never used for CPU timing. Persistent streams
enter Tokio once per batch, Vision framing state is fresh per operation, and fake-IP misses
rotate 8,192 hosts through a bounded 256-entry pool without resetting between measurement
batches. Memory sinks consume opaque slices but do not send/copy payloads: their logical input
rates are not network or memory bandwidth.

On the 2026-10-04 optimization batch, paired runs used 200,000 CPU / 2,000 heap operations
per case. Measured-loop allocation churn with unchanged workloads:

| Workload | Calls/op before | Calls/op after | Bytes/op before | Bytes/op after |
| --- | ---: | ---: | ---: | ---: |
| Established VLESS, persistent memory sink | 0 | 0 | 0 | 0 |
| AES-GCM seal/open and ChaCha seal, reused buffers | 0 | 0 | 0 | 0 |
| Warm 16 KiB buffer get/put | 0 | 0 | 0 | 0 |
| DomainMap exact hit | 3 | 0 | 15 | 0 |
| IPv4 CIDR lookup | 1 | 0 | 16 | 0 |
| Fake-IP hit | 3 | 0 | 50.535 | 0 |
| Complete miss through 256 mixed rules | 256 | 0 | 2,628 | 0 |
| Fresh Vision encode, 16 KiB | 13 | 8 | 33,672 | 864 |
| Established VLESS through compatibility pipe, 16 KiB | 5 | 4 | 33,312 | 16,976 |

These are production ownership changes, not different benchmark inputs. ASCII DomainMap
labels and fixed IPv4/IPv6 groups no longer allocate temporary vectors; Unicode normalization
and wildcard precedence stay unchanged. `Metadata::rule_host()` now returns `&str` and
`Rule::match_()` returns `(bool, Cow<'_, str>)`, preserving the existing adapter value on
both hits and misses. `LruCache::get()` takes a borrowed key, and `touch()` performs the same
expiry/recency updates without cloning a discarded value. Every in-tree Rust caller was migrated;
these Rust API ownership changes do not change configuration or controller payloads.
The CIDR traversal also avoids looking up each child twice.

Vision returns its owned scratch and queued buffers to the existing pool on connection drop,
keeps the UUID in an array and reuses the frame queue. Reverse TLS marker search checks up to
four candidate starts with `memrchr_iter`, then uses `memmem::rfind` on the remaining prefix
to bound work on dense false candidates. Fresh-frame allocations include the queue, benchmark
transport ownership and formatted debug events. Log subscribers still receive those events.
The pipe transfers its owned payload through the channel and returns the unread tail with
each acknowledgement instead of copying it again. The larger acknowledgement adds 20 bytes
to the tiny first-write IPv4 workload (6,456 to 6,476 bytes), while removing one allocation.

The measured allocation savings do not establish an end-to-end network speedup. Short
nanosecond-scale timing samples vary; in particular, removing the CIDR allocation alone is
not evidence of a faster lookup. Reports are in `/tmp/murmur-opt-baseline-20261004` and
`/tmp/murmur-opt-complete-20261004`; their `results.json` files retain operation counts and scope.

**Vision reverse marker search (2026-10-19, [#175](https://github.com/labi-le/murmur/issues/175)):**
the existing fresh 16 KiB encode workload measured 4,924 ns/op before and 1,521-1,571 ns/op
with the bounded candidate scan (1,000,000 CPU operations, 2,000 heap operations). The final
source measured 1,571 ns/op; a preserved baseline repeat measured 4,959. Allocations stayed at four calls /
376 bytes per operation. A dense 16 KiB false-candidate probe measured 9,244 versus 9,265 ns;
the unbounded candidate-only version was rejected after a 5.8x regression on that input.
Last-occurrence selection and frame boundaries are unchanged. These x86 microbenchmarks
include fresh connection state and do not establish ARM router throughput or retained heap.
Artifacts: `/drive/tmp/murmur-component-audit-20261019/vision-final` and
`/drive/tmp/murmur-component-audit-20261019/vision-baseline-repeat`.

The existing `vision_decode_1024` helper calls the concrete inherent `Conn::read`, not the
trait-based production relay path. Its per-operation `b.to_vec()` allocation is not evidence
of an allocation on every production `AsyncRead` call, whose scratch buffer is reused.
[#176](https://github.com/labi-le/murmur/issues/176) tracks separate fresh and steady-state
trait-based measurements without changing the existing workload identity.

**Vision forward marker search (2026-10-04):** the filter now skips non-candidate bytes with
`memchr_iter` and compares each complete candidate without changing marker priority or TLS state.
Paired 50-sample Criterion runs measured mean fresh encode latency of 14.073 to 6.362 microseconds
at 16 KiB (54.8% lower), 849.95 to 344.96 ns at 1 KiB (59.4% lower), and 361.81 to 329.25 ns at
64 bytes (9.0% lower). Mean 16 KiB decode latency fell from 9.113 to 1.328 microseconds.
All nine encode/decode/roundtrip workloads improved by more than 1% even using conservative
confidence bounds. Unconditional substring-searcher setup and a scalar-size threshold were
discarded after they regressed the smaller workloads. The filter runs only during the initial
packets; these are not steady-state network speedups. Paired evidence is retained in
`/tmp/murmur-auto-opt-20261004/vision-forward-comparison.json`; the updated binary also passed
the controlled VM transfer, routing, DNS and provider scenarios.

**Borrowed rule helpers (2026-10-04):** `Rule::match_` now takes `&RuleMatchHelper`, eliminating
per-rule ownership copies and three populated-hook `Arc` clone/drop pairs. Nested no-resolve and
source-IP rule sets still construct a local masked helper, preserving the sibling's resolver and
metadata swap/restore behavior. All implementations, callers and tests use the borrowed contract.
Paired 50-sample mean populated 256-rule miss time fell from 6.833 to 1.201 microseconds (82.4%
lower); the 1024-rule miss fell from 27.314 to 4.746 microseconds (82.6% lower). Empty-helper
cases also improved, but they never measured populated-hook refcount traffic.
The full workspace tests and controlled VM routing scenarios passed. Paired evidence is in
`/tmp/murmur-auto-opt-20261004/helper-comparison.json`.

**Pipe waiter lifecycle fixed (2026-10-04):** the shared close latch now uses the existing
`CancellationToken` primitive instead of a global `Vec<Waker>`. Dropping a `wait()` future
unregisters that waiter. Poll-based readers own independent cached cancellation futures,
replace their waker in place, and reset/reuse their pinned allocation after a completed receive.
Re-arming a fired deadline changes the signal identity and replaces the old subscription.
All active waiters still wake on close; no last-waker shortcut or waiter cap is used.
An errored/cancelled polling read may retain its last cached registration until replacement,
reset or connection drop, but registrations no longer accumulate with operation count.
Dropping a `PipeDeadline` aborts the timer it armed, and that timer holds the deadline state
weakly, so neither an abandoned task nor the state outlives the last owner of the deadline.

The unchanged `vless_established_pipe_16384` workload includes the compatibility pipe and peer
drain, not just VLESS. Before the fix, the waiter deduplication scan consumed 90.70% of sampled
CPU at 10,000 operations and 99.40% at 200,000. Entering Tokio once per batch did not fix it.
At the same 50,000 CPU / 2,000 heap operation counts, the new implementation measured
78.388 µs -> 1.354 µs per operation (57.9x), retained heap growth 378,880 -> 0 bytes,
and RSS 3,692 -> 9,680 KiB before versus 3,692 -> 3,692 KiB after. At 200,000 CPU /
4,000 heap operations, latency remained 1.383 µs and retained heap growth remained zero,
instead of the previous 306.614 µs at 200,000 operations.

There is a setup tradeoff: the tiny first-write IPv4 pipe workload rose from 1.371 to
2.108 µs and from 5,800 to 6,456 allocated bytes per operation because the token and owned
poll subscriptions have fixed initialization costs. The established memory-sink VLESS case
still allocates zero bytes. These results are component measurements, not an end-to-end TCP
speedup or proof that proxy RSS equals the benchmark process's RSS.

AnyTLS now uses the same owned close/deadline subscriptions; its obsolete local registry was
removed. mKCP uses a fresh close-signal generation per deadline arm and reusable per-handle
`Notify` subscriptions for read/write pulses, registered before the guarded readiness check.
Pulses remain pulses, not permanently latched cancellation. Re-poll/drop lifetime regressions
failed before the cutover and pass afterward; deadline re-arm and multi-waiter wake tests
cover the notification boundaries. A Tokio channel may retain one cached last reader waker;
that bounded pre-existing cache is distinct from the removed accumulating registries.

### Allocation and CPU profiling

The default `flake.nix` development shell includes `tokei`, `heaptrack`, `perf` and
`cargo-flamegraph`. Count Rust sources with `nix develop . --command tokei crates -t Rust`.
Profile an already-built executable, not Cargo itself:

```bash
nix develop . --command heaptrack --record-only /path/to/murmur -d /path/to/home
nix develop . --command perf stat -e task-clock,cycles,instructions \
  -- /path/to/murmur -d /path/to/home
nix develop . --command flamegraph -o cpu.svg -- /path/to/murmur -d /path/to/home
```

[Heaptrack](https://github.com/KDE/heaptrack) reports allocation calls, temporary allocations,
peak heap consumers and their stacks; use `heaptrack_print` on its emitted trace for headless
analysis. Its allocator traces are not the process's RSS. `--record-only` avoids automatically
opening a GUI. [Flamegraph](https://github.com/flamegraph-rs/flamegraph) uses CPU samples to
identify hot stacks; recording permissions depend on the host's perf policy.

For useful source locations, build optimized profiling binaries on `pc` with
`CARGO_PROFILE_RELEASE_DEBUG=1` (or `CARGO_PROFILE_BENCH_DEBUG=1` for benchmarks).
The shell uses mold: append `-Clink-arg=-Wl,--no-rosegment` to its existing `RUSTFLAGS`
inside the remote build payload when collecting CPU stacks. Do not replace the linker flags.
Run profiling separately from clean Criterion measurements because instrumentation changes
execution costs. Optimize identified hot paths, then rerun the same benchmark baseline.

## Verification

Almost all of the suite was written by this project, for this project: client and server are both
this tree's own code, so a passing round-trip test mostly proves the two sides agree with each
other, not that either one agrees with a third-party implementation or with a real proxy server on
the wire. The differential sweep described at the end of this section is the check that goes
outside the tree.

The last full sweep of that shape passed 2,574 tests, failed 3 and left 26 `#[ignore]`d with a
written reason, run one crate at a time on the shared build host — 105 test targets across the 89
workspace members. Two targets contributed no verdict to that sweep, and both do now:
`murmur-hub`'s lib-test target did not compile while its pprof/`/ui` work was still landing, and
compiles now with 31 route tests added (`route::server` 20, `route::pprof` 11); and
`murmur-transport-jls`'s integration target never finished because of the camouflage-relay hang
recorded below, and now completes in 53 s warm with its tests passing. The three failures that
sweep recorded — the REALITY/gun ALPN rejection, the mekya ALPN routing test and that same hang —
are each fixed in-tree and re-run green on their own targets, so they are recorded under "Known,
open defects" as closed rather than open. The toolchain-dependent harnesses that accounted for
most of the 26 ignored tests have since been removed, so those totals describe that sweep, not
the current tree. Dated gate runs appear in `docs/guidelines-review.md`. The two remaining
ignored tests are real-timer soaks, run separately by `make test-heavy`.

A lint campaign ran over the whole workspace: at its start `cargo clippy` reported 6,576
diagnostics (5,587 in production code, 989 in test targets) under the manifest's
`[workspace.lints]` levels. That campaign reached a clean lint and dependency gate;
`docs/guidelines-review.md` records both the historical audit and dated verification of
later repairs. Advisory results depend on the database revision, not just the lockfile.
The rewrite that removed the panicking operations was audited differentially, hunk
by hunk, against `git show HEAD:` and the reference implementation: about 4,600 changed hunks over 60 crates,
of which every hunk that replaced an index or slice with a checked form was reconstructed
symbolically and compared with the expression it replaced. That audit, together with the
integration suite, found and closed eight silent semantic defects the rewrite had introduced:

- a `split_at` head/tail swap in `transport-vless`'s `BytesReader::read` handed the copier an empty
  source slice, caught by 24 `inbound::vless` tests;
- the same swap in `component-tls`'s `UtlsClient::poll_read` returned EOF on the first read after
  every decrypted record, caught by the vmess tls-mirror test;
- the same class again in `transport-anytls`'s `SessionStream::poll_read`, which stored the pad
  tail instead of the surplus of a parked oversized read and so dropped data;
- two saturating casts where the reference truncates: `transport-anytls`'s peer version (a byte cast)
  and `transport-xhttp`'s reuse accounting (a 32-bit cast);
- `transport-mkcp`'s `elapsed` saturating where the reference wraps the 32-bit timestamp domain,
  which pinned every RTO/idle comparison after 49.7 days of connection life;
- `zerotier`'s `match_ipv6_prefix` reading the length byte one position early, so a `/32` rule
  became `/0` and matched every address;
- `zerotier`'s multicast frame body reading the ADI four bytes early, so groups were keyed off the
  destination MAC's tail instead of the ADI that follows it (with the follow-on that the answering
  node then skipped the gather acknowledgement the reference sends).

Each fix carries a regression test that fails on the pre-audit form; the `mekya`/gun/JLS/trusttunnel
entries under "Known, open defects" record the earlier round of the same work. One test's
expectation had to move with the last of those: `adapter-outbound`'s ARP replication test asserted
exactly one frame in the answering node's queue, which is what the ADI mis-read produced — with the
wire layout read correctly the node answers the ARP request *and* sends the `MulticastFrame`-`OK`
its reference counterpart does for a frame that asked for the group's members
(`sendMulticastFrameGatherOKLocked`). `an_unsafe_state_dir_is_refused` is skipped when the `cmfa`
feature is on, because that build makes `is_safe_path` short-circuit to `true` — the same guard
`murmur-constant`'s own path test carries.

Which of `RUST_GUIDELINES.md`'s rules the toolchain enforces, and how the prose-only ones (fake
`Deref`, blanket impls, `..Default::default()`, cancel-safety notes, naming) were
audited, is written up in [`docs/guidelines-review.md`](docs/guidelines-review.md); the single open
item recorded there is the cancel-safety note pass.

One check exists beyond the unit suite: a fresh debug binary built from this tree was driven end to
end. It matches the reference's flag set and `-t` output, serves `GET /`, `/version`, `/configs`
(key set identical to the reference's) and `/rules` (byte-shaped like the reference's rules route),
relays a SOCKS5 and an HTTP-CONNECT round trip through the mixed port, survives `PUT /configs`, and
exits 0 on `SIGTERM` with its shutdown line after releasing both ports. It also found the two
defects and one documented gap recorded below: the `/proxies` and `/group` wrapper shape (fixed, and
re-verified byte-identical to a reference binary built from the same tree), the SIGHUP reload that
permanently kills the REST API, and the `-v` wording. A second smoke run drove the streaming
endpoints — `GET /logs` (both the plain and `format=structured` frames), `/traffic`, `/memory`, the
`/connections` websocket and `DELETE /connections/{id}`, and `/dns/query` — against a reference
binary built from the same tree. The nine wire differences it turned up were fixed — JSON encoder
frames and bodies (a trailing `\n`, `<`/`>`/`&` escaped), `null` for an empty
`connections`/`sourceGeoIP`/`destinationGeoIP` where the reference emits `null`, `405` + `Allow:
GET` on `/logs`, `/traffic`, `/memory`, exact-segment routing, the `?interval=` websocket paths,
`application/json` and unconditional `Vary: Origin` — along with the router's `404 page not found`
body and its mount-boundary trailing-slash rule, and both binaries were re-run side by side to
confirm it over all six endpoints, 23 routing cases and a 28-case trailing-slash battery (every case
byte-equal, the four `/proxies`/`/group` sub-router JSON 404s included).

A green tree is green from `--test-threads=1` up through roughly threefold oversubscription of the
host's available cores. On a 12-core machine, that means green at `--test-threads=32` and green
in CI at the runner's default. At `--test-threads=64` (roughly fivefold oversubscription), two
tests stop being meaningful under CPU starvation:

- `adapter::outbound::masque::tests::h2_tls_stream_close_delivers_full_write` measures wall-clock
  time because the production code it exercises calls `tokio::task::block_in_place` and needs a
  dedicated multi-threaded runtime to prove the blocking does not starve other tasks.
- `common::net::context::tests::setup_context_for_conn_with_timeout_1` measures wall-clock time
  to assert the relative firing order of a cancellation racing a timeout inside a 100ms window.

The right way to run the suite is `cargo test --workspace` (which defaults to the runner's logical
core count), not an arbitrary thread count. This prevents these two deadline-sensitive tests from
colliding with the load and spuriously failing while still exercising the suite's full coverage.

`.github/workflows/test.yml` is the CI gate. It runs on a push to `main`, on any pull request, and
on a manual `workflow_dispatch`, and no job is under `continue-on-error`, so a failing job fails
the run. Its jobs are `fmt` (`cargo fmt --all -- --check`), `clippy` (`cargo clippy --workspace
--all-targets --locked --keep-going -- -D warnings`, plus a `cargo check --workspace --all-targets
--locked --keep-going`, with `CARGO_BUILD_WARNINGS: deny` set for the whole workflow), `deny`
(cargo-deny against `deny.toml`), `audit` (RustSec advisories), `machete` (unused dependencies)
and `test` (`cargo test --workspace --no-fail-fast --locked`) on `ubuntu-latest`, `macos-latest`
and `windows-latest`. The lint, format and supply-chain jobs run once, on Linux: the source tree is
identical on all three, so repeating them would only print the same finding three times.

The release workflow is `rust/.github/workflows/release.yml`. It runs on a push of a `v*` tag and
on `workflow_dispatch`; a `guard-tag` job fails the run when the tag disagrees with the version in
`Cargo.toml`, the five-target build matrix covers x86_64 and aarch64 musl,
`x86_64-pc-windows-msvc` and x86_64/aarch64 Darwin, each runnable row runs the freshly built
binary's config-test mode (`-t`) before packaging, and the publish job is gated on the tag push,
so a manual run only rehearses the build. That tag namespace is not this tree's: in this
repository `v*` belongs to another project's releases, so a release job on the same tag would
collide with it, and cutting releases from here needs either a tag namespace of its own or a
repository of its own, neither of which is this change's to invent.

The three-OS test matrix proves the workspace builds and its own lib tests run on all three
platforms, which Linux-only CI never checked before it existed: the Darwin ioctl constants in
`component::iface::anet`, the deliberate absence of `SO_REUSEADDR` on Windows in
`component::dialer::control` (the reference does not set it there either), and the non-atomic
close-on-exec fallback on Darwin had compiled but never run anywhere before this workflow. It does
not prove anything about behaviour under real traffic on Windows or macOS: the differential harness
below (`diff_sweep.py`) has no Windows or macOS run of its own, needs a live subscription this CI
has none of, and is not wired into `cargo test` on any platform. A green run of this workflow is
evidence the workspace builds and its own lib tests pass on that platform — not a compatibility
claim about anything beyond that.

`make act-test` builds a throwaway local image (`rust:latest` plus `apt-get install nodejs`,
defined inline in the `Makefile`, not a checked-in Dockerfile) and then runs the `test` job of
`.github/workflows/test.yml` through `act`, pinned with `--matrix os:ubuntu-latest` and
`-P ubuntu-latest=<image>`. The image is needed because `act`'s own default images are bootstrap
images without a Rust toolchain, and the official `rust:latest` image is missing `nodejs`, which
the job's cache step execs directly inside the container. Running the Linux job in a clean
container catches the class of bug that only a from-scratch environment exposes — this project
found a test wired to an absolute path on the development machine, `/drive/tmp`, that way — and
`act` has no Windows or macOS backend, so it can only stand in for the Linux row of the matrix,
never for the other two, which run on real GitHub-hosted runners. It needs Docker.

The tool that actually checks against something external is `rust/tools/diff_sweep.py`, committed
in this repository. Given a reference binary, a build of this tree, and a config with real proxy
nodes, it starts both binaries, switches a selector group through each one's Clash-compatible
controller API, fires the same HTTPS request through each proxy port, and reports where the two
disagree:

```
python3 rust/tools/diff_sweep.py \
    --ref-bin /path/to/reference-binary \
    --rust-bin /path/to/target/debug/murmur \
    --home /path/to/my-subscription-workdir \
    --repeats 3
```

`--home` is a directory holding your own `config.yaml` and whatever `providers/` files or provider
cache it references, relative to that directory — point it at a subscription you have permission
to test against. This repository ships no subscription, node list or credential, and none should
ever be committed to it. The tool only reads `--home`; each side runs off a private copy with its
own auto-picked ports, so it never collides with an already-running instance. It needs only the
Python standard library and a `curl` on `PATH` — no new Cargo dependency, and it is not wired into
`cargo test`, so the ordinary test suite never needs a subscription.

A node that fails on both sides is a dead node, not a defect — public proxies flicker, which is why
every node is probed `--repeats` times (default 3) before either side is judged "ok" or "dead".
Output is a per-node table (`both-ok` / `both-dead` / `differ`) plus, for every real divergence,
that node's protocol type and — when this side is the one that failed — the most recent WARN/ERROR
line this binary logged for that attempt. Exit code is `1` when at least one real divergence was
found, `0` when every disagreement is explained by dead-on-both nodes (or there were none), and `2`
on a setup error. Run `python3 rust/tools/diff_sweep.py --help` for every flag.

`tools/e2e_vm.py` runs a fixed set of controlled scenarios — the protocol, routing and
DNS behaviours below — inside a disposable NixOS/QEMU/KVM guest, so a regression is caught
without a manual VM, a router or a subscription:

```
python3 tools/e2e_vm.py \
    --rust-bin /path/to/murmur \
    --ref-bin /path/to/reference-binary \
    --workdir /somewhere/to/keep/results
```

It builds its own guest (NixOS `qemu-vm`, KVM, no disk image), generates a temporary SSH key
and a fresh self-signed test certificate at run time, picks a free localhost port for SSH
forwarding, stages both binaries and the synthetic fixtures under `--workdir/share`, and drives
the scenarios over SSH. The guest mounts the host `/nix/store` read-only, so a Nix-built
binary's ELF interpreter resolves without copying a closure; a binary whose interpreter is not
a Nix store path fails the run instead of degrading. The offline scenarios talk only to loopback
endpoints and network namespaces created for them: none needs the internet, a router or a
credential. Prerequisites are `nix-build` with `nixpkgs` in `NIX_PATH`, `/dev/kvm`, `ssh`,
`ssh-keygen`, `openssl`, an executable `--rust-bin` (Nix-built) and an executable `--ref-bin`;
a missing prerequisite fails before the VM launches.

`--workdir` must be empty and is restricted to mode `0700`, protecting private inputs and
evidence. Omit it to create a fresh temporary directory. For the optional real-node sweep,
add `--home /path/to/private/config-home --group NAME --repeats 3` to the command.

The scenarios, each asserting a consumer-visible body, status, digest or routing decision:

- config parse of every generated config shape with `-t`;
- HTTP and SOCKS5 ingress to `DIRECT`;
- Trojan over TLS 1.3 with an X25519 key share and with a P-256 HelloRetryRequest against a
  synthetic fixture (`diagnostic fixture reached`);
- VLESS plain and VLESS `xtls-rprx-vision` against the same fixture;
- a genuine reference VLESS/Vision server with a 1,028,096-byte TLS 1.3 download and upload
  verified by SHA-256, for no fingerprint, Chrome and Firefox;
- a genuine reference VMess server with `alterId: 4` and `alterId: 0`, expecting the HTTP
  target body;
- wildcard `bind-address: "*"` `allow-lan` TPROXY: TCP and 1/127/1200-byte UDP from a LAN
  network namespace, with the original sender preserved;
- fake-IP DNS requests over UDP and TCP, VPN/Telegram/WARP filter rule-sets, a `.lan`
  real-IP exclusion, AAAA suppression, and fake-IP persistence across a restart;
- a fallback group falling through to `DIRECT` and an empty-provider `url-test` group with
  `empty-fallback: REJECT` failing closed;
- the supplied router config end to end: an HTTP proxy provider serves one synthetic share-URI
  node backed by a genuine reference VMess listener, the `WARP`/`VPN`/`VPN-ALL-AUTO` groups load
  with the supplied membership and types (including the `url-test` `empty-fallback: REJECT`), a
  dead first `WARP` adapter fails over to the next one, the provider node wins `VPN`, fake-IP
  `RULE-SET` routing sends VPN/Telegram/WARP domain and IP destinations through the expected group
  with the expected rule-set in the log, a real-IP destination bypasses the proxy, and 24
  concurrent LAN requests at 8 workers all return the exact target body.

`--workdir/results.json` holds one named outcome per scenario with its checks and evidence files
under `--workdir/evidence/`; the command exits `0` only when every requested scenario passes, and
it always stops its own VM process group and removes the temporary key. On a failure the VM
console log, the guest runner log and the evidence are kept.

Passing `--home` adds one optional comparison against real proxy nodes: it runs the existing
`tools/diff_sweep.py` inside the guest for every node in `--group` (`--repeats` probes per side)
and the command fails on a real divergence. `--home` must be a private directory you have
permission to test; it is only read and is removed from the shared directory afterwards.

Limits: the runner needs an x86_64 Linux host with KVM and `nix-build`, and is not wired into
`cargo test` or any CI job. The guest has QEMU user-mode networking, so the optional sweep can
reach public nodes, but the controlled scenarios never depend on it. Browser fingerprints are
covered only for the three tested profiles; nothing here claims fingerprint parity beyond them.
The supplied-router scenario's `WARP-AWG*` members are synthetic VM-local `type: direct` egress
(bound to `lo`, or to a deliberately absent interface to exercise failover), not real
WireGuard/AWG router tunnels: that scenario proves provider loading, routing, failover and
concurrent traffic, not router-tunnel interoperability.

Every defect listed below that was actually found in the field — as opposed to a protocol this
crate simply never implemented — was found by running the two binaries side by side this way, not
by the unit test suite.

## Known, open defects

- **Router-config VM interoperability failures.** Closed for the reproduced protocol paths.
  Vision writes now reserve padding headroom and resume queued frames without wrapping them twice.
  Authenticated REALITY and TLS sessions expose an engine-backed session capability; XTLS switches
  each direction to its actual raw transport only after flushing the old writer, and delivers
  buffered incoming plaintext before raw bytes. The ordinary rustls path uses a record-boundary
  reader, so an unconfigured client fingerprint does not strand the first raw record. Deadlines
  and half-close operations follow the active direction across the switch.
  Fingerprinted TLS handles HelloRetryRequest, including cookie-only retries, fresh key shares,
  the `message_hash` transcript, and rejection of a changed final cipher suite or requested group.
  VMess `alterId > 0` now uses the reference's HMAC-MD5/AES-CFB request and response headers while
  retaining the configured body codec; the separate `cipher: aes-128-cfb` body mode remains
  unsupported. REALITY records emit their header and payload together instead of a standalone
  five-byte header write: a fresh-session wire probe reproduced direct failures with split writes
  and successful authentication with coalesced records, including the REALITY/XHTTP path.
  Verification uses real reference VLESS/Vision and VMess servers, TLS 1.3 bulk transfers with no
  fingerprint, Chrome and Firefox, and a frozen subscription comparison. This is not a claim of
  browser-fingerprint parity for the REALITY engine.

- **Wildcard transparent listeners and supplied-config corrections.** `bind-address: "*"` with
  `allow-lan: true` now produces an explicit IPv4 wildcard address for Tokio TCP and UDP listeners,
  rather than the bare `:port` spelling. Real namespace TPROXY TCP and UDP echo checks cover the bind.
  Fake-IP persistence belongs under `profile.store-fake-ip`, not `dns.store-fake-ip`; the final
  catch-all rule must name the configured outbound (`MATCH,DIRECT`, not `MATCH,DIREC`).

- **trusttunnel over QUIC**: this is closed. The listener test is no longer `#[ignore]`d —
  `listener::inbound::trusttunnel::tests::test_inbound_trust_tunnel_quic` is a plain
  `#[tokio::test]`, and it passes 3/3 including the 128-simultaneous-CONNECT h3 case — and the h3
  transport path passes 11/11, over 20 repeated clean runs. The one compatibility gap this entry
  used to carry, an incoming-stream ceiling of `1<<60`, is now the deliberate clamp recorded
  under "Known limitations" (this build admits 4096 concurrent streams at the quinn boundary
  instead of passing the configured number through).

- **A REALITY-wrapped gRPC (gun) dial was rejected by the ALPN gate.** Closed. The gate in
  `crates/transport/src/gun/gun.rs` now carries the full predicate —
  `shadow_tls.is_none() && restls.is_none() && reality.is_none() && tls_mirror.is_none()`,
  including the Restls term the failure exposed — and `reality_wrapped_conn_passes_the_alpn_gate`
  passes with the crate's other 27 tests (28/28). Part of the failure was the test's own config: a
  REALITY `TlsConfig` with no `client-fingerprint` is rejected by the reference too, so the test now
  sets the `chrome` default the converter supplies. The Restls term itself has no end-to-end test
  here, so it rests on the predicate plus review.

- **The mekya ALPN routing test failed against its own derived server.** Closed. The cause was the
  chrome-fingerprint client-hello path, not the routing: `crates/component-tls/src/utls.rs`'s
  branch built the hello through `new_client_hello` without installing any extensions, so the
  fingerprinted ClientHello went out with a zero-length extension block (no ALPN, key_share,
  signature_algorithms or supported_versions) and the test server answered `handshake_failure`. It
  now calls `apply_preset_by_id()` to build the standard handshake hello, and the ALPN-routing test
  and the crate's 21 tests pass.

- **The JLS camouflage relay could hang.** Closed for the two shapes found, after the originally
  reported one. The reported case was a probe whose header declared a body it never sent; the
  first-record guard now matches the reference (`crates/jls-tls/src/record.rs`, with no
  `ChangeCipherSpec` exemption while read keys are uninstalled), and the reference's pre-body
  ciphertext caps (`MAX_CIPHERTEXT_RECORD` / `MAX_CIPHERTEXT_RECORD_TLS13`) refuse an oversized
  declared length before the body read. Both are covered by regression tests that hung before the
  fix (`crates/transport-jls/tests/jls.rs`: `a_leading_change_cipher_spec_probe_...`,
  `an_oversized_declared_record_body_...`), and the integration target now finishes in 53 s warm,
  with `a_non_jls_probe_is_relayed_to_the_camouflage_destination` passing.

- **No test here has ever opened a real TUN device.** Every TUN test drives a fake packet device
  (`crates/listener/src/tun.rs`'s harness), and the device-open path
  (`crates/listener/src/tun/device/linux.rs`: `open(O_RDWR|O_CLOEXEC)` + `TUNSETIFF`, then netlink
  for the addresses and routes) needs `CAP_NET_ADMIN` and `/dev/net/tun`, which no test host here
  has. A failed open takes the same branch a refused option takes (`errorln!` and `enable: false`),
  and that branch is tested, but the open error itself is not.

- **A sudoku obfs hint group that failed to decode left the decoder mid-group**, so the next read
  indexed past the end of the hint buffer and panicked, killing the connection task instead of
  reporting the error. This is fixed and covered by
  `transport_sudoku::obfs::sudoku::conn::tests::test_conn_map_miss_resets_hint_group`; a peer that
  speaks with a different table is now reported as an ordinary read error.

- **`cargo audit` has never been run against this crate.** Closed. Dependency checks run on the
  build host. `deny.toml` and `.cargo/audit.toml` document the two retained exceptions: the RSA
  Marvin timing attack (the affected decryption operation is not used here) and unmaintained
  `rustls-pemfile` reached through the Tailscale engine. Wasmtime advisories and unmaintained
  `instant` are not accepted exceptions. See `docs/guidelines-review.md` for dated verification.

- **`/proxies` and `/group` lost the wrapper fields.** Closed. Every built-in proxy is wrapped so
  each entry carries `history`, `extra`, `alive`, `udp`, `xudp`, `tfo`, `mptcp`, `smux`, `interface`,
  `routing-mark`, `provider-name` and `dialer-proxy` on top of the adapter's own keys, where the
  previous code marshalled just `proxy.adapter()`. `crates/hub/src/route/proxies.rs` and `groups.rs`
  now render the wrapper, and the wrapper's own nested objects keep their declaration order because
  the bodies are assembled from each proxy's `marshal_json()` bytes instead of a `serde_json::Value`
  round trip (a `BTreeMap` would re-sort `history`/`extra`). Verified by a live A/B against a
  reference binary on the same config: `/proxies`, `/proxies/{name}`, `/group`, `/group/{name}` and
  `/providers/proxies/{p}/{n}` are byte-identical (16-key wrapper for a plain proxy, 21 keys for a
  selector/URLTest group, `null` for an empty group list), and after a real delay test both sides
  emit `"history":[{"time":…,"delay":N}]`. Tests: `route::proxies`/`route::groups`
  `proxies_routes_render_the_wrapper_for_a_builtin`, `group_routes_render_the_wrapper`,
  `wrapper_history_and_extra_after_a_delay_test`.

- **A SIGHUP reload permanently kills the REST API.** Closed. Observed on the live binary, 4 runs out
  of 4: after `kill -HUP` the log said `External controller listen error: Address already in use (os
  error 98)`, the process stayed up and the mixed proxy kept relaying, but the external-controller
  port was gone from `ss -ltnp` and every later request got `Connection refused`. The old listener
  has to be fully closed before rebinding: `re_create_server` closed the previous `RunningServer`,
  which only set a `closed` flag and called `Listener::close` — for the external controller a token
  cancel that merely unparks `accept()`, while the bound fd lives in the accept loop's own
  `Arc<dyn NetListener>` (`crates/std-compat/src/net.rs`) — so the old socket was still bound when
  `start` rebound and the `EADDRINUSE` path only logged and returned.
  `crates/hub/src/route/server.rs` now keeps the accept loop's `JoinHandle`, aborts and awaits it,
  and drops the listener before rebinding. Verified live: after SIGHUP the API answers again on the
  same port, the mixed proxy relays, zero error lines, and the re-listen line is logged.

## Licence

murmur is licensed under the GNU General Public License, version 3 only; every crate manifest
declares `license = "GPL-3.0-only"`. The full text is in the repository's `LICENSE` file.
