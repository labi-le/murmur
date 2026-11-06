# Verification and defect log

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
audited, is written up in [`docs/guidelines-review.md`](guidelines-review.md); the single open
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

`.github/workflows/pr-review.yml` runs `tools/pr_review.py` on pull-request `opened`, `synchronize`,
`reopened` and `ready_for_review` events (and on `workflow_dispatch` with a `pr` input). It checks
out the repository's default branch so untrusted pull-request code never runs with `REVIEWER_TOKEN`
in scope, loads `AGENTS.md` plus matching `docs/*.md` guides into the prompt, exposes a bounded
read-only `read_file` tool over the base checkout, and submits `APPROVE` or `REQUEST_CHANGES` under
the account owning `REVIEWER_TOKEN` via `REVIEWER_LLM_API_KEY` (model `PR_REVIEW_MODEL`, defaulting
to `gemini-4-argon`). Offline tests live in `tools/test_pr_review.py`.

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

Use `--memory-mib 256` to run the guest with 256 MiB instead of the 1,536 MiB
default. Swap and zram are disabled. Results include actual guest memory, minimum
sampled available memory, per-child RSS/high-water marks and kernel OOM counters.
The mixed-load scenario runs eight TCP, eight persistent UDP and two DNS workers
for 30 seconds, idles for 65 seconds, then repeats the burst. These are bounded
workload measurements, not a guarantee for arbitrary rules or connection counts.
If an inherited `LD_LIBRARY_PATH` mixes incompatible Nix library closures, launch
with `env -u LD_LIBRARY_PATH -u LD_PRELOAD python3 tools/e2e_vm.py ...`.

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

`tools/e2e-pc` is the native, no-VM counterpart. It builds the binary through `tools/cargo-slot`
and runs `tools/e2e_stability.py` on the same host. In the default outbound direction the suite
starts a reference server with listeners for VLESS (Vision, raw TCP, WS, gRPC, all three XHTTP
modes and REALITY), VMess, Trojan, Shadowsocks, Snell, AnyTLS, Hysteria2 and TUIC, then drives
each through repeated bulk downloads and uploads, mid-stream cancellations, idle keep-alive
requests and SOCKS5 UDP associations, restarts the reference server and checks that every
protocol recovers. `--direction inbound` swaps the roles: murmur runs the listeners, the reference
binary runs the client, and the restart phase restarts murmur; the same protocol matrix and checks
apply. VLESS Vision is outbound-only because `sing_vless` hardcodes `TlsConnCheck::Unsupported` on
the server side. A VLESS client left on its default `xudp`/mux UDP encoding sends the mux command,
whose listener handler still names the missing sing-vmess crate, so the `vless-packetaddr` row
carries UDP for that protocol instead: with `packet-encoding: packetaddr` the reference sends the
plain UDP command, which the listener implements, and the inbound UDP checks run against it. The
other VLESS rows exercise TCP only.
Everything is loopback: no subscription, root or VM. `E2E_REF_BIN` selects
the reference binary and `E2E_RUST_BIN` skips the build; pass `--protocols`, `--cycles`,
`--direction`, `--skip-restart` or `--keep` through to the suite.
Hysteria2 is QUIC: after a silent server restart its old connection is only known dead at the
30-second idle timer, so the restart phase retries once after a 35-second grace and reports a
delayed recovery. The reference client needs the same window. TUIC is QUIC too, but its cached
session is discarded by the five-second stream-open bound and one retry, so a request that lands
on the dead session fails at most once before the next one uses a fresh connection; the grace
remains for a slow handshake. The outbound matrix is 23 transports and 299 checks; the inbound
matrix is 21 transports and 265 checks. Every UDP association sends one warm-up datagram before
its measured requests, so a slow session setup is not mistaken for data loss. Each direction
reports a restart row per protocol.

```
tools/e2e-pc --cycles 2
```

Every defect listed below that was actually found in the field — as opposed to a protocol this
crate simply never implemented — was found by running the two binaries side by side this way, not
by the unit test suite.

## Known, open defects

- **The gRPC and XHTTP inbounds dropped the accepted connection's addresses.** Closed. `hyper`
  hands a service only the request, where Go's `net/http` also sets `Request.RemoteAddr` and the
  `http.LocalAddrContextKey` value, so `crates/listener/src/trojan/server.rs`,
  `crates/listener/src/sing_vmess/server.rs` and `crates/listener/src/sing_vless/server.rs` served
  every request with neither address. The relay's `metadata.source` therefore logged
  `invalid IP:0`, and Trojan's UDP loop — which keys each NAT entry on the accepted conn's peer —
  returned before reading the first datagram, so Trojan UDP over gRPC was silently dead while its
  TCP worked. `crates/listener/src/conn_addr.rs` captures both addresses once from the accepted
  conn and inserts them into every request it serves; the inbound suite now carries 20/20 UDP
  answers for `trojan-grpc` and logs real peer addresses.

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

- **Linux automatic TUN configuration blocked waiting for a netlink ACK.** Closed.
  Requests targeted their own userspace socket instead of the kernel, advertised a
  length excluding attributes and omitted the IPv4 local-address attribute. Address
  flags also incorrectly requested IPv6 `HOMEADDRESS`. The corrected binary passed
  automatic TUN creation, route installation, ICMP echo and interface removal in a
  disposable Linux namespace. A separate kernel-backed regression covers IPv4/IPv6
  address and route lifecycles. These checks do not establish TUN support on the
  experimental OpenWrt router, which has no `/dev/net/tun`.

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

- **A quiet `/logs` stream kept its subscription after the client left.** Closed. `get_logs`
  waited only on the event channel, so a client that disconnected while no record met `?level=`
  was noticed on the next qualifying write, if ever; the handler also ran detached from the
  connection, and the websocket sink never read, so an idle peer's close was invisible.
  `crates/hub/src/route/server.rs` now selects the sink's closure against the channel and releases
  through a guard that also covers an aborted or panicking task; `crates/hub/src/route/common.rs`
  watches the HTTP body receiver and the upgraded websocket's control frames (ping answered, valid
  close echoed, invalid close answered with a 1002 protocol error, data discarded). `/traffic`,
  `/memory` and `/connections` select the same closure against their ticker, and every websocket
  write shares the writer mutex with the close path: the close sets a flag before it writes, so no
  data frame can follow the close frame even if the ticker fires in between. A close also cancels
  the stream before it waits for that mutex, so a handler blocked on a peer that stopped reading
  still releases its subscription; that in-flight write is abandoned and marks the stream poisoned
  while the writer guard is still held, so a concurrent close or pong cannot acquire the mutex and
  write onto the partial frame; the connection is dropped rather than reused or followed by a close
  frame. A control frame (pong, close echo) bounds its lock acquisition and write, and its own
  timeout sets the poison before releasing the guard, so a ping that cannot be answered does not
  hide the close that follows it. Tests:
  `a_closed_logs_stream_releases_its_subscription_without_a_qualifying_record`,
  `a_websocket_logs_client_is_answered_and_released_on_close`,
  `an_invalid_close_payload_is_answered_with_a_protocol_error`,
  `an_empty_close_payload_is_echoed`,
  `a_close_frame_stops_the_traffic_stream_before_its_next_frame`,
  `a_close_frame_stops_an_hour_interval_connection_stream`,
  `a_close_frame_releases_a_log_subscription_blocked_on_backpressure` and
  `a_ping_before_close_releases_a_log_subscription_blocked_on_backpressure`; all but the
  empty-close case fail on the previous form. A loopback `level=error` probe opened and closed
  1,000 plain HTTP streams and 1,000 websocket streams with no qualifying record: the process held
  11 descriptors and no `CLOSE_WAIT` sockets before, between and after the churn, against 112
  descriptors and 101 `CLOSE_WAIT` sockets for 100 websocket disconnects with only the old
  receive loop restored. A second probe sent a close frame to `/traffic`, `/memory`,
  `/logs?level=error` and
  `/connections?interval=3600000` and read only the echoed close followed by EOF; payloads
  `78`, `03ed` and `03e8ff` drew `03ea`, and an empty close was echoed empty
  ([#192](https://github.com/labi-le/murmur/issues/192)).

- **Every UDP flow the adapter resolved leaked its socket.** Closed. `handle_udp_dial` joined the
  flow to the global tracker manager and only then read `addr_port()` from the metadata it was
  given, while the address the adapter had resolved lived in the copy handed to the dial. For a
  fake-ip destination that copy is the only one carrying an address, so `addr_port()` answered
  `None`, the function returned before spawning the read loop, and the registered tracker kept the
  outbound socket open for the life of the process: one descriptor and one dead `/connections`
  entry per flow (`component-proxydialer` had the same unclosed early return when `udp_addr()`
  returned `None` after registering a `UdpTracker`). `handle_udp_to_remote` compounded it by arming
  a read deadline on the connection whose read side `handle_udp_to_local` was already parked on,
  and a deadline set during an initially unbounded read in `deadline::{packet,packet_enhance,conn}`
  latched `disable_pipe` on for the rest of that connection, delegating to an inner `PacketConn`
  whose default `set_read_deadline` is a no-op so a flow that received no reply could not reach its
  60-second timeout either. The dial now returns its resolved metadata, the early returns in both
  `tunnel` and `component-proxydialer` close the connection, the write path no longer arms the read
  deadline, and `deadline::{packet,packet_enhance,conn}` always race `deadline_token.token()` (which
  `DeadlineToken::set` cancels in place when a deadline is armed while a read is already parked)
  with `disable_pipe`/`in_read` removed. Tests:
  `fake_ip_udp_flow_uses_adapter_resolved_address_and_expires_after_udp_timeout`,
  `udp_dial_whose_adapter_leaves_destination_unresolved_closes_conn_and_leaves_manager`,
  `udp_dial_without_resolved_address_closes_conn_and_leaves_manager`,
  `a_read_deadline_set_while_a_read_is_parked_ends_that_read_and_subsequent_reads`,
  `wait_read_from_honours_deadline_set_during_and_after_an_unbounded_parked_read` and
  `read_deadline_set_while_read_is_parked_wakes_it_and_keeps_future_deadlines_working`. Measured on
  the router, a silent fake-ip flow kept its tracker and its socket indefinitely before the fix;
  afterwards both are gone at 70 seconds and the UDPv6 descriptor count returns from 5 to the
  baseline of 4.
