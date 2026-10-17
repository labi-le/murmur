# Guidelines review: the lint posture this workspace actually enforces

This review records which rules `RUST_GUIDELINES.md` enforces through tools and which
need source inspection. The original audit measurements refer to the tree that first
became lint-clean. Later verification entries are dated separately.

## Original gate audit

| Check | Command | Result |
| --- | --- | --- |
| Lints | `cargo clippy --all-targets --all-features -- -D warnings` | exit 0, no diagnostics |
| Lint census | `./.census.sh` (`--cap-lints warn`, whole workspace) | 0 production + 0 test diagnostics |
| Formatting | `cargo fmt --all -- --check` | exit 0 |
| Supply chain | `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok |
| Advisories | `cargo audit` | 752 lockfile entries, no finding |
| Unused deps | `cargo machete` | none |
| Spelling | `typos` | no first-party finding |
| Tests | `cargo test --all-features --no-fail-fast` | recorded at the time of this audit as 2811 passed, 0 failed, 1 ignored (the documented real-timer soak); the tree has since grown, so re-run rather than reuse this figure |

The burn-down that reached this state started at **6,576 diagnostics** (5,587 in
production code, 989 in test targets, 85 distinct lints). The manifest levels
they were measured against live in `Cargo.toml` `[workspace.lints]`; thresholds
in `clippy.toml`; supply-chain policy in `deny.toml` and `.cargo/audit.toml`.
Test code is exempt at the source (`#![cfg_attr(test, allow(...))]` in every
crate root, `#![allow(...)]` in `crates/*/tests/*.rs`) rather than through the
gate flags, so the exemption is visible where it applies.

## Gate repair verification, 2026-10-17 (#171)

Verified on `pc` with the pinned rustc 1.97.1 / Cargo 1.97.0, on the separate repair
commit `d8d2565` based on `37bccfd`, before integrating watcher PR #170. The first full run
exposed the redir fixture's independent TCP/UDP port race;
the test now probes both port spaces and retries a fresh number if the TCP probe loses
its reservation. Snell cancellation is arranged with one poll rather than a zero-duration
timer. Both retain their payload/retry assertions. Hysteria2 releases its stream guard
immediately after reset.

```sh
timeout 1200 env CARGO_TARGET_DIR=issue169-watch-config CARGO_BUILD_JOBS=2 \
  tools/cargo-slot bash -c 'cargo fmt --all && cargo test -p murmur-listener --lib a_failed_redir_udp_bind_is_retried_on_the_next_re_create && make -k gate && make lint'
```

This command exited 0. Workspace all-features nextest ran **3,208 tests: all passed**;
the two documented real-timer soaks were skipped. Formatting and all-targets/all-features
clippy passed with `-D warnings`. Blocking deny, machete, audit and spelling checks passed.
Cargo-deny's duplicate-version and unmatched-license-allowance warnings remain informational
under the existing policy. The audit scanned 752 dependencies against 1,338 advisories,
database commit `999ec89d5d3f10f20be14750ec8c2d8b44e0ac9b`; it found no unaccepted
vulnerabilities or informational warnings. The two advisory exceptions below are unchanged.
That historical repair commit's lockfile SHA-256 was
`da135e862846a06c936a62f756e2878a4285c520ed29445bc1db47f36cebdfaa`;
it does not identify the integrated watcher tree's lockfile.

A separate targeted lib-test run passed 561 tests across common, config, updater, Snell,
Hysteria2 and EasyTier. A default-feature binary built and passed real loopback smoke:
YAML anchors/aliases, authenticated config reload, malformed-file rejection with the live
proxy preserved, DIRECT/REJECT routing, stable fake-IP mappings with distinct new allocations,
UI ZIP download/extraction and certificate-verified Trojan streams over TLS 1.2 and 1.3.
Another process compiled/instantiated the embedded EasyTier WASM core and returned its configured
`10.126.126.126` through the management-RPC-backed DNS resolver. The existing Tailscale
engine-startup test passed in the full sweep; authenticated live-tailnet traffic was not exercised.

The static AArch64-musl release also built and ran in an isolated OpenWrt process: config-test
with YAML aliases, HTTP DIRECT/REJECT/recovery and fake-IP preservation passed without changing
the PID. `readelf` showed no interpreter or dynamic section. The binary SHA-256 was
`c12a1b51cf451d033548ed578c679bd589438f8d18d8830c116de9c82a1d44d4` on both hosts.
The test process and staging files were removed; production PID 3350, configuration and firewall
were unchanged. The cross-build emitted existing deprecated `libc::time_t` / `suseconds_t`
warnings in `ntp/time_unix.rs`; this is not an ARM clippy-clean claim. Native macOS/FreeBSD,
Windows linting and the ignored timer soaks were not part of this gate run.

## Integrated watcher verification, 2026-10-18 (#170 / #172)

The integrated tree combines watcher merge `56cb139` and gate repair `d8d2565` through
`a2e41ff`, plus the subsequent lint-only integration fixes. Those fixes release five listener
guards after their final mutation, rename the watch callback's path binding, consume the
failure vector during aggregation and remove a redundant async `must_use` annotation.
No lint allowances or advisory exceptions were added.

```sh
timeout 1200 env CARGO_TARGET_DIR=issue169-watch-config CARGO_BUILD_JOBS=2 \
  tools/cargo-slot bash -c 'make gate && make lint && cargo build -p murmur --bin murmur'
```

All three stages completed successfully: **3,224 nextest tests passed**, the two documented
soaks were skipped, all-targets/all-features clippy with `-D warnings` and formatting passed,
and blocking deny/machete/audit/spelling checks passed. The integrated lockfile SHA-256 is
`8e953411ce9462e847e0373c08225f80d147ff29139fbc56ac24b6b6571c09af`.
This is the dependency graph verified after watcher integration; the earlier digest belongs
only to the separate repair commit. Advisory policy and database revision are unchanged.

Real default-feature binary smoke passed four atomic replacements, in-place editing,
malformed-file retention, missing-file recreation, stable fake-IP mappings and distinct new
allocations. An incomplete authenticated PATCH body did not block automatic reloads.
A controller port change released the old endpoint; new connections accepted the CLI secret
and rejected the different file secret, verifying override precedence across watched reloads.
The PID remained unchanged. The throwaway HTTP probe initially sent a mismatched Host header;
correcting that probe to match its absolute request target produced the passing runtime result.

The final static AArch64-musl binary, SHA-256
`1b1dedfadb23bc3e58b4d6fefb4f0b21766b66b820dcfdc708301ccbc400d762`, passed the real OpenWrt
watcher/edit/rename/delete-recreate, proxy and fake-IP smoke again. Temporary process and files
were removed; production PID 3350 and deployment were unchanged. Platform and live-tailnet
limits from the preceding verification entry still apply.

## What the lints cannot see, and what the tree does about it

### The rewrite itself: differential audit

Removing 6,576 diagnostics means rewriting hundreds of indexing, slicing, cast
and `unwrap` sites into checked forms — a class of change that can alter
behaviour without failing to compile. Every such hunk was therefore audited
differentially against `git show HEAD:<path>` and the reference
implementation: about
**4,644 changed hunks across 60 crates**, of which every hunk that replaced an
index or slice with a checked form was reconstructed symbolically and compared
with the expression it replaced.

Eight real defects came out of it, each with a regression test that fails on the
pre-audit form:

| Crate | Defect | Failure it caused |
| --- | --- | --- |
| `transport-vless` | `BytesReader::read` bound the head of `split_at` where the tail was meant | `copy_from_slice` got an empty source; 24 `inbound::vless` tests failed |
| `component-tls` | the same swap in `UtlsClient::poll_read` | EOF on the first read after every decrypted record; the vmess tls-mirror test failed |
| `transport-anytls` | `SessionStream::poll_read` stored the pad tail instead of the surplus of a parked oversized read | silent data loss on session reuse |
| `transport-anytls` | peer version saturated at `u8::MAX` where the reference truncates | a peer reporting 256+ looked like version 2 |
| `transport-xhttp` | reuse accounting saturated at `i32::MAX` where the reference truncates into an int32 | reuse counters wrong for large configs |
| `transport-mkcp` | `elapsed` saturated where the reference wraps the 32-bit timestamp domain | every RTO/idle comparison wrong after 49.7 days of connection life |
| `zerotier` | `match_ipv6_prefix` read the length byte one position early | a `/32` rule became `/0` and matched every address |
| `zerotier` | the multicast frame body read the ADI four bytes early | groups keyed off the destination MAC's tail; the answering node then skipped the gather acknowledgement the reference sends |

The lesson recorded for the next rewrite of this shape: a checked-access
rewrite of a byte-oriented parser is a behaviour change until proven otherwise,
and the proof is a differential reconstruction, not a green test suite.

### Prose rules audited by hand

**`Deref` for fake inheritance (section 7).** Five `Deref` impls exist. Two were
the guideline's own bad example — `config::General` promoting every `Inbound`
field, and `component_tls::utls::UConn` promoting its inner `Conn` — and both are
gone: `General`'s call sites now name `general.inbound.<field>`, and `UConn`'s
promotion turned out to have no users at all (removing it compiled unchanged).
The three kept are collection delegation with a written rationale in place
(`SessionID` -> `[u8; 16]`, `IntRanges<T>` -> `[Range<T>]`, `socks5::Addr` ->
`[u8]`).

**Blanket impls on unsealed traits (section 8).** Nine `impl<T: Bound> Trait for
T` sites exist, eight on public traits (`BufferedReader`, `WindowedFilterTime`,
`Conn`, `Cipher`, `AsyncReadWriteUnpinSend`, `SingPacketConn`,
`EnhanceSingPacketConn`, `Ordered`) and one on a crate-private trait (`Duplex`).
The rule exists to stop a downstream implementation from colliding with a later
blanket impl; every member of this workspace is `publish = false`, so there is no
downstream implementor to collide with and no semver surface to protect. Each
site already carries a comment saying which intersection it names. Kept as-is,
deliberately, with this paragraph as the rationale.

**`..Default::default()` hiding new fields (section 3).** 18 occurrences remain
in production code (953 more sit inside `#[cfg(test)] mod tests` blocks, where
fixtures are the point). Every one of those 18 now targets a struct whose
`Default` is written out field by field rather than derived, so adding a field
stops the build at one place instead of silently defaulting at eighteen:
`BaseOption`, `BasicOption`, `PubClientHelloMsg`, `Config` (`component-tls`),
`Metadata`, `NetworkAuthenticationInfo`, `PeerPathState`, `NetworkConfigData`,
`Network`, `FrameRuleDecision`. `VerifyOptions`, `FragmentAssembly` and
`Event` already had manual impls. This is the protection the rule asks for
without duplicating 25-35 field lists at each call site.

**Naming.** No identifier survives in an upstream spelling: zero lowerCamelCase
function or method names in the tree (rustc's `non_snake_case` would have flagged
them anyway, and the burn-down renamed the rest, e.g. `conn` fields that shadowed a
type). Doc comments describe the behaviour in this tree's own terms; they quote no
expression from another implementation.

**Async cancel safety (section 5).** The rule covers the async functions this
tree awaits *inside* a `select!` arm, because that is where a future can be
dropped mid-flight. Every one of them now carries a note. At the time of this audit that was 59
implementations (`accept`, `wait_read_from`, `round_trip`, `receive_datagram`, `handshake`,
`read_packet_bundle`, `write_all`, `read_exact`, `get`, `wait`, `send`,
`recv`, ...) across 41 files, each judged against its own body -- delegation to
a wrapped conn inherits that conn's answer, a `poll_fn` over `self`'s state
machine resumes, a channel `recv` leaves the item queued, a `read_exact`/framed
read or a handshake that has already written is `NOT cancel-safe` and says so
with the reason. 92 notes were added in this pass; the tree now carries 145 of these notes
across 92 files.

The wider metric -- functions that merely *contain* a `select!` and are not
themselves awaited in one -- was recorded as 174 of 283 (61%) at the time; re-derive it before
relying on the ratio. Those are not covered by the
rule (nothing cancels them from outside), so their absence is not a finding;
any of them that later becomes an arm of someone else's `select!` needs a note
at that point.

### Supply chain (section 10)

`cargo deny check` and `cargo audit` are clean, with two documented ignores that
both live in `deny.toml` and `.cargo/audit.toml` (same advisory, same reason, in
both files, because the two tools read different configs):

- `RUSTSEC-2023-0071` (Marvin attack on `rsa` decryption, no fixed release): the
  tree uses `rsa` only for PKCS#1 v1.5 signing and PKCS#8 encoding of locally
  generated CA certificates (`component-ca`) and PSS verification of a server
  key (`restls`) — never decryption of attacker-supplied ciphertext, which is the
  operation the attack targets.
- `RUSTSEC-2025-0134` (`rustls-pemfile` unmaintained): reachable only through
  `geiserx_tailscale` -> `geiserx_ts_control`; nothing in this workspace names it
  in a manifest or calls it (`cargo tree -i rustls-pemfile` confirms the path).

Wasmtime is 49.0.3; `instant` and `lru` do not appear in the lockfile. The #171 dependency repair
also uses rustls 0.23.46, zip 9.0.5 and geiserx_tailscale 0.57.7 (ruzstd 0.9.1).
YAML consumers use the maintained `yaml_serde` 0.10.7 with `libyaml-rs` 0.3.0 instead of
`serde_yaml` and unmaintained `unsafe-libyaml`. Existing advisory exceptions are unchanged.

## Per-change checklist

`RUST_GUIDELINES.md`'s section 13 checklist applies to changes, not to the tree
as a whole, so it is not "satisfied" by this review. Three of its items are worth
watching in this codebase specifically, because the tree tripped each of them
during that sweep:

- *No `..Default::default()` hiding new fields* — enforced by the manual `Default`
  impls listed above; do not add a derive back.
- *Every async fn that may run inside `select!`/`timeout` carries a cancel-safety
  note* — satisfied for every arm in the tree today; re-audit when a new arm is
  added, because nothing enforces this one.
- *No `Deref` for fake inheritance* — the two instances are gone; the three
  remaining impls are delegation to a collection and say so in a comment.
