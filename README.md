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
`tools/e2e_vm.py` drives both through a fixed set of controlled scenarios in a disposable
NixOS/QEMU/KVM guest, and `tools/e2e-pc` runs the native protocol stability suite on the build
host.

Internally the design is idiomatic Rust: closed enums where a dynamic dispatch would otherwise be
needed, `Option` for absence instead of a zero value, typed errors instead of stringly-typed ones,
and `unsafe` denied outside a handful of justified, audited exceptions. Code paths that were carried
but never reached were deleted rather than kept.

For router deployment, start with the self-contained [LLM setup runbook](docs/router-setup.md).
Its [shareable copy](https://gist.github.com/labi-le/6da046cc76cdd9b32bc965fe82823632)
does not require repository access. It separates OpenWrt from Keenetic/Entware,
starts with an isolated proxy and requires recovery checks before LAN routing changes.

The `x86_64-musl`, `aarch64-musl`, `mipsel-musl` and `windows` Nix shells select
their target toolchains. The MIPS shell uses MIPS32r2/o32 soft-float throughout
the C runtime and native dependencies; do not mix hard-float CRT objects with
Rust's soft-float target. Shared 64-bit counters use `portable-atomic`, retaining
native atomics where available and a lock-based fallback on MIPS32. This does
not establish compatibility with every router kernel; inspect the artifact ABI
and test it before replacing a working service.

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
commands bypass the slot limit. Slot locks sit in `/drive/tmp/cargo-slots`;
`CARGO_SLOT_DIR` moves them when that path is unavailable, and an unwritable
slot directory stops the wrapper with exit status 2 instead of waiting forever
for a slot it cannot create.

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

During startup or configuration apply, external TCP admissions wait for the completed
configuration instead of closing immediately. At most 64 TCP admissions wait at once,
each for up to five seconds. UDP retains its bounded queues and the same deadline;
an independent bounded internal queue lets provider traffic progress during loading.
Consecutive successful applies preserve pending requests. Cancellation, shutdown or
an apply error rejects pending traffic and leaves new admissions suspended until a
successful apply; a parse rejection leaves the previous configuration running.
Established flows keep their existing connections. Changing listener addresses can
still recreate sockets, and queue overflow or an apply exceeding the deadline can
still reject traffic. This admission barrier is not a transactional rollback of
configuration components that have already changed.

The binary prepares the shared UDP dispatch queues and workers before applying its
initial configuration, avoiding their construction on the first-packet receive path.
Configuration-test mode (`-t`) does not start them. Library users retain lazy UDP
initialization unless they call `murmur_tunnel::tunnel::prepare_udp()` on the runtime
that will serve traffic; the process-global workers cannot migrate between runtimes.
Queue bounds and admission rules are unchanged.

A native paired experiment with 20 fresh processes per arm and 16 synchronized
senders of 16,000-byte payloads measured 33/320 cold losses before eager preparation
and 4/320 with binary-startup preparation. Both warmed arms lost 0/320. The remaining
losses still matched the listener's kernel drop counter. Moving dispatcher creation
off first-packet ingress reduces the observed cold-burst loss, but does not establish
zero-loss delivery or explain every cold-start cost. These measurements are not
router UDP evidence.

A follow-up measured the listener's effective receive buffer as 212,992 bytes.
Across 480 fresh native processes, 8 of 4,800 burst datagrams were lost, all matched
by listener kernel-drop increments; losses also occurred after a successful UDP
warmup. A standard socket with the same buffer, held until all senders finished,
accepted only three of four 60,000-byte frames or twelve of sixteen 16,000-byte
frames. The full bursts require more queue memory than that buffer holds. This
establishes a finite burst-capacity limit, not identical scheduling between the
proxy and the control, and does not justify claiming loss-free UDP.

TCP loopback detection distinguishes physical peer endpoints for HTTP and SOCKS
inbounds, so unrelated sockets sharing a source address and port do not reject each
other. Registrations are counted and removed independently when each connection
closes. Transparent or incomplete inbound metadata retains conservative source-only
matching; the requested proxy destination is not used as the physical peer.

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

For a reduced router build, add `--no-default-features --features router` to the Cargo
command. This keeps TUN, WireGuard and the ordinary proxy transports, but excludes
EasyTier/Wasmtime/WASI, Tailscale and ZeroTier from the selected binary's dependency
graph. Configurations requesting an omitted engine fail explicitly. The default build
still includes these engines. Positive `easytier`, `tailscale` and `zerotier` features
select dependencies; existing `no_*` flags deny configuration and cannot subtract a
dependency selected elsewhere. `--features router` without `--no-default-features`,
or building the entire workspace together, can therefore retain unwanted engines.
Version output reports unavailable engines.

For VLESS, Trojan and VMess only, use `--no-default-features --features router-vvt`.
This retains their transport variants, DNS, rules/providers, the controller, mixed
inbound and TUN/redir/TPROXY infrastructure. It omits other optional proxy protocol
implementations; a configuration or provider containing an omitted protocol fails
explicitly instead of dropping that entry. Shared transport and crypto dependencies
remain where retained protocols or the TUN stack need them.

`extra-protocols` is enabled by default and by `router`. Cargo features are additive:
adding it to `router-vvt`, or unifying workspace defaults, restores the full protocol
set. `-v` reports the effective protocol set; `/version` exposes `protocol-set` and
`core-update`. Full builds use `version.txt` and the normal release assets. Reduced
builds on non-Android Linux ARM64 musl use `version-vvt.txt` and
`murmur-linux-arm64-vvt-<version>.gz`, published by `.github/workflows/release-vvt.yml`;
a reduced build for any other target refuses `POST /upgrade` before downloading or
replacing anything, even with `force=true`. UI and geodata updates remain available.

The current ARM64 compact VVT artifact is 18,125,952 bytes. Isolated OpenWrt
checks exercised Trojan, VLESS Vision framing and VMess AEAD through HTTP/SOCKS,
fake-IP DNS, provider refresh rejection, controller reload rejection and the
reduced updater's target gate. TCP redir, TCP/UDP TPROXY and TCP/UDP TUN passed
exact-payload checks, REJECT controls and DIRECT recovery in owned namespaces.
These fixtures do not cover every retained transport variant.

The shared userspace TCP stack drains accepted writes before FIN and keeps dropped
streams' sockets alive for acknowledgements and retransmission. This prevents a
client half-close from truncating the reverse stream with RST. A socket whose last
stream owner has gone has at most 30 seconds to finish transport shutdown before
an explicit abort; live half-closed streams keep their existing deadline behavior.
The regression covers a 128 KiB request and 256 KiB reverse response through EOF.
The ARM namespace fixture verifies the original 32 KiB half-close failure end to end.

Use the same ARM command below with `router-vvt` in place of `router`. Test the
reduced configuration with the explicit package list in the `router-features` CI
job, not `--workspace`, which can re-enable the default protocol dependencies.

`router` does not enable `diagnostic-profiling`; the normal/default build does.
Excluding CPU sampling and symbolization reduced the ARM64 compact router binary
from 26,495,528 to 26,099,816 bytes (395,712 bytes, 1.49%). `/debug/pprof/profile`
and `/debug/pprof/symbol` answer 501 in that build while the rest of the controller
API keeps working; a test exercises both feature states.

On the OpenWrt ARM CPU, seven paired runs of 20,000 scans over 256 nonmatching
domain rules measured median scan times of 6.61 us bare and 20.53 us with the real
statistics wrapper. At 1,024 rules the medians were 27.54 and 81.81 us. These are
single-threaded monotonic wall times, not contention measurements or a cost
attributed to one atomic instruction. Exact hit/miss counts were checked outside
timing. A SeqCst read fast path now skips the read-modify-write when the outcome bit
and `STAMPED` are already set and no sampling boundary is due; tests check exact
concurrent counts and that a boundary still refreshes the timestamp. The Criterion
last-hit fixture checks an actual final-rule match; its former purported hit input
matched no rule.
Raw samples and build evidence are under `/drive/tmp/murmur-release-20261024/`.

Use `--profile compact` instead of `--release` for a size-oriented build. This
profile uses `opt-level = "s"`, full LTO, one codegen unit and stripped symbols.
It retains `panic = "unwind"` because connection and session handlers catch panics;
it does not change the selected features. The normal release profile is unchanged.

```bash
timeout 1800 env CARGO_TARGET_DIR=openwrt-compact CARGO_BUILD_JOBS=2 \
  tools/cargo-slot bash -c 'nix develop .#aarch64-musl --command cargo build -j2 --locked --profile compact -p murmur --bin murmur --no-default-features --features router --target aarch64-unknown-linux-musl'
```

The artifact is on `pc` at
`/home/labile/.cache/cargo-pc/openwrt-compact/aarch64-unknown-linux-musl/compact/murmur`.
On the 2026-10-24 source tree, the same-feature stripped static ARM64 comparison was:

| Optimization | LTO | Bytes |
| --- | --- | ---: |
| Existing release | Default | 61,568,392 |
| `s` | Thin | 33,387,728 |
| `z` | Thin | 29,586,672 |
| `s` (`compact`) | Full | 26,495,528 |
| `z` | Full | 22,497,808 |

These are executable sizes, not package sizes or RSS. The smallest measured
same-feature build is 22.5 MB (21.5 MiB), not a demonstrated 10-20 MB build.
All four candidates passed native ARM HTTP/SOCKS bulk payload checks, UDP exchanges
from 512 through 65,000 bytes and 30 configuration reloads each. Both full-LTO builds
also passed six external VLESS/REALITY/Vision HTTPS requests each. These checks cover the
exercised paths, not every compiled protocol. Measurements and hashes are retained
under `/drive/tmp/murmur-compact-20261024/`; full LTO takes longer to build.

In longer fixed-byte LAN runs, baseline, full-LTO `s` and full-LTO `z` each verified
320 MiB of measured TCP application traffic plus warmup and 24 UDP exchanges.
Candidate-process CPU time was 3.56 s, 3.43 s and 4.23 s respectively. The compact
profile selects `s`: the measured CPU cost did not increase, while `z` used about
19% more CPU than baseline. Peak sampled RSS was 18,268, 14,416 and 14,116 KiB.
Combined upload/download goodput was 23.30, 25.03 and 26.05 MiB/s, but Wi-Fi and
fixture timing prevent interpreting those differences as speedups. These runs
do not establish equal CPU performance for every protocol or under saturation.

The router profile enables `with_low_memory`: TCP relay buffers are 16 KiB. UDP
receive buffers remain 64 KiB in both profiles to preserve large datagrams; reducing
receive capacity to 8 or 16 KiB silently truncated packets. Idle allocator payload is
bounded to 3,520 KiB across its size classes, plus at most 1,024 KiB in the BytesMut
pool. The combined 4,544 KiB bound excludes metadata, active buffers, protocol state,
rules, providers and DNS caches. It is not a process RSS limit or an admission limit
on concurrent connections. Retained allocator blocks are wiped before reuse.

UI ZIP/tar members and core ZIP executables stream through the unpacked-size limiter
into staged files rather than allocating a buffer for each complete member. Decoder,
limit and write errors remove partial members; UI extraction failures leave the live
installation untouched. The compressed UI download still resides in memory.

On 2026-10-24, native x86_64 router-release runs against a local controller/HTTP fixture
installed a 32 MiB member with these sampled process RSS peaks:

| UI archive | Before streaming (KiB) | Streaming (KiB) |
| --- | ---: | ---: |
| ZIP | 63,884 | 13,716 |
| tar.gz | 56,004 | 13,988 |

Both builds preserved the installed files after corrupt-archive requests. These are
single-run process measurements with highly compressible fixture contents, not an
ARM memory limit or a steady-state proxy improvement.

Routing creates DNS/pass-rule callbacks only in RULE mode and process callbacks only
when process rules can use them. Hosts lookup and ALWAYS process enrichment retain
their ordering. A DHAT probe of the production metadata-resolution function measured
5 allocations / 120 bytes becoming zero in DIRECT/GLOBAL with process lookup OFF or
STRICT, and for INNER traffic. RULE with process lookup OFF or INNER traffic fell
from 5 allocations / 120 bytes to 3 / 72; external RULE/STRICT remained 5 / 120.
The probe excludes metadata construction, uses empty rules and does not measure full
connection throughput. External ALWAYS process discovery depends on the live OS
process table and is not included in those fixed allocation comparisons.
Evidence is retained under `/drive/tmp/murmur-opt-20261024/`.

The 2026-10-20 stripped static ARM64 router artifact is 61,502,824 bytes, compared
with 94,098,248 bytes for the preceding full build. This is a binary-size comparison,
not evidence of proportional RSS savings. Both native and ARM builds use the same
router feature selection.

Router-profile validation on 2026-10-20 passed 17 controlled VM scenarios with
256 MiB assigned RAM and no swap; the optional real-node sweep was not requested.
The guest reported 213,824 KiB usable memory. The mixed burst/idle/burst completed
1,908 TCP requests, 1,920 UDP exchanges and 444 DNS queries without failure. Kernel
OOM kills stayed at zero; the largest observed murmur high-water mark across the
suite was 14,384 KiB. Minimum guest available memory was 12,072 KiB, including the
test harness, fixtures and reference processes. These small synthetic rules and
provider sets do not establish the footprint of a large subscription.

An isolated ARM64 OpenWrt canary passed 193 exact TCP upload/download transactions,
256 UDP checks up to 65,000 bytes in both directions, 64 stable distinct fake-IP
names and DIRECT/REJECT/provider routing. Its peak RSS was 23,396 KiB and HWM
23,740 KiB. The device has 496,508 KiB RAM, so this is ARM runtime evidence, not
the 256 MiB capacity proof. The preceding mixed run lost one 32,000-byte UDP request;
the later diagnostic run had no failures or kernel reassembly-error increments.
The original loss remains unexplained. The old binary reproducibly truncated large
requests to 16,374 bytes and responses to 16,384 bytes; the router build preserved
the full payload. Production service, firewall and configuration were unchanged.
Evidence is under `/drive/tmp/murmur-router256-20261020/`, especially
`vm256-final/results.json`, `baseline-udp-reachable/results.json`,
`candidate-full/results.json` and `candidate-full-diagnostic/results.json`.

The final source-matched ARM run also preserved all sizes in the focused UDP check.
Its concurrent run lost one 8,192-byte response: the capture shows the full advertised
response forwarded to the correct client, while client counters show one missing
fragment and a later reassembly timeout. This localizes that failure to IP fragment
delivery/reassembly after application forwarding, not buffer truncation; the exact
driver, wireless or ingress loss point is unverified. That run remains failed rather
than being replaced by the successful focused check. See `final-arm-smoke/results.json`,
`final-arm-loss-investigation.json` and `final-arm-udp/results.json` in the same directory.

Verification ran 3,333 workspace tests successfully (three skipped), followed by
targeted tests after lint-only fixes. Formatting, all-targets/all-features clippy,
router-only clippy and default/minimal feature checks passed. Machete found no unused
dependencies. Wasmtime and WASI require at least 49.0.4 to address
[RUSTSEC-2026-0378](https://rustsec.org/advisories/RUSTSEC-2026-0378) and
[RUSTSEC-2026-0379](https://rustsec.org/advisories/RUSTSEC-2026-0379). The lockfile
includes the matching Cranelift patch release. The router dependency graph excludes
Wasmtime; the full build uses the patched engine. Neither advisory is suppressed.

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
that state rather than a nonzero delay alone to validate node availability. At
the configured test timeout the probe is asked to cancel; the check awaits its
completion so the failed measurement is published instead of leaving the node's
previous state in place. Adapters that do not observe the cancellation token can
delay that publication past the deadline. The timeout watch is owned by the probe
and is retired as soon as the probe finishes.

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

Eleven kinds of bug have shown up repeatedly in this tree, each costing real debugging time before its
root cause was understood. Each is a case where code compiled, type-checked, and passed under light
load, and then broke under a load shape it did not preserve.

1. **A lost guarantee.** `tokio_rustls`'s `TlsStream` behaves like a buffered writer: `poll_write`
   can report the plaintext as consumed while the ciphertext is still sitting in an internal
   buffer, and only `poll_flush` guarantees it reaches the peer. A `write_all(...).await` with no
   following flush strands a fraction of requests in the TLS buffer forever under concurrency. This
   was found once in the VMess WebSocket client, then found six more times elsewhere in the tree by
   an audit for the same shape (write, then await a reply, over a TLS-wrapped connection).
   WebSocket data, Pong/Close replies, explicit close, and flush now share one whole-frame
   writer owner, including every partial write and flush. Read-side control decoding does not
   acquire that owner until the complete response is ready. On backpressure an accepted data
   frame keeps its owned writer guard in a drain task, so cancelling the caller cannot strand
   a partial frame or let a small control header resume another writer's pending TLS record.
   `poll_write` accepts at most 16 KiB from the current buffer; `flush` waits for the accepted
   frame and reports retained write errors. A pending write waiting for ownership accepts no
   bytes, so replacing its buffer cannot receive an earlier caller's completion length.
   Dropping the WebSocket owner cancels any blocked drain and releases its underlay. An explicit
   `close()` transfers that lifetime to the existing five-second best-effort close task, keeping
   preceding data ordered even if the wrapper is dropped immediately afterward.
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
   HTTP/2 had a separate serialization bug: the sender mutex stayed locked while waiting for
   download response headers, blocking packet-up uploads when the peer withheld those headers
   until upload data arrived. The transport now releases the mutex immediately after dispatching
   each request. A real-H2 regression with delayed download headers covers custom GET uploads;
   an isolated ARM router smoke with all 171 subscription nodes verified an exact 65,536-byte HTTPS
   response and valid UDP DNS through the previously failing XHTTP node.
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
   Hysteria2 also needs explicit ownership at cancellation boundaries: each client reuses one
   QUIC endpoint, so retired connections still draining cannot compete with replacements for
   reads from the cached UDP socket. Dropping the socket adapter aborts its receive/send workers
   without closing that socket. Caller cancellation and client shutdown interrupt connection
   establishment and authentication; abandoned authentication closes its provisional connection
   rather than leaving the offer mutex or HTTP/3 driver alive. Controlled real-UDP and QUIC/HTTP3
   regressions cover datagram preservation, a single concurrent packet reader across reconnects,
   cancellation, peer-observed closure and a successful subsequent dial. These tests do not
   establish the cause of the separately observed persistent real-node failure.
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
7. **Acknowledging a buffer the writer no longer owns.** `RealityStream::poll_write` kept a copy
   of the first call's plaintext in its in-flight record future, but on completion reported the
   length of whatever buffer the caller passed on the latest poll. A multiplexed HTTP/2 caller
   legitimately grows that buffer between polls by appending control frames, so REALITY
   acknowledged bytes it had never encrypted or sent. The peer's receive window had already been
   credited for them, and downloads stalled after a few megabytes while a fresh handshake and
   small requests still worked. `poll_write` now accepts at most one bounded TLS plaintext record,
   acknowledges only that prefix, and drains it from later writes, `flush`, `shutdown` and
   read-side polls; a separate writer task is woken when a read poll drives its record to
   completion. Byte-exact regressions cover appended and replacement caller buffers, the bounded
   acceptance, flush without another write, and the split read/write wake path. The same isolated
   ARM router completed four concurrent 8 MiB downloads and exact 256 KiB uploads through XHTTP
   and gRPC REALITY nodes that previously stalled, with recovery after each cancelled stream.
8. **A packet conn that serializes its two directions.** The VMess and Snell outbounds kept
   their UDP connection behind one mutex and held it across `recv_from`. The tunnel's receive
   loop re-enters that call as soon as it hands a response back, so it owned the lock while
   waiting for the next response, and the next `send_to` could never deliver the request that
   response depended on. The first datagram in an association worked; every later one timed
   out. Both outbounds now split the stream into independently locked read and write halves.
   A regression drives the eager-read pattern for each, and the protocol suite reports 20/20
   answers on one association and 20/20 across four reconnects for VMess over TCP, WS and gRPC
   and Snell v4. VLESS, Trojan, Shadowsocks, AnyTLS, Hysteria2 and TUIC already had
   independent directions.
9. **A cached QUIC session that outlives its peer.** After a reference-server restart TUIC
   kept its cached QUIC connection. `open_stream` waited on the dead session, the outer dial
   timeout cancelled the request without clearing the cache, and every later request reused
   it. Stream opening and the connect write are now bounded at five seconds, the cached
   session is force-closed, and the dial retries once on a fresh connection. The restart phase
   recovers; a request that lands on the dead session can still fail once before the retry
   clears it. Hysteria2 has no such cache and recovers at the 30-second idle timer, as the
   reference does.
10. **One certificate watcher per listener.** Every TLS listener built its own
    `new_tls_key_pair_loader`, and every loader installed a `notify` watcher on the same
    certificate and private-key paths. With two listeners sharing those files the second
    `watch` call waited on a callback the first watcher was running, and listener startup
    stopped after the first TLS listener. The loader is now cached per resolved path pair
    (a weak entry, so the watcher stops with the last listener), and two listeners share one
    watcher. A unit regression creates both loaders under a five-second timeout.
11. **A SOCKS5 preface on a Shadowsocks UDP reply.** The inbound SS UDP path built its reply
    with `socks5::encode_udp_packet`, which prepends the SOCKS5 RSV/RSV/FRAG bytes. Shadowsocks
    UDP carries the target address and payload with no such preface, so a real client could not
    parse any reply. The outbound suite never saw it because the reply was generated by the
    reference server; the inbound suite's 20/20 UDP checks found it. The reply now writes the
    address bytes and payload directly, pinned by a byte-exact unit test.

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

## Real-process workload benchmarks

`tools/bench_workloads.py` runs local, offline traffic through an already-built
native Linux murmur binary. It complements the component benchmarks below; it does
not time compilation or use a subscription. Python 3.11+, PyYAML and OpenSSL are
required. The `relay` case also needs a native reference binary for actual Vision
handoff. Each run owns its loopback listeners and child processes; use a fresh output
directory under `/tmp` or the repository's `tmp/` directory.

```sh
python3 -B tools/bench_workloads.py --list
timeout 600 make bench-workloads WORKLOAD_ARGS='--binary /absolute/path/to/murmur --reference /absolute/path/to/mihomo --smoke --workdir /tmp/murmur-workload-smoke'
timeout 900 make bench-workloads WORKLOAD_ARGS='--binary /absolute/path/to/murmur --case dns --case reload --iterations 20 --concurrency 4 --rules 10000 --workdir /tmp/murmur-dns-reload'
```

| Case | Measured workload and validation |
| --- | --- |
| `tls` | Trojan/VLESS forwarding through normal TLS and Chrome-fingerprinted TLS; unfragmented and paced small writes; cold first request and warm new connections; verified origin certificate, payloads and handshake counts |
| `healthcheck` | Real provider fanout over healthy, slow and unavailable peers; unified delay on/off; HTTP response/error matrix; observed request counts and per-node health/history |
| `relay` | Short-lived and sustained concurrent SOCKS TCP/UDP; exact payload/source validation; slow receiver with observed sender backpressure; reference Vision bulk transfers with direct-read/write handoff evidence |
| `dns` | UDP/TCP cache hits and unique misses, concurrent identical queries, real-time expiry/refresh and fake-IP identity; upstream counters distinguish cache activity from query timing |
| `reload` | HTTP/file rule-provider updates and full config application under miss-heavy traffic; observed routing generations, established-flow integrity, request errors and sampled memory peak |

`results.json` records binary hashes, native architecture, reported build tags,
parameters, raw latency samples and percentile summaries. CPU deltas belong to the
actual murmur PID over each stated measurement window; fixture CPU is excluded.
RSS snapshots and process-lifetime high-water marks are not live heap measurements.
Startup includes full configuration/provider initialization: the runner waits for its
owned `-post-up` marker before checking the controller. A successful `/version` response
alone is not a data-plane readiness signal. Startup and scenario warmups are reported
separately or excluded explicitly. DNS expiry includes stale-while-revalidate behavior,
not an assumed synchronous miss. Health-check cache-expiry waits are outside its
measured windows.

The UDP echo fixture sizes its receive queue for the configured concurrent burst and
records the requested/effective capacity; it does not change murmur's sockets or
host-wide network settings. Exact payload and source checks remain mandatory.
UDP response timeouts produce a degraded row with attempted/delivered/lost counts,
per-attempt timestamps and per-socket kernel drop evidence. They are not retried or
included in successful-response latency percentiles. Incorrect payloads or source
addresses remain validation failures.

Vision switches to its raw transport before the recognized inner application-data
record: an empty-content DIRECT frame is flushed through outer TLS, then the original
inner record bytes follow unchanged. It never puts an arbitrary 4096-byte ciphertext
prefix inside the final padded frame. That split left a random ciphertext suffix at
the raw boundary, which an outer TLS reader's alert read-ahead could mistake for a
TLS alert and close before the upload completed. The same boundary applies to
fingerprinted and ordinary TLS connections; workload failures are not retried.

Exit status 0 means the workload validations passed; 1 means a runner or validation
failure; 2 means a completed but degraded measurement. Any interrupted requests remain
in the reload results even when established connections survive. The benchmark does
not treat controller HTTP 204 as proof of uninterrupted service. Use the same
parameters and native build features for comparisons; smoke counts establish
coverage, not statistically useful p99s.

Run allocation profiling separately with `--mode heaptrack`. It requires Heaptrack
on the executing host and retains raw artifacts in each process directory. These
profiles include startup, setup and warmup; their instrumented timings must not be
compared with clean timing runs. Missing profiling support is an error, not zero
allocations. For ARM/low-memory measurements, run the same script with native ARM
binaries and record their build tags; running an x86 binary does not establish ARM
performance. The runner does not deploy binaries or change router configuration.

## Component benchmarks

Nine crate-local [Criterion](https://criterion-rs.github.io/book/) targets exercise production
APIs without changing the proxy's public interfaces:

| Target | Workloads |
| --- | --- |
| `vless` | IPv4/domain/IPv6/UDP/MUX first-write request framing; established memory-stream writes; Vision padding encode/decode/roundtrip at 64 B, 1 KiB and 16 KiB; VLESS AES-256-GCM and ChaCha20-Poly1305 seal/open/roundtrip |
| `v4_read` | Snell v4 decode of pre-encoded maximum-length records through the production `AsyncRead` at 1 B, 64 B, 512 B and one-full-record consumer windows; the fixture, salt exchange and AEAD key derivation sit outside the timed region |
| `domain_match` | DomainSet/DomainMap/DomainTrie lookup over 10,000 generated patterns plus boundary cases; builds at 100/10,000 patterns; IPv4/IPv6 CIDR hit/miss |
| `fakeip` | In-memory lookup hit and bounded eviction/miss, reverse lookup and existence; the miss workload rotates 8,192 hosts through a 256-entry pool across measurement batches |
| `rule_match` | Ordered mixed-rule scans with 16/256/1,024 rules, matching first/last or missing; no DNS or network resolution. Also the `DomainKeyword` needle-search A/B: `str::contains` against the rule's cached `memchr::memmem::Finder` over 14/64/253-byte hosts, empty/one-byte/ASCII/non-ASCII needles, early/late/miss/shared-prefix cases, and keyword chains of 0/1/16/51/256 rules |
| `buffer_pool` | Buffer get/put, fill, and cold allocation/free at 64 B through 128 KiB, including an unpooled size above the 64 KiB ceiling; BytesMut recycling |
| `rule_wrapper` | A bare rule chain against the same chain inside the production `RuleWrapper`, at 16/256/1,024 rules, on a full-chain miss and on a steady all-hit streak. The miss case pays a clock reading per rule because the streak gate is cold; the hit case pays it once per 256 matches |
| `udp_path` | The per-datagram metadata path the UDP entry point walks |

Five further targets are not Criterion and are not part of `make bench`:

| Target | Output |
| --- | --- |
| `alloc_census` (`make bench-alloc`) | Heap allocations per operation from `dhat` as the global allocator: `Metadata::clone`, `DomainSet::has` and `DomainMap::lookup` in ASCII and upper-case, and rule-chain scans at 16/256/1,024 rules on a first-rule hit and a full-chain miss. Prints the measured figure beside the hand count for `Metadata::clone` so a disagreement between arithmetic and measurement is visible |
| `recv_alloc` (`cargo bench -p murmur-transport-sudoku --bench recv_alloc`) | The same `dhat` accounting for the sudoku receive paths, `RecordConn` and `AEADConn`: heap blocks and bytes per decrypted frame, plus the exact receive-buffer capacity reported by the connection after a warm-up frame, at 1 KiB and 16 KiB stable and alternating sizes and at the 65,507 B protocol maximum. Both readers keep one frame buffer per connection and decrypt in place, so after one warm-up frame the measured loop must report zero blocks and the buffer capacity must stay within one protocol maximum |
| `udp_hit_path` (`make bench-alloc`) | Heap allocations per datagram on an established NAT key, before and after the borrowed-key fast path: the key clone, `Metadata` clone, metadata-cell `Arc`, maker box and `get_or_create` key copy against `key_ref` + `NatTable::get` + the packet `Arc`. This is the modeled subset; `metadata_clone` calibrates the clone against its hand count |
| `udp_dispatch` (`make bench-alloc`) | The real `handle_udp_conn` called once per datum, with fixture construction outside the window: established hits against an installed key, misses through the real `get_or_create`/maker path, both with sniffing off and with a QUIC dispatcher installed. Reports `dhat` blocks and wall-clock nanoseconds per dispatch, so the miss-side cost of the added lookup is visible; the failed dial is drained outside the miss window |
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
`domain_keyword/*` and `domain_keyword_chain/*` compare the pre-change `str::contains` needle
search with the cached `memchr::memmem::Finder` in one process, so their point estimates are a
direct implementation delta rather than a cross-run comparison. The suite currently declares
**53 `bench_function` sites** across the eight Criterion targets; several
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

`tools/bench_metrics.py` runs 34 isolated workloads through two optimized, `harness = false`
targets: `metrics_cpu` uses the normal allocator, while `metrics_heap` installs
[dhat](https://docs.rs/dhat/latest/dhat/) only in that benchmark executable. These two targets
are built by `make bench-metrics`, not by `make bench` or `make bench-smoke`; the Criterion
target list in `Makefile` deliberately omits them because this runner needs to harvest
executable paths itself and to keep the `dhat` allocator confined to `metrics_heap`. Production
binaries and Criterion targets do not use its allocator. The suite covers VLESS first/established
writes, fresh Vision encode/decode plus the four read-path split cases, AEAD, domain/IP lookup,
fake-IP forward hits, reverse hits and eviction at 256- and 1,000-entry capacities in lowercase and
mixed-case forms, rule scans and buffer reuse, plus a zero-work control and a separately named
stateful pipe diagnostic.
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

**Vision split buffers (2026-10-23):** split frames allocate for their content and
existing transport headroom rather than the generic stream-buffer capacity. Pool
returns still wipe the entire allocation. The isolated x86 Criterion encode-16-KiB
case measured 1,493.6 to 1,179.6 ns; roundtrip-16-KiB improved about 8.9%, while the
64-byte roundtrip control regressed about 2.8%. A five-million-operation low-memory
repeat measured 1,317.7 to 1,219.7 ns for encode-16-KiB. Warm allocation counts stayed
at four calls / 376 bytes per operation. These are component measurements, not ARM
or whole-proxy throughput claims. Evidence: `/tmp/murmur-opt-20261023/vision`.

**Vision read paths (2026-10-20, [#176](https://github.com/labi-le/murmur/issues/176)):** four
cases separate the read implementation from the connection lifecycle, leaving the existing
`vision_decode_1024` identity byte-for-byte unchanged. `vision_decode_async_inherent_1024` reads a
fresh concrete `VisionConn` through `AsyncReadExt::read` (the `AsyncRead` impl, statically
dispatched, not the inherent `Conn::read`); `vision_decode_async_boxed_1024` adds the
`Box<dyn ExtendedStream>` adapter the relay holds, so its operation includes the box allocation.
`vision_decode_warm_boxed_1024` and `vision_decode_alternating_boxed_1024_512` keep one warmed
boxed conn over a pre-encoded stream whose five continuation frames replay after the UUID frame:
the encoder ends padding once its filter allowance runs out, so only whole continuation frames are
replayed. All four encode outside the timed region and verify exact plaintext before returning
their runner. The pre-optimization baseline used 200,000 CPU and 2,000 heap operations per case:

| Case | Caller buffer | Read path | Blocks/op | Bytes/op | ns/op |
| --- | --- | --- | ---: | ---: | ---: |
| `vision_decode_1024` | 1 KiB, fresh conn | inherent `Conn::read` | 4.0 | 1,117 | 251.6 |
| `vision_decode_async_inherent_1024` | 1 KiB, fresh conn | `AsyncRead` impl, concrete | 4.0 | 1,117 | 259.9 |
| `vision_decode_async_boxed_1024` | 1 KiB, fresh conn | `AsyncRead` impl, boxed | 5.0 | 1,581 | 268.7 |
| `vision_decode_warm_boxed_1024` | 1 KiB, warmed conn | `AsyncRead` impl, boxed | 1.0 | 5 | 53.8 |
| `vision_decode_alternating_boxed_1024_512` | 1 KiB/512 B, warmed conn | `AsyncRead` impl, boxed | 1.5 | 770.5 | 72.6 |

In that baseline, fixed-size reads allocated a 5-byte header per frame; alternating caller
windows also replaced the scratch buffer. The current reader stores headers inline and reuses
sufficient scratch capacity while limiting each read to the caller's available window. Pending
content reads resumed with a smaller window preserve the remaining plaintext.

A paired rerun on 2026-10-20 used 1,000,000 CPU and 2,000 heap operations per case:

| Warm boxed read | Blocks/op before / after | Bytes/op before / after | ns/op before / after |
| --- | ---: | ---: | ---: |
| Fixed 1 KiB window | 1 / 0 | 5 / 0 | 54.24 / 53.26 |
| Alternating 1 KiB / 512 B | 1.5 / 0 | 770.5 / 0 | 77.70 / 78.40 |

These runs establish removal of measured allocation churn, not a timing or network-throughput
improvement. The alternating case is diagnostic; production readers normally keep a stable
window. Scratch retains the largest requested window until connection drop. Fresh-connection
cases include lifecycle allocations; the inherent `Conn::read` baseline's `b.to_vec()` is not
evidence of an allocation on each production `AsyncRead` call. Artifacts:
`/drive/tmp/router256-vision-before` and `/drive/tmp/router256-vision-after`.

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

The 2026-10-22 TLS allocation follow-up removes the per-extension temporary buffer
from `serialize_client_hello`: extensions write into a zeroed tail of the assembly
buffer, retaining only the bytes they report. A private release harness rebuilding
the same Firefox hello through `UConn::build_handshake_state` measured 89 to 63
allocations and 21,628 to 18,832 requested bytes per rebuild (five 1,000-iteration
allocation rounds, identical 1,507-byte output). Fixture construction and key
generation were outside the measurement. Ten interleaved uninstrumented rounds of
one million rebuilds had median process CPU time 2.147 s before and 2.014 s after
on the same pinned x86_64 CPU; this is not a whole-proxy or ARM throughput claim.
The original 8,650,752-byte TLS read stack belongs to rustls's deframer buffer
growth, not this serializer, and remains unchanged. The targeted TLS suite includes
short/empty/error extension writes and a real loopback TCP fingerprinted handshake
with ALPN and application data. Private measurement artifacts are retained under
`/drive/tmp/murmur-tls-opt-20261022`. A separate full-process comparison with fixed
inputs counted 502 hello serializations on each side: per-extension scratch
allocations fell from 6,501 (650,214 requested bytes) to zero. Both runs completed
all three selected-node VPN requests; each also had one DIRECT request timeout.
Background network activity prevents treating total process allocation differences
as a controlled throughput or memory-footprint improvement. This comparison used
the original dependency lockfile to isolate the serializer change.

The deployment candidate also updates `rustls-webpki` to 0.103.16 and
`webpki-root-certs` / `webpki-roots` to 1.0.10 for RUSTSEC-2026-0382,
RUSTSEC-2026-0383 and RUSTSEC-2026-0381. No advisory exceptions were added.
The hygiene target tolerates command failures, so release verification runs
`make deny && make audit` separately as blocking checks, including the vendored
dependency checks described below.

The 2026-10-23 reload-fix build also requires `ctutils` 0.4.4, which fixes
[RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html):
secret-dependent branches in mask generation and 32-bit `u128` comparisons.
The lockfile carries the patched version without an advisory exception.

Tokio is locked to 1.53.3 for
[RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html).
Linux TUN registration uses `AsyncFd::register` with an owned `File`; the descriptor
stays valid and unchanged until the registration is dropped. No advisory exception
or deprecated-constructor allowance is added.

`crypto-bigint` is locked to 0.7.6, with `ctutils` 0.4.5, for
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
The update removes reported secret-dependent branches in arithmetic intended to be
constant-time; the advisory is not excluded from dependency checks.

The workspace vendors rustls 0.23.46 with a narrow deframer growth change: consume
initialized tail space before growing the buffer. Record and handshake limits,
authentication and idle shrinking remain unchanged. In a controlled full-proxy
comparison with 56 identical handshake counts, deframer allocation traffic fell
from 7.91 to 5.02 MB. Real-node runs measured 9.80 to 3.65 MB, but differing network
fragmentation and connection counts prevent treating that reduction as a controlled
speedup. These are cumulative allocation bytes, not retained memory or RSS savings.
The custom-uTLS control passed unchanged. Evidence and limitations are in
`/tmp/murmur-opt-20261023/deframer/report.txt`.

`vendor/rustls/provenance.json` records the published archive checksum, upstream
revision, licenses and file hashes; `murmur.patch` records the source changes.
Refresh the verified upstream package and `tools/audit_vendored.py` together.
Cargo audit and deny skip path dependencies when matching advisories, so `make audit`
and `make deny` also audit a temporary lockfile containing rustls's original registry
identity. The helper checks the installed source inventory and fails on identity or
hash mismatches; it never changes the build lockfile. Run
`python3 tools/test_audit_vendored.py` in the pinned toolchain shell when updating it.
Run upstream rustls tests in a disposable copy: resolving its development lockfile
in the vendor directory would change the reviewed inventory.

The combined 2026-10-23 build completed 20 controlled proxy runs: 1,120 handshakes,
960 byte-checked HTTPS transfers and 160 health checks without errors. The normal-TLS
profile measured 838 to 348 deframer allocation events and 7,651,328 to 4,714,496
requested bytes; the custom-uTLS control still allocated no rustls deframer buffers.
Median process CPU time was unchanged at 0.25 s for normal TLS and 0.22 s for uTLS.
Three alternating five-million-operation Vision repeats measured encode-16-KiB at
1,497.48 to 1,218.78 ns in normal mode and 1,315.44 to 1,224.70 ns in low-memory mode.
The normal 64-byte encode control regressed 2.88%, while low-memory was within 1%.
These measurements justify reduced buffer work, not a whole-proxy throughput claim.
The combined binary also passed real reference Vision transfers with and without
Chrome fingerprints, checking 1,028,096-byte uploads and downloads by SHA-256.
Commands, source hashes and raw samples: `/tmp/murmur-opt-20261023/combined`.

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

## Licence

murmur is licensed under the GNU General Public License, version 3 only; every crate manifest
declares `license = "GPL-3.0-only"`. The full text is in the repository's `LICENSE` file.
