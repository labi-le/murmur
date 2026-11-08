# Building, runtime operations, and router builds

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

For VLESS, Trojan, VMess, Shadowsocks, Hysteria2 and AnyTLS only, use
`--no-default-features --features router-vvt`. This retains their transport variants,
DNS, rules/providers, the controller, mixed inbound and TUN/redir/TPROXY
infrastructure. It omits other optional proxy protocol
implementations; a configuration or provider containing an omitted protocol fails
explicitly instead of dropping that entry. Shared transport and crypto dependencies
remain where retained protocols or the TUN stack need them.

`extra-protocols` is enabled by default and by `router`. Cargo features are additive:
adding it to `router-vvt`, or unifying workspace defaults, restores the full protocol
set. `-v` reports the effective protocol set and the checkout it was built from as
`Commit: <hash>`; `/version` exposes `protocol-set`, `core-update` and the same `commit`.
Full builds use `version.txt` and the normal release assets. Reduced
builds on non-Android Linux ARM64 musl use `version-vvt.txt` and
`murmur-linux-arm64-vvt-<version>.gz`, attached to a published release by
`.github/workflows/release-vvt.yml`, which also attaches the soft-float MIPS asset
`murmur-linux-mipsle-softfloat-vvt-<version>.gz` (`.ipk` package `murmur-vvt`,
`mipsel_24kc`) built by the same `router-vvt` profile in the `mipsel-musl` shell; the
nightly matrix builds both reduced targets as well. A reduced
build for any target other than ARM64 musl refuses `POST /upgrade` before downloading
or replacing anything, even with `force=true`, so a MIPS VVT install is updated by
reinstalling the artifact. UI and geodata updates remain available.

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

### CI toolchain cache

The nightly and release jobs enter a flake shell with `nix develop .#<shell>` before
building. Every shell's closure comes from `cache.nixos.org` except the soft-float
MIPS cross set: the flake instantiates it with a custom `crossSystem`
(`arch = mips32r2`, `abi = 32`, `float = soft`), so `musl-mipsel`, `binutils`,
`gcc-15.3.0` and the cross `rustc` are built from source on a runner. That is ~38 of
the ~46 minutes a MIPS job spends; the `cargo build --profile compact` itself is ~7.

`.github/workflows/nightly.yml` and `release-vvt.yml` therefore push and pull through a
Cachix cache named by `CACHIX_CACHE` (`murmur-lab`), and `warm-nix-cache.yml` builds
every shell once and pushes it. Both need a repository secret `CACHIX_AUTH_TOKEN` for
that cache; without it the Cachix steps are skipped and each job rebuilds its toolchain,
which is slower but correct. Re-run the warm workflow after a `flake.lock` or
`flake.nix` change.

Sizing measured from the closure itself — every output path of a shell checked for a
`cache.nixos.org` narinfo: the `mipsel-musl` closure is 1,692 paths / 1,789 MiB, of
which the uncached part is ~0.5 GiB, and `aarch64-musl`, `x86_64-musl` and `windows`
have a handful of tiny uncached wrappers each. A 5 GiB cache holds all of them.
