# murmur

murmur is a Rust proxy core. It reads the Clash-compatible YAML configuration format and exposes
the matching HTTP control API, so configs and controller clients written for that interface drive it
unchanged: the same `proxies` / `proxy-groups` / `rules` sections, the same `mixed-port` and
`external-controller` keys, the same `/proxies`, `/configs`, `/rules`, `/connections` and `/logs`
endpoints. That compatibility is deliberate — it is what lets this binary run side by side with
another implementation of the same interface against real proxy servers, and be checked against it,
rather than only against its own test suite. Where the documentation needs a baseline for a
compatibility claim it says **the reference**: another implementation of that interface, which
`tools/diff_sweep.py` (see [`docs/verification.md`](docs/verification.md)) can start and probe
beside this binary, `tools/e2e_vm.py` drives both through a fixed set of controlled scenarios in a
disposable NixOS/QEMU/KVM guest, and `tools/e2e-pc` runs the native protocol stability suite on the
build host.

Internally the design is idiomatic Rust: closed enums where a dynamic dispatch would otherwise be
needed, `Option` for absence instead of a zero value, typed errors instead of stringly-typed ones,
and `unsafe` denied outside a handful of justified, audited exceptions. Code paths that were carried
but never reached were deleted rather than kept.

## Quick start

```sh
nix develop .        # rustc/cargo/clippy/rustfmt + cargo-deny/audit/machete/nextest/typos/sccache
cargo check --all-targets
cargo test --workspace
cargo build --bin murmur --release
./target/release/murmur -f /path/to/config.yaml
```

Common CLI flags:
- `-f <path>` — configuration file path (`-f -` reads from standard input)
- `-d <dir>` — working directory for providers, cache, geodata, and UI assets
- `-t` — parse and validate the configuration, then exit without starting listeners
- `--watch-config` — automatically reload the configuration file when it changes on disk
- `-v` — print version, target, protocol set, and build tags

On the shared development hosts, compile through `tools/cargo-slot` so builds run in a bounded remote
slot on `pc` rather than locally; see [`docs/building.md`](docs/building.md) for cross-compilation
and router build profiles (`--features router`, `--features router-vvt`, `--profile compact`).

## Router deployment

For OpenWrt and Keenetic/Entware deployment, start with the self-contained
[LLM setup runbook](docs/router-setup.md) (or its
[shareable copy](https://gist.github.com/labi-le/6da046cc76cdd9b32bc965fe82823632), which does not
require repository access). It separates OpenWrt from Keenetic/Entware, starts with an isolated
loopback proxy, and requires recovery checks before changing LAN routing or DNS.

## Documentation map

Detailed technical reference is split by topic under `docs/`:

| Document | Contents |
| --- | --- |
| [`docs/router-setup.md`](docs/router-setup.md) | Step-by-step router installation, DNS/TPROXY/TUN setup, and rollback runbook |
| [`docs/building.md`](docs/building.md) | Toolchain, `--watch-config` reload semantics, admission behavior, and ARM64/MIPS OpenWrt builds |
| [`docs/architecture.md`](docs/architecture.md) | 89-crate workspace map, request lifecycle, correctness invariants, and concurrency hazards found under load |
| [`docs/protocols.md`](docs/protocols.md) | Per-protocol implementation status, dial-time engine caveats, and known limitations vs. the reference |
| [`docs/benchmarks.md`](docs/benchmarks.md) | Real-process workloads (`bench_workloads.py`), Criterion microbenchmarks, DHAT allocation accounting, and CPU/heap profiling |
| [`docs/verification.md`](docs/verification.md) | Test suite, CI/release gates, differential sweep (`diff_sweep.py`), VM/native E2E harnesses (`e2e_vm.py`, `e2e-pc`), and closed defect log |
| [`docs/guidelines-review.md`](docs/guidelines-review.md) | Lint posture, supply-chain audit, and verification history against [`RUST_GUIDELINES.md`](RUST_GUIDELINES.md) |

## Licence

murmur is licensed under the GNU General Public License, version 3 only; every crate manifest
declares `license = "GPL-3.0-only"`. The full text is in the repository's `LICENSE` file.
