CARGO ?= cargo
ACT ?= act
ACT_BASE_IMAGE ?= rust:latest
ACT_IMAGE ?= murmur-act-rust
BENCH_PACKAGES = -p murmur-transport-vless -p murmur-transport-snell -p murmur-component-trie \
	-p murmur-component-fakeip -p murmur-rules-common -p murmur-common-pool -p murmur-tunnel \
	-p murmur-rules
BENCH_TARGETS = --bench vless --bench v4_read --bench domain_match --bench fakeip --bench rule_match \
	--bench buffer_pool --bench geodata_bridge --bench udp_path --bench rule_wrapper
# Prints heap allocations per operation rather than timings, so it is kept out of the Criterion sweep.
bench-alloc:
	$(CARGO) bench -j 2 -p murmur-rules-common --bench alloc_census
BENCH_ARGS ?=
METRICS_ARGS ?=

.PHONY: check fmt fmt-check clippy clippy-windows test nextest test-heavy bench bench-smoke bench-alloc bench-metrics gate gate-full hygiene deny machete audit typos lint act-test test-windows all

check:
	$(CARGO) check --all-targets --all-features

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

# RUST_GUIDELINES.md section 12 gate: `-- -D warnings` and nothing else. Levels live in
# `[workspace.lints]`, thresholds in `clippy.toml`, and every `allow` there carries the reason
# section 9 demands. The `-A clippy::pedantic -A clippy::nursery -A clippy::restriction`
# neutralizers this target used to carry are gone: they existed only because the tree tripped those
# families, and they had the side effect of cancelling the per-lint `deny`s the manifest sets.
# Test code is exempt at the source level (`#![cfg_attr(test, allow(...))]` in every crate root and
# `#![allow(...)]` in `crates/*/tests/*.rs`) rather than through a flag, so the exemption is
# visible in the file it applies to.
clippy:
	$(CARGO) clippy --all-targets --all-features -- -D warnings


test:
	$(CARGO) test --all-features

nextest:
	$(CARGO) nextest run --workspace --all-features --profile ci

# Explicit targets avoid forwarding Criterion arguments to the default libtest benches.
bench:
	$(CARGO) bench -j 2 $(BENCH_PACKAGES) $(BENCH_TARGETS) -- $(BENCH_ARGS)

# Run each workload once, including its correctness checks, without statistical measurement.
bench-smoke:
	$(CARGO) bench -j 2 $(BENCH_PACKAGES) $(BENCH_TARGETS) -- --test

# The runner owns the remote slot; do not wrap this target in another cargo-slot invocation.
bench-metrics:
	python3 tools/bench_metrics.py $(METRICS_ARGS)

# The two tests marked #[ignore]: real-timer soaks too slow for the default gate
# (crates/common-net/src/io.rs and crates/common-net/src/deadline/pipe.rs): not part of `gate`,
# run explicitly.
test-heavy:
	$(CARGO) nextest run --workspace --all-features --run-ignored ignored-only --profile ci \
		-E 'test(deadline_token_clear_always_wins_a_race_with_the_firing_timer) | test(pipe_deadline_set_always_wins_a_race_with_the_firing_timer)'

# Cheapest correct pre-commit gate. `cargo clippy` only wraps the workspace crate itself in
# clippy-driver (`RUSTC_WORKSPACE_WRAPPER`); every dependency is still built by plain rustc under
# cargo's normal fingerprinting, so nextest and clippy always share identical dependency
# artifacts regardless of order — running clippy before or after never reuses the *murmur* crate's
# compile between the two (it is a distinct cargo unit per wrapper), so that part is always paid
# twice. Building the test binary first (nextest) warms every dependency once; clippy afterward
# then only pays for its own murmur pass plus the `--all-targets` bin target nextest never
# touches, instead of also paying full dependency compilation again.
gate: fmt-check nextest clippy hygiene

gate-full: gate clippy-windows test-heavy

# Wired into `gate` but non-blocking, so a missing tool or an unreachable advisory database
# cannot fail the gate. Read the output: a successful `make gate` alone does not establish
# clean dependency hygiene. The accepted advisory exceptions are documented in `deny.toml`
# and mirrored in `.cargo/audit.toml`; duplicate-version warnings remain informational.
# Keep the `-` prefixes. `lint` runs these checks as blocking targets, alongside spelling.
hygiene:
	-$(CARGO) deny check
	-$(CARGO) machete
	-$(CARGO) audit

deny:
	$(CARGO) deny check

machete:
	$(CARGO) machete

audit:
	$(CARGO) audit

typos:
	typos crates

lint: fmt-check clippy deny machete audit typos

act-test:
	printf 'FROM %s\nRUN apt-get update && apt-get install -y --no-install-recommends nodejs && rm -rf /var/lib/apt/lists/*\n' '$(ACT_BASE_IMAGE)' | docker build -t $(ACT_IMAGE) -
	$(ACT) push -j test -W .github/workflows/test.yml \
		--pull=false \
		--matrix os:ubuntu-latest \
		-P ubuntu-latest=$(ACT_IMAGE)

# Matches release.yml's Windows build (`cargo build --release --target x86_64-pc-windows-msvc
# --bin murmur`, no --features flag): default features only, i.e. with_gvisor on and cmfa/
# no_easytier/no_tailscale off, the configuration actually shipped.
test-windows:
	nix develop .#windows --command $(CARGO) test --workspace --target x86_64-pc-windows-gnu

# Same recipe and the same lint set as `clippy` above; only the target triple and the toolchain
# differ. Cross-compiling cannot run the resulting test binaries, so this is a compile-and-lint
# check, not a test run.
clippy-windows:
	nix develop .#windows --command $(CARGO) clippy --target x86_64-pc-windows-gnu --all-targets --all-features -- -D warnings

all: check clippy test
