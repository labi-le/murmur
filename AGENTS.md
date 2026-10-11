# AGENTS.md

This repository is **murmur**: a virtual workspace of 89 crates under `crates/`, exactly one of them
a binary (`crates/murmur`). Read these before changing anything:

| File | What it answers |
| --- | --- |
| `README.md` | what murmur is, how it is built and run, the crate map, the correctness invariants, the six hazards found under load, per-protocol status |
| `RUST_GUIDELINES.md` | the 13 sections of rules this tree is written to; section 12 is the tooling gate |
| `docs/guidelines-review.md` | last audit against those rules: what was found, what was fixed, what is deliberately left |

## Invariants

These hold everywhere, including in code nobody is currently touching. A change that needs to break
one of them needs a different design.

- **No `unsafe`.** Denied crate-wide, including through a local `#[allow(unsafe_code)]`. The few
  syscall-level exceptions sit in one small function each with a safety comment naming the
  invariant the surrounding code maintains.
- **Never hold a `parking_lot` guard across an `.await`** — not directly, not through a helper that
  awaits, not inside a `select!` branch.
- **No `.unwrap()` / `.expect()` on a fallible runtime path** — I/O, config, network input, anything
  an attacker or a misconfigured user controls. `expect()` only for an invariant that genuinely
  cannot fail, with a message naming which one.
- **No silent degradation.** A path that cannot do what it claims fails closed with an error naming
  the reason; it never falls back to a weaker behaviour that looks like success.
- **Never weaken a test to make it pass.** A failing test found a real behaviour change. A test that
  pinned only an incidental detail is deleted outright, not re-pinned to new text.
- **Annotate cancel safety.** Every async fn that can be awaited inside a `select!` arm carries a
  `// cancel-safe:` or `// NOT cancel-safe:` note with the reason. Delegation inherits the wrapped
  call's answer; a `poll_fn` over `self`'s state machine resumes; a channel `recv` leaves the item
  queued; a framed `read_exact`, a handshake that has already written, or a request sent on a locked
  half is **not** cancel-safe. Add the note in the same commit that makes a function a select arm.

## Toolchain

This workstation has **no `cargo` or `rustc` in `PATH`**. Two ways in:

- **Local shell** — `nix develop .` gives the pinned toolchain (`cargo 1.97.0`, `rustc 1.97.1`,
  clippy, rustfmt, `cargo-nextest`, sccache). Use it for `cargo fmt`, `cargo metadata`, reading
  manifests — anything that does not compile.
- **Compiling, testing, linting** — `tools/cargo-slot`. Run it from inside the repository:

  ```bash
  tools/cargo-slot cargo check -j 2 --all-targets
  tools/cargo-slot cargo test -p murmur-transport-tuic
  tools/cargo-slot bash -c 'cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings'
  ```

  The wrapper holds one of **5** shared slots (`CARGO_REMOTE_SLOTS`), ssh's to `pc`, enters this
  project's `nix develop` shell there, and runs the command in a systemd scope capped at 11G
  (`CARGO_SLOT_MEM`). Artifacts land in `/home/labile/.cache/cargo-pc/<name>` on `pc`, not in
  `./target`; a fresh `CARGO_TARGET_DIR` is seeded from a warm template, so give it a name rather
  than reusing `default` when you want an isolated build. If `pc` is unreachable the wrapper refuses
  to compile locally instead of falling back. **Compile on `pc` only** — a local `cargo build` in
  the dev shell competes with everyone else for the same machine.

  `tools/cargo-slot cargo fmt …` takes the local shortcut and will fail here (`cargo: command not
  found`); pass `fmt` inside a remote payload, as above.

Forwarded to the remote shell: `RUST_BACKTRACE`, `RUST_LOG`, `RUST_TEST_THREADS`,
`SKIP_SYSTEM_IPV6_CHECK`, every `MURMUR_*` and every `CARGO_*` except `CARGO_TARGET_DIR`.

### Recipes

| Task | Command |
| --- | --- |
| Fast type check | `tools/cargo-slot cargo check --all-targets --all-features` |
| One crate's tests while iterating | `tools/cargo-slot cargo test -p murmur-<crate> <filter>` |
| Full sweep | `tools/cargo-slot cargo nextest run --workspace --all-features` |
| Lints | `tools/cargo-slot cargo clippy --all-targets --all-features -- -D warnings` |
| Formatting | `tools/cargo-slot bash -c 'cargo fmt --all'` (add `-- --check` to verify) |
| Cheapest pre-commit gate | `make gate` = `fmt-check nextest clippy hygiene` |
| Everything | `make gate-full` = `gate` + `clippy-windows` + `test-heavy` |
| Dependency and advisory hygiene | `make deny`, `make machete`, `make audit`, `make typos` |

Run every test command under a wall-clock timeout. A suite that deadlocks on a poisoned lock or an
unawaited peer never returns, and the wrapper then holds one of the five compile slots for the rest
of the day. Prefix with `timeout` and pick a bound from the command's normal duration, never run a
test unwrapped:

```bash
timeout 900 tools/cargo-slot bash -c 'cargo nextest run --workspace --all-features'
```

Exit code 124 is a timeout, not a failure of the code under test. Read it as "this run found a
hang" and bisect for the culprit rather than re-running the same command longer.

`make test-heavy` runs the single `#[ignore]`d test — a real-timer soak that is deliberately outside
the default gate (`crates/common-net/src/io.rs`). Every crate is published as `murmur-<name>` except
the binary, which is plain `murmur`. Lint levels live in `[workspace.lints]`, thresholds in
`clippy.toml`; test code is exempt at the source level (`#![cfg_attr(test, allow(...))]` in crate
roots, `#![allow(...)]` in `crates/*/tests/*.rs`), not through a flag.

## Unverified behaviour

Some crates implement engines with no external specification on this workspace:
`easytier`, `mieru`, `zerotier`, `sing`, `sing-mux`, `smux`, `yamux`, `quic`, `kcp`, `reality`,
`restls`, `jls-tls`, `ws`, `component-wireguard`, `transport-hysteria2`, `murmur`, `compat`,
`std-compat`, `testsupport-probe`. For those, a behavioural claim rests on the crate's own tests and
internal consistency; say that it is unverified rather than guessing from memory. Several carry
documented deviations in `README.md`.

## Tests

2874 `#[test]` / `#[tokio::test]` functions across the workspace. Most sit in an inline
`#[cfg(test)]` module beside the code they cover; integration tests live in `crates/<crate>/tests/`,
and fixtures in the neighbouring `testdata/`.

- **Names describe behaviour** — `a_qos_holding_time_past_the_u16_range_saturates_instead_of_wrapping`,
  `bonding_selects_paths_per_policy` — rather than `test_…`, though 543 of the 2874 still carry the
  prefix, so match the file you are in.
- **`#[tokio::test]` single-threaded is the default** (1074 uses). Reach for
  `flavor = "multi_thread"` when the test needs real concurrency (127 uses, `worker_threads` where a
  specific count matters), and `start_paused = true` when a timer's behaviour is under test rather
  than its wall-clock duration.
- **A test that pinned only an incidental detail is deleted, not re-pinned** — see Invariants.

## Working agreements

- **Briefs name the exact command.** A subagent that has to guess how to build will build the wrong
  way. Include the `tools/cargo-slot …` line, the acceptance criterion, and the files in scope.
- **No builds mid-flight.** Agents write code and run the smallest targeted check; the full gate
  runs once, at the end, when the tree is quiet.
- **Five slots.** More than five concurrent compiling agents just queue — batch the work into waves
  that fit, or accept the wait knowingly.
- **Report evidence.** Command plus observed output. "Tests pass" without the run is not a result;
  neither is a claim about the reference that was not read from its source.
- **Commits only when asked.** The convention is `COMPONENT: imperative description`, one `-m`, at
  most 70 characters, no body, no trailers — the components used here are `murmur:` and the module
  name for a single-crate change (`tuic:`, `listener:`, `net:`). Code, comments, docs and commit
  messages are English.

## Publishing

`main` on `labi-le/murmur` is **one squashed root commit whose tree is exactly this workspace** —
history is not carried over, only content. `origin` is that repository, so publishing means
building a fresh root commit from the current tree and replacing `main`:

```bash
git fetch origin                            # --force-with-lease compares against this ref
tree=$(git rev-parse HEAD^{tree})
GIT_AUTHOR_NAME=labi-le GIT_AUTHOR_EMAIL=1a6i1e@gmail.com \
GIT_COMMITTER_NAME=labi-le GIT_COMMITTER_EMAIL=1a6i1e@gmail.com \
  git commit-tree "$tree" -m "murmur: init"
git push --force-with-lease origin <sha>:refs/heads/main
git ls-remote origin refs/heads/main    # verify, and compare the tree
```

`commit-tree` never touches the worktree. Always `--force-with-lease`, never `--force`; verify
afterwards that `git rev-parse origin/main^{tree}` equals `HEAD^{tree}`, and check that nothing was
deleted relative to the previous published tree:

```bash
git diff --diff-filter=D --name-only origin/main HEAD   # expect empty
```

## Verification expectations

- **Behaviour change** — the targeted test for the crate plus `make gate`. If the change touches a
  runtime path, also run the thing: parse a config with `-t`, hit the controller API, dial through
  the proxy. Tests alone are not proof that the binary works.
- **A claim about compatibility with the reference** — `tools/diff_sweep.py`, which starts a
  reference binary and this build side by side against the same config and the same real nodes and
  reports where they disagree.
- **A claim about the reference's behaviour** — its source line, quoted. Not recall.
