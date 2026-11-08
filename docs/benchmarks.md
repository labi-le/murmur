# Benchmarks and profiling

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
| the metrics pair | Documented under [Additional measurement suite](#additional-measurement-suite) |
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

