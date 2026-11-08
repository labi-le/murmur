# Architecture, workspace layout, and correctness invariants

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

