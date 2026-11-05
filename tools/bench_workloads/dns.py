"""Real murmur DNS cache, expiry, fake-IP and concurrent-request workloads."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
from pathlib import Path
import threading
import time

from .common import ProxyProcess, free_port, summarize_latencies
from .dns_support import DnsUpstream, V4, query


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _real(result, *, positive_ttl=True):
    _require(result["answers"] == [V4], f"unexpected DNS A answer: {result}")
    if positive_ttl:
        _require(result["ttls"] and min(result["ttls"]) > 0,
                 f"cache-hit measurement reached an expired/stale answer: {result}")
    return result


def _config(upstream, transport, *, fake=False):
    address = f"{'tcp://' if transport == 'tcp' else ''}127.0.0.1:{upstream.port}"
    return {
        "ipv6": False,
        "dns": {
            "enable": True, "listen": f"127.0.0.1:{free_port()}", "ipv6": False,
            "enhanced-mode": "fake-ip" if fake else "redir-host",
            "fake-ip-range": "198.18.1.0/24", "fake-ip-filter": [],
            "nameserver": [address], "default-nameserver": [address],
            "proxy-server-nameserver": [address], "direct-nameserver": [address],
            "fallback": [], "use-hosts": False, "use-system-hosts": False,
        },
        "profile": {"store-fake-ip": False, "store-selected": False},
        "rules": ["MATCH,DIRECT"],
    }


def _ready(proxy, timeout):
    deadline = time.monotonic() + timeout
    while True:
        proxy.assert_alive()
        try:
            return query(proxy.dns_port, "readiness.bench.invalid", "udp", min(timeout, 1.0))
        except (OSError, EOFError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def _counts(before, after):
    _require(not after["errors"], f"DNS fixture errors: {after['errors']}")
    return {key: after[key] - before[key] for key in ("total", "udp", "tcp")}


def _row(args, name, transport, upstream_transport, results, resources, before, after, validation, **parameters):
    observed = _counts(before, after)
    _require(observed["tcp" if upstream_transport == "udp" else "udp"] == 0,
             f"DNS used an unexpected upstream transport: {observed}")
    return {
        "name": name,
        "parameters": {"clientTransport": transport, "upstreamTransport": upstream_transport,
                       "warmupExcluded": True, **parameters},
        "operationScope": "loopback client DNS request/response, including fresh TCP connection when selected; "
                          "resources cover the real murmur process over the whole measured window, not fixture CPU",
        "operations": len(results), "bytes": sum(result["bytes"] for result in results),
        "elapsedSeconds": resources["elapsedSeconds"],
        "latency": summarize_latencies([result["latencySeconds"] for result in results]),
        "resources": resources,
        "validation": {"upstreamRequests": observed, "upstreamBefore": before,
                       "upstreamAfter": after, **validation},
        "instrumented": args.mode != "clean",
    }


def _persist(root, rows, upstream=None):
    evidence = {"completedRows": rows}
    if upstream is not None:
        evidence["upstream"] = upstream.snapshot()
    temporary = root / "dns-progress.json.tmp"
    temporary.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    temporary.replace(root / "dns-progress.json")


def _cache_matrix(args, root, rows):
    for upstream_transport in ("udp", "tcp"):
        with DnsUpstream(ttl=300, delay=0.02, timeout=args.timeout) as upstream:
            try:
                with ProxyProcess(args, root / f"cache-{upstream_transport}",
                                  _config(upstream, upstream_transport)) as proxy:
                    _real(_ready(proxy, args.timeout))
                    for transport in ("udp", "tcp"):
                        prefix = f"{upstream_transport}-{transport}"
                        _real(query(proxy.dns_port, f"warmup.{prefix}.bench.invalid", transport, args.timeout))
                        hit_name = f"hit.{prefix}.bench.invalid"
                        prime_before = upstream.snapshot()
                        _real(query(proxy.dns_port, hit_name, transport, args.timeout))
                        prime_counts = _counts(prime_before, upstream.snapshot())
                        _require(prime_counts["total"] >= 1, "cache-hit prime never reached local upstream")
                        before = upstream.snapshot()
                        mark = proxy.mark()
                        results = [_real(query(proxy.dns_port, hit_name, transport, args.timeout))
                                   for _ in range(args.iterations)]
                        resources = proxy.delta(mark)
                        after = upstream.snapshot()
                        _require(_counts(before, after)["total"] == 0, "positive-TTL cache-hit generated upstream traffic")
                        rows.append(_row(args, f"dns/cache-hit/{prefix}", transport, upstream_transport,
                                         results, resources, before, after,
                                         {"expectedAddress": V4, "positiveTtl": True,
                                          "primeUpstreamRequests": prime_counts}, ttlSeconds=300))
                        _persist(root, rows, upstream)

                        before = upstream.snapshot()
                        mark = proxy.mark()
                        results = [_real(query(proxy.dns_port, f"cold-{index}.{prefix}.bench.invalid",
                                               transport, args.timeout)) for index in range(args.iterations)]
                        resources = proxy.delta(mark)
                        after = upstream.snapshot()
                        counts = _counts(before, after)
                        _require(counts["total"] >= args.iterations, "cold unique names did not all reach upstream")
                        for index in range(args.iterations):
                            key = f"{upstream_transport}/cold-{index}.{prefix}.bench.invalid/1"
                            _require(after["questions"].get(key, 0) >= 1, f"missing cold upstream question: {key}")
                        rows.append(_row(args, f"dns/cold-unique/{prefix}", transport, upstream_transport,
                                         results, resources, before, after,
                                         {"expectedAddress": V4, "uniqueNames": args.iterations}, ttlSeconds=300))
                        _persist(root, rows, upstream)

                        results, batch_counts, peaks = [], [], []
                        before = upstream.snapshot()
                        mark = proxy.mark()
                        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                            for index in range(args.iterations):
                                barrier = threading.Barrier(args.concurrency)
                                lock = threading.Lock()
                                active = 0
                                peak = 0
                                name = f"concurrent-{index}.{prefix}.bench.invalid"
                                def request():
                                    nonlocal active, peak
                                    barrier.wait(timeout=args.timeout)
                                    with lock:
                                        active += 1
                                        peak = max(peak, active)
                                    try:
                                        return _real(query(proxy.dns_port, name, transport, args.timeout))
                                    finally:
                                        with lock:
                                            active -= 1
                                batch_before = upstream.snapshot()
                                futures = [pool.submit(request) for _ in range(args.concurrency)]
                                results.extend(future.result(timeout=args.timeout + 1) for future in futures)
                                count = _counts(batch_before, upstream.snapshot())
                                _require(count["total"] >= 1, "cold concurrent batch did not reach upstream")
                                batch_counts.append(count)
                                peaks.append(peak)
                        resources = proxy.delta(mark)
                        after = upstream.snapshot()
                        rows.append(_row(args, f"dns/concurrent-identical/{prefix}", transport, upstream_transport,
                                         results, resources, before, after,
                                         {"expectedAddress": V4, "batchUpstreamRequests": batch_counts,
                                          "peakClientRequestsInFlightPerBatch": peaks,
                                          "coalescingAssumed": False},
                                         ttlSeconds=300, upstreamDelaySeconds=0.02,
                                         concurrency=args.concurrency, batches=args.iterations))
                        _persist(root, rows, upstream)
                    proxy.assert_alive()
            finally:
                _persist(root, rows, upstream)


def _expiry(args, root, rows):
    for transport in ("udp", "tcp"):
        with DnsUpstream(ttl=2, delay=0.02, timeout=args.timeout) as upstream:
            try:
                with ProxyProcess(args, root / f"expiry-{transport}", _config(upstream, transport)) as proxy:
                    _real(_ready(proxy, args.timeout))
                    names = [f"expiry-{index}.{transport}.bench.invalid" for index in range(args.iterations)]
                    for name in names:
                        _real(query(proxy.dns_port, name, transport, args.timeout))
                    refreshed_address = "203.0.113.10"
                    upstream.set_answer(v4=refreshed_address, ttl=300)
                    sleep_start = time.monotonic()
                    time.sleep(2.2)
                    sleep_elapsed = time.monotonic() - sleep_start
                    before = upstream.snapshot()
                    mark = proxy.mark()
                    results, refresh_latencies = [], []
                    for name in names:
                        key = f"{transport}/{name}/1"
                        count_before = upstream.snapshot()["questions"].get(key, 0)
                        start = time.monotonic()
                        result = _real(query(proxy.dns_port, name, transport, args.timeout), positive_ttl=False)
                        results.append(result)
                        deadline = time.monotonic() + args.timeout
                        while upstream.snapshot()["questions"].get(key, 0) <= count_before:
                            proxy.assert_alive()
                            _require(time.monotonic() < deadline, f"expired name was not refreshed upstream: {name}")
                            time.sleep(0.005)
                        refresh_latencies.append(time.monotonic() - start)
                    resources = proxy.delta(mark)
                    after = upstream.snapshot()
                    refresh_checks = []
                    for name in names:
                        deadline = time.monotonic() + args.timeout
                        while True:
                            check = query(proxy.dns_port, name, transport, args.timeout)
                            if check["answers"] == [refreshed_address]:
                                _require(min(check["ttls"]) > 0, "refreshed DNS entry has zero TTL")
                                refresh_checks.append(check)
                                break
                            _require(check["answers"] == [V4], f"unexpected expiry answer: {check}")
                            _require(time.monotonic() < deadline, f"refreshed answer never became visible: {name}")
                            time.sleep(0.025)
                    rows.append(_row(args, f"dns/expired-request-and-refresh/{transport}", transport, transport,
                                     results, resources, before, after,
                                     {"expiredAddress": V4, "refreshedAddress": refreshed_address,
                                      "refreshChecksExcludedFromMeasurement": refresh_checks,
                                      "realSleepSeconds": sleep_elapsed,
                                      "responseTtls": [result["ttls"] for result in results],
                                      "requestToUpstreamObservationSeconds": refresh_latencies,
                                      "upstreamRefreshesObserved": _counts(before, after)["total"],
                                      "staleResponsesAllowed": True}, ttlSeconds=2,
                                     sleepExcluded=True))
                    _persist(root, rows, upstream)
            finally:
                _persist(root, rows, upstream)


def _fake_ip(args, root, rows):
    pool = ipaddress.ip_network("198.18.1.0/24")
    with DnsUpstream(timeout=args.timeout) as upstream:
        try:
            with ProxyProcess(args, root / "fake-ip", _config(upstream, "udp", fake=True)) as proxy:
                _ready(proxy, args.timeout)
                query(proxy.dns_port, "warmup.fake.bench.invalid", "udp", args.timeout)
                identities = {}
                names = ["identity-a.fake.bench.invalid", "identity-b.fake.bench.invalid"]
                for name in names:
                    answer = query(proxy.dns_port, name, "udp", args.timeout)
                    _require(len(answer["answers"]) == 1, f"fake-IP did not return one address: {answer}")
                    address = ipaddress.ip_address(answer["answers"][0])
                    _require(address in pool and address not in (pool.network_address, pool.broadcast_address),
                             f"fake-IP answer outside usable configured pool: {address}")
                    identities[name] = str(address)
                    tcp_answer = query(proxy.dns_port, name, "tcp", args.timeout)
                    _require(tcp_answer["answers"] == answer["answers"],
                             f"fake-IP UDP/TCP identity mismatch for {name}")
                _require(len(set(identities.values())) == len(names), "distinct fake-IP names share an allocation")
                for transport in ("udp", "tcp"):
                    before = upstream.snapshot()
                    mark = proxy.mark()
                    results = []
                    for index in range(args.iterations):
                        name = names[index % len(names)]
                        result = query(proxy.dns_port, name, transport, args.timeout)
                        _require(result["answers"] == [identities[name]],
                                 f"fake-IP identity changed across repeated transports: {name}: {result}")
                        results.append(result)
                    resources = proxy.delta(mark)
                    after = upstream.snapshot()
                    _require(_counts(before, after)["total"] == 0, "fake-IP A queries contacted upstream")
                    rows.append(_row(args, f"dns/fake-ip-forward/{transport}", transport, "udp",
                                     results, resources, before, after,
                                     {"pool": str(pool), "identities": identities,
                                      "consistentAcrossUdpAndTcp": True,
                                      "reverseLookup": {"status": "unavailable",
                                                        "reason": "reverse mapping is internal-only; DNS PTR delegates to real resolver, no controller reverse endpoint"}}))
                    _persist(root, rows, upstream)
        finally:
            _persist(root, rows, upstream)


def run(args, root: Path) -> list[dict]:
    root.mkdir(parents=True, exist_ok=True)
    rows = []
    _cache_matrix(args, root, rows)
    _expiry(args, root, rows)
    _fake_ip(args, root, rows)
    return rows
