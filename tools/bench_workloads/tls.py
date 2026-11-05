"""Full-process Trojan/VLESS TLS controls against an isolated verified origin.

Cold means the first request after controller readiness, not process startup.
Warm means a warmed process with NEW TCP/TLS connections, not session resumption
or keep-alive. Each operation includes two independently counted TLS handshakes:
outer murmur transport and inner client-to-origin HTTPS. CPU is murmur-only.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import ssl
import time
import uuid

from .common import ProxyProcess, certificate, http_proxy_request, summarize_latencies
from .tls_support import TLSFixture, USER_ID


def _validate(events, operations, payload, fragmented):
    errors = [event for event in events if event["kind"] == "error"]
    if errors:
        raise RuntimeError(f"TLS fixture errors: {errors}")
    counts = {kind: sum(event["kind"] == kind for event in events)
              for kind in ("outerHandshake", "originHandshake", "forward", "originRequest")}
    if any(count != operations for count in counts.values()):
        raise RuntimeError(f"TLS expected {operations} of each event, observed {counts}")
    handshakes = [event for event in events if event["kind"].endswith("Handshake")]
    if any(event["version"] != "TLSv1.3" or event["sessionReused"] for event in handshakes):
        raise RuntimeError(f"TLS expected full TLS1.3 handshakes: {handshakes}")
    digest = hashlib.sha256(payload).hexdigest()
    targets = [event for event in events if event["kind"] == "originRequest"]
    if any(event["bytes"] != len(payload) or event["sha256"] != digest for event in targets):
        raise RuntimeError("TLS origin payload evidence mismatch")
    fragments = [event for event in events if event["kind"] == "fragmentStream"]
    if fragmented and (len(fragments) != operations
                       or any(event["writes"] <= 1 for event in fragments)):
        raise RuntimeError(f"TLS fragmentation missing for {operations} streams: {fragments}")
    return {
        "expectedRequests": operations, "observedCounts": counts,
        "outerFullTLSHandshakes": counts["outerHandshake"],
        "innerFullTLSHandshakes": counts["originHandshake"],
        "resumedHandshakes": 0, "payloadSHA256": digest,
        "verifiedResponseBytes": operations * len(payload),
        "originCertificateVerified": True, "outerCertificateVerified": True,
        "fragmentedStreams": len(fragments),
        "fragmentWrites": sum(event["writes"] for event in fragments),
        "fragmentedWireBytes": sum(event["bytes"] for event in fragments),
        "fixtureErrors": errors,
    }


def _phase(args, fixture, proxy, ssl_context, payload, phase, parameters, directory):
    operations = 1 if phase == "cold-first-request" else args.iterations
    concurrency = 1 if phase == "cold-first-request" else min(args.concurrency, operations)
    before_events = len(fixture.snapshot())
    requests = []

    def request(index):
        started = time.monotonic()
        status, headers, body = http_proxy_request(
            proxy.mixed_port, f"https://localhost:{fixture.origin_port}/payload",
            timeout=args.timeout, ssl_context=ssl_context,
        )
        elapsed = time.monotonic() - started
        if status != 200 or body != payload:
            raise RuntimeError(f"TLS request {index}: status={status}, bytes={len(body)}, "
                               f"sha256={hashlib.sha256(body).hexdigest()}")
        return {"index": index, "elapsedSeconds": elapsed, "status": status,
                "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        before = proxy.mark()
        started = time.monotonic()
        try:
            for result in executor.map(request, range(operations)):
                requests.append(result)
        finally:
            elapsed = time.monotonic() - started
            resources = proxy.delta(before)
            (directory / f"{phase}-requests.json").write_text(json.dumps(requests, indent=2) + "\n")
    fixture.wait_idle()
    proxy.assert_alive()
    events = fixture.snapshot()[before_events:]
    fixture.save(directory / "fixture-events.json")
    validation = _validate(events, operations, payload, fixture.fragment_bytes)
    row = {
        "name": f"tls-{parameters['protocol']}-{parameters['fingerprint']}-"
                f"{parameters['fragmentBytes']}-{phase}",
        "parameters": {**parameters, "phase": phase, "concurrency": concurrency,
                       "warmupRequestsExcluded": 0 if phase == "cold-first-request" else 1,
                       "processStartupSecondsExcluded": proxy.startup_seconds,
                       "sessionResumption": False, "freshConnectionPerOperation": True,
                       "originWriteBytes": 1024, "originWriteDelaySeconds": 0.001},
        "operationScope": "One verified HTTPS GET through the real murmur HTTP CONNECT "
                          "listener and Trojan/VLESS TLS forwarder, including fresh outer "
                          "and inner TLS handshakes and exact payload validation. Process "
                          "startup, fixture setup and post-request fixture drain excluded. "
                          "Not a per-handshake microbenchmark; fixture CPU excluded.",
        "operations": operations, "bytes": operations * len(payload),
        "elapsedSeconds": elapsed,
        "latency": summarize_latencies([request["elapsedSeconds"] for request in requests]),
        "resources": resources, "validation": validation,
        "instrumented": args.mode != "clean",
    }
    (directory / f"{phase}-result.json").write_text(json.dumps(row, indent=2) + "\n")
    return row


def run(args, root: Path) -> list[dict]:
    root.mkdir(parents=True, exist_ok=True)
    cert, key = certificate(root)
    client_context = ssl.create_default_context(cafile=str(cert))
    client_context.minimum_version = ssl.TLSVersion.TLSv1_3
    client_context.maximum_version = ssl.TLSVersion.TLSv1_3
    payload = (bytes(range(256)) * ((args.payload_bytes + 255) // 256))[:args.payload_bytes]
    rows = []
    for protocol in ("trojan", "vless"):
        for fingerprint in ("none", "chrome"):
            for fragment_bytes in (0, 128):
                directory = root / f"{protocol}-{fingerprint}-{fragment_bytes}"
                directory.mkdir(mode=0o700)
                with TLSFixture(cert, key, protocol, payload, args.timeout, fragment_bytes) as fixture:
                    config = {
                        "proxies": [{"name": "TLS", "type": protocol, "server": "127.0.0.1",
                                     "port": fixture.port, "sni": "localhost", "servername": "localhost",
                                     "tls": True, "skip-cert-verify": False,
                                     "client-fingerprint": fingerprint, "alpn": ["http/1.1"],
                                     **({"password": "e2e-synthetic-password"} if protocol == "trojan"
                                        else {"uuid": str(uuid.UUID(bytes=USER_ID))})}],
                        "rules": ["MATCH,TLS"],
                    }
                    parameters = {"protocol": protocol, "fingerprint": fingerprint,
                                  "fragmentBytes": fragment_bytes,
                                  "fragmentDelaySeconds": fixture.fragment_delay,
                                  "fragmentBoundary": "server-to-client TCP writes; TCP may coalesce reads",
                                  "payloadBytes": args.payload_bytes}
                    try:
                        with ProxyProcess(args, directory / "proxy", config,
                                          env={"SSL_CERT_FILE": str(cert)}) as proxy:
                            for phase in ("cold-first-request", "warm-new-connections"):
                                rows.append(_phase(args, fixture, proxy, client_context, payload,
                                                   phase, parameters, directory))
                    finally:
                        fixture.save(directory / "fixture-events.json")
    return rows
