"""Real SOCKS relay and reference-backed Vision workload measurements."""
from __future__ import annotations

import copy
import hashlib
import json
import platform
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from .common import (
    ProxyProcess, certificate, free_port, http_proxy_request, socks_connect,
    summarize_latencies,
)
from .relay_support import (
    EchoFixture, blocked_upload, bulk_origin, receive_exact, udp_association,
    udp_roundtrip, udp_socket_evidence,
)


def _payload(size: int) -> bytes:
    return (bytes(range(251)) * ((size + 250) // 251))[:size]


def _row(args, proxy, name, before, started, samples, byte_count, parameters, validation, scope):
    resources = proxy.delta(before)
    elapsed = resources["elapsedSeconds"]
    proxy.assert_alive()
    return {
        "name": name,
        "parameters": {"warmupOperations": 0, "architectureExecuted": platform.machine(), **parameters},
        "operationScope": scope,
        "operations": len(samples),
        "bytes": byte_count,
        "elapsedSeconds": elapsed,
        "goodputBytesPerSecond": byte_count / elapsed if elapsed else 0,
        **({"latency": summarize_latencies(samples)} if samples else {}),
        "resources": resources,
        "validation": validation,
        "instrumented": args.mode != "clean",
        "startedAt": started,
        "finishedAt": datetime.now(timezone.utc).isoformat(),
        "resourceScope": "murmur process only during measured window; excludes fixture/reference CPU; RSS/HWM are not live heap",
        "startupSecondsExcluded": proxy.startup_seconds,
    }


def _concurrent(args, worker):
    barrier = threading.Barrier(args.concurrency)
    lock = threading.Lock()
    active = peak = 0

    def measured(index):
        nonlocal active, peak
        barrier.wait(timeout=args.timeout)
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            return worker(index)
        finally:
            with lock:
                active -= 1

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        results = list(pool.map(measured, range(args.concurrency)))
    return results, peak


def _tcp(args, root, sustained):
    payload = _payload(args.payload_bytes)
    name = "relay-tcp-sustained" if sustained else "relay-tcp-short-lived"
    with EchoFixture(args.timeout) as fixture, ProxyProcess(args, root, {}) as proxy:
        def worker(index):
            samples = []
            sock = None
            try:
                if sustained:
                    sock = socks_connect(proxy.mixed_port, "127.0.0.1", fixture.port, timeout=args.timeout)
                for sequence in range(args.iterations):
                    start = time.perf_counter()
                    if not sustained:
                        sock = socks_connect(proxy.mixed_port, "127.0.0.1", fixture.port, timeout=args.timeout)
                    for offset in range(0, len(payload), 65536):
                        chunk = payload[offset:offset + 65536]
                        sock.sendall(chunk)
                        if receive_exact(sock, len(chunk)) != chunk:
                            raise RuntimeError(f"TCP payload mismatch worker={index} operation={sequence}")
                    if not sustained:
                        sock.close()
                        sock = None
                    samples.append(time.perf_counter() - start)
                return samples
            finally:
                if sock is not None:
                    sock.close()

        started = datetime.now(timezone.utc).isoformat()
        before = proxy.mark()
        batches, peak = _concurrent(args, worker)
        samples = [sample for batch in batches for sample in batch]
        fixture.check()
        expected_connections = args.concurrency * (1 if sustained else args.iterations)
        expected_bytes = len(payload) * len(samples)
        if fixture.connections != expected_connections or fixture.received_bytes != expected_bytes:
            raise RuntimeError("TCP fixture connection/byte accounting mismatch")
        return _row(args, proxy, name, before, started, samples, expected_bytes * 2,
                    {"concurrency": args.concurrency, "iterationsPerWorker": args.iterations,
                     "payloadBytes": len(payload), "persistentConnections": sustained},
                    {"exactPayloadMatches": len(samples), "connections": fixture.connections,
                     "fixtureReceivedBytes": fixture.received_bytes, "peakActiveWorkers": peak,
                     "payloadSHA256": hashlib.sha256(payload).hexdigest()},
                    "SOCKS5 TCP exact echo; aggregate window includes connection setup/thread dispatch; "
                    + ("latency is established-stream send/receive" if sustained else "latency includes SOCKS connect/send/receive/close")
                    + "; byte count includes both directions")


def _udp(args, root, sustained):
    # A UDP payload must fit one SOCKS-encapsulated IP datagram.
    payload = _payload(min(args.payload_bytes, 60000))
    name = "relay-udp-sustained" if sustained else "relay-udp-short-lived"
    # Leave room for a full worker burst plus kernel packet bookkeeping, not just one payload.
    receive_buffer = args.concurrency * 2 * 65536
    with EchoFixture(args.timeout, udp=True, receive_buffer=receive_buffer) as fixture, \
            ProxyProcess(args, root, {"udp": True}) as proxy:
        observations = []
        evidence_lock = threading.Lock()

        def snapshot(client_port=None):
            ports = {"fixture": fixture.port, "proxyListener": proxy.mixed_port}
            if client_port is not None:
                ports["client"] = client_port
            return udp_socket_evidence(proxy.pid, ports)

        initial_sockets = snapshot()

        def worker(index):
            samples = []

            def exchange(sock, sequence, start):
                tag = hashlib.sha256(f"{index}:{sequence}".encode()).digest()
                data = (tag + payload)[:len(payload)]
                observation = {"worker": index, "sequence": sequence,
                               "startedAt": datetime.now(timezone.utc).isoformat(),
                               "clientPort": sock.getsockname()[1]}
                try:
                    udp_roundtrip(sock, fixture.port, data)
                except TimeoutError:
                    observation.update(status="timeout", socketEvidence=snapshot(sock.getsockname()[1]))
                except Exception as exc:
                    observation.update(status="failed", error=f"{type(exc).__name__}: {exc}",
                                       socketEvidence=snapshot(sock.getsockname()[1]))
                    raise
                else:
                    observation["status"] = "matched"
                    samples.append(time.perf_counter() - start)
                finally:
                    observation["elapsedSeconds"] = time.perf_counter() - start
                    with evidence_lock:
                        observations.append(observation)
                        (root / "datagram-observations.json").write_text(json.dumps(observations, indent=2) + "\n")

            if sustained:
                with udp_association(proxy.mixed_port, args.timeout) as (sock, _):
                    for sequence in range(args.iterations):
                        exchange(sock, sequence, time.perf_counter())
            else:
                for sequence in range(args.iterations):
                    start = time.perf_counter()
                    with udp_association(proxy.mixed_port, args.timeout) as (sock, _):
                        exchange(sock, sequence, start)
            return samples

        started = datetime.now(timezone.utc).isoformat()
        before = proxy.mark()
        batches, peak = _concurrent(args, worker)
        samples = [sample for batch in batches for sample in batch]
        fixture.check()
        attempted = args.iterations * args.concurrency
        timeouts = sum(observation["status"] == "timeout" for observation in observations)
        if (len(observations) != attempted or len(samples) + timeouts != attempted
                or not len(samples) <= fixture.messages <= attempted
                or fixture.received_bytes != len(payload) * fixture.messages):
            raise RuntimeError("UDP fixture datagram/byte accounting mismatch")
        socket_evidence = {"before": initial_sockets, "after": snapshot()}
        socket_evidence["capturedAt"] = datetime.now(timezone.utc).isoformat()
        (root / "socket-evidence.json").write_text(json.dumps(socket_evidence, indent=2) + "\n")
        result = _row(args, proxy, name, before, started, samples, len(payload) * len(samples) * 2,
                      {"concurrency": args.concurrency, "iterationsPerWorker": args.iterations,
                       "requestedPayloadBytes": args.payload_bytes, "datagramPayloadBytes": len(payload),
                       "persistentAssociations": sustained, "fixtureRequestedReceiveBufferBytes": receive_buffer,
                       "responseTimeoutSeconds": args.timeout, "retries": 0},
                      {"attemptedDatagrams": attempted, "exactPayloadAndSourceMatches": len(samples),
                       "timedOutDatagrams": timeouts, "deliveryRatio": len(samples) / attempted,
                       "fixtureDatagrams": fixture.messages, "fixtureReceivedBytes": fixture.received_bytes,
                       "peakActiveWorkers": peak, "fixtureEffectiveReceiveBufferBytes": fixture.receive_buffer,
                       "validatedEncapsulatedSource": f"127.0.0.1:{fixture.port}",
                       "transportSourceChecked": True, "fragmentFlagZeroChecked": True,
                       "socketEvidence": socket_evidence, "observations": observations},
                      "SOCKS5 UDP ASSOCIATE; operations count attempted datagrams, bytes count only exact echoed "
                      "payload in both directions; latency contains successful exchanges only; timeouts are "
                      "reported loss, never retried; aggregate includes association setup and timeout waits; "
                      + ("latency excludes persistent association setup" if sustained else "latency includes association setup"))
        result["operations"] = attempted
        result["status"] = "degraded" if timeouts else "ok"
        return result


def _backpressure(args, root):
    # Larger than loopback kernel buffers; a 100ms non-writable observation is mandatory.
    payload = _payload(max(args.payload_bytes, 8 * 1024 * 1024))
    samples, observations = [], []
    with ProxyProcess(args, root, {}) as proxy:
        started = datetime.now(timezone.utc).isoformat()
        before = proxy.mark()
        for _ in range(args.iterations):
            with EchoFixture(args.timeout, slow=True) as fixture:
                with socks_connect(proxy.mixed_port, "127.0.0.1", fixture.port, timeout=args.timeout) as sock:
                    start = time.perf_counter()
                    observations.append(blocked_upload(sock, fixture, payload, args.timeout))
                    samples.append(time.perf_counter() - start)
                fixture.check()
                if fixture.received_bytes != len(payload):
                    raise RuntimeError("backpressure fixture received-byte mismatch")
        return _row(args, proxy, "relay-tcp-backpressure", before, started, samples,
                    len(payload) * len(samples),
                    {"concurrency": 1, "payloadBytes": len(payload), "iterations": args.iterations,
                     "minimumNonWritableObservationSeconds": 0.1},
                    {"exactUploadCountAndSHA256Matches": len(samples), "observations": observations,
                     "payloadSHA256": hashlib.sha256(payload).hexdigest()},
                    "SOCKS5 upload into gated slow receiver, require would-block and non-writability before release, "
                    "then drain and verify remote SHA-256; latency includes pressure hold/drain but excludes connect; "
                    "aggregate includes per-operation fixture setup/teardown; bytes count uploaded payload only")


def _vision(args, root):
    if args.reference is None:
        raise RuntimeError("relay Vision requires --reference pointing to a native Go mihomo binary")
    cert, key = certificate(root / "reference" / "certificates")
    listener_port, origin_port = free_port(), free_port()
    identity = "d7f8a3c5-1b2d-4e6f-8a90-123456789abc"
    reference_args = copy.copy(args)
    reference_args.binary = args.reference
    reference_args.mode = "clean"
    reference_config = {
        "log-level": "debug",
        "listeners": [{"name": "vision", "type": "vless", "listen": "127.0.0.1",
                       "port": listener_port,
                       "users": [{"username": "benchmark", "uuid": identity, "flow": "xtls-rprx-vision"}],
                       "certificate": str(cert), "private-key": str(key)}],
    }
    download = bytes(range(251)) * 4096
    upload = _payload(max(65536, min(args.payload_bytes, 4 * 1024 * 1024)))
    context = ssl.create_default_context(cafile=str(cert))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    rows = []
    with ProxyProcess(reference_args, root / "reference", reference_config) as reference:
        with bulk_origin(root / "origin", cert, key, origin_port, args.timeout) as fixture_path:
            for fingerprint in (None, "chrome"):
                label = fingerprint or "none"
                entry = {"name": "VISION", "type": "vless", "server": "127.0.0.1",
                         "port": listener_port, "uuid": identity, "tls": True,
                         "servername": "localhost", "skip-cert-verify": True,
                         "flow": "xtls-rprx-vision"}
                if fingerprint:
                    entry["client-fingerprint"] = fingerprint
                config = {"proxies": [entry], "rules": ["MATCH,VISION"]}
                with ProxyProcess(args, root / label, config) as proxy:
                    log_offset = reference.log_path.stat().st_size
                    def worker(index):
                        samples = []
                        for _ in range(args.iterations):
                            start = time.perf_counter()
                            status, headers, result = http_proxy_request(
                                proxy.mixed_port, f"https://127.0.0.1:{origin_port}/", method="POST",
                                body=upload, timeout=args.timeout, ssl_context=context)
                            if status != 200:
                                raise RuntimeError(f"Vision {label} duplex POST: HTTP {status}")
                            if result != download:
                                raise RuntimeError(f"Vision {label} duplex download byte mismatch")
                            if (headers.get("X-Received-Bytes") != str(len(upload))
                                    or headers.get("X-Received-SHA256") != hashlib.sha256(upload).hexdigest()):
                                raise RuntimeError(f"Vision {label} duplex upload digest/count mismatch")
                            samples.append(time.perf_counter() - start)
                        return samples

                    started = datetime.now(timezone.utc).isoformat()
                    before = proxy.mark()
                    batches, peak = _concurrent(args, worker)
                    samples = [sample for batch in batches for sample in batch]
                    reference.assert_alive()
                    with reference.log_path.open("rb") as log:
                        log.seek(log_offset)
                        handoff_log = log.read().decode(errors="replace")
                    (root / label / "reference-operation.log").write_text(handoff_log)
                    read_marker = "XTLS Vision direct read start"
                    write_marker = "XTLS Vision direct write start"
                    direct_reads = handoff_log.count(read_marker)
                    direct_writes = handoff_log.count(write_marker)
                    direct_lines = [line for line in handoff_log.splitlines()
                                    if read_marker in line or write_marker in line]
                    if direct_reads != len(samples) or direct_writes != len(samples):
                        raise RuntimeError(f"Vision handoff count mismatch: {direct_reads} reads, "
                                           f"{direct_writes} writes, {len(samples)} requests; see reference-operation.log")
                    rows.append(_row(args, proxy, f"relay-vision-{label}", before, started, samples,
                                     (len(download) + len(upload)) * args.iterations * args.concurrency,
                                     {"clientFingerprint": fingerprint, "concurrency": args.concurrency,
                                      "iterationsPerWorker": args.iterations, "downloadBytes": len(download),
                                      "uploadBytes": len(upload), "originTLS": "TLS1.3", "flow": "xtls-rprx-vision",
                                      "operation": "duplex bulk POST: upload then bulk response"},
                                     {"exactDownloads": len(samples), "digestCheckedUploads": len(samples),
                                      "downloadSHA256": hashlib.sha256(download).hexdigest(),
                                      "uploadSHA256": hashlib.sha256(upload).hexdigest(),
                                      "originCertificateVerified": True, "outerProxyCertificateVerification": "disabled for generated reference fixture",
                                      "peakActiveWorkers": peak, "referenceDirectHandoffEvidence": direct_lines,
                                      "directReadHandoffs": direct_reads, "directWriteHandoffs": direct_writes,
                                      "reusedOriginFixture": str(fixture_path)},
                                     "HTTP CONNECT through murmur -> Go reference VLESS Vision -> verified TLS1.3 bulk origin; "
                                     "per-operation duplex POST latency includes connect/inner TLS/upload/download/byte checks; "
                                     "bytes count upload plus download payload only"))
                    (root / "completed-rows.json").write_text(json.dumps(rows, indent=2) + "\n")
    return rows


def run(args, root: Path) -> list[dict]:
    root.mkdir(parents=True, exist_ok=True)
    if args.reference is None:
        raise RuntimeError("--case relay requires --reference for real Vision no-fingerprint/chrome handoff workloads")
    rows = []
    def retain(row):
        rows.append(row)
        (root / "completed-rows.json").write_text(json.dumps(rows, indent=2) + "\n")
    for sustained in (False, True):
        retain(_tcp(args, root / ("tcp-sustained" if sustained else "tcp-short"), sustained))
        retain(_udp(args, root / ("udp-sustained" if sustained else "udp-short"), sustained))
    retain(_backpressure(args, root / "backpressure"))
    for row in _vision(args, root / "vision"):
        retain(row)
    return rows
