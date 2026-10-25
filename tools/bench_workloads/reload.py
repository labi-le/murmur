"""Provider refresh and full configuration apply under verified loopback traffic."""
from __future__ import annotations

import copy
import hashlib
import http.client
import json
import threading
import time
from pathlib import Path

from .common import ProxyProcess, http_proxy_request, socks_connect, summarize_latencies
from .reload_support import MemorySampler, ReloadFixtures, recv_exact


class RequestDisruption(RuntimeError):
    """A rejected request is measured separately from corrupted route output."""


def _provider_payload(rules, enabled, generation):
    lines = [f"# generation {generation}", "payload:"]
    lines.extend(f"  - DOMAIN,miss-{index}.invalid" for index in range(rules))
    if enabled:
        lines.append("  - IP-CIDR,127.0.0.1/32,no-resolve")
    return ("\n".join(lines) + "\n").encode("ascii")


def _replace(path, payload):
    temporary = path.with_suffix(".next")
    temporary.write_bytes(payload)
    temporary.replace(path)


def _config(fixtures, root, rules):
    return {
        "dns": {"enable": False},
        "proxies": [
            {"name": name, "type": "socks5", "server": "127.0.0.1", "port": port, "udp": False}
            for name, port in fixtures.proxy_ports.items()
        ],
        "rule-providers": {
            "http-rules": {"type": "http", "behavior": "classical", "format": "yaml", "interval": 86400,
                           "url": f"http://127.0.0.1:{fixtures.http_port}/provider.yaml",
                           "path": str(root / "http-rules.yaml")},
            "file-rules": {"type": "file", "behavior": "classical", "format": "yaml",
                           "path": str(root / "file-rules.yaml")},
        },
        "rules": [f"DOMAIN,miss-{index}.invalid,REJECT" for index in range(rules)] + [
            "RULE-SET,http-rules,route-b", "RULE-SET,file-rules,route-b", "MATCH,route-a"],
    }


def _run_source(args, root: Path, source):
    root.mkdir(parents=True, exist_ok=True)
    requests = []
    transitions = []
    errors = []
    observations = []
    request_errors = []
    held = {"exchanges": 0, "bytes": 0, "initialRoute": None, "sha256": None}
    memory = None
    fixtures = None
    stop = threading.Event()
    lock = threading.Lock()
    generation = 0
    expected_routes = {"127.0.0.2", "127.0.0.3"}
    workers = []
    held_socket = None
    try:
        with ReloadFixtures(args.timeout) as fixtures:
            initial = _provider_payload(args.rules, False, 0)
            fixtures.set_provider(initial)
            _replace(root / "file-rules.yaml", initial)
            config = _config(fixtures, root, args.rules)
            with ProxyProcess(args, root, config) as process:
                url = f"http://127.0.0.1:{fixtures.http_port}/route"

                def request(kind, timeout=None):
                    started = time.monotonic()
                    entry = {"startedAt": started, "requestedGeneration": generation, "kind": kind}
                    try:
                        status, _, body = http_proxy_request(process.mixed_port, url, timeout=args.timeout if timeout is None else timeout)
                        entry.update(status=status, bytes=len(body))
                        if status != 200:
                            raise RequestDisruption(f"routing request HTTP {status}: {body!r}")
                        route = body.decode("ascii")
                        entry["observedRoute"] = route
                        if route not in expected_routes:
                            raise RuntimeError(f"invalid route output {body!r}")
                        return route
                    except Exception as exc:
                        entry["error"] = str(exc)
                        raise
                    finally:
                        entry["elapsedSeconds"] = time.monotonic() - started
                        with lock:
                            requests.append(entry)

                # Controller readiness may precede provider loading and data-plane readiness.
                warmup_started = time.monotonic()
                deadline = warmup_started + args.timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("initial route did not become ready before its deadline")
                    process.assert_alive()
                    try:
                        observed = request("warmup", remaining)
                    except (RequestDisruption, OSError, http.client.HTTPException):
                        time.sleep(min(0.005, max(0, deadline - time.monotonic())))
                        continue
                    if observed != "127.0.0.2":
                        raise RuntimeError("initial route was not route-a")
                    break
                warmup_seconds = time.monotonic() - warmup_started
                held_socket = socks_connect(process.mixed_port, "127.0.0.1", fixtures.echo_port, timeout=args.timeout)
                peer = bytearray()
                while not peer.endswith(b"\n") and len(peer) < 64:
                    peer.extend(recv_exact(held_socket, 1))
                held["initialRoute"] = peer.decode("ascii").strip()
                if held["initialRoute"] != "127.0.0.2":
                    raise RuntimeError("held stream did not start on route-a")
                seed = bytes(range(256))
                payload = (seed * ((args.payload_bytes + 255) // 256))[:args.payload_bytes]

                def held_worker():
                    digest = hashlib.sha256()
                    try:
                        while not stop.is_set():
                            sequence = held["exchanges"].to_bytes(8, "big")
                            block = sequence + payload
                            held_socket.sendall(block)
                            returned = recv_exact(held_socket, len(block))
                            if returned != block:
                                raise RuntimeError("held stream bytes changed across reload")
                            digest.update(returned)
                            with lock:
                                held["exchanges"] += 1
                                held["bytes"] += len(returned)
                            stop.wait(0.001)
                    except Exception as exc:
                        with lock:
                            errors.append(f"held flow: {exc}")
                    finally:
                        held["sha256"] = digest.hexdigest()

                def request_worker():
                    while not stop.is_set():
                        try:
                            request("background")
                        except (RequestDisruption, OSError, http.client.HTTPException) as exc:
                            with lock:
                                request_errors.append(str(exc))
                        except Exception as exc:
                            with lock:
                                errors.append(f"invalid background output: {exc}")
                            return

                def healthy():
                    process.assert_alive()
                    if errors or fixtures.errors:
                        raise RuntimeError("; ".join(errors + fixtures.errors))

                def wait_held(after):
                    deadline = time.monotonic() + args.timeout
                    while held["exchanges"] <= after:
                        healthy()
                        if time.monotonic() >= deadline:
                            raise TimeoutError("held stream stopped making progress")
                        time.sleep(0.001)

                def background_count():
                    with lock:
                        return sum(entry["kind"] == "background" and "error" not in entry for entry in requests)

                def wait_background(after):
                    deadline = time.monotonic() + args.timeout
                    while background_count() <= after:
                        healthy()
                        if time.monotonic() >= deadline:
                            raise TimeoutError("background traffic stopped making progress")
                        time.sleep(0.001)

                before = process.mark()
                memory = MemorySampler(process)
                with memory:
                    workers = [threading.Thread(target=held_worker, daemon=True)] + [
                        threading.Thread(target=request_worker, daemon=True) for _ in range(args.concurrency)]
                    for worker in workers:
                        worker.start()
                    try:
                        wait_held(0)
                        wait_background(args.concurrency - 1)
                        for generation in range(1, args.iterations + 1):
                            enabled = bool(generation % 2)
                            expected = "127.0.0.3" if enabled else "127.0.0.2"
                            transition = {"requestedGeneration": generation, "expectedRoute": expected,
                                          "startedAt": time.monotonic(), "heldExchangesBefore": held["exchanges"],
                                          "backgroundRequestsBefore": background_count()}
                            transitions.append(transition)
                            payload_bytes = _provider_payload(args.rules, enabled, generation)
                            if source == "http":
                                fixtures.set_provider(payload_bytes)
                                method, path, body = "PUT", "/providers/rules/http-rules", None
                            elif source == "file":
                                _replace(root / "file-rules.yaml", payload_bytes)
                                method, path, body = "PUT", "/providers/rules/file-rules", None
                            else:
                                updated = copy.deepcopy(process.config)
                                updated["rules"][-1] = "MATCH," + ("route-b" if enabled else "route-a")
                                # An inline payload preserves every effective port and the controller secret.
                                method, path, body = "PUT", "/configs", {"payload": json.dumps(updated)}
                            transition["submittedPayloadSHA256"] = hashlib.sha256(
                                body["payload"].encode("utf-8") if source == "config" else payload_bytes).hexdigest()
                            transition["submissionKind"] = source
                            api_started = time.monotonic()
                            status, response = process.api(method, path, body)
                            transition.update(apiStatus=status, apiSeconds=time.monotonic() - api_started,
                                              response=response.decode("utf-8", errors="replace"))
                            if status != 204:
                                raise RuntimeError(f"{source} reload generation {generation}: HTTP {status}: {response!r}")
                            deadline = time.monotonic() + args.timeout
                            while True:
                                healthy()
                                remaining = deadline - time.monotonic()
                                if remaining <= 0:
                                    raise RuntimeError(f"reload acknowledged but generation {generation} route was not applied")
                                try:
                                    observed = request("generation-proof", remaining)
                                except (RequestDisruption, OSError, http.client.HTTPException) as exc:
                                    with lock:
                                        request_errors.append(f"generation {generation} proof: {exc}")
                                    observations.append({"requestedGeneration": generation, "error": str(exc),
                                                         "at": time.monotonic()})
                                else:
                                    observations.append({"requestedGeneration": generation, "observedRoute": observed,
                                                         "at": time.monotonic()})
                                    if observed == expected:
                                        break
                                time.sleep(min(0.005, max(0, deadline - time.monotonic())))
                            wait_held(held["exchanges"])
                            wait_background(background_count())
                            transition.update(appliedGeneration=generation, observedRoute=observed,
                                              heldExchangesAfter=held["exchanges"],
                                              backgroundRequestsAfter=background_count(),
                                              elapsedSeconds=time.monotonic() - transition["startedAt"])
                        healthy()
                    finally:
                        stop.set()
                        for worker in workers:
                            worker.join(timeout=args.timeout + 1)
                        if any(worker.is_alive() for worker in workers):
                            errors.append("traffic worker did not stop before its deadline")
                resources = process.delta(before)
                healthy()
                if memory.errors:
                    raise RuntimeError("resource sampler failed: " + "; ".join(memory.errors))
                status, _ = process.api("GET", "/configs")
                if status != 200:
                    raise RuntimeError(f"controller unavailable after reload: {status}")
                apply_errors = [line for line in process.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
                                if "running configuration incomplete" in line]
                if apply_errors:
                    raise RuntimeError("configuration apply logged failure: " + "; ".join(apply_errors))
                measured = [entry for entry in requests if entry["kind"] != "warmup"]
                background = [entry for entry in measured if entry["kind"] == "background"]
                proofs = [entry for entry in measured if entry["kind"] == "generation-proof"]
                failed_proofs = [entry for entry in proofs if "error" in entry]
                failed_measured = [entry for entry in measured if "error" in entry]
                successful = [entry for entry in background if "error" not in entry]
                failed = [entry for entry in background if "error" in entry]
                if not background or not memory.samples or not held["exchanges"]:
                    raise RuntimeError("reload window lacks concurrent traffic or memory observations")
                if source == "http" and len(fixtures.provider_reads) < args.iterations + 1:
                    raise RuntimeError("HTTP provider refreshes did not produce the expected fixture reads")
                result = {
                    "name": f"reload.{source}",
                    "parameters": {"rules": args.rules, "providerRules": args.rules,
                                   "iterations": args.iterations, "concurrency": args.concurrency,
                                   "payloadBytes": args.payload_bytes, "memorySampleIntervalSeconds": memory.interval},
                    "operationScope": "provider publication/config apply through observed new route, with sustained miss-heavy HTTP routing and an unchanged established SOCKS TCP echo stream; startup and warmup excluded",
                    "operations": len(transitions),
                    "bytes": sum(entry.get("bytes", 0) for entry in measured) + held["bytes"],
                    "elapsedSeconds": resources["elapsedSeconds"],
                    "latency": summarize_latencies([entry["elapsedSeconds"] for entry in transitions]),
                    "requestLatency": summarize_latencies([entry["elapsedSeconds"] for entry in successful]),
                    "failedRequestLatency": summarize_latencies([entry["elapsedSeconds"] for entry in failed_measured]) if failed_measured else None,
                    "allRequestLatency": summarize_latencies([entry["elapsedSeconds"] for entry in measured]),
                    "generationProofLatency": summarize_latencies([entry["elapsedSeconds"] for entry in proofs]),
                    "resources": resources,
                    "sampledMemory": {"sampleCount": len(memory.samples),
                                      "peakRssKiB": max(sample["rssKiB"] for sample in memory.samples),
                                      "boundary": "sampled whole murmur process RSS, not live heap; sub-interval peaks may be missed"},
                    "validation": {"appliedGenerations": [entry["appliedGeneration"] for entry in transitions],
                                   "routeObservations": observations, "heldFlow": held,
                                   "backgroundRequests": len(background), "processAlive": True,
                                   "controllerStatus": status, "providerHttpReads": len(fixtures.provider_reads),
                                   "errors": errors, "requestErrors": request_errors,
                                   "configApplyErrors": apply_errors,
                                   "failedBackgroundRequests": len(failed),
                                   "failedGenerationProofRequests": len(failed_proofs),
                                   "measuredRequests": len(measured),
                                   "requestErrorRate": len(failed_measured) / len(measured),
                                   "warmupSeconds": warmup_seconds,
                                   "warmupRequestFailures": sum(entry["kind"] == "warmup" and "error" in entry for entry in requests)},
                    "instrumented": args.mode != "clean",
                }
                result["status"] = "degraded" if request_errors else "ok"
                (root / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
                return result
    except Exception as exc:
        errors.append(str(exc))
        raise
    finally:
        stop.set()
        if held_socket is not None:
            held_socket.close()
        evidence = {"source": source, "requests": requests, "transitions": transitions,
                    "heldFlow": held, "errors": errors, "requestErrors": request_errors,
                    "memorySamples": memory.samples if memory else [],
                    "providerReads": fixtures.provider_reads if fixtures else [],
                    "originReads": fixtures.origin_reads if fixtures else [],
                    "fixtureErrors": fixtures.errors if fixtures else []}
        (root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


def run(args, root: Path) -> list[dict]:
    results = []
    for source in ("http", "file", "config"):
        results.append(_run_source(args, root / source, source))
        (root / "completed.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return results
