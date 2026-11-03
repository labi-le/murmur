"""Manual real-provider fanout with independent network and history evidence."""

from __future__ import annotations

import json
import time
from pathlib import Path

from .common import ProxyProcess, summarize_latencies
from .health_support import HealthNetwork


_CACHE_QUIET_SECONDS = 1.05
_MATRIX = ("fast", "close", "length", "chunked", "status", "malformed", "interim",
           "large", "eof", "timeout", "second-timeout")


def _provider(process, name):
    status, body = process.api("GET", f"/providers/proxies/{name}")
    if status != 200:
        raise RuntimeError(f"provider {name} state returned {status}: {body!r}")
    value = json.loads(body)
    proxies = value.get("proxies", [])
    return {proxy["name"]: proxy for proxy in proxies}


def _validate_histories(proxies, names, profiles, url, expected_length, previous):
    if set(proxies) != set(names):
        raise RuntimeError(f"provider node roster differs: {set(proxies)} != {set(names)}")
    checked = {}
    for name in names:
        proxy = proxies[name]
        profile = profiles[name]
        alive = profile not in ("dead", "eof", "malformed", "timeout")
        status_healthy = alive and profile != "status"
        state = proxy.get("extra", {}).get(url, {})
        history = proxy.get("history", [])
        extra_history = state.get("history", [])
        if proxy.get("alive") is not alive or state.get("alive") is not status_healthy:
            raise RuntimeError(f"{name} unexpected alive/status state: {proxy}")
        if len(history) != expected_length or len(extra_history) != expected_length:
            raise RuntimeError(f"{name} history length does not match completed checks: {proxy}")
        for records, healthy in ((history, alive), (extra_history, status_healthy)):
            latest = records[-1]
            if not isinstance(latest.get("delay"), int) or not latest.get("time"):
                raise RuntimeError(f"{name} invalid delay history: {records}")
            if not healthy and latest["delay"] != 0:
                raise RuntimeError(f"{name} failed probe recorded a nonzero delay: {records}")
            if profile == "slow" and latest["delay"] <= 0:
                raise RuntimeError(f"{name} delayed response recorded no elapsed delay: {records}")
        if previous and history[-1]["time"] == previous[name]["history"][-1]["time"]:
            raise RuntimeError(f"{name} cached healthcheck did not publish a new result")
        checked[name] = {"profile": profile, "alive": alive, "statusHealthy": status_healthy,
                         "historyLength": len(history), "lastDelayMs": history[-1]["delay"],
                         "lastStatusDelayMs": extra_history[-1]["delay"]}
    return checked


def _validate_counts(before, after, names, profiles, unified, checks):
    evidence = {}
    for name in names:
        profile = profiles[name]
        requests_per_check = 2 if unified and profile not in (
            "dead", "eof", "malformed", "timeout", "close") else 1
        delta = {key: after[name][key] - before[name][key]
                 for key in ("connects", "requests", "responseBytes", "headRequests", "hostMatches")}
        if delta["connects"] != checks or delta["requests"] != checks * requests_per_check:
            raise RuntimeError(f"{name} unexpected actual probe count: {delta}; "
                               f"expected {checks} tunnels/{checks * requests_per_check} HEADs")
        if delta["headRequests"] != delta["requests"] or delta["hostMatches"] != delta["requests"]:
            raise RuntimeError(f"{name} incorrect HEAD method/path/Host: {delta}")
        evidence[name] = delta
    return evidence


def _check(process, provider):
    status, body = process.api("GET", f"/providers/proxies/{provider}/healthcheck")
    if status != 204 or body:
        raise RuntimeError(f"provider healthcheck returned {status}: {body!r}")


def _measure(args, root, process, network, provider, names, unified, url, probe_timeout_ms):
    profiles = {name: network.nodes[name]["profile"] for name in names}
    initial = _provider(process, provider)
    if set(initial) != set(names) or any(proxy.get("history") for proxy in initial.values()):
        raise RuntimeError(f"{provider} unexpectedly ran automatic healthchecks: {initial}")
    warm_before = network.snapshot()
    _check(process, provider)
    network.quiesce()
    previous = _provider(process, provider)
    _validate_histories(previous, names, profiles, url, 1, None)
    _validate_counts(warm_before, network.snapshot(), names, profiles, unified, 1)
    baseline = network.snapshot()
    network.reset_peak()
    latencies = []
    windows = []
    states = []
    evidence_path = root / f"{provider}-samples.jsonl"
    with evidence_path.open("w") as evidence:
        for iteration in range(args.iterations):
            # Single::do_ caches completion for one second; cached 204s are not fanout samples.
            time.sleep(_CACHE_QUIET_SECONDS)
            before = process.mark()
            _check(process, provider)
            window = process.delta(before)
            latencies.append(window["elapsedSeconds"])
            windows.append(window)
            network.quiesce()
            current = _provider(process, provider)
            checked = _validate_histories(current, names, profiles, url, min(iteration + 2, 10), previous)
            counts = _validate_counts(baseline, network.snapshot(), names, profiles, unified, iteration + 1)
            record = {"iteration": iteration, "resources": window, "nodes": checked, "counts": counts}
            evidence.write(json.dumps(record) + "\n")
            evidence.flush()
            states.append(checked)
            previous = current
            process.assert_alive()
    final_counts = _validate_counts(baseline, network.snapshot(), names, profiles, unified, args.iterations)
    network.save()
    resources = {
        "elapsedSeconds": sum(window["elapsedSeconds"] for window in windows),
        "cpuSeconds": sum(window["cpuSeconds"] for window in windows),
        "rssBeforeKiB": windows[0]["rssBeforeKiB"],
        "rssAfterKiB": windows[-1]["rssAfterKiB"],
        "hwmKiB": max(window["hwmKiB"] for window in windows),
    }
    return {
        "name": f"healthcheck-{provider}-unified-{str(unified).lower()}",
        "parameters": {"nodes": len(names), "iterations": args.iterations, "unifiedDelay": unified,
                       "profiles": profiles, "probeTimeoutMs": probe_timeout_ms,
                       "slowOriginSeconds": network.slow_seconds, "warmupChecks": 1,
                       "automaticHealthchecks": False, "cacheCooldownSeconds": _CACHE_QUIET_SECONDS,
                       "cooldownExcludedFromMeasurement": True, "startupSeconds": process.startup_seconds},
        "operationScope": "Sum of manual /providers/proxies/{name}/healthcheck request windows, "
                          "including controller HTTP and actual outbound CONNECT/HTTP HEAD fanout; "
                          "startup, warmup, one-second result-cache expiry waits, and state validation excluded. "
                          "CPU is murmur child only; RSS/HWM are process memory, not live heap.",
        "operations": args.iterations,
        "bytes": sum(count["responseBytes"] for count in final_counts.values()),
        "elapsedSeconds": resources["elapsedSeconds"],
        "latency": summarize_latencies(latencies), "resources": resources,
        "validation": {"controller204Responses": args.iterations, "nodeChecks": len(names) * args.iterations,
                       "headRequests": sum(count["requests"] for count in final_counts.values()),
                       "byteScope": "HTTP origin response bytes excluding CONNECT and subscription/control traffic",
                       "observedMaximumActiveTunnels": network.peak,
                       "subscriptionRequests": dict(network.subscription_requests),
                       "perNodeCounts": final_counts, "finalStates": states[-1],
                       "sampleEvidence": str(evidence_path), "networkEvidence": str(root / "network-evidence.json")},
        "instrumented": args.mode != "clean",
    }


def run(args, root: Path) -> list[dict]:
    rows = []
    probe_timeout_ms = max(1, min(250, int(args.timeout * 100)))
    slow_seconds = min(0.025, probe_timeout_ms / 4000)
    for unified in (False, True):
        case_root = root / f"unified-{str(unified).lower()}"
        with HealthNetwork(case_root, args.timeout, slow_seconds) as network:
            mixed = [network.add_node(f"mixed-{index:04d}", ("fast", "slow", "dead")[index % 3])
                     for index in range(args.nodes)]
            matrix = [network.add_node(f"response-{profile}", profile) for profile in _MATRIX]
            providers = {"fanout": mixed, "responses": matrix}
            subscription_port = network.subscription(providers)
            url = f"http://{network.authority}/health?benchmark=1"
            config = {
                "unified-delay": unified,
                "proxy-providers": {
                    name: {"type": "http", "url": f"http://127.0.0.1:{subscription_port}/{name}.json",
                           "path": f"./providers/{name}.yaml", "interval": 0,
                           "health-check": {"enable": False, "url": url, "timeout": probe_timeout_ms,
                                            "lazy": True, "expected-status": "200-299"}}
                    for name in providers
                },
                "proxy-groups": [{"name": "health-nodes", "type": "select", "use": list(providers)}],
            }
            with ProxyProcess(args, case_root / "murmur", config) as process:
                for provider, nodes in providers.items():
                    if network.subscription_requests.get(f"/{provider}.json", 0) != 1:
                        raise RuntimeError(f"HTTP provider {provider} was not fetched exactly once")
                    names = [node["name"] for node in nodes]
                    row = _measure(args, case_root, process, network, provider, names, unified, url,
                                   probe_timeout_ms)
                    rows.append(row)
                    (root / "completed-healthcheck-rows.json").write_text(json.dumps(rows, indent=2) + "\n")
    return rows
