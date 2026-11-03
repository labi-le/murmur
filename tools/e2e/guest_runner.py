#!/usr/bin/env python3
"""In-guest scenario driver for tools/e2e_vm.py.

Runs inside the disposable NixOS/QEMU guest, where the staged binaries and
fixtures are visible under /mnt/test. Every scenario starts real processes,
speaks real protocols over real sockets, and asserts consumer-visible results
(a response body, a SHA-256, a routing decision, a rejected connection). It
writes results.json and per-scenario evidence under --out and exits non-zero
when any requested scenario fails.

Standard library only, matching the tools/diff_sweep.py convention.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DEFAULT_PATH = "/run/current-system/sw/bin:/run/wrappers/bin:/usr/bin:/bin"
SECRET = "e2e-synthetic-secret"
FIXTURE_BODY = b"diagnostic fixture reached\n"
VMESS_BODY = b"VMess interoperability target reached\n"
TROJAN_UUID = "d7f8a3c5-1b2d-4e6f-8a90-123456789abc"
VMESS_UUID4 = TROJAN_UUID
VMESS_UUID0 = "e1a2b3c4-5d6e-4f70-8192-a3b4c5d6e7f8"
BULK = bytes(range(251)) * 4096
BULK_SHA = hashlib.sha256(BULK).hexdigest()
UPLOAD = bytes(i % 253 for i in range(len(BULK)))
UPLOAD_SHA = hashlib.sha256(UPLOAD).hexdigest()

SUPPLIED_TARGET_BODY = b"supplied router target reached\n"
SUPPLIED_TARGET_ADDR = "203.0.113.9"
SUPPLIED_TARGET_PORT = 18085
SUPPLIED_PROVIDER_PORT = 18086
SUPPLIED_PROVIDER_NODE = "e2e-provider-node"
SUPPLIED_REFERENCE_PORT = 13014
SUPPLIED_DNS_PORT = 12344
SUPPLIED_TPROXY_PORT = 12342

BIN: dict[str, str] = {}


def tool(name: str) -> str:
    if name not in BIN:
        path = shutil.which(name, path=DEFAULT_PATH) or shutil.which(name)
        if path is None:
            raise RuntimeError(f"required guest binary not found: {name}")
        BIN[name] = path
    return BIN[name]


def run(cmd, timeout=30, cwd=None, env=None):
    merged = dict(os.environ)
    merged["PATH"] = DEFAULT_PATH
    if env:
        merged.update(env)
    return subprocess.run(
        [str(part) for part in cmd],
        capture_output=True,
        timeout=timeout,
        cwd=cwd,
        env=merged,
    )


def free_port() -> int:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def wait_for(predicate, timeout: float, interval: float = 0.3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = predicate()
        except Exception:  # noqa: BLE001 - not ready yet, retried below
            value = None
        if value:
            return value
        time.sleep(interval)
    return None


class Check:
    def __init__(self) -> None:
        self.items: list[dict] = []
        self.skipped = False

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.items.append({"name": name, "ok": bool(ok), "detail": str(detail)[:2000]})
        return bool(ok)

    def passed(self) -> bool:
        return all(item["ok"] for item in self.items)


class MemoryEvidence:
    """One sampler for owned children; all values are KiB, not a process cap."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.done = threading.Event()
        self.active: dict[int, tuple[Proc, dict]] = {}
        self.processes: list[dict] = []
        self.guest = self.empty_guest()
        self.scenario: dict | None = None
        self.scenario_name = ""
        self.sample()
        self.thread = threading.Thread(target=self.loop, name="guest-memory-sampler", daemon=True)
        self.thread.start()

    @staticmethod
    def empty_guest() -> dict:
        return {"memTotalKiB": None, "swapTotalKiB": None, "minMemAvailableKiB": None,
                "lastMemAvailableKiB": None, "samples": 0, "sampleFailures": 0, "lastSampleError": None}

    @staticmethod
    def failure(record: dict, error: Exception) -> None:
        record["sampleFailures"] += 1
        record["lastSampleError"] = f"{type(error).__name__}: {error}"

    @staticmethod
    def start_ticks(pid: int) -> int:
        # comm may contain spaces and parentheses; starttime is field 22.
        return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])

    def register(self, proc: Proc, executable: str) -> None:
        with self.lock:
            record = {"name": proc.name, "pid": proc.proc.pid, "executable": executable,
                      "isMurmur": executable == BIN.get("murmur"), "scenario": self.scenario_name,
                      "startTimeTicks": None, "maxVmRSSKiB": None, "maxVmHWMKiB": None,
                      "lastVmRSSKiB": None, "lastVmHWMKiB": None,
                      "samples": 0, "sampleFailures": 0, "lastSampleError": None,
                      "exitCodeBeforeStop": None, "runningBeforeStop": None}
            self.processes.append(record)
            try:
                record["startTimeTicks"] = self.start_ticks(proc.proc.pid)
            except (OSError, ValueError, IndexError) as error:
                self.failure(record, error)
            self.active[proc.proc.pid] = (proc, record)
            self.sample_process(proc, record)

    def sample_process(self, proc: Proc, record: dict) -> None:
        try:
            pid = proc.proc.pid
            if record["startTimeTicks"] is None or self.start_ticks(pid) != record["startTimeTicks"]:
                raise RuntimeError("child process identity unavailable or changed")
            fields = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
            if int(fields["PPid"].strip()) != os.getpid():
                raise RuntimeError("PID is no longer an owned child")
            rss = int(fields["VmRSS"].split()[0])
            hwm = int(fields["VmHWM"].split()[0])
            record["lastVmRSSKiB"] = rss
            record["lastVmHWMKiB"] = hwm
            record["maxVmRSSKiB"] = max(record["maxVmRSSKiB"] or 0, rss)
            record["maxVmHWMKiB"] = max(record["maxVmHWMKiB"] or 0, hwm)
            record["samples"] += 1
        except (OSError, ValueError, KeyError, IndexError, RuntimeError) as error:
            self.failure(record, error)

    def before_stop(self, proc: Proc) -> None:
        with self.lock:
            tracked = self.active.pop(proc.proc.pid, None)
            if tracked is not None:
                _, record = tracked
                self.sample_process(proc, record)
                record["exitCodeBeforeStop"] = proc.proc.poll()
                record["runningBeforeStop"] = record["exitCodeBeforeStop"] is None

    def sample(self) -> None:
        with self.lock:
            records = [self.guest] + ([self.scenario] if self.scenario is not None else [])
            try:
                fields = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
                total, swap, available = (int(fields[key].split()[0]) for key in ("MemTotal", "SwapTotal", "MemAvailable"))
                for record in records:
                    record["memTotalKiB"] = total
                    record["swapTotalKiB"] = swap
                    record["lastMemAvailableKiB"] = available
                    previous = record["minMemAvailableKiB"]
                    record["minMemAvailableKiB"] = available if previous is None else min(previous, available)
                    record["samples"] += 1
            except (OSError, ValueError, KeyError, IndexError) as error:
                for record in records:
                    self.failure(record, error)
            for proc, record in self.active.values():
                self.sample_process(proc, record)

    def loop(self) -> None:
        while not self.done.wait(0.1):
            self.sample()

    def begin(self, name: str) -> None:
        with self.lock:
            self.scenario_name = name
            self.scenario = self.empty_guest()
            self.sample()

    def snapshot(self, scenario: bool = False) -> dict:
        with self.lock:
            return json.loads(json.dumps({
                "sampleIntervalSeconds": 0.1,
                "guest": self.scenario if scenario else self.guest,
                "processes": [record for record in self.processes
                              if not scenario or record["scenario"] == self.scenario_name],
            }))

    def close(self) -> None:
        self.done.set()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("guest memory sampler did not stop")
        self.sample()


def kernel_memory_evidence(ctx: Context, label: str) -> dict:
    evidence = {"oomKillCount": None, "oomLines": [], "errors": []}
    try:
        fields = dict(line.split() for line in Path("/proc/vmstat").read_text().splitlines())
        evidence["oomKillCount"] = int(fields["oom_kill"])
        evidence["swaps"] = Path("/proc/swaps").read_text()
    except (OSError, ValueError, KeyError) as error:
        evidence["errors"].append(str(error))
    try:
        result = run([tool("dmesg")], timeout=10)
        text = result.stdout.decode(errors="replace")
        (ctx.out / "logs" / f"{label}.dmesg").write_text(text)
        if result.returncode:
            evidence["errors"].append(f"dmesg exit={result.returncode}: {result.stderr.decode(errors='replace')}")
        evidence["oomLines"] = [line for line in text.splitlines()
                                if re.search(r"out of memory|oom-kill|oom_reaper|killed process|invoked oom", line, re.I)]
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        evidence["errors"].append(str(error))
    return evidence


class Proc:
    def __init__(self, name: str, cmd, log: Path, cwd=None, memory: MemoryEvidence | None = None) -> None:
        self.name = name
        self.log = Path(log)
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.log, "ab")
        env = dict(os.environ)
        env["PATH"] = DEFAULT_PATH
        self.proc = subprocess.Popen(
            [str(part) for part in cmd],
            stdout=self.handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            cwd=cwd,
            start_new_session=True,
        )
        self.memory = memory
        if memory is not None:
            memory.register(self, str(cmd[0]))

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self, timeout: float = 6.0) -> None:
        if self.handle.closed:
            return
        if self.memory is not None:
            self.memory.before_stop(self)
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        self.handle.close()

    def tail(self, limit: int = 3000) -> str:
        try:
            data = self.log.read_bytes()
        except OSError:
            return "(no log)"
        return data[-limit:].decode("utf-8", errors="replace")


class Context:
    def __init__(self, args) -> None:
        self.args = args
        self.share = Path(args.share)
        self.out = Path(args.out)
        self.work = self.out.parent / "work"
        self.cert = self.share / "certs" / "fixture-cert.pem"
        self.key = self.share / "certs" / "fixture-key.pem"
        self.home_private = Path(args.home) if args.home else None
        self.rust_sha = ""
        self.ref_sha = ""
        self.curl_seq = 0
        self.procs: list[Proc] = []
        for sub in ("logs", "events", "artifacts", "home"):
            (self.out / sub).mkdir(parents=True, exist_ok=True)
        self.work.mkdir(parents=True, exist_ok=True)
        self.results: list[dict] = []
        self.memory = MemoryEvidence()
        self.kernel_start = kernel_memory_evidence(self, "startup")
        self.kernel_latest = self.kernel_start

    def start(self, name: str, cmd, log_name: str | None = None, cwd=None) -> Proc:
        proc = Proc(name, cmd, self.out / "logs" / (log_name or f"{name}.log"), cwd=cwd, memory=self.memory)
        self.procs.append(proc)
        return proc

    def home(self, name: str) -> Path:
        path = self.work / "home" / name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def stop_all(self) -> None:
        for proc in reversed(self.procs):
            proc.stop()

    def wait_port(self, host: str, port: int, timeout: float = 20.0, name: str = "") -> None:
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1):
                    return
            except OSError as error:
                last = error
                time.sleep(0.2)
        raise RuntimeError(f"{name or 'listener'} {host}:{port} never accepted a connection: {last}")

    def wait_udp(self, host: str, port: int, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            try:
                sock.sendto(b"\x00", (host, port))
                return
            except OSError:
                time.sleep(0.2)
            finally:
                sock.close()
        raise RuntimeError(f"udp listener {host}:{port} never accepted a datagram")

    def api(self, port: int, path: str, timeout: float = 3.0):
        import urllib.request

        request = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
        request.add_header("Authorization", f"Bearer {SECRET}")
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())

    def wait_api(self, port: int, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                self.api(port, "/version", timeout=2)
                return
            except Exception as error:  # noqa: BLE001 - transient while the listener comes up
                last = error
                time.sleep(0.2)
        raise RuntimeError(f"controller API on 127.0.0.1:{port} never came up: {last}")

    def murmur(self, name: str, cfg: dict, files: dict[str, str] | None = None):
        home = self.home(name)
        for rel, content in (files or {}).items():
            target = home / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        cfg["secret"] = SECRET
        cfg_path = home / "config.yaml"
        cfg_path.write_text(json.dumps(cfg, indent=2))
        mixed = cfg["mixed-port"]
        api_port = int(cfg["external-controller"].rsplit(":", 1)[1])
        proc = self.start(f"murmur-{name}", [tool("murmur"), "-d", home, "-f", cfg_path])
        self.wait_api(api_port)
        self.wait_port("127.0.0.1", mixed, name=f"murmur {name} mixed port")
        return proc, mixed, api_port

    def reference(self, name: str, cfg: dict, files: dict[str, str] | None = None, listener_port: int | None = None):
        home = self.home(name)
        for rel, content in (files or {}).items():
            target = home / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        cfg["secret"] = SECRET
        cfg_path = home / "config.yaml"
        cfg_path.write_text(json.dumps(cfg, indent=2))
        api_port = int(cfg["external-controller"].rsplit(":", 1)[1])
        proc = self.start(f"reference-{name}", [tool("reference"), "-d", home, "-f", cfg_path])
        self.wait_api(api_port)
        if listener_port is not None:
            self.wait_port("127.0.0.1", listener_port, name=f"reference {name} listener")
        log = proc.tail()
        for line in log.splitlines():
            if re.search(r"listener|inbound", line, re.I) and re.search(r"error|failed", line, re.I):
                raise RuntimeError(f"reference {name} reported a listener error: {line}")
        return proc

    def curl(self, mixed: int, url: str, proxy: str | None = None, extra=(), timeout: int = 30, out: Path | None = None):
        body_path = Path(out) if out else self.out / "artifacts" / f"curl-body-{self.curl_seq}.bin"
        if out is None:
            self.curl_seq += 1
        args = [tool("curl"), "-sS", "--noproxy", ""]
        if proxy == "http":
            args += ["-x", f"http://127.0.0.1:{mixed}"]
        elif proxy == "socks":
            args += ["--socks5-hostname", f"127.0.0.1:{mixed}"]
        args += ["--max-time", str(timeout), "-o", str(body_path), "-w", "%{http_code}"]
        args += [str(item) for item in extra]
        args += [url]
        result = run(args, timeout=timeout + 15)
        body = body_path.read_bytes() if body_path.exists() else b""
        return result.returncode, result.stdout.decode().strip(), body, result.stderr.decode()

    def dig(self, port: int, name: str, rtype: str, tcp: bool = False) -> list[str]:
        args = [tool("dig"), "+short", "@127.0.0.1", "-p", str(port)]
        if tcp:
            args.append("+tcp")
        args += [name, rtype]
        result = run(args, timeout=10)
        return result.stdout.decode().split()

    def fixture(self, name: str = "fixtures") -> Proc:
        events = self.out / "events" / f"{name}.jsonl"
        events.write_text("")
        proc = self.start(
            name,
            [
                tool("python3"),
                self.share / "e2e" / "fixtures" / "fixture_server.py",
                "--cert",
                self.cert,
                "--key",
                self.key,
                "--events",
                events,
            ],
            log_name=f"{name}.log",
        )
        for port in (11001, 11002, 11003):
            self.wait_port("127.0.0.1", port, name=f"fixture {port}")
        return proc

    def fixture_events(self, name: str = "fixtures") -> list[dict]:
        path = self.out / "events" / f"{name}.jsonl"
        events = []
        for line in path.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events


def proxy(mixed: int, api_port: int, name: str, entry: dict, rules=None) -> dict:
    return {
        "mode": "rule",
        "log-level": "debug",
        "mixed-port": mixed,
        "external-controller": f"127.0.0.1:{api_port}",
        "proxies": [entry],
        "rules": rules or [f"MATCH,{name}"],
    }


def trojan_entry(port: int) -> dict:
    return {
        "name": "trojan",
        "type": "trojan",
        "server": "127.0.0.1",
        "port": port,
        "password": "e2e-synthetic-password",
        "sni": "localhost",
        "skip-cert-verify": True,
        "client-fingerprint": "chrome",
        "alpn": ["http/1.1"],
    }


def vless_entry(flow: str, fingerprint: str | None = "chrome") -> dict:
    entry = {
        "name": "vless",
        "type": "vless",
        "server": "127.0.0.1",
        "port": 11003,
        "uuid": TROJAN_UUID,
        "tls": True,
        "servername": "localhost",
        "skip-cert-verify": True,
        "flow": flow,
        "alpn": ["http/1.1"],
    }
    if fingerprint:
        entry["client-fingerprint"] = fingerprint
    return entry


def vision_entry(fingerprint: str | None) -> dict:
    entry = {
        "name": "VISION",
        "type": "vless",
        "server": "127.0.0.1",
        "port": 13003,
        "uuid": TROJAN_UUID,
        "tls": True,
        "servername": "localhost",
        "skip-cert-verify": True,
        "flow": "xtls-rprx-vision",
    }
    if fingerprint:
        entry["client-fingerprint"] = fingerprint
    return entry


def vmess_entry(alter_id: int, uuid: str) -> dict:
    return {
        "name": "vmess",
        "type": "vmess",
        "server": "127.0.0.1",
        "port": 13004,
        "uuid": uuid,
        "alterId": alter_id,
        "cipher": "auto",
    }


def dns_config(mixed: int, api_port: int, home: Path) -> dict:
    rules = {
        "vpn": "+.vpn.example\n",
        "telegram": "+.telegram.example\n",
        "warp": "+.warp.example\n",
    }
    for name, content in rules.items():
        (home / "rules").mkdir(parents=True, exist_ok=True)
        (home / "rules" / f"{name}.txt").write_text(content)
    return {
        "mode": "rule",
        "log-level": "debug",
        "mixed-port": mixed,
        "external-controller": f"127.0.0.1:{api_port}",
        "ipv6": False,
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:12344",
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.1.0/24",
            "fake-ip-filter-mode": "rule",
            "fake-ip-filter": [
                "DOMAIN-SUFFIX,lan,real-ip",
                "DOMAIN-SUFFIX,local,real-ip",
                "RULE-SET,vpn,fake-ip",
                "RULE-SET,telegram,fake-ip",
                "RULE-SET,warp,fake-ip",
                "MATCH,real-ip",
            ],
            "nameserver": ["127.0.0.1:5453"],
        },
        "rule-providers": {
            name: {
                "type": "file",
                "path": f"./rules/{name}.txt",
                "behavior": "domain",
                "format": "text",
            }
            for name in rules
        },
        "profile": {"store-fake-ip": True},
        "rules": ["MATCH,DIRECT"],
    }


def groups_config(mixed: int, api_port: int, home: Path) -> dict:
    (home / "providers").mkdir(parents=True, exist_ok=True)
    (home / "providers" / "empty.yaml").write_text("proxies: []\n")
    return {
        "mode": "rule",
        "log-level": "debug",
        "mixed-port": mixed,
        "external-controller": f"127.0.0.1:{api_port}",
        "proxies": [
            {
                "name": "dead",
                "type": "vmess",
                "server": "127.0.0.1",
                "port": 19999,
                "uuid": VMESS_UUID4,
                "alterId": 4,
                "cipher": "auto",
            }
        ],
        "proxy-providers": {"empty": {"type": "file", "path": "./providers/empty.yaml"}},
        "proxy-groups": [
            {
                "name": "WARP",
                "type": "fallback",
                "proxies": ["dead", "DIRECT"],
                "url": "http://127.0.0.1:18080/",
                "interval": 60,
                "lazy": False,
                "timeout": 1000,
                "expected-status": "200",
            },
            {
                "name": "EMPTY",
                "type": "url-test",
                "use": ["empty"],
                "url": "http://127.0.0.1:18080/",
                "interval": 60,
                "lazy": False,
                "timeout": 1000,
                "expected-status": "200",
                "empty-fallback": "REJECT",
            },
        ],
        "rules": ["DST-PORT,18081,EMPTY", "IP-CIDR,127.0.0.1/32,WARP", "MATCH,REJECT"],
    }


def tproxy_config(mixed: int, api_port: int) -> dict:
    return {
        "mode": "rule",
        "allow-lan": True,
        "bind-address": "*",
        "ipv6": False,
        "log-level": "debug",
        "mixed-port": mixed,
        "tproxy-port": 12342,
        "external-controller": f"127.0.0.1:{api_port}",
        "iptables": {"inbound-interface": "br-lan"},
        "rules": ["MATCH,DIRECT"],
    }


def supplied_router_config(mixed: int, api_port: int, home: Path, provider_port: int) -> dict:
    health = f"http://{SUPPLIED_TARGET_ADDR}:{SUPPLIED_TARGET_PORT}/"
    rules = {
        "vpn": "+.vpn.example\n",
        "telegram": "+.telegram.example\n",
        "warp": "+.warp.example\n",
        "telegram_ip": "198.51.100.0/24\n",
        "warp_ip": "198.51.101.0/24\n",
    }
    for name, content in rules.items():
        (home / "rules").mkdir(parents=True, exist_ok=True)
        (home / "rules" / f"{name}.txt").write_text(content)
    return {
        "mode": "rule",
        "allow-lan": True,
        "bind-address": "*",
        "log-level": "info",
        "ipv6": False,
        "mixed-port": mixed,
        "tproxy-port": SUPPLIED_TPROXY_PORT,
        "external-controller": f"127.0.0.1:{api_port}",
        "iptables": {"inbound-interface": "br-lan"},
        "proxies": [
            {"name": "WARP-AWG0", "type": "direct", "udp": True, "interface-name": "e2e-awg0-missing"},
            {"name": "WARP-AWG1", "type": "direct", "udp": True, "interface-name": "lo"},
            {"name": "WARP-AWG2", "type": "direct", "udp": True, "interface-name": "lo"},
        ],
        "dns": {
            "enable": True,
            "listen": f"0.0.0.0:{SUPPLIED_DNS_PORT}",
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.1.0/24",
            "fake-ip-filter-mode": "rule",
            "fake-ip-filter": [
                "DOMAIN-SUFFIX,lan,real-ip",
                "DOMAIN-SUFFIX,local,real-ip",
                "RULE-SET,vpn,fake-ip",
                "RULE-SET,telegram,fake-ip",
                "RULE-SET,warp,fake-ip",
                "MATCH,real-ip",
            ],
            "nameserver": ["127.0.0.1:5453"],
        },
        "proxy-providers": {
            "stable": {
                "type": "http",
                "url": f"http://127.0.0.1:{provider_port}/stable.txt",
                "path": "./providers/stable.yaml",
                "interval": 60,
                "health-check": {
                    "enable": True,
                    "url": health,
                    "interval": 10,
                    "timeout": 3000,
                    "lazy": False,
                    "expected-status": 200,
                },
            }
        },
        "proxy-groups": [
            {
                "name": "WARP",
                "type": "fallback",
                "proxies": ["WARP-AWG0", "WARP-AWG1", "DIRECT"],
                "url": health,
                "interval": 3,
                "lazy": False,
                "timeout": 3000,
                "expected-status": "200",
            },
            {
                "name": "VPN",
                "type": "fallback",
                "proxies": ["VPN-ALL-AUTO", "WARP-AWG2"],
                "url": health,
                "interval": 3,
                "lazy": False,
                "expected-status": "200-399",
            },
            {
                "name": "VPN-ALL-AUTO",
                "type": "url-test",
                "use": ["stable"],
                "url": health,
                "interval": 3,
                "timeout": 3000,
                "tolerance": 150,
                "lazy": False,
                "expected-status": "200-399",
                "empty-fallback": "REJECT",
            },
        ],
        "rule-providers": {
            "vpn": {"type": "file", "path": "./rules/vpn.txt", "behavior": "domain", "format": "text"},
            "warp": {"type": "file", "path": "./rules/warp.txt", "behavior": "domain", "format": "text"},
            "warp_ip": {"type": "file", "path": "./rules/warp_ip.txt", "behavior": "ipcidr", "format": "text"},
            "telegram": {"type": "file", "path": "./rules/telegram.txt", "behavior": "domain", "format": "text"},
            "telegram_ip": {
                "type": "file",
                "path": "./rules/telegram_ip.txt",
                "behavior": "ipcidr",
                "format": "text",
            },
        },
        "rules": [
            "RULE-SET,vpn,VPN",
            "RULE-SET,telegram,WARP",
            "RULE-SET,telegram_ip,WARP,no-resolve",
            "RULE-SET,warp,WARP",
            "RULE-SET,warp_ip,WARP,no-resolve",
            "MATCH,DIRECT",
        ],
        "profile": {"store-fake-ip": True},
    }


def supplied_provider_reference(ctx: Context) -> Proc:
    api_port = free_port()
    cfg = {
        "mode": "rule",
        "log-level": "info",
        "external-controller": f"127.0.0.1:{api_port}",
        "hosts": {
            "host.vpn.example": SUPPLIED_TARGET_ADDR,
            "host.telegram.example": SUPPLIED_TARGET_ADDR,
            "host.warp.example": SUPPLIED_TARGET_ADDR,
        },
        "listeners": [
            {
                "name": "supplied-provider",
                "type": "vmess",
                "listen": "127.0.0.1",
                "port": SUPPLIED_REFERENCE_PORT,
                "users": [{"username": "e2e-provider", "uuid": VMESS_UUID0, "alterId": 0}],
            }
        ],
        "rules": ["MATCH,DIRECT"],
    }
    return ctx.reference("supplied-provider", cfg, listener_port=SUPPLIED_REFERENCE_PORT)


def supplied_subscription() -> bytes:
    share = {
        "v": "2",
        "ps": SUPPLIED_PROVIDER_NODE,
        "add": "127.0.0.1",
        "port": SUPPLIED_REFERENCE_PORT,
        "id": VMESS_UUID0,
        "aid": 0,
        "scy": "auto",
        "net": "tcp",
        "type": "none",
        "host": "",
        "path": "",
        "tls": "",
    }
    uri = "vmess://" + base64.b64encode(json.dumps(share).encode()).decode()
    return base64.b64encode((uri + "\n").encode())


def parse_configs(ctx: Context) -> None:
    home = ctx.home("parse")
    configs = {
        "direct": {
            "mode": "rule",
            "log-level": "debug",
            "mixed-port": 17890,
            "external-controller": "127.0.0.1:19090",
            "rules": ["MATCH,DIRECT"],
        },
        "trojan": proxy(17891, 19091, "trojan", trojan_entry(11001)),
        "vless_vision": proxy(17892, 19092, "vless", vless_entry("xtls-rprx-vision")),
        "vmess_legacy": proxy(17893, 19093, "vmess", vmess_entry(4, VMESS_UUID4)),
        "tproxy": tproxy_config(17894, 19094),
        "dns": dns_config(17895, 19095, home),
        "groups": groups_config(17896, 19096, home),
        "supplied_router": supplied_router_config(17897, 19097, home, SUPPLIED_PROVIDER_PORT),
    }
    checks = Check()
    cfg_path = home / "config.yaml"
    for name, cfg in configs.items():
        cfg["secret"] = SECRET
        cfg_path.write_text(json.dumps(cfg, indent=2))
        result = run([tool("murmur"), "-t", "-d", home, "-f", cfg_path], timeout=30)
        stdout = result.stdout.decode()
        checks.add(
            f"parse_{name}",
            result.returncode == 0 and "test is successful" in stdout,
            f"exit={result.returncode} stdout={stdout.strip()} stderr={result.stderr.decode().strip()}",
        )
    return checks


def scen_config_parse(ctx: Context, chk: Check) -> str:
    parsed = parse_configs(ctx)
    for item in parsed.items:
        chk.add(item["name"], item["ok"], item["detail"])
    return f"{sum(item['ok'] for item in parsed.items)}/{len(parsed.items)} generated configs parsed"


def scen_direct(ctx: Context, chk: Check) -> str:
    target = ctx.start(
        "http-direct",
        [tool("python3"), ctx.share / "e2e" / "fixtures" / "http_target.py", "--port", "18080", "--body", "direct target reached\n"],
    )
    ctx.wait_port("127.0.0.1", 18080, name="direct target")
    mixed, api_port = free_port(), free_port()
    cfg = {
        "mode": "rule",
        "log-level": "debug",
        "mixed-port": mixed,
        "external-controller": f"127.0.0.1:{api_port}",
        "rules": ["MATCH,DIRECT"],
    }
    proc, mixed, _ = ctx.murmur("direct", cfg)
    try:
        rc, code, body, err = ctx.curl(mixed, "http://127.0.0.1:18080/", proxy="http")
        chk.add(
            "http_inbound_direct",
            rc == 0 and code == "200" and body == b"direct target reached\n",
            f"exit={rc} code={code} body={body!r} err={err.strip()}",
        )
        rc, code, body, err = ctx.curl(mixed, "http://127.0.0.1:18080/", proxy="socks")
        chk.add(
            "socks_inbound_direct",
            rc == 0 and code == "200" and body == b"direct target reached\n",
            f"exit={rc} code={code} body={body!r} err={err.strip()}",
        )
    finally:
        proc.stop()
        target.stop()
    return "mixed port served both HTTP and SOCKS5 DIRECT requests"


def fixture_scenario(ctx: Context, chk: Check, name: str, entry: dict, expect_vision: bool, label: str) -> str:
    ctx.fixture()
    mixed, api_port = free_port(), free_port()
    proc, mixed, _ = ctx.murmur(name, proxy(mixed, api_port, entry["name"], entry))
    try:
        rc, code, body, err = ctx.curl(mixed, "http://fixture.test/", proxy="http")
        chk.add(
            f"{label}_body",
            rc == 0 and code == "200" and body == FIXTURE_BODY,
            f"exit={rc} code={code} body={body!r} err={err.strip()}",
        )
    finally:
        proc.stop()
        for started in ctx.procs:
            if started.name == "fixtures":
                started.stop()
    events = [event for event in ctx.fixture_events() if event.get("httpStatus") == 200]
    chk.add(
        f"{label}_fixture_record",
        bool(events) and all(event.get("vision") == expect_vision for event in events),
        json.dumps(events),
    )
    return f"{label}: fixture answered {FIXTURE_BODY!r}"


def scen_trojan_x25519(ctx: Context, chk: Check) -> str:
    return fixture_scenario(ctx, chk, "trojan-x25519", trojan_entry(11001), False, "trojan_x25519")


def scen_trojan_p256(ctx: Context, chk: Check) -> str:
    detail = fixture_scenario(ctx, chk, "trojan-p256", trojan_entry(11002), False, "trojan_p256_hrr")
    events = [event for event in ctx.fixture_events() if event.get("port") == 11002]
    chk.add(
        "p256_retry_completed_on_wire",
        any(event.get("helloRetryRequest") for event in events)
        and sum(bool(event.get("clientHello")) for event in events) == 2,
        json.dumps(events),
    )
    return detail


def scen_vless_plain(ctx: Context, chk: Check) -> str:
    return fixture_scenario(ctx, chk, "vless-plain", vless_entry(""), False, "vless_plain")


def scen_vless_vision(ctx: Context, chk: Check) -> str:
    return fixture_scenario(ctx, chk, "vless-vision", vless_entry("xtls-rprx-vision"), True, "vless_vision")


def vision_server(ctx: Context, name: str = "vision-server") -> Proc:
    api_port = free_port()
    cfg = {
        "mode": "rule",
        "log-level": "info",
        "external-controller": f"127.0.0.1:{api_port}",
        "listeners": [
            {
                "name": "vision",
                "type": "vless",
                "listen": "127.0.0.1",
                "port": 13003,
                "users": [{"username": "e2e", "uuid": TROJAN_UUID, "flow": "xtls-rprx-vision"}],
                "certificate": "./cert.pem",
                "private-key": "./key.pem",
            }
        ],
        "rules": ["MATCH,DIRECT"],
    }
    files = {
        "cert.pem": ctx.cert.read_text(),
        "key.pem": ctx.key.read_text(),
    }
    return ctx.reference(name, cfg, files, listener_port=13003)


def scen_vision_bulk(ctx: Context, chk: Check, label: str, fingerprint: str | None) -> str:
    server = vision_server(ctx)
    bulk = ctx.start(
        "bulk-target",
        [tool("python3"), ctx.share / "e2e" / "fixtures" / "https_bulk_target.py", "--port", "18083", "--cert", ctx.cert, "--key", ctx.key],
    )
    ctx.wait_port("127.0.0.1", 18083, name="bulk target")
    mixed, api_port = free_port(), free_port()
    proc, mixed, _ = ctx.murmur(label, proxy(mixed, api_port, "VISION", vision_entry(fingerprint)))
    try:
        download = ctx.out / "artifacts" / f"{label}-download.bin"
        rc, code, body, err = ctx.curl(mixed, "https://127.0.0.1:18083/", proxy="http", extra=["-k"], timeout=60, out=download)
        chk.add(f"{label}_download_status", rc == 0 and code == "200", f"exit={rc} code={code} err={err.strip()}")
        digest = hashlib.sha256(download.read_bytes()).hexdigest() if download.exists() else ""
        chk.add(f"{label}_download_bytes", download.exists() and download.stat().st_size == len(BULK), f"size={download.stat().st_size if download.exists() else -1}")
        chk.add(f"{label}_download_sha256", digest == BULK_SHA, f"got={digest} want={BULK_SHA}")

        upload = ctx.out / "artifacts" / f"{label}-upload.bin"
        upload.write_bytes(UPLOAD)
        rc, code, body, err = ctx.curl(
            mixed,
            "https://127.0.0.1:18083/",
            proxy="http",
            extra=["-k", "--data-binary", f"@{upload}"],
            timeout=60,
        )
        received = json.loads(body) if body else {}
        chk.add(f"{label}_upload_status", rc == 0 and code == "200", f"exit={rc} code={code} err={err.strip()}")
        chk.add(f"{label}_upload_bytes", received.get("receivedBytes") == len(UPLOAD), json.dumps(received))
        chk.add(f"{label}_upload_sha256", received.get("sha256") == UPLOAD_SHA, f"got={received.get('sha256')} want={UPLOAD_SHA}")
    finally:
        proc.stop()
        bulk.stop()
        server.stop()
    return f"{label}: {len(BULK)}-byte download and upload verified by SHA-256"


def scen_vision_no_fingerprint(ctx: Context, chk: Check) -> str:
    return scen_vision_bulk(ctx, chk, "vision-no-fingerprint", None)


def scen_vision_chrome(ctx: Context, chk: Check) -> str:
    return scen_vision_bulk(ctx, chk, "vision-chrome", "chrome")


def scen_vision_firefox(ctx: Context, chk: Check) -> str:
    return scen_vision_bulk(ctx, chk, "vision-firefox", "firefox")


def vmess_server(ctx: Context) -> Proc:
    api_port = free_port()
    cfg = {
        "mode": "rule",
        "log-level": "info",
        "external-controller": f"127.0.0.1:{api_port}",
        "listeners": [
            {
                "name": "vmess",
                "type": "vmess",
                "listen": "127.0.0.1",
                "port": 13004,
                "users": [
                    {"username": "e2e-legacy", "uuid": VMESS_UUID4, "alterId": 4},
                    {"username": "e2e-aead", "uuid": VMESS_UUID0, "alterId": 0},
                ],
            }
        ],
        "rules": ["MATCH,DIRECT"],
    }
    return ctx.reference("vmess-server", cfg, listener_port=13004)


def scen_vmess(ctx: Context, chk: Check, label: str, alter_id: int, uuid: str) -> str:
    server = vmess_server(ctx)
    target = ctx.start(
        "vmess-target",
        [tool("python3"), ctx.share / "e2e" / "fixtures" / "http_target.py", "--port", "18080", "--body", "VMess interoperability target reached\n"],
    )
    try:
        ctx.wait_port("127.0.0.1", 18080, name="vmess target")
        mixed, api_port = free_port(), free_port()
        proc, mixed, _ = ctx.murmur(label, proxy(mixed, api_port, "vmess", vmess_entry(alter_id, uuid)))
        try:
            rc, code, body, err = ctx.curl(mixed, "http://127.0.0.1:18080/", proxy="http")
            chk.add(
                f"{label}_body",
                rc == 0 and code == "200" and body == VMESS_BODY,
                f"exit={rc} code={code} body={body!r} err={err.strip()}",
            )
        finally:
            proc.stop()
    finally:
        target.stop()
        server.stop()
    return f"{label}: reference VMess server answered {VMESS_BODY!r}"


def scen_vmess_legacy(ctx: Context, chk: Check) -> str:
    return scen_vmess(ctx, chk, "vmess-legacy-alterid4", 4, VMESS_UUID4)


def scen_vmess_aead(ctx: Context, chk: Check) -> str:
    return scen_vmess(ctx, chk, "vmess-aead-alterid0", 0, VMESS_UUID0)


def scen_tproxy(ctx: Context, chk: Check) -> str:
    setup = run([tool("bash"), ctx.share / "e2e" / "fixtures" / "tproxy_setup.sh"], timeout=40)
    chk.add("topology_setup", setup.returncode == 0, f"exit={setup.returncode} err={setup.stderr.decode()[-1000:]}")
    if setup.returncode != 0:
        return "network namespace topology failed to build"

    target = ctx.start(
        "tproxy-target",
        [tool("ip"), "netns", "exec", "target", tool("python3"), ctx.share / "e2e" / "fixtures" / "tproxy_target.py"],
    )
    ctx.wait_port("149.154.160.10", 18080, name="tproxy target")

    mixed, api_port = free_port(), free_port()
    proc, mixed, _ = ctx.murmur("tproxy", tproxy_config(mixed, api_port))
    try:
        listeners = ""
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            listeners = run([tool("ss"), "-lntu"], timeout=10).stdout.decode()
            if re.search(r"(\*|0\.0\.0\.0):12342\b", listeners):
                break
            time.sleep(0.3)
        chk.add(
            "wildcard_listener",
            re.search(r"(\*|0\.0\.0\.0):12342\b", listeners) is not None,
            "; ".join(line for line in listeners.splitlines() if "12342" in line) or listeners[-500:],
        )
        command = [
            tool("ip"),
            "netns",
            "exec",
            "lan",
            tool("curl"),
            "--noproxy",
            "*",
            "-sS",
            "--max-time",
            "20",
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
            "http://149.154.160.10:18080/",
        ]
        result = run(command, timeout=30)
        output = result.stdout.decode()
        lines = output.rsplit("\n", 1)
        chk.add(
            "tproxy_tcp",
            result.returncode == 0 and lines[-1].strip() == "200" and lines[0].encode() == b"transparent target reached\n",
            f"exit={result.returncode} out={output!r} err={result.stderr.decode().strip()}",
        )
        result = run(
            [tool("ip"), "netns", "exec", "lan", tool("python3"), ctx.share / "e2e" / "fixtures" / "tproxy_udp_client.py"],
            timeout=30,
        )
        try:
            udp = json.loads(result.stdout.decode())
        except json.JSONDecodeError:
            udp = []
        chk.add(
            "tproxy_udp",
            len(udp) == 3 and all(item["payloadEqual"] and item["senderCorrect"] for item in udp),
            f"exit={result.returncode} out={result.stdout.decode().strip()} err={result.stderr.decode().strip()}",
        )
    finally:
        proc.stop()
        target.stop()
    return "wildcard TPROXY carried TCP and 1/127/1200-byte UDP with the original sender preserved"


def dns_checks(ctx: Context, chk: Check, prefix: str) -> str | None:
    fake = [ip for ip in ctx.dig(12344, "host.vpn.example", "A")]
    fake_ip = fake[0] if fake else ""
    chk.add(f"{prefix}_vpn_fake_ip", bool(fake_ip) and fake_ip.startswith("198.18.1."), f"answer={fake}")
    telegram = ctx.dig(12344, "host.telegram.example", "A")
    chk.add(f"{prefix}_telegram_fake_ip", bool(telegram) and telegram[0].startswith("198.18.1."), f"answer={telegram}")
    warp = ctx.dig(12344, "host.warp.example", "A")
    chk.add(f"{prefix}_warp_fake_ip", bool(warp) and warp[0].startswith("198.18.1."), f"answer={warp}")
    real = ctx.dig(12344, "plain.example", "A")
    chk.add(f"{prefix}_real_ip", real == ["203.0.113.9"], f"answer={real}")
    local = ctx.dig(12344, "something.lan", "A")
    chk.add(f"{prefix}_local_real_ip", local == ["203.0.113.9"], f"answer={local}")
    aaaa = ctx.dig(12344, "host.vpn.example", "AAAA")
    chk.add(f"{prefix}_aaaa_disabled", aaaa == [], f"answer={aaaa}")
    tcp = ctx.dig(12344, "host.vpn.example", "A", tcp=True)
    chk.add(f"{prefix}_tcp_fake_ip", bool(tcp) and tcp[0].startswith("198.18.1."), f"answer={tcp}")
    return fake_ip or None


def dns_upstream(ctx: Context) -> Proc:
    proc = ctx.start("dns-upstream", [tool("python3"), ctx.share / "e2e" / "fixtures" / "dns_upstream.py", "--port", "5453"])
    ctx.wait_udp("127.0.0.1", 5453)
    return proc


def start_dns_murmur(ctx: Context, name: str):
    home = ctx.home(name)
    mixed, api_port = free_port(), free_port()
    cfg = dns_config(mixed, api_port, home)
    proc, mixed, api_port = ctx.murmur(name, cfg)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if ctx.dig(12344, "plain.example", "A") == ["203.0.113.9"]:
            break
        time.sleep(0.2)
    return proc, home, mixed, api_port, cfg


def scen_dns_fakeip(ctx: Context, chk: Check) -> str:
    upstream = dns_upstream(ctx)
    proc, home, mixed, api_port, cfg = start_dns_murmur(ctx, "dns-fakeip")
    try:
        fake_ip = dns_checks(ctx, chk, "dns")
    finally:
        proc.stop()
        upstream.stop()
    return f"fake-IP DNS filters, real-IP exclusions and AAAA suppression verified (vpn.example -> {fake_ip})"


def scen_dns_restart(ctx: Context, chk: Check) -> str:
    upstream = dns_upstream(ctx)
    proc, home, mixed, api_port, cfg = start_dns_murmur(ctx, "dns-restart")

    def fake(answer: list[str]) -> bool:
        return len(answer) == 1 and answer[0].startswith("198.18.1.")

    seed_one = ctx.dig(SUPPLIED_DNS_PORT, "first.vpn.example", "A")
    seed_two = ctx.dig(SUPPLIED_DNS_PORT, "second.vpn.example", "A")
    first = ctx.dig(SUPPLIED_DNS_PORT, "host.vpn.example", "A")
    chk.add(
        "fake_ip_seeds_are_distinct_allocations",
        fake(seed_one) and fake(seed_two) and fake(first)
        and len({seed_one[0], seed_two[0], first[0]}) == 3,
        f"first.example={seed_one} second.example={seed_two} host.example={first}",
    )
    proc.stop()
    proc, _, _ = ctx.murmur("dns-restart", cfg)
    deadline = time.monotonic() + 15
    second: list[str] = []
    while time.monotonic() < deadline:
        second = ctx.dig(SUPPLIED_DNS_PORT, "host.vpn.example", "A")
        if second:
            break
        time.sleep(0.2)
    upstream.stop()
    chk.add(
        "fake_ip_stable_across_restart",
        fake(first) and first == second,
        f"before={first} after={second}",
    )
    return f"stored fake-IP survived a restart ({first} == {second})"


def scen_groups(ctx: Context, chk: Check) -> str:
    fallback_target = ctx.start(
        "fallback-target",
        [tool("python3"), ctx.share / "e2e" / "fixtures" / "http_target.py", "--port", "18080", "--body", "fallback target reached\n"],
    )
    rejected_target = ctx.start(
        "rejected-target",
        [tool("python3"), ctx.share / "e2e" / "fixtures" / "http_target.py", "--port", "18081", "--body", "rejected target reached\n"],
    )
    ctx.wait_port("127.0.0.1", 18081, name="rejected target")
    home = ctx.home("groups")
    mixed, api_port = free_port(), free_port()
    cfg = groups_config(mixed, api_port, home)
    proc, mixed, api_port = ctx.murmur("groups", cfg)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if ctx.api(api_port, "/proxies/WARP").get("now") == "DIRECT":
                    break
            except Exception:  # noqa: BLE001 - the group health check is still running
                pass
            time.sleep(0.3)
        rc, code, body, err = ctx.curl(mixed, "http://127.0.0.1:18080/", proxy="http")
        chk.add(
            "fallback_group_reaches_direct",
            rc == 0 and code == "200" and body == b"fallback target reached\n",
            f"exit={rc} code={code} body={body!r} err={err.strip()}",
        )
        rc, code, body, err = ctx.curl(mixed, "http://127.0.0.1:18081/", proxy="http", timeout=20)
        chk.add(
            "empty_provider_fails_closed",
            code != "200" and b"rejected target reached" not in body,
            f"exit={rc} code={code} body={body!r} err={err.strip()}",
        )
    finally:
        proc.stop()
        fallback_target.stop()
        rejected_target.stop()
    return "fallback group fell through to DIRECT; empty-provider url-test rejected instead of leaking"


def scen_real_node_sweep(ctx: Context, chk: Check) -> str:
    if ctx.home_private is None:
        chk.skipped = True
        return "skipped: no --home supplied, so no real-node comparison was requested"
    sweep = ctx.out / "artifacts" / "sweep-output.txt"
    cmd = [
        tool("python3"),
        ctx.share / "e2e" / "diff_sweep.py",
        "--ref-bin",
        tool("reference"),
        "--rust-bin",
        tool("murmur"),
        "--home",
        ctx.home_private,
        "--repeats",
        str(ctx.args.repeats),
        "--workdir",
        ctx.work / "sweep",
        "--keep-workdir",
    ]
    if ctx.args.group:
        cmd += ["--group", ctx.args.group]
    result = run(cmd, timeout=1800)
    sweep.write_text(result.stdout.decode())
    (ctx.out / "artifacts" / "sweep-stderr.txt").write_text(result.stderr.decode())
    summary = next((line for line in result.stdout.decode().splitlines() if line.startswith("summary:")), "")
    chk.add("real_node_sweep_exit", result.returncode == 0, f"exit={result.returncode} {summary}")
    if result.returncode == 2:
        raise RuntimeError(f"diff_sweep reported a setup error: {result.stderr.decode()[-1000:]}")
    return summary or "diff_sweep produced no summary"


def log_line(log: str, needle: str) -> str:
    for line in log.splitlines():
        if needle in line:
            return line[-400:]
    return ""


def supplied_reached(result: dict) -> bool:
    return result.get("exit") == 0 and result.get("code") == "200" and result.get("body") == SUPPLIED_TARGET_BODY


def ensure_lan_topology(ctx: Context, chk: Check) -> None:
    table = run([tool("nft"), "list", "table", "inet", "murmur_e2e_tproxy"], timeout=10)
    netns = run([tool("ip"), "netns", "show"], timeout=10).stdout.decode().split()
    if table.returncode != 0 or "lan" not in netns:
        setup = run([tool("bash"), ctx.share / "e2e" / "fixtures" / "tproxy_setup.sh"], timeout=40)
        chk.add("supplied_topology_setup", setup.returncode == 0, f"exit={setup.returncode} err={setup.stderr.decode()[-600:]}")
    else:
        chk.add("supplied_topology_reused", True, "br-lan/lan namespaces and the TPROXY table already exist")
    rules = run([tool("nft"), "list", "chain", "inet", "murmur_e2e_tproxy", "prerouting"], timeout=10).stdout.decode()
    if "198.18.1.0/24" in rules:
        chk.add("supplied_fakeip_tproxy_rule", True, "fake-IP TPROXY rule already present")
        return
    add = run(
        [
            tool("nft"), "add", "rule", "inet", "murmur_e2e_tproxy", "prerouting",
            "iifname", "br-lan", "ip", "daddr", "198.18.1.0/24", "meta", "l4proto", "tcp",
            "meta", "mark", "set", "0x1", "tproxy", "ip", "to", f":{SUPPLIED_TPROXY_PORT}", "accept",
        ],
        timeout=10,
    )
    chk.add("supplied_fakeip_tproxy_rule", add.returncode == 0, f"exit={add.returncode} err={add.stderr.decode()[-400:]}")


def ensure_loopback_addresses(ctx: Context, chk: Check) -> None:
    existing = run([tool("ip"), "-o", "addr", "show", "dev", "lo"], timeout=10).stdout.decode()
    for addr in (SUPPLIED_TARGET_ADDR, "198.51.100.9", "198.51.101.9"):
        if addr in existing:
            chk.add(f"supplied_loopback_{addr}", True, "already assigned to lo")
            continue
        result = run([tool("ip"), "addr", "add", f"{addr}/32", "dev", "lo"], timeout=10)
        chk.add(
            f"supplied_loopback_{addr}",
            result.returncode == 0,
            f"exit={result.returncode} err={result.stderr.decode().strip()[-200:]}",
        )


def lan_curl(domain: str, port: int, ip: str, path: str = "/", timeout: int = 25) -> dict:
    cmd = [
        tool("ip"), "netns", "exec", "lan", tool("curl"), "--noproxy", "*", "-sS",
        "--max-time", str(timeout), "--resolve", f"{domain}:{port}:{ip}",
        "-o", "-", "-w", "\n%{http_code}", f"http://{domain}:{port}{path}",
    ]
    result = run(cmd, timeout=timeout + 15)
    body, _, code = result.stdout.decode().rpartition("\n")
    return {
        "exit": result.returncode,
        "code": code.strip(),
        "body": body.encode(),
        "error": result.stderr.decode().strip(),
    }


def supplied_body_detail(result: dict) -> str:
    return json.dumps({**result, "body": result["body"].decode(errors="replace")})


def scen_supplied_router(ctx: Context, chk: Check) -> str:
    ensure_lan_topology(ctx, chk)
    ensure_loopback_addresses(ctx, chk)

    target = ctx.start(
        "supplied-target",
        [
            tool("python3"), ctx.share / "e2e" / "fixtures" / "http_target.py",
            "--listen", "0.0.0.0", "--port", str(SUPPLIED_TARGET_PORT), "--body", SUPPLIED_TARGET_BODY.decode(),
        ],
    )
    ctx.wait_port(SUPPLIED_TARGET_ADDR, SUPPLIED_TARGET_PORT, name="supplied router target")
    provider_http = ctx.start(
        "supplied-provider-http",
        [
            tool("python3"), ctx.share / "e2e" / "fixtures" / "http_target.py",
            "--port", str(SUPPLIED_PROVIDER_PORT), "--body", supplied_subscription().decode(),
        ],
    )
    ctx.wait_port("127.0.0.1", SUPPLIED_PROVIDER_PORT, name="supplied provider HTTP")
    reference = supplied_provider_reference(ctx)
    upstream = dns_upstream(ctx)

    home = ctx.home("supplied-router")
    mixed, api_port = free_port(), free_port()
    cfg = supplied_router_config(mixed, api_port, home, SUPPLIED_PROVIDER_PORT)
    proc, mixed, api_port = ctx.murmur("supplied-router", cfg, files={"providers/.keep": ""})
    try:
        listeners = ""

        def tproxy_up() -> bool:
            nonlocal listeners
            listeners = run([tool("ss"), "-lntu"], timeout=10).stdout.decode()
            return re.search(rf"(\*|0\.0\.0\.0):{SUPPLIED_TPROXY_PORT}\b", listeners) is not None

        chk.add(
            "supplied_tproxy_listener",
            bool(wait_for(tproxy_up, 20)),
            "; ".join(line for line in listeners.splitlines() if str(SUPPLIED_TPROXY_PORT) in line) or "no listener",
        )

        rule_set = wait_for(lambda: ctx.api(api_port, "/providers/rules")["providers"], 20) or {}
        expected_rules = {"vpn", "telegram", "telegram_ip", "warp", "warp_ip"}
        chk.add("supplied_rule_providers_loaded", expected_rules <= set(rule_set), json.dumps(sorted(rule_set)))

        wait_for(
            lambda: ctx.dig(SUPPLIED_DNS_PORT, "plain.example", "A") == [SUPPLIED_TARGET_ADDR],
            20,
        )

        def wait_fake(name: str) -> tuple[str, list[str]]:
            deadline = time.monotonic() + 20
            answers: list[str] = []
            while time.monotonic() < deadline:
                answers = ctx.dig(SUPPLIED_DNS_PORT, name, "A")
                if len(answers) == 1 and answers[0].startswith("198.18.1."):
                    return answers[0], answers
                time.sleep(0.3)
            return "", answers

        fake_vpn, vpn_answers = wait_fake("host.vpn.example")
        fake_telegram, telegram_answers = wait_fake("host.telegram.example")
        fake_warp, warp_answers = wait_fake("host.warp.example")
        chk.add(
            "supplied_fakeip_allocations",
            bool(fake_vpn and fake_telegram and fake_warp) and len({fake_vpn, fake_telegram, fake_warp}) == 3,
            f"vpn={vpn_answers} telegram={telegram_answers} warp={warp_answers}",
        )

        proxies: dict = {}

        def settled():
            nonlocal proxies
            proxies = ctx.api(api_port, "/proxies")["proxies"]
            if (
                proxies.get("WARP", {}).get("now") == "WARP-AWG1"
                and proxies.get("VPN", {}).get("now") == "VPN-ALL-AUTO"
                and proxies.get("VPN-ALL-AUTO", {}).get("now") == SUPPLIED_PROVIDER_NODE
            ):
                return proxies
            return None

        wait_for(settled, 45)
        if not proxies:
            proxies = ctx.api(api_port, "/proxies")["proxies"]
        topology = {
            name: {key: proxies.get(name, {}).get(key) for key in ("type", "all", "now", "alive", "emptyFallback")}
            for name in ("WARP", "VPN", "VPN-ALL-AUTO", "WARP-AWG0", "WARP-AWG1", "WARP-AWG2")
        }
        chk.add(
            "supplied_group_topology",
            proxies.get("WARP", {}).get("type") == "Fallback"
            and proxies.get("WARP", {}).get("all") == ["WARP-AWG0", "WARP-AWG1", "DIRECT"]
            and proxies.get("VPN", {}).get("type") == "Fallback"
            and proxies.get("VPN", {}).get("all") == ["VPN-ALL-AUTO", "WARP-AWG2"]
            and proxies.get("VPN-ALL-AUTO", {}).get("type") == "URLTest"
            and proxies.get("VPN-ALL-AUTO", {}).get("emptyFallback") == "REJECT",
            json.dumps(topology),
        )
        chk.add(
            "supplied_warp_failover_promotes_healthy",
            proxies.get("WARP", {}).get("now") == "WARP-AWG1"
            and proxies.get("WARP-AWG0", {}).get("alive") is False
            and proxies.get("WARP-AWG1", {}).get("alive") is True,
            json.dumps(topology),
        )
        chk.add(
            "supplied_provider_wins_vpn",
            proxies.get("VPN", {}).get("now") == "VPN-ALL-AUTO"
            and proxies.get("VPN-ALL-AUTO", {}).get("now") == SUPPLIED_PROVIDER_NODE
            and proxies.get("VPN-ALL-AUTO", {}).get("alive") is True,
            json.dumps(topology),
        )

        provider_state = ctx.api(api_port, "/providers/proxies")["providers"].get("stable", {})
        provider_names = [proxy.get("name") for proxy in provider_state.get("proxies", [])]
        chk.add(
            "supplied_provider_http_fetch",
            provider_state.get("vehicleType") == "HTTP"
            and SUPPLIED_PROVIDER_NODE in provider_names
            and str(provider_state.get("updatedAt", "")).startswith("2"),
            json.dumps(
                {
                    "vehicleType": provider_state.get("vehicleType"),
                    "names": provider_names,
                    "updatedAt": provider_state.get("updatedAt"),
                }
            ),
        )

        vpn_lan = lan_curl("host.vpn.example", SUPPLIED_TARGET_PORT, fake_vpn)
        chk.add("supplied_lan_vpn_route", supplied_reached(vpn_lan), supplied_body_detail(vpn_lan))
        telegram_lan = lan_curl("host.telegram.example", SUPPLIED_TARGET_PORT, fake_telegram)
        chk.add("supplied_lan_telegram_route", supplied_reached(telegram_lan), supplied_body_detail(telegram_lan))
        warp_lan = lan_curl("host.warp.example", SUPPLIED_TARGET_PORT, fake_warp)
        chk.add("supplied_lan_warp_route", supplied_reached(warp_lan), supplied_body_detail(warp_lan))

        rc, code, body, err = ctx.curl(mixed, f"http://direct.example:{SUPPLIED_TARGET_PORT}/", proxy="http")
        chk.add(
            "supplied_mixed_direct",
            rc == 0 and code == "200" and body == SUPPLIED_TARGET_BODY,
            f"exit={rc} code={code} body={body!r} err={err.strip()}",
        )
        rc, code, body, err = ctx.curl(mixed, f"http://198.51.100.9:{SUPPLIED_TARGET_PORT}/", proxy="http")
        chk.add(
            "supplied_telegram_ip_ruleset",
            rc == 0 and code == "200" and body == SUPPLIED_TARGET_BODY,
            f"exit={rc} code={code} body={body!r} err={err.strip()}",
        )
        rc, code, body, err = ctx.curl(mixed, f"http://198.51.101.9:{SUPPLIED_TARGET_PORT}/", proxy="http")
        chk.add(
            "supplied_warp_ip_ruleset",
            rc == 0 and code == "200" and body == SUPPLIED_TARGET_BODY,
            f"exit={rc} code={code} body={body!r} err={err.strip()}",
        )

        bypass = lan_curl("bypass.example", SUPPLIED_TARGET_PORT, SUPPLIED_TARGET_ADDR)
        log = proc.log.read_text(errors="replace") if proc.log.exists() else ""
        chk.add("supplied_lan_direct_bypass", supplied_reached(bypass) and "bypass.example" not in log, supplied_body_detail(bypass))

        with ThreadPoolExecutor(max_workers=8) as pool:
            load = list(pool.map(lambda _: lan_curl("host.vpn.example", SUPPLIED_TARGET_PORT, fake_vpn), range(24)))
        good = [item for item in load if supplied_reached(item)]
        chk.add(
            "supplied_load_24_vpn_workers8",
            len(good) == 24,
            f"{len(good)}/24 reached the exact body; failures="
            + json.dumps([supplied_body_detail(item) for item in load if not supplied_reached(item)][:3]),
        )

        log = proc.log.read_text(errors="replace") if proc.log.exists() else ""
        evidence = {
            "vpn_ruleset_provider_group": f"match RuleSet(vpn) using VPN[{SUPPLIED_PROVIDER_NODE}]",
            "telegram_ruleset_warp_group": "match RuleSet(telegram) using WARP[WARP-AWG1]",
            "warp_ruleset_warp_group": "match RuleSet(warp) using WARP[WARP-AWG1]",
            "telegram_ip_ruleset": "match RuleSet(telegram_ip) using WARP[WARP-AWG1]",
            "warp_ip_ruleset": "match RuleSet(warp_ip) using WARP[WARP-AWG1]",
            "match_direct": f"--> direct.example:{SUPPLIED_TARGET_PORT} match Match using DIRECT",
        }
        for name, needle in evidence.items():
            chk.add(f"supplied_log_{name}", needle in log, log_line(log, needle) or "no matching log line")

        panics = [line for line in log.splitlines() if "panic" in line.lower()]
        chk.add("supplied_murmur_alive_after_load", proc.alive() and not panics, f"alive={proc.alive()} panics={panics[:2]}")
    finally:
        proc.stop()
        upstream.stop()
        reference.stop()
        provider_http.stop()
        target.stop()
    return (
        "supplied router config: the HTTP provider node won VPN and WARP promoted past a dead adapter, "
        "fake-IP LAN traffic and the direct bypass reached the target, and 24/24 concurrent VPN requests at "
        "workers=8 returned the exact body"
    )


def mixed_load_client() -> int:
    """Run only in the disposable guest's LAN namespace, never on the host."""
    workers = 18
    gate = threading.Barrier(workers + 1)
    schedule: list[float] = []
    phase_gate = threading.Barrier(workers, action=lambda: schedule.append(time.monotonic() + 65))

    def worker(index: int) -> dict:
        kind = "tcp" if index < 8 else "udp" if index < 16 else "dns"
        result = {"worker": index, "kind": kind, "phases": []}
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if kind == "udp" else None
        if udp is not None:
            udp.settimeout(2)
            udp.bind(("0.0.0.0", 0))
            result["localPort"] = udp.getsockname()[1]
        try:
            gate.wait(timeout=15)
            for phase_index in range(2):
                time.sleep(max(0, schedule[phase_index] - time.monotonic()))
                deadline = schedule[phase_index] + 30
                phase = {"phase": phase_index + 1, "attempts": 0, "successes": 0, "failures": 0, "errors": []}
                phase["startedSeconds"] = round(time.monotonic() - schedule[0], 3)
                while time.monotonic() < deadline:
                    iteration = phase["attempts"]
                    phase["attempts"] += 1
                    try:
                        if kind == "tcp":
                            conn = http.client.HTTPConnection("149.154.160.10", 18080, timeout=2)
                            try:
                                conn.request("GET", "/")
                                response = conn.getresponse()
                                body = response.read(1024)
                                if response.status != 200 or body != b"transparent target reached\n":
                                    raise RuntimeError(f"HTTP status={response.status} body={body!r}")
                            finally:
                                conn.close()
                        elif kind == "udp":
                            length = (1, 127, 1200)[iteration % 3]
                            payload = bytes((index + iteration + phase_index + n) % 251 for n in range(length))
                            udp.sendto(payload, ("149.154.160.10", 53535))
                            received, sender = udp.recvfrom(2048)
                            if received != payload or sender != ("149.154.160.10", 53535):
                                raise RuntimeError(f"UDP exact={received == payload} sender={sender}")
                        else:
                            case = iteration % 5
                            name = f"load-{index}-{iteration % 16}.vpn.example"
                            rtype = "AAAA" if case == 3 else "A"
                            if case == 1:
                                name = "plain.example"
                            elif case == 2:
                                name = "something.lan"
                            cmd = [tool("dig"), "+short", "+tries=1", "+time=2", "@192.0.2.1", "-p", "12344"]
                            if case == 4:
                                cmd.append("+tcp")
                            answer = run(cmd + [name, rtype], timeout=3)
                            records = answer.stdout.decode().split()
                            valid = records == [] if case == 3 else records == ["203.0.113.9"] if case in (1, 2) else (
                                len(records) == 1 and records[0].startswith("198.18.1."))
                            if answer.returncode != 0 or not valid:
                                raise RuntimeError(f"DNS {name}/{rtype} exit={answer.returncode} answer={records}")
                        phase["successes"] += 1
                    except Exception as error:  # noqa: BLE001 - retain bounded per-worker failure evidence
                        phase["failures"] += 1
                        if len(phase["errors"]) < 3:
                            phase["errors"].append(f"{type(error).__name__}: {error}")
                    time.sleep(min(0.25, max(0, deadline - time.monotonic())))
                result["phases"].append(phase)
                phase["finishedSeconds"] = round(time.monotonic() - schedule[0], 3)
                if phase_index == 0:
                    phase_gate.wait(timeout=15)
        finally:
            if udp is not None:
                udp.close()
        return result

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker, index) for index in range(workers)]
        schedule.append(time.monotonic() + 0.2)
        gate.wait(timeout=15)
        results = [future.result() for future in futures]
    payload = {"tcpWorkers": 8, "persistentUdpWorkers": 8, "dnsWorkers": 2,
               "burstSeconds": 30, "idleSeconds": 65, "bursts": 2, "paceSeconds": 0.25,
               "udpPayloadBytes": [1, 127, 1200], "workers": results}
    print(json.dumps(payload), flush=True)
    return 0 if all(phase["successes"] > 0 and phase["failures"] == 0
                    for worker_result in results for phase in worker_result["phases"]) else 1


def scen_router_mixed_load(ctx: Context, chk: Check) -> str:
    ensure_lan_topology(ctx, chk)
    target = ctx.start("mixed-target", [tool("ip"), "netns", "exec", "target", tool("python3"),
                                        ctx.share / "e2e" / "fixtures" / "tproxy_target.py"])
    ctx.wait_port("149.154.160.10", 18080, name="mixed target")
    upstream = dns_upstream(ctx)
    mixed, api_port = free_port(), free_port()
    cfg = dns_config(mixed, api_port, ctx.home("router-mixed"))
    cfg.update(tproxy_config(mixed, api_port))
    proc, _, _ = ctx.murmur("router-mixed", cfg)
    client = None
    try:
        chk.add("mixed_dns_ready", bool(wait_for(lambda: ctx.dig(12344, "plain.example", "A") == ["203.0.113.9"], 20)))
        client = ctx.start("mixed-load-client", [tool("ip"), "netns", "exec", "lan", tool("python3"),
                                                Path(__file__).resolve(), "--mixed-load-client"])
        started = time.monotonic()
        snapshots = []
        next_snapshot = 0
        while client.alive() and time.monotonic() - started < 150:
            elapsed = time.monotonic() - started
            if next_snapshot < 3 and elapsed >= (30, 95, 125)[next_snapshot]:
                snapshots.append({"seconds": round(elapsed, 3), "memory": ctx.memory.snapshot(scenario=True)})
                next_snapshot += 1
            if not proc.alive():
                break
            time.sleep(0.2)
        rc = client.proc.poll()
        chk.add("mixed_client_completed", rc == 0, f"exit={rc}; log={client.log.name}")
        if rc is None:
            client.stop()
        try:
            workload = json.loads(client.log.read_text())
        except (OSError, ValueError) as error:
            workload = {"error": str(error)}
        ctx.scenario_workload = {"traffic": workload, "phaseMemory": snapshots}
        worker_results = workload.get("workers", [])
        chk.add("mixed_exact_payloads_all_workers", len(worker_results) == 18 and all(
            len(worker["phases"]) == 2 and all(phase["successes"] > 0 and phase["failures"] == 0 for phase in worker["phases"])
            for worker in worker_results), json.dumps(workload))
        log = proc.log.read_text(errors="replace")
        chk.add("mixed_murmur_alive", proc.alive() and "panic" not in log.lower(), f"exit={proc.proc.poll()}")
    finally:
        if client is not None:
            client.stop()
        proc.stop()
        upstream.stop()
        target.stop()
    return "8 TCP + 8 persistent UDP + 2 DNS workers: 30s burst / 65s idle / 30s burst; exact responses and sender checked"


SCENARIOS = [
    ("config_parse", scen_config_parse),
    ("direct_http_socks", scen_direct),
    ("trojan_x25519", scen_trojan_x25519),
    ("trojan_p256_hrr", scen_trojan_p256),
    ("vless_plain", scen_vless_plain),
    ("vless_vision", scen_vless_vision),
    ("vision_bulk_no_fingerprint", scen_vision_no_fingerprint),
    ("vision_bulk_chrome", scen_vision_chrome),
    ("vision_bulk_firefox", scen_vision_firefox),
    ("vmess_legacy_alterid4", scen_vmess_legacy),
    ("vmess_aead_alterid0", scen_vmess_aead),
    ("tproxy_wildcard_tcp_udp", scen_tproxy),
    ("dns_fakeip_filters", scen_dns_fakeip),
    ("dns_restart_persistence", scen_dns_restart),
    ("group_fallback_and_empty_reject", scen_groups),
    ("supplied_router_routing_load", scen_supplied_router),
    ("router_mixed_burst_idle_burst", scen_router_mixed_load),
    ("real_node_sweep", scen_real_node_sweep),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-bin", required=True)
    parser.add_argument("--ref-bin", required=True)
    parser.add_argument("--share", default="/mnt/test")
    parser.add_argument("--out", required=True)
    parser.add_argument("--home", default=None, help="private config home staged by the host, if any")
    parser.add_argument("--group", default=None)
    parser.add_argument("--repeats", type=int, default=3)
    return parser.parse_args()


def write_results(ctx: Context, exit_code: int, error: str = "") -> None:
    summary: dict[str, int] = {}
    for result in ctx.results:
        summary[result["status"]] = summary.get(result["status"], 0) + 1
    payload = {
        "rustBin": {"path": BIN.get("murmur"), "sha256": ctx.rust_sha},
        "refBin": {"path": BIN.get("reference"), "sha256": ctx.ref_sha},
        "scenarios": ctx.results,
        "memory": ctx.memory.snapshot(),
        "kernelMemory": {"startup": ctx.kernel_start, "latest": ctx.kernel_latest},
        "summary": summary,
        "error": error,
        "exitCode": exit_code,
    }
    path = ctx.out / "results.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def main() -> int:
    args = parse_args()
    global BIN
    BIN["murmur"] = args.rust_bin
    BIN["reference"] = args.ref_bin
    for name, path in (("murmur", args.rust_bin), ("reference", args.ref_bin)):
        if not os.access(path, os.X_OK):
            print(f"error: {name} {path} is not executable", file=sys.stderr)
            return 2

    rust_sha = sha256_file(Path(args.rust_bin))
    ref_sha = sha256_file(Path(args.ref_bin))
    ctx = Context(args)
    ctx.rust_sha, ctx.ref_sha = rust_sha, ref_sha

    def shutdown(signum, _frame):
        ctx.stop_all()
        ctx.memory.close()
        write_results(ctx, 128 + signum, f"interrupted by signal {signum}")
        sys.exit(128 + signum)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    failures = 0
    try:
        for name, scenario in SCENARIOS:
            checks = Check()
            status = "pass"
            detail = ""
            started = time.monotonic()
            ctx.memory.begin(name)
            ctx.scenario_workload = None
            kernel_before = kernel_memory_evidence(ctx, f"{name}-before")
            try:
                detail = scenario(ctx, checks) or ""
                if checks.skipped:
                    status = "skip"
                else:
                    status = "pass" if checks.passed() else "fail"
                    if status == "fail":
                        failed = [item["name"] for item in checks.items if not item["ok"]]
                        detail = f"{len(failed)} checks failed: {', '.join(failed)}"
            except Exception as error:  # noqa: BLE001 - one scenario must not abort the rest
                status = "error"
                detail = f"{type(error).__name__}: {error}"
                (ctx.out / "logs" / f"{name}.traceback").write_text(traceback.format_exc())
            ctx.stop_all()
            ctx.memory.sample()
            memory = ctx.memory.snapshot(scenario=True)
            kernel_after = kernel_memory_evidence(ctx, f"{name}-after")
            ctx.kernel_latest = kernel_after
            for process in memory["processes"]:
                if process["isMurmur"]:
                    checks.add(f"{process['name']}_survived_until_stop", process["runningBeforeStop"] is True,
                               f"pid={process['pid']} exit={process['exitCodeBeforeStop']}")
                    checks.add(f"{process['name']}_memory_sampled", process["samples"] > 0, json.dumps(process))
            before_count, after_count = kernel_before["oomKillCount"], kernel_after["oomKillCount"]
            checks.add("guest_oom_counter_available", before_count is not None and after_count is not None,
                       json.dumps(kernel_after["errors"]))
            checks.add("guest_no_oom_kills", before_count is not None and after_count == before_count,
                       f"before={before_count} after={after_count}")
            checks.add("guest_memory_sampled", memory["guest"]["samples"] > 0, json.dumps(memory["guest"]))
            if status != "error" and not checks.passed():
                status = "fail"
                failed = [item["name"] for item in checks.items if not item["ok"]]
                detail = f"{len(failed)} checks failed: {', '.join(failed)}"
            result = {
                "name": name,
                "status": status,
                "detail": detail,
                "seconds": round(time.monotonic() - started, 3),
                "checks": checks.items,
                "memory": memory,
                "kernelMemory": {"before": kernel_before, "after": kernel_after},
                "workload": ctx.scenario_workload,
            }
            ctx.results.append(result)
            if status in ("fail", "error"):
                failures += 1
            write_results(ctx, 1 if failures else 0)
            print(f"[{status}] {name}: {detail}", flush=True)
            ctx.stop_all()
    except Exception as error:  # noqa: BLE001 - report and preserve evidence
        ctx.stop_all()
        write_results(ctx, 1, f"{type(error).__name__}: {error}")
        print(f"fatal: {error}", file=sys.stderr)
        return 1
    finally:
        ctx.stop_all()
        ctx.memory.close()

    exit_code = 1 if failures else 0
    write_results(ctx, exit_code)
    return exit_code


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    sys.exit(mixed_load_client() if sys.argv[1:] == ["--mixed-load-client"] else main())
