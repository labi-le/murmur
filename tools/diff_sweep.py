#!/usr/bin/env python3
"""Differential sweep: run a reference proxy binary and this build side by side
against the same subscription and the same real proxy nodes, and report where their
observable behaviour disagrees.

For each node in a proxy-selector group this starts both binaries against copies of
the same config (on distinct, auto-picked ports), switches the group to that node on
both sides through the clash-compatible controller API (``PUT /proxies/<group>``),
fires the same HTTPS request through each binary's proxy port, and compares the HTTP
status codes. A node is only a *divergence* when the two sides disagree; a node that
fails on both sides is a dead node, not a defect -- public proxy nodes flicker, so
every node is probed ``--repeats`` times (default 3) before either side is judged
"ok" or "dead".

Usage
-----
    python3 rust/tools/diff_sweep.py \\
        --ref-bin /path/to/reference/binary \\
        --rust-bin /path/to/target/debug/murmur \\
        --home /path/to/a/directory/containing/config.yaml \\
        --workdir /somewhere/with/space

``--home`` is a directory holding a real ``config.yaml`` (plus whatever relative
``providers/`` files or provider cache it references) -- point it at your own
subscription's working directory. It is only ever read; a private, per-side copy is
made under ``--workdir`` and mutated there (ports rewritten so both sides, and any
already-running instance, never collide). Nothing under ``--home`` is modified and
nothing about it is written anywhere by this script.

The script prints a per-node table (`both-ok` / `both-dead` / `differ`) followed by a
summary line and, for every `differ` node, its protocol type and the two sides'
per-attempt status codes. When a side never once produced ``--expect-status`` for a
divergent node, the most recent WARN/ERROR line that side's own log printed for that
attempt window is quoted alongside it -- this is usually the exact reason a side
refused the node (a missing protocol implementation, a missing crate, an unsupported
cipher), not just "it failed".

Exit code is 1 when at least one real divergence is found, 0 when every disagreement
is explained by both-dead nodes (or there are none), 2 for a setup/usage error (bad
paths, no reachable controller, nothing to probe). This makes the exit code usable as
a CI/pre-merge gate: `differ == 0` is the passing state.

Example (placeholders -- point these at your own binaries/subscription, never commit
real values):

    python3 rust/tools/diff_sweep.py \\
        --ref-bin /path/to/reference-binary \\
        --rust-bin /path/to/target/debug/murmur \\
        --home /path/to/my-subscription-workdir \\
        --repeats 3 --workdir /var/tmp/murmur-diffsweep

Requires only the Python 3 standard library and a ``curl`` on PATH; no pip packages,
no new Cargo dependency. Nothing here talks to the network unless you pass ``--home``
pointing at a config that does.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

DEFAULT_TEST_URL = "https://cp.cloudflare.com/generate_204"
DEFAULT_EXPECT_STATUS = 204
DEFAULT_REPEATS = 3
DEFAULT_TIMEOUT = 6.0
DEFAULT_READY_TIMEOUT = 20.0
RESET_PORT_KEYS = ("port", "socks-port", "redir-port", "tproxy-port")


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def extract_secret(config_text: str) -> str:
    m = re.search(r"(?m)^secret:\s*['\"]?([^'\"\n]*)", config_text)
    return m.group(1).strip() if m else ""


def detect_group(config_text: str) -> str | None:
    idx = config_text.find("proxy-groups:")
    if idx == -1:
        return None
    m = re.search(r"-\s*name:\s*['\"]?([^'\"\n]+?)['\"]?\s*$", config_text[idx:], re.MULTILINE)
    return m.group(1).strip() if m else None


def prepare_home(src_home: Path, dst_home: Path, mixed_port: int, api_port: int) -> Path:
    shutil.copytree(src_home, dst_home)
    cfg_path = dst_home / "config.yaml"
    text = cfg_path.read_text()

    text, n = re.subn(r"(?m)^mixed-port:\s*\d+\s*$", f"mixed-port: {mixed_port}", text)
    if n == 0:
        text += f"\nmixed-port: {mixed_port}\n"

    text, n = re.subn(
        r"(?m)^external-controller:\s*.*$", f"external-controller: 127.0.0.1:{api_port}", text
    )
    if n == 0:
        text += f"\nexternal-controller: 127.0.0.1:{api_port}\n"

    for key in RESET_PORT_KEYS:
        text = re.sub(rf"(?m)^{re.escape(key)}:\s*\d+\s*$", "", text)

    cfg_path.write_text(text)
    return cfg_path


def tail_file(path: Path, max_bytes: int = 4000) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return "(no log)"
    return data[-max_bytes:].decode("utf-8", errors="replace")


def current_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def read_new_lines(path: Path, offset: int) -> list[str]:
    try:
        with path.open("rb") as f:
            f.seek(offset)
            data = f.read()
    except OSError:
        return []
    return data.decode("utf-8", errors="replace").splitlines()


NOISE_REASON_RE = re.compile(
    r"context canceled|deadline exceeded|i/o timeout|operation timed out|connection reset", re.IGNORECASE
)


def extract_reason(lines: list[str]) -> str | None:
    """Pick the most informative WARN/ERROR line in a probe's log window.

    A single probe often logs several lines (the proxy retries a failing dial internally): an
    early one canceling the *previous* node's in-flight attempt, then the real, specific
    failure for the node under test. Prefer the most recent line that isn't generic
    cancellation/timeout noise; only fall back to noise if nothing else matched.
    """
    fallback: str | None = None
    for line in reversed(lines):
        low = line.lower()
        if "warn" not in low and "error" not in low:
            continue
        m = re.search(r"error:\s*(.*)$", line)
        text = m.group(1).strip() if m else line.strip()
        text = text[:300]
        if NOISE_REASON_RE.search(text):
            if fallback is None:
                fallback = text
            continue
        return text
    return fallback


class ProcSet:
    def __init__(self) -> None:
        self.procs: list[tuple[str, subprocess.Popen]] = []

    def add(self, label: str, proc: subprocess.Popen) -> None:
        self.procs.append((label, proc))

    def cleanup(self) -> None:
        for _, proc in self.procs:
            if proc.poll() is None:
                proc.terminate()
        deadline = time.time() + 5
        for label, proc in self.procs:
            remaining = max(0.0, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass


def start_binary(binary: Path, home_dir: Path, config_path: Path, log_path: Path) -> subprocess.Popen:
    log_f = open(log_path, "wb")
    return subprocess.Popen(
        [str(binary), "-d", str(home_dir), "-f", str(config_path)],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        cwd=str(home_dir),
        stdin=subprocess.DEVNULL,
    )


def api_get(api_port: int, secret: str, path: str, timeout: float = 10.0):
    req = urlrequest.Request(f"http://127.0.0.1:{api_port}{path}")
    if secret:
        req.add_header("Authorization", f"Bearer {secret}")
    with urlrequest.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def api_put(api_port: int, secret: str, path: str, body: dict, timeout: float = 10.0):
    data = json.dumps(body).encode()
    req = urlrequest.Request(f"http://127.0.0.1:{api_port}{path}", data=data, method="PUT")
    req.add_header("Content-Type", "application/json")
    if secret:
        req.add_header("Authorization", f"Bearer {secret}")
    with urlrequest.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def wait_ready(proc: subprocess.Popen, log_path: Path, api_port: int, secret: str, timeout: float) -> None:
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"process exited early (code {proc.returncode}) before the controller API came up\n"
                f"last log output:\n{tail_file(log_path)}"
            )
        try:
            api_get(api_port, secret, "/version", timeout=2)
            return
        except Exception as exc:  # noqa: BLE001 - retry loop, any transient error is fine
            last_err = exc
            time.sleep(0.25)
    raise RuntimeError(
        f"controller API on 127.0.0.1:{api_port} did not come up within {timeout}s ({last_err})\n"
        f"last log output:\n{tail_file(log_path)}"
    )


def node_types(api_port: int, secret: str) -> dict[str, str]:
    types: dict[str, str] = {}
    try:
        data = api_get(api_port, secret, "/providers/proxies")
        for prov in data.get("providers", {}).values():
            for p in prov.get("proxies", []):
                name = p.get("name")
                if name:
                    types[name] = p.get("type", "?")
    except Exception:
        pass
    try:
        data = api_get(api_port, secret, "/proxies")
        for name, p in data.get("proxies", {}).items():
            types.setdefault(name, p.get("type", "?"))
    except Exception:
        pass
    return types


def curl_probe(proxy_port: int, test_url: str, timeout: float) -> str:
    try:
        out = subprocess.run(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "-x",
                f"http://127.0.0.1:{proxy_port}",
                "--connect-timeout",
                str(timeout),
                "--max-time",
                str(timeout),
                test_url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired:
        return "000"
    code = out.stdout.strip()
    if not code.isdigit():
        return "000"
    return code.zfill(3)


def probe_node(
    side: SimpleNamespace,
    group: str,
    node: str,
    repeats: int,
    test_url: str,
    timeout: float,
    expect_status: int,
) -> tuple[str, bool, str | None]:
    switch_path = f"/proxies/{urlparse.quote(group, safe='')}"
    expect = f"{expect_status:03d}"
    codes: list[str] = []
    reason: str | None = None
    for _ in range(repeats):
        try:
            api_put(side.api_port, side.secret, switch_path, {"name": node})
        except Exception:
            codes.append("000")
            continue
        time.sleep(0.15)
        pre_offset = current_size(side.log_path)
        code = curl_probe(side.mixed_port, test_url, timeout)
        codes.append(code)
        if code != expect and reason is None:
            time.sleep(0.3)  # let a block-buffered child log flush its most recent write
            reason = extract_reason(read_new_lines(side.log_path, pre_offset))
    ok = any(c == expect for c in codes)
    return "".join(codes), ok, reason


def print_report(results: list[dict], repeats: int) -> None:
    both_ok = [r for r in results if r["class"] == "both-ok"]
    both_dead = [r for r in results if r["class"] == "both-dead"]
    differ = [r for r in results if r["class"] == "differ"]

    name_w = max((len(r["node"]) for r in results), default=4)
    name_w = min(name_w, 56)
    code_w = repeats * 3

    header = f"{'NODE':<{name_w}}  {'TYPE':<10}  {'REF':<{code_w}}  {'RUST':<{code_w}}  RESULT"
    print(header)
    for r in results:
        print(
            f"{r['node']:<{name_w}.{name_w}}  {r['type']:<10}  "
            f"{r['ref_codes']:<{code_w}}  {r['rust_codes']:<{code_w}}  {r['class']}"
        )

    print()
    print(
        f"summary: {len(both_ok)} both-ok, {len(both_dead)} both-dead, "
        f"{len(differ)} differ (of {len(results)} nodes, {repeats} attempts/side)"
    )

    if differ:
        print()
        print("divergences:")
        for r in differ:
            dead_side = "rust" if not r["rust_ok"] else "ref"
            reason = r.get(f"{dead_side}_reason")
            reason_txt = f"\n      {dead_side} log: {reason}" if reason else ""
            print(f"  {r['node']} [{r['type']}]: ref={r['ref_codes']} rust={r['rust_codes']}{reason_txt}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="diff_sweep.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--ref-bin", required=True, type=Path, help="path to the reference proxy binary")
    p.add_argument("--rust-bin", required=True, type=Path, help="path to the murmur binary under test")
    p.add_argument(
        "--home",
        required=True,
        type=Path,
        help="directory containing your own config.yaml (and any relative providers/ it needs); "
        "read-only, copied privately per side",
    )
    p.add_argument(
        "--group",
        default=None,
        help="proxy-selector group to switch through PUT /proxies/<group> (default: first "
        "proxy-groups entry found in config.yaml)",
    )
    p.add_argument(
        "--nodes",
        default=None,
        help="comma-separated subset of node names to probe (default: every node in --group)",
    )
    p.add_argument("--repeats", type=int, default=DEFAULT_REPEATS, help=f"probes per node per side (default: {DEFAULT_REPEATS})")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"seconds per probe request (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--test-url", default=DEFAULT_TEST_URL, help=f"HTTPS URL fetched through each proxy port (default: {DEFAULT_TEST_URL})")
    p.add_argument("--expect-status", type=int, default=DEFAULT_EXPECT_STATUS, help=f"HTTP status that counts as success (default: {DEFAULT_EXPECT_STATUS})")
    p.add_argument("--ready-timeout", type=float, default=DEFAULT_READY_TIMEOUT, help="seconds to wait for each controller API to come up")
    p.add_argument("--workdir", type=Path, default=None, help="base directory for the two private home-dir copies (default: a fresh mkdtemp)")
    p.add_argument("--keep-workdir", action="store_true", help="do not delete --workdir on exit (for post-mortem log inspection)")
    p.add_argument("-v", "--verbose", action="store_true", help="print per-node progress to stderr while running")
    return p


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)

    for label, p in (("--ref-bin", args.ref_bin), ("--rust-bin", args.rust_bin)):
        if not p.is_file() or not os.access(p, os.X_OK):
            print(f"error: {label} {p} is not an executable file", file=sys.stderr)
            return 2

    cfg_src = args.home / "config.yaml"
    if not cfg_src.is_file():
        print(f"error: --home {args.home} does not contain a config.yaml", file=sys.stderr)
        return 2

    config_text = cfg_src.read_text()
    secret = extract_secret(config_text)
    group = args.group or detect_group(config_text)
    if not group:
        print("error: could not find a proxy-groups entry in config.yaml; pass --group explicitly", file=sys.stderr)
        return 2

    owns_workdir = args.workdir is None
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="murmur-diffsweep-"))
    workdir.mkdir(parents=True, exist_ok=True)

    procs = ProcSet()

    def handle_signal(signum, _frame):
        procs.cleanup()
        sys.exit(128 + signum)

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, handle_signal)
    atexit.register(procs.cleanup)

    try:
        sides: dict[str, SimpleNamespace] = {}
        for label, binary in (("ref", args.ref_bin), ("rust", args.rust_bin)):
            side_home = workdir / label
            mixed_port = free_port()
            api_port = free_port()
            cfg_path = prepare_home(args.home, side_home, mixed_port, api_port)
            log_path = side_home / f"{label}.log"
            try:
                proc = start_binary(binary, side_home, cfg_path, log_path)
            except OSError as exc:
                print(f"error: failed to start {label} binary {binary}: {exc}", file=sys.stderr)
                return 2
            procs.add(label, proc)
            try:
                wait_ready(proc, log_path, api_port, secret, args.ready_timeout)
            except RuntimeError as exc:
                print(f"error: {label} side never became reachable: {exc}", file=sys.stderr)
                return 2
            sides[label] = SimpleNamespace(
                proc=proc, mixed_port=mixed_port, api_port=api_port, secret=secret, log_path=log_path
            )

        try:
            members = api_get(sides["rust"].api_port, secret, f"/proxies/{urlparse.quote(group, safe='')}").get("all", [])
        except Exception:
            try:
                members = api_get(sides["ref"].api_port, secret, f"/proxies/{urlparse.quote(group, safe='')}").get("all", [])
            except Exception as exc:
                print(f"error: group {group!r} not found on either side's controller API: {exc}", file=sys.stderr)
                return 2

        if args.nodes:
            wanted = {n.strip() for n in args.nodes.split(",") if n.strip()}
            missing = wanted - set(members)
            if missing:
                print(f"warning: requested nodes not in group {group!r}: {', '.join(sorted(missing))}", file=sys.stderr)
            members = [m for m in members if m in wanted]

        if not members:
            print(f"error: no nodes to probe in group {group!r}", file=sys.stderr)
            return 2

        types: dict[str, str] = {}
        for label in ("ref", "rust"):
            for name, t in node_types(sides[label].api_port, secret).items():
                types.setdefault(name, t)

        results = []
        for i, node in enumerate(members, 1):
            row: dict = {"node": node, "type": types.get(node, "?")}
            for label in ("ref", "rust"):
                codes, ok, reason = probe_node(
                    sides[label], group, node, args.repeats, args.test_url, args.timeout, args.expect_status
                )
                row[f"{label}_codes"] = codes
                row[f"{label}_ok"] = ok
                row[f"{label}_reason"] = reason
            if row["ref_ok"] and row["rust_ok"]:
                row["class"] = "both-ok"
            elif not row["ref_ok"] and not row["rust_ok"]:
                row["class"] = "both-dead"
            else:
                row["class"] = "differ"
            results.append(row)
            if args.verbose:
                print(
                    f"[{i}/{len(members)}] {node} ({row['type']}): "
                    f"ref={row['ref_codes']} rust={row['rust_codes']} -> {row['class']}",
                    file=sys.stderr,
                )

        print_report(results, args.repeats)
        return 1 if any(r["class"] == "differ" for r in results) else 0
    finally:
        procs.cleanup()
        if owns_workdir and not args.keep_workdir:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
