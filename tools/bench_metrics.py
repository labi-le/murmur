#!/usr/bin/env python3
"""Benchmark metric orchestrator for the transport-vless metrics targets.

Remote mode (default) re-invokes this file with --local on the build host via
tools/cargo-slot, so a single build slot covers build plus every measurement.
Local mode must already run inside the build host's Nix shell; it never falls
back to compiling anywhere else.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = Path(__file__).resolve()
CARGO_SLOT = REPO_ROOT / "tools" / "cargo-slot"

PACKAGE = "murmur-transport-vless"
CPU_TARGET = "metrics_cpu"
HEAP_TARGET = "metrics_heap"
TARGETS = (CPU_TARGET, HEAP_TARGET)

DEFAULT_TARGET_DIR = "bench-metrics"
DEFAULT_CPU_ITERATIONS = 100_000
DEFAULT_HEAP_ITERATIONS = 1_000
DEFAULT_WARMUP = 100
DEFAULT_SMOKE_ITERATIONS = 2
DEFAULT_SMOKE_WARMUP = 2
DEFAULT_JOBS = 2
DEFAULT_TIMEOUT = 1_800.0
DEFAULT_BUILD_TIMEOUT = 3_600.0
DEFAULT_REMOTE_TIMEOUT = 21_600.0

MANDATORY_EVENTS = ("task-clock", "cycles", "instructions")
OPTIONAL_EVENTS = (
    "branches",
    "branch-misses",
    "cache-references",
    "cache-misses",
    "context-switches",
    "cpu-migrations",
    "page-faults",
)
PERF_EVENTS = MANDATORY_EVENTS + OPTIONAL_EVENTS

PERF_SCOPE = (
    "whole process including startup, fixture setup and warmup; ratios to operation "
    "counts are amortized process totals, never per-operation CPU usage"
)
HEAP_PEAK_FALLBACK_SCOPE = "profiler lifetime including setup and warmup"


def which(name: str) -> str | None:
    return shutil.which(name)


def base_env() -> dict[str, str]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    return env


def _run(cmd: list, env: dict[str, str], cwd: Path, stdout, stderr, timeout: float | None) -> dict:
    argv = [str(part) for part in cmd]
    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            timeout=timeout,
        )
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        returncode = None
        timed_out = True
    return {
        "argv": argv,
        "commandLine": shlex.join(argv),
        "returncode": returncode,
        "timedOut": timed_out,
        "elapsedSeconds": round(time.monotonic() - started, 3),
    }


def _capture(cmd: list, env: dict[str, str], cwd: Path, out_path: Path, err_path: Path, timeout: float | None) -> dict:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as out_f, err_path.open("wb") as err_f:
        return _run(cmd, env=env, cwd=cwd, stdout=out_f, stderr=err_f, timeout=timeout)


def read_single_json(path: Path) -> tuple[dict | None, str | None]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"cannot read {path.name}: {exc}"
    for line in reversed([ln for ln in text.splitlines() if ln.strip()]):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj, None
    return None, "no JSON object found"


def rel(path: Path, workdir: Path) -> str:
    try:
        return path.relative_to(workdir).as_posix()
    except ValueError:
        return str(path)


def default_workdir_root() -> Path:
    override = os.environ.get("BENCH_METRICS_WORKDIR_ROOT")
    if override:
        return Path(override)
    shared = Path("/drive/tmp")
    if shared.is_dir():
        return shared
    return REPO_ROOT


def prepare_workdir(raw: str | None) -> Path:
    if raw is None:
        root = default_workdir_root()
        try:
            return Path(tempfile.mkdtemp(prefix="bench-metrics-", dir=str(root)))
        except OSError as exc:
            raise SystemExit(f"bench_metrics: cannot create workdir under {root}: {exc}") from exc
    path = Path(raw)
    if path.exists():
        if not path.is_dir():
            raise SystemExit(f"bench_metrics: --workdir is not a directory: {path}")
        if any(path.iterdir()):
            raise SystemExit(f"bench_metrics: --workdir is not empty: {path}")
        return path
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path, 0o700)
    except OSError as exc:
        raise SystemExit(f"bench_metrics: cannot create --workdir {path}: {exc}") from exc
    return path


def tool_version(exe: str, args: list[str]) -> str | None:
    found = which(exe)
    if found is None:
        return None
    try:
        proc = subprocess.run(
            [found, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
            env=base_env(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    line = (proc.stdout or "").strip().splitlines()
    return line[0] if line else None


def machine_metadata() -> dict:
    cpu_model = None
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu": {"model": cpu_model, "count": os.cpu_count()},
        "tools": {
            "rustc": tool_version("rustc", ["--version"]),
            "cargo": tool_version("cargo", ["--version"]),
            "perf": tool_version("perf", ["--version"]),
        },
    }


def parse_perf_json(path: Path) -> dict:
    counters: dict[str, dict] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return counters
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = obj.get("event")
        if not isinstance(event, str):
            continue
        name = event.split(":", 1)[0]
        raw = obj.get("counter-value")
        entry = {
            "event": event,
            "value": None,
            "unit": obj.get("unit"),
            "eventRuntimeNs": obj.get("event-runtime"),
            "pcntRunning": obj.get("pcnt-running"),
            "supported": False,
            "reason": None,
        }
        if isinstance(raw, bool):
            entry["reason"] = f"unexpected counter value {raw!r}"
        else:
            try:
                entry["value"] = float(raw)
                entry["supported"] = True
            except (TypeError, ValueError):
                entry["reason"] = str(raw)
        counters[name] = entry
    for name in OPTIONAL_EVENTS:
        counters.setdefault(
            name,
            {
                "event": name,
                "value": None,
                "unit": None,
                "eventRuntimeNs": None,
                "pcntRunning": None,
                "supported": False,
                "reason": "event not reported by perf",
            },
        )
    return counters


def validate_record(record: dict, target: str, case: str, iterations: int) -> list[str]:
    problems: list[str] = []
    if record.get("schemaVersion") != 1:
        problems.append(f"schemaVersion={record.get('schemaVersion')!r}")
    if record.get("target") != target:
        problems.append(f"target={record.get('target')!r}")
    if record.get("case") != case:
        problems.append(f"case={record.get('case')!r}")
    if record.get("iterations") != iterations:
        problems.append(f"iterations={record.get('iterations')!r}")
    if not isinstance(record.get("checksum"), int):
        problems.append(f"checksum={record.get('checksum')!r}")
    if not isinstance(record.get("bytesPerOperation"), (int, float)):
        problems.append(f"bytesPerOperation={record.get('bytesPerOperation')!r}")
    if not isinstance(record.get("operationScope"), str):
        problems.append(f"operationScope={record.get('operationScope')!r}")
    if target == CPU_TARGET:
        if not isinstance(record.get("elapsedNs"), int):
            problems.append(f"elapsedNs={record.get('elapsedNs')!r}")
        for key in ("rssBeforeKiB", "rssAfterKiB", "hwmKiB"):
            if not isinstance(record.get(key), int):
                problems.append(f"{key}={record.get(key)!r}")
    else:
        for key in (
            "allocationCount",
            "allocatedBytes",
            "liveBlocksBefore",
            "liveBlocksAfter",
            "liveBytesBefore",
            "liveBytesAfter",
            "peakHeapBytesLifetime",
            "peakHeapBlocksLifetime",
        ):
            if not isinstance(record.get(key), int):
                problems.append(f"{key}={record.get(key)!r}")
    return problems


def list_cases(binary: Path, target: str, env: dict[str, str], workdir: Path, errors: list[str]) -> list[str] | None:
    out_path = workdir / f"list.{target}.json"
    err_path = workdir / f"list.{target}.err.log"
    res = _capture([binary, "--list"], env, REPO_ROOT, out_path, err_path, 300.0)
    if res["timedOut"]:
        errors.append(f"{target} --list timed out")
        return None
    record, problem = read_single_json(out_path)
    if record is None:
        errors.append(f"{target} --list produced no JSON: {problem}")
        return None
    if record.get("schemaVersion") != 1:
        errors.append(f"{target} --list schemaVersion={record.get('schemaVersion')!r}")
    if record.get("target") != target:
        errors.append(f"{target} --list target={record.get('target')!r}")
    cases = record.get("cases")
    if not isinstance(cases, list) or not cases or not all(isinstance(c, str) for c in cases):
        errors.append(f"{target} --list has no case list")
        return None
    return cases


def build_environment(args: argparse.Namespace) -> dict[str, str]:
    env = base_env()
    env.setdefault("CARGO_TARGET_DIR", args.target_dir)
    if args.hotspots:
        env["CARGO_PROFILE_BENCH_DEBUG"] = "1"
        env["RUSTFLAGS"] = f"{env.get('RUSTFLAGS', '')} -Clink-arg=-Wl,--no-rosegment".strip()
    return env


def build_targets(args: argparse.Namespace, workdir: Path, errors: list[str], warnings: list[str]) -> dict[str, Path]:
    cargo = which("cargo")
    if cargo is None:
        errors.append("cargo not on PATH; local mode must run inside the build host Nix shell")
        return {}
    env = build_environment(args)
    cmd = [
        cargo,
        "bench",
        "-j",
        str(args.jobs),
        "-p",
        PACKAGE,
        "--bench",
        HEAP_TARGET,
        "--bench",
        CPU_TARGET,
        "--no-run",
        "--message-format=json",
    ]
    out_path = workdir / "build.jsonl"
    err_path = workdir / "build.log"
    result = _capture(cmd, env, REPO_ROOT, out_path, err_path, args.build_timeout)
    if result["timedOut"]:
        errors.append(f"cargo bench build timed out after {args.build_timeout}s")
        return {}
    found: dict[str, Path] = {}
    try:
        lines = out_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        errors.append(f"cannot read build output: {exc}")
        return {}
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("reason") != "compiler-artifact":
            continue
        target = obj.get("target") or {}
        name = target.get("name")
        executable = obj.get("executable")
        if name in TARGETS and executable:
            found[name] = Path(executable)
    if result["returncode"] != 0:
        errors.append(f"cargo bench build exited with {result['returncode']}")
    for name in TARGETS:
        if name not in found:
            errors.append(f"build produced no executable for target {name}")
    resolved: dict[str, Path] = {}
    for name in TARGETS:
        binary = found.get(name)
        if binary is None:
            continue
        if not binary.exists():
            errors.append(f"built executable missing: {binary}")
            continue
        resolved[name] = binary
    return resolved


def resolve_binaries(args: argparse.Namespace, workdir: Path, errors: list[str], warnings: list[str]) -> dict[str, Path]:
    provided = {"cpu": args.cpu_bin, "heap": args.heap_bin}
    if args.skip_build or (args.cpu_bin and args.heap_bin):
        if not (args.cpu_bin and args.heap_bin):
            errors.append("--skip-build requires both --cpu-bin and --heap-bin")
            return {}
        if not args.cpu_bin.exists() or not args.heap_bin.exists():
            errors.append("provided --cpu-bin/--heap-bin do not exist")
            return {}
        resolved = {CPU_TARGET: args.cpu_bin, HEAP_TARGET: args.heap_bin}
        if args.hotspots:
            warnings.append(
                "hotspot run uses prebuilt binaries; CARGO_PROFILE_BENCH_DEBUG/RUSTFLAGS were not applied "
                "and perf symbol rows may be missing"
            )
        return resolved
    if provided["cpu"] or provided["heap"]:
        errors.append("provide both --cpu-bin and --heap-bin, or neither")
        return {}
    return build_targets(args, workdir, errors, warnings)


def cpu_entry(
    args: argparse.Namespace,
    workdir: Path,
    cpu_bin: Path,
    case: str,
    iterations: int,
    warmup: int,
    phase: str,
    env: dict[str, str],
    errors: list[str],
) -> dict:
    cdir = workdir / "cases" / case
    perf_path = cdir / f"{phase}.cpu.perf.json"
    out_path = cdir / f"{phase}.cpu.json"
    err_path = cdir / f"{phase}.cpu.err.log"
    entry = {
        "target": CPU_TARGET,
        "case": case,
        "phase": phase,
        "iterations": iterations,
        "warmup": warmup,
        "record": None,
        "counters": None,
        "countersScope": PERF_SCOPE,
        "perfInvocation": None,
        "files": {
            "perf": rel(perf_path, workdir),
            "stdout": rel(out_path, workdir),
            "stderr": rel(err_path, workdir),
        },
        "error": None,
    }
    cmd = [
        "perf",
        "stat",
        "--json-output",
        "-o",
        str(perf_path),
        "-e",
        ",".join(PERF_EVENTS),
        "--",
        str(cpu_bin),
        "--case",
        case,
        "--iterations",
        str(iterations),
        "--warmup",
        str(warmup),
    ]
    result = _capture(cmd, env, REPO_ROOT, out_path, err_path, args.timeout)
    entry["perfInvocation"] = result
    if result["timedOut"]:
        entry["error"] = f"perf stat timed out after {args.timeout}s"
        errors.append(f"{case} [{phase}]: perf stat timed out")
        return entry
    record, problem = read_single_json(out_path)
    if record is None:
        entry["error"] = f"cpu target produced no JSON record: {problem}"
        errors.append(f"{case} [{phase}]: {entry['error']}")
        return entry
    entry["record"] = record
    entry["counters"] = parse_perf_json(perf_path)
    if result["returncode"] != 0:
        entry["perfReturnCode"] = result["returncode"]
    problems = validate_record(record, CPU_TARGET, case, iterations)
    missing = [ev for ev in MANDATORY_EVENTS if not entry["counters"].get(ev, {}).get("supported")]
    if missing:
        problems.append("mandatory perf counters unavailable: " + ", ".join(missing))
    if problems:
        entry["error"] = "; ".join(problems)
        errors.append(f"{case} [{phase}] cpu: {entry['error']}")
    return entry


def heap_entry(
    args: argparse.Namespace,
    workdir: Path,
    heap_bin: Path,
    case: str,
    iterations: int,
    warmup: int,
    phase: str,
    env: dict[str, str],
    errors: list[str],
    dhat_json: Path | None = None,
    directory: Path | None = None,
) -> dict:
    cdir = directory if directory is not None else workdir / "cases" / case
    out_path = cdir / f"{phase}.heap.json"
    err_path = cdir / f"{phase}.heap.err.log"
    entry = {
        "target": HEAP_TARGET,
        "case": case,
        "phase": phase,
        "iterations": iterations,
        "warmup": warmup,
        "record": None,
        "dhatJson": rel(dhat_json, workdir) if dhat_json else None,
        "files": {"stdout": rel(out_path, workdir), "stderr": rel(err_path, workdir)},
        "error": None,
    }
    cmd = [str(heap_bin), "--case", case, "--iterations", str(iterations), "--warmup", str(warmup)]
    if dhat_json is not None:
        cmd += ["--dhat-json", str(dhat_json)]
    result = _capture(cmd, env, REPO_ROOT, out_path, err_path, args.timeout)
    entry["invocation"] = result
    if result["timedOut"]:
        entry["error"] = f"heap target timed out after {args.timeout}s"
        errors.append(f"{case} [{phase}] heap: timed out")
        return entry
    record, problem = read_single_json(out_path)
    if record is None:
        entry["error"] = f"heap target produced no JSON record: {problem}"
        errors.append(f"{case} [{phase}] heap: {entry['error']}")
        return entry
    entry["record"] = record
    entry["heapPeakScope"] = record.get("heapPeakScope", HEAP_PEAK_FALLBACK_SCOPE)
    problems = validate_record(record, HEAP_TARGET, case, iterations)
    if problems:
        entry["error"] = "; ".join(problems)
        errors.append(f"{case} [{phase}] heap: {entry['error']}")
    return entry


SAMPLE_RE = re.compile(r"^#\s*Samples:\s*([0-9]+(?:\.[0-9]+)?)\s*([KMG]?)", re.MULTILINE)
SYMBOL_ROW_RE = re.compile(r"^\s*[0-9]+(?:\.[0-9]+)?%\s+\S", re.MULTILINE)


def parse_sample_count(text: str) -> int | None:
    match = SAMPLE_RE.search(text)
    if match is None:
        return None
    scale = {"": 1, "K": 1_000, "M": 1_000_000, "G": 1_000_000_000}[match.group(2)]
    return int(float(match.group(1)) * scale)


def run_hotspots(
    args: argparse.Namespace,
    workdir: Path,
    cpu_bin: Path,
    heap_bin: Path,
    cases: list[str],
    env: dict[str, str],
    errors: list[str],
) -> dict:
    hotspots: dict[str, dict] = {}
    for case in cases:
        cdir = workdir / "hotspots" / case
        cdir.mkdir(parents=True, exist_ok=True)
        perf_data = cdir / "perf.data"
        record_out = cdir / "record.out.log"
        record_err = cdir / "record.err.log"
        report_path = cdir / "report.txt"
        report_err = cdir / "report.err.log"
        dhat_json = cdir / "heap.dhat.json"
        entry = {
            "case": case,
            "iterations": args.iterations,
            "warmup": args.warmup,
            "sampleCount": None,
            "symbolRows": None,
            "files": {
                "perfData": rel(perf_data, workdir),
                "report": rel(report_path, workdir),
                "dhatJson": rel(dhat_json, workdir),
            },
            "recordInvocation": None,
            "reportInvocation": None,
            "dhatInvocation": None,
            "error": None,
        }
        record_cmd = [
            "perf",
            "record",
            "-g",
            "--call-graph",
            "dwarf",
            "-o",
            str(perf_data),
            "--",
            str(cpu_bin),
            "--case",
            case,
            "--iterations",
            str(args.iterations),
            "--warmup",
            str(args.warmup),
        ]
        entry["recordInvocation"] = _capture(record_cmd, env, REPO_ROOT, record_out, record_err, args.timeout)
        report_cmd = ["perf", "report", "--stdio", "--no-children", "-i", str(perf_data)]
        entry["reportInvocation"] = _capture(report_cmd, env, REPO_ROOT, report_path, report_err, args.timeout)
        dhat = heap_entry(
            args,
            workdir,
            heap_bin,
            case,
            args.heap_iterations,
            args.warmup,
            "hotspot",
            env,
            errors,
            dhat_json=dhat_json,
            directory=cdir,
        )
        entry["dhatInvocation"] = dhat.get("invocation")
        entry["dhatError"] = dhat.get("error")
        if not perf_data.exists() or perf_data.stat().st_size == 0:
            entry["error"] = "perf.data missing or empty"
        try:
            report_text = report_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            entry["error"] = entry["error"] or f"cannot read perf report: {exc}"
            report_text = ""
        samples = parse_sample_count(report_text)
        rows = len(SYMBOL_ROW_RE.findall(report_text))
        entry["sampleCount"] = samples
        entry["symbolRows"] = rows
        if samples is None or samples <= 0:
            entry["error"] = entry["error"] or "perf report recorded no samples"
        if rows <= 0:
            entry["error"] = entry["error"] or "perf report has no symbol rows"
        if dhat.get("error"):
            entry["error"] = entry["error"] or f"heap stack trace run failed: {dhat['error']}"
        elif not dhat_json.exists() or dhat_json.stat().st_size == 0:
            entry["error"] = entry["error"] or "dhat stack trace file missing or empty"
        else:
            entry["dhatBytes"] = dhat_json.stat().st_size
            try:
                json.loads(dhat_json.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                entry["error"] = entry["error"] or "dhat stack trace is not valid JSON"
        if entry["error"]:
            errors.append(f"{case} [hotspot]: {entry['error']}")
        hotspots[case] = entry
    return hotspots


def summarize(phases: dict, cases: list[str]) -> dict:
    per_case: dict[str, dict] = {}
    for case in cases:
        entry = phases.get(case, {}).get("measured", {})
        cpu = (entry.get("cpu") or {}).get("record") or {}
        heap = (entry.get("heap") or {}).get("record") or {}
        per_case[case] = {
            "nsPerOperation": cpu.get("nsPerOperation"),
            "bytesPerOperation": cpu.get("bytesPerOperation"),
            "checksum": cpu.get("checksum"),
            "allocatedBytesPerOperation": heap.get("allocatedBytesPerOperation"),
            "allocationsPerOperation": heap.get("allocationsPerOperation"),
            "liveBytesAfter": heap.get("liveBytesAfter"),
            "peakHeapBytesLifetime": heap.get("peakHeapBytesLifetime"),
        }
    return {"caseCount": len(cases), "cases": per_case}


def run_local(args: argparse.Namespace) -> int:
    started = time.time()
    errors: list[str] = []
    warnings: list[str] = []
    workdir = prepare_workdir(args.workdir)
    env = base_env()
    results: dict = {
        "schemaVersion": 1,
        "runner": {
            "mode": "local",
            "script": str(SCRIPT_PATH),
            "argv": sys.argv,
            "workdir": str(workdir),
            "startedAt": started,
        },
        "machine": machine_metadata(),
        "config": {
            "cases": args.case,
            "hotspots": args.hotspots,
            "iterations": args.iterations,
            "heapIterations": args.heap_iterations,
            "warmup": args.warmup,
            "smoke": args.smoke,
            "smokeIterations": args.smoke_iterations,
            "smokeWarmup": args.smoke_warmup,
            "jobs": args.jobs,
            "targetDir": os.environ.get("CARGO_TARGET_DIR") or args.target_dir,
            "skipBuild": args.skip_build,
            "cpuBin": str(args.cpu_bin) if args.cpu_bin else None,
            "heapBin": str(args.heap_bin) if args.heap_bin else None,
            "timeout": args.timeout,
            "buildTimeout": args.build_timeout,
        },
        "build": None,
        "roster": None,
        "cases": {},
        "hotspots": {},
        "errors": errors,
        "warnings": warnings,
        "status": "error",
        "summary": None,
    }

    def finish(status: str) -> int:
        results["status"] = status
        results["runner"]["finishedAt"] = time.time()
        results["errors"] = errors
        results["warnings"] = warnings
        (workdir / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": status, "workdir": str(workdir), "errors": errors}, indent=2))
        return 0 if status == "ok" else 1

    if which("perf") is None:
        errors.append("perf not on PATH; measurements require perf stat/record")
        return finish("error")

    binaries = resolve_binaries(args, workdir, errors, warnings)
    if errors or len(binaries) != 2:
        return finish("error")
    cpu_bin = binaries[CPU_TARGET]
    heap_bin = binaries[HEAP_TARGET]
    built_here = not (args.skip_build or (args.cpu_bin and args.heap_bin))
    effective_build_env = build_environment(args) if built_here else {}
    results["build"] = {
        "cpuBin": str(cpu_bin),
        "heapBin": str(heap_bin),
        "buildEnvironmentKnown": built_here,
        "cargoProfileBenchDebug": effective_build_env.get("CARGO_PROFILE_BENCH_DEBUG"),
        "rustflags": effective_build_env.get("RUSTFLAGS"),
    }

    cpu_cases = list_cases(cpu_bin, CPU_TARGET, env, workdir, errors)
    heap_cases = list_cases(heap_bin, HEAP_TARGET, env, workdir, errors)
    if cpu_cases is None or heap_cases is None:
        return finish("error")
    roster_match = sorted(cpu_cases) == sorted(heap_cases)
    results["roster"] = {"cpu": cpu_cases, "heap": heap_cases, "match": roster_match}
    if not roster_match:
        only_cpu = sorted(set(cpu_cases) - set(heap_cases))
        only_heap = sorted(set(heap_cases) - set(cpu_cases))
        errors.append(f"case roster mismatch: cpu-only={only_cpu} heap-only={only_heap}")
        return finish("error")

    selected = args.case or list(cpu_cases)
    unknown = [case for case in selected if case not in cpu_cases]
    if unknown:
        errors.append(f"unknown case(s): {', '.join(unknown)}")
        return finish("error")

    phases = [
        ("smoke", args.smoke_iterations, args.smoke_warmup, args.smoke_iterations),
    ]
    if not args.smoke:
        phases.append(("measured", args.iterations, args.warmup, args.heap_iterations))

    for case in selected:
        results["cases"][case] = {}
    for phase, iterations, warmup, heap_iterations in phases:
        for case in selected:
            print(f"[{phase}] {case}: cpu n={iterations} w={warmup}", file=sys.stderr, flush=True)
            cpu = cpu_entry(args, workdir, cpu_bin, case, iterations, warmup, phase, env, errors)
            print(f"[{phase}] {case}: heap n={heap_iterations} w={warmup}", file=sys.stderr, flush=True)
            heap = heap_entry(args, workdir, heap_bin, case, heap_iterations, warmup, phase, env, errors)
            results["cases"][case][phase] = {"cpu": cpu, "heap": heap}

    if args.hotspots:
        hotspot_cases = [case for case in args.hotspots]
        unknown_hot = [case for case in hotspot_cases if case not in cpu_cases]
        if unknown_hot:
            errors.append(f"unknown hotspot case(s): {', '.join(unknown_hot)}")
        else:
            results["hotspots"] = run_hotspots(
                args, workdir, cpu_bin, heap_bin, hotspot_cases, env, errors
            )

    results["summary"] = summarize(results["cases"], selected)
    return finish("ok" if not errors else "error")


def inner_argv(args: argparse.Namespace, workdir: Path) -> list[str]:
    argv = ["--local", "--workdir", str(workdir), "--jobs", str(args.jobs), "--target-dir", args.target_dir]
    argv += ["--iterations", str(args.iterations), "--heap-iterations", str(args.heap_iterations)]
    argv += ["--warmup", str(args.warmup)]
    argv += ["--smoke-iterations", str(args.smoke_iterations), "--smoke-warmup", str(args.smoke_warmup)]
    argv += ["--timeout", str(args.timeout), "--build-timeout", str(args.build_timeout)]
    for case in args.case:
        argv += ["--case", case]
    for case in args.hotspots:
        argv += ["--hotspots", case]
    if args.smoke:
        argv.append("--smoke")
    if args.skip_build:
        argv.append("--skip-build")
    if args.cpu_bin:
        argv += ["--cpu-bin", str(args.cpu_bin)]
    if args.heap_bin:
        argv += ["--heap-bin", str(args.heap_bin)]
    return argv


def fetch_remote_tree(workdir: Path, errors: list[str]) -> bool:
    ssh = which("ssh")
    tar = which("tar")
    if ssh is None or tar is None:
        errors.append("ssh and tar are required to retrieve remote artifacts")
        print("bench_metrics: ssh/tar missing; cannot retrieve remote artifacts", file=sys.stderr)
        return False
    host = os.environ.get("BENCH_METRICS_REMOTE_HOST", "pc")
    remote = [ssh, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, "tar", "-C", str(workdir), "-cf", "-", "."]
    print(f"fetching remote artifacts from {host}:{workdir}", file=sys.stderr)
    ssh_log = workdir / "fetch.ssh.log"
    tar_log = workdir / "fetch.tar.log"
    tar_rc = None
    ssh_rc = None
    with ssh_log.open("ab") as ssh_err, tar_log.open("ab") as tar_err:
        ssh_proc = subprocess.Popen(remote, stdout=subprocess.PIPE, stderr=ssh_err, stdin=subprocess.DEVNULL)
        tar_proc = subprocess.Popen(
            [tar, "-C", str(workdir), "-xf", "-"],
            stdin=ssh_proc.stdout,
            stdout=subprocess.DEVNULL,
            stderr=tar_err,
        )
        if ssh_proc.stdout is not None:
            ssh_proc.stdout.close()
        try:
            tar_rc = tar_proc.wait(timeout=900)
            ssh_rc = ssh_proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            tar_proc.kill()
            ssh_proc.kill()
            errors.append("remote artifact fetch timed out")
            print("bench_metrics: remote artifact fetch timed out", file=sys.stderr)
            return False
    if tar_rc != 0 or ssh_rc != 0:
        errors.append(f"remote artifact fetch failed (ssh={ssh_rc} tar={tar_rc})")
        print(f"bench_metrics: remote artifact fetch failed (ssh={ssh_rc} tar={tar_rc})", file=sys.stderr)
        return False
    return True


def run_remote(args: argparse.Namespace) -> int:
    workdir = prepare_workdir(args.workdir)
    env = base_env()
    env.setdefault("CARGO_TARGET_DIR", args.target_dir)
    command = [str(CARGO_SLOT), "python3", str(SCRIPT_PATH), *inner_argv(args, workdir)]
    log_path = workdir.parent / f"{workdir.name}.remote.log"
    timeout = args.remote_timeout if args.remote_timeout > 0 else None
    with log_path.open("wb") as log_f:
        result = _run(command, env=env, cwd=REPO_ROOT, stdout=log_f, stderr=subprocess.STDOUT, timeout=timeout)
    print(f"outer command: {result['commandLine']}")
    print(f"remote log: {log_path}")
    outer_record = {
        "argv": result["argv"],
        "commandLine": result["commandLine"],
        "returncode": result["returncode"],
        "timedOut": result["timedOut"],
        "elapsedSeconds": result["elapsedSeconds"],
        "cargoTargetDir": env.get("CARGO_TARGET_DIR"),
        "remoteLog": str(log_path),
    }
    try:
        (workdir / "outer-command.json").write_text(json.dumps(outer_record, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass
    results_path = workdir / "results.json"
    if not results_path.exists():
        # The build host may not share this path; retrieve whatever it produced,
        # including a failed run's logs and partial profiles.
        fetch_remote_tree(workdir, [])
    if not results_path.exists():
        tail = ""
        try:
            tail = "\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-40:])
        except OSError:
            pass
        print(f"bench_metrics: no results.json produced (outer rc={result['returncode']})", file=sys.stderr)
        if tail:
            print(tail, file=sys.stderr)
        return 1
    try:
        results = json.loads(results_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"bench_metrics: cannot parse results.json: {exc}", file=sys.stderr)
        return 1
    summary = results.get("summary") or {}
    print(json.dumps({"status": results.get("status"), "workdir": str(workdir), "errors": results.get("errors", [])}, indent=2))
    for case, values in (summary.get("cases") or {}).items():
        print(
            f"  {case}: ns/op={values.get('nsPerOperation')} bytes/op={values.get('bytesPerOperation')} "
            f"allocB/op={values.get('allocatedBytesPerOperation')}"
        )
    return 0 if results.get("status") == "ok" else 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bench_metrics.py",
        description="Run transport-vless allocation and CPU metric benchmarks on the build host.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Remote mode holds one tools/cargo-slot slot for the whole run and drives this file\n"
            "again with --local on the build host. Artifacts are read from --workdir directly when\n"
            "the path is shared; otherwise the remote tree is fetched over ssh+tar, failed runs\n"
            "included. perf stat counters cover the whole process: startup, setup and warmup are\n"
            "inside the count, so counter/operation ratios are amortized, not per-operation usage."
        ),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--remote", dest="mode", action="store_const", const="remote", help="run on the build host via tools/cargo-slot (default)")
    mode.add_argument("--local", dest="mode", action="store_const", const="local", help="run here, already inside the build host Nix shell")
    parser.set_defaults(mode="remote")
    parser.add_argument("--case", action="append", default=[], help="case to measure (repeatable; default: target roster)")
    parser.add_argument("--hotspots", action="append", default=[], help="case for perf record/report and dhat stacks (repeatable)")
    parser.add_argument("--iterations", type=int, default=DEFAULT_CPU_ITERATIONS, help=f"measured CPU iterations (default {DEFAULT_CPU_ITERATIONS})")
    parser.add_argument("--heap-iterations", type=int, default=DEFAULT_HEAP_ITERATIONS, help=f"measured heap iterations (default {DEFAULT_HEAP_ITERATIONS})")
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP, help=f"measured warmup iterations (default {DEFAULT_WARMUP})")
    parser.add_argument("--smoke", action="store_true", help="run only the small smoke pass over every case")
    parser.add_argument("--smoke-iterations", type=int, default=DEFAULT_SMOKE_ITERATIONS, help=f"smoke iterations (default {DEFAULT_SMOKE_ITERATIONS})")
    parser.add_argument("--smoke-warmup", type=int, default=DEFAULT_SMOKE_WARMUP, help=f"smoke warmup (default {DEFAULT_SMOKE_WARMUP})")
    parser.add_argument("--skip-build", action="store_true", help="do not build; requires --cpu-bin and --heap-bin")
    parser.add_argument("--cpu-bin", type=Path, default=None, help="prebuilt metrics_cpu executable")
    parser.add_argument("--heap-bin", type=Path, default=None, help="prebuilt metrics_heap executable")
    parser.add_argument("--jobs", type=int, default=DEFAULT_JOBS, help=f"cargo build jobs (default {DEFAULT_JOBS})")
    parser.add_argument("--target-dir", default=DEFAULT_TARGET_DIR, help=f"CARGO_TARGET_DIR seed name when unset (default {DEFAULT_TARGET_DIR})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"per-invocation timeout in seconds (default {DEFAULT_TIMEOUT:g})")
    parser.add_argument("--build-timeout", type=float, default=DEFAULT_BUILD_TIMEOUT, help=f"build timeout in seconds (default {DEFAULT_BUILD_TIMEOUT:g})")
    parser.add_argument("--remote-timeout", type=float, default=DEFAULT_REMOTE_TIMEOUT, help=f"remote run timeout in seconds, 0 disables (default {DEFAULT_REMOTE_TIMEOUT:g})")
    parser.add_argument("--workdir", default=None, help="output directory, fresh or empty; fetched from the build host when the path is not shared")
    parser.add_argument("--bench", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.iterations <= 0:
        parser.error("--iterations must be positive")
    if args.heap_iterations <= 0:
        parser.error("--heap-iterations must be positive")
    if args.warmup < 0:
        parser.error("--warmup must be non-negative")
    if args.smoke_iterations <= 0 or args.smoke_warmup < 0:
        parser.error("smoke iterations must be positive and smoke warmup non-negative")
    if args.jobs <= 0:
        parser.error("--jobs must be positive")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.mode == "local":
        return run_local(args)
    return run_remote(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
