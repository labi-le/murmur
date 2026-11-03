#!/usr/bin/env python3
"""Offline, real-process proxy workloads with retained measurement evidence."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import struct
import subprocess
import sys
import tempfile
import time
import traceback
sys.dont_write_bytecode = True

from bench_workloads.common import process_start_ticks, summarize_latencies, terminate_process_group

CASES = ("tls", "healthcheck", "relay", "dns", "reload")


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be positive and finite")
    return number


def save_json(path: Path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def binary_metadata(path: Path, timeout: float):
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError(f"binary is not an executable file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        header = handle.read(64)
        digest.update(header)
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    if len(header) < 20 or header[:4] != b"\x7fELF" or header[5] not in (1, 2):
        raise ValueError(f"expected a native Linux ELF binary, not a wrapper or cross-platform artifact: {path}")
    machine = struct.unpack(("<" if header[5] == 1 else ">") + "H", header[18:20])[0]
    architectures = {3: "i386", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv64"}
    architecture = architectures.get(machine, f"elf-machine-{machine}")
    host = platform.machine().lower()
    host = {"amd64": "x86_64", "arm64": "aarch64"}.get(host, host)
    if host.startswith("armv"):
        host = "arm"
    if architecture != host:
        raise ValueError(f"binary architecture {architecture} does not match executing host {host}: {path}")
    version = subprocess.run([str(path), "-v"], capture_output=True, text=True, timeout=timeout, check=True)
    output = (version.stdout + version.stderr).strip()
    if not output:
        raise ValueError(f"binary -v returned no version/build metadata: {path}")
    tag_lines = [line.partition(":")[2].strip() for line in output.splitlines()
                 if line.strip().lower().startswith("use tags:")]
    tags = [tag.strip() for line in tag_lines for tag in line.split(",") if tag.strip()]
    return {"path": str(path), "sha256": digest.hexdigest(), "architecture": architecture,
            "elfMachine": machine, "elfBits": {1: 32, 2: 64}.get(header[4]),
            "version": output, "versionCommand": [str(path), "-v"],
            "features": [line.strip() for line in output.splitlines()
                         if "feature" in line.lower() or line.strip().lower().startswith("use tags:")],
            "tags": tags, "lowMemory": "with_low_memory" in tags if tag_lines else None,
            "featureSource": "verbatim -v feature/Use tags lines; absent tags mean unknown, not disabled"}


def machine_metadata():
    cpu = platform.processor()
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            key, _, value = line.partition(":")
            if key.strip() in ("model name", "Hardware"):
                cpu = value.strip()
                break
    return {"platform": platform.platform(), "architecture": platform.machine(), "cpu": cpu,
            "logicalCPUs": os.cpu_count(), "python": platform.python_version(),
            "kernel": platform.release()}


def validate_rows(rows, instrumented):
    if not isinstance(rows, list) or not rows:
        raise ValueError("scenario must return nonempty result rows; missing cases are not skips")
    required = {"name", "parameters", "operationScope", "operations", "bytes", "elapsedSeconds",
                "resources", "validation", "instrumented"}
    for row in rows:
        if not isinstance(row, dict) or required - row.keys():
            raise ValueError(f"scenario result missing required fields: {row!r}")
        if not isinstance(row["name"], str) or not row["name"] or not row["operationScope"]:
            raise ValueError("scenario must describe its name and measured operation boundary")
        if row["instrumented"] is not instrumented:
            raise ValueError("scenario instrumented flag differs from actual execution mode")
        for key in ("operations", "bytes"):
            if type(row[key]) is not int or row[key] < (1 if key == "operations" else 0):
                raise ValueError(f"invalid {key}: {row[key]!r}")
        if not math.isfinite(row["elapsedSeconds"]) or row["elapsedSeconds"] < 0:
            raise ValueError("elapsedSeconds must be finite and nonnegative")
        if not isinstance(row["validation"], dict) or not row["validation"]:
            raise ValueError("scenario must retain observed correctness evidence")
        if row.get("status", "ok") not in ("ok", "passed", "degraded"):
            raise ValueError(f"unsupported row status: {row.get('status')!r}")
        for key in ("elapsedSeconds", "cpuSeconds", "rssBeforeKiB", "rssAfterKiB", "hwmKiB"):
            value = row["resources"].get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise ValueError(f"invalid process resource {key}: {value!r}")
        if "latency" in row:
            latency = row["latency"]
            samples = latency.get("samplesSeconds")
            if not samples or latency.get("count") != len(samples):
                raise ValueError("latency summaries must retain all raw samplesSeconds")
            expected = summarize_latencies(samples)
            if any(latency.get(key) != expected[key] for key in ("p50Seconds", "p95Seconds", "p99Seconds", "maxSeconds")):
                raise ValueError("latency percentiles disagree with retained raw samples")


def worker(config_path):
    config = json.loads(Path(config_path).read_text())
    case = config.pop("selectedCase")
    root = Path(config.pop("caseRoot"))
    args = argparse.Namespace(**config)
    args.binary = Path(args.binary)
    args.reference = Path(args.reference) if args.reference else None
    args.workdir = Path(args.workdir)
    result = {"case": case, "status": "failed", "rows": [], "errors": []}
    def interrupted(signum, frame):
        raise TimeoutError(f"scenario worker interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        scenario = importlib.import_module("bench_workloads." + case)
        rows = scenario.run(args, root)
        validate_rows(rows, args.mode == "heaptrack")
        degraded = [row["name"] for row in rows if row.get("status") == "degraded"]
        result.update(status="degraded" if degraded else "passed", rows=rows,
                      degradedRows=degraded)
    except BaseException as error:
        result["errors"].append(f"{type(error).__name__}: {error}")
        (root / "error.txt").write_text(traceback.format_exc())
    finally:
        save_json(root / "case-result.json", result)
    return {"passed": 0, "degraded": 2, "failed": 1}[result["status"]]


def cleanup_proxy_groups(root):
    """Only registered session IDs, checked against their recorded process birth."""
    errors = []
    for metadata_path in root.rglob("process.json"):
        try:
            metadata = json.loads(metadata_path.read_text())
            pgid, born = metadata["processGroup"], metadata["groupLeaderStartTicks"]
            if metadata.get("status") == "stopped":
                continue
            owned = False
            try:
                owned = process_start_ticks(pgid) == born
            except FileNotFoundError:
                # A wrapper can die while its profiled child remains in its session.
                for entry in Path("/proc").iterdir():
                    if not entry.name.isdecimal():
                        continue
                    try:
                        fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                        if int(fields[2]) == pgid and int(fields[3]) == pgid and int(fields[19]) >= born:
                            owned = True
                            break
                    except (FileNotFoundError, ProcessLookupError):
                        continue
            if owned:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                metadata["status"] = "killed-by-runner-cleanup"
                save_json(metadata_path, metadata)
        except (OSError, ValueError, KeyError) as error:
            errors.append(f"cleanup {metadata_path}: {error}")
    return errors


def run_case(args, case, root):
    root.mkdir(mode=0o700)
    config = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    config.update(selectedCase=case, caseRoot=str(root))
    save_json(root / "worker-config.json", config)
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--_worker", str(root / "worker-config.json")]
    started = time.monotonic()
    timed_out = False
    with (root / "worker.log").open("wb") as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            proc.wait(timeout=args.case_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            # Also clears a fixture left behind after an otherwise successful worker exit.
            terminate_process_group(proc, grace=5 if timed_out else 0.1)
            cleanup_errors = cleanup_proxy_groups(root)
    path = root / "case-result.json"
    result = json.loads(path.read_text()) if path.exists() else {
        "case": case, "status": "failed", "rows": [], "errors": ["worker produced no result JSON"]}
    result.update(workerExitCode=proc.returncode, timedOut=timed_out,
                  wallSeconds=time.monotonic() - started, artifacts=str(root))
    result["errors"].extend(cleanup_errors)
    if timed_out:
        result["errors"].append(f"case exceeded {args.case_timeout} second wall-clock deadline")
    if proc.returncode != 0 and not (proc.returncode == 2 and result["status"] == "degraded"):
        result["errors"].append(f"worker exited with status {proc.returncode}")
    if result["errors"]:
        result["status"] = "failed"
    save_json(path, result)
    return result


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--list", action="store_true", help="list cases without importing their dependencies")
    result.add_argument("--case", action="append", choices=CASES)
    result.add_argument("--binary", type=Path, help="native murmur executable; never built by this runner")
    result.add_argument("--reference", type=Path, help="native mihomo executable, required for relay Vision")
    for option in ("iterations", "concurrency", "payload-bytes", "nodes", "rules"):
        result.add_argument("--" + option, type=positive_int)
    result.add_argument("--timeout", type=positive_float, default=30, help="per-operation/startup timeout in seconds")
    result.add_argument("--case-timeout", type=positive_float, default=600, help="hard wall-clock deadline per scenario")
    result.add_argument("--smoke", action="store_true")
    result.add_argument("--workdir", type=Path, help="fresh or empty evidence directory (default /tmp/murmur-workloads-*)")
    result.add_argument("--mode", choices=("clean", "heaptrack"), default="clean")
    result.add_argument("--_worker", help=argparse.SUPPRESS)
    return result


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    if args._worker:
        return worker(args._worker)
    if args.list:
        print("\n".join(CASES))
        return 0
    if args.binary is None:
        cli.error("--binary is required (the runner does not build executables)")
    if sys.platform != "linux":
        cli.error("workload resource and process ownership evidence requires Linux /proc")
    def interrupted(signum, frame):
        raise TimeoutError(f"runner interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    args.binary = args.binary.expanduser().resolve()
    args.reference = args.reference.expanduser().resolve() if args.reference else None
    args.case = list(dict.fromkeys(args.case or CASES))
    defaults = {"iterations": (20, 2), "concurrency": (4, 2), "payload_bytes": (65536, 4096),
                "nodes": (20, 4), "rules": (10000, 128)}
    for key, values in defaults.items():
        if getattr(args, key) is None:
            setattr(args, key, values[bool(args.smoke)])
    if args.workdir is None:
        args.workdir = Path(tempfile.mkdtemp(prefix="murmur-workloads-", dir="/tmp"))
    else:
        args.workdir = args.workdir.expanduser().resolve()
        if args.workdir.exists() and (not args.workdir.is_dir() or any(args.workdir.iterdir())):
            cli.error("--workdir must be fresh or empty; existing evidence is never overwritten")
        args.workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.workdir.chmod(0o700)
    results = {
        "schemaVersion": 1, "runner": "bench_workloads.py", "machine": machine_metadata(),
        "config": {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()
                   if not key.startswith("_")},
        "cases": [], "errors": [], "status": "running",
        "measurement": {
            "mode": args.mode, "instrumented": args.mode == "heaptrack",
            "cpu": "actual proxy PID user+system CPU delta over measured operation window; fixtures excluded",
            "memory": "Linux VmRSS snapshots and process-lifetime VmHWM; not live heap or allocation count",
            "latency": "successful operations, nearest-rank percentiles with raw seconds; reload disruptions and UDP losses are retained as degraded rows, while invalid data fails the case",
            "startup": "separate process.json startupSeconds; excluded from scenario operation timing",
            "heaptrack": "separate instrumented execution, whole lifetime including startup/setup/warmup; raw artifacts in process.json; extract with heaptrack_print; absent totals are unknown, not zero",
            "portability": "metadata describes this executing host and supplied native ELF, not cross-architecture coverage",
        },
    }
    try:
        results["binary"] = binary_metadata(args.binary, args.timeout)
        results["binarySHA256"] = results["binary"]["sha256"]
        if args.reference:
            results["reference"] = binary_metadata(args.reference, args.timeout)
        if "relay" in args.case and args.reference is None:
            raise ValueError("relay includes real Vision handoff and requires --reference; select other --case values to omit relay explicitly")
        save_json(args.workdir / "results.json", results)
        for case in args.case:
            result = run_case(args, case, args.workdir / case)
            results["cases"].append(result)
            results["errors"].extend(f"{case}: {error}" for error in result["errors"])
            save_json(args.workdir / "results.json", results)
    except BaseException as error:
        results["errors"].append(f"{type(error).__name__}: {error}")
        (args.workdir / "runner-error.txt").write_text(traceback.format_exc())
    degraded = any(case["status"] == "degraded" for case in results["cases"])
    results["status"] = "failed" if results["errors"] else "degraded" if degraded else "passed"
    save_json(args.workdir / "results.json", results)
    print(f"{results['status']}: {args.workdir / 'results.json'}")
    return {"passed": 0, "degraded": 2, "failed": 1}[results["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
