"""Behavioral checks for measurement math and owned-process cleanup."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import threading
from types import SimpleNamespace

from bench_workloads.common import ProxyProcess, summarize_latencies, terminate_process_group


class LatencyTests(unittest.TestCase):
    def test_nearest_rank_preserves_raw_samples(self):
        samples = [0.03, 0.01, 0.02, 0.04]
        result = summarize_latencies(samples)
        self.assertEqual(result["count"], 4)
        self.assertEqual(result["p50Seconds"], 0.02)
        self.assertEqual(result["p95Seconds"], 0.04)
        self.assertEqual(result["p99Seconds"], 0.04)
        self.assertEqual(result["samplesSeconds"], samples)
        self.assertEqual(samples, [0.03, 0.01, 0.02, 0.04])

    def test_invalid_samples_fail_instead_of_becoming_success(self):
        for samples in ([], [-1.0], [math.nan], [math.inf], [True]):
            with self.subTest(samples=samples), self.assertRaises(ValueError):
                summarize_latencies(samples)

    def test_single_sample_has_identical_percentiles(self):
        result = summarize_latencies([0.125])
        for key in ("p50Seconds", "p95Seconds", "p99Seconds", "maxSeconds"):
            self.assertEqual(result[key], 0.125)


@unittest.skipUnless(sys.platform == "linux" and os.environ.get("MURMUR_BENCH_TEST_BINARY"),
                     "set MURMUR_BENCH_TEST_BINARY to a built native murmur")
class StartupTests(unittest.TestCase):
    @contextmanager
    def blocked_provider(self, timeout=5):
        requested, release = threading.Event(), threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requested.set()
                if not release.wait(10):
                    return
                body = b"payload:\n  - DOMAIN,ready.invalid\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory(prefix="murmur-ready-' ", dir="/tmp") as directory:
            with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
                serving = threading.Thread(target=server.serve_forever, daemon=True)
                serving.start()
                args = SimpleNamespace(binary=Path(os.environ["MURMUR_BENCH_TEST_BINARY"]).resolve(),
                                       mode="clean", timeout=timeout)
                proxy = ProxyProcess(args, Path(directory), {
                    "dns": {"enable": False},
                    "rule-providers": {"delayed": {
                        "type": "http", "behavior": "classical", "format": "yaml",
                        "url": f"http://127.0.0.1:{server.server_port}/rules.yaml",
                        "path": str(Path(directory) / "rules.yaml"), "interval": 86400,
                    }},
                    "rules": ["RULE-SET,delayed,REJECT", "MATCH,DIRECT"],
                })
                try:
                    yield proxy, requested, release
                finally:
                    release.set()
                    proxy.stop()
                    server.shutdown()
                    serving.join(timeout=5)

    def test_controller_response_does_not_finish_startup_before_providers(self):
        with self.blocked_provider() as (proxy, requested, release):
            with ThreadPoolExecutor(max_workers=1) as executor:
                entered = executor.submit(proxy.__enter__)
                try:
                    self.assertTrue(requested.wait(5), "provider initialization did not begin")
                    started_at = time.monotonic()
                    self.assertEqual(proxy.api("GET", "/version")[0], 200)
                    with self.assertRaises(TimeoutError):
                        entered.result(timeout=0.1)
                    released_at = time.monotonic()
                finally:
                    release.set()
                self.assertIs(entered.result(timeout=5), proxy)
                self.assertGreaterEqual(proxy.startup_seconds, released_at - started_at)
                status, body = proxy.api("GET", "/providers/rules")
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["providers"]["delayed"]["ruleCount"], 1)

    def test_startup_timeout_stops_proxy_even_when_controller_answers(self):
        with self.blocked_provider(timeout=0.5) as (proxy, requested, release):
            (proxy.root / "startup-ready").touch()
            with ThreadPoolExecutor(max_workers=1) as executor:
                entered = executor.submit(proxy.__enter__)
                try:
                    self.assertTrue(requested.wait(5), "provider initialization did not begin")
                    self.assertEqual(proxy.api("GET", "/version")[0], 200)
                    with self.assertRaises(TimeoutError):
                        entered.result(timeout=5)
                    self.assertIsNotNone(proxy.proc.poll())
                    self.assertIsNone(proxy.startup_seconds)
                finally:
                    release.set()


@unittest.skipUnless(sys.platform == "linux", "owned Linux process groups")
class CleanupTests(unittest.TestCase):
    def test_timeout_cleanup_kills_term_resistant_descendant(self):
        with tempfile.TemporaryDirectory(prefix="murmur-cleanup-", dir="/tmp") as directory:
            marker = Path(directory) / "descendant"
            child_code = (
                "import os,signal,time; from pathlib import Path; "
                "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                f"Path({str(marker)!r}).write_text(str(os.getpid())); time.sleep(60)"
            )
            parent_code = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{child_code!r}]); time.sleep(60)"
            )
            proc = subprocess.Popen([sys.executable, "-c", parent_code], start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists(), "descendant did not initialize")
                child_pid = int(marker.read_text())
                terminate_process_group(proc, grace=0.1)
                self.assertIsNotNone(proc.poll())
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    try:
                        state = Path(f"/proc/{child_pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                    except FileNotFoundError:
                        break
                    if state == "Z":
                        break
                    time.sleep(0.01)
                else:
                    self.fail("term-resistant descendant survived timeout cleanup")
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
