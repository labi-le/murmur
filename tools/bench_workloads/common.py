"""Owned processes, loopback clients and explicit whole-process measurements."""
from __future__ import annotations

import copy
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import time
from urllib.parse import urlsplit


def free_port(socktype=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, socktype) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_config(root: Path, config: dict) -> Path:
    try:
        import yaml
    except ImportError as error:
        raise RuntimeError("PyYAML is required: install python3-pyyaml or pip install PyYAML") from error
    root = Path(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / "config.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)
    return path


def certificate(root: Path) -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("TLS workloads require openssl in PATH")
    root = Path(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
         "-addext", "basicConstraints=critical,CA:FALSE",
         "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
         "-addext", "extendedKeyUsage=serverAuth"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    key.chmod(0o600)
    cert.chmod(0o600)
    return cert, key


def summarize_latencies(samples_seconds: list) -> dict:
    """Nearest-rank percentiles; retain original-order successful observations."""
    samples = list(samples_seconds)
    if not samples or any(isinstance(x, bool) or not isinstance(x, (int, float))
                          or not math.isfinite(x) or x < 0 for x in samples):
        raise ValueError("latencies must contain finite nonnegative seconds, not an empty/error sample")
    ordered = sorted(samples)
    return {
        "count": len(samples),
        **{f"p{p}Seconds": ordered[math.ceil(p / 100 * len(ordered)) - 1] for p in (50, 95, 99)},
        "maxSeconds": ordered[-1], "samplesSeconds": samples,
        "percentileMethod": "nearest-rank",
    }


def process_start_ticks(pid: int) -> int:
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])


def terminate_process_group(proc: subprocess.Popen, grace: float = 3.0) -> None:
    """Stop an owned session, including descendants surviving their leader."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    # A leader may exit before a TERM-resistant descendant. Do not equate the two.
    while time.monotonic() < deadline:
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait(timeout=5)


class ProxyProcess:
    def __init__(self, args, root: Path, config: dict, *, env: dict | None = None):
        self.args = args
        self.root = Path(root).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.config = {
            "mixed-port": free_port(), "external-controller": f"127.0.0.1:{free_port()}",
            "secret": secrets.token_hex(24), "bind-address": "127.0.0.1", "allow-lan": False,
            "log-level": "warning", "mode": "rule", "rules": ["MATCH,DIRECT"],
        }
        self.config.update(copy.deepcopy(config))
        self.mixed_port = int(self.config["mixed-port"])
        controller = urlsplit("http://" + self.config["external-controller"])
        if controller.hostname not in ("127.0.0.1", "localhost", "::1") or not controller.port:
            raise ValueError("benchmark controller must listen on a loopback address and explicit port")
        self.controller_host = controller.hostname
        self.controller_port = controller.port
        dns = self.config.get("dns", {})
        self.dns_port = int(str(dns["listen"]).rsplit(":", 1)[1]) if dns.get("listen") else None
        self.log_path = self.root / "process.log"
        self.metadata_path = self.root / "process.json"
        self.env = env or {}
        self.proc = None
        self.pid = None
        self.startup_seconds = None
        self._log = None
        self._metadata = {}
        self._start_ticks = None

    def __enter__(self):
        config_path = write_config(self.root, self.config)
        ready_path = self.root / "startup-ready"
        ready_path.unlink(missing_ok=True)
        # The controller starts before providers; post-up runs only after successful full apply.
        post_up = f"umask 077; : > {shlex.quote(str(ready_path))}"
        command = [str(self.args.binary), "-d", str(self.root), "-f", str(config_path),
                   "-post-up", post_up]
        instrumented = self.args.mode == "heaptrack"
        if instrumented:
            heaptrack = shutil.which("heaptrack")
            if not heaptrack:
                raise RuntimeError("--mode heaptrack requires heaptrack in PATH; clean timing is not a substitute")
            command = [heaptrack, "--record-only", "-o", str(self.root / "heaptrack"), *command]
        self._log = self.log_path.open("wb")
        started = time.monotonic()
        try:
            self.proc = subprocess.Popen(
                command, stdout=self._log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                env={**os.environ, **self.env}, start_new_session=True,
            )
            self._metadata = {
                "command": command, "processGroup": self.proc.pid,
                "groupLeaderStartTicks": process_start_ticks(self.proc.pid),
                "instrumented": instrumented, "binary": str(self.args.binary),
                "status": "starting", "resourceScope": "actual proxy process only; excludes fixtures and clients",
                "startupReadySignal": "post-up hook after successful initial configuration apply, then /version",
            }
            self._save_metadata()
            deadline = started + self.args.timeout
            last_error = "waiting for successful initial configuration apply (post-up hook)"
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"proxy exited {self.proc.returncode}; see {self.log_path}")
                if self.pid is None:
                    self.pid = self._find_binary_pid() if instrumented else self.proc.pid
                    if self.pid is not None:
                        self._start_ticks = process_start_ticks(self.pid)
                if self.pid is not None and ready_path.is_file():
                    try:
                        status, body = self.api("GET", "/version", _timeout=min(0.3, max(0.01, deadline - time.monotonic())))
                        last_error = f"controller /version returned HTTP {status}"
                        if status == 200 and isinstance(json.loads(body), dict):
                            self.assert_alive()
                            self.startup_seconds = time.monotonic() - started
                            self._metadata.update(pid=self.pid, childStartTicks=self._start_ticks,
                                                  startupSeconds=self.startup_seconds, status="running",
                                                  controllerVersion=json.loads(body))
                            self._save_metadata()
                            return self
                    except (OSError, ValueError, http.client.HTTPException) as error:
                        last_error = str(error)
                time.sleep(min(0.02, max(0, deadline - time.monotonic())))
            raise TimeoutError(f"proxy startup readiness timed out: {last_error}; see {self.log_path}")
        except BaseException:
            self.stop()
            raise

    def _find_binary_pid(self):
        matches = []
        for path in Path("/proc").iterdir():
            if not path.name.isdecimal():
                continue
            pid = int(path.name)
            try:
                if os.getpgid(pid) == self.proc.pid and os.path.samefile(path / "exe", self.args.binary):
                    matches.append(pid)
            except (OSError, ProcessLookupError):
                continue
        if len(matches) > 1:
            raise RuntimeError(f"ambiguous heaptrack child PIDs: {matches}")
        return matches[0] if matches else None

    def _save_metadata(self):
        temporary = self.metadata_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(self._metadata, indent=2) + "\n")
        temporary.replace(self.metadata_path)

    def api(self, method, path, body=None, *, _timeout=None):
        connection = http.client.HTTPConnection(self.controller_host, self.controller_port,
                                                timeout=self.args.timeout if _timeout is None else _timeout)
        headers = {"Authorization": "Bearer " + str(self.config["secret"])}
        if body is not None:
            body = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def assert_alive(self):
        if self.proc is None or self.proc.poll() is not None:
            raise RuntimeError(f"proxy process is not alive; see {self.log_path}")
        if self.pid is None or process_start_ticks(self.pid) != self._start_ticks:
            raise RuntimeError("proxy child PID disappeared or was reused")
        state = Path(f"/proc/{self.pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        if state == "Z":
            raise RuntimeError(f"proxy child exited; see {self.log_path}")

    def resource(self):
        self.assert_alive()
        fields = Path(f"/proc/{self.pid}/stat").read_text().rsplit(")", 1)[1].split()
        status = {}
        for line in Path(f"/proc/{self.pid}/status").read_text().splitlines():
            key, _, value = line.partition(":")
            if key in ("VmRSS", "VmHWM"):
                status[key] = int(value.split()[0])
        return {"cpuSeconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
                "rssKiB": status["VmRSS"], "hwmKiB": status["VmHWM"]}

    def mark(self):
        return {**self.resource(), "monotonicSeconds": time.monotonic()}

    def delta(self, before):
        after = self.mark()
        return {"elapsedSeconds": after["monotonicSeconds"] - before["monotonicSeconds"],
                "cpuSeconds": after["cpuSeconds"] - before["cpuSeconds"],
                "rssBeforeKiB": before["rssKiB"], "rssAfterKiB": after["rssKiB"],
                "hwmKiB": after["hwmKiB"], "pid": self.pid,
                "scope": "proxy process delta over operation window; HWM is process-lifetime RSS, not live heap"}

    def stop(self):
        if self._log is None or self._log.closed:
            return
        profile_error = None
        try:
            if self.proc is not None:
                self._metadata["exitCodeBeforeStop"] = self.proc.poll()
                if self.args.mode == "heaptrack" and self.pid is not None:
                    # Let the injected profiler flush while its wrapper is still alive.
                    try:
                        if process_start_ticks(self.pid) == self._start_ticks:
                            os.kill(self.pid, signal.SIGTERM)
                    except (ProcessLookupError, FileNotFoundError):
                        pass
                    try:
                        self.proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                terminate_process_group(self.proc)
                self._metadata.update(status="stopped", exitCodeAfterStop=self.proc.returncode)
                if self.args.mode == "heaptrack":
                    artifacts = [str(p) for p in sorted(self.root.glob("heaptrack*"))
                                 if p.is_file() and p.stat().st_size > 0]
                    self._metadata.update(heaptrackArtifacts=artifacts,
                                          heaptrackScope="whole process lifetime including startup, setup and warmup",
                                          heaptrackExtraction="heaptrack_print <artifact>",
                                          allocationTotals=None)
                    if not artifacts:
                        profile_error = RuntimeError(f"heaptrack produced no nonempty raw profile in {self.root}")
                    elif self.proc.returncode != 0:
                        profile_error = RuntimeError(
                            f"heaptrack exited {self.proc.returncode}; profile may be incomplete: {self.log_path}"
                        )
                self._save_metadata()
        finally:
            self._log.close()
        if profile_error:
            raise profile_error

    def __exit__(self, kind, value, traceback):
        alive_error = None
        if kind is None:
            try:
                self.assert_alive()
            except Exception as error:
                alive_error = error
        try:
            self.stop()
        except Exception:
            if kind is None:
                raise
        if alive_error is not None:
            raise alive_error
        return False


def http_proxy_request(proxy_port, url, method="GET", body=b"", timeout=30, *, ssl_context=None):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("proxy request requires an absolute http or https URL")
    if parsed.scheme == "https":
        connection = http.client.HTTPSConnection("127.0.0.1", proxy_port, timeout=timeout,
                                                 context=ssl_context)
        connection.set_tunnel(parsed.hostname, parsed.port or 443)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
    else:
        connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=timeout)
        target = url
    try:
        connection.request(method, target, body=body, headers={"Connection": "close", "Host": parsed.netloc})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def _recv_exact(sock, length):
    chunks = bytearray()
    while len(chunks) < length:
        part = sock.recv(length - len(chunks))
        if not part:
            raise EOFError("SOCKS peer closed before completing its response")
        chunks.extend(part)
    return bytes(chunks)


def socks_connect(proxy_port, host, port, timeout=30):
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 proxy refused no-authentication negotiation")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            encoded = host.encode("idna")
            if not 0 < len(encoded) <= 255:
                raise ValueError("SOCKS5 domain length must be 1..255 bytes")
            target = b"\x03" + bytes([len(encoded)]) + encoded
        else:
            target = (b"\x01" if address.version == 4 else b"\x04") + address.packed
        sock.sendall(b"\x05\x01\x00" + target + struct.pack("!H", port))
        version, reply, reserved, family = _recv_exact(sock, 4)
        if version != 5 or reserved != 0 or reply != 0:
            raise RuntimeError(f"SOCKS5 connect failed: version={version}, reply={reply}, reserved={reserved}")
        if family == 1:
            length = 4
        elif family == 4:
            length = 16
        elif family == 3:
            length = _recv_exact(sock, 1)[0]
        else:
            raise RuntimeError(f"SOCKS5 returned invalid address type {family}")
        _recv_exact(sock, length + 2)
        return sock
    except BaseException:
        sock.close()
        raise
