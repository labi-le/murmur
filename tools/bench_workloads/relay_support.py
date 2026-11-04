"""Owned loopback fixtures and wire validation for the relay workloads."""
from __future__ import annotations

import contextlib
import hashlib
import select
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path


def receive_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError(f"truncated stream: received {len(chunks)} of {size} bytes")
        chunks.extend(chunk)
    return bytes(chunks)


def udp_socket_evidence(proxy_pid: int, sockets: dict[str, int]) -> dict:
    result = {"ports": sockets, "sockets": [], "errors": []}
    try:
        owned = set()
        for fd in (Path("/proc") / str(proxy_pid) / "fd").iterdir():
            try:
                target = fd.readlink().as_posix()
            except OSError:
                continue
            if target.startswith("socket:["):
                owned.add(target[8:-1])
        for family in ("udp", "udp6"):
            for line in (Path("/proc/net") / family).read_text().splitlines()[1:]:
                fields = line.split()
                port = int(fields[1].split(":")[1], 16)
                if fields[9] in owned or port in sockets.values():
                    result["sockets"].append({
                        "family": family, "localAddressHex": fields[1], "remoteAddressHex": fields[2],
                        "port": port, "inode": fields[9], "proxyOwned": fields[9] in owned,
                        "roles": [role for role, value in sockets.items() if value == port],
                        "receiveQueueBytes": int(fields[4].split(":")[1], 16),
                        "kernelDrops": int(fields[-1]),
                    })
    except (OSError, ValueError, IndexError) as exc:
        result["errors"].append(f"{type(exc).__name__}: {exc}")
    return result


class EchoFixture:
    """Track every accepted socket and join every owned thread on exit."""

    def __init__(self, timeout: float, *, udp: bool = False, slow: bool = False, receive_buffer: int = 0):
        self.timeout, self.udp, self.slow = timeout, udp, slow
        self.stop = threading.Event()
        self.accepted = threading.Event()
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.sockets: set[socket.socket] = set()
        self.threads: list[threading.Thread] = []
        self.errors: list[str] = []
        self.connections = self.messages = self.received_bytes = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        if slow:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
        elif receive_buffer:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.receive_buffer = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        if receive_buffer and self.receive_buffer < receive_buffer:
            self.sock.close()
            raise RuntimeError(f"fixture receive buffer clamped to {self.receive_buffer}; "
                               f"need {receive_buffer} bytes for the concurrent datagram burst")
        if not udp:
            self.sock.listen(128)
        self.sock.settimeout(0.1)

    def __enter__(self):
        self.thread = threading.Thread(target=self._serve, name="relay-fixture")
        self.thread.start()
        return self

    def _serve(self):
        while not self.stop.is_set():
            try:
                if self.udp:
                    data, peer = self.sock.recvfrom(65535)
                    with self.lock:
                        self.messages += 1
                        self.received_bytes += len(data)
                    self.sock.sendto(data, peer)
                else:
                    conn, _ = self.sock.accept()
                    conn.settimeout(self.timeout)
                    with self.lock:
                        self.connections += 1
                        self.sockets.add(conn)
                    thread = threading.Thread(target=self._handle, args=(conn,), name="relay-stream")
                    self.threads.append(thread)
                    thread.start()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.stop.is_set():
                    self.errors.append(repr(exc))
                break

    def _handle(self, conn):
        try:
            if self.slow:
                remaining = struct.unpack("!Q", receive_exact(conn, 8))[0]
                self.accepted.set()
                if not self.release.wait(self.timeout):
                    raise TimeoutError("slow receiver was never released")
                digest = hashlib.sha256()
                total = 0
                while remaining:
                    data = conn.recv(min(65536, remaining))
                    if not data:
                        raise RuntimeError("slow receiver observed truncated upload")
                    remaining -= len(data)
                    total += len(data)
                    digest.update(data)
                with self.lock:
                    self.messages += 1
                    self.received_bytes += total
                conn.sendall(struct.pack("!Q", total) + digest.digest())
            else:
                while not self.stop.is_set():
                    data = conn.recv(65536)
                    if not data:
                        break
                    with self.lock:
                        self.received_bytes += len(data)
                    conn.sendall(data)
        except Exception as exc:
            if not self.stop.is_set():
                self.errors.append(repr(exc))
        finally:
            with self.lock:
                self.sockets.discard(conn)
            conn.close()

    def check(self):
        if self.errors:
            raise RuntimeError(f"relay fixture failed: {self.errors}")

    def __exit__(self, exc_type, exc, tb):
        self.stop.set()
        self.release.set()
        self.sock.close()
        self.thread.join(timeout=1)
        with self.lock:
            sockets = list(self.sockets)
        for conn in sockets:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_RDWR)
            conn.close()
        for thread in self.threads:
            thread.join(timeout=1)
        if self.thread.is_alive() or any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("relay fixture thread failed to stop")
        if exc_type is None:
            self.check()


@contextlib.contextmanager
def udp_association(proxy_port: int, timeout: float):
    with socket.create_connection(("127.0.0.1", proxy_port), timeout) as control:
        control.sendall(b"\x05\x01\x00")
        if receive_exact(control, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 UDP authentication negotiation failed")
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        header = receive_exact(control, 4)
        if header[:3] != b"\x05\x00\x00":
            raise RuntimeError(f"SOCKS5 UDP ASSOCIATE rejected: {header.hex()}")
        if header[3] == 1:
            host = socket.inet_ntop(socket.AF_INET, receive_exact(control, 4))
        elif header[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, receive_exact(control, 16))
        elif header[3] == 3:
            host = receive_exact(control, receive_exact(control, 1)[0]).decode("ascii")
        else:
            raise RuntimeError("unknown SOCKS5 UDP bind address type")
        port = struct.unpack("!H", receive_exact(control, 2))[0]
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        if host not in ("127.0.0.1", "::1") or not port:
            raise RuntimeError(f"UDP relay advertised unexpected non-loopback endpoint {host}:{port}")
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(timeout)
            udp.bind((host, 0))
            # A connected UDP socket also rejects packets from a different relay source.
            udp.connect((host, port))
            yield udp, (host, port)


def udp_roundtrip(sock: socket.socket, target_port: int, payload: bytes):
    frame = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target_port) + payload
    sock.send(frame)
    reply, peer = sock.recvfrom(65535)
    if peer[:2] != sock.getpeername()[:2]:
        raise RuntimeError(f"UDP transport source mismatch: {peer}")
    if reply != frame:
        raise RuntimeError("SOCKS5 UDP response payload, fragment flag, or encapsulated source mismatch")


def blocked_upload(sock: socket.socket, fixture: EchoFixture, payload: bytes, timeout: float) -> dict:
    """Require a sustained non-writable sender while the target cannot read."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)
    send_buffer = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
    sock.sendall(struct.pack("!Q", len(payload)))
    if not fixture.accepted.wait(timeout):
        raise TimeoutError("slow receiver did not accept the upload")
    sock.setblocking(False)
    view = memoryview(payload)
    offset = 0
    pending = 0
    blocked_seconds = 0.0
    deadline = time.monotonic() + timeout
    try:
        while offset < len(payload):
            if time.monotonic() >= deadline:
                raise TimeoutError("backpressure observation deadline exceeded")
            try:
                sent = sock.send(view[offset:])
                if not sent:
                    raise RuntimeError("sender closed during pressure observation")
                offset += sent
            except BlockingIOError:
                pending += 1
                start = time.perf_counter()
                _, writable, _ = select.select([], [sock], [], 0.1)
                duration = time.perf_counter() - start
                if not writable:
                    blocked_seconds = duration
                    break
        if not blocked_seconds or offset == len(payload):
            raise RuntimeError("bounded upload never produced sustained socket backpressure; refusing to label it backpressure")
        observed_offset = offset
        fixture.release.set()
        sock.settimeout(timeout)
        sock.sendall(view[offset:])
        ack = receive_exact(sock, 40)
        if ack != struct.pack("!Q", len(payload)) + hashlib.sha256(payload).digest():
            raise RuntimeError("slow receiver upload byte count or SHA-256 mismatch")
        return {
            "wouldBlockCount": pending,
            "observedNonWritableSeconds": blocked_seconds,
            "bytesAcceptedBeforeRelease": observed_offset,
            "bytesRemainingAtRelease": len(payload) - observed_offset,
            "senderSocketBufferBytes": send_buffer,
            "receiverSocketBufferBytes": fixture.receive_buffer,
            "receiverReadGateClosedDuringObservation": True,
        }
    finally:
        fixture.release.set()


@contextlib.contextmanager
def bulk_origin(root: Path, cert: Path, key: Path, port: int, timeout: float):
    import sys

    fixture = Path(__file__).resolve().parents[1] / "e2e" / "fixtures" / "https_bulk_target.py"
    root.mkdir(parents=True, exist_ok=True)
    with (root / "origin.log").open("wb") as log:
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--duplex-origin", "--port", str(port),
             "--cert", str(cert), "--key", str(key)],
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + timeout
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"TLS bulk origin exited; see {root / 'origin.log'}")
                try:
                    with socket.create_connection(("127.0.0.1", port), 0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("TLS bulk origin readiness timeout")
                    time.sleep(0.02)
            yield fixture
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def _duplex_origin_main():
    """Reuse the E2E TLS/bulk fixture, adding a digest-checked request body."""
    import importlib.util
    import sys

    fixture = Path(__file__).resolve().parents[1] / "e2e" / "fixtures" / "https_bulk_target.py"
    spec = importlib.util.spec_from_file_location("relay_bulk_target", fixture)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class DuplexHandler(module.Handler):
        def do_POST(self):
            remaining = int(self.headers.get("Content-Length", "0"))
            if remaining <= 0 or remaining > 4 * 1024 * 1024:
                self.send_error(413)
                return
            received = 0
            digest = hashlib.sha256()
            while remaining:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    self.close_connection = True
                    return
                digest.update(chunk)
                received += len(chunk)
                remaining -= len(chunk)
            self.upload_evidence = (received, digest.hexdigest())
            self.do_GET()

        def end_headers(self):
            if hasattr(self, "upload_evidence"):
                received, digest = self.upload_evidence
                self.send_header("X-Received-Bytes", str(received))
                self.send_header("X-Received-SHA256", digest)
            super().end_headers()

    module.Handler = DuplexHandler
    sys.argv.remove("--duplex-origin")
    module.main()


if __name__ == "__main__":
    _duplex_origin_main()
