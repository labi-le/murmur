"""Controlled loopback HTTP origins, CONNECT peers, and subscription server."""

from __future__ import annotations

import contextlib
import json
import select
import socket
import socketserver
import threading
import time
from pathlib import Path


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False


class HealthNetwork:
    """Every CONNECT peer forwards real bytes to its own controlled HTTP origin."""

    def __init__(self, root: Path, timeout: float, slow_seconds: float):
        self.root = root
        self.timeout = timeout
        self.slow_seconds = slow_seconds
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.servers = []
        self.threads = []
        self.connections = set()
        self.nodes = {}
        self.events = []
        self.errors = []
        self.subscription_requests = {}
        self.active = 0
        self.peak = 0
        self.authority = None

    def __enter__(self):
        self.root.mkdir(parents=True, exist_ok=True)
        return self

    def __exit__(self, *_):
        self.stop.set()
        with self.lock:
            connections = list(self.connections)
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)
        self.save()

    def save(self):
        with self.lock:
            evidence = {
                "nodes": {name: {key: value for key, value in node.items() if key != "port"}
                          for name, node in self.nodes.items()},
                "events": list(self.events), "errors": list(self.errors),
                "subscriptionRequests": dict(self.subscription_requests),
                "maximumActiveTunnels": self.peak,
            }
        (self.root / "network-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")

    def _serve(self, callback):
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(owner.timeout)
                with owner.lock:
                    owner.connections.add(self.request)
                try:
                    callback(self.request)
                except (BrokenPipeError, ConnectionResetError):
                    # Probe cancellation and Connection: close can close the peer first.
                    pass
                except Exception as error:
                    if not owner.stop.is_set():
                        with owner.lock:
                            owner.errors.append(repr(error))
                finally:
                    with owner.lock:
                        owner.connections.discard(self.request)

        server = _Server(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.servers.append(server)
        self.threads.append(thread)
        thread.start()
        return server.server_address[1]

    @staticmethod
    def _head(stream):
        lines = []
        total = 0
        while True:
            line = stream.readline(16385)
            if not line:
                if not lines:
                    return None
                raise RuntimeError("incomplete HTTP request headers")
            total += len(line)
            if total > 16384:
                raise RuntimeError("oversized fixture request headers")
            lines.append(line)
            if line == b"\r\n":
                return b"".join(lines)

    def add_node(self, name, profile):
        node = {"profile": profile, "connects": 0, "requests": 0, "responseBytes": 0,
                "headRequests": 0, "hostMatches": 0, "closeRequests": 0}
        self.nodes[name] = node
        origin_port = self._serve(lambda conn: self._origin(conn, name))
        if self.authority is None:
            self.authority = f"127.0.0.1:{origin_port}"
        peer_port = self._serve(lambda conn: self._peer(conn, name, origin_port))
        node["port"] = peer_port
        return {"name": name, "type": "http", "server": "127.0.0.1", "port": peer_port}

    def _peer(self, conn, name, origin_port):
        with conn.makefile("rb", buffering=0) as stream:
            head = self._head(stream)
            if head is None:
                return
            first = head.split(b"\r\n", 1)[0]
            if first != f"CONNECT {self.authority} HTTP/1.1".encode():
                raise RuntimeError(f"unexpected outbound CONNECT: {first!r}")
        with socket.create_connection(("127.0.0.1", origin_port), self.timeout) as origin:
            with self.lock:
                self.connections.add(origin)
                self.nodes[name]["connects"] += 1
                self.active += 1
                self.peak = max(self.peak, self.active)
            try:
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                deadline = time.monotonic() + self.timeout
                while not self.stop.is_set():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("health peer exceeded operation timeout")
                    ready, _, _ = select.select([conn, origin], [], [], min(remaining, 0.1))
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (origin if source is conn else conn).sendall(data)
            finally:
                with self.lock:
                    self.active -= 1
                    self.connections.discard(origin)

    def _origin(self, conn, name):
        profile = self.nodes[name]["profile"]
        request_number = 0
        with conn.makefile("rb") as stream:
            while not self.stop.is_set():
                head = self._head(stream)
                if head is None:
                    return
                request_number += 1
                lines = head.decode("ascii").split("\r\n")
                headers = dict(line.lower().split(":", 1) for line in lines[1:] if ":" in line)
                valid_method = lines[0] == "HEAD /health?benchmark=1 HTTP/1.1"
                valid_host = headers.get("host", "").strip() == self.authority
                with self.lock:
                    node = self.nodes[name]
                    node["requests"] += 1
                    node["headRequests"] += int(valid_method)
                    node["hostMatches"] += int(valid_host)
                    node["closeRequests"] += int(headers.get("connection", "").strip() == "close")
                    self.events.append({"node": name, "request": request_number,
                                        "monotonic": time.monotonic(), "profile": profile})
                if not valid_method or not valid_host:
                    raise RuntimeError(f"invalid health request for {name}: {lines!r}")
                if profile in ("dead", "eof"):
                    return
                if profile == "timeout" or (profile == "second-timeout" and request_number == 2):
                    # Wait for real cancellation/EOF, not an artificial clock advance.
                    while not self.stop.is_set():
                        if not conn.recv(1):
                            return
                    return
                if profile == "slow":
                    if self.stop.wait(self.slow_seconds):
                        return
                response = {
                    "status": b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
                    "close": b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
                    "length": b"HTTP/1.1 200 OK\r\nContent-Length: 12345\r\n\r\n",
                    "chunked": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                    "malformed": b"not an HTTP response\r\n\r\n",
                    "interim": b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
                    "large": b"HTTP/1.1 204 No Content\r\nX-Padding: " + b"a" * 8192 + b"\r\n\r\n",
                }.get(profile, b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                conn.sendall(response)
                with self.lock:
                    self.nodes[name]["responseBytes"] += len(response)
                if profile in ("close", "malformed"):
                    return

    def subscription(self, providers):
        payloads = {f"/{name}.json": json.dumps({"proxies": proxies}).encode()
                    for name, proxies in providers.items()}

        def serve(conn):
            with conn.makefile("rb") as stream:
                head = self._head(stream)
            if head is None:
                return
            request = head.split(b"\r\n", 1)[0].decode("ascii")
            method, path, _ = request.split(" ")
            if method != "GET" or path not in payloads:
                raise RuntimeError(f"unexpected subscription request: {request}")
            payload = payloads[path]
            with self.lock:
                self.subscription_requests[path] = self.subscription_requests.get(path, 0) + 1
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                         + str(len(payload)).encode() + b"\r\nConnection: close\r\n\r\n" + payload)

        return self._serve(serve)

    def snapshot(self):
        with self.lock:
            if self.errors:
                raise RuntimeError(f"health network fixture failed: {self.errors}")
            return {name: dict(node) for name, node in self.nodes.items()}

    def quiesce(self):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            with self.lock:
                if self.errors:
                    raise RuntimeError(f"health network fixture failed: {self.errors}")
                if self.active == 0:
                    return
            time.sleep(0.005)
        raise TimeoutError("health network did not quiesce")

    def reset_peak(self):
        with self.lock:
            if self.active:
                raise RuntimeError("cannot reset active health network counters")
            self.peak = 0
