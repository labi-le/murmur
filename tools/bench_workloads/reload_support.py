"""Loopback-only network fixtures and resource sampling for live reload."""
from __future__ import annotations

import hashlib
import http.server
import ipaddress
import select
import socket
import socketserver
import struct
import threading
import time


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError(f"socket closed after {len(data)}/{size} bytes")
        data.extend(chunk)
    return bytes(data)


class _ThreadedTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ReloadFixtures:
    """Real forwarding SOCKS peers with distinct origin-observable source IPs."""

    def __init__(self, timeout):
        self.timeout = timeout
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.servers = []
        self.threads = []
        self.provider_bytes = b""
        self.provider_reads = []
        self.origin_reads = []
        self.errors = []
        self.allowed_ports = set()

    def _serve(self, server):
        self.servers.append(server)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.threads.append(thread)
        return server.server_address[1]

    def __enter__(self):
        owner = self

        class HTTP(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/provider.yaml":
                    with owner.lock:
                        body = owner.provider_bytes
                        owner.provider_reads.append({"at": time.monotonic(), "bytes": len(body),
                                                     "sha256": hashlib.sha256(body).hexdigest(),
                                                     "generationHeader": body.split(b"\n", 1)[0].decode("ascii")})
                else:
                    body = self.client_address[0].encode("ascii")
                    with owner.lock:
                        owner.origin_reads.append({"at": time.monotonic(), "peer": self.client_address[0], "path": self.path})
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(owner.timeout)
                self.request.sendall((self.client_address[0] + "\n").encode("ascii"))
                try:
                    while not owner.stop.is_set():
                        block = self.request.recv(65536)
                        if not block:
                            return
                        self.request.sendall(block)
                except OSError as exc:
                    if not owner.stop.is_set():
                        with owner.lock:
                            owner.errors.append(f"echo: {exc}")

        self.http_port = self._serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP))
        self.echo_port = self._serve(_ThreadedTCP(("127.0.0.1", 0), Echo))
        self.allowed_ports.update((self.http_port, self.echo_port))
        self.proxy_ports = {}
        for name, source in (("route-a", "127.0.0.2"), ("route-b", "127.0.0.3")):
            self.proxy_ports[name] = self._serve(_ThreadedTCP(("127.0.0.1", 0), self._forwarder(source)))
        return self

    def _forwarder(self, source):
        owner = self

        class Forward(socketserver.BaseRequestHandler):
            def handle(self):
                client = self.request
                client.settimeout(owner.timeout)
                try:
                    version, count = recv_exact(client, 2)
                    methods = recv_exact(client, count)
                    if version != 5 or 0 not in methods:
                        raise ValueError("expected SOCKS5 unauthenticated greeting")
                    client.sendall(b"\x05\x00")
                    version, command, reserved, address_type = recv_exact(client, 4)
                    if (version, command, reserved) != (5, 1, 0):
                        raise ValueError("only SOCKS5 CONNECT is supported")
                    if address_type == 1:
                        host = socket.inet_ntoa(recv_exact(client, 4))
                    elif address_type == 3:
                        host = recv_exact(client, recv_exact(client, 1)[0]).decode("ascii")
                    else:
                        raise ValueError("fixture requires IPv4 loopback target")
                    port = struct.unpack("!H", recv_exact(client, 2))[0]
                    if not ipaddress.ip_address(host).is_loopback or port not in owner.allowed_ports:
                        raise ValueError(f"refusing non-fixture target {host}:{port}")
                    with socket.create_connection((host, port), timeout=owner.timeout, source_address=(source, 0)) as target:
                        client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                        while not owner.stop.is_set():
                            ready, _, _ = select.select([client, target], [], [], 0.1)
                            for origin in ready:
                                block = origin.recv(65536)
                                if not block:
                                    return
                                (target if origin is client else client).sendall(block)
                except (OSError, EOFError, ValueError) as exc:
                    if not owner.stop.is_set():
                        with owner.lock:
                            owner.errors.append(f"SOCKS {source}: {exc}")

        return Forward

    def set_provider(self, payload):
        with self.lock:
            self.provider_bytes = payload

    def __exit__(self, *_args):
        self.stop.set()
        for server in reversed(self.servers):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)


class MemorySampler:
    def __init__(self, process, interval=0.01):
        self.process = process
        self.interval = interval
        self.samples = []
        self.errors = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self):
        while not self.stop.is_set():
            try:
                self.samples.append({"at": time.monotonic(), **self.process.resource()})
            except Exception as exc:
                self.errors.append(str(exc))
                return
            self.stop.wait(self.interval)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.stop.set()
        self.thread.join(timeout=2)
