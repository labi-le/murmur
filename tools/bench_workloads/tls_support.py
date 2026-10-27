"""Loopback-only TLS forwarding fixtures; never substitutes for the tested proxy."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
from pathlib import Path
import socket
import ssl
import struct
import threading
import time

from e2e.fixtures.fixture_server import PASSWORD_HASH, USER_ID


class TLSFixture:
    """Own a verified HTTPS origin, protocol server and optional fragmenting hop."""

    def __init__(self, cert: Path, key: Path, protocol: str, payload: bytes,
                 timeout: float, fragment_bytes: int):
        self.protocol = protocol
        self.payload = payload
        self.timeout = timeout
        self.fragment_bytes = fragment_bytes
        self.fragment_delay = 0.00015 if fragment_bytes else 0.0
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.set_ecdh_curve("X25519")
        self.context.load_cert_chain(cert, key)
        self.context.set_alpn_protocols(["http/1.1"])
        # Fresh connections must really perform full handshakes in both controls.
        self.context.num_tickets = 0
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name="tls-fixture")
        self.servers = []
        self.tasks = set()
        self.events = []
        self.lock = threading.Lock()
        self.origin_port = 0
        self.forward_port = 0
        self.port = 0

    def event(self, kind, **fields):
        with self.lock:
            self.events.append({"kind": kind, "monotonicSeconds": time.monotonic(), **fields})

    def snapshot(self):
        with self.lock:
            return [dict(event) for event in self.events]

    def save(self, path: Path):
        path.write_text(json.dumps(self.snapshot(), indent=2) + "\n")

    async def close_writer(self, writer):
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)

    def accepted(self, handler, reader, writer):
        task = asyncio.create_task(self.connection(handler, reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def connection(self, handler, reader, writer):
        try:
            await asyncio.wait_for(handler(reader, writer), self.timeout)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.event("error", handler=handler.__name__, error=repr(error))
        finally:
            await self.close_writer(writer)

    async def listen(self, handler, tls=False):
        server = await asyncio.start_server(
            lambda reader, writer: self.accepted(handler, reader, writer),
            "127.0.0.1", 0, ssl=self.context if tls else None,
            **({"ssl_handshake_timeout": self.timeout} if tls else {}),
        )
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def start(self):
        self.origin_port = await self.listen(self.origin, tls=True)
        self.forward_port = await self.listen(self.forward, tls=True)
        self.port = await self.listen(self.fragment) if self.fragment_bytes else self.forward_port

    def __enter__(self):
        self.thread.start()
        try:
            asyncio.run_coroutine_threadsafe(self.start(), self.loop).result(self.timeout)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    async def stop(self):
        for server in self.servers:
            server.close()
        for server in self.servers:
            await server.wait_closed()
        pending = list(self.tasks)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    def __exit__(self, *_):
        try:
            asyncio.run_coroutine_threadsafe(self.stop(), self.loop).result(self.timeout + 2)
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(self.timeout + 2)
            if self.thread.is_alive():
                raise RuntimeError("TLS fixture event loop did not stop")
            self.loop.close()

    async def idle(self):
        deadline = self.loop.time() + self.timeout
        while self.tasks:
            if self.loop.time() >= deadline:
                raise TimeoutError("TLS fixture connections did not finish")
            await asyncio.sleep(0.005)

    def wait_idle(self):
        asyncio.run_coroutine_threadsafe(self.idle(), self.loop).result(self.timeout + 1)

    def handshake(self, kind, writer):
        tls = writer.get_extra_info("ssl_object")
        self.event(kind, version=tls.version(), cipher=tls.cipher()[0],
                   sessionReused=tls.session_reused)

    async def origin(self, reader, writer):
        self.handshake("originHandshake", writer)
        headers = await reader.readuntil(b"\r\n\r\n")
        lines = headers.split(b"\r\n")
        if lines[0] != b"GET /payload HTTP/1.1":
            raise ValueError(f"unexpected origin request: {lines[0]!r}")
        expected_host = f"host: localhost:{self.origin_port}".encode()
        if expected_host not in [line.lower() for line in lines]:
            raise ValueError("HTTPS origin Host did not match the verified destination")
        writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                     + str(len(self.payload)).encode() + b"\r\n\r\n")
        for offset in range(0, len(self.payload), 1024):
            writer.write(self.payload[offset:offset + 1024])
            await writer.drain()
            if offset + 1024 < len(self.payload):
                await asyncio.sleep(0.001)
        self.event("originRequest", bytes=len(self.payload),
                   sha256=hashlib.sha256(self.payload).hexdigest())

    async def address(self, reader):
        kind = (await reader.readexactly(1))[0]
        if kind == 1:
            return socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
        if kind == (2 if self.protocol == "vless" else 3):
            length = (await reader.readexactly(1))[0]
            return (await reader.readexactly(length)).decode("ascii")
        if kind == (3 if self.protocol == "vless" else 4):
            return socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        raise ValueError(f"unsupported destination type {kind}")

    async def forward(self, reader, writer):
        self.handshake("outerHandshake", writer)
        if self.protocol == "trojan":
            if await reader.readexactly(59) != PASSWORD_HASH + b"\r\n\x01":
                raise ValueError("Trojan authentication or TCP command mismatch")
            host = await self.address(reader)
            port = struct.unpack("!H", await reader.readexactly(2))[0]
            if await reader.readexactly(2) != b"\r\n":
                raise ValueError("Trojan delimiter mismatch")
        else:
            if await reader.readexactly(19) != b"\x00" + USER_ID + b"\x00\x01":
                raise ValueError("VLESS version, UUID, addons or TCP command mismatch")
            port = struct.unpack("!H", await reader.readexactly(2))[0]
            host = await self.address(reader)
        if host not in ("localhost", "127.0.0.1") or port != self.origin_port:
            raise ValueError(f"refusing non-fixture destination {host}:{port}")
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            self.event("forward", host=host, port=port, protocol=self.protocol)
            if self.protocol == "vless":
                writer.write(b"\x00\x00")
                await writer.drain()
            await self.duplex(reader, writer, upstream_reader, upstream_writer)
        finally:
            await self.close_writer(upstream_writer)

    async def pump(self, reader, writer, fragmented=False):
        total = chunks = 0
        try:
            while data := await reader.read(65536):
                step = self.fragment_bytes if fragmented else len(data)
                for offset in range(0, len(data), step):
                    chunk = data[offset:offset + step]
                    writer.write(chunk)
                    await writer.drain()
                    total += len(chunk)
                    chunks += 1
                    if fragmented:
                        await asyncio.sleep(self.fragment_delay)
        finally:
            if fragmented:
                self.event("fragmentStream", bytes=total, writes=chunks,
                           maxWriteBytes=self.fragment_bytes, delaySeconds=self.fragment_delay)

    async def duplex(self, reader, writer, other_reader, other_writer, fragmented=False):
        tasks = [asyncio.create_task(self.pump(reader, other_writer)),
                 asyncio.create_task(self.pump(other_reader, writer, fragmented))]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def fragment(self, reader, writer):
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", self.forward_port)
        for endpoint in (writer, upstream_writer):
            endpoint.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            await self.duplex(reader, writer, upstream_reader, upstream_writer, fragmented=True)
        finally:
            await self.close_writer(upstream_writer)
