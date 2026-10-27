"""Bounded DNS wire helpers and counted loopback UDP/TCP upstream.

The deterministic A/AAAA answers follow tools/e2e/fixtures/dns_upstream.py;
this fixture adds compression-safe parsing, TTL/delay controls and counters.
"""
from __future__ import annotations

from collections import Counter
import ipaddress
import secrets
import socket
import struct
import threading
import time

V4 = "203.0.113.9"
V6 = "2001:db8::9"


def decode_name(message: bytes, offset: int) -> tuple[str, int]:
    labels = []
    seen = set()
    end = None
    wire_length = 1
    while True:
        if offset >= len(message) or offset in seen:
            raise ValueError("truncated or cyclic DNS name")
        seen.add(offset)
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated DNS compression pointer")
            target = ((length & 0x3F) << 8) | message[offset + 1]
            if target >= offset:
                raise ValueError("DNS compression pointer does not refer backwards")
            if end is None:
                end = offset + 2
            offset = target
            continue
        if length & 0xC0:
            raise ValueError("unsupported DNS label encoding")
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), end if end is not None else offset
        if offset + length > len(message):
            raise ValueError("truncated DNS label")
        wire_length += length + 1
        if wire_length > 255:
            raise ValueError("DNS name exceeds 255 octets")
        labels.append(message[offset:offset + length].decode("ascii"))
        offset += length


def encode_name(name: str) -> bytes:
    labels = name.rstrip(".").encode("ascii").split(b".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid DNS label length")
    wire = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    if len(wire) > 255:
        raise ValueError("DNS name exceeds 255 octets")
    return wire


def parse_message(message: bytes) -> dict:
    if not 12 <= len(message) <= 65535:
        raise ValueError("invalid DNS message length")
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", message)
    if qd != 1:
        raise ValueError("fixture requires exactly one DNS question")
    name, offset = decode_name(message, 12)
    if offset + 4 > len(message):
        raise ValueError("truncated DNS question")
    qtype, qclass = struct.unpack_from("!HH", message, offset)
    offset += 4
    records = []
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            owner, offset = decode_name(message, offset)
            if offset + 10 > len(message):
                raise ValueError("truncated DNS resource record")
            rtype, rclass, ttl, length = struct.unpack_from("!HHIH", message, offset)
            offset += 10
            end = offset + length
            if end > len(message):
                raise ValueError("truncated DNS resource data")
            value = None
            if rtype in (1, 28):
                if length != (4 if rtype == 1 else 16):
                    raise ValueError("invalid DNS address length")
                value = str(ipaddress.ip_address(message[offset:end]))
            elif rtype == 12:
                value, consumed = decode_name(message, offset)
                if consumed != end:
                    raise ValueError("invalid DNS PTR length")
            records.append({"section": section, "name": owner, "type": rtype,
                            "class": rclass, "ttl": ttl, "value": value})
            offset = end
    if offset != len(message):
        raise ValueError("trailing bytes in DNS message")
    return {"id": ident, "flags": flags, "name": name, "type": qtype,
            "class": qclass, "records": records}


def recv_exact(sock: socket.socket, size: int, deadline: float) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("DNS TCP frame deadline exceeded")
        sock.settimeout(remaining)
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise EOFError("truncated DNS TCP frame")
        chunks.extend(chunk)
    return bytes(chunks)


def query(port: int, name: str, transport: str, timeout: float, qtype: int = 1) -> dict:
    ident = secrets.randbelow(65536)
    packet = struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", qtype, 1)
    start = time.monotonic()
    deadline = start + timeout
    if transport == "tcp":
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            length = struct.unpack("!H", recv_exact(sock, 2, deadline))[0]
            response = recv_exact(sock, length, deadline)
    elif transport == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect(("127.0.0.1", port))
            sock.send(packet)
            response = sock.recv(65535)
    else:
        raise ValueError(f"unsupported DNS transport: {transport}")
    elapsed = time.monotonic() - start
    parsed = parse_message(response)
    if parsed["id"] != ident or not parsed["flags"] & 0x8000:
        raise AssertionError("DNS transaction identity or response bit mismatch")
    if parsed["flags"] & 0x7A0F:
        raise AssertionError(f"DNS opcode/truncation/rcode error: {parsed['flags']:#x}")
    if (parsed["name"], parsed["type"], parsed["class"]) != (name.rstrip(".").lower(), qtype, 1):
        raise AssertionError("DNS response question mismatch")
    answers = [r for r in parsed["records"] if r["section"] == "answer" and r["type"] == qtype]
    if any(r["name"] != parsed["name"] or r["class"] != 1 for r in answers):
        raise AssertionError("DNS answer owner or class mismatch")
    return {"answers": [r["value"] for r in answers], "ttls": [r["ttl"] for r in answers],
            "latencySeconds": elapsed, "bytes": len(packet) + len(response)}


class DnsUpstream:
    """Thread-owned loopback fixture; counters count received valid questions."""

    def __init__(self, *, ttl: int = 60, delay: float = 0.0, timeout: float = 30.0):
        if not 0 < ttl <= 0xFFFFFFFF or delay < 0 or timeout <= 0:
            raise ValueError("DNS fixture requires positive TTL/timeout and nonnegative delay")
        self.ttl, self.delay, self.timeout = ttl, delay, timeout
        self.v4 = V4
        self.port = 0
        self._lock = threading.Lock()
        self._counts = Counter()
        self._errors = []
        self._stop = threading.Event()
        self._threads = []
        self._clients = set()
        self._udp = None
        self._tcp = None

    def __enter__(self):
        try:
            self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp.bind(("127.0.0.1", 0))
            self.port = self._tcp.getsockname()[1]
            self._tcp.listen(128)
            self._tcp.settimeout(0.1)
            self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp.bind(("127.0.0.1", self.port))
            self._udp.settimeout(0.1)
            self._spawn(self._udp_loop)
            self._spawn(self._tcp_loop)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _spawn(self, target, *args):
        thread = threading.Thread(target=target, args=args, daemon=True)
        with self._lock:
            self._threads.append(thread)
        thread.start()

    def snapshot(self) -> dict:
        with self._lock:
            return {"total": sum(self._counts.values()),
                    "udp": sum(n for (transport, _, _), n in self._counts.items() if transport == "udp"),
                    "tcp": sum(n for (transport, _, _), n in self._counts.items() if transport == "tcp"),
                    "questions": {f"{transport}/{name}/{qtype}": n for (transport, name, qtype), n in self._counts.items()},
                    "errors": list(self._errors)}

    def set_answer(self, *, v4: str, ttl: int):
        ipaddress.IPv4Address(v4)
        if not 0 < ttl <= 0xFFFFFFFF:
            raise ValueError("DNS fixture TTL must be positive")
        with self._lock:
            self.v4, self.ttl = v4, ttl

    def _answer(self, packet: bytes, transport: str) -> bytes:
        parsed = parse_message(packet)
        if parsed["flags"] & 0xF800 or parsed["class"] != 1:
            raise ValueError("fixture received invalid DNS query opcode/class")
        with self._lock:
            self._counts[(transport, parsed["name"], parsed["type"])] += 1
            ttl, delay, v4 = self.ttl, self.delay, self.v4
        if self._stop.wait(delay):
            return b""
        qtype = parsed["type"]
        question = encode_name(parsed["name"]) + struct.pack("!HH", qtype, 1)
        rdata = socket.inet_aton(v4) if qtype == 1 else socket.inet_pton(socket.AF_INET6, V6) if qtype == 28 else b""
        record = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata if rdata else b""
        opt = next((r for r in parsed["records"] if r["type"] == 41), None)
        additional = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0) if opt else b""
        return struct.pack("!6H", parsed["id"], 0x8080 | (parsed["flags"] & 0x0100), 1,
                           int(bool(rdata)), 0, int(bool(opt))) + question + record + additional

    def _error(self, error):
        if not self._stop.is_set():
            with self._lock:
                self._errors.append(f"{type(error).__name__}: {error}")

    def _udp_reply(self, packet, peer):
        try:
            response = self._answer(packet, "udp")
            if response:
                self._udp.sendto(response, peer)
        except (OSError, ValueError, UnicodeError) as error:
            self._error(error)

    def _udp_loop(self):
        while not self._stop.is_set():
            try:
                packet, peer = self._udp.recvfrom(65535)
                self._spawn(self._udp_reply, packet, peer)
            except socket.timeout:
                continue
            except OSError as error:
                self._error(error)
                return

    def _tcp_loop(self):
        while not self._stop.is_set():
            try:
                client, _ = self._tcp.accept()
                with self._lock:
                    self._clients.add(client)
                self._spawn(self._tcp_client, client)
            except socket.timeout:
                continue
            except OSError as error:
                self._error(error)
                return

    def _tcp_client(self, client):
        try:
            with client:
                while not self._stop.is_set():
                    deadline = time.monotonic() + self.timeout
                    client.settimeout(self.timeout)
                    first = client.recv(1)
                    if not first:
                        return
                    length = struct.unpack("!H", first + recv_exact(client, 1, deadline))[0]
                    response = self._answer(recv_exact(client, length, deadline), "tcp")
                    if response:
                        client.settimeout(max(0.001, deadline - time.monotonic()))
                        client.sendall(struct.pack("!H", len(response)) + response)
        except socket.timeout:
            pass  # An upstream connection may be pooled without another query.
        except (OSError, EOFError, ValueError, UnicodeError) as error:
            self._error(error)
        finally:
            with self._lock:
                self._clients.discard(client)

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        for sock in (self._udp, self._tcp):
            if sock is not None:
                sock.close()
        with self._lock:
            clients = list(self._clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        # Stop listener threads before taking the final worker roster.
        for thread in self._threads[:2]:
            thread.join(timeout=2)
        for thread in list(self._threads):
            thread.join(timeout=2)
        if any(thread.is_alive() for thread in self._threads) and exc_type is None:
            raise RuntimeError("DNS fixture worker did not stop")
