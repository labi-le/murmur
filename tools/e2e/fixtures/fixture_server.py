#!/usr/bin/env python3
"""Synthetic Trojan and VLESS servers driven by tools/e2e_vm.py.

These are controlled, test-only endpoints. They use a synthetic UUID and a
synthetic password, terminate TLS 1.3 at each listener, speak just enough of
the Trojan/VLESS request layout to answer a single HTTP request, and append a
JSON line to an events file describing what each accepted connection carried
(protocol, curve, vision flow, destination, HTTP status). The runner reads
that file to assert which protocol and flow the binary under test selected,
not merely that some connection succeeded.

Ports are fixed so the generated client configs can address them:

    11001  Trojan, TLS 1.3 with an X25519 key share
    11002  Trojan, TLS 1.3 pinned to P-256 (forces HelloRetryRequest)
    11003  VLESS,  TLS 1.3 with an X25519 key share

Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import ssl
import struct
import threading
import uuid

PASSWORD_HASH = hashlib.sha224(b"e2e-synthetic-password").hexdigest().encode()
USER_ID = uuid.UUID("d7f8a3c5-1b2d-4e6f-8a90-123456789abc").bytes
BODY = b"diagnostic fixture reached\n"
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

PORTS = [(11001, "trojan", "X25519"), (11002, "trojan", "prime256v1"), (11003, "vless", "X25519")]

LOG_LOCK = threading.Lock()
EVENTS_PATH = "fixture-events.jsonl"


def record(**event: object) -> None:
    line = json.dumps(event, sort_keys=True)
    with LOG_LOCK:
        with open(EVENTS_PATH, "a", encoding="utf-8") as output:
            output.write(line + "\n")


def exact(stream, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise EOFError(f"EOF after {len(result)} of {count} bytes")
        result.extend(chunk)
    return bytes(result)


def address(stream, protocol: str) -> str:
    kind = exact(stream, 1)[0]
    if kind == 1:
        return socket.inet_ntop(socket.AF_INET, exact(stream, 4))
    if kind == (2 if protocol == "vless" else 3):
        return exact(stream, exact(stream, 1)[0]).decode()
    if kind == (3 if protocol == "vless" else 4):
        return socket.inet_ntop(socket.AF_INET6, exact(stream, 16))
    raise ValueError(f"unsupported address type {kind}")


def request_headers(stream, prefix: bytes = b"") -> bytes:
    data = bytearray(prefix)
    while b"\r\n\r\n" not in data:
        if len(data) > 65536:
            raise ValueError("HTTP request exceeds fixture limit")
        data.extend(exact(stream, 1))
    if not data.startswith((b"GET ", b"POST ")):
        raise ValueError("unexpected HTTP request method")
    return bytes(data)


def handle(stream, protocol: str, port: int) -> None:
    vision = False
    if protocol == "trojan":
        if exact(stream, 56) != PASSWORD_HASH or exact(stream, 2) != b"\r\n":
            raise ValueError("Trojan authentication failed")
        if exact(stream, 1) != b"\x01":
            raise ValueError("Trojan command is not TCP")
        destination = address(stream, protocol)
        destination_port = struct.unpack("!H", exact(stream, 2))[0]
        if exact(stream, 2) != b"\r\n":
            raise ValueError("Trojan address delimiter missing")
    else:
        if exact(stream, 1) != b"\x00" or exact(stream, 16) != USER_ID:
            raise ValueError("VLESS version or UUID mismatch")
        addons = exact(stream, exact(stream, 1)[0])
        vision = b"xtls-rprx-vision" in addons
        if exact(stream, 1) != b"\x01":
            raise ValueError("VLESS command is not TCP")
        destination_port = struct.unpack("!H", exact(stream, 2))[0]
        destination = address(stream, protocol)

    if vision:
        payload = bytearray()
        first = True
        while b"\r\n\r\n" not in payload:
            if first:
                if exact(stream, 16) != USER_ID:
                    raise ValueError("Vision UUID mismatch")
                first = False
            _, content_length, padding_length = struct.unpack("!BHH", exact(stream, 5))
            payload.extend(exact(stream, content_length))
            exact(stream, padding_length)
            if len(payload) > 65536:
                raise ValueError("Vision payload exceeds fixture limit")
        request_headers(stream, bytes(payload))
    else:
        request_headers(stream)

    response = (
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(BODY)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + BODY
    )
    if protocol == "vless":
        prefix = b"\x00\x00"
        if vision:
            prefix += USER_ID + struct.pack("!BHH", 1, len(response), 0)
        response = prefix + response
    stream.sendall(response)
    record(
        port=port,
        protocol=protocol,
        vision=vision,
        destination=destination,
        destinationPort=destination_port,
        httpStatus=200,
    )


def serve(port: int, protocol: str, curve: str | None, cert: str, key: str) -> None:
    context = None
    if curve is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_ecdh_curve(curve)
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols(["http/1.1"])

        def handshake_message(connection, direction, version, content_type, message_type, data):
            if int(content_type) == 22 and direction == "write" and int(message_type) == 2:
                record(port=port, helloRetryRequest=data[6:38] == HRR_RANDOM)
            if int(content_type) == 22 and direction == "read" and int(message_type) == 1:
                record(port=port, clientHello=True)

        context._msg_callback = handshake_message

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen()
    record(port=port, ready=True, protocol=protocol, curve=curve)

    def connection(client) -> None:
        with client:
            client.settimeout(10)
            try:
                if context is None:
                    handle(client, protocol, port)
                else:
                    with context.wrap_socket(client, server_side=True) as secured:
                        handle(secured, protocol, port)
            except Exception as error:  # noqa: BLE001 - per-connection fixture must not die
                record(port=port, protocol=protocol, error=type(error).__name__, message=str(error))

    while True:
        client, _ = listener.accept()
        threading.Thread(target=connection, args=(client,), daemon=True).start()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True, help="TLS certificate path")
    parser.add_argument("--key", required=True, help="TLS private key path")
    parser.add_argument("--events", required=True, help="JSONL file to append connection records to")
    return parser.parse_args()


def main() -> None:
    global EVENTS_PATH
    args = parse_args()
    EVENTS_PATH = args.events
    for port, protocol, curve in PORTS:
        threading.Thread(
            target=serve, args=(port, protocol, curve, args.cert, args.key), daemon=True
        ).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()
