#!/usr/bin/env python3
"""Controlled DNS upstream for the fake-IP scenarios.

Answers every A query with 203.0.113.9 and every AAAA query with 2001:db8::9,
so the runner can tell a real-IP answer (the upstream value) apart from a
fake-IP answer (a 198.18.1.0/24 address minted by the resolver). It serves UDP
and TCP, and echoes an EDNS OPT record when the query carries one, so it stays
usable whichever transport the resolver picks. No external resolver, router or
DNS server is involved. Standard library only.
"""

from __future__ import annotations

import argparse
import socket
import struct
import threading

V4 = "203.0.113.9"
V6 = "2001:db8::9"


def question_end(message: bytes) -> int:
    offset = 12
    for _ in range(struct.unpack("!H", message[4:6])[0]):
        while offset < len(message) and message[offset] != 0:
            offset += message[offset] + 1
        offset += 5
    return offset


def answer(query: bytes) -> bytes:
    end = question_end(query)
    qtype = struct.unpack("!H", query[end - 4 : end - 2])[0]
    header = bytearray(query[:12])
    header[2] = 0x81
    header[3] = 0x80
    if qtype == 1:
        rdata, rtype, count = socket.inet_aton(V4), 1, 1
    elif qtype == 28:
        rdata, rtype, count = socket.inet_pton(socket.AF_INET6, V6), 28, 1
    else:
        rdata, rtype, count = b"", qtype, 0
    struct.pack_into("!H", header, 6, count)
    record = b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
    additional = b""
    if struct.unpack("!H", query[10:12])[0]:
        struct.pack_into("!H", header, 10, 1)
        additional = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)
    return bytes(header) + query[12:end] + record + additional


def udp_loop(sock: socket.socket) -> None:
    while True:
        query, peer = sock.recvfrom(65535)
        if len(query) >= 12:
            sock.sendto(answer(query), peer)


def tcp_loop(listener: socket.socket) -> None:
    while True:
        connection, _ = listener.accept()
        with connection:
            try:
                header = connection.recv(2)
                if len(header) != 2:
                    continue
                query = b""
                remaining = struct.unpack("!H", header)[0]
                while remaining:
                    chunk = connection.recv(remaining)
                    if not chunk:
                        break
                    query += chunk
                    remaining -= len(chunk)
                if len(query) >= 12:
                    response = answer(query)
                    connection.sendall(struct.pack("!H", len(response)) + response)
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5453)
    args = parser.parse_args()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(("127.0.0.1", args.port))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", args.port))
    tcp.listen()
    threading.Thread(target=tcp_loop, args=(tcp,), daemon=True).start()
    print("dns upstream listening", flush=True)
    udp_loop(udp)


if __name__ == "__main__":
    main()
