#!/usr/bin/env python3
"""HTTP and UDP echo endpoints living inside the target network namespace.

The HTTP listener is bound to the address the transparent rule matches, and
the UDP echo returns the exact payload to the exact sender, so the runner can
assert that TPROXY preserved the original source address. Standard library
only.
"""

from __future__ import annotations

import argparse
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"transparent target reached\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, fmt: str, *args: object) -> None:
        pass


def udp_echo(address: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, port))
    while True:
        payload, peer = sock.recvfrom(65535)
        sock.sendto(payload, peer)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", default="149.154.160.10")
    parser.add_argument("--http-port", type=int, default=18080)
    parser.add_argument("--udp-port", type=int, default=53535)
    args = parser.parse_args()
    threading.Thread(target=udp_echo, args=(args.address, args.udp_port), daemon=True).start()
    ThreadingHTTPServer((args.address, args.http_port), Handler).serve_forever()


if __name__ == "__main__":
    main()
