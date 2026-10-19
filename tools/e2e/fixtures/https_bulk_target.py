#!/usr/bin/env python3
"""TLS 1.3 bulk HTTP target for the vision interop scenarios.

GET returns a fixed 1,028,096-byte body (251 * 4096) so the runner can compare
a SHA-256 of the bytes that arrived through the proxy against the bytes this
target sent. POST hashes exactly the body it received and answers JSON with
the byte count and digest, so an upload can be verified the same way. The
listener picks its ECDH curve explicitly to keep the handshake shape stable.
Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = bytes(range(251)) * 4096


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(BODY)

    def do_POST(self) -> None:
        remaining = int(self.headers.get("Content-Length", "0"))
        if remaining > 4 * 1024 * 1024:
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
        body = json.dumps({"receivedBytes": received, "sha256": digest.hexdigest()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18083)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_ecdh_curve("X25519")
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
