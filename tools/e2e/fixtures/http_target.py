#!/usr/bin/env python3
"""Plain HTTP target with a fixed, assertable body. Standard library only."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    body = b"http target reached\n"

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, fmt: str, *args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--listen", default="127.0.0.1", help="address to bind; the supplied-router scenario needs a VM-local address it assigned to lo")
    parser.add_argument("--body", default="http target reached\n")
    parser.add_argument(
        "--keep-alive",
        action="store_true",
        help="answer with HTTP/1.1 keep-alive instead of closing after each response",
    )
    args = parser.parse_args()
    Handler.body = args.body.encode()
    if args.keep_alive:
        Handler.protocol_version = "HTTP/1.1"
    ThreadingHTTPServer((args.listen, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
