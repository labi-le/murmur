#!/usr/bin/env python3
"""UDP echo probe run from the LAN namespace.

Sends 1-, 127- and 1200-byte datagrams through the transparent rule and
asserts that each comes back byte-identical from the original target address
and port. Prints one JSON object to stdout. Standard library only.
"""

from __future__ import annotations

import json
import socket


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(8)
    results = []
    for size in (1, 127, 1200):
        payload = bytes(i % 251 for i in range(size))
        sock.sendto(payload, ("149.154.160.10", 53535))
        data, sender = sock.recvfrom(65535)
        results.append(
            {
                "bytes": size,
                "payloadEqual": data == payload,
                "sender": list(sender),
                "senderCorrect": sender == ("149.154.160.10", 53535),
            }
        )
    print(json.dumps(results))


if __name__ == "__main__":
    main()
