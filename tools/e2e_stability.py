#!/usr/bin/env python3
"""Native end-to-end stability suite for murmur's outbound and inbound protocols.

In the default outbound direction the suite runs on one Linux host and talks
only to process endpoints it starts itself: a reference proxy server with one
listener per protocol, a target HTTP and HTTPS server, a DNS upstream, and a
murmur client.  It then drives repeated bulk downloads and uploads, mid-stream
cancellations, idle keep-alive requests and SOCKS5 UDP associations through
every protocol, restarts the reference server, and checks that each protocol
recovers.

With ``--direction inbound`` the roles swap: murmur runs the listeners, the
reference binary runs the client, and the restart phase restarts murmur.  Both
directions use the same protocol matrix and the same checks.

Unlike tools/e2e_vm.py this needs no VM, namespaces, root or network access.  It
is intended to run on the build machine next to the cargo slot; tools/e2e-pc
builds the binary there and invokes this script.

Usage
-----
    python3 tools/e2e_stability.py \\
        --rust-bin /path/to/murmur \\
        --ref-bin /path/to/reference-proxy \\
        [--cycles 2] [--protocols vless-vision,vmess-ws] \\
        [--direction outbound|inbound] \\
        [--workdir /path/to/empty/dir] [--skip-restart] [--keep]

``--ref-bin`` must be a proxy binary that can serve every protocol as a
listener (mihomo is the reference used by this repository).  The script exits
non-zero when a required check fails.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tools" / "e2e" / "fixtures"
CERT_NAME = "e2e.test"
UUID = "11111111-1111-1111-1111-111111111111"
PASSWORD = "e2e-password"
BULK = bytes(range(251)) * 4096
BULK_SHA = hashlib.sha256(BULK).hexdigest()
UPLOAD = bytes(range(251)) * 1024
UPLOAD_SHA = hashlib.sha256(UPLOAD).hexdigest()
UDP_ANSWER = socket.inet_aton("203.0.113.9")
HTTP_BODY = b"http target reached\n"


def free_port(udp: bool = False) -> int:
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    sock = socket.socket(socket.AF_INET, kind)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def wait_tcp(port: int, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def wait_udp(port: int, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        while time.monotonic() < deadline:
            try:
                probe.sendto(b"\x00", ("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.1)
        return False
    finally:
        probe.close()


def wait_api(port: int, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _ = api(port, "GET", "/version")
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


def api(port: int, method: str, path: str, body: dict | None = None) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        payload = None if body is None else json.dumps(body).encode()
        headers = {} if payload is None else {"Content-Type": "application/json"}
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def select(port: int, name: str) -> None:
    status, payload = api(port, "PUT", "/proxies/TEST", {"name": name})
    if status != 204:
        raise RuntimeError(f"select {name} on {port}: status={status} body={payload[:200]!r}")


def close_connections(port: int) -> None:
    try:
        api(port, "DELETE", "/connections")
    except Exception:
        pass


class Managed:
    def __init__(self, name: str, command: list[str], cwd: Path, log: Path) -> None:
        self.name = name
        self.command = command
        self.cwd = cwd
        self.log = log
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        log = self.log.open("ab")
        try:
            self.process = subprocess.Popen(
                self.command,
                cwd=self.cwd,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            log.close()

    def stop(self) -> None:
        process = self.process
        if process is None:
            return
        self.process = None
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def tail(self, limit: int = 6000) -> str:
        try:
            return self.log.read_text(errors="replace")[-limit:]
        except OSError:
            return ""


class Curl:
    def __init__(self, proxy: int) -> None:
        self.proxy = proxy

    def run(
        self,
        url: str,
        *,
        output: Path | None = None,
        data: Path | None = None,
        max_time: float = 30.0,
        limit_rate: str | None = None,
        extra: list[str] | None = None,
    ) -> dict:
        destination = output or Path("/dev/null")
        command = [
            "curl", "--noproxy", "", "-x", f"http://127.0.0.1:{self.proxy}",
            "--silent", "--show-error", "--output", str(destination),
            "--write-out", "%{http_code} %{size_download}",
            "--connect-timeout", "8", "--max-time", str(max_time),
        ]
        if url.startswith("https://"):
            command.append("-k")
        if data is not None:
            command += ["--data-binary", f"@{data}", "-H", "Content-Type: application/octet-stream"]
        if limit_rate is not None:
            command += ["--limit-rate", limit_rate]
        command += extra or []
        command.append(url)
        started = time.monotonic()
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=max_time + 8)
            fields = process.stdout.split()
            return {
                "exit": process.returncode,
                "status": fields[0] if fields else "",
                "bytes": int(fields[1]) if len(fields) > 1 else 0,
                "seconds": round(time.monotonic() - started, 3),
                "error": process.stderr.strip(),
                "output": destination,
            }
        except subprocess.TimeoutExpired:
            return {
                "exit": 124,
                "status": "",
                "bytes": 0,
                "seconds": round(time.monotonic() - started, 3),
                "error": "curl process timeout",
                "output": destination,
            }


def body_matches(result: dict, expected: bytes) -> bool:
    if result["exit"] != 0 or result["status"] != "200" or result["bytes"] != len(expected):
        return False
    path = Path(result["output"])
    return path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == hashlib.sha256(expected).hexdigest()


def control_body_matches(result: dict, expected: bytes) -> bool:
    return body_matches(result, expected)


def dns_query(identifier: int) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in "e2e.test".split("."))
    return struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)


def read_exact(sock: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise OSError("short SOCKS reply")
        chunks.extend(chunk)
    return bytes(chunks)


def socks_udp_association(proxy_port: int, target_port: int, count: int, timeout: float = 2.0) -> list[bool]:
    control = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    control.settimeout(timeout)
    udp = None
    results: list[bool] = []
    try:
        control.sendall(b"\x05\x01\x00")
        if read_exact(control, 2) != b"\x05\x00":
            return [False] * count
        control.sendall(b"\x05\x03\x00\x01" + b"\x00\x00\x00\x00" + struct.pack("!H", 0))
        reply = read_exact(control, 4)
        if reply[0] != 5 or reply[1] != 0:
            return [False] * count
        atyp = reply[3]
        if atyp == 1:
            host = socket.inet_ntoa(read_exact(control, 4))
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, read_exact(control, 16))
        elif atyp == 3:
            length = read_exact(control, 1)[0]
            host = read_exact(control, length).decode("ascii", "replace")
        else:
            return [False] * count
        port = struct.unpack("!H", read_exact(control, 2))[0]
        if host in {"0.0.0.0", "::"}:
            host = "127.0.0.1"
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        destination = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port)
        # A new UDP association can be accepted before its relay session is ready; the first
        # datagram then disappears. Warm the association up and retry once, then measure the
        # established session. A path that is actually broken still fails the measured datagrams.
        warmed = False
        for attempt in range(2):
            try:
                udp.sendto(destination + dns_query(0), (host, port))
                udp.recvfrom(65535)
                warmed = True
                break
            except OSError:
                if attempt == 0:
                    time.sleep(0.2)
        if not warmed:
            return [False] * count
        for identifier in range(1, count + 1):
            query = dns_query(identifier)
            try:
                udp.sendto(destination + query, (host, port))
                payload, _ = udp.recvfrom(65535)
                answer = payload[10:] if len(payload) >= 10 else b""
                results.append(
                    len(payload) >= 10
                    and payload[3] == 1
                    and len(answer) >= len(query) + 4
                    and answer[-4:] == UDP_ANSWER
                )
            except OSError:
                results.append(False)
                results.extend([False] * (count - len(results)))
                break
        return results
    except OSError:
        return [False] * count
    finally:
        if udp is not None:
            udp.close()
        control.close()


def keepalive_probe(proxy_port: int, target_port: int, idle: float, count: int = 3) -> tuple[bool, str]:
    connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
    try:
        for index in range(count):
            connection.request(
                "GET",
                f"http://127.0.0.1:{target_port}/",
                headers={"Host": f"127.0.0.1:{target_port}", "Connection": "keep-alive"},
            )
            response = connection.getresponse()
            body = response.read()
            if response.status != 200 or body != HTTP_BODY:
                return False, f"request {index}: status={response.status} body={body!r}"
            if index + 1 < count:
                time.sleep(idle)
        return True, f"{count} requests over one connection with {idle:g}s idle"
    except Exception as error:
        return False, repr(error)
    finally:
        connection.close()


def make_cert(workdir: Path) -> tuple[Path, Path]:
    cert, key = workdir / "cert.pem", workdir / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "2",
            "-subj", f"/CN={CERT_NAME}",
            "-addext", f"subjectAltName=DNS:{CERT_NAME},IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert, key


def protocol_entries(ports: "Ports", cert: Path, key: Path, reality: tuple[str, str]) -> list[dict]:
    private, public = reality
    cert_opts = {"certificate": str(cert), "private-key": str(key)}
    entries: list[dict] = []

    def add(
        name: str,
        listener: dict,
        client: dict,
        udp: bool = True,
        inbound: bool = True,
        inbound_udp: bool = True,
    ) -> None:
        listener = {"name": name, "listen": "127.0.0.1", **listener}
        client = {"name": name, "server": "127.0.0.1", "port": listener["port"], **client}
        entries.append({
            "name": name,
            "listener": listener,
            "client": client,
            "udp": udp,
            "inbound": inbound,
            "inbound_udp": inbound_udp,
        })

    def vless(
        name: str,
        *,
        flow: str = "",
        network: str = "tcp",
        transport: dict | None = None,
        reality_config: dict | None = None,
        reality_opts: dict | None = None,
        packet_encoding: str = "xudp",
        inbound_udp: bool = False,
    ) -> None:
        port = ports.tcp()
        listener = {
            "type": "vless",
            "port": port,
            "users": [{"username": "e2e", "uuid": UUID, **({"flow": flow} if flow else {})}],
        }
        client = {
            "type": "vless",
            "uuid": UUID,
            "tls": True,
            "servername": CERT_NAME,
            "skip-cert-verify": True,
            "network": network,
            "udp": True,
        }
        if packet_encoding:
            client["packet-encoding"] = packet_encoding
        if flow:
            client["flow"] = flow
        if transport:
            listener.update(transport["listener"])
            client.update(transport["client"])
        if reality_config is not None:
            listener["reality-config"] = reality_config
            client["reality-opts"] = reality_opts
            client["client-fingerprint"] = "chrome"
        else:
            listener.update(cert_opts)
        # The inbound Vision path is hardcoded to TlsConnCheck::Unsupported (the erased server
        # conn exposes no downcast), so an inbound Vision listener fails closed by design.
        # VLESS clients carrying UDP in xudp/mux (mihomo's default) send the mux command, which the
        # listener does not implement yet (`handle_mux_connection` names the missing sing-vmess
        # crate); the `vless-packetaddr` row exercises the COMMAND_UDP path instead. Vision has no
        # inbound path at all.
        add(name, listener, client, inbound=not flow, inbound_udp=inbound_udp)

    def vmess(name: str, network: str, transport: dict | None = None) -> None:
        port = ports.tcp()
        listener = {
            "type": "vmess",
            "port": port,
            "users": [{"username": "e2e", "uuid": UUID, "alterId": 0}],
            **cert_opts,
        }
        client = {
            "type": "vmess",
            "uuid": UUID,
            "alterId": 0,
            "cipher": "auto",
            "tls": True,
            "servername": CERT_NAME,
            "skip-cert-verify": True,
            "network": network,
            "udp": True,
        }
        if transport:
            listener.update(transport["listener"])
            client.update(transport["client"])
        add(name, listener, client)

    def trojan(name: str, network: str, transport: dict | None = None) -> None:
        port = ports.tcp()
        listener = {
            "type": "trojan",
            "port": port,
            "users": [{"username": "e2e", "password": PASSWORD}],
            **cert_opts,
        }
        client = {
            "type": "trojan",
            "password": PASSWORD,
            "sni": CERT_NAME,
            "skip-cert-verify": True,
            "network": network,
            "udp": True,
        }
        if transport:
            listener.update(transport["listener"])
            client.update(transport["client"])
        add(name, listener, client)

    ws = lambda path: {"listener": {"ws-path": path}, "client": {"ws-opts": {"path": path}}}
    grpc = lambda service: {
        "listener": {"grpc-service-name": service},
        "client": {"grpc-opts": {"grpc-service-name": service}},
    }
    xhttp = lambda mode: {
        "listener": {"xhttp-config": {"path": "/xhttp", "mode": mode}},
        "client": {"xhttp-opts": {"path": "/xhttp", "mode": mode}},
    }

    vless("vless-vision", flow="xtls-rprx-vision")
    vless("vless-tcp", packet_encoding="")
    vless("vless-packetaddr", packet_encoding="packetaddr", inbound_udp=True)
    vless("vless-ws", network="ws", transport=ws("/vlws"))
    vless("vless-grpc", network="grpc", transport=grpc("VlessGun"))
    vless("vless-xhttp-packet-up", network="xhttp", transport=xhttp("packet-up"))
    vless("vless-xhttp-stream-up", network="xhttp", transport=xhttp("stream-up"))
    vless("vless-xhttp-stream-one", network="xhttp", transport=xhttp("stream-one"))

    reality_config = {
        "dest": f"127.0.0.1:{ports.https_target}",
        "private-key": private,
        "short-id": ["0123456789abcdef"],
        "server-names": [CERT_NAME],
    }
    reality_opts = {"public-key": public, "short-id": "0123456789abcdef"}
    vless(
        "vless-reality-vision",
        flow="xtls-rprx-vision",
        reality_config=reality_config,
        reality_opts=reality_opts,
    )
    vless(
        "vless-reality-xhttp-packet-up",
        network="xhttp",
        transport=xhttp("packet-up"),
        reality_config=reality_config,
        reality_opts=reality_opts,
    )
    vless(
        "vless-reality-grpc",
        network="grpc",
        transport=grpc("RealityGun"),
        reality_config=reality_config,
        reality_opts=reality_opts,
    )

    vmess("vmess-ws", "ws", ws("/vmess"))
    vmess("vmess-grpc", "grpc", grpc("VmessGun"))
    vmess("vmess-tcp", "tcp")

    trojan("trojan", "tcp")
    trojan("trojan-ws", "ws", ws("/tjws"))
    trojan("trojan-grpc", "grpc", grpc("TrojanGun"))

    for name, cipher in (("ss-chacha20", "chacha20-ietf-poly1305"), ("ss-aes256", "aes-256-gcm")):
        port = ports.tcp()
        add(
            name,
            {"type": "shadowsocks", "port": port, "password": PASSWORD, "cipher": cipher, "udp": True},
            {"type": "ss", "password": PASSWORD, "cipher": cipher, "udp": True},
        )

    port = ports.tcp()
    add(
        "snell-v4",
        {"type": "snell", "port": port, "psk": PASSWORD, "version": 4, "udp": True},
        {"type": "snell", "psk": PASSWORD, "version": 4, "udp": True},
    )

    port = ports.tcp()
    add(
        "anytls",
        {"type": "anytls", "port": port, "users": {"e2e": PASSWORD}, **cert_opts},
        {"type": "anytls", "password": PASSWORD, "sni": CERT_NAME, "skip-cert-verify": True, "udp": True},
    )

    port = ports.udp()
    add(
        "hysteria2",
        {
            "type": "hysteria2", "port": port, "users": {"e2e": PASSWORD}, **cert_opts,
            "up": "200 Mbps", "down": "200 Mbps",
        },
        {
            "type": "hysteria2", "password": PASSWORD, "sni": CERT_NAME, "skip-cert-verify": True,
            "up": "200 Mbps", "down": "200 Mbps",
        },
    )

    port = ports.udp()
    add(
        "tuic",
        {"type": "tuic", "port": port, "users": {UUID: PASSWORD}, **cert_opts, "alpn": ["h3"]},
        {
            "type": "tuic", "uuid": UUID, "password": PASSWORD, "sni": CERT_NAME,
            "skip-cert-verify": True, "alpn": ["h3"], "congestion-controller": "bbr",
            "udp-relay-mode": "native",
        },
    )

    return entries


class Ports:
    def __init__(self) -> None:
        self.used: set[int] = set()
        self.https_target = free_port()
        self.abort_target = free_port()
        self.http_target = free_port()
        self.dns = free_port(udp=True)
        self.used.update((self.https_target, self.abort_target, self.http_target, self.dns))

    def _pick(self, udp: bool) -> int:
        for _ in range(500):
            port = free_port(udp)
            if port not in self.used:
                self.used.add(port)
                return port
        raise RuntimeError("cannot allocate a free port")

    def tcp(self) -> int:
        return self._pick(False)

    def udp(self) -> int:
        return self._pick(True)


def check(record: dict, name: str, ok: bool, detail: str) -> None:
    record["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
    status = "ok" if ok else "FAIL"
    print(f"    {name}: {status} {detail}", flush=True)


def bulk_checks(record: dict, label: str, curl: Curl, target: int, threads: int) -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        results = list(
            pool.map(
                lambda index: curl.run(
                    f"https://127.0.0.1:{target}/",
                    output=Path(record["artifacts"]) / f"{label}-{index}.bin",
                    max_time=40,
                ),
                range(threads),
            )
        )
    passed = sum(body_matches(result, BULK) for result in results)
    check(record, f"{label}_downloads", passed == threads, f"{passed}/{threads} exact {len(BULK)}-byte bodies")

    upload_path = Path(record["artifacts"]) / f"{label}-upload.bin"
    upload_path.write_bytes(UPLOAD)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        uploads = list(
            pool.map(
                lambda index: curl.run(
                    f"https://127.0.0.1:{target}/",
                    output=Path(record["artifacts"]) / f"{label}-upload-{index}.json",
                    data=upload_path,
                    max_time=40,
                ),
                range(threads),
            )
        )
    reported = 0
    for result in uploads:
        try:
            payload = json.loads(Path(result["output"]).read_text())
        except (OSError, ValueError):
            continue
        if payload.get("receivedBytes") == len(UPLOAD) and payload.get("sha256") == UPLOAD_SHA:
            reported += 1
    check(record, f"{label}_uploads", reported == threads, f"{reported}/{threads} {len(UPLOAD)}-byte uploads with matching digest")


def abort_check(record: dict, label: str, curl: Curl, target: int, api_port: int, threads: int) -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [
            pool.submit(
                curl.run,
                f"https://127.0.0.1:{target}/",
                output=Path(record["artifacts"]) / f"{label}-abort-{index}.bin",
                max_time=20,
            )
            for index in range(threads)
        ]
        time.sleep(1.5)
        close_connections(api_port)
        attempts = [future.result() for future in futures]
    partial = sum(0 < attempt["bytes"] < len(BULK) for attempt in attempts)
    check(record, f"{label}_aborted", partial == threads, f"{partial}/{threads} streams were mid-body when the controller closed them")

    recovery = curl.run(f"https://127.0.0.1:{target}/", output=Path(record["artifacts"]) / f"{label}-recovery.bin", max_time=30)
    check(record, f"{label}_recovery", body_matches(recovery, BULK), f"exit={recovery['exit']} status={recovery['status']} bytes={recovery['bytes']} error={recovery['error'][:120]}")


def udp_checks(record: dict, proxy: int, dns_port: int, expected: bool) -> None:
    if not expected:
        check(record, "udp", True, "not applicable")
        return
    first = socks_udp_association(proxy, dns_port, 20)
    check(record, "udp_long_session", all(first), f"{sum(first)}/20 answers in one association")
    reconnects: list[bool] = []
    for _ in range(4):
        reconnects.extend(socks_udp_association(proxy, dns_port, 5))
    check(record, "udp_reconnects", all(reconnects), f"{sum(reconnects)}/20 answers across 4 associations")


def run_protocol(
    record: dict,
    entry: dict,
    *,
    murmur: int,
    api_port: int,
    control: int | None,
    control_api: int | None,
    https_target: int,
    abort_target: int,
    http_target: int,
    dns_port: int,
    cycles: int,
    idle: float,
) -> None:
    curl = Curl(murmur)
    select(api_port, entry["name"])
    for cycle in range(cycles):
        label = f"cycle{cycle + 1}"
        result = curl.run(f"https://127.0.0.1:{https_target}/", output=Path(record["artifacts"]) / f"{label}-handshake.bin", max_time=30)
        check(record, f"{label}_handshake", body_matches(result, BULK), f"exit={result['exit']} status={result['status']} bytes={result['bytes']} error={result['error'][:120]}")
        if not body_matches(result, BULK):
            break
        bulk_checks(record, label, curl, https_target, 4)
        abort_check(record, label, curl, abort_target, api_port, 4)

    idle_ok, idle_detail = keepalive_probe(murmur, http_target, idle)
    check(record, "idle_keepalive", idle_ok, idle_detail)
    udp_checks(record, murmur, dns_port, entry["udp"])

    if control is not None and control_api is not None:
        try:
            select(control_api, entry["name"])
            control_curl = Curl(control)
            result = control_curl.run(
                f"https://127.0.0.1:{https_target}/",
                output=Path(record["artifacts"]) / "control.bin",
                max_time=30,
            )
            record["control_ok"] = body_matches(result, BULK)
            record["control_detail"] = f"status={result['status']} bytes={result['bytes']} exit={result['exit']}"
        except Exception as error:
            record["control_ok"] = False
            record["control_detail"] = repr(error)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rust-bin", required=True, type=Path, help="murmur binary under test")
    parser.add_argument("--ref-bin", required=True, type=Path, help="reference proxy binary used as the protocol server and control client")
    parser.add_argument(
        "--workdir",
        type=Path,
        default=None,
        help="empty directory for configs, logs and artifacts; use a local filesystem (inotify watches on sshfs/NFS can stall TLS listeners)",
    )
    parser.add_argument("--protocols", default="", help="comma-separated subset of protocol names")
    parser.add_argument(
        "--direction",
        choices=("outbound", "inbound"),
        default="outbound",
        help="outbound: murmur client against reference listeners; inbound: murmur listeners against the reference client",
    )
    parser.add_argument("--cycles", type=int, default=2, help="bulk/abort cycles per protocol (default 2)")
    parser.add_argument("--idle", type=float, default=3.0, help="seconds between keep-alive requests")
    parser.add_argument("--skip-restart", action="store_true", help="skip the server restart/reconnect phase")
    parser.add_argument(
        "--quic-restart-grace",
        type=float,
        default=35.0,
        help="seconds to wait before retrying Hysteria2/TUIC after a silent server restart (default 35, above the 30s QUIC idle timeout)",
    )
    parser.add_argument("--keep", action="store_true", help="keep the working directory on success")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    for name, path in (("--rust-bin", args.rust_bin), ("--ref-bin", args.ref_bin)):
        if not os.access(path, os.X_OK):
            print(f"error: {name} {path} is not executable", file=sys.stderr)
            return 2

    workdir = args.workdir
    if workdir is None:
        workdir = Path(f"/tmp/murmur-e2e-stability-{os.getpid()}")
    workdir = workdir.resolve()
    if workdir.exists() and any(workdir.iterdir()):
        print(f"error: --workdir must be empty: {workdir}", file=sys.stderr)
        return 2
    workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    workdir.chmod(0o700)
    artifacts = workdir / "artifacts"
    artifacts.mkdir()
    logs = workdir / "logs"
    logs.mkdir()

    ports = Ports()
    cert, key = make_cert(workdir)
    reality_private = subprocess.run(
        [str(args.ref_bin), "generate", "reality-keypair"],
        capture_output=True, text=True, check=True,
    ).stdout
    private = next(line.split(":", 1)[1].strip() for line in reality_private.splitlines() if line.startswith("PrivateKey:"))
    public = next(line.split(":", 1)[1].strip() for line in reality_private.splitlines() if line.startswith("PublicKey:"))
    entries = protocol_entries(ports, cert, key, (private, public))
    if args.protocols:
        wanted = {name.strip() for name in args.protocols.split(",") if name.strip()}
        unknown = wanted - {entry["name"] for entry in entries}
        if unknown:
            print(f"error: unknown protocols: {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        entries = [entry for entry in entries if entry["name"] in wanted]
    if args.direction == "inbound":
        # Inbound Vision is documented unsupported; the outbound direction still exercises it.
        entries = [entry for entry in entries if entry.get("inbound", True)]

    server_api = ports.tcp()
    murmur_api = ports.tcp()
    control_api = ports.tcp()
    proxies = [entry["client"] for entry in entries]
    common_client = {
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [{"name": "TEST", "type": "select", "proxies": [proxy["name"] for proxy in proxies]}],
        "rules": ["MATCH,TEST"],
    }
    if args.direction == "outbound":
        server_config = {
            "mode": "rule",
            "log-level": "info",
            "allow-lan": False,
            "external-controller": f"127.0.0.1:{server_api}",
            "listeners": [entry["listener"] for entry in entries],
            "rules": ["MATCH,DIRECT"],
        }
        murmur_config = {"mixed-port": ports.tcp(), "external-controller": f"127.0.0.1:{murmur_api}", **common_client}
        control_config = {"mixed-port": ports.tcp(), "external-controller": f"127.0.0.1:{control_api}", **common_client}
    else:
        # Murmur is the server under test; the reference binary is the traffic client.
        murmur_config = {
            "mode": "rule",
            "log-level": "info",
            "external-controller": f"127.0.0.1:{murmur_api}",
            "listeners": [entry["listener"] for entry in entries],
            "rules": ["MATCH,DIRECT"],
        }
        server_config = {"mixed-port": ports.tcp(), "external-controller": f"127.0.0.1:{server_api}", **common_client}
        control_config = None

    (workdir / "server.yaml").write_text(json.dumps(server_config, indent=1))
    (workdir / "murmur.yaml").write_text(json.dumps(murmur_config, indent=1))
    if control_config is not None:
        (workdir / "control.yaml").write_text(json.dumps(control_config, indent=1))

    server = Managed(
        "server",
        [str(args.ref_bin), "-d", str(workdir), "-f", str(workdir / "server.yaml")],
        workdir,
        logs / "server.log",
    )
    murmur = Managed(
        "murmur",
        [str(args.rust_bin), "-d", str(workdir / "murmur-state"), "-f", str(workdir / "murmur.yaml")],
        workdir,
        logs / "murmur.log",
    )
    control = None
    if control_config is not None:
        control = Managed(
            "control",
            [str(args.ref_bin), "-d", str(workdir / "control-state"), "-f", str(workdir / "control.yaml")],
            workdir,
            logs / "control.log",
        )
    targets = [
        Managed(
            "https-target",
            [sys.executable, str(FIXTURES / "https_bulk_target.py"), "--port", str(ports.https_target), "--cert", str(cert), "--key", str(key)],
            workdir,
            logs / "https-target.log",
        ),
        Managed(
            "abort-target",
            [
                sys.executable, str(FIXTURES / "https_bulk_target.py"),
                "--port", str(ports.abort_target), "--cert", str(cert), "--key", str(key),
                "--rate", "131072",
            ],
            workdir,
            logs / "abort-target.log",
        ),
        Managed(
            "http-target",
            [sys.executable, str(FIXTURES / "http_target.py"), "--port", str(ports.http_target), "--keep-alive"],
            workdir,
            logs / "http-target.log",
        ),
        Managed(
            "dns-target",
            [sys.executable, str(FIXTURES / "dns_upstream.py"), "--port", str(ports.dns)],
            workdir,
            logs / "dns-target.log",
        ),
    ]

    results: dict = {"workdir": str(workdir), "protocols": [], "started": time.time()}
    exit_code = 0
    try:
        for target in targets:
            target.start()
        if not (
            wait_tcp(ports.https_target)
            and wait_tcp(ports.abort_target)
            and wait_tcp(ports.http_target)
            and wait_udp(ports.dns)
        ):
            raise RuntimeError("target fixtures did not become ready")

        if args.direction == "outbound":
            server.start()
            if not wait_api(server_api, 30):
                raise RuntimeError("reference server did not answer its controller")
            for entry in entries:
                listener = entry["listener"]
                if listener["type"] in {"hysteria2", "tuic"}:
                    time.sleep(0.5)
                elif not wait_tcp(listener["port"], 15):
                    raise RuntimeError(f"listener {entry['name']} did not open {listener['port']}")
            server_log = server.tail()
            if "listen err" in server_log:
                raise RuntimeError(f"reference server reported a listener error:\n{server_log}")

            murmur.start()
            if not wait_api(murmur_api, 30):
                raise RuntimeError("murmur did not answer its controller")
            control.start()
            control_ready = wait_api(control_api, 30)
        else:
            murmur.start()
            if not wait_api(murmur_api, 30):
                raise RuntimeError("murmur did not answer its controller")
            for entry in entries:
                listener = entry["listener"]
                if listener["type"] in {"hysteria2", "tuic"}:
                    time.sleep(0.5)
                elif not wait_tcp(listener["port"], 15):
                    raise RuntimeError(f"murmur listener {entry['name']} did not open {listener['port']}")
            murmur_log = murmur.tail()
            if "listen err" in murmur_log:
                raise RuntimeError(f"murmur reported a listener error:\n{murmur_log}")

            server.start()
            if not wait_api(server_api, 30):
                raise RuntimeError("reference client did not answer its controller")
            control_ready = False

        if args.direction == "outbound":
            traffic_port = murmur_config["mixed-port"]
            traffic_api = murmur_api
            control_port = control_config["mixed-port"] if control_ready else None
            control_api_port = control_api if control_ready else None
        else:
            traffic_port = server_config["mixed-port"]
            traffic_api = server_api
            control_port = None
            control_api_port = None

        print(f"workdir {workdir}", flush=True)
        print(f"direction {args.direction}", flush=True)
        print(f"targets https={ports.https_target} abort={ports.abort_target} http={ports.http_target} dns={ports.dns}", flush=True)
        for entry in entries:
            if args.direction == "inbound" and not entry.get("inbound_udp", True):
                entry = {**entry, "udp": False}
            print(f"\n[{entry['name']}]", flush=True)
            record = {
                "name": entry["name"],
                "type": entry["client"]["type"],
                "artifacts": str(artifacts / entry["name"]),
                "checks": [],
            }
            Path(record["artifacts"]).mkdir(parents=True, exist_ok=True)
            try:
                run_protocol(
                    record,
                    entry,
                    murmur=traffic_port,
                    api_port=traffic_api,
                    control=control_port,
                    control_api=control_api_port,
                    https_target=ports.https_target,
                    abort_target=ports.abort_target,
                    http_target=ports.http_target,
                    dns_port=ports.dns,
                    cycles=args.cycles,
                    idle=args.idle,
                )
            except Exception as error:
                check(record, "runner", False, repr(error))
            record["passed"] = all(item["ok"] for item in record["checks"])
            results["protocols"].append(record)
            (workdir / "results.json").write_text(json.dumps(results, indent=2))
            if not record["passed"]:
                exit_code = 1

        if not args.skip_restart:
            if args.direction == "outbound":
                restart_process, restart_api = server, server_api
            else:
                restart_process, restart_api = murmur, murmur_api
            print(f"\n[restart {restart_process.name}]", flush=True)
            restart_process.stop()
            time.sleep(1)
            restart_process.start()
            if not wait_api(restart_api, 30):
                raise RuntimeError(f"{restart_process.name} did not answer after restart")
            time.sleep(1)
            restart_results = []
            for entry in entries:
                try:
                    select(traffic_api, entry["name"])
                    result = Curl(traffic_port).run(
                        f"https://127.0.0.1:{ports.https_target}/",
                        output=artifacts / f"{entry['name']}-restart.bin",
                        max_time=30,
                    )
                    ok = body_matches(result, BULK)
                    detail = f"exit={result['exit']} status={result['status']} bytes={result['bytes']} error={result['error'][:100]}"
                    if not ok and entry["client"]["type"] in {"hysteria2", "tuic"} and args.quic_restart_grace > 0:
                        # A silent QUIC peer death is only visible when the idle timer expires. The
                        # reference client needs the same window, so a delayed recovery is still a
                        # recovery; a second failure is real.
                        time.sleep(args.quic_restart_grace)
                        select(traffic_api, entry["name"])
                        retry = Curl(traffic_port).run(
                            f"https://127.0.0.1:{ports.https_target}/",
                            output=artifacts / f"{entry['name']}-restart-retry.bin",
                            max_time=30,
                        )
                        if body_matches(retry, BULK):
                            ok = True
                            detail += f" (recovered after {args.quic_restart_grace:g}s QUIC grace)"
                        else:
                            detail += (
                                f" (retry after {args.quic_restart_grace:g}s: exit={retry['exit']}"
                                f" status={retry['status']} bytes={retry['bytes']} error={retry['error'][:100]})"
                            )
                except Exception as error:
                    ok, detail = False, repr(error)
                restart_results.append({"name": entry["name"], "ok": ok, "detail": detail})
                print(f"    {entry['name']}: {'ok' if ok else 'FAIL'} {detail}", flush=True)
                if not ok:
                    exit_code = 1
            results["restart"] = restart_results
            (workdir / "results.json").write_text(json.dumps(results, indent=2))
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        print(f"server log:\n{server.tail()}", file=sys.stderr)
        print(f"murmur log:\n{murmur.tail()}", file=sys.stderr)
        exit_code = 1
    finally:
        processes = [murmur, server, *targets]
        if control is not None:
            processes.append(control)
        if not args.keep and exit_code == 0:
            for process in processes:
                process.stop()
        else:
            for process in processes:
                process.stop()
            print(f"logs kept in {workdir / 'logs'}")

    summary: dict[str, int] = {}
    for check_item in (item for record in results["protocols"] for item in record["checks"]):
        summary["passed" if check_item["ok"] else "failed"] = summary.get("passed" if check_item["ok"] else "failed", 0) + 1
    print(f"\nsummary: {summary.get('passed', 0)} passed, {summary.get('failed', 0)} failed")
    for record in results["protocols"]:
        if not record["passed"]:
            failed = [item["name"] for item in record["checks"] if not item["ok"]]
            print(f"  {record['name']}: {', '.join(failed)}")
            if record.get("control_ok"):
                print(f"    reference control passed: {record.get('control_detail')}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
