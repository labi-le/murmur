#!/usr/bin/env python3
"""End-to-end VM runner for murmur.

Builds a throwaway NixOS/QEMU guest, stages the binary under test and a
reference binary plus synthetic fixtures into its shared directory, runs a
fixed battery of real protocol, routing and DNS scenarios inside the guest,
and writes results.json plus evidence to the output directory.

Offline by default: every controlled scenario talks only to process and
namespace endpoints created for it, needs neither a router nor a subscription,
and must pass for the command to exit 0. Passing --home adds one optional
comparison against real proxy nodes using the existing tools/diff_sweep.py.

Usage
-----
    python3 tools/e2e_vm.py \\
        --rust-bin /path/to/murmur \\
        --ref-bin /path/to/reference-binary \\
        [--home /path/to/private/config-home --group NAME --repeats 3] \\
        [--workdir /somewhere/to/keep/results]

Requires nix-build, ssh, ssh-keygen, openssl and /dev/kvm on the host, and a
Nix-built binary under test (the guest mounts the host /nix/store read-only,
so the binary's interpreter resolves). Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
E2E_SRC = REPO_ROOT / "tools" / "e2e"
DIFF_SWEEP_SRC = REPO_ROOT / "tools" / "diff_sweep.py"
GUEST_OUT = "/tmp/murmur-e2e/out"
GUEST_PYTHON = "/run/current-system/sw/bin/python3"
GUEST_PATH = "/run/current-system/sw/bin:/run/wrappers/bin:/usr/bin:/bin"

VM_NIX = """let
  pkgsPath = builtins.findFile builtins.nixPath "nixpkgs";
  system = import (pkgsPath + "/nixos") {
    configuration = { config, pkgs, lib, ... }: {
      imports = [ (pkgsPath + "/nixos/modules/virtualisation/qemu-vm.nix") ];
      system.stateVersion = "26.05";
      networking.hostName = "murmur-e2e";
      networking.firewall.enable = false;
      networking.useDHCP = true;
      services.openssh.enable = true;
      services.openssh.settings.PermitRootLogin = "prohibit-password";
      users.users.root.openssh.authorizedKeys.keys = [ "@PUBKEY@" ];
      documentation.enable = false;
      documentation.nixos.enable = false;
      environment.systemPackages = with pkgs; [ curl python3 bind iproute2 nftables iptables tcpdump ];
      virtualisation.graphics = false;
      virtualisation.memorySize = 1536;
      virtualisation.cores = 2;
      virtualisation.diskImage = null;
      virtualisation.sharedDirectories.test = { source = "@SHARE@"; target = "/mnt/test"; securityModel = "none"; };
      virtualisation.forwardPorts = [ { host.address = "127.0.0.1"; host.port = @PORT@; guest.port = 22; } ];
      virtualisation.qemu.options = [ "-enable-kvm" ];
    };
  };
in system.config.system.build.vm
"""


def which(name: str) -> str | None:
    return shutil.which(name)


def free_port() -> int:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def tail(path: Path, limit: int = 4000) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return "(no output)"
    return data[-limit:].decode("utf-8", errors="replace")


class Runner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.workdir = Path(args.workdir).resolve()
        if self.workdir.exists() and any(self.workdir.iterdir()):
            raise SystemExit(f"error: --workdir must be empty: {self.workdir}")
        self.workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.workdir.chmod(0o700)
        self.share = self.workdir / "share"
        self.key = self.workdir / "id_ed25519"
        self.known_hosts = self.workdir / "known_hosts"
        self.port = free_port()
        self.vm_proc: subprocess.Popen | None = None
        self.results: dict = {}
        self.error = ""
        self.guest_log = self.workdir / "guest-runner.log"
        self.vm_log = self.workdir / "vm-console.log"

    def require_host_tools(self) -> None:
        missing = [
            name
            for name in ("nix-build", "nix-store", "ssh", "ssh-keygen", "openssl", "tar")
            if which(name) is None
        ]
        if missing:
            raise SystemExit(f"error: required host tools missing from PATH: {', '.join(missing)}")
        if not os.path.exists("/dev/kvm") or not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise SystemExit("error: /dev/kvm is absent or not readable/writable; the VM needs KVM")
        for label, path in (("--rust-bin", Path(self.args.rust_bin)), ("--ref-bin", Path(self.args.ref_bin))):
            if not path.is_file() or not os.access(path, os.X_OK):
                raise SystemExit(f"error: {label} {path} is not an executable file")
        if self.args.home is not None and not (Path(self.args.home) / "config.yaml").is_file():
            raise SystemExit(f"error: --home {self.args.home} does not contain config.yaml")
        if which("nix-instantiate") is None:
            raise SystemExit("error: nix-instantiate is required to resolve nixpkgs from NIX_PATH")

    def stage(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        for path in (self.share / "bin", self.share / "certs", self.share / "e2e" / "fixtures"):
            path.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.args.rust_bin, self.share / "bin" / "murmur")
        shutil.copy2(self.args.ref_bin, self.share / "bin" / "reference")
        for source in sorted(E2E_SRC.glob("*")):
            if source.name == "__pycache__":
                continue
            target = self.share / "e2e" / source.name
            if source.is_dir():
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)
        shutil.copy2(DIFF_SWEEP_SRC, self.share / "e2e" / "diff_sweep.py")
        self.generate_certificates()
        self.verify_binaries()
        if self.args.home is not None:
            destination = self.share / "private-home"
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(self.args.home, destination)

    def verify_binaries(self) -> None:
        lines = []
        for label, path in (("--rust-bin", Path(self.args.rust_bin)), ("--ref-bin", Path(self.args.ref_bin))):
            interp = elf_interp(path)
            if not interp:
                lines.append(f"{label} {path}: statically linked or non-ELF; no interpreter needed")
                continue
            if not interp.startswith("/nix/store/"):
                raise SystemExit(
                    f"error: {label} {path} requests interpreter {interp}, which the guest cannot resolve; "
                    "the guest mounts only the host /nix/store, so build the binary with Nix"
                )
            if not os.path.exists(interp):
                raise SystemExit(f"error: {label} {path} interpreter {interp} is absent from the host store")
            closure = []
            result = subprocess.run(
                [which("nix-store"), "-qR", interp], capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                closure = result.stdout.split()
            lines.append(f"{label} {path}: interpreter {interp}; closure members {len(closure)}")
        (self.workdir / "closure.txt").write_text("\n".join(lines) + "\n")

    def generate_certificates(self) -> None:
        certs = self.share / "certs"
        cert, key = certs / "fixture-cert.pem", certs / "fixture-key.pem"
        if cert.exists() and key.exists():
            return
        subprocess.run(
            [
                which("openssl"),
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "2",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
        key.chmod(0o600)

    def generate_key(self) -> None:
        for path in (self.key, Path(f"{self.key}.pub")):
            path.unlink(missing_ok=True)
        subprocess.run(
            [which("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-f", str(self.key), "-C", "murmur-e2e"],
            check=True,
            capture_output=True,
            timeout=60,
        )

    def nixpkgs_path(self) -> str:
        result = subprocess.run(
            [which("nix-instantiate"), "--eval", "-E", 'builtins.findFile builtins.nixPath "nixpkgs"'],
            capture_output=True,
            text=True,
            timeout=120,
        )
        value = result.stdout.strip().strip('"')
        if result.returncode != 0 or not value.startswith("/nix/store/"):
            raise SystemExit(f"error: could not resolve nixpkgs from NIX_PATH: {result.stderr.strip()}")
        return value

    def build_vm(self) -> Path:
        self.nixpkgs_path()
        pubkey = Path(f"{self.key}.pub").read_text().strip()
        expression = (
            VM_NIX.replace("@PUBKEY@", pubkey)
            .replace("@SHARE@", str(self.share))
            .replace("@PORT@", str(self.port))
        )
        vm_nix = self.workdir / "vm.nix"
        vm_nix.write_text(expression)
        result = subprocess.run(
            [which("nix-build"), str(vm_nix), "-o", str(self.workdir / "vm-result")],
            capture_output=True,
            text=True,
            timeout=1800,
            cwd=str(self.workdir),
        )
        if result.returncode != 0:
            raise SystemExit(f"error: nix-build failed:\n{result.stdout}\n{result.stderr}")
        candidates = sorted((self.workdir / "vm-result" / "bin").glob("run-*-vm"))
        if not candidates:
            raise SystemExit(f"error: no run script under {self.workdir}/vm-result/bin")
        return candidates[0]

    def launch_vm(self, run_script: Path) -> None:
        vm_tmp = self.workdir / "vm-tmp"
        vm_tmp.mkdir(parents=True, exist_ok=True)
        environment = dict(os.environ)
        environment["TMPDIR"] = str(vm_tmp)
        environment["USE_TMPDIR"] = "1"
        log = open(self.vm_log, "wb")
        self.vm_proc = subprocess.Popen(
            [str(run_script)],
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=environment,
            cwd=str(self.workdir),
            start_new_session=True,
        )

    def ssh_argv(self, remote: str) -> list[str]:
        return [
            which("ssh"),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=4",
            "-i",
            str(self.key),
            "-p",
            str(self.port),
            "root@127.0.0.1",
            remote,
        ]

    def wait_ssh(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            if self.vm_proc is not None and self.vm_proc.poll() is not None:
                raise SystemExit(
                    f"error: VM exited during boot (code {self.vm_proc.returncode})\n{tail(self.vm_log)}"
                )
            result = subprocess.run(self.ssh_argv("true"), capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return
            last = result.stderr.strip()
            time.sleep(2)
        raise SystemExit(f"error: SSH on 127.0.0.1:{self.port} never became ready: {last}")

    def run_guest(self) -> int:
        command = (
            f"PATH={GUEST_PATH} {GUEST_PYTHON} /mnt/test/e2e/guest_runner.py"
            f" --rust-bin /mnt/test/bin/murmur --ref-bin /mnt/test/bin/reference"
            f" --share /mnt/test --out {GUEST_OUT}"
        )
        if self.args.home is not None:
            command += " --home /mnt/test/private-home"
        if self.args.group:
            command += f" --group {shlex.quote(self.args.group)}"
        command += f" --repeats {self.args.repeats}"
        with open(self.guest_log, "wb") as log:
            result = subprocess.run(
                self.ssh_argv(command),
                stdout=log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                timeout=self.args.runner_timeout,
            )
        return result.returncode

    def fetch_results(self) -> None:
        evidence = self.workdir / "evidence"
        evidence.mkdir(parents=True, exist_ok=True)
        remote = f"tar -C {GUEST_OUT} -cf - ."
        ssh_proc = subprocess.Popen(self.ssh_argv(remote), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        tar_proc = subprocess.Popen(
            ["tar", "-xf", "-", "-C", str(evidence)],
            stdin=ssh_proc.stdout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if ssh_proc.stdout is not None:
            ssh_proc.stdout.close()
        tar_proc.wait(timeout=300)
        ssh_proc.wait(timeout=60)
        guest_results = evidence / "results.json"
        if guest_results.is_file():
            self.results = json.loads(guest_results.read_text())

    def merge_results(self, exit_code: int) -> None:
        payload = self.results or {"scenarios": [], "summary": {}, "exitCode": 1}
        digest = {}
        for label, path in (("rust", self.args.rust_bin), ("reference", self.args.ref_bin)):
            entry = {"path": str(path), "sha256": ""}
            try:
                entry["sha256"] = sha256_file(Path(path))
            except OSError:
                pass
            digest[label] = entry
        try:
            nixpkgs = self.nixpkgs_path()
        except (SystemExit, subprocess.SubprocessError):
            nixpkgs = ""
        payload["host"] = {
            "workdir": str(self.workdir),
            "vmConsoleLog": str(self.vm_log),
            "guestRunnerLog": str(self.guest_log),
            "sshPort": self.port,
            "nixpkgs": nixpkgs,
            "binaries": digest,
            "error": self.error,
            "exitCode": exit_code,
        }
        payload["exitCode"] = exit_code
        payload["error"] = self.error or payload.get("error", "")
        (self.workdir / "results.json").write_text(json.dumps(payload, indent=2, sort_keys=True))

    def cleanup(self) -> None:
        if self.vm_proc is not None and self.vm_proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.vm_proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self.vm_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.vm_proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    self.vm_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        for path in (self.key, Path(f"{self.key}.pub"), self.known_hosts):
            path.unlink(missing_ok=True)
        shutil.rmtree(self.share / "private-home", ignore_errors=True)

    def print_summary(self, exit_code: int) -> None:
        scenarios = self.results.get("scenarios", [])
        for scenario in scenarios:
            print(f"[{scenario.get('status')}] {scenario.get('name')}: {scenario.get('detail', '')}")
        summary = self.results.get("summary", {})
        print(f"summary: {summary}")
        print(f"results: {self.workdir / 'results.json'}")
        print(f"evidence: {self.workdir / 'evidence'}")
        if self.error:
            print(f"error: {self.error}", file=sys.stderr)
        print(f"exit: {exit_code}")


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def elf_interp(path: Path) -> str:
    with path.open("rb") as handle:
        header = handle.read(64)
        if header[:4] != b"\x7fELF" or header[4] != 2:
            return ""
        endian = "<" if header[5] == 1 else ">"
        phoff = struct.unpack_from(endian + "Q", header, 32)[0]
        phentsize = struct.unpack_from(endian + "H", header, 54)[0]
        phnum = struct.unpack_from(endian + "H", header, 56)[0]
        for index in range(phnum):
            handle.seek(phoff + index * phentsize)
            entry = handle.read(phentsize)
            if struct.unpack_from(endian + "I", entry, 0)[0] != 3:
                continue
            offset = struct.unpack_from(endian + "Q", entry, 8)[0]
            size = struct.unpack_from(endian + "Q", entry, 32)[0]
            handle.seek(offset)
            return handle.read(size).split(b"\x00")[0].decode("utf-8", errors="replace")
    return ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="e2e_vm.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--rust-bin", required=True, type=Path, help="Nix-built murmur binary under test")
    parser.add_argument("--ref-bin", required=True, type=Path, help="reference binary")
    parser.add_argument("--home", type=Path, default=None, help="private config home for the optional real-node sweep")
    parser.add_argument("--group", default=None, help="proxy group for the real-node sweep")
    parser.add_argument("--repeats", type=int, default=3, help="probes per node per side in the real-node sweep")
    parser.add_argument("--workdir", type=Path, default=None, help="output directory (default: a fresh mkdtemp)")
    parser.add_argument("--ssh-timeout", type=float, default=600.0, help="seconds to wait for SSH after launch")
    parser.add_argument("--runner-timeout", type=float, default=5400.0, help="seconds allowed for the whole guest run")
    parser.add_argument("--remove-workdir", action="store_true", help="delete the output directory on success")
    return parser.parse_args()


def main(argv: list[str]) -> int:
    args = parse_args()
    if args.workdir is None:
        import tempfile

        args.workdir = Path(tempfile.mkdtemp(prefix="murmur-e2e-vm-"))
    runner = Runner(args)
    exit_code = 1
    interrupted = {"signal": 0}

    def handle_signal(signum, _frame):
        interrupted["signal"] = signum
        raise KeyboardInterrupt

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, handle_signal)

    try:
        runner.require_host_tools()
        runner.stage()
        runner.generate_key()
        run_script = runner.build_vm()
        runner.launch_vm(run_script)
        runner.wait_ssh(args.ssh_timeout)
        guest_code = runner.run_guest()
        runner.fetch_results()
        if not runner.results:
            runner.error = "guest runner produced no results.json"
        exit_code = 0 if guest_code == 0 and runner.results.get("exitCode") == 0 else 1
    except KeyboardInterrupt:
        exit_code = 128 + interrupted["signal"]
        runner.error = f"interrupted by signal {interrupted['signal']}"
    except SystemExit as error:
        runner.error = str(error)
        print(str(error), file=sys.stderr)
    except subprocess.TimeoutExpired as error:
        runner.error = f"timeout: {error}"
        print(runner.error, file=sys.stderr)
    except Exception as error:  # noqa: BLE001 - report any orchestration failure with the output directory
        runner.error = f"{type(error).__name__}: {error}"
        print(runner.error, file=sys.stderr)
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if not runner.results:
            try:
                runner.fetch_results()
            except Exception:  # noqa: BLE001 - a dead VM cannot yield results; the logs stand as evidence
                pass
        try:
            runner.cleanup()
        finally:
            runner.merge_results(exit_code)
            runner.print_summary(exit_code)

    if exit_code == 0 and args.remove_workdir:
        shutil.rmtree(runner.workdir, ignore_errors=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
