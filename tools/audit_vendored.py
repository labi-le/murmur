#!/usr/bin/env python3
"""Audit the original lock and registry identities hidden by local source patches."""
import argparse
import hashlib
import json
import pathlib
import re
import shlex
import subprocess
import tempfile
import tomllib

SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUM = "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf"
VERSION = "0.23.46"
REVISION = "f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb"
# Reviewed deframer storage reuse and portable 64-bit atomics in the test-CA example.
PATCH_SHA256 = "14291371e8dd3015add15249edbe9b41b6fd44611e56604718b407abd97cfc9a"


def require(condition, message):
    if not condition:
        raise ValueError(message + "; update the reviewed vendor provenance and audit policy together")


def project_lock(root):
    """Return an audit-only lock; never change Cargo's actual source selection."""
    root = pathlib.Path(root)
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    require(manifest.get("patch", {}).get("crates-io", {}).get("rustls") == {"path": "vendor/rustls"}, "unexpected rustls root patch")
    vendor = root / "vendor/rustls"
    require(not vendor.is_symlink(), "vendored rustls must not be a symlink")
    package = tomllib.loads((vendor / "Cargo.toml").read_text())["package"]
    require((package["name"], package["version"]) == ("rustls", VERSION), "unexpected rustls vendor package identity")
    provenance = json.loads((vendor / "provenance.json").read_text())
    require((provenance.get("name"), provenance.get("version"), provenance.get("source"), provenance.get("archive_sha256"), provenance.get("upstream_revision")) == ("rustls", VERSION, SOURCE, CHECKSUM, REVISION), "unexpected rustls upstream provenance")
    hashes = provenance.get("files")
    require(isinstance(hashes, dict) and bool(hashes), "missing rustls source hash inventory")
    require(provenance.get("patch") == "murmur.patch" and hashes.get("murmur.patch") == PATCH_SHA256, "unexpected rustls reviewed patch")
    actual = {str(p.relative_to(vendor)) for p in vendor.rglob("*") if p.is_file() and p != vendor / "provenance.json"}
    require(actual == set(hashes), "rustls vendor file inventory changed")
    for name, digest in hashes.items():
        path = pathlib.PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts, "invalid vendor inventory path")
        source = vendor / path
        require(not source.is_symlink() and source.resolve().is_relative_to(vendor.resolve()), "vendor source escapes reviewed directory")
        require(hashlib.sha256(source.read_bytes()).hexdigest() == digest, "rustls source hash mismatch: " + name)
    fixtures = root / "vendor/test-ca"
    require(fixtures.is_dir() and not fixtures.is_symlink(), "missing or symlinked upstream test-ca directory")
    fixture_hashes = provenance.get("test_ca_files")
    require(isinstance(fixture_hashes, dict) and bool(fixture_hashes), "missing upstream test-ca hash inventory")
    actual_fixtures = {str(p.relative_to(fixtures)) for p in fixtures.rglob("*") if p.is_file()}
    require(actual_fixtures == set(fixture_hashes), "upstream test-ca file inventory changed")
    for name, digest in fixture_hashes.items():
        path = pathlib.PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts, "invalid test-ca inventory path")
        source = fixtures / path
        require(not source.is_symlink() and source.resolve().is_relative_to(fixtures.resolve()), "test-ca source escapes reviewed directory")
        require(hashlib.sha256(source.read_bytes()).hexdigest() == digest, "upstream test-ca hash mismatch: " + name)
    text = (root / "Cargo.lock").read_text()
    lock = tomllib.loads(text)
    selected = [p for p in lock["package"] if p["name"] == "rustls"]
    require(len(selected) == 1, "expected exactly one rustls lock entry")
    package = selected[0]
    require(package["version"] == VERSION and "source" not in package and "checksum" not in package, "unexpected rustls path lock identity")
    # Parse every selected stanza, so formatting or an unrelated version cannot redirect the insertion.
    chunks = re.split(r"(?m)^\[\[package\]\]\s*$", text)
    matches = [i for i in range(1, len(chunks)) if tomllib.loads("[[package]]" + chunks[i])["package"][0]["name"] == "rustls"]
    require(len(matches) == 1, "ambiguous rustls lock stanza")
    index = matches[0]
    chunks[index], count = re.subn(r'(?m)^version = "0\.23\.46"$', 'version = "' + VERSION + '"\nsource = "' + SOURCE + '"\nchecksum = "' + CHECKSUM + '"', chunks[index])
    require(count == 1, "unsupported rustls lock formatting")
    projected = "[[package]]".join(chunks)
    expected = tomllib.loads(text)
    next(p for p in expected["package"] if p["name"] == "rustls").update(source=SOURCE, checksum=CHECKSUM)
    require(tomllib.loads(projected) == expected, "audit projection changed unrelated dependencies")
    return projected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo", help="Cargo command, matching Makefile CARGO")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    try:
        projected = project_lock(root)
        cargo = shlex.split(args.cargo)
        require(bool(cargo), "empty Cargo command")
        # Keep existing audit config/ignores, yanked checks and database freshness policy.
        original = subprocess.run([*cargo, "audit"], cwd=root, check=False).returncode
        with tempfile.TemporaryDirectory(prefix="murmur-vendor-audit-") as temp:
            lock = pathlib.Path(temp) / "Cargo.lock"
            lock.write_text(projected)
            supplemental = subprocess.run([*cargo, "audit", "--file", str(lock)], cwd=root, check=False).returncode
        return original or supplemental
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"vendored dependency audit failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
