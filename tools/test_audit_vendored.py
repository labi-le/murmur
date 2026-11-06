#!/usr/bin/env python3
"""Offline regression tests for vendored dependency advisory coverage."""
import copy
import importlib.util
import json
import pathlib
import shutil
import subprocess
import tempfile
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("audit_vendored", ROOT / "tools/audit_vendored.py")


class ProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SPEC.origin or not pathlib.Path(SPEC.origin).exists():
            raise AssertionError("vendored advisory projection is not implemented")
        cls.module = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.module)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="murmur-audit-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copy2(ROOT / name, self.root / name)
        shutil.copytree(ROOT / "vendor/rustls", self.root / "vendor/rustls")
        shutil.copytree(ROOT / "vendor/test-ca", self.root / "vendor/test-ca")

    def test_projection_restores_only_upstream_identity_without_changing_input(self):
        before = (self.root / "Cargo.lock").read_bytes()
        projected = tomllib.loads(self.module.project_lock(self.root))
        original = tomllib.loads(before.decode())
        expected = copy.deepcopy(original)
        rustls = next(p for p in expected["package"] if p["name"] == "rustls")
        rustls.update(source=self.module.SOURCE, checksum=self.module.CHECKSUM)
        self.assertEqual(projected, expected)
        self.assertEqual((self.root / "Cargo.lock").read_bytes(), before)

    def test_rejects_version_source_duplicate_and_checksum_drift(self):
        lock = (self.root / "Cargo.lock").read_text()
        marker = 'name = "rustls"\nversion = "0.23.46"'
        for replacement in (
            'name = "rustls"\nversion = "0.23.47"',
            marker + '\nsource = "registry+https://github.com/rust-lang/crates.io-index"',
            marker + '\nchecksum = "wrong"',
        ):
            with self.subTest(replacement=replacement):
                (self.root / "Cargo.lock").write_text(lock.replace(marker, replacement))
                with self.assertRaises(ValueError):
                    self.module.project_lock(self.root)
        (self.root / "Cargo.lock").write_text(lock + '\n[[package]]\n' + marker + '\n')
        with self.assertRaises(ValueError):
            self.module.project_lock(self.root)

    def test_rejects_root_patch_and_vendor_source_drift(self):
        manifest = self.root / "Cargo.toml"
        original = manifest.read_text()
        manifest.write_text(original.replace('path = "vendor/rustls"', 'path = "elsewhere"'))
        with self.assertRaises(ValueError):
            self.module.project_lock(self.root)
        manifest.write_text(original)
        source = self.root / "vendor/rustls/src/msgs/deframer/buffers.rs"
        source.write_text(source.read_text() + '\n// drift\n')
        with self.assertRaises(ValueError):
            self.module.project_lock(self.root)

    def test_rejects_provenance_archive_checksum_drift(self):
        path = self.root / "vendor/rustls/provenance.json"
        data = json.loads(path.read_text())
        data["archive_sha256"] = "0" * 64
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.module.project_lock(self.root)

    def test_rejects_sibling_fixture_mutation_and_inventory_changes(self):
        fixture = next(p for p in (self.root / "vendor/test-ca").rglob("*") if p.is_file())
        original = fixture.read_bytes()
        fixture.write_bytes(original + b"changed")
        with self.assertRaises(ValueError):
            self.module.project_lock(self.root)
        fixture.write_bytes(original)
        extra = self.root / "vendor/test-ca/unreviewed"
        extra.write_text("unexpected")
        with self.assertRaises(ValueError):
            self.module.project_lock(self.root)
        extra.unlink()
        fixture.unlink()
        with self.assertRaises(ValueError):
            self.module.project_lock(self.root)

    def test_main_propagates_either_audit_failure_and_cleans_projected_lock(self):
        # Exercise CLI process status, not a mock of subprocess.run.
        for original, supplemental in ((7, 0), (0, 9), (0, 0)):
            with self.subTest(original=original, supplemental=supplemental):
                fake = self.root / "cargo.py"
                record = self.root / "calls.jsonl"
                record.unlink(missing_ok=True)
                fake.write_text(
                    "import json,pathlib,sys\n"
                    f"record=pathlib.Path({str(record)!r})\n"
                    "args=sys.argv[1:]\n"
                    "with record.open('a') as f: f.write(json.dumps(args)+'\\n')\n"
                    f"raise SystemExit({supplemental} if '--file' in args else {original})\n"
                )
                result = subprocess.run(["python3", str(ROOT / "tools/audit_vendored.py"), "--cargo", "python3 " + str(fake)], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, original or supplemental, result.stderr)
                calls = [json.loads(line) for line in record.read_text().splitlines()]
                self.assertEqual(len(calls), 2)
                self.assertEqual(calls[0], ["audit"])
                self.assertEqual(calls[1][:2], ["audit", "--file"])
                self.assertFalse(pathlib.Path(calls[1][2]).exists())


class InstalledAuditTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cargo-audit"), "cargo-audit required for installed-tool sentinel")
    def test_path_source_blind_spot_is_closed_by_registry_projection(self):
        with tempfile.TemporaryDirectory(prefix="murmur-audit-sentinel-") as temp:
            root = pathlib.Path(temp)
            (root / "db/crates/rustls").mkdir(parents=True)
            (root / "db/crates/rustls/RUSTSEC-2099-0001.md").write_text('''```toml
[advisory]
id = "RUSTSEC-2099-0001"
package = "rustls"
date = "2026-01-01"
[versions]
patched = [">=0.23.1"]
```
# Synthetic local audit regression

Test-only advisory; never used by production auditing.
''')
            findings = []
            for source in ("", '\nsource = "registry+https://github.com/rust-lang/crates.io-index"'):
                lock = root / "Cargo.lock"
                lock.write_text('version = 4\n[[package]]\nname = "rustls"\nversion = "0.23.0"' + source + '\n')
                result = subprocess.run(["cargo", "audit", "--no-fetch", "--no-yanked", "--db", str(root / "db"), "--file", str(lock), "--json"], cwd=root, capture_output=True, text=True, timeout=30)
                report = json.loads(result.stdout)
                findings.append((result.returncode, report["vulnerabilities"]["count"]))
            self.assertEqual(findings, [(0, 0), (1, 1)])


if __name__ == "__main__":
    unittest.main()
