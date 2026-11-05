# SPDX-License-Identifier: BSD-3-Clause
"""Only repository-owned synthetic code; no OSUs, Microsoft payloads or GUI."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

CLI, COMPONENT, EVIDENCE = map(lambda s: Path(s).resolve(), sys.argv[1:4])
del sys.argv[1:]


def quote(text):
    return '"' + str(text).replace('\\', '\\\\').replace('"', '\\"') + '"'


def manifest(component):
    sha = hashlib.sha256(component.read_bytes()).hexdigest()
    return (f'xboxone-systemos-v1\nprofile "owned-synthetic" "synthetic-1" synthetic "{sha}"\n'
            'entry "entry"\n'
            f'artifact "entry" "synthetic-1" {quote(component.as_posix())} "{sha}" executable "repository-owned source"\n'
            'bind "entry" "kernel32.dll" "host:kernel32" "documented Windows API used by owned test"\n')


class BootstrapCLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xboxone_bootstrap_cli_")
        self.root = Path(self.temp.name)
        self.profile = self.root / "profile.txt"
        self.profile.write_text(manifest(COMPONENT), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, *args):
        return subprocess.run([str(CLI), *map(str, args)], capture_output=True, encoding="utf-8", timeout=10)

    def test_run_and_record_owned_execution(self):
        result = self.run_cli("run", self.profile, "5000")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["stage"], "exited")
        self.assertGreater(report["process_id"], 0)
        self.assertTrue(report["primary_thread_resumed"])
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["declared_origin"], "synthetic")
        self.assertFalse(report["dashboard_boot_verified"])
        self.assertEqual(report["authentic_frames_observed"], 0)
        self.assertEqual(report["dependencies"][0]["status"], "host_exports_verified")
        self.assertEqual(report["entry_sha256"], hashlib.sha256(COMPONENT.read_bytes()).hexdigest())
        EVIDENCE.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        EVIDENCE.with_suffix(".manifest").write_text(manifest(COMPONENT), encoding="utf-8")

    def test_prepare_does_not_execute(self):
        result = self.run_cli("prepare", self.profile)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["stage"], "prepared")
        self.assertEqual(report["process_id"], 0)
        self.assertIsNone(report["exit_code"])

    def test_hash_mismatch_is_blocked(self):
        text = manifest(COMPONENT).replace(hashlib.sha256(COMPONENT.read_bytes()).hexdigest(), "0" * 64)
        self.profile.write_text(text, encoding="utf-8")
        result = self.run_cli("run", self.profile)
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["process_id"], 0)
        self.assertIn("hash_mismatch", [d["code"] for d in report["diagnostics"]])

    def test_unicode_path(self):
        own_copy = self.root / "componente_próprio_测试.exe"
        shutil.copyfile(COMPONENT, own_copy)  # Owned synthetic bytes only.
        self.profile.write_text(manifest(own_copy), encoding="utf-8")
        result = self.run_cli("run", self.profile)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_invalid_timeout(self):
        for value in ("0", "60001", "-1", "10x"):
            self.assertEqual(self.run_cli("run", self.profile, value).returncode, 2)

    def test_missing_and_malformed_manifest(self):
        self.assertEqual(self.run_cli("prepare", self.root / "missing").returncode, 2)
        self.profile.write_text('xboxone-systemos-v1\nprofile invalid\n', encoding="utf-8")
        self.assertEqual(self.run_cli("prepare", self.profile).returncode, 2)

    def test_unknown_service_does_not_succeed(self):
        with self.profile.open("a", encoding="utf-8") as out:
            out.write('service "test-broker" xbox_broker "synthetic missing contract"\n')
        result = self.run_cli("run", self.profile)
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["process_id"], 0)
        self.assertIn("service_adapter_missing", [d["code"] for d in report["diagnostics"]])


if __name__ == "__main__":
    unittest.main()
