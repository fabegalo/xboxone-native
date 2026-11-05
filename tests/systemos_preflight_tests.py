# SPDX-License-Identifier: BSD-3-Clause
"""Identity/cohort/target gates using synthetic XVDs; no original Xbox content."""

import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile


INSPECTOR = Path(sys.argv.pop(1)).resolve()
TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
from study_update_zip import study
from systemos_preflight import assess, pinned_source


def image(content_type=2, revision=123, flags=1):
    data = bytearray(0xE00)
    data[0x200:0x208] = b"msft-xvd"
    struct.pack_into("<I", data, 0x20C, 3)
    struct.pack_into("<I", data, 0x208, flags)
    struct.pack_into("<I", data, 0x284, content_type)
    struct.pack_into("<Q", data, 0x3BC, revision)
    return data


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="xboxone_preflight_")
        self.root = Path(self.temporary.name).resolve()
        self.archive = self.root / "OSU1.zip"
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content_type, revision in (
                ("system", 2, 123), ("systemaux", 20, 123), ("host", 7, 123),
                ("ScarlettHost", 7, 123), ("nvmefw", 12, 123), ("uERA", 3, 42),
                ("SettingsTemplate", 13, 0),
            ):
                archive.writestr(f"$SystemUpdate/{name}.xvd", image(content_type, revision))
        self.reference = {"schema_version": 1, "sources": [study(self.archive, INSPECTOR, True, True)]}

    def tearDown(self):
        self.temporary.cleanup()

    def test_separate_scarlett_and_gameos_keep_archive(self):
        before = self.archive.read_bytes()
        fresh = pinned_source(self.archive, INSPECTOR, self.reference)
        plan = assess(fresh)
        self.assertEqual(plan["package_family"], "xbox_one_and_series_osu1")
        self.assertTrue(plan["contains_xbox_one_candidates"])
        self.assertFalse(plan["can_boot_original_dashboard"])
        selected = [entry["archive_member"] for entry in plan["systemos_inputs"]]
        self.assertEqual(selected, ["$SystemUpdate/system.xvd", "$SystemUpdate/systemaux.xvd"])
        self.assertEqual([entry["documented_mount_hint"] for entry in plan["systemos_inputs"]], ["C:\\", "X:\\"])
        codes = {blocker["code"] for blocker in plan["blockers"]}
        self.assertIn("encrypted_systemos_inputs", codes)
        self.assertNotIn("mixed_systemos_revisions", codes)  # uERA and templates are separate.
        self.assertEqual(self.archive.read_bytes(), before)
        self.assertFalse((self.root / "$SystemUpdate").exists())

    def test_archive_rename_uses_hash_identity(self):
        renamed = self.root / "OSU3.zip"
        shutil.copyfile(self.archive, renamed)  # Synthetic test ZIP only.
        plan = assess(pinned_source(renamed, INSPECTOR, self.reference))
        self.assertEqual(plan["reference_source_name"], "OSU1.zip")
        self.assertEqual(plan["package_family"], "xbox_one_and_series_osu1")

    def test_changed_zip_rejected(self):
        with self.archive.open("ab") as stream:
            stream.write(b"changed archive identity")
        with self.assertRaisesRegex(ValueError, "pinned identity"):
            pinned_source(self.archive, INSPECTOR, self.reference)

    def test_reference_cannot_override_fresh_encryption_flags(self):
        reference = copy.deepcopy(self.reference)
        reference["sources"][0]["files"][0]["inspection"]["volume_flags"] = 2
        with self.assertRaisesRegex(ValueError, "fresh probe"):
            pinned_source(self.archive, INSPECTOR, reference)

    def test_missing_member_hash_and_incomplete_study_rejected(self):
        reference = copy.deepcopy(self.reference)
        reference["sources"][0]["files"][0]["sha256"] = None
        with self.assertRaisesRegex(ValueError, "member SHA-256"):
            pinned_source(self.archive, INSPECTOR, reference)
        reference = copy.deepcopy(self.reference)
        reference["sources"][0]["complete"] = False
        with self.assertRaisesRegex(ValueError, "incomplete"):
            pinned_source(self.archive, INSPECTOR, reference)

    def test_revision_mismatch_and_unencrypted_flag_do_not_grant_boot(self):
        source = copy.deepcopy(self.reference["sources"][0])
        source["reference_source_name"] = "OSU1.zip"
        for entry in source["files"]:
            entry["inspection"]["volume_flags"] |= 2
            if entry["path"].endswith("/systemaux.xvd"):
                entry["inspection"]["package_version_raw"] += 1
        plan = assess(source)
        codes = {blocker["code"] for blocker in plan["blockers"]}
        self.assertIn("mixed_systemos_revisions", codes)
        self.assertNotIn("encrypted_systemos_inputs", codes)
        self.assertIn("original_shell_and_matching_resources_not_identified", codes)
        self.assertFalse(plan["can_boot_original_dashboard"])

    def test_unknown_layout_not_declared_disposable(self):
        source = copy.deepcopy(self.reference["sources"][0])
        source["reference_source_name"] = "unknown.zip"
        plan = assess(source)
        self.assertEqual(plan["package_family"], "unclassified")
        self.assertIsNone(plan["contains_xbox_one_candidates"])  # Unknown is not absence.

    def test_malformed_catalog_reports_invalid_input(self):
        reference_path = self.root / "reference.json"
        for malformed in ([], {"schema_version": 1, "sources": [None]}):
            reference_path.write_text(json.dumps(malformed), encoding="utf8")
            result = subprocess.run(
                [sys.executable, str(TOOLS / "systemos_preflight.py"), str(self.archive),
                 "--reference", str(reference_path), "--inspector", str(INSPECTOR)],
                capture_output=True, timeout=20,
            )
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b"Traceback", result.stderr)

    def test_cli_blocked_report_has_no_delete_candidates(self):
        reference_path = self.root / "reference.json"
        reference_path.write_text(json.dumps(self.reference), encoding="utf8")
        result = subprocess.run(
            [sys.executable, str(TOOLS / "systemos_preflight.py"), str(self.archive),
             "--reference", str(reference_path), "--inspector", str(INSPECTOR)],
            capture_output=True, timeout=20,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["diagnostic_completed"])
        self.assertFalse(report["can_boot_original_dashboard"])
        self.assertEqual(report["cleanup"]["delete_archives"], [])
        self.assertEqual(report["profiles"][0]["archive_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
