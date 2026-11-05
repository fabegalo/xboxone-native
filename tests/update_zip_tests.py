# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic archive adapter and CLI contracts; no Microsoft inputs."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zipfile


inspector = Path(sys.argv[1]).resolve()
adapter = Path(__file__).resolve().parents[1] / "tools" / "study_update_zip.py"


def run(*args, **kwargs):
    return subprocess.run([str(inspector), *map(str, args)], capture_output=True, timeout=15, **kwargs)


def require(value, message):
    if not value:
        raise AssertionError(message)


with tempfile.TemporaryDirectory(prefix="xboxone_zip_tests_") as temporary:
    root = Path(temporary).resolve()  # macOS temp aliases may contain /var symlinks.
    prefix = bytearray(0xE00)
    prefix[0x200:0x208] = b"msft-xvd"
    struct.pack_into("<I", prefix, 0x20C, 3)
    struct.pack_into("<I", prefix, 0x284, 2)
    struct.pack_into("<Q", prefix, 0x3BC, 0x800A000065F425AF)
    payload = bytes(prefix) + b"synthetic-payload"
    archive_path = root / "synthetic.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("$SystemUpdate/system.xvd", payload)
    before = archive_path.read_bytes()
    command = [sys.executable, str(adapter), str(archive_path), "--inspector", str(inspector)]
    output = subprocess.run(command, capture_output=True, timeout=20)
    require(output.returncode == 0, "archive prefix scan succeeds: " + repr(output.stderr))
    report = json.loads(output.stdout)["sources"][0]
    entry = report["files"][0]
    require(entry["inspection"]["file_size"] == len(payload), "archive member size, not prefix size")
    require(entry["inspection"]["content_type"] == 2, "uses native XVD parser")
    require(entry["inspection"]["package_version_raw"] == 0x800A000065F425AF, "opaque 64-bit version retained")
    require(entry["sha256"] is None and report["archive_sha256"] is None, "prefix hash not promoted to file hash")
    require(entry["prefix_sha256"] == hashlib.sha256(prefix).hexdigest(), "prefix identity")
    output = subprocess.run(command + ["--hash-archives", "--hash-members"], capture_output=True, timeout=20)
    require(output.returncode == 0, "streaming hash scan succeeds")
    report = json.loads(output.stdout)["sources"][0]
    require(report["archive_sha256"] == hashlib.sha256(before).hexdigest(), "archive SHA256")
    require(report["files"][0]["sha256"] == hashlib.sha256(payload).hexdigest(), "member SHA256")
    require(report["files"][0]["zip_crc_verified"], "member CRC checked only after full read")
    require(archive_path.read_bytes() == before, "archive remains unchanged")
    require(not (root / "$SystemUpdate").exists(), "no files extracted")

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("$SystemUpdate/system.xvd", b"truncated")
    output = subprocess.run(command, capture_output=True, timeout=20)
    require(output.returncode == 1 and not json.loads(output.stdout)["sources"][0]["complete"], "malformed entry remains visible")
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escape.xvd", payload)
    require(subprocess.run(command, capture_output=True, timeout=20).returncode == 1, "reject traversal paths")
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("system.xvd", payload)
        archive.writestr("SYSTEM.XVD", payload)
    require(subprocess.run(command, capture_output=True, timeout=20).returncode == 1, "reject ambiguous member paths")

    content = root / "conteúdo"
    content.mkdir()
    (content / "sistema.xvd").write_bytes(prefix)
    output = run("inventory", content, "--json")
    require(output.returncode == 0, "Unicode directory on native CLI")
    report = json.loads(output.stdout)
    require(report["files"][0]["path"] == "sistema.xvd", "valid inventory JSON")
    require(run("inventory", content, "--max-file-bytes", 10, "--json").returncode == 1, "CLI byte limit")
    for invalid in ("0", "-1", "1garbage", "18446744073709551616"):
        require(run("inventory", content, "--max-file-bytes", invalid).returncode == 2, "CLI rejects invalid size")
    require(run("inventory", content, "--json", "--json").returncode == 2, "CLI rejects duplicate option")
    require(run("inspect", content / "sistema.xvd", "--json").returncode == 0, "original inspect still works")
    require(run("inspect-xvd-header", len(prefix), "--json", input=b"short").returncode == 1, "reject truncated stdin")
    if sys.platform == "win32":
        outside = root / "outside"
        outside.mkdir()
        (outside / "escaped.xvd").write_bytes(prefix)
        junction = content / "junction"
        linked = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
                                capture_output=True, timeout=10)
        if linked.returncode == 0:
            try:
                output = run("inventory", content, "--json")
                report = json.loads(output.stdout)
                require(output.returncode == 0 and len(report["files"]) == 1, "junction target not traversed")
                require(report["excluded"] == [{"path": "junction", "reason": "symlink_or_reparse_point"}], "junction exclusion reported")
                require(run("inventory", junction, "--json").returncode == 1, "junction cannot be inventory root")
            finally:
                junction.rmdir()  # Remove the junction itself; never recurse into its target.
        else:
            print("SKIP: junction creation unavailable:", linked.stderr.decode(errors="replace").strip())
print("Synthetic ZIP adapter and CLI contracts passed")
