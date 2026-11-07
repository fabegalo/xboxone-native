# SPDX-License-Identifier: GPL-2.0-only
"""Owned fixtures only; no package deployment, keys, mounting or Xbox execution."""
from pathlib import Path
import ctypes
from ctypes import wintypes
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile

tool = Path(sys.argv[1]).resolve()
fixtures = Path(sys.argv[2]).resolve()
create = ctypes.WinDLL('kernel32', use_last_error=True).CreateFileW
create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                   wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
create.restype = wintypes.HANDLE
close = ctypes.WinDLL('kernel32', use_last_error=True).CloseHandle
close.argtypes = [wintypes.HANDLE]
expected = b'Owned fixture payload; not Xbox software.\n'
results = []


def run(source, output, code):
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    guard = create(str(source), 0x80000000, 1, None, 3, 0x80, None)
    assert guard != ctypes.c_void_p(-1).value
    try:
        result = subprocess.run([str(tool), 'extract', str(source), '-o', str(output)],
                                capture_output=True, timeout=30)
    finally:
        close(guard)
    text = (result.stdout + result.stderr).decode('utf-8', errors='replace')
    assert result.returncode == code, (result.returncode, code, text)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert not list(output.parent.glob('.systemos-extract-*'))
    results.append({'input': source.name, 'exit_code': result.returncode,
                    'source_hash_unchanged': True})
    return text


with tempfile.TemporaryDirectory(prefix='xvd_systemos_owned_') as temporary:
    root = Path(temporary).resolve()
    for name in ('fixed.xvd', 'dynamic.xvd', 'hashed-fixed.xvd'):
        output = root / (name + '-output')
        text = run(fixtures / name, output, 0)
        assert (output / 'shell' / 'owned.txt').read_bytes() == expected
        assert 'Extracted SystemOS files=' in text

    existing = root / 'existing'
    existing.mkdir()
    (existing / 'keep.txt').write_bytes(b'preserve')
    run(fixtures / 'fixed.xvd', existing, 1)
    assert (existing / 'keep.txt').read_bytes() == b'preserve'

    encrypted = root / 'owned-encrypted-marker.xvd'
    shutil.copyfile(fixtures / 'fixed.xvd', encrypted)
    with encrypted.open('r+b') as stream:
        stream.seek(0x208)
        stream.write(struct.pack('<I', 12))
    output = root / 'encrypted-output'
    text = run(encrypted, output, 3)
    assert 'encrypted' in text and not output.exists()

    truncated = root / 'truncated.xvd'
    truncated.write_bytes(b'msft-xvd')
    output = root / 'truncated-output'
    run(truncated, output, 1)
    assert not output.exists()

    version = root / 'unsupported-version.xvd'
    shutil.copyfile(fixtures / 'fixed.xvd', version)
    with version.open('r+b') as stream:
        stream.seek(0x20c)
        stream.write(struct.pack('<I', 99))
    output = root / 'version-output'
    run(version, output, 1)
    assert not output.exists()

    damaged = root / 'damaged-hashed.xvd'
    shutil.copyfile(fixtures / 'hashed-fixed.xvd', damaged)
    with damaged.open('r+b') as stream:
        stream.seek(-4096, 2)
        value = stream.read(1)
        stream.seek(-1, 1)
        stream.write(bytes([value[0] ^ 1]))
    output = root / 'damaged-output'
    run(damaged, output, 1)
    assert not output.exists()

    output = root / '..' / root.name / 'traversal-output'
    run(fixtures / 'fixed.xvd', output, 1)
    assert not output.exists()

    bat = root / 'invalid-bat.xvd'
    shutil.copyfile(fixtures / 'dynamic.xvd', bat)
    with bat.open('r+b') as stream:
        stream.seek(0x3000)
        stream.write(struct.pack('<I', 171))
    output = root / 'bat-output'
    text = run(bat, output, 1)
    assert 'BAT entry alignment' in text and not output.exists()

    no_partition = root / 'no-partition.xvd'
    shutil.copyfile(fixtures / 'fixed.xvd', no_partition)
    with no_partition.open('r+b') as stream:
        stream.seek(0x3000)
        stream.write(bytes(512))
    output = root / 'no-partition-output'
    run(no_partition, output, 1)
    assert not output.exists()

print(json.dumps({'cases_passed': len(results), 'owned_payloads_extracted': 3,
                  'original_xbox_components_executed': 0, 'results': results}))
