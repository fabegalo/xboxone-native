# SPDX-License-Identifier: BSD-3-Clause
"""Own byte fixtures only: PE inspection and version-bound bootstrap graphs."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

INSPECTOR, BOOTSTRAP = (Path(p).resolve() for p in sys.argv[1:3])
del sys.argv[1:]


def put(b, at, value, size=4):
    b[at:at + size] = value.to_bytes(size, "little")


def text(b, at, value):
    data = value.encode("ascii") + b"\0"
    b[at:at + len(data)] = data


def rva(offset):
    return offset + 0x1e00


def image(imports=(), exports=(), base=7, manifest=None):
    b = bytearray(0x2000)
    text(b, 0, "MZ"); put(b, 0x3c, 0x80); text(b, 0x80, "PE")
    put(b, 0x84, 0x8664, 2); put(b, 0x86, 1, 2)
    put(b, 0x94, 0xf0, 2); put(b, 0x96, 2, 2)
    put(b, 0x98, 0x20b, 2); put(b, 0xa8, rva(0x1f00))
    put(b, 0xb0, 0x140000000, 8); put(b, 0xd4, 0x200)
    put(b, 0xdc, 3, 2); put(b, 0x104, 16)
    put(b, 0x190, 0x1e00); put(b, 0x194, 0x2000)
    put(b, 0x198, 0x1e00); put(b, 0x19c, 0x200)
    # Fixed regions make malformed offsets independently reproducible.
    for delay in (False, True):
        group = [i for i in imports if i[2] == delay]
        if not group:
            continue
        start, width, directory = (0x400, 32, 13) if delay else (0x200, 20, 1)
        put(b, 0x108 + directory * 8, rva(start))
        put(b, 0x10c + directory * 8, (len(group) + 1) * width)
        for n, (library, symbols, _) in enumerate(group):
            slot = list(imports).index((library, symbols, delay))
            assert slot < 8
            at, table, name = start + n * width, 0x600 + slot * 0x100, 0xe00 + slot * 0x40
            if delay:
                put(b, at, 1); put(b, at + 4, rva(name))
                put(b, at + 12, rva(table)); put(b, at + 16, rva(table))
            else:
                put(b, at, rva(table)); put(b, at + 12, rva(name)); put(b, at + 16, rva(table))
            text(b, name, library)
            for k, symbol in enumerate(symbols):
                if isinstance(symbol, int):
                    put(b, table + k * 8, (1 << 63) | symbol, 8)
                else:
                    target = table + 0x40 + k * 0x30
                    put(b, table + k * 8, rva(target), 8); text(b, target + 2, symbol)
    if exports:
        put(b, 0x108, rva(0x1000)); put(b, 0x10c, 0x400)
        put(b, 0x100c, rva(0x1050)); text(b, 0x1050, "own.dll")
        put(b, 0x1010, base); put(b, 0x1014, len(exports))
        aliases = [(i, name) for i, (names, _) in enumerate(exports) for name in names]
        put(b, 0x1018, len(aliases)); put(b, 0x101c, rva(0x1080))
        put(b, 0x1020, rva(0x1100)); put(b, 0x1024, rva(0x1180))
        for i, (_, forward) in enumerate(exports):
            target = 0 if forward is False else rva(0x1f00 + i)
            if isinstance(forward, str):
                target = rva(0x1200 + i * 0x40); text(b, 0x1200 + i * 0x40, forward)
            put(b, 0x1080 + i * 4, target)
        for i, (slot, name) in enumerate(aliases):
            put(b, 0x1100 + i * 4, rva(0x1300 + i * 0x30))
            put(b, 0x1180 + i * 2, slot, 2); text(b, 0x1300 + i * 0x30, name)
    if manifest is not None:
        put(b, 0x118, rva(0x1500)); put(b, 0x11c, 0x400)
        for at in (0x1500, 0x1520, 0x1540):
            put(b, at + 14, 1, 2)
        put(b, 0x1510, 24); put(b, 0x1514, 0x80000020)
        put(b, 0x1530, 1); put(b, 0x1534, 0x80000040)
        put(b, 0x1550, 1033); put(b, 0x1554, 0x60)
        put(b, 0x1560, rva(0x1600)); put(b, 0x1564, len(manifest))
        put(b, 0x1568, 65001); b[0x1600:0x1600 + len(manifest)] = manifest
    return b


def quote(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def tls_image():
    b = image()
    put(b, 0x150, rva(0x1a00)); put(b, 0x154, 40)
    put(b, 0x1ac, 0xe0000040)  # Writable index and executable callback fixture section.
    for at, offset in ((0x1a00, 0x1a80), (0x1a08, 0x1a90), (0x1a10, 0x1aa0), (0x1a18, 0x1ac0)):
        put(b, at, 0x140000000 + rva(offset), 8)
    put(b, 0x1a20, 32); put(b, 0x1a24, 4 << 20)  # 8-byte alignment.
    put(b, 0x1ac0, 0x140000000 + rva(0x1f00), 8)
    return b


class Dependencies(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xboxone_pe_graph_")
        # Fixture-only canonicalization: real inputs must still reject links.
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def inspect(self, data, valid=True):
        path = self.root / "own.exe"
        path.write_bytes(data)
        result = subprocess.run([str(INSPECTOR), "inspect", str(path), "--json"], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0 if valid else 1, result.stderr)
        self.assertEqual(path.read_bytes(), data)
        return json.loads(result.stdout) if valid else result.stderr

    def prepare(self, files, bindings, versions=None, reverse=False, hashes=None, duplicate_ids=()):
        rows = ['xboxone-systemos-v1', 'profile "own" "revision-1" synthetic "' + "a" * 64 + '"', 'entry "entry"']
        records = []
        for id, data in files.items():
            path = self.root / (id + (".exe" if id == "entry" else ".dll"))
            path.write_bytes(data)
            version = (versions or {}).get(id, "revision-1")
            records.append(f'artifact {quote(id)} {quote(version)} {quote(path.as_posix())} '
                           f'"{(hashes or {}).get(id, hashlib.sha256(data).hexdigest())}" {"executable" if id == "entry" else "module"} "own fixture"')
        records += [records[list(files).index(id)] for id in duplicate_ids]
        records += [f'bind {quote(id)} {quote(lib)} {quote(provider)} "own audited fixture"' for id, lib, provider in bindings]
        rows += list(reversed(records)) if reverse else records
        profile = self.root / "profile.txt"
        profile.write_text("\n".join(rows) + "\n", encoding="utf-8")
        result = subprocess.run([str(BOOTSTRAP), "prepare", str(profile)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["stage"], "blocked")
        self.assertEqual(report["process_id"], 0)
        self.assertFalse(report["dashboard_boot_verified"])
        return report

    def test_imports_normal_delay_and_api_set(self):
        p = self.inspect(image(imports=[("own.dll", ["Start", 7], False), ("API-MS-own-l1-1-0.dll", ["Later"], True)]))
        self.assertEqual(p["imports"][0]["symbols"], ["Start", "#7"])
        self.assertEqual(p["imports"][0]["ordinal_indices"], [1])
        self.assertFalse(p["imports"][0]["delay_load"])
        self.assertTrue(p["imports"][1]["delay_load"])
        self.assertTrue(p["imports"][1]["api_set"])
        self.assertTrue(p["has_delay_imports"])

    def test_iat_fallback_and_legacy_delay_va(self):
        b = image(imports=[("own.dll", ["Start"], False)])
        put(b, 0x200, 0)
        self.assertEqual(self.inspect(b)["imports"][0]["symbols"], ["Start"])
        b = image(imports=[("own.dll", ["Later"], True)])
        put(b, 0xb0, 0x10000000, 8); put(b, 0x400, 0)
        for at in (0x404, 0x40c, 0x410):
            put(b, at, int.from_bytes(b[at:at+4], "little") + 0x10000000)
        put(b, 0x600, rva(0x640) + 0x10000000, 8)
        self.assertEqual(self.inspect(b)["imports"][0]["symbols"], ["Later"])

    def test_exports_aliases_ordinals_sparse_and_forwarders(self):
        p = self.inspect(image(exports=[(["Start", "Alias"], None), ([], False), (["Next"], "other.#19")]))
        self.assertEqual([e["ordinal"] for e in p["exports"]], [7, 9])
        self.assertEqual(p["exports"][0]["names"], ["Alias", "Start"])
        self.assertEqual(p["exports"][1]["forward_library"], "other.dll")
        self.assertEqual(p["exports"][1]["forward_symbol"], "#19")

    def test_export_only_and_import_only_images(self):
        self.assertEqual(self.inspect(image())["exports"], [])
        p = self.inspect(image(exports=[([], None)]))
        self.assertEqual(p["imports"], [])
        self.assertEqual(p["exports"][0]["ordinal"], 7)
        b = image(exports=[(["ZeroInitializedData"], None)])
        put(b, 0x190, 0x2000); put(b, 0x1080, 0x3f00)
        self.assertEqual(self.inspect(b)["exports"][0]["rva"], 0x3f00)

    def test_available_activation_metadata(self):
        payload = b'<assembly><assemblyIdentity name="own" version="1.0.0.0"/></assembly>'
        b = image(manifest=payload)
        tls = tls_image()
        b[0x1a00:0x1b00] = tls[0x1a00:0x1b00]
        put(b, 0x150, rva(0x1a00)); put(b, 0x154, 40)
        put(b, 0x1ac, 0xe0000040)
        put(b, 0x178, rva(0x1b00)); put(b, 0x17c, 72)  # CLR directory presence only.
        p = self.inspect(b)
        self.assertEqual([m["kind"] for m in p["activation_metadata"]], ["tls_directory", "clr_directory", "rt_manifest"])
        m = p["activation_metadata"][-1]
        self.assertEqual(bytes.fromhex(m["bytes_hex"]), payload)
        self.assertEqual(m["resource_path"], ["#24", "#1", "#1033"])
        self.assertEqual(m["code_page"], 65001)

    def test_tls_metadata_and_callback_order(self):
        b = tls_image()
        put(b, 0x1ac8, 0x140000000 + rva(0x1f10), 8)
        p = self.inspect(b)
        self.assertEqual(p["tls"], {"template_rva": rva(0x1a80), "template_size": 16,
                                  "index_rva": rva(0x1aa0), "callbacks_rva": rva(0x1ac0),
                                  "zero_fill_size": 32, "alignment_bytes": 8,
                                  "callback_rvas": [rva(0x1f00), rva(0x1f10)]})
        self.assertIsNone(self.inspect(image())["tls"])

    def test_tls_empty_template_and_bss_index(self):
        b = tls_image()
        put(b, 0x1a00, 0, 8); put(b, 0x1a08, 0, 8); put(b, 0x1a18, 0, 8)
        put(b, 0x190, 0x2200)  # Extend virtual storage beyond file-backed bytes.
        put(b, 0x1a10, 0x140004000, 8)
        p = self.inspect(b)
        self.assertEqual(p["tls"]["template_size"], 0)
        self.assertEqual(p["tls"]["index_rva"], 0x4000)
        self.assertEqual(p["tls"]["callback_rvas"], [])

    def test_malformed_tls_rejected_before_execution(self):
        mutations = ((0x154, 39, 4), (0x1a00, 0x13fffffff, 8),
                     (0x1a08, 0x140000001, 8), (0x1a08, 0, 8),
                     (0x1a08, 0x240000000, 8), (0x1a10, 0, 8),
                     (0x1a10, 0x140003fff, 8), (0x1a18, 0x140003fff, 8),
                     (0x1ac0, 0x140004000, 8), (0x1ac0, 0x13fffffff, 8),
                     (0x1a24, 15 << 20, 4), (0x1ac, 0x60000040, 4))
        for at, value, size in mutations:
            with self.subTest(at=at, value=value):
                b = tls_image(); put(b, at, value, size)
                self.assertIn("TLS", self.inspect(b, valid=False))
                report = self.prepare({"entry": b}, [])
                self.assertIn("image_invalid", [d["code"] for d in report["diagnostics"]])
        b = tls_image(); put(b, 0x1ac, 0xc0000040)  # Callback storage is not executable.
        self.assertIn("TLS callback", self.inspect(b, valid=False))

    def test_tls_unterminated_callback_table(self):
        b = tls_image()
        for at in range(0x1ac0, 0x2000, 8):
            put(b, at, 0x140000000 + rva(0x1f00), 8)
        self.assertIn("unterminated", self.inspect(b, valid=False))

    def test_tls_callback_limit_includes_terminator(self):
        b = tls_image()
        b.extend(bytes(0x2000))
        put(b, 0x190, len(b) - 0x200); put(b, 0x198, len(b) - 0x200)
        for at in range(0x1ac0, 0x1ac0 + 1023 * 8, 8):
            put(b, at, 0x140000000 + rva(0x1f00), 8)
        self.assertEqual(len(self.inspect(b)["tls"]["callback_rvas"]), 1023)
        put(b, 0x1ac0 + 1023 * 8, 0x140000000 + rva(0x1f00), 8)
        self.assertIn("oversized TLS callback", self.inspect(b, valid=False))

    def test_malformed_tables(self):
        cases = [
            (0x114, 20, 4),  # No terminating normal import descriptor.
            (0x20c, 0xfffffff0, 4), (0x200, 0, 4),
            (0x600, (1 << 63) | 0x10000, 8),  # Reserved ordinal bits.
            (0x600, 0x100000000, 8), (0x210, 0, 4),
            (0x1014, 65537, 4), (0x1018, 65537, 4),
            (0x1180, 99, 2), (0x1080, 0, 4),
            (0x1010, 0xffffffff, 4), (0x101c, 0xfffffffe, 4),
            (0x1080, 0xfffffff0, 4), (0x10c, 39, 4),
            (0x400, 2, 4), (0x174, 32, 4),
            (0x170, 0, 4), (0x194, 0xfffffff0, 4),
            (0x198, 0x1e01, 4), (0x104, 17, 4),
        ]
        original = image(imports=[("own.dll", ["Start"], False), ("later.dll", ["Later"], True)],
                         exports=[(["Start"], None), (["Next"], None)])
        for at, value, width in cases:
            with self.subTest(offset=hex(at), value=value):
                b = bytearray(original); put(b, at, value, width)
                if at == 0x200:  # Both thunk tables absent (fallback itself is valid).
                    put(b, 0x210, 0)
                self.inspect(b, valid=False)
        b = bytearray(original); put(b, 0x86, 2, 2)
        b[0x1b0:0x1d8] = b[0x188:0x1b0]  # Overlapping virtual/raw sections.
        self.inspect(b, valid=False)
        for size in (0x90, 0x19f, 0x200, 0x1fff):
            with self.subTest(truncated_size=size):
                self.inspect(original[:size], valid=False)

    def test_forwarder_bounds_and_syntax(self):
        for f in ("missingseparator", ".Start", "other.", "../escape.Start", "other.#65536", "other.#x"):
            with self.subTest(forwarder=f):
                self.inspect(image(exports=[(["Start"], f)]), valid=False)
        b = image(exports=[(["Start"], "other.Start")])
        put(b, 0x10c, 0x20b)  # NUL is just outside export directory.
        self.inspect(b, valid=False)

    def test_unterminated_and_cross_section_names(self):
        b = image(imports=[("own.dll", ["Start"], False)])
        b[0x642:0x742] = b"x" * 256
        self.inspect(b, valid=False)
        b = image(imports=[("own.dll", ["Start"], False)])
        put(b, 0x600, rva(0x1ffd), 8); b[0x1fff] = ord('X')
        b += b"\0" * 8  # Physical bytes outside section cannot terminate name.
        self.inspect(b, valid=False)

    def test_resource_limits_cycles_and_version_bytes(self):
        original = image(manifest=b"own")
        for at, value in ((0x1514, 0x80000000), (0x1554, 0x500), (0x1560, 0xfffffff0), (0x1564, 0x100001)):
            with self.subTest(offset=hex(at)):
                b = bytearray(original); put(b, at, value); self.inspect(b, valid=False)
        b = bytearray(original); put(b, 0x1510, 16)
        self.assertEqual(self.inspect(b)["activation_metadata"][0]["kind"], "rt_version")

    def test_graph_transitive_forwarder_and_determinism(self):
        files = {"entry": image(imports=[("a.dll", ["Start"], False)]),
                 "a": image(exports=[(["Start"], "b.#7")]), "b": image(exports=[([], None)])}
        bindings = [("entry", "a.dll", "artifact:a"), ("a", "b.dll", "artifact:b")]
        report = self.prepare(files, bindings)
        self.assertEqual(report, self.prepare(files, bindings, reverse=True))
        self.assertEqual([n["id"] for n in report["nodes"]], ["a", "b", "entry"])
        self.assertEqual({d["status"] for d in report["dependencies"]}, {"private_forwarder_present", "private_export_present"})
        self.assertTrue(any(d["kind"] == "forwarder" and d["symbol"] == "#7" for d in report["dependencies"]))
        self.assertIn("private_module_activation_unsupported", [d["code"] for d in report["diagnostics"]])

    def test_graph_missing_export_and_no_name_fallback(self):
        files = {"entry": image(imports=[("a.dll", ["Absent"], False)]), "a": image(exports=[(["Start"], None)])}
        report = self.prepare(files, [])
        self.assertEqual(report["dependencies"][0]["status"], "missing_binding")
        report = self.prepare(files, [("entry", "a.dll", "artifact:a")])
        self.assertEqual(report["dependencies"][0]["status"], "private_symbol_missing")

    def test_graph_missing_forwarder_cycle_and_duplicate_binding(self):
        files = {"entry": image(imports=[("a.dll", ["Start"], False)]), "a": image(exports=[(["Start"], "a.Start")])}
        binding = [("entry", "a.dll", "artifact:a")]
        report = self.prepare(files, binding)
        self.assertIn("missing_import", [d["code"] for d in report["diagnostics"]])
        report = self.prepare(files, binding + [("a", "a.dll", "artifact:a")])
        self.assertIn("forwarder_cycle", [d["code"] for d in report["diagnostics"]])
        report = self.prepare(files, binding + binding)
        self.assertIn("binding_rejected", [d["status"] for d in report["dependencies"]])

    def test_graph_delay_api_set_version_and_activation_blockers(self):
        files = {"entry": image(imports=[("ext-ms-own-l1-1-0.dll", ["Start"], True)], manifest=b"<assembly/>")}
        report = self.prepare(files, [])
        edge = report["dependencies"][0]
        self.assertTrue(edge["api_set"]); self.assertEqual(edge["kind"], "delay_import")
        codes = {d["code"] for d in report["diagnostics"]}
        self.assertTrue({"api_set_mapping_missing", "delay_imports_unaudited", "activation_manifest_unaudited"} <= codes)
        files = {"entry": image(imports=[("a.dll", ["Start"], False)]), "a": image(exports=[(["Start"], None)])}
        report = self.prepare(files, [("entry", "a.dll", "artifact:a")], versions={"a": "OSU3-must-not-be-used"})
        self.assertEqual(report["dependencies"][0]["status"], "private_identity_unverified")
        self.assertIn("version_mismatch", [d["code"] for d in report["diagnostics"]])
        report = self.prepare(files, [("entry", "a.dll", "artifact:a")], hashes={"a": "0" * 64})
        self.assertEqual(report["dependencies"][0]["status"], "private_identity_unverified")
        self.assertIn("hash_mismatch", [d["code"] for d in report["diagnostics"]])

    def test_named_numeric_export_is_distinct_from_ordinal(self):
        files = {"entry": image(imports=[("a.dll", ["#7", 7], False)]), "a": image(exports=[(["Other"], None), (["#7"], None)])}
        report = self.prepare(files, [("entry", "a.dll", "artifact:a")])
        edges = report["dependencies"]
        self.assertEqual([e["by_ordinal"] for e in edges], [False, True])
        self.assertEqual([e["status"] for e in edges], ["private_export_present"] * 2)
        files["a"] = image(exports=[(["Other"], None)])
        report = self.prepare(files, [("entry", "a.dll", "artifact:a")])
        self.assertEqual([e["status"] for e in report["dependencies"]], ["private_symbol_missing", "private_export_present"])

    def test_graph_forwarder_depth_limit(self):
        files = {"entry": image(imports=[("m0.dll", ["Start"], False)])}
        bindings = [("entry", "m0.dll", "artifact:m0")]
        for n in range(65):
            files[f"m{n}"] = image(exports=[(["Start"], f"m{n+1}.Start" if n < 64 else None)])
            if n < 64:
                bindings.append((f"m{n}", f"m{n+1}.dll", f"artifact:m{n+1}"))
        report = self.prepare(files, bindings)
        self.assertIn("dependency_graph_limit", [d["code"] for d in report["diagnostics"]])

    def test_duplicate_artifact_never_selects_first_provider(self):
        files = {"entry": image(imports=[("a.dll", ["Start"], False)]), "a": image(exports=[(["Start"], None)])}
        bindings = [("entry", "a.dll", "artifact:a")]
        report = self.prepare(files, bindings, duplicate_ids=("a",))
        self.assertEqual(report, self.prepare(files, bindings, duplicate_ids=("a",), reverse=True))
        self.assertEqual(report["dependencies"][0]["status"], "private_identity_unverified")
        self.assertTrue(all(n["status"] == "ambiguous_artifact" and n["pe"] is None for n in report["nodes"] if n["id"] == "a"))


if __name__ == "__main__":
    unittest.main()
