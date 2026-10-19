import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "build_release", ROOT / "Tools/release/build_release.py"
)
build_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_release)


class ReleaseToolsTest(unittest.TestCase):
    def test_parse_version_and_reject_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            header = Path(temp) / "patchlevel.h"
            header.write_text(
                '#define PY_VERSION_BASE "2.7.18"\n'
                '#define AC_BUILD 4\n#define AC_BUILD_TAG "ac4"\n'
            )
            self.assertEqual(build_release.parse_version(header)["version"],
                             "2.7.18-ac4")
            header.write_text(header.read_text().replace('"ac4"', '"ac3"'))
            with self.assertRaises(ValueError):
                build_release.parse_version(header)

    def test_metadata_is_stable_and_verifiable(self):
        version = {"version": "2.7.18-ac2"}
        with tempfile.TemporaryDirectory() as temp:
            drawer = Path(temp)
            (drawer / "lib").mkdir()
            (drawer / "Python").write_bytes(b"binary")
            (drawer / "lib/python27.zip").write_bytes(b"zip")
            first = build_release.write_metadata(drawer, version, "a" * 40)
            manifest_one = (drawer / "openamigapython-release.json").read_bytes()
            sums_one = (drawer / "SHA256SUMS").read_bytes()
            second = build_release.write_metadata(drawer, version, "a" * 40)
            self.assertEqual(first, second)
            self.assertEqual(manifest_one,
                             (drawer / "openamigapython-release.json").read_bytes())
            self.assertEqual(sums_one, (drawer / "SHA256SUMS").read_bytes())
            decoded = json.loads(manifest_one)
            for entry in decoded["files"]:
                digest = hashlib.sha256((drawer / entry["path"]).read_bytes()).hexdigest()
                self.assertEqual(entry["sha256"], digest)

    def test_openup_part_is_sorted_versioned_and_self_contained(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            drawer = base / "drawer"
            drawer.mkdir()
            (drawer / "z").write_text("z")
            (drawer / "a").write_text("a")
            part_dir = base / "OpenAmigaPython"
            build_release.write_openup_part(
                drawer, part_dir, {"version": "2.7.18-ac2"}
            )
            text = (part_dir / "Part").read_text(encoding="latin-1")
            self.assertIn("part OpenAmigaPython 2.7.18-ac2", text)
            # any Amiga: no "needs" line (OpenUp would skip it off AmigaChrome)
            self.assertFalse(any(line.startswith("needs")
                                 for line in text.splitlines()))
            self.assertIn("68020 or later; no FPU", text)
            self.assertIn("opentls.library", text)
            self.assertLess(text.index('"Payload/a"'), text.index('"Payload/z"'))
            self.assertIn(
                '"SYS:Tools/OpenAmigaPython/2.7.18-ac2/a"', text
            )
            self.assertIn("startup Assign >NIL: Python:", text)
            self.assertEqual((part_dir / "Payload/a").read_text(), "a")

    def test_symlink_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            target.write_text("x")
            (root / "link").symlink_to(target)
            with self.assertRaises(ValueError):
                build_release.files_under(root)

    def test_openup_output_name_is_guarded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            drawer = root / "drawer"
            drawer.mkdir()
            (drawer / "file").write_text("x")
            with self.assertRaises(ValueError):
                build_release.write_openup_part(
                    drawer, root / "wrong-name", {"version": "2.7.18-ac2"}
                )


if __name__ == "__main__":
    unittest.main()

