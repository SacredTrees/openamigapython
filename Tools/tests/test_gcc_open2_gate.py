import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class GCCOpen2GateTest(unittest.TestCase):
    def test_manifest_pins_complete_open2_stack(self):
        manifest = json.loads(
            (ROOT / "Tools/cross/gcc-16.2-open2.json").read_text()
        )
        files = manifest["files"]
        self.assertEqual(manifest["id"], "gcc-16.2-open2")
        self.assertEqual(manifest["target"], "m68k-amigaos")
        self.assertEqual(manifest["full_version"], "16.2.0b")
        self.assertEqual(len([p for p in files if p.startswith("patches/gcc/")]), 10)
        self.assertEqual(len([p for p in files if p.startswith("patches/libnix/")]), 6)
        self.assertEqual(len([p for p in files if p.startswith("patches/aros-stuff/")]), 4)
        self.assertIn("prefix/libexec/gcc/m68k-amigaos/16.2.0b/cc1", files)
        self.assertIn("prefix/m68k-amigaos/libnix/lib/libnix.a", files)
        self.assertTrue(all(len(digest) == 64 for digest in files.values()))

    def test_ac4_compile_guard_and_vbcc_refusal_are_present(self):
        pyconfig = (ROOT / "Source/Include/pyconfig.h").read_text()
        vbcc_builder = (ROOT / "Tools/cross/build-linux-vbcc.sh").read_text()
        self.assertIn("OPENAMIGA_GCC_OPEN2", pyconfig)
        self.assertIn("ac4 is GCC 16.2-open2 only", vbcc_builder)


if __name__ == "__main__":
    unittest.main()
