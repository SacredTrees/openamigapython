from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE_LIB = str(ROOT / "Source/Lib")
sys.path.insert(0, SOURCE_LIB)

from amigachrome import acceleration
from amigachrome import info

# Do not let the Python 2.7 stdlib shadow the host Python 3 stdlib while the
# remaining release-tool tests are imported by unittest discovery.
sys.path.remove(SOURCE_LIB)


class InfoTest(unittest.TestCase):
    def test_capabilities_are_probeable_without_opening_services(self):
        seen = []

        def probe(path):
            seen.append(path)
            return path == "LIBS:openmulticore.library"

        result = info.capabilities(probe)
        self.assertTrue(result["openmulticore"])
        self.assertFalse(result["opencrypto"])
        self.assertEqual(len(seen), len(info.CAPABILITY_PATHS))

    def test_report_is_stable(self):
        state = {
            "python": "2.7.18-ac2",
            "platform": "amiga",
            "capabilities": {"openmulticore": True},
        }
        report = info.format_report(state)
        self.assertIn("OpenAmigaPython 2.7.18-ac2", report)
        self.assertIn("openmulticore=available", report)
        self.assertIn("openservice=unavailable", report)


class AccelerationTest(unittest.TestCase):
    def test_unsupported_and_small_work_stay_on_cpu0(self):
        caps = {"openmulticore": True}
        self.assertEqual(
            acceleration.plan("python-object", 99999, caps)["provider"],
            acceleration.CPU0,
        )
        self.assertEqual(
            acceleration.plan("crc32", 100, caps)["reason"],
            "below-threshold",
        )

    def test_eligible_flat_buffer_uses_openmulticore(self):
        result = acceleration.plan(
            "sha256", 8192, {"openmulticore": True}
        )
        self.assertEqual(result["provider"], acceleration.OPENMULTICORE)

    def test_backend_failure_falls_back(self):
        class BrokenBackend(object):
            def run(self, kernel, data):
                raise RuntimeError("secondary CPU unavailable")

        output = acceleration.run(
            "copy", b"abcdefgh", lambda data: b"cpu:" + data,
            backend=BrokenBackend(), capabilities={"openmulticore": True},
            threshold=1,
        )
        self.assertEqual(output, b"cpu:abcdefgh")

    def test_backend_success_is_returned(self):
        class Backend(object):
            def run(self, kernel, data):
                return kernel.encode("ascii") + b":" + data

        output = acceleration.run(
            "copy", b"abcdefgh", lambda data: b"cpu:" + data,
            backend=Backend(), capabilities={"openmulticore": True},
            threshold=1,
        )
        self.assertEqual(output, b"copy:abcdefgh")


if __name__ == "__main__":
    unittest.main()
