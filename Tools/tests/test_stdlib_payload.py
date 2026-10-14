from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from build_pure_wheel import build_wheel


ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "Source/Lib"
SITE_PACKAGES = ROOT / "Python/lib/site-packages"

STDLIB_MARKERS = (
    "json/__init__.py",
    "logging/__init__.py",
    "unittest/__init__.py",
    "email/__init__.py",
    "wsgiref/__init__.py",
    "importlib/__init__.py",
    "xml/__init__.py",
    "encodings/__init__.py",
    "distutils/__init__.py",
)

PACKAGING_MARKERS = (
    "pip/__init__.py",
    "setuptools/__init__.py",
    "pkg_resources/__init__.py",
    "wheel/__init__.py",
)


class StandardLibraryPayloadTest(unittest.TestCase):
    def test_required_packages_are_present(self):
        missing_stdlib = [
            name for name in STDLIB_MARKERS if not (LIB / name).is_file()
        ]
        missing_packaging = [
            name for name in PACKAGING_MARKERS
            if not (SITE_PACKAGES / name).is_file()
        ]
        self.assertEqual(missing_stdlib + missing_packaging, [])

    def test_bootstrap_versions_are_pinned(self):
        self.assertIn('__version__ = "20.3.4"',
                      (SITE_PACKAGES / "pip/__init__.py").read_text())
        self.assertTrue((SITE_PACKAGES / "pip-20.3.4.dist-info/METADATA").is_file())
        self.assertTrue((SITE_PACKAGES / "setuptools-44.1.1.dist-info/METADATA").is_file())
        self.assertTrue((SITE_PACKAGES / "wheel-0.37.1.dist-info/METADATA").is_file())

    def test_classic_filesystem_payload_components_fit(self):
        too_long = [
            str(path.relative_to(SITE_PACKAGES))
            for path in SITE_PACKAGES.rglob("*")
            if len(path.name) > 30
        ]
        self.assertEqual(too_long, [])

    def test_amiga_runtime_compatibility_patches_are_present(self):
        pyconfig = (ROOT / "Source/Include/pyconfig.h").read_text()
        tempfile_source = (LIB / "tempfile.py").read_text()
        zipfile_source = (LIB / "zipfile.py").read_text()
        req_tracker = (
            SITE_PACKAGES / "pip/_internal/req/req_tracker.py"
        ).read_text()
        pip_misc = (
            SITE_PACKAGES / "pip/_internal/utils/misc.py"
        ).read_text()

        self.assertIn("#define Py_USING_UNICODE", pyconfig)
        self.assertIn("_os.sys.platform == 'amiga'", tempfile_source)
        self.assertIn("file = open(name, mode, bufsize)", tempfile_source)
        self.assertIn(
            "opener = io.open if sys.platform == 'amiga' else open",
            zipfile_source,
        )
        self.assertIn("hashed = hashed[:28]", req_tracker)
        self.assertIn("e.errno == errno.EBUSY", pip_misc)

    def test_reproducible_zip_contains_packages(self):
        tool = ROOT / "Source/Tools/amiga/mkpythonzip.py"
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / "first.zip"
            second = Path(temp) / "second.zip"
            for output in (first, second):
                subprocess.check_call([
                    "python3", str(tool), str(LIB), str(output)
                ])
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                names = set(archive.namelist())
                self.assertTrue(all(
                    item.compress_type == zipfile.ZIP_STORED
                    for item in archive.infolist()
                ))
            for marker in STDLIB_MARKERS:
                self.assertIn(marker, names)
            for marker in PACKAGING_MARKERS:
                self.assertNotIn(marker, names)

    def test_offline_wheel_fixture_is_reproducible(self):
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / "acsmoke-1.0-py2-none-any.whl"
            second = Path(temp) / "again.whl"
            first_digest = build_wheel(first)
            second_digest = build_wheel(second)
            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertIn("acsmoke/__init__.py", archive.namelist())
                self.assertIn(
                    "acsmoke-1.0.dist-info/RECORD", archive.namelist()
                )


if __name__ == "__main__":
    unittest.main()

