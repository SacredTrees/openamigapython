import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "write_build_provenance",
    ROOT / "Tools/cross/write_build_provenance.py",
)
provenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provenance)


class AC4GCCBuildTest(unittest.TestCase):
    def test_builder_pins_ac4_abi_and_reproducibility_flags(self):
        script = (ROOT / "Tools/cross/build-linux-gcc-open2.sh").read_text()
        self.assertIn("check_gcc_open2.py", script)
        self.assertIn("OPENAMIGA_GCC_STOVE", script)
        self.assertIn("-mcrt=nix20 -m68040 -m68881", script)
        self.assertIn("-DOPENAMIGA_GCC_OPEN2=1", script)
        self.assertIn("AMIGAPYTHON_STARTUP_TRACE", script)
        self.assertIn("-DOPENAMIGAPYTHON_STARTUP_TRACE=1", script)
        self.assertIn("-O3 -std=gnu99 -fwrapv", script)
        self.assertIn("--disable-ipv6", script)
        self.assertIn('AR="$ar"', script)
        self.assertIn('RANLIB="$ranlib"', script)
        self.assertIn("ac_cv_func_getpwent=no", script)
        self.assertIn("ac_cv_func_setgroups=no", script)
        self.assertIn("ac_cv_func_setuid=no", script)
        self.assertIn('Modules/Setup.ac4" "$build_dir/Modules/Setup"',
                      script)
        self.assertIn("Amiga/open2_runtime.o", script)
        self.assertIn("Amiga/pyamiga_host.o", script)
        self.assertIn("write_build_provenance.py", script)
        self.assertIn('"--configure-option=$option"', script)

    def test_configure_and_headers_select_the_amiga_target(self):
        configure_ac = (ROOT / "Source/configure.ac").read_text()
        python_h = (ROOT / "Source/Include/Python.h").read_text()
        self.assertIn("*-*-amigaos*)", configure_ac)
        self.assertIn('ac_sys_system=AmigaOS', configure_ac)
        self.assertIn('DYNLOADFILE="dynload_amiga.o"', configure_ac)
        self.assertIn("AC_CACHE_CHECK([for setgroups]", configure_ac)
        self.assertIn("ac_cv_func_setgroups", configure_ac)
        self.assertIn("#ifdef OPENAMIGA_GCC_OPEN2", python_h)
        self.assertIn("# include <pyconfig.h>", python_h)
        self.assertIn("ac4 requires verified GCC 16.2-open2", python_h)

    def test_vbcc_path_remains_and_workbench_shift_is_defined(self):
        host = (ROOT / "Source/Amiga/pyamiga_host.c").read_text()
        wbargs = (ROOT / "Source/Amiga/wbargs.c").read_text()
        pyport = (ROOT / "Source/Include/pyport.h").read_text()
        strings = (ROOT / "Source/Objects/stringobject.c").read_text()
        self.assertIn("#ifdef __VBCC__", host)
        self.assertIn("AMITCP_LVO", host)
        self.assertNotIn("argv[j] = argv[--j]", wbargs)
        self.assertIn("argv[j + 1] = argv[j]", wbargs)
        self.assertIn("!defined(OPENAMIGA_GCC_OPEN2)", pyport)
        self.assertIn("#define unsigned_PY_LONG_LONG unsigned PY_LONG_LONG",
                      pyport)
        self.assertNotIn('PY_FORMAT_SIZE_T "ld"', strings)
        self.assertIn("va_arg(vargs, unsigned_PY_LONG_LONG)", strings)

    def test_ac4_skips_posixlib_warmup_and_has_early_tracepoints(self):
        entry = (ROOT / "Source/Modules/python.c").read_text()
        main = (ROOT / "Source/Modules/main.c").read_text()
        pythonrun = (ROOT / "Source/Python/pythonrun.c").read_text()
        sysmodule = (ROOT / "Source/Python/sysmodule.c").read_text()
        getpath = (ROOT / "Source/Modules/getpath.c").read_text()
        runtime = (ROOT / "Source/Amiga/open2_runtime.c").read_text()
        pydebug = (ROOT / "Source/Include/pydebug.h").read_text()
        warmup = entry.index('FILE *warmup = fopen("NIL:", "w")')
        guard = entry.rfind("#ifndef OPENAMIGA_GCC_OPEN2", 0, warmup)
        end_guard = entry.find("#endif", warmup)
        self.assertGreaterEqual(guard, 0)
        self.assertGreater(end_guard, warmup)
        for marker in (
                "main:entry", "main:after-locale-init",
                "main:after-dosio-init", "main:before-wb-prepare",
                "main:after-wb-prepare", "main:before-py-main",
                "main:after-py-main"):
            self.assertIn(marker, entry)
        self.assertIn("OPENAMIGAPYTHON_TRACE", runtime)
        self.assertIn("OPENAMIGAPYTHON_TRACE_FILE", runtime)
        self.assertIn("OPENAMIGAPYTHON_STARTUP_TRACE", runtime)
        self.assertIn("DH0:ACAgent/OpenAmigaPython.trace", runtime)
        self.assertIn("ADD2INIT(name, priority)", runtime)
        self.assertIn("init:before-socket", runtime)
        self.assertIn("init:after-socket", runtime)
        for marker in (
                "py-main:entry", "py-main:before-random-init",
                "py-main:after-random-init", "py-main:before-initialize",
                "py-main:after-initialize", "py-main:before-set-argv",
                "py-main:after-set-argv", "py-main:before-command",
                "py-main:after-command", "py-main:before-finalize",
                "py-main:after-finalize"):
            self.assertIn(marker, main)
        for marker in (
                "initialize:entry", "initialize:after-environment",
                "initialize:after-random", "initialize:after-thread-state",
                "initialize:after-ready-types", "initialize:after-core-types",
                "initialize:after-module-dicts", "initialize:after-unicode",
                "initialize:after-builtins", "initialize:after-sys",
                "initialize:before-get-path", "initialize:after-get-path",
                "initialize:after-import", "initialize:after-exceptions",
                "initialize:after-import-hooks", "initialize:after-signals",
                "initialize:after-warnings", "initialize:after-main-module",
                "initialize:after-site", "initialize:complete"):
            self.assertIn(marker, pythonrun)
        for marker in (
                "sys-init:entry", "sys-init:after-module",
                "sys-init:before-stdin", "sys-init:after-stdin",
                "sys-init:after-stdout", "sys-init:after-stderr",
                "sys-init:after-standard-streams",
                "sys-init:after-core-metadata",
                "sys-init:after-builtin-names", "sys-init:after-flags",
                "sys-init:complete"):
            self.assertIn(marker, sysmodule)
        self.assertIn("T:OpenAmigaPython.trace", runtime)
        self.assertIn("GVF_GLOBAL_ONLY", runtime)
        self.assertIn("GVF_LOCAL_ONLY", runtime)
        self.assertIn("openamiga_ac4_getenv", runtime)
        self.assertIn("openamiga_ac4_getenv", pydebug)
        self.assertIn("#ifdef OPENAMIGA_GCC_OPEN2", pydebug)
        self.assertIn("Avoid libnix getenv()", getpath)
        self.assertIn('#ifndef OPENAMIGA_GCC_OPEN2\n    char *path = getenv("PATH")',
                      getpath)
        for source in (entry, main, pythonrun, sysmodule):
            self.assertIn("defined(OPENAMIGAPYTHON_STARTUP_TRACE)", source)

    def test_ac4_builtin_profile_excludes_unix_account_database(self):
        setup = (ROOT / "Source/Modules/Setup.ac4").read_text()
        active = [line.split()[0] for line in setup.splitlines()
                  if line and not line.startswith("#")]
        self.assertIn("posix", active)
        self.assertNotIn("pwd", active)

    def test_provenance_document_hashes_binary_and_records_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "python"
            binary.write_bytes(b"amiga executable")
            header = root / "patchlevel.h"
            header.write_text(
                "#define PY_MAJOR_VERSION 2\n"
                "#define PY_MINOR_VERSION 7\n"
                "#define PY_MICRO_VERSION 18\n"
                "#define AC_BUILD 4\n"
                '#define AC_BUILD_TAG "ac4"\n'
            )
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "schema": 1,
                "id": "gcc-16.2-open2",
                "target": "m68k-amigaos",
                "full_version": "16.2.0b",
                "version_stamp": "stamp",
            }))
            args = argparse.Namespace(
                binary=str(binary), manifest=str(manifest),
                compiler="m68k-amigaos-gcc", source_root=str(root),
                version_header=str(header), cflags="-O3 -fwrapv",
                configure_option=["--host=m68k-amigaos"],
                support_object=["Amiga/open2_runtime.o"],
            )
            outputs = ["m68k-amigaos\n", "16.2.0b\n"]
            with mock.patch.object(provenance.subprocess, "check_output",
                                   side_effect=outputs), \
                    mock.patch.object(provenance, "git_state",
                                      return_value=("a" * 40, False)):
                document = provenance.build_document(args)
            self.assertEqual(document["version"], "2.7.18-ac4")
            self.assertEqual(document["binary"]["size"], len(b"amiga executable"))
            self.assertEqual(
                document["binary"]["sha256"],
                hashlib.sha256(b"amiga executable").hexdigest(),
            )
            self.assertEqual(document["toolchain"]["id"], "gcc-16.2-open2")
            self.assertEqual(document["configuration"]["support_objects"],
                             ["Amiga/open2_runtime.o"])


if __name__ == "__main__":
    unittest.main()
