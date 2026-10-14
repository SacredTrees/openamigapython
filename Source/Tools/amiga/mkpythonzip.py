# Build python27.zip from Lib/ for AmigaPython public release packaging.
# Run from Source/ with a working interpreter that can import zipfile:
#   Python27 Tools/amiga/mkpythonzip.py
#   Python27 Tools/amiga/mkpythonzip.py Lib python27.zip
#
# Do not pass AmigaDOS parent paths like /Python/... into this script:
# PosixLib open()/stat() treat / as volume root, not parent.

# Zip members are relative to Lib/ (and site-python/*.py at archive root).
# LoadSeg plugins stay outside the zip under lib/lib-dynload/.
#
# Uses ZipFile.writestr() rather than write(): write() seeks backwards to
# patch local headers, and that seek fails on some Amiga/PosixLib handles
# (IOError with errno 0).

from __future__ import print_function

import os
import sys

# Prefer flat Lib/ over any python27.zip already on sys.path (old archives
# may still ship a unicode-dependent zipfile.py).
if sys.version_info[0] == 2 and os.path.isdir("Lib"):
    sys.path.insert(0, os.path.abspath("Lib"))
elif sys.version_info[0] == 2:
    _here = os.path.dirname(os.path.abspath(sys.argv[0]))
    _lib = os.path.join(os.path.dirname(os.path.dirname(_here)), "Lib")
    if os.path.isdir(_lib):
        sys.path.insert(0, _lib)

import zipfile

# Use the earliest timestamp accepted by the ZIP format.  Amiga builds often
# run without a reliable real-time clock, and source mtimes must not make two
# otherwise identical releases differ.
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

# Directories under Lib/ that are not shipped in the Amiga stdlib zip.
SKIP_DIRS = {
    "test",
    "site-packages",
    "site-python",
    "lib-dynload",
    "idlelib",
    "lib-tk",
    "lib2to3",
    "ensurepip",
    "bsddb",
    "ctypes",
    "curses",
    "hotshot",
    "multiprocessing",
    "sqlite3",
    "msilib",
}


def _is_plat_dir(name):
    return name.startswith("plat-")


def _skip_file(name):
    if name.startswith("."):
        return 1
    if name.endswith(".pyc") or name.endswith(".pyo"):
        return 1
    if name.endswith(".egg-info"):
        return 1
    return 0


def _add_file(zf, abspath, arcname, compression):
    """Read file and writestr - no seek-back required."""
    f = open(abspath, "rb")
    try:
        data = f.read()
    finally:
        f.close()
    info = zipfile.ZipInfo(arcname, ZIP_TIMESTAMP)
    info.compress_type = compression
    # Regular file, mode 0644.  This keeps host umasks out of the archive.
    info.external_attr = (0o100644 << 16)
    zf.writestr(info, data)


def _add_tree(zf, root, rel_prefix, compression):
    """Add files under root into zf; rel_prefix is archive path prefix or ''."""
    stack = [""]
    while stack:
        rel = stack.pop()
        absdir = root if rel == "" else os.path.join(root, rel)
        try:
            names = sorted(os.listdir(absdir), reverse=True)
        except OSError:
            continue
        for name in names:
            if _skip_file(name):
                continue
            abspath = os.path.join(absdir, name)
            relpath = name if rel == "" else os.path.join(rel, name)
            if os.path.isdir(abspath):
                if name in SKIP_DIRS or _is_plat_dir(name):
                    continue
                stack.append(relpath)
                continue
            arcname = relpath
            if os.sep != "/":
                arcname = arcname.replace(os.sep, "/")
            if rel_prefix:
                arcname = rel_prefix + "/" + arcname
            _add_file(zf, abspath, arcname, compression)


def _add_site_python(zf, site_dir, compression):
    """Flatten Lib/site-python/*.py into the zip root (overrides / extras)."""
    if not os.path.isdir(site_dir):
        return
    for name in sorted(os.listdir(site_dir)):
        if _skip_file(name) or not name.endswith(".py"):
            continue
        abspath = os.path.join(site_dir, name)
        if os.path.isfile(abspath):
            _add_file(zf, abspath, name, compression)


def main(argv):
    libdir = "Lib"
    outzip = "python27.zip"
    if len(argv) >= 2:
        libdir = argv[1]
    if len(argv) >= 3:
        outzip = argv[2]

    if not os.path.isdir(libdir):
        sys.stderr.write("mkpythonzip: Lib directory not found: %s\n" % libdir)
        return 1

    outdir = os.path.dirname(outzip)
    if outdir and not os.path.isdir(outdir):
        try:
            os.makedirs(outdir)
        except OSError:
            # Amiga may need MakeDir ALL from the makefile first.
            pass

    # Keep members stored.  This is deterministic across host/target zlib
    # versions, is faster on 68k, and avoids a target zlib/zipimport edge case
    # that can corrupt the leading byte of larger deflated Python modules.
    compression = zipfile.ZIP_STORED

    zf = zipfile.ZipFile(outzip, "w", compression)
    try:
        _add_tree(zf, libdir, "", compression)
        _add_site_python(zf, os.path.join(libdir, "site-python"), compression)
    finally:
        zf.close()

    print("Wrote %s (%d bytes)" % (outzip, os.path.getsize(outzip)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
