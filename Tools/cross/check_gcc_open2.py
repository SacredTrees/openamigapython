#!/usr/bin/env python3
"""Refuse an ac4 build unless the exact GCC 16.2-open2 stove is present."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


DEFAULT_STOVE = Path("/home/da1ek/AmigaChrome/stoves/os32-gcc16")
MANIFEST = Path(__file__).with_name("gcc-16.2-open2.json")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path=MANIFEST):
    with Path(path).open("r", encoding="utf-8") as stream:
        result = json.load(stream)
    if result.get("schema") != 1 or result.get("id") != "gcc-16.2-open2":
        raise ValueError("not a GCC 16.2-open2 provenance manifest")
    return result


def checked_path(stove, relative):
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("unsafe provenance path: %s" % relative)
    return stove / relative


def verify(stove, manifest):
    stove = Path(stove).resolve()
    failures = []
    for relative, expected in sorted(manifest["files"].items()):
        path = checked_path(stove, relative)
        if not path.is_file():
            failures.append("missing %s" % relative)
            continue
        actual = sha256(path)
        if actual != expected:
            failures.append("hash mismatch %s" % relative)

    compiler = checked_path(stove, manifest["compiler"])
    if compiler.is_file():
        probes = (
            ([str(compiler), "-dumpmachine"], manifest["target"], "target"),
            ([str(compiler), "-dumpfullversion"], manifest["full_version"], "version"),
        )
        for command, expected, label in probes:
            actual = subprocess.check_output(command, text=True).strip()
            if actual != expected:
                failures.append("%s mismatch: %r" % (label, actual))
        verbose = subprocess.run(
            [str(compiler), "-v"], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=True,
        ).stdout
        if manifest["version_stamp"] not in verbose:
            failures.append("compiler build stamp mismatch")

    if failures:
        raise RuntimeError("GCC 16.2-open2 gate failed:\n- " + "\n- ".join(failures))
    return compiler


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stove",
        default=os.environ.get("OPENAMIGA_GCC_STOVE", str(DEFAULT_STOVE)),
    )
    parser.add_argument("--manifest", default=str(MANIFEST))
    args = parser.parse_args(argv)
    manifest = load_manifest(args.manifest)
    compiler = verify(args.stove, manifest)
    print("OPENAMIGA-GCC-GATE-OK %s" % manifest["id"])
    print("compiler=%s" % compiler)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, ValueError, RuntimeError) as error:
        sys.stderr.write("%s\n" % error)
        raise SystemExit(1)
