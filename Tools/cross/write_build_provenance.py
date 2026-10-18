#!/usr/bin/env python3
"""Write stable provenance for an OpenAmigaPython cross-build."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_version(header):
    text = Path(header).read_text(encoding="utf-8")

    def integer(name):
        match = re.search(r"^#define\s+%s\s+(\d+)\s*$" % name,
                          text, re.MULTILINE)
        if match is None:
            raise ValueError("missing integer macro %s" % name)
        return int(match.group(1))

    tag = re.search(r'^#define\s+AC_BUILD_TAG\s+"([^"]+)"\s*$',
                    text, re.MULTILINE)
    if tag is None:
        raise ValueError("missing AC_BUILD_TAG")
    build = integer("AC_BUILD")
    if tag.group(1) != "ac%d" % build:
        raise ValueError("AC_BUILD and AC_BUILD_TAG disagree")
    return "%d.%d.%d-%s" % (
        integer("PY_MAJOR_VERSION"), integer("PY_MINOR_VERSION"),
        integer("PY_MICRO_VERSION"), tag.group(1),
    )


def git_state(source_root):
    source_root = Path(source_root)
    revision = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    status = subprocess.check_output(
        ["git", "-C", str(source_root), "status", "--porcelain",
         "--untracked-files=normal"],
        text=True,
    )
    return revision, bool(status.strip())


def build_document(args):
    binary = Path(args.binary)
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    if manifest.get("schema") != 1 or manifest.get("id") != "gcc-16.2-open2":
        raise ValueError("not the GCC 16.2-open2 provenance manifest")

    target = subprocess.check_output(
        [args.compiler, "-dumpmachine"], text=True
    ).strip()
    compiler_version = subprocess.check_output(
        [args.compiler, "-dumpfullversion"], text=True
    ).strip()
    if target != manifest["target"] or compiler_version != manifest["full_version"]:
        raise ValueError("compiler does not match provenance manifest")

    revision, dirty = git_state(args.source_root)
    return {
        "schema": 1,
        "product": "OpenAmigaPython",
        "version": parse_version(args.version_header),
        "source": {
            "revision": revision,
            "dirty": dirty,
        },
        "toolchain": {
            "id": manifest["id"],
            "target": target,
            "version": compiler_version,
            "version_stamp": manifest["version_stamp"],
            "compiler": Path(args.compiler).name,
        },
        "configuration": {
            "cflags": args.cflags,
            "configure": args.configure_option,
            "support_objects": args.support_object,
        },
        "binary": {
            "name": binary.name,
            "size": binary.stat().st_size,
            "sha256": sha256(binary),
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--version-header", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--cflags", required=True)
    parser.add_argument("--configure-option", action="append", default=[])
    parser.add_argument("--support-object", action="append", default=[])
    args = parser.parse_args(argv)

    output = Path(args.output)
    output.write_text(
        json.dumps(build_document(args), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("OPENAMIGAPYTHON-PROVENANCE-OK %s" % output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
