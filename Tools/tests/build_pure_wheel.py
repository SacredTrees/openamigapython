"""Build the tiny deterministic wheel used by target-side pip tests."""

from __future__ import print_function

import argparse
import hashlib
from pathlib import Path
import zipfile


FILES = {
    "acsmoke/__init__.py": (
        'VALUE = "openamigapython"\n'
        '__version__ = "1.0"\n'
    ),
    "acsmoke-1.0.dist-info/METADATA": (
        "Metadata-Version: 2.1\n"
        "Name: acsmoke\n"
        "Version: 1.0\n"
        "Summary: OpenAmigaPython offline pip smoke fixture\n"
    ),
    "acsmoke-1.0.dist-info/WHEEL": (
        "Wheel-Version: 1.0\n"
        "Generator: OpenAmigaPython\n"
        "Root-Is-Purelib: true\n"
        "Tag: py2-none-any\n"
    ),
}


def build_wheel(output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = ["%s,," % name for name in sorted(FILES)]
    rows.append("acsmoke-1.0.dist-info/RECORD,,")
    payload = dict(FILES)
    payload["acsmoke-1.0.dist-info/RECORD"] = "\n".join(rows) + "\n"

    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        for name in sorted(payload):
            info = zipfile.ZipInfo(name, (2020, 4, 20, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, payload[name].encode("ascii"))
    return hashlib.sha256(output.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    digest = build_wheel(args.output)
    print("%s  %s" % (digest, args.output))


if __name__ == "__main__":
    main()
