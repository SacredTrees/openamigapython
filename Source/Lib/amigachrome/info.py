"""Report the AmigaChrome services visible to this interpreter."""

from __future__ import print_function

import os
import sys


CAPABILITY_PATHS = (
    ("openmulticore", "LIBS:openmulticore.library"),
    ("openservice", "DEVS:openservice.device"),
    ("opencrypto", "LIBS:opencrypto.library"),
    ("opentls", "LIBS:opentls.library"),
    ("bsdsocket", "LIBS:bsdsocket.library"),
    ("accontrol", "DEVS:accontrol.device"),
)


def _exists(path):
    try:
        return bool(os.path.exists(path))
    except (OSError, IOError):
        return False


def capabilities(probe=None):
    """Return service availability without opening libraries or devices.

    ``probe`` exists for diagnostics and tests.  Production callers normally
    use the Amiga-aware ``os.path.exists`` implementation.
    """
    if probe is None:
        probe = _exists
    result = {}
    for name, path in CAPABILITY_PATHS:
        try:
            result[name] = bool(probe(path))
        except (OSError, IOError):
            result[name] = False
    return result


def snapshot(probe=None):
    return {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "capabilities": capabilities(probe),
    }


def format_report(state=None):
    if state is None:
        state = snapshot()
    lines = [
        "OpenAmigaPython %s" % state["python"],
        "platform=%s" % state["platform"],
    ]
    available = state["capabilities"]
    for name, unused_path in CAPABILITY_PATHS:
        value = "available" if available.get(name, False) else "unavailable"
        lines.append("%s=%s" % (name, value))
    return "\n".join(lines)


def main(argv=None):
    print(format_report())
    return 0


if __name__ == "__main__":
    sys.exit(main())

