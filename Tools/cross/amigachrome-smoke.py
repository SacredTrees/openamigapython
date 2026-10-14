"""Target-side smoke coverage for the AmigaChrome integration package."""

from amigachrome import acceleration
from amigachrome import info


state = info.snapshot()
assert state["platform"] == "amiga"
assert "openmulticore" in state["capabilities"]

# The policy must never send Python objects to another CPU implicitly.
unsupported = acceleration.plan(
    "python-object", 1024 * 1024, {"openmulticore": True}
)
assert unsupported["provider"] == acceleration.CPU0


class Backend(object):
    def run(self, kernel, data):
        return "omc:" + data


class BrokenBackend(object):
    def run(self, kernel, data):
        raise RuntimeError("simulated secondary CPU failure")


caps = {"openmulticore": True}
result = acceleration.run(
    "copy", "buffer", lambda data: "cpu:" + data,
    backend=Backend(), capabilities=caps, threshold=1,
)
assert result == "omc:buffer"

result = acceleration.run(
    "copy", "buffer", lambda data: "cpu:" + data,
    backend=BrokenBackend(), capabilities=caps, threshold=1,
)
assert result == "cpu:buffer"

print "AMIGACHROME-SMOKE-OK"
print info.format_report(state)
