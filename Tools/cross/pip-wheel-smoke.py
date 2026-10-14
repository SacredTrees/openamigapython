"""Verify the package installed by the offline pure-wheel smoke test."""

import os
import sys

target = os.path.join(os.getcwd(), "wheel-target")
sys.path.insert(0, target)

import acsmoke
import pkg_resources

pkg_resources.working_set.add_entry(target)

assert acsmoke.VALUE == "openamigapython"
assert acsmoke.__version__ == "1.0"
distribution = pkg_resources.get_distribution("acsmoke")
assert distribution.version == "1.0"

print "OPENAMIGAPYTHON-PIP-WHEEL-SMOKE-OK"
print "acsmoke", distribution.version, distribution.location
