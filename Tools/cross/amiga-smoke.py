import cStringIO
import csv
import datetime
import hashlib
import itertools
import math
import os
import sys
import zlib

import amiga
import arexx

assert sys.version_info[:3] == (2, 7, 18)
assert sys.platform == "amiga"
assert math.sqrt(81) == 9
assert zlib.decompress(zlib.compress("amigapython")) == "amigapython"
assert datetime.date(2026, 10, 14).year == 2026
assert list(itertools.islice(itertools.count(5), 3)) == [5, 6, 7]
assert hasattr(amiga, "getcwd")
assert hashlib.md5("amiga").hexdigest() == "836821929cb02aade5072aec0c1aa93c"

output = cStringIO.StringIO()
csv.writer(output).writerow(["Amiga", "Python", 27])
assert output.getvalue().startswith("Amiga,Python,27")

print "AMIGAPYTHON-SMOKE-OK"
print sys.version
print sys.platform
print os.getcwd()
