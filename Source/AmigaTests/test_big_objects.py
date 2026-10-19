# Objects bigger than 64 KiB.
#
# VBCC works out the index into an array it knows to be smaller than 64 KiB
# in 16 bits, and CPython's variable-size objects end in such an array
# (Py_VAR_ARRAY in Include/pyport.h).  Before that was fixed, a string of
# 64 KiB or more had its NUL written over byte (size % 65536) of its data,
# a tuple of 16384 items or more used the wrong slots, and big longs,
# literals and regular expressions went wrong too.
# ASCII only (Python 2.7 / Amiga).

from __future__ import print_function

from AmigaTests.support import check, require_import, temp_path, safe_remove

# zlib.crc32 of pattern(n), worked out with CPython on Linux.  The sizes
# cross 64 KiB and 128 KiB, both exactly and between, and reach 1.5 MB.
SIZES = (
    (65536, 0xd3f67a9f),
    (70000, 0xce8ac8d1),
    (131072, 0x52713c80),
    (140000, 0xaf57cb94),
    (1500000, 0x75eb95e3),
)


def pattern(n):
    # 256 bytes with no NUL in them, repeated and cut to n
    block = "".join([chr(1 + (i * 7) % 255) for i in range(256)])
    return (block * (n // 256 + 1))[:n]


def crc(data, zlib):
    return zlib.crc32(data) & 0xffffffff


def test_big_strings_read_back():
    zlib = require_import("zlib")
    if not zlib:
        return
    path = temp_path("w91_big.bin")
    try:
        for n, want in SIZES:
            data = pattern(n)
            check("pattern %d crc32" % n, crc(data, zlib) == want,
                  "%08x" % crc(data, zlib))
            check("pattern %d has no NUL" % n, data.find("\0") < 0,
                  "NUL at %d" % data.find("\0"))
            f = open(path, "wb")
            f.write(data)
            f.close()
            f = open(path, "rb")
            got = f.read()
            f.close()
            check("read() %d crc32" % n, len(got) == n and crc(got, zlib) == want,
                  "len %d, NUL at %d" % (len(got), got.find("\0")))
            f = open(path, "rb")
            got = f.read(n + 1)
            f.close()
            check("read(%d) crc32" % (n + 1), len(got) == n and crc(got, zlib) == want,
                  "len %d, NUL at %d" % (len(got), got.find("\0")))
            got = data[1:] + "x"
            check("slice and join %d" % n, got.find("\0") < 0 and got[-2:] == data[-1] + "x",
                  "NUL at %d" % got.find("\0"))
    finally:
        safe_remove(path)


def test_big_tuple():
    n = 20000
    t = tuple(range(n))
    check("tuple[16383]", t[16383] == 16383, t[16383])
    check("tuple[16384]", t[16384] == 16384, t[16384])
    check("tuple[-1]", t[-1] == n - 1, t[-1])
    check("tuple sum", sum(t) == n * (n - 1) // 2, sum(t))
    check("tuple from tuple", tuple(t[i] for i in xrange(n)) == t)


def test_big_long():
    x = (1 << 500000) - 1
    check("long bit_length", x.bit_length() == 500000, x.bit_length())
    check("long + 1", x + 1 == 1 << 500000)
    check("long >>", (x >> 499990) == 1023, x >> 499990)


def test_big_literal():
    n = 20000
    src = "[" + "7," * n + "]"
    try:
        v = eval(compile(src, "big_literal", "eval"))
    except Exception, e:
        check("compile %d-item literal" % n, False, "%s: %s" % (e.__class__.__name__, e))
        return
    check("compile %d-item literal" % n, len(v) == n and v.count(7) == n, len(v))


def test_big_regex():
    re = require_import("re")
    if not re:
        return
    try:
        p = re.compile("a" * 20000 + "b")
    except Exception, e:
        check("re 20001-char pattern", False, "%s: %s" % (e.__class__.__name__, e))
        return
    check("re 20001-char pattern", p.match("a" * 20000 + "b") is not None
          and p.match("a" * 19999 + "b") is None)
