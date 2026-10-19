# Local _ssl / ssl smoke tests (no remote hosts).
# Needs a rebuilt _ssl.module plus opentls.library (with opencrypto.library).
# amiga_plugin_rev 14 is the OpenTLS build (12 was AmiTLS and 13 AmiSSL,
# both removed on 19 October 2026).
# ASCII only (Python 2.7 / Amiga).
#
#   python27 AmigaTests/run.py ssl

from __future__ import print_function

import sys

from AmigaTests.support import check, skip, require_import


def test_00_dynload_ssl():
    check("_ssl not builtin", "_ssl" not in sys.builtin_module_names)
    mod = require_import("_ssl", report=True)
    if mod is None:
        return
    rev = getattr(mod, "amiga_plugin_rev", None)
    check("_ssl.amiga_plugin_rev is 14 (OpenTLS)", rev == 14,
          "got %r (rebuild _ssl.module: 14 is OpenTLS; 12 AmiTLS and"
          " 13 AmiSSL are gone)" % (rev,))
    check("_ssl has _SSLContext", hasattr(mod, "_SSLContext"))
    check("_ssl has CERT_NONE", hasattr(mod, "CERT_NONE"))
    check("_ssl has PROTOCOL_TLS", hasattr(mod, "PROTOCOL_TLS"))
    check("_ssl HAS_SNI", getattr(mod, "HAS_SNI", False) is True
          or getattr(mod, "HAS_SNI", 0) == 1)
    check("_ssl HAS_NPN is false", not getattr(mod, "HAS_NPN", True))
    if rev is not None:
        print("  NOTE: amiga_plugin_rev =", rev)
        print("  NOTE: OPENSSL_VERSION =", getattr(mod, "OPENSSL_VERSION", "?"))
        print("  NOTE: opentls.library %s.%s, accelerated=0x%x" % (
            getattr(mod, "opentls_lib_version", "?"),
            getattr(mod, "opentls_lib_revision", "?"),
            getattr(mod, "opentls_accelerated", 0)))
    sys.stdout.flush()


def test_01_txt2obj():
    mod = require_import("_ssl")
    if not mod:
        return
    try:
        t = mod.txt2obj("1.3.6.1.5.5.7.3.1")
        check("txt2obj SERVER_AUTH nid", t[0] > 0, repr(t))
        check("txt2obj SERVER_AUTH oid", t[3] == "1.3.6.1.5.5.7.3.1", repr(t))
    except Exception, e:
        check("txt2obj SERVER_AUTH", False, str(e))


def test_02_import_ssl_package():
    ssl = require_import("ssl", report=True)
    if not ssl:
        return
    check("ssl.SSLContext", hasattr(ssl, "SSLContext"))
    check("ssl.CERT_NONE", ssl.CERT_NONE == 0 or isinstance(ssl.CERT_NONE, (int, long)))
    check("ssl.PROTOCOL_TLS", hasattr(ssl, "PROTOCOL_TLS"))
    check("ssl.create_default_context", callable(ssl.create_default_context))
    check("ssl._create_unverified_context",
          callable(ssl._create_unverified_context))


def test_03_sslcontext_create():
    ssl = require_import("ssl")
    if not ssl:
        return
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        check("SSLContext()", ctx is not None)
        ctx.verify_mode = ssl.CERT_NONE
        check("verify_mode CERT_NONE", ctx.verify_mode == ssl.CERT_NONE)
        ctx.check_hostname = False
        check("check_hostname False", ctx.check_hostname is False)
    except Exception, e:
        check("SSLContext create", False, str(e))


def test_04_unverified_context():
    ssl = require_import("ssl")
    if not ssl:
        return
    try:
        ctx = ssl._create_unverified_context()
        check("unverified context", ctx is not None)
        check("unverified CERT_NONE", ctx.verify_mode == ssl.CERT_NONE)
    except Exception, e:
        check("unverified context", False, str(e))


def test_05_ssl_new_unconnected():
    # SSL_new without a live :443 connect. If this fails, do not run ssl_net
    # (CloseSocket of a handshake-pending fd deadlocks AmiTCP).
    ssl = require_import("ssl")
    socket = require_import("socket")
    if not ssl or not socket:
        return
    sock = None
    raw = None
    sslobj = None
    try:
        ctx = ssl._create_unverified_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw = getattr(sock, "_sock", sock)
        sslobj = ctx._wrap_socket(raw, 0, "localhost")
        check("_wrap_socket unconnected", sslobj is not None)
    except Exception, e:
        check("_wrap_socket unconnected", False, str(e))
    sslobj = None
    sock = None
    raw = None


def _opentls():
    mod = require_import("_ssl")
    if not mod or getattr(mod, "amiga_tls_backend", None) != "opentls":
        skip("OpenTLS backend", "this _ssl.module is not the OpenTLS build")
        return None
    return mod


def test_06_opentls_module():
    mod = _opentls()
    if not mod:
        return
    check("OpenTLS amiga_plugin_rev 14", mod.amiga_plugin_rev == 14)
    check("OpenTLS HAS_ALPN", mod.HAS_ALPN is True)
    check("OpenTLS OPENSSL_VERSION names the library",
          mod.OPENSSL_VERSION.startswith("opentls.library "),
          repr(mod.OPENSSL_VERSION))
    check("OpenTLS library version >= 1", mod.opentls_lib_version >= 1)
    paths = mod.get_default_verify_paths()
    check("OpenTLS default CA file", paths[1] == "S:OpenTLS/ca-bundle.pem",
          repr(paths))


def test_07_opentls_context():
    mod = _opentls()
    ssl = require_import("ssl")
    if not mod or not ssl:
        return
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        stats = ctx.cert_store_stats()
        check("OpenTLS new context trusts nothing", stats["x509_ca"] == 0,
              repr(stats))
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        check("OpenTLS set_alpn_protocols", True)
        ctx.set_ciphers("ECDHE+AESGCM")
        check("OpenTLS set_ciphers accepted", True)
        dctx = ssl.create_default_context()
        check("OpenTLS default context CERT_REQUIRED",
              dctx.verify_mode == ssl.CERT_REQUIRED)
        check("OpenTLS default context check_hostname",
              dctx.check_hostname is True)
    except Exception, e:
        check("OpenTLS context", False, str(e))
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS).load_verify_locations(
            capath="ENVARC:OpenTLS/certs")
        check("OpenTLS capath refused", False, "no exception")
    except NotImplementedError:
        check("OpenTLS capath refused", True)
    except Exception, e:
        check("OpenTLS capath refused", False, str(e))
