/*
 * Amiga _ssl: CPython 2.7 ssl.py API for OS3, on opentls.library.
 *
 * Built as lib/lib-dynload/_ssl.module (not linked into python27), by
 * Modules/plugin/vmakefile through Modules/plugin/sslmodule_plugin.c. The
 * backend is OpenTLS: sslmodule_opentls.c, with opentls.library's headers
 * through the opentlsinclude: assign.
 *
 * Until 19 October 2026 this file also held an AmiSSL 5 / OpenSSL 3 backend,
 * and sslmodule_amitls.c an amitls.library one, each selectable at build
 * time. The AmigaChrome Team's programs are OpenTLS only now, and both are
 * gone; the git history has them.
 */
#include "sslmodule_opentls.c"
