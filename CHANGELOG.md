# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
where practical for Amiga distribution tags.

Baseline for amigazen project work is the classic **AmigaPython 2.0** tree
(Irmen de Jong, Aminet, 28 October 2000), restored in git before the 2.7.18 port.

---

## [Unreleased]

Work on the tree after `7689479` (VBCC / PosixLib upgrade hardening, docs, tests).

### Removed

- `Python/lib/lib-dynload/_ssl.module`, the AmiTLS build: AmiTLS is pulled, as AmiSSL is. _ssl.module returns when ac4's plugins are built (GCC 16.2-open2).
- `_ssl`'s AmiTLS (`Modules/sslmodule_amitls.c`, `SSL_CFLAGS_AMITLS`) and AmiSSL (`Modules/sslmodule.c`'s OpenSSL code, `SSL_CFLAGS_AMISSL`) backends (19 October 2026): `_ssl.module` is OpenTLS only (Dale: AmiSSL and AmiTLS are pulled in favour of OpenTLS)

### Added

- `_ssl` OpenTLS backend (`Modules/sslmodule_opentls.c`, `-DPYAMIGA_USE_OPENTLS`, headers via `opentlsinclude:`), now the default `_ssl.module` build: `opentls.library` API version 1 with SNI, ALPN, `cipher()` / `version()` from the connection, `getpeercert()` decoded from the certificate's DER (subject, issuer, dates, `subjectAltName`), CPython's empty trust store until `load_default_certs()`, and socket timeouts and Ctrl-C honoured through non-blocking I/O; `_ssl.amiga_tls_backend`, `opentls_lib_version`, `opentls_accelerated`; AmiTLS stays selectable with `SSL_CFLAGS_AMITLS`
- OpenAmigaPython `ac2` distribution identity while retaining CPython ABI/version compatibility at 2.7.18
- Reproducible stdlib ZIP ordering and timestamps, plus a host-side release builder that emits a file manifest and `SHA256SUMS`
- Self-contained, versioned OpenUp Part generation with managed `Python:` and command-path startup entries
- `amigachrome.info` capability discovery for OpenMulticore, OpenService, OpenCrypto, OpenTLS, bsdsocket and ACControl
- `amigachrome.acceleration` flat-buffer offload policy with thresholding and mandatory CPU0 fallback
- Host regression coverage for release metadata, OpenUp payloads, capability probing and acceleration success/failure paths

- `Docs/PLUGIN_GUIDE.md` — LoadSeg native C module / PyHost plugin system (ABI, build, hard rules, carve-out checklist); reference `_socket.module`
- Compile-time **SlimPython** vs **standard** interpreter (`make -f vmakefile BUILD=slim|standard`; `compact`/`core`/`full` remain aliases): SlimPython keeps Amiga OS modules and stdlib boot; standard adds pyexpat/Expat, datetime, hashing, csv/bisect/heapq, cmath, pwd/grp/crypt/syslog
- PyHost ABI v2 + FastForward-style LoadSeg module head (security word + ID) for real `.module` plugins
- Real `_socket.module` built from `socketmodule.c` (host trampolines for Python C API, PosixLib sockets, and libc); `socketmodule.o` no longer linked into `Python27`
- Real `_ssl.module` implementing the CPython 2.7 `_ssl` API for `ssl.py`; default backend is `amitls.library` (`-DPYAMIGA_USE_AMITLS`, headers via `amitlsinclude:`); AmiSSL 5 remains an `#ifndef PYAMIGA_USE_AMITLS` branch; TLS I/O uses the AmiTCP native fd from host PosixLib `__fdesc`
- PyHost ABI v6: `ptr_SocketBase`, `fn_socket_native_fd`, PyCapsule/dict/bool/write-buffer trampolines
- PyHost ABI v8: `fn_socket_set_nbio` (host AmiTCP `IoctlSocket`/`FIONBIO`), `fn_object_gc_untrack`
- AmigaTests groups `ssl` / `ssl_net` (AmiTLS + optional live HTTPS GET)
- AmigaTests coverage for `_io` / text I/O and expanded legacy Amiga cases (where present in the working tree)

### Changed

- Default `make -f vmakefile` links **Python27** (standard) and **SlimPython** (slim, named after SlimPython 1.5.2) plus **Python27_Debug**; `config.c` / `getcompiler.c` are compiled twice so both share the other objects
- `dynload_amiga.c`: scan for module ID preceded by security word (FastForward `ff_loader` pattern)
- Plugin build: `-nostdlib`, no `-lposix`/`-lvc` in the `.module` (shared `SocketBase`/`__fdesc` via host)
- VBCC makefiles: PosixLib `-I` before `vincludeos3:` before NDK `include:` so PosixLib `#include_next` reaches vbcc headers while `libraries/*.h` still resolve
- `pyamiga_host.c`: open bsdsocket via PosixLib `__init_bsdsocket(-1)` instead of AmiTCP `proto/socket.h` (avoids macro clashes with PosixLib first on `-I`)
- `libcheck.c`: `SocketBase` owned by PosixLib under `HAVE_POSIXLIB`; do not `CloseLibrary` it on cleanup
- Top-level `vmakefile`: build each subdirectory once (phony `python_dir` / `amiga_dir` / …) instead of once per object file
- Link line: drop early `-lamiga` from `CLIBS` so PosixLib’s `umask` is not overridden by `amiga.lib`

### Fixed

- Objects bigger than 64 KiB (19 October 2026): VBCC works out the index into an array it knows to be smaller than 64 KiB in 16 bits, and CPython's variable-size objects end in a `[1]` array. A string of 64 KiB or more had its NUL written over byte `size % 65536` of its data (so `open().read()`, `recv` joins and slices of big data each had one byte zeroed), tuples of 16384 items or more used the wrong slots, longs past about 491,000 bits gave wrong results, and big list literals and regular expressions failed to compile. Under VBCC those arrays (`ob_sval`, tuple `ob_item`, `ob_digit`, `f_localsplus`, `asdl_seq` `elements`, sre `code`) are now C99 flexible array members (`Py_VAR_ARRAY` in `Include/pyport.h`), which VBCC indexes in 32 bits; AmigaTests `big` checks it
- `md5` gave a wrong digest for every input (19 October 2026): VBCC folds `md5.c`'s run-time byte-order test (`static const int w = 1`) with the byte order of the x86 machine it cross-compiles on, so the 68k took the little-endian path. `md5.c` now sets `ARCH_IS_BIG_ENDIAN` from `pyconfig.h`'s `WORDS_BIGENDIAN`; AmigaTests `builtins` checks RFC 1321's vectors
- `pyamiga_host.c` / `_socket.module`: host A4 for PosixLib trampolines; timeout soft-float via host (`fn_sock_timeout_*`); Amiga `HAVE_SOCKADDR_SA_LEN` + `sin_family` so DNS `gethostbyname` no longer fails with "unknown address family"
- `libcheck.c`: stop using fake `UserGroupBase`/`UtilityBase` pointer `1` (AmiTCP LVOs through a dummy base hard-crash). Open `usergroup.library` / `utility.library` on demand; `checksocketlib()` only succeeds when PosixLib `SocketBase` is already live (gated `_socket` / `__init_bsdsocket`)
- `crypt` / `syslog`: call usergroup/bsdsocket LVOs only after a real library open; soft-fail with `SystemError` otherwise
- `socketmodule.c`: use PosixLib `__P*` sockets (fds in `__fdesc`) so `select`/`settimeout` work; `ioctl(FIONBIO)` for non-blocking; retry `EINTR` in select loops (HTTP GET no longer hangs forever)
- `amiga.getpgrp` / `setsid`: local stubs (PosixLib has no getpgrp; AmiTCP usergroup stubs hang/crash without a live base). Dropped `AmiTCP:libs/usergroup.library` OpenLibrary fallback (missing volume requester lockup)
- `Modules/syslog.c`: PosixLib-style `openlog`/`closelog`/`setlogmask`/`amiga_syslog` via `__init_bsdsocket` + local LVOs (no `proto/socket.h`; PosixLib does not ship these APIs)
- `strftime` / `datetime.strftime`: `_conv` in `Amiga/strftime.c` now NUL-terminates its digit buffer (fixes empty/garbage `%Y-%m-%d` output)
- `socketmodule.c`: undef PosixLib `__P*` socket / netdb macros before AmiTCP `proto/socket.h`; supply `addrinfo` / `EAI_*` / `NI_*` from `addrinfo.h` when PosixLib `netdb.h` lacks them
- Duplicate link symbols after newer PosixLib: `_umask` (`amiga.lib` vs `posix.lib`) and `_SocketBase` (`libcheck.o` vs `posix.lib`)
- `_ssl` AmiTLS: host `IoctlSocket(FIONBIO)` so Python `settimeout` nbio is actually cleared on the AmiTCP fd AmiTLS `recv`s; GC-untrack SSL objects before `DisposeTls*` (fixes 8808 on slow HTTPS hosts and `gcmodule.c:331` at shutdown)

---

## [2.7.18-alpha] - 2026-08-16

Builtin `_io`, GUI/libs modules, and Library Reference–style Amiga docs.
(`7689479`)

### Added

- Builtin `_io` with Amiga no-Unicode text shims so `io` / `tempfile` work without `Py_USING_UNICODE`
- `amigagui` and `amigalibs` modules, intuition helpers, and ConvertFD tooling
- AmigaTests for amigalibs, GUI extras, and expanded builtin coverage

### Changed

- Amiga documentation rewritten to Library Reference–style reST (`Source/Amiga_Misc/Docs`, `Python/Docs/Amiga`)
- Docs and indexes updated for `site-python`, Dos-on-`amiga`, ASL / catalog / icon layout

### Removed

- Obsolete plain-text Amiga module notes superseded by the reST set

---

## [2.7.18-alpha] - 2026-08-15

ASL / catalogs / icons, Dos helpers, site-python bootstrap, pyexpat, classic docs refresh.
(`f9ed3da`)

### Added

- ASL `FileRequest` / `MessageBox`, locale `OpenCatalog`, and icon `DiskObject` on builtin `amiga`
- Path converters `amiga.to_unix` / `amiga.from_unix`, Dos helpers via `_amigados`
- OS4-style shims under `Lib/site-python/` (`asl`, `catalog`, `icon`, `arexx`, …)
- AmigaTests coverage for GUI extras and ziplib-related cases

### Fixed

- `site.py`: Amiga adds `Lib/site-python` to `sys.path` and loads `_amigados` after bootstrap
- pyexpat / expat and related Amiga build wiring for the VBCC port

### Changed

- Classic documentation updated for AmigaPython 2.7.18 (`Python/Docs`, `Amiga_Misc`, `README.AMIGA`, Embed, `CHANGES`, `RunTest`, cheatsheet)
- Contact / branding cleaned of private emails and 1.6/2.0-only wording

### Removed

- Standalone `Lib/Dos.py` in favour of Dos APIs on `amiga` plus a legacy `dos` shim

---

## [2.7.18-alpha] - 2026-08-14

ARexx accelerator, hashlib/crc, more builtins, LoadSeg `_socket`, stdlib tree, AmigaTests foundation.
(`4a29795`, `a8d2673`, `b055626`, `5db468e`)

### Added

- `_arexx` accelerator with high-level ARexx wrappers (replacing `ARexxll` naming)
- `crc.library` hashlib backend and classic Amiga `HAVE_*` exports where applicable
- Builtins: `zipimport`, `datetime`, `_symtable`, `_bisect`, `_heapq`, `_csv` (and related inventory)
- Amiga LoadSeg dynamic C modules and **gated** `_socket` networking: `bsdsocket.library` opens only on `import _socket` via lib-dynload plugin + PyHost ABI (interpreter starts without a TCP stack)
- AmiTCP-safe `getaddrinfo` / `getnameinfo` wrappers (avoid Roadshow-only LVOs that panic on classic stacks)
- Socket test script; separate release vs debug binaries
- Full `Lib/*.py` stdlib tree for the 2.7 port
- AmigaTests runner and smoke-test entry point; inventory / extras / optional net–socket groups
- VBCC-safe `CheckStack`; C-based CRC32 for stack ABI
- `LocaleBase` opened at startup for locale / PosixLib consumers

### Fixed

- `typeobject` `slotdefs` / `slotptr` using `offsetof` (no string-paste macros; safer under VBCC optimisers)
- Amiga paths kept as `volume:path` for PosixLib; more stable `getpath` reduce/prefix behaviour
- `amiga` `ParseTuple` methods registered with `METH_VARARGS`; `access` returns bool
- ARexx build against VBCC proto headers (`BPTR` / `NULL`, missing `strupr`)
- `amiga.uname` without `sys/utsname.h`
- Test suite quieted away from AmiTCP uid calls when stack/usergroup is absent

### Changed

- Optional AmiTCP modules (`pwd`, `grp`, `crypt`, `syslog`) treated as inventory / optional groups rather than hard failures without a stack

---

## [2.7.18-alpha] - 2025-08-16

Mainline merge and build documentation.
(`8e3c525`, `fc46f18`, `4d75d04`)

### Added

- `BUILD.md` build instructions
- README updates for the 2.7.18 / ToolKit-oriented port

### Changed

- Rebased / merged on upstream **Python 2.7.18** mainline into the `AmigaPython2.7.18` line (preferring mainline where conflicts required a choice)

---

## [2.7.18-alpha] - 2025-08-14

First amigazen project alpha toward Python 2.7.18 on classic Amiga.
(`c370a03`, `4eec5bc`)

### Added

- Branch and initial adaptations for **Amiga Python 2.7.18** (first alpha)
- amigazen project `README.md` and `LICENSE.md` after original archives were committed

### Changed

- Project framing: classic AmigaPython continued under amigazen project / ToolKit, not a new language fork

---

## Archive — classic AmigaPython (pre–amigazen project 2.7 work)

Git history preserves the Aminet line before the 2.7.18 port. These commits are archival imports, not amigazen feature releases.

| Date | Commit | Notes |
|------|--------|--------|
| 2025-08-14 | `21b4936` / `0a63008` | **AmigaPython 2.0** (Irmen de Jong, Aminet, 28 Oct 2000) — baseline for this changelog |
| 2025-08-14 | `4c257f9` | Merged Docs folders |
| 2025-08-14 | `8d305bc` | Original Amiga Python **1.6** |
| 2025-08-14 | `617e357` | Original Amiga Python **1.5** + source |
| 2025-08-14 | `b6ec2a4` | Aminet readme for Python **1.4** |
| 2025-08-14 | `cbe62a3` | Initial commit: original Python **1.4** binary-only release |

Historic Aminet package: [dev/lang/Python20](https://www.aminet.net/package/dev/lang/Python20).

---

## Links

- Repository: https://github.com/amigazen/amigapython/
- Docs (Amiga modules): `Python/Docs/Amiga/`, `Source/Amiga_Misc/Docs/`
- Upstream Python 2.7: https://docs.python.org/2.7/

[Unreleased]: https://github.com/amigazen/amigapython/compare/7689479...HEAD
[2.7.18-alpha]: https://github.com/amigazen/amigapython/tree/AmigaPython2.7.18
