# Build Instructions

Follow these instructions to build AmigaPython.

## Release lines

- `ac3-classic`: AmigaOS 3.2.3-friendly, built with VBCC + PosixLib.
- `ac4`: AmigaChrome-native and built only after the GCC 16.2-open2 provenance
  gate succeeds. ac4 does not promise ABI or binary compatibility with ac3.

## ToolKit

Building AmigaPython is most easily achieved if your development environment is setup following the ToolKit standard. See ToolKit.md or https://github.com/amigazen/ToolKit

## Prerequisites

AmigaPython requires:

- VBCC compiler with PosixLib extension
- NDK3.2
- include: assign pointed at NDK headers
- netinclude: assign pointed at Roadshow headers (included in NDK3.2)

`pyexpat` is linked with the bundled `Modules/expat` sources (same as
desktop Python). No `expat.library` is required. Shared-library callbacks
into VBCC were not reliable on classic Amiga (JMP to data).

### AmigaOS APIs on the `amiga` module

Classic AmigaPython folds OS helpers into the builtin `amiga` module (and
a single `Lib/arexx.py`). This maps to AmigaOS 4 Python extras as follows:

| OS4 import | OS3 AmigaPython |
|------------|-----------------|
| `import asl` | `import asl` (shim) or `amiga.FileRequest` / `MessageBox` |
| `import catalog` | `import catalog` or `amiga.OpenCatalog` |
| `import icon` | `import icon` or `amiga.DiskObject` |
| `import arexx` | `import arexx` (`_arexx` accelerator) |
| dos helpers | `import amiga` (former `Doslib` / `Dos.py` / `amigapath`) |

Amiga filesystems are case-insensitive: only one of `arexx.py` /
`ARexx.py` can exist. Use `arexx`.

### Optional shared libraries

| Library | Used by | If missing |
|---------|---------|------------|
| `crc.library` 2+ | `_hashlib` / `hashlib` | `import _hashlib` raises ImportError |
| `asl.library` | `amiga.FileRequest` | RuntimeError on use |
| `locale.library` | `amiga.OpenCatalog` | RuntimeError on use |
| `icon.library` | `amiga.DiskObject` | RuntimeError on use |
| `rexxsyslib.library` | `_arexx` / `arexx` | ARexx APIs unavailable |
| `bsdsocket.library` | `_socket.module` | `import _socket` fails cleanly |
| `opentls.library` 1+ with `opencrypto.library` | `_ssl.module` (default) | `import _ssl` fails; OpenUp installs both |
| `amitls.library` | `_ssl.module` (AmiTLS build) | `import _ssl` fails |
| AmiSSL 5 (`amisslmaster.library`) | `_ssl.module` (AmiSSL build) | `import _ssl` fails |

The interpreter starts without `crc.library`; install from Aminet when you need hashing.

### LoadSeg plugins (`_socket` / `_ssl`)

Build from `Source/` with VBCC (same as the interpreter):

```
Assign opentlsinclude: <DalsinAI/openamigatls include>
; or for AmiTLS:
Assign amitlsinclude: <AmiTLS SDK Include_H>
; or for AmiSSL:
Assign sslinclude: <AmiSSL SDK Developer/include>

Delete Modules/plugin/sslmodule_plugin.o lib/lib-dynload/_ssl.module
smake -f Modules/plugin/vmakefile
```

`Modules/plugin/vmakefile` selects the `_ssl` backend via `SSL_CFLAGS`:

| `SSL_CFLAGS` | Library | `_ssl.amiga_plugin_rev` |
|--------------|---------|-------------------------|
| `SSL_CFLAGS_OPENTLS` (default) | `opentls.library` | 14 |
| `SSL_CFLAGS_AMITLS` | `amitls.library` | 12 |
| `SSL_CFLAGS_AMISSL` (experimental) | AmiSSL 5 | 13 |

OpenTLS (`Modules/sslmodule_opentls.c`) is the AmigaChrome Team's TLS client:
BearSSL with `opencrypto.library` doing the maths, which AmigaChrome runs on
its x86 or ARM64 cores (`_ssl.opentls_accelerated` shows which). Its
`include/` needs the VBCC calls in `inline/opentls_protos.h` (openamigatls's
`tools/gen_opentls_headers.py` writes them); GCC uses `inline/opentls.h`.
What it offers through `ssl.py`:

- TLS 1.2 for `PROTOCOL_TLS` (1.0 and 1.1 only when asked for by protocol),
  SNI, ALPN (`set_alpn_protocols`), `cipher()` and `version()` from the
  connection, and `getpeercert()` with subject, issuer, dates and
  `subjectAltName`, so `ssl.match_hostname` works.
- The trust store: a new context trusts nothing, as CPython's, until
  `load_default_certs()` / `set_default_verify_paths()` (then
  `S:OpenTLS/ca-bundle.pem` and `ENVARC:OpenTLS/certs/*.pem`) or
  `load_verify_locations(cafile=..., cadata=...)`.
- Not offered by OpenTLS API version 1: server sockets, client certificates,
  NPN, `capath`.

AmiSSL builds import and wrap, but `SSL_connect` currently fails with
`SSLERR` / `want=NOTHING` (empty ERR queue) on live HTTPS. See the BUG
comment in `Modules/sslmodule.c`.

Flip the commented `SSL_CFLAGS=` line in that vmakefile to switch. After rebuild:

```
python27 AmigaTests/run.py ssl ssl_net
```

Expect `OPENSSL_VERSION` to show `opentls.library`, AmiTLS or OpenSSL/AmiSSL
text accordingly; the OpenTLS build also sets `_ssl.amiga_tls_backend` to
`"opentls"`.

## Compiler

The ac4 development line requires the verified GCC 16.2-open2 stove.

| SAS/C | VBCC | GCC |
|-------|------|-----|
| [ ]   | [ ]  | [X] |

The preserved `ac3-classic` branch uses VBCC + PosixLib. ac4 is a separate GCC
16.2-open2-only product line and must not silently fall back to another GCC or
to ac3 VBCC objects.

Before compiling any ac4 object, verify the complete compiler, front ends,
runtime libraries and OpenAmigaGCC patch set against the pinned provenance
manifest:

```sh
python3 Tools/cross/check_gcc_open2.py
```

The compiler's upstream version text is `16.2.0b`; it does not itself contain
the OpenAmiga release label. The gate therefore also checks the dated compiler
build, `cc1`, `cc1plus`, patched libnix/libpthread archives and the GCC 0001-0010,
libnix 0001-0006 and pthread 0001-0004 patch files by SHA-256. ac4 sources also
require `OPENAMIGA_GCC_OPEN2` at compile time, so bypassing the gate with VBCC
or a generic GCC fails in `pyconfig.h`.

## How To Build ac4

The ac4 makefile conversion follows the provenance gate above. Until that
conversion is complete, the repository intentionally has no command that can
produce an ac4 binary: the VBCC builder refuses ac4 and `pyconfig.h` rejects any
compiler invocation that does not carry the verified-open2 build definition.

## How To Build ac3-classic

Check out the `ac3-classic` branch, then use the classic ToolKit assignments:

```
Assign Python: Source/
cd Source/
make -f vmakefile
```

This creates **Python27** (standard / full) and **SlimPython** (slim / core, named after SlimPython 1.5.2) in the Source folder, plus **Python27_Debug**.

## Standard vs SlimPython

Two compile-time builds. C modules that own a `PyTypeObject` (or Expat callbacks) cannot be LoadSeg plugins, so extras are omitted from the **SlimPython** link instead.

```
make -f vmakefile                  # Python27 + SlimPython + Python27_Debug
make -f vmakefile slim             # SlimPython only (aliases: compact, core)
make -f vmakefile standard         # Python27 only (alias: full)
make -f vmakefile debug BUILD=slim # SlimPython_Debug
```

`BUILD=compact` and `BUILD=core` remain aliases for slim; `BUILD=full` remains an alias for standard (`debug` / `release` use `BUILD` to pick which binary to stage).

`config.c` and `getcompiler.c` are compiled twice (`config.o` / `config_slim.o`, `getcompiler.o` / `getcompiler_slim.o`) so both interpreters can share the rest of the objects.

| Build | Binary | Use |
|---------|--------|-----|
| **slim** | `SlimPython` | Amiga scripting: `amiga` / GUI / ARexx / ENV / DOS, zip stdlib (`zipimport`+`zlib`+`_io`+`_sre`), pickle, collections/itertools, `select` for the `_socket` plugin |
| **standard** | `Python27` | SlimPython plus XML (`pyexpat`+Expat), `datetime`, `cmath`, md5/sha/`_hashlib`, `_csv`/`_bisect`/`_heapq`, `pwd`/`grp`/`crypt`/`syslog` |

LoadSeg `_socket.module` / `_ssl.module` are built for both. `sys.version` shows `[VBCC-SlimPython]` or `[VBCC-standard]`.

## How to Clean

```
make -f vmakefile clean
```

## Workbench vs Shell

- **Shell / CLI:** stdin/stdout/stderr stay on the shell console (unchanged).
- **Workbench (icon double-click):** PosixLib has no SAS/C `__stdiowin`. The
  binary opens one `CON:.../CLOSE/SMART` (no WAIT — window closes when the
  FH is closed), clears all `PRF_CLOSE*` flags, and Closes the FH once on
  exit. Link with `-lposix` before `-lvc` (see `aos68k_posix`) so vclib
  fclose does not Close the same CON BPTR for each of stdin/stdout/stderr.
  Needs `lib/python27.zip` beside the tool (copy-anywhere) or optional
  `Assign Python:`. Quit via the CON close gadget or Ctrl+C.
- **Workbench + project icon** (Default Tool = Python): after the same
  console setup, `sm_ArgList[1]` is the script. The port uses
  `CurrentDir(wa_Lock)` + leaf `wa_Name` (no Lock of the project path while
  Workbench still owns startup locks). Extension need not be `.py`.

See `Source/Amiga/wbconsole.c` and RKR M DOS CON-Handler notes.

After a successful build in `Source/`:

```
make -f vmakefile release
```

This copies **public binary release artifacts** into the sibling `Python/`
drawer. AmigaDOS paths use `/Python` (parent). Do **not** pass those paths
into `Python27` — PosixLib treats `/` as volume root, not parent.

| From `Source/` | To `Python/` |
|----------------|--------------|
| `Python27` (stripped release link) | `Python` |
| `lib/lib-dynload/_socket.module` | `lib/lib-dynload/_socket.module` |
| `lib/lib-dynload/_ssl.module` | `lib/lib-dynload/_ssl.module` |
| `Lib/site-python/#?.py` | `lib/site-python/` |
| `Lib/` via `mkpythonzip` -> `python27.zip`, then Copy | `lib/python27.zip` |

`python27.zip` is the zipimported stdlib (excludes `test/`, `plat-*`, idle/tk, and other non-Amiga packages). LoadSeg plugins stay outside the zip under `lib/lib-dynload/`.

### Reproducible release and OpenUp Part

After building `Source/Python27` and `Source/lib/python27.zip`, assemble the
versioned release and its OpenUp input with:

```sh
python3 Tools/release/build_release.py
```

The tool reads `AC_BUILD` from `Source/Include/patchlevel.h`; it does not accept
an unrelated version on the command line. It produces:

- `dist/staging/OpenAmigaPython-<version>/` — standalone drawer with
  `openamigapython-release.json` and `SHA256SUMS`;
- `dist/staging/OpenUp/Parts/OpenAmigaPython/` — self-contained OpenUp Part
  and payload.

The OpenUp install is versioned below
`SYS:Tools/OpenAmigaPython/<version>/`. OpenUp owns both startup entries:
`Assign Python:` selects that version and `Path Python: ADD` provides the
normal command-line experience. Updating or removing the Part therefore does
not require an OpenAmigaPython-specific installer.

Host-side validation is intentionally independent of the cross toolchain:

```sh
python3 -m unittest discover -s Tools/tests -v
```

The ac3 packaging gate also installs a deterministic pure-Python wheel on the
target with no index or dependency resolution, then validates both importing
the package and discovering its metadata through `pkg_resources`:

```text
Python -m pip --disable-pip-version-check --no-python-version-warning \
  --no-cache-dir install --no-index --no-deps --no-compile \
  --target wheel-target wheels/acsmoke-1.0-py2-none-any.whl
Python pip-wheel-smoke.py
```

### Standalone release drawer (`Python/`)

`Python/` is the copy-anywhere end-user product (no installer script):

| Path | Role |
|------|------|
| `Python` | Interpreter binary |
| `Python.help` | AmigaDOS Help text |
| `lib/` | `python27.zip`, `lib-dynload/`, `site-python/` |
| `Help/AmigaPython.guide` | Port guide (AmigaGuide) |
| `Help/DiveIntoPython/` | Dive Into Python (AmigaGuide, GFDL) |
| `Help/Amiga/` | Amiga module notes (reST) |
| `Demo/` | Amiga-checked example scripts |
| `Demo/`, `Icons/` | Examples and icon extras |
| `README`, `DISCL_and_COPYRIGHT` | Quick start and licenses |

Regenerate Dive Into Python guides on a host with Python 3:

```
python3 Source/Tools/amiga/html2amigaguide.py \
  path/to/diveintopython.html Python/Help/DiveIntoPython
```

It does **not** copy `Python27_Debug`, object trees (`build-vbcc`), or documentation from the build. Docs, demos, and icons under `Python/` are maintained in-tree.

`release` depends on `Python27` and `plugins`, so those targets are built first if missing.
