# OpenUp integration

OpenAmigaPython does not maintain a second installer format. The normal release
drawer is transformed directly into an OpenUp Part by:

```sh
python3 Tools/release/build_release.py
```

The generated `OpenUp/Parts/OpenAmigaPython/` directory is ready to copy into
an OpenUp pack build. Its payload is self-contained, its copy directives are
stable and sorted, and the install destination contains the full `acN` build
identity so upgrades never overwrite a previous runtime in place.

The Part declares `needs AmigaChrome`. OpenMulticore, OpenService, OpenCrypto
and OpenTLS remain optional at runtime; inspect them with:

```
Python -m amigachrome.info
```

OpenUp manages the `Assign Python:` and `Path Python: ADD` startup entries.
There is deliberately no separate Amiga-only package manager: once the base
runtime is complete, pure-Python distribution will use standard pip semantics.
