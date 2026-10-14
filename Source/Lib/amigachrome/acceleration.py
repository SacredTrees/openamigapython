"""Conservative OpenMulticore dispatch policy.

CPython object access, allocation and exception handling remain on CPU0.  Only
explicit flat-buffer kernels are candidates for offload.  A failed or absent
native backend always returns to the caller-provided CPU implementation.
"""

CPU0 = "cpu0"
OPENMULTICORE = "openmulticore"

DEFAULT_THRESHOLD = 4096

# Names describe data-parallel operations, not Python callables.  The native
# backend is responsible for mapping a name to an append-compatible OMC ABI.
FLAT_BUFFER_KERNELS = frozenset((
    "copy",
    "crc32",
    "sha256",
    "byteswap32",
    "deflate",
    "inflate",
))


def plan(kernel, size, capabilities=None, threshold=DEFAULT_THRESHOLD):
    """Return a transparent, inspectable dispatch decision."""
    if capabilities is None:
        from amigachrome.info import capabilities as discover
        capabilities = discover()
    if kernel not in FLAT_BUFFER_KERNELS:
        return {"provider": CPU0, "reason": "unsupported-kernel"}
    if size < threshold:
        return {"provider": CPU0, "reason": "below-threshold"}
    if not capabilities.get("openmulticore", False):
        return {"provider": CPU0, "reason": "service-unavailable"}
    return {"provider": OPENMULTICORE, "reason": "eligible"}


def run(kernel, data, fallback, backend=None, capabilities=None,
        threshold=DEFAULT_THRESHOLD):
    """Run an eligible kernel, falling back safely on every backend failure.

    ``fallback`` is called as ``fallback(data)``.  A native backend implements
    ``run(kernel, data)``.  Keeping this boundary byte-buffer-only prevents an
    accelerator from observing CPython objects away from CPU0.
    """
    decision = plan(kernel, len(data), capabilities, threshold)
    if decision["provider"] == OPENMULTICORE and backend is not None:
        try:
            return backend.run(kernel, data)
        except Exception:
            pass
    return fallback(data)

