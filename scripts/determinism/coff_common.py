#!/usr/bin/env python3
"""Shared COFF guard for the determinism scripts.

These scripts read the COFF symbol table directly, because `nm` and `llvm-nm`
both refuse MSVC PowerPC objects. The cost of parsing a format by hand is that
a WRONG format parses to nothing rather than to an error: point any of them at
an ELF tree -- rb3 (Wii, mwcceppc) is ELF, rb3-xenon (X360, MSVC) is COFF, and
they sit next to each other -- and every object yields zero symbols, so the
script reports "0 symbols defined in more than one unit" and a reader takes
that for a clean bill of health.

It is not a result, it is a parse failure, and it must say so.
"""

import struct

# IMAGE_FILE_MACHINE_* values. 0x01f2 is IMAGE_FILE_MACHINE_POWERPCBE, the one
# that matters here. IMAGE_FILE_MACHINE_UNKNOWN (0) is deliberately NOT in this
# set: it is legal in a real object but matches almost any non-COFF file, which
# is exactly the confusion this guard exists to prevent.
COFF_MACHINES = frozenset({
    0x014c, 0x0162, 0x0166, 0x0168, 0x0169, 0x0184, 0x01a2, 0x01a3, 0x01a4,
    0x01a6, 0x01a8, 0x01c0, 0x01c2, 0x01c4, 0x01d3, 0x01f0, 0x01f1, 0x01f2,
    0x0200, 0x0266, 0x0284, 0x0366, 0x0466, 0x0520, 0x0cef, 0x0ebc, 0x5032,
    0x5064, 0x5128, 0x6232, 0x6264, 0x8664, 0x9041, 0xaa64,
})

_KNOWN_NOT_COFF = (
    (b"\x7fELF", "an ELF object"),
    (b"!<arch>\n", "an ar archive"),
    (b"\xcf\xfa\xed\xfe", "a Mach-O object"),
    (b"\xce\xfa\xed\xfe", "a Mach-O object"),
    (b"MZ", "a PE image, not an object file"),
    (b"PK\x03\x04", "a zip archive"),
)


class NotCoffError(ValueError):
    """Raised when a file that exists is not a COFF object."""


def require_coff(path, data):
    """Raise `NotCoffError` unless `data` looks like a COFF object file.

    Checks the format markers this repo's neighbours actually produce, then the
    machine id, then the bounds of the symbol table the callers are about to
    index into. Cheap, and it turns a silent empty result into a loud one.
    """
    if len(data) < 20:
        raise NotCoffError(f"{path}: {len(data)} bytes, too short to hold a COFF header")
    for magic, what in _KNOWN_NOT_COFF:
        if data.startswith(magic):
            raise NotCoffError(
                f"{path}: this is {what}, not COFF. These scripts read the MSVC/PE COFF "
                f"symbol table directly and cannot read it. Point them at a COFF project "
                f"(e.g. an X360/MSVC tree), not an ELF one."
            )
    machine, _nsec, _ts, sym_ptr, nsym, _opt, _char = struct.unpack_from("<HHIIIHH", data, 0)
    if machine not in COFF_MACHINES:
        raise NotCoffError(
            f"{path}: COFF machine id {machine:#06x} is not one this recognises, so this "
            f"is almost certainly not a COFF object. Refusing to report zero symbols as "
            f"if it were a finding."
        )
    if sym_ptr and sym_ptr + nsym * 18 > len(data):
        raise NotCoffError(
            f"{path}: COFF symbol table runs past end of file "
            f"(ptr {sym_ptr}, {nsym} symbols, {len(data)} bytes) -- truncated or not COFF."
        )
