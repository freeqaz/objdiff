#!/usr/bin/env python3
"""Dump the section bytes and size of a defined COFF symbol (sha256 + length)."""
import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from coff_common import NotCoffError, require_coff  # noqa: E402


def sections(data):
    (_m, nsec, _t, _sp, _ns, opt, _c) = struct.unpack_from("<HHIIIHH", data, 0)
    off = 20 + opt
    out = []
    for i in range(nsec):
        base = off + i * 40
        name = data[base:base + 8].split(b"\0")[0].decode()
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        out.append((name, rawsize, rawptr))
    return out


def symbols(data):
    (_m, _n, _t, sym_ptr, nsym, _o, _c) = struct.unpack_from("<HHIIIHH", data, 0)
    strtab = sym_ptr + nsym * 18
    i = 0
    while i < nsym:
        off = sym_ptr + i * 18
        raw = data[off:off + 8]
        value, secnum, _ty, sclass, naux = struct.unpack_from("<IhHBB", data, off + 8)
        if raw[:4] == b"\0\0\0\0":
            so = struct.unpack_from("<I", raw, 4)[0]
            end = data.find(b"\0", strtab + so)
            name = data[strtab + so:end].decode("utf-8", "replace")
        else:
            name = raw.split(b"\0")[0].decode("utf-8", "replace")
        aux = data[off + 18:off + 18 + 18 * naux]
        yield name, secnum, sclass, value, aux
        i += 1 + naux


def main():
    obj, want = Path(sys.argv[1]), sys.argv[2]
    data = obj.read_bytes()
    require_coff(obj, data)
    secs = sections(data)
    syms = list(symbols(data))
    # symbol -> (section, value); size = distance to next symbol in same section
    hit = [s for s in syms if s[0] == want and s[2] == 2 and s[1] > 0]
    if not hit:
        print(f"{obj}: NOT DEFINED")
        return
    for name, secnum, _sc, value, _aux in hit:
        sname, rawsize, rawptr = secs[secnum - 1]
        # end = next defined symbol address in the same section, else section end
        addrs = sorted({v for n, sn, sc, v, _a in syms if sn == secnum and v > value})
        end = addrs[0] if addrs else rawsize
        blob = data[rawptr + value:rawptr + end]
        print(f"{obj}  sec={sname} off=0x{value:x} len={len(blob)} "
              f"sha256={hashlib.sha256(blob).hexdigest()[:16]}")


if __name__ == "__main__":
    try:
        main()
    except NotCoffError as e:
        # Exit 2, not a traceback and never a silent empty result: a wrong-format
        # object means this run measured nothing.
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
