#!/usr/bin/env python3
"""List symbols that exercise the cross-unit COMDAT fallback ambiguously.

A symbol qualifies when it is a defined FUNCTION in some target object whose
matching base object does NOT define it, while >=2 *other* base objects do --
so the fallback's base_symbol_index lookup has more than one candidate unit.

Usage: fallback_candidates.py <project-dir> [limit]
"""
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from coff_common import NotCoffError, require_coff  # noqa: E402
from coff_symbol_bytes import symbols  # noqa: E402

IMAGE_SYM_TYPE_FUNC = 0x20


def defined(path, funcs_only):
    out = set()
    try:
        data = path.read_bytes()
    except OSError:
        return out
    # Loud on a non-COFF object: see coff_common. A missing file is a skip, a
    # file in the wrong format is a failed measurement.
    require_coff(path, data)
    (_m, _n, _t, sym_ptr, nsym, _o, _c) = struct.unpack_from("<HHIIIHH", data, 0)
    if sym_ptr == 0 or nsym == 0:
        return out
    strtab = sym_ptr + nsym * 18
    i = 0
    while i < nsym:
        off = sym_ptr + i * 18
        raw = data[off:off + 8]
        _value, secnum, ty, sclass, naux = struct.unpack_from("<IhHBB", data, off + 8)
        if raw[:4] == b"\0\0\0\0":
            so = struct.unpack_from("<I", raw, 4)[0]
            end = data.find(b"\0", strtab + so)
            name = data[strtab + so:end].decode("utf-8", "replace")
        else:
            name = raw.split(b"\0")[0].decode("utf-8", "replace")
        if sclass == 2 and secnum > 0 and (not funcs_only or ty == IMAGE_SYM_TYPE_FUNC):
            out.add(name)
        i += 1 + naux
    return out


def main():
    proj = Path(sys.argv[1])
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    cfg = json.loads((proj / "objdiff.json").read_text())
    units = cfg["units"]
    tdefs, bdefs = {}, {}
    base_owners = {}
    for u in units:
        n = u["name"]
        if u.get("target_path"):
            tdefs[n] = defined(proj / u["target_path"], True)
        if u.get("base_path"):
            b = defined(proj / u["base_path"], True)
            bdefs[n] = b
            for s in b:
                base_owners.setdefault(s, []).append(n)
    out = []
    for u in units:
        n = u["name"]
        for s in tdefs.get(n, ()):
            if s in bdefs.get(n, ()):
                continue
            owners = base_owners.get(s, [])
            if len([o for o in owners if o != n]) >= 2:
                out.append((len(owners), s, n))
    out.sort(key=lambda t: -t[0])
    seen = set()
    for cnt, s, n in out:
        if s in seen:
            continue
        seen.add(s)
        print(s)
        if len(seen) >= limit:
            break
    print(f"# {len(out)} (unit,symbol) fallback-ambiguous pairs, "
          f"{len({s for _, s, _ in out})} distinct symbols", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except NotCoffError as e:
        # Exit 2, not a traceback and never a silent empty result: a wrong-format
        # object means this run measured nothing.
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
