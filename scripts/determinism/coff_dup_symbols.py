#!/usr/bin/env python3
"""Find function symbols defined in more than one object file of an objdiff project.

Reads objdiff.json, parses the COFF symbol table of every target (and base)
object, and reports symbols whose defining unit is ambiguous -- these are the
inputs that make a first-wins HashMap index nondeterministic.

Usage: coff_dup_symbols.py <project-dir> [target|base]
"""
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from coff_common import NotCoffError, require_coff  # noqa: E402

IMAGE_SYM_CLASS_EXTERNAL = 2


def coff_symbols(path: Path):
    """Yield (name, section_number, storage_class, value) for a COFF object."""
    data = path.read_bytes()
    require_coff(path, data)
    (_machine, nsec, _ts, sym_ptr, nsym, _opt, _char) = struct.unpack_from("<HHIIIHH", data, 0)
    if sym_ptr == 0 or nsym == 0:
        return
    strtab_off = sym_ptr + nsym * 18
    if strtab_off + 4 > len(data):
        return
    i = 0
    while i < nsym:
        off = sym_ptr + i * 18
        if off + 18 > len(data):
            break
        raw = data[off:off + 8]
        value, secnum, _type, sclass, naux = struct.unpack_from("<IhHBB", data, off + 8)
        if raw[:4] == b"\0\0\0\0":
            stroff = struct.unpack_from("<I", raw, 4)[0]
            end = data.find(b"\0", strtab_off + stroff)
            name = data[strtab_off + stroff:end].decode("utf-8", "replace")
        else:
            name = raw.split(b"\0")[0].decode("utf-8", "replace")
        yield (name, secnum, sclass, value)
        i += 1 + naux


def main():
    proj = Path(sys.argv[1])
    side = sys.argv[2] if len(sys.argv) > 2 else "target"
    cfg = json.loads((proj / "objdiff.json").read_text())
    units = cfg["units"]
    index = {}
    for idx, u in enumerate(units):
        p = u.get(f"{side}_path")
        if not p:
            continue
        op = proj / p
        if not op.exists():
            continue
        # A NotCoffError is NOT a per-file skip: one wrong-format object means
        # the whole run is measuring nothing, and a "0 duplicates" line would
        # read as a result. Let it terminate the run.
        try:
            for name, secnum, sclass, _v in coff_symbols(op):
                # defined external symbols only
                if sclass != IMAGE_SYM_CLASS_EXTERNAL or secnum <= 0:
                    continue
                index.setdefault(name, []).append(u["name"])
        except NotCoffError:
            raise
        except Exception as e:  # noqa: BLE001
            print(f"# skip {op}: {e}", file=sys.stderr)
    dups = {k: v for k, v in index.items() if len(set(v)) > 1}
    print(f"# {side}: {len(index)} defined externals, {len(dups)} defined in >1 unit",
          file=sys.stderr)
    for name, us in sorted(dups.items(), key=lambda kv: (-len(set(kv[1])), kv[0])):
        print(f"{len(set(us))}\t{name}\t{','.join(sorted(set(us))[:6])}")


if __name__ == "__main__":
    try:
        main()
    except NotCoffError as e:
        # Exit 2, not a traceback and never a silent empty result: a wrong-format
        # object means this run measured nothing.
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
