#!/usr/bin/env python3
"""Compare two `report generate` outputs: measures and the per-function
(unit, name) -> (fuzzy, size) set.

Usage: report_neutrality.py <a.json> <b.json>
"""
import json
import sys


def load(p):
    r = json.load(open(p))
    fns = {}
    for u in r.get("units", []):
        un = u.get("name")
        for f in u.get("functions", []):
            fns[(un, f.get("name"))] = (f.get("fuzzyMatchPercent"), f.get("size"))
    return r.get("measures", {}), fns


def main():
    ma, fa = load(sys.argv[1])
    mb, fb = load(sys.argv[2])
    keys = set(ma) | set(mb)
    mdiff = {k: (ma.get(k), mb.get(k)) for k in sorted(keys) if ma.get(k) != mb.get(k)}
    only_a = set(fa) - set(fb)
    only_b = set(fb) - set(fa)
    changed = {k: (fa[k], fb[k]) for k in set(fa) & set(fb) if fa[k] != fb[k]}
    print(f"functions: a={len(fa)} b={len(fb)} only_a={len(only_a)} only_b={len(only_b)} "
          f"changed={len(changed)}")
    print(f"measures differing: {len(mdiff)}")
    for k, v in mdiff.items():
        print(f"  {k}: {v[0]} -> {v[1]}")
    for k, v in list(changed.items())[:10]:
        print(f"  * {k}: {v[0]} -> {v[1]}")
    for k in list(only_a)[:5]:
        print(f"  - only in a: {k}")
    for k in list(only_b)[:5]:
        print(f"  + only in b: {k}")
    return 1 if (mdiff or only_a or only_b or changed) else 0


if __name__ == "__main__":
    sys.exit(main())
