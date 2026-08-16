#!/usr/bin/env python3
"""How much of a default-mode report is dedup-eligible, and how much of THAT
could move a number if the walk order changed?

A duplicate name whose copies all carry the same (fuzzy, size) is a tie no
order can break into a different answer. Only names whose copies DISAGREE are
capable of turning a walk-order flip into a different score.

Usage: dup_surface.py <plain-report.json> [dedup-report.json]
"""
import json
import sys
from collections import defaultdict


def main():
    plain = json.load(open(sys.argv[1]))
    by_name = defaultdict(list)
    for u in plain.get("units", []):
        for f in u.get("functions", []):
            by_name[f["name"]].append(
                (u["name"], f.get("fuzzyMatchPercent", 0.0), f.get("size"))
            )
    dups = {n: v for n, v in by_name.items() if len(v) > 1}
    divergent = {
        n: v for n, v in dups.items() if len({(p, s) for _, p, s in v}) > 1
    }
    total = sum(len(u.get("functions", [])) for u in plain.get("units", []))
    print(f"functions={total} distinct_names={len(by_name)} "
          f"duplicated_names={len(dups)} extra_copies={sum(len(v) - 1 for v in dups.values())} "
          f"divergent_names={len(divergent)}")
    for n, v in list(divergent.items())[:10]:
        print(f"  DIVERGENT {n}")
        for un, p, s in v:
            print(f"      {un}  fuzzy={p} size={s}")
    if len(sys.argv) > 2:
        ded = json.load(open(sys.argv[2]))
        dtotal = sum(len(u.get("functions", [])) for u in ded.get("units", []))
        print(f"dedup report functions={dtotal} dropped={total - dtotal}")


if __name__ == "__main__":
    main()
