#!/usr/bin/env python3
"""Compare the fixed run's scores against the full set of answers the old
nondeterministic build produced for the same symbols.

Usage: score_delta.py <before-dir> <after-dir>
"""
import glob
import json
import sys
from collections import defaultdict

F = ("unit", "fuzzy_match_percent", "raw_match_percent", "normalized_match_percent", "base_size")


def load(d):
    runs = []
    for p in sorted(glob.glob(f"{d}/run*.jsonl")):
        r = {}
        for line in open(p):
            o = json.loads(line)
            r[o["symbol"]] = tuple(o.get(k) for k in F)
        runs.append(r)
    return runs


def main():
    before, after = load(sys.argv[1]), load(sys.argv[2])
    a = after[0]
    counts = defaultdict(int)
    seen = defaultdict(lambda: defaultdict(int))
    for r in before:
        for s, v in r.items():
            seen[s][v] += 1
    stable_same = changed = varied = 0
    examples = []
    for s, v in a.items():
        obs = seen.get(s, {})
        if len(obs) == 1:
            if next(iter(obs)) == v:
                stable_same += 1
            else:
                changed += 1
                examples.append((s, next(iter(obs)), v))
        else:
            varied += 1
            if v in obs:
                counts["fixed_answer_was_one_of_the_old_answers"] += 1
            else:
                counts["fixed_answer_is_new"] += 1
            examples.append((s, sorted(obs.items()), v))
    print(f"symbols={len(a)}  old_stable_and_unchanged={stable_same}  "
          f"old_stable_but_changed={changed}  old_varied={varied}")
    for k, v in counts.items():
        print(f"  {k}: {v}")
    for e in examples[:12]:
        print("  *", e[0][:80])
        print("      old:", e[1])
        print("      new:", e[2])


if __name__ == "__main__":
    main()
