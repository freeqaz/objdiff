#!/usr/bin/env python3
"""Sample function symbols from a project's target objects (units that also
have a built base object), deterministically.

Usage: sample_symbols.py <project-dir> <n>
"""
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fallback_candidates import defined  # noqa: E402


def main():
    proj = Path(sys.argv[1])
    n = int(sys.argv[2])
    cfg = json.loads((proj / "objdiff.json").read_text())
    pool = []
    for u in cfg["units"]:
        tp, bp = u.get("target_path"), u.get("base_path")
        if not tp or not bp or not (proj / bp).exists():
            continue
        pool.extend(sorted(defined(proj / tp, True)))
    pool = sorted(set(pool))
    random.Random(1234).shuffle(pool)
    for s in pool[:n]:
        print(s)
    print(f"# pool={len(pool)} sampled={min(n, len(pool))}", file=sys.stderr)


if __name__ == "__main__":
    main()
