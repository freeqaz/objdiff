#!/usr/bin/env python3
"""Compare repeated `diff --batch` JSONL outputs; report per-symbol instability."""
import json
import sys
from collections import defaultdict


def load(path):
    rows = {}
    order = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            rows[o["symbol"]] = o
            order.append(o["symbol"])
    return rows, order


def flatten(o, prefix=""):
    out = {}
    if isinstance(o, dict):
        for k, v in o.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            out.update(flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = o
    return out


def main():
    paths = sys.argv[1:]
    runs = [load(p) for p in paths]
    all_syms = set()
    for r, _ in runs:
        all_syms |= set(r)
    unstable = {}
    field_hits = defaultdict(set)
    for s in sorted(all_syms):
        variants = {json.dumps(r.get(s), sort_keys=True) for r, _ in runs}
        if len(variants) > 1:
            unstable[s] = len(variants)
            flats = [flatten(r.get(s) or {}) for r, _ in runs]
            keys = set()
            for f in flats:
                keys |= set(f)
            for k in keys:
                if len({json.dumps(f.get(k)) for f in flats}) > 1:
                    field_hits[k].add(s)
    orders = {tuple(o) for _, o in runs}
    print(f"runs={len(runs)} symbols={len(all_syms)} unstable_rows={len(unstable)}")
    print(f"distinct_row_orders={len(orders)}")
    for s, n in sorted(unstable.items(), key=lambda kv: -kv[1])[:20]:
        print(f"  {n} variants  {s}")
    if field_hits:
        print("unstable fields (field -> #symbols):")
        for k, v in sorted(field_hits.items(), key=lambda kv: -len(kv[1]))[:40]:
            print(f"  {len(v):5d}  {k}")
    return 1 if unstable or len(orders) > 1 else 0


if __name__ == "__main__":
    sys.exit(main())
