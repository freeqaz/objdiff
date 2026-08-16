#!/bin/sh
# Repeat `report generate` N times with ONE binary over ONE unchanged tree and
# report how many distinct outputs came out.
#
# Usage: repeat_report.sh <objdiff-cli> <project-dir> <n> <outdir> [extra args...]
#
# Two things this script exists to get right, both of which have produced a
# false clean result here:
#
#   * Every repeat gets its OWN `-o`. The report cache sidecar path is derived
#     by replacing the `-o` suffix with `.cache`, so two runs sharing an `-o`
#     feed each other and the second one measures the first one's answer.
#   * The `provenance` block is stripped before comparing. It legitimately
#     carries per-run values (cache hit/miss counts, timing), so comparing it
#     reports a difference on a perfectly deterministic pair.
set -eu

BIN=$1
PROJECT=$2
N=$3
OUTDIR=$4
shift 4

mkdir -p "$OUTDIR"
i=1
while [ "$i" -le "$N" ]; do
    "$BIN" report generate -p "$PROJECT" -f json -o "$OUTDIR/run$i.json" "$@" \
        >"$OUTDIR/run$i.log" 2>&1
    python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))
r.pop("provenance", None)
json.dump(r, open(sys.argv[2], "w"), indent=1, sort_keys=True)
' "$OUTDIR/run$i.json" "$OUTDIR/run$i.body.json"
    i=$((i + 1))
done

cd "$OUTDIR"
echo "distinct bodies: $(sha256sum run*.body.json | awk '{print $1}' | sort -u | wc -l) of $N"
sha256sum run*.body.json
