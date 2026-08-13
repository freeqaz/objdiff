#!/usr/bin/env bash
# Run `objdiff-cli diff --batch --analyze --verdict` N times over the same symbol
# list in the same project with the same binary, and report how many symbol rows
# are not byte-identical across the repeats.
#
# Usage: repeat_batch.sh <objdiff-cli> <project-dir> <symbol-list> <n> <outdir> [extra cli args...]
set -euo pipefail
BIN=$1; PROJ=$2; SYMS=$3; N=$4; OUT=$5; shift 5
mkdir -p "$OUT"
for i in $(seq 1 "$N"); do
  (cd "$PROJ" && "$BIN" diff --batch --analyze --verdict "$@" < "$SYMS") \
    > "$OUT/run$i.jsonl" 2> "$OUT/run$i.err"
done
python3 "$(dirname "$0")/compare_runs.py" "$OUT"/run*.jsonl
