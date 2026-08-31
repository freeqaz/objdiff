#!/usr/bin/env bash
#
# Drive a real objdiff-cli through EVERY strict exit code, including the reds.
#
# WHY THIS SCRIPT EXISTS
# ----------------------
# A `--strict` flag nobody has watched fail is worth nothing. The consuming
# decomp repos have a documented case of `rustfmt --check` on stdin ALWAYS
# exiting 0, and of a coverage ratchet silently disarmed by deleting its own
# budget file. Unit tests cover `StrictConfig` in isolation; this covers the
# thing a consumer actually runs -- argument parsing, the wiring at each call
# site, and `main`'s exit-code mapping -- end to end on a real binary.
#
# It is a CONTROL, not a smoke test: every case below asserts an exact exit
# code, and four of them assert a RED. Two are negative controls that assert
# the flag is what makes the difference:
#
#   * the same invocation as the min-match red, WITHOUT --strict, must exit 0.
#     If it does not, the red proves nothing about --strict.
#   * an ordinary failure (symbol not found) must still exit 1. If a strict
#     code leaked onto it, every existing consumer's error handling changed.
#
# USAGE
#   scripts/strict-selftest.sh [path/to/objdiff-cli]
#
# Defaults to target/release/objdiff-cli. Pass an explicit path when testing a
# binary built in a private target dir -- which you should be doing, because
# bin/objdiff-cli in dc3-decomp, rb3 and rb3-xenon are all symlinks to ONE
# shared target/release/objdiff-cli and rebuilding it swaps the measurement
# instrument for three repos at once.
#
# NOTE ON READING EXIT CODES: never `cmd | tail; echo $?`. In zsh that reports
# TAIL's status (and `PIPESTATUS` is empty there; the array is `pipestatus`).
# This script runs each case with no pipe at all.

set -uo pipefail   # deliberately NOT -e: this script's job is to run failures

REPO_ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="${1:-$REPO_ROOT/target/release/objdiff-cli}"
DATA="$REPO_ROOT/objdiff-core/tests/data/ppc"
TGT="$DATA/CDamageVulnerability_target.o"
BASE="$DATA/CDamageVulnerability_base.o"

# A symbol that matches perfectly, and one that does not. Both come from the
# committed fixture pair, so the numbers below are reproducible.
PERFECT='GetVulnerability__20CDamageVulnerabilityCFRC11CWeaponModei'
IMPERFECT='LoadData__20CDamageVulnerabilityFR12CInputStreami'   # 73.97%

if [ ! -x "$CLI" ]; then
  echo "error: $CLI is not an executable objdiff-cli" >&2
  echo "  build one first: cargo build --release --bin objdiff-cli" >&2
  exit 127
fi
for f in "$TGT" "$BASE"; do
  [ -f "$f" ] || { echo "error: missing fixture $f" >&2; exit 127; }
done

echo "instrument: $($CLI --version)"
echo

pass=0; fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# expect <wanted-code> <description> -- <command...>
expect() {
  local want="$1"; shift
  local what="$1"; shift
  [ "$1" = "--" ] && shift
  "$@" >"$tmp/out" 2>"$tmp/err"
  local got=$?
  if [ "$got" = "$want" ]; then
    printf 'ok    exit %s  %s\n' "$got" "$what"
    pass=$((pass + 1))
  else
    printf 'FAIL  exit %s (wanted %s)  %s\n' "$got" "$want" "$what"
    sed 's/^/        | /' "$tmp/err" | head -6
    fail=$((fail + 1))
  fi
}

D=("$CLI" diff -1 "$TGT" -2 "$BASE" -f json --analyze)

# --- 0: green ---------------------------------------------------------------
expect 0 "no --strict at all (default behaviour unchanged)" -- \
  "${D[@]}" "$IMPERFECT"
expect 0 "--strict min-match satisfied" -- \
  "${D[@]}" --strict min-match=70 "$IMPERFECT"
expect 0 "--strict detectors=starved on a symbol whose detectors all ran" -- \
  "${D[@]}" --strict detectors=starved "$IMPERFECT"

# --- 2: threshold violated --------------------------------------------------
expect 2 "--strict min-match=99.5 on a 73.97% symbol" -- \
  "${D[@]}" --strict min-match=99.5 "$IMPERFECT"
expect 2 "--strict min-match=100 on a 73.97% symbol" -- \
  "${D[@]}" --strict min-match=100 "$IMPERFECT"

# NEGATIVE CONTROL. Identical to the case above minus the flag. If this is not
# 0, the reds above are not attributable to --strict and this script is lying.
expect 0 "NEGATIVE CONTROL: the same invocation without --strict" -- \
  "${D[@]}" "$IMPERFECT"

# --- 3: a detector could not run --------------------------------------------
# A 100%-matched symbol has no mismatch rows, so no detector has anything to
# read: 26 of 26 not_applicable. Under the OLD patterns_checked this reported
# "26 patterns checked" and nothing could tell.
expect 3 "--strict detectors on a 100%-matched symbol (all 26 not_applicable)" -- \
  "${D[@]}" --strict detectors "$PERFECT"
# The ruler starving the relocation-fed detectors, which is the state worth
# alerting on and the one detectors=starved exists for.
expect 3 "--strict detectors=starved under functionRelocDiffs=none" -- \
  "${D[@]}" --strict detectors=starved -c functionRelocDiffs=none "$IMPERFECT"
# ...and the control for it: the same symbol under a ruler that starves nothing.
expect 0 "NEGATIVE CONTROL: detectors=starved under functionRelocDiffs=name_address" -- \
  "${D[@]}" --strict detectors=starved -c functionRelocDiffs=name_address "$IMPERFECT"

# --- 4: nothing examined ----------------------------------------------------
# A batch whose every requested symbol is absent. Without the strict channel
# this exits 0 having measured nothing -- the shape that opened this work.
printf 'no_such_symbol_one\nno_such_symbol_two\n' > "$tmp/nosyms.txt"
mkdir -p "$tmp/proj/obj" "$tmp/proj/src"
cp "$TGT" "$tmp/proj/obj/unit.o"
cp "$BASE" "$tmp/proj/src/unit.o"
cat > "$tmp/proj/objdiff.json" <<JSON
{
  "target_dir": "obj",
  "base_dir": "src",
  "units": [{ "name": "unit", "target_path": "obj/unit.o", "base_path": "src/unit.o" }]
}
JSON
expect 4 "--strict on a batch where every symbol was not_found" -- \
  env sh -c "cd '$tmp/proj' && '$CLI' diff --batch --analyze --strict min-match=0 -o - < '$tmp/nosyms.txt'"
# NEGATIVE CONTROL: the identical batch without --strict still exits 0, which
# is precisely the silence this exit code was added to break.
expect 0 "NEGATIVE CONTROL: the same empty batch without --strict exits 0" -- \
  env sh -c "cd '$tmp/proj' && '$CLI' diff --batch --analyze -o - < '$tmp/nosyms.txt'"
# ...and a batch that DID examine something is not swept up by the vacuity gate.
printf '%s\n' "$IMPERFECT" > "$tmp/syms.txt"
expect 0 "a batch that examined one symbol passes --strict min-match=0" -- \
  env sh -c "cd '$tmp/proj' && '$CLI' diff --batch --analyze --strict min-match=0 -o - < '$tmp/syms.txt'"
expect 2 "...and the same batch fails --strict min-match=99.5" -- \
  env sh -c "cd '$tmp/proj' && '$CLI' diff --batch --analyze --strict min-match=99.5 -o - < '$tmp/syms.txt'"

# --- 5: the strict configuration is unusable here ---------------------------
expect 5 "--strict with an unknown rule" -- \
  "${D[@]}" --strict bogus "$IMPERFECT"
expect 5 "--strict min-match with an unparsable threshold" -- \
  "${D[@]}" --strict min-match=abc "$IMPERFECT"
expect 5 "--strict min-match with an out-of-range threshold" -- \
  "${D[@]}" --strict min-match=101 "$IMPERFECT"
expect 5 "--strict detectors with an unknown scope" -- \
  "${D[@]}" --strict detectors=all "$IMPERFECT"
expect 5 "--strict detectors without --analyze (no coverage was computed)" -- \
  "$CLI" diff -1 "$TGT" -2 "$BASE" -f json --strict detectors "$IMPERFECT"
expect 5 "--strict with -f tui (no measured result to adjudicate)" -- \
  "$CLI" diff -1 "$TGT" -2 "$BASE" -f tui --strict min-match=50 "$IMPERFECT"
expect 5 "--strict detectors on \`report generate\` (it runs no detectors)" -- \
  env sh -c "cd '$tmp/proj' && '$CLI' report generate --strict detectors -o '$tmp/r.json'"

# --- 1: ordinary errors are untouched ---------------------------------------
expect 1 "NEGATIVE CONTROL: a symbol that does not exist still exits 1" -- \
  "${D[@]}" --strict min-match=50 no_such_symbol_at_all
expect 1 "NEGATIVE CONTROL: a missing object file still exits 1" -- \
  "$CLI" diff -1 "$tmp/nope.o" -2 "$BASE" -f json --strict min-match=50 "$IMPERFECT"

# --- report generate greens and reds ----------------------------------------
expect 0 "report generate --strict min-match satisfied" -- \
  env sh -c "cd '$tmp/proj' && '$CLI' report generate --strict min-match=10 -o '$tmp/r.json'"
expect 2 "report generate --strict min-match=100 on an imperfect project" -- \
  env sh -c "cd '$tmp/proj' && '$CLI' report generate --strict min-match=100 -o '$tmp/r.json'"
expect 0 "NEGATIVE CONTROL: the same report generate without --strict" -- \
  env sh -c "cd '$tmp/proj' && '$CLI' report generate -o '$tmp/r.json'"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ] || exit 1
# A run that asserted nothing must not report success -- the same rule this
# whole change is about.
[ "$pass" -ge 20 ] || { echo "error: only $pass cases ran; expected >= 20" >&2; exit 1; }
echo "strict channel: every exit code demonstrated, reds included."
