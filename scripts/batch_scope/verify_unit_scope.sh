#!/usr/bin/env bash
# Verify that `objdiff-cli diff --batch -u <unit>` actually scopes to that unit.
#
# `-u` was declared on `Args` and never read by `run_batch`: batch mode walked
# the whole project and returned plausible, wrongly-scoped results. Nothing in
# the output said so, which is why it survived. This is the check that says so.
#
# Usage:
#   scripts/batch_scope/verify_unit_scope.sh <new-cli> <project-dir> [old-cli]
#
# With <old-cli> (a binary built before the fix) it additionally asserts the
# regression that matters most: with NO `-u`, stdout must be byte-identical.
# Six of the seven known batch consumers pass no `-u` at all.
#
# READ-ONLY on the project: it never builds it and never writes into it.
# Needs python3. Scratch goes to a temp dir that is cleaned up.
set -uo pipefail

NEW=${1:?usage: verify_unit_scope.sh <new-cli> <project-dir> [old-cli]}
PROJ=${2:?usage: verify_unit_scope.sh <new-cli> <project-dir> [old-cli]}
OLD=${3:-}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); }

echo "=== $PROJ"

# ---------------------------------------------------------------------------
# A symbol list. Sampling the project at random is NOT good enough: on
# rb3-xenon 400 random symbols landed in 250 different units and missed any
# unit we might name, which makes "the scope restricted the result" vacuously
# true. So sample broadly first, then derive the unit under test from where
# those symbols actually went.
# ---------------------------------------------------------------------------
python3 - "$PROJ" "$TMP/syms.txt" <<'PY'
import json, subprocess, sys, random
proj, out = sys.argv[1], sys.argv[2]
cfg = json.load(open(f"{proj}/objdiff.json"))
units = [u for u in cfg["units"] if u.get("target_path")]
random.seed(7)
syms = []
for u in random.sample(units, min(80, len(units))):
    # nm handles ELF; it refuses MSVC PowerPC COFF, in which case this yields
    # nothing for that unit and we simply take the units it does read. Both
    # object formats in this repo's target projects are covered because the
    # COFF ones fall through to the objdiff-side listing below.
    try:
        p = subprocess.run(["nm", "--defined-only", "-g", "--format=posix",
                            f"{proj}/{u['target_path']}"],
                           capture_output=True, text=True, timeout=20)
        got = [l.split()[0] for l in p.stdout.splitlines()
               if len(l.split()) > 1 and l.split()[1] in "TtWw"]
        syms.extend(got[:8])
    except Exception:
        pass
open(out, "w").write("\n".join(syms[:400]) + "\n")
print(f"    {len(syms[:400])} symbols sampled via nm")
PY

if [ ! -s "$TMP/syms.txt" ] || [ "$(wc -l <"$TMP/syms.txt")" -lt 10 ]; then
    # nm does not recognise MSVC PowerPC objects. Fall back to asking the
    # differ itself: an unscoped batch over the project's own report.
    if [ -f "$PROJ/build"/*/report.json ]; then :; fi
    python3 - "$PROJ" "$TMP/syms.txt" <<'PY'
import glob, json, sys
proj, out = sys.argv[1], sys.argv[2]
rep = sorted(glob.glob(f"{proj}/build/*/report.json"))
if not rep:
    print("    no nm symbols and no report.json — cannot build a symbol list",
          file=sys.stderr)
    sys.exit(3)
d = json.load(open(rep[0]))
names = []
for u in d["units"]:
    for f in (u.get("functions") or [])[:8]:
        names.append(f["name"])
open(out, "w").write("\n".join(names[:400]) + "\n")
print(f"    {len(names[:400])} symbols taken from {rep[0].split('/')[-2]}/report.json")
PY
    [ -s "$TMP/syms.txt" ] || { echo "  SKIP  no symbol list available"; exit 0; }
fi

BATCH=(diff -p "$PROJ" --batch --analyze --verdict -f json)

# ---------------------------------------------------------------------------
# 1. No -u must be byte-identical to the pre-fix binary.
# ---------------------------------------------------------------------------
"$NEW" "${BATCH[@]}" <"$TMP/syms.txt" >"$TMP/open.jsonl" 2>"$TMP/open.err"
if [ -n "$OLD" ]; then
    echo "--- 1. no -u: new vs pre-fix binary"
    "$OLD" "${BATCH[@]}" <"$TMP/syms.txt" >"$TMP/open_old.jsonl" 2>/dev/null
    if cmp -s "$TMP/open_old.jsonl" "$TMP/open.jsonl"; then
        ok "stdout byte-identical ($(wc -l <"$TMP/open.jsonl") rows)"
    else
        bad "stdout differs from the pre-fix binary"
    fi
fi

# ---------------------------------------------------------------------------
# 2/3. Scope: restricts, and does not move a score while doing it.
# ---------------------------------------------------------------------------
UNIT=$(python3 -c "
import json, collections
c = collections.Counter()
for l in open('$TMP/open.jsonl'):
    r = json.loads(l)
    if r.get('unit'): c[r['unit']] += 1
print(c.most_common(1)[0][0] if c else '')
")
[ -z "$UNIT" ] && { echo "  SKIP  unscoped run placed nothing"; exit 0; }
echo "--- 2. -u '$UNIT'"

python3 -c "
import json
ins, outs = [], []
for l in open('$TMP/open.jsonl'):
    r = json.loads(l)
    if r.get('unit') == '$UNIT': ins.append(r['symbol'])
    elif r.get('unit'): outs.append(r['symbol'])
open('$TMP/mixed.txt','w').write('\n'.join(ins + outs[:40]) + '\n')
print(f'    {len(ins)} in-unit + {len(outs[:40])} out-of-unit symbols')
"
"$NEW" diff -p "$PROJ" -u "$UNIT" --batch --analyze --verdict -f json \
    <"$TMP/mixed.txt" >"$TMP/scoped.jsonl" 2>"$TMP/scoped.err"
"$NEW" "${BATCH[@]}" <"$TMP/mixed.txt" >"$TMP/mixed_open.jsonl" 2>/dev/null

python3 - "$UNIT" "$TMP/scoped.jsonl" "$TMP/mixed_open.jsonl" >"$TMP/flags" <<'PY'
import json, sys
unit, sp, op = sys.argv[1], sys.argv[2], sys.argv[3]
scoped = {json.loads(l)["symbol"]: json.loads(l) for l in open(sp)}
opened = {json.loads(l)["symbol"]: json.loads(l) for l in open(op)}
diffed = {k: v for k, v in scoped.items() if not v.get("error")}
print("RESTRICT", "OK" if diffed and all(v["unit"] == unit for v in diffed.values()) else "BAD",
      len(diffed))
# Scoping must not change a row the unscoped run already placed in this unit.
moved = [k for k, v in diffed.items()
         if opened.get(k, {}).get("unit") == unit
         and json.dumps(opened[k], sort_keys=True) != json.dumps(v, sort_keys=True)]
print("NOMOVE", "OK" if not moved else "BAD", len(moved))
# Out-of-unit symbols must be REPORTED, never silently diffed elsewhere and
# never dropped -- silence is the defect this whole flag is about.
oob = [k for k in scoped if opened.get(k, {}).get("unit") not in (unit, None)]
print("OOB", "OK" if oob and all(scoped[k].get("error") == "not_in_unit" for k in oob) else "BAD",
      len(oob))
PY
cat "$TMP/flags" | sed 's/^/    /'
grep -q "^RESTRICT OK" "$TMP/flags" && ok "every diffed row is in '$UNIT'" || bad "rows escaped the unit"
grep -q "^NOMOVE OK"   "$TMP/flags" && ok "scoping moved no score" || bad "scoping changed row content"
grep -q "^OOB OK"      "$TMP/flags" && ok "out-of-unit symbols reported not_in_unit" || bad "out-of-unit symbols mishandled"

# Every requested symbol produced exactly one row: nothing silently vanished.
acct=$(python3 -c "
want = [l.strip() for l in open('$TMP/mixed.txt') if l.strip()]
import json
got = [json.loads(l)['symbol'] for l in open('$TMP/scoped.jsonl')]
print(len(want), len(got), len(set(want) - set(got)))
")
set -- $acct
[ "$3" = "0" ] && ok "all $1 requested symbols accounted for ($2 rows)" \
                || bad "$3 of $1 requested symbols produced no row"

# ---------------------------------------------------------------------------
# 4. An unknown unit is a hard error, before the expensive index walk.
# ---------------------------------------------------------------------------
echo "--- 3. -u NoSuchUnitAtAll"
"$NEW" diff -p "$PROJ" -u NoSuchUnitAtAll --batch -f json \
    <"$TMP/syms.txt" >"$TMP/bad.jsonl" 2>"$TMP/bad.err"
rc=$?
[ "$rc" -ne 0 ] && ok "exit $rc" || bad "exit 0 on an unknown unit"
grep -q "Unit not found: NoSuchUnitAtAll" "$TMP/bad.err" \
    && ok "error names the unit" || bad "error does not name the unit"
[ ! -s "$TMP/bad.jsonl" ] && ok "no stdout rows" || bad "emitted rows anyway"
grep -q "Symbol index built" "$TMP/bad.err" \
    && bad "built the symbol index before failing" \
    || ok "failed before building the symbol index"

# ---------------------------------------------------------------------------
# 5. A basename resolves the way it does on the one-shot path, and says so.
# ---------------------------------------------------------------------------
echo "--- 4. -u '${UNIT##*/}' (basename)"
"$NEW" diff -p "$PROJ" -u "${UNIT##*/}" --batch --analyze --verdict -f json \
    <"$TMP/mixed.txt" >"$TMP/basename.jsonl" 2>"$TMP/basename.err"
if cmp -s "$TMP/basename.jsonl" "$TMP/scoped.jsonl"; then
    ok "basename gives the same rows as the canonical name"
else
    # Legitimate when the basename is ambiguous across units.
    if grep -q "Ambiguous unit" "$TMP/basename.err"; then
        ok "basename is ambiguous here and said so"
    else
        bad "basename run differs for no stated reason"
    fi
fi

echo
echo "=== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
