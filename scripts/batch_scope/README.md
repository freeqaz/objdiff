# Batch unit-scope verification

`objdiff-cli diff --batch` accepted `-u` / `--unit` and ignored it. `Args`
declared the field, the one-shot path read it, and `run_batch` never did — it
built its object configs from `project_config.units` and walked the entire
project. Callers passing `-u` believed they had unit scope and had
whole-project results.

That bug lived a long time because of *how* it failed. An ignored scope flag
does not error and does not return nothing; it returns a plausible result set
with the wrong scope, and every row the caller wanted is in there, next to
several thousand it did not ask for. No consumer noticed, and the one that
grouped its own work by unit and passed `-u` per unit
(rb3-xenon `tools/classify_nearmiss_codegen.py`) went on keying answers into
per-unit buckets that objdiff had never scoped.

So the check has to assert the *scope*, not merely that a run succeeded.

```sh
scripts/batch_scope/verify_unit_scope.sh \
    target/release/objdiff-cli <project-dir> [pre-fix-cli]
```

Read-only on the project: it never builds it and never writes into it.

## What it asserts

1. **With no `-u`, stdout is byte-identical to a pre-fix binary.** Pass a
   binary built before the fix as the third argument to get this one. It is the
   assertion that matters most — six of the seven known batch consumers pass no
   `-u` at all, so any unscoped divergence is a silent change to all of them.
2. **`-u U` restricts**: every diffed row carries `unit == U`.
3. **`-u U` moves no score.** For a symbol the unscoped run already placed in
   `U`, the scoped row must be identical field for field. Scoping is a scoping
   change; a flag that also changes numbers is a second bug.
4. **Out-of-unit symbols are reported, not dropped and not diffed elsewhere** —
   they come back as `not_in_unit` with a `defined_in` list. Silence is the
   defect being closed, so an empty answer is not an acceptable one.
5. **Every requested symbol produces exactly one row.**
6. **An unknown unit is a hard error naming it, with a non-zero exit and no
   rows — raised before the symbol index is built**, so the operator pays a
   message rather than a multi-minute walk over every object in the project.
7. **A basename resolves as it does on the one-shot path**, or says it is
   ambiguous.

## Picking the unit under test

The script derives it rather than taking it as an argument, because the obvious
way to write this test is vacuous. A broad random sample of a real project does
not intersect any unit you might name: 400 symbols sampled from rb3-xenon
landed in 250 distinct units, so `-u <anything>` returned zero diffed rows and
"all rows are in the requested unit" passed on the empty set.

So it samples broadly, runs *unscoped* first, takes the unit that sample put
the most symbols in, and builds a deliberately mixed list — that unit's symbols
plus forty from elsewhere. Both halves matter: the first proves rows survive
the scope, the second proves the others are refused rather than quietly
answered.

`nm` reads the ELF projects and refuses MSVC PowerPC COFF ("file format not
recognized"), so the sampler falls back to the project's own `report.json` for
those. A fallback that yielded an empty list would make the whole run pass
vacuously, so the empty case exits early and says `SKIP`.

## Verified

30 assertions, 3 projects, both object formats, 2026-08-16:

| project | format | result |
|---|---|---|
| rb3 | Wii, ELF | 10 passed, 0 failed |
| rb3-xenon | X360, MSVC PPC COFF | 10 passed, 0 failed |
| dc3-decomp | X360, MSVC PPC COFF | 10 passed, 0 failed |

### And verified to FAIL against the bug

A regression guard written after the fix has a habit of passing against the bug
it was written for. Point this at a pre-fix binary as the *first* argument and
it must go red:

```sh
scripts/batch_scope/verify_unit_scope.sh <pre-fix-cli> <project-dir>
```

Measured on rb3: **exit 1, 5 passed, 6 failed** — `RESTRICT BAD 48` (all 48
requested symbols answered, spanning many units, where 8 were in the unit),
`OOB BAD 40` (forty out-of-unit symbols answered instead of refused), and all
four unknown-unit assertions. Against the fixed binary, exit 0, 12/12.

**Five of the twelve assertions pass against the buggy binary**, and a reader
counting greens should know none of them is doing the work here. Two pass for a
wrong reason and three pass vacuously:

- **the basename check** — wrong reason. With `-u` ignored, the canonical-name
  run and the basename run return the same whole-project result, so "they
  agree" is true because both are equally unscoped. It tests name *resolution*,
  not scope.
- **the accounting check** ("all N requested symbols accounted for") — wrong
  reason. The buggy binary passes by answering *everything*, which is the bug.
  Accounting catches dropped rows, not over-broad ones.
- **the no-move check** — vacuous: with nothing scoped, no score can have moved.
- **`not_found` survives a scope** — vacuous: with `-u` ignored, a symbol
  defined nowhere was already going to be `not_found`.
- **every `not_in_unit` names where the symbol is defined** — vacuous: the buggy
  binary emits no `not_in_unit` rows at all, so the assertion quantifies over an
  empty set.

None is redundant — each catches a different regression — but `RESTRICT` and
`OOB` are the two that see *this* one. The three vacuous passes guard the fixed
binary, where the sets they quantify over are not empty.

## Known weaknesses of the guard

- **`NOMOVE` is asserted over few rows.** The unit under test is the busiest one
  in a broad sample, and on a project with thousands of units that is still
  thin: 8 rows on rb3, 8 on rb3-xenon, 8 on dc3-decomp. On the COFF projects the
  sampler falls back to `report.json` order, so the unit is simply whichever
  comes first (`default/MasterAudio`, `default/keygen_xbox`) rather than a unit
  chosen to be interesting. Treat a green `NOMOVE` here as a smoke test; the
  exhaustive version is to sweep every multiply-defined symbol against each of
  its defining units.
- **The COFF sampler takes the first 8 functions per unit from `report.json`**,
  so it inherits that file's ordering rather than sampling uniformly.
