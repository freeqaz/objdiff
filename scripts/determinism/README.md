# Determinism repro harness

Scripts that find, reproduce and re-check run-to-run nondeterminism in
`objdiff-cli` against a real project. They exist because `diff --batch` used to
emit a *score* — `raw_match_percent` — that changed between runs of one binary,
and a score that moves on its own makes any A/B measurement unsound.

Everything here takes paths as arguments; nothing hardcodes a project.

## The check you actually run

```sh
scripts/determinism/repeat_batch.sh \
    target/release/objdiff-cli <project-dir> <symbol-list> 15 <outdir>
```

Runs `diff --batch --analyze --verdict` 15 times over the same symbols with the
same binary and reports unstable rows, the fields that moved, and how many
distinct *row orders* came out. The bar is `unstable_rows=0` and
`distinct_row_orders=1`.

One run per repeat is the whole point: `std::collections::HashMap` reseeds its
hasher per process, so a leak of iteration order is invisible within a single
run and only shows up across repeats of the *same* binary. Do not compare two
different builds and call the difference nondeterminism.

## Finding a symbol list that actually flips

A random sample mostly hits symbols with one candidate unit and proves nothing.
These narrow it:

- `coff_dup_symbols.py <project-dir> [target|base]` — symbols defined in more
  than one object on that side. These are COMDATs (inline functions, template
  instantiations, vtable thunks) and they are what makes a symbol → unit index
  a *choice*.
- `fallback_candidates.py <project-dir> [limit]` — symbols that reach the
  cross-unit COMDAT fallback with more than one candidate base unit.
- `sample_symbols.py <project-dir> <n>` — a deterministic broad sample, for a
  magnitude number rather than a targeted one.
- `coff_symbol_bytes.py <object> <symbol>` — sha256 of one symbol's bytes in one
  object. Use it to answer whether two candidate objects hold the *same* body:
  a tie you may break however you like, or two different functions under one
  name, which is an upstream alias collision no tie-break can fix.

These parse COFF directly rather than shelling out; `nm`/`llvm-nm` do not
recognise MSVC PowerPC objects. They **refuse to run on a non-COFF object**
(exit 2, one line, no traceback) rather than reporting zero symbols: rb3 is ELF
and rb3-xenon is COFF, they sit next to each other, and "0 symbols defined in
more than one unit" reads exactly like a clean bill of health when it is really
a parse failure. See `coff_common.py`.

The multiply-defined count is a property of the extracted target objects and
moves when that tree is rebuilt (7 names became 6 mid-session here, an unrelated
rebuild dropping a byte-identical one). The **divergent-body** subset was 3 both
times. Re-derive, don't quote.

## Two things a reader of batch output must know

**A deterministic row is not necessarily an unambiguous one.** Where several
target objects hold genuinely *different* bodies under one name — an ICF alias
collision in the extracted target objects, 3 such names on rb3-xenon — the
resolver's pick is stable but **arbitrary**, and nothing in the emitted row says
so. It reported *lower* than the pre-fix majority answer on 2 of those 3
(`?Null@Symbol@@QBA_NXZ` 48.57 where the old build answered 90.57 on 10 of 15
runs; `?NodeCmp@@YAHPBX0@Z` raw 99.189 where it answered 99.518 on 11 of 15).
The old build was not *more right* — it had no single answer at all — but a
consumer reading one row today cannot tell that row is ambiguous. Surfacing the
ambiguity in the row is follow-up work, tracked separately; until then, check a
surprising low score against `coff_dup_symbols.py` before believing it.

**`--limit` on a batch consumer is now a biased sample, not a random one.**
`rb3-xenon/scripts/harvest/subobject_ref_scan.py --limit` truncates batch rows
positionally without sorting first. Before this fix that prefix was unbiased but
irreproducible; now it is reproducible but a deterministic prefix skewed toward
early units in project-declared order. Nothing banked is invalidated — a
`--limit` run was never reproducible to begin with — but whoever owns that
script should sort or sample explicitly rather than trust the prefix.

## Checking that a determinism fix did not move the numbers

- `compare_runs.py <run*.jsonl>` — the comparator `repeat_batch.sh` calls.
- `score_delta.py <before-dir> <after-dir>` — every answer the old build gave
  for a symbol, against the one the new build gives. Distinguishes "the old
  build was stable and we changed it" from "the old build had no single answer
  to preserve".
- `report_neutrality.py <a.json> <b.json>` — two `report generate` outputs, by
  measures and by the per-function `(unit, name) -> (fuzzy, size)` set. Run it
  per ruler (`-c functionRelocDiffs=none` and `name_check`) and pass
  `--no-cache`, or use one fresh `-o` per binary: the report cache sidecar is
  keyed on the output path.
