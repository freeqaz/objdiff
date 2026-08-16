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

## `report generate`, including `--deduplicate`

```sh
scripts/determinism/repeat_report.sh \
    target/release/objdiff-cli <project-dir> 6 <outdir> --deduplicate
```

Repeats `report generate` and reports how many distinct report *bodies* came
out. Two details it exists to get right, both of which have produced a false
result here:

- **One `-o` per repeat.** The report cache sidecar path is the `-o` path with
  the suffix replaced, so two runs sharing an `-o` feed each other and the
  second measures the first one's answer rather than the tree.
- **Strip `provenance` before comparing.** It legitimately carries per-run
  values (cache hits/misses), so comparing it reports a difference on a
  perfectly deterministic pair.

`dup_surface.py <plain-report.json> [dedup-report.json]` bounds what any
dedup-ordering bug could ever do to a given tree: it counts the names defined
in more than one unit, and — the number that matters — how many of those have
copies that *disagree* on `(fuzzy, size)`. Copies that agree are a tie no walk
order can break into a different answer.

### `--deduplicate` was measured and is NOT nondeterministic (2026-08-16)

`report generate --deduplicate` was carried as a "known remaining exposure"
with a figure attached — `fuzzy_match_percent` moving ~0.47 pp and
`matched_functions` by up to 104 — in `a08c12a`, `bd389f0` and the 2026-08-13
landing doc. **That figure is unsourced and did not reproduce.** No primary
artifact for it exists anywhere on this machine: all three mentions restate the
same sentence, each says "has been measured" in the passive with no project,
binary or run count, and the landing doc attributes it to "review". Every other
number in those same messages names its tree, its binary and its run count.

Measured on `6bf7ba7`, one binary per row, per-run `-o`, provenance stripped,
input trees fingerprinted before and after (mtime+size over the object trees;
unmoved). `dropped` is how many functions `-d` removes on that tree — the
ceiling on what any dedup-ordering bug could possibly do there:

| project | ruler | dropped by `-d` | repeats | distinct bodies |
| --- | --- | --- | --- | --- |
| dc3-decomp | project default (`none`) | 19 | 20 | 1 |
| dc3-decomp | `-c functionRelocDiffs=none` | 19 | 6 | 1 |
| rb3-xenon | project default (`name_check`) | 1 | 5 | 1 |
| rb3-xenon | `-c functionRelocDiffs=none` | 1 | 6 | 1 |
| rb3 | project default | 0 | 6 | 1 |
| decomp-clones/zeldaret_tww | project default | **12,266** | 6 | 1 |
| decomp-clones/zeldaret_tp | project default | **10,542** | 6 | 1 |
| decomp-clones/mariopartyrd_marioparty4 | project default | **1,296** | 6 | 1 |

(Surface census over every project on this box that generates a report:
`zeldaret_ss` 3,210 dropped, `cea-decomp` 169, and 0 for melee, bfbb,
smstrikers, FFCC and the three pikmin trees.)

The three game repos have almost no dedup surface at all — 19, 1 and 0
functions — so a flat result on them alone would prove little. The clone trees
are the real test: `zeldaret_tww` defines 360 names in more than one unit
(12,708 surplus copies, 51 of them disagreeing on `(fuzzy, size)`) and
`mariopartyrd_marioparty4` has 826 divergent duplicated names out of 876. If
walk order leaked into the answer anywhere, those are the trees that would show
it, and they do not.

`dup_surface.py` also bounds the specific claim about `matched_functions`: on
all five trees examined, **zero** duplicated names have one copy at 100% and
another below it, so no choice between copies can move `matched_functions` by
even 1, let alone 104. The entire effect of `-d` on dc3-decomp — not its
variance, its whole effect — is 19 functions and 53.88503 → 53.885654, i.e.
0.0006 pp. On rb3 (Wii, mwcc) `-d` drops nothing at all: its duplicate names
are local, and `-d` only suppresses global/weak.

The comparator is not blind, either: on the same tree it separates default
(`dd6bcae7…`), `-d` (`1d05f95b…`) and a second ruler (`c50b255b…`) into three
distinct hashes.

A guess at where the figure came from, offered as a guess: numbers of exactly
that magnitude are what `-d` *itself* does, i.e. the difference between the two
MODES, not between two runs of one mode. On `zeldaret_tww`, turning `-d` on
moves `fuzzy_match_percent` 77.01107 → 77.24625 (+0.235 pp) and
`matched_functions` 31,534 → 22,375; on `zeldaret_ss`, 31.92137 → 31.23235
(−0.69 pp). A default-vs-`-d` pair read as a repeat-run pair produces a claim
shaped exactly like this one.

**Trees move under you.** rb3-xenon's object fingerprint changed mid-session
here (`77cc8648…` → `dd1468f5…`) — peers rebuild it — so its reports from
07:36 and 08:20 differ for reasons that have nothing to do with the binary.
Fingerprint before and after, and compare two binaries only inside one
fingerprint window.

Why the code has nowhere left to leak: the walk is over `project_units` in
declared order; `existing_functions` is a `HashSet<String>` that is only ever
`insert`ed and never iterated; within a unit the walk is by section index then
by symbol index over `obj.symbols`, which `objdiff-core/src/obj/read.rs` sorts
by (section, section-symbols-first, address, size) over the object file's own
symbol table; and `report_object`'s one hash-order iteration
(`partner_groups.values()`) picks a per-group owner by a rule that is
independent of group order and yields a set. Default mode shares all of that
and has been byte-identical here across every measurement.

What IS real, and is already fixed, is the same shape one layer down: the
report cache used to be served under `-d`. On `f9333e6` (= `345778c^`),
dc3-decomp, three runs through one shared `-o`:

    1 dedup (cold cache)   total_fn 48325   <- correct dedup answer
    2 default              total_fn 48325   <- WRONG, 2224 cache hits, should be 48344
    3 dedup (warm cache)   total_fn 48325

A `-d` run poisoned the cache and the *default-mode* run after it silently
reported the deduplicated number. On `6bf7ba7` the same sequence gives
48325 / 48344 / 48325 and logs `report cache disabled`. That rule is now a
named function with a truth-table test (`report_cache_enabled`) rather than an
inline expression, because its failure mode is a moved progress number and not
an error.

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
