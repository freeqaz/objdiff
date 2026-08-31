# Fork Roadmap & Branch Disposition

Status log for the freeqaz/objdiff fork. The fork's focus is CLI + structured
JSON output for AI/MCP-assisted decompilation, consumed by sibling projects
`dc3-decomp` and `rb3` (both PPC targets).

## Shipped

### `patterns_checked` reports what could RUN, and `pattern_checks[]` says why not

`patterns_checked` was a hardcoded `vec![...]` of all 26 detector names,
emitted unconditionally — for an all-equal diff, for a one-sided diff, and for
a run under `functionRelocDiffs=none` where the five callee classes cannot see
relocation evidence at all. `patterns_checked: 26` beside an empty findings
list could not be told apart from "nothing ran".

dc3-decomp's `scripts/analysis/pattern_census.py` printed exactly that
conflation, built from this field unioned over a whole-binary sweep: *"N of 26
checked patterns fired on ZERO functions under this ruler (measured zero, not
an unmeasured one)"*. The parenthetical was false whenever a detector was
starved, and that script's own `--negative-control` mode (`--ruler none`)
starves ten of them by design.

Three statuses, one per real reason a detector can be silent:

| status | meaning |
|--------|---------|
| `ran` | had rows of the kind it reads, nothing suppressed its evidence class. **A zero is a measurement.** |
| `starved` | had rows, but the configured relocation ruler suppresses its evidence upstream in `objdiff_core::diff::code::reloc_eq`. Not *impossible* to fire — the evidence can ride a row that is `diff_arg` for another reason — hence a third state. **A zero is not a measurement.** |
| `not_applicable` | zero rows of the kind it reads. Could not have fired at all. |

`patterns_checked` is now the `ran` subset (so the census sentence becomes true
with no consumer change); `pattern_checks[]` is the full table with a reason on
every non-`ran` entry. Markdown prints `Detectors that ran: N/26` and names the
rest.

Measured on the committed `CDamageVulnerability` fixture pair, one symbol,
three rulers — the old field said `26` for all three:

| ruler | ran | starved | not_applicable |
|-------|----:|--------:|---------------:|
| `name_address` | 17 | 0 | 9 |
| `name_check` | 16 | 1 | 9 |
| `none` | 7 | 10 | 9 |

The single `starved` under `name_check` is `UNVERIFIABLE_CALLEE_NAME` — the
case dc3's census reads as `0` and dc3's CLAUDE.md annotates BY HAND as
"structural — the graded ruler exempts placeholder names before the detector
runs". That annotation lived in a human doc because the tool could not say it.

`DETECTOR_REQS` is transcribed from the detector bodies, so a wrong entry would
be a new false statement in the other direction. It is held to the bodies by
`declared_rows_are_not_narrower_than_the_detector_bodies`, which re-labels
every fixture to every `match_type` a detector disclaims and asserts silence —
exhaustive over all 25 row-driven detectors and independent of whether any
fixture makes a given detector fire. That independence is the point: the first
draft walked a corpus and checked only detectors that fired, and a
`FSEL_TERNARY` sabotage **passed** it.

**Follow-up for the consuming repos (not done here):** `pattern_census.py`
should read `pattern_checks[]` and report starved detectors separately, rather
than inferring "measured zero" from absence. Its stored `patterns_checked`
column now means "detectors whose zero was a measurement", which is a narrower
and more useful thing than the vocabulary it used to hold.

### `--strict`: failing a job on a measurement, with distinct exit codes

objdiff-cli exited `0` or `1`, and `1` meant only "an I/O, parse or config
error happened". Consumers wanting "fail if the match regressed" re-implemented
threshold logic against parsed JSON.

`--strict <rule>` is repeatable, available on `diff` and `report generate`:
`min-match=<pct>`, `detectors[=any]`, `detectors=starved`, `nonempty`.

| exit | cause |
|-----:|-------|
| 0 | rules satisfied **and** something was examined |
| 1 | error: I/O, parse, config — unchanged |
| 2 | a measurement threshold was violated |
| 3 | a pattern detector could not run |
| 4 | the check examined zero things |
| 5 | the strict configuration is unusable here |

`nonempty` is not opt-in: any `--strict` enforces it, before the threshold, so
a run that analysed nothing cannot present as a threshold pass. A *missing*
measurement is filed there too. Default behaviour is untouched — without
`--strict` nothing runs and `exit_code_for` maps everything that is not a
`StrictFailure` to `1`, with a test pinning that.

`scripts/strict-selftest.sh` drives a real binary through 25 cases: every exit
code, reds included, plus six negative controls. Wired into CI's test job.
Watched fail twice before being trusted — forcing `StrictConfig::enabled()` to
`false` turns 8 cases red; short-circuiting `check_examined` turns exactly the
empty-batch case red. The script refuses to report success on fewer than 20
cases.

### Control-flow (branch) graph in CLI JSON diff output
Each `InstructionDiffOutput` row now carries the per-side branch graph that
objdiff-core already computes (and the GUI uses to draw branch arrows):

- `target_branch_from` / `base_branch_from`: `{ source_indices: [u32], branch_idx }`
  — rows that branch **to** this row.
- `target_branch_to` / `base_branch_to`: `{ target_index: u32, branch_idx }`
  — the row this row branches **to**.

`*_index` values reference the `index` field of rows in the same `instructions`
list. `branch_idx` is objdiff's per-branch coloring/group id. Fields are omitted
when absent. Verified on `tests/data/ppc/m_Do_hostIO.o`: loops (`bdnz` → back
edge), conditional `bne`, and merge points (`[19, 36] → 46`) all resolve
correctly. This supersedes the earlier `stash@{0}` draft, which predated the
current `TypedArg`/`InstructionInfo` shape and never compiled.

### Data-symbol diff in JSON (`--include-data`)
`--include-data` was a no-op flag; it now emits a `data_diff` object on the JSON
`DiffOutput` for data symbols (code symbols produce nothing). Built from
objdiff-core's `DataDiffRow`/`DataDiff`/`DataRelocationDiff`:

- `match_percent`, `mismatch_byte_count`, `total_byte_count` — quick assessment.
- `segments`: contiguous byte runs (objdiff's 16-byte rows flattened + merged by
  kind), each `{ offset, size, kind, bytes? }`. `kind` ∈ equal/replace/insert/
  delete; `bytes` (hex) present only for differing runs that carry data on this
  side.
- `relocations`: `{ offset, size, kind, target_symbol, addend?, base_target_symbol?,
  base_addend? }` — the most actionable signal for data symbols (vtables, pointer
  tables). De-duplicated across row boundaries; `target_symbol` resolved by name.
  When the base side points at a *different* symbol (a `replace` — e.g. a vtable
  slot resolving to the wrong function), `base_target_symbol`/`base_addend` name
  it; base-only relocations surface as `insert` entries. Paired by symbol-relative
  offset (reloc lists aren't positionally aligned).
- `segments` carry both sides: `bytes` (resolved side) and `base_bytes` (matched
  other side), the latter emitted only when present and different — so `replace`
  runs show target vs base byte values directly, and `insert` runs surface the
  base-only bytes. Built by walking both symbols' `data_rows` in lockstep
  (objdiff-core builds them structurally identical, differing only in payload),
  with a defensive shape guard that falls back to single-side if they diverge.

Verified on `tests/data/arm/LinkStateItem.o` (`_ZTV13LinkStateItem`, a 68-byte
vtable — all 17 relocations resolve to their target function names) and
`tests/data/ppc/m_Do_hostIO.o` (`@stringBase0`, 200-byte string pool), plus unit
tests for merge/replace/insert/`base_bytes`/relocation resolution. See
`data-diff.md` for the prior actionability investigation (relocations + vtables
are the key case for dc3/rb3).

The `data_diff` feature is now complete (bytes both sides, relocations both
sides). No outstanding data-diff work.

## Branches evaluated and dropped (cleaned from the fork)

All re-fetchable from `origin` (encounter/objdiff) if ever needed.

- `mips-gprel32`, `pr-270`: redundant — main already has PR #270
  (`03f2bcb R_MIPS_GPREL32 Support`). The two were identical to each other.
- `feature/analysis-pattern-detection` (local + remote), `metric-honest-immediates`:
  fully contained in main; nothing unique.
- `alt-keys`: upstream GUI hotkeys (LagoLunatic). Real feature but GUI-only,
  254 commits behind, conflict-heavy — out of scope for a CLI/MCP fork.
- `omf`: upstream `[WIP] OMF object support`. Intel OMF is an x86 16-bit/DOS-era
  format and depends on an external `encounter/object` fork branch; the branch is
  all `/* TODO */` stubs. Irrelevant to PPC targets (dc3/rb3).

## Standalone-consumer defects — FIXED 2026-08-21

Found by linking `objdiff-core` directly from a new Rust consumer (decomp-synth
`tools/score-server/`), the first thing other than objdiff-cli to depend on it.
There were **three**, not the two first reported, and they shared one root
cause: every CI job builds `--all-features --workspace`, under which cargo
unifies features across packages and objdiff-cli's dependency declarations
quietly satisfy what objdiff-core fails to declare for itself. No job built
objdiff-core alone, so the crate's own declaration was never tested.

- **`regex` declared featureless while `map_file.rs` needs Unicode classes.**
  `obj/map_file.rs` compiles `^\s*\d{4}:...(\S+)...`, and regex-syntax rejects
  those classes at `Regex::new` time unless `unicode-perl` is on — so
  `parse_msvc_map` panicked on first use for any external consumer, taking ICF
  alias parsing with it. Note this is a **runtime** failure: a build check
  cannot see it. Fixed by declaring `unicode-perl` (and propagating
  `regex?/std`).
- **`crate::bindings::report` referenced from `std`-only-gated items.**
  `reconcile_global_byte_matches`, `recalc_unit_measure_percents` and seven
  supporting items were gated `#[cfg(feature = "std")]` but name types that
  exist only under `bindings`, so a `std`-without-`bindings` build failed to
  compile. Fixed by gating them on `all(std, bindings)`; the only caller is
  objdiff-cli's report command, which has `bindings` on.
- **`std` did not propagate to `serde_json`.** `serde_json` is declared
  `features = ["alloc"]` and the `std` feature list forwarded `serde?/std` but
  never `serde_json?/std`, so `from_reader`/`to_writer_pretty` were missing in
  any std build that did not get `serde_json/std` from elsewhere. Fixed by
  adding `serde_json?/std`.

**The guard is the deliverable, not the three fixes.** `scripts/check-standalone.sh`
builds and *runs* `objdiff-core` from a crate deliberately outside this
workspace (`scripts/standalone-check/`, note its empty `[workspace]` table),
with a minimal feature set and no `regex`/`bindings` to unify against. It is
wired into the CI `check` job. Verified against deliberately broken input: it
fails on the unfixed tree with both compile errors, and — with the compile
defects fixed but `regex` reverted to featureless — fails with the runtime
`Unicode-aware Perl class not found` panic. That last arm is why the script
runs the binary instead of only compiling it.

Follow-up from the same consumer, **still open**: `FlowAnalysisResult` is
`!Sync`, which forces per-connection (rather than global) parsed-object stores
in any threaded server. An upstream `Sync` bound (or an audit of why it is
`!Sync`) would let consumers share parsed objects across threads.

## Upstream follow-up (encounter/objdiff, low urgency)

### `report generate` credits unpaired symbols 100% — fixed here, still live upstream

`complete` substitutes 100% for a percent `diff_objs` did not compute. Upstream
gates that on `object.complete` alone, so it also fires **per symbol** inside a
*paired* object: a symbol with no counterpart is reported as fully matched, and
the symptom is a higher progress number rather than an error. Precondition is
two-part — unpaired symbol **and** `units[].metadata.complete == true` (note
`metadata`; reading `unit["complete"]` returns 0 even on a tree that fires it).

Fixed here in `3d51181` ("random changes", 2026-03-12) by adding the
`base_is_none` term, which restricts the substitution to the whole-unit
target-only case it was written for. That fix shipped unnamed and untested for
five months; it is now factored into `complete_substitution_percent` with a
truth table and a sabotage control in `objdiff-cli/src/cmd/report.rs`.

Two things make this worth carrying upstream rather than leaving fork-local:

- **A merge from upstream reverts it silently.** `upstream/main` still has the
  old form at both sites, and the guard is one term in a match arm — no conflict
  marker, no failing build, just a different number.
- **Version cannot identify an affected build.** Fork tags `v4.1.0`+ carry the
  fix, but `v4.1.0` did not bump `Cargo.toml`, so both boundary builds
  self-report `4.0.0`. Consumers must pin by commit or test the behaviour.

Affected build range, measured: **2.7.1 through 4.0.0 inclusive**.

After fleet runs validate the immediate-diff tweak, merge
`metric-honest-immediates` into encounter/objdiff `main`, and rename the CLI's
confusingly-named `normalized_match_percent` — it actually measures
reloc-strictness, not argument normalization.
