# Fork Roadmap & Branch Disposition

Status log for the freeqaz/objdiff fork. The fork's focus is CLI + structured
JSON output for AI/MCP-assisted decompilation, consumed by sibling projects
`dc3-decomp` and `rb3` (both PPC targets).

## Shipped

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

## Known defects (found 2026-08-21 by decomp-synth's score-server lane, first non-cli consumer of objdiff-core)

Both were found by linking `objdiff-core` directly from a new Rust consumer
(decomp-synth `tools/score-server/`, lane `scoring-server`). objdiff-cli never
hits either because cargo feature unification papers over them; any other
consumer does.

- **`regex` declared featureless while `map_file.rs` needs Unicode classes.**
  `objdiff-core`'s `regex` dependency disables default features, but
  `map_file.rs` compiles patterns using `\s`/`\d` character classes, which
  require the `unicode-perl` (or default) feature. Building the crate alone
  and calling `parse_msvc_map` panics at pattern-compile time. objdiff-cli
  survives only because another workspace dependency re-enables the regex
  features via unification. Fix: declare the feature `objdiff-core` itself
  needs.
- **`bindings` feature referenced unconditionally.** Code reachable from a
  plain `objdiff-core` dependency references items only present under the
  `bindings` feature, forcing downstream consumers to enable a feature they
  do not want. The score-server consumer carries `bindings` as a documented
  deviation until this is fixed.

Follow-up from the same consumer, lower urgency: `FlowAnalysisResult` is
`!Sync`, which forces per-connection (rather than global) parsed-object stores
in any threaded server. An upstream `Sync` bound (or an audit of why it is
`!Sync`) would let consumers share parsed objects across threads.

## Upstream follow-up (encounter/objdiff, low urgency)

After fleet runs validate the immediate-diff tweak, merge
`metric-honest-immediates` into encounter/objdiff `main`, and rename the CLI's
confusingly-named `normalized_match_percent` — it actually measures
reloc-strictness, not argument normalization.
