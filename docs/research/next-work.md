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
- `relocations`: `{ offset, size, kind, target_symbol, addend? }` — the most
  actionable signal for data symbols (vtables, pointer tables). De-duplicated
  across row boundaries; `target_symbol` resolved by name.
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

## Next up

### Data diff: base-side relocation target names
`relocations` currently report the resolved side's `target_symbol`. For a
mismatched (`replace`) reloc, the base side may point at a *different* symbol;
surfacing both target names would pinpoint "this vtable slot points to the wrong
function." Left/right reloc lists are not structurally aligned (unlike byte
segments), so this needs pairing by offset rather than position.

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

## Upstream follow-up (encounter/objdiff, low urgency)

After fleet runs validate the immediate-diff tweak, merge
`metric-honest-immediates` into encounter/objdiff `main`, and rename the CLI's
confusingly-named `normalized_match_percent` — it actually measures
reloc-strictness, not argument normalization.
