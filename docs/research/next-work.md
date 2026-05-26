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

Verified on `tests/data/ppc/m_Do_hostIO.o` (`@stringBase0`, 200-byte string pool)
plus unit tests for merge/replace/insert/relocation resolution. See
`data-diff.md` for the prior actionability investigation (relocations are the
key case for dc3/rb3).

## Next up

### Data diff: base-side bytes for `replace` runs
The current `data_diff` shows one side's bytes (the resolved symbol's). For a
`replace` run, showing the *other* side's bytes too would make string/init-value
typos directly diffable. Requires aligning both symbols' `data_rows`.

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
