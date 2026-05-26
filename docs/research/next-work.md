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

## Next up

### Data-symbol diff in JSON (`--include-data`)
The `--include-data` flag is currently a **no-op** (declared, never read). Wire
it to emit structured data-section diffs from objdiff-core's existing
`DataDiffRow` / `DataDiff` / `DataRelocationDiff` (objdiff-core/src/diff/mod.rs).
See `data-diff.md` for the prior investigation. Useful for matching data symbols
(vtables, jump tables, string pools) in dc3/rb3.

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
