# Doc links resolve against the repo that reads them

**Landed 2026-08-04 as `7e5eb98` / merge `1030000`.** Implementation lives in
`objdiff-cli/src/cmd/analysis.rs` (`DocProject`, `DocLink`, `doc_entry`,
`doc_url_for`, `detect_doc_project_*`); verification in
`scripts/check_doc_links.py`.

## The problem

Every doc URL objdiff emits is project-relative (`docs/decomp/patterns/…`), so
it is a claim about the *consuming* repo's filesystem. `pattern_doc_urls()` was
a pure function with no repo context, holding a single hard-coded table — which
means it could only ever be right for one consumer.

There are two consumers and they disagree on both axes:

| Topic | dc3-decomp (MSVC/PPC) | rb3 (MetroWerks/PPC) |
|---|---|---|
| Permuter ROI / pattern automation | `PERMUTER_ROI_ANALYSIS.md` | `permuter-roi.md` |
| Systemic at-limit classes | `at-limit-systemic.md` | `at-limit-mwcc.md` |
| Compiler floors | `unfixable-compiler.md` | (folded into `at-limit-mwcc.md`) |

Section anchors diverge even where filenames agree.

Measured before the fix, mechanically rather than by eye:

- **29 of the 30 emittable URLs failed against the RB3 tree.** Exactly one
  resolved.
- `at-limit-mwcc.md` — an RB3-only filename carrying **MetroWerks-specific
  content** — was listed on four patterns inside an MSVC repo, and
  `permuter-roi.md#register-allocation-cascades` was the third `REGISTER_SWAP`
  link handed to DC3 readers.
- Two URLs existed in **neither** repo:
  `fixable-comparison.md#signed-vs-unsigned-comparison` and
  `fixable-casting.md#signedness-and-width-mismatch`. They had presumably never
  resolved for anyone.
- Three docs DC3 *does* have (`fixable-liveness.md`, `unfixable-compiler.md`,
  `at-limit-systemic.md`) could not be linked at all, because the table had no
  way to name a per-project file.

A wrong filename is not merely a 404 here. The two projects target different
compilers, so an RB3-named doc that happens to exist in DC3 hands the reader
advice written for a different backend — a confidently wrong link costs more
than a missing one.

## The mechanism

Links are named by **what they explain** (`DocLink::InstructionScheduling`,
`DocLink::IcfAtLimit`, …) and resolved through a per-project table
(`doc_entry`), keyed by `DocProject::{Dc3, Rb3, Unknown}`.

Project identity is **detected**, not declared:

1. `OBJDIFF_DOC_PROJECT` (`dc3` / `rb3` / `unknown`) wins if set.
2. Otherwise walk up from `--project` (or, when absent, the working directory)
   up to 12 levels looking for `docs/decomp/patterns/`.
3. Inside that directory, probe **marker filenames**:
   `PERMUTER_ROI_ANALYSIS.md` ⇒ DC3; `at-limit-mwcc.md` or `permuter-roi.md`
   ⇒ RB3; a patterns directory that matches neither ⇒ `Unknown`.
4. The result is memoised in a `OnceLock` for the process.

`Unknown` degrades to the **intersection** of the two known projects: a link is
emitted only when both use the same file, and the anchor only when the anchors
also agree. Anything project-specific is dropped. Twelve links survive that
filter — deliberately fewer than either project gets, on the principle that a
plausible-looking link into another compiler's documentation is worse than no
link.

No detector, threshold, or verdict was touched. This is purely *where the reader
is sent*.

### Why probing, and not a flag or a config field

A **CLI flag** was rejected because objdiff-cli is not invoked by hand. Ninja
rules, the DC3 MCP orchestrator, `tools/retriage_85_100.py`, and several
`.claude/skills` all shell out to the binary. A flag means editing every call
site, and any new call site silently regresses to the wrong project — the
failure is invisible, because a wrong link still renders.

A **field in `objdiff.json`** was rejected because it needs a schema change in
`objdiff-core`'s `ProjectConfig`, which is upstream-shared code carried across
rebases for a fork-local concern, plus a hand-edit to each consumer's
`objdiff.json` (including RB3's, which this fork does not own).

Probing needs nothing from anybody: it asks the question we actually care about
("which filenames exist in this repo?") by looking, it self-heals when a repo is
moved or renamed, and every existing wrapper got correct links without changing
a line.

## Adding a consuming project

1. Add a variant to `DocProject` and to `DocProject::from_name` (accept both the
   short name and the repo name).
2. Extend `DocEntry` and every arm of `doc_entry` with the new project's
   `file.md#anchor`, or `None` where that project has no such doc. **`None` is a
   correct answer** — omitting a link beats inventing one.
3. Add a marker probe to `detect_doc_project_at`. Pick a filename unique to that
   repo; the probe order matters only if two repos share a marker, which is
   itself a signal to pick a better one.
4. Decide what the `Unknown` intersection should now mean. It is currently the
   two-way DC3∩RB3 rule inside `doc_url_for`; a third project makes it an
   N-way agreement, and that rule has to be written deliberately rather than
   extended by accident.
5. Re-run the checker against a real checkout of the new repo (below) and fix
   every failure before landing.

## Verification workflow

`objdiff-cli doc-links` dumps exactly what the binary would emit, so the check
is mechanical and re-runnable rather than editorial:

```bash
cargo build --release -p objdiff-cli
scripts/check_doc_links.py --dc3 ../dc3-decomp --rb3 ../rb3
```

`check_doc_links.py` calls `objdiff-cli doc-links -P <project> -f json` and
resolves every URL against that repo's working tree: the file must exist, and
the `#anchor` must match a real markdown heading under GitHub slug rules
(fenced code blocks skipped). It also enforces the anchor contract below and the
`Unknown` intersection rule, and exits non-zero on any failure.

Current state (2026-08-04):

| project | result |
|---|---|
| dc3-decomp | 30 / 30 |
| rb3 | 25 / 25 |
| unknown (fallback) | 12 / 12 |

### The checker has a negative control

A checker that passes everything is worthless if it cannot fail. Feeding the
**DC3** link set to the **RB3** tree still reports **29 failures out of 30**:

```bash
scripts/check_doc_links.py --dc3 ../rb3 --allow-missing   # expect 29 failures
```

That is the pre-fix rot number, reproduced on demand. If this control ever
starts passing, the checker has stopped resolving anything and the green runs
above mean nothing.

## The anchor contract

objdiff renders **only the first doc URL** for a pattern inline. That makes the
first entry contractual: the consuming repo's headings must not move under it.

| pattern | first URL (dc3-decomp) |
|---|---|
| `REGISTER_SWAP` | `fixable-declarations.md#pre-compute-references-before-clobbering-calls` |
| `OFFSET_SWAP` | `fixable-declarations.md#offset-swap` |

plus one anchor that is cited from prose and from
`register-swap-symptom-not-cause.md` and must stay reachable somewhere in the
emitted set:

- `PERMUTER_ROI_ANALYSIS.md#instruction-scheduling`

**These are asserted by test, not by eye.** `check_doc_links.py` fails if a
first URL changes (`DC3_FIRST_URL_CONTRACT`) or if the required anchor stops
being emitted (`DC3_REQUIRED_ANCHORS`), and the objdiff-cli unit tests assert
the same first-URL identities plus cross-project filename leakage in both
directions, the `Unknown` intersection rule, URL well-formedness, `DocLink`
enumeration completeness, and marker-file detection from a subdirectory.
dc3-decomp's `docs/decomp/patterns/INDEX.md` carries the matching
divergence table on the consumer side.
