# `parse_msvc_map` → `reloc_eq`: the settled design

**Verdict: the parser hands `reloc_eq` the co-location relation, exactly** —
`aliases(a, b)` is true iff some address group in the map file contains both
`a` and `b` — packaged as a dedicated type, `SymbolEquivalences`, whose only
public questions are the two the consumers actually ask: the pairwise
`aliases(a, b)` and the keying `canonical(name)`.

This adopts the *semantics* of the unmerged union candidate
(`laneU-mapfile-union`, `a1d31ea`) and rejects the landed first-wins design
(`7451d70`), while replacing both candidates' return type
(`HashMap<String, HashSet<String>>`).

## Why the relation, and not a partition

These map files are synthetic. rb3-xenon's `tools/gen_symbol_alias_map.py` and
dc3's `scripts/gen_icf_alias_map.py` render them from `symbol_aliases.json`:
each group is one assertion — "any of these spellings may denote the body at
this address" — emitted as lines sharing an 8-hex address. A real linker map
gives every name one address (a partition); the synthetic maps can emit one
name at several addresses, because the underlying alias data is a many-to-many
relation and the `.map` format can only express one group per address.

The full semantic content of such a file is therefore the set of co-location
assertions it makes: the symmetric relation "∃ a group containing both". The
parser's job is to hand that on with nothing added and nothing dropped.

- **First-wins drops.** Assigning a multi-address name the group of its first
  appearance discards every later group's assertions about it. Which pairs
  survive then depends on the order the generator emitted groups in — order of
  assertion is not evidence. The concrete failure shape: `A` first in
  `{A, X}`, `B` first in `{B, Y}`, and the file also asserts `{A, B}` later;
  first-wins answers "not equivalent" for `(A, B)` even through `reloc_eq`'s
  symmetric two-way lookup — a false `[sym]` charge for a file-asserted alias
  (`test_pair_asserted_only_in_a_late_group_still_aliases`).
- **Closure adds.** Making two names equivalent because they share a neighbor
  (rb3-xenon's star shape: two retail survivors both folding one of our
  spellings) asserts something the file does not. The co-location evidence is
  "bodies identical modulo relocations", which is **not transitive in callee
  identity**: two survivors whose bodies both masked-match one spelling can
  still call different functions through their relocations. A fabricated
  survivor↔survivor alias would tell `reloc_eq` that a `bl` to a *different
  callee* is equal — invisible to the default `functionRelocDiffs=none` ruler
  by construction (see decomp-synth `docs/reloc-name-blindness.md`), and
  corrosive to the byte-exact admission gate. Closure is a *data* decision
  with its own evidence bar: dc3's generator takes it (its groups arrive as
  closure classes, so the parser's refusal costs it nothing); rb3-xenon's
  generator refuses it. The parser has no evidence of its own and takes no
  position (`test_union_is_not_transitive_closure`).
- **Nondeterminism (the original bug) cannot recur structurally.** The union
  over unordered groups is invariant under any iteration order and under any
  permutation of the file's groups (`test_parse_msvc_map_is_reproducible`,
  `test_line_order_is_not_evidence`). First-wins was deterministic only
  per-byte-stream; the union is deterministic per-*assertion-set*, which is
  the right invariance class for a generated file.

## Why a dedicated type

`HashMap<String, HashSet<String>>` is a partition-shaped answer to a pairwise
question. `reloc_eq` only ever asks "may name A stand in for name B?", and
both call sites in `diff/code.rs` had to hand-spell a two-way membership OR to
compensate for the representation. `SymbolEquivalences` stores the adjacency
sets of the co-location graph (`HashMap<String, BTreeSet<String>>` — hash
lookup on the hot path, ordered sets so `canonical`, `Eq`, and `Debug` are
deterministic) and answers:

- `aliases(a, b)` — symmetric by construction; one lookup; exactly the
  file's assertions.
- `canonical(name)` — lexicographic minimum over *all* of a name's groups.
  This is a **keying heuristic** for the opt-in case-B promotion index
  (`--global-byte-eq`), not part of the forgiveness semantics. Keying by
  representative forces an equivalence relation, and the relation is
  deliberately not transitive, so no labeling can be exact; the case-B pass's
  own gates (unique retail VA, oracle own-TU, byte-masked equality) screen the
  resulting index collisions. The exact scheme — key on relocation-masked
  bytes alone, verify reloc names pairwise via `aliases` at lookup — is named
  in the docstring and deliberately not built here.

## What the design deliberately refuses to do

1. Choose a group for a multi-address name (first-wins, last-wins, or any
   order-derived pick).
2. Take the transitive closure, in the relation or in `canonical`'s keying.
3. Warn about or "repair" non-partition maps: the many-to-many shape is the
   *intended* content of rb3-xenon's file, not a defect.
4. Redesign the case-B index keying (documented as future work in
   `canonical`'s docstring).

## Evidence (measured 2026-08-13, this branch)

On today's real maps the rejected first-wins design and this design are
**extensionally identical at the `reloc_eq` seam**, and the design decision is
therefore about which invariants hold when the data grows, not about moving
today's scores:

- rb3-xenon `build/45410914/icf_aliases.map`: 1,503 groups, 6,920 names, 842
  names at >1 address (all folded spellings; every group is star-shaped — one
  survivor, survivors never reused). 638,357 co-occurring pairs; **0** pairs
  where first-wins and union disagree on `aliases` — every folded↔survivor
  pair is rescued by the survivor's own single-group entry via the symmetric
  lookup. That rescue is *provable* from a generator invariant, not luck:
  every co-occurring pair contains its group's survivor, and survivors are
  single-address (measured: survivors also folded in another group — 0 on
  both repos; adversarial review shuffled group order 200× per map, 0
  divergence, worst case 0 dropped pairs). But it is a **data invariant no
  generator checks** — nothing in either repo's tooling enforces it, so it
  is one `symbol_aliases.json` edit from breaking, silently.
  `test_line_order_is_not_evidence` and
  `test_pair_asserted_only_in_a_late_group_still_aliases` guard a shape
  neither generator can currently emit.
- dc3 `build/373307D9/icf_aliases.map`: 2,056 groups, 8,703 names, **0**
  names at >1 address (closure classes = a true partition). 599,914 pairs, 0
  disagreements; every design under consideration is identical here.
- The `canonical` labelings DO differ on rb3-xenon (389 of 6,920 names;
  first-wins' labeling conflates 4,990 pairs union's does not, union's 389
  first-wins' does not — both artifacts of representative-keying over a
  non-transitive relation). The safety-relevant split of those numbers
  (adversarial review): **spurious** keying collisions — unasserted pairs
  conflated — are SET-IDENTICAL under both designs (3,651 pairs, symmetric
  difference 0), so union adds *zero* new fabrication risk; what changes is
  **misses** of asserted pairs (union 7,035 vs first-wins 2,434), a pure
  recall reduction in the opt-in case-B index — strictly the safe
  direction. This reaches only the case-B pass, which is oracle-gated; the
  default `report generate` path never calls `canonical`.
- Report-level verification (fresh release binaries — main at `9f6c6c3`,
  this branch at its first commit of this design — one `-o` per binary,
  `--no-cache`, `.cache` sidecars removed, rb3-xenon and dc3 at both
  `functionRelocDiffs=none` and `name_check`): all eight report bodies are
  **exactly equal** between the two binaries; the only differing fields are
  `provenance.tool_binary_hash` and `provenance.tool_commit`. Read the
  table honestly: it is **4 arms of signal plus 4 controls**. At
  `functionRelocDiffs=none`, `reloc_eq` returns at
  `if relax_reloc_diffs { return true; }` *before* either `aliases()` call,
  and `canonical()` is unreachable without `--global-byte-eq` — so on the
  default report path under `none`, `SymbolEquivalences` is never consulted
  at all (proved by a control assertion in the real path during adversarial
  review); the two `none` arms would match even if `aliases()` returned
  garbage. The controls are still worth running: they prove the type change
  touches nothing outside the name-checking rulers. Headline numbers
  (identical main vs lane in every arm):

  | arm | matched_code | matched_code% | matched_fns | complete_code |
  |---|---|---|---|---|
  | rb3-xenon `none` | 4,337,956 | 42.0316 | 44,130 | 80 |
  | rb3-xenon `name_check` | 3,512,924 | 34.0377 | 44,130 | 80 |
  | dc3 `none` | 4,981,696 | 43.8012 | 29,398 | 6,343,132 |
  | dc3 `name_check` | 4,911,176 | 43.1812 | 29,398 | 6,343,132 |

  (The `laneC2-clippy` merge that landed on main mid-lane was independently
  verified scoring-neutral on both repos at both rulers, so the `9f6c6c3`
  comparison arm remains valid against current main.)

## Recommendation for `laneU-mapfile-union`

Do not merge it; delete after this lane lands. Its semantics are adopted here,
its docstring's argument is preserved in `SymbolEquivalences`' docs, and its
implementation (per-name `HashSet` under the old type, plus the vestigial
`address_order` walk) is superseded by the typed design. Nothing else on that
branch exists to salvage.
