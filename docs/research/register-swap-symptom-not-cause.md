# REGISTER_SWAP is a symptom, not a cause

**Scope of this finding: n = 3 functions, MSVC 2010-era PowerPC (Xbox 360), one
codebase (dc3-decomp), measured 2026-08-02/03.** It is not a general law of
compilers, and it has not been checked against MWCC/PowerPC (RB3), GCC, or any
other backend. Treat it as a strong prior for this target and a hypothesis
elsewhere.

## The claim

When objdiff reports `REGISTER_SWAP`, the swapped register names are almost
never the thing to edit, and the historically-recommended first move —
reordering local variable declarations — was inert in every case measured.

The swaps are downstream of something else:

| Mismatch class | What it tracks | First lever |
|---|---|---|
| `OFFSET_SWAP` (stack slots, `r1`-relative) | where locals get packed in the frame | **declaration scoping and order** |
| `REGISTER_SWAP` (GPR/FPR names) | which values are live where, and in what order operations are emitted | **liveness and scheduling** |
| `PROLOGUE_MISMATCH` (save count) | the callee-saved *budget*, i.e. how many values survive across calls | **liveness** (same as above) |

Conflating the two rows is the error the previous guidance encouraged: the
`REGISTER_SWAP` hint pointed at the declaration-order documentation, which is
correct advice attached to the wrong pattern.

## The evidence

Three functions taken to or near 100%. In all three, no register name was ever
permuted directly; the entire swap set flipped at once when the underlying
cause was fixed.

### `ObjectDir::Iterate` — 99.4% → 100%

Lever: **live-range shortening.** Call arguments were read back out of an
already-constructed, never-modified `std::pair` (`key.first` / `key.second`)
instead of from the original locals — a provable no-op at the source level. That
ended one value's live range at the pair store rather than carrying it across a
call inside the loop.

- All 17 swapped registers flipped, with **zero change to the instruction
  stream** otherwise.
- Negative results on the same function: 6 declaration-reorder variants compiled
  byte-identical, 2 regressed. A 65-variant permuter beam search found 0
  improvements.

### `RndText::FitTextScroll` — 92.7% → 98.2%

Lever: **not re-loading a member at a call site.** The target keeps a local
pointer in a callee-saved register across an intervening call; our build
reloaded the member instead. That reload cost one whole callee-saved register —
visible in the prologue as `__savegprlr_23` where the target had `_22` — and
cascaded into roughly 40 register swaps (`r27`↔`r28`, `r22`↔`r23`,
`f12`↔`f13`).

Separately and independently, scoping two out-parameter declarations into the
`if` block that used them reproduced the target's stack packing and eliminated
all 14 offset diffs. **This is the boundary in one function:** the declaration
edit fixed the offsets and nothing else; the liveness edit fixed the registers
and nothing else.

### `RndText::SizeCheck` — 96.5% → 99.1%

Lever: **instruction scheduling, then comparison polarity.** Hoisting a product
so the `fmuls` landed before the `fcmpu` that consumes it, then flipping two
float compares to the target's operand order (`fcmpu f13,f0; bge` versus our
`fcmpu f0,f12; ble` — exact logical equivalences, including NaN behaviour).

All nine FPR swaps fell out automatically.

Note that these were *volatile* FPRs (`f0`–`f13`), which the detector classifies
as `RarelyHandFixable`. Hand analysis closed them anyway — so that label should
not be read as "hand-editing won't work".

## The volatile / callee-saved split is decidable, not heuristic

The register-class split the detector already computes is stronger than it was
being used as. It follows from the ABI rather than from these measurements: a
volatile register cannot hold a value across a call, so **a swap confined to
volatile registers is never itself a disagreement about what stays live across a
call.** That rules liveness out and leaves scheduling and operand order — which
is what closed `SizeCheck`.

The converse is not symmetric, and the difference matters:

- A pure-volatile swap set: liveness is *excluded* as the direct cause. Look at
  emission order.
- A pure-callee-saved swap set: liveness across calls is the cause.
- A mixed set: **one liveness cause, and the volatile half is its shadow.**
  `FitTextScroll` showed `r27`↔`r28` and `r22`↔`r23` (callee-saved) alongside
  `f12`↔`f13` (volatile) simultaneously, all from a single member reload at a
  call site. So a volatile swap can be *downstream* of a liveness problem
  elsewhere in the function even though it cannot *be* one.

Unlike the rest of this document, the exclusion argument is an ABI consequence
and does not depend on n=3; only the claim about which causes show up in
practice does.

## How to use a REGISTER_SWAP hint

1. Read the prologue first. A different callee-saved save count
   (`__savegprlr_NN`) means the two builds disagree about how many values must
   survive calls — that is the cause, and the swaps are its shadow.
2. Read the register-class label; it tells you which cause is even possible.
3. For callee-saved (or mixed) swaps: find a value the target holds across a
   call that we reload (or one we hold that the target rematerializes). Shorten
   or lengthen that live range.
4. For volatile-only swaps: liveness is excluded. Look at emission order around
   the swap — a producer scheduled after its consumer, or a compare with the
   operands the other way round.
5. Do not chase individual register names, and do not expect swap *count* to
   predict fix size. Cascades of 17 and ~40 swaps both collapsed to zero from a
   single edit.
6. Reach for declaration reorder when `OFFSET_SWAP` or stack-slot diffs are also
   present. That guidance is still correct — for that class.

## What changed in the tool

Documentation and hint text only; no classification logic was changed. The
detectors' thresholds, the `Fixability` values assigned to register swaps, and
the resulting `VerdictClassification` are all untouched — three functions on one
compiler is not enough to justify changing what the tool asserts.

- `pattern_doc_urls(RegisterSwap)` and `pattern_doc_urls(PrologueMismatch)` now
  list liveness/scheduling docs first; the declaration-order link is retained
  but demoted (it is still the right link for `OFFSET_SWAP`, which is
  unchanged).
- `Pattern::summarize()` register-class labels name the cause to look for
  (`[callee-saved — check liveness across calls]`,
  `[volatile — scheduling/operand order, not liveness]`,
  `[mixed volatile+callee-saved — one liveness cause, start there]`) instead of
  prescribing a sweep.
- The `compute_verdict` register-swap branch leads with "find the cause", keeps
  the permuter as the second move, and explicitly marks declaration reorder as
  usually inert for register-only swaps.
- `match_guidance()`'s 95%+ band no longer recommends variable reorder for
  register swaps.

## The cross-repo link problem

Doc URLs are relative to the *consuming* project (`docs/decomp/patterns/`), and
the two consumers use **different filenames for the same document**:

| Topic | dc3-decomp (MSVC) | rb3 (MetroWerks) |
|---|---|---|
| Permuter ROI / pattern automation | `PERMUTER_ROI_ANALYSIS.md` | `permuter-roi.md` |
| Systemic at-limit classes | `at-limit-systemic.md` | `at-limit-mwcc.md` |

`pattern_doc_urls()` is a pure function with no repo context, so no single
string is correct for both. Worse, a wrong-repo filename is not merely a 404: the
two projects target different compilers, so RB3-named content is usually written
for MWCC and can be actively misleading in a DC3 hint even when a
similarly-named file exists.

Current resolution: the scheduling link uses the DC3 filename
(`PERMUTER_ROI_ANALYSIS.md#instruction-scheduling`), because that is where the
scheduling section and the measurements behind this document live, with a
comment at the call site naming the divergence. dc3-decomp's
`docs/decomp/patterns/INDEX.md` carries the divergence table and an "anchor
contract" listing the headings objdiff links into.

`permuter-roi.md#register-allocation-cascades` (third URL for `REGISTER_SWAP`)
and the `at-limit-mwcc.md` links used by other patterns still carry RB3 names.
Those predate this work and were left alone. **A real fix — mapping doc URLs per
consuming project, e.g. via `objdiff.json` — is a separate piece of work and
should not be improvised inside a guidance change.**
