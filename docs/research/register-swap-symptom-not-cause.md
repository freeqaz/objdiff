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
as `RarelyHandFixable`. Hand analysis closed them anyway. The
volatile/callee-saved split remains useful as a hint about *which cause* to look
for — scheduling versus liveness — but it should not be read as "hand-editing
won't work".

## How to use a REGISTER_SWAP hint

1. Read the prologue first. A different callee-saved save count
   (`__savegprlr_NN`) means the two builds disagree about how many values must
   survive calls — that is the cause, and the swaps are its shadow.
2. For callee-saved swaps: find a value the target holds across a call that we
   reload (or one we hold that the target rematerializes). Shorten or lengthen
   that live range.
3. For volatile swaps: look at emission order around the swap — a producer
   scheduled after its consumer, or a compare with the operands the other way
   round.
4. Do not chase individual register names, and do not expect swap *count* to
   predict fix size. Cascades of 17 and ~40 swaps both collapsed to zero from a
   single edit.
5. Reach for declaration reorder when `OFFSET_SWAP` or stack-slot diffs are also
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
- `Pattern::summarize()` register-class labels name the likely cause
  (`[callee-saved — check liveness across calls]`,
  `[volatile — scheduling/operand order]`) instead of prescribing a sweep.
- The `compute_verdict` register-swap branch leads with "find the cause", keeps
  the permuter as the second move, and explicitly marks declaration reorder as
  usually inert for register-only swaps.
- `match_guidance()`'s 95%+ band no longer recommends variable reorder for
  register swaps.

Doc URLs are relative to the *consuming* project (`docs/decomp/patterns/`), and
anchor names differ between dc3-decomp and rb3 — links that don't resolve
degrade to the top of the same file. Several pre-existing URLs already dangle in
dc3-decomp (`permuter-roi.md`, `at-limit-mwcc.md` exist only in rb3); that
naming reconciliation is a separate, downstream job.
