# REGISTER_SWAP is a symptom, not a cause

**Scope of this finding: n = 4 functions, MSVC 2010-era PowerPC (Xbox 360), one
codebase (dc3-decomp), measured 2026-08-02/04.** It is not a general law of
compilers, and it has not been checked against MWCC/PowerPC (RB3), GCC, or any
other backend. Treat it as a strong prior for this target and a hypothesis
elsewhere.

> **2026-08-04 update.** A fourth function
> (`LabelShrinkWrapper::UpdateAndDrawWrapper`) added a *second* stack-slot
> lever, which is the exact inverse of the scope-narrowing one — see
> "[Naming temporaries is the other stack-slot
> lever](#naming-temporaries-is-the-other-stack-slot-lever)". The same session
> also pinned down why EH funclet scores wobble when you fix their parent — see
> "[Funclet score wobble is parent frame size](#funclet-score-wobble-is-parent-frame-size)".

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

### `LabelShrinkWrapper::UpdateAndDrawWrapper` — 80.4% → 99.9%

Lever: **naming unnamed temporaries so they get frame-packed.** Covered in full
in the next section, because it is a lever the earlier three did not exercise.

## Naming temporaries is the other stack-slot lever

Scope-narrowing (`FitTextScroll`, above) packs *locals* by shortening the scope
they are declared in. This one goes the other way: it widens the live range of
**unnamed temporaries**, by giving them names, so the frame packer sees them at
all.

An unnamed `Vector3(...)` passed by const-ref dies at the end of its own call
expression. Four such temporaries in four consecutive calls therefore share
**one** stack slot: each dies before the next is built. The frame comes out
short — `stwu r1, -0xb0` against the target's `-0xc0` — with 21 inserts / 21
deletes and essentially every FPR and GPR downstream of the first call permuted.

Naming all four extended each live range to the end of the enclosing block, so
all four were in the frame at once. MSVC's frame packer then coalesced two of
them on its own: the first value dies as soon as its 16 bytes have been copied
into the callee, before the third is stored, so those two share a slot. Four
names, three slots — the target's shape.

Getting the **slot count** right fixed the FPR assignment and the instruction
schedule with no further edits.

| lever | what it moves | direction |
|---|---|---|
| narrow a declaration's scope | where *locals* pack in the frame | shorten a live range |
| name an unnamed temporary | whether *temporaries* are in the frame at all | lengthen a live range |

Both are stack-slot levers, and both surface as `REGISTER_SWAP` — which is the
whole point of this document. A wrong slot *count* repermutes every register
downstream of it.

### The intermediate-shape trap

**Fewer names is not closer to the answer.** Two partial spellings were measured
on the same function and both read exactly like floors:

| shape | score | what is wrong |
|---|---:|---|
| two named right-column locals + two unnamed temps | 90.6% | right slot *count*, wrong assignment |
| three names + a mid-function `.Set()` to recycle one | 86.2% | right slots *and* frame, but one value materializes in the wrong basic block |

Each buys real points and then stalls. If you are partway through this lever and
the score has stopped moving, the reading "this is the floor" is available and
wrong — match the target's **number of live values** and let the packer choose
the sharing, rather than hand-recycling a slot.

## Funclet score wobble is parent frame size

An MSVC EH funclet's first instruction reconstructs its parent's frame pointer
by subtracting the **parent's** frame size:

```asm
subi r31, r12, 0x80          ; <- parent frame size, not the funclet's
mflr r12
stw  r12, -0x8(r1)
stwu r1,  -0x60(r1)          ; the funclet's own frame
addi r3,  r31, 0x58          ; a parent local, by parent-frame offset
bl   ??1<T>@@QAA@XZ
```

So **any edit that grows the parent's frame changes one instruction inside every
one of its funclets**, and the funclet bodies also address the parent's locals
by parent-frame offset.

Verified directly in `dc3-decomp`'s `default/system/obj/Dir` (target
disassembly, 2026-08-04). The listing above is `fn_82590924` verbatim: a 40-byte
funclet whose `subi` immediate is `0x80` and whose sole job is to destroy a
parent local at `r31+0x58`. Across that one unit the funclet immediates take the
values `0x70`, `0x80`, `0x90`, `0xc0`, `0xd0`, `0xe0` — the distinct frame sizes
of their parents, not of themselves; every funclet establishes the same
`stwu r1, -0x60` for its own use. `ObjectDir::Iterate` is one of the `0xe0`
parents (`stwu r1, -0xe0`, `DataNode` at `r31+0x68`, `ObjDirItr` at `r31+0x80`),
and the `0xe0` funclets in the unit address exactly those offsets.

Consequences:

1. A funclet body is ~10 instructions. One changed instruction is ~10% of it,
   so a **16-byte frame growth in the parent shows up as a visible score drop in
   a tiny symbol** while the parent itself improves. That is the same edit
   counted twice, not a regression.
2. **Do not read it as funclet pairing noise, and do not let it veto a parent
   fix.** The byte-signature pairing is doing its job; the immediate genuinely
   differs.
3. A liveness lever that does *not* move the frame leaves the funclet at exactly
   100.0. That is the control: if the funclets moved, your edit changed the
   frame, whether or not you meant it to.

Practically: when scoring a stack-slot lever, score the parent and its funclets
together, or score the parent alone and expect the funclets to follow.

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

1. Read the prologue first, for two things.
   - A different **callee-saved save count** (`__savegprlr_NN`) means the two
     builds disagree about how many values must survive calls — that is the
     cause, and the swaps are its shadow.
   - A different **frame size** (`stwu r1, -N`) means the two builds disagree
     about how many stack slots there are. Fix that before reading a single
     register: a wrong slot count repermutes everything downstream of it. If
     *our* frame is the smaller one, look for aggregates constructed inside call
     argument lists (see the naming-temporaries lever above).
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
6. Reach for the stack-slot levers when `OFFSET_SWAP`, a frame-size delta, or
   stack-slot diffs are also present: declaration reorder, scope narrowing, and
   naming temporaries. That guidance is still correct — for that class.
7. Ignore the funclets while you work. Their scores move with the parent's frame
   size (above), so a drop there during a stack-slot fix is expected and is not
   a reason to back the fix out.

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

**Resolved 2026-08-04 in `7e5eb98` / `1030000`** — the "separate piece of work"
this section called for was done. Links are now named by what they explain
(`DocLink`) and resolved through a per-project table, with project identity
detected from the consuming repo's `docs/decomp/patterns/` directory by marker
filename. Full writeup, including why detection beat a CLI flag or an
`objdiff.json` field, how to add a third consumer, and the verification
workflow: **[`doc-link-project-detection.md`](doc-link-project-detection.md)**.

For the record, the interim state described here was worse than it looked: 29 of
the 30 emittable URLs failed against the RB3 tree, `at-limit-mwcc.md` was
putting MetroWerks content on four patterns inside an MSVC repo, and two of the
URLs existed in neither repo. dc3-decomp's `docs/decomp/patterns/INDEX.md` still
carries the consumer-side divergence table and the anchor contract; both are now
asserted by `scripts/check_doc_links.py` and by unit test rather than by eye.
