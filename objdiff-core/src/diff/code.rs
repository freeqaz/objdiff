use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map},
    string::{String, ToString},
    vec,
    vec::Vec,
};

use anyhow::{Context, Result, anyhow, ensure};

use super::{
    DiffObjConfig, FunctionRelocDiffs, InstructionArgDiffIndex, InstructionBranchFrom,
    InstructionBranchTo, InstructionDiffKind, InstructionDiffRow, PreferredStringEncoding,
    SymbolDiff, display::display_ins_data_literals,
};
use crate::obj::{
    InstructionArg, InstructionArgValue, InstructionRef, Object, ParsedInstruction,
    ResolvedInstructionRef, ResolvedRelocation, ResolvedSymbol, Section, SectionKind, SymbolKind,
};

pub fn no_diff_code(
    obj: &Object,
    symbol_index: usize,
    diff_config: &DiffObjConfig,
) -> Result<SymbolDiff> {
    let symbol = &obj.symbols[symbol_index];
    let section_index = symbol.section.ok_or_else(|| anyhow!("Missing section for symbol"))?;
    let section = &obj.sections[section_index];
    let data = section.data_range(symbol.address, symbol.size as usize).ok_or_else(|| {
        anyhow!(
            "Symbol data out of bounds: {:#x}..{:#x}",
            symbol.address,
            symbol.address + symbol.size
        )
    })?;
    let ops = obj.arch.scan_instructions(
        ResolvedSymbol { obj, symbol_index, symbol, section_index, section, data },
        diff_config,
    )?;
    let mut instruction_rows = Vec::<InstructionDiffRow>::new();
    for i in &ops {
        instruction_rows.push(InstructionDiffRow { ins_ref: Some(*i), ..Default::default() });
    }
    resolve_branches(&ops, &mut instruction_rows);
    Ok(SymbolDiff {
        target_symbol: None,
        match_percent: None,
        diff_score: None,
        instruction_rows,
        ..Default::default()
    })
}

const PENALTY_IMM_DIFF: u64 = 1;
const PENALTY_REG_DIFF: u64 = 5;
const PENALTY_REPLACE: u64 = 60;
const PENALTY_INSERT_DELETE: u64 = 100;

pub fn diff_code(
    left_obj: &Object,
    right_obj: &Object,
    left_symbol_idx: usize,
    right_symbol_idx: usize,
    diff_config: &DiffObjConfig,
    #[cfg(feature = "std")] symbol_equivalences: &std::collections::HashMap<
        alloc::string::String,
        std::collections::HashSet<alloc::string::String>,
    >,
) -> Result<(SymbolDiff, SymbolDiff)> {
    let left_symbol = &left_obj.symbols[left_symbol_idx];
    let right_symbol = &right_obj.symbols[right_symbol_idx];
    let left_section = left_symbol
        .section
        .and_then(|i| left_obj.sections.get(i))
        .ok_or_else(|| anyhow!("Missing section for symbol"))?;
    let right_section = right_symbol
        .section
        .and_then(|i| right_obj.sections.get(i))
        .ok_or_else(|| anyhow!("Missing section for symbol"))?;
    let left_data = left_section
        .data_range(left_symbol.address, left_symbol.size as usize)
        .ok_or_else(|| {
            anyhow!(
                "Symbol data out of bounds: {:#x}..{:#x}",
                left_symbol.address,
                left_symbol.address + left_symbol.size
            )
        })?;
    let right_data = right_section
        .data_range(right_symbol.address, right_symbol.size as usize)
        .ok_or_else(|| {
            anyhow!(
                "Symbol data out of bounds: {:#x}..{:#x}",
                right_symbol.address,
                right_symbol.address + right_symbol.size
            )
        })?;

    let left_section_idx = left_symbol.section.unwrap();
    let right_section_idx = right_symbol.section.unwrap();

    // Fast path: if raw bytes are identical, check if relocations also match.
    // This avoids the expensive scan_instructions + Patience/Myers diff pipeline
    // for the ~90% of functions that are already 100% matches.
    if left_data == right_data {
        let left_relocs: Vec<_> = left_section
            .relocations
            .iter()
            .filter(|r| {
                r.address >= left_symbol.address
                    && r.address < left_symbol.address + left_symbol.size
            })
            .collect();
        let right_relocs: Vec<_> = right_section
            .relocations
            .iter()
            .filter(|r| {
                r.address >= right_symbol.address
                    && r.address < right_symbol.address + right_symbol.size
            })
            .collect();

        let relocs_match = left_relocs.len() == right_relocs.len()
            && left_relocs.iter().zip(right_relocs.iter()).all(|(l, r)| {
                l.flags == r.flags
                    && (l.address - left_symbol.address) == (r.address - right_symbol.address)
                    && l.addend == r.addend
                    && left_obj.symbols[l.target_symbol].name
                        == right_obj.symbols[r.target_symbol].name
            });

        if relocs_match {
            // Perfect match — build minimal instruction rows without diffing
            let left_ops = left_obj.arch.scan_instructions(
                ResolvedSymbol {
                    obj: left_obj,
                    symbol_index: left_symbol_idx,
                    symbol: left_symbol,
                    section_index: left_section_idx,
                    section: left_section,
                    data: left_data,
                },
                diff_config,
            )?;
            let right_ops = right_obj.arch.scan_instructions(
                ResolvedSymbol {
                    obj: right_obj,
                    symbol_index: right_symbol_idx,
                    symbol: right_symbol,
                    section_index: right_section_idx,
                    section: right_section,
                    data: right_data,
                },
                diff_config,
            )?;
            let num_ops = left_ops.len();
            let mut left_rows: Vec<InstructionDiffRow> = left_ops
                .iter()
                .map(|i| InstructionDiffRow { ins_ref: Some(*i), ..Default::default() })
                .collect();
            let mut right_rows: Vec<InstructionDiffRow> = right_ops
                .iter()
                .map(|i| InstructionDiffRow { ins_ref: Some(*i), ..Default::default() })
                .collect();
            resolve_branches(&left_ops, &mut left_rows);
            resolve_branches(&right_ops, &mut right_rows);

            let max_score = num_ops as u64 * PENALTY_INSERT_DELETE;
            return Ok((
                SymbolDiff {
                    target_symbol: Some(right_symbol_idx),
                    match_percent: Some(100.0),
                    diff_score: Some((0, max_score)),
                    instruction_rows: left_rows,
                    ..Default::default()
                },
                SymbolDiff {
                    target_symbol: Some(left_symbol_idx),
                    match_percent: Some(100.0),
                    diff_score: Some((0, max_score)),
                    instruction_rows: right_rows,
                    ..Default::default()
                },
            ));
        }
    }

    let left_ops = left_obj.arch.scan_instructions(
        ResolvedSymbol {
            obj: left_obj,
            symbol_index: left_symbol_idx,
            symbol: left_symbol,
            section_index: left_section_idx,
            section: left_section,
            data: left_data,
        },
        diff_config,
    )?;
    let right_ops = right_obj.arch.scan_instructions(
        ResolvedSymbol {
            obj: right_obj,
            symbol_index: right_symbol_idx,
            symbol: right_symbol,
            section_index: right_section_idx,
            section: right_section,
            data: right_data,
        },
        diff_config,
    )?;
    let (mut left_rows, mut right_rows) = diff_instructions(&left_ops, &right_ops)?;
    resolve_branches(&left_ops, &mut left_rows);
    resolve_branches(&right_ops, &mut right_rows);

    // Detect the FP-anchor hairline slip (semantically-equal frame-anchor
    // codegen). Rows in this set are scored as equal — see
    // `detect_fp_anchor_compensation` for the (conservative) invariants.
    #[cfg(feature = "std")]
    let fp_anchor_equal_rows = detect_fp_anchor_compensation(
        left_obj,
        right_obj,
        left_symbol_idx,
        right_symbol_idx,
        &left_rows,
        &right_rows,
        diff_config,
        symbol_equivalences,
    );
    #[cfg(not(feature = "std"))]
    let fp_anchor_equal_rows = BTreeSet::<usize>::new();

    let mut diff_state = InstructionDiffState::default();
    // Masked-equality disclosure counters (do not affect the score). A row is
    // `masked_equal` when it was scored equal (kind == None) only because a
    // normalization erased a real difference; `reloc_ignored_rows` is the
    // subset attributable to reloc-mode relaxation.
    let mut masked_equal_rows: u32 = 0;
    let mut reloc_ignored_rows: u32 = 0;
    for (i, (left_row, right_row)) in left_rows.iter_mut().zip(right_rows.iter_mut()).enumerate() {
        // FP-anchor compensated pair: provably-equal effective address despite a
        // differing frame-anchor constant. Score as equal, no penalty.
        if fp_anchor_equal_rows.contains(&i) {
            left_row.kind = InstructionDiffKind::None;
            right_row.kind = InstructionDiffKind::None;
            left_row.arg_diff = Vec::new();
            right_row.arg_diff = Vec::new();
            left_row.masked_equal = true;
            right_row.masked_equal = true;
            masked_equal_rows += 1;
            continue;
        }
        let result = diff_instruction(
            left_obj,
            right_obj,
            left_symbol_idx,
            right_symbol_idx,
            left_row.ins_ref,
            right_row.ins_ref,
            left_row,
            right_row,
            diff_config,
            &mut diff_state,
            #[cfg(feature = "std")]
            symbol_equivalences,
        )?;
        left_row.kind = result.kind;
        right_row.kind = result.kind;
        left_row.arg_diff = result.left_args_diff;
        right_row.arg_diff = result.right_args_diff;
        if result.masked_reloc {
            left_row.masked_equal = true;
            right_row.masked_equal = true;
            masked_equal_rows += 1;
            reloc_ignored_rows += 1;
        }
    }

    let max_score = left_ops.len() as u64 * PENALTY_INSERT_DELETE;
    let diff_score = diff_state.diff_score.min(max_score);
    let match_percent = if max_score == 0 {
        0.0
    } else {
        ((1.0 - (diff_score as f64 / max_score as f64)) * 100.0) as f32
    };
    // Normalized match percent: excludes arg-only penalties (register swaps,
    // offset swaps) that don't represent real structural mismatches.
    let normalized_diff_score =
        diff_score.saturating_sub(diff_state.arg_diff_score).min(max_score);
    let match_percent_normalized = if max_score == 0 {
        0.0
    } else {
        ((1.0 - (normalized_diff_score as f64 / max_score as f64)) * 100.0) as f32
    };

    Ok((
        SymbolDiff {
            target_symbol: Some(right_symbol_idx),
            match_percent: Some(match_percent),
            match_percent_normalized: Some(match_percent_normalized),
            diff_score: Some((diff_score, max_score)),
            masked_equal_rows,
            reloc_ignored_rows,
            instruction_rows: left_rows,
            ..Default::default()
        },
        SymbolDiff {
            target_symbol: Some(left_symbol_idx),
            match_percent: Some(match_percent),
            match_percent_normalized: Some(match_percent_normalized),
            diff_score: Some((diff_score, max_score)),
            masked_equal_rows,
            reloc_ignored_rows,
            instruction_rows: right_rows,
            ..Default::default()
        },
    ))
}

/// One side of a frame-pointer-anchor establisher instruction, e.g.
/// `subi r31, r12, K` (the canonical MSVC PowerPC EH/FP-establisher prologue,
/// where r12 holds `this`/the incoming frame base and rA becomes the frame
/// anchor). `effective_base` is the value placed into rA expressed relative to
/// the source register: `r12 + effective_base`. For `subi` that is `-K`; for
/// `addi` that is `+K`.
#[cfg(feature = "std")]
struct FpAnchor {
    /// Destination (anchor) register, e.g. "r31".
    dst: String,
    /// `r12 + effective_base` is what the anchor register holds.
    effective_base: i64,
}

/// One side of a memory access relative to the FP anchor register, e.g.
/// `lwz r11, off(r31)`. `off` is the signed displacement; the effective address
/// reached is `<anchor register value> + off`.
#[cfg(feature = "std")]
struct AnchorMemAccess {
    /// Base register the access is relative to, e.g. "r31".
    base: String,
    /// Signed displacement.
    off: i64,
}

/// Classify an instruction as a frame-pointer-anchor establisher, if it is one.
///
/// Recognizes `subi rA, r12, K` / `addi rA, r12, K` where rA is a non-volatile
/// register (r14..r31) and the source is r12. This is the MSVC X360
/// FP/EH-establisher idiom. Returns `None` for anything else (including
/// `addi rA, r12, K` where the value is later used as data rather than a frame
/// anchor — the caller further constrains validity by requiring a compensating
/// access through rA).
#[cfg(feature = "std")]
fn classify_fp_anchor(ins: &ParsedInstruction) -> Option<FpAnchor> {
    let mnemonic: &str = &ins.mnemonic;
    let is_subi = mnemonic == "subi";
    let is_addi = mnemonic == "addi";
    if !is_subi && !is_addi {
        return None;
    }
    // Expect exactly: [GPR dst, GPR src, Signed imm]
    let [a0, a1, a2] = ins.args.as_slice() else {
        return None;
    };
    let dst = opaque_reg(a0)?;
    let src = opaque_reg(a1)?;
    let imm = signed_value(a2)?;
    // Source must be r12 (the incoming frame/this pointer in the MSVC idiom).
    if src != "r12" {
        return None;
    }
    // Destination must be a callee-saved GPR used as the frame anchor.
    if !is_nonvolatile_gpr(&dst) {
        return None;
    }
    let effective_base = if is_subi { -imm } else { imm };
    Some(FpAnchor { dst, effective_base })
}

/// Classify an instruction as a load/store relative to a base register, if it is
/// one of the form `<op> rD, off(base)`. The PowerPC backend prints offset
/// load/stores as `[rD, Signed(off), GPR(base)]`.
#[cfg(feature = "std")]
fn classify_anchor_mem(ins: &ParsedInstruction) -> Option<AnchorMemAccess> {
    // Offset load/stores have exactly 3 args: dest/src reg, signed offset, base reg.
    let [_a0, a1, a2] = ins.args.as_slice() else {
        return None;
    };
    let off = signed_value(a1)?;
    let base = opaque_reg(a2)?;
    Some(AnchorMemAccess { base, off })
}

#[cfg(feature = "std")]
fn opaque_reg(arg: &InstructionArg) -> Option<String> {
    match arg {
        InstructionArg::Value(InstructionArgValue::Opaque(s)) => Some(s.to_string()),
        _ => None,
    }
}

#[cfg(feature = "std")]
fn signed_value(arg: &InstructionArg) -> Option<i64> {
    match arg {
        InstructionArg::Value(InstructionArgValue::Signed(v)) => Some(*v),
        InstructionArg::Value(InstructionArgValue::Unsigned(v)) => i64::try_from(*v).ok(),
        _ => None,
    }
}

#[cfg(feature = "std")]
fn is_nonvolatile_gpr(reg: &str) -> bool {
    let Some(num) = reg.strip_prefix('r') else {
        return false;
    };
    matches!(num.parse::<u32>(), Ok(n) if (14..=31).contains(&n))
}

/// Detect the "FP-anchor hairline slip": MSVC's frame-pointer-establisher
/// constant `K` in `subi/addi rA, r12, K` differs between target and base, and
/// every differing memory access through rA shifts its displacement by exactly
/// the compensating amount so the *effective address* reached is identical on
/// both sides. This is provably semantically-equal codegen (it arises when a
/// base class grows/shrinks by a fixed amount, e.g. the ObjPtr polymorphism
/// migration): the anchor lands at a different frame offset but every access
/// compensates, so the same bytes are read/written.
///
/// Returns the set of paired-row indices whose `diff_arg` should be suppressed
/// (the anchor row plus its compensated accesses). The rule is intentionally
/// per-instruction, not whole-function: any *other* differing instruction (a
/// `bl` to a different callee, an *uncompensated* access, a real constant diff)
/// is left fully scored, so a function only reaches 100% if the anchor slip was
/// its *sole* difference.
///
/// Conservatism invariants (ALL required before suppressing anything):
/// 1. Exactly one FP-anchor establisher row, present on both sides at the same
///    paired index, with the same destination register and a differing K.
/// 2. The frame size (`stwu r1, -F, r1`) is byte-identical on both sides.
/// 3. At least one differing access through the anchor register exists and
///    compensates exactly (so a lone, uncompensated `subi` — a real diff — is
///    never suppressed; the anchor is only de-penalized once a compensation
///    proof exists).
///
/// Suppression is strictly local: only the anchor row and the load/stores that
/// compensate it are de-penalized. A differing row that is NOT a compensated
/// access (a `bl` to a different callee, a register swap, an uncompensated
/// member access, an `addi` building a derived pointer) is deliberately left
/// fully scored. The compensation claim is a per-instruction arithmetic
/// identity on the displacement immediates, so it holds regardless of whatever
/// else differs in the function — and a function only reaches 100% if the
/// anchor slip was its sole remaining difference.
///
/// Structural safety: any opcode replacement or insert/delete row (alignment
/// gap) aborts the whole detection (suppresses nothing), since those indicate
/// the sequences are not a clean 1:1 pairing of the FP-anchor idiom.
#[cfg(feature = "std")]
fn detect_fp_anchor_compensation(
    left_obj: &Object,
    right_obj: &Object,
    left_symbol_idx: usize,
    right_symbol_idx: usize,
    left_rows: &[InstructionDiffRow],
    right_rows: &[InstructionDiffRow],
    diff_config: &DiffObjConfig,
    symbol_equivalences: &std::collections::HashMap<
        alloc::string::String,
        std::collections::HashSet<alloc::string::String>,
    >,
) -> BTreeSet<usize> {
    let empty = BTreeSet::new();
    // Cheap pre-screen: the fast path already handled byte-identical functions,
    // so we only run when there is at least one row whose raw code differs and
    // both sides are present.
    if left_rows.len() != right_rows.len() {
        return empty;
    }

    // Parse helper for a single row on a given side.
    let parse = |obj: &Object, sym_idx: usize, row: &InstructionDiffRow| -> Option<ParsedInstruction> {
        let ins_ref = row.ins_ref?;
        let resolved = obj.resolve_instruction_ref(sym_idx, ins_ref)?;
        obj.arch.process_instruction(resolved, diff_config).ok()
    };

    let mut anchor_row: Option<usize> = None;
    let mut anchor_dst: Option<String> = None;
    let mut left_eff: i64 = 0;
    let mut right_eff: i64 = 0;
    let mut compensated_rows: BTreeSet<usize> = BTreeSet::new();
    let mut saw_compensated_access = false;
    let mut frame_size_ok = false;

    // First pass: locate the single FP-anchor establisher and the frame setup.
    for (i, (lr, rr)) in left_rows.iter().zip(right_rows.iter()).enumerate() {
        let (Some(lref), Some(rref)) = (lr.ins_ref, rr.ins_ref) else { continue };
        // Only consider rows whose raw bytes actually differ; identical rows
        // need no scrutiny (and the common case is they are equal).
        if lref.opcode != rref.opcode {
            // An opcode replacement is a real structural diff; bail entirely —
            // the FP-anchor idiom never changes opcodes.
            return empty;
        }
        let (Some(lp), Some(rp)) =
            (parse(left_obj, left_symbol_idx, lr), parse(right_obj, right_symbol_idx, rr))
        else {
            continue;
        };

        // Track frame size establisher (must be identical on both sides).
        let (lmn, rmn): (&str, &str) = (&lp.mnemonic, &rp.mnemonic);
        if lmn == "stwu" && rmn == "stwu" {
            // `stwu r1, -F, r1`
            if lp.args == rp.args {
                // Confirm it is the r1 frame push.
                if let (Some(ld), Some(rd)) =
                    (lp.args.first().and_then(opaque_reg), rp.args.first().and_then(opaque_reg))
                    && ld == "r1"
                    && rd == "r1"
                {
                    frame_size_ok = true;
                }
            } else {
                // Differing frame size => not a compensated slip; abort.
                return empty;
            }
        }

        if let (Some(la), Some(ra)) = (classify_fp_anchor(&lp), classify_fp_anchor(&rp)) {
            if la.dst != ra.dst {
                return empty; // anchor moved to a different register: structural
            }
            if anchor_row.is_some() {
                return empty; // more than one anchor establisher: too ambiguous
            }
            // Only a *differing* anchor is interesting; an identical one is fine
            // but means the slip (if any) is elsewhere — record it so we know
            // the anchor register and its effective base on each side.
            anchor_row = Some(i);
            anchor_dst = Some(la.dst.clone());
            left_eff = la.effective_base;
            right_eff = ra.effective_base;
        }
    }

    let (Some(anchor_idx), Some(dst)) = (anchor_row, anchor_dst) else {
        return empty;
    };
    if !frame_size_ok {
        return empty;
    }
    // If the anchor establisher is identical on both sides there is no slip to
    // reclaim here (a real diff, if present, lives in another row).
    if left_eff == right_eff {
        return empty;
    }

    // Second pass: find every differing memory access through the anchor
    // register that *compensates* the anchor slip (same effective address on
    // both sides). These are the only rows we will suppress, alongside the
    // anchor itself. Every *other* differing row is deliberately left fully
    // scored — so an unrelated `bl`, a register swap, or an *uncompensated*
    // access keeps the function below 100%. The suppression is a strictly
    // local, per-instruction soundness claim: for a compensated pair the bytes
    // read/written are provably identical.
    for (i, (lr, rr)) in left_rows.iter().zip(right_rows.iter()).enumerate() {
        if i == anchor_idx {
            continue;
        }
        let (Some(lref), Some(rref)) = (lr.ins_ref, rr.ins_ref) else {
            // An insert/delete row (alignment gap) means the sequences are not a
            // clean 1:1 pairing; abort entirely to stay safe.
            return empty;
        };
        let (Some(lres), Some(rres)) = (
            left_obj.resolve_instruction_ref(left_symbol_idx, lref),
            right_obj.resolve_instruction_ref(right_symbol_idx, rref),
        ) else {
            return empty;
        };
        // Identical rows (byte- and reloc-equal) need no handling.
        if lref.opcode == rref.opcode
            && lres.code == rres.code
            && reloc_eq(left_obj, right_obj, lres, rres, diff_config, symbol_equivalences)
        {
            continue;
        }

        // This row differs. Parse it; if it is not a clean compensated access we
        // leave it scored (do NOT suppress) and move on.
        let (Some(lp), Some(rp)) =
            (parse(left_obj, left_symbol_idx, lr), parse(right_obj, right_symbol_idx, rr))
        else {
            continue;
        };
        if lref.opcode != rref.opcode || lp.mnemonic != rp.mnemonic {
            continue; // opcode/mnemonic mismatch: real diff, leave scored
        }
        // A row whose args all compare equal (e.g. a `bl` to the same callee) is
        // already equal — nothing to suppress, just skip.
        if lp.args.len() == rp.args.len()
            && lp.args.iter().zip(rp.args.iter()).all(|(a, b)| {
                arg_eq(
                    left_obj, right_obj, lr, rr, a, b, lres, rres, diff_config, symbol_equivalences,
                )
            })
        {
            continue;
        }

        // Is it a load/store relative to the anchor register with a compensating
        // displacement? Only then do we suppress it.
        let (Some(lm), Some(rm)) = (classify_anchor_mem(&lp), classify_anchor_mem(&rp)) else {
            continue; // not an offset access (e.g. a differing `bl`): real diff
        };
        if lm.base != dst || rm.base != dst {
            continue; // relative to a different register: not part of this slip
        }
        // Exactly 3 args [reg, off, base]; the non-offset arg (reg) must match,
        // else it is a register diff, not a pure displacement compensation.
        if lp.args.len() != 3 || rp.args.len() != 3 || !lp.args[0].loose_eq(&rp.args[0]) {
            continue;
        }
        // Compensation invariant: effective address identical on both sides.
        //   left:  (r12 + left_eff)  + lm.off
        //   right: (r12 + right_eff) + rm.off
        if left_eff + lm.off != right_eff + rm.off {
            continue; // uncompensated: a real member-offset difference
        }
        saw_compensated_access = true;
        compensated_rows.insert(i);
    }

    if !saw_compensated_access {
        // The anchor differs but NO access compensates it: the anchor genuinely
        // reaches a different frame slot (a real difference). Suppress nothing —
        // never de-penalize a lone, uncompensated frame-anchor constant.
        return empty;
    }

    // Suppress the anchor establisher plus every compensated access. All other
    // differing rows remain fully scored.
    compensated_rows.insert(anchor_idx);
    compensated_rows
}

fn diff_instructions(
    left_insts: &[InstructionRef],
    right_insts: &[InstructionRef],
) -> Result<(Vec<InstructionDiffRow>, Vec<InstructionDiffRow>)> {
    let left_ops = left_insts.iter().map(|i| i.opcode).collect::<Vec<_>>();
    let right_ops = right_insts.iter().map(|i| i.opcode).collect::<Vec<_>>();
    // Fast path: if the opcode sequences are element-wise IDENTICAL, pair 1:1 and skip
    // the diff algorithm. This is exactly what `capture_diff_slices` produces for equal
    // slices (a single `Equal` op covering both ranges), so the fast path is provably
    // equivalent to the general path here — it only saves the work.
    //
    // ⚠ This condition used to be `left_insts.len() == right_insts.len()`, justified by
    // "same-length sequences have no insertions/deletions". THAT IS FALSE: N insertions
    // plus N deletions preserve length. The consequence was a FALSE REGRESSION — a
    // function whose length became EQUAL to its target's would drop off the real
    // alignment onto a 1:1 pairing and score far lower (measured by lane DQ-1:
    // 1253-vs-1259 → 98.7%, 1259-vs-1259 → 72.2% with 578 spurious `replace` rows,
    // 1261-vs-1259 → 99.8%). i.e. getting a function's SIZE RIGHT collapsed its score.
    // Do not re-weaken this guard to a length comparison. (lanes DQ-1, DR-1)
    if left_ops == right_ops {
        let left_diff = left_insts
            .iter()
            .map(|i| InstructionDiffRow { ins_ref: Some(*i), ..Default::default() })
            .collect();
        let right_diff = right_insts
            .iter()
            .map(|i| InstructionDiffRow { ins_ref: Some(*i), ..Default::default() })
            .collect();
        return Ok((left_diff, right_diff));
    }
    let ops = similar::capture_diff_slices(similar::Algorithm::Patience, &left_ops, &right_ops);
    if ops.is_empty() {
        ensure!(left_insts.len() == right_insts.len());
        let left_diff = left_insts
            .iter()
            .map(|i| InstructionDiffRow { ins_ref: Some(*i), ..Default::default() })
            .collect();
        let right_diff = right_insts
            .iter()
            .map(|i| InstructionDiffRow { ins_ref: Some(*i), ..Default::default() })
            .collect();
        return Ok((left_diff, right_diff));
    }

    let row_count = ops
        .iter()
        .map(|op| match *op {
            similar::DiffOp::Equal { len, .. } => len,
            similar::DiffOp::Delete { old_len, .. } => old_len,
            similar::DiffOp::Insert { new_len, .. } => new_len,
            similar::DiffOp::Replace { old_len, new_len, .. } => old_len.max(new_len),
        })
        .sum();
    let mut left_diff = Vec::<InstructionDiffRow>::with_capacity(row_count);
    let mut right_diff = Vec::<InstructionDiffRow>::with_capacity(row_count);
    for op in ops {
        let (_tag, left_range, right_range) = op.as_tag_tuple();
        let len = left_range.len().max(right_range.len());
        left_diff.extend(
            left_range
                .clone()
                .map(|i| InstructionDiffRow { ins_ref: Some(left_insts[i]), ..Default::default() }),
        );
        right_diff.extend(
            right_range.clone().map(|i| InstructionDiffRow {
                ins_ref: Some(right_insts[i]),
                ..Default::default()
            }),
        );
        if left_range.len() < len {
            left_diff.extend((left_range.len()..len).map(|_| InstructionDiffRow::default()));
        }
        if right_range.len() < len {
            right_diff.extend((right_range.len()..len).map(|_| InstructionDiffRow::default()));
        }
    }
    Ok((left_diff, right_diff))
}

fn arg_to_string(arg: &InstructionArg, reloc: Option<ResolvedRelocation>) -> String {
    match arg {
        InstructionArg::Value(arg) => arg.to_string(),
        InstructionArg::Reloc => {
            reloc.as_ref().map_or_else(|| "<unknown>".to_string(), |r| r.symbol.name.clone())
        }
        InstructionArg::BranchDest(arg) => arg.to_string(),
    }
}

fn resolve_branches(ops: &[InstructionRef], rows: &mut [InstructionDiffRow]) {
    let mut branch_idx = 0u32;
    // Map addresses to indices
    let mut addr_map = BTreeMap::<u64, u32>::new();
    for (i, ins_diff) in rows.iter().enumerate() {
        if let Some(ins) = ins_diff.ins_ref {
            addr_map.insert(ins.address, i as u32);
        }
    }
    // Generate branches
    let mut branches = BTreeMap::<u32, InstructionBranchFrom>::new();
    for ((i, ins_diff), ins) in
        rows.iter_mut().enumerate().filter(|(_, row)| row.ins_ref.is_some()).zip(ops)
    {
        if let Some(ins_idx) = ins.branch_dest.and_then(|a| addr_map.get(&a).copied()) {
            match branches.entry(ins_idx) {
                btree_map::Entry::Vacant(e) => {
                    ins_diff.branch_to = Some(InstructionBranchTo { ins_idx, branch_idx });
                    e.insert(InstructionBranchFrom { ins_idx: vec![i as u32], branch_idx });
                    branch_idx += 1;
                }
                btree_map::Entry::Occupied(e) => {
                    let branch = e.into_mut();
                    ins_diff.branch_to =
                        Some(InstructionBranchTo { ins_idx, branch_idx: branch.branch_idx });
                    branch.ins_idx.push(i as u32);
                }
            }
        }
    }
    // Store branch from
    for (i, branch) in branches {
        rows[i as usize].branch_from = Some(branch);
    }
}

pub(crate) fn address_eq(left: ResolvedRelocation, right: ResolvedRelocation) -> bool {
    if right.symbol.size == 0 && left.symbol.size != 0 {
        // The base relocation is against a pool but the target relocation isn't.
        // This can happen in rare cases where the compiler will generate a pool+addend relocation
        // in the base's data, but the one detected in the target is direct with no addend.
        // Just check that the final address is the same so these count as a match.
        left.symbol.address as i64 + left.relocation.addend
            == right.symbol.address as i64 + right.relocation.addend
    } else {
        // But otherwise, if the compiler isn't using a pool, we're more strict and check that the
        // target symbol address and relocation addend both match exactly.
        left.symbol.address == right.symbol.address
            && left.relocation.addend == right.relocation.addend
    }
}

pub(crate) fn section_name_eq(
    left_obj: &Object,
    right_obj: &Object,
    left_section_index: usize,
    right_section_index: usize,
) -> bool {
    left_obj.sections.get(left_section_index).is_some_and(|left_section| {
        right_obj
            .sections
            .get(right_section_index)
            .is_some_and(|right_section| left_section.name == right_section.name)
    })
}

/// The base of a (possibly COMDAT-grouped) section name: everything before the
/// first `$`. MSVC groups COMDAT definitions into `$`-suffixed buckets of a
/// logical section (`.text$mn`, `.text$dup`, `.rdata$r`, …); the linker folds
/// and orders by these, but which bucket a given definition lands in is a
/// build/link artifact. The base name (`.text`, `.rdata`) is the stable logical
/// section identity, so `.text` and `.text$dup` share the base `.text` while
/// `.text` and `.data` do not.
fn section_base_name(name: &str) -> &str {
    match name.split_once('$') {
        Some((base, _)) => base,
        None => name,
    }
}

/// True when a section holds executable code. Keyed on the reader-supplied
/// [`SectionKind`], with a name fallback for readers that leave the kind
/// unknown.
fn is_code_section(section: &Section) -> bool {
    section.kind == SectionKind::Code || section_base_name(&section.name) == ".text"
}

/// COMDAT-tolerant section comparison used by NameOnly/NameCheck reloc matching.
///
/// Like [`section_name_eq`] but tolerant of the two ways the same symbol legally
/// lands in a differently-named section across two producers of the same object:
///
/// 1. **COMDAT bucket.** MSVC parks a DEFINED COMDAT symbol into a `$`-suffixed
///    bucket of its logical section (`.text$mn`, `.text$dup`, `.rdata$r`, …), so
///    the very same symbol is in `.text` in one object and `.text$dup` in
///    another. Compare the base name (see [`section_base_name`]).
///
/// 2. **Data placement.** WHICH data section a datum lands in is a producer
///    choice, not a property of the referent: a compiler puts a zero-initialised
///    static in `.bss` while a splitter that reconstructs the object from a
///    linked image emits every writable datum into `.data$dup`, and throw-info
///    records show up as `.rdata$dup` against `.xdata$x`. Same mangled name, same
///    datum, different emitter. Charging that difference reports a defect that no
///    source edit can reach — measured on dc3, it was 1,831 of 1,834 such
///    charges and it exposed 1,024 functions that have no other disagreement.
///    So two NON-CODE sections are treated as the same logical section.
///
/// The code/data split is still enforced, which is all the guard was ever for:
/// it exists to stop a name coincidence across genuinely different logical
/// sections. This is only ever paired with an exact-symbol-name guard
/// (`names_match`), so it cannot credit two genuinely different callees.
pub(crate) fn section_name_eq_comdat(
    left_obj: &Object,
    right_obj: &Object,
    left_section_index: usize,
    right_section_index: usize,
) -> bool {
    left_obj.sections.get(left_section_index).is_some_and(|left_section| {
        right_obj.sections.get(right_section_index).is_some_and(|right_section| {
            section_base_name(&left_section.name) == section_base_name(&right_section.name)
                || (!is_code_section(left_section) && !is_code_section(right_section))
        })
    })
}

/// Normalize a mangled symbol by stripping array dimension sizes.
/// Template instantiations differing only in array sizes produce identical code
/// (arrays decay to pointers), making them ICF-equivalent.
///
/// Handles both template array args (`$$BY0<size>`) and function parameter
/// arrays (`AAY0<size>`, etc.). `Y<digit>` always indicates an array type
/// (`Y0`=1D, `Y1`=2D, etc.), distinct from calling convention (`YA`, `YE`)
/// which uses letters.
fn normalize_mangled_array_sizes(name: &str) -> Option<String> {
    if !name.starts_with("??$") {
        return None;
    }
    let bytes = name.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut had_array = false;
    while i < bytes.len() {
        if bytes[i] == b'Y'
            && i + 1 < bytes.len()
            && bytes[i + 1] >= b'0'
            && bytes[i + 1] <= b'9'
        {
            let dims = (bytes[i + 1] - b'0') as usize + 1;
            result.push(b'Y');
            result.push(bytes[i + 1]);
            i += 2;
            had_array = true;
            // Skip encoded size for each dimension
            for _ in 0..dims {
                if i < bytes.len() && bytes[i] >= b'0' && bytes[i] <= b'9' {
                    // Single digit encoding (values 1-10)
                    i += 1;
                } else {
                    // Multi-char hex encoding (A-P)+ terminated by @
                    while i < bytes.len() && bytes[i] >= b'A' && bytes[i] <= b'P' {
                        i += 1;
                    }
                    if i < bytes.len() && bytes[i] == b'@' {
                        i += 1;
                    }
                }
            }
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    if had_array { String::from_utf8(result).ok() } else { None }
}

/// True for the auto-generated placeholder names a splitter assigns to
/// symbols it could not identify. Used by `FunctionRelocDiffs::NameCheck` to
/// treat relocations against unidentified symbols as unverifiable rather than
/// as mismatches. Covers dtk (PowerPC ELF: `fn_<hexaddr>`, `lbl_<hexaddr>`,
/// `jumptable_<hexaddr>`) and csplit (i386 PE: `code_<hexaddr>`,
/// `data_<hexaddr>`, `bss_<hexaddr>`, `rdata_<hexaddr>`, each optionally
/// carrying the cdecl leading underscore, e.g. `_bss_00456208`).
/// The suffix must be non-empty hex (plus `_` separators) so a genuine source
/// symbol that merely starts with one of these prefixes is not swallowed.
fn is_placeholder_symbol_name(name: &str) -> bool {
    // Tolerate a single leading underscore (i386 PE cdecl decoration).
    let name = name.strip_prefix('_').unwrap_or(name);
    ["fn_", "lbl_", "jumptable_", "code_", "data_", "bss_", "rdata_"].iter().any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit() || b == b'_')
        })
    })
}

/// True for a compiler-generated name whose numeric suffix is a per-TU
/// compilation counter rather than an identity. Metrowerks (mwcc) spells these
/// `__FUNCTION__$12505`, `__PRETTY_FUNCTION__$27320`, `s_seed$34`, and numbers
/// its anonymous literal-pool entries `@23858`. Recompiling the same source
/// renumbers them, so the NAME carries no information — but unlike MSVC's `$L`
/// code labels these name DATA, so the bytes they point at can be compared
/// instead. See `counter_named_data_eq`.
fn is_counter_suffixed_name(name: &str) -> bool {
    // `@<digits>`: mwcc's anonymous literal pool.
    if let Some(rest) = name.strip_prefix('@')
        && !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
            return true;
        }
    // `<identifier>$<digits>`: a named datum plus the TU counter that
    // disambiguates it. Require a non-empty identifier so a bare `$12` (which
    // `is_compiler_local_label` already owns) does not land here.
    match name.rsplit_once('$') {
        Some((head, digits)) => {
            !head.is_empty()
                && !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit())
                && !head.contains('$')
        }
        None => false,
    }
}

/// NameCheck: both sides name a counter-suffixed datum (see
/// [`is_counter_suffixed_name`]) AND the two data are byte-identical.
///
/// This is a CONTENT check standing in for a name check that cannot work. The
/// number in `__FUNCTION__$12505` is a compilation-order counter, so comparing
/// it charges every string literal in a matching function; comparing the string
/// itself answers the question the name check was asking — is this the same
/// literal — and answers it more strongly than a name ever could.
///
/// Where the content cannot be read the site is UNVERIFIABLE, not wrong, and is
/// treated the same way NameCheck already treats a missing left relocation or a
/// placeholder left name: matched. A dtk-split target routinely carries a
/// truncated `.rodata` whose bytes for a given offset are simply not in the
/// object, and a `.bss` datum has no bytes anywhere by definition. Neither is
/// evidence of a different referent, and both sides' names are counters, so
/// there is nothing left to check.
fn counter_named_data_eq(
    left_obj: &Object,
    right_obj: &Object,
    left_reloc: &ResolvedRelocation,
    right_reloc: &ResolvedRelocation,
) -> bool {
    if !is_counter_suffixed_name(&left_reloc.symbol.name)
        || !is_counter_suffixed_name(&right_reloc.symbol.name)
    {
        return false;
    }
    match (
        counter_named_content(left_obj, left_reloc.relocation.target_symbol),
        counter_named_content(right_obj, right_reloc.relocation.target_symbol),
    ) {
        (Some(l), Some(r)) => content_eq(&l, &r),
        // Unreadable on one or both sides: unverifiable, so not charged.
        _ => true,
    }
}

/// NameCheck: the MIXED counter/anchor shape, verified by CONTENT.
///
/// [`counter_named_data_eq`] handles counter-vs-counter and
/// [`resolve_pool_anchor`] handles anchor-vs-anchor, but the two producers do
/// not have to agree on which spelling to use for the same datum: a datum that
/// sits at offset 0 of `.data`/`.bss` has BOTH a counter name and the section
/// anchor sitting on it, and retail's dtk-split object relocates against the
/// counter (`@13392`) where ours relocates against the anchor (`...bss.0`).
/// Measured on rb3, that mixed shape was 146 charges over 72 functions — half
/// the whole `name_check` residual — and no source edit can reach any of it.
///
/// So compose the two tolerances: the caller has already resolved whichever
/// side is an anchor to the sized symbol its addend lands in, and this compares
/// the CONTENT of the two resolved referents whenever both of their names are
/// per-TU counters and therefore carry no identity.
///
/// The guards are the ones the rest of NameCheck keeps: a counter-named
/// FUNCTION is never credited against a counter-named datum, the code/data
/// section guard still applies, and content that cannot be read on either side
/// is UNVERIFIABLE rather than wrong (see [`counter_named_data_eq`]).
///
/// Measured on rb3: 146 exposed functions -> 75, +71 complete at `name_check`
/// and none lost, with the `none` ruler byte-identical. The four charges of
/// this shape that SURVIVE are the check doing its job — `NANDInit` and
/// `ReportOSInfo` reach an SDK banner string whose build date genuinely differs
/// (`Dec 11 2009 15:59:08` against `Dec 11 2007 01:35:48`), which is a real
/// difference in what is referenced and not a spelling of it.
fn counter_named_referents_eq(
    left_obj: &Object,
    right_obj: &Object,
    left_index: usize,
    right_index: usize,
) -> bool {
    let (Some(left_symbol), Some(right_symbol)) =
        (left_obj.symbols.get(left_index), right_obj.symbols.get(right_index))
    else {
        return false;
    };
    if !is_counter_suffixed_name(&left_symbol.name)
        || !is_counter_suffixed_name(&right_symbol.name)
    {
        return false;
    }
    if left_symbol.kind == SymbolKind::Function || right_symbol.kind == SymbolKind::Function {
        return false;
    }
    let (Some(left_section), Some(right_section)) = (left_symbol.section, right_symbol.section)
    else {
        return false;
    };
    if !section_name_eq_comdat(left_obj, right_obj, left_section, right_section) {
        return false;
    }
    match (
        counter_named_content(left_obj, left_index),
        counter_named_content(right_obj, right_index),
    ) {
        (Some(l), Some(r)) => content_eq(&l, &r),
        // Unreadable on one or both sides: unverifiable, so not charged.
        _ => true,
    }
}

/// What a counter-named datum holds, for [`counter_named_data_eq`].
enum CounterContent<'a> {
    /// A `.bss`/NOBITS datum: `size` bytes of zero, stored nowhere.
    Zeroed(u64),
    Bytes(&'a [u8]),
}

fn counter_named_content(obj: &Object, index: usize) -> Option<CounterContent<'_>> {
    let symbol = obj.symbols.get(index)?;
    if symbol.size == 0 {
        return None;
    }
    let section = obj.sections.get(symbol.section?)?;
    if section.kind == SectionKind::Bss {
        return Some(CounterContent::Zeroed(symbol.size));
    }
    obj.symbol_data(index).map(CounterContent::Bytes)
}

fn content_eq(left: &CounterContent, right: &CounterContent) -> bool {
    match (left, right) {
        (CounterContent::Zeroed(l), CounterContent::Zeroed(r)) => l == r,
        // One side stores its zeros, the other does not. Same value.
        (CounterContent::Zeroed(n), CounterContent::Bytes(b))
        | (CounterContent::Bytes(b), CounterContent::Zeroed(n)) => {
            b.len() as u64 == *n && b.iter().all(|&byte| byte == 0)
        }
        (CounterContent::Bytes(l), CounterContent::Bytes(r)) => l == r,
    }
}

/// What a relocation against a zero-sized section/pool ANCHOR actually reaches.
///
/// mwcc's small-data addressing relocates against a section anchor and gets to
/// the datum with an addend; dtk names those anchors `...data.0` / `...bss.0`,
/// and a dtk-split object names them `_f_data` / `_f_bss`. The anchor names a
/// SECTION, so comparing anchor spellings answers nothing — but the addend says
/// which datum, so the real referent can be recovered and compared instead.
enum PoolAnchor<'a> {
    /// Not an anchor; use the relocation's own symbol name.
    No,
    /// An anchor, and the datum at `anchor + addend` was found: its name, and
    /// its symbol index (which is what [`counter_named_referents_eq`] reads the
    /// datum's CONTENT through when the name turns out to be a counter).
    Resolved(&'a str, usize),
    /// An anchor whose addend lands in no sized symbol: unverifiable.
    Unresolved,
}

fn resolve_pool_anchor<'a>(obj: &'a Object, reloc: &ResolvedRelocation) -> PoolAnchor<'a> {
    if reloc.symbol.size != 0 || reloc.symbol.kind == SymbolKind::Function {
        return PoolAnchor::No;
    }
    let Some(section_index) = reloc.symbol.section else {
        // Undefined extern, not an anchor: its name is the referent.
        return PoolAnchor::No;
    };
    let Some(section) = obj.sections.get(section_index) else {
        return PoolAnchor::No;
    };
    if is_code_section(section) {
        return PoolAnchor::No;
    }
    let Some(address) = reloc.symbol.address.checked_add_signed(reloc.relocation.addend) else {
        return PoolAnchor::Unresolved;
    };
    match obj.symbols.iter().position(|s| {
        s.section == Some(section_index)
            && s.size > 0
            && s.kind != SymbolKind::Section
            && (s.address..s.address + s.size).contains(&address)
    }) {
        Some(index) => PoolAnchor::Resolved(obj.symbols[index].name.as_str(), index),
        None => PoolAnchor::Unresolved,
    }
}

/// True for MSVC compiler-internal local labels: `$L18077` (block / jump-table
/// labels), `$T18082` (SEH scope-table records), `$SG...` etc. The numeric
/// suffix is a compilation-order counter, NOT a stable identity — the same
/// source recompiled produces different numbers — so comparing these names
/// across target/base is pure noise. `FunctionRelocDiffs::NameCheck` treats a
/// target-side relocation against one as unverifiable. (Content-derived names
/// like `__real@3f800000` / `??_C@...` string literals are deterministic and
/// are deliberately NOT covered: a mismatch there is a real defect.)
fn is_compiler_local_label(name: &str) -> bool {
    name.strip_prefix('$').is_some_and(|rest| !rest.is_empty())
}

/// True when `obj` declares `name` as an UNDEFINED COFF weak external whose
/// auxiliary record defaults to exactly `other`.
///
/// Deliberately an equality test against the resolved default, not a
/// name-shape rule: `??_E<X>` defaulting to `??_G<X>` is forgiven, `??_E<X>`
/// defaulting to `??_G<Y>` while the other side calls `??_G<Z>` is NOT. The
/// map is empty for non-COFF objects and for any symbol this object defines.
fn weak_external_aliases(obj: &Object, name: &str, other: &str) -> bool {
    obj.weak_external_defaults.get(name).is_some_and(|default| default == other)
}

fn ins_data_literals_eq(
    left_obj: &Object,
    right_obj: &Object,
    left_ins: ResolvedInstructionRef,
    right_ins: ResolvedInstructionRef,
    diff_config: &DiffObjConfig,
) -> bool {
    let mut left_literals = display_ins_data_literals(left_obj, left_ins);
    let mut right_literals = display_ins_data_literals(right_obj, right_ins);
    if left_literals == right_literals {
        return true;
    }
    if diff_config.preferred_string_encoding == PreferredStringEncoding::Auto {
        return left_literals == right_literals;
    }
    left_literals.retain(|lit_info| !lit_info.hidden(Some(diff_config)));
    right_literals.retain(|lit_info| !lit_info.hidden(Some(diff_config)));
    left_literals == right_literals
}

/// NameCheck: the MSVC-PPC switch-dispatch base, where the target object has
/// LOST the addend it needs to say what it points at.
///
/// MSVC-PPC compiles a dense `switch` into
/// `lis/addi r12, <table>` ; `lhzx r0, r12, r0` ; `lis/addi r12, <first case>` ;
/// `add r12, r12, r0` ; `mtctr` ; `bctr`. The second `lis/addi` pair materializes
/// an address INTERIOR to the function being compiled — the first case block —
/// and MSVC names it with a `$LN<n>` local label, whose counter is a
/// compilation-order artifact (see `is_compiler_local_label`).
///
/// A dtk-split target object cannot spell that. dtk's disassembly knows the real
/// referent (it writes `"?Fn@@..."+0x98`), but its COFF writer can only name a
/// symbol and drops the addend, so the relocation arrives as
/// `<enclosing function> + 0`. objdiff then resolves the target's branch
/// destination to instruction 0 and ours to the real case block, and `arg_eq`
/// charges `BranchDest 0 != 38` — a difference that exists only because the
/// addend was thrown away.
///
/// Verified on dc3 `SaveLoadManager::GetDialogMsg`: the two `.text` words are
/// byte-identical (`3d800000` / `398c0000`, immediates zero and linker-filled),
/// the two 94-entry jump tables are byte-identical, and each side is internally
/// consistent only at function+0x98 — retail's default arm
/// (`bgt` at func+0x6c, displacement 0x1868 -> func+0x18d4) minus its table's
/// default entry (0x183c) is 0x98, which is exactly where our `$LN738` sits.
/// Both sides denote the SAME linked address.
///
/// The tolerance is therefore keyed on dtk's addend-loss signature and nothing
/// wider:
///   * ours is a `$`-label with a zero addend, in the same section as, and
///     inside the extent of, the function being diffed;
///   * theirs is a zero-addend relocation naming that very function, in that
///     function's own section.
///
/// A wrong callee, a wrong datum, or a reference to any OTHER function is still
/// charged. What it cannot see — and no reading of the target object can, since
/// the addend is gone — is our interior offset differing from retail's; that
/// residual is why this is NameCheck-only and `name_address` still charges it.
fn interior_self_reference(
    left_ins: ResolvedInstructionRef,
    right_ins: ResolvedInstructionRef,
    left_reloc: &ResolvedRelocation,
    right_reloc: &ResolvedRelocation,
) -> bool {
    // Ours: an MSVC `$` local label, addressed directly, inside this function.
    if !is_compiler_local_label(&right_reloc.symbol.name)
        || right_reloc.relocation.addend != 0
        || right_reloc.symbol.section != Some(right_ins.section_index)
    {
        return false;
    }
    let right_fn = right_ins.symbol;
    if right_fn.size == 0
        || !(right_fn.address..right_fn.address + right_fn.size)
            .contains(&right_reloc.symbol.address)
    {
        return false;
    }
    // Theirs: dtk's addend-losing fallback — the enclosing function, addend 0.
    left_reloc.relocation.addend == 0
        && left_reloc.symbol.name == left_ins.symbol.name
        && left_reloc.symbol.section == Some(left_ins.section_index)
}

fn reloc_eq(
    left_obj: &Object,
    right_obj: &Object,
    left_ins: ResolvedInstructionRef,
    right_ins: ResolvedInstructionRef,
    diff_config: &DiffObjConfig,
    #[cfg(feature = "std")] symbol_equivalences: &std::collections::HashMap<
        alloc::string::String,
        std::collections::HashSet<alloc::string::String>,
    >,
) -> bool {
    let relax_reloc_diffs = diff_config.function_reloc_diffs == FunctionRelocDiffs::None;
    let name_check = diff_config.function_reloc_diffs == FunctionRelocDiffs::NameCheck;
    let (left_reloc, right_reloc) = match (left_ins.relocation, right_ins.relocation) {
        (Some(left_reloc), Some(right_reloc)) => (left_reloc, right_reloc),
        // If relocations are relaxed, match if left is missing a reloc
        // NameCheck: split/disassembled target objects add relocations on a
        // per-site basis with no guarantee of coverage (dtk), so a MISSING
        // left-side relocation is "unverifiable", never evidence of a diff.
        (None, Some(_)) => return relax_reloc_diffs || name_check,
        (None, None) => return true,
        _ => return false,
    };
    if left_reloc.relocation.flags != right_reloc.relocation.flags {
        return false;
    }
    if relax_reloc_diffs {
        return true;
    }
    // NameCheck: a placeholder-named target (fn_8xxxxxxx / lbl_* / jumptable_* /
    // _bss_xxxxxxxx / ...) is a split symbol that was never identified — there
    // is no real name to verify our callee/data target against, so the site is
    // unverifiable. Likewise MSVC `$`-labels, whose numeric suffixes are
    // nondeterministic across compilations. Only a REAL left-side name that
    // disagrees with ours is charged.
    if name_check
        && (is_placeholder_symbol_name(&left_reloc.symbol.name)
            || is_compiler_local_label(&left_reloc.symbol.name))
    {
        return true;
    }

    // NameCheck: INTERIOR SELF-REFERENCE (MSVC-PPC switch dispatch base).
    //
    // See `interior_self_reference` for the dialect fact and the evidence.
    if name_check && interior_self_reference(left_ins, right_ins, &left_reloc, &right_reloc) {
        return true;
    }

    // NameCheck: COUNTER-SUFFIXED LITERAL, verified by CONTENT.
    //
    // mwcc numbers `__FUNCTION__$<n>` and its anonymous literal pool `@<n>` with
    // a per-TU counter, so the names disagree whenever anything earlier in the
    // file moved -- on rb3 that alone accounted for 2,279 of 2,518 exposed
    // functions. The name is unusable, but the DATA is right there, so compare
    // that instead. Absent data on either side is not evidence and is charged.
    if name_check && counter_named_data_eq(left_obj, right_obj, &left_reloc, &right_reloc) {
        return true;
    }

    // NameCheck: SECTION/POOL ANCHOR, resolved through the addend.
    //
    // mwcc small-data addressing relocates against a zero-sized section anchor
    // (`...data.0`, `...bss.0`; a dtk-split object spells them `_f_data`) and
    // reaches the datum with an addend. Comparing anchor spellings measures
    // nothing, and simply forgiving them would leave the site unchecked, so
    // resolve each anchor to the sized symbol its addend lands in and compare
    // THOSE. An anchor whose addend lands in no sized symbol is unverifiable.
    let left_anchor =
        if name_check { resolve_pool_anchor(left_obj, &left_reloc) } else { PoolAnchor::No };
    let right_anchor =
        if name_check { resolve_pool_anchor(right_obj, &right_reloc) } else { PoolAnchor::No };
    match (&left_anchor, &right_anchor) {
        (PoolAnchor::No, PoolAnchor::No) => {}
        (PoolAnchor::Unresolved, _) | (_, PoolAnchor::Unresolved) => return true,
        _ => {
            let (left_name, left_index) = match left_anchor {
                PoolAnchor::Resolved(name, index) => (name, index),
                _ => (
                    left_reloc.symbol.name.as_str(),
                    left_reloc.relocation.target_symbol,
                ),
            };
            let (right_name, right_index) = match right_anchor {
                PoolAnchor::Resolved(name, index) => (name, index),
                _ => (
                    right_reloc.symbol.name.as_str(),
                    right_reloc.relocation.target_symbol,
                ),
            };
            if left_name == right_name {
                return true;
            }
            // NameCheck: MIXED counter/anchor, verified by CONTENT.
            //
            // One side names the datum with its per-TU counter, the other
            // reaches the very same datum through the section anchor. Both
            // names are now counters (the anchor has been resolved above), so
            // neither carries identity and the bytes answer the question.
            if counter_named_referents_eq(left_obj, right_obj, left_index, right_index) {
                return true;
            }
            #[cfg(feature = "std")]
            if symbol_equivalences.get(left_name).is_some_and(|g| g.contains(right_name))
                || symbol_equivalences.get(right_name).is_some_and(|g| g.contains(left_name))
            {
                return true;
            }
            return false;
        }
    }

    // NameCheck: COFF WEAK-EXTERNAL ALIAS.
    //
    // A weak external is a linkage directive, not a definition. If one side's
    // relocation names an UNDEFINED weak external whose auxiliary record defaults
    // to the *other* side's symbol, then both references link to the same code and
    // charging the name difference is spurious. MSVC's vector deleting destructor
    // is the systematic case: `??_E<C>` is an undefined weak external defaulting to
    // `??_G<C>`, so our `bl ??_E<C>` and retail's `bl ??_G<C>` reach one body.
    //
    // The gate lives in the reader: `Object::weak_external_defaults` only contains
    // symbols that are UNDEFINED weak externals in that object
    // (`ImageSymbol::has_aux_weak_external()`), so where a definition exists the
    // pair is NOT forgiven -- it stays a charge, because a defined `??_E<C>` binds
    // to itself and the call does not reach `??_G<C>`. Measured on rb3-xenon: 1,158
    // `??_E` are defined by our own objects and are correctly excluded.
    //
    // Checked in both directions purely so the rule cannot silently depend on which
    // object is "target" and which is "base". Each direction is independently gated
    // by that side's own symbol table, so the symmetry adds no forgiveness that the
    // COFF data does not license. (In practice only the base side fires: dtk-split
    // target objects contain no weak externals.)
    if name_check
        && (weak_external_aliases(right_obj, &right_reloc.symbol.name, &left_reloc.symbol.name)
            || weak_external_aliases(
                left_obj,
                &left_reloc.symbol.name,
                &right_reloc.symbol.name,
            ))
    {
        return true;
    }

    let names_match = left_reloc.symbol.name == right_reloc.symbol.name || {
        #[cfg(feature = "std")]
        {
            symbol_equivalences
                .get(&left_reloc.symbol.name)
                .is_some_and(|group| group.contains(&right_reloc.symbol.name))
                || symbol_equivalences
                    .get(&right_reloc.symbol.name)
                    .is_some_and(|group| group.contains(&left_reloc.symbol.name))
        }
        #[cfg(not(feature = "std"))]
        false
    } || {
        // Template array-size equivalence: instantiations differing only in
        // array sizes produce identical code (arrays decay to pointers).
        normalize_mangled_array_sizes(&left_reloc.symbol.name)
            .zip(normalize_mangled_array_sizes(&right_reloc.symbol.name))
            .is_some_and(|(l, r)| l == r)
    };
    let symbol_name_addend_matches =
        names_match && left_reloc.relocation.addend == right_reloc.relocation.addend;
    // NameOnly: target symbol name (+ section) must match, but the addend is ignored.
    // This is the strict wrong-call-target / wrong-data-symbol check WITHOUT penalizing
    // benign build-address (addend) differences, which NameAddress couples in.
    let name_only = matches!(
        diff_config.function_reloc_diffs,
        FunctionRelocDiffs::NameOnly | FunctionRelocDiffs::NameCheck
    );
    match (&left_reloc.symbol.section, &right_reloc.symbol.section) {
        (Some(sl), Some(sr)) => {
            if name_only {
                // NameOnly is address-agnostic: it keys purely on the target SYMBOL
                // NAME (`names_match`, exact or equivalence-mapped). The section check
                // only guards against a name coincidence across genuinely different
                // logical sections (e.g. code vs data). It must therefore be tolerant
                // of the COMDAT grouping suffix: MSVC parks a DEFINED COMDAT symbol
                // (template instantiation, inline fn) into a `$`-suffixed bucket
                // (`.text$dup`, `.text$mn`, …) chosen at compile/link time, so the
                // very same symbol lands in `.text` in one object and `.text$dup` in
                // another. That suffix is a build artifact, not a semantic property of
                // the callee — see LightPreset::FillSpotPresetData, where the fixed and
                // target objects both call `ObjRefConcrete<RndDrawable>::SetObjConcrete`
                // but the target parked its definition in `.text$dup`. Strict name
                // equality wrongly rejected the match and left the fix unmeasurable.
                return section_name_eq_comdat(left_obj, right_obj, *sl, *sr) && names_match;
            }
            // Match if section and name or address match
            section_name_eq(left_obj, right_obj, *sl, *sr)
                && (diff_config.function_reloc_diffs == FunctionRelocDiffs::DataValue
                    || symbol_name_addend_matches
                    || address_eq(left_reloc, right_reloc))
                && (diff_config.function_reloc_diffs == FunctionRelocDiffs::NameAddress
                    || left_reloc.symbol.kind != SymbolKind::Object
                    || right_reloc.symbol.size == 0 // Likely a pool symbol like ...data, don't treat this as a diff
                    || ins_data_literals_eq(left_obj, right_obj, left_ins, right_ins, diff_config))
        }
        (Some(_), None) | (None, Some(_)) | (None, None) => {
            // No section on one/both sides (e.g. external symbols): match on name alone
            // when NameOnly, otherwise require name + addend.
            if name_only { names_match } else { symbol_name_addend_matches }
        }
    }
}

fn arg_eq(
    left_obj: &Object,
    right_obj: &Object,
    left_row: &InstructionDiffRow,
    right_row: &InstructionDiffRow,
    left_arg: &InstructionArg,
    right_arg: &InstructionArg,
    left_ins: ResolvedInstructionRef,
    right_ins: ResolvedInstructionRef,
    diff_config: &DiffObjConfig,
    #[cfg(feature = "std")] symbol_equivalences: &std::collections::HashMap<
        alloc::string::String,
        std::collections::HashSet<alloc::string::String>,
    >,
) -> bool {
    match left_arg {
        InstructionArg::Value(l) => match right_arg {
            InstructionArg::Value(r) => l.loose_eq(r),
            // If relocations are relaxed, match if left is a constant and right is a reloc
            // Useful for instances where the target object is created without relocations
            //
            // NameCheck: the same rule `reloc_eq` already applies to a missing
            // left-side relocation, reached by a different path. A dtk-split
            // target object relocates on a per-site basis with no guarantee of
            // coverage; where it failed to attribute an address it leaves the
            // computed constant in the operand (`lis r0, 0x80d1`), so the arch
            // types the operand as a Value and never reaches `reloc_eq`. There
            // is no target-side NAME, so the wrong-symbol check NameCheck exists
            // to perform is vacuous, and charging the site measures dtk's
            // coverage rather than our source. `name_address` still charges it.
            InstructionArg::Reloc => matches!(
                diff_config.function_reloc_diffs,
                FunctionRelocDiffs::None | FunctionRelocDiffs::NameCheck
            ),
            _ => false,
        },
        InstructionArg::Reloc => {
            matches!(right_arg, InstructionArg::Reloc)
                && reloc_eq(
                    left_obj,
                    right_obj,
                    left_ins,
                    right_ins,
                    diff_config,
                    #[cfg(feature = "std")]
                    symbol_equivalences,
                )
        }
        InstructionArg::BranchDest(_) => match right_arg {
            // Compare dest instruction idx after diffing
            InstructionArg::BranchDest(_) => {
                left_row.branch_to.as_ref().map(|b| b.ins_idx)
                    == right_row.branch_to.as_ref().map(|b| b.ins_idx)
            }
            // If relocations are relaxed, match if left is a constant and right is a reloc
            // Useful for instances where the target object is created without relocations
            InstructionArg::Reloc => diff_config.function_reloc_diffs == FunctionRelocDiffs::None,
            _ => false,
        },
    }
}

#[derive(Default)]
struct InstructionDiffState {
    diff_score: u64,
    /// Diff score from argument-only mismatches (same opcode, different args).
    /// Subtracting this from diff_score gives the "normalized" score that
    /// ignores register swaps, offset swaps, and other arg-level noise.
    arg_diff_score: u64,
    left_arg_idx: u32,
    right_arg_idx: u32,
    left_args_idx: BTreeMap<String, u32>,
    right_args_idx: BTreeMap<String, u32>,
}

#[derive(Default)]
struct InstructionDiffResult {
    kind: InstructionDiffKind,
    left_args_diff: Vec<InstructionArgDiffIndex>,
    right_args_diff: Vec<InstructionArgDiffIndex>,
    /// This row was scored `equal` (kind == None) but a relocation-target
    /// difference was smoothed over by `function_reloc_diffs` (None relaxation
    /// or NameOnly addend-ignoring). Disclosure only — the score is unchanged.
    masked_reloc: bool,
}

impl InstructionDiffResult {
    #[inline]
    const fn new(kind: InstructionDiffKind) -> Self {
        Self {
            kind,
            left_args_diff: Vec::new(),
            right_args_diff: Vec::new(),
            masked_reloc: false,
        }
    }
}

/// Byte-strict relocation identity for a paired instruction: the relocations
/// are equal WITHOUT any normalization (same presence, flags, target-symbol
/// name, and addend). Used only to detect masked equality — when `reloc_eq`
/// (which applies the configured relaxations, name equivalences, template
/// array-size normalization, pool address_eq, …) accepts a pair that is NOT
/// strictly equal, the row's equality relied on a normalization and is
/// disclosed as `masked`. Intentionally strict: it is an upper-bound
/// disclosure signal, never a score input.
fn relocs_strictly_equal(
    left_ins: ResolvedInstructionRef,
    right_ins: ResolvedInstructionRef,
) -> bool {
    match (left_ins.relocation, right_ins.relocation) {
        (None, None) => true,
        (Some(l), Some(r)) => {
            l.relocation.flags == r.relocation.flags
                && l.relocation.addend == r.relocation.addend
                && l.symbol.name == r.symbol.name
        }
        _ => false,
    }
}

fn diff_instruction(
    left_obj: &Object,
    right_obj: &Object,
    left_symbol_idx: usize,
    right_symbol_idx: usize,
    l: Option<InstructionRef>,
    r: Option<InstructionRef>,
    left_row: &InstructionDiffRow,
    right_row: &InstructionDiffRow,
    diff_config: &DiffObjConfig,
    state: &mut InstructionDiffState,
    #[cfg(feature = "std")] symbol_equivalences: &std::collections::HashMap<
        alloc::string::String,
        std::collections::HashSet<alloc::string::String>,
    >,
) -> Result<InstructionDiffResult> {
    let (l, r) = match (l, r) {
        (Some(l), Some(r)) => (l, r),
        (Some(_), None) => {
            state.diff_score += PENALTY_INSERT_DELETE;
            return Ok(InstructionDiffResult::new(InstructionDiffKind::Delete));
        }
        (None, Some(_)) => {
            state.diff_score += PENALTY_INSERT_DELETE;
            return Ok(InstructionDiffResult::new(InstructionDiffKind::Insert));
        }
        (None, None) => return Ok(InstructionDiffResult::new(InstructionDiffKind::None)),
    };

    // If opcodes don't match, replace
    if l.opcode != r.opcode {
        state.diff_score += PENALTY_REPLACE;
        return Ok(InstructionDiffResult::new(InstructionDiffKind::Replace));
    }

    let left_resolved = left_obj
        .resolve_instruction_ref(left_symbol_idx, l)
        .context("Failed to resolve left instruction")?;
    let right_resolved = right_obj
        .resolve_instruction_ref(right_symbol_idx, r)
        .context("Failed to resolve right instruction")?;

    if left_resolved.code != right_resolved.code
        || !reloc_eq(
            left_obj,
            right_obj,
            left_resolved,
            right_resolved,
            diff_config,
            #[cfg(feature = "std")]
            symbol_equivalences,
        )
    {
        // If either the raw code bytes or relocations don't match, process instructions and compare args
        let left_ins = left_obj.arch.process_instruction(left_resolved, diff_config)?;
        let right_ins = right_obj.arch.process_instruction(right_resolved, diff_config)?;
        if left_ins.args.len() != right_ins.args.len() {
            state.diff_score += PENALTY_REPLACE;
            return Ok(InstructionDiffResult::new(InstructionDiffKind::Replace));
        }
        let mut result = InstructionDiffResult::new(InstructionDiffKind::None);
        if left_ins.mnemonic != right_ins.mnemonic {
            state.diff_score += PENALTY_REG_DIFF;
            result.kind = InstructionDiffKind::OpMismatch;
        }
        for (a, b) in left_ins.args.iter().zip(right_ins.args.iter()) {
            if arg_eq(
                left_obj,
                right_obj,
                left_row,
                right_row,
                a,
                b,
                left_resolved,
                right_resolved,
                diff_config,
                #[cfg(feature = "std")]
                symbol_equivalences,
            ) {
                result.left_args_diff.push(InstructionArgDiffIndex::NONE);
                result.right_args_diff.push(InstructionArgDiffIndex::NONE);
            } else {
                let is_immediate = matches!(
                    a,
                    InstructionArg::Value(
                        InstructionArgValue::Signed(_) | InstructionArgValue::Unsigned(_),
                    )
                );
                let penalty =
                    if is_immediate { PENALTY_IMM_DIFF } else { PENALTY_REG_DIFF };
                state.diff_score += penalty;
                // Immediates (constants, memory offsets, vtable slots) represent
                // real semantic differences — they survive into a native port,
                // so they must count toward the normalized score. Only register
                // permutation, branch destinations, and relocations are folded
                // into `arg_diff_score` and thus normalized away: the host
                // compiler reallocates registers, branch offsets are relative
                // layout, and reloc diffs are dominated by benign noise (pool
                // addend, `_savegpr_N`, outline helpers, `__vt__` literal vs
                // reloc construction). The audit at
                // scripts/analysis/audit_normalized_masking.py (rb3-decomp)
                // showed every in-scope masked bug — wrong vtable slot, wrong
                // struct size, wrong member offset, wrong constant — was an
                // immediate diff; reloc diffs were dominated by benign cases.
                if !is_immediate {
                    state.arg_diff_score += penalty;
                }
                if result.kind == InstructionDiffKind::None {
                    result.kind = InstructionDiffKind::ArgMismatch;
                }
                let a_str = arg_to_string(a, left_resolved.relocation);
                let a_diff = match state.left_args_idx.entry(a_str) {
                    btree_map::Entry::Vacant(e) => {
                        let idx = state.left_arg_idx;
                        state.left_arg_idx = idx + 1;
                        e.insert(idx);
                        idx
                    }
                    btree_map::Entry::Occupied(e) => *e.get(),
                };
                let b_str = arg_to_string(b, right_resolved.relocation);
                let b_diff = match state.right_args_idx.entry(b_str) {
                    btree_map::Entry::Vacant(e) => {
                        let idx = state.right_arg_idx;
                        state.right_arg_idx = idx + 1;
                        e.insert(idx);
                        idx
                    }
                    btree_map::Entry::Occupied(e) => *e.get(),
                };
                result.left_args_diff.push(InstructionArgDiffIndex::new(a_diff));
                result.right_args_diff.push(InstructionArgDiffIndex::new(b_diff));
            }
        }
        if result.kind == InstructionDiffKind::None
            && left_resolved.code.len() != right_resolved.code.len()
        {
            // If everything else matches but the raw code length differs (e.g. x86 instructions
            // with same disassembly but different encoding), mark as op mismatch
            result.kind = InstructionDiffKind::OpMismatch;
            state.diff_score += PENALTY_REG_DIFF;
        }
        // Disclosure: the row was scored equal (all args accepted, same
        // mnemonic) but a relocation difference was smoothed over by the
        // configured reloc relaxation. Flag it — the score is untouched.
        if result.kind == InstructionDiffKind::None
            && !relocs_strictly_equal(left_resolved, right_resolved)
        {
            result.masked_reloc = true;
        }
        return Ok(result);
    }

    // Reached only when the raw code bytes AND `reloc_eq` both matched. If the
    // relocations were not byte-strictly equal, equality relied on a reloc-mode
    // normalization (e.g. `bl` to a different callee under `None`): disclose it.
    let mut result = InstructionDiffResult::new(InstructionDiffKind::None);
    result.masked_reloc = !relocs_strictly_equal(left_resolved, right_resolved);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_makestring_equivalence() {
        let a = "??$MakeString@$$BY07$$CBDH$$BY0CD@$$CBD@@YAPBDPBDAAY07$$CBDABHAAY0CD@$$CBD@Z";
        let b = "??$MakeString@$$BY0N@$$CBDH$$BY0CG@$$CBD@@YAPBDPBDAAY0N@$$CBDABHAAY0CG@$$CBD@Z";
        let na = normalize_mangled_array_sizes(a);
        let nb = normalize_mangled_array_sizes(b);
        assert!(na.is_some());
        assert!(nb.is_some());
        assert_eq!(na, nb);
    }

    #[test]
    fn test_normalize_non_template() {
        assert!(normalize_mangled_array_sizes("?Foo@@YAXXZ").is_none());
    }

    #[test]
    fn test_normalize_different_types() {
        // char[8],int,char[35] vs char*,float,char[35] — different non-array types
        let a = "??$MakeString@$$BY07$$CBDH$$BY0CD@$$CBD@@YA";
        let b = "??$MakeString@PBDM$$BY0CD@$$CBD@@YA";
        let na = normalize_mangled_array_sizes(a);
        let nb = normalize_mangled_array_sizes(b);
        // b has no $$BY0 for the first param, so different skeleton
        assert_ne!(na, nb);
    }

    #[test]
    fn test_normalize_same_sizes_unchanged() {
        let a = "??$MakeString@$$BY07$$CBDH$$BY0CD@$$CBD@@YAPBDZ";
        let na = normalize_mangled_array_sizes(a).unwrap();
        let nb = normalize_mangled_array_sizes(a).unwrap();
        assert_eq!(na, nb);
    }

    #[test]
    fn test_normalize_no_array_in_template() {
        // Template but no array params
        assert!(normalize_mangled_array_sizes("??$Foo@HH@@YAXXZ").is_none());
    }

    // ---- FP-anchor hairline-slip normalization helpers ----
    // (the classifiers are std-gated, matching the detector that uses them)

    #[cfg(feature = "std")]
    use alloc::borrow::Cow;

    #[cfg(feature = "std")]
    fn reg(name: &str) -> InstructionArg<'static> {
        InstructionArg::Value(InstructionArgValue::Opaque(Cow::Owned(name.to_string())))
    }
    #[cfg(feature = "std")]
    fn imm(v: i64) -> InstructionArg<'static> {
        InstructionArg::Value(InstructionArgValue::Signed(v))
    }
    #[cfg(feature = "std")]
    fn pins(mnemonic: &str, args: Vec<InstructionArg<'static>>) -> ParsedInstruction {
        ParsedInstruction {
            ins_ref: InstructionRef::default(),
            mnemonic: Cow::Owned(mnemonic.to_string()),
            args,
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_classify_fp_anchor_subi() {
        // subi r31, r12, 0x80  =>  r31 = r12 - 0x80
        let ins = pins("subi", vec![reg("r31"), reg("r12"), imm(0x80)]);
        let a = classify_fp_anchor(&ins).expect("subi r31,r12,K is an anchor");
        assert_eq!(a.dst, "r31");
        assert_eq!(a.effective_base, -0x80);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_classify_fp_anchor_addi() {
        // addi r31, r12, 0x10  =>  r31 = r12 + 0x10
        let ins = pins("addi", vec![reg("r31"), reg("r12"), imm(0x10)]);
        let a = classify_fp_anchor(&ins).expect("addi r31,r12,K is an anchor");
        assert_eq!(a.effective_base, 0x10);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_classify_fp_anchor_rejects_non_r12_source() {
        // addi r31, r1, 0x80 is a stack-frame addressing op, NOT the FP idiom.
        assert!(classify_fp_anchor(&pins("addi", vec![reg("r31"), reg("r1"), imm(0x80)])).is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_classify_fp_anchor_rejects_volatile_dst() {
        // addi r3, r12, K targets a volatile register; not a frame anchor.
        assert!(classify_fp_anchor(&pins("addi", vec![reg("r3"), reg("r12"), imm(0x10)])).is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_classify_anchor_mem_load() {
        // lwz r11, 0x94(r31)
        let ins = pins("lwz", vec![reg("r11"), imm(0x94), reg("r31")]);
        let m = classify_anchor_mem(&ins).expect("offset load");
        assert_eq!(m.base, "r31");
        assert_eq!(m.off, 0x94);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_classify_anchor_mem_rejects_addi() {
        // addi r3, r31, 0x78 is [reg, reg, imm], not an offset access; must not
        // be treated as a compensable load. (This guards AsyncFile/fn_8251A200,
        // a real-diff function whose anchor slip is NOT compensated.)
        assert!(classify_anchor_mem(&pins("addi", vec![reg("r3"), reg("r31"), imm(0x78)])).is_none());
    }

    #[test]
    fn test_compensation_invariant_holds() {
        // The semantic core: subi 0x80/0x90 with lwz 0x94/0xa4 compensates.
        // effective address = effective_base + off, must be equal on both sides.
        let l_eff = -0x80i64; // subi r31,r12,0x80
        let r_eff = -0x90i64; // subi r31,r12,0x90
        let l_off = 0x94i64; // lwz r11,0x94(r31)
        let r_off = 0xa4i64; // lwz r11,0xa4(r31)
        assert_eq!(l_eff + l_off, r_eff + r_off); // 0x14 == 0x14
    }

    #[test]
    fn test_compensation_invariant_rejects_uncompensated() {
        // Cluster-B real diff: subi 0x80/0x70 with lwz 0x50/0x84 does NOT
        // compensate (eff -0x30 vs +0x14) and must remain a scored difference.
        let l_eff = -0x80i64;
        let r_eff = -0x70i64;
        let l_off = 0x50i64;
        let r_off = 0x84i64;
        assert_ne!(l_eff + l_off, r_eff + r_off); // -0x30 != 0x14
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_is_nonvolatile_gpr() {
        assert!(is_nonvolatile_gpr("r31"));
        assert!(is_nonvolatile_gpr("r14"));
        assert!(!is_nonvolatile_gpr("r13")); // r13 is the small-data anchor / volatile boundary
        assert!(!is_nonvolatile_gpr("r3"));
        assert!(!is_nonvolatile_gpr("r12"));
        assert!(!is_nonvolatile_gpr("f31"));
        assert!(!is_nonvolatile_gpr("lr"));
    }

    // ---- FunctionRelocDiffs::NameOnly semantics ----
    // Strict callee/data-target check (name + section must match) that IGNORES the
    // relocation addend, the one mode the lenient report pipeline lacked. These tests
    // pin the truth table directly on reloc_eq so they cannot drift with fixtures.

    #[cfg(feature = "std")]
    use crate::obj::{
        Relocation, RelocationFlags, Section, SectionData, SectionKind, Symbol,
    };

    /// Build a one-section object whose single instruction at `address` carries a
    /// relocation referencing a symbol named `target_name` (in section "text") with
    /// the given addend. The caller-symbol is index 0, the target-symbol is index 1.
    #[cfg(feature = "std")]
    fn obj_with_reloc(target_name: &str, addend: i64) -> Object {
        let mut obj = Object::default();
        // section 0: "text" holding 4 bytes of code at address 0
        let section = Section {
            id: "text".to_string(),
            name: "text".to_string(),
            address: 0,
            size: 4,
            kind: SectionKind::Code,
            data: SectionData(vec![0u8; 4]),
            relocations: vec![Relocation {
                flags: RelocationFlags::Coff(1),
                address: 0,
                target_symbol: 1,
                addend,
            }],
            ..Default::default()
        };
        obj.sections.push(section);
        // symbol 0: the caller function spanning the section
        obj.symbols.push(Symbol {
            name: "caller".to_string(),
            address: 0,
            size: 4,
            kind: SymbolKind::Function,
            section: Some(0),
            ..Default::default()
        });
        // symbol 1: the relocation target (a function in section "text")
        obj.symbols.push(Symbol {
            name: target_name.to_string(),
            address: 0,
            size: 0,
            kind: SymbolKind::Function,
            section: Some(0),
            ..Default::default()
        });
        obj
    }

    /// Like `obj_with_reloc`, but the reloc TARGET symbol is a DEFINED symbol that
    /// lives in its own section named `target_section` (e.g. `.text` vs `.text$dup`).
    /// Models an in-object COMDAT template instantiation, whose section the compiler
    /// may park in any COMDAT bucket of the logical section.
    #[cfg(feature = "std")]
    fn obj_with_reloc_in_section(target_name: &str, addend: i64, target_section: &str) -> Object {
        let mut obj = Object::default();
        // section 0: "text" holding the caller's 4 bytes of code + the relocation.
        obj.sections.push(Section {
            id: "text".to_string(),
            name: "text".to_string(),
            address: 0,
            size: 4,
            kind: SectionKind::Code,
            data: SectionData(vec![0u8; 4]),
            relocations: vec![Relocation {
                flags: RelocationFlags::Coff(1),
                address: 0,
                target_symbol: 1,
                addend,
            }],
            ..Default::default()
        });
        // section 1: the COMDAT bucket the target definition lives in. The kind
        // follows the NAME, the way a real reader reports it, so a `.data`/`.bss`
        // section in a test is genuinely non-code and the code/data guard is
        // exercised rather than bypassed.
        obj.sections.push(Section {
            id: format!("{target_section}-0"),
            name: target_section.to_string(),
            address: 0,
            size: 4,
            kind: match section_base_name(target_section) {
                ".text" => SectionKind::Code,
                ".bss" => SectionKind::Bss,
                _ => SectionKind::Data,
            },
            data: SectionData(vec![0u8; 4]),
            ..Default::default()
        });
        // symbol 0: the caller function in section 0.
        obj.symbols.push(Symbol {
            name: "caller".to_string(),
            address: 0,
            size: 4,
            kind: SymbolKind::Function,
            section: Some(0),
            ..Default::default()
        });
        // symbol 1: the DEFINED relocation target, in its own COMDAT section.
        obj.symbols.push(Symbol {
            name: target_name.to_string(),
            address: 0,
            size: 4,
            kind: SymbolKind::Function,
            section: Some(1),
            ..Default::default()
        });
        obj
    }

    #[cfg(feature = "std")]
    fn resolved_ref(obj: &Object) -> ResolvedInstructionRef<'_> {
        let section = &obj.sections[0];
        let reloc = &section.relocations[0];
        ResolvedInstructionRef {
            ins_ref: InstructionRef { address: 0, size: 4, opcode: 0, branch_dest: None },
            symbol_index: 0,
            symbol: &obj.symbols[0],
            section_index: 0,
            section,
            code: &section.data.0,
            relocation: Some(ResolvedRelocation {
                relocation: reloc,
                symbol: &obj.symbols[reloc.target_symbol],
            }),
        }
    }

    #[cfg(feature = "std")]
    fn reloc_match(left: &Object, right: &Object, mode: FunctionRelocDiffs) -> bool {
        let cfg = DiffObjConfig { function_reloc_diffs: mode, ..Default::default() };
        reloc_eq(
            left,
            right,
            resolved_ref(left),
            resolved_ref(right),
            &cfg,
            &std::collections::HashMap::new(),
        )
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_only_forgives_addend() {
        // Same callee name, different addend (benign build-address noise).
        let left = obj_with_reloc("Callee", 0x100);
        let right = obj_with_reloc("Callee", 0x200);
        // NameOnly: addend ignored -> MATCH (the whole point of the mode).
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));
        // NameAddress: couples name+addend -> NO MATCH (over-penalizes benign addend).
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameAddress));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_only_catches_wrong_callee() {
        // Different callee name, same addend (a genuine wrong-call-target).
        let left = obj_with_reloc("RightCallee", 0x100);
        let right = obj_with_reloc("WrongCallee", 0x100);
        // NameOnly: names differ -> NO MATCH (catches the false-100%).
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));
        // None (the report.json/decomp.db mode): forgives ANY same-flags reloc -> MATCH
        // (this is exactly the uncounted false-100% surface NameOnly exists to expose).
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::None));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_only_exact_match() {
        // Identical name + identical addend matches under every mode.
        let left = obj_with_reloc("Callee", 0x100);
        let right = obj_with_reloc("Callee", 0x100);
        for mode in [
            FunctionRelocDiffs::None,
            FunctionRelocDiffs::NameOnly,
            FunctionRelocDiffs::NameAddress,
            FunctionRelocDiffs::DataValue,
            FunctionRelocDiffs::All,
        ] {
            assert!(reloc_match(&left, &right, mode), "exact match should hold for {mode:?}");
        }
    }

    // ---- Defined/COMDAT reloc targets (blind spot 3) ----
    // A relocation whose target is a DEFINED in-object symbol (typically a COMDAT
    // template instantiation) must be credited by NAME even when the compiler parked
    // its definition in a different COMDAT bucket of the same logical section
    // (`.text` vs `.text$dup`). The `$` suffix is a build artifact; the exact symbol
    // name is the identity. Fixture: LightPreset::FillSpotPresetData, where the fixed
    // and target objects both call `ObjRefConcrete<RndDrawable>::SetObjConcrete` but
    // the target defined it in `.text$dup`.

    #[cfg(feature = "std")]
    #[test]
    fn test_name_only_comdat_bucket_variant_matches() {
        // Same DEFINED callee, but parked in `.text$dup` (left) vs `.text` (right).
        let left = obj_with_reloc_in_section("Callee", 0x100, ".text$dup");
        let right = obj_with_reloc_in_section("Callee", 0x100, ".text");
        // NameOnly: base section name (`.text`) matches AND the symbol name matches
        // -> MATCH. Before the fix this was rejected (`.text$dup` != `.text`), which
        // is exactly blind spot 3.
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_only_comdat_bucket_variant_wrong_name_still_diffs() {
        // Two DIFFERENT template instantiations, each in its own COMDAT bucket.
        // The COMDAT-bucket tolerance must NOT let a genuine wrong-callee slip past:
        // the exact-name guard still rejects it.
        let left = obj_with_reloc_in_section("ObjRefConcrete_RndDrawable", 0x100, ".text$dup");
        let right = obj_with_reloc_in_section("ObjRefConcrete_RndTransformable", 0x100, ".text");
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_only_same_name_different_logical_section_diffs() {
        // Same symbol name but genuinely different LOGICAL sections (code vs data):
        // the base names (`.text` vs `.data`) differ, so NameOnly does NOT match.
        // This pins that the tolerance only spans COMDAT buckets, not section kinds.
        let left = obj_with_reloc_in_section("Callee", 0x100, ".text$dup");
        let right = obj_with_reloc_in_section("Callee", 0x100, ".data");
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));
    }

    // ---- FunctionRelocDiffs::NameCheck semantics ----
    // NameOnly with two tolerances for split/disassembled TARGET objects (dtk):
    // a missing left-side relocation and a placeholder-named left target are both
    // "unverifiable" (score equal); only a REAL left name that disagrees is charged.

    /// `resolved_ref` variant that strips the relocation (models a dtk split
    /// site where no relocation was emitted for the branch).
    #[cfg(feature = "std")]
    fn resolved_ref_no_reloc(obj: &Object) -> ResolvedInstructionRef<'_> {
        ResolvedInstructionRef { relocation: None, ..resolved_ref(obj) }
    }

    /// A caller in `.text` whose single relocation points at a DATA symbol named
    /// `target_name`, holding `data`, in a section of kind `kind`. `Bss` sections
    /// carry no bytes: the symbol's size comes from `data.len()` regardless, which
    /// is how a NOBITS datum is described.
    #[cfg(feature = "std")]
    fn obj_with_data_reloc(
        target_name: &str,
        data: &[u8],
        kind: SectionKind,
        addend: i64,
    ) -> Object {
        let mut obj = Object::default();
        obj.sections.push(Section {
            id: "text".to_string(),
            name: ".text".to_string(),
            address: 0,
            size: 4,
            kind: SectionKind::Code,
            data: SectionData(vec![0u8; 4]),
            relocations: vec![Relocation {
                flags: RelocationFlags::Coff(1),
                address: 0,
                target_symbol: 1,
                addend,
            }],
            ..Default::default()
        });
        obj.sections.push(Section {
            id: "data-0".to_string(),
            name: if kind == SectionKind::Bss { ".bss" } else { ".data" }.to_string(),
            address: 0,
            size: data.len() as u64,
            kind,
            data: SectionData(if kind == SectionKind::Bss { Vec::new() } else { data.to_vec() }),
            ..Default::default()
        });
        obj.symbols.push(Symbol {
            name: "caller".to_string(),
            address: 0,
            size: 4,
            kind: SymbolKind::Function,
            section: Some(0),
            ..Default::default()
        });
        obj.symbols.push(Symbol {
            name: target_name.to_string(),
            address: 0,
            size: data.len() as u64,
            kind: SymbolKind::Object,
            section: Some(1),
            ..Default::default()
        });
        obj
    }

    /// A caller whose relocation points at a zero-sized section ANCHOR named
    /// `anchor` with `addend`, in a `.data` section that also defines `datum` at
    /// offset `datum_at` with `datum_size` bytes.
    #[cfg(feature = "std")]
    fn obj_with_pool_anchor(
        anchor: &str,
        addend: i64,
        datum: &str,
        datum_at: u64,
        datum_size: u64,
    ) -> Object {
        let mut obj = Object::default();
        obj.sections.push(Section {
            id: "text".to_string(),
            name: ".text".to_string(),
            address: 0,
            size: 4,
            kind: SectionKind::Code,
            data: SectionData(vec![0u8; 4]),
            relocations: vec![Relocation {
                flags: RelocationFlags::Coff(1),
                address: 0,
                target_symbol: 1,
                addend,
            }],
            ..Default::default()
        });
        obj.sections.push(Section {
            id: "data-0".to_string(),
            name: ".data".to_string(),
            address: 0,
            size: 0x100,
            kind: SectionKind::Data,
            data: SectionData(vec![0u8; 0x100]),
            ..Default::default()
        });
        obj.symbols.push(Symbol {
            name: "caller".to_string(),
            address: 0,
            size: 4,
            kind: SymbolKind::Function,
            section: Some(0),
            ..Default::default()
        });
        // symbol 1: the zero-sized anchor at the start of the data section.
        obj.symbols.push(Symbol {
            name: anchor.to_string(),
            address: 0,
            size: 0,
            kind: SymbolKind::Unknown,
            section: Some(1),
            ..Default::default()
        });
        obj.symbols.push(Symbol {
            name: datum.to_string(),
            address: datum_at,
            size: datum_size,
            kind: SymbolKind::Object,
            section: Some(1),
            ..Default::default()
        });
        obj
    }

    #[test]
    fn test_is_counter_suffixed_name() {
        assert!(is_counter_suffixed_name("__FUNCTION__$14031"));
        assert!(is_counter_suffixed_name("__PRETTY_FUNCTION__$27320"));
        assert!(is_counter_suffixed_name("s_seed$34"));
        assert!(is_counter_suffixed_name("@23858"));
        // Not counters: a bare `$`-label (owned by is_compiler_local_label), an
        // `@`-prefixed name that is not all digits, a name with no suffix, and
        // MSVC mangling, which is full of `$` but never ends in `$<digits>`.
        assert!(!is_counter_suffixed_name("$L18077"));
        assert!(!is_counter_suffixed_name("@LOCAL@random__Fl@s_seed"));
        assert!(!is_counter_suffixed_name("gConsole"));
        assert!(!is_counter_suffixed_name("?$S3@?4??FixClassName@DirLoader@@AAA@Z"));
        assert!(!is_counter_suffixed_name("??_C@_06PFFNFMJI@XDEMOS?$AA@"));
        assert!(!is_counter_suffixed_name("name$"));
        assert!(!is_counter_suffixed_name("$12"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_counter_named_literal_compares_content() {
        // Same string, renumbered by the per-TU counter: MATCH on content.
        let left = obj_with_data_reloc("__FUNCTION__$14031", b"_M_inc\0", SectionKind::Data, 0);
        let right = obj_with_data_reloc("__FUNCTION__$43813", b"_M_inc\0", SectionKind::Data, 0);
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        // NameOnly has no content check, so it still charges the renumbering.
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));

        // DIFFERENT strings behind counter names stay a mismatch. This is the
        // half that makes the tolerance a check rather than a blanket pass.
        let right = obj_with_data_reloc("__FUNCTION__$43813", b"_M_dec\0", SectionKind::Data, 0);
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_counter_named_bss_compares_size() {
        // `.bss` stores no bytes, so equal-sized zeroed data is equal data...
        let left = obj_with_data_reloc("@5042", &[0u8; 12], SectionKind::Bss, 0);
        let right = obj_with_data_reloc("@2566", &[0u8; 12], SectionKind::Bss, 0);
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        // ...and a differently-sized datum is not.
        let right = obj_with_data_reloc("@2566", &[0u8; 8], SectionKind::Bss, 0);
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        // One side stores its zeros and the other does not: same value.
        let right = obj_with_data_reloc("@2566", &[0u8; 12], SectionKind::Data, 0);
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_pool_anchor_resolves_through_addend() {
        // Our side reaches `sChinNum` through the section anchor `...bss.0` + 0x20;
        // the target names it outright. Same datum.
        let left = obj_with_reloc("sChinNum", 0);
        let right = obj_with_pool_anchor("...data.0", 0x20, "sChinNum", 0x20, 4);
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));

        // A DIFFERENT datum at that offset is still charged: resolving the anchor
        // restores the check, it does not remove it.
        let right = obj_with_pool_anchor("...data.0", 0x20, "sOtherThing", 0x20, 4);
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    /// Write `bytes` at `at` into the data section of an object built by
    /// `obj_with_pool_anchor`, so a content comparison has something to
    /// disagree about (the helper's section is otherwise all zeros).
    #[cfg(feature = "std")]
    fn write_datum(obj: &mut Object, at: u64, bytes: &[u8]) {
        let data = &mut obj.sections[1].data.0;
        data[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_mixed_counter_and_anchor_compares_content() {
        // The MIXED shape: a datum at offset 0 of `.data`/`.bss` carries BOTH a
        // counter name and the section anchor, and the two producers disagree
        // about which to relocate against. Retail names `@145`, we name
        // `...data.0` + addend. 146 charges over 72 functions on rb3.
        let left = obj_with_data_reloc("@145", b"json\0", SectionKind::Data, 0);
        let mut right = obj_with_pool_anchor("...data.0", 0x20, "@375", 0x20, 5);
        write_datum(&mut right, 0x20, b"json\0");
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        // Symmetric: the anchor may be on either side.
        assert!(reloc_match(&right, &left, FunctionRelocDiffs::NameCheck));
        // NameOnly has no content check, so it still charges the pair.
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));

        // DIFFERENT content behind the two counters is still charged: resolving
        // the anchor restores the check, it does not remove it.
        let mut right = obj_with_pool_anchor("...data.0", 0x20, "@375", 0x20, 5);
        write_datum(&mut right, 0x20, b"xml\0\0");
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));

        // The anchor resolving to a REAL name is not a counter pair at all, so
        // the name check stands and the disagreement is charged.
        let right = obj_with_pool_anchor("...data.0", 0x20, "json_null_str", 0x20, 5);
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_mixed_counter_never_crosses_code_and_data() {
        // A counter-named FUNCTION against a counter-named DATUM whose bytes
        // happen to agree (both four zero bytes). Content equality must not be
        // allowed to credit a call against a data reference: the code/data
        // guard outranks it.
        let left = obj_with_reloc_in_section("@13392", 0, ".text");
        let right = obj_with_pool_anchor("...data.0", 0x20, "@375", 0x20, 4);
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        assert!(!reloc_match(&right, &left, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_unresolvable_pool_anchor_is_unverifiable() {
        // The addend lands in no sized symbol -- e.g. a pointer walked past the
        // end of a literal. Nothing to compare, so nothing is charged.
        let left = obj_with_reloc("sChinNum", 0);
        let right = obj_with_pool_anchor("...data.0", 0x80, "sChinNum", 0x20, 4);
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_forgives_missing_target_reloc() {
        let left = obj_with_reloc("Callee", 0x100);
        let right = obj_with_reloc("Callee", 0x100);
        let cfg_check = DiffObjConfig {
            function_reloc_diffs: FunctionRelocDiffs::NameCheck,
            ..Default::default()
        };
        let cfg_name_only = DiffObjConfig {
            function_reloc_diffs: FunctionRelocDiffs::NameOnly,
            ..Default::default()
        };
        let eq = std::collections::HashMap::new();
        // Left (target) side has NO relocation, right (base) does: unverifiable
        // under NameCheck -> MATCH; NameOnly treats it as a diff (the reason
        // NameOnly alone is not deployable against dtk-split targets).
        assert!(reloc_eq(
            &left,
            &right,
            resolved_ref_no_reloc(&left),
            resolved_ref(&right),
            &cfg_check,
            &eq
        ));
        assert!(!reloc_eq(
            &left,
            &right,
            resolved_ref_no_reloc(&left),
            resolved_ref(&right),
            &cfg_name_only,
            &eq
        ));
        // The REVERSE (target relocated, base not) stays a mismatch under NameCheck.
        assert!(!reloc_eq(
            &left,
            &right,
            resolved_ref(&left),
            resolved_ref_no_reloc(&right),
            &cfg_check,
            &eq
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_forgives_placeholder_target_name() {
        // Target callee was never identified by the splitter: placeholder name.
        let left = obj_with_reloc("fn_82345678", 0x100);
        let right = obj_with_reloc("?Poll@CharServoBone@@UAAXXZ", 0x100);
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        // NameOnly would charge it — placeholder tolerance is NameCheck-specific.
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));
    }

    /// A function `fn_name` of `fn_size` bytes at address 0 of section "text",
    /// with one relocation at address 0 pointing at `target_name`, a symbol
    /// placed at `target_at` in section index `target_section`.
    ///
    /// Models both halves of the MSVC-PPC switch-dispatch site: the dtk target
    /// (`target_name == fn_name`, `target_at == 0`) and ours (`target_name`
    /// a `$`-label at an interior address).
    #[cfg(feature = "std")]
    fn obj_with_interior_ref(
        fn_name: &str,
        fn_size: u64,
        target_name: &str,
        target_at: u64,
        target_section: usize,
        addend: i64,
    ) -> Object {
        let mut obj = Object::default();
        obj.sections.push(Section {
            id: "text".to_string(),
            name: "text".to_string(),
            address: 0,
            size: fn_size,
            kind: SectionKind::Code,
            data: SectionData(vec![0u8; fn_size as usize]),
            relocations: vec![Relocation {
                flags: RelocationFlags::Coff(16),
                address: 0,
                target_symbol: 1,
                addend,
            }],
            ..Default::default()
        });
        // section 1: an unrelated code section, so "same section" is a real test.
        obj.sections.push(Section {
            id: "other".to_string(),
            name: "other".to_string(),
            address: 0,
            size: fn_size,
            kind: SectionKind::Code,
            data: SectionData(vec![0u8; fn_size as usize]),
            ..Default::default()
        });
        // symbol 0: the function being diffed.
        obj.symbols.push(Symbol {
            name: fn_name.to_string(),
            address: 0,
            size: fn_size,
            kind: SymbolKind::Function,
            section: Some(0),
            ..Default::default()
        });
        // symbol 1: the relocation target.
        obj.symbols.push(Symbol {
            name: target_name.to_string(),
            address: target_at,
            size: 0,
            kind: SymbolKind::Unknown,
            section: Some(target_section),
            ..Default::default()
        });
        obj
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_forgives_switch_dispatch_interior_self_ref() {
        // dc3 SaveLoadManager::GetDialogMsg, reduced. Ours materializes the first
        // case block as `$LN738` at function+0x98; dtk's writer dropped the
        // `+0x98` and left `<enclosing function> + 0`. Same linked address, and
        // the target object no longer says so.
        let f = "?GetDialogMsg@SaveLoadManager@@QAA?AVDataNode@@XZ";
        let left = obj_with_interior_ref(f, 0x1934, f, 0, 0, 0);
        let right = obj_with_interior_ref(f, 0x1934, "$LN738", 0x98, 0, 0);
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        // NameCheck-only: NameAddress must keep charging it, because the residual
        // (our interior offset differing from retail's) is unverifiable, not absent.
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameAddress));
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_interior_self_ref_stays_narrow() {
        let f = "?GetDialogMsg@SaveLoadManager@@QAA?AVDataNode@@XZ";
        let dtk = obj_with_interior_ref(f, 0x1934, f, 0, 0, 0);

        // Our `$`-label is in a DIFFERENT section: not an interior reference to
        // the function being diffed, so the name difference is still charged.
        let elsewhere = obj_with_interior_ref(f, 0x1934, "$LN738", 0x98, 1, 0);
        assert!(!reloc_match(&dtk, &elsewhere, FunctionRelocDiffs::NameCheck));

        // Our `$`-label is past the end of the function: likewise charged.
        let outside = obj_with_interior_ref(f, 0x80, "$LN738", 0x98, 0, 0);
        assert!(!reloc_match(&dtk, &outside, FunctionRelocDiffs::NameCheck));

        // The target's relocation names some OTHER function, not the one being
        // diffed. dtk's addend loss can only produce a SELF-reference, so this
        // is a real wrong-target charge and stays one.
        let other_fn = obj_with_interior_ref(f, 0x1934, "?Other@@QAAXXZ", 0, 0, 0);
        let ours = obj_with_interior_ref(f, 0x1934, "$LN738", 0x98, 0, 0);
        assert!(!reloc_match(&other_fn, &ours, FunctionRelocDiffs::NameCheck));

        // The target carries a NON-ZERO addend: it did not lose the offset, so
        // there is something to check and we do not forgive it.
        let with_addend = obj_with_interior_ref(f, 0x1934, f, 0, 0, 0x98);
        assert!(!reloc_match(&with_addend, &ours, FunctionRelocDiffs::NameCheck));

        // Our side names a REAL symbol rather than a `$`-label: charged.
        let real = obj_with_interior_ref(f, 0x1934, "?Callee@@QAAXXZ", 0x98, 0, 0);
        assert!(!reloc_match(&dtk, &real, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_forgives_unrelocated_target_operand() {
        // dtk left the computed constant in the operand because it could not
        // attribute the address (`lis r0, 0x80d1`); we name the datum. The arch
        // types the target operand as a Value, so this never reaches `reloc_eq`
        // -- but it is the same "no left-side name to check" case that
        // `reloc_eq` already forgives under NameCheck.
        let left = obj_with_reloc("unused", 0);
        let right = obj_with_reloc("?TheAccomplishmentMgr@@3PAVAccomplishmentManager@@A", 0);
        let row = InstructionDiffRow::default();
        let eq = std::collections::HashMap::new();
        let constant = InstructionArg::Value(InstructionArgValue::Unsigned(0x8311));
        let check = |left_arg: &InstructionArg, mode| {
            arg_eq(
                &left,
                &right,
                &row,
                &row,
                left_arg,
                &InstructionArg::Reloc,
                resolved_ref_no_reloc(&left),
                resolved_ref(&right),
                &DiffObjConfig { function_reloc_diffs: mode, ..Default::default() },
                &eq,
            )
        };
        assert!(check(&constant, FunctionRelocDiffs::None));
        assert!(check(&constant, FunctionRelocDiffs::NameCheck));
        // Address-coupled rulers keep charging it: the constant IS the address,
        // so there it is evidence, not a coverage hole.
        assert!(!check(&constant, FunctionRelocDiffs::NameOnly));
        assert!(!check(&constant, FunctionRelocDiffs::NameAddress));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_still_charges_two_differing_constants() {
        // The tolerance is about a MISSING left name, not about immediates:
        // two operands that are both plain constants are compared as before.
        let obj = obj_with_reloc("unused", 0);
        let row = InstructionDiffRow::default();
        let eq = std::collections::HashMap::new();
        let l = InstructionArg::Value(InstructionArgValue::Unsigned(0x8311));
        let r = InstructionArg::Value(InstructionArgValue::Unsigned(0x8312));
        for mode in [FunctionRelocDiffs::None, FunctionRelocDiffs::NameCheck] {
            assert!(!arg_eq(
                &obj,
                &obj,
                &row,
                &row,
                &l,
                &r,
                resolved_ref_no_reloc(&obj),
                resolved_ref_no_reloc(&obj),
                &DiffObjConfig { function_reloc_diffs: mode, ..Default::default() },
                &eq,
            ));
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_catches_wrong_callee() {
        // Both sides relocated, both REAL names, names differ: the wrong-callee
        // case the report pipeline's None mode scores as 100%.
        let left = obj_with_reloc("RightCallee", 0x100);
        let right = obj_with_reloc("WrongCallee", 0x100);
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::None));
    }

    // ---- NameCheck: COFF weak-external alias ----

    /// Like `obj_with_reloc`, but the reloc target is an UNDEFINED symbol that this
    /// object declares as a COFF weak external defaulting to `default_name`.
    ///
    /// `weak` selects whether the weak-external declaration is present. Passing
    /// `false` models the object DEFINING the symbol instead (the 1,158 `??_E` we
    /// define ourselves) and is what makes the resolution gate testable: the names
    /// are identical either way, so a test that passes under both would prove the
    /// implementation was keying on name SHAPE rather than on the COFF record.
    #[cfg(feature = "std")]
    fn obj_with_weak_external(target_name: &str, default_name: &str, weak: bool) -> Object {
        let mut obj = obj_with_reloc(target_name, 0x100);
        if weak {
            // Undefined: a weak external has no section.
            obj.symbols[1].section = None;
            obj.weak_external_defaults
                .insert(target_name.to_string(), default_name.to_string());
        }
        obj
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_forgives_coff_weak_external_alias() {
        // Retail calls the SCALAR deleting destructor; we emit a call to the VECTOR
        // deleting destructor, which our object declares as an undefined weak
        // external defaulting to exactly that scalar one. Both link to one body.
        let left = obj_with_reloc("??_GFoo@@UAAPAXI@Z", 0x100);
        let right =
            obj_with_weak_external("??_EFoo@@UAAPAXI@Z", "??_GFoo@@UAAPAXI@Z", true);
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        // Tolerance is NameCheck-specific; NameOnly still charges the name diff.
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_weak_external_gate_defined_symbol_still_charged() {
        // NULL 1 -- THE RESOLUTION GATE. Byte-for-byte the same names as the test
        // above, with ONE difference: the object does not declare `??_E` as an
        // undefined weak external (i.e. it DEFINES it). A defined weak-external
        // name binds to itself, so the call does NOT reach `??_G` and the row is
        // ambiguous, never benign. This must stay charged.
        let left = obj_with_reloc("??_GFoo@@UAAPAXI@Z", 0x100);
        let right =
            obj_with_weak_external("??_EFoo@@UAAPAXI@Z", "??_GFoo@@UAAPAXI@Z", false);
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_weak_external_cross_class_still_charged() {
        // NULL 2 -- natural experiment. The base side IS an undefined weak external,
        // so the rule CAN fire here; but its default is `??_GBar`, while retail calls
        // `??_GQux`. Different classes, different code: the rule must DECLINE.
        let left = obj_with_reloc("??_GQux@@UAAPAXI@Z", 0x100);
        let right =
            obj_with_weak_external("??_EBar@@UAAPAXI@Z", "??_GBar@@UAAPAXI@Z", true);
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_weak_external_does_not_forgive_arbitrary_names() {
        // NULL 3 -- the alias is an EQUALITY test against the resolved default, not
        // a licence to forgive any pair where a weak external is involved. Base is a
        // weak external defaulting to `Alpha`; retail calls `Beta`.
        let left = obj_with_reloc("Beta", 0x100);
        let right = obj_with_weak_external("Weak", "Alpha", true);
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_forgives_addend() {
        // Same callee, different addend: benign build-address noise, like NameOnly.
        let left = obj_with_reloc("Callee", 0x100);
        let right = obj_with_reloc("Callee", 0x200);
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_comdat_bucket_variant_matches() {
        // COMDAT-bucket tolerance carries over from NameOnly.
        let left = obj_with_reloc_in_section("Callee", 0x100, ".text$dup");
        let right = obj_with_reloc_in_section("Callee", 0x100, ".text");
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_forgives_data_placement() {
        // The dc3 case: a splitter emits every writable datum into `.data$dup`
        // while the compiler leaves a zero-initialised static in `.bss`. Same
        // mangled name, same datum -- WHICH data section it lands in is a
        // property of the emitter, not of the referent.
        let left = obj_with_reloc_in_section("?gCache@@3PAVFileCache@@A", 0x100, ".data$dup");
        let right = obj_with_reloc_in_section("?gCache@@3PAVFileCache@@A", 0x100, ".bss");
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        // Throw-info records: `.rdata$dup` against `.xdata$x`.
        let left = obj_with_reloc_in_section("_TI4?AVlength_error@@", 0x100, ".rdata$dup");
        let right = obj_with_reloc_in_section("_TI4?AVlength_error@@", 0x100, ".xdata$x");
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        // Const-vs-mutable placement of the same datum.
        let left = obj_with_reloc_in_section("sDepthRectDecl", 0x100, ".data$dup");
        let right = obj_with_reloc_in_section("sDepthRectDecl", 0x100, ".rdata");
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_data_placement_tolerance_is_still_name_gated() {
        // Two DIFFERENT data symbols in two different data sections stay a
        // mismatch: placement tolerance never substitutes for the name check.
        let left = obj_with_reloc_in_section("?gStream@@3PAVBinStream@@A", 0x100, ".data$dup");
        let right = obj_with_reloc_in_section("?gBinStream@@3PAVBinStream@@A", 0x100, ".bss");
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_code_vs_data_still_diffs() {
        // The guard the tolerance must NOT dissolve: one side names a function,
        // the other a datum that happens to share the name.
        let left = obj_with_reloc_in_section("Callee", 0x100, ".text$dup");
        let right = obj_with_reloc_in_section("Callee", 0x100, ".data");
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));
    }

    #[test]
    fn test_is_placeholder_symbol_name() {
        assert!(is_placeholder_symbol_name("fn_82345678"));
        assert!(is_placeholder_symbol_name("fn_82345678_0"));
        assert!(is_placeholder_symbol_name("lbl_829fc4a0"));
        assert!(is_placeholder_symbol_name("jumptable_82A477BC"));
        // csplit (i386 PE) placeholders, with and without cdecl underscore.
        assert!(is_placeholder_symbol_name("_bss_00456208"));
        assert!(is_placeholder_symbol_name("_data_00317a84"));
        assert!(is_placeholder_symbol_name("_code_000fab20"));
        assert!(is_placeholder_symbol_name("_rdata_002e4c84"));
        assert!(is_placeholder_symbol_name("code_000fab20"));
        // Real names that merely share a prefix are NOT placeholders.
        assert!(!is_placeholder_symbol_name("fn_helper"));
        assert!(!is_placeholder_symbol_name("fnord"));
        assert!(!is_placeholder_symbol_name("fn_"));
        assert!(!is_placeholder_symbol_name("?Poll@CharServoBone@@UAAXXZ"));
        assert!(!is_placeholder_symbol_name("label_1234"));
        assert!(!is_placeholder_symbol_name("_data_ptr"));
        assert!(!is_placeholder_symbol_name("_bss_"));
        assert!(!is_placeholder_symbol_name("_code_gen_table"));
    }

    #[test]
    fn test_is_compiler_local_label() {
        assert!(is_compiler_local_label("$L18077"));
        assert!(is_compiler_local_label("$T18082"));
        assert!(is_compiler_local_label("$SG12345"));
        assert!(!is_compiler_local_label("$"));
        assert!(!is_compiler_local_label("_main"));
        // Content-derived literal names are NOT local labels: they are stable
        // across compilations and must still be compared.
        assert!(!is_compiler_local_label("__real@3f800000"));
        assert!(!is_compiler_local_label("??_C@_06PFFNFMJI@XDEMOS?$AA@"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_name_check_forgives_msvc_local_label_numbering() {
        // SEH scope-table label: same construct, different compilation counter.
        let left = obj_with_reloc("$T18083", 0x100);
        let right = obj_with_reloc("$T18082", 0x100);
        assert!(reloc_match(&left, &right, FunctionRelocDiffs::NameCheck));
        assert!(!reloc_match(&left, &right, FunctionRelocDiffs::NameOnly));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_section_base_name_strips_comdat_suffix() {
        assert_eq!(section_base_name(".text"), ".text");
        assert_eq!(section_base_name(".text$dup"), ".text");
        assert_eq!(section_base_name(".text$mn"), ".text");
        assert_eq!(section_base_name(".rdata$r"), ".rdata");
        assert_ne!(section_base_name(".text$dup"), section_base_name(".data"));
    }

    // ---- diff_instructions: the equal-LENGTH false-regression regression test ----

    fn irefs(opcodes: &[u16]) -> Vec<InstructionRef> {
        opcodes
            .iter()
            .enumerate()
            .map(|(i, &opcode)| InstructionRef {
                address: (i * 4) as u64,
                size: 4,
                opcode,
                branch_dest: None,
            })
            .collect()
    }

    /// Number of row positions where BOTH sides carry an instruction and the
    /// opcodes agree — i.e. rows the scorer can possibly credit as equal.
    fn aligned_equal_rows(
        left: &[InstructionDiffRow],
        right: &[InstructionDiffRow],
    ) -> usize {
        left.iter()
            .zip(right.iter())
            .filter(|(l, r)| match (l.ins_ref, r.ins_ref) {
                (Some(a), Some(b)) => a.opcode == b.opcode,
                _ => false,
            })
            .count()
    }

    /// What the OLD (buggy) `left.len() == right.len()` fast path would have
    /// produced: a blind 1:1 pairing. Kept in the test only, as the counterfactual.
    fn one_to_one_equal_rows(left: &[InstructionRef], right: &[InstructionRef]) -> usize {
        left.iter().zip(right.iter()).filter(|(a, b)| a.opcode == b.opcode).count()
    }

    #[test]
    fn test_diff_instructions_equal_length_still_aligns() {
        // N deletions + N insertions preserve length. The old fast path keyed on
        // length equality and therefore mis-scored exactly this shape.
        let left = irefs(&[1, 2, 3, 100, 101, 4, 5, 6, 7, 8]);
        let right = irefs(&[1, 2, 3, 4, 5, 6, 7, 8, 200, 201]);
        assert_eq!(left.len(), right.len(), "fixture must be EQUAL length or it tests nothing");

        let (l, r) = diff_instructions(&left, &right).unwrap();

        // Real alignment inserts gap rows, so the row count EXCEEDS the input length.
        // Under the length-equality fast path this was exactly 10.
        assert!(l.len() > left.len(), "no gap rows emitted => fast path was taken (len {})", l.len());
        assert_eq!(l.len(), r.len());
        assert!(l.iter().any(|row| row.ins_ref.is_none()), "expected a gap row on the left");
        assert!(r.iter().any(|row| row.ins_ref.is_none()), "expected a gap row on the right");

        // The whole point: real alignment recovers the 8 shared opcodes; the blind
        // 1:1 pairing the old guard produced recovers only 3.
        let real = aligned_equal_rows(&l, &r);
        let naive = one_to_one_equal_rows(&left, &right);
        assert_eq!(real, 8, "expected the 8-opcode common run to align");
        assert_eq!(naive, 3, "counterfactual: the old fast path only lined up the 3-op prefix");
        assert!(real > naive);
    }

    #[test]
    fn test_diff_instructions_identical_takes_fast_path() {
        // Positive control for the *retained* fast path: identical opcode sequences
        // must pair 1:1 with no gap rows (identical to what the general path yields).
        let left = irefs(&[1, 2, 3, 4, 5]);
        let right = irefs(&[1, 2, 3, 4, 5]);
        let (l, r) = diff_instructions(&left, &right).unwrap();
        assert_eq!(l.len(), 5);
        assert_eq!(r.len(), 5);
        assert!(l.iter().all(|row| row.ins_ref.is_some()));
        assert!(r.iter().all(|row| row.ins_ref.is_some()));
        assert_eq!(aligned_equal_rows(&l, &r), 5);
    }

    #[test]
    fn test_diff_instructions_unequal_length_unchanged() {
        // The pre-existing (already-correct) unequal-length behaviour must not move.
        let left = irefs(&[1, 2, 3, 4, 5]);
        let right = irefs(&[1, 2, 9, 3, 4, 5]);
        let (l, r) = diff_instructions(&left, &right).unwrap();
        assert_eq!(l.len(), r.len());
        assert_eq!(l.len(), 6);
        assert_eq!(aligned_equal_rows(&l, &r), 5);
    }

    #[test]
    fn test_diff_instructions_empty() {
        let (l, r) = diff_instructions(&[], &[]).unwrap();
        assert!(l.is_empty());
        assert!(r.is_empty());
    }
}
