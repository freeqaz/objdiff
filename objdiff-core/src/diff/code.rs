use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map},
    string::{String, ToString},
    vec,
    vec::Vec,
};

use anyhow::{Context, Result, anyhow, ensure};

use super::{
    DiffObjConfig, FunctionRelocDiffs, InstructionArgDiffIndex, InstructionBranchFrom,
    InstructionBranchTo, InstructionDiffKind, InstructionDiffRow, SymbolDiff,
    display::display_ins_data_literals,
};
use crate::obj::{
    InstructionArg, InstructionArgValue, InstructionRef, Object, ParsedInstruction,
    ResolvedInstructionRef, ResolvedRelocation, ResolvedSymbol, SymbolKind,
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
    for (i, (left_row, right_row)) in left_rows.iter_mut().zip(right_rows.iter_mut()).enumerate() {
        // FP-anchor compensated pair: provably-equal effective address despite a
        // differing frame-anchor constant. Score as equal, no penalty.
        if fp_anchor_equal_rows.contains(&i) {
            left_row.kind = InstructionDiffKind::None;
            right_row.kind = InstructionDiffKind::None;
            left_row.arg_diff = Vec::new();
            right_row.arg_diff = Vec::new();
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
            instruction_rows: left_rows,
            ..Default::default()
        },
        SymbolDiff {
            target_symbol: Some(left_symbol_idx),
            match_percent: Some(match_percent),
            match_percent_normalized: Some(match_percent_normalized),
            diff_score: Some((diff_score, max_score)),
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
    // Fast path: if same length, pair instructions 1:1 without running the diff algorithm.
    // This is valid because same-length sequences have no insertions/deletions, and
    // instruction order is preserved in decomp output, so 1:1 alignment is optimal.
    if left_insts.len() == right_insts.len() {
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
    let left_ops = left_insts.iter().map(|i| i.opcode).collect::<Vec<_>>();
    let right_ops = right_insts.iter().map(|i| i.opcode).collect::<Vec<_>>();
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
    let (left_reloc, right_reloc) = match (left_ins.relocation, right_ins.relocation) {
        (Some(left_reloc), Some(right_reloc)) => (left_reloc, right_reloc),
        // If relocations are relaxed, match if left is missing a reloc
        (None, Some(_)) => return relax_reloc_diffs,
        (None, None) => return true,
        _ => return false,
    };
    if left_reloc.relocation.flags != right_reloc.relocation.flags {
        return false;
    }
    if relax_reloc_diffs {
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
    match (&left_reloc.symbol.section, &right_reloc.symbol.section) {
        (Some(sl), Some(sr)) => {
            // Match if section and name or address match
            section_name_eq(left_obj, right_obj, *sl, *sr)
                && (diff_config.function_reloc_diffs == FunctionRelocDiffs::DataValue
                    || symbol_name_addend_matches
                    || address_eq(left_reloc, right_reloc))
                && (diff_config.function_reloc_diffs == FunctionRelocDiffs::NameAddress
                    || left_reloc.symbol.kind != SymbolKind::Object
                    || right_reloc.symbol.size == 0 // Likely a pool symbol like ...data, don't treat this as a diff
                    || display_ins_data_literals(left_obj, left_ins)
                        == display_ins_data_literals(right_obj, right_ins))
        }
        (Some(_), None) | (None, Some(_)) | (None, None) => symbol_name_addend_matches,
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
            InstructionArg::Reloc => diff_config.function_reloc_diffs == FunctionRelocDiffs::None,
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
}

impl InstructionDiffResult {
    #[inline]
    const fn new(kind: InstructionDiffKind) -> Self {
        Self { kind, left_args_diff: Vec::new(), right_args_diff: Vec::new() }
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
        return Ok(result);
    }

    Ok(InstructionDiffResult::new(InstructionDiffKind::None))
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
}
