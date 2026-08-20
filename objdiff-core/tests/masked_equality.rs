//! Masked-equality disclosure fixture (V1 §S1).
//!
//! The fork normalizes several byte-level differences to "equal" so they do not
//! count against the fuzzy `match_percent`. The most important channel is
//! relocation-mode relaxation: under `functionRelocDiffs=none` a `bl` to a
//! *different* callee scores as an equal row, so a wrong-callee bug is invisible
//! in the score. S1 adds a per-row `masked_equal` disclosure bit plus the
//! symbol-level counters `masked_equal_rows` / `reloc_ignored_rows`, set at the
//! normalization sites, WITHOUT changing any score.
//!
//! This fixture builds two tiny PPC relocatable objects that are byte-identical
//! except for the target symbol of a single `bl` relocation, and asserts the
//! registered S1 gate:
//!   * under `None`  → `match_percent == 100` AND `masked_equal_rows >= 1`
//!     (`reloc_ignored_rows >= 1`), i.e. the wrong callee is masked but disclosed;
//!   * under `NameOnly` → `match_percent < 100` AND no masked rows, i.e. the
//!     difference is metric-visible and there is nothing left to disclose.

#![cfg(feature = "ppc")]

use objdiff_core::{diff, obj};
use object::{
    Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope,
    write::{Object as WriteObject, Relocation, StandardSection, Symbol, SymbolSection},
};

/// Build a minimal big-endian PPC ELF relocatable object containing a single
/// function `func` whose body is `bl <callee>; blr`, with an `R_PPC_REL24`
/// relocation at offset 0 pointing at an undefined `callee` symbol. The `.text`
/// bytes are identical regardless of `callee` (the branch displacement lives in
/// the relocation, not the encoded instruction), so two objects built with
/// different callees differ ONLY in that relocation's target symbol name.
fn build_object(callee: &str) -> Vec<u8> { build_object_named(callee, "func") }

/// As `build_object`, but names the ENCLOSING function too. Needed to exercise
/// the funclet carve-out, which keys off the enclosing symbol's name rather
/// than the relocation target's.
fn build_object_named(callee: &str, func_name: &str) -> Vec<u8> {
    let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::PowerPc, Endianness::Big);
    let text = obj.section_id(StandardSection::Text);

    // bl 0 (0x48000001, LK=1) ; blr (0x4e800020) — big-endian.
    let code: [u8; 8] = [0x48, 0x00, 0x00, 0x01, 0x4e, 0x80, 0x00, 0x20];
    let func_off = obj.append_section_data(text, &code, 4);

    let _func = obj.add_symbol(Symbol {
        name: func_name.as_bytes().to_vec(),
        value: func_off,
        size: code.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });

    let callee_sym = obj.add_symbol(Symbol {
        name: callee.as_bytes().to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });

    obj.add_relocation(text, Relocation {
        offset: func_off,
        symbol: callee_sym,
        addend: 0,
        flags: object::RelocationFlags::Elf { r_type: object::elf::R_PPC_REL24 },
    })
    .expect("add bl relocation");

    obj.write().expect("write ELF object")
}

/// Diff `func` (target vs base) under the given reloc mode and return
/// `(match_percent, masked_equal_rows, reloc_ignored_rows)` for the target side.
fn diff_func(
    target_bytes: &[u8],
    base_bytes: &[u8],
    reloc_mode: diff::FunctionRelocDiffs,
) -> (f32, u32, u32) {
    let (pct, _norm, masked, reloc) = diff_func_full(target_bytes, base_bytes, reloc_mode, "func");
    (pct, masked, reloc)
}

/// As `diff_func`, but also returns `match_percent_normalized` — the CANONICAL
/// metric this project reports — and lets the caller name the symbol.
fn diff_func_full(
    target_bytes: &[u8],
    base_bytes: &[u8],
    reloc_mode: diff::FunctionRelocDiffs,
    sym_name: &str,
) -> (f32, f32, u32, u32) {
    let diff_config =
        diff::DiffObjConfig { function_reloc_diffs: reloc_mode, ..Default::default() };
    let mapping_config = diff::MappingConfig::default();

    let target_obj =
        obj::read::parse(target_bytes, &diff_config, diff::DiffSide::Target).expect("parse target");
    let base_obj =
        obj::read::parse(base_bytes, &diff_config, diff::DiffSide::Base).expect("parse base");

    let result =
        diff::diff_objs(Some(&target_obj), Some(&base_obj), None, &diff_config, &mapping_config)
            .expect("diff objects");

    let target_diff = result.left.as_ref().expect("target diff present");
    let idx = target_obj.symbols.iter().position(|s| s.name == sym_name).expect("symbol present");
    let sym = &target_diff.symbols[idx];

    (
        sym.match_percent.expect("match percent present"),
        sym.match_percent_normalized.expect("normalized match percent present"),
        sym.masked_equal_rows,
        sym.reloc_ignored_rows,
    )
}

#[test]
fn bl_reloc_only_diff_is_masked_under_none_and_visible_under_name_only() {
    let target = build_object("callee_a");
    let base = build_object("callee_b");

    // Sanity: the objects are byte-identical in .text; only the reloc target
    // differs. If this ever regresses (e.g. the encoder embeds the callee in the
    // instruction), the rest of the gate is meaningless.
    // (We assert the observable diff behavior below rather than the raw bytes,
    // since ELF section ordering/symbol tables legitimately differ by name.)

    // --- functionRelocDiffs = None: wrong callee is MASKED but DISCLOSED. ---
    let (pct_none, masked_none, reloc_none) =
        diff_func(&target, &base, diff::FunctionRelocDiffs::None);
    assert_eq!(
        pct_none, 100.0,
        "under None a bl-to-different-callee must score 100% (masking channel)"
    );
    assert!(
        masked_none >= 1,
        "under None the masked bl row must be disclosed: masked_equal_rows={masked_none}"
    );
    assert!(reloc_none >= 1, "the mask is a reloc relaxation: reloc_ignored_rows={reloc_none}");

    // --- functionRelocDiffs = NameOnly: the difference is METRIC-VISIBLE. ---
    let (pct_name_only, masked_name_only, reloc_name_only) =
        diff_func(&target, &base, diff::FunctionRelocDiffs::NameOnly);
    assert!(
        pct_name_only < 100.0,
        "under NameOnly a wrong callee name must drop below 100%: got {pct_name_only}"
    );
    assert_eq!(
        masked_name_only, 0,
        "nothing is masked once the diff is visible: masked_equal_rows={masked_name_only}"
    );
    assert_eq!(reloc_name_only, 0, "reloc_ignored_rows must be 0 under NameOnly");
}

#[test]
fn identical_objects_report_no_masking() {
    // Two byte-identical objects (same callee) must have zero masked rows under
    // every reloc mode: the disclosure signal fires only when a normalization
    // was actually load-bearing.
    let obj_bytes = build_object("callee_a");

    for mode in [diff::FunctionRelocDiffs::None, diff::FunctionRelocDiffs::NameOnly] {
        let (pct, masked, reloc) = diff_func(&obj_bytes, &obj_bytes, mode);
        assert_eq!(pct, 100.0, "identical objects score 100% ({mode:?})");
        assert_eq!(masked, 0, "identical objects have no masked rows ({mode:?})");
        assert_eq!(reloc, 0, "identical objects have no reloc-ignored rows ({mode:?})");
    }
}

// ---------------------------------------------------------------------------
// NameCheck: a vetted wrong-callee must reach the CANONICAL metric.
//
// These are the gate for the 2026-08-20 un-fold. Every one of them FAILS on the
// parent commit — which is the point. The 118 tests that already existed were
// all green while `match_percent_normalized` was structurally blind to this
// entire bug class, because they tested `reloc_eq` (the detector, which was
// always correct) and never the scoring fold downstream of it.
// ---------------------------------------------------------------------------

#[test]
fn namecheck_wrong_callee_is_visible_in_the_normalized_metric() {
    let target = build_object("callee_a");
    let base = build_object("callee_b");

    let (fuzzy, norm, _, _) =
        diff_func_full(&target, &base, diff::FunctionRelocDiffs::NameCheck, "func");

    assert!(fuzzy < 100.0, "NameCheck must detect the wrong callee in fuzzy: {fuzzy}");
    assert!(
        norm < 100.0,
        "a vetted wrong-callee name must also reach match_percent_normalized, \
         the metric this project reports as canonical; got {norm}. Before the \
         un-fold this asserted 100.0: the reloc penalty went into BOTH \
         diff_score and arg_diff_score and cancelled exactly."
    );
}

#[test]
fn none_still_forgives_the_wrong_callee_in_both_metrics() {
    // Negative control: the un-fold is scoped to NameCheck. Under None the
    // relocation is not even compared, so nothing may change.
    let target = build_object("callee_a");
    let base = build_object("callee_b");

    let (fuzzy, norm, _, _) =
        diff_func_full(&target, &base, diff::FunctionRelocDiffs::None, "func");
    assert_eq!(fuzzy, 100.0, "None must still mask the wrong callee in fuzzy");
    assert_eq!(norm, 100.0, "None must still mask the wrong callee in normalized");
}

#[test]
fn namecheck_same_callee_stays_perfect() {
    // Negative control: no name difference, no charge. Guards against the
    // un-fold charging every relocation site indiscriminately.
    let obj_bytes = build_object("callee_a");
    let (fuzzy, norm, _, _) =
        diff_func_full(&obj_bytes, &obj_bytes, diff::FunctionRelocDiffs::NameCheck, "func");
    assert_eq!(fuzzy, 100.0, "identical callees score 100% fuzzy under NameCheck");
    assert_eq!(norm, 100.0, "identical callees score 100% normalized under NameCheck");
}

#[test]
fn namecheck_regalloc_save_helper_stays_folded() {
    // CARVE-OUT 1. Which `__savegprlr_N` a function calls is decided by how many
    // callee-save registers the allocator used. Normalization exists to forgive
    // register allocation, so this must NOT reach the normalized score — while
    // fuzzy, which charges register differences by design, still sees it.
    //
    // Measured on the DC3 binary: 467 of 1,537 charged sites were this class,
    // and 223 functions were charged on nothing else.
    let target = build_object("__savegprlr_25");
    let base = build_object("__savegprlr_26");

    let (fuzzy, norm, _, _) =
        diff_func_full(&target, &base, diff::FunctionRelocDiffs::NameCheck, "func");
    assert!(fuzzy < 100.0, "fuzzy still charges the save-helper difference: {fuzzy}");
    assert_eq!(
        norm, 100.0,
        "a register-save-helper difference is register allocation and must stay \
         folded out of the normalized score; got {norm}"
    );
}

#[test]
fn namecheck_codewarrior_save_helper_stays_folded() {
    // CARVE-OUT 1, non-MSVC spelling. CodeWarrior emits `_savegpr_14` — ONE
    // leading underscore and no `lr` — where MSVC/Xenon emits `__savegprlr_25`.
    // The original matcher stripped one underscore then REQUIRED a second, so it
    // silently excluded every CodeWarrior target: measured on RB3, 188 sites of
    // pure register-allocation noise were charged into the canonical score that
    // an otherwise identical MSVC target would have forgiven.
    let target = build_object("_savegpr_14");
    let base = build_object("_savegpr_18");

    let (fuzzy, norm, _, _) =
        diff_func_full(&target, &base, diff::FunctionRelocDiffs::NameCheck, "func");
    assert!(fuzzy < 100.0, "fuzzy still charges the save-helper difference: {fuzzy}");
    assert_eq!(
        norm, 100.0,
        "a CodeWarrior register-save-helper difference is register allocation and must \
         stay folded, exactly as the MSVC spelling is; got {norm}"
    );
}

#[test]
fn namecheck_a_real_symbol_that_merely_starts_like_a_helper_is_still_charged() {
    // Negative control for the underscore relaxation above: the suffix must
    // still be all digits, so a genuine symbol sharing the prefix is charged.
    let target = build_object("_saveguard_state");
    let base = build_object("_saveguard_other");

    let (_, norm, _, _) =
        diff_func_full(&target, &base, diff::FunctionRelocDiffs::NameCheck, "func");
    assert!(norm < 100.0, "a real symbol sharing a helper prefix must be charged; got {norm}");
}

#[test]
fn namecheck_anonymous_vftable_placeholder_stays_folded() {
    // CARVE-OUT 2, sibling spelling. RB3-Xenon's splitter names an unrecovered
    // .rdata vtable `vftable_<hex>` — the same address-numbered placeholder
    // shape as `lbl_`/`data_`, and just as meaningless to compare by name. 34
    // sites across 16 functions were charged purely for that spelling.
    let target = build_object("vftable_82016268");
    let base = build_object("vftable_8201D76C");

    let (_, norm, _, _) =
        diff_func_full(&target, &base, diff::FunctionRelocDiffs::NameCheck, "func");
    assert_eq!(
        norm, 100.0,
        "two address-numbered vtable placeholders must stay folded; got {norm}"
    );
}

#[test]
fn namecheck_a_named_vtable_is_still_charged() {
    // Negative control for the vftable_ placeholder: the suffix must be hex, so
    // a genuine wrong-vtable reference still reaches the canonical score.
    let target = build_object("??_7RndMat@@6B@");
    let base = build_object("??_7RndFont@@6B@");

    let (_, norm, _, _) =
        diff_func_full(&target, &base, diff::FunctionRelocDiffs::NameCheck, "func");
    assert!(norm < 100.0, "referencing a different NAMED vtable must be charged; got {norm}");
}

#[test]
fn namecheck_funclet_pairing_stays_folded() {
    // CARVE-OUT 2. MSVC EH funclets are split as `fn_<addr>` and objdiff pairs
    // them BY BYTE SIGNATURE — a heuristic. Charging relocation names on a
    // heuristically-paired symbol measures the pairing, not the source. On the
    // DC3 binary this was 204 of 226 static-guard sites, including pairs whose
    // two sides belonged to different classes outright.
    let target = build_object_named("callee_a", "fn_82E35C6C");
    let base = build_object_named("callee_b", "fn_82E35C6C");

    let (_fuzzy, norm, _, _) =
        diff_func_full(&target, &base, diff::FunctionRelocDiffs::NameCheck, "fn_82E35C6C");
    assert_eq!(
        norm, 100.0,
        "relocation names on a byte-signature-paired funclet are not \
         attributable to our source; got {norm}"
    );
}

#[test]
fn namecheck_local_static_scope_ordinal_stays_folded() {
    // CARVE-OUT 3. MSVC numbers a function-local static's enclosing scope with a
    // per-TU ordinal (`?PC@` vs `?PK@`) that moves whenever anything earlier in
    // the file moves. Same variable, same enclosing function => no divergence.
    let target = build_object("?msg@?PC@??OnBeat@RhythmBattle@@AAAXXZ@4VMessage@@A");
    let base = build_object("?msg@?PK@??OnBeat@RhythmBattle@@AAAXXZ@4VMessage@@A");

    let (_fuzzy, norm, _, _) =
        diff_func_full(&target, &base, diff::FunctionRelocDiffs::NameCheck, "func");
    assert_eq!(
        norm, 100.0,
        "a moved local-static scope ordinal is a counter, not a bug; got {norm}"
    );
}

#[test]
fn namecheck_local_static_in_a_different_function_is_charged() {
    // ...and the matching POSITIVE control for carve-out 3: same shape, but the
    // ENCLOSING FUNCTION differs. That is a real divergence and must be charged,
    // so the ordinal exemption cannot be written as "ignore anything that looks
    // like a local static".
    let target = build_object("?msg@?PC@??OnBeat@RhythmBattle@@AAAXXZ@4VMessage@@A");
    let base = build_object("?msg@?PC@??OnBeat@RhythmSolo@@AAAXXZ@4VMessage@@A");

    let (_fuzzy, norm, _, _) =
        diff_func_full(&target, &base, diff::FunctionRelocDiffs::NameCheck, "func");
    assert!(
        norm < 100.0,
        "a local static in a DIFFERENT function is a real divergence; got {norm}"
    );
}
