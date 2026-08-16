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
fn build_object(callee: &str) -> Vec<u8> {
    let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::PowerPc, Endianness::Big);
    let text = obj.section_id(StandardSection::Text);

    // bl 0 (0x48000001, LK=1) ; blr (0x4e800020) — big-endian.
    let code: [u8; 8] = [0x48, 0x00, 0x00, 0x01, 0x4e, 0x80, 0x00, 0x20];
    let func_off = obj.append_section_data(text, &code, 4);

    let _func = obj.add_symbol(Symbol {
        name: b"func".to_vec(),
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
    let idx =
        target_obj.symbols.iter().position(|s| s.name == "func").expect("func symbol present");
    let sym = &target_diff.symbols[idx];

    (
        sym.match_percent.expect("match percent present"),
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
