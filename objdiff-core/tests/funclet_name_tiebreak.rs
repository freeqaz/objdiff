//! Deterministic funclet pairing by relocation-target NAME (4.2.9).
//!
//! `funclet_signature` zeroes every relocation word and DROPS the target names, so
//! MSVC EH funclets that differ only in which destructor they call collapse onto one
//! signature key. Inside such an equivalence class `pair_funclets_by_bytes` used to
//! resolve the many-to-many assignment by symbol-name sort order plus a greedy zip —
//! arbitrarily. Measured on rb3-xenon retail (lane W16-T): `RockCentral`'s
//! `subi r31,r12,0x90` + `addi r3,r31,0x50` class has 5 retail members and >= 5 of
//! ours, and ALL FIVE retail rows scored 99.5 — 0/5 correct.
//!
//! The tiebreaker pairs first the candidates whose relocation target names agree and
//! nowhere conflict, then falls back to the historical zip. These tests pin the
//! three properties that matter:
//!
//!   1. the agreeing partner is chosen even when it is LAST in sort order (1-vs-N),
//!   2. the same holds when every naive zip pairing is wrong (N-vs-N),
//!   3. a group with NO agreeing candidate still pairs exactly as before (control),
//!   4. the choice does not depend on the order symbols are emitted in.
//!
//! (3) and (4) are the controls: without them a tiebreaker that simply reordered
//! everything, or one that only ever fired in one emission order, would pass.

#![cfg(feature = "ppc")]

use objdiff_core::{diff, obj};
use object::{
    Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope,
    write::{Object as WriteObject, Relocation, StandardSection, Symbol, SymbolSection},
};

/// Build a PPC ELF object holding one `bl <callee>; blr` function per entry of
/// `funcs` (`(symbol name, callee name)`).
///
/// Every function's `.text` bytes are identical — the branch displacement lives in
/// the relocation, not the encoding — so all of them share ONE reloc-masked funclet
/// signature and land in the same `pair_funclets_by_bytes` signature group. Only the
/// relocation's target NAME distinguishes them, which is exactly what the tiebreaker
/// reads and what `funclet_signature` throws away.
fn build_bl_obj(funcs: &[(&str, &str)]) -> Vec<u8> {
    // bl 0 (LK=1) ; blr — big-endian.
    const CODE: [u8; 8] = [0x48, 0x00, 0x00, 0x01, 0x4e, 0x80, 0x00, 0x20];
    let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::PowerPc, Endianness::Big);
    let text = obj.section_id(StandardSection::Text);
    for (name, callee) in funcs {
        let off = obj.append_section_data(text, &CODE, 4);
        obj.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value: off,
            size: CODE.len() as u64,
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
            offset: off,
            symbol: callee_sym,
            addend: 0,
            flags: object::RelocationFlags::Elf { r_type: object::elf::R_PPC_REL24 },
        })
        .expect("add bl relocation");
    }
    obj.write().expect("write ELF object")
}

/// Diff under `name_check` (the shipped ruler) and report, for each named target
/// symbol, `(base partner's name, match_percent)`.
fn partners(target_bytes: &[u8], base_bytes: &[u8], names: &[&str]) -> Vec<(String, f32)> {
    let diff_config = diff::DiffObjConfig {
        function_reloc_diffs: diff::FunctionRelocDiffs::NameCheck,
        ..Default::default()
    };
    let mapping_config = diff::MappingConfig::default();
    let target =
        obj::read::parse(target_bytes, &diff_config, diff::DiffSide::Target).expect("parse target");
    let base =
        obj::read::parse(base_bytes, &diff_config, diff::DiffSide::Base).expect("parse base");
    let result = diff::diff_objs(Some(&target), Some(&base), None, &diff_config, &mapping_config)
        .expect("diff objects");
    let target_diff = result.left.as_ref().expect("target diff present");
    names
        .iter()
        .map(|name| {
            let idx =
                target.symbols.iter().position(|s| &s.name == name).expect("target symbol present");
            let sym = &target_diff.symbols[idx];
            let partner = sym
                .target_symbol
                .map(|r| base.symbols[r].name.clone())
                .unwrap_or_else(|| "<unpaired>".to_string());
            (partner, sym.match_percent.expect("match percent present"))
        })
        .collect()
}

const DTOR_LIST: &str = "??1DataResultList@@UAA@XZ";
const DTOR_MSG: &str = "??1Message@@UAA@XZ";
const DTOR_STR: &str = "??1_String_base@@QAA@XZ";

#[test]
fn one_vs_n_picks_the_name_agreeing_partner_even_when_it_sorts_last() {
    // One retail funclet destroying a DataResultList; three of ours in the same
    // signature class, of which only `__unwind$3` calls the same destructor — and it
    // sorts LAST, so the historical name-sorted zip picked `__unwind$1`.
    let target = build_bl_obj(&[("fn_82345678", DTOR_LIST)]);
    let base = build_bl_obj(&[
        ("__unwind$1", DTOR_MSG),
        ("__unwind$2", DTOR_STR),
        ("__unwind$3", DTOR_LIST),
    ]);
    let got = partners(&target, &base, &["fn_82345678"]);
    assert_eq!(
        got[0].0, "__unwind$3",
        "the tiebreaker must pick the funclet whose reloc target name AGREES, not the \
         first in sort order (got {got:?})"
    );
    assert_eq!(got[0].1, 100.0, "the correctly-paired funclet scores 100% under name_check");
}

#[test]
fn n_vs_n_repairs_a_wholly_wrong_zip() {
    // The RockCentral shape in miniature: the naive zip pairs target[0] with base[0]
    // and target[1] with base[1], and BOTH are wrong (0/2 correct). Names fix both.
    let target = build_bl_obj(&[("fn_82345678", DTOR_LIST), ("fn_8234567c", DTOR_MSG)]);
    let base = build_bl_obj(&[("__unwind$1", DTOR_MSG), ("__unwind$2", DTOR_LIST)]);
    let got = partners(&target, &base, &["fn_82345678", "fn_8234567c"]);
    assert_eq!(
        got[0].0, "__unwind$2",
        "DataResultList target must pair with the DataResultList base"
    );
    assert_eq!(got[1].0, "__unwind$1", "Message target must pair with the Message base");
    assert_eq!(got[0].1, 100.0);
    assert_eq!(got[1].1, 100.0);
}

#[test]
fn control_no_agreeing_candidate_still_pairs_unchanged() {
    // CONTROL. Nothing in the base names the target's callee, so there is no positive
    // evidence and the tiebreaker must abstain — the historical name-sorted zip still
    // pairs the funclet with `__unwind$1`. A tiebreaker that reshuffled groups it
    // cannot decide would fail here.
    let target = build_bl_obj(&[("fn_82345678", DTOR_LIST)]);
    let base = build_bl_obj(&[("__unwind$1", DTOR_MSG), ("__unwind$2", DTOR_STR)]);
    let got = partners(&target, &base, &["fn_82345678"]);
    assert_eq!(
        got[0].0, "__unwind$1",
        "with no name agreement the pairing must be exactly what it always was"
    );
    assert!(got[0].1 < 100.0, "a genuinely wrong callee must still be charged under name_check");
}

#[test]
fn choice_is_independent_of_emission_order() {
    // DETERMINISM. Same three base funclets, emitted in the reverse order. The
    // pairing is a pure function of the object contents, so the answer must not move.
    let target = build_bl_obj(&[("fn_82345678", DTOR_LIST)]);
    let forward = build_bl_obj(&[
        ("__unwind$1", DTOR_MSG),
        ("__unwind$2", DTOR_STR),
        ("__unwind$3", DTOR_LIST),
    ]);
    let reverse = build_bl_obj(&[
        ("__unwind$3", DTOR_LIST),
        ("__unwind$2", DTOR_STR),
        ("__unwind$1", DTOR_MSG),
    ]);
    let a = partners(&target, &forward, &["fn_82345678"]);
    let b = partners(&target, &reverse, &["fn_82345678"]);
    assert_eq!(a[0].0, "__unwind$3");
    assert_eq!(a, b, "emission order must not change the pairing");
}

#[test]
fn placeholder_target_name_carries_no_evidence() {
    // The target side's `fn_<hex>` callees were never identified, so there is nothing
    // to verify ours against — `reloc_eq` forgives such a site under name_check and
    // the tiebreaker must likewise read no evidence from it, leaving the zip in
    // charge. Were placeholders treated as real names, EVERY base candidate would
    // "conflict" and the tiebreaker would abstain for a different reason; this test
    // pins that the abstention is the zip's, i.e. the historical answer.
    let target = build_bl_obj(&[("fn_82345678", "fn_8250b510")]);
    let base = build_bl_obj(&[("__unwind$1", DTOR_MSG), ("__unwind$2", DTOR_LIST)]);
    let got = partners(&target, &base, &["fn_82345678"]);
    assert_eq!(got[0].0, "__unwind$1", "an unidentified target callee decides nothing");
    assert_eq!(got[0].1, 100.0, "and a placeholder target name is not charged under name_check");
}
