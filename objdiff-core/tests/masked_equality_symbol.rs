//! Symbol/report-level masked-equality disclosure fixture (V1 §S1b).
//!
//! S1 disclosed masking at the two PER-INSTRUCTION-ROW normalization sites
//! (reloc-mode relaxation + the MSVC X360 FP-anchor slip) via `masked_equal`
//! bits and the `masked_equal_rows` / `reloc_ignored_rows` counters. S1b closes
//! the two remaining SYMBOL / REPORT-granularity masking sites the register
//! named, neither of which a per-row bit can express:
//!
//!   1. **Funclet-pairing** (`pair_funclets_by_bytes`): MSVC EH funclets paired
//!      by masked byte signature (reloc bytes zeroed) and/or over-subscribed
//!      byte-identical funclets paired many-to-one. The identity rests on a
//!      masked signature, not a name. Disclosed as `SymbolDiff.masked_equal_symbol`
//!      and surfaced on the CLI `-f json` / batch JSONL path.
//!
//!   2. **case-B global byte-equality second pass** (`reconcile_global_byte_matches`,
//!      report-driver only, opt-in): promotes an unmatched named method to 100%
//!      when its retail body is byte-identical to a body carved into a foreign
//!      unit's target span. Disclosed as `ReportItem.masked_equal` plus the
//!      `Measures.masked_equal_functions` report-level counter.
//!
//! Both are disclosure-only: no `match_percent` / `diff_score` is changed.

#![cfg(all(feature = "ppc", feature = "bindings"))]

use object::{
    Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope,
    write::{Object as WriteObject, StandardSection, Symbol, SymbolSection},
};
use objdiff_core::{diff, obj};

/// Build a minimal big-endian PPC ELF relocatable object with a single code
/// symbol `name` covering `code`, no relocations. Two objects built with the
/// same `code` are byte-identical in `.text`; only the symbol name differs.
fn build_func_obj(name: &str, code: &[u8]) -> Vec<u8> {
    let mut obj = WriteObject::new(BinaryFormat::Elf, Architecture::PowerPc, Endianness::Big);
    let text = obj.section_id(StandardSection::Text);
    let off = obj.append_section_data(text, code, 4);
    let _sym = obj.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: off,
        size: code.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    obj.write().expect("write ELF object")
}

/// Diff two objects and return `(match_percent, masked_equal_symbol)` for the
/// named symbol on the target side.
fn diff_symbol(target_bytes: &[u8], base_bytes: &[u8], name: &str) -> (f32, bool) {
    let diff_config = diff::DiffObjConfig::default();
    let mapping_config = diff::MappingConfig::default();
    let target =
        obj::read::parse(target_bytes, &diff_config, diff::DiffSide::Target).expect("parse target");
    let base =
        obj::read::parse(base_bytes, &diff_config, diff::DiffSide::Base).expect("parse base");
    let result =
        diff::diff_objs(Some(&target), Some(&base), None, &diff_config, &mapping_config)
            .expect("diff objects");
    let target_diff = result.left.as_ref().expect("target diff present");
    let idx = target.symbols.iter().position(|s| s.name == name).expect("symbol present");
    let sym = &target_diff.symbols[idx];
    (sym.match_percent.expect("match percent present"), sym.masked_equal_symbol)
}

/// li r3,0 ; blr — 8 identical bytes, no relocations.
const CODE8: [u8; 8] = [0x38, 0x60, 0x00, 0x00, 0x4e, 0x80, 0x00, 0x20];

#[test]
fn funclet_paired_symbol_is_disclosed_named_control_is_clear() {
    // --- Funclet fallback: `fn_<addr>` (target, dtk-stripped COMDAT name) vs
    // `__unwind$NNN` (base, MSVC EH funclet). No name match exists, so the pair
    // is produced ONLY by `pair_funclets_by_bytes` on the masked byte signature.
    let target = build_func_obj("fn_82345678", &CODE8);
    let base = build_func_obj("__unwind$42", &CODE8);
    let (pct, masked) = diff_symbol(&target, &base, "fn_82345678");
    assert_eq!(pct, 100.0, "byte-identical funclets score 100%");
    assert!(
        masked,
        "a symbol paired only via funclet byte-signature fallback must set masked_equal_symbol"
    );

    // --- Control: a normally-NAMED symbol (`func` on both sides) that is
    // genuinely byte-identical is paired by NAME, not funclet fallback. Same
    // 100% score, but the masking signal must be clear.
    let target = build_func_obj("func", &CODE8);
    let base = build_func_obj("func", &CODE8);
    let (pct, masked) = diff_symbol(&target, &base, "func");
    assert_eq!(pct, 100.0, "byte-identical named symbols score 100%");
    assert!(!masked, "a name-matched, genuinely-identical symbol must NOT set masked_equal_symbol");
}

// ─────────────────────────────────────────────────────────────────────────────
// case-B report-level disclosure.
// ─────────────────────────────────────────────────────────────────────────────

use std::collections::{HashMap, HashSet};

use objdiff_core::bindings::report::{Measures, ReportItem, ReportUnit, ReportUnitMetadata};

#[test]
fn caseb_promotion_sets_report_masked_equal_and_counter() {
    // 48 identical bytes (> CASEB_STUB_MAX = 44), no relocations, so the named
    // base method and the anonymous foreign retail body share an identical
    // reloc-masked + reloc-name signature.
    let body: Vec<u8> = [0x60u8, 0x00, 0x00, 0x00].repeat(12); // 48 bytes of `nop`

    // Claiming unit "foo": our compiled BASE obj DEFINES the mangled method.
    let foo_base_bytes = build_func_obj("?Bar@Foo@@QAEXXZ", &body);
    // Foreign unit "other": its carved TARGET obj physically holds the
    // byte-identical retail body as an anonymous `fn_<VA>`.
    let other_target_bytes = build_func_obj("fn_82345678", &body);

    let cfg = diff::DiffObjConfig::default();
    let foo_base = obj::read::parse(&foo_base_bytes, &cfg, diff::DiffSide::Base).expect("foo base");
    let other_target =
        obj::read::parse(&other_target_bytes, &cfg, diff::DiffSide::Target).expect("other target");

    let unit_objs = vec![
        diff::UnitObjs { unit_name: "foo".to_string(), target: None, base: Some(foo_base) },
        diff::UnitObjs {
            unit_name: "other".to_string(),
            target: Some(other_target),
            base: None,
        },
    ];

    // Report units. "foo" has the still-<100% case-B method plus a genuinely
    // matched control at 100% (the disclosure signal must stay clear on it).
    let mut units = vec![
        ReportUnit {
            name: "foo".to_string(),
            measures: Some(Measures {
                total_functions: 2,
                matched_functions: 1, // the control below
                total_code: 80,
                matched_code: 32,
                ..Default::default()
            }),
            sections: vec![],
            functions: vec![
                ReportItem {
                    name: "?Bar@Foo@@QAEXXZ".to_string(),
                    size: 48,
                    fuzzy_match_percent: 40.0,
                    match_percent_normalized: Some(40.0),
                    metadata: None,
                    address: None,
                    masked_equal: None,
                },
                ReportItem {
                    name: "?Ok@Foo@@QAEXXZ".to_string(),
                    size: 32,
                    fuzzy_match_percent: 100.0,
                    match_percent_normalized: Some(100.0),
                    metadata: None,
                    address: None,
                    masked_equal: None,
                },
            ],
            metadata: Some(ReportUnitMetadata {
                source_path: Some("src/foo.cpp".to_string()),
                ..Default::default()
            }),
        },
        ReportUnit {
            name: "other".to_string(),
            measures: Some(Measures::default()),
            sections: vec![],
            functions: vec![],
            metadata: Some(ReportUnitMetadata {
                source_path: Some("src/other.cpp".to_string()),
                ..Default::default()
            }),
        },
    ];

    let equivalences: HashMap<String, HashSet<String>> = HashMap::new();
    // Rule 3 oracle: VA 0x82345678 attributes to the claiming unit's TU ("foo")
    // with similarity >= CASEB_ORACLE_SIM_MIN.
    let mut oracle: diff::VaOracle = HashMap::new();
    oracle.insert(0x8234_5678, ("foo".to_string(), 0.9));

    let promotions =
        diff::reconcile_global_byte_matches(&mut units, &unit_objs, &equivalences, &oracle);

    assert_eq!(promotions.len(), 1, "exactly one honest case-B promotion");
    assert_eq!(promotions[0].unit_name, "foo");
    assert_eq!(promotions[0].virtual_address, 0x8234_5678);

    let foo = &units[0];
    let method = &foo.functions[0];
    assert_eq!(method.fuzzy_match_percent, 100.0, "case-B method promoted to 100%");
    assert_eq!(method.match_percent_normalized, Some(100.0));
    assert_eq!(
        method.masked_equal,
        Some(true),
        "a case-B-promoted item must disclose masked_equal"
    );

    // Control: the genuinely-matched item is untouched — signal clear.
    let control = &foo.functions[1];
    assert_eq!(
        control.masked_equal, None,
        "a normally-matched 100% item must NOT be flagged masked_equal"
    );

    // Report-level counter: the unit's measures count the promotion, which
    // aggregates up to report/category totals via `AddAssign`.
    let m = foo.measures.as_ref().expect("foo measures");
    assert_eq!(m.masked_equal_functions, 1, "unit measures count the case-B promotion");
    assert_eq!(m.matched_functions, 2, "control (1) + case-B promotion (1)");
}
