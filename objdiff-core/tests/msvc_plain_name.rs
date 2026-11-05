//! PDB plain-name equivalence for MSVC internal-linkage symbols (4.2.10).
//!
//! A dtk-split target names a `static` C++ function by its PDB `S_LPROC32`
//! spelling (`ds_data::CBImpl<3,char,unsigned char>`); our compiled object can
//! only carry its decoration (`??$CBImpl@$02DE@ds_data@@YAHPBK0@Z`). Exact name
//! comparison never paired the two, and every relocation pointing at the
//! function was charged as a wrong target. Measured on cea-decomp (2026-11-04):
//! 2,856 such target rows, none ever matched.
//!
//! These tests pin, on real Xenon-style COFF objects:
//!
//!   1. the plain-named target function pairs with the decorated static, and a
//!      caller's `bl` to it is no longer charged (name_only and name_check),
//!      and a data relocation to it matches too;
//!   2. whitespace in the PDB spelling does not matter (`<3, char, ...>`,
//!      `TSTR<char> >`);
//!   3. ambiguity is refused: two static overloads undecorating to one plain
//!      name pair with nothing, and neither does a plain name the target holds
//!      twice;
//!   4. an EXTERNAL decorated symbol never stands in for a plain name (the PDB
//!      would have given it a decorated public), but an anonymous-namespace one
//!      does;
//!   5. two decorated names are never equated through their undecorations;
//!   6. the option off, and any non-COFF object, are exact no-ops.
//!
//! All decorations below are verbatim output of the X360 cl.exe 16.00.11886.00
//! on a probe file (storage classes as that compiler emitted them).

#![cfg(feature = "ppc")]

use objdiff_core::{diff, obj};
use object::{
    Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope,
    write::{Object as WriteObject, Relocation, StandardSection, Symbol, SymbolSection},
};

/// `li r3,3 ; blr`
const LEAF: [u8; 8] = [0x38, 0x60, 0x00, 0x03, 0x4e, 0x80, 0x00, 0x20];
/// `bl 0 ; blr` (the displacement lives in the relocation)
const CALL: [u8; 8] = [0x48, 0x00, 0x00, 0x01, 0x4e, 0x80, 0x00, 0x20];

const CALLER: &str = "?use@@YAHH@Z";
/// A leading function on the base side only, so the callee's ADDRESS differs
/// between the objects and a data relocation can only match by name (data
/// relocations otherwise also match on equal target addresses).
const PAD: &str = "?pad@@YAXXZ";
const TABLE: &str = "?tbl@@3PAP6AHPBK0@ZA";

/// One defined function or data object of a fixture.
struct Def<'a> {
    name: &'a str,
    /// `SymbolScope::Compilation` is COFF storage class STATIC (internal
    /// linkage); `Dynamic` is EXTERNAL.
    scope: SymbolScope,
}

fn local(name: &str) -> Def<'_> { Def { name, scope: SymbolScope::Compilation } }
fn external(name: &str) -> Def<'_> { Def { name, scope: SymbolScope::Dynamic } }

/// Build an object holding `leaves` (each `li r3,3; blr`), then `CALLER`
/// (`bl <callee>; blr`) and a `TABLE` data word relocated against `callee`.
/// `callee` must be one of `leaves`.
fn build(format: BinaryFormat, leaves: &[Def], callee: &str) -> Vec<u8> {
    let mut obj = WriteObject::new(format, Architecture::PowerPc, Endianness::Big);
    let text = obj.section_id(StandardSection::Text);
    let data = obj.section_id(StandardSection::Data);
    let mut callee_id = None;
    for leaf in leaves {
        let off = obj.append_section_data(text, &LEAF, 4);
        let id = obj.add_symbol(Symbol {
            name: leaf.name.as_bytes().to_vec(),
            value: off,
            size: LEAF.len() as u64,
            kind: SymbolKind::Text,
            scope: leaf.scope,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        if leaf.name == callee {
            callee_id = Some(id);
        }
    }
    let callee_id = callee_id.expect("callee is one of the leaves");
    let off = obj.append_section_data(text, &CALL, 4);
    obj.add_symbol(Symbol {
        name: CALLER.as_bytes().to_vec(),
        value: off,
        size: CALL.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    let (call_flags, data_flags) = match format {
        BinaryFormat::Coff => (
            object::RelocationFlags::Coff { typ: object::pe::IMAGE_REL_PPC_REL24 },
            object::RelocationFlags::Coff { typ: object::pe::IMAGE_REL_PPC_ADDR32 },
        ),
        _ => (
            object::RelocationFlags::Elf { r_type: object::elf::R_PPC_REL24 },
            object::RelocationFlags::Elf { r_type: object::elf::R_PPC_ADDR32 },
        ),
    };
    obj.add_relocation(text, Relocation {
        offset: off,
        symbol: callee_id,
        addend: 0,
        flags: call_flags,
    })
    .expect("add bl relocation");
    let data_off = obj.append_section_data(data, &[0; 4], 4);
    obj.add_symbol(Symbol {
        name: TABLE.as_bytes().to_vec(),
        value: data_off,
        size: 4,
        kind: SymbolKind::Data,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(data),
        flags: SymbolFlags::None,
    });
    obj.add_relocation(data, Relocation {
        offset: data_off,
        symbol: callee_id,
        addend: 0,
        flags: data_flags,
    })
    .expect("add data relocation");
    obj.write().expect("write object")
}

fn coff(leaves: &[Def], callee: &str) -> Vec<u8> { build(BinaryFormat::Coff, leaves, callee) }

struct Outcome {
    /// Base partner of each queried target symbol (`None` = unpaired).
    partners: Vec<Option<String>>,
    /// Match percent of the target `CALLER` (whose only relocation is the `bl`).
    caller: f32,
    /// Match percent of the target `TABLE` data object.
    table: f32,
}

fn diff_with(
    target_bytes: &[u8],
    base_bytes: &[u8],
    queried: &[&str],
    diff_config: &diff::DiffObjConfig,
) -> Outcome {
    let target =
        obj::read::parse(target_bytes, diff_config, diff::DiffSide::Target).expect("parse target");
    let base = obj::read::parse(base_bytes, diff_config, diff::DiffSide::Base).expect("parse base");
    let result = diff::diff_objs(
        Some(&target),
        Some(&base),
        None,
        diff_config,
        &diff::MappingConfig::default(),
    )
    .expect("diff objects");
    let left = result.left.as_ref().expect("target diff present");
    let index = |name: &str| {
        target.symbols.iter().position(|s| s.name == name).expect("target symbol present")
    };
    Outcome {
        partners: queried
            .iter()
            .map(|n| left.symbols[index(n)].target_symbol.map(|r| base.symbols[r].name.clone()))
            .collect(),
        caller: left.symbols[index(CALLER)].match_percent.expect("caller scored"),
        table: left.symbols[index(TABLE)].match_percent.expect("table scored"),
    }
}

fn config(relocs: diff::FunctionRelocDiffs) -> diff::DiffObjConfig {
    diff::DiffObjConfig { function_reloc_diffs: relocs, ..Default::default() }
}

fn name_only() -> diff::DiffObjConfig { config(diff::FunctionRelocDiffs::NameOnly) }

const CB_PLAIN: &str = "ds_data::CBImpl<3,char,unsigned char>";
const CB_DECORATED: &str = "??$CBImpl@$02DE@ds_data@@YAHPBK0@Z";

#[test]
fn plain_target_pairs_with_decorated_static_and_its_callers_match() {
    let target = coff(&[external(CB_PLAIN)], CB_PLAIN);
    let base = coff(&[external(PAD), local(CB_DECORATED)], CB_DECORATED);
    for relocs in [diff::FunctionRelocDiffs::NameOnly, diff::FunctionRelocDiffs::NameCheck] {
        let out = diff_with(&target, &base, &[CB_PLAIN], &config(relocs));
        assert_eq!(out.partners, vec![Some(CB_DECORATED.to_string())], "{relocs:?}");
        assert_eq!(out.caller, 100.0, "{relocs:?}: the bl target is the same function");
        assert_eq!(out.table, 100.0, "{relocs:?}: the data relocation is the same function");
    }
}

#[test]
fn option_off_is_the_historical_behaviour() {
    let target = coff(&[external(CB_PLAIN)], CB_PLAIN);
    let base = coff(&[external(PAD), local(CB_DECORATED)], CB_DECORATED);
    let off = diff::DiffObjConfig { msvc_plain_name_equivalence: false, ..name_only() };
    let out = diff_with(&target, &base, &[CB_PLAIN], &off);
    assert_eq!(out.partners, vec![None]);
    assert!(out.caller < 100.0, "the bl is charged as a wrong target ({})", out.caller);
    assert!(out.table < 100.0, "the data relocation is charged ({})", out.table);
}

#[test]
fn non_coff_objects_are_untouched() {
    // Identical fixture, ELF container: the table is never built.
    let target = build(BinaryFormat::Elf, &[external(CB_PLAIN)], CB_PLAIN);
    let base = build(BinaryFormat::Elf, &[external(PAD), local(CB_DECORATED)], CB_DECORATED);
    let out = diff_with(&target, &base, &[CB_PLAIN], &name_only());
    assert_eq!(out.partners, vec![None]);
    assert!(out.caller < 100.0);
    assert!(out.table < 100.0);
}

#[test]
fn whitespace_in_the_pdb_spelling_is_normalised() {
    let spaced = "ds_data::CBImpl<3, char, unsigned char>";
    let target = coff(&[external(spaced)], spaced);
    let base = coff(&[local(CB_DECORATED)], CB_DECORATED);
    let out = diff_with(&target, &base, &[spaced], &name_only());
    assert_eq!(out.partners, vec![Some(CB_DECORATED.to_string())]);
    assert_eq!(out.caller, 100.0);

    // Nested template: undname writes `TSTR<char> >`, the demangler `TSTR<char>>`.
    let nested_plain = "ds_data::Conv<ds_data::TSTR<char>,ds_data::TSTR<ds_data::TSTR<char> > >";
    let nested = "??$Conv@U?$TSTR@D@ds_data@@U?$TSTR@U?$TSTR@D@ds_data@@@2@@ds_data@@YAHPBU?$TSTR@D@0@PAU?$TSTR@U?$TSTR@D@ds_data@@@0@@Z";
    let target = coff(&[external(nested_plain)], nested_plain);
    let base = coff(&[local(nested)], nested);
    let out = diff_with(&target, &base, &[nested_plain], &name_only());
    assert_eq!(out.partners, vec![Some(nested.to_string())]);
    assert_eq!(out.caller, 100.0);
}

#[test]
fn static_overloads_are_ambiguous_and_refused() {
    // `static int Ovl(int)` and `static int Ovl(float)` both undecorate to
    // `ds_data::Ovl`; the PDB plain name cannot say which one it is.
    let ovl_int = "?Ovl@ds_data@@YAHH@Z";
    let ovl_float = "?Ovl@ds_data@@YAHM@Z";
    let target = coff(&[external("ds_data::Ovl")], "ds_data::Ovl");
    let base = coff(&[local(ovl_int), local(ovl_float)], ovl_int);
    let out = diff_with(&target, &base, &["ds_data::Ovl"], &name_only());
    assert_eq!(out.partners, vec![None]);
    assert!(out.caller < 100.0);

    // An EXTERNAL overload sharing the key makes it just as ambiguous.
    let base = coff(&[local(ovl_int), external(ovl_float)], ovl_int);
    let out = diff_with(&target, &base, &["ds_data::Ovl"], &name_only());
    assert_eq!(out.partners, vec![None]);
    assert!(out.caller < 100.0);

    // The other direction: the target holds the plain name twice (two static
    // overloads in the PDB), we hold one decoration.
    let single = "?Single@ds_data@@YAHH@Z";
    let target =
        coff(&[external("ds_data::Single"), external("ds_data::Single")], "ds_data::Single");
    let base = coff(&[local(single)], single);
    let out = diff_with(&target, &base, &[], &name_only());
    assert!(out.caller < 100.0, "an ambiguous plain name decides nothing ({})", out.caller);
}

#[test]
fn external_decorated_symbols_never_stand_in_for_a_plain_name() {
    // An external function has a decorated public record in the PDB, so a
    // plain target name can only be an internal-linkage one.
    let single = "?Single@ds_data@@YAHH@Z";
    let target = coff(&[external("ds_data::Single")], "ds_data::Single");
    let base = coff(&[external(single)], single);
    let out = diff_with(&target, &base, &["ds_data::Single"], &name_only());
    assert_eq!(out.partners, vec![None]);
    assert!(out.caller < 100.0);

    // ...but an anonymous-namespace function is internal whatever its storage
    // class (cl.exe emits it EXTERNAL, uniquified by `?A0x<hash>`).
    let anon = "?anonFn@?A0xa2a4621a@@YAHH@Z";
    let anon_plain = "`anonymous namespace'::anonFn";
    let target = coff(&[external(anon_plain)], anon_plain);
    let base = coff(&[external(anon)], anon);
    let out = diff_with(&target, &base, &[anon_plain], &name_only());
    assert_eq!(out.partners, vec![Some(anon.to_string())]);
    assert_eq!(out.caller, 100.0);
}

#[test]
fn two_decorated_names_are_never_equated_through_their_undecorations() {
    let ovl_int = "?Ovl@ds_data@@YAHH@Z";
    let ovl_float = "?Ovl@ds_data@@YAHM@Z";
    let target = coff(&[external(ovl_int)], ovl_int);
    let base = coff(&[local(ovl_float)], ovl_float);
    let out = diff_with(&target, &base, &[ovl_int], &name_only());
    assert_eq!(out.partners, vec![None]);
    assert!(out.caller < 100.0);
}

#[test]
fn an_exact_name_partner_blocks_the_equivalence() {
    // The target holds the decoration too (as a public), alongside a plain name
    // undecorating to the same key: the key is no longer unambiguous on the
    // target side, so only the exact-name pair forms.
    let target = coff(&[external(CB_PLAIN), external(CB_DECORATED)], CB_PLAIN);
    let base = coff(&[local(CB_DECORATED)], CB_DECORATED);
    let out = diff_with(&target, &base, &[CB_PLAIN, CB_DECORATED], &name_only());
    assert_eq!(out.partners, vec![None, Some(CB_DECORATED.to_string())]);
    assert!(out.caller < 100.0);
}

#[test]
fn dynamic_initializers_use_the_pdb_spelling() {
    for (plain, decorated) in [
        ("D3D::`dynamic initializer for 'g_RGB''", "??__Eg_RGB@D3D@@YAXXZ"),
        ("`dynamic initializer for 'gStatic''", "??__EgStatic@@YAXXZ"),
        (
            "`GetPresets'::`2'::`dynamic atexit destructor for 'presets''",
            "??__Fpresets@?1??GetPresets@@YAAAUPOOL@@XZ@YAXXZ",
        ),
        (
            "`dynamic initializer for 'MEM<char,50>::pool''",
            "??__E?pool@?$MEM@D$0DC@@@2UPOOL@@A@@YAXXZ",
        ),
    ] {
        let target = coff(&[external(plain)], plain);
        let base = coff(&[local(decorated)], decorated);
        let out = diff_with(&target, &base, &[plain], &name_only());
        assert_eq!(out.partners, vec![Some(decorated.to_string())], "{plain}");
        assert_eq!(out.caller, 100.0, "{plain}");
    }
}
