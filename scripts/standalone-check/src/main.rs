//! Exercises objdiff-core as an EXTERNAL consumer would: minimal features, no
//! workspace feature unification. Compiling at all covers the compile-time
//! defects; the assertions below cover the runtime ones, which a build alone
//! cannot see (a regex whose classes need an undeclared feature compiles fine
//! and panics on first use).
//!
//! Exit 0 = objdiff-core is usable standalone. Any panic or non-zero exit is a
//! packaging defect in objdiff-core, not in this file.

use std::io::Cursor;

/// Two symbols ICF-folded onto address 00001000, one alone at 00002000.
/// Leading whitespace and the `NNNN:` section prefix are load-bearing: they are
/// what the parser's `\s` and `\d` classes match.
const MAP: &str = "\
 Address         Publics by Value              Rva+Base
 0001:00000000   ?Alpha@@YAXXZ             00001000     f   a.obj
 0001:00000000   ?Beta@@YAXXZ              00001000     f   b.obj
 0001:00000010   ?Gamma@@YAXXZ             00002000     f   c.obj
";

fn main() {
    let eq = objdiff_core::obj::map_file::parse_msvc_map(Cursor::new(MAP));

    // If `regex`'s Perl classes are unavailable, parse_msvc_map panics before
    // reaching here. If it somehow returned empty instead, that is equally a
    // failure: an empty relation would silently disable ICF aliasing in every
    // consumer.
    assert!(
        eq.aliases("?Alpha@@YAXXZ", "?Beta@@YAXXZ"),
        "co-located symbols did not alias — the map parse produced nothing usable"
    );
    assert!(
        !eq.aliases("?Alpha@@YAXXZ", "?Gamma@@YAXXZ"),
        "symbols at different addresses must not alias"
    );
    assert_eq!(eq.len(), 2, "only the folded group's members belong in the relation");

    println!("objdiff-core standalone check: ok");
}
