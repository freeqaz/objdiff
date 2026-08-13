use std::collections::{BTreeSet, HashMap};
use std::io::BufRead;

use regex::Regex;

/// The symbol-equivalence relation parsed from an ICF map file.
///
/// # What this is
///
/// A symmetric, reflexive-on-members, deliberately NON-transitive relation:
/// [`aliases`](Self::aliases)`(a, b)` is true iff some address group in the map
/// file contains both `a` and `b`. That is exactly the set of assertions the
/// file makes — each group of lines sharing an address asserts "any of these
/// spellings may denote the body at this address" — rendered with nothing added
/// and nothing dropped.
///
/// Internally this is the adjacency relation of the co-location graph: each
/// name maps to the union of every group it appears in (a `BTreeSet`, so
/// iteration order, `canonical`, and `Debug` output are deterministic). A
/// per-name *single* group would be a partition-shaped answer to a pairwise
/// question; `reloc_eq` only ever asks "may name A stand in for name B?", and
/// adjacency answers precisely that.
///
/// # What this deliberately is not
///
/// * **Not a choice.** A real linker map gives every symbol one address, so the
///   relation is a partition and no question arises. The synthetic maps
///   rb3-xenon and dc3 generate (`icf_aliases.map`, rendered from
///   `symbol_aliases.json`) can and do emit one name at several addresses,
///   because the alias data behind them is a many-to-many relation and the
///   `.map` format can only express one group per address. An earlier build
///   picked ONE group per name — first the last group a seeded `HashMap` walk
///   happened to visit (nondeterministic: the same binary on the same map could
///   score a function 100% one run and charge a `[sym]` mismatch the next),
///   then, deterministically, the first group in file order. Both drop
///   file-asserted pairs, and which pairs survive depends on the order the
///   generator happened to emit groups in. Order of assertion is not evidence;
///   the union keeps every asserted pair and is invariant under permuting the
///   file's groups.
/// * **Not the transitive closure.** Two names that never share an address stay
///   non-equivalent even when they share a neighbor. The co-location evidence
///   these maps carry (bodies identical modulo relocations) is not transitive
///   in the property `reloc_eq` guards — callee identity: two retail survivors
///   whose bodies both masked-match one of our spellings can still call
///   different functions through their relocations, so widening survivor↔
///   survivor would fabricate an alias invisible to the default
///   `functionRelocDiffs=none` ruler by construction. Closure is a DATA
///   decision with its own evidence bar: dc3's generator takes it (its groups
///   are already closure classes, so this parser's refusal costs it nothing),
///   rb3-xenon's refuses it. The parser has no evidence of its own and takes no
///   position: it hands on the relation the generator asserted, exactly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolEquivalences {
    /// name → union of every multi-symbol address group containing it (self
    /// included). Names that never share an address are absent.
    adjacency: HashMap<String, BTreeSet<String>>,
}

impl SymbolEquivalences {
    /// May `a` stand in for `b` (or vice versa)? True iff the map file asserts
    /// them co-located at some address. Symmetric by construction — the
    /// adjacency sets are built from unordered groups — so callers need no
    /// two-way lookup. Names never seen in a group alias nothing (a name is not
    /// even self-aliased unless it appears in some multi-symbol group; callers
    /// compare for plain equality first).
    pub fn aliases(&self, a: &str, b: &str) -> bool {
        self.adjacency.get(a).is_some_and(|s| s.contains(b))
    }

    /// Deterministic representative for `name`: the lexicographically smallest
    /// member of its adjacency set (which includes `name` itself), or `name`
    /// unchanged if it appears in no group.
    ///
    /// This is a KEYING HEURISTIC for the opt-in case-B promotion index, not
    /// part of the forgiveness semantics. Keying by a representative forces an
    /// equivalence relation, and the relation here is deliberately not
    /// transitive, so no labeling can be exact: two names asserted equivalent
    /// may get different representatives (a missed index collision — the pass
    /// misses a candidate, conservative), and two names NOT asserted equivalent
    /// may share one through a common neighbor (a spurious index collision —
    /// screened downstream by the case-B pass's unique-retail-VA, oracle
    /// own-TU, and byte-masked-equality gates). An exact scheme would key the
    /// index on the relocation-masked bytes alone and verify reloc names
    /// pairwise via [`aliases`](Self::aliases) at lookup; that redesign is
    /// intentionally out of scope here.
    pub fn canonical<'a>(&'a self, name: &'a str) -> &'a str {
        match self.adjacency.get(name).and_then(|s| s.first()) {
            Some(min) => min.as_str(),
            None => name,
        }
    }

    /// Number of names that appear in at least one multi-symbol group.
    pub fn len(&self) -> usize {
        self.adjacency.len()
    }

    pub fn is_empty(&self) -> bool {
        self.adjacency.is_empty()
    }

    /// Record one address group's assertion: every pair of names in `group` may
    /// stand in for each other.
    fn add_group(&mut self, group: &[String]) {
        for sym in group {
            self.adjacency.entry(sym.clone()).or_default().extend(group.iter().cloned());
        }
    }
}

/// Parse an MSVC linker map file into the ICF symbol-equivalence relation.
///
/// Only addresses with multiple symbols (ICF-merged) contribute; see
/// [`SymbolEquivalences`] for what the result means and what it refuses to be.
pub fn parse_msvc_map(reader: impl BufRead) -> SymbolEquivalences {
    let pattern =
        Regex::new(r"^\s*\d{4}:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{8})\s+").expect("invalid regex");

    // Bucket lines by address. The HashMap is only a lookup; the result is a
    // union over unordered groups, so no iteration order can reach the output
    // (proven by `line_order_is_not_evidence` below).
    let mut address_to_symbols: HashMap<String, Vec<String>> = HashMap::new();

    for line in reader.lines() {
        let Ok(line) = line else { continue };
        if let Some(caps) = pattern.captures(&line) {
            let symbol = caps[1].to_string();
            let address = caps[2].to_uppercase();
            address_to_symbols.entry(address).or_default().push(symbol);
        }
    }

    let mut equivalences = SymbolEquivalences::default();
    for symbols in address_to_symbols.values() {
        if symbols.len() > 1 {
            equivalences.add_group(symbols);
        }
    }
    equivalences
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_msvc_map_icf() {
        let map_content = "\
 0005:00001360       ??_GObjRef@@UAAPAXI@Z      82331360 f i App.obj
 0005:00001360       ??_EObjRef@@UAAPAXI@Z      82331360 f i App.obj
 0005:00002000       ?Foo@@YAXXZ                82332000 f   App.obj
 0005:00003000       ?Bar@@YAXXZ                82333000 f   App.obj
";
        let equivalences = parse_msvc_map(Cursor::new(map_content));

        // The two symbols at 82331360 are equivalent, both ways round.
        assert!(equivalences.aliases("??_GObjRef@@UAAPAXI@Z", "??_EObjRef@@UAAPAXI@Z"));
        assert!(equivalences.aliases("??_EObjRef@@UAAPAXI@Z", "??_GObjRef@@UAAPAXI@Z"));
        assert_eq!(equivalences.len(), 2);

        // Unique symbols alias nothing, and canonicalize to themselves.
        assert!(!equivalences.aliases("?Foo@@YAXXZ", "?Bar@@YAXXZ"));
        assert_eq!(equivalences.canonical("?Foo@@YAXXZ"), "?Foo@@YAXXZ");
    }

    #[test]
    fn test_parse_msvc_map_empty() {
        let equivalences = parse_msvc_map(Cursor::new(""));
        assert!(equivalences.is_empty());
    }

    /// A name at two addresses keeps BOTH groups' assertions. Under the
    /// rejected first-wins design this name was assigned only its first group,
    /// so `aliases("?Dup...", "?Second...")` answered false in one direction
    /// and the pair survived only through the caller's two-way lookup; under
    /// the original nondeterministic code the group was a per-process coin
    /// flip. This test fails on first-wins (the `?Second` membership below) and
    /// failed on roughly half of runs of the SAME binary before determinism.
    ///
    /// Run it many times in one process to make the old failure deterministic —
    /// each `parse_msvc_map` call builds fresh `HashMap`s with fresh seeds.
    #[test]
    fn test_parse_msvc_map_duplicate_address_unions() {
        let map_content = "\
 0005:00001360       ?Dup@@YAXXZ                82331360 f i App.obj
 0005:00001360       ?First@@YAXXZ              82331360 f i App.obj
 0005:00002000       ?Dup@@YAXXZ                82332000 f i App.obj
 0005:00002000       ?Second@@YAXXZ             82332000 f i App.obj
";
        for _ in 0..256 {
            let equivalences = parse_msvc_map(Cursor::new(map_content));
            // Both asserted pairs hold, in the name's OWN entry (no reliance on
            // a symmetric consumer). First-wins fails the second assertion.
            assert!(equivalences.aliases("?Dup@@YAXXZ", "?First@@YAXXZ"));
            assert!(equivalences.aliases("?Dup@@YAXXZ", "?Second@@YAXXZ"), "later group must not be dropped");
            assert!(equivalences.aliases("?First@@YAXXZ", "?Dup@@YAXXZ"));
            assert!(equivalences.aliases("?Second@@YAXXZ", "?Dup@@YAXXZ"));
        }
    }

    /// THE shape where first-wins and union give different reloc_eq answers
    /// even through a symmetric consumer: A and B each appear FIRST in their
    /// own earlier group, and co-occur only in a later group. The file asserts
    /// the pair (they share address 82333000); first-wins assigns A={A,X},
    /// B={B,Y} and drops it — a false `[sym]` charge for a file-asserted alias,
    /// manufactured by the order the generator emitted groups in. Zero such
    /// pairs exist in today's rb3-xenon (638,357 co-occurring pairs) and dc3
    /// (599,914) maps — their group shapes rescue first-wins via the symmetric
    /// lookup — which is an accident of shape, not a property of the design.
    #[test]
    fn test_pair_asserted_only_in_a_late_group_still_aliases() {
        let map_content = "\
 0005:00001000       ?A@@YAXXZ                  82331000 f i App.obj
 0005:00001000       ?X@@YAXXZ                  82331000 f i App.obj
 0005:00002000       ?B@@YAXXZ                  82332000 f i App.obj
 0005:00002000       ?Y@@YAXXZ                  82332000 f i App.obj
 0005:00003000       ?A@@YAXXZ                  82333000 f i App.obj
 0005:00003000       ?B@@YAXXZ                  82333000 f i App.obj
";
        let equivalences = parse_msvc_map(Cursor::new(map_content));
        // Asserted at 82333000; first-wins (with or without a symmetric
        // consumer) answers false in both directions.
        assert!(equivalences.aliases("?A@@YAXXZ", "?B@@YAXXZ"));
        assert!(equivalences.aliases("?B@@YAXXZ", "?A@@YAXXZ"));
        // The earlier groups still hold too.
        assert!(equivalences.aliases("?A@@YAXXZ", "?X@@YAXXZ"));
        assert!(equivalences.aliases("?B@@YAXXZ", "?Y@@YAXXZ"));
    }

    /// The union is NOT the transitive closure: two survivors that never share
    /// an address stay non-equivalent even though both fold a common spelling.
    /// This is the rb3-xenon star shape (one survivor + our folded spellings
    /// per group; 842 folded spellings span several groups in today's map). A
    /// closure design fails this test — and in doing so would tell reloc_eq
    /// that a `bl` to Survivor1 equals a `bl` to Survivor2, a fabricated alias
    /// the default `none` ruler could never surface.
    #[test]
    fn test_union_is_not_transitive_closure() {
        let map_content = "\
 0005:00001000       ?Survivor1@@YAXXZ          82331000 f i App.obj
 0005:00001000       ?Folded@@YAXXZ             82331000 f i App.obj
 0005:00002000       ?Survivor2@@YAXXZ          82332000 f i App.obj
 0005:00002000       ?Folded@@YAXXZ             82332000 f i App.obj
";
        let equivalences = parse_msvc_map(Cursor::new(map_content));
        assert!(equivalences.aliases("?Survivor1@@YAXXZ", "?Folded@@YAXXZ"));
        assert!(equivalences.aliases("?Survivor2@@YAXXZ", "?Folded@@YAXXZ"));
        assert!(!equivalences.aliases("?Survivor1@@YAXXZ", "?Survivor2@@YAXXZ"), "closure is a data decision the parser must not take");
        assert!(!equivalences.aliases("?Survivor2@@YAXXZ", "?Survivor1@@YAXXZ"));
    }

    /// The whole result must be reproducible: parsing the same bytes twice has
    /// to give the same equivalences. Before determinism this failed IN A
    /// SINGLE PROCESS — direct proof that the order was per-`HashMap` random
    /// rather than per-binary.
    #[test]
    fn test_parse_msvc_map_is_reproducible() {
        let map_content = "\
 0005:00001360       ?A@@YAXXZ                  82331360 f i App.obj
 0005:00001360       ?Shared@@YAXXZ             82331360 f i App.obj
 0005:00002000       ?B@@YAXXZ                  82332000 f i App.obj
 0005:00002000       ?Shared@@YAXXZ             82332000 f i App.obj
 0005:00003000       ?C@@YAXXZ                  82333000 f i App.obj
 0005:00003000       ?Shared@@YAXXZ             82333000 f i App.obj
";
        let first = parse_msvc_map(Cursor::new(map_content));
        for _ in 0..256 {
            assert_eq!(parse_msvc_map(Cursor::new(map_content)), first);
        }
    }

    /// The order the generator emits groups in is not evidence: permuting the
    /// file's groups must not change the relation. First-wins fails this test
    /// (reversed, `?Dup` keeps the OTHER group, so the parsed structures
    /// differ); union is invariant by construction.
    #[test]
    fn test_line_order_is_not_evidence() {
        let forward = "\
 0005:00001000       ?Dup@@YAXXZ                82331000 f i App.obj
 0005:00001000       ?First@@YAXXZ              82331000 f i App.obj
 0005:00002000       ?Dup@@YAXXZ                82332000 f i App.obj
 0005:00002000       ?Second@@YAXXZ             82332000 f i App.obj
";
        let reversed = "\
 0005:00002000       ?Dup@@YAXXZ                82332000 f i App.obj
 0005:00002000       ?Second@@YAXXZ             82332000 f i App.obj
 0005:00001000       ?Dup@@YAXXZ                82331000 f i App.obj
 0005:00001000       ?First@@YAXXZ              82331000 f i App.obj
";
        assert_eq!(parse_msvc_map(Cursor::new(forward)), parse_msvc_map(Cursor::new(reversed)));
    }

    /// `canonical` is the lexicographic minimum over EVERY group the name
    /// appears in, so it too is independent of group order. First-wins fails
    /// this test: it would canonicalize `?M@@YAXXZ` through its first group
    /// only, giving `?M@@YAXXZ` instead of `?A@@YAXXZ`.
    #[test]
    fn test_canonical_spans_all_groups() {
        let map_content = "\
 0005:00001000       ?M@@YAXXZ                  82331000 f i App.obj
 0005:00001000       ?Z@@YAXXZ                  82331000 f i App.obj
 0005:00002000       ?A@@YAXXZ                  82332000 f i App.obj
 0005:00002000       ?M@@YAXXZ                  82332000 f i App.obj
";
        let equivalences = parse_msvc_map(Cursor::new(map_content));
        assert_eq!(equivalences.canonical("?M@@YAXXZ"), "?A@@YAXXZ");
        assert_eq!(equivalences.canonical("?Z@@YAXXZ"), "?M@@YAXXZ");
        assert_eq!(equivalences.canonical("?A@@YAXXZ"), "?A@@YAXXZ");
        // A name in no group is its own canonical.
        assert_eq!(equivalences.canonical("?Absent@@YAXXZ"), "?Absent@@YAXXZ");
    }

    #[test]
    fn test_parse_msvc_map_three_way_merge() {
        let map_content = "\
 0005:00001360       ?A@@YAXXZ                  82331360 f i App.obj
 0005:00001360       ?B@@YAXXZ                  82331360 f i App.obj
 0005:00001360       ?C@@YAXXZ                  82331360 f i App.obj
";
        let equivalences = parse_msvc_map(Cursor::new(map_content));
        assert_eq!(equivalences.len(), 3);
        assert!(equivalences.aliases("?A@@YAXXZ", "?B@@YAXXZ"));
        assert!(equivalences.aliases("?A@@YAXXZ", "?C@@YAXXZ"));
        assert!(equivalences.aliases("?B@@YAXXZ", "?C@@YAXXZ"));
    }
}
