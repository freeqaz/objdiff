use std::collections::{HashMap, HashSet};
use std::io::BufRead;

use regex::Regex;

/// Parse an MSVC linker map file and return ICF equivalence groups.
///
/// Each symbol name maps to the set of all symbol names sharing the same address.
/// Only addresses with multiple symbols (ICF-merged) produce entries.
pub fn parse_msvc_map(reader: impl BufRead) -> HashMap<String, HashSet<String>> {
    let pattern = Regex::new(r"^\s*\d{4}:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{8})\s+")
        .expect("invalid regex");

    let mut address_to_symbols: HashMap<String, Vec<String>> = HashMap::new();

    for line in reader.lines() {
        let Ok(line) = line else { continue };
        if let Some(caps) = pattern.captures(&line) {
            let symbol = caps[1].to_string();
            let address = caps[2].to_uppercase();
            address_to_symbols.entry(address).or_default().push(symbol);
        }
    }

    // Build equivalence map: only for addresses with multiple symbols
    let mut equivalences: HashMap<String, HashSet<String>> = HashMap::new();
    for (_addr, symbols) in &address_to_symbols {
        if symbols.len() > 1 {
            let group: HashSet<String> = symbols.iter().cloned().collect();
            for sym in symbols {
                equivalences.insert(sym.clone(), group.clone());
            }
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
        let reader = Cursor::new(map_content);
        let equivalences = parse_msvc_map(reader);

        // The two symbols at 82331360 should be equivalent
        assert!(equivalences.contains_key("??_GObjRef@@UAAPAXI@Z"));
        assert!(equivalences.contains_key("??_EObjRef@@UAAPAXI@Z"));
        let group = &equivalences["??_GObjRef@@UAAPAXI@Z"];
        assert!(group.contains("??_EObjRef@@UAAPAXI@Z"));
        assert!(group.contains("??_GObjRef@@UAAPAXI@Z"));
        assert_eq!(group.len(), 2);

        // Unique symbols should not be in the map
        assert!(!equivalences.contains_key("?Foo@@YAXXZ"));
        assert!(!equivalences.contains_key("?Bar@@YAXXZ"));
    }

    #[test]
    fn test_parse_msvc_map_empty() {
        let reader = Cursor::new("");
        let equivalences = parse_msvc_map(reader);
        assert!(equivalences.is_empty());
    }

    #[test]
    fn test_parse_msvc_map_three_way_merge() {
        let map_content = "\
 0005:00001360       ?A@@YAXXZ                  82331360 f i App.obj
 0005:00001360       ?B@@YAXXZ                  82331360 f i App.obj
 0005:00001360       ?C@@YAXXZ                  82331360 f i App.obj
";
        let reader = Cursor::new(map_content);
        let equivalences = parse_msvc_map(reader);

        assert_eq!(equivalences.len(), 3);
        let group = &equivalences["?A@@YAXXZ"];
        assert!(group.contains("?B@@YAXXZ"));
        assert!(group.contains("?C@@YAXXZ"));
        assert_eq!(group.len(), 3);
    }
}
