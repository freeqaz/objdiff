//! PDB plain-name equivalence for MSVC internal-linkage symbols.
//!
//! A dtk-split TARGET object names each symbol from the original binary's PDB.
//! Externally visible functions appear there as public symbols carrying their
//! decorated name (`?Foo@ds_data@@YAXH@Z`), but an INTERNAL-linkage function
//! (`static`, a static function template's instantiation, a dynamic
//! initializer, ...) has no public record: the only name the PDB keeps is the
//! `S_LPROC32` spelling, which is the undecorated, name-only form
//! (`ds_data::CBBinaryOpImpl<3,char,unsigned char>`). Our compiled BASE object
//! can only carry MSVC's decorated name for that same function
//! (`??$CBBinaryOpImpl@$02DE@ds_data@@YA?AW4dsDATA_MATH_RES@@PBK0AAVdsDATA@@@Z`),
//! so exact name comparison never pairs the two and every relocation pointing
//! at the function is charged as a wrong target.
//!
//! The rule implemented here is deliberately narrow:
//!
//! * One side's symbol is decorated (`?...`), the other's is plain. Two
//!   decorated names are never equated through their undecorated forms --
//!   overloads differ only in the parts the name-only form drops.
//! * The decorated symbol has internal linkage: it is DEFINED in its object
//!   with storage class `STATIC` (objdiff's `SymbolFlag::Local`), or its name
//!   lies in an anonymous namespace (`?A0x...`). An external symbol has a
//!   public record in the PDB and therefore a decorated target name of its own;
//!   letting a plain name stand for it would hide a real wrong-callee.
//! * The decorated name's name-only undecoration, normalised, EQUALS the plain
//!   name, normalised. Normalisation only removes whitespace next to `,`, `<`
//!   and `>` and collapses other whitespace runs; nothing is fuzzy.
//! * The key is unambiguous in both objects: the decorated side holds exactly
//!   one decorated symbol with that key and no plain symbol spelled that way,
//!   and the plain side holds exactly one plain symbol with that key and no
//!   decorated symbol undecorating to it. Static overloads (`ds_data::F(int)`
//!   and `ds_data::F(float)` both undecorate to `ds_data::F`) are therefore
//!   refused rather than guessed at.
//!
//! The table is built only for COFF objects and only when
//! `DiffObjConfig::msvc_plain_name_equivalence` is set; for every other object
//! it is empty and the equivalence can never hold.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use crate::obj::{Symbol, SymbolFlag, SymbolKind};

/// Which spelling a participating symbol carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Spelling {
    /// A decorated MSVC name with internal linkage, keyed by its undecoration.
    Decorated,
    /// A plain (undecorated) name, keyed by itself.
    Plain,
}

#[derive(Debug, Clone, Copy, Default)]
struct KeyCounts {
    /// Decorated symbols (any linkage) whose name-only undecoration is the key.
    decorated: u32,
    /// Plain symbols spelled as the key.
    plain: u32,
}

/// Per-object lookup table for [`plain_name_equivalent`].
#[derive(Clone, Default)]
pub struct MsvcPlainNames {
    /// Indexed by symbol index. `None` for a symbol that cannot take part.
    keys: Vec<Option<(String, Spelling)>>,
    counts: BTreeMap<String, KeyCounts>,
}

// A summary, not the table: `Object`'s Debug output is snapshotted, and a dump
// of every key would bury the rest of the object.
impl core::fmt::Debug for MsvcPlainNames {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let participating = self.keys.iter().filter(|k| k.is_some()).count();
        f.debug_struct("MsvcPlainNames")
            .field("symbols", &self.keys.len())
            .field("participating", &participating)
            .finish()
    }
}

impl MsvcPlainNames {
    /// Build the table for one object's final symbol list.
    pub fn build(symbols: &[Symbol]) -> Self {
        let mut keys = Vec::with_capacity(symbols.len());
        let mut counts = BTreeMap::<String, KeyCounts>::new();
        for symbol in symbols {
            if symbol.kind == SymbolKind::Section || symbol.name.is_empty() {
                keys.push(None);
                continue;
            }
            if symbol.name.starts_with('?') {
                let Some(key) = decorated_plain_key(&symbol.name) else {
                    keys.push(None);
                    continue;
                };
                // Every decorated symbol counts towards ambiguity, whatever its
                // linkage: an external overload sharing the key makes the plain
                // name just as ambiguous as a second static one would.
                counts.entry(key.clone()).or_default().decorated += 1;
                if is_internal_linkage(symbol) {
                    keys.push(Some((key, Spelling::Decorated)));
                } else {
                    keys.push(None);
                }
            } else {
                let key = normalize_plain_name(&symbol.name);
                counts.entry(key.clone()).or_default().plain += 1;
                keys.push(Some((key, Spelling::Plain)));
            }
        }
        Self { keys, counts }
    }

    pub fn is_empty(&self) -> bool { self.keys.is_empty() }

    /// Whether symbol `symbol_index` can be equivalent to anything at all.
    pub fn participates(&self, symbol_index: usize) -> bool { self.get(symbol_index).is_some() }

    fn get(&self, symbol_index: usize) -> Option<(&str, Spelling)> {
        self.keys.get(symbol_index)?.as_ref().map(|(k, s)| (k.as_str(), *s))
    }

    fn counts(&self, key: &str) -> KeyCounts { self.counts.get(key).copied().unwrap_or_default() }
}

/// True if `left_names[left_index]` and `right_names[right_index]` are the same
/// internal-linkage symbol, one spelled by its PDB plain name and the other by
/// its MSVC decoration. See the module docs for the exact rule.
pub fn plain_name_equivalent(
    left_names: &MsvcPlainNames,
    left_index: usize,
    right_names: &MsvcPlainNames,
    right_index: usize,
) -> bool {
    let (Some((left_key, left_spelling)), Some((right_key, right_spelling))) =
        (left_names.get(left_index), right_names.get(right_index))
    else {
        return false;
    };
    if left_spelling == right_spelling || left_key != right_key {
        return false;
    }
    let (decorated_side, plain_side) = if left_spelling == Spelling::Decorated {
        (left_names, right_names)
    } else {
        (right_names, left_names)
    };
    let decorated = decorated_side.counts(left_key);
    let plain = plain_side.counts(left_key);
    decorated.decorated == 1 && decorated.plain == 0 && plain.plain == 1 && plain.decorated == 0
}

/// Internal linkage, as far as the object can tell: a defined `STATIC`
/// symbol, or one whose decoration places it in an anonymous namespace.
fn is_internal_linkage(symbol: &Symbol) -> bool {
    symbol.section.is_some()
        && (symbol.flags.contains(SymbolFlag::Local) || symbol.name.contains("?A0x"))
}

/// The name-only undecoration of an MSVC decorated name, normalised: the
/// scoped name with its template arguments, without return type, calling
/// convention, parameters or class-key keywords.
///
/// Dynamic initializers and atexit destructors (`??__E` / `??__F`) are spelled
/// the way the PDB spells them, which is not how the demangler does:
///
/// | decoration                                  | PDB `S_LPROC32` name                                   |
/// |---------------------------------------------|--------------------------------------------------------|
/// | `??__Eg_RGB@D3D@@YAXXZ`                      | ``D3D::`dynamic initializer for 'g_RGB''``             |
/// | `??__Fpresets@?1??GetPresets@@YA...@YAXXZ`   | ``` `GetPresets'::`2'::`dynamic atexit destructor for 'presets'' ``` |
/// | `??__E?pool@?$MEM@D$0DC@@@2UPOOL@@A@@YAXXZ`  | ``` `dynamic initializer for 'MEM<char,50>::pool'' ``` |
///
/// i.e. a namespace or function scope stays outside the quotes, and a class
/// static member (whose decoration nests a complete `?...` symbol) is quoted
/// whole.
#[cfg(feature = "demangler")]
pub fn decorated_plain_key(name: &str) -> Option<String> {
    const FORMS: [(&str, &str, &str); 2] = [
        ("??__E", "::`dynamic initializer'", "dynamic initializer"),
        ("??__F", "::`dynamic atexit destructor'", "dynamic atexit destructor"),
    ];
    for (prefix, demangled_suffix, kind) in FORMS {
        let Some(rest) = name.strip_prefix(prefix) else { continue };
        if rest.starts_with('?') {
            // Class static member: `??__E` + complete inner decoration + `@@YAXXZ`.
            let inner = rest.strip_suffix("@@YAXXZ")?;
            let inner = demangle_name_only(inner)?;
            return Some(normalize_plain_name(&alloc::format!("`{kind} for '{inner}''")));
        }
        let demangled = demangle_name_only(name)?;
        let body = demangled.strip_suffix(demangled_suffix)?;
        let plain = match split_last_scope(body) {
            Some((scope, var)) => alloc::format!("{scope}::`{kind} for '{var}''"),
            None => alloc::format!("`{kind} for '{body}''"),
        };
        return Some(normalize_plain_name(&plain));
    }
    Some(normalize_plain_name(&demangle_name_only(name)?))
}

#[cfg(not(feature = "demangler"))]
pub fn decorated_plain_key(_name: &str) -> Option<String> { None }

#[cfg(feature = "demangler")]
fn demangle_name_only(name: &str) -> Option<String> {
    use msvc_demangler::DemangleFlags;
    let flags = DemangleFlags::NAME_ONLY | DemangleFlags::NO_CLASS_TYPE;
    let demangled = msvc_demangler::demangle(name, flags).ok()?;
    // Refuse anything that did not come out as a name.
    if demangled.is_empty() || demangled.starts_with('?') {
        return None;
    }
    Some(demangled)
}

/// Split `a::b<c::d>::`f::g'::v` at its last `::` that is neither inside
/// template brackets nor inside a `` `...' `` quoted scope.
#[cfg_attr(not(feature = "demangler"), allow(dead_code))]
fn split_last_scope(name: &str) -> Option<(&str, &str)> {
    let bytes = name.as_bytes();
    let (mut angle, mut quote) = (0i32, 0i32);
    let mut last = None;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => angle += 1,
            b'>' => angle -= 1,
            b'`' => quote += 1,
            b'\'' if quote > 0 => quote -= 1,
            b':' if angle == 0 && quote == 0 && bytes.get(i + 1) == Some(&b':') => {
                last = Some(i);
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    last.map(|i| (&name[..i], &name[i + 2..]))
}

/// Canonical spelling for comparing undecorated names: whitespace next to
/// `,`, `<` or `>` is dropped (`<3, char, unsigned char>` and
/// `<3,char,unsigned char>` agree, as do `dsTSTRING<char> >` and
/// `dsTSTRING<char>>`), any other whitespace run becomes one space, and the
/// ends are trimmed. Nothing else changes.
pub fn normalize_plain_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending_space = false;
    for c in name.chars() {
        if c.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space {
            let glued =
                matches!(c, ',' | '<' | '>') || out.ends_with([',', '<', '>']) || out.is_empty();
            if !glued {
                out.push(' ');
            }
            pending_space = false;
        }
        out.push(c);
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn normalisation_only_touches_whitespace_next_to_brackets_and_commas() {
        assert_eq!(
            normalize_plain_name("ds_data::CBBinaryOpImpl<3, char, unsigned char>"),
            "ds_data::CBBinaryOpImpl<3,char,unsigned char>"
        );
        assert_eq!(
            normalize_plain_name("ds_data::Convert<dsSTRID,dsTSTRING<char> >"),
            "ds_data::Convert<dsSTRID,dsTSTRING<char>>"
        );
        assert_eq!(
            normalize_plain_name("getNumElements<hkClass const >"),
            "getNumElements<hkClass const>"
        );
        // Interior spaces of a type name survive, runs collapse, ends trim.
        assert_eq!(normalize_plain_name("  F<unsigned   long>  "), "F<unsigned long>");
        // Nothing else is rewritten: case, scope, quotes, digits.
        assert_eq!(
            normalize_plain_name("`a::B'::`2'::`dynamic atexit destructor for 'x''"),
            "`a::B'::`2'::`dynamic atexit destructor for 'x''"
        );
        assert_ne!(normalize_plain_name("F<3,char>"), normalize_plain_name("F<3,unsigned char>"));
    }

    #[cfg(feature = "demangler")]
    #[test]
    fn decorated_keys_match_pdb_spellings() {
        // Decorations from X360 cl.exe 16.00.11886.00; PDB spellings as the
        // cea-decomp target objects carry them.
        for (decorated, plain) in [
            (
                "??$CBBinaryOpImpl@$02DE@ds_data@@YA?AW4dsDATA_MATH_RES@@PBK0AAVdsDATA@@@Z",
                "ds_data::CBBinaryOpImpl<3,char,unsigned char>",
            ),
            (
                "??$CBBinaryOpImpl@$06_N_N@ds_data@@YA?AW4dsDATA_MATH_RES@@PBK0AAVdsDATA@@@Z",
                "ds_data::CBBinaryOpImpl<7,bool,bool>",
            ),
            (
                "??$CBConvertImpl@VdsSTRID@@V?$dsTSTRING@D@@@ds_data@@YAHPBKPAK@Z",
                "ds_data::CBConvertImpl<dsSTRID,dsTSTRING<char> >",
            ),
            ("?InitTables@@YAXXZ", "InitTables"),
            ("?anonFn@?A0xa2a4621a@@YAHH@Z", "`anonymous namespace'::anonFn"),
            ("??__Eg_RGB@D3D@@YAXXZ", "D3D::`dynamic initializer for 'g_RGB''"),
            ("??__EgStatic@@YAXXZ", "`dynamic initializer for 'gStatic''"),
            (
                "??__EanonVar@?A0xa2a4621a@@YAXXZ",
                "`anonymous namespace'::`dynamic initializer for 'anonVar''",
            ),
            (
                "??__Fpresets@?1??GetPresets@@YAAAUPOOL@@XZ@YAXXZ",
                "`GetPresets'::`2'::`dynamic atexit destructor for 'presets''",
            ),
            (
                "??__E?pool@?$MEM@D$0DC@@@2UPOOL@@A@@YAXXZ",
                "`dynamic initializer for 'MEM<char,50>::pool''",
            ),
            (
                "??__F?pool@?$MEM@D$0DC@@@2UPOOL@@A@@YAXXZ",
                "`dynamic atexit destructor for 'MEM<char,50>::pool''",
            ),
        ] {
            assert_eq!(
                decorated_plain_key(decorated).as_deref(),
                Some(normalize_plain_name(plain).as_str()),
                "{decorated}"
            );
        }
        // Overloads collapse onto one key -- which is why ambiguity is refused.
        assert_eq!(
            decorated_plain_key("?Ovl@ds_data@@YAHH@Z"),
            decorated_plain_key("?Ovl@ds_data@@YAHM@Z")
        );
        assert_eq!(decorated_plain_key("?not a decoration"), None);
    }

    #[test]
    fn split_last_scope_skips_templates_and_quoted_scopes() {
        assert_eq!(split_last_scope("a::b<c::d>::v"), Some(("a::b<c::d>", "v")));
        assert_eq!(split_last_scope("`a::F'::`2'::v"), Some(("`a::F'::`2'", "v")));
        assert_eq!(split_last_scope("`a::F'"), None);
        assert_eq!(split_last_scope("v"), None);
    }
}
