use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec,
    vec::Vec,
};

use core::{num::NonZeroU32, ops::Range};
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use anyhow::Result;

use crate::{
    diff::{
        code::{diff_code, no_diff_code},
        data::{
            diff_bss_section, diff_bss_symbol, diff_data_section, diff_data_symbol,
            diff_generic_section, no_diff_bss_section, no_diff_data_section, no_diff_data_symbol,
            symbol_name_matches,
        },
    },
    obj::{InstructionRef, Object, Relocation, SectionKind, Symbol, SymbolFlag},
};

pub mod code;
pub mod data;
pub mod demangler;
pub mod display;

include!(concat!(env!("OUT_DIR"), "/config.gen.rs"));

impl DiffObjConfig {
    pub fn separator(&self) -> &'static str {
        if self.space_between_args { ", " } else { "," }
    }
}

#[derive(Debug, Clone)]
pub struct SectionDiff {
    // pub target_section: Option<usize>,
    pub match_percent: Option<f32>,
    pub data_diff: Vec<DataDiff>,
    pub reloc_diff: Vec<DataRelocationDiff>,
}

#[derive(Debug, Clone, Default)]
pub struct SymbolDiff {
    /// The symbol index in the _other_ object that this symbol was diffed against
    pub target_symbol: Option<usize>,
    pub match_percent: Option<f32>,
    /// Match percent excluding arg-only penalties (register/offset swaps).
    pub match_percent_normalized: Option<f32>,
    pub diff_score: Option<(u64, u64)>,
    pub instruction_rows: Vec<InstructionDiffRow>,
    pub data_rows: Vec<DataDiffRow>,
}

#[derive(Debug, Clone, Default)]
pub struct MappingSymbolDiff {
    pub symbol_index: usize,
    pub symbol_diff: SymbolDiff,
}

#[derive(Debug, Clone, Default)]
pub struct InstructionDiffRow {
    /// Instruction reference
    pub ins_ref: Option<InstructionRef>,
    /// Diff kind
    pub kind: InstructionDiffKind,
    /// Branches from instruction(s)
    pub branch_from: Option<InstructionBranchFrom>,
    /// Branches to instruction
    pub branch_to: Option<InstructionBranchTo>,
    /// Arg diffs
    pub arg_diff: Vec<InstructionArgDiffIndex>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub enum InstructionDiffKind {
    #[default]
    None,
    OpMismatch,
    ArgMismatch,
    Replace,
    Delete,
    Insert,
}

#[derive(Debug, Clone, Default)]
pub struct DataDiff {
    pub data: Vec<u8>,
    pub size: usize,
    pub kind: DataDiffKind,
}

#[derive(Debug, Clone)]
pub struct DataRelocationDiff {
    pub reloc: Relocation,
    pub range: Range<u64>,
    pub kind: DataDiffKind,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub enum DataDiffKind {
    #[default]
    None,
    Replace,
    Delete,
    Insert,
}

#[derive(Debug, Clone, Default)]
pub struct DataDiffRow {
    pub address: u64,
    pub segments: Vec<DataDiff>,
    pub relocations: Vec<DataRelocationDiff>,
}

/// Index of the argument diff for coloring.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Default)]
pub struct InstructionArgDiffIndex(pub Option<NonZeroU32>);

impl InstructionArgDiffIndex {
    pub const NONE: Self = Self(None);

    #[inline(always)]
    pub fn new(idx: u32) -> Self {
        Self(Some(unsafe { NonZeroU32::new_unchecked(idx.saturating_add(1)) }))
    }

    #[inline(always)]
    pub fn get(&self) -> Option<u32> {
        self.0.map(|idx| idx.get() - 1)
    }

    #[inline(always)]
    pub fn is_some(&self) -> bool {
        self.0.is_some()
    }

    #[inline(always)]
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }
}

#[derive(Debug, Clone)]
pub struct InstructionBranchFrom {
    /// Source instruction indices
    pub ins_idx: Vec<u32>,
    /// Incrementing index for coloring
    pub branch_idx: u32,
}

#[derive(Debug, Clone)]
pub struct InstructionBranchTo {
    /// Target instruction index
    pub ins_idx: u32,
    /// Incrementing index for coloring
    pub branch_idx: u32,
}

#[derive(Debug, Default)]
pub struct ObjectDiff {
    /// A list of all symbol diffs in the object.
    pub symbols: Vec<SymbolDiff>,
    /// A list of all section diffs in the object.
    pub sections: Vec<SectionDiff>,
    /// If `selecting_left` or `selecting_right` is set, this is the list of symbols
    /// that are being mapped to the other object.
    pub mapping_symbols: Vec<MappingSymbolDiff>,
}

impl ObjectDiff {
    pub fn new_from_obj(obj: &Object) -> Self {
        let mut result = Self {
            symbols: Vec::with_capacity(obj.symbols.len()),
            sections: Vec::with_capacity(obj.sections.len()),
            mapping_symbols: vec![],
        };
        for _ in obj.symbols.iter() {
            result.symbols.push(SymbolDiff {
                target_symbol: None,
                match_percent: None,
                diff_score: None,
                ..Default::default()
            });
        }
        for _ in obj.sections.iter() {
            result.sections.push(SectionDiff {
                // target_section: None,
                match_percent: None,
                data_diff: vec![],
                reloc_diff: vec![],
            });
        }
        result
    }
}

#[derive(Debug, Default)]
pub struct DiffObjsResult {
    pub left: Option<ObjectDiff>,
    pub right: Option<ObjectDiff>,
    pub prev: Option<ObjectDiff>,
}

pub fn diff_objs(
    left: Option<&Object>,
    right: Option<&Object>,
    prev: Option<&Object>,
    diff_config: &DiffObjConfig,
    mapping_config: &MappingConfig,
) -> Result<DiffObjsResult> {
    diff_objs_filtered(left, right, prev, diff_config, mapping_config, None)
}

/// Like `diff_objs`, but only diffs symbols whose left-side index is in `symbol_filter`.
/// When `symbol_filter` is `Some`, skips section-level diffs and mapping symbol generation.
/// This is much faster for batch mode where only a subset of symbols are needed.
pub fn diff_objs_filtered(
    left: Option<&Object>,
    right: Option<&Object>,
    prev: Option<&Object>,
    diff_config: &DiffObjConfig,
    mapping_config: &MappingConfig,
    symbol_filter: Option<&BTreeSet<usize>>,
) -> Result<DiffObjsResult> {
    let symbol_matches = matching_symbols(left, right, prev, mapping_config, symbol_filter)?;
    let section_matches = matching_sections(left, right)?;
    let mut left = left.map(|p| (p, ObjectDiff::new_from_obj(p)));
    let mut right = right.map(|p| (p, ObjectDiff::new_from_obj(p)));
    let mut prev = prev.map(|p| (p, ObjectDiff::new_from_obj(p)));

    for symbol_match in symbol_matches {
        // Skip symbols not in the filter set (when filtering is active)
        if let Some(filter) = symbol_filter {
            let dominated_by_filter = match &symbol_match {
                SymbolMatch { left: Some(idx), .. } => filter.contains(idx),
                _ => false,
            };
            if !dominated_by_filter {
                // Still need to record the target_symbol mapping for matched pairs
                // so that symbol_by_name_or_demangled lookups can find the match
                if let SymbolMatch { left: Some(l), right: Some(r), .. } = &symbol_match {
                    if let Some((_, left_out)) = left.as_mut() {
                        left_out.symbols[*l].target_symbol = Some(*r);
                    }
                    if let Some((_, right_out)) = right.as_mut() {
                        right_out.symbols[*r].target_symbol = Some(*l);
                    }
                }
                continue;
            }
        }

        match symbol_match {
            SymbolMatch {
                left: Some(left_symbol_ref),
                right: Some(right_symbol_ref),
                prev: prev_symbol_ref,
                section_kind,
            } => {
                let (left_obj, left_out) = left.as_mut().unwrap();
                let (right_obj, right_out) = right.as_mut().unwrap();
                match section_kind {
                    SectionKind::Code => {
                        let (left_diff, right_diff) = diff_code(
                            left_obj,
                            right_obj,
                            left_symbol_ref,
                            right_symbol_ref,
                            diff_config,
                            #[cfg(feature = "std")]
                            &mapping_config.symbol_equivalences,
                        )?;
                        left_out.symbols[left_symbol_ref] = left_diff;
                        right_out.symbols[right_symbol_ref] = right_diff;

                        if let Some(prev_symbol_ref) = prev_symbol_ref {
                            let (_prev_obj, prev_out) = prev.as_mut().unwrap();
                            let (_, prev_diff) = diff_code(
                                left_obj,
                                right_obj,
                                right_symbol_ref,
                                prev_symbol_ref,
                                diff_config,
                                #[cfg(feature = "std")]
                                &mapping_config.symbol_equivalences,
                            )?;
                            prev_out.symbols[prev_symbol_ref] = prev_diff;
                        }
                    }
                    SectionKind::Data => {
                        let (left_diff, right_diff) = diff_data_symbol(
                            left_obj,
                            right_obj,
                            left_symbol_ref,
                            right_symbol_ref,
                        )?;
                        left_out.symbols[left_symbol_ref] = left_diff;
                        right_out.symbols[right_symbol_ref] = right_diff;
                    }
                    SectionKind::Bss | SectionKind::Common => {
                        let (left_diff, right_diff) = diff_bss_symbol(
                            left_obj,
                            right_obj,
                            left_symbol_ref,
                            right_symbol_ref,
                        )?;
                        left_out.symbols[left_symbol_ref] = left_diff;
                        right_out.symbols[right_symbol_ref] = right_diff;
                    }
                    SectionKind::Unknown => unreachable!(),
                }
            }
            SymbolMatch { left: Some(left_symbol_ref), right: None, prev: _, section_kind } => {
                let (left_obj, left_out) = left.as_mut().unwrap();
                match section_kind {
                    SectionKind::Code => {
                        left_out.symbols[left_symbol_ref] =
                            no_diff_code(left_obj, left_symbol_ref, diff_config)?;
                    }
                    SectionKind::Data => {
                        left_out.symbols[left_symbol_ref] =
                            no_diff_data_symbol(left_obj, left_symbol_ref)?;
                    }
                    SectionKind::Bss | SectionKind::Common => {
                        // Nothing needs to be done
                    }
                    SectionKind::Unknown => unreachable!(),
                }
            }
            SymbolMatch { left: None, right: Some(right_symbol_ref), prev: _, section_kind } => {
                let (right_obj, right_out) = right.as_mut().unwrap();
                match section_kind {
                    SectionKind::Code => {
                        right_out.symbols[right_symbol_ref] =
                            no_diff_code(right_obj, right_symbol_ref, diff_config)?;
                    }
                    SectionKind::Data => {
                        right_out.symbols[right_symbol_ref] =
                            no_diff_data_symbol(right_obj, right_symbol_ref)?;
                    }
                    SectionKind::Bss | SectionKind::Common => {
                        // Nothing needs to be done
                    }
                    SectionKind::Unknown => unreachable!(),
                }
            }
            SymbolMatch { left: None, right: None, .. } => {
                // Should not happen
            }
        }
    }

    // Skip section-level diffs and mapping generation when filtering symbols
    // (not needed for batch mode, saves significant time)
    if symbol_filter.is_none() {
        for section_match in section_matches {
            match section_match {
                SectionMatch {
                    left: Some(left_section_idx),
                    right: Some(right_section_idx),
                    section_kind,
                } => {
                    let (left_obj, left_out) = left.as_mut().unwrap();
                    let (right_obj, right_out) = right.as_mut().unwrap();
                    match section_kind {
                        SectionKind::Code => {
                            let (left_diff, right_diff) = diff_generic_section(
                                left_obj,
                                right_obj,
                                left_out,
                                right_out,
                                left_section_idx,
                                right_section_idx,
                            )?;
                            left_out.sections[left_section_idx] = left_diff;
                            right_out.sections[right_section_idx] = right_diff;
                        }
                        SectionKind::Data => {
                            let (left_diff, right_diff) = diff_data_section(
                                left_obj,
                                right_obj,
                                left_out,
                                right_out,
                                left_section_idx,
                                right_section_idx,
                            )?;
                            left_out.sections[left_section_idx] = left_diff;
                            right_out.sections[right_section_idx] = right_diff;
                        }
                        SectionKind::Bss | SectionKind::Common => {
                            let (left_diff, right_diff) = diff_bss_section(
                                left_obj,
                                right_obj,
                                left_out,
                                right_out,
                                left_section_idx,
                                right_section_idx,
                            )?;
                            left_out.sections[left_section_idx] = left_diff;
                            right_out.sections[right_section_idx] = right_diff;
                        }
                        SectionKind::Unknown => unreachable!(),
                    }
                }
                SectionMatch { left: Some(left_section_idx), right: None, section_kind } => {
                    let (left_obj, left_out) = left.as_mut().unwrap();
                    match section_kind {
                        SectionKind::Code => {}
                        SectionKind::Data => {
                            left_out.sections[left_section_idx] =
                                no_diff_data_section(left_obj, left_section_idx)?;
                        }
                        SectionKind::Bss | SectionKind::Common => {
                            left_out.sections[left_section_idx] = no_diff_bss_section()?;
                        }
                        SectionKind::Unknown => unreachable!(),
                    }
                }
                SectionMatch { left: None, right: Some(right_section_idx), section_kind } => {
                    let (right_obj, right_out) = right.as_mut().unwrap();
                    match section_kind {
                        SectionKind::Code => {}
                        SectionKind::Data => {
                            right_out.sections[right_section_idx] =
                                no_diff_data_section(right_obj, right_section_idx)?;
                        }
                        SectionKind::Bss | SectionKind::Common => {
                            right_out.sections[right_section_idx] = no_diff_bss_section()?;
                        }
                        SectionKind::Unknown => unreachable!(),
                    }
                }
                SectionMatch { left: None, right: None, .. } => {
                    // Should not happen
                }
            }
        }

        if let (Some((right_obj, right_out)), Some((left_obj, left_out))) =
            (right.as_mut(), left.as_mut())
        {
            if let Some(right_name) = mapping_config.selecting_left.as_deref() {
                generate_mapping_symbols(
                    left_obj,
                    left_out,
                    right_obj,
                    right_out,
                    MappingSymbol::Right(right_name),
                    diff_config,
                )?;
            }
            if let Some(left_name) = mapping_config.selecting_right.as_deref() {
                generate_mapping_symbols(
                    left_obj,
                    left_out,
                    right_obj,
                    right_out,
                    MappingSymbol::Left(left_name),
                    diff_config,
                )?;
            }
        }
    }

    Ok(DiffObjsResult {
        left: left.map(|(_, o)| o),
        right: right.map(|(_, o)| o),
        prev: prev.map(|(_, o)| o),
    })
}

#[derive(Clone, Copy)]
enum MappingSymbol<'a> {
    Left(&'a str),
    Right(&'a str),
}

/// When we're selecting a symbol to use as a comparison, we'll create comparisons for all
/// symbols in the other object that match the selected symbol's section and kind. This allows
/// us to display match percentages for all symbols in the other object that could be selected.
fn generate_mapping_symbols(
    left_obj: &Object,
    left_out: &mut ObjectDiff,
    right_obj: &Object,
    right_out: &mut ObjectDiff,
    mapping_symbol: MappingSymbol,
    config: &DiffObjConfig,
) -> Result<()> {
    let (base_obj, base_name, target_obj) = match mapping_symbol {
        MappingSymbol::Left(name) => (left_obj, name, right_obj),
        MappingSymbol::Right(name) => (right_obj, name, left_obj),
    };
    let Some(base_symbol_ref) = base_obj.symbol_by_name(base_name) else {
        return Ok(());
    };
    let base_section_kind = symbol_section_kind(base_obj, &base_obj.symbols[base_symbol_ref]);
    for (target_symbol_index, target_symbol) in target_obj.symbols.iter().enumerate() {
        if target_symbol.size == 0
            || target_symbol.flags.contains(SymbolFlag::Ignored)
            || symbol_section_kind(target_obj, target_symbol) != base_section_kind
        {
            continue;
        }
        let (left_symbol_idx, right_symbol_idx) = match mapping_symbol {
            MappingSymbol::Left(_) => (base_symbol_ref, target_symbol_index),
            MappingSymbol::Right(_) => (target_symbol_index, base_symbol_ref),
        };
        let (left_diff, right_diff) = match base_section_kind {
            SectionKind::Code => {
                #[cfg(feature = "std")]
                let empty_equivalences = HashMap::new();
                diff_code(
                    left_obj,
                    right_obj,
                    left_symbol_idx,
                    right_symbol_idx,
                    config,
                    #[cfg(feature = "std")]
                    &empty_equivalences,
                )
            }
            SectionKind::Data => {
                diff_data_symbol(left_obj, right_obj, left_symbol_idx, right_symbol_idx)
            }
            SectionKind::Bss | SectionKind::Common => {
                diff_bss_symbol(left_obj, right_obj, left_symbol_idx, right_symbol_idx)
            }
            SectionKind::Unknown => continue,
        }?;
        match mapping_symbol {
            MappingSymbol::Left(_) => right_out.mapping_symbols.push(MappingSymbolDiff {
                symbol_index: right_symbol_idx,
                symbol_diff: right_diff,
            }),
            MappingSymbol::Right(_) => left_out
                .mapping_symbols
                .push(MappingSymbolDiff { symbol_index: left_symbol_idx, symbol_diff: left_diff }),
        }
    }
    Ok(())
}

#[derive(Copy, Clone, Eq, PartialEq)]
struct SymbolMatch {
    left: Option<usize>,
    right: Option<usize>,
    prev: Option<usize>,
    section_kind: SectionKind,
}

#[derive(Copy, Clone, Eq, PartialEq)]
struct SectionMatch {
    left: Option<usize>,
    right: Option<usize>,
    section_kind: SectionKind,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize), serde(default))]
pub struct MappingConfig {
    /// Manual symbol mappings
    pub mappings: BTreeMap<String, String>,
    /// The right object symbol name that we're selecting a left symbol for
    pub selecting_left: Option<String>,
    /// The left object symbol name that we're selecting a right symbol for
    pub selecting_right: Option<String>,
    /// ICF merged symbol equivalence groups.
    /// Maps each symbol name to the set of names it's equivalent to.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub symbol_equivalences: HashMap<String, HashSet<String>>,
}

fn apply_symbol_mappings(
    left: &Object,
    right: &Object,
    mapping_config: &MappingConfig,
    left_used: &mut BTreeSet<usize>,
    right_used: &mut BTreeSet<usize>,
    matches: &mut Vec<SymbolMatch>,
) -> Result<()> {
    // If we're selecting a symbol to use as a comparison, mark it as used
    // This ensures that we don't match it to another symbol at any point
    if let Some(left_name) = &mapping_config.selecting_left
        && let Some(left_symbol) = left.symbol_by_name(left_name)
    {
        left_used.insert(left_symbol);
    }
    if let Some(right_name) = &mapping_config.selecting_right
        && let Some(right_symbol) = right.symbol_by_name(right_name)
    {
        right_used.insert(right_symbol);
    }

    // Apply manual symbol mappings
    for (left_name, right_name) in &mapping_config.mappings {
        let Some(left_symbol_index) = left.symbol_by_name(left_name) else {
            continue;
        };
        if left_used.contains(&left_symbol_index) {
            continue;
        }
        let Some(right_symbol_index) = right.symbol_by_name(right_name) else {
            continue;
        };
        if right_used.contains(&right_symbol_index) {
            continue;
        }
        let left_section_kind = left
            .symbols
            .get(left_symbol_index)
            .and_then(|s| s.section)
            .and_then(|section_index| left.sections.get(section_index))
            .map_or(SectionKind::Unknown, |s| s.kind);
        let right_section_kind = right
            .symbols
            .get(right_symbol_index)
            .and_then(|s| s.section)
            .and_then(|section_index| right.sections.get(section_index))
            .map_or(SectionKind::Unknown, |s| s.kind);
        if left_section_kind != right_section_kind {
            log::warn!(
                "Symbol section kind mismatch: {left_name} ({left_section_kind:?}) vs {right_name} ({right_section_kind:?})"
            );
            continue;
        }
        matches.push(SymbolMatch {
            left: Some(left_symbol_index),
            right: Some(right_symbol_index),
            prev: None, // TODO
            section_kind: left_section_kind,
        });
        left_used.insert(left_symbol_index);
        right_used.insert(right_symbol_index);
    }
    Ok(())
}

/// Find matching symbols between each object.
/// When `symbol_filter` is provided, only do expensive matching (data diffs for
/// compiler-generated literals) for filtered symbols. Unfiltered symbols get
/// cheap name-only matching via `find_symbol_by_name`.
fn matching_symbols(
    left: Option<&Object>,
    right: Option<&Object>,
    prev: Option<&Object>,
    mappings: &MappingConfig,
    symbol_filter: Option<&BTreeSet<usize>>,
) -> Result<Vec<SymbolMatch>> {
    let mut matches = Vec::new();
    let mut left_used = BTreeSet::new();
    let mut right_used = BTreeSet::new();
    if let Some(left) = left {
        if let Some(right) = right {
            apply_symbol_mappings(
                left,
                right,
                mappings,
                &mut left_used,
                &mut right_used,
                &mut matches,
            )?;
        }
        // Do two passes for nameless literals. The first only pairs up perfect matches to ensure
        // those are correct first, while the second pass catches near matches.
        for fuzzy_literals in [false, true] {
            for (symbol_idx, symbol) in left.symbols.iter().enumerate() {
                if symbol.size == 0 || symbol.flags.contains(SymbolFlag::Ignored) {
                    continue;
                }
                let section_kind = symbol_section_kind(left, symbol);
                if section_kind == SectionKind::Unknown {
                    continue;
                }
                if left_used.contains(&symbol_idx) {
                    continue;
                }
                // When filtering, use cheap name-only matching for unfiltered symbols
                let is_filtered = symbol_filter.is_none_or(|f| f.contains(&symbol_idx));
                let symbol_match = if is_filtered {
                    SymbolMatch {
                        left: Some(symbol_idx),
                        right: find_symbol(right, left, symbol_idx, Some(&right_used), fuzzy_literals),
                        prev: find_symbol(prev, left, symbol_idx, None, fuzzy_literals),
                        section_kind,
                    }
                } else {
                    // Cheap path: name-only match (skip data diffs for compiler-generated)
                    SymbolMatch {
                        left: Some(symbol_idx),
                        right: find_symbol_by_name(right, left, symbol_idx, Some(&right_used)),
                        prev: None,
                        section_kind,
                    }
                };
                matches.push(symbol_match);
                if let Some(right) = symbol_match.right {
                    left_used.insert(symbol_idx);
                    right_used.insert(right);
                }
            }
        }
    }
    // MSVC EH funclet fallback: pair `__unwind$NNN`/`__catch$NNN`/`fn_<addr>` symbols
    // by byte-equality when name-based pairing fails. The two sides number funclets
    // per-translation-unit, so the integers never agree, and the target side sometimes
    // loses the funclet name entirely (becomes `fn_<addr>`) when dtk's splitter sees a
    // COMDAT name collision across object files. See
    // docs/sessions/2026-05-26-msvc-funclet-pairing.md for the full investigation.
    if let (Some(left), Some(right)) = (left, right) {
        pair_funclets_by_bytes(left, right, &mut left_used, &mut right_used, &mut matches);
    }

    if let Some(right) = right {
        // Do two passes for nameless literals. The first only pairs up perfect matches to ensure
        // those are correct first, while the second pass catches near matches.
        for fuzzy_literals in [false, true] {
            for (symbol_idx, symbol) in right.symbols.iter().enumerate() {
                if symbol.size == 0 || symbol.flags.contains(SymbolFlag::Ignored) {
                    continue;
                }
                let section_kind = symbol_section_kind(right, symbol);
                if section_kind == SectionKind::Unknown {
                    continue;
                }
                if right_used.contains(&symbol_idx) {
                    continue;
                }
                let symbol_match = SymbolMatch {
                    left: None,
                    right: Some(symbol_idx),
                    prev: find_symbol(prev, right, symbol_idx, None, fuzzy_literals),
                    section_kind,
                };
                matches.push(symbol_match);
                if symbol_match.prev.is_some() {
                    right_used.insert(symbol_idx);
                }
            }
        }
    }
    Ok(matches)
}

/// True for MSVC EH funclet symbols that should participate in byte-fallback pairing:
/// `__unwind$NNN`, `__catch$NNN`, `__unwind__merged_<addr>`, `fn_<8 hex digits>`,
/// `??__E<mangled>` (MSVC dynamic initializer), `??__F<mangled>` (MSVC dynamic destructor).
///
/// The `??__E` / `??__F` entries are included because dtk's splitter renames the
/// corresponding target-side COMDAT sections to `fn_<addr>` when the original symbol
/// name cannot be recovered from the XEX.  Both sides emit byte-identical thunks for
/// these global-lifecycle functions, so they are safe to pair by byte signature.
fn is_funclet_like(name: &str) -> bool {
    if let Some(rest) = name.strip_prefix("__unwind$") {
        return rest.chars().all(|c| c.is_ascii_digit());
    }
    if let Some(rest) = name.strip_prefix("__catch$") {
        return rest.chars().all(|c| c.is_ascii_digit());
    }
    if name.starts_with("__unwind__merged_") {
        return true;
    }
    if let Some(rest) = name.strip_prefix("fn_") {
        return rest.len() == 8 && rest.chars().all(|c| c.is_ascii_hexdigit());
    }
    // MSVC global dynamic initializer (??__E) and dynamic destructor (??__F).
    // These appear as mangled names in the compiled base object but as fn_<addr>
    // on the target side (the XEX split loses the original COMDAT name).
    if name.starts_with("??__E") || name.starts_with("??__F") {
        return true;
    }
    false
}

/// Extract a symbol's byte payload with all relocation-targeted bytes zeroed.
/// Both sides emit COFF with zero immediates at every relocation site, so
/// after masking we can compare the pure instruction encoding.
pub(crate) fn funclet_signature(obj: &Object, sym_idx: usize) -> Option<alloc::vec::Vec<u8>> {
    let symbol = obj.symbols.get(sym_idx)?;
    if symbol.size == 0 {
        return None;
    }
    let section = obj.sections.get(symbol.section?)?;
    let start = symbol.address.checked_sub(section.address)? as usize;
    let end = start.checked_add(symbol.size as usize)?;
    let raw = section.data.get(start..end)?;
    let mut bytes = raw.to_vec();
    // Mask reloc-affected bytes. PowerPC ELF/COFF relocs cover 4 bytes; mask the
    // low 2 bytes (for @h/@l/@ha 16-bit halves) and rel24 displacement bits. Simplest
    // robust approach: zero the whole 4-byte instruction word at each reloc address.
    let sym_start_abs = symbol.address;
    let sym_end_abs = sym_start_abs + symbol.size;
    for reloc in &section.relocations {
        if reloc.address < sym_start_abs || reloc.address >= sym_end_abs {
            continue;
        }
        let off = (reloc.address - sym_start_abs) as usize;
        // zero a 4-byte window starting at the reloc address (PowerPC instruction-sized).
        let end_off = (off + 4).min(bytes.len());
        for b in &mut bytes[off..end_off] {
            *b = 0;
        }
    }
    Some(bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Global byte-equality second pass (case-B identity transfer).
//
// objdiff pairs symbols WITHIN a unit (one target obj ↔ one base obj). An
// ICF-scattered TU's method whose retail bytes physically live inside ANOTHER
// TU's pinned span ("case-B", see docs/decomp/identity-transfer.md) can never
// pair: the claiming unit's compiled base obj DEFINES the mangled method, but
// the target bytes live in the foreign unit's target obj. The bytes match — the
// pairing is impossible because it is cross-unit.
//
// `reconcile_global_byte_matches` is a SECOND PASS in the report driver only. It
// promotes such methods to 100% under a strict honesty predicate (the rules in
// the task `correctness_constraints`). Per-unit diff semantics
// (`diff_objs`/`matching_symbols`/`pair_funclets_by_bytes`) are UNCHANGED.
// ─────────────────────────────────────────────────────────────────────────────

/// Real-bodied threshold. Methods ≤ this many bytes are ICF-folding stubs/thunks
/// (73% of the oracle pool); byte-equality on them asserts nothing about
/// ownership. Only count case-B promotions whose retail body exceeds this.
pub const CASEB_STUB_MAX: u64 = 44;

/// An ordered, name-resolved relocation descriptor for a symbol. The honest
/// equality predicate (code.rs:122-129) requires a true 100% to agree on
/// reloc count, flags, offsets, addends AND reloc-target NAMES — `funclet_signature`
/// masks the bytes but DROPS the target names, so two >44B fns of identical
/// instruction shape but different callees/strings mask-EQUAL. This carries the
/// names so we can demand structural reloc equality.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(crate) struct RelocDesc {
    /// Byte offset of the reloc from the symbol's start.
    pub off_from_sym: u64,
    /// Normalized, totally-ordered encoding of `obj::RelocationFlags`
    /// (`(discriminant, value)`): the shared enum isn't `Ord`, so we project it
    /// to a comparable scalar locally (keeps the global-pass keys `Ord` without
    /// touching the shared `obj` type's derives). 0 = ELF, 1 = COFF.
    pub flags: (u8, u32),
    /// Resolved target-symbol name (canonicalized through the ICF equivalence map
    /// by the caller before comparison).
    pub target_name: String,
    pub addend: i64,
}

/// Project a shared `RelocationFlags` to a totally-ordered scalar key.
fn reloc_flags_key(flags: crate::obj::RelocationFlags) -> (u8, u32) {
    match flags {
        crate::obj::RelocationFlags::Elf(v) => (0, v),
        crate::obj::RelocationFlags::Coff(v) => (1, v as u32),
    }
}

/// The full honesty signature of a named code symbol: reloc-masked instruction
/// bytes PLUS the ordered, name-resolved relocation descriptors. Two symbols are
/// byte-identical for promotion iff BOTH components are equal (rule 5).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(crate) struct NamedSig {
    pub masked_bytes: Vec<u8>,
    pub relocs: Vec<RelocDesc>,
}

/// Compute the full reloc-masked + reloc-name signature of a code symbol.
/// Returns `None` for size-0 symbols or symbols with no resolvable section.
///
/// This is the honesty primitive for the global pass. Unlike `is_funclet_like`,
/// it accepts ANY code symbol (the caller gates on name-ness / size / kind).
pub(crate) fn named_symbol_signature(obj: &Object, sym_idx: usize) -> Option<NamedSig> {
    let masked_bytes = funclet_signature(obj, sym_idx)?;
    let symbol = obj.symbols.get(sym_idx)?;
    let section = obj.sections.get(symbol.section?)?;
    let sym_start_abs = symbol.address;
    let sym_end_abs = sym_start_abs + symbol.size;
    let mut relocs = Vec::new();
    for reloc in &section.relocations {
        if reloc.address < sym_start_abs || reloc.address >= sym_end_abs {
            continue;
        }
        // Resolve the target-symbol name. A reloc into an out-of-range symbol index
        // makes the signature un-comparable; bail (fail-closed).
        let target = obj.symbols.get(reloc.target_symbol)?;
        relocs.push(RelocDesc {
            off_from_sym: reloc.address - sym_start_abs,
            flags: reloc_flags_key(reloc.flags),
            target_name: target.name.clone(),
            addend: reloc.addend,
        });
    }
    // Sort by offset so the descriptor order is canonical (section.relocations is
    // already address-sorted in practice, but make it explicit).
    relocs.sort_by(|a, b| a.off_from_sym.cmp(&b.off_from_sym));
    Some(NamedSig { masked_bytes, relocs })
}

/// Canonical reloc-target name through the ICF equivalence map: pick the
/// lexicographically smallest member of the symbol's equivalence group (so an
/// ICF-folded base callee compares equal to its named sibling). If the symbol is
/// not in any group it maps to itself.
fn canonical_reloc_name<'a>(
    name: &'a str,
    equivalences: &'a HashMap<String, HashSet<String>>,
) -> &'a str {
    match equivalences.get(name) {
        Some(group) => group.iter().map(|s| s.as_str()).min().unwrap_or(name),
        None => name,
    }
}

/// Canonicalize a `NamedSig`'s reloc-target names through the ICF equivalence map.
/// Returns a key suitable for cross-unit comparison.
fn canonicalize_sig(sig: &NamedSig, equivalences: &HashMap<String, HashSet<String>>) -> NamedSig {
    let relocs = sig
        .relocs
        .iter()
        .map(|r| RelocDesc {
            off_from_sym: r.off_from_sym,
            flags: r.flags,
            target_name: canonical_reloc_name(&r.target_name, equivalences).to_string(),
            addend: r.addend,
        })
        .collect();
    NamedSig { masked_bytes: sig.masked_bytes.clone(), relocs }
}

/// Parse the retail virtual address out of an anonymous `fn_<8hex>` symbol name.
/// dtk names every un-renamed carved retail body `fn_<VA>` where `<VA>` is its
/// retail virtual address in hex — that is the authoritative VA source in this
/// pipeline (the carved COFF objs carry no `.note.split` per-symbol VA array).
fn parse_fn_va(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("fn_")?;
    if rest.len() != 8 || !rest.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(rest, 16).ok()
}

/// True if `name` is an anonymous/funclet target with no asserted source identity
/// (`fn_<8hex>`, `__unwind$`, `__catch$`, `__unwind__merged_`). These MUST NOT be
/// promoted (rule 3: no oracle name = no identity). Note `??__E`/`??__F` global
/// init/dtor ARE mangled names, but they ICF-fold widely and carry no own-TU
/// body, so we also exclude them here (the size>44B gate already filters most).
fn is_anonymous_or_funclet(name: &str) -> bool {
    if let Some(rest) = name.strip_prefix("fn_") {
        return rest.len() == 8 && rest.chars().all(|c| c.is_ascii_hexdigit());
    }
    name.starts_with("__unwind$")
        || name.starts_with("__catch$")
        || name.starts_with("__unwind__merged_")
        || name.starts_with("??__E")
        || name.starts_with("??__F")
}

/// One promotion decided by the global pass, for provenance / auditing.
#[derive(Clone, Debug)]
pub struct GlobalPromotion {
    /// The claiming unit's name (the unit whose BASE obj defines this mangled
    /// method — i.e. the unit we ported the source for).
    pub unit_name: String,
    /// The promoted symbol's mangled name.
    pub symbol_name: String,
    /// Retail virtual address (collision-free dedup key).
    pub virtual_address: u64,
    /// Symbol size in bytes.
    pub size: u64,
    /// The unit whose TARGET (carved retail) obj physically held the byte-identical
    /// body — i.e. where the case-B method's retail bytes were spatially carved.
    pub base_unit_name: String,
}

/// A target/base obj pair for one report unit, threaded out of `report_object`.
pub struct UnitObjs {
    pub unit_name: String,
    pub target: Option<Object>,
    pub base: Option<Object>,
}

/// Global byte-equality second pass. Promotes case-B methods to 100% under the
/// honesty predicate. Mutates `units` in place (bumps the claiming unit's
/// `measures.matched_functions` / `matched_code`, sets the promoted ReportItem's
/// `match_percent_normalized`/`fuzzy_match_percent` to 100). Returns the list of
/// promotions for auditing.
///
/// ORIENTATION (decomp, confirmed against rb3-xenon objdiff.json +
/// docs/decomp/identity-transfer.md):
///   * TARGET obj = the dtk-carved RETAIL obj (`build/.../obj/...`). It holds the
///     retail instruction bytes AND each symbol's retail VA via `.note.split`
///     (`symbol.virtual_address`). A case-B method's retail body lives here, in a
///     FOREIGN unit's carved span, typically as an anonymous `fn_<VA>`.
///   * BASE obj   = our MSVC-COMPILED obj (`build/.../src/...`). It DEFINES the
///     MSVC-mangled method `?M@Foo@@...` when we ported Foo's source. No VA.
///
/// A case-B method for claiming unit Foo: Foo's BASE obj defines `?M@Foo@@`, but
/// the retail bytes are carved into a DIFFERENT unit's TARGET obj, so the normal
/// per-unit pairing leaves `?M@Foo@@` unmatched. This pass finds the byte-identical
/// retail body in ANY target obj and promotes the BASE-named method.
///
/// Rule 3 (oracle attribution) is structurally guaranteed UPSTREAM: a mangled
/// method only appears in Foo's base obj because Foo's source was ported, and the
/// per-VA naming used by the wider pipeline is generated from the rb3-Wii oracle
/// (`gen_game_target_map.py`, `target_symbol_map.json`). The promotion log lets
/// `icf_alias_check.py` re-audit own-TU + real-bodied per the PROCESS GATE.
///
/// See task `correctness_constraints` rules 1-5 + FOO monotonicity.
/// Per-VA rb3-Wii BinDiff oracle attribution: `va -> (source-file basename
/// without extension, similarity)`. Required to enforce Rule 3 (oracle-named +
/// own-TU sim>=0.5): byte-equality + a map name alone MIS-ATTRIBUTES (STL
/// template instantiations like `_Vector_base<T>` / `_M_create_node` are
/// byte-identical across TUs and carry NO asserted source identity). Without
/// this gate the pass produces fake matches (verified: 4 un-oracle'd STL folds).
#[cfg(feature = "std")]
pub type VaOracle = HashMap<u64, (String, f32)>;

/// Oracle similarity floor for own-TU attribution (Rule 3).
pub const CASEB_ORACLE_SIM_MIN: f32 = 0.5;

#[cfg(feature = "std")]
pub fn reconcile_global_byte_matches(
    units: &mut [crate::bindings::report::ReportUnit],
    unit_objs: &[UnitObjs],
    equivalences: &HashMap<String, HashSet<String>>,
    oracle: &VaOracle,
) -> Vec<GlobalPromotion> {
    use crate::bindings::report::Measures;

    // Build unit_name -> source-file basename (no extension) for Rule 3 own-TU
    // attribution. e.g. "default/File" -> source_path "src/.../File.cpp" -> "file".
    let mut unit_src_basename: HashMap<&str, String> = HashMap::new();
    for unit in units.iter() {
        if let Some(sp) = unit.metadata.as_ref().and_then(|m| m.source_path.as_ref()) {
            let base = sp
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(sp)
                .rsplit_once('.')
                .map(|(stem, _)| stem)
                .unwrap_or(sp)
                .to_ascii_lowercase();
            unit_src_basename.insert(unit.name.as_str(), base);
        }
    }

    // name → UnitObjs for fast per-unit target/base lookup.
    let mut unit_obj_by_name: HashMap<&str, &UnitObjs> = HashMap::new();
    for uo in unit_objs.iter() {
        unit_obj_by_name.insert(uo.unit_name.as_str(), uo);
    }

    // ── PRE: already-matched-VA set (the pre-pass 100-set), keyed by RETAIL VA.
    //
    // Rule 4: each VA contributes at most one matched-count binary-wide. A case-B
    // body already living in a foreign target span MAY already be matched there
    // (e.g. via pair_funclets_by_bytes counting the foreign `fn_<VA>`). The retail
    // VA lives on the TARGET symbol (via split_meta), NOT on the report item, so we
    // resolve each already-100% ReportItem's name to its target symbol and take
    // that symbol's `virtual_address`. The VA is the only collision-free dedup key
    // (name-keyed dedup is unsafe — ICF folds many real bodies onto one name).
    let mut already_matched_va: HashSet<u64> = HashSet::new();
    for unit in units.iter() {
        let Some(uo) = unit_obj_by_name.get(unit.name.as_str()) else { continue };
        let Some(target) = &uo.target else { continue };
        for item in &unit.functions {
            let is_matched =
                item.match_percent_normalized.unwrap_or(item.fuzzy_match_percent) == 100.0;
            if !is_matched {
                continue;
            }
            // VA from split_meta if present, else from a `fn_<VA>` item/symbol name
            // (a body matched via funclet pairing stays anonymous). Renamed-matched
            // bodies lose the `fn_<VA>` form and are excluded from the retail index
            // anyway, so this set is a belt-and-braces guard.
            let va = item
                .metadata
                .as_ref()
                .and_then(|m| m.virtual_address)
                .or_else(|| parse_fn_va(&item.name))
                .or_else(|| {
                    target
                        .symbol_by_name(&item.name)
                        .and_then(|t_idx| target.symbols[t_idx].virtual_address)
                });
            if let Some(va) = va {
                already_matched_va.insert(va);
            }
        }
    }

    // ── PRE: global retail index over EVERY TARGET obj's real-bodied Code symbols.
    // Key = canonicalized (masked bytes + reloc-name) signature. Value = the list
    // of (unit_idx, target_sym_idx, retail_va) carrying that signature.
    //
    // Rule 1: only size > CASEB_STUB_MAX (stubs/thunks ICF-fold widely; byte-equality
    // on them asserts nothing). Rule 2 (injective on the RETAIL side): a signature
    // carried by >1 DISTINCT retail VA is non-unique and is rejected at lookup —
    // N retail bodies of identical shape = ambiguous identity. Rule 5: the signature
    // carries reloc-target names canonicalized through the ICF equivalence map.
    //
    // Both anonymous `fn_<VA>` and named retail bodies are indexed: a case-B body in
    // a foreign carved span is typically anonymous, and that is exactly what we must
    // match a base-named method against.
    // VA source: the carved COFF objs carry NO `.note.split` per-symbol VA array
    // (`symbol.virtual_address` is None for every target symbol here). dtk instead
    // names each UN-RENAMED carved retail body `fn_<VA>` — the hex VA is in the
    // name. A retail body that some unit ALREADY matched was renamed by the
    // pre-compile renamer to its mangled name, so it is NO LONGER `fn_<VA>`; only
    // un-renamed (still-available) retail bodies are anonymous. Indexing by the
    // `fn_<VA>` name therefore (a) supplies the rule-4 VA dedup key and
    // (b) intrinsically excludes already-claimed bodies (rule 4) — a case-B body
    // not yet pinned anywhere is exactly the anonymous one we want.
    let dbg = std::env::var("OBJDIFF_CASEB_DEBUG").is_ok();
    let mut dbg_tgt_code = 0u64;
    let mut dbg_tgt_have_va = 0u64;
    let mut retail_index: BTreeMap<NamedSig, Vec<(usize, usize, u64)>> = BTreeMap::new();
    for (uidx, uo) in unit_objs.iter().enumerate() {
        let Some(target) = &uo.target else { continue };
        for (sidx, sym) in target.symbols.iter().enumerate() {
            if sym.size <= CASEB_STUB_MAX {
                continue;
            }
            if sym.flags.contains(SymbolFlag::Ignored) || sym.flags.contains(SymbolFlag::Hidden) {
                continue;
            }
            if symbol_section_kind(target, sym) != SectionKind::Code {
                continue;
            }
            dbg_tgt_code += 1;
            // The retail VA: prefer the split_meta VA if present, else parse the
            // `fn_<VA>` name. Only un-renamed anonymous carved bodies are candidates.
            let Some(va) = sym.virtual_address.or_else(|| parse_fn_va(&sym.name)) else {
                continue;
            };
            dbg_tgt_have_va += 1;
            let Some(sig) = named_symbol_signature(target, sidx) else { continue };
            let key = canonicalize_sig(&sig, equivalences);
            retail_index.entry(key).or_default().push((uidx, sidx, va));
        }
    }
    if dbg {
        eprintln!(
            "[caseb] target code syms>44B={} of which have_va(or fn_VA name)={}",
            dbg_tgt_code, dbg_tgt_have_va
        );
    }

    // Track which retail bodies have been claimed (rule 2: a retail body is consumed
    // at most once globally), keyed by RETAIL VA (collision-free, dedups ICF folds).
    let mut retail_va_claimed: HashSet<u64> = HashSet::new();

    // ── PASS: for each unit's still-<100% NAMED method (defined in the BASE obj),
    // compute its signature and look it up in the retail index. Promote iff the
    // signature is uniquely matched on BOTH sides, real-bodied, and the retail VA is
    // not already counted.
    //
    // First collect decisions (immutable scan), then apply (mutable) so the read
    // borrow of `units` doesn't conflict with mutation.
    struct Decision {
        unit_idx: usize,
        item_idx: usize,
        va: u64,
        size: u64,
        name: String,
        base_unit_name: String,
        /// Signature key — used to enforce target-side injectivity across decisions
        /// (two distinct base methods resolving to the SAME retail body / signature
        /// = ambiguous; drop all).
        sig_key: NamedSig,
    }
    let mut decisions: Vec<Decision> = Vec::new();

    let mut c_named_unmatched = 0u64;
    let mut c_have_base_body = 0u64;
    let mut c_have_sig = 0u64;
    let mut c_sig_in_index = 0u64;
    let mut c_unique_retail = 0u64;
    let mut c_not_already = 0u64;
    let mut c_oracle_ok = 0u64;
    if dbg {
        eprintln!(
            "[caseb] retail_index sigs={} total_entries={} already_matched_va={}",
            retail_index.len(),
            retail_index.values().map(|v| v.len()).sum::<usize>(),
            already_matched_va.len()
        );
    }

    for (unit_idx, unit) in units.iter().enumerate() {
        let Some(uo) = unit_obj_by_name.get(unit.name.as_str()) else { continue };
        let Some(base) = &uo.base else { continue };
        for (item_idx, item) in unit.functions.iter().enumerate() {
            // Skip already-matched items (FOO monotonicity: never perturb a match).
            let cur = item.match_percent_normalized.unwrap_or(item.fuzzy_match_percent);
            if cur == 100.0 {
                continue;
            }
            // Rule 3: must carry a real MSVC-mangled (non-anonymous) name.
            if is_anonymous_or_funclet(&item.name) {
                continue;
            }
            // Rule 1 (size>44B). ReportItem size == the unit's listed symbol size.
            if item.size <= CASEB_STUB_MAX {
                continue;
            }
            c_named_unmatched += 1;
            // Locate the method's body in OUR compiled BASE obj to sign it.
            let Some(b_idx) = base.symbol_by_name(&item.name) else { continue };
            let b_sym = &base.symbols[b_idx];
            if b_sym.size <= CASEB_STUB_MAX {
                continue;
            }
            if symbol_section_kind(base, b_sym) != SectionKind::Code {
                continue;
            }
            c_have_base_body += 1;
            let Some(b_sig_raw) = named_symbol_signature(base, b_idx) else { continue };
            c_have_sig += 1;
            let key = canonicalize_sig(&b_sig_raw, equivalences);
            // Rule 2 (injective on the retail side): require EXACTLY ONE distinct
            // retail VA carrying this signature.
            let Some(retail_entries) = retail_index.get(&key) else { continue };
            c_sig_in_index += 1;
            let distinct_vas: HashSet<u64> = retail_entries.iter().map(|(_, _, va)| *va).collect();
            if distinct_vas.len() != 1 {
                continue;
            }
            c_unique_retail += 1;
            let va = *distinct_vas.iter().next().unwrap();
            // Rule 4: never promote a retail VA already counted somewhere.
            if already_matched_va.contains(&va) {
                continue;
            }
            c_not_already += 1;
            // Rule 3 (oracle-named + own-TU attribution): the retail VA must be
            // named by the rb3-Wii oracle with similarity >= floor AND attribute to
            // the CLAIMING unit's source TU. This is the DECISIVE honesty gate —
            // byte-equality + a mangled name alone mis-attributes STL template
            // instantiations (which the oracle never names). A VA absent from the
            // oracle has NO asserted identity → reject.
            //
            // OBJDIFF_CASEB_UNSAFE_NO_ORACLE: demonstration/diagnostic ONLY — bypasses
            // Rule 3 to exercise the byte-equality+injectivity transport end-to-end.
            // NEVER use for a real measurement (produces the documented STL-fold
            // inflation). Default (unset) enforces the oracle gate.
            if !std::env::var("OBJDIFF_CASEB_UNSAFE_NO_ORACLE").is_ok() {
                let Some((oracle_tu, sim)) = oracle.get(&va) else { continue };
                if *sim < CASEB_ORACLE_SIM_MIN {
                    continue;
                }
                let Some(claim_base) = unit_src_basename.get(unit.name.as_str()) else { continue };
                if oracle_tu.to_ascii_lowercase() != *claim_base {
                    continue;
                }
            }
            c_oracle_ok += 1;
            decisions.push(Decision {
                unit_idx,
                item_idx,
                va,
                size: item.size,
                name: item.name.clone(),
                base_unit_name: unit_objs[retail_entries[0].0].unit_name.clone(),
                sig_key: key,
            });
        }
    }

    if dbg {
        eprintln!(
            "[caseb] funnel: named_unmatched>44B={} have_base_body={} have_sig={} sig_in_retail_index={} unique_retail_va={} not_already_matched={} oracle_own_tu_ok={} -> decisions={}",
            c_named_unmatched, c_have_base_body, c_have_sig, c_sig_in_index, c_unique_retail, c_not_already, c_oracle_ok, decisions.len()
        );
    }

    // Rule 2 (injective on the BASE side too): a retail VA / signature claimed by ≥2
    // DISTINCT base methods (different mangled names) = ambiguous identity → drop ALL.
    // Key by retail VA (the physical body) AND by signature to catch both forms.
    let mut va_decided: HashMap<u64, usize> = HashMap::new();
    let mut sig_decided: HashMap<NamedSig, usize> = HashMap::new();
    for d in &decisions {
        *va_decided.entry(d.va).or_insert(0) += 1;
        *sig_decided.entry(d.sig_key.clone()).or_insert(0) += 1;
    }

    let mut promotions: Vec<GlobalPromotion> = Vec::new();
    for d in decisions {
        // Rule 2: reject if two distinct base methods resolved to the same retail
        // body (by VA) or the same signature (defensive — N-to-1 inflation).
        if va_decided.get(&d.va).copied().unwrap_or(0) != 1 {
            continue;
        }
        if sig_decided.get(&d.sig_key).copied().unwrap_or(0) != 1 {
            continue;
        }
        // Rule 4: final guard against double-count.
        if already_matched_va.contains(&d.va) || retail_va_claimed.contains(&d.va) {
            continue;
        }
        // ── APPLY the promotion.
        retail_va_claimed.insert(d.va);
        already_matched_va.insert(d.va);

        let unit = &mut units[d.unit_idx];
        // FOO monotonicity: we only ADD; never clear an existing matched member.
        let item = &mut unit.functions[d.item_idx];
        item.match_percent_normalized = Some(100.0);
        item.fuzzy_match_percent = 100.0;
        if let Some(measures) = unit.measures.as_mut() {
            measures.matched_functions += 1;
            measures.matched_code += d.size;
            recalc_unit_measure_percents(measures);
        } else {
            let mut m = Measures::default();
            m.matched_functions = 1;
            m.matched_code = d.size;
            unit.measures = Some(m);
        }
        promotions.push(GlobalPromotion {
            unit_name: unit.name.clone(),
            symbol_name: d.name,
            virtual_address: d.va,
            size: d.size,
            base_unit_name: d.base_unit_name,
        });
    }

    promotions
}

#[cfg(feature = "std")]
fn recalc_unit_measure_percents(m: &mut crate::bindings::report::Measures) {
    m.matched_code_percent =
        if m.total_code == 0 { 100.0 } else { m.matched_code as f32 / m.total_code as f32 * 100.0 };
    m.matched_functions_percent = if m.total_functions == 0 {
        100.0
    } else {
        m.matched_functions as f32 / m.total_functions as f32 * 100.0
    };
}

fn pair_funclets_by_bytes(
    left: &Object,
    right: &Object,
    left_used: &mut BTreeSet<usize>,
    right_used: &mut BTreeSet<usize>,
    matches: &mut Vec<SymbolMatch>,
) {
    // Collect unmatched funclet symbols on each side with their masked byte signature.
    let mut left_candidates: Vec<(usize, alloc::vec::Vec<u8>)> = Vec::new();
    for (idx, sym) in left.symbols.iter().enumerate() {
        if left_used.contains(&idx) || sym.size == 0 || sym.flags.contains(SymbolFlag::Ignored) {
            continue;
        }
        if !is_funclet_like(&sym.name) {
            continue;
        }
        if symbol_section_kind(left, sym) != SectionKind::Code {
            continue;
        }
        if let Some(sig) = funclet_signature(left, idx) {
            left_candidates.push((idx, sig));
        }
    }
    let mut right_candidates: Vec<(usize, alloc::vec::Vec<u8>)> = Vec::new();
    for (idx, sym) in right.symbols.iter().enumerate() {
        if right_used.contains(&idx) || sym.size == 0 || sym.flags.contains(SymbolFlag::Ignored) {
            continue;
        }
        if !is_funclet_like(&sym.name) {
            continue;
        }
        if symbol_section_kind(right, sym) != SectionKind::Code {
            continue;
        }
        if let Some(sig) = funclet_signature(right, idx) {
            right_candidates.push((idx, sig));
        }
    }

    // Make the greedy assignment below deterministic w.r.t. symbol-table order.
    //
    // The candidate lists are collected in symbol-table iteration order. When a
    // signature group is over-subscribed (e.g. N identical target funclets vs M<N
    // identical base funclets, which happens for compiler-generated static-init
    // thunks that the splitter renamed to `fn_<addr>`), passes 2 and 3 below pair
    // greedily, so *which* of the N candidates win the M exact partners depends on
    // their relative position in the symbol table. If an upstream change reorders
    // the symbol table (e.g. dtk's phantom-symbol fix), a different subset wins, and
    // the losers fall through to pass 3's fuzzy matching against a non-identical
    // candidate — producing a spurious match-percent "regression" even though the
    // funclet's own bytes never changed.
    //
    // Sorting both candidate lists by symbol name (which is stable and unique on
    // both sides — `fn_<addr>` encodes the retail address, `__unwind$NNN` the
    // funclet index) makes the per-signature index vectors, the pass-2 zip, and the
    // pass-3 scored insertion order all independent of symbol-table order. The
    // resulting pairing is then a pure function of the object contents.
    left_candidates.sort_by(|a, b| left.symbols[a.0].name.cmp(&left.symbols[b.0].name));
    right_candidates.sort_by(|a, b| right.symbols[a.0].name.cmp(&right.symbols[b.0].name));

    // Pass 1: exact byte-equality pairings, only when uniquely determined on both sides.
    // (If multiple left candidates share the same signature, defer them to pass 2; we
    // can't pick a winner without parent-association data.)
    use alloc::collections::BTreeMap;
    let mut left_by_sig: BTreeMap<&[u8], Vec<usize>> = BTreeMap::new();
    for (idx, sig) in &left_candidates {
        left_by_sig.entry(sig.as_slice()).or_default().push(*idx);
    }
    let mut right_by_sig: BTreeMap<&[u8], Vec<usize>> = BTreeMap::new();
    for (idx, sig) in &right_candidates {
        right_by_sig.entry(sig.as_slice()).or_default().push(*idx);
    }
    for (sig, left_indices) in &left_by_sig {
        if left_indices.len() != 1 {
            continue;
        }
        let Some(right_indices) = right_by_sig.get(sig) else { continue };
        if right_indices.len() != 1 {
            continue;
        }
        let l_idx = left_indices[0];
        let r_idx = right_indices[0];
        if left_used.contains(&l_idx) || right_used.contains(&r_idx) {
            continue;
        }
        matches.push(SymbolMatch {
            left: Some(l_idx),
            right: Some(r_idx),
            prev: None,
            section_kind: SectionKind::Code,
        });
        left_used.insert(l_idx);
        right_used.insert(r_idx);
    }

    // Pass 2: ambiguous exact-match groups. Greedily pair within each group.
    let mut pass2_pairs: Vec<(usize, usize)> = Vec::new();
    for (sig, left_indices) in &left_by_sig {
        let Some(right_indices) = right_by_sig.get(sig) else { continue };
        let l_remaining: Vec<usize> = left_indices.iter().copied().filter(|i| !left_used.contains(i)).collect();
        let r_remaining: Vec<usize> = right_indices.iter().copied().filter(|i| !right_used.contains(i)).collect();
        for (l_idx, r_idx) in l_remaining.iter().zip(r_remaining.iter()) {
            pass2_pairs.push((*l_idx, *r_idx));
        }
    }
    for (l_idx, r_idx) in pass2_pairs {
        if left_used.contains(&l_idx) || right_used.contains(&r_idx) {
            continue;
        }
        matches.push(SymbolMatch {
            left: Some(l_idx),
            right: Some(r_idx),
            prev: None,
            section_kind: SectionKind::Code,
        });
        left_used.insert(l_idx);
        right_used.insert(r_idx);
    }

    // Pass 2b: over-subscribed exact-match overflow. After pass 2, a signature group
    // can have N target funclets but only M<N byte-identical base funclets, so N-M
    // targets remain unmatched even though their bytes are *byte-identical* (after
    // reloc masking) to a base symbol. This happens for compiler-generated funclets
    // that get ICF-folded / duplicated (e.g. the BandDirector `fn_<addr>` static-init
    // thunks: 7 identical target funclets vs 5 identical base ones). Strict 1:1 would
    // shove these overflow targets into pass-3 fuzzy matching against a *non-identical*
    // base symbol, dragging their match-percent below the group's true ceiling for no
    // real reason — and *which* targets lose flips whenever the symbol table is
    // reordered (e.g. dtk's phantom-symbol prune grew this group 6->7), producing a
    // spurious regression.
    //
    // Since the overflow target's bytes genuinely match a base symbol, pair it
    // many-to-one to one of the identical base partners. This is sound: byte-identical
    // funclets diff to the same result regardless of which copy they pair with, so the
    // target's reported match-percent is the honest one. We reuse an already-consumed
    // base index *without* clearing `right_used` (it stays owned by its pass-1/2
    // winner; the base-side display just reflects the last writer, which is identical
    // bytes anyway). We DO mark the overflow target `left_used` so it never reaches the
    // fuzzy pass. Crucially this fires ONLY on an exact signature-key hit in
    // `right_by_sig`, so funclets that differ from every base symbol are untouched.
    for (sig, left_indices) in &left_by_sig {
        let Some(right_indices) = right_by_sig.get(sig) else { continue };
        // A deterministic identical base partner for this signature: the name-sorted
        // first index (right_candidates were sorted by name, so right_by_sig vectors
        // preserve that order). Any of them is byte-identical by construction.
        let Some(&partner) = right_indices.first() else { continue };
        for &l_idx in left_indices.iter() {
            if left_used.contains(&l_idx) {
                continue;
            }
            matches.push(SymbolMatch {
                left: Some(l_idx),
                right: Some(partner),
                prev: None,
                section_kind: SectionKind::Code,
            });
            left_used.insert(l_idx);
            // Intentionally do NOT touch `right_used`: many-to-one onto an identical
            // base symbol is allowed for the overflow.
        }
    }

    // Pass 3: same-size fuzzy match. For each remaining left funclet, find the best
    // unmatched right funclet of the same size by Hamming-equality of bytes.
    let mut remaining_left: Vec<(usize, &alloc::vec::Vec<u8>)> =
        left_candidates.iter().filter(|(i, _)| !left_used.contains(i)).map(|(i, s)| (*i, s)).collect();
    let mut remaining_right: Vec<(usize, &alloc::vec::Vec<u8>)> =
        right_candidates.iter().filter(|(i, _)| !right_used.contains(i)).map(|(i, s)| (*i, s)).collect();
    // Pair greedily: highest similarity first.
    let mut scored: Vec<(usize, usize, usize)> = Vec::new(); // (matching_bytes, l, r)
    for (l_idx, l_sig) in &remaining_left {
        for (r_idx, r_sig) in &remaining_right {
            if l_sig.len() != r_sig.len() {
                continue;
            }
            let matching = l_sig.iter().zip(r_sig.iter()).filter(|(a, b)| a == b).count();
            // Require at least 50% byte equality after masking — purely a tunable
            // threshold; in practice the funclets either match cleanly (95%+) or
            // they're truly different code.
            if matching * 2 >= l_sig.len() {
                scored.push((matching, *l_idx, *r_idx));
            }
        }
    }
    // Sort by descending byte-similarity, breaking ties by symbol name so the greedy
    // assignment is fully deterministic w.r.t. symbol-table order (not relying on
    // sort stability + insertion order).
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| left.symbols[a.1].name.cmp(&left.symbols[b.1].name))
            .then_with(|| right.symbols[a.2].name.cmp(&right.symbols[b.2].name))
    });
    for (_, l_idx, r_idx) in scored {
        if left_used.contains(&l_idx) || right_used.contains(&r_idx) {
            continue;
        }
        matches.push(SymbolMatch {
            left: Some(l_idx),
            right: Some(r_idx),
            prev: None,
            section_kind: SectionKind::Code,
        });
        left_used.insert(l_idx);
        right_used.insert(r_idx);
    }
    let _ = (remaining_left.len(), remaining_right.len()); // suppress warning on no-op shrink
    remaining_left.clear();
    remaining_right.clear();
}

fn unmatched_symbols<'obj, 'used>(
    obj: &'obj Object,
    used: Option<&'used BTreeSet<usize>>,
) -> impl Iterator<Item = (usize, &'obj Symbol)> + 'used
where
    'obj: 'used,
{
    obj.symbols.iter().enumerate().filter(move |&(symbol_idx, symbol)| {
        !symbol.flags.contains(SymbolFlag::Ignored)
            // Skip symbols that have already been matched
            && !used.is_some_and(|u| u.contains(&symbol_idx))
    })
}

fn symbol_section<'obj>(obj: &'obj Object, symbol: &Symbol) -> Option<(&'obj str, SectionKind)> {
    if let Some(section) = symbol.section.and_then(|section_idx| obj.sections.get(section_idx)) {
        // Match x86 .rdata$r against .rdata$rs
        let section_name =
            section.name.split_once('$').map_or(section.name.as_str(), |(prefix, _)| prefix);
        Some((section_name, section.kind))
    } else if symbol.flags.contains(SymbolFlag::Common) {
        Some((".comm", SectionKind::Common))
    } else {
        None
    }
}

fn symbol_section_kind(obj: &Object, symbol: &Symbol) -> SectionKind {
    match symbol.section {
        Some(section_index) => obj.sections[section_index].kind,
        None if symbol.flags.contains(SymbolFlag::Common) => SectionKind::Common,
        None => SectionKind::Unknown,
    }
}

fn find_symbol(
    obj: Option<&Object>,
    in_obj: &Object,
    in_symbol_idx: usize,
    used: Option<&BTreeSet<usize>>,
    fuzzy_literals: bool,
) -> Option<usize> {
    let in_symbol = &in_obj.symbols[in_symbol_idx];
    let obj = obj?;
    let (section_name, section_kind) = symbol_section(in_obj, in_symbol)?;

    // Match compiler-generated symbols against each other (e.g. @251 -> @60)
    // If they are in the same section and have the same value
    if in_symbol.flags.contains(SymbolFlag::CompilerGenerated)
        && matches!(section_kind, SectionKind::Code | SectionKind::Data | SectionKind::Bss)
    {
        let mut closest_match_symbol_idx = None;
        let mut closest_match_percent = 0.0;
        for (symbol_idx, symbol) in unmatched_symbols(obj, used) {
            let Some(section_index) = symbol.section else {
                continue;
            };
            if obj.sections[section_index].name != section_name {
                continue;
            }
            if !symbol.flags.contains(SymbolFlag::CompilerGenerated) {
                continue;
            }
            match section_kind {
                SectionKind::Data | SectionKind::Code => {
                    // For code or data, pick the first symbol with exactly matching bytes and relocations.
                    // If no symbols match exactly, and `fuzzy_literals` is true, pick the closest
                    // plausible match instead.
                    if let Ok((left_diff, _right_diff)) =
                        diff_data_symbol(in_obj, obj, in_symbol_idx, symbol_idx)
                        && let Some(match_percent) = left_diff.match_percent
                        && (match_percent == 100.0
                            || (fuzzy_literals
                                && match_percent >= 50.0
                                && match_percent > closest_match_percent))
                    {
                        closest_match_symbol_idx = Some(symbol_idx);
                        closest_match_percent = match_percent;
                        if match_percent == 100.0 {
                            break;
                        }
                    }
                }
                SectionKind::Bss => {
                    // For BSS, pick the first symbol that has the exact matching size.
                    if in_symbol.size == symbol.size {
                        closest_match_symbol_idx = Some(symbol_idx);
                        break;
                    }
                }
                _ => unreachable!(),
            }
        }
        return closest_match_symbol_idx;
    }

    // Try to find a symbol with a matching name
    if let Some((symbol_idx, _)) = unmatched_symbols(obj, used).find(|&(_, symbol)| {
        symbol_name_matches(in_symbol, symbol)
            && symbol_section_kind(obj, symbol) == section_kind
            && symbol_section(obj, symbol).is_some_and(|(name, _)| name == section_name)
    }) {
        return Some(symbol_idx);
    }

    None
}

/// Cheap name-only symbol matching (skips expensive data diffs for compiler-generated symbols).
/// Used when filtering symbols to avoid O(n²) data diffs for symbols we don't care about.
fn find_symbol_by_name(
    obj: Option<&Object>,
    in_obj: &Object,
    in_symbol_idx: usize,
    used: Option<&BTreeSet<usize>>,
) -> Option<usize> {
    let in_symbol = &in_obj.symbols[in_symbol_idx];
    let obj = obj?;
    let (section_name, section_kind) = symbol_section(in_obj, in_symbol)?;

    // Skip compiler-generated symbols entirely (they need data diffs to match)
    if in_symbol.flags.contains(SymbolFlag::CompilerGenerated) {
        return None;
    }

    // Name-based match only
    if let Some((symbol_idx, _)) = unmatched_symbols(obj, used).find(|&(_, symbol)| {
        symbol_name_matches(in_symbol, symbol)
            && symbol_section_kind(obj, symbol) == section_kind
            && symbol_section(obj, symbol).is_some_and(|(name, _)| name == section_name)
    }) {
        return Some(symbol_idx);
    }

    None
}

/// Find matching sections between each object.
fn matching_sections(left: Option<&Object>, right: Option<&Object>) -> Result<Vec<SectionMatch>> {
    let mut matches = Vec::with_capacity(
        left.as_ref()
            .map_or(0, |o| o.sections.len())
            .max(right.as_ref().map_or(0, |o| o.sections.len())),
    );
    if let Some(left) = left {
        for (section_idx, section) in left.sections.iter().enumerate() {
            if section.kind == SectionKind::Unknown {
                continue;
            }
            matches.push(SectionMatch {
                left: Some(section_idx),
                right: find_section(right, &section.name, section.kind, &matches),
                section_kind: section.kind,
            });
        }
    }
    if let Some(right) = right {
        for (section_idx, section) in right.sections.iter().enumerate() {
            if section.kind == SectionKind::Unknown {
                continue;
            }
            if matches.iter().any(|m| m.right == Some(section_idx)) {
                continue;
            }
            matches.push(SectionMatch {
                left: None,
                right: Some(section_idx),
                section_kind: section.kind,
            });
        }
    }
    Ok(matches)
}

fn find_section(
    obj: Option<&Object>,
    name: &str,
    section_kind: SectionKind,
    matches: &[SectionMatch],
) -> Option<usize> {
    obj?.sections.iter().enumerate().position(|(i, s)| {
        s.kind == section_kind && s.name == name && !matches.iter().any(|m| m.right == Some(i))
    })
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiffSide {
    /// The target/expected side of the diff.
    Target,
    /// The base side of the diff.
    Base,
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::obj::{RelocationFlags, Section, SectionData, SymbolKind};

    /// `is_funclet_like` defines exactly which symbols are eligible for byte-equality
    /// fallback pairing in `pair_funclets_by_bytes`. Lock both the positive and
    /// negative cases so we don't accidentally widen the predicate (e.g. start
    /// matching ordinary `fn_XXXXXXXX`-style functions outside of EH funclets).
    #[test]
    fn test_is_funclet_like_positives() {
        assert!(is_funclet_like("__unwind$0"));
        assert!(is_funclet_like("__unwind$117007"));
        assert!(is_funclet_like("__catch$12"));
        assert!(is_funclet_like("__catch$999"));
        assert!(is_funclet_like("__unwind__merged_82345678"));
        // dtk's splitter sometimes emits a target funclet as `fn_<8 hex digits>` when
        // the original COMDAT name collides across object files.
        assert!(is_funclet_like("fn_8239FCE0"));
        assert!(is_funclet_like("fn_00000000"));
        // MSVC global dynamic initializer / destructor thunks.  These appear by their
        // mangled names in the compiled base object, but as `fn_<addr>` on the XEX
        // target side where dtk loses the original COMDAT name.
        assert!(is_funclet_like("??__EgFile@@YAXXZ"));
        assert!(is_funclet_like("??__EgConditional@@YAXXZ"));
        assert!(is_funclet_like("??__FgDataReadCrit@@YAXXZ"));
        assert!(is_funclet_like("??__EsLicense@@YAXXZ"));
        assert!(is_funclet_like("??__E?sRand@CameraManager@@2VRand@@A@@YAXXZ"));
    }

    #[test]
    fn test_is_funclet_like_negatives() {
        // Mangled C++ symbol — not a funclet.
        assert!(!is_funclet_like("?Foo@Bar@@QAEXXZ"));
        // PowerPC compiler-emitted helper — not a funclet.
        assert!(!is_funclet_like("__savegprlr_14"));
        // Label-style synthetic symbol — not a funclet.
        assert!(!is_funclet_like("lbl_82F64970"));
        // Ordinary MSVC mangled name — not a funclet.
        assert!(!is_funclet_like("?ClassName@@QAEXXZ"));
        // Empty / wrong-length / non-hex `fn_` candidates.
        assert!(!is_funclet_like("fn_"));
        assert!(!is_funclet_like("fn_123")); // too short
        assert!(!is_funclet_like("fn_GGGGGGGG")); // not hex
        // `__unwind$` followed by non-digits.
        assert!(!is_funclet_like("__unwind$abc"));
        // Plain text.
        assert!(!is_funclet_like("main"));
        assert!(!is_funclet_like(""));
        // `??__` followed by non-E/F is NOT a dynamic-init/dtor pattern.
        assert!(!is_funclet_like("??__G"));   // scalar deleting destructor — not a lifecycle thunk
        assert!(!is_funclet_like("??__R"));   // RTTI base-class descriptor — not a thunk
    }

    /// Build a minimal `Object` containing a single `.text` section with the given
    /// bytes, one symbol named `name` covering the whole section, optionally with
    /// the given relocations attached to the section.
    fn make_funclet_obj(name: &str, bytes: Vec<u8>, relocs: Vec<Relocation>) -> Object {
        let size = bytes.len() as u64;
        let section = Section {
            id: ".text-0".to_string(),
            name: ".text".to_string(),
            address: 0,
            size,
            kind: SectionKind::Code,
            data: SectionData(bytes),
            relocations: relocs,
            ..Default::default()
        };
        let symbol = Symbol {
            name: name.to_string(),
            address: 0,
            size,
            kind: SymbolKind::Function,
            section: Some(0),
            ..Default::default()
        };
        Object { symbols: vec![symbol], sections: vec![section], ..Default::default() }
    }

    /// Pass-1 fixture: target side has `fn_82345678` (dtk's stripped-COMDAT name),
    /// base side has `__unwind$42` (MSVC EH funclet number). The bytes are
    /// identical *after* zeroing the 4-byte reloc window at offset 4, so the
    /// signature-based pairing must produce a single match.
    #[test]
    fn test_pair_funclets_by_bytes_pass1_pairs_fn_with_unwind() {
        // 8 bytes: a "lis" word at offset 0 and a relocated word at offset 4 that
        // differs between the two sides. After the 4-byte reloc-window zero, the
        // signatures are equal.
        let target_bytes = vec![0x3C, 0x60, 0x82, 0x34, 0xAA, 0xBB, 0xCC, 0xDD];
        let base_bytes = vec![0x3C, 0x60, 0x82, 0x34, 0x11, 0x22, 0x33, 0x44];
        let reloc = Relocation {
            flags: RelocationFlags::Coff(0),
            address: 4,
            target_symbol: 0,
            addend: 0,
        };

        let left = make_funclet_obj("fn_82345678", target_bytes, vec![reloc.clone()]);
        let right = make_funclet_obj("__unwind$42", base_bytes, vec![reloc]);

        let mut left_used = BTreeSet::new();
        let mut right_used = BTreeSet::new();
        let mut matches = Vec::new();

        pair_funclets_by_bytes(&left, &right, &mut left_used, &mut right_used, &mut matches);

        assert_eq!(matches.len(), 1, "expected exactly one funclet pairing, got {}", matches.len());
        let m = &matches[0];
        assert_eq!(m.left, Some(0));
        assert_eq!(m.right, Some(0));
        assert_eq!(m.section_kind, SectionKind::Code);
        assert!(left_used.contains(&0));
        assert!(right_used.contains(&0));
    }

    /// Sanity check: two funclets with *different* underlying bytes (even after
    /// reloc masking) must not be paired. This guards against a buggy pass-1
    /// that pairs any unmatched funclet-like symbol regardless of signature.
    #[test]
    fn test_pair_funclets_by_bytes_does_not_pair_dissimilar_bytes() {
        let target_bytes = vec![0x3C, 0x60, 0x82, 0x34, 0x00, 0x00, 0x00, 0x00];
        let base_bytes = vec![0x60, 0x00, 0x00, 0x00, 0x4E, 0x80, 0x00, 0x20];

        let left = make_funclet_obj("fn_DEADBEEF", target_bytes, vec![]);
        let right = make_funclet_obj("__unwind$7", base_bytes, vec![]);

        let mut left_used = BTreeSet::new();
        let mut right_used = BTreeSet::new();
        let mut matches = Vec::new();

        pair_funclets_by_bytes(&left, &right, &mut left_used, &mut right_used, &mut matches);

        // Pass 3 fuzzy requires >=50% byte equality. These two share fewer than
        // half their bytes after masking, so nothing should pair.
        assert!(matches.is_empty(), "expected no pairings, got {}", matches.len());
        assert!(left_used.is_empty());
        assert!(right_used.is_empty());
    }

    /// Build an `Object` with one `.text` section holding several equal-size funclet
    /// symbols laid out back-to-back. `funcs` is `(name, bytes)`. Relocations are
    /// applied at absolute section offsets in `relocs`.
    fn make_multi_funclet_obj(funcs: &[(&str, Vec<u8>)], relocs: Vec<Relocation>) -> Object {
        let mut data = Vec::new();
        let mut symbols = Vec::new();
        let mut addr = 0u64;
        for (name, bytes) in funcs {
            let size = bytes.len() as u64;
            symbols.push(Symbol {
                name: name.to_string(),
                address: addr,
                size,
                kind: SymbolKind::Function,
                section: Some(0),
                ..Default::default()
            });
            data.extend_from_slice(bytes);
            addr += size;
        }
        let section = Section {
            id: ".text-0".to_string(),
            name: ".text".to_string(),
            address: 0,
            size: data.len() as u64,
            kind: SectionKind::Code,
            data: SectionData(data),
            relocations: relocs,
            ..Default::default()
        };
        Object { symbols, sections: vec![section], ..Default::default() }
    }

    /// Over-subscription regression (the BandDirector `fn_<addr>` case).
    ///
    /// The target side has N=3 funclets whose masked signatures are all byte-identical;
    /// the base side has only M=2 byte-identical funclets plus one *different* funclet.
    /// Strict 1:1 would pair 2 targets to the 2 identical base funclets and shove the
    /// 3rd (overflow) target into pass-3 fuzzy matching against the non-identical base
    /// funclet, dragging it below the group ceiling. With the pass-2b overflow fix, the
    /// overflow target must instead pair many-to-one to one of the *identical* base
    /// funclets, and the non-identical base funclet must be left unpaired.
    #[test]
    fn test_pair_funclets_oversubscribed_identical_group_pairs_overflow_to_identical() {
        // 8-byte funclets. Byte 4..8 is reloc-masked, so it doesn't affect the signature.
        // "A" signature (first 4 bytes 3C 60 82 34); "B" signature is different code.
        let sig_a_1 = vec![0x3C, 0x60, 0x82, 0x34, 0x11, 0x11, 0x11, 0x11];
        let sig_a_2 = vec![0x3C, 0x60, 0x82, 0x34, 0x22, 0x22, 0x22, 0x22];
        let sig_a_3 = vec![0x3C, 0x60, 0x82, 0x34, 0x33, 0x33, 0x33, 0x33];
        let sig_a_b1 = vec![0x3C, 0x60, 0x82, 0x34, 0x44, 0x44, 0x44, 0x44];
        let sig_a_b2 = vec![0x3C, 0x60, 0x82, 0x34, 0x55, 0x55, 0x55, 0x55];
        // Different code, but >=50% byte-equal to sig_a after masking (so pass-3 fuzzy
        // *would* greedily grab it if the overflow reached pass 3): first two bytes
        // match (0x3C 0x60), the rest differs.
        let sig_diff = vec![0x3C, 0x60, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66];

        // Relocation at offset 4 of every 8-byte funclet, so bytes 4..8 are masked.
        let mut relocs = Vec::new();
        for i in 0..6u64 {
            relocs.push(Relocation {
                flags: RelocationFlags::Coff(0),
                address: i * 8 + 4,
                target_symbol: 0,
                addend: 0,
            });
        }

        // Target: 3 identical-signature funclets. Names chosen so that after the name
        // sort, fn_82282350 is the lexicographic overflow loser (it has no exact 1:1
        // partner left after pass 2 consumes the two base funclets).
        let left = make_multi_funclet_obj(
            &[
                ("fn_82281000", sig_a_1.clone()),
                ("fn_82282000", sig_a_2.clone()),
                ("fn_82283000", sig_a_3.clone()),
            ],
            relocs.iter().take(3).cloned().collect(),
        );
        // Base: 2 identical-signature funclets + 1 different funclet.
        let right = make_multi_funclet_obj(
            &[
                ("__unwind$100", sig_a_b1.clone()),
                ("__unwind$200", sig_a_b2.clone()),
                ("__unwind$300", sig_diff.clone()),
            ],
            relocs.iter().take(3).cloned().collect(),
        );

        let mut left_used = BTreeSet::new();
        let mut right_used = BTreeSet::new();
        let mut matches = Vec::new();
        pair_funclets_by_bytes(&left, &right, &mut left_used, &mut right_used, &mut matches);

        // All three target funclets must be paired (none left for pass-3 fuzzy).
        for l in 0..3usize {
            assert!(left_used.contains(&l), "target funclet {l} should be paired");
        }

        // Compute the identical "A" masked signature to validate each pairing.
        let sig_a = funclet_signature(&left, 0).unwrap();

        // Every target must be paired to a base funclet whose signature is byte-identical
        // to the "A" signature — i.e. NEVER to __unwind$300 (the non-identical funclet).
        let diff_base_idx = 2usize; // __unwind$300
        for m in &matches {
            let Some(l) = m.left else { continue };
            let r = m.right.expect("paired target must have a right");
            assert_ne!(
                r, diff_base_idx,
                "target {} ({}) was fuzzy-paired to the non-identical base __unwind$300",
                l, left.symbols[l].name
            );
            let r_sig = funclet_signature(&right, r).unwrap();
            assert_eq!(
                r_sig, sig_a,
                "target {} ({}) paired to base {} ({}) which is NOT byte-identical",
                l, left.symbols[l].name, r, right.symbols[r].name
            );
        }

        // The non-identical base funclet must be left unpaired (it has no identical
        // target and the overflow was satisfied by reuse, not fuzzy).
        assert!(
            !right_used.contains(&diff_base_idx),
            "non-identical base __unwind$300 should not be consumed"
        );

        // Exactly one base partner is reused (many-to-one): 3 targets, 2 distinct
        // identical base partners.
        let distinct_rights: BTreeSet<usize> = matches.iter().filter_map(|m| m.right).collect();
        assert_eq!(distinct_rights.len(), 2, "overflow should reuse an identical base partner");
        assert_eq!(matches.len(), 3, "all three targets should be matched");
    }

    /// Negative guard for the pass-2b overflow fix: an over-subscribed target funclet
    /// that is NOT byte-identical to any base funclet must still be handled by pass-3
    /// fuzzy (or left unpaired) — the overflow reuse must fire ONLY on exact signature
    /// hits, never inflating a genuinely-different funclet.
    #[test]
    fn test_pair_funclets_oversubscribed_does_not_reuse_for_nonidentical() {
        // Target: 2 funclets with signature "A", base: 1 funclet with signature "A".
        // Plus a target funclet with a totally different signature and NO base partner.
        let sig_a_1 = vec![0x3C, 0x60, 0x82, 0x34, 0x11, 0x11, 0x11, 0x11];
        let sig_a_2 = vec![0x3C, 0x60, 0x82, 0x34, 0x22, 0x22, 0x22, 0x22];
        let sig_a_b1 = vec![0x3C, 0x60, 0x82, 0x34, 0x33, 0x33, 0x33, 0x33];
        // Totally different code, <50% equal to sig_a after masking.
        let sig_other = vec![0x7F, 0xE0, 0xFB, 0x78, 0x66, 0x66, 0x66, 0x66];

        let mut relocs = Vec::new();
        for i in 0..3u64 {
            relocs.push(Relocation {
                flags: RelocationFlags::Coff(0),
                address: i * 8 + 4,
                target_symbol: 0,
                addend: 0,
            });
        }

        let left = make_multi_funclet_obj(
            &[("fn_82281000", sig_a_1), ("fn_82282000", sig_a_2), ("fn_82283000", sig_other)],
            relocs.iter().take(3).cloned().collect(),
        );
        let right =
            make_multi_funclet_obj(&[("__unwind$100", sig_a_b1)], relocs.iter().take(1).cloned().collect());

        let mut left_used = BTreeSet::new();
        let mut right_used = BTreeSet::new();
        let mut matches = Vec::new();
        pair_funclets_by_bytes(&left, &right, &mut left_used, &mut right_used, &mut matches);

        // The single base funclet is byte-identical to the two "A" targets: one pairs
        // 1:1 (pass 2), the overflow reuses it (pass 2b). Both A targets are paired.
        assert!(left_used.contains(&0));
        assert!(left_used.contains(&1));
        // The third target (sig_other) is NOT byte-identical to any base funclet and
        // there is no same-size >=50% fuzzy partner, so it must remain UNPAIRED — the
        // overflow reuse must not have grabbed the "A" base for it.
        assert!(!left_used.contains(&2), "non-identical target must not be paired");
        for m in &matches {
            assert_ne!(m.left, Some(2), "non-identical target must not be in matches");
        }
    }
}
