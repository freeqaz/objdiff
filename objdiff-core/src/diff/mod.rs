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
/// `__unwind$NNN`, `__catch$NNN`, `__unwind__merged_<addr>`, `fn_<8 hex digits>`.
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
    false
}

/// Extract a symbol's byte payload with all relocation-targeted bytes zeroed.
/// Both sides emit COFF with zero immediates at every relocation site, so
/// after masking we can compare the pure instruction encoding.
fn funclet_signature(obj: &Object, sym_idx: usize) -> Option<alloc::vec::Vec<u8>> {
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
    scored.sort_by(|a, b| b.0.cmp(&a.0));
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
}
