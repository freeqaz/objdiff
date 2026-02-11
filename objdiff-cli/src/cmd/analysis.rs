//! Pattern detection and fixability analysis for decompilation diffs.
//!
//! This module implements automated diagnosis of instruction mismatches,
//! detecting common patterns that explain why code doesn't match and
//! providing verdict classifications for triage.

use std::{collections::HashMap, sync::LazyLock};

use regex::Regex;
use serde::Serialize;

use super::diff::{InstructionDiffOutput, InstructionInfo, InstructionSummary};

// =============================================================================
// Constants
// =============================================================================

/// Threshold: if >= 80% of mismatches are merged function calls, consider at limit
const MERGED_RATIO_AT_LIMIT: f32 = 0.8;

/// Threshold: if < 50% merged, control flow issues may still be fixable
const MERGED_RATIO_LIKELY_FIXABLE: f32 = 0.5;

/// Minimum occurrences of a register swap to consider it significant
const MIN_REGISTER_SWAP_OCCURRENCES: usize = 3;

/// Don't analyze functions with only 1 mismatch (simple manual check)
const MIN_MISMATCH_FOR_ANALYSIS: usize = 2;

// =============================================================================
// Patterns
// =============================================================================

/// Regex to detect linker-merged function names.
/// Matches:
/// - `merged_*` (named or address-based merged functions)
/// - `OnlyReturns` (trivial return functions)
/// - `??_G*PAXI@Z` (MSVC scalar destructors)
/// - `??_E*PAXI@Z` (MSVC vector destructors)
static MERGED_FUNC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(merged_|OnlyReturns|\?\?_[EG].*PAXI@Z$)").unwrap());

/// Regex to extract register names (r0-r31, f0-f31)
static REGISTER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b([rf]\d+)\b").unwrap());

// =============================================================================
// Types
// =============================================================================

/// Types of patterns that can be detected in instruction diffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PatternType {
    /// Calls to linker-merged functions (unfixable)
    LinkerMerged,
    /// Bool return masking with clrlwi/rlwinm (usually unfixable)
    BoolMask,
    /// Consistent register allocation swaps (sometimes fixable)
    RegisterSwap,
    /// Comparison immediate differs by 1, suggesting > vs >= style difference
    ComparisonStyle,
    /// Branch instruction differences (diff_op/replace on branches)
    ControlFlow,
    /// Operand order swapped in commutative operations (fadd, fmul, add, etc.)
    CommutativeOpOrder,
    /// Two offsets swapped between target and base
    OffsetSwap,
}

impl PatternType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PatternType::LinkerMerged => "LINKER_MERGED",
            PatternType::BoolMask => "BOOL_MASK",
            PatternType::RegisterSwap => "REGISTER_SWAP",
            PatternType::ComparisonStyle => "COMPARISON_STYLE",
            PatternType::ControlFlow => "CONTROL_FLOW",
            PatternType::CommutativeOpOrder => "COMMUTATIVE_OP_ORDER",
            PatternType::OffsetSwap => "OFFSET_SWAP",
        }
    }
}

/// Confidence level of pattern detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// How likely a pattern is to be fixable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fixability {
    Unfixable,
    UsuallyUnfixable,
    MaybeFixable,
    LikelyFixable,
}

/// Count of calls to a specific merged function.
#[derive(Debug, Clone, Serialize)]
pub struct MergedFunctionCount {
    pub name: String,
    pub count: usize,
}

/// Information about a detected register swap.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterSwapInfo {
    pub target_reg: String,
    pub base_reg: String,
    pub count: usize,
}

/// Information about a comparison style difference.
#[derive(Debug, Clone, Serialize)]
pub struct ComparisonStyleInfo {
    pub index: usize,
    pub opcode: String,
    pub target_value: i64,
    pub base_value: i64,
}

/// Information about a branch instruction difference.
#[derive(Debug, Clone, Serialize)]
pub struct BranchDiffInfo {
    pub index: usize,
    pub target_opcode: Option<String>,
    pub base_opcode: Option<String>,
    pub match_type: String,
}

/// Information about a commutative operation with swapped operands.
#[derive(Debug, Clone, Serialize)]
pub struct CommutativeOpInfo {
    pub index: usize,
    pub opcode: String,
    pub target_operands: Vec<String>,
    pub base_operands: Vec<String>,
}

/// Information about an offset swap between two instructions.
#[derive(Debug, Clone, Serialize)]
pub struct OffsetSwapInfo {
    pub indices: (usize, usize),
    pub target_offsets: (i64, i64),
    pub base_offsets: (i64, i64),
}

/// Details specific to each pattern type.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum PatternDetails {
    /// Merged function call counts
    MergedFunctions { merged_functions: Vec<MergedFunctionCount> },
    /// Bool mask bit positions detected
    BoolMask { bit_positions: Vec<u8> },
    /// Register swap mappings with occurrence counts
    RegisterSwap { swaps: Vec<RegisterSwapInfo> },
    /// Comparison style differences (> vs >=)
    ComparisonStyle { comparisons: Vec<ComparisonStyleInfo> },
    /// Control flow branch differences
    ControlFlow { branch_diffs: Vec<BranchDiffInfo> },
    /// Commutative operation with swapped operands
    CommutativeOpOrder { swaps: Vec<CommutativeOpInfo> },
    /// Offset swaps between instruction pairs
    OffsetSwap { swaps: Vec<OffsetSwapInfo> },
}

/// A detected pattern in the instruction diff.
#[derive(Debug, Clone, Serialize)]
pub struct Pattern {
    pub pattern: PatternType,
    pub confidence: Confidence,
    pub instruction_count: usize,
    pub fixability: Fixability,
    pub details: PatternDetails,
}

/// Full analysis results.
#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    pub patterns: Vec<Pattern>,
    pub patterns_checked: Vec<&'static str>,
    pub unattributed_mismatches: usize,
}

impl Analysis {
    /// Check if a specific pattern type was detected.
    pub fn has_pattern(&self, pattern_type: PatternType) -> bool {
        self.patterns.iter().any(|p| p.pattern == pattern_type)
    }

    /// Get total instruction count attributed to a pattern type.
    pub fn pattern_instruction_count(&self, pattern_type: PatternType) -> usize {
        self.patterns
            .iter()
            .filter(|p| p.pattern == pattern_type)
            .map(|p| p.instruction_count)
            .sum()
    }
}

// =============================================================================
// Pattern Summarization (compact markdown output)
// =============================================================================

/// Compact summary of a pattern for markdown rendering.
/// JSON output retains full details; this is only used for markdown.
#[derive(Debug, Clone)]
pub struct PatternSummary {
    pub one_line: String,
    pub top_details: Vec<String>,
    pub truncated: bool,
    pub total_items: usize,
}

impl Pattern {
    /// Generate a compact summary for markdown rendering.
    pub fn summarize(&self) -> PatternSummary {
        match &self.details {
            PatternDetails::RegisterSwap { swaps } => {
                let total_occurrences: usize = swaps.iter().map(|s| s.count).sum();
                let pairs = swaps.len();
                let one_line = if pairs == 1 {
                    format!(
                        "{} instructions, {} pair ({}↔{})",
                        total_occurrences, pairs, swaps[0].target_reg, swaps[0].base_reg
                    )
                } else {
                    let dominant = &swaps[0]; // sorted by count descending
                    format!(
                        "{} instructions across {} pairs, dominated by {}↔{} ({} of {})",
                        self.instruction_count,
                        pairs,
                        dominant.target_reg,
                        dominant.base_reg,
                        dominant.count,
                        total_occurrences
                    )
                };
                let top_details: Vec<String> = swaps
                    .iter()
                    .take(3)
                    .map(|s| format!("{}↔{}: {}", s.target_reg, s.base_reg, s.count))
                    .collect();
                PatternSummary {
                    one_line,
                    top_details,
                    truncated: swaps.len() > 3,
                    total_items: pairs,
                }
            }
            PatternDetails::OffsetSwap { swaps } => {
                let total = swaps.len();
                // Group by offset pair to find dominant pattern
                let mut pair_counts: HashMap<(i64, i64), usize> = HashMap::new();
                for swap in swaps {
                    let key = if swap.target_offsets.0 < swap.target_offsets.1 {
                        (swap.target_offsets.0, swap.target_offsets.1)
                    } else {
                        (swap.target_offsets.1, swap.target_offsets.0)
                    };
                    *pair_counts.entry(key).or_insert(0) += 1;
                }
                let mut sorted_pairs: Vec<_> = pair_counts.into_iter().collect();
                sorted_pairs.sort_by(|a, b| b.1.cmp(&a.1));

                let one_line = if sorted_pairs.len() == 1 {
                    let ((a, b), count) = sorted_pairs[0];
                    format!("{} swap(s) of (0x{:x},0x{:x})", count, a, b)
                } else {
                    let ((a, b), count) = sorted_pairs[0];
                    format!("{} offset swaps, dominated by (0x{:x},0x{:x}) x{}", total, a, b, count)
                };
                let top_details: Vec<String> = sorted_pairs
                    .iter()
                    .take(3)
                    .map(|((a, b), count)| format!("(0x{:x},0x{:x}): {} swap(s)", a, b, count))
                    .collect();
                PatternSummary {
                    one_line,
                    top_details,
                    truncated: sorted_pairs.len() > 3,
                    total_items: total,
                }
            }
            PatternDetails::ControlFlow { branch_diffs } => {
                // Categorize branch diffs
                let mut inversions = 0usize;
                let mut replacements = 0usize;
                let mut inversion_types: HashMap<String, usize> = HashMap::new();
                let mut replacement_types: HashMap<String, usize> = HashMap::new();

                for bd in branch_diffs {
                    let target = bd.target_opcode.as_deref().unwrap_or("-");
                    let base = bd.base_opcode.as_deref().unwrap_or("-");
                    if bd.match_type == "diff_op" {
                        inversions += 1;
                        let key = format!("{}↔{}", target, base);
                        *inversion_types.entry(key).or_insert(0) += 1;
                    } else {
                        replacements += 1;
                        let key = format!("{}↔{}", target, base);
                        *replacement_types.entry(key).or_insert(0) += 1;
                    }
                }

                let mut parts = Vec::new();
                if inversions > 0 {
                    // Find dominant inversion type
                    let dominant = inversion_types.iter().max_by_key(|(_, c)| *c);
                    if let Some((typ, _)) = dominant {
                        parts.push(format!("{} condition inversion(s) ({})", inversions, typ));
                    } else {
                        parts.push(format!("{} condition inversion(s)", inversions));
                    }
                }
                if replacements > 0 {
                    let dominant = replacement_types.iter().max_by_key(|(_, c)| *c);
                    if let Some((typ, _)) = dominant {
                        parts.push(format!("{} replacement(s) ({})", replacements, typ));
                    } else {
                        parts.push(format!("{} replacement(s)", replacements));
                    }
                }
                let one_line = parts.join(", ");

                let top_details: Vec<String> = branch_diffs
                    .iter()
                    .take(3)
                    .map(|bd| {
                        let target = bd.target_opcode.as_deref().unwrap_or("-");
                        let base = bd.base_opcode.as_deref().unwrap_or("-");
                        format!("idx {}: {} vs {} ({})", bd.index, target, base, bd.match_type)
                    })
                    .collect();

                PatternSummary {
                    one_line,
                    top_details,
                    truncated: branch_diffs.len() > 3,
                    total_items: branch_diffs.len(),
                }
            }
            // These patterns are already compact - just format normally
            PatternDetails::MergedFunctions { merged_functions } => {
                let total_calls: usize = merged_functions.iter().map(|f| f.count).sum();
                let unique = merged_functions.len();
                let one_line = format!("{} call(s) to {} merged function(s)", total_calls, unique);
                let top_details: Vec<String> = merged_functions
                    .iter()
                    .take(3)
                    .map(|mf| format!("`{}`: {} call(s)", mf.name, mf.count))
                    .collect();
                PatternSummary {
                    one_line,
                    top_details,
                    truncated: merged_functions.len() > 3,
                    total_items: unique,
                }
            }
            PatternDetails::BoolMask { bit_positions } => {
                let positions: Vec<String> = bit_positions.iter().map(|b| b.to_string()).collect();
                PatternSummary {
                    one_line: format!(
                        "{} instruction(s), bit positions: [{}]",
                        self.instruction_count,
                        positions.join(", ")
                    ),
                    top_details: vec![],
                    truncated: false,
                    total_items: bit_positions.len(),
                }
            }
            PatternDetails::ComparisonStyle { comparisons } => {
                let one_line = format!("{} comparison(s) differing by 1", comparisons.len());
                let top_details: Vec<String> = comparisons
                    .iter()
                    .take(3)
                    .map(|c| {
                        format!(
                            "idx {}: {} ({} vs {})",
                            c.index, c.opcode, c.target_value, c.base_value
                        )
                    })
                    .collect();
                PatternSummary {
                    one_line,
                    top_details,
                    truncated: comparisons.len() > 3,
                    total_items: comparisons.len(),
                }
            }
            PatternDetails::CommutativeOpOrder { swaps } => {
                let one_line = format!("{} commutative operand swap(s)", swaps.len());
                let top_details: Vec<String> = swaps
                    .iter()
                    .take(3)
                    .map(|s| {
                        format!(
                            "idx {}: {} ({} vs {})",
                            s.index,
                            s.opcode,
                            s.target_operands.join(","),
                            s.base_operands.join(",")
                        )
                    })
                    .collect();
                PatternSummary {
                    one_line,
                    top_details,
                    truncated: swaps.len() > 3,
                    total_items: swaps.len(),
                }
            }
        }
    }
}

// =============================================================================
// Function Call Diff
// =============================================================================

/// Differences in function calls between target and base.
#[derive(Debug, Clone, Serialize)]
pub struct CallDiffOutput {
    /// Calls present only in target (reference binary)
    pub target_only: Vec<CallEntry>,
    /// Calls present only in base (decompiled)
    pub base_only: Vec<CallEntry>,
    /// Calls present in both but with different counts
    pub count_differs: Vec<CallCountDiff>,
}

/// A function call entry with count.
#[derive(Debug, Clone, Serialize)]
pub struct CallEntry {
    pub name: String,
    pub count: usize,
}

/// A function call present in both sides but with different counts.
#[derive(Debug, Clone, Serialize)]
pub struct CallCountDiff {
    pub name: String,
    pub target_count: usize,
    pub base_count: usize,
}

/// Compute the difference in function calls between target and base.
pub fn compute_call_diff(instructions: &[InstructionDiffOutput]) -> Option<CallDiffOutput> {
    let mut target_calls: HashMap<String, usize> = HashMap::new();
    let mut base_calls: HashMap<String, usize> = HashMap::new();

    for instr in instructions {
        // Check target side for bl calls
        if let Some(target) = &instr.target
            && target.opcode == "bl"
            && let Some(args) = &target.args
        {
            let name = args.trim().to_string();
            if !MERGED_FUNC_RE.is_match(&name) {
                *target_calls.entry(name).or_insert(0) += 1;
            }
        }
        // Check base side for bl calls
        if let Some(base) = &instr.base
            && base.opcode == "bl"
            && let Some(args) = &base.args
        {
            let name = args.trim().to_string();
            if !MERGED_FUNC_RE.is_match(&name) {
                *base_calls.entry(name).or_insert(0) += 1;
            }
        }
    }

    let mut target_only = Vec::new();
    let mut count_differs = Vec::new();

    for (name, t_count) in &target_calls {
        match base_calls.get(name) {
            None => target_only.push(CallEntry { name: name.clone(), count: *t_count }),
            Some(b_count) if b_count != t_count => {
                count_differs.push(CallCountDiff {
                    name: name.clone(),
                    target_count: *t_count,
                    base_count: *b_count,
                });
            }
            _ => {}
        }
    }

    let mut base_only: Vec<CallEntry> = base_calls
        .iter()
        .filter(|(name, _)| !target_calls.contains_key(*name))
        .map(|(name, count)| CallEntry { name: name.clone(), count: *count })
        .collect();

    // Sort all by name for stable output
    target_only.sort_by(|a, b| a.name.cmp(&b.name));
    base_only.sort_by(|a, b| a.name.cmp(&b.name));
    count_differs.sort_by(|a, b| a.name.cmp(&b.name));

    if target_only.is_empty() && base_only.is_empty() && count_differs.is_empty() {
        return None;
    }

    Some(CallDiffOutput { target_only, base_only, count_differs })
}

// =============================================================================
// Insert/Delete Clustering
// =============================================================================

/// A cluster of consecutive insert/delete instructions.
#[derive(Debug, Clone, Serialize)]
pub struct InsertDeleteCluster {
    pub start_index: usize,
    pub end_index: usize,
    pub insert_count: usize,
    pub delete_count: usize,
    pub dominant_opcodes: Vec<String>,
}

/// Compute clusters of consecutive insert/delete instructions.
/// Groups runs of insert/delete (allowing gaps of <= 2 equal instructions).
/// Only returns runs of 3+ insert/delete instructions.
pub fn compute_insert_delete_clusters(
    instructions: &[InstructionDiffOutput],
) -> Vec<InsertDeleteCluster> {
    let mut clusters = Vec::new();
    let mut i = 0;

    while i < instructions.len() {
        let mt = instructions[i].match_type.as_str();
        if mt != "insert" && mt != "delete" {
            i += 1;
            continue;
        }

        // Start of a potential cluster
        let start = i;
        let mut inserts = 0usize;
        let mut deletes = 0usize;
        let mut opcode_counts: HashMap<String, usize> = HashMap::new();
        let mut end = i;
        let mut gap = 0usize;

        while i < instructions.len() {
            let mt = instructions[i].match_type.as_str();
            if mt == "insert" || mt == "delete" {
                gap = 0;
                end = i;
                if mt == "insert" {
                    inserts += 1;
                    if let Some(base) = &instructions[i].base {
                        *opcode_counts.entry(base.opcode.clone()).or_insert(0) += 1;
                    }
                } else {
                    deletes += 1;
                    if let Some(target) = &instructions[i].target {
                        *opcode_counts.entry(target.opcode.clone()).or_insert(0) += 1;
                    }
                }
            } else {
                gap += 1;
                if gap > 2 {
                    break;
                }
            }
            i += 1;
        }

        let total = inserts + deletes;
        if total >= 3 {
            let mut sorted_opcodes: Vec<_> = opcode_counts.into_iter().collect();
            sorted_opcodes.sort_by(|a, b| b.1.cmp(&a.1));
            let dominant_opcodes: Vec<String> =
                sorted_opcodes.into_iter().take(3).map(|(op, _)| op).collect();

            clusters.push(InsertDeleteCluster {
                start_index: start,
                end_index: end,
                insert_count: inserts,
                delete_count: deletes,
                dominant_opcodes,
            });
        }
    }

    clusters
}

// =============================================================================
// Block-Level Diff Regions
// =============================================================================

/// A region of instructions with a local match percentage.
#[derive(Debug, Clone, Serialize)]
pub struct DiffRegion {
    pub start_index: usize,
    pub end_index: usize,
    pub instruction_count: usize,
    pub match_percent: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Minimum run of consecutive equal instructions to split regions.
const REGION_SPLIT_THRESHOLD: usize = 8;

/// Divide the instruction stream into matched/mismatched regions.
pub fn compute_diff_regions(
    instructions: &[InstructionDiffOutput],
    analysis: &Analysis,
) -> Vec<DiffRegion> {
    if instructions.is_empty() {
        return Vec::new();
    }

    // Find boundaries: runs of >= REGION_SPLIT_THRESHOLD equal instructions
    // These become "matched" regions; everything between becomes "mismatched" regions
    let mut regions = Vec::new();
    let len = instructions.len();
    let mut i = 0;

    // Build list of (start, end, is_matched) spans
    let mut spans: Vec<(usize, usize, bool)> = Vec::new();
    while i < len {
        if instructions[i].match_type == "equal" {
            // Count consecutive equals
            let start = i;
            while i < len && instructions[i].match_type == "equal" {
                i += 1;
            }
            let run_len = i - start;
            if run_len >= REGION_SPLIT_THRESHOLD {
                spans.push((start, i - 1, true));
            } else {
                spans.push((start, i - 1, false));
            }
        } else {
            let start = i;
            while i < len && instructions[i].match_type != "equal" {
                i += 1;
            }
            spans.push((start, i - 1, false));
        }
    }

    // Merge consecutive non-matched spans
    let mut merged_spans: Vec<(usize, usize, bool)> = Vec::new();
    for span in spans {
        if let Some(last) = merged_spans.last_mut()
            && !last.2
            && !span.2
        {
            // Both non-matched, merge
            last.1 = span.1;
            continue;
        }
        merged_spans.push(span);
    }

    // Convert spans to regions with stats
    for (start, end, _is_matched) in &merged_spans {
        let start = *start;
        let end = *end;
        let count = end - start + 1;
        let equal_count =
            instructions[start..=end].iter().filter(|i| i.match_type == "equal").count();
        let match_pct = (equal_count as f32 / count as f32) * 100.0;

        // Generate notes for mismatched regions
        let notes = if match_pct < 100.0 {
            let mut note_parts = Vec::new();

            // Check for dominant patterns in this region
            for pattern in &analysis.patterns {
                let region_instr_count =
                    count_pattern_in_range(pattern, &instructions[start..=end]);
                if region_instr_count > 0 {
                    let pname = match pattern.pattern {
                        PatternType::RegisterSwap => "register swaps",
                        PatternType::OffsetSwap => "offset swaps",
                        PatternType::ControlFlow => "control flow",
                        PatternType::LinkerMerged => "merged calls",
                        PatternType::BoolMask => "bool masks",
                        PatternType::ComparisonStyle => "comparison style",
                        PatternType::CommutativeOpOrder => "commutative ops",
                    };
                    note_parts.push(format!("{} {}", region_instr_count, pname));
                }
            }

            // Check for inserts/deletes
            let insert_count =
                instructions[start..=end].iter().filter(|i| i.match_type == "insert").count();
            let delete_count =
                instructions[start..=end].iter().filter(|i| i.match_type == "delete").count();
            if insert_count > 0 {
                note_parts.push(format!("{} inserts", insert_count));
            }
            if delete_count > 0 {
                note_parts.push(format!("{} deletes", delete_count));
            }

            if note_parts.is_empty() { None } else { Some(note_parts.join(", ")) }
        } else {
            None
        };

        regions.push(DiffRegion {
            start_index: start,
            end_index: end,
            instruction_count: count,
            match_percent: match_pct,
            notes,
        });
    }

    regions
}

/// Count how many instructions of a pattern fall within a given instruction slice.
fn count_pattern_in_range(pattern: &Pattern, instructions: &[InstructionDiffOutput]) -> usize {
    match &pattern.details {
        PatternDetails::RegisterSwap { swaps } => {
            // Register swaps are counted globally, not per-index, so approximate
            // by checking diff_arg instructions in range
            let diff_arg_count = instructions.iter().filter(|i| i.match_type == "diff_arg").count();
            // If there are diff_args and register swaps detected, attribute proportionally
            if diff_arg_count > 0 && pattern.instruction_count > 0 {
                // Simple heuristic: check if any diff_arg in range has register diffs
                let mut count = 0;
                for instr in instructions {
                    if instr.match_type != "diff_arg" {
                        continue;
                    }
                    let (Some(target), Some(base)) = (&instr.target, &instr.base) else {
                        continue;
                    };
                    if target.opcode != base.opcode {
                        continue;
                    }
                    let t_args = target.args.as_deref().unwrap_or("");
                    let b_args = base.args.as_deref().unwrap_or("");
                    let t_regs: Vec<&str> =
                        REGISTER_RE.find_iter(t_args).map(|m| m.as_str()).collect();
                    let b_regs: Vec<&str> =
                        REGISTER_RE.find_iter(b_args).map(|m| m.as_str()).collect();
                    for (t, b) in t_regs.iter().zip(b_regs.iter()) {
                        if t != b {
                            let key = if *t < *b {
                                (t.to_string(), b.to_string())
                            } else {
                                (b.to_string(), t.to_string())
                            };
                            // Check if this pair is in the swap list
                            if swaps.iter().any(|s| {
                                let swap_key = if s.target_reg < s.base_reg {
                                    (&s.target_reg, &s.base_reg)
                                } else {
                                    (&s.base_reg, &s.target_reg)
                                };
                                swap_key.0 == &key.0 && swap_key.1 == &key.1
                            }) {
                                count += 1;
                                break; // count each instruction once
                            }
                        }
                    }
                }
                count
            } else {
                0
            }
        }
        PatternDetails::ControlFlow { branch_diffs } => {
            // Check which branch diffs fall within this range
            let start_idx = instructions.first().map(|i| i.index).unwrap_or(0);
            let end_idx = instructions.last().map(|i| i.index).unwrap_or(0);
            branch_diffs.iter().filter(|bd| bd.index >= start_idx && bd.index <= end_idx).count()
        }
        PatternDetails::MergedFunctions { .. } => {
            // Count bl instructions to merged functions in range
            instructions
                .iter()
                .filter(|i| {
                    i.match_type == "diff_arg"
                        && i.target.as_ref().is_some_and(|t| {
                            t.opcode == "bl"
                                && t.args
                                    .as_ref()
                                    .is_some_and(|a| MERGED_FUNC_RE.is_match(a.trim()))
                        })
                })
                .count()
        }
        PatternDetails::OffsetSwap { swaps } => {
            let start_idx = instructions.first().map(|i| i.index).unwrap_or(0);
            let end_idx = instructions.last().map(|i| i.index).unwrap_or(0);
            swaps
                .iter()
                .filter(|s| {
                    s.indices.0 >= start_idx && s.indices.0 <= end_idx
                        || s.indices.1 >= start_idx && s.indices.1 <= end_idx
                })
                .count()
        }
        PatternDetails::BoolMask { .. } => instructions
            .iter()
            .filter(|i| {
                matches!(i.match_type.as_str(), "delete" | "insert")
                    && [&i.target, &i.base].iter().any(|side| {
                        side.as_ref().is_some_and(|s| {
                            matches!(s.opcode.as_str(), "clrlwi" | "rlwinm")
                                && (check_clrlwi_bool_mask(s).is_some()
                                    || check_rlwinm_bool_mask(s).is_some())
                        })
                    })
            })
            .count(),
        PatternDetails::ComparisonStyle { comparisons } => {
            let start_idx = instructions.first().map(|i| i.index).unwrap_or(0);
            let end_idx = instructions.last().map(|i| i.index).unwrap_or(0);
            comparisons.iter().filter(|c| c.index >= start_idx && c.index <= end_idx).count()
        }
        PatternDetails::CommutativeOpOrder { swaps } => {
            let start_idx = instructions.first().map(|i| i.index).unwrap_or(0);
            let end_idx = instructions.last().map(|i| i.index).unwrap_or(0);
            swaps.iter().filter(|s| s.index >= start_idx && s.index <= end_idx).count()
        }
    }
}

// =============================================================================
// Verdict
// =============================================================================

/// Classification of function fixability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerdictClassification {
    /// 100% match, no action needed
    Complete,
    /// Has fixable patterns (control flow, etc.)
    LikelyFixable,
    /// May be fixable with effort (register reordering)
    MaybeFixable,
    /// At practical limit due to linker/compiler
    AtLimit,
    /// Mixed signals, needs manual analysis
    NeedsInvestigation,
}

/// A factor that contributed to the verdict.
#[derive(Debug, Clone, Serialize)]
pub struct VerdictFactor {
    pub name: &'static str,
    pub value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f32>,
    pub result: &'static str,
}

/// A suggestion for improving the match.
#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    pub action: String,
}

/// Final verdict on function fixability.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub classification: VerdictClassification,
    pub confidence: Confidence,
    pub explanation: String,
    pub factors: Vec<VerdictFactor>,
    pub recommendation: String,
    pub suggestions: Vec<Suggestion>,
}

// =============================================================================
// Pattern Detection Functions
// =============================================================================

/// Detect calls to linker-merged functions.
///
/// Looks for `diff_arg` instructions where the opcode is `bl` and the
/// target argument matches the merged function regex.
pub fn detect_linker_merged(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut merged_calls: HashMap<String, usize> = HashMap::new();

    for instr in instructions {
        if instr.match_type != "diff_arg" {
            continue;
        }

        let Some(target) = &instr.target else { continue };

        // Only look at branch-and-link (function calls)
        if target.opcode != "bl" {
            continue;
        }

        let Some(args) = &target.args else { continue };

        // The args for bl is typically just the function name
        let func_name = args.trim();

        if MERGED_FUNC_RE.is_match(func_name) {
            *merged_calls.entry(func_name.to_string()).or_insert(0) += 1;
        }
    }

    if merged_calls.is_empty() {
        return None;
    }

    let total_count: usize = merged_calls.values().sum();

    // Convert to sorted vec for consistent output
    let mut merged_functions: Vec<MergedFunctionCount> =
        merged_calls.into_iter().map(|(name, count)| MergedFunctionCount { name, count }).collect();
    merged_functions.sort_by(|a, b| b.count.cmp(&a.count));

    Some(Pattern {
        pattern: PatternType::LinkerMerged,
        confidence: Confidence::High,
        instruction_count: total_count,
        fixability: Fixability::Unfixable,
        details: PatternDetails::MergedFunctions { merged_functions },
    })
}

/// Check clrlwi for bool mask pattern using typed args or string fallback.
/// clrlwi rD, rS, N - clears left N bits. N=24 masks to u8, N=31 masks to bool.
fn check_clrlwi_bool_mask(side: &InstructionInfo) -> Option<u8> {
    // Prefer typed args if available
    if let Some(typed_args) = &side.typed_args {
        // clrlwi has 3 args: dest reg, src reg, bit count
        // The bit count is the 3rd arg (index 2)
        if typed_args.len() >= 3
            && let Some(bit_count) = typed_args[2].as_i64()
        {
            if bit_count == 24 {
                return Some(24);
            } else if bit_count == 31 {
                return Some(31);
            }
        }
    }

    // Fall back to string matching
    if let Some(args) = &side.args {
        if args.contains(", 24") || args.ends_with(", 0x18") {
            return Some(24);
        } else if args.contains(", 31") || args.ends_with(", 0x1f") {
            return Some(31);
        }
    }
    None
}

/// Check rlwinm for bool mask pattern using typed args or string fallback.
/// rlwinm rD, rS, SH, MB, ME - bit rotate/mask
/// For byte mask: SH=0, MB=24, ME=31
/// For bool mask: SH=0, MB=31, ME=31
fn check_rlwinm_bool_mask(side: &InstructionInfo) -> Option<u8> {
    // Prefer typed args if available
    if let Some(typed_args) = &side.typed_args {
        // rlwinm has 5 args: dest, src, shift, mask_begin, mask_end
        if typed_args.len() >= 5 {
            let sh = typed_args[2].as_i64();
            let mb = typed_args[3].as_i64();
            let me = typed_args[4].as_i64();

            if let (Some(0), Some(24), Some(31)) = (sh, mb, me) {
                return Some(24); // byte mask
            } else if let (Some(0), Some(31), Some(31)) = (sh, mb, me) {
                return Some(31); // bool mask
            }
        }
    }

    // Fall back to string matching
    if let Some(args) = &side.args {
        if args.contains("0, 24, 31") || args.contains("0x0, 0x18, 0x1f") {
            return Some(24);
        } else if args.contains("0, 31, 31") || args.contains("0x0, 0x1f, 0x1f") {
            return Some(31);
        }
    }
    None
}

/// Detect bool return masking patterns.
///
/// Looks for `delete`/`insert` instructions with `clrlwi` or `rlwinm`
/// opcodes that mask values to bool (bit 31) or byte (bits 24-31).
///
/// Uses typed args when available for more reliable detection,
/// falling back to string parsing for backward compatibility.
pub fn detect_bool_mask(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut mask_count = 0;
    let mut bit_positions: Vec<u8> = Vec::new();

    for instr in instructions {
        if !matches!(instr.match_type.as_str(), "delete" | "insert") {
            continue;
        }

        // Check both target and base sides for bool masking
        for side in [&instr.target, &instr.base].into_iter().flatten() {
            let detected_bit = match side.opcode.as_str() {
                "clrlwi" => check_clrlwi_bool_mask(side),
                "rlwinm" => check_rlwinm_bool_mask(side),
                _ => None,
            };

            if let Some(bit) = detected_bit {
                mask_count += 1;
                if !bit_positions.contains(&bit) {
                    bit_positions.push(bit);
                }
            }
        }
    }

    if mask_count == 0 {
        return None;
    }

    bit_positions.sort();

    Some(Pattern {
        pattern: PatternType::BoolMask,
        confidence: Confidence::High,
        instruction_count: mask_count,
        fixability: Fixability::UsuallyUnfixable,
        details: PatternDetails::BoolMask { bit_positions },
    })
}

/// Detect consistent register allocation swaps.
///
/// Looks for `diff_arg` instructions where the opcode matches but
/// registers are swapped consistently (e.g., r30 <-> r31 throughout).
pub fn detect_register_swap(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    // Map from (reg1, reg2) normalized pair to count
    let mut mappings: HashMap<(String, String), usize> = HashMap::new();

    for instr in instructions {
        if instr.match_type != "diff_arg" {
            continue;
        }

        let (Some(target), Some(base)) = (&instr.target, &instr.base) else {
            continue;
        };

        // Only consider when opcodes match (pure register allocation diff)
        if target.opcode != base.opcode {
            continue;
        }

        let target_args = target.args.as_deref().unwrap_or("");
        let base_args = base.args.as_deref().unwrap_or("");

        // Extract all registers from both sides
        let target_regs: Vec<&str> =
            REGISTER_RE.find_iter(target_args).map(|m| m.as_str()).collect();
        let base_regs: Vec<&str> = REGISTER_RE.find_iter(base_args).map(|m| m.as_str()).collect();

        // Compare corresponding registers
        for (t, b) in target_regs.iter().zip(base_regs.iter()) {
            if t != b {
                // Normalize key ordering for consistent counting (smaller first)
                let key = if *t < *b {
                    (t.to_string(), b.to_string())
                } else {
                    (b.to_string(), t.to_string())
                };
                *mappings.entry(key).or_insert(0) += 1;
            }
        }
    }

    // Filter to swaps with >= threshold occurrences
    let significant: Vec<_> =
        mappings.into_iter().filter(|(_, count)| *count >= MIN_REGISTER_SWAP_OCCURRENCES).collect();

    if significant.is_empty() {
        return None;
    }

    let total: usize = significant.iter().map(|(_, c)| c).sum();

    // Higher confidence if single consistent swap with many occurrences
    let confidence =
        if significant.len() == 1 && total >= 5 { Confidence::High } else { Confidence::Medium };

    let mut swaps: Vec<RegisterSwapInfo> = significant
        .into_iter()
        .map(|((reg1, reg2), count)| RegisterSwapInfo { target_reg: reg1, base_reg: reg2, count })
        .collect();
    swaps.sort_by(|a, b| b.count.cmp(&a.count));

    Some(Pattern {
        pattern: PatternType::RegisterSwap,
        confidence,
        instruction_count: total,
        fixability: Fixability::MaybeFixable,
        details: PatternDetails::RegisterSwap { swaps },
    })
}

/// Detect comparison style differences (> vs >=).
///
/// Looks for `diff_arg` instructions where the opcode is `cmpwi` or `cmplwi`
/// and the immediate values differ by exactly 1. This often indicates a
/// comparison operator style difference (e.g., `>= 5` compiled as `> 4`).
pub fn detect_comparison_style(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut comparisons: Vec<ComparisonStyleInfo> = Vec::new();

    for instr in instructions {
        if instr.match_type != "diff_arg" {
            continue;
        }

        let (Some(target), Some(base)) = (&instr.target, &instr.base) else {
            continue;
        };

        // Only look at comparison instructions with matching opcodes
        if target.opcode != base.opcode {
            continue;
        }

        if !matches!(target.opcode.as_str(), "cmpwi" | "cmplwi") {
            continue;
        }

        let (Some(target_args), Some(base_args)) = (&target.args, &base.args) else {
            continue;
        };

        // Parse immediate values from args
        // Format: "crN, rX, IMM" or "rX, IMM"
        let target_imm = parse_comparison_immediate(target_args);
        let base_imm = parse_comparison_immediate(base_args);

        let (Some(t_val), Some(b_val)) = (target_imm, base_imm) else {
            continue;
        };

        // Check if they differ by exactly 1
        if (t_val - b_val).abs() == 1 {
            comparisons.push(ComparisonStyleInfo {
                index: instr.index,
                opcode: target.opcode.clone(),
                target_value: t_val,
                base_value: b_val,
            });
        }
    }

    if comparisons.is_empty() {
        return None;
    }

    let count = comparisons.len();

    Some(Pattern {
        pattern: PatternType::ComparisonStyle,
        confidence: Confidence::Medium,
        instruction_count: count,
        fixability: Fixability::MaybeFixable,
        details: PatternDetails::ComparisonStyle { comparisons },
    })
}

/// Parse the immediate value from comparison instruction arguments.
/// Handles formats like "cr0, r3, 5" or "r3, 5".
fn parse_comparison_immediate(args: &str) -> Option<i64> {
    // Split by comma and take the last element (the immediate)
    let parts: Vec<&str> = args.split(',').map(|s| s.trim()).collect();
    let last = parts.last()?;

    // Try to parse as integer (can be negative or hex)
    if let Some(hex) = last.strip_prefix("0x").or_else(|| last.strip_prefix("-0x")) {
        let is_neg = last.starts_with('-');
        let val = i64::from_str_radix(hex.trim_start_matches('-'), 16).ok()?;
        Some(if is_neg { -val } else { val })
    } else {
        last.parse::<i64>().ok()
    }
}

/// Branch opcodes for PowerPC (without hint suffixes).
/// Used as fallback when branch_dest is not available.
const BRANCH_OPCODES: &[&str] = &[
    "b", "bl", "blr", "bctr", "bctrl", "blrl", "beq", "bne", "blt", "ble", "bgt", "bge", "bdnz",
    "bdz", "bdnzt", "bdnzf", "bdzt", "bdzf", "bso", "bns", "bun", "bnu",
    // Link register variants
    "beqlr", "bnelr", "bltlr", "blelr", "bgtlr", "bgelr", // Count register variants
    "beqctr", "bnectr", "bltctr", "blectr", "bgtctr", "bgectr",
];

/// Check if an opcode is a branch instruction.
/// Handles hint suffixes (+/-) that may be appended.
fn is_branch_opcode(opcode: &str) -> bool {
    // Strip hint suffix if present
    let base = opcode.trim_end_matches(['+', '-']);
    BRANCH_OPCODES.contains(&base)
}

/// Check if an instruction is a branch using branch_dest (preferred) or opcode fallback.
fn is_branch_instruction(info: &InstructionInfo) -> bool {
    // Prefer branch_dest if available (more accurate, architecture-agnostic)
    if info.branch_dest.is_some() {
        return true;
    }
    // Fall back to opcode-based detection
    is_branch_opcode(&info.opcode)
}

/// Detect control flow differences on branch instructions.
///
/// Looks for `diff_op` or `replace` match types where either the target
/// or base instruction is a branch. This indicates structural control
/// flow differences that are often fixable.
///
/// Uses branch_dest when available for more accurate detection,
/// falling back to opcode-based detection for backward compatibility.
pub fn detect_control_flow(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut branch_diffs: Vec<BranchDiffInfo> = Vec::new();

    for instr in instructions {
        // Only look at opcode differences or replacements
        if !matches!(instr.match_type.as_str(), "diff_op" | "replace") {
            continue;
        }

        // Check if either side is a branch instruction using the new method
        let target_is_branch = instr.target.as_ref().is_some_and(is_branch_instruction);
        let base_is_branch = instr.base.as_ref().is_some_and(is_branch_instruction);

        if target_is_branch || base_is_branch {
            branch_diffs.push(BranchDiffInfo {
                index: instr.index,
                target_opcode: instr.target.as_ref().map(|t| t.opcode.clone()),
                base_opcode: instr.base.as_ref().map(|b| b.opcode.clone()),
                match_type: instr.match_type.clone(),
            });
        }
    }

    if branch_diffs.is_empty() {
        return None;
    }

    let count = branch_diffs.len();

    Some(Pattern {
        pattern: PatternType::ControlFlow,
        confidence: Confidence::Medium,
        instruction_count: count,
        fixability: Fixability::LikelyFixable,
        details: PatternDetails::ControlFlow { branch_diffs },
    })
}

/// Commutative opcodes where operand order doesn't affect the result.
/// Includes both integer and floating-point variants.
const COMMUTATIVE_OPCODES: &[&str] = &[
    // Floating-point
    "fadd", "fadds", "fmul", "fmuls", // Integer
    "add", "addi", "addis", "and", "andi.", "andis.", "or", "ori", "oris", "xor", "xori", "xoris",
    // Dot variants (set CR0)
    "add.", "and.", "or.", "xor.",
];

/// Check if an opcode is a commutative operation.
fn is_commutative_opcode(opcode: &str) -> bool {
    COMMUTATIVE_OPCODES.contains(&opcode)
}

/// Extract operands from an instruction (excluding the destination register).
/// For commutative operations like `fadd f0, f1, f2`, returns ["f1", "f2"].
fn extract_source_operands(info: &InstructionInfo) -> Vec<String> {
    // Prefer typed_args if available
    if let Some(typed_args) = &info.typed_args {
        // Skip the first arg (destination) and collect the rest
        return typed_args
            .iter()
            .skip(1)
            .filter_map(|arg| match arg {
                super::diff::TypedArg::Register(r) => Some(r.clone()),
                _ => None,
            })
            .collect();
    }

    // Fall back to string parsing
    if let Some(args) = &info.args {
        let parts: Vec<&str> = args.split(',').map(|s| s.trim()).collect();
        // Skip the first (destination), return the rest
        return parts.iter().skip(1).map(|s| s.to_string()).collect();
    }

    Vec::new()
}

/// Detect commutative operation order differences.
///
/// Looks for `diff_arg` instructions where the opcode is commutative
/// (fadd, fmul, add, and, or, xor, etc.) and the operands are
/// permuted between target and base.
pub fn detect_commutative_op_order(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut swaps: Vec<CommutativeOpInfo> = Vec::new();

    for instr in instructions {
        if instr.match_type != "diff_arg" {
            continue;
        }

        let (Some(target), Some(base)) = (&instr.target, &instr.base) else {
            continue;
        };

        // Opcodes must match and be commutative
        if target.opcode != base.opcode {
            continue;
        }

        if !is_commutative_opcode(&target.opcode) {
            continue;
        }

        let target_ops = extract_source_operands(target);
        let base_ops = extract_source_operands(base);

        // Must have exactly 2 source operands for a simple swap check
        if target_ops.len() != 2 || base_ops.len() != 2 {
            continue;
        }

        // Check if operands are swapped (a,b vs b,a)
        if target_ops[0] == base_ops[1] && target_ops[1] == base_ops[0] {
            swaps.push(CommutativeOpInfo {
                index: instr.index,
                opcode: target.opcode.clone(),
                target_operands: target_ops,
                base_operands: base_ops,
            });
        }
    }

    if swaps.is_empty() {
        return None;
    }

    let count = swaps.len();

    Some(Pattern {
        pattern: PatternType::CommutativeOpOrder,
        confidence: Confidence::High,
        instruction_count: count,
        fixability: Fixability::LikelyFixable,
        details: PatternDetails::CommutativeOpOrder { swaps },
    })
}

/// Extract offset value from an instruction's memory operand.
/// For instructions like `lwz r3, 0x10(r4)`, extracts 0x10.
fn extract_offset(info: &InstructionInfo) -> Option<i64> {
    // Prefer typed_args if available
    if let Some(typed_args) = &info.typed_args {
        // Look for a signed/unsigned integer that represents an offset
        for arg in typed_args {
            match arg {
                super::diff::TypedArg::Signed(v) => return Some(*v),
                super::diff::TypedArg::Unsigned(v) => return Some(*v as i64),
                _ => continue,
            }
        }
    }

    // Fall back to string parsing: look for offset(reg) pattern
    if let Some(args) = &info.args {
        // Match patterns like "0x10(r4)" or "-0x8(r1)"
        static OFFSET_RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"(-?0x[0-9a-fA-F]+|-?\d+)\(").unwrap());

        if let Some(cap) = OFFSET_RE.captures(args) {
            let offset_str = cap.get(1)?.as_str();
            // Parse hex or decimal
            if let Some(hex) =
                offset_str.strip_prefix("0x").or_else(|| offset_str.strip_prefix("-0x"))
            {
                let is_neg = offset_str.starts_with('-');
                if let Ok(val) = i64::from_str_radix(hex, 16) {
                    return Some(if is_neg { -val } else { val });
                }
            } else {
                return offset_str.parse().ok();
            }
        }
    }

    None
}

/// Detect offset swap patterns.
///
/// Looks for pairs of `diff_arg` instructions where the offsets are
/// swapped between target and base. For example:
/// - Instruction A: target has offset 0x4, base has offset 0x8
/// - Instruction B: target has offset 0x8, base has offset 0x4
///
/// This indicates the compiler reordered struct field accesses.
pub fn detect_offset_swap(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    // Collect all diff_arg instructions with offset differences
    let mut offset_diffs: Vec<(usize, i64, i64)> = Vec::new(); // (index, target_offset, base_offset)

    for instr in instructions {
        if instr.match_type != "diff_arg" {
            continue;
        }

        let (Some(target), Some(base)) = (&instr.target, &instr.base) else {
            continue;
        };

        // Opcodes should match (same instruction type)
        if target.opcode != base.opcode {
            continue;
        }

        let target_offset = extract_offset(target);
        let base_offset = extract_offset(base);

        if let (Some(t_off), Some(b_off)) = (target_offset, base_offset)
            && t_off != b_off
        {
            offset_diffs.push((instr.index, t_off, b_off));
        }
    }

    // Look for symmetric swaps
    let mut swaps: Vec<OffsetSwapInfo> = Vec::new();
    let mut used: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for i in 0..offset_diffs.len() {
        if used.contains(&i) {
            continue;
        }

        let (idx_a, t_off_a, b_off_a) = offset_diffs[i];

        for (j, &(idx_b, t_off_b, b_off_b)) in offset_diffs.iter().enumerate().skip(i + 1) {
            if used.contains(&j) {
                continue;
            }

            // Check for symmetric swap: A's target=B's base and A's base=B's target
            if t_off_a == b_off_b && b_off_a == t_off_b {
                swaps.push(OffsetSwapInfo {
                    indices: (idx_a, idx_b),
                    target_offsets: (t_off_a, t_off_b),
                    base_offsets: (b_off_a, b_off_b),
                });
                used.insert(i);
                used.insert(j);
                break;
            }
        }
    }

    if swaps.is_empty() {
        return None;
    }

    // Each swap involves 2 instructions
    let count = swaps.len() * 2;

    Some(Pattern {
        pattern: PatternType::OffsetSwap,
        confidence: Confidence::High,
        instruction_count: count,
        fixability: Fixability::LikelyFixable,
        details: PatternDetails::OffsetSwap { swaps },
    })
}

// =============================================================================
// Analysis
// =============================================================================

/// Run all pattern detection on an instruction diff.
pub fn analyze_instructions(instructions: &[InstructionDiffOutput]) -> Analysis {
    let mut patterns = Vec::new();

    // Run all detectors
    if let Some(p) = detect_linker_merged(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_bool_mask(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_register_swap(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_comparison_style(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_control_flow(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_commutative_op_order(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_offset_swap(instructions) {
        patterns.push(p);
    }

    // Count total mismatches
    let total_mismatches = instructions.iter().filter(|i| i.match_type != "equal").count();

    // Count attributed mismatches
    let attributed: usize = patterns.iter().map(|p| p.instruction_count).sum();

    // Unattributed = mismatches not explained by any pattern
    // Note: patterns may overlap, so this can be negative (we clamp to 0)
    let unattributed = total_mismatches.saturating_sub(attributed);

    Analysis {
        patterns,
        patterns_checked: vec![
            "LINKER_MERGED",
            "BOOL_MASK",
            "REGISTER_SWAP",
            "COMPARISON_STYLE",
            "CONTROL_FLOW",
            "COMMUTATIVE_OP_ORDER",
            "OFFSET_SWAP",
        ],
        unattributed_mismatches: unattributed,
    }
}

// =============================================================================
// Verdict Computation
// =============================================================================

/// Compute a fixability verdict based on analysis results.
pub fn compute_verdict(
    summary: &InstructionSummary,
    analysis: &Analysis,
    match_percent: Option<f32>,
) -> Verdict {
    let total_mismatches = summary.total - summary.equal;
    let mut factors = Vec::new();

    // Check for complete match
    if total_mismatches == 0 {
        return Verdict {
            classification: VerdictClassification::Complete,
            confidence: Confidence::High,
            explanation: "Function matches 100%.".to_string(),
            factors: vec![VerdictFactor {
                name: "total_mismatches",
                value: serde_json::json!(0),
                threshold: None,
                result: "complete",
            }],
            recommendation: "No action needed.".to_string(),
            suggestions: vec![],
        };
    }

    // Very few mismatches - likely fixable with manual inspection
    if total_mismatches < MIN_MISMATCH_FOR_ANALYSIS {
        factors.push(VerdictFactor {
            name: "total_mismatches",
            value: serde_json::json!(total_mismatches),
            threshold: Some(MIN_MISMATCH_FOR_ANALYSIS as f32),
            result: "below_threshold",
        });

        return Verdict {
            classification: VerdictClassification::LikelyFixable,
            confidence: Confidence::Medium,
            explanation: format!(
                "Only {} mismatch(es) - simple manual inspection recommended.",
                total_mismatches
            ),
            factors,
            recommendation: "Inspect the few mismatched instructions directly.".to_string(),
            suggestions: vec![Suggestion {
                action: "Review diff output for specific differences".to_string(),
            }],
        };
    }

    // Check for BOOL_MASK (hard blocker)
    let has_bool_mask = analysis.has_pattern(PatternType::BoolMask);
    factors.push(VerdictFactor {
        name: "bool_mask_detected",
        value: serde_json::json!(has_bool_mask),
        threshold: None,
        result: if has_bool_mask { "detected" } else { "not_detected" },
    });

    if has_bool_mask {
        let bool_count = analysis.pattern_instruction_count(PatternType::BoolMask);
        return Verdict {
            classification: VerdictClassification::AtLimit,
            confidence: Confidence::High,
            explanation: format!(
                "{} bool mask instruction(s) detected -- compiler bool return handling cannot be matched.",
                bool_count
            ),
            factors,
            recommendation: format!(
                "Accept current match ({:.1}%). This is a compiler optimization difference.",
                match_percent.unwrap_or(0.0)
            ),
            suggestions: vec![],
        };
    }

    // Calculate merged function ratio
    let merged_count = analysis.pattern_instruction_count(PatternType::LinkerMerged);
    let merged_ratio =
        if total_mismatches > 0 { merged_count as f32 / total_mismatches as f32 } else { 0.0 };

    factors.push(VerdictFactor {
        name: "merged_call_ratio",
        value: serde_json::json!(merged_ratio),
        threshold: Some(MERGED_RATIO_AT_LIMIT),
        result: if merged_ratio >= MERGED_RATIO_AT_LIMIT {
            "exceeds_limit"
        } else if merged_ratio >= MERGED_RATIO_LIKELY_FIXABLE {
            "moderate"
        } else {
            "below_threshold"
        },
    });

    // High merged ratio = at limit
    if merged_ratio >= MERGED_RATIO_AT_LIMIT {
        let merged_summary = analysis
            .patterns
            .iter()
            .find(|p| p.pattern == PatternType::LinkerMerged)
            .map(|p| p.summarize());
        let detail =
            merged_summary.as_ref().map(|s| format!(" ({})", s.one_line)).unwrap_or_default();
        return Verdict {
            classification: VerdictClassification::AtLimit,
            confidence: Confidence::High,
            explanation: format!(
                "{:.1}% of mismatches are calls to linker-merged functions{}.",
                merged_ratio * 100.0,
                detail
            ),
            factors,
            recommendation: format!(
                "Accept current match ({:.1}%). Effort better spent elsewhere.",
                match_percent.unwrap_or(0.0)
            ),
            suggestions: vec![],
        };
    }

    // Check for fixable control flow patterns
    let has_control_flow = summary.diff_op > 0 || summary.replace > 0;
    factors.push(VerdictFactor {
        name: "control_flow_diffs",
        value: serde_json::json!(summary.diff_op + summary.replace),
        threshold: Some(1.0),
        result: if has_control_flow { "detected" } else { "not_detected" },
    });

    if has_control_flow && merged_ratio < MERGED_RATIO_LIKELY_FIXABLE {
        let mut suggestions = Vec::new();

        // Use pattern summary for context-aware suggestions
        if let Some(cf_pattern) =
            analysis.patterns.iter().find(|p| p.pattern == PatternType::ControlFlow)
        {
            let cf_summary = cf_pattern.summarize();
            suggestions.push(Suggestion { action: cf_summary.one_line.clone() });
            // Add specific indices from top details
            for detail in cf_summary.top_details.iter().take(2) {
                suggestions.push(Suggestion { action: detail.clone() });
            }
        }

        suggestions.push(Suggestion {
            action: "Try `> 0` vs `!= 0`, `>=` vs `>`, if/else inversion".to_string(),
        });

        return Verdict {
            classification: VerdictClassification::LikelyFixable,
            confidence: Confidence::Medium,
            explanation: format!(
                "{} control flow difference(s) detected with low merged ratio ({:.1}%).",
                summary.diff_op + summary.replace,
                merged_ratio * 100.0
            ),
            factors,
            recommendation: "Investigate control flow structure.".to_string(),
            suggestions,
        };
    }

    // Check for register swap only patterns
    let has_register_swap = analysis.has_pattern(PatternType::RegisterSwap);
    let register_swap_count = analysis.pattern_instruction_count(PatternType::RegisterSwap);

    factors.push(VerdictFactor {
        name: "register_swap_count",
        value: serde_json::json!(register_swap_count),
        threshold: Some(MIN_REGISTER_SWAP_OCCURRENCES as f32),
        result: if has_register_swap { "detected" } else { "not_detected" },
    });

    if has_register_swap && merged_ratio < 0.3 {
        let mut suggestions = Vec::new();

        // Use pattern summary for context-aware message
        if let Some(rs_pattern) =
            analysis.patterns.iter().find(|p| p.pattern == PatternType::RegisterSwap)
        {
            let rs_summary = rs_pattern.summarize();
            suggestions.push(Suggestion { action: rs_summary.one_line.clone() });
        }

        suggestions.push(Suggestion { action: "Reorder local variable declarations".to_string() });
        suggestions.push(Suggestion {
            action: "Move variable initialization closer to first use".to_string(),
        });

        let explanation = if register_swap_count > 20 {
            format!(
                "{} register swap instructions -- usually unfixable. Consider marking at_limit.",
                register_swap_count
            )
        } else {
            format!(
                "{} register swap instruction(s) detected. May be fixable by reordering variable declarations.",
                register_swap_count
            )
        };

        return Verdict {
            classification: VerdictClassification::MaybeFixable,
            confidence: Confidence::Medium,
            explanation,
            factors,
            recommendation: "Try reordering variable declarations or delaying assignments."
                .to_string(),
            suggestions,
        };
    }

    // Default: needs investigation - summarize what we found
    let mut suggestions = Vec::new();
    for pattern in &analysis.patterns {
        let ps = pattern.summarize();
        suggestions
            .push(Suggestion { action: format!("{}: {}", pattern.pattern.as_str(), ps.one_line) });
    }
    if summary.delete > 0 || summary.insert > 0 {
        suggestions.push(Suggestion {
            action: format!(
                "{} delete(s), {} insert(s) -- check for missing/extra code blocks",
                summary.delete, summary.insert
            ),
        });
    }
    if suggestions.is_empty() {
        suggestions.push(Suggestion {
            action: "Use --include-instructions to inspect specific differences".to_string(),
        });
    }

    Verdict {
        classification: VerdictClassification::NeedsInvestigation,
        confidence: Confidence::Low,
        explanation: format!(
            "Mixed patterns detected ({} total mismatches) -- manual analysis recommended.",
            total_mismatches
        ),
        factors,
        recommendation: "Review instruction diff manually to understand mismatch causes."
            .to_string(),
        suggestions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::diff::{InstructionInfo, TypedArg};

    fn make_instr(
        index: usize,
        match_type: &str,
        target_op: Option<&str>,
        target_args: Option<&str>,
        base_op: Option<&str>,
        base_args: Option<&str>,
    ) -> InstructionDiffOutput {
        InstructionDiffOutput {
            index,
            target: target_op.map(|op| InstructionInfo {
                address: format!("{:#x}", index * 4),
                opcode: op.to_string(),
                args: target_args.map(|s| s.to_string()),
                typed_args: None,
                branch_dest: None,
                line_number: None,
                source_file: None,
            }),
            base: base_op.map(|op| InstructionInfo {
                address: format!("{:#x}", index * 4),
                opcode: op.to_string(),
                args: base_args.map(|s| s.to_string()),
                typed_args: None,
                branch_dest: None,
                line_number: None,
                source_file: None,
            }),
            match_type: match_type.to_string(),
            diff_breakdown: None,
        }
    }

    /// Helper function to create instruction with typed args for testing
    fn make_instr_typed(
        index: usize,
        match_type: &str,
        target_op: Option<&str>,
        target_typed_args: Option<Vec<TypedArg>>,
        base_op: Option<&str>,
        base_typed_args: Option<Vec<TypedArg>>,
        target_branch_dest: Option<u64>,
        base_branch_dest: Option<u64>,
    ) -> InstructionDiffOutput {
        InstructionDiffOutput {
            index,
            target: target_op.map(|op| InstructionInfo {
                address: format!("{:#x}", index * 4),
                opcode: op.to_string(),
                args: None, // typed_args takes precedence
                typed_args: target_typed_args,
                branch_dest: target_branch_dest,
                line_number: None,
                source_file: None,
            }),
            base: base_op.map(|op| InstructionInfo {
                address: format!("{:#x}", index * 4),
                opcode: op.to_string(),
                args: None,
                typed_args: base_typed_args,
                branch_dest: base_branch_dest,
                line_number: None,
                source_file: None,
            }),
            match_type: match_type.to_string(),
            diff_breakdown: None,
        }
    }

    #[test]
    fn test_detect_linker_merged() {
        let instructions = vec![
            make_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_instr(
                1,
                "diff_arg",
                Some("bl"),
                Some("merged_Read4FloatStruct"),
                Some("bl"),
                Some("SomeFunction"),
            ),
            make_instr(
                2,
                "diff_arg",
                Some("bl"),
                Some("OnlyReturns"),
                Some("bl"),
                Some("OtherFunc"),
            ),
            make_instr(
                3,
                "diff_arg",
                Some("bl"),
                Some("merged_Read4FloatStruct"),
                Some("bl"),
                Some("AnotherFunc"),
            ),
        ];

        let pattern = detect_linker_merged(&instructions).expect("Should detect merged");
        assert_eq!(pattern.pattern, PatternType::LinkerMerged);
        assert_eq!(pattern.instruction_count, 3);
        assert_eq!(pattern.fixability, Fixability::Unfixable);

        if let PatternDetails::MergedFunctions { merged_functions } = &pattern.details {
            assert_eq!(merged_functions.len(), 2);
            assert_eq!(merged_functions[0].name, "merged_Read4FloatStruct");
            assert_eq!(merged_functions[0].count, 2);
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_bool_mask() {
        let instructions = vec![
            make_instr(0, "equal", Some("li"), Some("r3, 1"), Some("li"), Some("r3, 1")),
            make_instr(1, "delete", Some("clrlwi"), Some("r3, r11, 24"), None, None),
        ];

        let pattern = detect_bool_mask(&instructions).expect("Should detect bool mask");
        assert_eq!(pattern.pattern, PatternType::BoolMask);
        assert_eq!(pattern.instruction_count, 1);

        if let PatternDetails::BoolMask { bit_positions } = &pattern.details {
            assert!(bit_positions.contains(&24));
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_register_swap() {
        let instructions = vec![
            make_instr(0, "diff_arg", Some("mr"), Some("r31, r3"), Some("mr"), Some("r30, r3")),
            make_instr(
                1,
                "diff_arg",
                Some("lwz"),
                Some("r4, 0(r31)"),
                Some("lwz"),
                Some("r4, 0(r30)"),
            ),
            make_instr(
                2,
                "diff_arg",
                Some("stw"),
                Some("r5, 4(r31)"),
                Some("stw"),
                Some("r5, 4(r30)"),
            ),
            make_instr(3, "diff_arg", Some("mr"), Some("r3, r31"), Some("mr"), Some("r3, r30")),
        ];

        let pattern = detect_register_swap(&instructions).expect("Should detect register swap");
        assert_eq!(pattern.pattern, PatternType::RegisterSwap);
        assert_eq!(pattern.instruction_count, 4);
        assert_eq!(pattern.confidence, Confidence::Medium);
    }

    #[test]
    fn test_verdict_complete() {
        let summary = InstructionSummary { total: 10, equal: 10, ..Default::default() };
        let analysis = Analysis {
            patterns: vec![],
            patterns_checked: vec!["LINKER_MERGED", "BOOL_MASK", "REGISTER_SWAP"],
            unattributed_mismatches: 0,
        };

        let verdict = compute_verdict(&summary, &analysis, Some(100.0));
        assert_eq!(verdict.classification, VerdictClassification::Complete);
    }

    #[test]
    fn test_verdict_at_limit_merged() {
        let summary = InstructionSummary { total: 10, equal: 5, diff_arg: 5, ..Default::default() };
        let analysis = Analysis {
            patterns: vec![Pattern {
                pattern: PatternType::LinkerMerged,
                confidence: Confidence::High,
                instruction_count: 4, // 4/5 = 80%
                fixability: Fixability::Unfixable,
                details: PatternDetails::MergedFunctions {
                    merged_functions: vec![MergedFunctionCount {
                        name: "merged_test".to_string(),
                        count: 4,
                    }],
                },
            }],
            patterns_checked: vec!["LINKER_MERGED", "BOOL_MASK", "REGISTER_SWAP"],
            unattributed_mismatches: 1,
        };

        let verdict = compute_verdict(&summary, &analysis, Some(97.0));
        assert_eq!(verdict.classification, VerdictClassification::AtLimit);
    }

    #[test]
    fn test_detect_comparison_style() {
        // Test case: cmpwi with values differing by 1 (5 vs 4)
        let instructions = vec![
            make_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_instr(
                1,
                "diff_arg",
                Some("cmpwi"),
                Some("cr0, r3, 5"),
                Some("cmpwi"),
                Some("cr0, r3, 4"),
            ),
            make_instr(2, "equal", Some("beq"), Some("0x100"), Some("beq"), Some("0x100")),
        ];

        let pattern =
            detect_comparison_style(&instructions).expect("Should detect comparison style");
        assert_eq!(pattern.pattern, PatternType::ComparisonStyle);
        assert_eq!(pattern.instruction_count, 1);
        assert_eq!(pattern.confidence, Confidence::Medium);
        assert_eq!(pattern.fixability, Fixability::MaybeFixable);

        if let PatternDetails::ComparisonStyle { comparisons } = &pattern.details {
            assert_eq!(comparisons.len(), 1);
            assert_eq!(comparisons[0].index, 1);
            assert_eq!(comparisons[0].opcode, "cmpwi");
            assert_eq!(comparisons[0].target_value, 5);
            assert_eq!(comparisons[0].base_value, 4);
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_comparison_style_cmplwi() {
        // Test case: cmplwi (unsigned comparison)
        let instructions = vec![make_instr(
            0,
            "diff_arg",
            Some("cmplwi"),
            Some("r5, 10"),
            Some("cmplwi"),
            Some("r5, 9"),
        )];

        let pattern = detect_comparison_style(&instructions).expect("Should detect cmplwi");
        assert_eq!(pattern.pattern, PatternType::ComparisonStyle);

        if let PatternDetails::ComparisonStyle { comparisons } = &pattern.details {
            assert_eq!(comparisons[0].target_value, 10);
            assert_eq!(comparisons[0].base_value, 9);
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_comparison_style_not_by_one() {
        // Test case: values differ by more than 1, should NOT detect
        let instructions = vec![make_instr(
            0,
            "diff_arg",
            Some("cmpwi"),
            Some("cr0, r3, 10"),
            Some("cmpwi"),
            Some("cr0, r3, 5"),
        )];

        let pattern = detect_comparison_style(&instructions);
        assert!(pattern.is_none(), "Should not detect when diff > 1");
    }

    #[test]
    fn test_detect_control_flow_diff_op() {
        // Test case: diff_op on branch instruction (beq vs bne)
        let instructions = vec![
            make_instr(
                0,
                "equal",
                Some("cmpwi"),
                Some("cr0, r3, 0"),
                Some("cmpwi"),
                Some("cr0, r3, 0"),
            ),
            make_instr(1, "diff_op", Some("beq"), Some("0x100"), Some("bne"), Some("0x100")),
        ];

        let pattern = detect_control_flow(&instructions).expect("Should detect control flow");
        assert_eq!(pattern.pattern, PatternType::ControlFlow);
        assert_eq!(pattern.instruction_count, 1);
        assert_eq!(pattern.confidence, Confidence::Medium);
        assert_eq!(pattern.fixability, Fixability::LikelyFixable);

        if let PatternDetails::ControlFlow { branch_diffs } = &pattern.details {
            assert_eq!(branch_diffs.len(), 1);
            assert_eq!(branch_diffs[0].index, 1);
            assert_eq!(branch_diffs[0].target_opcode, Some("beq".to_string()));
            assert_eq!(branch_diffs[0].base_opcode, Some("bne".to_string()));
            assert_eq!(branch_diffs[0].match_type, "diff_op");
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_control_flow_replace() {
        // Test case: replace where one side is branch
        let instructions =
            vec![make_instr(0, "replace", Some("blt"), Some("0x200"), Some("mr"), Some("r3, r4"))];

        let pattern =
            detect_control_flow(&instructions).expect("Should detect replace with branch");
        assert_eq!(pattern.pattern, PatternType::ControlFlow);

        if let PatternDetails::ControlFlow { branch_diffs } = &pattern.details {
            assert_eq!(branch_diffs[0].target_opcode, Some("blt".to_string()));
            assert_eq!(branch_diffs[0].base_opcode, Some("mr".to_string()));
            assert_eq!(branch_diffs[0].match_type, "replace");
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_control_flow_with_hints() {
        // Test case: branch with hint suffix (beq+ vs beq-)
        let instructions = vec![make_instr(
            0,
            "diff_op",
            Some("beq+"),
            Some("0x100"),
            Some("beq-"),
            Some("0x100"),
        )];

        let pattern = detect_control_flow(&instructions).expect("Should detect branch with hints");
        assert_eq!(pattern.pattern, PatternType::ControlFlow);
    }

    #[test]
    fn test_detect_control_flow_no_branch() {
        // Test case: diff_op but not on branch instruction
        let instructions = vec![make_instr(
            0,
            "diff_op",
            Some("add"),
            Some("r3, r4, r5"),
            Some("sub"),
            Some("r3, r4, r5"),
        )];

        let pattern = detect_control_flow(&instructions);
        assert!(pattern.is_none(), "Should not detect non-branch diff_op");
    }

    #[test]
    fn test_parse_comparison_immediate() {
        // Test various immediate formats
        assert_eq!(parse_comparison_immediate("cr0, r3, 5"), Some(5));
        assert_eq!(parse_comparison_immediate("r3, 5"), Some(5));
        assert_eq!(parse_comparison_immediate("r5, -1"), Some(-1));
        assert_eq!(parse_comparison_immediate("cr0, r3, 0x10"), Some(16));
        assert_eq!(parse_comparison_immediate("r3, 0"), Some(0));
    }

    #[test]
    fn test_analyze_instructions_includes_new_patterns() {
        // Verify that analyze_instructions includes the new patterns in patterns_checked
        let instructions =
            vec![make_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4"))];

        let analysis = analyze_instructions(&instructions);
        assert!(analysis.patterns_checked.contains(&"COMPARISON_STYLE"));
        assert!(analysis.patterns_checked.contains(&"CONTROL_FLOW"));
    }

    #[test]
    fn test_detect_bool_mask_with_typed_args() {
        // Test bool mask detection using typed args (more reliable than string matching)
        let instructions = vec![make_instr_typed(
            0,
            "delete",
            Some("clrlwi"),
            Some(vec![
                TypedArg::Register("r3".to_string()),
                TypedArg::Register("r11".to_string()),
                TypedArg::Unsigned(24), // bit position
            ]),
            None,
            None,
            None,
            None,
        )];

        let pattern =
            detect_bool_mask(&instructions).expect("Should detect bool mask with typed args");
        assert_eq!(pattern.pattern, PatternType::BoolMask);
        assert_eq!(pattern.instruction_count, 1);

        if let PatternDetails::BoolMask { bit_positions } = &pattern.details {
            assert!(bit_positions.contains(&24));
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_bool_mask_rlwinm_typed_args() {
        // Test rlwinm bool mask detection using typed args
        let instructions = vec![make_instr_typed(
            0,
            "insert",
            None,
            None,
            Some("rlwinm"),
            Some(vec![
                TypedArg::Register("r3".to_string()),
                TypedArg::Register("r5".to_string()),
                TypedArg::Unsigned(0),  // shift
                TypedArg::Unsigned(31), // mask begin
                TypedArg::Unsigned(31), // mask end
            ]),
            None,
            None,
        )];

        let pattern = detect_bool_mask(&instructions).expect("Should detect rlwinm bool mask");
        assert_eq!(pattern.pattern, PatternType::BoolMask);

        if let PatternDetails::BoolMask { bit_positions } = &pattern.details {
            assert!(bit_positions.contains(&31));
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_control_flow_with_branch_dest() {
        // Test control flow detection using branch_dest (more accurate than opcode matching)
        let instructions = vec![make_instr_typed(
            0,
            "diff_op",
            Some("beq"), // custom opcode, but has branch_dest
            None,
            Some("bne"),
            None,
            Some(0x100), // target branch dest
            Some(0x100), // base branch dest
        )];

        let pattern = detect_control_flow(&instructions)
            .expect("Should detect control flow with branch_dest");
        assert_eq!(pattern.pattern, PatternType::ControlFlow);
        assert_eq!(pattern.instruction_count, 1);
    }

    #[test]
    fn test_typed_arg_methods() {
        // Test TypedArg helper methods
        assert!(TypedArg::Register("r3".to_string()).is_register());
        assert!(!TypedArg::Signed(5).is_register());

        assert!(TypedArg::Signed(-10).is_numeric());
        assert!(TypedArg::Unsigned(100).is_numeric());
        assert!(!TypedArg::Symbol("func".to_string()).is_numeric());

        assert_eq!(TypedArg::Signed(-5).as_i64(), Some(-5));
        assert_eq!(TypedArg::Unsigned(100).as_i64(), Some(100));
        assert_eq!(TypedArg::Register("r3".to_string()).as_i64(), None);
    }

    #[test]
    fn test_detect_commutative_op_order() {
        // Test case: fmuls with swapped operands (f0, f13, f0 vs f0, f0, f13)
        let instructions = vec![make_instr(
            0,
            "diff_arg",
            Some("fmuls"),
            Some("f0, f13, f0"),
            Some("fmuls"),
            Some("f0, f0, f13"),
        )];

        let pattern =
            detect_commutative_op_order(&instructions).expect("Should detect commutative op order");
        assert_eq!(pattern.pattern, PatternType::CommutativeOpOrder);
        assert_eq!(pattern.instruction_count, 1);
        assert_eq!(pattern.confidence, Confidence::High);
        assert_eq!(pattern.fixability, Fixability::LikelyFixable);

        if let PatternDetails::CommutativeOpOrder { swaps } = &pattern.details {
            assert_eq!(swaps.len(), 1);
            assert_eq!(swaps[0].index, 0);
            assert_eq!(swaps[0].opcode, "fmuls");
            assert_eq!(swaps[0].target_operands, vec!["f13", "f0"]);
            assert_eq!(swaps[0].base_operands, vec!["f0", "f13"]);
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_commutative_op_order_integer() {
        // Test case: add with swapped operands
        let instructions = vec![make_instr(
            0,
            "diff_arg",
            Some("add"),
            Some("r3, r5, r4"),
            Some("add"),
            Some("r3, r4, r5"),
        )];

        let pattern = detect_commutative_op_order(&instructions)
            .expect("Should detect integer commutative op order");
        assert_eq!(pattern.pattern, PatternType::CommutativeOpOrder);

        if let PatternDetails::CommutativeOpOrder { swaps } = &pattern.details {
            assert_eq!(swaps[0].opcode, "add");
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_commutative_op_order_not_swapped() {
        // Test case: same order, no swap
        let instructions = vec![make_instr(
            0,
            "diff_arg",
            Some("fmuls"),
            Some("f0, f1, f2"),
            Some("fmuls"),
            Some("f0, f1, f3"), // Different operand, not swapped
        )];

        let pattern = detect_commutative_op_order(&instructions);
        assert!(pattern.is_none(), "Should not detect when operands aren't swapped");
    }

    #[test]
    fn test_detect_commutative_op_order_non_commutative() {
        // Test case: sub is not commutative
        let instructions = vec![make_instr(
            0,
            "diff_arg",
            Some("sub"),
            Some("r3, r5, r4"),
            Some("sub"),
            Some("r3, r4, r5"),
        )];

        let pattern = detect_commutative_op_order(&instructions);
        assert!(pattern.is_none(), "Should not detect non-commutative opcode");
    }

    #[test]
    fn test_detect_offset_swap() {
        // Test case: two instructions with swapped offsets
        let instructions = vec![
            make_instr(
                0,
                "diff_arg",
                Some("lwz"),
                Some("r3, 0x4(r31)"),
                Some("lwz"),
                Some("r3, 0x8(r31)"),
            ),
            make_instr(
                1,
                "diff_arg",
                Some("lwz"),
                Some("r4, 0x8(r31)"),
                Some("lwz"),
                Some("r4, 0x4(r31)"),
            ),
        ];

        let pattern = detect_offset_swap(&instructions).expect("Should detect offset swap");
        assert_eq!(pattern.pattern, PatternType::OffsetSwap);
        assert_eq!(pattern.instruction_count, 2); // 1 swap = 2 instructions
        assert_eq!(pattern.confidence, Confidence::High);
        assert_eq!(pattern.fixability, Fixability::LikelyFixable);

        if let PatternDetails::OffsetSwap { swaps } = &pattern.details {
            assert_eq!(swaps.len(), 1);
            assert_eq!(swaps[0].indices, (0, 1));
            assert_eq!(swaps[0].target_offsets, (0x4, 0x8));
            assert_eq!(swaps[0].base_offsets, (0x8, 0x4));
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_offset_swap_negative() {
        // Test case: negative offsets
        let instructions = vec![
            make_instr(
                0,
                "diff_arg",
                Some("stw"),
                Some("r3, -0x10(r1)"),
                Some("stw"),
                Some("r3, -0x8(r1)"),
            ),
            make_instr(
                1,
                "diff_arg",
                Some("stw"),
                Some("r4, -0x8(r1)"),
                Some("stw"),
                Some("r4, -0x10(r1)"),
            ),
        ];

        let pattern =
            detect_offset_swap(&instructions).expect("Should detect negative offset swap");
        assert_eq!(pattern.pattern, PatternType::OffsetSwap);

        if let PatternDetails::OffsetSwap { swaps } = &pattern.details {
            assert_eq!(swaps[0].target_offsets, (-0x10, -0x8));
            assert_eq!(swaps[0].base_offsets, (-0x8, -0x10));
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_offset_swap_not_symmetric() {
        // Test case: offsets differ but aren't swapped
        let instructions = vec![
            make_instr(
                0,
                "diff_arg",
                Some("lwz"),
                Some("r3, 0x4(r31)"),
                Some("lwz"),
                Some("r3, 0x8(r31)"),
            ),
            make_instr(
                1,
                "diff_arg",
                Some("lwz"),
                Some("r4, 0xc(r31)"),
                Some("lwz"),
                Some("r4, 0x10(r31)"),
            ),
        ];

        let pattern = detect_offset_swap(&instructions);
        assert!(pattern.is_none(), "Should not detect non-symmetric offsets");
    }

    #[test]
    fn test_analyze_instructions_includes_all_patterns() {
        // Verify that analyze_instructions includes all patterns in patterns_checked
        let instructions =
            vec![make_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4"))];

        let analysis = analyze_instructions(&instructions);
        assert!(analysis.patterns_checked.contains(&"COMMUTATIVE_OP_ORDER"));
        assert!(analysis.patterns_checked.contains(&"OFFSET_SWAP"));
    }

    // =========================================================================
    // Pattern::summarize() tests
    // =========================================================================

    #[test]
    fn test_summarize_register_swap_single_pair() {
        let pattern = Pattern {
            pattern: PatternType::RegisterSwap,
            confidence: Confidence::High,
            instruction_count: 5,
            fixability: Fixability::MaybeFixable,
            details: PatternDetails::RegisterSwap {
                swaps: vec![RegisterSwapInfo {
                    target_reg: "r30".to_string(),
                    base_reg: "r31".to_string(),
                    count: 5,
                }],
            },
        };
        let summary = pattern.summarize();
        assert!(summary.one_line.contains("1 pair"));
        assert!(summary.one_line.contains("r30"));
        assert!(summary.one_line.contains("r31"));
        assert!(!summary.truncated);
        assert_eq!(summary.total_items, 1);
    }

    #[test]
    fn test_summarize_register_swap_multiple_pairs() {
        let pattern = Pattern {
            pattern: PatternType::RegisterSwap,
            confidence: Confidence::Medium,
            instruction_count: 20,
            fixability: Fixability::MaybeFixable,
            details: PatternDetails::RegisterSwap {
                swaps: vec![
                    RegisterSwapInfo {
                        target_reg: "r30".to_string(),
                        base_reg: "r31".to_string(),
                        count: 10,
                    },
                    RegisterSwapInfo {
                        target_reg: "r28".to_string(),
                        base_reg: "r29".to_string(),
                        count: 5,
                    },
                    RegisterSwapInfo {
                        target_reg: "r26".to_string(),
                        base_reg: "r27".to_string(),
                        count: 3,
                    },
                    RegisterSwapInfo {
                        target_reg: "f0".to_string(),
                        base_reg: "f1".to_string(),
                        count: 2,
                    },
                ],
            },
        };
        let summary = pattern.summarize();
        assert!(summary.one_line.contains("dominated by"));
        assert!(summary.one_line.contains("r30"));
        assert!(summary.truncated);
        assert_eq!(summary.total_items, 4);
        assert_eq!(summary.top_details.len(), 3);
    }

    #[test]
    fn test_summarize_offset_swap_single() {
        let pattern = Pattern {
            pattern: PatternType::OffsetSwap,
            confidence: Confidence::High,
            instruction_count: 2,
            fixability: Fixability::LikelyFixable,
            details: PatternDetails::OffsetSwap {
                swaps: vec![OffsetSwapInfo {
                    indices: (0, 1),
                    target_offsets: (0x4, 0x8),
                    base_offsets: (0x8, 0x4),
                }],
            },
        };
        let summary = pattern.summarize();
        assert!(summary.one_line.contains("swap"));
        assert!(summary.one_line.contains("0x4"));
        assert!(summary.one_line.contains("0x8"));
        assert!(!summary.truncated);
    }

    #[test]
    fn test_summarize_offset_swap_multiple() {
        let pattern = Pattern {
            pattern: PatternType::OffsetSwap,
            confidence: Confidence::High,
            instruction_count: 4,
            fixability: Fixability::LikelyFixable,
            details: PatternDetails::OffsetSwap {
                swaps: vec![
                    OffsetSwapInfo {
                        indices: (0, 1),
                        target_offsets: (0x4, 0x8),
                        base_offsets: (0x8, 0x4),
                    },
                    OffsetSwapInfo {
                        indices: (2, 3),
                        target_offsets: (0xc, 0x10),
                        base_offsets: (0x10, 0xc),
                    },
                ],
            },
        };
        let summary = pattern.summarize();
        assert!(summary.one_line.contains("offset swaps"));
        assert_eq!(summary.total_items, 2);
    }

    #[test]
    fn test_summarize_control_flow() {
        let pattern = Pattern {
            pattern: PatternType::ControlFlow,
            confidence: Confidence::Medium,
            instruction_count: 3,
            fixability: Fixability::LikelyFixable,
            details: PatternDetails::ControlFlow {
                branch_diffs: vec![
                    BranchDiffInfo {
                        index: 5,
                        target_opcode: Some("beq".to_string()),
                        base_opcode: Some("bne".to_string()),
                        match_type: "diff_op".to_string(),
                    },
                    BranchDiffInfo {
                        index: 10,
                        target_opcode: Some("blt".to_string()),
                        base_opcode: Some("mr".to_string()),
                        match_type: "replace".to_string(),
                    },
                ],
            },
        };
        let summary = pattern.summarize();
        assert!(summary.one_line.contains("inversion"));
        assert!(summary.one_line.contains("replacement"));
        assert_eq!(summary.total_items, 2);
    }

    #[test]
    fn test_summarize_merged_functions() {
        let pattern = Pattern {
            pattern: PatternType::LinkerMerged,
            confidence: Confidence::High,
            instruction_count: 5,
            fixability: Fixability::Unfixable,
            details: PatternDetails::MergedFunctions {
                merged_functions: vec![
                    MergedFunctionCount { name: "merged_Read4FloatStruct".to_string(), count: 3 },
                    MergedFunctionCount { name: "OnlyReturns".to_string(), count: 2 },
                ],
            },
        };
        let summary = pattern.summarize();
        assert!(summary.one_line.contains("5 call(s)"));
        assert!(summary.one_line.contains("2 merged function(s)"));
        assert!(summary.top_details[0].contains("merged_Read4FloatStruct"));
        assert!(!summary.truncated);
    }

    #[test]
    fn test_summarize_bool_mask() {
        let pattern = Pattern {
            pattern: PatternType::BoolMask,
            confidence: Confidence::High,
            instruction_count: 2,
            fixability: Fixability::UsuallyUnfixable,
            details: PatternDetails::BoolMask { bit_positions: vec![24, 31] },
        };
        let summary = pattern.summarize();
        assert!(summary.one_line.contains("bit positions: [24, 31]"));
        assert!(!summary.truncated);
    }

    #[test]
    fn test_summarize_comparison_style() {
        let pattern = Pattern {
            pattern: PatternType::ComparisonStyle,
            confidence: Confidence::Medium,
            instruction_count: 2,
            fixability: Fixability::MaybeFixable,
            details: PatternDetails::ComparisonStyle {
                comparisons: vec![
                    ComparisonStyleInfo {
                        index: 5,
                        opcode: "cmpwi".to_string(),
                        target_value: 5,
                        base_value: 4,
                    },
                    ComparisonStyleInfo {
                        index: 12,
                        opcode: "cmplwi".to_string(),
                        target_value: 10,
                        base_value: 9,
                    },
                ],
            },
        };
        let summary = pattern.summarize();
        assert!(summary.one_line.contains("2 comparison(s)"));
        assert_eq!(summary.top_details.len(), 2);
    }

    #[test]
    fn test_summarize_commutative_op_order() {
        let pattern = Pattern {
            pattern: PatternType::CommutativeOpOrder,
            confidence: Confidence::High,
            instruction_count: 1,
            fixability: Fixability::LikelyFixable,
            details: PatternDetails::CommutativeOpOrder {
                swaps: vec![CommutativeOpInfo {
                    index: 3,
                    opcode: "fmuls".to_string(),
                    target_operands: vec!["f13".to_string(), "f0".to_string()],
                    base_operands: vec!["f0".to_string(), "f13".to_string()],
                }],
            },
        };
        let summary = pattern.summarize();
        assert!(summary.one_line.contains("1 commutative"));
        assert!(!summary.truncated);
    }

    // =========================================================================
    // compute_call_diff() tests
    // =========================================================================

    #[test]
    fn test_call_diff_no_differences() {
        let instructions = vec![
            make_instr(0, "equal", Some("bl"), Some("foo"), Some("bl"), Some("foo")),
            make_instr(1, "equal", Some("bl"), Some("bar"), Some("bl"), Some("bar")),
        ];
        let result = compute_call_diff(&instructions);
        assert!(result.is_none());
    }

    #[test]
    fn test_call_diff_target_only() {
        let instructions =
            vec![make_instr(0, "diff_arg", Some("bl"), Some("foo"), Some("bl"), Some("bar"))];
        let result = compute_call_diff(&instructions).expect("Should have diff");
        assert_eq!(result.target_only.len(), 1);
        assert_eq!(result.target_only[0].name, "foo");
        assert_eq!(result.base_only.len(), 1);
        assert_eq!(result.base_only[0].name, "bar");
    }

    #[test]
    fn test_call_diff_base_only() {
        let instructions = vec![
            make_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_instr(1, "insert", None, None, Some("bl"), Some("extra_func")),
        ];
        let result = compute_call_diff(&instructions).expect("Should have diff");
        assert_eq!(result.base_only.len(), 1);
        assert_eq!(result.base_only[0].name, "extra_func");
        assert!(result.target_only.is_empty());
    }

    #[test]
    fn test_call_diff_count_differs() {
        let instructions = vec![
            make_instr(0, "equal", Some("bl"), Some("foo"), Some("bl"), Some("foo")),
            make_instr(1, "equal", Some("bl"), Some("foo"), Some("bl"), Some("foo")),
            make_instr(2, "delete", Some("bl"), Some("foo"), None, None),
        ];
        let result = compute_call_diff(&instructions).expect("Should have diff");
        assert_eq!(result.count_differs.len(), 1);
        assert_eq!(result.count_differs[0].name, "foo");
        assert_eq!(result.count_differs[0].target_count, 3);
        assert_eq!(result.count_differs[0].base_count, 2);
    }

    #[test]
    fn test_call_diff_skips_merged() {
        let instructions = vec![make_instr(
            0,
            "diff_arg",
            Some("bl"),
            Some("merged_Func"),
            Some("bl"),
            Some("other"),
        )];
        let result = compute_call_diff(&instructions).expect("Should have diff");
        // merged_Func should be filtered out
        assert!(result.target_only.is_empty());
        assert_eq!(result.base_only.len(), 1);
        assert_eq!(result.base_only[0].name, "other");
    }

    // =========================================================================
    // compute_insert_delete_clusters() tests
    // =========================================================================

    #[test]
    fn test_clusters_basic() {
        let instructions = vec![
            make_instr(0, "insert", None, None, Some("stw"), Some("r3, 0(r1)")),
            make_instr(1, "insert", None, None, Some("stw"), Some("r4, 4(r1)")),
            make_instr(2, "insert", None, None, Some("stw"), Some("r5, 8(r1)")),
        ];
        let clusters = compute_insert_delete_clusters(&instructions);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].start_index, 0);
        assert_eq!(clusters[0].end_index, 2);
        assert_eq!(clusters[0].insert_count, 3);
        assert_eq!(clusters[0].delete_count, 0);
    }

    #[test]
    fn test_clusters_with_small_gap() {
        let instructions = vec![
            make_instr(0, "insert", None, None, Some("stw"), Some("r3, 0(r1)")),
            make_instr(1, "insert", None, None, Some("stw"), Some("r4, 4(r1)")),
            make_instr(2, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_instr(3, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_instr(4, "insert", None, None, Some("stw"), Some("r5, 8(r1)")),
        ];
        let clusters = compute_insert_delete_clusters(&instructions);
        assert_eq!(clusters.len(), 1, "Gap <= 2 should merge into one cluster");
        assert_eq!(clusters[0].insert_count, 3);
    }

    #[test]
    fn test_clusters_gap_breaks_cluster() {
        let instructions = vec![
            make_instr(0, "insert", None, None, Some("stw"), Some("r3, 0(r1)")),
            make_instr(1, "insert", None, None, Some("stw"), Some("r4, 4(r1)")),
            make_instr(2, "insert", None, None, Some("stw"), Some("r5, 8(r1)")),
            make_instr(3, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_instr(4, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_instr(5, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_instr(6, "delete", Some("lwz"), Some("r3, 0(r1)"), None, None),
            make_instr(7, "delete", Some("lwz"), Some("r4, 4(r1)"), None, None),
            make_instr(8, "delete", Some("lwz"), Some("r5, 8(r1)"), None, None),
        ];
        let clusters = compute_insert_delete_clusters(&instructions);
        assert_eq!(clusters.len(), 2, "Gap > 2 should split into two clusters");
    }

    #[test]
    fn test_clusters_below_threshold() {
        let instructions = vec![
            make_instr(0, "insert", None, None, Some("stw"), Some("r3, 0(r1)")),
            make_instr(1, "insert", None, None, Some("stw"), Some("r4, 4(r1)")),
        ];
        let clusters = compute_insert_delete_clusters(&instructions);
        assert!(clusters.is_empty(), "Fewer than 3 inserts/deletes should return empty");
    }

    #[test]
    fn test_clusters_dominant_opcodes() {
        let instructions = vec![
            make_instr(0, "insert", None, None, Some("stw"), Some("r3, 0(r1)")),
            make_instr(1, "insert", None, None, Some("stw"), Some("r4, 4(r1)")),
            make_instr(2, "insert", None, None, Some("lwz"), Some("r5, 8(r1)")),
        ];
        let clusters = compute_insert_delete_clusters(&instructions);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].dominant_opcodes[0], "stw");
    }

    // =========================================================================
    // compute_diff_regions() tests
    // =========================================================================

    #[test]
    fn test_regions_all_equal() {
        let instructions: Vec<InstructionDiffOutput> = (0..10)
            .map(|i| make_instr(i, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")))
            .collect();
        let analysis =
            Analysis { patterns: vec![], patterns_checked: vec![], unattributed_mismatches: 0 };
        let regions = compute_diff_regions(&instructions, &analysis);
        assert_eq!(regions.len(), 1);
        assert!((regions[0].match_percent - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_regions_split_by_long_equal_run() {
        let mut instructions = Vec::new();
        // 3 mismatches
        for i in 0..3 {
            instructions.push(make_instr(
                i,
                "diff_arg",
                Some("mr"),
                Some("r3, r4"),
                Some("mr"),
                Some("r4, r3"),
            ));
        }
        // 10 equals (>= REGION_SPLIT_THRESHOLD=8)
        for i in 3..13 {
            instructions.push(make_instr(
                i,
                "equal",
                Some("mr"),
                Some("r3, r4"),
                Some("mr"),
                Some("r3, r4"),
            ));
        }
        // 2 more mismatches
        for i in 13..15 {
            instructions.push(make_instr(
                i,
                "diff_op",
                Some("beq"),
                Some("0x100"),
                Some("bne"),
                Some("0x100"),
            ));
        }
        let analysis =
            Analysis { patterns: vec![], patterns_checked: vec![], unattributed_mismatches: 5 };
        let regions = compute_diff_regions(&instructions, &analysis);
        assert!(regions.len() >= 2, "Long equal run should split into multiple regions");
    }

    #[test]
    fn test_regions_short_equal_no_split() {
        let mut instructions = Vec::new();
        // 3 mismatches
        for i in 0..3 {
            instructions.push(make_instr(
                i,
                "diff_arg",
                Some("mr"),
                Some("r3, r4"),
                Some("mr"),
                Some("r4, r3"),
            ));
        }
        // 5 equals (< REGION_SPLIT_THRESHOLD=8)
        for i in 3..8 {
            instructions.push(make_instr(
                i,
                "equal",
                Some("mr"),
                Some("r3, r4"),
                Some("mr"),
                Some("r3, r4"),
            ));
        }
        // 2 more mismatches
        for i in 8..10 {
            instructions.push(make_instr(
                i,
                "diff_op",
                Some("beq"),
                Some("0x100"),
                Some("bne"),
                Some("0x100"),
            ));
        }
        let analysis =
            Analysis { patterns: vec![], patterns_checked: vec![], unattributed_mismatches: 5 };
        let regions = compute_diff_regions(&instructions, &analysis);
        // Short equal run should merge into one region (non-matched spans merge)
        assert_eq!(regions.len(), 1, "Short equal run should not split into separate regions");
    }

    #[test]
    fn test_regions_empty() {
        let instructions: Vec<InstructionDiffOutput> = vec![];
        let analysis =
            Analysis { patterns: vec![], patterns_checked: vec![], unattributed_mismatches: 0 };
        let regions = compute_diff_regions(&instructions, &analysis);
        assert!(regions.is_empty());
    }

    // =========================================================================
    // count_pattern_in_range() tests
    // =========================================================================

    #[test]
    fn test_count_pattern_control_flow_in_range() {
        let pattern = Pattern {
            pattern: PatternType::ControlFlow,
            confidence: Confidence::Medium,
            instruction_count: 2,
            fixability: Fixability::LikelyFixable,
            details: PatternDetails::ControlFlow {
                branch_diffs: vec![
                    BranchDiffInfo {
                        index: 5,
                        target_opcode: Some("beq".to_string()),
                        base_opcode: Some("bne".to_string()),
                        match_type: "diff_op".to_string(),
                    },
                    BranchDiffInfo {
                        index: 20,
                        target_opcode: Some("blt".to_string()),
                        base_opcode: Some("bge".to_string()),
                        match_type: "diff_op".to_string(),
                    },
                ],
            },
        };
        // Range covers indices 3-10 (only branch at index 5 is in range)
        let instructions: Vec<InstructionDiffOutput> = (3..=10)
            .map(|i| {
                make_instr(i, "diff_op", Some("beq"), Some("0x100"), Some("bne"), Some("0x100"))
            })
            .collect();
        let count = count_pattern_in_range(&pattern, &instructions);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_count_pattern_register_swap_in_range() {
        let pattern = Pattern {
            pattern: PatternType::RegisterSwap,
            confidence: Confidence::Medium,
            instruction_count: 4,
            fixability: Fixability::MaybeFixable,
            details: PatternDetails::RegisterSwap {
                swaps: vec![RegisterSwapInfo {
                    target_reg: "r30".to_string(),
                    base_reg: "r31".to_string(),
                    count: 4,
                }],
            },
        };
        let instructions = vec![
            make_instr(0, "diff_arg", Some("mr"), Some("r30, r3"), Some("mr"), Some("r31, r3")),
            make_instr(1, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_instr(
                2,
                "diff_arg",
                Some("lwz"),
                Some("r4, 0(r30)"),
                Some("lwz"),
                Some("r4, 0(r31)"),
            ),
        ];
        let count = count_pattern_in_range(&pattern, &instructions);
        assert_eq!(count, 2);
    }

    // =========================================================================
    // Verdict integration tests
    // =========================================================================

    #[test]
    fn test_verdict_merged_includes_summary() {
        let summary = InstructionSummary { total: 10, equal: 5, diff_arg: 5, ..Default::default() };
        let analysis = Analysis {
            patterns: vec![Pattern {
                pattern: PatternType::LinkerMerged,
                confidence: Confidence::High,
                instruction_count: 4,
                fixability: Fixability::Unfixable,
                details: PatternDetails::MergedFunctions {
                    merged_functions: vec![
                        MergedFunctionCount { name: "merged_test".to_string(), count: 3 },
                        MergedFunctionCount { name: "OnlyReturns".to_string(), count: 1 },
                    ],
                },
            }],
            patterns_checked: vec!["LINKER_MERGED"],
            unattributed_mismatches: 1,
        };
        let verdict = compute_verdict(&summary, &analysis, Some(97.0));
        assert_eq!(verdict.classification, VerdictClassification::AtLimit);
        // Explanation should include summarize output
        assert!(verdict.explanation.contains("call(s)"));
    }

    #[test]
    fn test_verdict_control_flow_includes_summary() {
        let summary = InstructionSummary {
            total: 20,
            equal: 15,
            diff_op: 3,
            replace: 2,
            ..Default::default()
        };
        let analysis = Analysis {
            patterns: vec![Pattern {
                pattern: PatternType::ControlFlow,
                confidence: Confidence::Medium,
                instruction_count: 3,
                fixability: Fixability::LikelyFixable,
                details: PatternDetails::ControlFlow {
                    branch_diffs: vec![BranchDiffInfo {
                        index: 5,
                        target_opcode: Some("beq".to_string()),
                        base_opcode: Some("bne".to_string()),
                        match_type: "diff_op".to_string(),
                    }],
                },
            }],
            patterns_checked: vec!["CONTROL_FLOW"],
            unattributed_mismatches: 2,
        };
        let verdict = compute_verdict(&summary, &analysis, Some(85.0));
        assert_eq!(verdict.classification, VerdictClassification::LikelyFixable);
        // Suggestions should include pattern-specific info
        assert!(!verdict.suggestions.is_empty());
    }
}
