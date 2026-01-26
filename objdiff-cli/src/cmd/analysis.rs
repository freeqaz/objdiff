//! Pattern detection and fixability analysis for decompilation diffs.
//!
//! This module implements automated diagnosis of instruction mismatches,
//! detecting common patterns that explain why code doesn't match and
//! providing verdict classifications for triage.

use std::{collections::HashMap, sync::LazyLock};

use regex::Regex;
use serde::Serialize;

use super::diff::{InstructionDiffOutput, InstructionSummary};

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
static MERGED_FUNC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(merged_|OnlyReturns|\?\?_[EG].*PAXI@Z$)").unwrap()
});

/// Regex to extract register names (r0-r31, f0-f31)
static REGISTER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([rf]\d+)\b").unwrap()
});

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
}

impl PatternType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PatternType::LinkerMerged => "LINKER_MERGED",
            PatternType::BoolMask => "BOOL_MASK",
            PatternType::RegisterSwap => "REGISTER_SWAP",
            PatternType::ComparisonStyle => "COMPARISON_STYLE",
            PatternType::ControlFlow => "CONTROL_FLOW",
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

/// Details specific to each pattern type.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum PatternDetails {
    /// Merged function call counts
    MergedFunctions {
        merged_functions: Vec<MergedFunctionCount>,
    },
    /// Bool mask bit positions detected
    BoolMask {
        bit_positions: Vec<u8>,
    },
    /// Register swap mappings with occurrence counts
    RegisterSwap {
        swaps: Vec<RegisterSwapInfo>,
    },
    /// Comparison style differences (> vs >=)
    ComparisonStyle {
        comparisons: Vec<ComparisonStyleInfo>,
    },
    /// Control flow branch differences
    ControlFlow {
        branch_diffs: Vec<BranchDiffInfo>,
    },
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
    let mut merged_functions: Vec<MergedFunctionCount> = merged_calls
        .into_iter()
        .map(|(name, count)| MergedFunctionCount { name, count })
        .collect();
    merged_functions.sort_by(|a, b| b.count.cmp(&a.count));

    Some(Pattern {
        pattern: PatternType::LinkerMerged,
        confidence: Confidence::High,
        instruction_count: total_count,
        fixability: Fixability::Unfixable,
        details: PatternDetails::MergedFunctions { merged_functions },
    })
}

/// Detect bool return masking patterns.
///
/// Looks for `delete`/`insert` instructions with `clrlwi` or `rlwinm`
/// opcodes that mask values to bool (bit 31) or byte (bits 24-31).
pub fn detect_bool_mask(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut mask_count = 0;
    let mut bit_positions: Vec<u8> = Vec::new();

    for instr in instructions {
        if !matches!(instr.match_type.as_str(), "delete" | "insert") {
            continue;
        }

        // Check both target and base sides for bool masking
        for side in [&instr.target, &instr.base].into_iter().flatten() {
            match side.opcode.as_str() {
                "clrlwi" => {
                    // clrlwi rD, rS, N - clears left N bits
                    // N=24 masks to u8, N=31 masks to bool (1 bit)
                    if let Some(args) = &side.args {
                        if args.contains(", 24") {
                            mask_count += 1;
                            if !bit_positions.contains(&24) {
                                bit_positions.push(24);
                            }
                        } else if args.contains(", 31") {
                            mask_count += 1;
                            if !bit_positions.contains(&31) {
                                bit_positions.push(31);
                            }
                        }
                    }
                }
                "rlwinm" => {
                    // rlwinm rD, rS, 0, 24, 31 - equivalent to clrlwi for byte
                    // rlwinm rD, rS, 0, 31, 31 - equivalent to clrlwi for bool
                    if let Some(args) = &side.args {
                        if args.contains("0, 24, 31") {
                            mask_count += 1;
                            if !bit_positions.contains(&24) {
                                bit_positions.push(24);
                            }
                        } else if args.contains("0, 31, 31") {
                            mask_count += 1;
                            if !bit_positions.contains(&31) {
                                bit_positions.push(31);
                            }
                        }
                    }
                }
                _ => {}
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
        let base_regs: Vec<&str> =
            REGISTER_RE.find_iter(base_args).map(|m| m.as_str()).collect();

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
    let significant: Vec<_> = mappings
        .into_iter()
        .filter(|(_, count)| *count >= MIN_REGISTER_SWAP_OCCURRENCES)
        .collect();

    if significant.is_empty() {
        return None;
    }

    let total: usize = significant.iter().map(|(_, c)| c).sum();

    // Higher confidence if single consistent swap with many occurrences
    let confidence = if significant.len() == 1 && total >= 5 {
        Confidence::High
    } else {
        Confidence::Medium
    };

    let mut swaps: Vec<RegisterSwapInfo> = significant
        .into_iter()
        .map(|((reg1, reg2), count)| RegisterSwapInfo {
            target_reg: reg1,
            base_reg: reg2,
            count,
        })
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
const BRANCH_OPCODES: &[&str] = &[
    "b", "bl", "blr", "bctr", "bctrl", "blrl",
    "beq", "bne", "blt", "ble", "bgt", "bge",
    "bdnz", "bdz", "bdnzt", "bdnzf", "bdzt", "bdzf",
    "bso", "bns", "bun", "bnu",
    // Link register variants
    "beqlr", "bnelr", "bltlr", "blelr", "bgtlr", "bgelr",
    // Count register variants
    "beqctr", "bnectr", "bltctr", "blectr", "bgtctr", "bgectr",
];

/// Check if an opcode is a branch instruction.
/// Handles hint suffixes (+/-) that may be appended.
fn is_branch_opcode(opcode: &str) -> bool {
    // Strip hint suffix if present
    let base = opcode.trim_end_matches(['+', '-']);
    BRANCH_OPCODES.contains(&base)
}

/// Detect control flow differences on branch instructions.
///
/// Looks for `diff_op` or `replace` match types where either the target
/// or base instruction is a branch. This indicates structural control
/// flow differences that are often fixable.
pub fn detect_control_flow(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut branch_diffs: Vec<BranchDiffInfo> = Vec::new();

    for instr in instructions {
        // Only look at opcode differences or replacements
        if !matches!(instr.match_type.as_str(), "diff_op" | "replace") {
            continue;
        }

        let target_op = instr.target.as_ref().map(|t| t.opcode.as_str());
        let base_op = instr.base.as_ref().map(|b| b.opcode.as_str());

        // Check if either side is a branch instruction
        let target_is_branch = target_op.is_some_and(is_branch_opcode);
        let base_is_branch = base_op.is_some_and(is_branch_opcode);

        if target_is_branch || base_is_branch {
            branch_diffs.push(BranchDiffInfo {
                index: instr.index,
                target_opcode: target_op.map(|s| s.to_string()),
                base_opcode: base_op.map(|s| s.to_string()),
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

    // Count total mismatches
    let total_mismatches = instructions
        .iter()
        .filter(|i| i.match_type != "equal")
        .count();

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
        return Verdict {
            classification: VerdictClassification::AtLimit,
            confidence: Confidence::High,
            explanation:
                "Bool mask pattern detected - compiler bool return handling cannot be matched."
                    .to_string(),
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
    let merged_ratio = if total_mismatches > 0 {
        merged_count as f32 / total_mismatches as f32
    } else {
        0.0
    };

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
        return Verdict {
            classification: VerdictClassification::AtLimit,
            confidence: Confidence::High,
            explanation: format!(
                "{:.1}% of mismatches are calls to linker-merged functions.",
                merged_ratio * 100.0
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
        let mut suggestions = vec![Suggestion {
            action: "Check branch conditions and if/else structure".to_string(),
        }];

        if summary.diff_op > 0 {
            suggestions.push(Suggestion {
                action: "Try equivalent comparison operators (>= vs >, etc.)".to_string(),
            });
        }

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
        return Verdict {
            classification: VerdictClassification::MaybeFixable,
            confidence: Confidence::Medium,
            explanation: format!(
                "{} register swap(s) detected. May be fixable by reordering variable declarations.",
                register_swap_count
            ),
            factors,
            recommendation: "Try reordering variable declarations or delaying assignments."
                .to_string(),
            suggestions: vec![
                Suggestion {
                    action: "Reorder local variable declarations".to_string(),
                },
                Suggestion {
                    action: "Move variable initialization closer to first use".to_string(),
                },
            ],
        };
    }

    // Default: needs investigation
    Verdict {
        classification: VerdictClassification::NeedsInvestigation,
        confidence: Confidence::Low,
        explanation: "Mixed patterns detected - manual analysis recommended.".to_string(),
        factors,
        recommendation: "Review instruction diff manually to understand mismatch causes."
            .to_string(),
        suggestions: vec![Suggestion {
            action: "Use --include-instructions to inspect specific differences".to_string(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::diff::InstructionInfo;

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
            }),
            base: base_op.map(|op| InstructionInfo {
                address: format!("{:#x}", index * 4),
                opcode: op.to_string(),
                args: base_args.map(|s| s.to_string()),
            }),
            match_type: match_type.to_string(),
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
            make_instr(1, "diff_arg", Some("lwz"), Some("r4, 0(r31)"), Some("lwz"), Some("r4, 0(r30)")),
            make_instr(2, "diff_arg", Some("stw"), Some("r5, 4(r31)"), Some("stw"), Some("r5, 4(r30)")),
            make_instr(3, "diff_arg", Some("mr"), Some("r3, r31"), Some("mr"), Some("r3, r30")),
        ];

        let pattern = detect_register_swap(&instructions).expect("Should detect register swap");
        assert_eq!(pattern.pattern, PatternType::RegisterSwap);
        assert_eq!(pattern.instruction_count, 4);
        assert_eq!(pattern.confidence, Confidence::Medium);
    }

    #[test]
    fn test_verdict_complete() {
        let summary = InstructionSummary {
            total: 10,
            equal: 10,
            ..Default::default()
        };
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
        let summary = InstructionSummary {
            total: 10,
            equal: 5,
            diff_arg: 5,
            ..Default::default()
        };
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

        let pattern = detect_comparison_style(&instructions).expect("Should detect comparison style");
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
        let instructions = vec![
            make_instr(
                0,
                "diff_arg",
                Some("cmplwi"),
                Some("r5, 10"),
                Some("cmplwi"),
                Some("r5, 9"),
            ),
        ];

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
        let instructions = vec![
            make_instr(
                0,
                "diff_arg",
                Some("cmpwi"),
                Some("cr0, r3, 10"),
                Some("cmpwi"),
                Some("cr0, r3, 5"),
            ),
        ];

        let pattern = detect_comparison_style(&instructions);
        assert!(pattern.is_none(), "Should not detect when diff > 1");
    }

    #[test]
    fn test_detect_control_flow_diff_op() {
        // Test case: diff_op on branch instruction (beq vs bne)
        let instructions = vec![
            make_instr(0, "equal", Some("cmpwi"), Some("cr0, r3, 0"), Some("cmpwi"), Some("cr0, r3, 0")),
            make_instr(
                1,
                "diff_op",
                Some("beq"),
                Some("0x100"),
                Some("bne"),
                Some("0x100"),
            ),
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
        let instructions = vec![
            make_instr(
                0,
                "replace",
                Some("blt"),
                Some("0x200"),
                Some("mr"),
                Some("r3, r4"),
            ),
        ];

        let pattern = detect_control_flow(&instructions).expect("Should detect replace with branch");
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
        let instructions = vec![
            make_instr(
                0,
                "diff_op",
                Some("beq+"),
                Some("0x100"),
                Some("beq-"),
                Some("0x100"),
            ),
        ];

        let pattern = detect_control_flow(&instructions).expect("Should detect branch with hints");
        assert_eq!(pattern.pattern, PatternType::ControlFlow);
    }

    #[test]
    fn test_detect_control_flow_no_branch() {
        // Test case: diff_op but not on branch instruction
        let instructions = vec![
            make_instr(
                0,
                "diff_op",
                Some("add"),
                Some("r3, r4, r5"),
                Some("sub"),
                Some("r3, r4, r5"),
            ),
        ];

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
        let instructions = vec![
            make_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
        ];

        let analysis = analyze_instructions(&instructions);
        assert!(analysis.patterns_checked.contains(&"COMPARISON_STYLE"));
        assert!(analysis.patterns_checked.contains(&"CONTROL_FLOW"));
    }
}
