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

/// Check if a PowerPC register is callee-saved (preserved across function calls).
/// GPR r13-r31 and FPR f14-f31 are callee-saved per the Xbox 360 ABI.
///
/// This is the discriminator behind the register-swap hints: a volatile
/// register (GPR r0,r3-r12; FPR f0-f13) cannot hold a value across a call, so a
/// swap confined to volatiles is never itself a live-across-call disagreement —
/// look at scheduling and operand order instead. That does NOT mean volatile
/// allocation is beyond source-level influence: measured on MSVC/PPC,
/// rescheduling a product before its compare and matching the target's compare
/// operand order closed nine volatile FPR swaps by hand
/// (`RndText::SizeCheck`).
fn is_callee_saved_register(reg: &str) -> bool {
    if let Some(num_str) = reg.strip_prefix('r')
        && let Ok(n) = num_str.parse::<u32>()
    {
        return (13..=31).contains(&n);
    }
    if let Some(num_str) = reg.strip_prefix('f')
        && let Ok(n) = num_str.parse::<u32>()
    {
        return (14..=31).contains(&n);
    }
    false
}

/// Highest-count key of a count map, ties broken by the key itself.
///
/// `Iterator::max_by_key` returns the LAST maximum in iteration order, and over
/// a `HashMap` that order is per-instance random — so on a tie this picked a
/// different opcode pair on every run of the same binary. The witness was a
/// dc3-decomp control-flow row whose verdict suggestion alternated between
/// `2 replacement(s) (bl↔beq)` and `2 replacement(s) (addi↔bne)`, 11/15 vs
/// 4/15 over one binary, on a 1↔1 count tie.
fn dominant_key(counts: &HashMap<String, usize>) -> Option<&str> {
    counts.iter().max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0))).map(|(k, _)| k.as_str())
}

/// Total-order key for a PowerPC register name, by class then number.
///
/// Used to break ties in count-ordered summaries. Without an explicit
/// tie-break those orderings fall out of `HashMap` iteration, which
/// `std::collections::HashMap` reseeds per instance — so equal-count entries
/// came out in a different order on every run of the same binary against the
/// same object, making diff reports irreproducible.
///
/// Ordering by number rather than lexicographically also puts `f9` before
/// `f10`, which is what a reader expects.
fn register_sort_key(reg: &str) -> (u8, u32, &str) {
    if let (Some(class), Some(rest)) = (reg.as_bytes().first(), reg.get(1..))
        && let Ok(number) = rest.parse::<u32>()
    {
        return (*class, number, reg);
    }
    // Not `<class><number>`: sort after everything recognisable, by name.
    (u8::MAX, u32::MAX, reg)
}

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
    /// Calls to linker-merged functions (ICF — source-immune at the call site)
    LinkerMerged,
    /// Bool return masking with clrlwi/rlwinm (permuter-class)
    BoolMask,
    /// Consistent register allocation swaps. Usually a *symptom*, not a cause:
    /// the whole swap set tends to flip at once when the underlying liveness or
    /// scheduling difference is fixed. Declaration reorder is the lever for
    /// stack-slot mismatches (`OffsetSwap`), and is usually inert here.
    /// See `docs/research/register-swap-symptom-not-cause.md`.
    RegisterSwap,
    /// Comparison immediate differs by 1, suggesting > vs >= style difference
    ComparisonStyle,
    /// Branch instruction differences (diff_op/replace on branches)
    ControlFlow,
    /// Operand order swapped in commutative operations (fadd, fmul, add, etc.)
    CommutativeOpOrder,
    /// Two offsets swapped between target and base
    OffsetSwap,
    /// Anonymous namespace TU hash mismatch (source-immune — derived from TU path)
    AnonymousNamespaceHash,
    /// Static guard counter (`$S#`) mismatch from wrong TU function order
    StaticGuardCounter,
    /// Unnecessary dynamic_cast — base calls `__dynamic_cast`, target doesn't
    DynamicCastMismatch,
    /// Dead store elimination — base stores zero to RAII member, target omits it
    DeadStoreElimination,
    /// Prologue saves different number of callee-saved registers
    PrologueMismatch,
    /// One side uses `_alloca` intrinsic, other uses CRT `alloca` wrapper
    AllocaMismatch,
    /// Scope counter `?N?` in static local name differs (extra braces in source)
    ScopeCounterMismatch,
    /// MakeString template parameter mismatch (type or __FILE__ length)
    MakeStringTemplateMismatch,
    /// Address relocation noise — lis/addi loading different absolute addresses
    AddressRelocationNoise,
    /// Boolean negation — subfic vs subic compiler choice
    BooleanNegation,
    /// Float precision mismatch — fmul vs fmuls, fadd vs fadds, etc.
    FloatPrecisionMismatch,
    /// Explicit ternary for fsel — fneg/fsubs + fsel vs branched comparison
    FselTernary,
    /// Float to int to float conversion — fctiwz + stfd/fmr vs direct float use
    FloatToIntToFloat,
    /// Signed/unsigned instruction-pair mismatch at aligned rows — one side
    /// emits the signed opcode, the other the logical/unsigned counterpart
    /// (lha/lhz, srawi/srwi, cmpw/cmplw, extsb/extsh). Fingerprint of a
    /// source-level signedness/width type disagreement (e.g. `char` vs
    /// `unsigned char`, `int` vs `unsigned`, loop-index signedness).
    SignednessMismatch,
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
            PatternType::AnonymousNamespaceHash => "ANONYMOUS_NAMESPACE_HASH",
            PatternType::StaticGuardCounter => "STATIC_GUARD_COUNTER",
            PatternType::DynamicCastMismatch => "DYNAMIC_CAST_MISMATCH",
            PatternType::DeadStoreElimination => "DEAD_STORE_ELIMINATION",
            PatternType::PrologueMismatch => "PROLOGUE_MISMATCH",
            PatternType::AllocaMismatch => "ALLOCA_MISMATCH",
            PatternType::ScopeCounterMismatch => "SCOPE_COUNTER_MISMATCH",
            PatternType::MakeStringTemplateMismatch => "MAKESTRING_TEMPLATE_MISMATCH",
            PatternType::AddressRelocationNoise => "ADDRESS_RELOCATION_NOISE",
            PatternType::BooleanNegation => "BOOLEAN_NEGATION",
            PatternType::FloatPrecisionMismatch => "FLOAT_PRECISION_MISMATCH",
            PatternType::FselTernary => "FSEL_TERNARY",
            PatternType::FloatToIntToFloat => "FLOAT_TO_INT_TO_FLOAT",
            PatternType::SignednessMismatch => "SIGNEDNESS_MISMATCH",
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
///
/// IMPORTANT: "RarelyHandFixable" does NOT mean "give up." It means a single
/// hand-edit is unlikely to converge — these patterns are typically either
/// (a) genuine build artifacts (anonymous-namespace hashes, address relocation
/// noise — where source mutation cannot help), or (b) compiler-internal
/// decisions that the source permuter usually cracks given enough rounds.
/// Always dispatch the permuter on the function before classifying it as
/// truly stuck.
///
/// `PermuterClass` is the primary handle for register-allocation cascades,
/// FPR scheduling, bool materialization, and stack-slot inversions. These
/// are tedious by hand but mechanical for the source permuter. The permuter
/// has 100+ mutation patterns and is evolving constantly — let it choose
/// which patterns to apply; do not hand-enumerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fixability {
    /// Hand-editing is unlikely to converge. Either a genuine artifact
    /// (linker/path-derived) or a compiler decision typically fixed by the
    /// permuter. Run the permuter on the function before classifying as stuck.
    RarelyHandFixable,
    /// Mechanical to fix via the source permuter; hand-edits usually thrash.
    /// Dispatch the permuter on the function/unit.
    PermuterClass,
    /// Either hand-edit or permuter; the permuter is a low-effort first try.
    MaybeFixable,
    /// Clear source-level edit path. Hand-edit is the primary handle.
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

/// Information about an anonymous namespace TU hash mismatch.
#[derive(Debug, Clone, Serialize)]
pub struct AnonNamespaceInfo {
    pub symbol: String,
    pub target_hash: String,
    pub base_hash: String,
}

/// Information about a static guard counter mismatch.
#[derive(Debug, Clone, Serialize)]
pub struct StaticGuardInfo {
    pub target_immediate: i64,
    pub base_immediate: i64,
}

/// Information about a prologue register count mismatch.
#[derive(Debug, Clone, Serialize)]
pub struct PrologueMismatchInfo {
    pub target_first_reg: u32,
    pub base_first_reg: u32,
    /// Stack frame size from `stwu r1, -N(r1)` in target prologue, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_frame_size: Option<u32>,
    /// Stack frame size from `stwu r1, -N(r1)` in base prologue, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_frame_size: Option<u32>,
}

/// Sub-type of MakeString template mismatch.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MakeStringMismatchSubType {
    /// Template parameter types differ (e.g., PBD vs VSymbol@@)
    Type,
    /// Only __FILE__ char[N] dimension differs
    FileLength,
    /// Both type and __FILE__ differ
    Mixed,
}

/// Information about a MakeString template mismatch.
#[derive(Debug, Clone, Serialize)]
pub struct MakeStringMismatchInfo {
    pub index: usize,
    pub target_template: String,
    pub base_template: String,
    pub sub_type: MakeStringMismatchSubType,
}

/// Information about address relocation noise.
#[derive(Debug, Clone, Serialize)]
pub struct AddressRelocationInfo {
    pub count: usize,
    pub pair_count: usize,
}

/// Information about a float precision mismatch.
#[derive(Debug, Clone, Serialize)]
pub struct FloatPrecisionMismatchEntry {
    pub index: usize,
    pub target_op: String,
    pub base_op: String,
}

/// Information about a signed/unsigned instruction-pair mismatch.
#[derive(Debug, Clone, Serialize)]
pub struct SignednessMismatchEntry {
    pub index: usize,
    pub target_op: String,
    pub base_op: String,
    /// The signed member of the matched pair (e.g. `lha`, `srawi`, `cmpw`,
    /// `extsb`). Disambiguates which side carried the signed interpretation.
    pub signed_op: String,
    /// The unsigned/logical member of the matched pair (e.g. `lhz`, `srwi`,
    /// `cmplw`, `extsh`).
    pub unsigned_op: String,
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
    /// Anonymous namespace TU hash mismatches
    AnonymousNamespaceHash { mismatches: Vec<AnonNamespaceInfo> },
    /// Static guard counter mismatches
    StaticGuardCounter { guards: Vec<StaticGuardInfo> },
    /// Dynamic cast calls present in base but not target
    DynamicCastMismatch { count: usize },
    /// Dead store elimination — null stores in base not in target
    DeadStoreElimination { count: usize },
    /// Prologue saves different registers
    PrologueMismatch { info: PrologueMismatchInfo },
    /// Alloca intrinsic vs CRT wrapper mismatch
    AllocaMismatch { target_uses_intrinsic: bool },
    /// Scope counter mismatch in static local names
    ScopeCounterMismatch { count: usize },
    /// MakeString template parameter mismatches
    MakeStringTemplateMismatch { mismatches: Vec<MakeStringMismatchInfo> },
    /// Address relocation noise (lis/addi loading different globals)
    AddressRelocationNoise { info: AddressRelocationInfo },
    /// Boolean negation (subfic vs subic)
    BooleanNegation { count: usize },
    /// Float precision mismatches (fmul vs fmuls, etc.)
    FloatPrecisionMismatch { mismatches: Vec<FloatPrecisionMismatchEntry> },
    /// Explicit ternary for fsel — fneg/fsubs + fsel vs branched comparison
    FselTernary { count: usize },
    /// Float to int to float conversion — fctiwz + stfd/fmr vs direct float use
    FloatToIntToFloat { count: usize },
    /// Signed/unsigned instruction-pair mismatches at aligned rows
    SignednessMismatch { mismatches: Vec<SignednessMismatchEntry> },
}

/// A detected pattern in the instruction diff.
#[derive(Debug, Clone, Serialize)]
pub struct Pattern {
    pub pattern: PatternType,
    pub confidence: Confidence,
    pub instruction_count: usize,
    pub fixability: Fixability,
    pub details: PatternDetails,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub doc_urls: Vec<String>,
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
                // Classify register types for display
                // These labels name the CAUSE to look for, not a fix recipe.
                // The volatile/callee-saved split is decidable from the ABI, not
                // guessed: a volatile register can't hold a value across a call,
                // so a pure-volatile swap rules liveness out and leaves
                // scheduling and operand order. Callee-saved swaps are the
                // live-across-call case. Declaration order is deliberately not
                // suggested here — see
                // docs/research/register-swap-symptom-not-cause.md.
                let reg_class = match self.fixability {
                    Fixability::RarelyHandFixable => {
                        " [volatile — scheduling/operand order, not liveness]"
                    }
                    Fixability::MaybeFixable => {
                        let has_callee = swaps.iter().any(|s| {
                            is_callee_saved_register(&s.target_reg)
                                && is_callee_saved_register(&s.base_reg)
                        });
                        let has_volatile = swaps.iter().any(|s| {
                            !is_callee_saved_register(&s.target_reg)
                                || !is_callee_saved_register(&s.base_reg)
                        });
                        if has_callee && has_volatile {
                            " [mixed volatile+callee-saved — one liveness cause, start there]"
                        } else {
                            " [callee-saved — check liveness across calls]"
                        }
                    }
                    _ => "",
                };
                let one_line = if pairs == 1 {
                    format!(
                        "{} instructions, {} pair ({}↔{}){}",
                        total_occurrences, pairs, swaps[0].target_reg, swaps[0].base_reg,
                        reg_class
                    )
                } else {
                    let dominant = &swaps[0]; // sorted by count descending
                    format!(
                        "{} instructions across {} pairs, dominated by {}↔{} ({} of {}){}",
                        self.instruction_count,
                        pairs,
                        dominant.target_reg,
                        dominant.base_reg,
                        dominant.count,
                        total_occurrences,
                        reg_class
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
                // Tie-break on the offset pair itself: see register_sort_key.
                sorted_pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

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
                    let dominant = dominant_key(&inversion_types);
                    if let Some(typ) = dominant {
                        parts.push(format!("{} condition inversion(s) ({})", inversions, typ));
                    } else {
                        parts.push(format!("{} condition inversion(s)", inversions));
                    }
                }
                if replacements > 0 {
                    let dominant = dominant_key(&replacement_types);
                    if let Some(typ) = dominant {
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
            PatternDetails::AnonymousNamespaceHash { mismatches } => PatternSummary {
                one_line: format!(
                    "{} anon namespace hash mismatch(es) (linker artifact — derived from TU path)",
                    mismatches.len()
                ),
                top_details: mismatches
                    .iter()
                    .take(3)
                    .map(|m| format!("{}: {} vs {}", m.symbol, m.target_hash, m.base_hash))
                    .collect(),
                truncated: mismatches.len() > 3,
                total_items: mismatches.len(),
            },
            PatternDetails::StaticGuardCounter { guards } => PatternSummary {
                one_line: format!(
                    "{} static guard counter mismatch(es) (fixable: reorder TU definitions)",
                    guards.len()
                ),
                top_details: guards
                    .iter()
                    .take(3)
                    .map(|g| format!("target imm {} vs base imm {}", g.target_immediate, g.base_immediate))
                    .collect(),
                truncated: guards.len() > 3,
                total_items: guards.len(),
            },
            PatternDetails::DynamicCastMismatch { count } => PatternSummary {
                one_line: format!(
                    "{} dynamic_cast call(s) in base not in target (use GetObj instead)",
                    count
                ),
                top_details: vec![],
                truncated: false,
                total_items: *count,
            },
            PatternDetails::DeadStoreElimination { count } => PatternSummary {
                one_line: format!(
                    "{} dead store(s) in base eliminated by target compiler — try permuter sweep",
                    count
                ),
                top_details: vec![],
                truncated: false,
                total_items: *count,
            },
            PatternDetails::PrologueMismatch { info } => PatternSummary {
                one_line: format!(
                    "prologue saves r{}-r31 (target) vs r{}-r31 (base) -- variable count differs",
                    info.target_first_reg, info.base_first_reg
                ),
                top_details: vec![],
                truncated: false,
                total_items: 1,
            },
            PatternDetails::AllocaMismatch { target_uses_intrinsic } => PatternSummary {
                one_line: format!(
                    "target uses {} alloca, base uses {} -- change to match",
                    if *target_uses_intrinsic { "_alloca (intrinsic)" } else { "alloca (CRT)" },
                    if *target_uses_intrinsic { "alloca (CRT)" } else { "_alloca (intrinsic)" }
                ),
                top_details: vec![],
                truncated: false,
                total_items: 1,
            },
            PatternDetails::ScopeCounterMismatch { count } => PatternSummary {
                one_line: format!(
                    "{} scope counter `?N?` mismatch(es) -- remove extra braces in source",
                    count
                ),
                top_details: vec![],
                truncated: false,
                total_items: *count,
            },
            PatternDetails::MakeStringTemplateMismatch { mismatches } => {
                let type_count = mismatches
                    .iter()
                    .filter(|m| matches!(m.sub_type, MakeStringMismatchSubType::Type))
                    .count();
                let file_count = mismatches
                    .iter()
                    .filter(|m| matches!(m.sub_type, MakeStringMismatchSubType::FileLength))
                    .count();
                let mut parts = Vec::new();
                if type_count > 0 {
                    parts.push(format!("{} type", type_count));
                }
                if file_count > 0 {
                    parts.push(format!("{} __FILE__", file_count));
                }
                let mixed = mismatches.len() - type_count - file_count;
                if mixed > 0 {
                    parts.push(format!("{} mixed", mixed));
                }
                let one_line = format!(
                    "{} MakeString template mismatch(es) ({})",
                    mismatches.len(),
                    parts.join(", ")
                );
                let top_details: Vec<String> = mismatches
                    .iter()
                    .take(3)
                    .map(|m| {
                        let sub = match m.sub_type {
                            MakeStringMismatchSubType::Type => "type",
                            MakeStringMismatchSubType::FileLength => "__FILE__",
                            MakeStringMismatchSubType::Mixed => "mixed",
                        };
                        format!("idx {}: {} ({})", m.index, sub, m.target_template)
                    })
                    .collect();
                PatternSummary {
                    one_line,
                    top_details,
                    truncated: mismatches.len() > 3,
                    total_items: mismatches.len(),
                }
            }
            PatternDetails::AddressRelocationNoise { info } => PatternSummary {
                one_line: format!(
                    "{} address relocation(s), {} lis/addi pair(s) (linker artifact — different .text layout)",
                    info.count, info.pair_count
                ),
                top_details: vec![],
                truncated: false,
                total_items: info.count,
            },
            PatternDetails::BooleanNegation { count } => PatternSummary {
                one_line: format!(
                    "{} boolean negation(s) subfic↔subic — compiler choice, try permuter sweep",
                    count
                ),
                top_details: vec![],
                truncated: false,
                total_items: *count,
            },
            PatternDetails::FloatPrecisionMismatch { mismatches } => {
                // Group by opcode pair
                let mut pair_counts: HashMap<String, usize> = HashMap::new();
                for m in mismatches {
                    let key = format!("{}↔{}", m.target_op, m.base_op);
                    *pair_counts.entry(key).or_insert(0) += 1;
                }
                let mut sorted: Vec<_> = pair_counts.into_iter().collect();
                // Tie-break on the opcode pair: see register_sort_key.
                sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                let dominant = sorted.first().map(|(k, _)| k.as_str()).unwrap_or("?");
                let one_line = format!(
                    "{} float precision mismatch(es), dominated by {}",
                    mismatches.len(),
                    dominant
                );
                let top_details: Vec<String> = sorted
                    .iter()
                    .take(3)
                    .map(|(pair, count)| format!("{}: {} instruction(s)", pair, count))
                    .collect();
                PatternSummary {
                    one_line,
                    top_details,
                    truncated: sorted.len() > 3,
                    total_items: mismatches.len(),
                }
            }
            PatternDetails::FselTernary { count } => PatternSummary {
                one_line: format!(
                    "{} fsel explicit ternary pattern(s) detected",
                    count
                ),
                top_details: vec![],
                truncated: false,
                total_items: *count,
            },
            PatternDetails::FloatToIntToFloat { count } => PatternSummary {
                one_line: format!(
                    "{} float-to-int-to-float conversion(s) detected (fctiwz+stfd)",
                    count
                ),
                top_details: vec![],
                truncated: false,
                total_items: *count,
            },
            PatternDetails::SignednessMismatch { mismatches } => {
                // Group by signed↔unsigned opcode pair
                let mut pair_counts: HashMap<String, usize> = HashMap::new();
                for m in mismatches {
                    let key = format!("{}↔{}", m.signed_op, m.unsigned_op);
                    *pair_counts.entry(key).or_insert(0) += 1;
                }
                let mut sorted: Vec<_> = pair_counts.into_iter().collect();
                // Tie-break on the opcode pair: see register_sort_key.
                sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                let dominant = sorted.first().map(|(k, _)| k.as_str()).unwrap_or("?");
                let one_line = format!(
                    "{} signed/unsigned mismatch(es), dominated by {}",
                    mismatches.len(),
                    dominant
                );
                let top_details: Vec<String> = sorted
                    .iter()
                    .take(3)
                    .map(|(pair, count)| format!("{}: {} instruction(s)", pair, count))
                    .collect();
                PatternSummary {
                    one_line,
                    top_details,
                    truncated: sorted.len() > 3,
                    total_items: mismatches.len(),
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

/// Extract the call target name for a `bl` instruction.
///
/// Prefers `typed_args[0]` when it's a `Symbol`-typed arg — this resolves
/// ICF-merged symbols (e.g. `merged_004ab12c`) to their canonical name.
/// Falls back to `args.trim()` when `typed_args` is absent or the first arg
/// is not a symbol (e.g. a direct branch destination).
fn bl_target_name(info: &InstructionInfo) -> Option<String> {
    // Prefer typed_args[0] if it carries a Symbol — these are populated by
    // build_instruction_info from relocation data and resolve through ICF merges.
    if let Some(typed_args) = &info.typed_args
        && let Some(super::diff::TypedArg::Symbol(sym)) = typed_args.first()
    {
        return Some(sym.clone());
    }
    // Fall back to the raw rendered args string.
    info.args.as_deref().map(|a| a.trim().to_string())
}

/// Compute the difference in function calls between target and base.
pub fn compute_call_diff(instructions: &[InstructionDiffOutput]) -> Option<CallDiffOutput> {
    let mut target_calls: HashMap<String, usize> = HashMap::new();
    let mut base_calls: HashMap<String, usize> = HashMap::new();

    for instr in instructions {
        // Check target side for bl calls
        if let Some(target) = &instr.target
            && target.opcode == "bl"
            && let Some(name) = bl_target_name(target)
            && !MERGED_FUNC_RE.is_match(&name)
        {
            *target_calls.entry(name).or_insert(0) += 1;
        }
        // Check base side for bl calls
        if let Some(base) = &instr.base
            && base.opcode == "bl"
            && let Some(name) = bl_target_name(base)
            && !MERGED_FUNC_RE.is_match(&name)
        {
            *base_calls.entry(name).or_insert(0) += 1;
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
            // Tie-break on the opcode name: see register_sort_key.
            sorted_opcodes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
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
                        PatternType::AnonymousNamespaceHash => "anon namespace hash",
                        PatternType::StaticGuardCounter => "static guard counter",
                        PatternType::DynamicCastMismatch => "dynamic_cast",
                        PatternType::DeadStoreElimination => "dead stores",
                        PatternType::PrologueMismatch => "prologue mismatch",
                        PatternType::AllocaMismatch => "alloca mismatch",
                        PatternType::ScopeCounterMismatch => "scope counter",
                        PatternType::MakeStringTemplateMismatch => "MakeString template",
                        PatternType::AddressRelocationNoise => "addr relocation",
                        PatternType::BooleanNegation => "bool negation",
                        PatternType::FloatPrecisionMismatch => "float precision",
                        PatternType::FselTernary => "fsel ternary",
                        PatternType::FloatToIntToFloat => "float-to-int-to-float",
                        PatternType::SignednessMismatch => "signed/unsigned mismatch",
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
        PatternDetails::AnonymousNamespaceHash { mismatches } => mismatches.len().min(
            instructions.iter().filter(|i| i.match_type == "diff_arg").count(),
        ),
        PatternDetails::StaticGuardCounter { guards } => guards.len().min(
            instructions.iter().filter(|i| i.match_type == "diff_arg").count(),
        ),
        PatternDetails::DynamicCastMismatch { count } => {
            instructions.iter().filter(|i| i.match_type == "insert").count().min(*count)
        }
        PatternDetails::DeadStoreElimination { count } => {
            instructions.iter().filter(|i| i.match_type == "insert").count().min(*count)
        }
        PatternDetails::PrologueMismatch { .. } => {
            instructions.iter().filter(|i| i.index < 10 && i.match_type == "diff_arg").count()
        }
        PatternDetails::AllocaMismatch { .. } => {
            instructions.iter().filter(|i| i.index < 10 && i.match_type == "diff_arg").count()
        }
        PatternDetails::ScopeCounterMismatch { count } => {
            instructions.iter().filter(|i| i.match_type == "diff_arg").count().min(*count)
        }
        PatternDetails::MakeStringTemplateMismatch { mismatches } => {
            let start_idx = instructions.first().map(|i| i.index).unwrap_or(0);
            let end_idx = instructions.last().map(|i| i.index).unwrap_or(0);
            mismatches.iter().filter(|m| m.index >= start_idx && m.index <= end_idx).count()
        }
        PatternDetails::AddressRelocationNoise { info } => {
            // Count diff_arg lis/addi in range as proxy
            instructions
                .iter()
                .filter(|i| {
                    i.match_type == "diff_arg"
                        && i.target
                            .as_ref()
                            .is_some_and(|t| matches!(t.opcode.as_str(), "lis" | "addi" | "ori"))
                })
                .count()
                .min(info.count)
        }
        PatternDetails::BooleanNegation { count } => {
            instructions
                .iter()
                .filter(|i| {
                    i.match_type == "replace"
                        && i.target.as_ref().is_some_and(|t| {
                            matches!(t.opcode.as_str(), "subfic" | "subic" | "subic.")
                        })
                })
                .count()
                .min(*count)
        }
        PatternDetails::FloatPrecisionMismatch { mismatches } => {
            let start_idx = instructions.first().map(|i| i.index).unwrap_or(0);
            let end_idx = instructions.last().map(|i| i.index).unwrap_or(0);
            mismatches.iter().filter(|m| m.index >= start_idx && m.index <= end_idx).count()
        }
        PatternDetails::FselTernary { count } => {
            instructions
                .iter()
                .filter(|i| {
                    i.match_type == "insert"
                        && i.target.as_ref().is_some_and(|t| t.opcode == "fsel")
                })
                .count()
                .min(*count)
        }
        PatternDetails::FloatToIntToFloat { count } => {
            instructions
                .iter()
                .filter(|i| {
                    i.match_type == "insert"
                        && i.target.as_ref().is_some_and(|t| t.opcode == "fctiwz")
                })
                .count()
                .min(*count)
        }
        PatternDetails::SignednessMismatch { mismatches } => {
            let start_idx = instructions.first().map(|i| i.index).unwrap_or(0);
            let end_idx = instructions.last().map(|i| i.index).unwrap_or(0);
            mismatches.iter().filter(|m| m.index >= start_idx && m.index <= end_idx).count()
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
    /// Base has no code (unimplemented stub)
    Stub,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_url: Option<String>,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub doc_urls: Vec<String>,
}

// =============================================================================
// Pattern Documentation URLs
// =============================================================================

/// Base URL prefix for pattern documentation.
///
/// Relative to the consuming project root. Both RB3 and DC3 mirror this
/// `docs/decomp/patterns/` directory layout — but *not* the filenames or the
/// section headings inside it, which is what [`DocProject`] exists to resolve.
const DOC_BASE: &str = "docs/decomp/patterns/";

/// Which decompilation project objdiff is being run inside.
///
/// Doc URLs are emitted relative to the consuming project root, so the same
/// string has to name a file that exists *in that repo*. DC3 and RB3 diverge
/// on both counts: DC3 keeps the permuter ROI writeup in
/// `PERMUTER_ROI_ANALYSIS.md` and its compiler-floor catalogue in
/// `unfixable-compiler.md` / `at-limit-systemic.md`, RB3 uses `permuter-roi.md`
/// and `at-limit-mwcc.md`, and nearly every section heading differs. Emitting
/// one repo's string in the other is worse than emitting nothing: DC3 is MSVC
/// and RB3 is MetroWerks, so a link that happens to resolve can hand the reader
/// advice written for a different backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DocProject {
    /// dc3-decomp (MSVC / PowerPC).
    Dc3,
    /// rb3 (MetroWerks / PowerPC).
    Rb3,
    /// Not recognised — only project-independent links are emitted.
    Unknown,
}

impl DocProject {
    pub fn as_str(&self) -> &'static str {
        match self {
            DocProject::Dc3 => "dc3",
            DocProject::Rb3 => "rb3",
            DocProject::Unknown => "unknown",
        }
    }

    pub fn from_name(s: &str) -> Option<DocProject> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dc3" | "dc3-decomp" => Some(DocProject::Dc3),
            "rb3" | "rb3-decomp" => Some(DocProject::Rb3),
            "unknown" | "none" | "generic" => Some(DocProject::Unknown),
            _ => None,
        }
    }
}

/// A documentation target, named by what it *explains* rather than by where it
/// lives. The file/anchor for each project is resolved by [`doc_entry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DocLink {
    /// ICF explained as a verifiable (accept-after-checking) pattern.
    IcfVerifiable,
    /// ICF listed in the project's compiler/linker floor catalogue.
    IcfAtLimit,
    /// Bool return masking shapes.
    BoolMask,
    /// Bool materialization as a permuter lever.
    BoolMaterialization,
    /// Pre-compute references before a call clobbers the register.
    PrecomputeRefsBeforeCalls,
    /// Instruction scheduling as a source-controllable lever.
    InstructionScheduling,
    /// How a single allocation difference cascades into many register swaps.
    RegallocCascades,
    /// Local variable declaration order (a stack-slot lever).
    DeclarationOrder,
    /// `>` vs `>=` style differences.
    ComparisonStyle,
    /// Branch polarity / early-return inversion.
    BranchPolarity,
    /// `x > 0` vs `x != 0` on unsigned types.
    UnsignedZeroComparison,
    /// Operand order in commutative operations.
    CommutativeOperandOrder,
    /// Two stack offsets swapped between target and base.
    OffsetSwap,
    /// Stack slot inversion as a permuter lever.
    StackSlotInversion,
    /// Anonymous-namespace TU hash (path-derived, source-immune).
    AnonymousNamespaceHash,
    /// TU-wide function definition order driving static guard counters.
    StaticGuardCounter,
    /// Order of static symbols within a TU.
    StaticSymbolOrder,
    /// Avoiding an unnecessary `dynamic_cast`.
    DynamicCast,
    /// Dead store elimination around RAII members.
    DeadStoreElimination,
    /// The permuter ROI writeup as a whole.
    PermuterRoi,
    /// `alloca` vs the `_alloca` intrinsic.
    Alloca,
    /// Scope counter in static local names (extra braces).
    ScopeCounter,
    /// MakeString template parameter mismatches in MILO macros.
    MakeStringTemplate,
    /// Address relocation noise (linker layout artifact).
    AddressRelocationNoise,
    /// Boolean negation, subfic vs subic.
    BooleanNegation,
    /// Cast placement controlling float precision (fmul vs fmuls).
    FloatPrecision,
    /// fsel via an explicit ternary.
    FselTernary,
    /// float→int→float reconversion.
    FloatToIntToFloat,
    /// Signed vs unsigned comparison.
    SignedVsUnsignedComparison,
    /// Signedness/width type disagreements.
    SignednessWidth,
}

/// Per-project location of a [`DocLink`]. `None` means the project has no
/// document covering it — better to emit no link than a wrong one.
struct DocEntry {
    dc3: Option<&'static str>,
    rb3: Option<&'static str>,
}

/// Resolve a logical link to its per-project `file.md#anchor`.
///
/// Every string here is checked against the real repositories by
/// `scripts/check_doc_links.py`; do not edit one without re-running it.
fn doc_entry(link: DocLink) -> DocEntry {
    macro_rules! e {
        (dc3: $d:expr, rb3: $r:expr) => {
            DocEntry { dc3: Some($d), rb3: Some($r) }
        };
        (dc3: $d:expr) => {
            DocEntry { dc3: Some($d), rb3: None }
        };
        (both: $b:expr) => {
            DocEntry { dc3: Some($b), rb3: Some($b) }
        };
    }
    match link {
        DocLink::IcfVerifiable => e!(
            dc3: "verifiable-icf.md#linker-merged-icf",
            rb3: "verifiable-icf.md#linker_merged-functions"
        ),
        DocLink::IcfAtLimit => e!(
            dc3: "at-limit-systemic.md#2-linker_merged-icf-identical-comdat-folding",
            rb3: "at-limit-mwcc.md#linker-merged-icf"
        ),
        DocLink::BoolMask => e!(
            dc3: "fixable-bool-mask.md#fixable-patterns-bool-mask",
            rb3: "fixable-bool-mask.md#fixable-bool-materialization"
        ),
        DocLink::BoolMaterialization => e!(
            dc3: "fixable-bool-mask.md#permuter-pattern",
            rb3: "permuter-roi.md#bool-materialization"
        ),
        DocLink::PrecomputeRefsBeforeCalls => e!(
            dc3: "fixable-declarations.md#pre-compute-references-before-clobbering-calls",
            rb3: "fixable-declarations.md#pre-declare-heavy-temp-before-a-function-call-to-force-callee-saved"
        ),
        DocLink::InstructionScheduling => e!(
            dc3: "PERMUTER_ROI_ANALYSIS.md#instruction-scheduling",
            rb3: "permuter-roi.md#instruction-scheduling"
        ),
        DocLink::RegallocCascades => e!(
            dc3: "fixable-liveness.md#diagnostic-order-for-a-register-swap-residual",
            rb3: "permuter-roi.md#register-allocation-cascades"
        ),
        DocLink::DeclarationOrder => e!(both: "fixable-declarations.md#variable-declaration-order"),
        DocLink::ComparisonStyle => e!(
            dc3: "fixable-comparison.md#comparison-style",
            rb3: "fixable-comparison.md#fixable-comparison-patterns"
        ),
        DocLink::BranchPolarity => e!(
            dc3: "fixable-control-flow.md#branch-polarity-steering-beqbne-blebge",
            rb3: "fixable-control-flow.md#early-return-inversion"
        ),
        DocLink::UnsignedZeroComparison => e!(
            dc3: "fixable-comparison.md#unsigned-zero-comparison",
            rb3: "fixable-casting.md#unsigned-int-diff-over-int-diff-for-cmplw"
        ),
        DocLink::CommutativeOperandOrder => e!(
            dc3: "fixable-operators.md#commutative-operand-order",
            rb3: "fixable-operators.md#operand-order-in-commutative-operations"
        ),
        DocLink::OffsetSwap => e!(
            dc3: "fixable-declarations.md#offset-swap",
            rb3: "at-limit-mwcc.md#stack-slot-inversion-offset_swap-on-r1"
        ),
        DocLink::StackSlotInversion => e!(
            dc3: "fixable-liveness.md#lever-4-scope-a-declaration-into-the-block-that-uses-it-stack-lever-not-a-register-lever",
            rb3: "permuter-roi.md#stack-slot-inversion"
        ),
        DocLink::AnonymousNamespaceHash => e!(
            dc3: "unfixable-compiler.md#anonymous-namespace-hash-mismatch",
            rb3: "at-limit-mwcc.md#anonymous-namespace-hash"
        ),
        DocLink::StaticGuardCounter => e!(
            dc3: "fixable-declarations.md#function-definition-order-tu-wide-static-guard-counters",
            rb3: "fixable-declarations.md#function-definition-order-affects-string-pool"
        ),
        DocLink::StaticSymbolOrder => e!(dc3: "fixable-declarations.md#static-symbol-order"),
        DocLink::DynamicCast => {
            e!(dc3: "fixable-casting.md#avoid-unnecessary-dynamic_cast-getobj-vs-objt")
        }
        DocLink::DeadStoreElimination => e!(
            dc3: "unfixable-compiler.md#dead-store-elimination-destructor-merging",
            rb3: "at-limit-mwcc.md#dead-store-elimination"
        ),
        DocLink::PermuterRoi => e!(dc3: "PERMUTER_ROI_ANALYSIS.md", rb3: "permuter-roi.md"),
        DocLink::Alloca => {
            e!(dc3: "fixable-declarations.md#alloca-vs-_alloca-intrinsic-stack-allocation")
        }
        DocLink::ScopeCounter => {
            e!(dc3: "fixable-declarations.md#braced-vs-braceless-if-scope-counter")
        }
        DocLink::MakeStringTemplate => e!(
            dc3: "fixable-casting.md#makestring-template-type-mismatch-milo-macro-arguments",
            rb3: "fixable-operators.md#milo_warnmilo_log-argument-order-affects-makestring-template"
        ),
        DocLink::AddressRelocationNoise => e!(
            dc3: "unfixable-compiler.md#address-relocation-noise",
            rb3: "at-limit-mwcc.md#address-relocation-noise"
        ),
        DocLink::BooleanNegation => e!(
            dc3: "unfixable-compiler.md#boolean-negation-subfic-vs-subic",
            rb3: "at-limit-mwcc.md#boolean-negation-subfic-vs-subic"
        ),
        DocLink::FloatPrecision => e!(
            dc3: "fixable-casting.md#cast-placement-controls-fmul-vs-fmuls",
            rb3: "fixable-casting.md#floatx-vs-floatlong-longx"
        ),
        DocLink::FselTernary => e!(
            dc3: "fixable-fsel-fma.md#fsel-via-explicit-ternary-subtractionnegation",
            rb3: "fixable-fsel-fma.md#fixable-float-scheduling-fsel-fma"
        ),
        DocLink::FloatToIntToFloat => e!(
            dc3: "fixable-casting.md#float-to-int-to-float-reconversion",
            rb3: "fixable-casting.md#tfloatfloor-forces-frsp-before-fctiwz"
        ),
        DocLink::SignedVsUnsignedComparison => e!(
            dc3: "fixable-comparison.md#signedunsigned-cast",
            rb3: "fixable-casting.md#unsigned-int-diff-over-int-diff-for-cmplw"
        ),
        DocLink::SignednessWidth => e!(
            dc3: "fixable-casting.md#sizeof-signedness",
            rb3: "fixable-casting.md#int-cast-for-signed-arithmetic-shift"
        ),
    }
}

/// Every [`DocLink`], for exhaustive checking.
pub const ALL_DOC_LINKS: &[DocLink] = &[
    DocLink::IcfVerifiable,
    DocLink::IcfAtLimit,
    DocLink::BoolMask,
    DocLink::BoolMaterialization,
    DocLink::PrecomputeRefsBeforeCalls,
    DocLink::InstructionScheduling,
    DocLink::RegallocCascades,
    DocLink::DeclarationOrder,
    DocLink::ComparisonStyle,
    DocLink::BranchPolarity,
    DocLink::UnsignedZeroComparison,
    DocLink::CommutativeOperandOrder,
    DocLink::OffsetSwap,
    DocLink::StackSlotInversion,
    DocLink::AnonymousNamespaceHash,
    DocLink::StaticGuardCounter,
    DocLink::StaticSymbolOrder,
    DocLink::DynamicCast,
    DocLink::DeadStoreElimination,
    DocLink::PermuterRoi,
    DocLink::Alloca,
    DocLink::ScopeCounter,
    DocLink::MakeStringTemplate,
    DocLink::AddressRelocationNoise,
    DocLink::BooleanNegation,
    DocLink::FloatPrecision,
    DocLink::FselTernary,
    DocLink::FloatToIntToFloat,
    DocLink::SignedVsUnsignedComparison,
    DocLink::SignednessWidth,
];

/// Every [`PatternType`], for exhaustive checking.
pub const ALL_PATTERN_TYPES: &[PatternType] = &[
    PatternType::LinkerMerged,
    PatternType::BoolMask,
    PatternType::RegisterSwap,
    PatternType::ComparisonStyle,
    PatternType::ControlFlow,
    PatternType::CommutativeOpOrder,
    PatternType::OffsetSwap,
    PatternType::AnonymousNamespaceHash,
    PatternType::StaticGuardCounter,
    PatternType::DynamicCastMismatch,
    PatternType::DeadStoreElimination,
    PatternType::PrologueMismatch,
    PatternType::AllocaMismatch,
    PatternType::ScopeCounterMismatch,
    PatternType::MakeStringTemplateMismatch,
    PatternType::AddressRelocationNoise,
    PatternType::BooleanNegation,
    PatternType::FloatPrecisionMismatch,
    PatternType::FselTernary,
    PatternType::FloatToIntToFloat,
    PatternType::SignednessMismatch,
];

/// Resolve a logical link to a project-relative URL.
///
/// For an unrecognised project this degrades to the *intersection*: a link is
/// emitted only when both known projects put the topic in the same file, and
/// then without the anchor unless the anchors also agree. Anything
/// project-specific is dropped rather than guessed.
pub fn doc_url_for(project: DocProject, link: DocLink) -> Option<String> {
    let entry = doc_entry(link);
    let path = match project {
        DocProject::Dc3 => entry.dc3?,
        DocProject::Rb3 => entry.rb3?,
        DocProject::Unknown => {
            let (dc3, rb3) = (entry.dc3?, entry.rb3?);
            if dc3 == rb3 {
                dc3
            } else {
                let dc3_file = dc3.split('#').next().unwrap_or(dc3);
                let rb3_file = rb3.split('#').next().unwrap_or(rb3);
                if dc3_file != rb3_file {
                    return None;
                }
                dc3_file
            }
        }
    };
    Some(format!("{}{}", DOC_BASE, path))
}

/// Detected project identity, resolved once per process.
static DOC_PROJECT: std::sync::OnceLock<DocProject> = std::sync::OnceLock::new();

/// Environment override, mostly for tests and for repos that have not been
/// taught to objdiff yet. Values: `dc3`, `rb3`, `unknown`.
const DOC_PROJECT_ENV: &str = "OBJDIFF_DOC_PROJECT";

/// Identify the project from the docs tree at `root`.
///
/// Detection is by marker filename rather than by repo name or git remote:
/// the thing we actually need to know is which filenames exist, and probing
/// that answers it directly (and self-heals if a repo is moved or renamed).
pub fn detect_doc_project_at(root: &std::path::Path) -> Option<DocProject> {
    let dir = root.join("docs").join("decomp").join("patterns");
    if !dir.is_dir() {
        return None;
    }
    if dir.join("PERMUTER_ROI_ANALYSIS.md").is_file() {
        return Some(DocProject::Dc3);
    }
    if dir.join("at-limit-mwcc.md").is_file() || dir.join("permuter-roi.md").is_file() {
        return Some(DocProject::Rb3);
    }
    Some(DocProject::Unknown)
}

/// Walk up from `start` looking for a recognisable docs tree.
pub fn detect_doc_project_from(start: &std::path::Path) -> DocProject {
    let mut cur = Some(start);
    for _ in 0..12 {
        let Some(dir) = cur else { break };
        if let Some(project) = detect_doc_project_at(dir) {
            return project;
        }
        cur = dir.parent();
    }
    DocProject::Unknown
}

fn doc_project_from_env() -> Option<DocProject> {
    std::env::var(DOC_PROJECT_ENV).ok().and_then(|v| DocProject::from_name(&v))
}

/// Pin the project identity for this process. Called once from the CLI entry
/// points with `--project` if given; a later call is ignored.
pub fn init_doc_project(project_dir: Option<&std::path::Path>) {
    let resolved = doc_project_from_env().unwrap_or_else(|| match project_dir {
        Some(dir) => detect_doc_project_from(dir),
        // No --project: fall back to the same working-directory walk the lazy
        // accessor uses, so `-1 a.obj -2 b.obj` inside a project still works.
        None => std::env::current_dir()
            .map(|dir| detect_doc_project_from(&dir))
            .unwrap_or(DocProject::Unknown),
    });
    let _ = DOC_PROJECT.set(resolved);
}

/// The project identity in effect. Falls back to detection from the current
/// working directory, so wrappers that `cd` into the project (ninja, the
/// orchestrator, the skills) get correct links without passing anything.
pub fn doc_project() -> DocProject {
    *DOC_PROJECT.get_or_init(|| {
        doc_project_from_env().unwrap_or_else(|| {
            std::env::current_dir()
                .map(|dir| detect_doc_project_from(&dir))
                .unwrap_or(DocProject::Unknown)
        })
    })
}

/// Resolve a logical link against the detected project.
fn doc_url(link: DocLink) -> Option<String> { doc_url_for(doc_project(), link) }

// =============================================================================
// `objdiff-cli doc-links` — dump the emitted URLs for external verification
// =============================================================================

#[derive(argp::FromArgs, PartialEq, Debug)]
#[argp(subcommand, name = "doc-links")]
/// Print the documentation URLs emitted for each pattern, for link checking.
pub struct DocLinksArgs {
    #[argp(option, short = 'P')]
    /// Project identity: dc3, rb3, unknown, or auto (default: auto-detect)
    project: Option<String>,
    #[argp(option, short = 'f')]
    /// Output format: text (default) or json
    format: Option<String>,
}

/// Everything `doc-links` knows, in a shape a checker can consume.
#[derive(Serialize)]
struct DocLinksOutput {
    project: &'static str,
    /// Every logical link that resolves for this project.
    links: Vec<DocLinkEntryOut>,
    /// Per-pattern URL lists, in emission order. The first entry is the only
    /// one objdiff renders inline, so its stability is contractual.
    patterns: Vec<PatternLinksOut>,
}

#[derive(Serialize)]
struct DocLinkEntryOut {
    link: DocLink,
    url: Option<String>,
}

#[derive(Serialize)]
struct PatternLinksOut {
    pattern: &'static str,
    urls: Vec<String>,
}

pub fn run_doc_links(args: DocLinksArgs) -> anyhow::Result<()> {
    let project = match args.project.as_deref() {
        None | Some("auto") => doc_project(),
        Some(name) => DocProject::from_name(name)
            .ok_or_else(|| anyhow::anyhow!("unknown project '{name}' (dc3, rb3, unknown, auto)"))?,
    };
    let out = DocLinksOutput {
        project: project.as_str(),
        links: ALL_DOC_LINKS
            .iter()
            .map(|&link| DocLinkEntryOut { link, url: doc_url_for(project, link) })
            .collect(),
        patterns: ALL_PATTERN_TYPES
            .iter()
            .map(|&pattern| PatternLinksOut {
                pattern: pattern.as_str(),
                urls: pattern_doc_urls_for(project, pattern),
            })
            .collect(),
    };
    match args.format.as_deref() {
        Some("json") => println!("{}", serde_json::to_string_pretty(&out)?),
        None | Some("text") => {
            println!("project: {}", out.project);
            for entry in &out.links {
                println!("  {:?} = {}", entry.link, entry.url.as_deref().unwrap_or("(none)"));
            }
            for pattern in &out.patterns {
                println!("  {} -> {}", pattern.pattern, pattern.urls.join(", "));
            }
        }
        Some(other) => anyhow::bail!("unknown format '{other}' (text, json)"),
    }
    Ok(())
}

/// Return documentation URLs for a pattern type.
///
/// The permuter is the first-line recommendation for anything classified as
/// `PermuterClass` — see `permuter-roi.md`. Linker/path-derived artifacts
/// (anon-namespace hash, address-relocation noise, ICF) live in
/// `at-limit-mwcc.md` (RB3) / `at-limit-msvc.md` (DC3) — these are genuinely
/// source-immune and the only correct action is to accept the match.
pub fn pattern_doc_links(pattern: PatternType) -> &'static [DocLink] {
    match pattern {
        PatternType::LinkerMerged => &[DocLink::IcfVerifiable, DocLink::IcfAtLimit],
        PatternType::BoolMask => &[DocLink::BoolMask, DocLink::BoolMaterialization],
        // REGISTER_SWAP reads as "the allocator picked different registers",
        // which invites a declaration-order edit. Measured on MSVC/PowerPC
        // (n=3, see docs/research/register-swap-symptom-not-cause.md) that is
        // the wrong first move: the swaps were symptoms of liveness and
        // scheduling differences, and flipped wholesale once the cause was
        // fixed. Liveness-shaping docs therefore come first; declaration order
        // is kept last because it is the lever for OFFSET_SWAP (stack slots),
        // which co-occurs with regswaps often enough to still be worth listing.
        // FILENAME/ANCHOR DIVERGENCE is handled by DocLink, not by picking a
        // winner: DC3 keeps the scheduling section in `PERMUTER_ROI_ANALYSIS.md`
        // and the regswap diagnostic order in `fixable-liveness.md`, RB3 keeps
        // both in `permuter-roi.md`, and the anchors differ. See
        // dc3-decomp `docs/decomp/patterns/INDEX.md` for the anchor contract
        // covering the first entry here.
        PatternType::RegisterSwap => &[
            DocLink::PrecomputeRefsBeforeCalls,
            DocLink::InstructionScheduling,
            DocLink::RegallocCascades,
            DocLink::DeclarationOrder,
        ],
        PatternType::ComparisonStyle => &[DocLink::ComparisonStyle],
        PatternType::ControlFlow => &[DocLink::BranchPolarity, DocLink::UnsignedZeroComparison],
        PatternType::CommutativeOpOrder => &[DocLink::CommutativeOperandOrder],
        PatternType::OffsetSwap => &[DocLink::OffsetSwap, DocLink::StackSlotInversion],
        PatternType::AnonymousNamespaceHash => &[DocLink::AnonymousNamespaceHash],
        PatternType::StaticGuardCounter => {
            &[DocLink::StaticGuardCounter, DocLink::StaticSymbolOrder]
        }
        PatternType::DynamicCastMismatch => &[DocLink::DynamicCast],
        PatternType::DeadStoreElimination => {
            &[DocLink::DeadStoreElimination, DocLink::PermuterRoi]
        }
        // A prologue that saves one more/fewer callee-saved register than the
        // target is a live-range budget difference, not a declaration-order
        // one: in the measured case (RndText::FitTextScroll, MSVC/PPC) our
        // build reloaded a member at a call site where the target held it in a
        // callee-saved register, costing exactly one extra save slot
        // (__savegprlr_23 vs _22) and cascading into ~40 register swaps.
        PatternType::PrologueMismatch => &[
            DocLink::PrecomputeRefsBeforeCalls,
            DocLink::RegallocCascades,
            DocLink::DeclarationOrder,
        ],
        PatternType::AllocaMismatch => &[DocLink::Alloca],
        PatternType::ScopeCounterMismatch => &[DocLink::ScopeCounter],
        PatternType::MakeStringTemplateMismatch => &[DocLink::MakeStringTemplate],
        PatternType::AddressRelocationNoise => &[DocLink::AddressRelocationNoise],
        PatternType::BooleanNegation => &[DocLink::BooleanNegation, DocLink::PermuterRoi],
        PatternType::FloatPrecisionMismatch => &[DocLink::FloatPrecision],
        PatternType::FselTernary => &[DocLink::FselTernary],
        PatternType::FloatToIntToFloat => &[DocLink::FloatToIntToFloat],
        PatternType::SignednessMismatch => {
            &[DocLink::SignedVsUnsignedComparison, DocLink::SignednessWidth]
        }
    }
}

/// Documentation URLs for a pattern, resolved for an explicit project.
pub fn pattern_doc_urls_for(project: DocProject, pattern: PatternType) -> Vec<String> {
    pattern_doc_links(pattern).iter().filter_map(|&l| doc_url_for(project, l)).collect()
}

/// Documentation URLs for a pattern, resolved against the detected project.
pub fn pattern_doc_urls(pattern: PatternType) -> Vec<String> {
    pattern_doc_urls_for(doc_project(), pattern)
}

// =============================================================================
// Pattern Detection Functions
// =============================================================================

/// Detect calls to linker-merged functions.
///
/// Looks for `diff_arg` instructions where the opcode is `bl` and the
/// target argument matches the merged function regex.
/// Extract the MSVC template base name from a mangled symbol.
/// E.g., `?Foo@?$ObjRefConcrete@VRndDrawable@@...` → `?$ObjRefConcrete`
/// Returns the portion before the first template argument.
fn msvc_template_base(mangled: &str) -> Option<&str> {
    // Find `?$` which starts a template name in MSVC mangling
    let idx = mangled.find("?$")?;
    // Find the next `@` after `?$` which ends the template name
    let after = &mangled[idx + 2..];
    let end = after.find('@')?;
    Some(&mangled[idx..idx + 2 + end])
}

pub fn detect_linker_merged(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut merged_calls: HashMap<String, usize> = HashMap::new();
    let mut icf_template_count = 0usize;

    for instr in instructions {
        if instr.match_type != "diff_arg" {
            continue;
        }

        let (Some(target), Some(base)) = (&instr.target, &instr.base) else { continue };

        // Only look at branch instructions (bl = call, b = tail call)
        if target.opcode != "bl" && target.opcode != "b" {
            continue;
        }

        let t_args = target.args.as_deref().unwrap_or("").trim();
        let b_args = base.args.as_deref().unwrap_or("").trim();

        // Check explicit merged_*/OnlyReturns/??_[EG] patterns
        if MERGED_FUNC_RE.is_match(t_args) {
            *merged_calls.entry(t_args.to_string()).or_insert(0) += 1;
            continue;
        }

        // Check ICF merging: both sides call different symbols.
        if t_args != b_args && !t_args.is_empty() && !b_args.is_empty() {
            // Check if same template with different type args
            if let (Some(t_base), Some(b_base)) =
                (msvc_template_base(t_args), msvc_template_base(b_args))
                && t_base == b_base
            {
                icf_template_count += 1;
                *merged_calls.entry(format!("ICF:{} (template merge)", t_base)).or_insert(0) += 1;
                continue;
            }

            // General ICF: bl/b to completely different symbols.
            // At least one side must be a proper function name (not a label
            // or number). This is likely ICF merging of unrelated functions
            // with identical machine code.
            let t_is_func = t_args.starts_with('?')
                || t_args.starts_with('_')
                || t_args.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
            let b_is_func = b_args.starts_with('?')
                || b_args.starts_with('_')
                || b_args.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
            if t_is_func && b_is_func {
                icf_template_count += 1;
                *merged_calls
                    .entry(format!("ICF:{} (cross-function merge)", b_args))
                    .or_insert(0) += 1;
            }
        }
    }

    if merged_calls.is_empty() {
        return None;
    }

    let total_count: usize = merged_calls.values().sum();

    // Count descending, then by name. The count key alone was NOT enough for
    // "consistent output", which is what the comment here used to claim: the
    // vec is built by draining a `HashMap`, `sort_by_key` is stable, so equal
    // counts kept the hasher's order — and `std::collections::HashMap` reseeds
    // per instance. Merged-call counts are overwhelmingly 1, so ties are the
    // common case, not the corner: on a 1500-symbol rb3-xenon batch this list
    // reordered on 16 of the 19 rows that differed between two runs of one
    // binary, and `summarize()` publishes its head into the verdict text.
    let mut merged_functions: Vec<MergedFunctionCount> =
        merged_calls.into_iter().map(|(name, count)| MergedFunctionCount { name, count }).collect();
    merged_functions.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));

    Some(Pattern {
        pattern: PatternType::LinkerMerged,
        confidence: if icf_template_count > 0 {
            Confidence::Medium
        } else {
            Confidence::High
        },
        instruction_count: total_count,
        fixability: Fixability::RarelyHandFixable,
        details: PatternDetails::MergedFunctions { merged_functions },
        doc_urls: pattern_doc_urls(PatternType::LinkerMerged),
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
        fixability: Fixability::PermuterClass,
        details: PatternDetails::BoolMask { bit_positions },
        doc_urls: pattern_doc_urls(PatternType::BoolMask),
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
    // Count descending, then by register so equal counts do not inherit the
    // HashMap's per-instance iteration order. `summarize()` reports the head of
    // this list as "dominated by", and a diff report that renames its dominant
    // pair between runs cannot be used to A/B a source edit.
    swaps.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| register_sort_key(&a.target_reg).cmp(&register_sort_key(&b.target_reg)))
            .then_with(|| register_sort_key(&a.base_reg).cmp(&register_sort_key(&b.base_reg)))
    });

    // Classify fixability based on register types. This split says which CAUSE
    // to look for, not how hard the fix is — in both classes the swap set is a
    // symptom that flips wholesale once the cause is addressed.
    //
    // The split is a first-principles discriminator, not just an empirical
    // heuristic: by ABI a volatile register cannot hold a value across a call,
    // so a *volatile* swap is never itself a disagreement about what stays live
    // across a call. It can still be the downstream shadow of one elsewhere in
    // the function — which is exactly why the mixed case points at liveness.
    //
    // - Pure callee-saved swaps (r13-r31, f14-f31): MaybeFixable — the cause is
    //   a live-range difference across a call (a value the target keeps in a
    //   callee-saved register that our build reloads, or vice versa).
    //   Shortening or extending that live range is the lever.
    // - Pure volatile swaps (r0-r12, f0-f13): RarelyHandFixable — rule liveness
    //   out and look at instruction scheduling and operand order. Reordering
    //   the source so a producer lands before its consumer, or flipping a
    //   commutative/compare operand order, has moved these by hand; the
    //   permuter's body-restructuring patterns also help. Try both.
    // - Mixed: MaybeFixable — the callee-saved half carries the cause and the
    //   volatile half usually follows it. Measured: RndText::FitTextScroll
    //   showed r27<->r28, r22<->r23 (callee-saved) and f12<->f13 (volatile)
    //   simultaneously, all from ONE member reload at a call site.
    //
    // Declaration reorder is NOT the first lever for either class; it is the
    // lever for stack-slot (OFFSET_SWAP) mismatches. Measured n=3 on
    // MSVC/PowerPC — see docs/research/register-swap-symptom-not-cause.md.
    let has_callee_saved_swap = swaps
        .iter()
        .any(|s| is_callee_saved_register(&s.target_reg) && is_callee_saved_register(&s.base_reg));
    let has_volatile_swap = swaps
        .iter()
        .any(|s| !is_callee_saved_register(&s.target_reg) || !is_callee_saved_register(&s.base_reg));

    let fixability = if has_volatile_swap && !has_callee_saved_swap {
        // Pure volatile: scheduling-driven, not declaration-driven. The
        // permuter still has a shot via body restructurings; flag it so the
        // verdict text recommends a sweep instead of "accept".
        Fixability::RarelyHandFixable
    } else {
        // Pure callee-saved or mixed: declaration reorder is the lever.
        Fixability::MaybeFixable
    };

    Some(Pattern {
        pattern: PatternType::RegisterSwap,
        confidence,
        instruction_count: total,
        fixability,
        details: PatternDetails::RegisterSwap { swaps },
        doc_urls: pattern_doc_urls(PatternType::RegisterSwap),
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
        doc_urls: pattern_doc_urls(PatternType::ComparisonStyle),
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
        doc_urls: pattern_doc_urls(PatternType::ControlFlow),
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
        doc_urls: pattern_doc_urls(PatternType::CommutativeOpOrder),
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
        doc_urls: pattern_doc_urls(PatternType::OffsetSwap),
    })
}

// =============================================================================
// New Pattern Detection Functions (Phase 3)
// =============================================================================

/// Regex for anonymous namespace TU hash symbols (`?A0xHEXHASH@@`)
static ANON_NS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\?A0x([0-9a-fA-F]+)@@").unwrap());

/// Regex for static guard symbols (`$S\d+`)
static STATIC_GUARD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$S(\d+)").unwrap());

/// Regex for prologue save calls (`__savegprlr_(\d+)` or `__savefpr_(\d+)`)
static SAVE_REG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"__(savegprlr|savefpr)_(\d+)").unwrap());

/// Regex for `stwu r1, -N(r1)` — extracts the positive frame size N.
/// The displacement is negative in the instruction (e.g. `-0x60`) so we
/// capture the absolute value.
static STWU_FRAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^r1, -(\d+)\(r1\)$").unwrap());

/// Detect anonymous namespace TU hash mismatches.
///
/// These appear when static functions inside anonymous namespaces have different
/// TU-hash suffixes between the target and decomp build (e.g., `?A0x7ea4e606@@` vs
/// `?A0x00000000@@`). The machine code is identical; only the relocation symbol name
/// differs. This is source-immune — the hash is derived from the TU path
/// (renaming the TU would change it, but that is rarely the right trade).
pub fn detect_anonymous_namespace_hash(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut mismatches: Vec<AnonNamespaceInfo> = Vec::new();

    for instr in instructions {
        if instr.match_type != "diff_arg" {
            continue;
        }
        let (Some(target), Some(base)) = (&instr.target, &instr.base) else { continue };
        let t_args = target.args.as_deref().unwrap_or("");
        let b_args = base.args.as_deref().unwrap_or("");

        // Find anon namespace hash in both sides
        let t_cap = ANON_NS_RE.captures(t_args);
        let b_cap = ANON_NS_RE.captures(b_args);

        match (t_cap, b_cap) {
            (Some(tc), Some(bc)) => {
                let t_hash = tc.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                let b_hash = bc.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                if t_hash != b_hash {
                    // Verify the rest of the symbol matches by replacing the hash
                    let t_normalized = ANON_NS_RE.replace_all(t_args, "?A0xNORM@@");
                    let b_normalized = ANON_NS_RE.replace_all(b_args, "?A0xNORM@@");
                    if t_normalized == b_normalized {
                        mismatches.push(AnonNamespaceInfo {
                            symbol: t_normalized.to_string(),
                            target_hash: t_hash,
                            base_hash: b_hash,
                        });
                    }
                }
            }
            (Some(tc), None) | (None, Some(tc)) => {
                // One side has anon ns, other doesn't — still flag it
                let hash = tc.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                mismatches.push(AnonNamespaceInfo {
                    symbol: t_args.to_string(),
                    target_hash: hash.clone(),
                    base_hash: "none".to_string(),
                });
            }
            _ => {}
        }
    }

    if mismatches.is_empty() {
        return None;
    }

    let count = mismatches.len();
    Some(Pattern {
        pattern: PatternType::AnonymousNamespaceHash,
        confidence: Confidence::High,
        instruction_count: count,
        fixability: Fixability::RarelyHandFixable,
        details: PatternDetails::AnonymousNamespaceHash { mismatches },
        doc_urls: pattern_doc_urls(PatternType::AnonymousNamespaceHash),
    })
}

/// Detect static guard counter (`$S#`) mismatches.
///
/// MSVC assigns `$S1`, `$S2`, ... counters to `static` local variables in TU order.
/// When function definitions are in the wrong order, the counter numbers shift.
/// Detected by: `diff_arg` on `ori` or `rlwinm.` with power-of-2 immediate values,
/// or symbol references containing `$S` with different numbers.
pub fn detect_static_guard_counter(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut guards: Vec<StaticGuardInfo> = Vec::new();

    for instr in instructions {
        if instr.match_type != "diff_arg" {
            continue;
        }
        let (Some(target), Some(base)) = (&instr.target, &instr.base) else { continue };

        // Check for $S symbol references in args
        let t_args = target.args.as_deref().unwrap_or("");
        let b_args = base.args.as_deref().unwrap_or("");

        let t_guard = STATIC_GUARD_RE.captures(t_args);
        let b_guard = STATIC_GUARD_RE.captures(b_args);

        if let (Some(tc), Some(bc)) = (&t_guard, &b_guard) {
            let t_num: i64 = tc.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
            let b_num: i64 = bc.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
            if t_num != b_num {
                guards.push(StaticGuardInfo { target_immediate: t_num, base_immediate: b_num });
                continue;
            }
        }

        // Also check for power-of-2 immediate differences in ori/rlwinm. (guard bit patterns)
        if !matches!(target.opcode.as_str(), "ori" | "rlwinm." | "rlwinm") {
            continue;
        }
        if target.opcode != base.opcode {
            continue;
        }

        // Try to find immediate values
        let t_imm = extract_last_immediate(t_args);
        let b_imm = extract_last_immediate(b_args);

        if let (Some(t_val), Some(b_val)) = (t_imm, b_imm)
            && t_val != b_val
            && t_val > 0
            && b_val > 0
            && t_val.count_ones() == 1
            && b_val.count_ones() == 1
        {
            guards.push(StaticGuardInfo {
                target_immediate: t_val as i64,
                base_immediate: b_val as i64,
            });
        }
    }

    if guards.is_empty() {
        return None;
    }

    let count = guards.len();
    Some(Pattern {
        pattern: PatternType::StaticGuardCounter,
        confidence: Confidence::Medium,
        instruction_count: count,
        fixability: Fixability::PermuterClass,
        details: PatternDetails::StaticGuardCounter { guards },
        doc_urls: pattern_doc_urls(PatternType::StaticGuardCounter),
    })
}

/// Extract the last integer immediate from an instruction's args string.
fn extract_last_immediate(args: &str) -> Option<u64> {
    // Split by comma and take the last, try to parse as u64
    let parts: Vec<&str> = args.split(',').map(|s| s.trim()).collect();
    let last = parts.last()?;
    if let Some(hex) = last.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        last.parse::<u64>().ok()
    }
}

/// Detect dynamic_cast mismatch — base calls `__dynamic_cast` but target doesn't.
///
/// The original code often uses `GetObj<T>(i)` directly rather than `DataArray::Obj<T>(i)`
/// which internally calls `dynamic_cast`. Fix: replace `DataArray::Obj<T>(i)` with `GetObj(i)`.
pub fn detect_dynamic_cast_mismatch(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut count = 0usize;

    for instr in instructions {
        if instr.match_type != "insert" {
            continue;
        }
        // insert = base has instruction that target doesn't
        let Some(base) = &instr.base else { continue };

        if base.opcode == "bl" {
            let args = base.args.as_deref().unwrap_or("");
            if args.contains("dynamic_cast") || args.contains("__dynamic_cast") {
                count += 1;
            }
        }
    }

    if count == 0 {
        return None;
    }

    Some(Pattern {
        pattern: PatternType::DynamicCastMismatch,
        confidence: Confidence::High,
        instruction_count: count,
        fixability: Fixability::LikelyFixable,
        details: PatternDetails::DynamicCastMismatch { count },
        doc_urls: pattern_doc_urls(PatternType::DynamicCastMismatch),
    })
}

/// Detect dead store elimination — base stores zero to stack slot, target doesn't.
///
/// Common with RAII wrappers (e.g., `CritSecTracker`) where the original compiler
/// would null out member pointers at scope end, but a newer/different compiler
/// recognizes these as dead stores and eliminates them.
pub fn detect_dead_store_elimination(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut count = 0usize;
    let mut i = 0;

    while i < instructions.len() {
        // Look for two consecutive inserts: li rN, 0x0 then stw rN, offset(rFP)
        if instructions[i].match_type == "insert"
            && let Some(base_i) = &instructions[i].base
            && base_i.opcode == "li"
            && base_i.args.as_deref().unwrap_or("").contains("0x0")
        {
            // Check next instruction
            if i + 1 < instructions.len()
                && instructions[i + 1].match_type == "insert"
                && let Some(base_next) = &instructions[i + 1].base
                && matches!(base_next.opcode.as_str(), "stw" | "stb" | "sth")
            {
                count += 2;
                i += 2;
                continue;
            }
        }
        i += 1;
    }

    if count == 0 {
        return None;
    }

    Some(Pattern {
        pattern: PatternType::DeadStoreElimination,
        confidence: Confidence::Medium,
        instruction_count: count,
        fixability: Fixability::RarelyHandFixable,
        details: PatternDetails::DeadStoreElimination { count },
        doc_urls: pattern_doc_urls(PatternType::DeadStoreElimination),
    })
}

/// Detect prologue register count mismatch — different `__savegprlr_N` values.
///
/// When target saves r28-r31 (`__savegprlr_28`) but base saves r29-r31
/// (`__savegprlr_29`), the target has one extra local variable forcing use
/// of an extra callee-saved register.
pub fn detect_prologue_mismatch(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    // Scan up to the first 10 instructions to collect frame sizes and find a
    // __savegprlr/__savefpr register mismatch.
    let prologue = instructions.iter().take(10).collect::<Vec<_>>();

    // Extract `stwu r1, -N(r1)` frame size from one side's instructions.
    // We prefer typed_args[1] (the signed displacement) if available, otherwise
    // fall back to parsing the raw args string.
    let extract_frame_size = |side: &InstructionInfo| -> Option<u32> {
        if side.opcode != "stwu" {
            return None;
        }
        // Try typed_args first: stwu has args [reg, displacement, base_reg]
        // The displacement is args[1] and is a negative Signed value.
        if let Some(typed_args) = &side.typed_args
            && typed_args.len() >= 2
            && let Some(v) = typed_args[1].as_i64()
            && v < 0
        {
            return Some((-v) as u32);
        }
        // Fallback: parse the raw args string "r1, -N(r1)"
        if let Some(args) = &side.args
            && let Some(cap) = STWU_FRAME_RE.captures(args.trim())
        {
            return cap.get(1).and_then(|m| m.as_str().parse().ok());
        }
        None
    };

    // Collect frame sizes from both sides of every prologue instruction.
    let mut target_frame_size: Option<u32> = None;
    let mut base_frame_size: Option<u32> = None;
    for instr in &prologue {
        if let Some(t) = &instr.target
            && target_frame_size.is_none()
        {
            target_frame_size = extract_frame_size(t);
        }
        if let Some(b) = &instr.base
            && base_frame_size.is_none()
        {
            base_frame_size = extract_frame_size(b);
        }
    }

    // Now find the __savegprlr/__savefpr register mismatch.
    for instr in &prologue {
        if instr.match_type != "diff_arg" {
            continue;
        }
        let (Some(target), Some(base)) = (&instr.target, &instr.base) else { continue };
        if target.opcode != "bl" || base.opcode != "bl" {
            continue;
        }

        let t_args = target.args.as_deref().unwrap_or("");
        let b_args = base.args.as_deref().unwrap_or("");

        let t_cap = SAVE_REG_RE.captures(t_args);
        let b_cap = SAVE_REG_RE.captures(b_args);

        if let (Some(tc), Some(bc)) = (t_cap, b_cap) {
            let t_reg: u32 = tc.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
            let b_reg: u32 = bc.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
            if t_reg != b_reg {
                return Some(Pattern {
                    pattern: PatternType::PrologueMismatch,
                    confidence: Confidence::High,
                    instruction_count: 1,
                    fixability: Fixability::RarelyHandFixable,
                    details: PatternDetails::PrologueMismatch {
                        info: PrologueMismatchInfo {
                            target_first_reg: t_reg,
                            base_first_reg: b_reg,
                            target_frame_size,
                            base_frame_size,
                        },
                    },
                    doc_urls: pattern_doc_urls(PatternType::PrologueMismatch),
                });
            }
        }
    }

    None
}

/// Detect `alloca` vs `_alloca` mismatch.
///
/// One side calls `_RtlCheckStack12` (intrinsic `_alloca` with stack probe),
/// the other calls the CRT `alloca` wrapper. Fix: change `alloca(...)` to `_alloca(...)`.
pub fn detect_alloca_mismatch(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut target_uses_intrinsic = false;
    let mut found = false;

    // Check prologue instructions for the pattern
    for instr in instructions.iter().take(20) {
        if instr.match_type != "diff_arg" {
            continue;
        }
        let (Some(target), Some(base)) = (&instr.target, &instr.base) else { continue };
        if target.opcode != "bl" || base.opcode != "bl" {
            continue;
        }

        let t_args = target.args.as_deref().unwrap_or("");
        let b_args = base.args.as_deref().unwrap_or("");

        let t_has_intrinsic =
            t_args.contains("_RtlCheckStack") || t_args.contains("RtlCheckStack");
        let b_has_intrinsic =
            b_args.contains("_RtlCheckStack") || b_args.contains("RtlCheckStack");
        let t_has_crt =
            t_args == "alloca" || t_args.ends_with("/alloca") || t_args.contains("alloca");
        let b_has_crt =
            b_args == "alloca" || b_args.ends_with("/alloca") || b_args.contains("alloca");

        if (t_has_intrinsic && b_has_crt) || (t_has_crt && b_has_intrinsic) {
            target_uses_intrinsic = t_has_intrinsic;
            found = true;
            break;
        }
    }

    if !found {
        return None;
    }

    Some(Pattern {
        pattern: PatternType::AllocaMismatch,
        confidence: Confidence::High,
        instruction_count: 1,
        fixability: Fixability::LikelyFixable,
        details: PatternDetails::AllocaMismatch { target_uses_intrinsic },
        doc_urls: pattern_doc_urls(PatternType::AllocaMismatch),
    })
}

/// Detect scope counter `?N?` mismatch in static local names.
///
/// MSVC numbers static locals by scope depth. Extra `{}` blocks increment the counter.
/// Detected when both sides reference the same static but with different `?N?` numbers.
pub fn detect_scope_counter_mismatch(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    static SCOPE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\?(\d+)\?").unwrap());

    let mut count = 0usize;

    for instr in instructions {
        if instr.match_type != "diff_arg" {
            continue;
        }
        let (Some(target), Some(base)) = (&instr.target, &instr.base) else { continue };
        let t_args = target.args.as_deref().unwrap_or("");
        let b_args = base.args.as_deref().unwrap_or("");

        let t_cap = SCOPE_RE.captures(t_args);
        let b_cap = SCOPE_RE.captures(b_args);

        if let (Some(tc), Some(bc)) = (t_cap, b_cap) {
            let t_num = tc.get(1).map(|m| m.as_str()).unwrap_or("");
            let b_num = bc.get(1).map(|m| m.as_str()).unwrap_or("");
            if t_num != b_num {
                // Verify rest of symbol matches by normalizing scope number
                let t_norm = SCOPE_RE.replace_all(t_args, "?N?");
                let b_norm = SCOPE_RE.replace_all(b_args, "?N?");
                if t_norm == b_norm {
                    count += 1;
                }
            }
        }
    }

    if count == 0 {
        return None;
    }

    Some(Pattern {
        pattern: PatternType::ScopeCounterMismatch,
        confidence: Confidence::High,
        instruction_count: count,
        fixability: Fixability::LikelyFixable,
        details: PatternDetails::ScopeCounterMismatch { count },
        doc_urls: pattern_doc_urls(PatternType::ScopeCounterMismatch),
    })
}

// =============================================================================
// New Pattern Detection Functions (Phase 4)
// =============================================================================

/// Regex for MakeString template calls (`??$MakeString@...`)
static MAKESTRING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\?\?\$MakeString@(.+)$").unwrap());

/// Regex for char[N] dimension in mangled template args (D followed by digits)
static CHAR_ARRAY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"D(0[A-P]+)@").unwrap());

/// Detect MakeString template parameter mismatches.
///
/// When MILO macros (MILO_ASSERT, etc.) receive arguments of different types
/// between target and decomp (e.g., `const char*` vs `Symbol`), the mangled
/// `MakeString<>` template instantiation differs. This manifests as `diff_arg`
/// on `bl` where both call `??$MakeString@` but with different template params.
///
/// Sub-classifies as:
/// - Type: different parameter types (LIKELY_FIXABLE: add .Str())
/// - FileLength: only char[N] dimension differs (SOURCE-IMMUNE: __FILE__ build env)
/// - Mixed: both differ
pub fn detect_makestring_template_mismatch(
    instructions: &[InstructionDiffOutput],
) -> Option<Pattern> {
    let mut mismatches: Vec<MakeStringMismatchInfo> = Vec::new();

    for instr in instructions {
        if instr.match_type != "diff_arg" {
            continue;
        }
        let (Some(target), Some(base)) = (&instr.target, &instr.base) else { continue };
        if target.opcode != "bl" || base.opcode != "bl" {
            continue;
        }

        let t_args = target.args.as_deref().unwrap_or("");
        let b_args = base.args.as_deref().unwrap_or("");

        let t_cap = MAKESTRING_RE.captures(t_args);
        let b_cap = MAKESTRING_RE.captures(b_args);

        if let (Some(tc), Some(bc)) = (t_cap, b_cap) {
            let t_template = tc.get(1).map(|m| m.as_str()).unwrap_or("");
            let b_template = bc.get(1).map(|m| m.as_str()).unwrap_or("");

            if t_template == b_template {
                continue;
            }

            // Classify: strip char[N] dimensions and compare the rest
            let t_no_char = CHAR_ARRAY_RE.replace_all(t_template, "D_N_@");
            let b_no_char = CHAR_ARRAY_RE.replace_all(b_template, "D_N_@");

            let char_differs = t_template != b_template
                && CHAR_ARRAY_RE.is_match(t_template)
                && CHAR_ARRAY_RE.is_match(b_template);
            let types_differ = t_no_char != b_no_char;

            let sub_type = match (types_differ, char_differs) {
                (true, true) => MakeStringMismatchSubType::Mixed,
                (true, false) => MakeStringMismatchSubType::Type,
                (false, true) => MakeStringMismatchSubType::FileLength,
                (false, false) => MakeStringMismatchSubType::FileLength, // only char dims differ
            };

            mismatches.push(MakeStringMismatchInfo {
                index: instr.index,
                target_template: t_template.to_string(),
                base_template: b_template.to_string(),
                sub_type,
            });
        }
    }

    if mismatches.is_empty() {
        return None;
    }

    let count = mismatches.len();

    // Fixability depends on sub-types
    let has_type = mismatches
        .iter()
        .any(|m| matches!(m.sub_type, MakeStringMismatchSubType::Type));
    let all_file_length = mismatches
        .iter()
        .all(|m| matches!(m.sub_type, MakeStringMismatchSubType::FileLength));
    let fixability = if all_file_length {
        Fixability::RarelyHandFixable
    } else if has_type {
        Fixability::LikelyFixable
    } else {
        Fixability::MaybeFixable
    };

    Some(Pattern {
        pattern: PatternType::MakeStringTemplateMismatch,
        confidence: Confidence::High,
        instruction_count: count,
        fixability,
        details: PatternDetails::MakeStringTemplateMismatch { mismatches },
        doc_urls: pattern_doc_urls(PatternType::MakeStringTemplateMismatch),
    })
}

/// Detect address relocation noise.
///
/// Detect CRT save/restore function suffix differences.
///
/// The compiler emits `bl __savegprlr` (or `b __restgprlr`) with different
/// suffixes depending on how many callee-saved registers are used. E.g.,
/// `__savegprlr_14` vs `__savegprlr_18`. These fall-through CRT functions
/// are functionally equivalent — the difference is just which entry point
/// in the save/restore chain is used. This is a prologue/epilogue convention
/// shift — the source-permuter's `prologue_pressure` family (and equivalents)
/// can adjust callee-saved usage; otherwise treat as cosmetic.
fn is_crt_save_restore_diff(target: &InstructionInfo, base: &InstructionInfo) -> bool {
    static CRT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^__(save|rest)(gpr|fpr|vmx)(lr)?(_\d+)?$").unwrap()
    });

    let t_args = target.args.as_deref().unwrap_or("");
    let b_args = base.args.as_deref().unwrap_or("");

    if t_args == b_args {
        return false;
    }

    CRT_RE.is_match(t_args.trim()) && CRT_RE.is_match(b_args.trim())
}

/// When the decomp binary has different symbol addresses than the target
/// (due to link-time layout differences), `lis`/`addi`/`ori` pairs that
/// load absolute addresses will have different immediate values even though
/// they reference the same logical symbol. These show up as `diff_arg` with
/// the same opcode but different immediates.
/// Check if two instructions both reference the same symbol via typed_args,
/// or if one side has a raw address label (`lbl_XXXXXXXX`) referencing the
/// same underlying data as the other side's proper symbol name.
/// Returns true if the diff is purely due to different relocation addresses
/// (address relocation noise) rather than genuinely different code.
fn has_same_symbol_reloc(target: &InstructionInfo, base: &InstructionInfo) -> bool {
    let (Some(t_args), Some(b_args)) = (&target.typed_args, &base.typed_args) else {
        return false;
    };

    // Find Symbol args on each side
    let t_syms: Vec<&str> = t_args
        .iter()
        .filter_map(|a| match a {
            super::diff::TypedArg::Symbol(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    let b_syms: Vec<&str> = b_args
        .iter()
        .filter_map(|a| match a {
            super::diff::TypedArg::Symbol(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();

    if t_syms.is_empty() || b_syms.is_empty() {
        return false;
    }

    // Case 1: Both sides have the same symbol name
    if t_syms == b_syms {
        return true;
    }

    // Case 2: One side has lbl_XXXXXXXX (raw address from split XEX) and the
    // other has a proper symbol name — this is address relocation noise since
    // the target .obj lacks symbol names for static/local data.
    for (t, b) in t_syms.iter().zip(b_syms.iter()) {
        if t.starts_with("lbl_") || b.starts_with("lbl_") {
            return true;
        }
    }

    // Case 3: ICF const-qualifier or access-specifier difference in mangled name.
    // MSVC encodes access as: @@QAA (non-const) vs @@QBA (const), @@IAA (protected)
    // vs @@IBA (protected const), etc. When the linker merges const and non-const
    // versions via ICF, the bl target differs only in this qualifier character.
    // Normalize A/B (non-const/const) at these positions and compare.
    static CONST_QUAL_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"@@[QI]([AB])").unwrap());
    for (t, b) in t_syms.iter().zip(b_syms.iter()) {
        let t_norm = CONST_QUAL_RE.replace_all(t, "@@Q_");
        let b_norm = CONST_QUAL_RE.replace_all(b, "@@Q_");
        if t_norm == b_norm {
            return true;
        }
    }

    // Case 4: ??_C@ string literal hash mismatch. MSVC string literals are
    // mangled as ??_C@_0XX@HASH@content where HASH is a CRC-32 of the string
    // + __FILE__ path. Different build paths produce different hashes for the
    // same string content. Normalize the hash portion and path separators
    // (?1 = '/' vs ?2 = '\') to compare the logical content.
    static STRING_LITERAL_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\?\?_C@_[0-9A-P]+@[A-P]+@").unwrap());
    for (t, b) in t_syms.iter().zip(b_syms.iter()) {
        if STRING_LITERAL_RE.is_match(t) && STRING_LITERAL_RE.is_match(b) {
            // Both are string literals — normalize hash and path separators
            static STRING_HASH_RE: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r"^(\?\?_C@_[0-9A-P]+@)[A-P]+@").unwrap());
            let t_norm = STRING_HASH_RE.replace(t, "${1}_@");
            let b_norm = STRING_HASH_RE.replace(b, "${1}_@");
            // Also normalize path separators: ?1 (/) and ?2 (\) are equivalent
            let t_norm = t_norm.replace("?1", "?_SEP_").replace("?2", "?_SEP_");
            let b_norm = b_norm.replace("?1", "?_SEP_").replace("?2", "?_SEP_");
            if t_norm == b_norm {
                return true;
            }
        }
    }

    // Case 5: Mangled vs unmangled function name. One side has a fully
    // MSVC-mangled name (?func@Namespace@@...) while the other has the
    // plain C name (func). This happens when the target .obj has C linkage
    // names while the decomp uses C++ mangled names, or vice versa.
    for (t, b) in t_syms.iter().zip(b_syms.iter()) {
        // One starts with ? (mangled), the other doesn't
        let t_mangled = t.starts_with('?');
        let b_mangled = b.starts_with('?');
        if t_mangled != b_mangled {
            // Extract the base name from the mangled side
            let mangled = if t_mangled { t } else { b };
            let plain = if t_mangled { b } else { t };
            // MSVC mangling: ?name@ or ?name@namespace@...
            // Extract name between first ? and first @
            if let Some(at_pos) = mangled[1..].find('@') {
                let mangled_base = &mangled[1..1 + at_pos];
                if mangled_base == *plain {
                    return true;
                }
            }
        }
    }

    false
}

pub fn detect_address_relocation_noise(
    instructions: &[InstructionDiffOutput],
) -> Option<Pattern> {
    let mut count = 0usize;
    let mut pair_count = 0usize;
    let mut prev_was_lis = false;

    for instr in instructions {
        if instr.match_type != "diff_arg" {
            prev_was_lis = false;
            continue;
        }
        let (Some(target), Some(base)) = (&instr.target, &instr.base) else {
            prev_was_lis = false;
            continue;
        };

        // Same opcode, different args (or same opcode with CRT suffix diff)
        if target.opcode != base.opcode {
            prev_was_lis = false;
            continue;
        }

        match target.opcode.as_str() {
            "lis" => {
                // Any diff_arg on lis is address relocation: either different
                // immediates (different address halves) or same symbol text with
                // different relocation address. Both are linker layout noise.
                count += 1;
                prev_was_lis = true;
            }
            "addi" | "ori" => {
                // For addi/ori following lis (address loading pair), always
                // count as relocation. For standalone addi, only count when
                // there's a symbol relocation or identical text — NOT for
                // different immediates which may be struct offset mismatches.
                let t_args = target.args.as_deref().unwrap_or("");
                let b_args = base.args.as_deref().unwrap_or("");
                if prev_was_lis
                    || has_same_symbol_reloc(target, base)
                    || (t_args == b_args && !t_args.is_empty())
                {
                    count += 1;
                    if prev_was_lis {
                        pair_count += 1;
                    }
                }
                prev_was_lis = false;
            }
            // Branch instructions: same symbol at different address, CRT
            // save/restore suffix differences (__savegprlr vs __savegprlr_14),
            // or identical args text with different relocation address
            "bl" | "b" => {
                let t_args = target.args.as_deref().unwrap_or("");
                let b_args = base.args.as_deref().unwrap_or("");
                if has_same_symbol_reloc(target, base)
                    || is_crt_save_restore_diff(target, base)
                    || (t_args == b_args && !t_args.is_empty())
                {
                    count += 1;
                }
                prev_was_lis = false;
            }
            // Any other opcode: same symbol relocation, or identical args text
            // with different relocation address (diff_arg but text matches)
            _ => {
                let t_args = target.args.as_deref().unwrap_or("");
                let b_args = base.args.as_deref().unwrap_or("");
                if has_same_symbol_reloc(target, base)
                    || (t_args == b_args && !t_args.is_empty())
                {
                    count += 1;
                }
                prev_was_lis = false;
            }
        }
    }

    if count == 0 {
        return None;
    }

    Some(Pattern {
        pattern: PatternType::AddressRelocationNoise,
        confidence: Confidence::High,
        instruction_count: count,
        fixability: Fixability::RarelyHandFixable,
        details: PatternDetails::AddressRelocationNoise {
            info: AddressRelocationInfo { count, pair_count },
        },
        doc_urls: pattern_doc_urls(PatternType::AddressRelocationNoise),
    })
}

/// Detect boolean negation pattern (subfic vs subic).
///
/// The compiler may choose `subfic rD, rA, 0` or `subic rD, rA, 0` for
/// boolean negation depending on context. This is permuter-class — the
/// emission flips with small body restructurings.
pub fn detect_boolean_negation(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut count = 0usize;

    for instr in instructions {
        if instr.match_type != "replace" {
            continue;
        }
        let (Some(target), Some(base)) = (&instr.target, &instr.base) else { continue };

        let t_op = target.opcode.as_str();
        let b_op = base.opcode.as_str();

        let is_subfic_subic = (t_op == "subfic"
            && matches!(b_op, "subic" | "subic."))
            || (matches!(t_op, "subic" | "subic.")
                && b_op == "subfic");

        if is_subfic_subic {
            count += 1;
        }
    }

    if count == 0 {
        return None;
    }

    Some(Pattern {
        pattern: PatternType::BooleanNegation,
        confidence: Confidence::High,
        instruction_count: count,
        fixability: Fixability::RarelyHandFixable,
        details: PatternDetails::BooleanNegation { count },
        doc_urls: pattern_doc_urls(PatternType::BooleanNegation),
    })
}

/// Known single-precision ↔ double-precision opcode pairs.
const FLOAT_PRECISION_PAIRS: &[(&str, &str)] = &[
    ("fmul", "fmuls"),
    ("fadd", "fadds"),
    ("fsub", "fsubs"),
    ("fmadd", "fmadds"),
    ("fmsub", "fmsubs"),
    ("fnmadd", "fnmadds"),
    ("fnmsub", "fnmsubs"),
];

/// Detect float precision mismatches.
///
/// When cast placement differs between target and decomp, the compiler may
/// emit a double-precision instruction (e.g., `fmul`) where the target uses
/// single-precision (`fmuls`), or vice versa. This is often fixable by
/// adjusting cast placement or using `float` literals.
pub fn detect_float_precision_mismatch(
    instructions: &[InstructionDiffOutput],
) -> Option<Pattern> {
    let mut mismatches: Vec<FloatPrecisionMismatchEntry> = Vec::new();

    for instr in instructions {
        if instr.match_type != "replace" {
            continue;
        }
        let (Some(target), Some(base)) = (&instr.target, &instr.base) else { continue };

        let t_op = target.opcode.as_str();
        let b_op = base.opcode.as_str();

        // Check if the opcodes form a known precision pair
        let is_pair = FLOAT_PRECISION_PAIRS
            .iter()
            .any(|(double, single)| {
                (t_op == *double && b_op == *single) || (t_op == *single && b_op == *double)
            });

        if is_pair {
            mismatches.push(FloatPrecisionMismatchEntry {
                index: instr.index,
                target_op: t_op.to_string(),
                base_op: b_op.to_string(),
            });
        }
    }

    if mismatches.is_empty() {
        return None;
    }

    let count = mismatches.len();

    Some(Pattern {
        pattern: PatternType::FloatPrecisionMismatch,
        confidence: Confidence::High,
        instruction_count: count,
        fixability: Fixability::LikelyFixable,
        details: PatternDetails::FloatPrecisionMismatch { mismatches },
        doc_urls: pattern_doc_urls(PatternType::FloatPrecisionMismatch),
    })
}

/// Detect fsel explicit ternary patterns.
///
/// Looks for sequences of fneg/fsubs followed by fsel in target where base has a branch.
pub fn detect_fsel_ternary(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut count = 0;
    for i in 0..instructions.len() {
        let instr = &instructions[i];
        if instr.match_type != "replace" {
            continue;
        }
        let Some(target) = &instr.target else { continue };
        if target.opcode == "fsel" {
            // Check for previous fneg or fsubs
            if i > 0
                && let Some(prev) = &instructions[i - 1].target
                && matches!(prev.opcode.as_str(), "fneg" | "fsubs")
            {
                count += 1;
            }
        }
    }

    if count == 0 {
        return None;
    }

    Some(Pattern {
        pattern: PatternType::FselTernary,
        confidence: Confidence::High,
        instruction_count: count,
        fixability: Fixability::LikelyFixable,
        details: PatternDetails::FselTernary { count },
        doc_urls: pattern_doc_urls(PatternType::FselTernary),
    })
}

/// Detect float-to-int-to-float reconversion patterns.
///
/// Looks for sequences of fctiwz followed by stfd or fmr in target where base has stfs.
pub fn detect_float_to_int_to_float(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut count = 0;
    for i in 0..instructions.len() {
        let instr = &instructions[i];
        if instr.match_type != "replace" {
            continue;
        }
        let Some(target) = &instr.target else { continue };
        if target.opcode == "fctiwz" {
            // Check for following stfd or fmr
            if i + 1 < instructions.len()
                && let Some(next) = &instructions[i + 1].target
                && matches!(next.opcode.as_str(), "stfd" | "fmr")
            {
                count += 1;
            }
        }
    }

    if count == 0 {
        return None;
    }

    Some(Pattern {
        pattern: PatternType::FloatToIntToFloat,
        confidence: Confidence::High,
        instruction_count: count,
        fixability: Fixability::LikelyFixable,
        details: PatternDetails::FloatToIntToFloat { count },
        doc_urls: pattern_doc_urls(PatternType::FloatToIntToFloat),
    })
}

/// Known PPC signed ↔ unsigned/logical opcode pairs, ordered `(signed,
/// unsigned)`.
///
/// - `lha`/`lhz`   — load halfword *algebraic* (sign-extend) vs *zero* extend.
/// - `srawi`/`srwi` — shift right *algebraic* word imm (arithmetic, sign-fill)
///   vs shift right *logical* word imm (zero-fill).
/// - `cmpw`/`cmplw` — compare word (signed) vs compare *logical* word (unsigned).
/// - `extsb`/`extsh` — extend sign byte (`char`) vs extend sign halfword
///   (`short`); a width/type disagreement on a signed value.
///
/// A `replace` row whose two sides are the two members of one pair is a strong
/// fingerprint of a source-level signedness (or, for extsb/extsh, width) type
/// disagreement — the #2 hazard family in the validator-accuracy audit.
const SIGNEDNESS_PAIRS: &[(&str, &str)] =
    &[("lha", "lhz"), ("srawi", "srwi"), ("cmpw", "cmplw"), ("extsb", "extsh")];

/// Detect signed/unsigned instruction-pair mismatches at aligned rows.
///
/// Fires when a `replace` row pairs the two members of a known signed/unsigned
/// PPC opcode pair (in either direction). Unlike `detect_comparison_style`
/// (which keys on immediate deltas at `diff_arg` rows for `cmpwi`/`cmplwi`),
/// this keys purely on the opcode identity of the two aligned instructions,
/// so it is disjoint from the existing detectors. Match-neutral by
/// construction on equal functions: an `equal` row is never inspected.
pub fn detect_signedness_mismatch(instructions: &[InstructionDiffOutput]) -> Option<Pattern> {
    let mut mismatches: Vec<SignednessMismatchEntry> = Vec::new();

    for instr in instructions {
        if instr.match_type != "replace" {
            continue;
        }
        let (Some(target), Some(base)) = (&instr.target, &instr.base) else { continue };

        let t_op = target.opcode.as_str();
        let b_op = base.opcode.as_str();

        // Find the pair this row matches (in either direction). Resolve which
        // side is signed independent of which side is target vs base.
        let matched = SIGNEDNESS_PAIRS.iter().find(|(signed, unsigned)| {
            (t_op == *signed && b_op == *unsigned) || (t_op == *unsigned && b_op == *signed)
        });

        if let Some((signed, unsigned)) = matched {
            mismatches.push(SignednessMismatchEntry {
                index: instr.index,
                target_op: t_op.to_string(),
                base_op: b_op.to_string(),
                signed_op: signed.to_string(),
                unsigned_op: unsigned.to_string(),
            });
        }
    }

    if mismatches.is_empty() {
        return None;
    }

    let count = mismatches.len();

    Some(Pattern {
        pattern: PatternType::SignednessMismatch,
        confidence: Confidence::High,
        instruction_count: count,
        fixability: Fixability::LikelyFixable,
        details: PatternDetails::SignednessMismatch { mismatches },
        doc_urls: pattern_doc_urls(PatternType::SignednessMismatch),
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
    if let Some(p) = detect_anonymous_namespace_hash(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_static_guard_counter(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_dynamic_cast_mismatch(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_dead_store_elimination(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_prologue_mismatch(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_alloca_mismatch(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_scope_counter_mismatch(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_makestring_template_mismatch(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_address_relocation_noise(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_boolean_negation(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_float_precision_mismatch(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_fsel_ternary(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_float_to_int_to_float(instructions) {
        patterns.push(p);
    }
    if let Some(p) = detect_signedness_mismatch(instructions) {
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
            "ANONYMOUS_NAMESPACE_HASH",
            "STATIC_GUARD_COUNTER",
            "DYNAMIC_CAST_MISMATCH",
            "DEAD_STORE_ELIMINATION",
            "PROLOGUE_MISMATCH",
            "ALLOCA_MISMATCH",
            "SCOPE_COUNTER_MISMATCH",
            "MAKESTRING_TEMPLATE_MISMATCH",
            "ADDRESS_RELOCATION_NOISE",
            "BOOLEAN_NEGATION",
            "FLOAT_PRECISION_MISMATCH",
            "FSEL_TERNARY",
            "FLOAT_TO_INT_TO_FLOAT",
            "SIGNEDNESS_MISMATCH",
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
    base_size: u64,
    target_size: u64,
) -> Verdict {
    // If base has no code but target does, the function is unimplemented.
    // objdiff produces placeholder instructions with no data on either side
    // that get counted as "equal", so we must check sizes first.
    if base_size == 0 && target_size > 0 {
        return Verdict {
            classification: VerdictClassification::Stub,
            confidence: Confidence::High,
            explanation: format!(
                "Function is unimplemented (base has no code, target is {} bytes).",
                target_size
            ),
            factors: vec![VerdictFactor {
                name: "base_size",
                value: serde_json::json!(0),
                threshold: None,
                result: "stub",
            }],
            recommendation: "Implement the function.".to_string(),
            suggestions: vec![],
            doc_urls: vec![],
        };
    }

    let total_mismatches = summary.total - summary.equal;
    let mut factors = Vec::new();

    // Collect all doc_urls from detected patterns for verdict-level reference
    let verdict_doc_urls: Vec<String> = {
        let mut urls: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for p in &analysis.patterns {
            for u in &p.doc_urls {
                urls.insert(u.clone());
            }
        }
        urls.into_iter().collect()
    };

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
            doc_urls: vec![],
        };
    }

    // Check if ALL mismatches are attributed to rarely-hand-fixable patterns.
    // If so, this function's hand-edit path is exhausted, but the source
    // permuter may still close the gap — recommend a permuter sweep before
    // marking at_limit.
    if analysis.unattributed_mismatches == 0 && !analysis.patterns.is_empty() {
        let has_linker_merged = analysis.has_pattern(PatternType::LinkerMerged);
        let all_rarely_hand_fixable = analysis.patterns.iter().all(|p| {
            p.fixability == Fixability::RarelyHandFixable
            // MakeString type mismatches become artifact-driven when co-detected
            // with LinkerMerged ICF — the different template is just the
            // linker's ICF address choice, not a real source-level type diff
            || (p.pattern == PatternType::MakeStringTemplateMismatch && has_linker_merged)
        });
        // Truly source-immune patterns: linker-derived only (path hash, address
        // reloc, ICF). Even the permuter cannot help here.
        let all_source_immune = analysis.patterns.iter().all(|p| {
            matches!(
                p.pattern,
                PatternType::AnonymousNamespaceHash
                    | PatternType::AddressRelocationNoise
                    | PatternType::LinkerMerged
            )
        });
        if all_rarely_hand_fixable {
            let pattern_names: Vec<&str> =
                analysis.patterns.iter().map(|p| p.pattern.as_str()).collect();
            factors.push(VerdictFactor {
                name: "all_rarely_hand_fixable",
                value: serde_json::json!(true),
                threshold: None,
                result: if all_source_immune { "at_limit_source_immune" } else { "at_limit_hand_edit" },
            });
            if all_source_immune {
                return Verdict {
                    classification: VerdictClassification::AtLimit,
                    confidence: Confidence::High,
                    explanation: format!(
                        "All {} mismatch(es) are source-immune build artifacts: {}.",
                        total_mismatches,
                        pattern_names.join(", ")
                    ),
                    factors,
                    recommendation: format!(
                        "Accept current match ({:.1}%). These are linker/path-derived; \
                         no source mutation can close them.",
                        match_percent.unwrap_or(0.0)
                    ),
                    suggestions: vec![Suggestion {
                        action: "Accept current match — remaining differences are linker/build-environment artifacts.".to_string(),
                        doc_url: None,
                    }],
                    doc_urls: verdict_doc_urls.clone(),
                };
            }
            return Verdict {
                classification: VerdictClassification::MaybeFixable,
                confidence: Confidence::Medium,
                explanation: format!(
                    "All {} mismatch(es) attributed to rarely-hand-fixable pattern(s): {}. \
                     A source-permuter sweep is the recommended next step.",
                    total_mismatches,
                    pattern_names.join(", ")
                ),
                factors,
                recommendation: "Run the source permuter on this function (~250 builds). \
                     If no improvement after a full sweep, mark at_limit. Do NOT accept \
                     before running the permuter — these patterns are typically permuter-class."
                    .to_string(),
                suggestions: vec![Suggestion {
                    action: "Run the source permuter on this function/unit before accepting.".to_string(),
                    doc_url: doc_url(DocLink::PermuterRoi),
                }],
                doc_urls: verdict_doc_urls.clone(),
            };
        }
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
                doc_url: None,
            }],
            doc_urls: verdict_doc_urls.clone(),
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
            classification: VerdictClassification::MaybeFixable,
            confidence: Confidence::Medium,
            explanation: format!(
                "{} bool mask instruction(s) detected. Bool-return masking differences \
                 are typically permuter-class — the source permuter can usually flip the \
                 emission via small body restructurings.",
                bool_count
            ),
            factors,
            recommendation: format!(
                "Try a source-permuter sweep on this function. If the gap is small (1-3%) \
                 and a full sweep yields nothing, then accept ({:.1}%) and mark at_limit. \
                 See fixable-bool-mask.md for the bool↔byte mask shapes that can be hand-edited.",
                match_percent.unwrap_or(0.0)
            ),
            suggestions: vec![Suggestion {
                action: "Run the source permuter on this function before accepting.".to_string(),
                doc_url: doc_url(DocLink::BoolMask),
            }],
            doc_urls: verdict_doc_urls.clone(),
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

    // High merged ratio = at limit. ICF (identical-code-folding) is genuinely
    // source-immune: the linker folded the target's identical function bodies
    // and our build did not. Only accept here when match% is ALSO high — a
    // low-match function dominated by merged calls usually means the
    // surrounding code is still wrong; don't accept based on merged ratio alone.
    if merged_ratio >= MERGED_RATIO_AT_LIMIT && match_percent.unwrap_or(0.0) >= 95.0 {
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
                "{:.1}% of mismatches are calls to linker-merged functions{}. \
                 ICF is source-immune at the call site.",
                merged_ratio * 100.0,
                detail
            ),
            factors,
            recommendation: format!(
                "Accept current match ({:.1}%). The merged-call targets are a linker \
                 folding artifact — no source mutation will change the call target.",
                match_percent.unwrap_or(0.0)
            ),
            suggestions: vec![Suggestion {
                action: "Accept current match — merged calls are a linker artifact.".to_string(),
                doc_url: doc_url(DocLink::IcfVerifiable),
            }],
            doc_urls: verdict_doc_urls.clone(),
        };
    }
    // High merged ratio but low overall match — surrounding code is still off.
    if merged_ratio >= MERGED_RATIO_AT_LIMIT {
        let merged_summary = analysis
            .patterns
            .iter()
            .find(|p| p.pattern == PatternType::LinkerMerged)
            .map(|p| p.summarize());
        let detail =
            merged_summary.as_ref().map(|s| format!(" ({})", s.one_line)).unwrap_or_default();
        return Verdict {
            classification: VerdictClassification::MaybeFixable,
            confidence: Confidence::Medium,
            explanation: format!(
                "{:.1}% of mismatches are merged-call targets{}, but overall match is \
                 only {:.1}% — surrounding code likely still has fixable differences.",
                merged_ratio * 100.0,
                detail,
                match_percent.unwrap_or(0.0)
            ),
            factors,
            recommendation: "Look past the merged-call noise: inspect the non-merged \
                mismatches (control flow, regalloc) and consider a permuter sweep."
                .to_string(),
            suggestions: vec![Suggestion {
                action: "Filter out merged-call diffs and inspect remaining mismatches.".to_string(),
                doc_url: doc_url(DocLink::IcfVerifiable),
            }],
            doc_urls: verdict_doc_urls.clone(),
        };
    }

    // Check for address relocation noise (linker-layout artifact, similar to merged)
    let addr_reloc_count = analysis.pattern_instruction_count(PatternType::AddressRelocationNoise);
    let addr_reloc_ratio =
        if total_mismatches > 0 { addr_reloc_count as f32 / total_mismatches as f32 } else { 0.0 };
    if addr_reloc_ratio >= MERGED_RATIO_AT_LIMIT {
        factors.push(VerdictFactor {
            name: "address_relocation_ratio",
            value: serde_json::json!(addr_reloc_ratio),
            threshold: Some(MERGED_RATIO_AT_LIMIT),
            result: "exceeds_limit",
        });
        return Verdict {
            classification: VerdictClassification::AtLimit,
            confidence: Confidence::High,
            explanation: format!(
                "{:.1}% of mismatches are address-relocation noise (lis/addi pairs loading \
                 the same logical symbol at a different absolute address). This is \
                 source-immune — it reflects .text layout, not code.",
                addr_reloc_ratio * 100.0
            ),
            factors,
            recommendation: format!(
                "Accept current match ({:.1}%). Address relocation is a link-time \
                 layout artifact; no source mutation can shift it.",
                match_percent.unwrap_or(0.0)
            ),
            suggestions: vec![Suggestion {
                action: "Accept current match — address-relocation noise is a linker artifact."
                    .to_string(),
                doc_url: doc_url(DocLink::AddressRelocationNoise),
            }],
            doc_urls: verdict_doc_urls.clone(),
        };
    }

    // Check for MakeString template mismatches
    if analysis.has_pattern(PatternType::MakeStringTemplateMismatch) {
        let ms_pattern = analysis
            .patterns
            .iter()
            .find(|p| p.pattern == PatternType::MakeStringTemplateMismatch);
        if let Some(pat) = ms_pattern
            && let PatternDetails::MakeStringTemplateMismatch { mismatches } = &pat.details
        {
            let all_file = mismatches
                .iter()
                .all(|m| matches!(m.sub_type, MakeStringMismatchSubType::FileLength));
            let has_type =
                mismatches.iter().any(|m| matches!(m.sub_type, MakeStringMismatchSubType::Type));
            factors.push(VerdictFactor {
                name: "makestring_template",
                value: serde_json::json!(mismatches.len()),
                threshold: None,
                result: if all_file { "file_length_only" } else { "type_mismatch" },
            });
            if has_type {
                // Type mismatches are likely fixable — suggest .Str() conversion
                return Verdict {
                    classification: VerdictClassification::LikelyFixable,
                    confidence: Confidence::High,
                    explanation: format!(
                        "{} MakeString template type mismatch(es) — add .Str() conversions to MILO macro arguments.",
                        mismatches.len()
                    ),
                    factors,
                    recommendation: "Add .Str() to Symbol/DataNode arguments in MILO macros."
                        .to_string(),
                    suggestions: vec![Suggestion {
                        action: "Add .Str() conversions to MILO macro arguments".to_string(),
                        doc_url: doc_url(DocLink::MakeStringTemplate),
                    }],
                    doc_urls: verdict_doc_urls.clone(),
                };
            }
        }
    }

    // Check for float precision mismatches (likely fixable)
    if analysis.has_pattern(PatternType::FloatPrecisionMismatch) {
        let fp_count = analysis.pattern_instruction_count(PatternType::FloatPrecisionMismatch);
        factors.push(VerdictFactor {
            name: "float_precision_mismatch",
            value: serde_json::json!(fp_count),
            threshold: None,
            result: "detected",
        });
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
            suggestions.push(Suggestion {
                action: cf_summary.one_line.clone(),
                doc_url: cf_pattern.doc_urls.first().cloned(),
            });
            // Add specific indices from top details
            for detail in cf_summary.top_details.iter().take(2) {
                suggestions.push(Suggestion { action: detail.clone(), doc_url: None });
            }
        }

        suggestions.push(Suggestion {
            action: "Try `> 0` vs `!= 0`, `>=` vs `>`, if/else inversion".to_string(),
            doc_url: doc_url(DocLink::UnsignedZeroComparison),
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
            doc_urls: verdict_doc_urls.clone(),
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
            suggestions.push(Suggestion {
                action: rs_summary.one_line.clone(),
                doc_url: rs_pattern.doc_urls.first().cloned(),
            });
        }

        // PRIMARY recommendation: treat the swap set as a symptom and go
        // looking for the liveness or scheduling difference behind it.
        // Measured on MSVC/PowerPC (n=3, one codebase — see
        // docs/research/register-swap-symptom-not-cause.md): in every case the
        // register names were never permuted directly, and the entire swap set
        // flipped at once when the cause was fixed. Declaration reorder — the
        // move the old text recommended first — was inert there (6 variants
        // byte-identical, 2 regressed on one function).
        suggestions.push(Suggestion {
            action: "Treat swaps as a symptom. Look for a liveness difference (a value the \
                     target holds across a call that we reload, or vice versa) or a scheduling \
                     difference (a producer emitted after its consumer, a compare with the \
                     operands the other way round). The pattern's register-class label says \
                     which: volatile registers cannot be live across a call, so a \
                     volatile-only swap rules liveness out. Fixing the cause flips the whole \
                     swap set."
                .to_string(),
            doc_url: doc_url(DocLink::PrecomputeRefsBeforeCalls),
        });
        suggestions.push(Suggestion {
            action: "Run the source permuter on this function/unit if the cause isn't visible."
                .to_string(),
            doc_url: doc_url(DocLink::PermuterRoi),
        });
        suggestions.push(Suggestion {
            action: "Declaration reorder is usually inert for register-only swaps (measured on \
                     MSVC/PPC); reach for it when stack-slot / OFFSET_SWAP diffs are also present."
                .to_string(),
            doc_url: doc_url(DocLink::DeclarationOrder),
        });

        // Register swaps are NEVER "unfixable" on their face. They are a
        // downstream effect of some other difference, and both hand analysis
        // (liveness/scheduling) and the permuter have closed them. Even
        // high-match functions deserve a look for the cause, then a sweep,
        // before being marked at_limit.
        let high_match = match_percent.unwrap_or(0.0) >= 99.0;

        let (classification, explanation, recommendation) = if high_match && register_swap_count <= 4 {
            // Very high match (≥99%) with a tiny regswap count — likely a
            // single FPR f0↔f1 swap or similar. Permuter still worth trying,
            // but accepting after a sweep is reasonable.
            (
                VerdictClassification::MaybeFixable,
                format!(
                    "{} register swap instruction(s) at {:.1}% match. Small regswap counts \
                     at very high match are usually one live-range or scheduling decision \
                     showing through — check that first, then sweep; if neither moves it, \
                     accepting is reasonable.",
                    register_swap_count,
                    match_percent.unwrap_or(0.0)
                ),
                format!(
                    "Look for the single liveness/scheduling difference behind the swaps, \
                     then run the source permuter (~250 builds). If neither improves it, \
                     accept ({:.1}%) and mark at_limit.",
                    match_percent.unwrap_or(0.0)
                ),
            )
        } else if register_swap_count > 20 {
            (
                VerdictClassification::MaybeFixable,
                format!(
                    "{} register swap instructions — large cascade, typically driven by ONE \
                     upstream decision (a value's live range across a call, or where an \
                     operation was scheduled). Large count does not mean large fix: cascades \
                     of 17 and ~40 swaps have both collapsed to zero from a single edit.",
                    register_swap_count
                ),
                "Find the one upstream difference rather than chasing individual registers: \
                 compare which values survive across calls (prologue save count is a tell), \
                 and whether producers are scheduled before their consumers. Then run the \
                 source permuter. Only mark at_limit after both yield nothing."
                    .to_string(),
            )
        } else {
            (
                VerdictClassification::MaybeFixable,
                format!(
                    "{} register swap instruction(s) detected. Symptom class — the swaps \
                     follow from a liveness or scheduling difference rather than being the \
                     difference themselves.",
                    register_swap_count
                ),
                "Look for the cause first: a member reloaded at a call site the target keeps \
                 in a register, a temp whose live range spans a call it need not, or an \
                 operation scheduled after the instruction that consumes it. Then run the \
                 source permuter. Declaration reorder is for stack-slot diffs, not this."
                    .to_string(),
            )
        };

        return Verdict {
            classification,
            confidence: Confidence::Medium,
            explanation,
            factors,
            recommendation,
            suggestions,
            doc_urls: verdict_doc_urls.clone(),
        };
    }

    // Default: needs investigation - summarize what we found
    let mut suggestions = Vec::new();
    for pattern in &analysis.patterns {
        let ps = pattern.summarize();
        suggestions.push(Suggestion {
            action: format!("{}: {}", pattern.pattern.as_str(), ps.one_line),
            doc_url: pattern.doc_urls.first().cloned(),
        });
    }
    if summary.delete > 0 || summary.insert > 0 {
        suggestions.push(Suggestion {
            action: format!(
                "{} delete(s), {} insert(s) -- check for missing/extra code blocks",
                summary.delete, summary.insert
            ),
            doc_url: None,
        });
    }
    if suggestions.is_empty() {
        suggestions.push(Suggestion {
            action: "Use --include-instructions to inspect specific differences".to_string(),
            doc_url: None,
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
        doc_urls: verdict_doc_urls,
    }
}

#[cfg(test)]
mod doc_link_tests {
    use super::*;

    /// Filenames that exist in only one of the two known projects. Emitting one
    /// of these for the other project is the failure mode this module exists to
    /// prevent: DC3 is MSVC and RB3 is MetroWerks, so a cross-repo doc link
    /// either 404s or, worse, hands the reader advice for the wrong backend.
    const DC3_ONLY_FILES: &[&str] = &[
        "PERMUTER_ROI_ANALYSIS.md",
        "at-limit-systemic.md",
        "unfixable-compiler.md",
        "fixable-liveness.md",
    ];
    const RB3_ONLY_FILES: &[&str] = &["permuter-roi.md", "at-limit-mwcc.md"];

    fn all_urls(project: DocProject) -> Vec<String> {
        let mut urls: Vec<String> =
            ALL_DOC_LINKS.iter().filter_map(|&l| doc_url_for(project, l)).collect();
        for &p in ALL_PATTERN_TYPES {
            urls.extend(pattern_doc_urls_for(project, p));
        }
        urls
    }

    fn file_of(url: &str) -> &str {
        let path = url.strip_prefix(DOC_BASE).unwrap_or(url);
        path.split('#').next().unwrap_or(path)
    }

    #[test]
    fn dc3_first_url_anchor_contract() {
        // objdiff renders only the FIRST doc URL inline, and dc3-decomp's docs
        // are maintained against these exact anchors.
        assert_eq!(
            pattern_doc_urls_for(DocProject::Dc3, PatternType::RegisterSwap)[0],
            "docs/decomp/patterns/fixable-declarations.md\
             #pre-compute-references-before-clobbering-calls"
        );
        assert_eq!(
            pattern_doc_urls_for(DocProject::Dc3, PatternType::OffsetSwap)[0],
            "docs/decomp/patterns/fixable-declarations.md#offset-swap"
        );
        assert!(
            pattern_doc_urls_for(DocProject::Dc3, PatternType::RegisterSwap).contains(
                &"docs/decomp/patterns/PERMUTER_ROI_ANALYSIS.md#instruction-scheduling".to_string()
            ),
            "the scheduling writeup must stay reachable from REGISTER_SWAP"
        );
    }

    #[test]
    fn no_cross_project_filenames() {
        for url in all_urls(DocProject::Dc3) {
            let file = file_of(&url);
            assert!(!RB3_ONLY_FILES.contains(&file), "DC3 emitted RB3-only doc: {url}");
        }
        for url in all_urls(DocProject::Rb3) {
            let file = file_of(&url);
            assert!(!DC3_ONLY_FILES.contains(&file), "RB3 emitted DC3-only doc: {url}");
        }
    }

    #[test]
    fn unknown_project_emits_only_universal_links() {
        for &link in ALL_DOC_LINKS {
            let Some(url) = doc_url_for(DocProject::Unknown, link) else { continue };
            let dc3 = doc_url_for(DocProject::Dc3, link)
                .unwrap_or_else(|| panic!("{link:?}: unknown resolved but dc3 did not"));
            let rb3 = doc_url_for(DocProject::Rb3, link)
                .unwrap_or_else(|| panic!("{link:?}: unknown resolved but rb3 did not"));
            assert!(
                dc3.starts_with(&url) && rb3.starts_with(&url),
                "{link:?}: unknown emitted {url}, not common to {dc3} and {rb3}"
            );
            if dc3 != rb3 {
                assert!(!url.contains('#'), "{link:?}: kept a diverging anchor: {url}");
            }
        }
        // Degrading gracefully must not mean degrading to nothing useful.
        assert!(all_urls(DocProject::Unknown).iter().any(|u| u.contains("fixable-declarations")));
    }

    #[test]
    fn every_pattern_has_a_dc3_doc() {
        for &pattern in ALL_PATTERN_TYPES {
            assert!(
                !pattern_doc_urls_for(DocProject::Dc3, pattern).is_empty(),
                "{pattern:?} has no DC3 documentation"
            );
        }
    }

    #[test]
    fn urls_are_well_formed() {
        for project in [DocProject::Dc3, DocProject::Rb3, DocProject::Unknown] {
            for url in all_urls(project) {
                assert!(url.starts_with(DOC_BASE), "{url} is not project-relative");
                assert!(file_of(&url).ends_with(".md"), "{url} does not name a markdown file");
                assert!(!url.ends_with('#'), "{url} has an empty anchor");
            }
        }
    }

    #[test]
    fn enumerations_are_complete_and_unique() {
        // Guards against adding a variant and forgetting the ALL_ table, which
        // would silently exclude it from the link checker.
        let mut links = ALL_DOC_LINKS.to_vec();
        links.sort_by_key(|l| format!("{l:?}"));
        links.dedup_by_key(|l| format!("{l:?}"));
        assert_eq!(links.len(), ALL_DOC_LINKS.len(), "duplicate entry in ALL_DOC_LINKS");
        assert_eq!(ALL_DOC_LINKS.len(), 30, "update ALL_DOC_LINKS when adding a DocLink");
        let mut patterns = ALL_PATTERN_TYPES.to_vec();
        patterns.sort_by_key(|p| p.as_str());
        patterns.dedup_by_key(|p| p.as_str());
        assert_eq!(patterns.len(), ALL_PATTERN_TYPES.len(), "duplicate in ALL_PATTERN_TYPES");
        assert_eq!(
            ALL_PATTERN_TYPES.len(),
            21,
            "update ALL_PATTERN_TYPES when adding a PatternType"
        );
    }

    #[test]
    fn project_names_round_trip() {
        for project in [DocProject::Dc3, DocProject::Rb3, DocProject::Unknown] {
            assert_eq!(DocProject::from_name(project.as_str()), Some(project));
        }
        assert_eq!(DocProject::from_name("DC3"), Some(DocProject::Dc3));
        assert_eq!(DocProject::from_name("none"), Some(DocProject::Unknown));
        assert_eq!(DocProject::from_name("mario"), None);
    }

    #[test]
    fn detection_reads_the_docs_tree() {
        let root = std::env::temp_dir().join(format!("objdiff-doclinks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let make = |name: &str, markers: &[&str]| {
            let dir = root.join(name).join("docs").join("decomp").join("patterns");
            std::fs::create_dir_all(&dir).unwrap();
            for marker in markers {
                std::fs::write(dir.join(marker), "# x\n").unwrap();
            }
            root.join(name)
        };
        let dc3 = make("dc3", &["PERMUTER_ROI_ANALYSIS.md"]);
        let rb3 = make("rb3", &["permuter-roi.md", "at-limit-mwcc.md"]);
        let bare = make("bare", &["something-else.md"]);
        let nodocs = root.join("nodocs");
        std::fs::create_dir_all(nodocs.join("src")).unwrap();

        assert_eq!(detect_doc_project_at(&dc3), Some(DocProject::Dc3));
        assert_eq!(detect_doc_project_at(&rb3), Some(DocProject::Rb3));
        assert_eq!(detect_doc_project_at(&bare), Some(DocProject::Unknown));
        assert_eq!(detect_doc_project_at(&nodocs), None);

        // Detection must work from a subdirectory (ninja and the orchestrator
        // both invoke objdiff-cli from wherever the build happens to be).
        let deep = dc3.join("src").join("system").join("rndobj");
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(detect_doc_project_from(&deep), DocProject::Dc3);
        assert_eq!(detect_doc_project_from(&nodocs), DocProject::Unknown);

        let _ = std::fs::remove_dir_all(&root);
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
            masked_equal: false,
            diff_breakdown: None,
            target_branch_from: None,
            target_branch_to: None,
            base_branch_from: None,
            base_branch_to: None,
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
            masked_equal: false,
            diff_breakdown: None,
            target_branch_from: None,
            target_branch_to: None,
            base_branch_from: None,
            base_branch_to: None,
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
        assert_eq!(pattern.fixability, Fixability::RarelyHandFixable);

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

    /// The REGISTER_SWAP summary's "dominated by" line must not depend on
    /// HashMap iteration order.
    ///
    /// `detect_register_swap` counts pairs into a `HashMap` and then sorts by
    /// count. With tied counts a plain count-sort leaves the order to whatever
    /// the hasher produced, and `std::collections::HashMap` reseeds per
    /// instance — so the same binary on the same object emitted `f0<->f10` on
    /// one run and `f13<->f9` on the next, with a varying third place. That
    /// makes diff reports non-reproducible and useless for A/B-ing a source
    /// edit. Regression test: build the same pattern many times and require
    /// every rendering to agree.
    #[test]
    fn test_register_swap_summary_is_deterministic_under_ties() {
        // Four pairs, all with exactly MIN_REGISTER_SWAP_OCCURRENCES
        // occurrences: nothing but the tie-break can order them.
        let mut instructions = Vec::new();
        let pairs = [("f0", "f10"), ("f13", "f9"), ("f2", "f8"), ("f11", "f3")];
        let reps = MIN_REGISTER_SWAP_OCCURRENCES;
        for (i, (t, b)) in pairs.iter().enumerate() {
            for rep in 0..reps {
                let index = i * reps + rep;
                instructions.push(make_instr(
                    index,
                    "diff_arg",
                    Some("fmr"),
                    Some(&format!("{t}, f31")),
                    Some("fmr"),
                    Some(&format!("{b}, f31")),
                ));
            }
        }

        let render = || {
            let pattern =
                detect_register_swap(&instructions).expect("Should detect register swap");
            let summary = pattern.summarize();
            (summary.one_line, summary.top_details)
        };

        let expected = render();
        assert!(
            expected.0.contains("dominated by"),
            "expected a dominated-by line: {}",
            expected.0
        );
        // A fresh HashMap (and therefore a fresh seed) on every iteration.
        for _ in 0..64 {
            assert_eq!(render(), expected, "REGISTER_SWAP summary varied between runs");
        }

        // And the tie-break orders by register NUMBER, not lexicographically:
        // f2 and f11 come before f13, where a string sort would give
        // f0, f11, f13, f2. (`top_details` is capped at 3.)
        assert_eq!(
            expected.1,
            vec![
                format!("f0↔f10: {reps}"),
                format!("f2↔f8: {reps}"),
                format!("f11↔f3: {reps}"),
            ]
        );
    }

    /// The CONTROL_FLOW summary's "dominated by" opcode pair must not depend on
    /// `HashMap` iteration order.
    ///
    /// `summarize()` counted opcode pairs into a `HashMap` and took
    /// `max_by_key`, which returns the LAST maximum in iteration order. On a
    /// tie that is a coin flip per process. It reaches the caller: this
    /// `one_line` is published verbatim as `verdict.suggestions[0].action`, so
    /// a dc3-decomp row alternated between `2 replacement(s) (bl↔beq)` and
    /// `2 replacement(s) (addi↔bne)`, 11 vs 4 over 15 runs of one binary.
    ///
    /// Run it many times in one process to make the old failure deterministic —
    /// each `detect_control_flow` + `summarize()` pair builds fresh `HashMap`s
    /// with fresh seeds.
    #[test]
    fn test_control_flow_summary_is_deterministic_under_ties() {
        // Four distinct replacement pairs, one occurrence each: nothing but the
        // tie-break can pick a winner.
        let instructions = vec![
            make_instr(0, "replace", Some("bl"), None, Some("beq"), None),
            make_instr(1, "replace", Some("addi"), None, Some("bne"), None),
            make_instr(2, "replace", Some("stw"), None, Some("blt"), None),
            make_instr(3, "replace", Some("b"), None, Some("bgt"), None),
            // ... and two tied condition inversions.
            make_instr(4, "diff_op", Some("beq"), None, Some("bne"), None),
            make_instr(5, "diff_op", Some("blt"), None, Some("bge"), None),
        ];

        let render = || {
            detect_control_flow(&instructions).expect("should detect control flow").summarize()
        };
        let expected = render();
        for _ in 0..256 {
            assert_eq!(
                render().one_line,
                expected.one_line,
                "CONTROL_FLOW summary varied between runs"
            );
        }
        // The tie-break is the pair string itself, ascending, so the winner is
        // the lexicographically smallest of the tied pairs: `addi↔bne` among
        // the four replacements, `beq↔bne` among the two inversions.
        assert_eq!(
            expected.one_line,
            "2 condition inversion(s) (beq↔bne), 4 replacement(s) (addi↔bne)"
        );
    }

    /// The LINKER_MERGED detail list must not depend on `HashMap` iteration
    /// order.
    ///
    /// `detect_linker_merged` counts call targets into a `HashMap`, drains it
    /// into a vec and sorted by count alone. `sort_by_key` is stable, so equal
    /// counts kept the hasher's order — and merged-call counts are almost
    /// always 1, so the tie is the normal case. The comment on that sort said
    /// "for consistent output" and was false: on a 1500-symbol rb3-xenon batch
    /// this list reordered on 16 of the 19 rows that differed between runs of
    /// one binary, and `summarize()` puts its head into the verdict text.
    #[test]
    fn test_linker_merged_details_are_deterministic_under_ties() {
        // Four distinct merged targets, one call each.
        // All four match MERGED_FUNC_RE, so all four land in the map with a
        // count of 1 and only the tie-break can order them.
        let names = ["merged_9", "??_Ezeta@@UAAPAXI@Z", "merged_1", "OnlyReturns"];
        let instructions: Vec<_> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                make_instr(i, "diff_arg", Some("bl"), Some(n), Some("bl"), Some("?other@@YAXXZ"))
            })
            .collect();

        let render = || {
            let pattern = detect_linker_merged(&instructions).expect("should detect merged calls");
            match pattern.details {
                PatternDetails::MergedFunctions { merged_functions } => {
                    merged_functions.into_iter().map(|f| f.name).collect::<Vec<_>>()
                }
                other => panic!("unexpected details: {other:?}"),
            }
        };
        let expected = render();
        for _ in 0..256 {
            assert_eq!(render(), expected, "LINKER_MERGED detail order varied between runs");
        }
        // All counts are 1, so the order is purely the name tie-break.
        assert_eq!(
            expected,
            vec!["??_Ezeta@@UAAPAXI@Z", "OnlyReturns", "merged_1", "merged_9"]
        );
    }

    #[test]
    fn test_verdict_complete() {
        let summary = InstructionSummary { total: 10, equal: 10, ..Default::default() };
        let analysis = Analysis {
            patterns: vec![],
            patterns_checked: vec!["LINKER_MERGED", "BOOL_MASK", "REGISTER_SWAP"],
            unattributed_mismatches: 0,
        };

        let verdict = compute_verdict(&summary, &analysis, Some(100.0), 100, 100);
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
                fixability: Fixability::RarelyHandFixable,
                details: PatternDetails::MergedFunctions {
                    merged_functions: vec![MergedFunctionCount {
                        name: "merged_test".to_string(),
                        count: 4,
                    }],
                },
                doc_urls: vec![],
            }],
            patterns_checked: vec!["LINKER_MERGED", "BOOL_MASK", "REGISTER_SWAP"],
            unattributed_mismatches: 1,
        };

        let verdict = compute_verdict(&summary, &analysis, Some(97.0), 100, 100);
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
            doc_urls: vec![],
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
            doc_urls: vec![],
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
            doc_urls: vec![],
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
            doc_urls: vec![],
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
            doc_urls: vec![],
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
            fixability: Fixability::RarelyHandFixable,
            details: PatternDetails::MergedFunctions {
                merged_functions: vec![
                    MergedFunctionCount { name: "merged_Read4FloatStruct".to_string(), count: 3 },
                    MergedFunctionCount { name: "OnlyReturns".to_string(), count: 2 },
                ],
            },
            doc_urls: vec![],
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
            fixability: Fixability::PermuterClass,
            details: PatternDetails::BoolMask { bit_positions: vec![24, 31] },
            doc_urls: vec![],
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
            doc_urls: vec![],
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
            doc_urls: vec![],
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
            doc_urls: vec![],
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
            doc_urls: vec![],
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
                fixability: Fixability::RarelyHandFixable,
                details: PatternDetails::MergedFunctions {
                    merged_functions: vec![
                        MergedFunctionCount { name: "merged_test".to_string(), count: 3 },
                        MergedFunctionCount { name: "OnlyReturns".to_string(), count: 1 },
                    ],
                },
                doc_urls: vec![],
            }],
            patterns_checked: vec!["LINKER_MERGED"],
            unattributed_mismatches: 1,
        };
        let verdict = compute_verdict(&summary, &analysis, Some(97.0), 100, 100);
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
                doc_urls: vec![],
            }],
            patterns_checked: vec!["CONTROL_FLOW"],
            unattributed_mismatches: 2,
        };
        let verdict = compute_verdict(&summary, &analysis, Some(85.0), 100, 100);
        assert_eq!(verdict.classification, VerdictClassification::LikelyFixable);
        // Suggestions should include pattern-specific info
        assert!(!verdict.suggestions.is_empty());
    }

    // =========================================================================
    // New detector tests (Phase 4)
    // =========================================================================

    #[test]
    fn test_detect_makestring_template_type_mismatch() {
        // Type mismatch: PBD (const char*) vs VSymbol@@
        let instructions = vec![make_instr(
            5,
            "diff_arg",
            Some("bl"),
            Some("??$MakeString@PBDVSymbol@@H@@YA?AVString@@PBDVSymbol@@H@Z"),
            Some("bl"),
            Some("??$MakeString@PBDPBDH@@YA?AVString@@PBDPBDH@Z"),
        )];

        let pattern = detect_makestring_template_mismatch(&instructions)
            .expect("Should detect MakeString type mismatch");
        assert_eq!(pattern.pattern, PatternType::MakeStringTemplateMismatch);
        assert_eq!(pattern.instruction_count, 1);
        assert_eq!(pattern.fixability, Fixability::LikelyFixable);

        if let PatternDetails::MakeStringTemplateMismatch { mismatches } = &pattern.details {
            assert_eq!(mismatches.len(), 1);
            assert_eq!(mismatches[0].index, 5);
            assert!(matches!(mismatches[0].sub_type, MakeStringMismatchSubType::Type));
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_makestring_template_file_length() {
        // __FILE__ length mismatch: char[N] differs
        let instructions = vec![make_instr(
            3,
            "diff_arg",
            Some("bl"),
            Some("??$MakeString@D0BC@@PBDH@@YA?AVString@@D0BC@@PBDH@Z"),
            Some("bl"),
            Some("??$MakeString@D0BF@@PBDH@@YA?AVString@@D0BF@@PBDH@Z"),
        )];

        let pattern = detect_makestring_template_mismatch(&instructions)
            .expect("Should detect MakeString __FILE__ mismatch");
        assert_eq!(pattern.pattern, PatternType::MakeStringTemplateMismatch);
        assert_eq!(pattern.fixability, Fixability::RarelyHandFixable);

        if let PatternDetails::MakeStringTemplateMismatch { mismatches } = &pattern.details {
            assert!(matches!(mismatches[0].sub_type, MakeStringMismatchSubType::FileLength));
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_makestring_no_match_same_template() {
        // Same template - should NOT detect
        let instructions = vec![make_instr(
            0,
            "diff_arg",
            Some("bl"),
            Some("??$MakeString@PBDPBDH@@YA?AVString@@PBDPBDH@Z"),
            Some("bl"),
            Some("??$MakeString@PBDPBDH@@YA?AVString@@PBDPBDH@Z"),
        )];

        // This actually won't be diff_arg if they're equal, but even if it is,
        // templates match so no detection
        let pattern = detect_makestring_template_mismatch(&instructions);
        assert!(pattern.is_none());
    }

    #[test]
    fn test_detect_address_relocation_noise_lis_pair() {
        // lis + addi pair with different immediates
        let instructions = vec![
            make_instr(
                0,
                "diff_arg",
                Some("lis"),
                Some("r3, 0x8234"),
                Some("lis"),
                Some("r3, 0x8235"),
            ),
            make_instr(
                1,
                "diff_arg",
                Some("addi"),
                Some("r3, r3, 0x1000"),
                Some("addi"),
                Some("r3, r3, 0x2000"),
            ),
        ];

        let pattern = detect_address_relocation_noise(&instructions)
            .expect("Should detect address relocation noise");
        assert_eq!(pattern.pattern, PatternType::AddressRelocationNoise);
        assert_eq!(pattern.instruction_count, 2);
        assert_eq!(pattern.fixability, Fixability::RarelyHandFixable);

        if let PatternDetails::AddressRelocationNoise { info } = &pattern.details {
            assert_eq!(info.count, 2);
            assert_eq!(info.pair_count, 1);
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_address_relocation_noise_lis_only() {
        // Lone lis without matching addi
        let instructions = vec![
            make_instr(
                0,
                "diff_arg",
                Some("lis"),
                Some("r3, 0x8234"),
                Some("lis"),
                Some("r3, 0x8235"),
            ),
            make_instr(1, "equal", Some("mr"), Some("r4, r3"), Some("mr"), Some("r4, r3")),
        ];

        let pattern = detect_address_relocation_noise(&instructions)
            .expect("Should detect lone lis relocation");
        assert_eq!(pattern.instruction_count, 1);

        if let PatternDetails::AddressRelocationNoise { info } = &pattern.details {
            assert_eq!(info.count, 1);
            assert_eq!(info.pair_count, 0);
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_address_relocation_noise_none() {
        // No lis/addi diff_arg
        let instructions = vec![make_instr(
            0,
            "diff_arg",
            Some("mr"),
            Some("r3, r4"),
            Some("mr"),
            Some("r3, r5"),
        )];

        let pattern = detect_address_relocation_noise(&instructions);
        assert!(pattern.is_none());
    }

    #[test]
    fn test_detect_boolean_negation() {
        let instructions = vec![make_instr(
            5,
            "replace",
            Some("subfic"),
            Some("r3, r3, 0"),
            Some("subic"),
            Some("r3, r3, 0"),
        )];

        let pattern =
            detect_boolean_negation(&instructions).expect("Should detect boolean negation");
        assert_eq!(pattern.pattern, PatternType::BooleanNegation);
        assert_eq!(pattern.instruction_count, 1);
        assert_eq!(pattern.fixability, Fixability::RarelyHandFixable);

        if let PatternDetails::BooleanNegation { count } = &pattern.details {
            assert_eq!(*count, 1);
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_boolean_negation_reverse() {
        // subic in target, subfic in base
        let instructions = vec![make_instr(
            0,
            "replace",
            Some("subic."),
            Some("r3, r3, 0"),
            Some("subfic"),
            Some("r3, r3, 0"),
        )];

        let pattern =
            detect_boolean_negation(&instructions).expect("Should detect reverse negation");
        assert_eq!(pattern.instruction_count, 1);
    }

    #[test]
    fn test_detect_boolean_negation_none() {
        // Not a subfic/subic pair
        let instructions = vec![make_instr(
            0,
            "replace",
            Some("add"),
            Some("r3, r3, r4"),
            Some("sub"),
            Some("r3, r3, r4"),
        )];

        let pattern = detect_boolean_negation(&instructions);
        assert!(pattern.is_none());
    }

    #[test]
    fn test_detect_float_precision_mismatch() {
        let instructions = vec![
            make_instr(
                3,
                "replace",
                Some("fmul"),
                Some("f0, f1, f2"),
                Some("fmuls"),
                Some("f0, f1, f2"),
            ),
            make_instr(
                7,
                "replace",
                Some("fadds"),
                Some("f3, f3, f0"),
                Some("fadd"),
                Some("f3, f3, f0"),
            ),
        ];

        let pattern = detect_float_precision_mismatch(&instructions)
            .expect("Should detect float precision mismatch");
        assert_eq!(pattern.pattern, PatternType::FloatPrecisionMismatch);
        assert_eq!(pattern.instruction_count, 2);
        assert_eq!(pattern.fixability, Fixability::LikelyFixable);

        if let PatternDetails::FloatPrecisionMismatch { mismatches } = &pattern.details {
            assert_eq!(mismatches.len(), 2);
            assert_eq!(mismatches[0].index, 3);
            assert_eq!(mismatches[0].target_op, "fmul");
            assert_eq!(mismatches[0].base_op, "fmuls");
            assert_eq!(mismatches[1].index, 7);
            assert_eq!(mismatches[1].target_op, "fadds");
            assert_eq!(mismatches[1].base_op, "fadd");
        } else {
            panic!("Wrong details type");
        }
    }

    #[test]
    fn test_detect_float_precision_mismatch_all_pairs() {
        // Test each known pair
        for (double, single) in &[
            ("fmul", "fmuls"),
            ("fadd", "fadds"),
            ("fsub", "fsubs"),
            ("fmadd", "fmadds"),
            ("fmsub", "fmsubs"),
            ("fnmadd", "fnmadds"),
            ("fnmsub", "fnmsubs"),
        ] {
            let instructions = vec![make_instr(
                0,
                "replace",
                Some(double),
                Some("f0, f1, f2"),
                Some(single),
                Some("f0, f1, f2"),
            )];
            let pattern = detect_float_precision_mismatch(&instructions);
            assert!(
                pattern.is_some(),
                "Should detect {} vs {} pair",
                double, single
            );
        }
    }

    #[test]
    fn test_detect_float_precision_mismatch_none() {
        // Not a precision pair — different float instructions
        let instructions = vec![make_instr(
            0,
            "replace",
            Some("fmul"),
            Some("f0, f1, f2"),
            Some("fadd"),
            Some("f0, f1, f2"),
        )];

        let pattern = detect_float_precision_mismatch(&instructions);
        assert!(pattern.is_none(), "fmul vs fadd is not a precision pair");
    }

    #[test]
    fn test_detect_signedness_mismatch_per_pair() {
        // Each named signed/unsigned pair, in both target/base directions,
        // must detect at HIGH confidence with exactly one attributed row.
        let pairs = [("lha", "lhz"), ("srawi", "srwi"), ("cmpw", "cmplw"), ("extsb", "extsh")];
        for (signed, unsigned) in pairs {
            for (t_op, b_op) in [(signed, unsigned), (unsigned, signed)] {
                let instructions = vec![make_instr(
                    0,
                    "replace",
                    Some(t_op),
                    Some("r3, r4, r5"),
                    Some(b_op),
                    Some("r3, r4, r5"),
                )];
                let pattern = detect_signedness_mismatch(&instructions)
                    .unwrap_or_else(|| panic!("should detect {t_op} vs {b_op}"));
                assert_eq!(pattern.pattern, PatternType::SignednessMismatch);
                assert_eq!(pattern.confidence, Confidence::High, "{t_op} vs {b_op}");
                assert_eq!(pattern.instruction_count, 1, "{t_op} vs {b_op}");
                if let PatternDetails::SignednessMismatch { mismatches } = &pattern.details {
                    assert_eq!(mismatches.len(), 1);
                    assert_eq!(mismatches[0].signed_op, signed);
                    assert_eq!(mismatches[0].unsigned_op, unsigned);
                    assert_eq!(mismatches[0].target_op, t_op);
                    assert_eq!(mismatches[0].base_op, b_op);
                } else {
                    panic!("wrong details variant for {t_op} vs {b_op}");
                }
            }
        }
    }

    #[test]
    fn test_detect_signedness_mismatch_equal_function_no_detection() {
        // An all-`equal` function — including rows carrying the signed opcodes
        // matched on BOTH sides — must yield ZERO detections. `equal` rows are
        // never inspected, so identical signed opcodes are not a mismatch.
        let instructions = vec![
            make_instr(0, "equal", Some("lha"), Some("r3, 0(r4)"), Some("lha"), Some("r3, 0(r4)")),
            make_instr(1, "equal", Some("cmpw"), Some("cr0, r3, r4"), Some("cmpw"), Some("cr0, r3, r4")),
            make_instr(2, "equal", Some("srawi"), Some("r3, r3, 2"), Some("srawi"), Some("r3, r3, 2")),
            make_instr(3, "equal", Some("extsb"), Some("r3, r3"), Some("extsb"), Some("r3, r3")),
        ];
        assert!(
            detect_signedness_mismatch(&instructions).is_none(),
            "equal-function fixture must produce zero signedness detections"
        );
    }

    #[test]
    fn test_detect_signedness_mismatch_non_pair_no_detection() {
        // A `replace` row whose opcodes are NOT a known signed/unsigned pair
        // (lha vs lwz — both loads, but not a signedness counterpart) must not
        // fire. Guards against over-broad matching.
        let instructions = vec![
            make_instr(0, "replace", Some("lha"), Some("r3, 0(r4)"), Some("lwz"), Some("r3, 0(r4)")),
            make_instr(1, "replace", Some("cmpw"), Some("cr0, r3, r4"), Some("cmpwi"), Some("cr0, r3, 0")),
        ];
        assert!(
            detect_signedness_mismatch(&instructions).is_none(),
            "non-pair replace rows must not be flagged as signedness mismatches"
        );
    }

    #[test]
    fn test_detect_signedness_mismatch_multiple_and_analyze() {
        // Multiple distinct pairs across a function accumulate; analyze_instructions
        // surfaces the pattern and always lists it in patterns_checked.
        let instructions = vec![
            make_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_instr(1, "replace", Some("lha"), Some("r3, 0(r4)"), Some("lhz"), Some("r3, 0(r4)")),
            make_instr(2, "replace", Some("cmplw"), Some("cr0, r3, r4"), Some("cmpw"), Some("cr0, r3, r4")),
        ];
        let pattern = detect_signedness_mismatch(&instructions).expect("should detect");
        assert_eq!(pattern.instruction_count, 2);

        let analysis = analyze_instructions(&instructions);
        assert!(analysis.patterns_checked.contains(&"SIGNEDNESS_MISMATCH"));
        assert!(analysis.has_pattern(PatternType::SignednessMismatch));
    }

    #[test]
    fn test_analyze_instructions_includes_phase4_patterns() {
        let instructions =
            vec![make_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4"))];

        let analysis = analyze_instructions(&instructions);
        assert!(analysis.patterns_checked.contains(&"MAKESTRING_TEMPLATE_MISMATCH"));
        assert!(analysis.patterns_checked.contains(&"ADDRESS_RELOCATION_NOISE"));
        assert!(analysis.patterns_checked.contains(&"BOOLEAN_NEGATION"));
        assert!(analysis.patterns_checked.contains(&"FLOAT_PRECISION_MISMATCH"));
        assert!(analysis.patterns_checked.contains(&"FSEL_TERNARY"));
        assert!(analysis.patterns_checked.contains(&"FLOAT_TO_INT_TO_FLOAT"));
    }

    #[test]
    fn test_detect_fsel_ternary() {
        let instructions = vec![
            make_instr(0, "replace", Some("fneg"), Some("f0, f1"), Some("fneg"), Some("f0, f1")),
            make_instr(1, "replace", Some("fsel"), Some("f1, f0, f12, f1"), Some("fsel"), Some("f1, f0, f12, f1")),
        ];
        let pattern = detect_fsel_ternary(&instructions).expect("Should detect fsel ternary");
        assert_eq!(pattern.pattern, PatternType::FselTernary);
        assert_eq!(pattern.instruction_count, 1);
    }

    #[test]
    fn test_detect_float_to_int_to_float() {
        let instructions = vec![
            make_instr(0, "replace", Some("fctiwz"), Some("f0, f1"), Some("fctiwz"), Some("f0, f1")),
            make_instr(1, "replace", Some("stfd"), Some("f0, 0x58(r31)"), Some("stfd"), Some("f0, 0x58(r31)")),
        ];
        let pattern = detect_float_to_int_to_float(&instructions).expect("Should detect float-to-int-to-float");
        assert_eq!(pattern.pattern, PatternType::FloatToIntToFloat);
        assert_eq!(pattern.instruction_count, 1);
    }

    #[test]
    fn test_verdict_at_limit_address_relocation() {
        let summary = InstructionSummary {
            total: 10,
            equal: 5,
            diff_arg: 5,
            ..Default::default()
        };
        let analysis = Analysis {
            patterns: vec![Pattern {
                pattern: PatternType::AddressRelocationNoise,
                confidence: Confidence::High,
                instruction_count: 4, // 4/5 = 80%
                fixability: Fixability::RarelyHandFixable,
                details: PatternDetails::AddressRelocationNoise {
                    info: AddressRelocationInfo { count: 4, pair_count: 2 },
                },
                doc_urls: vec![],
            }],
            patterns_checked: vec!["ADDRESS_RELOCATION_NOISE"],
            unattributed_mismatches: 1,
        };

        let verdict = compute_verdict(&summary, &analysis, Some(95.0), 100, 100);
        assert_eq!(verdict.classification, VerdictClassification::AtLimit);
        assert!(verdict.explanation.contains("address-relocation"));
    }

    #[test]
    fn test_verdict_likely_fixable_makestring_type() {
        let summary = InstructionSummary {
            total: 10,
            equal: 7,
            diff_arg: 3,
            ..Default::default()
        };
        let analysis = Analysis {
            patterns: vec![Pattern {
                pattern: PatternType::MakeStringTemplateMismatch,
                confidence: Confidence::High,
                instruction_count: 2,
                fixability: Fixability::LikelyFixable,
                details: PatternDetails::MakeStringTemplateMismatch {
                    mismatches: vec![
                        MakeStringMismatchInfo {
                            index: 2,
                            target_template: "PBDVSymbol@@H@@".to_string(),
                            base_template: "PBDPBDH@@".to_string(),
                            sub_type: MakeStringMismatchSubType::Type,
                        },
                        MakeStringMismatchInfo {
                            index: 5,
                            target_template: "PBDVSymbol@@H@@".to_string(),
                            base_template: "PBDPBDH@@".to_string(),
                            sub_type: MakeStringMismatchSubType::Type,
                        },
                    ],
                },
                doc_urls: vec![],
            }],
            patterns_checked: vec!["MAKESTRING_TEMPLATE_MISMATCH"],
            unattributed_mismatches: 1,
        };

        let verdict = compute_verdict(&summary, &analysis, Some(90.0), 100, 100);
        assert_eq!(verdict.classification, VerdictClassification::LikelyFixable);
        assert!(verdict.explanation.contains("MakeString"));
        assert!(verdict.suggestions.iter().any(|s| s.action.contains(".Str()")));
    }

    #[test]
    fn test_verdict_high_match_register_swap_recommends_permuter() {
        // 99%+ match with only register swaps used to be classified AtLimit,
        // but regswaps are permuter-class — the verdict should now nudge the
        // user toward a permuter sweep before accepting.
        let summary = InstructionSummary {
            total: 100,
            equal: 95,
            diff_arg: 5,
            ..Default::default()
        };
        let analysis = Analysis {
            patterns: vec![Pattern {
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
                doc_urls: vec![],
            }],
            patterns_checked: vec!["REGISTER_SWAP"],
            unattributed_mismatches: 0,
        };

        let verdict = compute_verdict(&summary, &analysis, Some(99.0), 100, 100);
        // High-match register swaps are MaybeFixable (permuter can crack them)
        // rather than AtLimit — the permuter should be given a chance first.
        assert_eq!(verdict.classification, VerdictClassification::MaybeFixable);
    }

    #[test]
    fn test_verdict_maybe_fixable_register_swap_low_match() {
        // Low match% with register swaps → still MaybeFixable
        let summary = InstructionSummary {
            total: 100,
            equal: 80,
            diff_arg: 20,
            ..Default::default()
        };
        let analysis = Analysis {
            patterns: vec![Pattern {
                pattern: PatternType::RegisterSwap,
                confidence: Confidence::High,
                instruction_count: 20,
                fixability: Fixability::MaybeFixable,
                details: PatternDetails::RegisterSwap {
                    swaps: vec![RegisterSwapInfo {
                        target_reg: "r30".to_string(),
                        base_reg: "r31".to_string(),
                        count: 20,
                    }],
                },
                doc_urls: vec![],
            }],
            patterns_checked: vec!["REGISTER_SWAP"],
            unattributed_mismatches: 0,
        };

        let verdict = compute_verdict(&summary, &analysis, Some(80.0), 100, 100);
        assert_eq!(verdict.classification, VerdictClassification::MaybeFixable);
    }
}
