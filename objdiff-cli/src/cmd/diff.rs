use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufWriter, Write, stdout},
    mem,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Wake, Waker},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use argp::FromArgs;
use crossterm::{
    event,
    event::{DisableMouseCapture, EnableMouseCapture},
    terminal::{
        EnterAlternateScreen, LeaveAlternateScreen, SetTitle, disable_raw_mode, enable_raw_mode,
    },
};
use objdiff_core::{
    bindings::diff::DiffResult,
    build::{
        BuildConfig, BuildStatus,
        watcher::{Watcher, create_watcher},
    },
    config::{
        ProjectConfig, ProjectObject, ProjectObjectMetadata, ProjectOptions, apply_project_options,
        build_globset,
        path::{check_path_buf, platform_path, platform_path_serde_option},
    },
    diff::{
        self, DiffObjConfig, DiffSide, InstructionDiffKind, InstructionDiffRow, MappingConfig,
        ObjectDiff, SymbolDiff,
    },
    jobs::{
        Job, JobQueue, JobResult,
        objdiff::{ObjDiffConfig, start_build},
    },
    obj::{self, Object, Symbol},
};
use ratatui::prelude::*;
use serde::Serialize;
use typed_path::{Utf8PlatformPath, Utf8PlatformPathBuf};

use crate::{
    cmd::apply_config_args,
    util::term::crossterm_panic_handler,
    views::{EventControlFlow, EventResult, UiView, function_diff::FunctionDiffUi},
};

// Output format enum for diff command
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiffOutputFormat {
    #[default]
    Tui,
    Json,
    JsonPretty,
    Markdown,
    Proto,
}

impl DiffOutputFormat {
    fn from_option(s: Option<&str>) -> Result<Self> {
        match s {
            Some("tui") => Ok(Self::Tui),
            Some("json") => Ok(Self::Json),
            Some("json-pretty") | Some("json_pretty") => Ok(Self::JsonPretty),
            None | Some("markdown") | Some("md") => Ok(Self::Markdown), // markdown is now default
            Some("proto") => Ok(Self::Proto),
            Some(other) => {
                bail!(
                    "Invalid output format: {}. Supported: markdown (default), tui, json, json-pretty, proto",
                    other
                )
            }
        }
    }

    fn is_json(&self) -> bool {
        matches!(self, Self::Json | Self::JsonPretty)
    }

    fn is_non_tui(&self) -> bool {
        !matches!(self, Self::Tui)
    }
}

// JSON output structures

/// Typed argument representation for JSON output.
/// Preserves type information from objdiff-core's InstructionArg.
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type", content = "value")]
pub enum TypedArg {
    /// Signed integer value
    Signed(i64),
    /// Unsigned integer value
    Unsigned(u64),
    /// Register name (opaque values that look like registers)
    Register(String),
    /// Symbol reference from relocation
    Symbol(String),
    /// Branch destination address
    BranchDest(u64),
    /// Other opaque values (labels, etc.)
    Other(String),
}

impl TypedArg {
    /// Check if this is a register argument.
    /// Used by analysis pattern detection and external consumers.
    #[allow(dead_code)]
    pub fn is_register(&self) -> bool {
        matches!(self, TypedArg::Register(_))
    }

    /// Check if this is a numeric value (signed or unsigned).
    /// Used by analysis pattern detection and external consumers.
    #[allow(dead_code)]
    pub fn is_numeric(&self) -> bool {
        matches!(self, TypedArg::Signed(_) | TypedArg::Unsigned(_))
    }

    /// Get the numeric value if this is a signed or unsigned arg.
    /// Used by analysis pattern detection for value comparisons.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            TypedArg::Signed(v) => Some(*v),
            TypedArg::Unsigned(v) => Some(*v as i64),
            _ => None,
        }
    }
}

#[derive(Serialize)]
pub struct DiffOutput {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    pub target_size: u64,
    pub base_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fuzzy_match_percent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_match_percent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_match_percent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_score: Option<DiffScoreOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_status: Option<BuildStatusOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_summary: Option<InstructionSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<super::analysis::Analysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<super::analysis::Verdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_diff: Option<super::analysis::CallDiffOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insert_delete_clusters: Option<Vec<super::analysis::InsertDeleteCluster>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_regions: Option<Vec<super::analysis::DiffRegion>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<Vec<InstructionDiffOutput>>,
    /// Number of instruction rows scored `equal` only because a normalization
    /// erased a real byte/relocation difference. Disclosure only — this does
    /// NOT change any match percent. 0 for a clean match.
    pub masked_equal_rows: u32,
    /// Subset of `masked_equal_rows` attributable to relocation-mode relaxation
    /// (`functionRelocDiffs=none` skipping a reloc, or NameOnly ignoring the
    /// addend). The #1 masking channel — a `bl` to a different callee.
    pub reloc_ignored_rows: u32,
    /// Disclosure: this symbol was *paired* only by the MSVC EH funclet
    /// byte-signature fallback (masked reloc bytes and/or many-to-one
    /// over-subscription), not by a name match — its identity rests on a
    /// symbol-level normalization. Does NOT change any match percent. Always
    /// serialized (false for a name-matched symbol) so old consumers degrade
    /// cleanly.
    pub masked_equal_symbol: bool,
    /// Byte/relocation diff for data symbols (populated with --include-data).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_diff: Option<DataDiffOutput>,
}

#[derive(Serialize)]
pub struct DiffScoreOutput {
    pub score: u64,
    pub max_score: u64,
}

/// Byte- and relocation-level diff for a data symbol, from the perspective of
/// the resolved side. Diff kinds ("replace"/"insert"/"delete") are relative to
/// the matched symbol on the other side.
#[derive(Serialize)]
pub struct DataDiffOutput {
    /// Byte-and-relocation-weighted match percent for the symbol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_percent: Option<f32>,
    /// Number of differing bytes (replace/insert/delete) on this side.
    pub mismatch_byte_count: usize,
    /// Total bytes in the symbol on this side.
    pub total_byte_count: usize,
    /// Contiguous byte runs, in order, each tagged with a diff kind. Equal runs
    /// are included (without `bytes`) so offsets stay unambiguous; differing
    /// runs carry their hex bytes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub segments: Vec<DataSegmentOutput>,
    /// Relocations within the symbol and whether each matches the other side.
    /// The most actionable signal for data symbols (vtables, pointer tables).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub relocations: Vec<DataRelocationOutput>,
}

#[derive(Serialize)]
pub struct DataSegmentOutput {
    /// Byte offset from the start of the symbol.
    pub offset: usize,
    pub size: usize,
    /// "equal", "replace", "insert", or "delete".
    pub kind: String,
    /// Hex of the bytes on the resolved side (omitted for equal runs and for
    /// inserts, which have no bytes on this side).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    /// Hex of the bytes on the matched (base/other) side, when a match exists
    /// and they differ from this side — lets string/init-value diffs be
    /// compared directly. Omitted for equal runs, one-sided diffs, and deletes
    /// (which have no bytes on the other side).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_bytes: Option<String>,
}

#[derive(Serialize)]
pub struct DataRelocationOutput {
    /// Byte offset from the start of the symbol.
    pub offset: u64,
    pub size: u64,
    /// "equal", "replace", "insert", or "delete".
    pub kind: String,
    /// Name of the symbol this relocation points to on the resolved side.
    /// Empty for base-only ("insert") relocations.
    pub target_symbol: String,
    /// Relocation addend (omitted when zero).
    #[serde(skip_serializing_if = "is_zero")]
    pub addend: i64,
    /// Symbol the matched base-side relocation points to, when it differs from
    /// `target_symbol` (a "replace" — e.g. a vtable slot resolving to a
    /// different function) or the relocation exists only on the base side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_target_symbol: Option<String>,
    /// Base-side addend, when a matched base relocation has a different addend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_addend: Option<i64>,
}

fn is_zero(v: &i64) -> bool { *v == 0 }

fn is_false(v: &bool) -> bool { !*v }

fn data_diff_kind_str(kind: objdiff_core::diff::DataDiffKind) -> &'static str {
    use objdiff_core::diff::DataDiffKind;
    match kind {
        DataDiffKind::None => "equal",
        DataDiffKind::Replace => "replace",
        DataDiffKind::Insert => "insert",
        DataDiffKind::Delete => "delete",
    }
}

#[derive(Serialize)]
pub struct BuildStatusOutput {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

/// Detailed breakdown of a single argument difference.
#[derive(Serialize, Clone)]
pub struct ArgumentDiff {
    /// Index of the argument in the instruction (0-based).
    pub index: usize,
    /// Type of argument: "register", "immediate", "symbol", "branch_dest", or "other".
    pub arg_type: String,
    /// The target (reference) value.
    pub target: TypedArg,
    /// The base (decompiled) value.
    pub base: TypedArg,
}

/// Breakdown of all differing arguments in an instruction.
#[derive(Serialize, Clone)]
pub struct InstructionDiffBreakdown {
    /// List of arguments that differ between target and base.
    pub arguments: Vec<ArgumentDiff>,
}

/// Control-flow edge: the instruction rows that branch TO this row.
/// Populated from objdiff-core's per-symbol branch graph; `source_indices`
/// are `index` values within the same diff's instruction list.
#[derive(Serialize, Clone)]
pub struct BranchFrom {
    /// Row indices of instructions that branch to this row.
    pub source_indices: Vec<u32>,
    /// Color/group index objdiff assigns this branch for visualization.
    pub branch_idx: u32,
}

/// Control-flow edge: the instruction row this row branches TO.
#[derive(Serialize, Clone)]
pub struct BranchTo {
    /// Row index of the branch target.
    pub target_index: u32,
    /// Color/group index objdiff assigns this branch for visualization.
    pub branch_idx: u32,
}

#[derive(Serialize)]
pub struct InstructionDiffOutput {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<InstructionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<InstructionInfo>,
    pub match_type: String,
    /// Disclosure: this row was scored `equal` only because a normalization
    /// (reloc-mode relaxation, FP-anchor slip compensation) erased a real
    /// difference. Omitted when false. Never affects the score.
    #[serde(default, skip_serializing_if = "is_false")]
    pub masked_equal: bool,
    /// Detailed breakdown of which arguments differ (only for diff_arg type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_breakdown: Option<InstructionDiffBreakdown>,
    /// Control-flow: rows that branch to this one on the target (reference) side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_branch_from: Option<BranchFrom>,
    /// Control-flow: the row this one branches to on the target (reference) side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_branch_to: Option<BranchTo>,
    /// Control-flow: rows that branch to this one on the base (decompiled) side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_branch_from: Option<BranchFrom>,
    /// Control-flow: the row this one branches to on the base (decompiled) side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_branch_to: Option<BranchTo>,
}

#[derive(Serialize, Clone)]
pub struct InstructionInfo {
    pub address: String,
    pub opcode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    /// Typed arguments preserving type information from objdiff-core.
    /// New in v3.6+: provides structured access to instruction arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typed_args: Option<Vec<TypedArg>>,
    /// Branch destination address if this instruction is a branch.
    /// Populated from InstructionArg::BranchDest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_dest: Option<u64>,
    /// Source line number from DWARF debug info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    /// Source file path from DWARF debug info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
}

/// Result of analyzing a single symbol for the batch analyze command.
/// Fields are accessed by the report module.
#[derive(Debug)]
#[allow(dead_code)]
pub struct SymbolAnalysisResult {
    pub symbol: String,
    pub demangled: Option<String>,
    pub match_percent: Option<f32>,
    pub size: u64,
    pub instruction_summary: InstructionSummary,
    pub analysis: super::analysis::Analysis,
    pub verdict: super::analysis::Verdict,
}

/// Summary of instruction match types for quick fixability assessment
#[derive(Serialize, Default, Debug, Clone)]
pub struct InstructionSummary {
    pub total: usize,
    pub equal: usize,
    pub diff_arg: usize,
    pub diff_op: usize,
    pub replace: usize,
    pub delete: usize,
    pub insert: usize,
    pub equal_percent: f32,
    pub mismatch_percent: f32,
}

/// Options for markdown rendering
#[derive(Default)]
pub struct MarkdownOptions {
    /// Show N instructions of context before/after each mismatch
    pub context: Option<usize>,
    /// Show all instructions, not just mismatches
    pub full_listing: bool,
    /// Concise output: match%, compact summary, pattern one-liners, verdict headline
    pub concise: bool,
}

impl InstructionSummary {
    pub fn from_instructions(instructions: &[InstructionDiffOutput]) -> Self {
        let mut s = Self::default();
        for instr in instructions {
            s.total += 1;
            match instr.match_type.as_str() {
                "equal" => s.equal += 1,
                "diff_arg" => s.diff_arg += 1,
                "diff_op" => s.diff_op += 1,
                "replace" => s.replace += 1,
                "delete" => s.delete += 1,
                "insert" => s.insert += 1,
                _ => {}
            }
        }
        let total = s.total.max(1) as f32;
        s.equal_percent = (s.equal as f32 / total) * 100.0;
        s.mismatch_percent = 100.0 - s.equal_percent;
        s
    }
}

fn match_type_str(kind: InstructionDiffKind) -> &'static str {
    match kind {
        InstructionDiffKind::None => "equal",
        InstructionDiffKind::OpMismatch => "diff_op",
        InstructionDiffKind::ArgMismatch => "diff_arg",
        InstructionDiffKind::Replace => "replace",
        InstructionDiffKind::Delete => "delete",
        InstructionDiffKind::Insert => "insert",
    }
}

#[derive(FromArgs, PartialEq, Debug)]
/// Diff two object files. (Interactive or one-shot mode)
#[argp(subcommand, name = "diff")]
pub struct Args {
    #[argp(option, short = '1', from_str_fn(platform_path))]
    /// Target object file
    target: Option<Utf8PlatformPathBuf>,
    #[argp(option, short = '2', from_str_fn(platform_path))]
    /// Base object file
    base: Option<Utf8PlatformPathBuf>,
    #[argp(option, short = 'p', from_str_fn(platform_path))]
    /// Project directory
    project: Option<Utf8PlatformPathBuf>,
    #[argp(option, short = 'u')]
    /// Unit name within project
    unit: Option<String>,
    #[argp(option, short = 'o', from_str_fn(platform_path))]
    /// Output file ("-" for stdout, requires --format)
    output: Option<Utf8PlatformPathBuf>,
    #[argp(option, short = 'f')]
    /// Output format: markdown (default), tui, json, json-pretty
    format: Option<String>,
    #[argp(positional)]
    /// Function symbol to diff
    symbol: Option<String>,
    #[argp(option, short = 'c')]
    /// Configuration property (key=value)
    config: Vec<String>,
    #[argp(switch)]
    /// Include instruction-level diff in output
    include_instructions: bool,
    #[argp(switch)]
    /// Include data section diff in output
    include_data: bool,
    #[argp(switch)]
    /// Include instruction match type summary (requires --include-instructions)
    summary: bool,
    #[argp(switch)]
    /// Analyze patterns in instruction mismatches (implies --summary)
    analyze: bool,
    #[argp(switch)]
    /// Include fixability verdict (implies --analyze)
    verdict: bool,
    #[argp(switch)]
    /// Rebuild object file before diffing (runs ninja)
    build: bool,
    #[argp(switch)]
    /// Perform full project build instead of incremental (requires --build)
    full_build: bool,
    #[argp(switch)]
    /// Use incremental build targeting specific .obj file (default when using --build)
    incremental: bool,
    #[argp(option, from_str_fn(platform_path))]
    /// Path to MSVC linker map file for ICF symbol equivalence
    map_file: Option<Utf8PlatformPathBuf>,
    #[argp(option, short = 'C')]
    /// Show N instructions of context before/after each mismatch (like grep -C)
    context: Option<usize>,
    #[argp(switch)]
    /// Show all instructions in output, not just mismatches (implies --include-instructions)
    full_listing: bool,
    #[argp(switch)]
    /// Concise output: match%, compact summary, pattern one-liners, verdict headline
    concise: bool,
    #[argp(switch)]
    /// Batch mode: read symbols from stdin (one per line), group by unit, output JSONL
    batch: bool,
}

pub fn run(args: Args) -> Result<()> {
    // Pin the doc-link project identity before any analysis runs. `--project`
    // when given, otherwise detection walks up from the working directory.
    super::analysis::init_doc_project(
        args.project.as_ref().map(|p| std::path::Path::new(p.as_str())),
    );

    if args.batch {
        return run_batch(args);
    }

    let (target_path, base_path, project_config, unit_options, project_dir) = match (
        &args.target,
        &args.base,
        &args.project,
        &args.unit,
    ) {
        (Some(_), Some(_), None, None)
        | (Some(_), None, None, None)
        | (None, Some(_), None, None) => (args.target.clone(), args.base.clone(), None, None, None),
        (None, None, p, u) => {
            let project = match p {
                Some(project) => project.clone(),
                _ => check_path_buf(
                    std::env::current_dir().context("Failed to get the current directory")?,
                )
                .context("Current directory is not valid UTF-8")?,
            };
            let Some((project_config, project_config_info)) =
                objdiff_core::config::try_project_config(project.as_ref())
            else {
                bail!("Project config not found in {}", &project)
            };
            let project_config = project_config.with_context(|| {
                format!("Reading project config {}", project_config_info.path.display())
            })?;
            let target_obj_dir = project_config
                .target_dir
                .as_ref()
                .map(|p| project.join(p.with_platform_encoding()));
            let base_obj_dir =
                project_config.base_dir.as_ref().map(|p| project.join(p.with_platform_encoding()));
            let units = project_config.units.as_deref().unwrap_or_default();
            let objects = units
                .iter()
                .enumerate()
                .map(|(idx, o)| {
                    (
                        ObjectConfig::new(
                            o,
                            &project,
                            target_obj_dir.as_deref(),
                            base_obj_dir.as_deref(),
                        ),
                        idx,
                    )
                })
                .collect::<Vec<_>>();
            let (object, unit_idx) = if let Some(u) = u {
                // Try exact match first (fast path, preserves any agent that
                // passes the canonical name).
                let exact = objects.iter().find(|(obj, _)| obj.name == *u);
                if let Some((obj, idx)) = exact {
                    (obj, *idx)
                } else {
                    // Suffix/contains match: accept "system/synth/MidiSynth"
                    // or just "MidiSynth" when the canonical name is
                    // "main/system/synth/MidiSynth". Match priority:
                    //   1. Path-component suffix: name == u OR name ends with "/" + u
                    //   2. Basename-only match: final path segment == u
                    //   3. Substring fallback (only if previous yields nothing)
                    let needle = u.as_str();
                    let suffix_pattern = format!("/{}", needle);
                    let mut suffix_hits: Vec<_> = objects
                        .iter()
                        .filter(|(obj, _)| obj.name.ends_with(&suffix_pattern))
                        .collect();
                    if suffix_hits.is_empty() {
                        // Basename match: final segment equals needle (handles
                        // single-token names like "MidiSynth")
                        suffix_hits = objects
                            .iter()
                            .filter(|(obj, _)| {
                                obj.name.rsplit('/').next() == Some(needle)
                            })
                            .collect();
                    }
                    if suffix_hits.is_empty() {
                        // Last resort: substring anywhere in the name.
                        suffix_hits = objects
                            .iter()
                            .filter(|(obj, _)| obj.name.contains(needle))
                            .collect();
                    }
                    match suffix_hits.len() {
                        0 => {
                            return Err(anyhow!(
                                "Unit not found: {}\n\
                                 Hint: pass a path-suffix (e.g. `system/synth/MidiSynth`) \
                                 or basename (e.g. `MidiSynth`) — these resolve against \
                                 the project's full unit names (e.g. `main/system/synth/MidiSynth`).",
                                u
                            ));
                        }
                        1 => {
                            let (obj, idx) = suffix_hits[0];
                            // Tell the user what we resolved to so they can
                            // copy the canonical name into scripts if needed.
                            // Skip the hint when input already equals the canonical name.
                            if obj.name != *u {
                                eprintln!(
                                    "objdiff: resolved unit `{}` -> `{}`",
                                    u, obj.name
                                );
                            }
                            (obj, *idx)
                        }
                        n => {
                            let mut names: Vec<&str> =
                                suffix_hits.iter().map(|(obj, _)| obj.name.as_str()).collect();
                            names.sort();
                            let preview: Vec<&&str> = names.iter().take(8).collect();
                            let trailer = if n > 8 {
                                format!("\n  ... and {} more", n - 8)
                            } else {
                                String::new()
                            };
                            return Err(anyhow!(
                                "Ambiguous unit `{}`: {} matches.\n  {}{}\n\
                                 Use a longer suffix or the canonical name.",
                                u,
                                n,
                                preview
                                    .iter()
                                    .map(|s| s.to_string())
                                    .collect::<Vec<_>>()
                                    .join("\n  "),
                                trailer
                            ));
                        }
                    }
                }
            } else if let Some(symbol_name) = &args.symbol {
                // Build a minimal diff config for demangling during symbol lookup
                let mut lookup_config = DiffObjConfig::default();
                if let Some(options) = project_config.options.as_ref() {
                    let _ = apply_project_options(&mut lookup_config, options);
                }
                let _ = apply_config_args(&mut lookup_config, &args.config);

                // First, try exact match on mangled name (fast path)
                let mut idx = None;
                let mut count = 0usize;
                for (i, (obj, unit_idx)) in objects.iter().enumerate() {
                    if obj
                        .target_path
                        .as_deref()
                        .map(|o| obj::read::has_function(o.as_ref(), symbol_name))
                        .transpose()?
                        .unwrap_or(false)
                    {
                        idx = Some((i, *unit_idx, symbol_name.clone()));
                        count += 1;
                        if count > 1 {
                            break;
                        }
                    }
                }

                // If no exact match, try demangled matching
                if count == 0 {
                    let mut exact_matches: Vec<(usize, usize, obj::read::SymbolMatch)> = Vec::new();
                    let mut partial_matches: Vec<(usize, usize, obj::read::SymbolMatch)> =
                        Vec::new();

                    for (i, (obj, unit_idx)) in objects.iter().enumerate() {
                        if let Some(target_path) = obj.target_path.as_deref() {
                            let matches = obj::read::match_symbol_by_query(
                                target_path.as_ref(),
                                symbol_name,
                                &lookup_config,
                            )?;
                            for m in matches {
                                if m.exact {
                                    exact_matches.push((i, *unit_idx, m));
                                } else {
                                    partial_matches.push((i, *unit_idx, m));
                                }
                            }
                        }
                    }

                    // Prefer exact matches, fall back to partial if there's exactly one
                    let all_matches =
                        if !exact_matches.is_empty() { exact_matches } else { partial_matches };

                    match all_matches.len() {
                        0 => bail!("Symbol not found: {}", symbol_name),
                        1 => {
                            let (i, unit_idx, m) = all_matches.into_iter().next().unwrap();
                            idx = Some((i, unit_idx, m.name));
                            count = 1;
                        }
                        _ => {
                            // Multiple matches - show disambiguation
                            eprintln!("Multiple matches for '{}'. Did you mean:", symbol_name);
                            for (_, unit_idx, m) in &all_matches {
                                let unit_name = &units[*unit_idx].name();
                                let display_name = m.demangled.as_ref().unwrap_or(&m.name);
                                eprintln!("  {} ({})", display_name, unit_name);
                            }
                            bail!(
                                "Ambiguous symbol '{}'. Use --unit or provide more specific name.",
                                symbol_name
                            );
                        }
                    }
                }

                match (count, idx) {
                    (0, None) => bail!("Symbol not found: {}", symbol_name),
                    (1, Some((i, unit_idx, _resolved_name))) => (&objects[i].0, unit_idx),
                    (2.., Some(_)) => bail!(
                        "Multiple instances of {} were found, try specifying a unit",
                        symbol_name
                    ),
                    _ => unreachable!(),
                }
            } else {
                bail!("Must specify one of: symbol, project and unit, target and base objects")
            };
            let unit_options = units.get(unit_idx).and_then(|u| u.options().cloned());
            let target_path = object.target_path.clone();
            let base_path = object.base_path.clone();
            (target_path, base_path, Some(project_config), unit_options, Some(project))
        }
        _ => bail!("Either target and base or project and unit must be specified"),
    };

    let output_format = DiffOutputFormat::from_option(args.format.as_deref())?;

    // Run ninja build if requested (builds the base/decompiled object, not the target/reference)
    if args.build {
        if let Some(base) = &base_path {
            // Determine build mode: incremental (default) or full
            let use_incremental = !args.full_build;

            if use_incremental {
                // Incremental build: target specific .obj file
                // Convert absolute paths to relative for ninja compatibility
                let build_target = if base.is_absolute() {
                    // Try to make it relative to current directory
                    std::path::Path::new(base.as_str())
                        .strip_prefix(std::env::current_dir()?)
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| base.to_string())
                } else {
                    base.to_string()
                };

                eprintln!("Building incremental: {}", build_target);
                let status = Command::new("ninja")
                    .arg(&build_target)
                    .status()
                    .context("Failed to run ninja")?;

                if !status.success() {
                    bail!("Incremental build failed for {}", build_target);
                }
            } else {
                // Full build: build entire project
                eprintln!("Building full project (--full-build specified)...");
                let status = Command::new("ninja").status().context("Failed to run ninja")?;

                if !status.success() {
                    bail!("Full build failed");
                }
            }
        } else {
            bail!("--build requires a base path (use -p with a project that has base_path set)");
        }
    }

    // Validate output file is only used with non-TUI formats
    if args.output.is_some() && !output_format.is_non_tui() {
        bail!("--output can only be used with --format json, json-pretty, markdown, or proto");
    }

    match output_format {
        DiffOutputFormat::Tui => {
            run_interactive(args, target_path, base_path, project_config, unit_options, project_dir)
        }
        DiffOutputFormat::Proto => {
            // Use upstream oneshot mode for proto output (binding format)
            let output = args.output.as_deref().unwrap_or(Utf8PlatformPath::new("-"));
            run_oneshot(
                &args,
                output,
                target_path.as_deref(),
                base_path.as_deref(),
                unit_options,
                project_dir.as_deref(),
            )
        }
        _ => {
            // Use enhanced JSON/markdown output with analysis support
            run_json(
                args,
                target_path,
                base_path,
                project_config,
                unit_options,
                output_format,
                project_dir,
            )
        }
    }
}

fn run_oneshot(
    args: &Args,
    output: &Utf8PlatformPath,
    target_path: Option<&Utf8PlatformPath>,
    base_path: Option<&Utf8PlatformPath>,
    unit_options: Option<ProjectOptions>,
    project_dir: Option<&Utf8PlatformPath>,
) -> Result<()> {
    use crate::util::output::{OutputFormat, write_output};
    let output_format = OutputFormat::Proto; // Proto is the only format that uses oneshot
    let (diff_config, mapping_config) =
        build_config_from_args(args, None, unit_options.as_ref(), project_dir)?;
    let target = target_path
        .map(|p| {
            obj::read::read(p.as_ref(), &diff_config, DiffSide::Target)
                .with_context(|| format!("Loading {p}"))
        })
        .transpose()?;
    let base = base_path
        .map(|p| {
            obj::read::read(p.as_ref(), &diff_config, DiffSide::Base)
                .with_context(|| format!("Loading {p}"))
        })
        .transpose()?;
    let result =
        diff::diff_objs(target.as_ref(), base.as_ref(), None, &diff_config, &mapping_config)?;
    let left = target.as_ref().zip(result.left.as_ref());
    let right = base.as_ref().zip(result.right.as_ref());
    let diff_result = DiffResult::new(left, right, &diff_config)?;
    write_output(&diff_result, Some(output), output_format)?;
    Ok(())
}

fn build_config_from_args(
    args: &Args,
    project_config: Option<&ProjectConfig>,
    unit_options: Option<&ProjectOptions>,
    project_dir: Option<&Utf8PlatformPath>,
) -> Result<(DiffObjConfig, MappingConfig)> {
    // Use relocation-normalized matching by default unless project/unit/CLI overrides it.
    let mut diff_config = DiffObjConfig {
        function_reloc_diffs: diff::FunctionRelocDiffs::DataValue,
        ..Default::default()
    };
    if let Some(options) = project_config.and_then(|config| config.options.as_ref()) {
        apply_project_options(&mut diff_config, options)?;
    }
    if let Some(options) = unit_options {
        apply_project_options(&mut diff_config, options)?;
    }
    apply_config_args(&mut diff_config, &args.config)?;

    let mut mapping_config = MappingConfig::default();

    // Load map file: CLI arg takes precedence over project config
    let map_file_path = args.map_file.clone().or_else(|| {
        project_config.and_then(|c| {
            c.map_file.as_ref().map(|p| {
                if let Some(dir) = project_dir {
                    dir.join(p.with_platform_encoding())
                } else {
                    Utf8PlatformPathBuf::from(p.as_str())
                }
            })
        })
    });
    if let Some(map_path) = &map_file_path {
        let file = std::fs::File::open(map_path.as_str())
            .with_context(|| format!("Failed to open map file: {}", map_path))?;
        let reader = std::io::BufReader::new(file);
        mapping_config.symbol_equivalences = objdiff_core::obj::map_file::parse_msvc_map(reader);
        eprintln!(
            "Loaded {} ICF equivalence entries from {}",
            mapping_config.symbol_equivalences.len(),
            map_path
        );
    }

    Ok((diff_config, mapping_config))
}

fn run_json(
    args: Args,
    target_path: Option<Utf8PlatformPathBuf>,
    base_path: Option<Utf8PlatformPathBuf>,
    project_config: Option<ProjectConfig>,
    unit_options: Option<ProjectOptions>,
    output_format: DiffOutputFormat,
    project_dir: Option<Utf8PlatformPathBuf>,
) -> Result<()> {
    use objdiff_core::diff::{DiffSide, diff_objs};

    let Some(symbol_name) = &args.symbol else {
        bail!("JSON output mode requires a symbol name");
    };

    let (diff_config, mapping_config) = build_config_from_args(
        &args,
        project_config.as_ref(),
        unit_options.as_ref(),
        project_dir.as_deref(),
    )?;

    // Read target object
    let target_obj = target_path
        .as_ref()
        .map(|p| {
            obj::read::read(p.as_ref(), &diff_config, DiffSide::Target)
                .with_context(|| format!("Failed to read target object: {}", p))
        })
        .transpose()?;

    // Read base object
    let base_obj = base_path
        .as_ref()
        .map(|p| {
            obj::read::read(p.as_ref(), &diff_config, DiffSide::Base)
                .with_context(|| format!("Failed to read base object: {}", p))
        })
        .transpose()?;

    // Perform the diff
    let diff_result =
        diff_objs(target_obj.as_ref(), base_obj.as_ref(), None, &diff_config, &mapping_config)?;

    // Find the symbol in the target or base object (supports both mangled and demangled names)
    let (symbol_idx, symbol, resolved_obj, obj_diff) = if let Some(ref target) = target_obj {
        let idx = target
            .symbol_by_name_or_demangled(symbol_name)
            .ok_or_else(|| anyhow!("Symbol not found in target: {}", symbol_name))?;
        let sym = &target.symbols[idx];
        let diff = diff_result.left.as_ref().unwrap();
        (idx, sym, target, diff)
    } else if let Some(ref base) = base_obj {
        let idx = base
            .symbol_by_name_or_demangled(symbol_name)
            .ok_or_else(|| anyhow!("Symbol not found in base: {}", symbol_name))?;
        let sym = &base.symbols[idx];
        let diff = diff_result.right.as_ref().unwrap();
        (idx, sym, base, diff)
    } else {
        bail!("No object files to diff");
    };

    let symbol_diff = &obj_diff.symbols[symbol_idx];

    // Get symbol indices and sizes for both sides.
    // Use the diff result's matched symbol for the "other" side — this is more
    // reliable than name lookup for anonymous namespace functions where the
    // hash differs between builds (e.g. ?A0xaf4cfd2b@@ vs ?A0x12345678@@).
    let (target_symbol_idx, base_symbol_idx, target_size, base_size) =
        if target_obj.is_some() {
            // Symbol was found in target; use diff match for base
            let target_size = target_obj
                .as_ref()
                .map(|o| o.symbols[symbol_idx].size)
                .unwrap_or(0);
            let base_symbol_idx = symbol_diff.target_symbol;
            let base_size = base_symbol_idx
                .and_then(|idx| base_obj.as_ref().map(|o| o.symbols[idx].size))
                .unwrap_or(0);
            (Some(symbol_idx), base_symbol_idx, target_size, base_size)
        } else {
            // Symbol was found in base; use diff match for target
            let base_size = base_obj
                .as_ref()
                .map(|o| o.symbols[symbol_idx].size)
                .unwrap_or(0);
            let target_symbol_idx = symbol_diff.target_symbol;
            let target_size = target_symbol_idx
                .and_then(|idx| target_obj.as_ref().map(|o| o.symbols[idx].size))
                .unwrap_or(0);
            (target_symbol_idx, Some(symbol_idx), target_size, base_size)
        };

    // Get both sides of the diff
    let left_diff = diff_result.left.as_ref();
    let right_diff = diff_result.right.as_ref();

    // Handle flag implications: --verdict implies --analyze implies --summary
    // --full-listing implies --include-instructions
    let wants_verdict = args.verdict;
    let wants_analyze = args.analyze || wants_verdict;
    let wants_summary = args.summary || wants_analyze;
    let wants_instructions = args.include_instructions || args.full_listing;

    // Build instruction diffs if requested (or if summary/analyze/verdict is requested)
    let instructions = if wants_instructions || wants_summary {
        Some(build_instruction_diffs(
            target_obj.as_ref(),
            base_obj.as_ref(),
            left_diff,
            right_diff,
            target_symbol_idx,
            base_symbol_idx,
            &diff_config,
        )?)
    } else {
        None
    };

    // Build data-symbol diff if requested (no-op for code symbols). The matched
    // symbol on the other side (if any) supplies the base bytes for side-by-side
    // comparison; `target_symbol` indexes into the other object's diff, which is
    // whichever of left/right we did NOT resolve by name.
    let data_diff = if args.include_data {
        let (other_obj, other_obj_diff) = if target_obj.is_some() {
            (base_obj.as_ref(), right_diff)
        } else {
            (target_obj.as_ref(), left_diff)
        };
        let other = symbol_diff.target_symbol.and_then(|idx| match (other_obj, other_obj_diff) {
            (Some(o), Some(d)) => Some((o.symbols.as_slice(), &d.symbols[idx])),
            _ => None,
        });
        build_data_diff(&resolved_obj.symbols, symbol_diff, other)
    } else {
        None
    };

    // Build instruction summary if requested
    let instruction_summary = if wants_summary {
        instructions.as_ref().map(|instrs| InstructionSummary::from_instructions(instrs))
    } else {
        None
    };

    // Run pattern analysis if requested
    let analysis = if wants_analyze {
        instructions.as_ref().map(|instrs| super::analysis::analyze_instructions(instrs))
    } else {
        None
    };

    // Compute verdict if requested
    let verdict = if wants_verdict {
        match (&instruction_summary, &analysis) {
            (Some(summary), Some(analysis)) => {
                Some(super::analysis::compute_verdict(summary, analysis, symbol_diff.match_percent, base_size, target_size))
            }
            _ => None,
        }
    } else {
        None
    };

    // Compute structural analysis if analyze is requested (and there are mismatches)
    let has_mismatches = instruction_summary.as_ref().map(|s| s.total > s.equal).unwrap_or(false);

    let call_diff = if wants_analyze && has_mismatches {
        instructions.as_ref().and_then(|instrs| super::analysis::compute_call_diff(instrs))
    } else {
        None
    };

    let insert_delete_clusters = if wants_analyze && has_mismatches {
        instructions
            .as_ref()
            .map(|instrs| {
                let clusters = super::analysis::compute_insert_delete_clusters(instrs);
                if clusters.is_empty() {
                    return Vec::new();
                }
                clusters
            })
            .filter(|v| !v.is_empty())
    } else {
        None
    };

    let diff_regions = if wants_analyze && has_mismatches {
        match (&instructions, &analysis) {
            (Some(instrs), Some(analysis)) => {
                let regions = super::analysis::compute_diff_regions(instrs, analysis);
                // Only include if there are mismatched regions (not just one 100% region)
                if regions.len() > 1 || regions.iter().any(|r| r.match_percent < 100.0) {
                    Some(regions)
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    };

    let primary_match_percent = symbol_diff.match_percent;
    let (normalized_match_percent, raw_match_percent) = match diff_config.function_reloc_diffs {
        diff::FunctionRelocDiffs::NameAddress => {
            let mut alt_config = diff_config.clone();
            alt_config.function_reloc_diffs = diff::FunctionRelocDiffs::DataValue;
            let alt_result = diff_objs(
                target_obj.as_ref(),
                base_obj.as_ref(),
                None,
                &alt_config,
                &mapping_config,
            )?;
            let alt_match = if target_obj.is_some() {
                alt_result
                    .left
                    .as_ref()
                    .and_then(|d| d.symbols.get(symbol_idx))
                    .and_then(|s| s.match_percent)
            } else {
                alt_result
                    .right
                    .as_ref()
                    .and_then(|d| d.symbols.get(symbol_idx))
                    .and_then(|s| s.match_percent)
            };
            (alt_match, primary_match_percent)
        }
        _ => {
            let mut alt_config = diff_config.clone();
            alt_config.function_reloc_diffs = diff::FunctionRelocDiffs::NameAddress;
            let alt_result = diff_objs(
                target_obj.as_ref(),
                base_obj.as_ref(),
                None,
                &alt_config,
                &mapping_config,
            )?;
            let alt_match = if target_obj.is_some() {
                alt_result
                    .left
                    .as_ref()
                    .and_then(|d| d.symbols.get(symbol_idx))
                    .and_then(|s| s.match_percent)
            } else {
                alt_result
                    .right
                    .as_ref()
                    .and_then(|d| d.symbols.get(symbol_idx))
                    .and_then(|s| s.match_percent)
            };
            (primary_match_percent, alt_match)
        }
    };

    // Build the output
    let output = DiffOutput {
        symbol: symbol_name.clone(),
        demangled: symbol.demangled_name.clone(),
        unit: args.unit.clone(),
        target_size,
        base_size,
        fuzzy_match_percent: normalized_match_percent,
        normalized_match_percent,
        raw_match_percent,
        diff_score: symbol_diff
            .diff_score
            .map(|(score, max)| DiffScoreOutput { score, max_score: max }),
        build_status: None, // No build status in one-shot mode
        instruction_summary,
        analysis,
        verdict,
        call_diff,
        insert_delete_clusters,
        diff_regions,
        // Only include instructions in output if explicitly requested (not just for summary)
        instructions: if wants_instructions { instructions } else { None },
        masked_equal_rows: symbol_diff.masked_equal_rows,
        reloc_ignored_rows: symbol_diff.reloc_ignored_rows,
        masked_equal_symbol: symbol_diff.masked_equal_symbol,
        data_diff,
    };

    // Create markdown options
    let md_options = MarkdownOptions {
        context: args.context,
        full_listing: args.full_listing,
        concise: args.concise,
    };

    // Write output
    write_diff_output(&output, args.output.as_deref(), output_format, &md_options)?;

    Ok(())
}

fn run_batch(args: Args) -> Result<()> {
    use objdiff_core::diff::{DiffSide, diff_objs};

    // Load project config
    let project_dir = match &args.project {
        Some(project) => project.clone(),
        _ => check_path_buf(
            std::env::current_dir().context("Failed to get the current directory")?,
        )
        .context("Current directory is not valid UTF-8")?,
    };
    let Some((project_config, project_config_info)) =
        objdiff_core::config::try_project_config(project_dir.as_ref())
    else {
        bail!("Project config not found in {}", &project_dir)
    };
    let project_config = project_config.with_context(|| {
        format!("Reading project config {}", project_config_info.path.display())
    })?;

    let target_obj_dir = project_config
        .target_dir
        .as_ref()
        .map(|p| project_dir.join(p.with_platform_encoding()));
    let base_obj_dir = project_config
        .base_dir
        .as_ref()
        .map(|p| project_dir.join(p.with_platform_encoding()));
    let units = project_config.units.as_deref().unwrap_or_default();

    // Build object configs indexed by unit name
    let object_configs: HashMap<String, (ObjectConfig, usize)> = units
        .iter()
        .enumerate()
        .map(|(idx, o)| {
            let config = ObjectConfig::new(
                o,
                &project_dir,
                target_obj_dir.as_deref(),
                base_obj_dir.as_deref(),
            );
            (config.name.clone(), (config, idx))
        })
        .collect();

    // Build a lookup config for demangling during symbol resolution
    let mut lookup_config = DiffObjConfig {
        function_reloc_diffs: diff::FunctionRelocDiffs::DataValue,
        ..Default::default()
    };
    if let Some(options) = project_config.options.as_ref() {
        let _ = apply_project_options(&mut lookup_config, options);
    }
    let _ = apply_config_args(&mut lookup_config, &args.config);

    // Load map file for ICF equivalences
    let mut mapping_config = MappingConfig::default();
    let map_file_path = args.map_file.clone().or_else(|| {
        project_config.map_file.as_ref().map(|p| {
            project_dir.join(p.with_platform_encoding())
        })
    });
    if let Some(map_path) = &map_file_path {
        let file = std::fs::File::open(map_path.as_str())
            .with_context(|| format!("Failed to open map file: {}", map_path))?;
        let reader = std::io::BufReader::new(file);
        mapping_config.symbol_equivalences = objdiff_core::obj::map_file::parse_msvc_map(reader);
        eprintln!(
            "Loaded {} ICF equivalence entries from {}",
            mapping_config.symbol_equivalences.len(),
            map_path
        );
    }

    // Build symbol indexes: open each .obj file ONCE, extract all text symbols.
    // This replaces the O(symbols × units) scan with O(units + symbols) lookups.
    let index_start = std::time::Instant::now();

    // Target index: mangled name → unit
    let mut target_mangled_index: HashMap<String, String> = HashMap::new();
    for (unit_name, (obj_config, _)) in &object_configs {
        if let Some(target_path) = obj_config.target_path.as_deref() {
            if let Ok(syms) = obj::read::list_function_symbols(target_path.as_ref()) {
                for sym in syms {
                    target_mangled_index
                        .entry(sym)
                        .or_insert_with(|| unit_name.clone());
                }
            }
        }
    }

    // Base index for cross-unit COMDAT fallback
    let mut base_symbol_index: HashMap<String, String> = HashMap::new();
    for (unit_name, (obj_config, _)) in &object_configs {
        if let Some(base_path) = obj_config.base_path.as_deref() {
            if let Ok(syms) = obj::read::list_function_symbols(base_path.as_ref()) {
                for sym in syms {
                    base_symbol_index
                        .entry(sym)
                        .or_insert_with(|| unit_name.clone());
                }
            }
        }
    }

    eprintln!(
        "Symbol index built in {:.1}s: {} target mangled, {} base",
        index_start.elapsed().as_secs_f64(),
        target_mangled_index.len(),
        base_symbol_index.len(),
    );

    // Read symbols from stdin
    let stdin = std::io::stdin();
    let symbols: Vec<String> = stdin
        .lock()
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() { None } else { Some(trimmed) }
        })
        .collect();

    if symbols.is_empty() {
        bail!("No symbols provided on stdin");
    }
    eprintln!("Batch mode: {} symbols to process", symbols.len());

    // Resolve each symbol to its unit via O(1) HashMap lookups
    let mut by_unit: HashMap<String, Vec<String>> = HashMap::new();
    let mut not_found: Vec<String> = Vec::new();

    for symbol in &symbols {
        if let Some(unit) = target_mangled_index.get(symbol.as_str()) {
            by_unit.entry(unit.clone()).or_default().push(symbol.clone());
        } else {
            // Demangled fallback: scan target .obj files for demangled match
            let mut found = false;
            for (unit_name, (obj_config, _)) in &object_configs {
                if let Some(target_path) = obj_config.target_path.as_deref() {
                    let matches = obj::read::match_symbol_by_query(
                        target_path.as_ref(), symbol, &lookup_config,
                    ).unwrap_or_default();
                    if matches.len() == 1 {
                        by_unit.entry(unit_name.clone()).or_default().push(symbol.clone());
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                not_found.push(symbol.clone());
            }
        }
    }

    eprintln!(
        "Resolved: {} symbols across {} units ({} not found)",
        symbols.len() - not_found.len(),
        by_unit.len(),
        not_found.len(),
    );

    // Output not-found symbols as error entries
    let mut not_found_lines: Vec<String> = Vec::new();
    for symbol in &not_found {
        let output = serde_json::json!({
            "symbol": symbol,
            "error": "not_found",
        });
        not_found_lines.push(serde_json::to_string(&output)?);
    }

    // Process units in parallel with rayon
    use rayon::prelude::*;
    use std::sync::atomic::AtomicUsize;

    let units_total = by_unit.len();
    let units_processed = AtomicUsize::new(0);

    let unit_results: Vec<Result<Vec<String>>> = by_unit
        .par_iter()
        .map(|(unit_name, unit_symbols)| -> Result<Vec<String>> {
            let mut lines: Vec<String> = Vec::new();

            let Some((object_config, unit_idx)) = object_configs.get(unit_name) else {
                for symbol in unit_symbols {
                    let output = serde_json::json!({
                        "symbol": symbol,
                        "error": "unit_not_found",
                    });
                    lines.push(serde_json::to_string(&output)?);
                }
                return Ok(lines);
            };

            // Build diff config with unit options
            let unit_options = units.get(*unit_idx).and_then(|u| u.options());
            let diff_config = build_unit_diff_config(
                &lookup_config,
                project_config.options.as_ref(),
                unit_options,
                &args.config,
            )?;

            // Load objects ONCE per unit
            let target_obj = object_config
                .target_path
                .as_ref()
                .map(|p| obj::read::read(p.as_ref(), &diff_config, DiffSide::Target))
                .transpose()?;
            let base_obj = object_config
                .base_path
                .as_ref()
                .map(|p| obj::read::read(p.as_ref(), &diff_config, DiffSide::Base))
                .transpose()?;

            // Build symbol filter: only diff the symbols we actually need
            let mut symbol_filter = std::collections::BTreeSet::new();
            for symbol_name in unit_symbols {
                if let Some(idx) = target_obj.as_ref().and_then(|o| o.symbol_by_name_or_demangled(symbol_name)) {
                    symbol_filter.insert(idx);
                } else if let Some(idx) = base_obj.as_ref().and_then(|o| o.symbol_by_name_or_demangled(symbol_name)) {
                    symbol_filter.insert(idx);
                }
            }

            // Diff only the filtered symbols for this unit
            let diff_result = diff::diff_objs_filtered(
                target_obj.as_ref(),
                base_obj.as_ref(),
                None,
                &diff_config,
                &mapping_config,
                Some(&symbol_filter),
            )?;

            // Compute alt diff for normalized/raw match percentages.
            // Skip when functionRelocDiffs=None since normalized == primary in that case.
            let needs_alt = diff_config.function_reloc_diffs != diff::FunctionRelocDiffs::None;
            let alt_diff_result = if needs_alt {
                let alt_config = {
                    let mut c = diff_config.clone();
                    match diff_config.function_reloc_diffs {
                        diff::FunctionRelocDiffs::NameAddress => {
                            c.function_reloc_diffs = diff::FunctionRelocDiffs::DataValue;
                        }
                        _ => {
                            c.function_reloc_diffs = diff::FunctionRelocDiffs::NameAddress;
                        }
                    }
                    c
                };
                Some(diff::diff_objs_filtered(
                    target_obj.as_ref(),
                    base_obj.as_ref(),
                    None,
                    &alt_config,
                    &mapping_config,
                    Some(&symbol_filter),
                )?)
            } else {
                None
            };

            // Process each symbol from this unit
            for symbol_name in unit_symbols {
                let name_target_idx =
                    target_obj.as_ref().and_then(|o| o.symbol_by_name_or_demangled(symbol_name));
                let name_base_idx =
                    base_obj.as_ref().and_then(|o| o.symbol_by_name_or_demangled(symbol_name));

                let (symbol_idx, symbol, _obj, obj_diff) =
                    if let Some(idx) = name_target_idx {
                        let obj = target_obj.as_ref().unwrap();
                        let diff = diff_result.left.as_ref().unwrap();
                        (idx, &obj.symbols[idx], obj, diff)
                    } else if let Some(idx) = name_base_idx {
                        let obj = base_obj.as_ref().unwrap();
                        let diff = diff_result.right.as_ref().unwrap();
                        (idx, &obj.symbols[idx], obj, diff)
                    } else {
                        let output = serde_json::json!({
                            "symbol": symbol_name,
                            "error": "symbol_not_in_objects",
                        });
                        lines.push(serde_json::to_string(&output)?);
                        continue;
                    };

                let symbol_diff = &obj_diff.symbols[symbol_idx];

                let (target_symbol_idx, base_symbol_idx, target_size, base_size) =
                    if name_target_idx.is_some() {
                        let ts = target_obj.as_ref()
                            .map(|o| o.symbols[symbol_idx].size).unwrap_or(0);
                        let bsi = symbol_diff.target_symbol;
                        let bs = bsi
                            .and_then(|idx| base_obj.as_ref().map(|o| o.symbols[idx].size))
                            .unwrap_or(0);
                        (Some(symbol_idx), bsi, ts, bs)
                    } else {
                        let bs = base_obj.as_ref()
                            .map(|o| o.symbols[symbol_idx].size).unwrap_or(0);
                        let tsi = symbol_diff.target_symbol;
                        let ts = tsi
                            .and_then(|idx| target_obj.as_ref().map(|o| o.symbols[idx].size))
                            .unwrap_or(0);
                        (tsi, Some(symbol_idx), ts, bs)
                    };

                // Cross-unit COMDAT fallback
                if base_size == 0 && name_target_idx.is_some() {
                    let fallback = base_symbol_index.get(symbol_name.as_str());
                    if let Some(fallback_unit) = fallback {
                        if fallback_unit != unit_name {
                            if let Some((fallback_config, _)) = object_configs.get(fallback_unit) {
                                if let Some(fallback_base_path) = fallback_config.base_path.as_deref() {
                                    if let Ok(fb_obj) = obj::read::read(fallback_base_path.as_ref(), &diff_config, DiffSide::Base) {
                                        let fb_diff = diff_objs(
                                            target_obj.as_ref(), Some(&fb_obj),
                                            None, &diff_config, &mapping_config,
                                        )?;
                                        let fb_sd = &fb_diff.left.as_ref().unwrap().symbols[symbol_idx];
                                        let fb_bsi = fb_sd.target_symbol;
                                        let fb_bs = fb_bsi.map(|i| fb_obj.symbols[i].size).unwrap_or(0);

                                        if fb_bs > 0 {
                                            let fb_alt_cfg = {
                                                let mut c = diff_config.clone();
                                                match c.function_reloc_diffs {
                                                    diff::FunctionRelocDiffs::NameAddress =>
                                                        c.function_reloc_diffs = diff::FunctionRelocDiffs::DataValue,
                                                    _ =>
                                                        c.function_reloc_diffs = diff::FunctionRelocDiffs::NameAddress,
                                                }
                                                c
                                            };
                                            let fb_alt = diff_objs(
                                                target_obj.as_ref(), Some(&fb_obj),
                                                None, &fb_alt_cfg, &mapping_config,
                                            )?;
                                            let fb_instrs = build_instruction_diffs(
                                                target_obj.as_ref(), Some(&fb_obj),
                                                fb_diff.left.as_ref(), fb_diff.right.as_ref(),
                                                Some(symbol_idx), fb_bsi, &diff_config,
                                            )?;
                                            let fb_summary = InstructionSummary::from_instructions(&fb_instrs);
                                            let fb_analysis = super::analysis::analyze_instructions(&fb_instrs);
                                            let fb_verdict = super::analysis::compute_verdict(
                                                &fb_summary, &fb_analysis, fb_sd.match_percent, fb_bs, target_size,
                                            );
                                            let (fb_norm, fb_raw) = match diff_config.function_reloc_diffs {
                                                diff::FunctionRelocDiffs::NameAddress => (
                                                    fb_alt.left.as_ref().and_then(|d| d.symbols.get(symbol_idx)).and_then(|s| s.match_percent),
                                                    fb_sd.match_percent,
                                                ),
                                                _ => (
                                                    fb_sd.match_percent,
                                                    fb_alt.left.as_ref().and_then(|d| d.symbols.get(symbol_idx)).and_then(|s| s.match_percent),
                                                ),
                                            };
                                            let output = DiffOutput {
                                                symbol: symbol_name.clone(),
                                                demangled: symbol.demangled_name.clone(),
                                                unit: Some(unit_name.clone()),
                                                target_size,
                                                base_size: fb_bs,
                                                fuzzy_match_percent: fb_norm,
                                                normalized_match_percent: fb_norm,
                                                raw_match_percent: fb_raw,
                                                diff_score: fb_sd.diff_score.map(|(s, m)| DiffScoreOutput { score: s, max_score: m }),
                                                build_status: None,
                                                instruction_summary: Some(fb_summary),
                                                analysis: Some(fb_analysis),
                                                verdict: Some(fb_verdict),
                                                call_diff: None,
                                                insert_delete_clusters: None,
                                                diff_regions: None,
                                                instructions: None,
                                                masked_equal_rows: fb_sd.masked_equal_rows,
                                                reloc_ignored_rows: fb_sd.reloc_ignored_rows,
                                                masked_equal_symbol: fb_sd.masked_equal_symbol,
                                                data_diff: None,
                                            };
                                            lines.push(serde_json::to_string(&output)?);
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Normal path
                let instructions = build_instruction_diffs(
                    target_obj.as_ref(),
                    base_obj.as_ref(),
                    diff_result.left.as_ref(),
                    diff_result.right.as_ref(),
                    target_symbol_idx,
                    base_symbol_idx,
                    &diff_config,
                )?;

                let instruction_summary = InstructionSummary::from_instructions(&instructions);
                let analysis = super::analysis::analyze_instructions(&instructions);
                let verdict = super::analysis::compute_verdict(
                    &instruction_summary,
                    &analysis,
                    symbol_diff.match_percent,
                    base_size,
                    target_size,
                );

                let primary_match_percent = symbol_diff.match_percent;
                let (normalized_match_percent, raw_match_percent) = if let Some(ref alt_result) = alt_diff_result {
                    let alt_match = if target_obj.is_some() {
                        alt_result
                            .left
                            .as_ref()
                            .and_then(|d| d.symbols.get(symbol_idx))
                            .and_then(|s| s.match_percent)
                    } else {
                        alt_result
                            .right
                            .as_ref()
                            .and_then(|d| d.symbols.get(symbol_idx))
                            .and_then(|s| s.match_percent)
                    };
                    match diff_config.function_reloc_diffs {
                        diff::FunctionRelocDiffs::NameAddress => (alt_match, primary_match_percent),
                        _ => (primary_match_percent, alt_match),
                    }
                } else {
                    // No alt diff (reloc diffs = None): normalized == primary
                    (primary_match_percent, primary_match_percent)
                };

                let output = DiffOutput {
                    symbol: symbol_name.clone(),
                    demangled: symbol.demangled_name.clone(),
                    unit: Some(unit_name.clone()),
                    target_size,
                    base_size,
                    fuzzy_match_percent: normalized_match_percent,
                    normalized_match_percent,
                    raw_match_percent,
                    diff_score: symbol_diff
                        .diff_score
                        .map(|(score, max)| DiffScoreOutput { score, max_score: max }),
                    build_status: None,
                    instruction_summary: Some(instruction_summary),
                    analysis: Some(analysis),
                    verdict: Some(verdict),
                    call_diff: None,
                    insert_delete_clusters: None,
                    diff_regions: None,
                    instructions: None,
                    masked_equal_rows: symbol_diff.masked_equal_rows,
                    reloc_ignored_rows: symbol_diff.reloc_ignored_rows,
                    masked_equal_symbol: symbol_diff.masked_equal_symbol,
                    data_diff: None,
                };

                lines.push(serde_json::to_string(&output)?);
            }

            let done = units_processed.fetch_add(1, Ordering::Relaxed) + 1;
            if done % 100 == 0 {
                eprintln!("  [{}/{}] units processed", done, units_total);
            }

            Ok(lines)
        })
        .collect();

    // Write all results to stdout
    let mut stdout = stdout();
    for line in &not_found_lines {
        writeln!(stdout, "{}", line)?;
    }
    for unit_result in unit_results {
        for line in unit_result? {
            writeln!(stdout, "{}", line)?;
        }
    }

    eprintln!(
        "Batch complete: {} symbols, {} units",
        symbols.len() - not_found.len(),
        by_unit.len(),
    );
    Ok(())
}

fn build_unit_diff_config(
    base: &DiffObjConfig,
    project_options: Option<&ProjectOptions>,
    unit_options: Option<&ProjectOptions>,
    cli_args: &[String],
) -> Result<DiffObjConfig> {
    let mut diff_config = base.clone();
    if let Some(options) = project_options {
        apply_project_options(&mut diff_config, options)?;
    }
    if let Some(options) = unit_options {
        apply_project_options(&mut diff_config, options)?;
    }
    apply_config_args(&mut diff_config, cli_args)?;
    Ok(diff_config)
}

/// Build a structured byte/relocation diff for a data symbol from the resolved
/// side's `data_rows`. Returns `None` for code symbols (which have no data rows).
/// Diff kinds are relative to the matched symbol on the other side.
fn build_data_diff(
    symbols: &[Symbol],
    symbol_diff: &SymbolDiff,
    other: Option<(&[Symbol], &SymbolDiff)>,
) -> Option<DataDiffOutput> {
    use objdiff_core::diff::DataDiffKind;
    if symbol_diff.data_rows.is_empty() {
        return None;
    }

    // Row 0's address is the symbol's start; reloc ranges are absolute.
    let base_addr = symbol_diff.data_rows.first().map(|r| r.address).unwrap_or(0);

    // The matched symbol on the other side has structurally identical data_rows
    // (objdiff-core builds both sides in lockstep), differing only in segment
    // bytes — so we can pair them positionally for side-by-side byte output.
    // Guard defensively: if the shapes don't match, drop the pairing entirely.
    let other_rows = other.map(|(_, d)| &d.data_rows).filter(|rows| {
        rows.len() == symbol_diff.data_rows.len()
            && rows.iter().zip(&symbol_diff.data_rows).all(|(o, t)| {
                o.segments.len() == t.segments.len()
                    && o.segments
                        .iter()
                        .zip(&t.segments)
                        .all(|(os, ts)| os.size == ts.size && os.kind == ts.kind)
            })
    });

    // objdiff chunks data into 16-byte rows; flatten them back into contiguous
    // runs, merging adjacent segments that share a diff kind. The other side's
    // bytes are accumulated in lockstep so merge boundaries stay aligned.
    let mut segments: Vec<DataSegmentOutput> = Vec::new();
    let mut seg_bytes: Vec<Vec<u8>> = Vec::new();
    let mut other_seg_bytes: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0usize;
    let mut total_byte_count = 0usize;
    let mut mismatch_byte_count = 0usize;

    for (row_idx, row) in symbol_diff.data_rows.iter().enumerate() {
        for (seg_idx, seg) in row.segments.iter().enumerate() {
            let other_data: &[u8] = other_rows
                .and_then(|rows| rows[row_idx].segments.get(seg_idx))
                .map(|os| os.data.as_slice())
                .unwrap_or(&[]);

            if seg.kind != DataDiffKind::Insert {
                total_byte_count += seg.size;
            }
            if seg.kind != DataDiffKind::None {
                mismatch_byte_count += seg.size;
            }
            let kind = data_diff_kind_str(seg.kind);
            if let Some(last) = segments.last_mut() {
                if last.kind == kind {
                    last.size += seg.size;
                    seg_bytes.last_mut().unwrap().extend_from_slice(&seg.data);
                    other_seg_bytes.last_mut().unwrap().extend_from_slice(other_data);
                    offset += seg.size;
                    continue;
                }
            }
            segments.push(DataSegmentOutput {
                offset,
                size: seg.size,
                kind: kind.to_string(),
                bytes: None,
                base_bytes: None,
            });
            seg_bytes.push(seg.data.clone());
            other_seg_bytes.push(other_data.to_vec());
            offset += seg.size;
        }
    }

    // Attach hex bytes for differing runs. `bytes` is the resolved side
    // (replace/delete carry data here); `base_bytes` is the matched other side,
    // emitted only when present and actually different (so matched runs and
    // inserts/deletes stay clean on the side that has no bytes).
    let have_other = other_rows.is_some();
    for ((seg, raw), other_raw) in
        segments.iter_mut().zip(seg_bytes.iter()).zip(other_seg_bytes.iter())
    {
        if seg.kind == "equal" {
            continue;
        }
        if !raw.is_empty() {
            seg.bytes = Some(raw.iter().map(|b| format!("{b:02x}")).collect());
        }
        if have_other && !other_raw.is_empty() && other_raw != raw {
            seg.base_bytes = Some(other_raw.iter().map(|b| format!("{b:02x}")).collect());
        }
    }

    // Index the matched (base) side's relocations by symbol-relative offset, so
    // we can show where a relocation points on the other side (e.g. a vtable
    // slot that resolves to a different function in the base build). Left/right
    // reloc lists are NOT positionally aligned, so we pair by offset.
    struct BaseReloc {
        offset: u64,
        size: u64,
        target_symbol: String,
        addend: i64,
    }
    let mut base_relocs: Vec<BaseReloc> = Vec::new();
    if let Some((other_symbols, other_diff)) = other {
        let other_base = other_diff.data_rows.first().map(|r| r.address).unwrap_or(0);
        let mut seen: Vec<(u64, u64)> = Vec::new();
        for row in &other_diff.data_rows {
            for rd in &row.relocations {
                let key = (rd.range.start, rd.range.end);
                if seen.contains(&key) {
                    continue;
                }
                seen.push(key);
                base_relocs.push(BaseReloc {
                    offset: rd.range.start.saturating_sub(other_base),
                    size: rd.range.end - rd.range.start,
                    target_symbol: other_symbols
                        .get(rd.reloc.target_symbol)
                        .map(|s| s.name.clone())
                        .unwrap_or_default(),
                    addend: rd.reloc.addend,
                });
            }
        }
    }

    // Collect this side's relocations (de-duplicating row-boundary spans) and
    // pair each with the base side by offset.
    let mut relocations: Vec<DataRelocationOutput> = Vec::new();
    let mut seen: Vec<(u64, u64)> = Vec::new();
    let mut matched_base: Vec<u64> = Vec::new();
    for row in &symbol_diff.data_rows {
        for rd in &row.relocations {
            let key = (rd.range.start, rd.range.end);
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            let offset = rd.range.start.saturating_sub(base_addr);
            let target_symbol =
                symbols.get(rd.reloc.target_symbol).map(|s| s.name.clone()).unwrap_or_default();
            let mut base_target_symbol = None;
            let mut base_addend = None;
            if let Some(b) = base_relocs.iter().find(|b| b.offset == offset) {
                matched_base.push(offset);
                if !b.target_symbol.is_empty() && b.target_symbol != target_symbol {
                    base_target_symbol = Some(b.target_symbol.clone());
                }
                if b.addend != rd.reloc.addend {
                    base_addend = Some(b.addend);
                }
            }
            relocations.push(DataRelocationOutput {
                offset,
                size: rd.range.end - rd.range.start,
                kind: data_diff_kind_str(rd.kind).to_string(),
                target_symbol,
                addend: rd.reloc.addend,
                base_target_symbol,
                base_addend,
            });
        }
    }

    // Surface base-only relocations (present on the base side, absent here).
    for b in &base_relocs {
        if matched_base.contains(&b.offset) {
            continue;
        }
        relocations.push(DataRelocationOutput {
            offset: b.offset,
            size: b.size,
            kind: "insert".to_string(),
            target_symbol: String::new(),
            addend: 0,
            base_target_symbol: Some(b.target_symbol.clone()),
            base_addend: if b.addend != 0 { Some(b.addend) } else { None },
        });
    }
    relocations.sort_by_key(|r| r.offset);

    Some(DataDiffOutput {
        match_percent: symbol_diff.match_percent,
        mismatch_byte_count,
        total_byte_count,
        segments,
        relocations,
    })
}

fn build_instruction_diffs(
    target_obj: Option<&Object>,
    base_obj: Option<&Object>,
    left_diff: Option<&ObjectDiff>,
    right_diff: Option<&ObjectDiff>,
    target_symbol_idx: Option<usize>,
    base_symbol_idx: Option<usize>,
    diff_config: &DiffObjConfig,
) -> Result<Vec<InstructionDiffOutput>> {
    let mut instructions = Vec::new();

    // Get the instruction rows from left (target) side
    let left_rows =
        left_diff.and_then(|d| target_symbol_idx.map(|idx| &d.symbols[idx].instruction_rows));

    // Get the instruction rows from right (base) side
    let right_rows =
        right_diff.and_then(|d| base_symbol_idx.map(|idx| &d.symbols[idx].instruction_rows));

    // Determine the length based on available data
    let row_count = match (left_rows, right_rows) {
        (Some(l), Some(r)) => l.len().max(r.len()),
        (Some(l), None) => l.len(),
        (None, Some(r)) => r.len(),
        (None, None) => return Ok(instructions),
    };

    for idx in 0..row_count {
        let left_row = left_rows.and_then(|rows| rows.get(idx));
        let right_row = right_rows.and_then(|rows| rows.get(idx));

        // Get target instruction info
        let target_info = if let (Some(row), Some(obj), Some(sym_idx)) =
            (left_row, target_obj, target_symbol_idx)
        {
            if let Some(ins_ref) = row.ins_ref {
                Some(build_instruction_info(obj, sym_idx, ins_ref, diff_config)?)
            } else {
                None
            }
        } else {
            None
        };

        // Get base instruction info
        let base_info =
            if let (Some(row), Some(obj), Some(sym_idx)) = (right_row, base_obj, base_symbol_idx) {
                if let Some(ins_ref) = row.ins_ref {
                    Some(build_instruction_info(obj, sym_idx, ins_ref, diff_config)?)
                } else {
                    None
                }
            } else {
                None
            };

        // Use the diff kind from whichever side is available.
        // When only one side has a row (one-sided diff), mark as insert/delete
        // rather than falling through to None (which maps to "equal").
        let kind = match (left_row, right_row) {
            (Some(l), Some(_)) => l.kind,
            (Some(l), None) => {
                // Target-only instruction: use the diff kind if the core assigned one,
                // otherwise mark as insert (target has code, base doesn't)
                if l.kind == InstructionDiffKind::None {
                    InstructionDiffKind::Insert
                } else {
                    l.kind
                }
            }
            (None, Some(r)) => {
                // Base-only instruction: use the diff kind if the core assigned one,
                // otherwise mark as delete (base has code, target doesn't)
                if r.kind == InstructionDiffKind::None {
                    InstructionDiffKind::Delete
                } else {
                    r.kind
                }
            }
            (None, None) => InstructionDiffKind::None,
        };

        // Compute diff breakdown if this is an argument mismatch
        let diff_breakdown = if kind == InstructionDiffKind::ArgMismatch {
            compute_arg_diff_breakdown(target_info.as_ref(), base_info.as_ref())
        } else {
            None
        };

        // Surface the control-flow (branch) graph from each side's diff row.
        let branch_from = |row: Option<&InstructionDiffRow>| {
            row.and_then(|r| r.branch_from.as_ref()).map(|b| BranchFrom {
                source_indices: b.ins_idx.clone(),
                branch_idx: b.branch_idx,
            })
        };
        let branch_to = |row: Option<&InstructionDiffRow>| {
            row.and_then(|r| r.branch_to.as_ref())
                .map(|b| BranchTo { target_index: b.ins_idx, branch_idx: b.branch_idx })
        };

        // Masked-equality disclosure bit, from whichever side carries the row.
        let masked_equal = left_row.map(|r| r.masked_equal).unwrap_or(false)
            || right_row.map(|r| r.masked_equal).unwrap_or(false);

        instructions.push(InstructionDiffOutput {
            index: idx,
            target: target_info,
            base: base_info,
            match_type: match_type_str(kind).to_string(),
            masked_equal,
            diff_breakdown,
            target_branch_from: branch_from(left_row),
            target_branch_to: branch_to(left_row),
            base_branch_from: branch_from(right_row),
            base_branch_to: branch_to(right_row),
        });
    }

    Ok(instructions)
}

/// Compute which arguments differ between target and base instructions.
fn compute_arg_diff_breakdown(
    target: Option<&InstructionInfo>,
    base: Option<&InstructionInfo>,
) -> Option<InstructionDiffBreakdown> {
    let target_args = target.and_then(|t| t.typed_args.as_ref())?;
    let base_args = base.and_then(|b| b.typed_args.as_ref())?;

    let mut arguments = Vec::new();

    // Compare arguments at each position
    let max_len = target_args.len().max(base_args.len());
    for i in 0..max_len {
        let target_arg = target_args.get(i);
        let base_arg = base_args.get(i);

        match (target_arg, base_arg) {
            (Some(t), Some(b)) if !typed_args_equal(t, b) => {
                arguments.push(ArgumentDiff {
                    index: i,
                    arg_type: typed_arg_type(t),
                    target: t.clone(),
                    base: b.clone(),
                });
            }
            (Some(t), None) => {
                // Target has arg, base doesn't
                arguments.push(ArgumentDiff {
                    index: i,
                    arg_type: typed_arg_type(t),
                    target: t.clone(),
                    base: TypedArg::Other("<missing>".to_string()),
                });
            }
            (None, Some(b)) => {
                // Base has arg, target doesn't
                arguments.push(ArgumentDiff {
                    index: i,
                    arg_type: typed_arg_type(b),
                    target: TypedArg::Other("<missing>".to_string()),
                    base: b.clone(),
                });
            }
            _ => {}
        }
    }

    if arguments.is_empty() { None } else { Some(InstructionDiffBreakdown { arguments }) }
}

/// Check if two TypedArgs are equal for diff purposes.
fn typed_args_equal(a: &TypedArg, b: &TypedArg) -> bool {
    match (a, b) {
        (TypedArg::Signed(x), TypedArg::Signed(y)) => x == y,
        (TypedArg::Unsigned(x), TypedArg::Unsigned(y)) => x == y,
        (TypedArg::Register(x), TypedArg::Register(y)) => x == y,
        (TypedArg::Symbol(x), TypedArg::Symbol(y)) => x == y,
        (TypedArg::BranchDest(x), TypedArg::BranchDest(y)) => x == y,
        (TypedArg::Other(x), TypedArg::Other(y)) => x == y,
        // Allow signed/unsigned comparison
        (TypedArg::Signed(x), TypedArg::Unsigned(y)) => *x as u64 == *y,
        (TypedArg::Unsigned(x), TypedArg::Signed(y)) => *x == *y as u64,
        _ => false,
    }
}

/// Get a string type name for a TypedArg.
fn typed_arg_type(arg: &TypedArg) -> String {
    match arg {
        TypedArg::Signed(_) | TypedArg::Unsigned(_) => "immediate".to_string(),
        TypedArg::Register(_) => "register".to_string(),
        TypedArg::Symbol(_) => "symbol".to_string(),
        TypedArg::BranchDest(_) => "branch_dest".to_string(),
        TypedArg::Other(_) => "other".to_string(),
    }
}

/// Regex to detect register names (r0-r31, f0-f31, cr0-cr7, etc.)
static REGISTER_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^([rf]\d+|cr\d+|sp|lr|ctr|xer)$").unwrap());

/// Convert an InstructionArg to a TypedArg for JSON serialization.
fn convert_to_typed_arg(
    arg: &objdiff_core::obj::InstructionArg,
    relocation: Option<&objdiff_core::obj::ResolvedRelocation>,
) -> TypedArg {
    use objdiff_core::obj::{InstructionArg, InstructionArgValue};

    match arg {
        InstructionArg::Value(v) => match v {
            InstructionArgValue::Signed(n) => TypedArg::Signed(*n),
            InstructionArgValue::Unsigned(n) => TypedArg::Unsigned(*n),
            InstructionArgValue::Opaque(s) => {
                // Classify opaque values as registers or other
                if REGISTER_RE.is_match(s.as_ref()) {
                    TypedArg::Register(s.to_string())
                } else {
                    TypedArg::Other(s.to_string())
                }
            }
        },
        InstructionArg::Reloc => {
            // Get symbol name from relocation if available
            let symbol_name =
                relocation.map(|r| r.symbol.name.clone()).unwrap_or_else(|| "<reloc>".to_string());
            TypedArg::Symbol(symbol_name)
        }
        InstructionArg::BranchDest(addr) => TypedArg::BranchDest(*addr),
    }
}

fn build_instruction_info(
    obj: &Object,
    symbol_idx: usize,
    ins_ref: objdiff_core::obj::InstructionRef,
    diff_config: &DiffObjConfig,
) -> Result<InstructionInfo> {
    let resolved = obj
        .resolve_instruction_ref(symbol_idx, ins_ref)
        .context("Failed to resolve instruction")?;
    let processed = obj.arch.process_instruction(resolved, diff_config)?;

    // Build string args for backward compatibility
    let args_str = if processed.args.is_empty() {
        None
    } else {
        let args: Vec<String> = processed
            .args
            .iter()
            .map(|arg| match arg {
                objdiff_core::obj::InstructionArg::Value(v) => v.to_string(),
                objdiff_core::obj::InstructionArg::Reloc => resolved
                    .relocation
                    .as_ref()
                    .map_or("<reloc>".to_string(), |r| r.symbol.name.clone()),
                objdiff_core::obj::InstructionArg::BranchDest(d) => format!("{:#x}", d),
            })
            .collect();
        Some(args.join(diff_config.separator()))
    };

    // Build typed args preserving type information
    let typed_args = if processed.args.is_empty() {
        None
    } else {
        Some(
            processed
                .args
                .iter()
                .map(|arg| convert_to_typed_arg(arg, resolved.relocation.as_ref()))
                .collect(),
        )
    };

    // Extract branch destination if present
    let branch_dest = processed.args.iter().find_map(|arg| {
        if let objdiff_core::obj::InstructionArg::BranchDest(addr) = arg {
            Some(*addr)
        } else {
            None
        }
    });

    // Extract line number and source file from section line_info
    let line_info =
        resolved.section.line_info.range(..=ins_ref.address).last().map(|(_, info)| info);

    let line_number = line_info.map(|(line, _)| *line);
    let source_file = line_info.map(|(_, file)| file.clone()).filter(|f| !f.is_empty());

    Ok(InstructionInfo {
        address: format!("{:#x}", ins_ref.address),
        opcode: processed.mnemonic.to_string(),
        args: args_str,
        typed_args,
        branch_dest,
        line_number,
        source_file,
    })
}

/// Analyze a single symbol from already-loaded and diffed objects.
///
/// This function is used by the batch `report analyze` command to analyze
/// multiple symbols from the same object files without re-reading them.
///
/// Returns `Ok(None)` if the symbol is not found in either object.
pub fn analyze_symbol(
    target_obj: Option<&Object>,
    base_obj: Option<&Object>,
    diff_result: &objdiff_core::diff::DiffObjsResult,
    symbol_name: &str,
    diff_config: &DiffObjConfig,
) -> Result<Option<SymbolAnalysisResult>> {
    // Find symbol index in target, falling back to base
    let name_target_idx = target_obj.and_then(|o| o.symbol_by_name_or_demangled(symbol_name));
    let name_base_idx = base_obj.and_then(|o| o.symbol_by_name_or_demangled(symbol_name));

    // Get the symbol index from whichever side has it
    let (symbol_idx, obj, obj_diff) = if let Some(idx) = name_target_idx {
        let obj = target_obj.unwrap();
        let diff = diff_result.left.as_ref().ok_or_else(|| anyhow!("Missing left diff result"))?;
        (idx, obj, diff)
    } else if let Some(idx) = name_base_idx {
        let obj = base_obj.unwrap();
        let diff =
            diff_result.right.as_ref().ok_or_else(|| anyhow!("Missing right diff result"))?;
        (idx, obj, diff)
    } else {
        // Symbol not found in either object
        return Ok(None);
    };

    let symbol = &obj.symbols[symbol_idx];
    let symbol_diff = &obj_diff.symbols[symbol_idx];

    // Use diff result's matched symbol for the "other" side
    let (target_symbol_idx, base_symbol_idx, target_size, base_size) =
        if name_target_idx.is_some() {
            let ts = target_obj.map(|o| o.symbols[symbol_idx].size).unwrap_or(0);
            let bsi = symbol_diff.target_symbol;
            let bs = bsi
                .and_then(|idx| base_obj.map(|o| o.symbols[idx].size))
                .unwrap_or(0);
            (Some(symbol_idx), bsi, ts, bs)
        } else {
            let bs = base_obj.map(|o| o.symbols[symbol_idx].size).unwrap_or(0);
            let tsi = symbol_diff.target_symbol;
            let ts = tsi
                .and_then(|idx| target_obj.map(|o| o.symbols[idx].size))
                .unwrap_or(0);
            (tsi, Some(symbol_idx), ts, bs)
        };

    // Get both sides of the diff
    let left_diff = diff_result.left.as_ref();
    let right_diff = diff_result.right.as_ref();

    // Build instruction diffs
    let instructions = build_instruction_diffs(
        target_obj,
        base_obj,
        left_diff,
        right_diff,
        target_symbol_idx,
        base_symbol_idx,
        diff_config,
    )?;

    // Compute summary, analysis, verdict
    let instruction_summary = InstructionSummary::from_instructions(&instructions);
    let analysis = super::analysis::analyze_instructions(&instructions);
    let verdict = super::analysis::compute_verdict(
        &instruction_summary,
        &analysis,
        symbol_diff.match_percent,
        base_size,
        target_size,
    );

    Ok(Some(SymbolAnalysisResult {
        symbol: symbol.name.clone(),
        demangled: symbol.demangled_name.clone(),
        match_percent: symbol_diff.match_percent,
        size: symbol.size,
        instruction_summary,
        analysis,
        verdict,
    }))
}

/// Get guidance text based on match percentage.
///
/// IMPORTANT: Do not tell agents to "accept" or "give up" here. Match%
/// alone is not enough information to declare a function at-limit. The
/// verdict (`compute_verdict`) does that classification using detected
/// patterns; this tier-text only suggests where to start looking.
///
/// The source permuter is a strong next step for anything in the 95-99.5%
/// band — bool materialization and stack-slot inversions in particular are
/// permuter-class even when patterns suggest otherwise. Register/FPR swaps in
/// that band are better attacked by first identifying the liveness or
/// scheduling difference they are a symptom of; see
/// `docs/research/register-swap-symptom-not-cause.md`.
fn match_guidance(percent: f32) -> &'static str {
    match percent {
        p if p >= 99.5 => {
            "Verdict-driven: check `verdict.classification` — likely at_limit only \
             if a source-immune pattern (anon-namespace-hash, address-relocation, \
             ICF) is detected. Otherwise run the source permuter on this function."
        }
        p if p >= 95.0 => {
            "High-match band. Register/FPR swaps here are usually symptoms — look for the \
             liveness or scheduling difference behind them (a value held across a call, a \
             member we reload that the target doesn't, a producer scheduled after its \
             consumer) before or alongside a permuter sweep. Variable reorder is the lever \
             for stack-slot/offset diffs, not for register-only swaps."
        }
        p if p >= 80.0 => {
            "Fine-tuning band. Check comparison patterns (>= vs >, signed vs \
             unsigned), casting, commutative-operand ordering, then run the \
             permuter on any residual cascade."
        }
        p if p >= 50.0 => {
            "Structural band. Inspect control flow, variable declarations, \
             and missing branches before reaching for the permuter."
        }
        _ => {
            "Likely missing implementation or wrong skeleton — start from \
             m2c output + Ghidra decompilation; do not run the permuter yet."
        }
    }
}

fn render_diff_markdown(output: &DiffOutput, options: &MarkdownOptions) -> String {
    use std::fmt::Write;

    let mut md = String::new();

    let display_name = output.demangled.as_ref().unwrap_or(&output.symbol);

    if options.concise {
        // --- Concise mode: compact ~10-15 line output ---

        // Header: one-line with match%
        if let Some(percent) = output.normalized_match_percent.or(output.fuzzy_match_percent) {
            if let Some(raw) = output.raw_match_percent {
                writeln!(
                    md,
                    "# {} -- Match: {:.1}% normalized ({:.1}% raw)",
                    display_name, percent, raw
                )
                .unwrap();
            } else {
                writeln!(md, "# {} -- Match: {:.1}%", display_name, percent).unwrap();
            }
        } else {
            writeln!(md, "# {}", display_name).unwrap();
        }
        writeln!(md).unwrap();
        if let Some(unit) = &output.unit {
            writeln!(md, "- **Unit**: `{}`", unit).unwrap();
        }
        writeln!(md).unwrap();

        // Instruction Summary: one-liner
        if let Some(summary) = &output.instruction_summary {
            let mut parts: Vec<String> = Vec::new();
            if summary.diff_arg > 0 {
                parts.push(format!("{} diff_arg", summary.diff_arg));
            }
            if summary.diff_op > 0 {
                parts.push(format!("{} diff_op", summary.diff_op));
            }
            if summary.replace > 0 {
                parts.push(format!("{} replace", summary.replace));
            }
            if summary.insert > 0 {
                parts.push(format!("{} insert", summary.insert));
            }
            if summary.delete > 0 {
                parts.push(format!("{} delete", summary.delete));
            }
            if parts.is_empty() {
                writeln!(md, "**Instructions**: {} total | all equal", summary.total).unwrap();
            } else {
                writeln!(md, "**Instructions**: {} total | {}", summary.total, parts.join(", "))
                    .unwrap();
            }
            writeln!(md).unwrap();
        }

        // Region Summary: skip
        // Function Call Diff: skip
        // Insert/Delete Clusters: skip

        // Patterns: one-liner per pattern, no details
        if let Some(analysis) = &output.analysis
            && !analysis.patterns.is_empty()
        {
            let pattern_lines: Vec<String> = analysis
                .patterns
                .iter()
                .map(|pattern| {
                    let summary = pattern.summarize();
                    {
                        let doc_part = if let Some(url) = pattern.doc_urls.first() {
                            format!(" [docs]({})", url)
                        } else {
                            String::new()
                        };
                        format!(
                            "{} ({:?}): {}{}",
                            pattern.pattern.as_str(),
                            pattern.fixability,
                            summary.one_line,
                            doc_part
                        )
                    }
                })
                .collect();
            writeln!(md, "**Patterns**: {}", pattern_lines.join(" | ")).unwrap();
            writeln!(md).unwrap();
        }

        // Verdict: one-liner
        if let Some(verdict) = &output.verdict {
            writeln!(
                md,
                "**Verdict**: {:?} ({:?}) -- {}",
                verdict.classification, verdict.confidence, verdict.recommendation
            )
            .unwrap();
            writeln!(md).unwrap();
        }

        // Instructions: skip entirely in concise mode

        return md;
    }

    // --- Full mode (existing behavior) ---

    // Header
    writeln!(md, "# Diff: {}", display_name).unwrap();
    writeln!(md).unwrap();

    // Basic info
    writeln!(md, "- **Symbol**: `{}`", output.symbol).unwrap();
    if let Some(demangled) = &output.demangled {
        writeln!(md, "- **Demangled**: `{}`", demangled).unwrap();
    }
    if let Some(unit) = &output.unit {
        writeln!(md, "- **Unit**: `{}`", unit).unwrap();
    }
    if let Some(percent) = output.normalized_match_percent.or(output.fuzzy_match_percent) {
        if let Some(raw) = output.raw_match_percent {
            writeln!(md, "- **Match**: {:.1}% normalized ({:.1}% raw)", percent, raw).unwrap();
        } else {
            writeln!(md, "- **Match**: {:.1}%", percent).unwrap();
        }
        // Add match guidance
        let guidance = match_guidance(percent);
        writeln!(md, "  - {}", guidance).unwrap();
    }
    writeln!(md, "- **Target Size**: {} bytes", output.target_size).unwrap();
    writeln!(md, "- **Base Size**: {} bytes", output.base_size).unwrap();
    if let Some(score) = &output.diff_score {
        writeln!(md, "- **Diff Score**: {} / {}", score.score, score.max_score).unwrap();
    }
    writeln!(md).unwrap();

    // Instruction Summary
    if let Some(summary) = &output.instruction_summary {
        writeln!(md, "## Instruction Summary").unwrap();
        writeln!(md).unwrap();
        writeln!(md, "| Type | Count | Percent |").unwrap();
        writeln!(md, "|------|------:|--------:|").unwrap();
        writeln!(md, "| equal | {} | {:.1}% |", summary.equal, summary.equal_percent).unwrap();
        if summary.diff_arg > 0 {
            let pct = (summary.diff_arg as f32 / summary.total.max(1) as f32) * 100.0;
            writeln!(md, "| diff_arg | {} | {:.1}% |", summary.diff_arg, pct).unwrap();
        }
        if summary.diff_op > 0 {
            let pct = (summary.diff_op as f32 / summary.total.max(1) as f32) * 100.0;
            writeln!(md, "| diff_op | {} | {:.1}% |", summary.diff_op, pct).unwrap();
        }
        if summary.replace > 0 {
            let pct = (summary.replace as f32 / summary.total.max(1) as f32) * 100.0;
            writeln!(md, "| replace | {} | {:.1}% |", summary.replace, pct).unwrap();
        }
        if summary.delete > 0 {
            let pct = (summary.delete as f32 / summary.total.max(1) as f32) * 100.0;
            writeln!(md, "| delete | {} | {:.1}% |", summary.delete, pct).unwrap();
        }
        if summary.insert > 0 {
            let pct = (summary.insert as f32 / summary.total.max(1) as f32) * 100.0;
            writeln!(md, "| insert | {} | {:.1}% |", summary.insert, pct).unwrap();
        }
        writeln!(md, "| **Total** | {} | 100.0% |", summary.total).unwrap();
        writeln!(md).unwrap();
    }

    // Region Summary (before patterns, gives structural overview)
    if let Some(regions) = &output.diff_regions
        && !regions.is_empty()
    {
        writeln!(md, "## Region Summary").unwrap();
        writeln!(md).unwrap();
        writeln!(md, "| Region | Instructions | Match % | Notes |").unwrap();
        writeln!(md, "|--------|------------:|--------:|-------|").unwrap();
        for region in regions {
            let notes = region.notes.as_deref().unwrap_or("");
            writeln!(
                md,
                "| {}-{} | {} | {:.0}% | {} |",
                region.start_index,
                region.end_index,
                region.instruction_count,
                region.match_percent,
                notes,
            )
            .unwrap();
        }
        writeln!(md).unwrap();
    }

    // Patterns (summarized for markdown)
    if let Some(analysis) = &output.analysis
        && !analysis.patterns.is_empty()
    {
        writeln!(md, "## Patterns Detected").unwrap();
        writeln!(md).unwrap();
        for pattern in &analysis.patterns {
            let summary = pattern.summarize();
            {
                let doc_part = if let Some(url) = pattern.doc_urls.first() {
                    format!(" [docs]({})", url)
                } else {
                    String::new()
                };
                writeln!(
                    md,
                    "- **{}** ({:?}): {}{}",
                    pattern.pattern.as_str(),
                    pattern.fixability,
                    summary.one_line,
                    doc_part,
                )
                .unwrap();
            }

            // Show top details (max 3)
            for detail in &summary.top_details {
                writeln!(md, "  - {}", detail).unwrap();
            }
            if summary.truncated {
                writeln!(md, "  - ...and {} more", summary.total_items - summary.top_details.len())
                    .unwrap();
            }
        }
        writeln!(md).unwrap();

        // Analysis Summary (compact)
        writeln!(
            md,
            "**Unattributed mismatches**: {} | **Patterns checked**: {}",
            analysis.unattributed_mismatches,
            analysis.patterns_checked.len()
        )
        .unwrap();
        writeln!(md).unwrap();
    }

    // Function Call Diff
    if let Some(call_diff) = &output.call_diff {
        writeln!(md, "## Function Call Diff").unwrap();
        writeln!(md).unwrap();
        if !call_diff.target_only.is_empty() {
            let entries: Vec<String> = call_diff
                .target_only
                .iter()
                .map(|e| format!("`{}` ({})", e.name, e.count))
                .collect();
            writeln!(md, "**Target only:** {}", entries.join(", ")).unwrap();
        }
        if !call_diff.base_only.is_empty() {
            let entries: Vec<String> =
                call_diff.base_only.iter().map(|e| format!("`{}` ({})", e.name, e.count)).collect();
            writeln!(md, "**Base only:** {}", entries.join(", ")).unwrap();
        }
        if !call_diff.count_differs.is_empty() {
            let entries: Vec<String> = call_diff
                .count_differs
                .iter()
                .map(|e| format!("`{}`: target {}, base {}", e.name, e.target_count, e.base_count))
                .collect();
            writeln!(md, "**Count differs:** {}", entries.join("; ")).unwrap();
        }
        writeln!(md).unwrap();
    }

    // Insert/Delete Clusters
    if let Some(clusters) = &output.insert_delete_clusters
        && !clusters.is_empty()
    {
        writeln!(md, "## Insert/Delete Clusters").unwrap();
        writeln!(md).unwrap();
        writeln!(md, "| Range | Inserts | Deletes | Dominant Opcodes |").unwrap();
        writeln!(md, "|-------|--------:|--------:|------------------|").unwrap();
        for cluster in clusters {
            writeln!(
                md,
                "| {}-{} | {} | {} | {} |",
                cluster.start_index,
                cluster.end_index,
                cluster.insert_count,
                cluster.delete_count,
                cluster.dominant_opcodes.join(", "),
            )
            .unwrap();
        }
        writeln!(md).unwrap();
    }

    // Verdict
    if let Some(verdict) = &output.verdict {
        writeln!(
            md,
            "## Verdict: {:?} ({:?} confidence)",
            verdict.classification, verdict.confidence
        )
        .unwrap();
        writeln!(md).unwrap();
        writeln!(md, "{}", verdict.explanation).unwrap();
        writeln!(md).unwrap();

        // Verdict Factors Table
        if !verdict.factors.is_empty() {
            writeln!(md, "### Verdict Factors").unwrap();
            writeln!(md).unwrap();
            writeln!(md, "| Factor | Value | Threshold | Result |").unwrap();
            writeln!(md, "|--------|-------|-----------|--------|").unwrap();
            for factor in &verdict.factors {
                let value_str = match &factor.value {
                    serde_json::Value::Bool(b) => b.to_string(),
                    serde_json::Value::Number(n) => {
                        if let Some(f) = n.as_f64() {
                            format!("{:.2}", f)
                        } else {
                            n.to_string()
                        }
                    }
                    v => v.to_string(),
                };
                let threshold_str =
                    factor.threshold.map_or("-".to_string(), |t| format!("{:.1}", t));
                writeln!(
                    md,
                    "| {} | {} | {} | {} |",
                    factor.name, value_str, threshold_str, factor.result
                )
                .unwrap();
            }
            writeln!(md).unwrap();
        }

        writeln!(md, "**Recommendation**: {}", verdict.recommendation).unwrap();
        writeln!(md).unwrap();

        if !verdict.suggestions.is_empty() {
            writeln!(md, "### Suggestions").unwrap();
            writeln!(md).unwrap();
            for (i, suggestion) in verdict.suggestions.iter().enumerate() {
                if let Some(url) = &suggestion.doc_url {
                    writeln!(md, "{}. {} ([docs]({}))", i + 1, suggestion.action, url).unwrap();
                } else {
                    writeln!(md, "{}. {}", i + 1, suggestion.action).unwrap();
                }
            }
            writeln!(md).unwrap();
        }

        if !verdict.doc_urls.is_empty() {
            writeln!(md, "### Related Documentation").unwrap();
            writeln!(md).unwrap();
            for url in &verdict.doc_urls {
                writeln!(md, "- [{}]({})", url, url).unwrap();
            }
            writeln!(md).unwrap();
        }
    }

    // Instructions
    if let Some(instructions) = &output.instructions {
        if options.full_listing {
            // Full listing: show all instructions
            writeln!(md, "## Full Instruction Listing").unwrap();
            writeln!(md).unwrap();
            writeln!(md, "| Index | Target | Base | Match |").unwrap();
            writeln!(md, "|------:|--------|------|-------|").unwrap();

            for instr in instructions {
                let is_mismatch = instr.match_type != "equal";
                let (target_str, base_str, match_str) = format_instruction_row(instr, is_mismatch);
                writeln!(md, "| {} | {} | {} | {} |", instr.index, target_str, base_str, match_str)
                    .unwrap();
            }
            writeln!(md).unwrap();
        } else if let Some(context) = options.context {
            // Context mode: show N instructions before/after each mismatch
            let mismatch_indices: Vec<usize> = instructions
                .iter()
                .enumerate()
                .filter(|(_, i)| i.match_type != "equal")
                .map(|(idx, _)| idx)
                .collect();

            if !mismatch_indices.is_empty() {
                writeln!(md, "## Instruction Mismatches (with context)").unwrap();
                writeln!(md).unwrap();
                writeln!(md, "| Index | Target | Base | Match |").unwrap();
                writeln!(md, "|------:|--------|------|-------|").unwrap();

                // Build set of indices to show (mismatch + context)
                let mut indices_to_show: Vec<usize> = Vec::new();
                for &mismatch_idx in &mismatch_indices {
                    let start = mismatch_idx.saturating_sub(context);
                    let end = (mismatch_idx + context + 1).min(instructions.len());
                    for i in start..end {
                        if !indices_to_show.contains(&i) {
                            indices_to_show.push(i);
                        }
                    }
                }
                indices_to_show.sort();

                // Track last printed index for separator detection
                let mut last_idx: Option<usize> = None;

                for &idx in &indices_to_show {
                    // Add separator if there's a gap
                    if let Some(last) = last_idx
                        && idx > last + 1
                    {
                        writeln!(md, "| ... | | | |").unwrap();
                    }

                    let instr = &instructions[idx];
                    let is_mismatch = instr.match_type != "equal";
                    let (target_str, base_str, match_str) =
                        format_instruction_row(instr, is_mismatch);

                    if is_mismatch {
                        // Bold mismatch lines
                        writeln!(
                            md,
                            "| **{}** | **{}** | **{}** | **{}** |",
                            instr.index, target_str, base_str, match_str
                        )
                        .unwrap();
                    } else {
                        writeln!(md, "| {} | {} | {} | |", instr.index, target_str, base_str)
                            .unwrap();
                    }

                    last_idx = Some(idx);
                }
                writeln!(md).unwrap();
            }
        } else {
            // Default: mismatches only
            let mismatches: Vec<_> =
                instructions.iter().filter(|i| i.match_type != "equal").collect();

            if !mismatches.is_empty() {
                writeln!(md, "## Instruction Mismatches").unwrap();
                writeln!(md).unwrap();
                writeln!(md, "| Index | Target | Base | Match |").unwrap();
                writeln!(md, "|------:|--------|------|-------|").unwrap();

                for instr in mismatches {
                    let (target_str, base_str, match_str) = format_instruction_row(instr, true);
                    writeln!(
                        md,
                        "| {} | {} | {} | {} |",
                        instr.index, target_str, base_str, match_str
                    )
                    .unwrap();
                }
                writeln!(md).unwrap();
            }
        }
    }

    md
}

/// Format an instruction for markdown table output.
fn format_instruction_row(
    instr: &InstructionDiffOutput,
    include_match: bool,
) -> (String, String, String) {
    let target_str = instr
        .target
        .as_ref()
        .map(|t| {
            if let Some(args) = &t.args {
                format!("`{} {}`", t.opcode, args)
            } else {
                format!("`{}`", t.opcode)
            }
        })
        .unwrap_or_else(|| "-".to_string());

    let base_str = instr
        .base
        .as_ref()
        .map(|b| {
            if let Some(args) = &b.args {
                format!("`{} {}`", b.opcode, args)
            } else {
                format!("`{}`", b.opcode)
            }
        })
        .unwrap_or_else(|| "-".to_string());

    let match_str = if include_match { instr.match_type.clone() } else { String::new() };

    (target_str, base_str, match_str)
}

fn write_diff_output(
    output: &DiffOutput,
    path: Option<&Utf8PlatformPath>,
    format: DiffOutputFormat,
    md_options: &MarkdownOptions,
) -> Result<()> {
    let write_content = |writer: &mut dyn Write| -> Result<()> {
        match format {
            DiffOutputFormat::Json => {
                serde_json::to_writer(writer, output).context("Failed to write JSON output")?;
            }
            DiffOutputFormat::JsonPretty => {
                serde_json::to_writer_pretty(writer, output)
                    .context("Failed to write JSON output")?;
            }
            DiffOutputFormat::Markdown => {
                let md = render_diff_markdown(output, md_options);
                writer.write_all(md.as_bytes()).context("Failed to write markdown output")?;
            }
            DiffOutputFormat::Tui | DiffOutputFormat::Proto => unreachable!(),
        }
        Ok(())
    };

    match path {
        Some(p) if p != Utf8PlatformPath::new("-") => {
            let file = File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .open(p)
                .with_context(|| format!("Failed to create file {}", p))?;
            let mut writer = BufWriter::new(file);
            write_content(&mut writer)?;
            writer.flush().context("Failed to flush output file")?;
        }
        _ => {
            let mut stdout = stdout();
            write_content(&mut stdout)?;
            if format.is_json() {
                println!(); // Add newline after JSON
            }
        }
    }
    Ok(())
}

pub struct AppState {
    pub jobs: JobQueue,
    pub waker: Arc<TermWaker>,
    pub project_dir: Option<Utf8PlatformPathBuf>,
    pub project_config: Option<ProjectConfig>,
    pub target_path: Option<Utf8PlatformPathBuf>,
    pub base_path: Option<Utf8PlatformPathBuf>,
    pub left_status: Option<BuildStatus>,
    pub right_status: Option<BuildStatus>,
    pub left_obj: Option<(Object, ObjectDiff)>,
    pub right_obj: Option<(Object, ObjectDiff)>,
    pub prev_obj: Option<(Object, ObjectDiff)>,
    pub reload_time: Option<time::OffsetDateTime>,
    pub time_format: Vec<time::format_description::FormatItem<'static>>,
    pub watcher: Option<Watcher>,
    pub modified: Arc<AtomicBool>,
    pub diff_obj_config: DiffObjConfig,
    pub mapping_config: MappingConfig,
}

fn create_objdiff_config(state: &AppState) -> ObjDiffConfig {
    ObjDiffConfig {
        build_config: BuildConfig {
            project_dir: state.project_dir.clone(),
            custom_make: state
                .project_config
                .as_ref()
                .and_then(|c| c.custom_make.as_ref())
                .cloned(),
            custom_args: state
                .project_config
                .as_ref()
                .and_then(|c| c.custom_args.as_ref())
                .cloned(),
            selected_wsl_distro: None,
        },
        build_base: state.project_config.as_ref().is_some_and(|p| p.build_base.unwrap_or(true)),
        build_target: state
            .project_config
            .as_ref()
            .is_some_and(|p| p.build_target.unwrap_or(false)),
        target_path: state.target_path.clone(),
        base_path: state.base_path.clone(),
        diff_obj_config: state.diff_obj_config.clone(),
        mapping_config: state.mapping_config.clone(),
    }
}

/// The configuration for a single object file.
#[derive(Default, Clone, serde::Deserialize, serde::Serialize)]
pub struct ObjectConfig {
    pub name: String,
    #[serde(default, with = "platform_path_serde_option")]
    pub target_path: Option<Utf8PlatformPathBuf>,
    #[serde(default, with = "platform_path_serde_option")]
    pub base_path: Option<Utf8PlatformPathBuf>,
    pub metadata: ProjectObjectMetadata,
    pub complete: Option<bool>,
}

impl ObjectConfig {
    pub fn new(
        object: &ProjectObject,
        project_dir: &Utf8PlatformPath,
        target_obj_dir: Option<&Utf8PlatformPath>,
        base_obj_dir: Option<&Utf8PlatformPath>,
    ) -> Self {
        let target_path = if let (Some(target_obj_dir), Some(path), None) =
            (target_obj_dir, &object.path, &object.target_path)
        {
            Some(target_obj_dir.join(path.with_platform_encoding()))
        } else {
            object.target_path.as_ref().map(|path| project_dir.join(path.with_platform_encoding()))
        };
        let base_path = if let (Some(base_obj_dir), Some(path), None) =
            (base_obj_dir, &object.path, &object.base_path)
        {
            Some(base_obj_dir.join(path.with_platform_encoding()))
        } else {
            object.base_path.as_ref().map(|path| project_dir.join(path.with_platform_encoding()))
        };
        Self {
            name: object.name().to_string(),
            target_path,
            base_path,
            metadata: object.metadata.clone().unwrap_or_default(),
            complete: object.complete(),
        }
    }
}

impl AppState {
    fn reload(&mut self) -> Result<()> {
        let config = create_objdiff_config(self);
        self.jobs.push_once(Job::ObjDiff, || start_build(Waker::from(self.waker.clone()), config));
        Ok(())
    }

    fn check_jobs(&mut self) -> Result<bool> {
        let mut redraw = false;
        self.jobs.collect_results();
        for result in mem::take(&mut self.jobs.results) {
            match result {
                JobResult::None => unreachable!("Unexpected JobResult::None"),
                JobResult::ObjDiff(result) => {
                    let result = result.unwrap();
                    self.left_status = Some(result.first_status);
                    self.right_status = Some(result.second_status);
                    self.left_obj = result.first_obj;
                    self.right_obj = result.second_obj;
                    self.reload_time = Some(result.time);
                    redraw = true;
                }
                JobResult::CheckUpdate(_) => todo!("CheckUpdate"),
                JobResult::Update(_) => todo!("Update"),
                JobResult::CreateScratch(_) => todo!("CreateScratch"),
            }
        }
        Ok(redraw)
    }
}

#[derive(Default)]
pub struct TermWaker(pub AtomicBool);

impl Wake for TermWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn run_interactive(
    args: Args,
    target_path: Option<Utf8PlatformPathBuf>,
    base_path: Option<Utf8PlatformPathBuf>,
    project_config: Option<ProjectConfig>,
    unit_options: Option<ProjectOptions>,
    project_dir: Option<Utf8PlatformPathBuf>,
) -> Result<()> {
    let Some(symbol_name) = &args.symbol else { bail!("Interactive mode requires a symbol name") };
    let time_format = time::format_description::parse_borrowed::<2>("[hour]:[minute]:[second]")
        .context("Failed to parse time format")?;
    let (diff_obj_config, mapping_config) = build_config_from_args(
        &args,
        project_config.as_ref(),
        unit_options.as_ref(),
        project_dir.as_deref(),
    )?;
    let mut state = AppState {
        jobs: Default::default(),
        waker: Default::default(),
        project_dir: args.project.clone(),
        project_config,
        target_path,
        base_path,
        left_status: None,
        right_status: None,
        left_obj: None,
        right_obj: None,
        prev_obj: None,
        reload_time: None,
        time_format,
        watcher: None,
        modified: Default::default(),
        diff_obj_config,
        mapping_config,
    };
    if let (Some(project_dir), Some(project_config)) = (&state.project_dir, &state.project_config) {
        let watch_patterns = project_config.build_watch_patterns()?;
        let ignore_patterns = project_config.build_ignore_patterns()?;
        state.watcher = Some(create_watcher(
            state.modified.clone(),
            project_dir.as_ref(),
            build_globset(&watch_patterns)?,
            build_globset(&ignore_patterns)?,
            Waker::from(state.waker.clone()),
        )?);
    }
    let mut view: Box<dyn UiView> =
        Box::new(FunctionDiffUi { symbol_name: symbol_name.clone(), ..Default::default() });
    state.reload()?;

    crossterm_panic_handler();
    enable_raw_mode()?;
    crossterm::queue!(
        stdout(),
        EnterAlternateScreen,
        EnableMouseCapture,
        SetTitle(format!("{symbol_name} - objdiff")),
    )?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut result = EventResult { redraw: true, ..Default::default() };
    'outer: loop {
        if result.redraw {
            terminal.draw(|f| {
                loop {
                    result.redraw = false;
                    view.draw(&state, f, &mut result);
                    result.click_xy = None;
                    if !result.redraw {
                        break;
                    }
                    // Clear buffer on redraw
                    f.buffer_mut().reset();
                }
            })?;
        }
        loop {
            if event::poll(Duration::from_millis(100))? {
                match view.handle_event(&mut state, event::read()?) {
                    EventControlFlow::Break => break 'outer,
                    EventControlFlow::Continue(r) => result = r,
                    EventControlFlow::Reload => {
                        state.reload()?;
                        result.redraw = true;
                    }
                }
                break;
            } else if state.waker.0.swap(false, Ordering::Relaxed) {
                if state.modified.swap(false, Ordering::Relaxed) {
                    state.reload()?;
                }
                result.redraw = true;
                break;
            }
        }
        if state.check_jobs()? {
            result.redraw = true;
            view.reload(&state)?;
        }
    }

    // Reset terminal
    disable_raw_mode()?;
    crossterm::execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_instr(
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

    // =========================================================================
    // build_data_diff() tests
    // =========================================================================

    #[test]
    fn test_build_data_diff_segments_relocs() {
        use objdiff_core::diff::{
            DataDiff, DataDiffKind, DataDiffRow, DataRelocationDiff, SymbolDiff,
        };
        use objdiff_core::obj::{Relocation, RelocationFlags, Symbol};

        // Symbols table for relocation target-name resolution.
        let symbols = vec![
            Symbol { name: "_self".to_string(), ..Default::default() },
            Symbol { name: "SomeVtableEntry".to_string(), ..Default::default() },
        ];

        // A 4-byte relocation at offset 4 (absolute 0x1004) that mismatches.
        let reloc = DataRelocationDiff {
            reloc: Relocation {
                flags: RelocationFlags::Elf(1),
                address: 0x1004,
                target_symbol: 1,
                addend: 0,
            },
            range: 0x1004..0x1008,
            kind: DataDiffKind::Replace,
        };

        let symbol_diff = SymbolDiff {
            match_percent: Some(75.0),
            // Two rows; row 0 carries the reloc and is split into two equal
            // segments that must merge; row 1 has a replace then an insert.
            data_rows: vec![
                DataDiffRow {
                    address: 0x1000,
                    segments: vec![
                        DataDiff { data: vec![0; 8], size: 8, kind: DataDiffKind::None },
                        DataDiff { data: vec![0; 8], size: 8, kind: DataDiffKind::None },
                    ],
                    relocations: vec![reloc.clone()],
                },
                DataDiffRow {
                    address: 0x1010,
                    segments: vec![
                        DataDiff {
                            data: vec![0xde, 0xad, 0xbe, 0xef],
                            size: 4,
                            kind: DataDiffKind::Replace,
                        },
                        DataDiff { data: vec![], size: 4, kind: DataDiffKind::Insert },
                    ],
                    // Same reloc repeated (spans into this row) — must de-dup.
                    relocations: vec![reloc.clone()],
                },
            ],
            ..Default::default()
        };

        // --- Single-side (no matched other side): back-compatible behavior. ---
        let out = build_data_diff(&symbols, &symbol_diff, None)
            .expect("data symbol should produce output");

        assert_eq!(out.match_percent, Some(75.0));
        // total = equal(16) + replace(4); insert is not bytes-on-this-side.
        assert_eq!(out.total_byte_count, 20);
        // mismatch = replace(4) + insert(4).
        assert_eq!(out.mismatch_byte_count, 8);

        // Adjacent equal segments merge into one 16-byte run.
        assert_eq!(out.segments.len(), 3);
        assert_eq!((out.segments[0].offset, out.segments[0].size, out.segments[0].kind.as_str()), (0, 16, "equal"));
        assert_eq!(out.segments[0].bytes, None);
        assert_eq!((out.segments[1].offset, out.segments[1].size, out.segments[1].kind.as_str()), (16, 4, "replace"));
        assert_eq!(out.segments[1].bytes.as_deref(), Some("deadbeef"));
        assert_eq!((out.segments[2].offset, out.segments[2].size, out.segments[2].kind.as_str()), (20, 4, "insert"));
        assert_eq!(out.segments[2].bytes, None); // inserts have no bytes on this side
        // With no other side, base_bytes is never populated.
        assert!(out.segments.iter().all(|s| s.base_bytes.is_none()));

        // Relocation resolved to its target symbol name and de-duplicated.
        assert_eq!(out.relocations.len(), 1);
        assert_eq!(out.relocations[0].offset, 4);
        assert_eq!(out.relocations[0].size, 4);
        assert_eq!(out.relocations[0].kind, "replace");
        assert_eq!(out.relocations[0].target_symbol, "SomeVtableEntry");
        // No other side => no base-side reloc naming.
        assert_eq!(out.relocations[0].base_target_symbol, None);

        // --- Both sides: structurally identical rows, different bytes/relocs. ---
        // (Equal-run bytes are irrelevant since equal segments emit no bytes.)
        let other_symbols = vec![
            Symbol { name: "_self".to_string(), ..Default::default() },
            Symbol { name: "BaseVtableEntry".to_string(), ..Default::default() },
            Symbol { name: "ExtraBaseEntry".to_string(), ..Default::default() },
        ];
        let other_symbol_diff = SymbolDiff {
            match_percent: Some(75.0),
            data_rows: vec![
                DataDiffRow {
                    address: 0x2000,
                    segments: vec![
                        DataDiff { data: vec![0; 8], size: 8, kind: DataDiffKind::None },
                        DataDiff { data: vec![0; 8], size: 8, kind: DataDiffKind::None },
                    ],
                    // Same offset (4) as this side's reloc, but a different target.
                    relocations: vec![DataRelocationDiff {
                        reloc: Relocation {
                            flags: RelocationFlags::Elf(1),
                            address: 0x2004,
                            target_symbol: 1,
                            addend: 0,
                        },
                        range: 0x2004..0x2008,
                        kind: DataDiffKind::Replace,
                    }],
                },
                DataDiffRow {
                    address: 0x2010,
                    segments: vec![
                        DataDiff {
                            data: vec![0x12, 0x34, 0x56, 0x78],
                            size: 4,
                            kind: DataDiffKind::Replace,
                        },
                        // The inserted bytes live on the OTHER (base) side.
                        DataDiff {
                            data: vec![0xaa, 0xbb, 0xcc, 0xdd],
                            size: 4,
                            kind: DataDiffKind::Insert,
                        },
                    ],
                    // A relocation present only on the base side (offset 20).
                    relocations: vec![DataRelocationDiff {
                        reloc: Relocation {
                            flags: RelocationFlags::Elf(1),
                            address: 0x2014,
                            target_symbol: 2,
                            addend: 0,
                        },
                        range: 0x2014..0x2018,
                        kind: DataDiffKind::Insert,
                    }],
                },
            ],
            ..Default::default()
        };

        let out = build_data_diff(&symbols, &symbol_diff, Some((&other_symbols, &other_symbol_diff)))
            .expect("data symbol should produce output");
        // equal run: still no bytes on either side.
        assert_eq!(out.segments[0].bytes, None);
        assert_eq!(out.segments[0].base_bytes, None);
        // replace: this side unchanged, other side now visible side-by-side.
        assert_eq!(out.segments[1].bytes.as_deref(), Some("deadbeef"));
        assert_eq!(out.segments[1].base_bytes.as_deref(), Some("12345678"));
        // insert: no bytes on this side, but the inserted base bytes show up.
        assert_eq!(out.segments[2].bytes, None);
        assert_eq!(out.segments[2].base_bytes.as_deref(), Some("aabbccdd"));

        // Relocations: the offset-4 reloc now names both sides; the base-only
        // reloc at offset 20 surfaces as an "insert".
        assert_eq!(out.relocations.len(), 2);
        assert_eq!(out.relocations[0].offset, 4);
        assert_eq!(out.relocations[0].target_symbol, "SomeVtableEntry");
        assert_eq!(out.relocations[0].base_target_symbol.as_deref(), Some("BaseVtableEntry"));
        assert_eq!(out.relocations[1].offset, 20);
        assert_eq!(out.relocations[1].kind, "insert");
        assert_eq!(out.relocations[1].target_symbol, "");
        assert_eq!(out.relocations[1].base_target_symbol.as_deref(), Some("ExtraBaseEntry"));

        // --- Defensive: a mismatched-shape other side disables byte pairing. ---
        let misshaped = SymbolDiff {
            data_rows: vec![DataDiffRow {
                address: 0x3000,
                segments: vec![DataDiff { data: vec![0; 4], size: 4, kind: DataDiffKind::None }],
                relocations: vec![],
            }],
            ..Default::default()
        };
        let out = build_data_diff(&symbols, &symbol_diff, Some((&symbols, &misshaped))).unwrap();
        assert!(out.segments.iter().all(|s| s.base_bytes.is_none()));
    }

    #[test]
    fn test_build_data_diff_code_symbol_is_none() {
        // A symbol with no data_rows (e.g. a function) yields no data diff.
        let symbol_diff = objdiff_core::diff::SymbolDiff::default();
        assert!(build_data_diff(&[], &symbol_diff, None).is_none());
    }

    // =========================================================================
    // match_guidance() tests
    // =========================================================================

    #[test]
    fn test_match_guidance_thresholds() {
        let g99 = match_guidance(99.5);
        assert!(g99.contains("Verdict-driven"));
        assert!(g99.contains("permuter"));

        let g95 = match_guidance(96.0);
        assert!(g95.contains("High-match"));
        assert!(g95.contains("permuter"));

        let g80 = match_guidance(85.0);
        assert!(g80.contains("Fine-tuning"));

        let g50 = match_guidance(60.0);
        assert!(g50.contains("Structural"));

        let glow = match_guidance(30.0);
        assert!(glow.contains("missing implementation"));
    }

    // =========================================================================
    // format_instruction_row() tests
    // =========================================================================

    #[test]
    fn test_format_row_both_sides() {
        let instr =
            make_test_instr(0, "diff_arg", Some("mr"), Some("r3, r4"), Some("mr"), Some("r4, r3"));
        let (target, base, match_str) = format_instruction_row(&instr, true);
        assert!(target.contains("mr"));
        assert!(target.contains("r3, r4"));
        assert!(base.contains("r4, r3"));
        assert_eq!(match_str, "diff_arg");
    }

    #[test]
    fn test_format_row_missing_side() {
        let instr = make_test_instr(0, "insert", None, None, Some("stw"), Some("r3, 0(r1)"));
        let (target, base, match_str) = format_instruction_row(&instr, true);
        assert_eq!(target, "-");
        assert!(base.contains("stw"));
        assert_eq!(match_str, "insert");
    }

    #[test]
    fn test_format_row_no_match() {
        let instr =
            make_test_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4"));
        let (_, _, match_str) = format_instruction_row(&instr, false);
        assert!(match_str.is_empty());
    }

    // =========================================================================
    // render_diff_markdown() tests
    // =========================================================================

    fn make_test_output(
        instructions: Vec<InstructionDiffOutput>,
        analysis: Option<super::super::analysis::Analysis>,
        verdict: Option<super::super::analysis::Verdict>,
    ) -> DiffOutput {
        let summary = InstructionSummary::from_instructions(&instructions);
        DiffOutput {
            symbol: "test_func".to_string(),
            demangled: Some("TestFunc()".to_string()),
            unit: Some("test.o".to_string()),
            target_size: 100,
            base_size: 100,
            fuzzy_match_percent: Some(90.0),
            normalized_match_percent: Some(90.0),
            raw_match_percent: Some(85.0),
            diff_score: None,
            build_status: None,
            instruction_summary: Some(summary),
            analysis,
            verdict,
            call_diff: None,
            insert_delete_clusters: None,
            diff_regions: None,
            instructions: Some(instructions),
            masked_equal_rows: 0,
            reloc_ignored_rows: 0,
            masked_equal_symbol: false,
            data_diff: None,
        }
    }

    #[test]
    fn test_markdown_concise_mode() {
        let instructions = vec![
            make_test_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_test_instr(1, "diff_arg", Some("mr"), Some("r3, r4"), Some("mr"), Some("r4, r3")),
        ];
        let output = make_test_output(instructions, None, None);
        let options = MarkdownOptions { concise: true, ..Default::default() };
        let md = render_diff_markdown(&output, &options);
        assert!(md.contains("Match: 90.0%"));
        assert!(md.contains("**Instructions**"));
        // Concise mode should not include instruction table
        assert!(!md.contains("| Index |"));
    }

    #[test]
    fn test_markdown_context_mode() {
        let mut instructions = Vec::new();
        // Mismatch at index 3 and index 15 (far apart, will create a gap with context=2)
        for i in 0..20 {
            if i == 3 || i == 15 {
                instructions.push(make_test_instr(
                    i,
                    "diff_arg",
                    Some("mr"),
                    Some("r3, r4"),
                    Some("mr"),
                    Some("r4, r3"),
                ));
            } else {
                instructions.push(make_test_instr(
                    i,
                    "equal",
                    Some("mr"),
                    Some("r3, r4"),
                    Some("mr"),
                    Some("r3, r4"),
                ));
            }
        }
        let output = make_test_output(instructions, None, None);
        let options = MarkdownOptions { context: Some(2), ..Default::default() };
        let md = render_diff_markdown(&output, &options);
        assert!(md.contains("with context"));
        // Gap between context windows of mismatch at 3 (shows 1-5) and 15 (shows 13-17)
        assert!(md.contains("..."));
    }

    #[test]
    fn test_markdown_full_listing() {
        let instructions = vec![
            make_test_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_test_instr(1, "diff_arg", Some("mr"), Some("r3, r4"), Some("mr"), Some("r4, r3")),
            make_test_instr(2, "equal", Some("blr"), None, Some("blr"), None),
        ];
        let output = make_test_output(instructions, None, None);
        let options = MarkdownOptions { full_listing: true, ..Default::default() };
        let md = render_diff_markdown(&output, &options);
        assert!(md.contains("Full Instruction Listing"));
        // Should show all 3 instructions
        assert!(md.contains("| 0 |"));
        assert!(md.contains("| 1 |"));
        assert!(md.contains("| 2 |"));
    }

    #[test]
    fn test_markdown_default_mismatches_only() {
        let instructions = vec![
            make_test_instr(0, "equal", Some("mr"), Some("r3, r4"), Some("mr"), Some("r3, r4")),
            make_test_instr(1, "diff_arg", Some("mr"), Some("r3, r4"), Some("mr"), Some("r4, r3")),
            make_test_instr(2, "equal", Some("blr"), None, Some("blr"), None),
        ];
        let output = make_test_output(instructions, None, None);
        let options = MarkdownOptions::default();
        let md = render_diff_markdown(&output, &options);
        assert!(md.contains("Instruction Mismatches"));
        // Should show only the mismatch at index 1 in the instruction table
        assert!(md.contains("| 1 |"));
        // The mismatch section should not have rows for index 0 or 2
        // (Note: summary table may contain "| 2 |" for counts, so check within instruction section)
        let instr_section = md.split("## Instruction Mismatches").nth(1).unwrap();
        assert!(!instr_section.contains("| 0 |"));
        // Index 2 should not appear in the mismatch table
        assert!(!instr_section.contains("\n| 2 |"));
    }
}
