use std::{
    collections::{BTreeMap, HashMap},
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

    fn is_json(&self) -> bool { matches!(self, Self::Json | Self::JsonPretty) }

    fn is_non_tui(&self) -> bool { !matches!(self, Self::Tui) }
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
    pub fn is_register(&self) -> bool { matches!(self, TypedArg::Register(_)) }

    /// Check if this is a numeric value (signed or unsigned).
    /// Used by analysis pattern detection and external consumers.
    #[allow(dead_code)]
    pub fn is_numeric(&self) -> bool { matches!(self, TypedArg::Signed(_) | TypedArg::Unsigned(_)) }

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
    /// Unit name within project (with --batch: diff every symbol in this unit)
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
    /// Rebuild object file before diffing (runs the project's custom_make, or
    /// ninja)
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

/// Resolve a `-u` / `--unit` argument to a position in `names`.
///
/// ONE resolver, shared by the one-shot path and batch mode, so `-u` cannot
/// come to mean two different things depending on which mode you are in. It
/// meant nothing at all in batch mode until this commit — `run_batch` never
/// read the flag and walked the whole project regardless — and the way that
/// survived is that it failed *silently*: a caller passing `-u` got a
/// plausible-looking result set that simply had the wrong scope.
///
/// Match priority, first non-empty wins:
///   0. Exact: `name == needle`. Fast path, and it preserves any caller that
///      passes the canonical name.
///   1. Path-component suffix: `name` ends with `/needle` — accepts
///      `system/synth/MidiSynth` for `main/system/synth/MidiSynth`.
///   2. Basename: the final `/`-separated segment equals `needle` — accepts
///      the single-token `MidiSynth`.
///   3. Substring anywhere in the name.
///
/// A needle matching nothing is an error naming the unit; a needle matching
/// several is an error listing them. Never an empty result, never a silent
/// pick — the caller asked for a specific unit and gets either that unit or a
/// message saying why not.
///
/// `names` is expected in project-declared order; the returned position indexes
/// it, so callers ordered by that same order can use it directly as a handle.
fn resolve_unit_name(names: &[&str], needle: &str) -> Result<usize> {
    // Exact match first.
    if let Some(pos) = names.iter().position(|name| *name == needle) {
        return Ok(pos);
    }

    let hits_by = |pred: &dyn Fn(&str) -> bool| -> Vec<usize> {
        names.iter().enumerate().filter(|(_, name)| pred(name)).map(|(pos, _)| pos).collect()
    };

    let suffix_pattern = format!("/{}", needle);
    let mut hits = hits_by(&|name: &str| name.ends_with(&suffix_pattern));
    if hits.is_empty() {
        hits = hits_by(&|name: &str| name.rsplit('/').next() == Some(needle));
    }
    if hits.is_empty() {
        hits = hits_by(&|name: &str| name.contains(needle));
    }

    match hits.len() {
        0 => Err(anyhow!(
            "Unit not found: {}\n\
             Hint: pass a path-suffix (e.g. `system/synth/MidiSynth`) \
             or basename (e.g. `MidiSynth`) — these resolve against \
             the project's full unit names (e.g. `main/system/synth/MidiSynth`).",
            needle
        )),
        1 => {
            let pos = hits[0];
            // Tell the user what we resolved to so they can copy the canonical
            // name into scripts if needed. (Unreachable when input already
            // equals the canonical name — that took the exact path above.)
            eprintln!("objdiff: resolved unit `{}` -> `{}`", needle, names[pos]);
            Ok(pos)
        }
        n => {
            let mut matched: Vec<&str> = hits.iter().map(|pos| names[*pos]).collect();
            matched.sort_unstable();
            let preview: Vec<&&str> = matched.iter().take(8).collect();
            let trailer = if n > 8 { format!("\n  ... and {} more", n - 8) } else { String::new() };
            Err(anyhow!(
                "Ambiguous unit `{}`: {} matches.\n  {}{}\n\
                 Use a longer suffix or the canonical name.",
                needle,
                n,
                preview.iter().map(|s| s.to_string()).collect::<Vec<_>>().join("\n  "),
                trailer
            ))
        }
    }
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
                let names: Vec<&str> = objects.iter().map(|(obj, _)| obj.name.as_str()).collect();
                let pos = resolve_unit_name(&names, u)?;
                let (obj, idx) = &objects[pos];
                (obj, *idx)
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

    // Run the build if requested (builds the base/decompiled object, not the
    // target/reference).
    //
    // This honours the project's `custom_make`/`custom_args`, like every other
    // build path in objdiff. It used to hardcode `Command::new("ninja")`, which
    // silently bypassed wrappers projects rely on -- notably `tools/ninja-locked`
    // in the rb3/rb3-xenon decomps, whose whole purpose is to serialize
    // concurrent ninja invocations in one build directory (concurrent ninja
    // there corrupts `.ninja_log`/`.ninja_deps`). Those projects set
    // `custom_make` and reasonably believed it applied.
    //
    // `--build` is a fork-only feature; upstream has no such flag and no
    // `Command::new` in this crate. `objdiff_core::build::run_make` has honoured
    // `custom_make` all along, and this crate's own TUI path builds a
    // `BuildConfig` from `project_config.custom_make` -- the one-shot path
    // simply never reached for it. So this is an oversight in a fork commit,
    // not an upstream design decision.
    //
    // The build still STREAMS to the terminal rather than going through
    // `run_make`, which captures into a `BuildStatus`; `--build`'s output has
    // always been inherited and callers parse the JSON on stdout, so capturing
    // would be a behavioural change beyond the defect being fixed.
    if args.build {
        if let Some(base) = &base_path {
            let make =
                project_config.as_ref().and_then(|c| c.custom_make.as_deref()).unwrap_or("ninja");
            let make_args: &[String] =
                project_config.as_ref().and_then(|c| c.custom_args.as_deref()).unwrap_or(&[]);

            let build_command = |target: Option<&str>| -> Result<()> {
                let mut command = Command::new(make);
                command.args(make_args);
                if let Some(t) = target {
                    command.arg(t);
                }
                // Run in the project directory. Without this the build ran in
                // the CALLER's cwd against a target belonging to the project --
                // latent today only because every in-repo call site already
                // passes cwd=repo_root.
                if let Some(dir) = &project_dir {
                    command.current_dir(dir);
                }
                let status = command
                    .status()
                    .with_context(|| format!("Failed to run build command `{}`", make))?;
                if !status.success() {
                    match target {
                        Some(t) => bail!("Incremental build failed for {}", t),
                        None => bail!("Full build failed"),
                    }
                }
                Ok(())
            };

            // Determine build mode: incremental (default) or full
            let use_incremental = !args.full_build;

            if use_incremental {
                // Incremental build: target specific .obj file.
                // Rewrite the path to one relative to the project dir, which is
                // where the build runs -- ninja matches targets against the
                // paths its manifest declares, so an absolute or caller-relative
                // spelling is an `unknown target`.
                //
                // `base` is built by joining the project dir, so its spelling
                // follows `--project`: absolute for `-p /abs/proj`, but
                // caller-cwd-relative for `-p proj`. Resolve BOTH against the
                // caller's cwd before stripping, so the emitted target is
                // project-dir-relative either way. Handling only the absolute
                // case would leave `-p proj` emitting `proj/obj/base.o` to a
                // command that has already chdir'd into `proj`.
                let build_target = {
                    let cwd = std::env::current_dir()?;
                    let absolutize = |p: &std::path::Path| -> std::path::PathBuf {
                        if p.is_absolute() { p.to_path_buf() } else { cwd.join(p) }
                    };
                    let rel_to = match &project_dir {
                        Some(dir) => absolutize(std::path::Path::new(dir.as_str())),
                        // No project: the build inherits the caller's cwd, so
                        // that is what the target is relative to.
                        None => cwd.clone(),
                    };
                    absolutize(std::path::Path::new(base.as_str()))
                        .strip_prefix(&rel_to)
                        .map(|p| p.to_string_lossy().into_owned())
                        // Reachable two ways: the project's own config spells an
                        // absolute out-of-tree target/base path (`Path::join`
                        // REPLACES rather than appends when its argument is
                        // absolute, so such a path never sits under the project
                        // dir), and --target/--base mode, where there is no
                        // project dir to be relative to. Either way the spelling
                        // the config or the caller gave is the right thing to
                        // hand the build; do not invent one.
                        .unwrap_or_else(|_| base.to_string())
                };

                eprintln!("Building incremental: {}", build_target);
                build_command(Some(&build_target))?;
            } else {
                // Full build: build entire project
                eprintln!("Building full project (--full-build specified)...");
                build_command(None)?;
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
    let (target_symbol_idx, base_symbol_idx, target_size, base_size) = if target_obj.is_some() {
        // Symbol was found in target; use diff match for base
        let target_size = target_obj.as_ref().map(|o| o.symbols[symbol_idx].size).unwrap_or(0);
        let base_symbol_idx = symbol_diff.target_symbol;
        let base_size = base_symbol_idx
            .and_then(|idx| base_obj.as_ref().map(|o| o.symbols[idx].size))
            .unwrap_or(0);
        (Some(symbol_idx), base_symbol_idx, target_size, base_size)
    } else {
        // Symbol was found in base; use diff match for target
        let base_size = base_obj.as_ref().map(|o| o.symbols[symbol_idx].size).unwrap_or(0);
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
            (Some(summary), Some(analysis)) => Some(super::analysis::compute_verdict(
                summary,
                analysis,
                symbol_diff.match_percent,
                base_size,
                target_size,
            )),
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

/// Unit names in project-declared order, paired with their project index.
///
/// Batch mode indexes its object configs by unit name in a `HashMap`, and
/// `std::collections::HashMap` reseeds its hasher per instance. Anything that
/// iterated that map to make a decision — building a first-wins symbol index,
/// taking the first demangled match, scheduling the parallel walk — made a
/// different decision on every run of the same binary. Ordering by the project
/// index restores the order the units are declared in, which is the order
/// `report generate` uses and the order they appear on the link line.
///
/// The map is keyed by unit name, so a name declared twice has already
/// collapsed to a single entry before this sees it; the surviving index is what
/// gets ordered.
fn units_in_project_order<T>(configs: &HashMap<String, (T, usize)>) -> Vec<(usize, &str)> {
    let mut ordered: Vec<(usize, &str)> =
        configs.iter().map(|(name, (_, idx))| (*idx, name.as_str())).collect();
    ordered.sort_unstable();
    ordered
}

/// Pick the unit a requested symbol should be diffed in.
///
/// `target_units` and `base_units` are the unit positions (ascending, in
/// project-declared order) whose target / base object defines the symbol. Both
/// lists are routinely longer than one entry: a COMDAT — an inline function, a
/// template instantiation, a vtable thunk — is emitted into every translation
/// unit that uses it.
///
/// Rule 1: prefer a unit that defines the symbol on BOTH sides. That is the
/// same-translation-unit pairing the diff is meant to make. A unit that defines
/// it only on the target side is not an equally good answer — the row falls
/// through to the cross-unit COMDAT fallback, which diffs this target object
/// against some *other* unit's base object and scores lower for reasons that
/// have nothing to do with the source.
///
/// Rule 2: otherwise the first candidate in project-declared order.
///
/// Rule 1 is a measurement-quality rule, not a score-maximizing one: it chooses
/// between *pairings*, never between bodies, and it does not consult any score.
/// Where several target objects hold genuinely different bodies under one name
/// no rule here can recover the right one; all this promises is the same answer
/// every run. See the long note at the call site for what that population
/// actually is now — it is one name on rb3-xenon, and it is legal C++ rather
/// than the upstream map defect this comment used to describe.
fn resolve_symbol_unit(target_units: &[u32], base_units: Option<&[u32]>) -> Option<u32> {
    target_units
        .iter()
        .copied()
        .find(|pos| base_units.is_some_and(|base| base.binary_search(pos).is_ok()))
        .or_else(|| target_units.first().copied())
}

/// Place one symbol, honouring a `-u` scope if there is one.
///
/// With no scope this is exactly `resolve_symbol_unit` — the batch-determinism
/// rules, unchanged, and `unit_filter == None` must stay a pure pass-through or
/// every unscoped run moves.
///
/// With a scope, neither rule runs. The caller named the unit; the point of the
/// flag is that its answer beats anything derived here, including Rule 1's
/// preference for a unit that defines the symbol on both sides. A scoped symbol
/// the unit does not define is `None` — reported to the caller as
/// `not_in_unit`, never silently relocated to some other unit, which is the
/// whole failure mode being closed.
///
/// `target_units` is ascending (built by walking units in project order), so
/// membership is a binary search.
fn pick_symbol_unit(
    unit_filter: Option<u32>,
    target_units: &[u32],
    base_units: Option<&[u32]>,
) -> Option<u32> {
    match unit_filter {
        Some(want) => target_units.binary_search(&want).ok().map(|_| want),
        None => resolve_symbol_unit(target_units, base_units),
    }
}

/// Classify EVERY field of `Args` for batch mode, and refuse the ones batch
/// mode would otherwise accept and quietly do nothing about.
///
/// `-u` was not a one-off. `Args` is one flat struct shared by two code paths,
/// `run_batch` reads a subset of it, and nothing in the type system or the
/// tests noticed the difference — so the same defect existed once per unread
/// field, waiting for someone to pass it. This is the walk.
///
/// The line it draws: **batch refuses a flag whose effect it would not
/// reproduce, and stays silent on a flag that one-shot ignores too for JSON
/// output.** A flag that is inert in `diff -f json` is not a batch defect; a
/// flag that changes `diff -f json` and does nothing here is.
///
/// - READ by batch: `project`, `unit`, `config`, `map_file` (and `batch`
///   itself, by the dispatch in `run`).
/// - HONOURED here, previously dropped: `output`, `include_instructions`,
///   `full_listing` (which implies instructions, exactly as one-shot does).
///
///   `include_instructions` is honoured rather than refused on purpose, and the
///   cost was measured before deciding. Its one live caller
///   (rb3-xenon `scripts/harvest/subobject_ref_scan.py`) passes it in a
///   whole-pool gate and never reads the field — 646 symbols, output 2.3 MB →
///   50.0 MB (21.4×), producer wall 4.35 s → 4.63 s, survivor list bit-identical
///   (400 narrow / 625 `--wide`), rows identical once `instructions` is removed.
///   Refusing would break that caller at exit 1 in a repo this lane must not
///   edit, and would make one flag mean two things by mode — the defect the
///   shared `resolve_unit_name` exists to prevent. The 21.4× is a vestigial
///   request on the caller's side, one word to delete there; it is not a reason
///   for the differ to lie about a flag it accepts.
/// - INERT, correctly: `summary`, `analyze`, `verdict` — batch computes all
///   three unconditionally, so asking for them is asking for what you already
///   have. `context` and `concise` shape MARKDOWN rendering only and are
///   equally inert in `diff -f json`.
///
///   Do not "fix" that asymmetry by gating batch's summary on `--summary`.
///   One-shot builds instruction rows for `wants_instructions || wants_summary`
///   but emits `instruction_summary` only under `wants_summary`, so
///   `diff <sym> --include-instructions` alone yields instructions and NO
///   summary (verified 2026-08-16). Batch's unconditional summary is therefore
///   a real difference, and a live consumer depends on it:
///   rb3-xenon `scripts/harvest/subobject_ref_scan.py` gates its whole pool on
///   `instruction_summary.replace` while passing neither `--summary` nor
///   `--analyze` nor `--verdict`. Gating it would silently empty that gate.
/// - REFUSED below: everything else.
///
/// Refusing beats warning here because it is verifiably safe: none of the seven
/// known batch call sites across rb3, rb3-xenon, dc3-decomp and decomp-synth
/// passes any refused flag (surveyed 2026-08-16). The two that would have been
/// hit — `--include-instructions` and `-o -`, both from
/// rb3-xenon `scripts/harvest/subobject_ref_scan.py` — are the two now
/// honoured, which is why they are honoured rather than refused.
fn check_batch_args(args: &Args) -> Result<()> {
    // Exhaustive destructure, deliberately WITHOUT `..`. This is the structural
    // half of the fix: add a field to `Args` and this line stops compiling,
    // forcing whoever adds it to decide which of the four classes above it
    // belongs to. A list of one-off `if args.foo.is_some()` guards cannot do
    // that, and a list is how the first two of these got missed.
    let Args {
        target,
        base,
        project: _, // read: locates the project config
        unit: _,    // read: scopes the batch
        output: _,  // honoured at the write site below
        format,
        symbol,
        config: _,               // read: layered into every unit's diff config
        include_instructions: _, // honoured at the row-construction sites
        include_data,
        summary: _, // inert: batch always emits `instruction_summary`
        analyze: _, // inert: batch always emits `analysis`
        verdict: _, // inert: batch always emits `verdict`
        build,
        full_build,
        incremental,
        map_file: _,     // read: ICF equivalences
        context: _,      // inert: markdown rendering only, as in `-f json`
        full_listing: _, // honoured: implies instructions, as in one-shot
        concise: _,      // inert: markdown rendering only, as in `-f json`
        batch: _,        // read by `run` to get here
    } = args;

    let mut refused: Vec<(&str, &str)> = Vec::new();

    // The object pair. Worse than the `-u` failure, because batch resolves
    // through the project and answers from whatever unit its index picked:
    // rb3-xenon documented (2026-07-01) that a symbol answered from the wrong
    // unit lands with `base_size=0` and reads as a false STUB verdict, and
    // abandoned batch mode rather than trust the flag. Reproduced on the
    // pre-fix binary: `-1 obj/DataArray.obj -2 src/system/obj/DataArray.obj`
    // with `?NodeCmp@@YAHPBX0@Z` answers from `default/BandWardrobe`.
    if target.is_some() || base.is_some() {
        refused.push((
            "-1/--target, -2/--base",
            "batch resolves symbols through the project's units; use `-u <unit>` \
             to scope a batch, or drop --batch to diff an explicit pair",
        ));
    }

    // Batch reads its symbols from stdin. A positional symbol is not a second
    // way to say the same thing — it is silently discarded.
    if symbol.is_some() {
        refused.push((
            "<symbol> (positional)",
            "batch reads symbols from stdin, one per line; pipe them in",
        ));
    }

    // Batch emits JSONL and nothing else. An ABSENT `-f` is accepted (four of
    // the seven known callers omit it, and JSONL is batch's own default), but
    // an explicit format batch cannot produce must not be answered with a
    // different one.
    if let Some(f) = format.as_deref()
        && f != "json"
    {
        refused.push((
            "-f/--format (other than json)",
            "batch emits JSON Lines — one object per line — and cannot render \
             markdown, tui or json-pretty",
        ));
    }

    // Batch hardcodes `data_diff: None`; there is no data-section diff to ask
    // for. Refused rather than honoured because honouring it is real work, not
    // a discarded value like the instruction rows.
    if *include_data {
        refused.push((
            "--include-data",
            "batch does not compute data-section diffs; use one-shot mode",
        ));
    }

    // Batch never invokes the build system. This is the dangerous one: a caller
    // passing --build believes it is measuring a fresh object and is measuring
    // whatever is on disk, which is precisely the stale-object false read this
    // repo has been bitten by before.
    if *build || *full_build || *incremental {
        refused.push((
            "--build, --full-build, --incremental",
            "batch never invokes the build system and would silently measure \
             whatever objects are on disk; build first, then run the batch",
        ));
    }

    if refused.is_empty() {
        return Ok(());
    }
    let detail = refused
        .iter()
        .map(|(flag, why)| format!("  {flag}\n      {why}"))
        .collect::<Vec<_>>()
        .join("\n");
    bail!("--batch does not support these flags and would silently ignore them:\n{}", detail)
}

/// Is an unplaceable symbol `not_in_unit` (as opposed to `not_found`)?
///
/// Only a SCOPED run can produce `not_in_unit`, and only for a symbol the
/// project defines somewhere. A scope must not swallow `not_found`: reporting a
/// symbol that exists nowhere as `not_in_unit` with an empty `defined_in`
/// leaves the consumer inferring "does not exist" from an empty list, a
/// contract nothing states and nothing asserts — and that is the caller's typo
/// case, the one most worth naming plainly.
///
/// `defined_anywhere` is the mangled target index's candidate list, which is
/// what `not_found` has always meant on the unscoped path.
fn is_not_in_unit(unit_filter: Option<u32>, defined_anywhere: Option<&[u32]>) -> bool {
    unit_filter.is_some() && defined_anywhere.is_some_and(|units| !units.is_empty())
}

fn run_batch(args: Args) -> Result<()> {
    use objdiff_core::diff::{DiffSide, diff_objs};

    check_batch_args(&args)?;

    // Matches one-shot: `--full-listing` implies `--include-instructions`.
    // Batch already builds these rows — it needs them for the summary, the
    // analysis and the verdict — and then threw them away at the row, so the
    // flag was accepted and dropped. Honouring it is keeping what is already
    // computed.
    let wants_instructions = args.include_instructions || args.full_listing;

    // Load project config
    let project_dir = match &args.project {
        Some(project) => project.clone(),
        _ => {
            check_path_buf(std::env::current_dir().context("Failed to get the current directory")?)
                .context("Current directory is not valid UTF-8")?
        }
    };
    let Some((project_config, project_config_info)) =
        objdiff_core::config::try_project_config(project_dir.as_ref())
    else {
        bail!("Project config not found in {}", &project_dir)
    };
    let project_config = project_config.with_context(|| {
        format!("Reading project config {}", project_config_info.path.display())
    })?;

    let target_obj_dir =
        project_config.target_dir.as_ref().map(|p| project_dir.join(p.with_platform_encoding()));
    let base_obj_dir =
        project_config.base_dir.as_ref().map(|p| project_dir.join(p.with_platform_encoding()));
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
        project_config.map_file.as_ref().map(|p| project_dir.join(p.with_platform_encoding()))
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

    // Every symbol → unit decision below is ordered by this list, never by
    // `object_configs` iteration. `object_configs` is a `HashMap`, and
    // `std::collections::HashMap` reseeds its hasher per instance, so a
    // first-wins index built by iterating it picks a different unit on every
    // run of the same binary against the same objects. That is not cosmetic:
    // the chosen unit selects which pair of .obj files gets diffed, so
    // `raw_match_percent` changed between runs (measured on rb3-xenon:
    // `??$PropSync@VEventTrigger@@…` scored 100.0 under `default/GemTrackDir`
    // and 99.5098 under `default/EventTrigger`, 8/15 vs 7/15 over one binary).
    //
    // The order of record is the project-declared unit order — the same order
    // `report generate` walks, and the order the units appear on the link
    // line. `object_configs` is keyed by unit name, so a name declared twice
    // collapses to one entry; the surviving index is what this orders by.
    // Positions in this vec (`pos` below) are used as compact unit handles.
    let units_in_order = units_in_project_order(&object_configs);

    // `-u` / `--unit` in batch mode.
    //
    // This flag was DECLARED and then never read here: `run_batch` built its
    // object configs from `project_config.units` and walked the whole project,
    // so every caller that passed `-u` believed it had unit scope and had
    // whole-project results. Resolving it here, before any symbol is placed,
    // is what makes the flag real.
    //
    // Meaning: `-u U` pins the batch to unit U — every requested symbol is
    // diffed as U defines it, and a symbol U's target object does not define
    // is reported as `not_in_unit` rather than quietly diffed somewhere else.
    // That is the SCOPE reading, not the FILTER reading, and the difference is
    // visible only for a COMDAT (inline function, template instantiation,
    // vtable thunk) that several translation units define: unrestricted
    // resolution places it by `resolve_symbol_unit`, which may well choose
    // another unit, so filtering the unrestricted run's rows would silently
    // drop it. Under the scope reading `-u` is instead the disambiguator for
    // exactly that case — the one thing batch mode had no way to express.
    //
    // Two consequences worth stating rather than discovering:
    //   - `-u U` is not guaranteed to reproduce the `unit == "U"` rows of an
    //     unrestricted run. For a symbol that unrestricted resolution assigned
    //     elsewhere it produces a row the unrestricted run did not have. That
    //     is the flag working, not drifting.
    //   - It does not disable the cross-unit COMDAT base fallback below. `-u`
    //     scopes which TARGET object's bytes are scored; the fallback only
    //     finds a base body to score them against, and gating it on this flag
    //     would make `-u` change scores as well as scope.
    //
    // Resolution goes through the same `resolve_unit_name` the one-shot path
    // uses, so an unknown unit is a hard error naming it — silence is how the
    // original bug survived — and a suffix or basename resolves identically in
    // both modes.
    let unit_filter: Option<u32> = match args.unit.as_deref() {
        Some(requested) => {
            let names: Vec<&str> = units_in_order.iter().map(|(_, name)| *name).collect();
            let pos = resolve_unit_name(&names, requested)?;
            eprintln!("Batch mode restricted to unit `{}`", names[pos]);
            Some(pos as u32)
        }
        None => None,
    };

    // Build symbol indexes: open each .obj file ONCE, extract all text symbols.
    // This replaces the O(symbols × units) scan with O(units + symbols) lookups.
    let index_start = std::time::Instant::now();

    // symbol name → every unit position that defines it, ascending. A COMDAT
    // (inline function, template instantiation, vtable thunk) is defined in
    // every translation unit that uses it, so these lists are routinely longer
    // than one entry — re-measured 2026-08-16 on rb3-xenon with this index
    // itself (`list_function_symbols`, text symbols only): 1 of 69,437 target
    // symbols and 45,878 of 160,539 base symbols (was 7 / 51,334 before that
    // project repaired its symbol map; see the resolver note below, which also
    // says why `coff_dup_symbols.py` reports different totals). The
    // lopsidedness is the point and it is stable: the extracted TARGET objects
    // are carved out of a linked image, where the linker already picked one
    // copy of each COMDAT, while our own BASE build emits every copy. Keeping
    // the whole candidate list rather than a first-wins winner is what lets the
    // resolver below prefer a unit where both sides define the symbol.
    let index_side = |target_side: bool| {
        let mut index: HashMap<String, Vec<u32>> = HashMap::new();
        for (pos, (_, unit_name)) in units_in_order.iter().enumerate() {
            let Some((obj_config, _)) = object_configs.get(*unit_name) else { continue };
            let path = if target_side {
                obj_config.target_path.as_deref()
            } else {
                obj_config.base_path.as_deref()
            };
            if let Some(path) = path
                && let Ok(syms) = obj::read::list_function_symbols(path.as_ref())
            {
                for sym in syms {
                    let entry: &mut Vec<u32> = index.entry(sym).or_default();
                    // Ascending by construction: units are visited in order.
                    if entry.last() != Some(&(pos as u32)) {
                        entry.push(pos as u32);
                    }
                }
            }
        }
        index
    };
    let target_mangled_index = index_side(true);
    let base_symbol_index = index_side(false);

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

    // Resolve each symbol to its unit via O(1) HashMap lookups.
    //
    // `by_unit` is keyed by unit position, not name, so the parallel walk below
    // and therefore the order of the emitted rows follow project-declared unit
    // order. A `HashMap` here made the row order of the whole batch differ on
    // every run (15 distinct orders over 15 runs of one binary).
    let mut by_unit: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let mut not_found: Vec<String> = Vec::new();
    // Only ever non-empty under `-u`: symbols the project defines somewhere,
    // just not in the unit the caller scoped the batch to.
    let mut not_in_unit: Vec<(String, Vec<&str>)> = Vec::new();

    for symbol in &symbols {
        if let Some(candidates) = target_mangled_index.get(symbol.as_str()) {
            // A COMDAT is defined in several target objects at once, so this is
            // a choice, and the choice moves the score: it decides which
            // (target.obj, base.obj) pair gets diffed.
            //
            // Rule 1 — prefer a unit whose BASE object also defines the symbol.
            // That is the same-translation-unit pairing the diff is meant to
            // make. The alternative is not an equally good answer: with no base
            // definition in the resolved unit the row falls through to the
            // cross-unit COMDAT fallback below, which diffs this target object
            // against an unrelated unit's base object and scores lower for
            // reasons that have nothing to do with the source. Measured on
            // rb3-xenon, `??$PropSync@VEventTrigger@@…` is byte-identical in
            // both target objects (sha256 4af97026e5ccc52b, 204 bytes in both
            // EventTrigger.obj and GemTrackDir.obj) and defined in the base
            // build only in GemTrackDir — so the target bytes being scored are
            // the same either way and only the pairing differs. This rule is
            // therefore a measurement-quality rule, not a score-maximizing one:
            // it never compares a *different* body, it only refuses a
            // cross-object pairing when a same-object one exists.
            //
            // Rule 2 — otherwise the first candidate in project-declared order.
            // When several target objects define one name with *different*
            // bodies there is no answer the CLI can derive; all it can promise
            // is the same answer every run.
            //
            // What that population is (re-measured 2026-08-16 on rb3-xenon with
            // this very index: 1 name multiply defined on the target side, of
            // 69,437; base side 45,878 of 160,539). This comment previously
            // read "7 names ... `?Null@Symbol@@QBA_NXZ` has three genuinely
            // different 28-byte bodies", and BOTH halves are now wrong:
            //
            //   - `?Null@Symbol@@QBA_NXZ` is gone. rb3-xenon proved on
            //     2026-08-13 that its collision was a defect in
            //     `scripts/target_symbol_map.json` — the map claimed one name
            //     at several VAs, which a linked image cannot do — nulled the
            //     disproved rows and added a ninja gate
            //     (`tools/map_name_injectivity.py`). The name is absent from
            //     the map and from the extracted objects.
            //   - The "7" was never the divergent-body count; it was the
            //     multiply-defined count (the number in the index comment
            //     above), quoted into the wrong sentence. The divergent-body
            //     subset was 3 at the time.
            //
            // The one survivor is `?NodeCmp@@YAHPBX0@Z` — 148 bytes in
            // BandWardrobe.obj, 332 in DataArray.obj, different sha256 — and it
            // is NOT a map defect. It is a file-static qsort comparator, and
            // rb3-xenon's injectivity gate carries it on an explicit
            // `_internal_linkage_allow` list for that reason: internal linkage
            // means one mangled name legitimately denotes a different function
            // per defining TU, so no map repair can remove this case and none
            // should try. Expect the class to persist at a low count, not to
            // reach zero.
            //
            // Rule 2 is therefore load-bearing for determinism regardless of
            // that count, and would be even at zero: `candidates` is only
            // ascending-and-total because it is built by walking units in
            // project order, and Rule 1 declines to answer whenever no unit
            // defines the symbol on both sides — the byte-identical COMDAT tie,
            // which is common. Something has to break those ties the same way
            // every run.
            //
            // Re-derive before quoting any of these numbers, and re-derive with
            // the RIGHT instrument: they come from the index above, i.e.
            // objdiff-core's `obj::read::list_function_symbols`, counting TEXT
            // symbols. `scripts/determinism/coff_dup_symbols.py` answers a
            // neighbouring question — COFF symbols with storage class EXTERNAL
            // and a positive section number, so code *and* data — and on the
            // same tree on the same day it reports 1 of 149,874 target and
            // 51,335 of 111,939 base. It agrees on the target duplicate (the
            // finding) and on nothing else (the denominators, and the base
            // count, which is dominated by compiler-generated data symbols:
            // its largest base group is `__C2_10224` across 1,047 units). Use
            // it to identify WHICH names collide, which is what it is for; do
            // not expect its totals to reproduce these.
            //
            // Under `-u` neither rule runs — see `pick_symbol_unit`.
            let pos = pick_symbol_unit(
                unit_filter,
                candidates,
                base_symbol_index.get(symbol.as_str()).map(Vec::as_slice),
            );
            if let Some(pos) = pos {
                by_unit.entry(pos).or_default().push(symbol.clone());
                continue;
            }
        }
        // Demangled fallback: scan target .obj files for demangled match.
        // Project-declared order again — this loop takes the first hit, and
        // over `object_configs` that first hit was whichever unit the hasher
        // happened to visit first. Under `-u` it visits exactly one unit, so
        // the demangled spelling of a symbol is scoped the same way the
        // mangled one is.
        let mut found = false;
        for (pos, (_, unit_name)) in units_in_order.iter().enumerate() {
            if unit_filter.is_some_and(|want| want != pos as u32) {
                continue;
            }
            let Some((obj_config, _)) = object_configs.get(*unit_name) else { continue };
            if let Some(target_path) = obj_config.target_path.as_deref() {
                let matches =
                    obj::read::match_symbol_by_query(target_path.as_ref(), symbol, &lookup_config)
                        .unwrap_or_default();
                if matches.len() == 1 {
                    by_unit.entry(pos as u32).or_default().push(symbol.clone());
                    found = true;
                    break;
                }
            }
        }
        if !found {
            // Two different failures, and conflating them is how a scoped run
            // misleads: `not_found` means no unit in the project defines this
            // symbol, `not_in_unit` means the requested unit does not — a
            // distinction that only exists once `-u` is honoured. The
            // `defined_in` list turns the second into an actionable message
            // instead of a row the caller has to go looking for.
            //
            // A scope must NOT swallow `not_found`. Reporting a symbol that
            // exists nowhere as `not_in_unit` with an empty `defined_in` leaves
            // the consumer inferring "does not exist" from an empty list — a
            // contract nothing states and nothing asserts — and it is the
            // caller's typo case, the one worth naming plainly.
            //
            // The membership test is on the MANGLED target index, which is
            // what `not_found` has always meant on the unscoped path. A name
            // reachable only through a demangled query in some OTHER unit
            // therefore reports `not_found` here rather than `not_in_unit`.
            // Classifying that case exactly would cost a demangled scan of
            // every unit per unresolved symbol — 3,088 object reads each on
            // rb3-xenon, paid once per out-of-unit symbol, and a scoped batch
            // is routinely mostly out-of-unit. Not worth it to refine an error
            // label; recorded so nobody reads the distinction as sharper than
            // it is.
            let defined_anywhere = target_mangled_index.get(symbol.as_str()).map(Vec::as_slice);
            if is_not_in_unit(unit_filter, defined_anywhere) {
                let want = unit_filter.unwrap();
                // Reaching here means the candidate list does not contain
                // `want`, so this list is never empty — which is what makes an
                // empty `defined_in` impossible rather than merely unlikely.
                let mut defined_in: Vec<&str> = defined_anywhere
                    .unwrap_or_default()
                    .iter()
                    .filter(|pos| **pos != want)
                    .map(|pos| units_in_order[*pos as usize].1)
                    .collect();
                defined_in.truncate(8);
                not_in_unit.push((symbol.clone(), defined_in));
            } else {
                not_found.push(symbol.clone());
            }
        }
    }

    eprintln!(
        "Resolved: {} symbols across {} units ({} not found)",
        symbols.len() - not_found.len() - not_in_unit.len(),
        by_unit.len(),
        not_found.len(),
    );
    if let Some(want) = unit_filter {
        eprintln!(
            "{} symbols not defined in unit `{}`",
            not_in_unit.len(),
            units_in_order[want as usize].1,
        );
    }

    // Output not-found symbols as error entries
    let mut not_found_lines: Vec<String> = Vec::new();
    for symbol in &not_found {
        let output = serde_json::json!({
            "symbol": symbol,
            "error": "not_found",
        });
        not_found_lines.push(serde_json::to_string(&output)?);
    }
    for (symbol, defined_in) in &not_in_unit {
        let unit_name = unit_filter.map(|want| units_in_order[want as usize].1);
        let output = serde_json::json!({
            "symbol": symbol,
            "error": "not_in_unit",
            "unit": unit_name,
            "defined_in": defined_in,
        });
        not_found_lines.push(serde_json::to_string(&output)?);
    }

    // Process units in parallel with rayon
    use std::sync::atomic::AtomicUsize;

    use rayon::prelude::*;

    let units_total = by_unit.len();
    let units_processed = AtomicUsize::new(0);

    let unit_results: Vec<Result<Vec<String>>> = by_unit
        .par_iter()
        .map(|(unit_pos, unit_symbols)| -> Result<Vec<String>> {
            let mut lines: Vec<String> = Vec::new();
            let unit_name = units_in_order[*unit_pos as usize].1;

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
                if let Some(idx) =
                    target_obj.as_ref().and_then(|o| o.symbol_by_name_or_demangled(symbol_name))
                {
                    symbol_filter.insert(idx);
                } else if let Some(idx) =
                    base_obj.as_ref().and_then(|o| o.symbol_by_name_or_demangled(symbol_name))
                {
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

                let (symbol_idx, symbol, _obj, obj_diff) = if let Some(idx) = name_target_idx {
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
                        let ts =
                            target_obj.as_ref().map(|o| o.symbols[symbol_idx].size).unwrap_or(0);
                        let bsi = symbol_diff.target_symbol;
                        let bs = bsi
                            .and_then(|idx| base_obj.as_ref().map(|o| o.symbols[idx].size))
                            .unwrap_or(0);
                        (Some(symbol_idx), bsi, ts, bs)
                    } else {
                        let bs = base_obj.as_ref().map(|o| o.symbols[symbol_idx].size).unwrap_or(0);
                        let tsi = symbol_diff.target_symbol;
                        let ts = tsi
                            .and_then(|idx| target_obj.as_ref().map(|o| o.symbols[idx].size))
                            .unwrap_or(0);
                        (tsi, Some(symbol_idx), ts, bs)
                    };

                // Cross-unit COMDAT fallback.
                //
                // Reached when the resolved unit's base object has no copy of
                // the symbol at all. The candidates are our own build's copies
                // of one COMDAT in different translation units; the linker keeps
                // exactly one of them and we have no way to know which, so this
                // really is a tie and the honest fix is a documented total
                // order. That order is project-declared unit order — `.first()`
                // on an ascending candidate list — not `HashMap` iteration.
                if base_size == 0 && name_target_idx.is_some() {
                    let fallback = base_symbol_index
                        .get(symbol_name.as_str())
                        .and_then(|units| units.first())
                        .map(|pos| units_in_order[*pos as usize].1);
                    if let Some(fallback_unit) = fallback
                        && fallback_unit != unit_name
                        && let Some((fallback_config, _)) = object_configs.get(fallback_unit)
                        && let Some(fallback_base_path) = fallback_config.base_path.as_deref()
                        && let Ok(fb_obj) = obj::read::read(
                            fallback_base_path.as_ref(),
                            &diff_config,
                            DiffSide::Base,
                        )
                    {
                        let fb_diff = diff_objs(
                            target_obj.as_ref(),
                            Some(&fb_obj),
                            None,
                            &diff_config,
                            &mapping_config,
                        )?;
                        let fb_sd = &fb_diff.left.as_ref().unwrap().symbols[symbol_idx];
                        let fb_bsi = fb_sd.target_symbol;
                        let fb_bs = fb_bsi.map(|i| fb_obj.symbols[i].size).unwrap_or(0);

                        if fb_bs > 0 {
                            let fb_alt_cfg = {
                                let mut c = diff_config.clone();
                                match c.function_reloc_diffs {
                                    diff::FunctionRelocDiffs::NameAddress => {
                                        c.function_reloc_diffs = diff::FunctionRelocDiffs::DataValue
                                    }
                                    _ => {
                                        c.function_reloc_diffs =
                                            diff::FunctionRelocDiffs::NameAddress
                                    }
                                }
                                c
                            };
                            let fb_alt = diff_objs(
                                target_obj.as_ref(),
                                Some(&fb_obj),
                                None,
                                &fb_alt_cfg,
                                &mapping_config,
                            )?;
                            let fb_instrs = build_instruction_diffs(
                                target_obj.as_ref(),
                                Some(&fb_obj),
                                fb_diff.left.as_ref(),
                                fb_diff.right.as_ref(),
                                Some(symbol_idx),
                                fb_bsi,
                                &diff_config,
                            )?;
                            let fb_summary = InstructionSummary::from_instructions(&fb_instrs);
                            let fb_analysis = super::analysis::analyze_instructions(&fb_instrs);
                            let fb_verdict = super::analysis::compute_verdict(
                                &fb_summary,
                                &fb_analysis,
                                fb_sd.match_percent,
                                fb_bs,
                                target_size,
                            );
                            let (fb_norm, fb_raw) = match diff_config.function_reloc_diffs {
                                diff::FunctionRelocDiffs::NameAddress => (
                                    fb_alt
                                        .left
                                        .as_ref()
                                        .and_then(|d| d.symbols.get(symbol_idx))
                                        .and_then(|s| s.match_percent),
                                    fb_sd.match_percent,
                                ),
                                _ => (
                                    fb_sd.match_percent,
                                    fb_alt
                                        .left
                                        .as_ref()
                                        .and_then(|d| d.symbols.get(symbol_idx))
                                        .and_then(|s| s.match_percent),
                                ),
                            };
                            let output = DiffOutput {
                                symbol: symbol_name.clone(),
                                demangled: symbol.demangled_name.clone(),
                                unit: Some(unit_name.to_string()),
                                target_size,
                                base_size: fb_bs,
                                fuzzy_match_percent: fb_norm,
                                normalized_match_percent: fb_norm,
                                raw_match_percent: fb_raw,
                                diff_score: fb_sd
                                    .diff_score
                                    .map(|(s, m)| DiffScoreOutput { score: s, max_score: m }),
                                build_status: None,
                                instruction_summary: Some(fb_summary),
                                analysis: Some(fb_analysis),
                                verdict: Some(fb_verdict),
                                call_diff: None,
                                insert_delete_clusters: None,
                                diff_regions: None,
                                instructions: wants_instructions.then_some(fb_instrs),
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
                let (normalized_match_percent, raw_match_percent) = if let Some(ref alt_result) =
                    alt_diff_result
                {
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
                    unit: Some(unit_name.to_string()),
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
                    instructions: wants_instructions.then_some(instructions),
                    masked_equal_rows: symbol_diff.masked_equal_rows,
                    reloc_ignored_rows: symbol_diff.reloc_ignored_rows,
                    masked_equal_symbol: symbol_diff.masked_equal_symbol,
                    data_diff: None,
                };

                lines.push(serde_json::to_string(&output)?);
            }

            let done = units_processed.fetch_add(1, Ordering::Relaxed) + 1;
            if done.is_multiple_of(100) {
                eprintln!("  [{}/{}] units processed", done, units_total);
            }

            Ok(lines)
        })
        .collect();

    // Write all results. `-o` was the third flag batch mode accepted and
    // dropped: rows went to stdout no matter what path you named, so
    // `-o results.jsonl` left you with an empty file and your output on the
    // terminal. `-` still means stdout, which is what the one caller passing
    // `-o` (rb3-xenon `scripts/harvest/subobject_ref_scan.py`) passes and what
    // `write_diff_output` means by it on the one-shot path.
    let mut writer: Box<dyn Write> = match args.output.as_deref() {
        Some(p) if p != Utf8PlatformPath::new("-") => {
            let file = File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .open(p)
                .with_context(|| format!("Failed to create file {}", p))?;
            Box::new(BufWriter::new(file))
        }
        _ => Box::new(stdout()),
    };
    for line in &not_found_lines {
        writeln!(writer, "{}", line)?;
    }
    for unit_result in unit_results {
        for line in unit_result? {
            writeln!(writer, "{}", line)?;
        }
    }
    // A BufWriter that is only dropped can swallow a write error; batch output
    // is somebody's corpus, so surface it.
    writer.flush().context("Failed to flush batch output")?;

    eprintln!(
        "Batch complete: {} symbols, {} units",
        symbols.len() - not_found.len() - not_in_unit.len(),
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
            if let Some(last) = segments.last_mut()
                && last.kind == kind
            {
                last.size += seg.size;
                seg_bytes.last_mut().unwrap().extend_from_slice(&seg.data);
                other_seg_bytes.last_mut().unwrap().extend_from_slice(other_data);
                offset += seg.size;
                continue;
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
            row.and_then(|r| r.branch_from.as_ref())
                .map(|b| BranchFrom { source_indices: b.ins_idx.clone(), branch_idx: b.branch_idx })
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

    // Build the string args from the DISPLAY parts, not from processed.args.
    // processed.args is the COMPARISON arg list: process_instruction appends a
    // trailing InstructionArg::Reloc whenever the row carries a relocation the
    // display never formatted (PPC fake-pool relocations attach to rows like
    // `mr r5, r6`), and it drops the Basic parts, so the old comma-join
    // rendered a phantom final operand (`mr r5, r6, sDevices__6UsbWii`) and
    // flattened memory operands (`lwz r0, 0x0, r5` for `lwz r0, 0x0(r5)`).
    // Walking display_instruction reproduces what the TUI shows: parens and
    // reloc suffixes (@l/@ha) included, non-displayed relocations excluded.
    // The non-displayed relocation still reaches consumers as the trailing
    // Symbol entry of typed_args (built from processed.args below, unchanged).
    // Display-layer only: scoring/diffing never reads these strings.
    let mut args_display = String::new();
    obj.arch.display_instruction(resolved, diff_config, &mut |part| {
        match part {
            objdiff_core::diff::display::InstructionPart::Opcode(..) => {}
            objdiff_core::diff::display::InstructionPart::Separator => {
                args_display.push_str(diff_config.separator());
            }
            objdiff_core::diff::display::InstructionPart::Basic(s) => {
                args_display.push_str(&s);
            }
            objdiff_core::diff::display::InstructionPart::Arg(arg) => match arg {
                objdiff_core::obj::InstructionArg::Value(v) => {
                    args_display.push_str(&v.to_string());
                }
                objdiff_core::obj::InstructionArg::Reloc => {
                    // Same branch-dest substitution process_instruction makes,
                    // so branch rows keep their resolved local target address.
                    if let Some(dest) = resolved.ins_ref.branch_dest {
                        args_display.push_str(&format!("{dest:#x}"));
                    } else {
                        match resolved.relocation.as_ref() {
                            Some(r) => args_display.push_str(&r.symbol.name),
                            None => args_display.push_str("<reloc>"),
                        }
                    }
                }
                objdiff_core::obj::InstructionArg::BranchDest(d) => {
                    args_display.push_str(&format!("{d:#x}"));
                }
            },
        }
        Ok(())
    })?;
    let args_str = if args_display.is_empty() { None } else { Some(args_display) };

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
    let (target_symbol_idx, base_symbol_idx, target_size, base_size) = if name_target_idx.is_some()
    {
        let ts = target_obj.map(|o| o.symbols[symbol_idx].size).unwrap_or(0);
        let bsi = symbol_diff.target_symbol;
        let bs = bsi.and_then(|idx| base_obj.map(|o| o.symbols[idx].size)).unwrap_or(0);
        (Some(symbol_idx), bsi, ts, bs)
    } else {
        let bs = base_obj.map(|o| o.symbols[symbol_idx].size).unwrap_or(0);
        let tsi = symbol_diff.target_symbol;
        let ts = tsi.and_then(|idx| target_obj.map(|o| o.symbols[idx].size)).unwrap_or(0);
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
    fn wake(self: Arc<Self>) { self.0.store(true, Ordering::Relaxed); }

    fn wake_by_ref(self: &Arc<Self>) { self.0.store(true, Ordering::Relaxed); }
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

    // =========================================================================
    // Batch-mode unit resolution determinism
    // =========================================================================

    /// The order batch mode walks its units in must not come out of a
    /// `HashMap`.
    ///
    /// `run_batch` indexes object configs by unit name in a `HashMap`, and
    /// `std::collections::HashMap` reseeds per instance. Every decision that
    /// iterated that map — first-wins symbol index, first demangled match, the
    /// rayon walk that fixes row order — therefore came out differently on
    /// every run of the SAME binary against the SAME objects. Measured on
    /// rb3-xenon: 15 runs, 15 distinct row orders, and scores that moved with
    /// the unit choice.
    ///
    /// Build a fresh map (fresh seed) on every iteration so the old failure is
    /// deterministic, the way the map-file parser's determinism test does.
    #[test]
    fn test_units_in_project_order_is_deterministic() {
        let names: Vec<String> = (0..64).map(|i| format!("default/unit_{i:02}")).collect();
        let build = || {
            // Insert in an order unrelated to the project index, so anything
            // that leaks insertion or hash order shows up.
            let mut configs: HashMap<String, ((), usize)> = HashMap::new();
            for (idx, name) in names.iter().enumerate() {
                configs.insert(name.clone(), ((), names.len() - 1 - idx));
            }
            units_in_project_order(&configs)
                .into_iter()
                .map(|(idx, name)| (idx, name.to_string()))
                .collect::<Vec<_>>()
        };
        let expected = build();
        for _ in 0..256 {
            assert_eq!(build(), expected, "unit order varied between runs");
        }
        // Project-declared index order, not name order and not hash order.
        assert_eq!(expected[0], (0, "default/unit_63".to_string()));
        assert_eq!(expected[63], (63, "default/unit_00".to_string()));
    }

    /// A COMDAT defined in several target objects is a choice, and the choice
    /// decides which pair of objects gets diffed — so it decides the score.
    /// Prefer the unit that defines the symbol on both sides.
    #[test]
    fn test_resolve_symbol_unit_prefers_a_unit_defined_on_both_sides() {
        // Target units 3 and 7; only 7 has a base definition. Answer: 7, even
        // though 3 comes first in project order. Picking 3 would send the row
        // through the cross-unit COMDAT fallback, which diffs this target
        // object against unit 7's base object -- a pairing that scores lower
        // for reasons unrelated to the source. Witnessed on rb3-xenon as
        // `??$PropSync@VEventTrigger@@...`: 100.0 under `default/GemTrackDir`
        // (both sides define it) vs 99.5098 under `default/EventTrigger`
        // (fallback), with byte-identical target bodies in both objects.
        assert_eq!(resolve_symbol_unit(&[3, 7], Some(&[7, 9])), Some(7));
        // Earliest of several both-sides candidates.
        assert_eq!(resolve_symbol_unit(&[3, 7, 9], Some(&[7, 9])), Some(7));
    }

    /// With no both-sides candidate the tie is genuine, and the documented
    /// total order is project-declared unit order.
    #[test]
    fn test_resolve_symbol_unit_falls_back_to_project_order() {
        assert_eq!(resolve_symbol_unit(&[3, 7], Some(&[9])), Some(3));
        assert_eq!(resolve_symbol_unit(&[3, 7], None), Some(3));
        assert_eq!(resolve_symbol_unit(&[5], None), Some(5));
        assert_eq!(resolve_symbol_unit(&[], Some(&[1])), None);
    }

    // =========================================================================
    // Batch-mode `-u` / `--unit` scope
    //
    // `run_batch` declared `unit` and never read it, so `-u` was accepted and
    // ignored: callers passing it got whole-project results. These pin the two
    // halves of the fix — what a unit NAME resolves to, and what a scope does
    // to symbol placement — including the case the bug consisted of, which is
    // that "no `-u`" must behave exactly as before.
    // =========================================================================

    #[test]
    fn test_resolve_unit_name_exact_beats_every_fuzzy_tier() {
        let names = ["main/system/synth/MidiSynth", "MidiSynth", "extra/MidiSynthImpl"];
        // "MidiSynth" is an exact name AND a path-suffix of names[0] AND a
        // substring of names[2]. Exact must win outright rather than report
        // three matches as ambiguous.
        assert_eq!(resolve_unit_name(&names, "MidiSynth").unwrap(), 1);
        assert_eq!(resolve_unit_name(&names, "main/system/synth/MidiSynth").unwrap(), 0);
    }

    #[test]
    fn test_resolve_unit_name_suffix_then_basename_then_substring() {
        let names = ["main/system/synth/MidiSynth", "game/audio/Mixer"];
        // Path-component suffix.
        assert_eq!(resolve_unit_name(&names, "system/synth/MidiSynth").unwrap(), 0);
        // Basename only.
        assert_eq!(resolve_unit_name(&names, "Mixer").unwrap(), 1);
        // Substring that is neither a suffix nor a basename.
        assert_eq!(resolve_unit_name(&names, "audio").unwrap(), 1);
    }

    #[test]
    fn test_resolve_unit_name_higher_tier_ambiguity_does_not_fall_through() {
        // Two basename matches, and "Foo" is also a substring of a third name.
        // Falling through to the substring tier would turn an ambiguous request
        // into three candidates; worse, an implementation that took the first
        // hit at some tier would silently pick one. This must report the
        // ambiguity at the tier that found it.
        let names = ["a/Foo", "b/Foo", "c/FooBarBaz"];
        let err = resolve_unit_name(&names, "Foo").unwrap_err().to_string();
        assert!(err.contains("Ambiguous unit `Foo`"), "{err}");
        assert!(err.contains("2 matches"), "{err}");
        assert!(err.contains("a/Foo") && err.contains("b/Foo"), "{err}");
        assert!(!err.contains("c/FooBarBaz"), "substring tier leaked in: {err}");
    }

    #[test]
    fn test_resolve_unit_name_unknown_is_an_error_naming_the_unit() {
        // The whole bug was silence. An unknown unit must not resolve to
        // "nothing to do" — it must say which unit it could not find.
        let names = ["main/system/synth/MidiSynth"];
        let err = resolve_unit_name(&names, "NoSuchUnit").unwrap_err().to_string();
        assert!(err.contains("Unit not found: NoSuchUnit"), "{err}");
        assert!(err.contains("Hint:"), "error should tell the user what to pass: {err}");
    }

    #[test]
    fn test_resolve_unit_name_ambiguity_preview_is_capped_and_sorted() {
        let names: Vec<String> = (0..12).map(|i| format!("u{:02}/Thing", i)).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let err = resolve_unit_name(&refs, "Thing").unwrap_err().to_string();
        assert!(err.contains("12 matches"), "{err}");
        assert!(err.contains("... and 4 more"), "preview should cap at 8: {err}");
        // Sorted, not hash order: the first previewed name is the lowest.
        let first_listed = err.lines().nth(1).unwrap().trim();
        assert_eq!(first_listed, "u00/Thing", "{err}");
    }

    #[test]
    fn test_resolve_unit_name_empty_project_still_errors() {
        let names: [&str; 0] = [];
        let err = resolve_unit_name(&names, "Anything").unwrap_err().to_string();
        assert!(err.contains("Unit not found: Anything"), "{err}");
    }

    #[test]
    fn test_pick_symbol_unit_without_a_scope_is_unchanged() {
        // The regression that matters most: every batch run that passes no `-u`
        // must place symbols exactly as it did before the flag existed. This is
        // the same table as the determinism tests above, routed through the new
        // entry point.
        for (target, base) in [
            (&[3u32, 7][..], Some(&[7u32, 9][..])),
            (&[3, 7][..], Some(&[9][..])),
            (&[3, 7][..], None),
            (&[5][..], None),
            (&[][..], Some(&[1][..])),
        ] {
            assert_eq!(
                pick_symbol_unit(None, target, base),
                resolve_symbol_unit(target, base),
                "unscoped pick diverged from resolve_symbol_unit for {target:?}"
            );
        }
    }

    #[test]
    fn test_pick_symbol_unit_scope_overrides_the_both_sides_preference() {
        // Unscoped, Rule 1 takes unit 7 because the base side defines it there
        // too. Scoped to unit 3, the caller's answer wins — this is the COMDAT
        // disambiguation batch mode could not express before.
        assert_eq!(pick_symbol_unit(None, &[3, 7], Some(&[7, 9])), Some(7));
        assert_eq!(pick_symbol_unit(Some(3), &[3, 7], Some(&[7, 9])), Some(3));
        assert_eq!(pick_symbol_unit(Some(7), &[3, 7], Some(&[7, 9])), Some(7));
    }

    #[test]
    fn test_pick_symbol_unit_scope_refuses_rather_than_relocates() {
        // Unit 5 does not define this symbol. The answer is None — which the
        // caller sees as `not_in_unit` — and emphatically NOT unit 3, which is
        // what a whole-project resolution would have quietly returned.
        assert_eq!(pick_symbol_unit(Some(5), &[3, 7], Some(&[3][..])), None);
        assert_eq!(pick_symbol_unit(None, &[3, 7], Some(&[3][..])), Some(3));
        // And an empty candidate list is None under any scope.
        assert_eq!(pick_symbol_unit(Some(0), &[], None), None);
    }

    // =========================================================================
    // Batch-mode flag compatibility
    //
    // `-u` was not a one-off: `Args` is one flat struct read by two code paths,
    // and every field `run_batch` does not read was a flag it accepted and
    // silently dropped. These pin the classification of all 21.
    // =========================================================================

    /// A batch invocation with nothing else set.
    ///
    /// Written as a full struct literal on purpose. Like the destructure in
    /// `check_batch_args`, it stops compiling when a field is added to `Args`,
    /// so the test suite cannot go on passing while a new flag joins the
    /// silently-ignored set.
    fn batch_args() -> Args {
        Args {
            target: None,
            base: None,
            project: None,
            unit: None,
            output: None,
            format: None,
            symbol: None,
            config: Vec::new(),
            include_instructions: false,
            include_data: false,
            summary: false,
            analyze: false,
            verdict: false,
            build: false,
            full_build: false,
            incremental: false,
            map_file: None,
            context: None,
            full_listing: false,
            concise: false,
            batch: true,
        }
    }

    #[test]
    fn test_scoping_does_not_swallow_not_found() {
        // A symbol the project defines nowhere must stay `not_found` under a
        // scope. Reporting it as `not_in_unit` with an empty `defined_in` makes
        // the consumer infer non-existence from an empty list -- undocumented,
        // unasserted, and it is the typo case, the one worth naming plainly.
        assert!(!is_not_in_unit(Some(3), None), "unknown symbol under a scope");
        assert!(!is_not_in_unit(Some(3), Some(&[])), "empty candidate list is not membership");

        // Defined somewhere the scope is not: that IS not_in_unit.
        assert!(is_not_in_unit(Some(3), Some(&[7])));
        assert!(is_not_in_unit(Some(3), Some(&[7, 9])));

        // With no scope there is no such thing as not_in_unit, however the
        // symbol is defined -- an unscoped run that failed to place a symbol
        // failed for the old reason and must keep the old label.
        assert!(!is_not_in_unit(None, None));
        assert!(!is_not_in_unit(None, Some(&[7])));
        assert!(!is_not_in_unit(None, Some(&[])));
    }

    #[test]
    fn test_not_in_unit_implies_a_non_empty_defined_in() {
        // The invariant the row's `defined_in` field rests on: whenever the
        // classification says not_in_unit, the candidate list has at least one
        // entry that is not the requested unit. If this can fail, an empty
        // `defined_in` becomes ambiguous again.
        for (want, candidates) in [(3u32, &[7u32][..]), (3, &[7, 9][..]), (0, &[1, 2, 3][..])] {
            assert!(is_not_in_unit(Some(want), Some(candidates)));
            let others: Vec<u32> = candidates.iter().copied().filter(|p| *p != want).collect();
            assert!(!others.is_empty(), "defined_in would be empty for {candidates:?}");
        }
    }

    #[test]
    fn test_check_batch_args_accepts_a_plain_batch() {
        assert!(check_batch_args(&batch_args()).is_ok());
    }

    #[test]
    fn test_check_batch_args_refuses_an_explicit_object_pair() {
        let mut a = batch_args();
        a.target = Some(Utf8PlatformPathBuf::from("t.o"));
        let err = check_batch_args(&a).unwrap_err().to_string();
        assert!(err.contains("-1/--target"), "{err}");
        assert!(err.contains("-u <unit>"), "should point at the flag that works: {err}");

        let mut b = batch_args();
        b.base = Some(Utf8PlatformPathBuf::from("b.o"));
        assert!(check_batch_args(&b).is_err());
    }

    #[test]
    fn test_check_batch_args_refuses_a_positional_symbol() {
        let mut a = batch_args();
        a.symbol = Some("MySymbol".to_string());
        let err = check_batch_args(&a).unwrap_err().to_string();
        assert!(err.contains("positional"), "{err}");
        assert!(err.contains("stdin"), "should say where symbols come from: {err}");
    }

    #[test]
    fn test_check_batch_args_refuses_a_format_it_cannot_produce() {
        for f in ["markdown", "tui", "json-pretty"] {
            let mut a = batch_args();
            a.format = Some(f.to_string());
            let err = check_batch_args(&a).unwrap_err().to_string();
            assert!(err.contains("--format"), "{f}: {err}");
        }
        // `json` is what batch emits, and an ABSENT format stays accepted --
        // four of the seven known callers omit `-f` entirely, so refusing the
        // absent case would break them for no gain.
        let mut ok = batch_args();
        ok.format = Some("json".to_string());
        assert!(check_batch_args(&ok).is_ok());
        assert!(check_batch_args(&batch_args()).is_ok());
    }

    #[test]
    fn test_check_batch_args_refuses_build_flags() {
        // The dangerous class: a caller passing --build believes it measured a
        // freshly built object and measured whatever was on disk.
        for set in [
            |a: &mut Args| a.build = true,
            |a: &mut Args| a.full_build = true,
            |a: &mut Args| a.incremental = true,
        ] {
            let mut a = batch_args();
            set(&mut a);
            let err = check_batch_args(&a).unwrap_err().to_string();
            assert!(err.contains("--build"), "{err}");
            assert!(err.contains("build first"), "should say what to do: {err}");
        }
    }

    #[test]
    fn test_check_batch_args_refuses_include_data() {
        let mut a = batch_args();
        a.include_data = true;
        assert!(check_batch_args(&a).unwrap_err().to_string().contains("--include-data"));
    }

    #[test]
    fn test_check_batch_args_reports_every_offending_flag_at_once() {
        // One round trip per mistake is a bad way to learn you made three.
        let mut a = batch_args();
        a.target = Some(Utf8PlatformPathBuf::from("t.o"));
        a.build = true;
        a.include_data = true;
        let err = check_batch_args(&a).unwrap_err().to_string();
        assert!(err.contains("-1/--target"), "{err}");
        assert!(err.contains("--build"), "{err}");
        assert!(err.contains("--include-data"), "{err}");
    }

    #[test]
    fn test_check_batch_args_accepts_the_honoured_and_the_inert() {
        // Honoured: these now do something in batch mode, so they must not be
        // refused. Inert: batch computes summary/analysis/verdict for every row
        // regardless, and context/concise shape markdown, which `-f json`
        // ignores in one-shot too -- neither is a batch defect.
        let mut a = batch_args();
        a.output = Some(Utf8PlatformPathBuf::from("rows.jsonl"));
        a.include_instructions = true;
        a.full_listing = true;
        a.summary = true;
        a.analyze = true;
        a.verdict = true;
        a.context = Some(3);
        a.concise = true;
        a.project = Some(Utf8PlatformPathBuf::from("."));
        a.unit = Some("some/Unit".to_string());
        a.config = vec!["functionRelocDiffs=none".to_string()];
        a.map_file = Some(Utf8PlatformPathBuf::from("icf.map"));
        assert!(check_batch_args(&a).is_ok(), "{:?}", check_batch_args(&a).err());
    }

    #[test]
    fn test_pick_symbol_unit_scope_is_membership_not_position() {
        // `binary_search` returns an INDEX into the candidate list; the value
        // returned must be the unit position, not that index. With candidates
        // [4, 9] and scope 9, an index-returning bug yields 1 (some unrelated
        // unit) instead of 9, and it would be invisible in any project whose
        // first units happen to be the interesting ones.
        assert_eq!(pick_symbol_unit(Some(9), &[4, 9], None), Some(9));
        assert_eq!(pick_symbol_unit(Some(4), &[4, 9], None), Some(4));
        assert_eq!(pick_symbol_unit(Some(1), &[4, 9], None), None);
    }

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
        use objdiff_core::{
            diff::{DataDiff, DataDiffKind, DataDiffRow, DataRelocationDiff, SymbolDiff},
            obj::{Relocation, RelocationFlags, Symbol},
        };

        // Symbols table for relocation target-name resolution.
        let symbols = vec![Symbol { name: "_self".to_string(), ..Default::default() }, Symbol {
            name: "SomeVtableEntry".to_string(),
            ..Default::default()
        }];

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
        assert_eq!(
            (out.segments[0].offset, out.segments[0].size, out.segments[0].kind.as_str()),
            (0, 16, "equal")
        );
        assert_eq!(out.segments[0].bytes, None);
        assert_eq!(
            (out.segments[1].offset, out.segments[1].size, out.segments[1].kind.as_str()),
            (16, 4, "replace")
        );
        assert_eq!(out.segments[1].bytes.as_deref(), Some("deadbeef"));
        assert_eq!(
            (out.segments[2].offset, out.segments[2].size, out.segments[2].kind.as_str()),
            (20, 4, "insert")
        );
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

        let out =
            build_data_diff(&symbols, &symbol_diff, Some((&other_symbols, &other_symbol_diff)))
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
