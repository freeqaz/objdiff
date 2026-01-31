use std::{
    fs::File,
    io::{BufWriter, Write, stdout},
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
    diff::{self, DiffObjConfig, DiffSide, InstructionDiffKind, MappingConfig, ObjectDiff},
    jobs::{
        Job, JobQueue, JobResult,
        objdiff::{ObjDiffConfig, start_build},
    },
    obj::{self, Object},
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
            None | Some("tui") => Ok(Self::Tui),
            Some("json") => Ok(Self::Json),
            Some("json-pretty") | Some("json_pretty") => Ok(Self::JsonPretty),
            Some("markdown") | Some("md") => Ok(Self::Markdown),
            Some("proto") => Ok(Self::Proto),
            Some(other) => {
                bail!("Invalid output format: {}. Supported: tui, json, json-pretty, markdown, proto", other)
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
    pub instructions: Option<Vec<InstructionDiffOutput>>,
}

#[derive(Serialize)]
pub struct DiffScoreOutput {
    pub score: u64,
    pub max_score: u64,
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

#[derive(Serialize)]
pub struct InstructionDiffOutput {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<InstructionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<InstructionInfo>,
    pub match_type: String,
    /// Detailed breakdown of which arguments differ (only for diff_arg type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_breakdown: Option<InstructionDiffBreakdown>,
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
    /// Output format: tui, json, json-pretty, markdown (default: tui)
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
}

pub fn run(args: Args) -> Result<()> {
    let (target_path, base_path, project_config, unit_options) =
        match (&args.target, &args.base, &args.project, &args.unit) {
            (Some(_), Some(_), None, None)
            | (Some(_), None, None, None)
            | (None, Some(_), None, None) => (args.target.clone(), args.base.clone(), None, None),
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
                let base_obj_dir = project_config
                    .base_dir
                    .as_ref()
                    .map(|p| project.join(p.with_platform_encoding()));
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
                    objects
                        .iter()
                        .find(|(obj, _)| obj.name == *u)
                        .map(|(obj, idx)| (obj, *idx))
                        .ok_or_else(|| anyhow!("Unit not found: {}", u))?
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
                        let mut partial_matches: Vec<(usize, usize, obj::read::SymbolMatch)> = Vec::new();

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
                        let all_matches = if !exact_matches.is_empty() {
                            exact_matches
                        } else {
                            partial_matches
                        };

                        match all_matches.len() {
                            0 => bail!("Symbol not found: {}", symbol_name),
                            1 => {
                                let (i, unit_idx, m) = all_matches.into_iter().next().unwrap();
                                idx = Some((i, unit_idx, m.name));
                                count = 1;
                            }
                            _ => {
                                // Multiple matches - show disambiguation
                                eprintln!(
                                    "Multiple matches for '{}'. Did you mean:",
                                    symbol_name
                                );
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
                (target_path, base_path, Some(project_config), unit_options)
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
                let status = Command::new("ninja")
                    .status()
                    .context("Failed to run ninja")?;

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
            run_interactive(args, target_path, base_path, project_config, unit_options)
        }
        DiffOutputFormat::Proto => {
            // Use upstream oneshot mode for proto output (binding format)
            let output = args.output.as_deref().unwrap_or(Utf8PlatformPath::new("-"));
            run_oneshot(&args, output, target_path.as_deref(), base_path.as_deref(), unit_options)
        }
        _ => {
            // Use enhanced JSON/markdown output with analysis support
            run_json(args, target_path, base_path, project_config, unit_options, output_format)
        }
    }
}

fn run_oneshot(
    args: &Args,
    output: &Utf8PlatformPath,
    target_path: Option<&Utf8PlatformPath>,
    base_path: Option<&Utf8PlatformPath>,
    unit_options: Option<ProjectOptions>,
) -> Result<()> {
    use crate::util::output::{OutputFormat, write_output};
    let output_format = OutputFormat::Proto; // Proto is the only format that uses oneshot
    let (diff_config, mapping_config) = build_config_from_args(args, None, unit_options.as_ref())?;
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
    let left = target.as_ref().and_then(|o| result.left.as_ref().map(|d| (o, d)));
    let right = base.as_ref().and_then(|o| result.right.as_ref().map(|d| (o, d)));
    let diff_result = DiffResult::new(left, right, &diff_config)?;
    write_output(&diff_result, Some(output), output_format)?;
    Ok(())
}

fn build_config_from_args(
    args: &Args,
    project_config: Option<&ProjectConfig>,
    unit_options: Option<&ProjectOptions>,
) -> Result<(DiffObjConfig, MappingConfig)> {
    let mut diff_config = DiffObjConfig::default();
    if let Some(options) = project_config.and_then(|config| config.options.as_ref()) {
        apply_project_options(&mut diff_config, options)?;
    }
    if let Some(options) = unit_options {
        apply_project_options(&mut diff_config, options)?;
    }
    apply_config_args(&mut diff_config, &args.config)?;
    Ok((diff_config, MappingConfig::default()))
}

fn run_json(
    args: Args,
    target_path: Option<Utf8PlatformPathBuf>,
    base_path: Option<Utf8PlatformPathBuf>,
    project_config: Option<ProjectConfig>,
    unit_options: Option<ProjectOptions>,
    output_format: DiffOutputFormat,
) -> Result<()> {
    use objdiff_core::diff::{DiffSide, diff_objs};

    let Some(symbol_name) = &args.symbol else {
        bail!("JSON output mode requires a symbol name");
    };

    let (diff_config, mapping_config) =
        build_config_from_args(&args, project_config.as_ref(), unit_options.as_ref())?;

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
    let diff_result = diff_objs(
        target_obj.as_ref(),
        base_obj.as_ref(),
        None,
        &diff_config,
        &mapping_config,
    )?;

    // Find the symbol in the target or base object (supports both mangled and demangled names)
    let (symbol_idx, symbol, _obj, obj_diff) = if let Some(ref target) = target_obj {
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

    // Get sizes from both objects (use demangled lookup)
    let target_size = target_obj
        .as_ref()
        .and_then(|o| o.symbol_by_name_or_demangled(symbol_name))
        .map(|idx| target_obj.as_ref().unwrap().symbols[idx].size)
        .unwrap_or(0);
    let base_size = base_obj
        .as_ref()
        .and_then(|o| o.symbol_by_name_or_demangled(symbol_name))
        .map(|idx| base_obj.as_ref().unwrap().symbols[idx].size)
        .unwrap_or(0);

    // Get symbol indices for both sides (use demangled lookup)
    let target_symbol_idx = target_obj
        .as_ref()
        .and_then(|o| o.symbol_by_name_or_demangled(symbol_name));
    let base_symbol_idx = base_obj
        .as_ref()
        .and_then(|o| o.symbol_by_name_or_demangled(symbol_name));

    // Get both sides of the diff
    let left_diff = diff_result.left.as_ref();
    let right_diff = diff_result.right.as_ref();

    // Handle flag implications: --verdict implies --analyze implies --summary
    let wants_verdict = args.verdict;
    let wants_analyze = args.analyze || wants_verdict;
    let wants_summary = args.summary || wants_analyze;

    // Build instruction diffs if requested (or if summary/analyze/verdict is requested)
    let instructions = if args.include_instructions || wants_summary {
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

    // Build instruction summary if requested
    let instruction_summary = if wants_summary {
        instructions.as_ref().map(|instrs| InstructionSummary::from_instructions(instrs))
    } else {
        None
    };

    // Run pattern analysis if requested
    let analysis = if wants_analyze {
        instructions
            .as_ref()
            .map(|instrs| super::analysis::analyze_instructions(instrs))
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
            )),
            _ => None,
        }
    } else {
        None
    };

    // Build the output
    let output = DiffOutput {
        symbol: symbol_name.clone(),
        demangled: symbol.demangled_name.clone(),
        unit: args.unit.clone(),
        target_size,
        base_size,
        fuzzy_match_percent: symbol_diff.match_percent,
        diff_score: symbol_diff.diff_score.map(|(score, max)| DiffScoreOutput {
            score,
            max_score: max,
        }),
        build_status: None, // No build status in one-shot mode
        instruction_summary,
        analysis,
        verdict,
        // Only include instructions in output if explicitly requested (not just for summary)
        instructions: if args.include_instructions { instructions } else { None },
    };

    // Write output
    write_diff_output(&output, args.output.as_deref(), output_format)?;

    Ok(())
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
    let left_rows = left_diff
        .and_then(|d| target_symbol_idx.map(|idx| &d.symbols[idx].instruction_rows));

    // Get the instruction rows from right (base) side
    let right_rows = right_diff
        .and_then(|d| base_symbol_idx.map(|idx| &d.symbols[idx].instruction_rows));

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
        let base_info = if let (Some(row), Some(obj), Some(sym_idx)) =
            (right_row, base_obj, base_symbol_idx)
        {
            if let Some(ins_ref) = row.ins_ref {
                Some(build_instruction_info(obj, sym_idx, ins_ref, diff_config)?)
            } else {
                None
            }
        } else {
            None
        };

        // Use the diff kind from whichever side is available
        let kind = left_row
            .map(|r| r.kind)
            .or_else(|| right_row.map(|r| r.kind))
            .unwrap_or(InstructionDiffKind::None);

        // Compute diff breakdown if this is an argument mismatch
        let diff_breakdown = if kind == InstructionDiffKind::ArgMismatch {
            compute_arg_diff_breakdown(target_info.as_ref(), base_info.as_ref())
        } else {
            None
        };

        instructions.push(InstructionDiffOutput {
            index: idx,
            target: target_info,
            base: base_info,
            match_type: match_type_str(kind).to_string(),
            diff_breakdown,
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

    if arguments.is_empty() {
        None
    } else {
        Some(InstructionDiffBreakdown { arguments })
    }
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
static REGISTER_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^([rf]\d+|cr\d+|sp|lr|ctr|xer)$").unwrap()
});

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
            let symbol_name = relocation
                .map(|r| r.symbol.name.clone())
                .unwrap_or_else(|| "<reloc>".to_string());
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
                objdiff_core::obj::InstructionArg::Reloc => {
                    resolved.relocation.as_ref().map_or("<reloc>".to_string(), |r| r.symbol.name.clone())
                }
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
    let line_info = resolved
        .section
        .line_info
        .range(..=ins_ref.address)
        .last()
        .map(|(_, info)| info);

    let line_number = line_info.map(|(line, _)| *line);
    let source_file = line_info
        .map(|(_, file)| file.clone())
        .filter(|f| !f.is_empty());

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
    let target_symbol_idx = target_obj.and_then(|o| o.symbol_by_name_or_demangled(symbol_name));
    let base_symbol_idx = base_obj.and_then(|o| o.symbol_by_name_or_demangled(symbol_name));

    // Get the symbol index from whichever side has it
    let (symbol_idx, obj, obj_diff) = if let Some(idx) = target_symbol_idx {
        let obj = target_obj.unwrap();
        let diff = diff_result.left.as_ref().ok_or_else(|| anyhow!("Missing left diff result"))?;
        (idx, obj, diff)
    } else if let Some(idx) = base_symbol_idx {
        let obj = base_obj.unwrap();
        let diff = diff_result.right.as_ref().ok_or_else(|| anyhow!("Missing right diff result"))?;
        (idx, obj, diff)
    } else {
        // Symbol not found in either object
        return Ok(None);
    };

    let symbol = &obj.symbols[symbol_idx];
    let symbol_diff = &obj_diff.symbols[symbol_idx];

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
    let verdict =
        super::analysis::compute_verdict(&instruction_summary, &analysis, symbol_diff.match_percent);

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

fn render_diff_markdown(output: &DiffOutput) -> String {
    use std::fmt::Write;
    use super::analysis::PatternDetails;

    let mut md = String::new();

    // Header
    let display_name = output.demangled.as_ref().unwrap_or(&output.symbol);
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
    if let Some(percent) = output.fuzzy_match_percent {
        writeln!(md, "- **Match**: {:.1}%", percent).unwrap();
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

    // Patterns
    if let Some(analysis) = &output.analysis {
        if !analysis.patterns.is_empty() {
            writeln!(md, "## Patterns Detected").unwrap();
            writeln!(md).unwrap();
            for pattern in &analysis.patterns {
                writeln!(
                    md,
                    "- **{}**: {} instruction(s), {:?} fixability",
                    pattern.pattern.as_str(),
                    pattern.instruction_count,
                    pattern.fixability
                )
                .unwrap();

                // Format pattern details
                match &pattern.details {
                    PatternDetails::MergedFunctions { merged_functions } => {
                        for mf in merged_functions {
                            writeln!(md, "  - `{}`: {} call(s)", mf.name, mf.count).unwrap();
                        }
                    }
                    PatternDetails::BoolMask { bit_positions } => {
                        writeln!(md, "  - Bit positions: {:?}", bit_positions).unwrap();
                    }
                    PatternDetails::RegisterSwap { swaps } => {
                        for swap in swaps {
                            writeln!(
                                md,
                                "  - {} ↔ {}: {} occurrence(s)",
                                swap.target_reg, swap.base_reg, swap.count
                            )
                            .unwrap();
                        }
                    }
                    PatternDetails::ComparisonStyle { comparisons } => {
                        for cmp in comparisons {
                            writeln!(
                                md,
                                "  - Index {}: {} ({} vs {})",
                                cmp.index, cmp.opcode, cmp.target_value, cmp.base_value
                            )
                            .unwrap();
                        }
                    }
                    PatternDetails::ControlFlow { branch_diffs } => {
                        for bd in branch_diffs {
                            let target = bd.target_opcode.as_deref().unwrap_or("-");
                            let base = bd.base_opcode.as_deref().unwrap_or("-");
                            writeln!(
                                md,
                                "  - Index {}: {} vs {} ({})",
                                bd.index, target, base, bd.match_type
                            )
                            .unwrap();
                        }
                    }
                    PatternDetails::CommutativeOpOrder { swaps } => {
                        for swap in swaps {
                            writeln!(
                                md,
                                "  - Index {}: {} operands swapped ({} vs {})",
                                swap.index,
                                swap.opcode,
                                swap.target_operands.join(", "),
                                swap.base_operands.join(", ")
                            )
                            .unwrap();
                        }
                    }
                    PatternDetails::OffsetSwap { swaps } => {
                        for swap in swaps {
                            writeln!(
                                md,
                                "  - Indices {:?}: offsets {:?} vs {:?}",
                                swap.indices, swap.target_offsets, swap.base_offsets
                            )
                            .unwrap();
                        }
                    }
                }
            }
            writeln!(md).unwrap();
        }
    }

    // Verdict
    if let Some(verdict) = &output.verdict {
        writeln!(md, "## Verdict: {:?}", verdict.classification).unwrap();
        writeln!(md).unwrap();
        writeln!(md, "{}", verdict.explanation).unwrap();
        writeln!(md).unwrap();
        writeln!(md, "**Recommendation**: {}", verdict.recommendation).unwrap();
        writeln!(md).unwrap();

        if !verdict.suggestions.is_empty() {
            writeln!(md, "### Suggestions").unwrap();
            writeln!(md).unwrap();
            for (i, suggestion) in verdict.suggestions.iter().enumerate() {
                writeln!(md, "{}. {}", i + 1, suggestion.action).unwrap();
            }
            writeln!(md).unwrap();
        }
    }

    // Instructions (mismatches only)
    if let Some(instructions) = &output.instructions {
        let mismatches: Vec<_> =
            instructions.iter().filter(|i| i.match_type != "equal").collect();

        if !mismatches.is_empty() {
            writeln!(md, "## Instruction Mismatches").unwrap();
            writeln!(md).unwrap();
            writeln!(md, "| Index | Target | Base | Match |").unwrap();
            writeln!(md, "|------:|--------|------|-------|").unwrap();

            for instr in mismatches {
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

                writeln!(
                    md,
                    "| {} | {} | {} | {} |",
                    instr.index, target_str, base_str, instr.match_type
                )
                .unwrap();
            }
            writeln!(md).unwrap();
        }
    }

    md
}

fn write_diff_output(
    output: &DiffOutput,
    path: Option<&Utf8PlatformPath>,
    format: DiffOutputFormat,
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
                let md = render_diff_markdown(output);
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
) -> Result<()> {
    let Some(symbol_name) = &args.symbol else { bail!("Interactive mode requires a symbol name") };
    let time_format = time::format_description::parse_borrowed::<2>("[hour]:[minute]:[second]")
        .context("Failed to parse time format")?;
    let (diff_obj_config, mapping_config) =
        build_config_from_args(&args, project_config.as_ref(), unit_options.as_ref())?;
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
