use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufWriter, Read, Write},
    path::PathBuf,
    sync::Mutex,
    time::Instant,
};

use anyhow::{Context, Result, bail};
use argp::FromArgs;
use globset::GlobBuilder;
use objdiff_core::{
    bindings::report::{
        ChangeItem, ChangeItemInfo, ChangeUnit, Changes, ChangesInput, Measures, REPORT_VERSION,
        Report, ReportCategory, ReportItem, ReportItemMetadata, ReportUnit, ReportUnitMetadata,
    },
    config::{ProjectObject, ProjectOptions, apply_project_options, path::platform_path},
    diff,
    obj::{self, SectionKind, SymbolFlag, SymbolKind},
};
use prost::Message;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use serde::Serialize;
use tracing::{info, warn};
use typed_path::{Utf8PlatformPath, Utf8PlatformPathBuf};

use crate::{
    cmd::{apply_config_args, diff::ObjectConfig},
    util::output::{OutputFormat, write_output},
};

/// Content-hash based cache for report units. Avoids re-diffing unchanged .obj files.
/// Cache format: u32 entry count, then for each entry: u64 hash, u32 data_len, data bytes.
struct ReportCache {
    entries: HashMap<u64, Vec<u8>>,
    path: PathBuf,
    hits: std::sync::atomic::AtomicU32,
    misses: std::sync::atomic::AtomicU32,
}

impl ReportCache {
    fn load(path: PathBuf) -> Self {
        let mut entries = HashMap::new();
        if let Ok(data) = std::fs::read(&path) {
            if data.len() >= 4 {
                let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
                let mut pos = 4;
                for _ in 0..count {
                    if pos + 12 > data.len() {
                        break;
                    }
                    let hash = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
                    let data_len =
                        u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap()) as usize;
                    pos += 12;
                    if pos + data_len > data.len() {
                        break;
                    }
                    entries.insert(hash, data[pos..pos + data_len].to_vec());
                    pos += data_len;
                }
            }
        }
        ReportCache {
            entries,
            path,
            hits: std::sync::atomic::AtomicU32::new(0),
            misses: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn get(&self, hash: u64) -> Option<ReportUnit> {
        if let Some(data) = self.entries.get(&hash) {
            if let Ok(unit) = ReportUnit::decode(data.as_slice()) {
                self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Some(unit);
            }
        }
        self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        None
    }

    fn save(&self, new_entries: &HashMap<u64, Vec<u8>>) {
        // Merge old and new entries, new entries override
        let mut merged = self.entries.clone();
        for (k, v) in new_entries {
            merged.insert(*k, v.clone());
        }
        let mut buf = Vec::with_capacity(4 + merged.len() * 128);
        buf.extend_from_slice(&(merged.len() as u32).to_le_bytes());
        for (hash, data) in &merged {
            buf.extend_from_slice(&hash.to_le_bytes());
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
        }
        let _ = std::fs::write(&self.path, buf);
    }

    /// Bump whenever the *content* of a cached `ReportUnit` changes for reasons the
    /// obj bytes + config args cannot express — i.e. whenever this file starts
    /// emitting a new field or a different value for the same inputs. The cache key
    /// is otherwise purely content-addressed, so without this a newly-installed
    /// binary would keep serving units produced by the old one and silently report
    /// the new fields as zero. Cost of a bump: one full re-diff of the report, no
    /// change to any measure.
    ///
    /// 2 — populated `Measures.masked_equal_functions` (funclet over-subscription)
    ///     and the per-item `ReportItem.masked_equal` bit.
    const CACHE_LOGIC_VERSION: u32 = 2;

    /// Hash a unit's target and base .obj file contents together.
    fn hash_unit(object: &ObjectConfig, config_args: &[String]) -> u64 {
        use xxhash_rust::xxh3::xxh3_64;
        let mut combined = Vec::new();
        combined.extend_from_slice(&Self::CACHE_LOGIC_VERSION.to_le_bytes());
        if let Some(p) = &object.target_path {
            if let Ok(data) = std::fs::read(p.as_str()) {
                combined.extend_from_slice(&data);
            }
        }
        combined.push(0xFF); // separator
        if let Some(p) = &object.base_path {
            if let Ok(data) = std::fs::read(p.as_str()) {
                combined.extend_from_slice(&data);
            }
        }
        // Include config args in hash so different report configs get different caches
        for arg in config_args {
            combined.push(0xFE);
            combined.extend_from_slice(arg.as_bytes());
        }
        xxh3_64(&combined)
    }
}

#[derive(FromArgs, PartialEq, Debug)]
/// Generate a progress report for a project.
#[argp(subcommand, name = "report")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
pub enum SubCommand {
    Generate(GenerateArgs),
    Changes(ChangesArgs),
    Summary(SummaryArgs),
    Query(QueryArgs),
    Function(FunctionArgs),
    Analyze(AnalyzeArgs),
    Trending(TrendingArgs),
}

#[derive(FromArgs, PartialEq, Debug)]
/// Generate a progress report for a project.
#[argp(subcommand, name = "generate")]
pub struct GenerateArgs {
    #[argp(option, short = 'p', from_str_fn(platform_path))]
    /// Project directory
    project: Option<Utf8PlatformPathBuf>,
    #[argp(option, short = 'o', from_str_fn(platform_path))]
    /// Output file
    output: Option<Utf8PlatformPathBuf>,
    #[argp(switch, short = 'd')]
    /// Deduplicate global and weak symbols (runs single-threaded)
    deduplicate: bool,
    #[argp(option, short = 'f')]
    /// Output format (json, json-pretty, proto) (default: json)
    format: Option<String>,
    #[argp(option, short = 'c')]
    /// Configuration property (key=value)
    config: Vec<String>,
    #[argp(switch)]
    /// Enable the case-B global byte-equality second pass: promote an unmatched
    /// NAMED real-bodied (>44B) target method to 100% when its reloc-masked +
    /// reloc-name signature uniquely (injective both sides) matches a base symbol
    /// in ANY unit, deduped by retail VA. Off by default (stock semantics).
    /// See docs/decomp/identity-transfer.md (case-B).
    global_byte_eq: bool,
    #[argp(option, from_str_fn(platform_path))]
    /// When --global-byte-eq is set, write the list of promotions (JSON) here for
    /// audit (icf_alias_check.py). One object per promoted VA.
    global_byte_eq_log: Option<Utf8PlatformPathBuf>,
    #[argp(option, from_str_fn(platform_path))]
    /// REQUIRED with --global-byte-eq: path to the rb3-Wii BinDiff oracle
    /// (unified_id_rb3wii.json). A promotion is gated on the retail VA being
    /// oracle-named (similarity >= 0.5) AND attributing to the claiming unit's
    /// source TU (Rule 3). Without it the pass would mis-attribute STL template
    /// folds; the pass refuses to run if this is absent.
    global_byte_eq_oracle: Option<Utf8PlatformPathBuf>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// List any changes from a previous report.
#[argp(subcommand, name = "changes")]
pub struct ChangesArgs {
    #[argp(positional, from_str_fn(platform_path))]
    /// Previous report file
    previous: Utf8PlatformPathBuf,
    #[argp(positional, from_str_fn(platform_path))]
    /// Current report file
    current: Utf8PlatformPathBuf,
    #[argp(option, short = 'o', from_str_fn(platform_path))]
    /// Output file
    output: Option<Utf8PlatformPathBuf>,
    #[argp(option, short = 'f')]
    /// Output format (json, json-pretty, proto) (default: json)
    format: Option<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Output aggregate statistics from a report.
#[argp(subcommand, name = "summary")]
pub struct SummaryArgs {
    #[argp(positional, from_str_fn(platform_path))]
    /// Report file (or "-" for stdin)
    report: Utf8PlatformPathBuf,
    #[argp(option, short = 'o', from_str_fn(platform_path))]
    /// Output file
    output: Option<Utf8PlatformPathBuf>,
    #[argp(option, short = 'f')]
    /// Output format (json, json-pretty, text) (default: json)
    format: Option<String>,
    #[argp(option)]
    /// Filter to specific category
    category: Option<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Filter and search report data.
#[argp(subcommand, name = "query")]
pub struct QueryArgs {
    #[argp(positional, from_str_fn(platform_path))]
    /// Report file (or "-" for stdin)
    report: Utf8PlatformPathBuf,
    #[argp(option, short = 'o', from_str_fn(platform_path))]
    /// Output file
    output: Option<Utf8PlatformPathBuf>,
    #[argp(option, short = 'f')]
    /// Output format (json, json-pretty, csv) (default: json)
    format: Option<String>,

    // Filtering options
    #[argp(option)]
    /// Filter units by glob pattern
    unit: Option<String>,
    #[argp(option)]
    /// Filter functions by regex pattern
    function: Option<String>,
    #[argp(option)]
    /// Minimum match percentage (0-100)
    min_percent: Option<f32>,
    #[argp(option)]
    /// Maximum match percentage (0-100)
    max_percent: Option<f32>,
    #[argp(switch)]
    /// Only show functions with 0% match (not implemented)
    unimplemented: bool,
    #[argp(option)]
    /// Minimum function size in bytes
    min_size: Option<u64>,
    #[argp(option)]
    /// Maximum function size in bytes
    max_size: Option<u64>,

    // Sorting options
    #[argp(option)]
    /// Sort by field: match_percent, size, name (default: name)
    sort_by: Option<String>,
    #[argp(option)]
    /// Sort order: asc, desc (default: asc)
    sort_order: Option<String>,
    #[argp(option)]
    /// Limit number of results
    limit: Option<usize>,

    // Output selection
    #[argp(switch)]
    /// Output only aggregate statistics
    summary: bool,
    #[argp(switch)]
    /// Output function-level data
    functions: bool,
    #[argp(switch)]
    /// Output unit-level data (default if no selection specified)
    units: bool,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Look up a function by name in a report.
#[argp(subcommand, name = "function")]
pub struct FunctionArgs {
    #[argp(positional, from_str_fn(platform_path))]
    /// Report file (or "-" for stdin)
    report: Utf8PlatformPathBuf,
    #[argp(positional)]
    /// Function name to search for
    function_name: String,
    #[argp(option, short = 'o', from_str_fn(platform_path))]
    /// Output file
    output: Option<Utf8PlatformPathBuf>,
    #[argp(option, short = 'f')]
    /// Output format (json, json-pretty, csv) (default: json)
    format: Option<String>,
    #[argp(switch)]
    /// Exact match only (no regex)
    exact: bool,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Batch analyze functions from a report with fixability verdicts.
#[argp(subcommand, name = "analyze")]
pub struct AnalyzeArgs {
    #[argp(positional, from_str_fn(platform_path))]
    /// Report file
    report: Utf8PlatformPathBuf,

    #[argp(option, short = 'p', from_str_fn(platform_path))]
    /// Project directory (defaults to current directory)
    project: Option<Utf8PlatformPathBuf>,

    #[argp(option)]
    /// Minimum match percentage (0-100)
    min_percent: Option<f32>,

    #[argp(option)]
    /// Maximum match percentage (0-100)
    max_percent: Option<f32>,

    #[argp(option)]
    /// Maximum number of functions to analyze
    limit: Option<usize>,

    #[argp(option, short = 'o', from_str_fn(platform_path))]
    /// Output file
    output: Option<Utf8PlatformPathBuf>,

    #[argp(option, short = 'f')]
    /// Output format (json, json-pretty, csv) (default: json)
    format: Option<String>,

    #[argp(option, short = 'c')]
    /// Configuration property (key=value)
    config: Vec<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Compare multiple reports over time to show progress trends.
#[argp(subcommand, name = "trending")]
pub struct TrendingArgs {
    #[argp(positional, from_str_fn(platform_path))]
    /// Report files to compare (in chronological order)
    reports: Vec<Utf8PlatformPathBuf>,

    #[argp(option, short = 'o', from_str_fn(platform_path))]
    /// Output file
    output: Option<Utf8PlatformPathBuf>,

    #[argp(option, short = 'f')]
    /// Output format (json, json-pretty, text) (default: json)
    format: Option<String>,

    #[argp(switch)]
    /// Use file modification times for ordering instead of argument order
    by_mtime: bool,

    #[argp(option)]
    /// Filter to specific category
    category: Option<String>,

    #[argp(option)]
    /// Maximum number of reports to include (default: 30)
    limit: Option<usize>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Generate(args) => generate(args),
        SubCommand::Changes(args) => changes(args),
        SubCommand::Summary(args) => summary(args),
        SubCommand::Query(args) => query(args),
        SubCommand::Function(args) => function(args),
        SubCommand::Analyze(args) => analyze(args),
        SubCommand::Trending(args) => trending(args),
    }
}

fn generate(args: GenerateArgs) -> Result<()> {
    let base_diff_config = diff::DiffObjConfig {
        function_reloc_diffs: diff::FunctionRelocDiffs::None,
        combine_data_sections: true,
        combine_text_sections: true,
        ppc_calculate_pool_relocations: false,
        ..Default::default()
    };

    let output_format = OutputFormat::from_option(args.format.as_deref())?;
    let project_dir = args.project.as_deref().unwrap_or_else(|| Utf8PlatformPath::new("."));
    info!("Loading project {}", project_dir);

    let project = match objdiff_core::config::try_project_config(project_dir.as_ref()) {
        Some((Ok(config), _)) => config,
        Some((Err(err), _)) => bail!("Failed to load project configuration: {}", err),
        None => bail!("No project configuration found"),
    };
    let target_obj_dir =
        project.target_dir.as_ref().map(|p| project_dir.join(p.with_platform_encoding()));
    let base_obj_dir =
        project.base_dir.as_ref().map(|p| project_dir.join(p.with_platform_encoding()));
    let project_units = project.units.as_deref().unwrap_or_default();
    let objects = project_units
        .iter()
        .enumerate()
        .map(|(idx, o)| {
            (
                ObjectConfig::new(
                    o,
                    project_dir,
                    target_obj_dir.as_deref(),
                    base_obj_dir.as_deref(),
                ),
                idx,
            )
        })
        .collect::<Vec<_>>();
    info!(
        "Generating report for {} units (using {} threads)",
        objects.len(),
        if args.deduplicate { 1 } else { rayon::current_num_threads() }
    );

    // Load map file for ICF symbol equivalences
    let mapping_config = if let Some(map_file) = &project.map_file {
        let map_path = project_dir.join(map_file.with_platform_encoding());
        let file = std::fs::File::open(map_path.as_str())
            .with_context(|| format!("Failed to open map file: {}", map_path))?;
        let reader = std::io::BufReader::new(file);
        let equivalences = objdiff_core::obj::map_file::parse_msvc_map(reader);
        info!("Loaded {} ICF equivalence entries from {}", equivalences.len(), map_path);
        diff::MappingConfig { symbol_equivalences: equivalences, ..Default::default() }
    } else {
        diff::MappingConfig::default()
    };

    // Load content-hash based cache for incremental report generation.
    // Cache key = xxHash3 of target+base .obj file contents + config args.
    let cache_path = args
        .output
        .as_ref()
        .map(|o| {
            let mut p = std::path::PathBuf::from(o.as_str());
            p.set_extension("cache");
            p
        })
        .unwrap_or_else(|| std::path::PathBuf::from(".objdiff_report_cache"));
    let cache = ReportCache::load(cache_path);
    let new_cache_entries: Mutex<HashMap<u64, Vec<u8>>> = Mutex::new(HashMap::new());

    let start = Instant::now();
    let mut units = vec![];
    let mut existing_functions: HashSet<String> = HashSet::new();
    if args.deduplicate {
        // If deduplicating, we need to run single-threaded
        for (object, unit_idx) in &objects {
            let diff_config = build_unit_diff_config(
                &base_diff_config,
                project.options.as_ref(),
                project_units.get(*unit_idx).and_then(ProjectObject::options),
                &args.config,
            )?;
            let hash = ReportCache::hash_unit(object, &args.config);
            if let Some(cached_unit) = cache.get(hash) {
                units.push(cached_unit);
            } else if let Some(unit) = report_object(
                object,
                &diff_config,
                Some(&mut existing_functions),
                Some(&mapping_config),
            )? {
                let encoded = unit.encode_to_vec();
                new_cache_entries.lock().unwrap().insert(hash, encoded);
                units.push(unit);
            }
        }
    } else {
        let vec = objects
            .par_iter()
            .map(|(object, unit_idx)| {
                let hash = ReportCache::hash_unit(object, &args.config);
                if let Some(cached_unit) = cache.get(hash) {
                    return Ok(Some(cached_unit));
                }
                let diff_config = build_unit_diff_config(
                    &base_diff_config,
                    project.options.as_ref(),
                    project_units.get(*unit_idx).and_then(ProjectObject::options),
                    &args.config,
                )?;
                let result =
                    report_object(object, &diff_config, None, Some(&mapping_config))?;
                if let Some(ref unit) = result {
                    let encoded = unit.encode_to_vec();
                    new_cache_entries.lock().unwrap().insert(hash, encoded);
                }
                Ok(result)
            })
            .collect::<Result<Vec<Option<ReportUnit>>>>()?;
        units = vec.into_iter().flatten().collect();
    }

    let hits = cache.hits.load(std::sync::atomic::Ordering::Relaxed);
    let misses = cache.misses.load(std::sync::atomic::Ordering::Relaxed);
    if hits + misses > 0 {
        info!("Report cache: {} hits, {} misses", hits, misses);
    }

    // Save updated cache
    let new_entries = new_cache_entries.into_inner().unwrap();
    if !new_entries.is_empty() {
        cache.save(&new_entries);
    }

    // ── Case-B global byte-equality second pass (opt-in via --global-byte-eq).
    //
    // Per the design (docs/decomp/identity-transfer.md + the report-driver seam):
    // this lives in `generate` — the ONLY place that enumerates all units' obj
    // paths — never inside diff_objs. It re-reads every target+base obj, builds a
    // global base signature index, and promotes still-<100% NAMED real-bodied
    // case-B methods to 100% under the honesty predicate, mutating the claiming
    // unit's measures in place. Per-unit diff semantics are unchanged. MUST run
    // AFTER cache reconstitution (the per-unit cache keys only on a unit's own two
    // objs, so a cross-unit promotion is stale-on-unrelated-obj-change; accepted
    // for the report-build use).
    if args.global_byte_eq {
        // Rule 3 is non-negotiable: refuse to run without the oracle.
        let oracle_path = args.global_byte_eq_oracle.as_ref().with_context(|| {
            "--global-byte-eq requires --global-byte-eq-oracle (unified_id_rb3wii.json): \
             the oracle own-TU gate is what keeps the pass from mis-attributing STL \
             template folds (see correctness rule 3)"
        })?;
        let oracle = load_va_oracle(oracle_path.as_str())
            .with_context(|| format!("Failed to load oracle: {oracle_path}"))?;
        info!("Loaded {} oracle VA-attribution entries from {}", oracle.len(), oracle_path);

        let gbe_diff_config = base_diff_config.clone();
        let unit_objs: Vec<diff::UnitObjs> = objects
            .par_iter()
            .map(|(object, _unit_idx)| {
                let target = object.target_path.as_ref().and_then(|p| {
                    obj::read::read(p.as_ref(), &gbe_diff_config, diff::DiffSide::Target).ok()
                });
                let base = object.base_path.as_ref().and_then(|p| {
                    obj::read::read(p.as_ref(), &gbe_diff_config, diff::DiffSide::Base).ok()
                });
                diff::UnitObjs { unit_name: object.name.clone(), target, base }
            })
            .collect();
        let promotions = diff::reconcile_global_byte_matches(
            &mut units,
            &unit_objs,
            &mapping_config.symbol_equivalences,
            &oracle,
        );
        info!("Case-B global byte-equality pass promoted {} method(s)", promotions.len());
        if let Some(log_path) = &args.global_byte_eq_log {
            let json: Vec<_> = promotions
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "unit": p.unit_name,
                        "symbol": p.symbol_name,
                        "virtual_address": format!("{:#010x}", p.virtual_address),
                        "size": p.size,
                        "base_unit": p.base_unit_name,
                    })
                })
                .collect();
            std::fs::write(
                log_path.as_str(),
                serde_json::to_string_pretty(&json).unwrap_or_default(),
            )
            .with_context(|| format!("Failed to write promotion log: {log_path}"))?;
        }
    }

    let measures = units.iter().flat_map(|u| u.measures.into_iter()).collect();
    let mut categories = Vec::new();
    for category in project.progress_categories() {
        categories.push(ReportCategory {
            id: category.id.clone(),
            name: category.name.clone(),
            measures: Some(Default::default()),
        });
    }
    let mut report =
        Report { measures: Some(measures), units, version: REPORT_VERSION, categories };
    report.calculate_progress_categories();
    let duration = start.elapsed();
    info!("Report generated in {}.{:03}s", duration.as_secs(), duration.subsec_millis());
    write_output(&report, args.output.as_deref(), output_format)?;
    Ok(())
}

/// Load the rb3-Wii BinDiff oracle (`unified_id_rb3wii.json`, a list of
/// `{rb3_addr, bindiff_src, similarity, ...}`) into the VA→(src-basename, sim) map
/// the global-byte-eq pass needs for its own-TU honesty gate (Rule 3). The
/// basename is lowercased with its extension stripped (e.g.
/// "band3/src/tour/TourProgress.cpp" → "tourprogress") to compare against a
/// unit's source basename. If a VA appears more than once, the highest-similarity
/// entry wins (best-attribution).
fn load_va_oracle(path: &str) -> Result<diff::VaOracle> {
    let data = std::fs::read_to_string(path)?;
    let entries: Vec<serde_json::Value> = serde_json::from_str(&data)?;
    let mut map: diff::VaOracle = HashMap::new();
    for e in entries {
        let Some(addr_s) = e.get("rb3_addr").and_then(|v| v.as_str()) else { continue };
        let va = match u64::from_str_radix(addr_s.trim_start_matches("0x"), 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(src) = e.get("bindiff_src").and_then(|v| v.as_str()) else { continue };
        let base = src
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(src)
            .rsplit_once('.')
            .map(|(stem, _)| stem)
            .unwrap_or(src)
            .to_ascii_lowercase();
        let sim = e.get("similarity").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
        map.entry(va)
            .and_modify(|cur| {
                if sim > cur.1 {
                    *cur = (base.clone(), sim);
                }
            })
            .or_insert((base, sim));
    }
    Ok(map)
}

fn build_unit_diff_config(
    base: &diff::DiffObjConfig,
    project_options: Option<&ProjectOptions>,
    unit_options: Option<&ProjectOptions>,
    cli_args: &[String],
) -> Result<diff::DiffObjConfig> {
    let mut diff_config = base.clone();
    if let Some(options) = project_options {
        apply_project_options(&mut diff_config, options)?;
    }
    if let Some(options) = unit_options {
        apply_project_options(&mut diff_config, options)?;
    }
    // CLI args override project and unit options
    apply_config_args(&mut diff_config, cli_args)?;
    Ok(diff_config)
}

fn report_object(
    object: &ObjectConfig,
    diff_config: &diff::DiffObjConfig,
    mut existing_functions: Option<&mut HashSet<String>>,
    mapping_config: Option<&diff::MappingConfig>,
) -> Result<Option<ReportUnit>> {
    match (&object.target_path, &object.base_path) {
        (None, Some(_)) if !object.complete.unwrap_or(false) => {
            warn!("Skipping object without target: {}", object.name);
            return Ok(None);
        }
        (None, None) => {
            warn!("Skipping object without target or base: {}", object.name);
            return Ok(None);
        }
        _ => {}
    }
    let default_mapping = diff::MappingConfig::default();
    let mapping_config = mapping_config.unwrap_or(&default_mapping);
    let target = object
        .target_path
        .as_ref()
        .map(|p| {
            obj::read::read(p.as_ref(), diff_config, diff::DiffSide::Target)
                .with_context(|| format!("Failed to open {p}"))
        })
        .transpose()?;
    let base = object
        .base_path
        .as_ref()
        .map(|p| {
            obj::read::read(p.as_ref(), diff_config, diff::DiffSide::Base)
                .with_context(|| format!("Failed to open {p}"))
        })
        .transpose()?;
    let result =
        diff::diff_objs(target.as_ref(), base.as_ref(), None, diff_config, mapping_config)?;

    let metadata = ReportUnitMetadata {
        complete: object.metadata.complete,
        module_name: target
            .as_ref()
            .and_then(|o| o.split_meta.as_ref())
            .and_then(|m| m.module_name.clone()),
        module_id: target.as_ref().and_then(|o| o.split_meta.as_ref()).and_then(|m| m.module_id),
        source_path: object.metadata.source_path.as_ref().map(|p| p.to_string()),
        progress_categories: object.metadata.progress_categories.clone().unwrap_or_default(),
        auto_generated: object.metadata.auto_generated,
    };
    let mut measures = Measures { total_units: 1, ..Default::default() };
    let mut sections = vec![];
    let mut functions = vec![];

    let obj = target.as_ref().or(base.as_ref()).unwrap();
    let obj_diff = result.left.as_ref().or(result.right.as_ref()).unwrap();

    // ── Disclosure: funclet OVER-SUBSCRIPTION (`pair_funclets_by_bytes` pass 2b) ──
    //
    // Pass 2b pairs a leftover anonymous target funclet many-to-one onto a base
    // funclet that some other target symbol already owns, and the overflow is
    // credited 100%. That credit is not backed by a symbol our compiled object
    // actually supplies, so it inflates `matched_functions` with machine code we
    // never generated.
    //
    // Detection needs no new plumbing: EVERY other pairing path (symbol mappings,
    // name matching, funclet passes 1/2/3) inserts its base partner into
    // `right_used` before moving on, so a base symbol can be the partner of at most
    // one target symbol. Two or more target symbols sharing a `target_symbol` index
    // is therefore *exactly* a pass-2b over-subscription, and a group of size N
    // contributes exactly N-1 surplus symbols.
    //
    // Which member is the surplus one is genuinely arbitrary — the group is
    // byte-identical by construction. We treat the member that did NOT come from
    // funclet pairing as the legitimate owner when there is one (there is at most
    // one, since a name match consumes the partner), else the lowest symbol index.
    // The per-group count is exact either way.
    let mut partner_groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for (idx, symbol_diff) in obj_diff.symbols.iter().enumerate() {
        if let Some(partner) = symbol_diff.target_symbol {
            partner_groups.entry(partner).or_default().push(idx);
        }
    }
    let mut oversubscribed: HashSet<usize> = HashSet::new();
    for group in partner_groups.values().filter(|g| g.len() > 1) {
        let owner = group
            .iter()
            .copied()
            .find(|&i| !obj_diff.symbols[i].masked_equal_symbol)
            .unwrap_or_else(|| group.iter().copied().min().expect("non-empty group"));
        oversubscribed.extend(group.iter().copied().filter(|&i| i != owner));
    }
    for ((section_idx, section), section_diff) in
        obj.sections.iter().enumerate().zip(&obj_diff.sections)
    {
        if section.kind == SectionKind::Unknown {
            continue;
        }
        let section_match_percent = match section_diff.match_percent {
            Some(pct) => pct,
            None if base.is_none() && object.complete.unwrap_or(false) => 100.0,
            None => 0.0,
        };
        sections.push(ReportItem {
            name: section.name.clone(),
            fuzzy_match_percent: section_match_percent,
            match_percent_normalized: None,
            size: section.size,
            metadata: Some(ReportItemMetadata {
                demangled_name: None,
                virtual_address: section.virtual_address,
            }),
            address: None,
            masked_equal: None,
        });

        match section.kind {
            SectionKind::Data | SectionKind::Bss => {
                measures.total_data += section.size;
                if section_match_percent == 100.0 {
                    measures.matched_data += section.size;
                }
                continue;
            }
            _ => {}
        }

        for (symbol_idx, (symbol, symbol_diff)) in
            obj.symbols.iter().zip(&obj_diff.symbols).enumerate()
        {
            if symbol.section != Some(section_idx)
                || symbol.size == 0
                || symbol.flags.contains(SymbolFlag::Hidden)
                || symbol.flags.contains(SymbolFlag::Ignored)
                || symbol.kind == SymbolKind::Section
            {
                continue;
            }
            if let Some(existing_functions) = &mut existing_functions
                && (symbol.flags.contains(SymbolFlag::Global)
                    || symbol.flags.contains(SymbolFlag::Weak))
                && !existing_functions.insert(symbol.name.clone())
            {
                continue;
            }
            let match_percent = match symbol_diff.match_percent {
                Some(pct) => pct,
                None if base.is_none() && object.complete.unwrap_or(false) => {
                    // No target object but unit is marked complete: assume 100% match
                    100.0
                }
                None => {
                    // Symbol exists in target but has no source implementation (0% match).
                    0.0
                }
            };
            let match_percent_normalized = match symbol_diff.match_percent_normalized {
                Some(pct) => pct,
                _ => match_percent,
            };
            measures.fuzzy_match_percent += match_percent_normalized * symbol.size as f32;
            measures.total_code += symbol.size;
            if match_percent == 100.0 {
                measures.matched_code += symbol.size;
            }
            let is_oversubscribed = oversubscribed.contains(&symbol_idx);
            functions.push(ReportItem {
                name: symbol.name.clone(),
                size: symbol.size,
                fuzzy_match_percent: match_percent,
                match_percent_normalized: Some(match_percent_normalized),
                metadata: Some(ReportItemMetadata {
                    demangled_name: symbol.demangled_name.clone(),
                    virtual_address: symbol.virtual_address,
                }),
                address: symbol.address.checked_sub(section.address),
                masked_equal: is_oversubscribed.then_some(true),
            });
            if match_percent_normalized == 100.0 {
                measures.matched_functions += 1;
                // Disclosure only: a SUBSET of the `matched_functions` just
                // credited, never an addition to it.
                if is_oversubscribed {
                    measures.masked_equal_functions += 1;
                }
            }
            measures.total_functions += 1;
        }
    }
    sections.sort_by(|a, b| a.name.cmp(&b.name));
    let reverse_fn_order = object.metadata.reverse_fn_order.unwrap_or(false);
    functions.sort_by(|a, b| {
        if reverse_fn_order {
            b.address.unwrap_or(0).cmp(&a.address.unwrap_or(0))
        } else {
            a.address.unwrap_or(u64::MAX).cmp(&b.address.unwrap_or(u64::MAX))
        }
        .then_with(|| a.size.cmp(&b.size))
    });
    if metadata.complete.unwrap_or(false) {
        measures.complete_code = measures.total_code;
        measures.complete_data = measures.total_data;
        measures.complete_units = 1;
    }
    measures.calc_fuzzy_match_percent();
    measures.calc_matched_percent();
    Ok(Some(ReportUnit {
        name: object.name.clone(),
        measures: Some(measures),
        sections,
        functions,
        metadata: Some(metadata),
    }))
}

fn changes(args: ChangesArgs) -> Result<()> {
    let output_format = OutputFormat::from_option(args.format.as_deref())?;
    let (previous, current) = if args.previous == "-" && args.current == "-" {
        // Special case for comparing two reports from stdin
        let mut data = vec![];
        std::io::stdin().read_to_end(&mut data)?;
        let input = ChangesInput::decode(data.as_slice())?;
        (input.from.unwrap(), input.to.unwrap())
    } else {
        let previous = read_report(&args.previous)?;
        let current = read_report(&args.current)?;
        (previous, current)
    };
    let mut changes = Changes { from: previous.measures, to: current.measures, units: vec![] };
    for prev_unit in &previous.units {
        let curr_unit = current.units.iter().find(|u| u.name == prev_unit.name);
        let sections = process_items(prev_unit, curr_unit, |u| &u.sections);
        let functions = process_items(prev_unit, curr_unit, |u| &u.functions);

        let prev_measures = prev_unit.measures;
        let curr_measures = curr_unit.and_then(|u| u.measures);
        if !functions.is_empty() || prev_measures != curr_measures {
            changes.units.push(ChangeUnit {
                name: prev_unit.name.clone(),
                from: prev_measures,
                to: curr_measures,
                sections,
                functions,
                metadata: curr_unit
                    .as_ref()
                    .and_then(|u| u.metadata.clone())
                    .or_else(|| prev_unit.metadata.clone()),
            });
        }
    }
    for curr_unit in &current.units {
        if !previous.units.iter().any(|u| u.name == curr_unit.name) {
            changes.units.push(ChangeUnit {
                name: curr_unit.name.clone(),
                from: None,
                to: curr_unit.measures,
                sections: process_new_items(&curr_unit.sections),
                functions: process_new_items(&curr_unit.functions),
                metadata: curr_unit.metadata.clone(),
            });
        }
    }
    write_output(&changes, args.output.as_deref(), output_format)?;
    Ok(())
}

fn process_items<F: Fn(&ReportUnit) -> &Vec<ReportItem>>(
    prev_unit: &ReportUnit,
    curr_unit: Option<&ReportUnit>,
    getter: F,
) -> Vec<ChangeItem> {
    let prev_items = getter(prev_unit);
    let mut items = vec![];
    if let Some(curr_unit) = curr_unit {
        let curr_items = getter(curr_unit);
        for prev_func in prev_items {
            let prev_func_info = ChangeItemInfo::from(prev_func);
            let curr_func = curr_items.iter().find(|f| f.name == prev_func.name);
            let curr_func_info = curr_func.map(ChangeItemInfo::from);
            if let Some(curr_func_info) = curr_func_info {
                if prev_func_info != curr_func_info {
                    items.push(ChangeItem {
                        name: prev_func.name.clone(),
                        from: Some(prev_func_info),
                        to: Some(curr_func_info),
                        metadata: curr_func.as_ref().unwrap().metadata.clone(),
                    });
                }
            } else {
                items.push(ChangeItem {
                    name: prev_func.name.clone(),
                    from: Some(prev_func_info),
                    to: None,
                    metadata: prev_func.metadata.clone(),
                });
            }
        }
        for curr_func in curr_items {
            if !prev_items.iter().any(|f| f.name == curr_func.name) {
                items.push(ChangeItem {
                    name: curr_func.name.clone(),
                    from: None,
                    to: Some(ChangeItemInfo::from(curr_func)),
                    metadata: curr_func.metadata.clone(),
                });
            }
        }
    } else {
        for prev_func in prev_items {
            items.push(ChangeItem {
                name: prev_func.name.clone(),
                from: Some(ChangeItemInfo::from(prev_func)),
                to: None,
                metadata: prev_func.metadata.clone(),
            });
        }
    }
    items
}

fn process_new_items(items: &[ReportItem]) -> Vec<ChangeItem> {
    items
        .iter()
        .map(|item| ChangeItem {
            name: item.name.clone(),
            from: None,
            to: Some(ChangeItemInfo::from(item)),
            metadata: item.metadata.clone(),
        })
        .collect()
}

fn read_report(path: &Utf8PlatformPath) -> Result<Report> {
    if path == Utf8PlatformPath::new("-") {
        let mut data = vec![];
        std::io::stdin().read_to_end(&mut data)?;
        return Report::parse(&data).with_context(|| "Failed to load report from stdin");
    }
    let file = File::open(path).with_context(|| format!("Failed to open {path}"))?;
    let mmap =
        unsafe { memmap2::Mmap::map(&file) }.with_context(|| format!("Failed to map {path}"))?;
    Report::parse(mmap.as_ref()).with_context(|| format!("Failed to load report {path}"))
}

#[derive(Serialize)]
struct SummaryOutput {
    fuzzy_match_percent: f32,
    matched_code_percent: f32,
    matched_functions: u32,
    total_functions: u32,
    matched_functions_percent: f32,
    total_code: u64,
    matched_code: u64,
}

impl From<&Measures> for SummaryOutput {
    fn from(measures: &Measures) -> Self {
        Self {
            fuzzy_match_percent: measures.fuzzy_match_percent,
            matched_code_percent: measures.matched_code_percent,
            matched_functions: measures.matched_functions,
            total_functions: measures.total_functions,
            matched_functions_percent: measures.matched_functions_percent,
            total_code: measures.total_code,
            matched_code: measures.matched_code,
        }
    }
}

impl std::fmt::Display for SummaryOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Fuzzy match:       {:.1}%", self.fuzzy_match_percent)?;
        writeln!(
            f,
            "Matched code:      {:.1}% ({} / {} bytes)",
            self.matched_code_percent, self.matched_code, self.total_code
        )?;
        writeln!(
            f,
            "Matched functions: {:.1}% ({} / {})",
            self.matched_functions_percent, self.matched_functions, self.total_functions
        )?;
        Ok(())
    }
}

fn summary(args: SummaryArgs) -> Result<()> {
    let report = read_report(&args.report)?;

    let measures = if let Some(category_id) = &args.category {
        report
            .categories
            .iter()
            .find(|c| &c.id == category_id)
            .and_then(|c| c.measures.as_ref())
            .with_context(|| format!("Category '{}' not found in report", category_id))?
    } else {
        report.measures.as_ref().context("Report has no measures")?
    };

    let output = SummaryOutput::from(measures);

    let format = args.format.as_deref().unwrap_or("json");
    match format.to_ascii_lowercase().as_str() {
        "json" => {
            let json = serde_json::to_string(&output)?;
            write_summary_output(&json, args.output.as_deref())?;
        }
        "json-pretty" | "json_pretty" => {
            let json = serde_json::to_string_pretty(&output)?;
            write_summary_output(&json, args.output.as_deref())?;
        }
        "text" => {
            let text = output.to_string();
            write_summary_output(&text, args.output.as_deref())?;
        }
        _ => bail!("Invalid output format: {}. Expected json, json-pretty, or text", format),
    }

    Ok(())
}

fn write_summary_output(content: &str, output: Option<&Utf8PlatformPath>) -> Result<()> {
    match output {
        Some(path) if path != Utf8PlatformPath::new("-") => {
            info!("Writing to {}", path);
            let file = File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .with_context(|| format!("Failed to create file {}", path))?;
            let mut writer = BufWriter::new(file);
            writer.write_all(content.as_bytes()).context("Failed to write output file")?;
            writer.flush().context("Failed to flush output file")?;
        }
        _ => {
            print!("{}", content);
        }
    }
    Ok(())
}

// Query output structures
#[derive(Serialize)]
struct QueryResult {
    query: QueryInfo,
    summary: QuerySummary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    results: Vec<QueryItem>,
}

#[derive(Serialize)]
struct QueryInfo {
    filters: QueryFilters,
    sort_by: Option<String>,
    sort_order: Option<String>,
    limit: Option<usize>,
    output_mode: String,
}

#[derive(Serialize)]
struct QueryFilters {
    #[serde(skip_serializing_if = "Option::is_none")]
    unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_percent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_percent: Option<f32>,
    unimplemented: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_size: Option<u64>,
}

#[derive(Serialize)]
struct QuerySummary {
    total_matched: usize,
    total_filtered: usize,
}

#[derive(Serialize)]
struct QueryItem {
    unit: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    demangled_name: Option<String>,
    size: u64,
    fuzzy_match_percent: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryOutputFormat {
    Json,
    JsonPretty,
    Csv,
}

impl QueryOutputFormat {
    fn from_option(s: Option<&str>) -> Result<Self> {
        match s {
            None | Some("json") => Ok(Self::Json),
            Some("json-pretty") | Some("json_pretty") => Ok(Self::JsonPretty),
            Some("csv") => Ok(Self::Csv),
            Some(other) => {
                bail!("Invalid output format: {}. Supported: json, json-pretty, csv", other)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortField {
    MatchPercent,
    Size,
    Name,
}

impl SortField {
    fn from_option(s: Option<&str>) -> Result<Self> {
        match s {
            None | Some("name") => Ok(Self::Name),
            Some("match_percent") | Some("percent") => Ok(Self::MatchPercent),
            Some("size") => Ok(Self::Size),
            Some(other) => {
                bail!("Invalid sort field: {}. Supported: name, match_percent, size", other)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortOrder {
    Asc,
    Desc,
}

impl SortOrder {
    fn from_option(s: Option<&str>) -> Result<Self> {
        match s {
            None | Some("asc") => Ok(Self::Asc),
            Some("desc") => Ok(Self::Desc),
            Some(other) => bail!("Invalid sort order: {}. Supported: asc, desc", other),
        }
    }
}

fn query(args: QueryArgs) -> Result<()> {
    let output_format = QueryOutputFormat::from_option(args.format.as_deref())?;
    let sort_field = SortField::from_option(args.sort_by.as_deref())?;
    let sort_order = SortOrder::from_option(args.sort_order.as_deref())?;

    // Load the report
    let report = read_report(&args.report)?;

    // Compile patterns
    let unit_glob = args
        .unit
        .as_ref()
        .map(|pattern| {
            GlobBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map(|g| g.compile_matcher())
                .with_context(|| format!("Invalid unit glob pattern: {}", pattern))
        })
        .transpose()?;

    let function_regex = args
        .function
        .as_ref()
        .map(|pattern| {
            Regex::new(pattern).with_context(|| format!("Invalid function regex: {}", pattern))
        })
        .transpose()?;

    // Determine output mode
    let output_mode = if args.summary {
        "summary"
    } else if args.functions {
        "functions"
    } else {
        "units"
    };

    // Collect and filter items
    let mut items: Vec<QueryItem> = Vec::new();

    for unit in &report.units {
        // Check unit filter
        if let Some(ref glob) = unit_glob
            && !glob.is_match(&unit.name)
        {
            continue;
        }

        if args.functions {
            // Output function-level data
            for func in &unit.functions {
                // Apply function name filter
                if let Some(ref regex) = function_regex {
                    let matches_name = regex.is_match(&func.name);
                    let matches_demangled = func
                        .metadata
                        .as_ref()
                        .and_then(|m| m.demangled_name.as_ref())
                        .is_some_and(|d| regex.is_match(d));
                    if !matches_name && !matches_demangled {
                        continue;
                    }
                }

                // Apply percent filters
                if args.unimplemented && func.fuzzy_match_percent != 0.0 {
                    continue;
                }
                if let Some(min) = args.min_percent
                    && func.fuzzy_match_percent < min
                {
                    continue;
                }
                if let Some(max) = args.max_percent
                    && func.fuzzy_match_percent > max
                {
                    continue;
                }

                // Apply size filters
                if let Some(min) = args.min_size
                    && func.size < min
                {
                    continue;
                }
                if let Some(max) = args.max_size
                    && func.size > max
                {
                    continue;
                }

                items.push(QueryItem {
                    unit: unit.name.clone(),
                    name: func.name.clone(),
                    demangled_name: func.metadata.as_ref().and_then(|m| m.demangled_name.clone()),
                    size: func.size,
                    fuzzy_match_percent: func.fuzzy_match_percent,
                    address: func.address,
                });
            }
        } else {
            // Output unit-level data (treat each unit as a single item)
            // For unit-level, use measures to get aggregate stats
            let measures = unit.measures.unwrap_or_default();
            let match_percent = measures.fuzzy_match_percent;
            let total_size = measures.total_code;

            // Apply percent filters at unit level
            if args.unimplemented && match_percent != 0.0 {
                continue;
            }
            if let Some(min) = args.min_percent
                && match_percent < min
            {
                continue;
            }
            if let Some(max) = args.max_percent
                && match_percent > max
            {
                continue;
            }

            // Apply size filters at unit level
            if let Some(min) = args.min_size
                && total_size < min
            {
                continue;
            }
            if let Some(max) = args.max_size
                && total_size > max
            {
                continue;
            }

            items.push(QueryItem {
                unit: unit.name.clone(),
                name: unit.name.clone(),
                demangled_name: None,
                size: total_size,
                fuzzy_match_percent: match_percent,
                address: None,
            });
        }
    }

    let total_matched = items.len();

    // Sort results
    items.sort_by(|a, b| {
        let cmp = match sort_field {
            SortField::Name => a.name.cmp(&b.name),
            SortField::Size => a.size.cmp(&b.size),
            SortField::MatchPercent => a
                .fuzzy_match_percent
                .partial_cmp(&b.fuzzy_match_percent)
                .unwrap_or(std::cmp::Ordering::Equal),
        };
        match sort_order {
            SortOrder::Asc => cmp,
            SortOrder::Desc => cmp.reverse(),
        }
    });

    // Apply limit
    if let Some(limit) = args.limit {
        items.truncate(limit);
    }

    let total_filtered = items.len();

    // Build result
    let result = QueryResult {
        query: QueryInfo {
            filters: QueryFilters {
                unit: args.unit.clone(),
                function: args.function.clone(),
                min_percent: args.min_percent,
                max_percent: args.max_percent,
                unimplemented: args.unimplemented,
                min_size: args.min_size,
                max_size: args.max_size,
            },
            sort_by: args.sort_by.clone(),
            sort_order: args.sort_order.clone(),
            limit: args.limit,
            output_mode: output_mode.to_string(),
        },
        summary: QuerySummary { total_matched, total_filtered },
        results: if args.summary { Vec::new() } else { items },
    };

    // Write output
    write_query_output(&result, args.output.as_deref(), output_format)?;

    Ok(())
}

fn render_query_csv(result: &QueryResult) -> String {
    let mut csv = String::new();
    // Header
    csv.push_str("unit,name,demangled_name,size,fuzzy_match_percent,address\n");
    // Rows
    for item in &result.results {
        let demangled = item.demangled_name.as_deref().unwrap_or("");
        let address = item.address.map(|a| format!("{:#x}", a)).unwrap_or_default();
        // Escape fields that might contain commas or quotes
        let escaped_name = escape_csv_field(&item.name);
        let escaped_demangled = escape_csv_field(demangled);
        csv.push_str(&format!(
            "{},{},{},{},{:.1},{}\n",
            escape_csv_field(&item.unit),
            escaped_name,
            escaped_demangled,
            item.size,
            item.fuzzy_match_percent,
            address
        ));
    }
    csv
}

fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn write_query_output(
    result: &QueryResult,
    output: Option<&Utf8PlatformPath>,
    format: QueryOutputFormat,
) -> Result<()> {
    let write_content = |writer: &mut dyn Write| -> Result<()> {
        match format {
            QueryOutputFormat::Json => {
                serde_json::to_writer(writer, result).context("Failed to write output file")?;
            }
            QueryOutputFormat::JsonPretty => {
                serde_json::to_writer_pretty(writer, result)
                    .context("Failed to write output file")?;
            }
            QueryOutputFormat::Csv => {
                let csv = render_query_csv(result);
                writer.write_all(csv.as_bytes()).context("Failed to write CSV output")?;
            }
        }
        Ok(())
    };

    match output {
        Some(path) if path != Utf8PlatformPath::new("-") => {
            info!("Writing to {}", path);
            let file = File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .with_context(|| format!("Failed to create file {}", path))?;
            let mut writer = BufWriter::new(file);
            write_content(&mut writer)?;
            writer.flush().context("Failed to flush output file")?;
        }
        _ => {
            let mut stdout = std::io::stdout();
            write_content(&mut stdout)?;
        }
    }
    Ok(())
}

// Function lookup output structures
#[derive(Serialize)]
struct FunctionResult {
    found: bool,
    query: String,
    matches: Vec<FunctionMatch>,
}

#[derive(Serialize)]
struct FunctionMatch {
    unit: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    demangled_name: Option<String>,
    size: u64,
    fuzzy_match_percent: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<u64>,
}

/// Detects if a symbol name is a mangled C++ name.
/// Mangled names typically start with:
/// - `?` for Microsoft Visual C++ (e.g., `?StaticClassName@...` or `??0StorePanel@@QAA@XZ`)
/// - `_Z` for GCC/Clang (e.g., `_ZN4MyClass5methodEv`)
fn is_mangled_name(name: &str) -> bool {
    (name.starts_with('?') && name.len() > 1) || name.starts_with("_Z")
}

fn function(args: FunctionArgs) -> Result<()> {
    let output_format = QueryOutputFormat::from_option(args.format.as_deref())?;

    // Load the report
    let report = read_report(&args.report)?;

    // Compile the pattern (regex or exact match)
    // Auto-detect and escape mangled names to allow piping from query results
    let pattern = if args.exact {
        regex::escape(&args.function_name)
    } else if is_mangled_name(&args.function_name) {
        // Mangled names contain regex special characters, so escape them
        regex::escape(&args.function_name)
    } else {
        args.function_name.clone()
    };
    let regex =
        Regex::new(&pattern).with_context(|| format!("Invalid function pattern: {}", pattern))?;

    // Search for matching functions
    let mut matches: Vec<FunctionMatch> = Vec::new();

    for unit in &report.units {
        for func in &unit.functions {
            // Check if the regex matches either the mangled name or demangled name
            let matches_name = regex.is_match(&func.name);
            let matches_demangled = func
                .metadata
                .as_ref()
                .and_then(|m| m.demangled_name.as_ref())
                .is_some_and(|d| regex.is_match(d));

            if matches_name || matches_demangled {
                matches.push(FunctionMatch {
                    unit: unit.name.clone(),
                    name: func.name.clone(),
                    demangled_name: func.metadata.as_ref().and_then(|m| m.demangled_name.clone()),
                    size: func.size,
                    fuzzy_match_percent: func.fuzzy_match_percent,
                    address: func.metadata.as_ref().and_then(|m| m.virtual_address),
                });
            }
        }
    }

    // Build result
    let result =
        FunctionResult { found: !matches.is_empty(), query: args.function_name.clone(), matches };

    // Write output
    write_function_output(&result, args.output.as_deref(), output_format)?;

    Ok(())
}

fn render_function_csv(result: &FunctionResult) -> String {
    let mut csv = String::new();
    // Header
    csv.push_str("unit,name,demangled_name,size,fuzzy_match_percent,address\n");
    // Rows
    for m in &result.matches {
        let demangled = m.demangled_name.as_deref().unwrap_or("");
        let address = m.address.map(|a| format!("{:#x}", a)).unwrap_or_default();
        csv.push_str(&format!(
            "{},{},{},{},{:.1},{}\n",
            escape_csv_field(&m.unit),
            escape_csv_field(&m.name),
            escape_csv_field(demangled),
            m.size,
            m.fuzzy_match_percent,
            address
        ));
    }
    csv
}

fn write_function_output(
    result: &FunctionResult,
    output: Option<&Utf8PlatformPath>,
    format: QueryOutputFormat,
) -> Result<()> {
    let write_content = |writer: &mut dyn Write| -> Result<()> {
        match format {
            QueryOutputFormat::Json => {
                serde_json::to_writer(writer, result).context("Failed to write output file")?;
            }
            QueryOutputFormat::JsonPretty => {
                serde_json::to_writer_pretty(writer, result)
                    .context("Failed to write output file")?;
            }
            QueryOutputFormat::Csv => {
                let csv = render_function_csv(result);
                writer.write_all(csv.as_bytes()).context("Failed to write CSV output")?;
            }
        }
        Ok(())
    };

    match output {
        Some(path) if path != Utf8PlatformPath::new("-") => {
            info!("Writing to {}", path);
            let file = File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .with_context(|| format!("Failed to create file {}", path))?;
            let mut writer = BufWriter::new(file);
            write_content(&mut writer)?;
            writer.flush().context("Failed to flush output file")?;
        }
        _ => {
            let mut stdout = std::io::stdout();
            write_content(&mut stdout)?;
        }
    }
    Ok(())
}

// =============================================================================
// Analyze command types and implementation
// =============================================================================

use crate::cmd::analysis::VerdictClassification;

/// Output structure for the analyze command.
#[derive(Serialize)]
struct AnalyzeOutput {
    query: AnalyzeQuery,
    summary: AnalyzeSummary,
    results: AnalyzeResults,
}

/// Query parameters used for the analyze command.
#[derive(Serialize)]
struct AnalyzeQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    min_percent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_percent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
}

/// Summary statistics for the analyze command.
#[derive(Serialize)]
struct AnalyzeSummary {
    total_analyzed: usize,
    by_verdict: HashMap<String, usize>,
}

/// Results grouped by verdict classification.
#[derive(Serialize)]
struct AnalyzeResults {
    #[serde(rename = "LIKELY_FIXABLE")]
    likely_fixable: Vec<AnalyzedFunction>,
    #[serde(rename = "MAYBE_FIXABLE")]
    maybe_fixable: Vec<AnalyzedFunction>,
    #[serde(rename = "AT_LIMIT")]
    at_limit: Vec<AnalyzedFunction>,
    #[serde(rename = "NEEDS_INVESTIGATION")]
    needs_investigation: Vec<AnalyzedFunction>,
}

/// A single analyzed function with triage-focused information.
#[derive(Serialize)]
struct AnalyzedFunction {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    demangled: Option<String>,
    unit: String,
    fuzzy_match_percent: f32,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    primary_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestion: Option<String>,
}

fn analyze(args: AnalyzeArgs) -> Result<()> {
    let output_format = QueryOutputFormat::from_option(args.format.as_deref())?;

    // Load report
    let report = read_report(&args.report)?;

    // Load project config
    let project_dir = args.project.as_deref().unwrap_or_else(|| Utf8PlatformPath::new("."));
    let (project_config, project_config_info) =
        objdiff_core::config::try_project_config(project_dir.as_ref())
            .ok_or_else(|| anyhow::anyhow!("Project config not found in {}", project_dir))?;
    let project_config = project_config.with_context(|| {
        format!("Reading project config {}", project_config_info.path.display())
    })?;

    // Build object configs (unit name -> ObjectConfig)
    let target_obj_dir =
        project_config.target_dir.as_ref().map(|p| project_dir.join(p.with_platform_encoding()));
    let base_obj_dir =
        project_config.base_dir.as_ref().map(|p| project_dir.join(p.with_platform_encoding()));
    let units = project_config.units.as_deref().unwrap_or_default();

    let object_configs: HashMap<String, (ObjectConfig, usize)> = units
        .iter()
        .enumerate()
        .map(|(idx, o)| {
            let config = ObjectConfig::new(
                o,
                project_dir,
                target_obj_dir.as_deref(),
                base_obj_dir.as_deref(),
            );
            (config.name.clone(), (config, idx))
        })
        .collect();

    // Filter functions from report
    let mut candidates: Vec<(&ReportUnit, &ReportItem)> = Vec::new();
    for unit in &report.units {
        for func in &unit.functions {
            // Skip 100% matches (nothing to analyze)
            if func.fuzzy_match_percent >= 100.0 {
                continue;
            }

            // Apply percent filters
            if let Some(min) = args.min_percent
                && func.fuzzy_match_percent < min
            {
                continue;
            }
            if let Some(max) = args.max_percent
                && func.fuzzy_match_percent > max
            {
                continue;
            }

            candidates.push((unit, func));
        }
    }

    // Sort by match percent descending (analyze best candidates first)
    candidates.sort_by(|a, b| {
        b.1.fuzzy_match_percent
            .partial_cmp(&a.1.fuzzy_match_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Apply limit
    if let Some(limit) = args.limit {
        candidates.truncate(limit);
    }

    let total_to_analyze = candidates.len();
    info!("Analyzing {} functions", total_to_analyze);

    // Group by unit for efficient loading
    let mut by_unit: HashMap<&str, Vec<(&ReportUnit, &ReportItem)>> = HashMap::new();
    for (unit, func) in &candidates {
        by_unit.entry(unit.name.as_str()).or_default().push((*unit, *func));
    }

    // Load map file for ICF symbol equivalences
    let mapping_config = if let Some(map_file) = &project_config.map_file {
        let map_path = project_dir.join(map_file.with_platform_encoding());
        let file = std::fs::File::open(map_path.as_str())
            .with_context(|| format!("Failed to open map file: {}", map_path))?;
        let reader = std::io::BufReader::new(file);
        let equivalences = objdiff_core::obj::map_file::parse_msvc_map(reader);
        info!("Loaded {} ICF equivalence entries from {}", equivalences.len(), map_path);
        diff::MappingConfig { symbol_equivalences: equivalences, ..Default::default() }
    } else {
        diff::MappingConfig::default()
    };

    // Process each unit
    let mut results = AnalyzeResults {
        likely_fixable: Vec::new(),
        maybe_fixable: Vec::new(),
        at_limit: Vec::new(),
        needs_investigation: Vec::new(),
    };
    let mut verdict_counts: HashMap<String, usize> = HashMap::new();

    for (unit_name, functions) in by_unit {
        // Find object config
        let Some((object_config, unit_idx)) = object_configs.get(unit_name) else {
            warn!("Unit not found in project: {}", unit_name);
            continue;
        };

        // Build diff config with unit options
        let unit_options = units.get(*unit_idx).and_then(|u| u.options());
        let diff_config = build_unit_diff_config(
            &diff::DiffObjConfig::default(),
            project_config.options.as_ref(),
            unit_options,
            &args.config,
        )?;

        // Load objects
        let target_obj = object_config
            .target_path
            .as_ref()
            .map(|p| {
                obj::read::read(p.as_ref(), &diff_config, diff::DiffSide::Target)
                    .with_context(|| format!("Failed to read target object: {}", p))
            })
            .transpose()?;
        let base_obj = object_config
            .base_path
            .as_ref()
            .map(|p| {
                obj::read::read(p.as_ref(), &diff_config, diff::DiffSide::Base)
                    .with_context(|| format!("Failed to read base object: {}", p))
            })
            .transpose()?;

        // Run diff once for the unit
        let diff_result = diff::diff_objs(
            target_obj.as_ref(),
            base_obj.as_ref(),
            None,
            &diff_config,
            &mapping_config,
        )?;

        // Analyze each function
        for (_unit, func) in functions {
            let result = super::diff::analyze_symbol(
                target_obj.as_ref(),
                base_obj.as_ref(),
                &diff_result,
                &func.name,
                &diff_config,
            )?;

            let Some(result) = result else {
                warn!("Symbol not found in objects: {} (unit: {})", func.name, unit_name);
                continue;
            };

            // Record verdict
            let classification = result.verdict.classification;
            *verdict_counts.entry(format!("{:?}", classification)).or_insert(0) += 1;

            // Build output item
            let analyzed = AnalyzedFunction {
                name: func.name.clone(),
                demangled: func.metadata.as_ref().and_then(|m| m.demangled_name.clone()),
                unit: unit_name.to_string(),
                fuzzy_match_percent: func.fuzzy_match_percent,
                size: func.size,
                primary_pattern: result
                    .analysis
                    .patterns
                    .first()
                    .map(|p| p.pattern.as_str().to_string()),
                suggestion: result.verdict.suggestions.first().map(|s| s.action.clone()),
            };

            // Add to appropriate bucket
            match classification {
                VerdictClassification::LikelyFixable => results.likely_fixable.push(analyzed),
                VerdictClassification::MaybeFixable => results.maybe_fixable.push(analyzed),
                VerdictClassification::AtLimit => results.at_limit.push(analyzed),
                VerdictClassification::NeedsInvestigation => {
                    results.needs_investigation.push(analyzed)
                }
                VerdictClassification::Complete => {} // Should not happen (filtered out)
                VerdictClassification::Stub => {} // Unimplemented, skip
            }
        }
    }

    // Build output
    let output = AnalyzeOutput {
        query: AnalyzeQuery {
            min_percent: args.min_percent,
            max_percent: args.max_percent,
            limit: args.limit,
        },
        summary: AnalyzeSummary { total_analyzed: total_to_analyze, by_verdict: verdict_counts },
        results,
    };

    // Write output
    write_analyze_output(&output, args.output.as_deref(), output_format)?;

    Ok(())
}

fn render_analyze_csv(output: &AnalyzeOutput) -> String {
    let mut csv = String::new();
    // Header
    csv.push_str(
        "verdict,name,demangled,unit,fuzzy_match_percent,size,primary_pattern,suggestion\n",
    );

    // Helper to write functions for a verdict category
    let write_functions = |csv: &mut String, verdict: &str, funcs: &[AnalyzedFunction]| {
        for f in funcs {
            let demangled = f.demangled.as_deref().unwrap_or("");
            let pattern = f.primary_pattern.as_deref().unwrap_or("");
            let suggestion = f.suggestion.as_deref().unwrap_or("");
            csv.push_str(&format!(
                "{},{},{},{},{:.1},{},{},{}\n",
                verdict,
                escape_csv_field(&f.name),
                escape_csv_field(demangled),
                escape_csv_field(&f.unit),
                f.fuzzy_match_percent,
                f.size,
                escape_csv_field(pattern),
                escape_csv_field(suggestion)
            ));
        }
    };

    write_functions(&mut csv, "LIKELY_FIXABLE", &output.results.likely_fixable);
    write_functions(&mut csv, "MAYBE_FIXABLE", &output.results.maybe_fixable);
    write_functions(&mut csv, "AT_LIMIT", &output.results.at_limit);
    write_functions(&mut csv, "NEEDS_INVESTIGATION", &output.results.needs_investigation);

    csv
}

fn write_analyze_output(
    output: &AnalyzeOutput,
    path: Option<&Utf8PlatformPath>,
    format: QueryOutputFormat,
) -> Result<()> {
    let write_content = |writer: &mut dyn Write| -> Result<()> {
        match format {
            QueryOutputFormat::Json => {
                serde_json::to_writer(writer, output).context("Failed to write JSON output")?;
            }
            QueryOutputFormat::JsonPretty => {
                serde_json::to_writer_pretty(writer, output)
                    .context("Failed to write JSON output")?;
            }
            QueryOutputFormat::Csv => {
                let csv = render_analyze_csv(output);
                writer.write_all(csv.as_bytes()).context("Failed to write CSV output")?;
            }
        }
        Ok(())
    };

    match path {
        Some(p) if p != Utf8PlatformPath::new("-") => {
            info!("Writing to {}", p);
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
            let mut stdout = std::io::stdout();
            write_content(&mut stdout)?;
            if matches!(format, QueryOutputFormat::Json | QueryOutputFormat::JsonPretty) {
                println!(); // Add newline after JSON
            }
        }
    }
    Ok(())
}

// =============================================================================
// Trending command types and implementation
// =============================================================================

/// Output structure for the trending command.
#[derive(Serialize)]
struct TrendingOutput {
    report_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    reports: Vec<TrendingReportEntry>,
    summary: TrendingSummary,
}

/// A single report entry in the trending output.
#[derive(Serialize)]
struct TrendingReportEntry {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtime: Option<String>,
    fuzzy_match_percent: f32,
    matched_code_percent: f32,
    matched_functions: u32,
    total_functions: u32,
    matched_code: u64,
    total_code: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    delta_fuzzy: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delta_functions: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delta_code: Option<i64>,
}

/// Summary statistics across all reports.
#[derive(Serialize)]
struct TrendingSummary {
    first_fuzzy_match_percent: f32,
    last_fuzzy_match_percent: f32,
    total_delta_fuzzy: f32,
    first_matched_functions: u32,
    last_matched_functions: u32,
    total_delta_functions: i32,
    first_matched_code: u64,
    last_matched_code: u64,
    total_delta_code: i64,
    trend: String, // "improving", "declining", "stable"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrendingOutputFormat {
    Json,
    JsonPretty,
    Text,
}

impl TrendingOutputFormat {
    fn from_option(s: Option<&str>) -> Result<Self> {
        match s {
            None | Some("json") => Ok(Self::Json),
            Some("json-pretty") | Some("json_pretty") => Ok(Self::JsonPretty),
            Some("text") => Ok(Self::Text),
            Some(other) => {
                bail!("Invalid output format: {}. Supported: json, json-pretty, text", other)
            }
        }
    }
}

fn trending(args: TrendingArgs) -> Result<()> {
    if args.reports.is_empty() {
        bail!("At least one report file is required");
    }

    let output_format = TrendingOutputFormat::from_option(args.format.as_deref())?;

    // Load reports with optional mtime
    let mut report_data: Vec<(Utf8PlatformPathBuf, Option<std::time::SystemTime>, Report)> =
        Vec::new();

    for path in &args.reports {
        let report = read_report(path)?;
        let mtime = if args.by_mtime {
            std::fs::metadata(path.as_path()).ok().and_then(|m| m.modified().ok())
        } else {
            None
        };
        report_data.push((path.clone(), mtime, report));
    }

    // Sort by mtime if requested
    if args.by_mtime {
        report_data.sort_by(|a, b| a.1.cmp(&b.1));
    }

    // Apply limit (default 30)
    let limit = args.limit.unwrap_or(30);
    if report_data.len() > limit {
        // Keep the most recent reports (last N after sorting)
        let start = report_data.len() - limit;
        report_data = report_data.split_off(start);
    }

    // Build output entries
    let mut entries: Vec<TrendingReportEntry> = Vec::new();
    let mut prev_fuzzy: Option<f32> = None;
    let mut prev_functions: Option<u32> = None;
    let mut prev_code: Option<u64> = None;

    for (path, mtime, report) in &report_data {
        let measures = if let Some(category_id) = &args.category {
            report
                .categories
                .iter()
                .find(|c| &c.id == category_id)
                .and_then(|c| c.measures.as_ref())
                .with_context(|| {
                    format!("Category '{}' not found in report {}", category_id, path)
                })?
        } else {
            report.measures.as_ref().with_context(|| format!("Report {} has no measures", path))?
        };

        let mtime_str = mtime.and_then(|t| {
            let offset_datetime = time::OffsetDateTime::from(t);
            let format =
                time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second]")
                    .ok()?;
            offset_datetime.format(&format).ok()
        });

        let delta_fuzzy = prev_fuzzy.map(|p| measures.fuzzy_match_percent - p);
        let delta_functions = prev_functions.map(|p| measures.matched_functions as i32 - p as i32);
        let delta_code = prev_code.map(|p| measures.matched_code as i64 - p as i64);

        entries.push(TrendingReportEntry {
            path: path.to_string(),
            mtime: mtime_str,
            fuzzy_match_percent: measures.fuzzy_match_percent,
            matched_code_percent: measures.matched_code_percent,
            matched_functions: measures.matched_functions,
            total_functions: measures.total_functions,
            matched_code: measures.matched_code,
            total_code: measures.total_code,
            delta_fuzzy,
            delta_functions,
            delta_code,
        });

        prev_fuzzy = Some(measures.fuzzy_match_percent);
        prev_functions = Some(measures.matched_functions);
        prev_code = Some(measures.matched_code);
    }

    // Calculate summary (extract values before moving entries)
    if entries.is_empty() {
        bail!("No reports loaded");
    }

    let first_fuzzy = entries.first().unwrap().fuzzy_match_percent;
    let first_functions = entries.first().unwrap().matched_functions;
    let first_code = entries.first().unwrap().matched_code;
    let last_fuzzy = entries.last().unwrap().fuzzy_match_percent;
    let last_functions = entries.last().unwrap().matched_functions;
    let last_code = entries.last().unwrap().matched_code;

    let total_delta_fuzzy = last_fuzzy - first_fuzzy;
    let total_delta_functions = last_functions as i32 - first_functions as i32;
    let total_delta_code = last_code as i64 - first_code as i64;

    let trend = if total_delta_fuzzy > 0.1 {
        "improving"
    } else if total_delta_fuzzy < -0.1 {
        "declining"
    } else {
        "stable"
    };

    let report_count = entries.len();

    let output = TrendingOutput {
        report_count,
        category: args.category.clone(),
        reports: entries,
        summary: TrendingSummary {
            first_fuzzy_match_percent: first_fuzzy,
            last_fuzzy_match_percent: last_fuzzy,
            total_delta_fuzzy,
            first_matched_functions: first_functions,
            last_matched_functions: last_functions,
            total_delta_functions,
            first_matched_code: first_code,
            last_matched_code: last_code,
            total_delta_code,
            trend: trend.to_string(),
        },
    };

    write_trending_output(&output, args.output.as_deref(), output_format)?;
    Ok(())
}

fn render_trending_text(output: &TrendingOutput) -> String {
    let mut text = String::new();

    // Header
    if let Some(cat) = &output.category {
        text.push_str(&format!("Progress Trend (category: {})\n", cat));
    } else {
        text.push_str("Progress Trend\n");
    }
    text.push_str(&"=".repeat(60));
    text.push('\n');
    text.push('\n');

    // Report entries
    for (i, entry) in output.reports.iter().enumerate() {
        let label = if i == 0 {
            "First"
        } else if i == output.reports.len() - 1 {
            "Last"
        } else {
            ""
        };

        // Extract just the filename for display
        let filename = entry.path.rsplit('/').next().unwrap_or(&entry.path);

        text.push_str(&format!("{:5} {:40} {:6.2}%", label, filename, entry.fuzzy_match_percent));

        if let Some(delta) = entry.delta_fuzzy {
            let sign = if delta >= 0.0 { "+" } else { "" };
            text.push_str(&format!("  ({}{:.2}%)", sign, delta));
        }
        text.push('\n');

        text.push_str(&format!(
            "      Functions: {}/{} ({:.1}%)  Code: {}/{} bytes\n",
            entry.matched_functions,
            entry.total_functions,
            if entry.total_functions > 0 {
                entry.matched_functions as f32 / entry.total_functions as f32 * 100.0
            } else {
                0.0
            },
            entry.matched_code,
            entry.total_code
        ));

        if let Some(mtime) = &entry.mtime {
            text.push_str(&format!("      Modified: {}\n", mtime));
        }
        text.push('\n');
    }

    // Summary
    text.push_str(&"-".repeat(60));
    text.push('\n');
    text.push_str("Summary:\n");

    let trend_arrow = match output.summary.trend.as_str() {
        "improving" => "^",
        "declining" => "v",
        _ => "-",
    };

    let sign = if output.summary.total_delta_fuzzy >= 0.0 { "+" } else { "" };
    text.push_str(&format!(
        "  Fuzzy match: {:.2}% -> {:.2}%  ({}{:.2}%) {}\n",
        output.summary.first_fuzzy_match_percent,
        output.summary.last_fuzzy_match_percent,
        sign,
        output.summary.total_delta_fuzzy,
        trend_arrow
    ));

    let func_sign = if output.summary.total_delta_functions >= 0 { "+" } else { "" };
    text.push_str(&format!(
        "  Functions:   {} -> {}  ({}{})\n",
        output.summary.first_matched_functions,
        output.summary.last_matched_functions,
        func_sign,
        output.summary.total_delta_functions
    ));

    let code_sign = if output.summary.total_delta_code >= 0 { "+" } else { "" };
    text.push_str(&format!(
        "  Matched code: {} -> {} bytes  ({}{} bytes)\n",
        output.summary.first_matched_code,
        output.summary.last_matched_code,
        code_sign,
        output.summary.total_delta_code
    ));

    text.push_str(&format!("  Trend: {}\n", output.summary.trend.to_uppercase()));

    text
}

fn write_trending_output(
    output: &TrendingOutput,
    path: Option<&Utf8PlatformPath>,
    format: TrendingOutputFormat,
) -> Result<()> {
    let write_content = |writer: &mut dyn Write| -> Result<()> {
        match format {
            TrendingOutputFormat::Json => {
                serde_json::to_writer(writer, output).context("Failed to write JSON output")?;
            }
            TrendingOutputFormat::JsonPretty => {
                serde_json::to_writer_pretty(writer, output)
                    .context("Failed to write JSON output")?;
            }
            TrendingOutputFormat::Text => {
                let text = render_trending_text(output);
                writer.write_all(text.as_bytes()).context("Failed to write text output")?;
            }
        }
        Ok(())
    };

    match path {
        Some(p) if p != Utf8PlatformPath::new("-") => {
            info!("Writing to {}", p);
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
            let mut stdout = std::io::stdout();
            write_content(&mut stdout)?;
            if matches!(format, TrendingOutputFormat::Json | TrendingOutputFormat::JsonPretty) {
                println!(); // Add newline after JSON
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_mangled_name_msvc() {
        // Microsoft mangled names start with ? (single or double)
        assert!(is_mangled_name("??0StorePanel@@QAA@XZ"));
        assert!(is_mangled_name("??1MyClass@@QAE@XZ"));
        assert!(is_mangled_name("??4MyClass@@QAEAAV0@ABV0@@Z"));
        assert!(is_mangled_name("?StaticClassName@HamStorePanel@@SA?AVSymbol@@XZ"));
        assert!(is_mangled_name("?NewObject@HamStorePanel@@SAPAVObject@Hmx@@XZ"));
    }

    #[test]
    fn test_is_mangled_name_gcc() {
        // GCC/Clang mangled names start with _Z
        assert!(is_mangled_name("_ZN4MyClass5methodEv"));
        assert!(is_mangled_name("_ZN3std5printEv"));
        assert!(is_mangled_name("_ZNK3std6vectorIiE3atEm"));
    }

    #[test]
    fn test_is_mangled_name_regular() {
        // Regular demangled names should not be detected as mangled
        assert!(!is_mangled_name("MyClass::method()"));
        assert!(!is_mangled_name("std::vector<int>::at"));
        assert!(!is_mangled_name("main"));
        assert!(!is_mangled_name("foo_bar_baz"));
        assert!(!is_mangled_name("StorePanel::StorePanel()"));
    }

    #[test]
    fn test_is_mangled_name_edge_cases() {
        // Edge cases
        assert!(!is_mangled_name(""));
        assert!(!is_mangled_name("?")); // Single ? alone is not mangled
        assert!(is_mangled_name("?A")); // But ?X (2+ chars) is mangled
        assert!(is_mangled_name("?foo"));
        assert!(!is_mangled_name("_"));
        assert!(!is_mangled_name("_foo")); // _foo alone is not mangled
        assert!(is_mangled_name("??"));
        assert!(is_mangled_name("_Z"));
    }
}
