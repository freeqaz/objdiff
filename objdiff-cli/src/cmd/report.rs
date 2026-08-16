use std::{
    collections::{BTreeMap, HashMap, HashSet},
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
        Report, ReportCategory, ReportItem, ReportItemMetadata, ReportProvenance, ReportUnit,
        ReportUnitMetadata,
    },
    config::{
        ProjectObject, ProjectOptions, apply_project_options,
        path::platform_path,
    },
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

/// The identity of the objdiff-cli binary doing the diffing, in the report-cache
/// key and in the report's provenance. See [`crate::build_id`] for why the hash
/// of the executable and not the version or the git commit, and for the two
/// 2026-08-12 measurements that were taken without it.
///
/// It also replaces the hand-maintained `CACHE_LOGIC_VERSION` counter this file
/// used to carry, which asked an author changing diff semantics anywhere in
/// objdiff-core to remember to bump a constant in objdiff-cli. Bumped three
/// times, missed at least once (4c38c31 / f2424d6 changed
/// `FunctionRelocDiffs::NameCheck` and never opened this file), and that miss is
/// the +71 complete functions an A/B measured as zero.
fn tool_binary_hash() -> Option<&'static str> { crate::build_id::binary_hash() }

/// May this run serve or write report-cache entries?
///
/// Three independent refusals, and the middle one is the reason this is a named
/// function with a test rather than an expression inlined at the call site.
///
/// * `no_cache` — the user asked.
/// * `deduplicate` — the cache and `-d` are INCOMPATIBLE, in both directions,
///   because a cached unit is a post-dedup unit while the cache key is per-unit
///   and knows nothing about the units before it. Measured on the build just
///   before this rule landed (objdiff `f9333e6`, i.e. `345778c^`), dc3-decomp,
///   one `-o` shared across three consecutive runs: `-d` on a cold cache
///   reported 48,325 functions, and the *default-mode* run that followed it
///   reported 48,325 as well — the deduplicated number, from 2,224 cache hits,
///   for a mode that deduplicates nothing. The correct default-mode answer on
///   that tree is 48,344. So the failure is not confined to `-d`: one `-d` run
///   silently reduces every later default-mode run through the same `-o`, which
///   is exactly how a progress number moves with no source change behind it.
/// * `binary_hash_available` — an entry that cannot name the binary that
///   produced it is not safe to serve.
fn report_cache_enabled(no_cache: bool, deduplicate: bool, binary_hash_available: bool) -> bool {
    !no_cache && !deduplicate && binary_hash_available
}

/// Render an effective [`diff::DiffObjConfig`] as canonically-ordered
/// `key=value` lines: the ruler, spelled out.
///
/// Every property objdiff knows about, in `ConfigPropertyId::variants()` order,
/// which is generated from config-schema.json and therefore stable within a
/// build. Two uses, and they want the same thing:
///   * the report-cache key, where hashing the RESOLVED config rather than the
///     inputs that produced it (`-c` args plus the `options` blocks) also covers
///     a change to the report's own `base_diff_config` fallback -- an input that
///     was previously invisible to the key;
///   * `ReportProvenance::diff_config`, so a banked report says which ruler
///     produced it instead of leaving the reader to guess from a filename.
fn render_diff_config(config: &diff::DiffObjConfig) -> Vec<String> {
    use objdiff_core::diff::{ConfigEnum, ConfigPropertyId};
    ConfigPropertyId::variants()
        .iter()
        .map(|id| format!("{}={}", id.as_str(), config.get_property_value(*id)))
        .collect()
}

/// The inputs shared by every unit in a report: the instrument, and the alias
/// map. Neither is per-unit, and neither was in the cache key before
/// 2026-08-12 -- see [`tool_binary_hash`] for the binary, and the `map_file`
/// handling in [`generate`] for the map.
struct GlobalCacheKey {
    /// `None` disables the cache: we could not identify the binary, so we cannot
    /// promise a cached unit came from this one.
    tool_binary_hash: Option<&'static str>,
    /// xxHash3-64 of the map file's bytes, or 0 when the project has no map.
    map_file_hash: u64,
}

/// Content-hash based cache for report units. Avoids re-diffing unchanged .obj files.
/// Cache format: u32 entry count, then for each entry: u64 hash, u32 data_len, data bytes.
struct ReportCache {
    entries: HashMap<u64, Vec<u8>>,
    path: PathBuf,
    hits: std::sync::atomic::AtomicU32,
    misses: std::sync::atomic::AtomicU32,
    /// When false, `get` always misses and nothing is written back. Set when the
    /// binary could not be hashed (we cannot key honestly), when `--no-cache` was
    /// passed, or under `--deduplicate` (see [`generate`]).
    enabled: bool,
}

impl ReportCache {
    /// A disabled cache reads nothing, never hits, and writes nothing back. It is
    /// not the same as an empty one: an empty cache would still be SAVED at the
    /// end of the run, leaving a sidecar whose provenance we could not vouch for.
    fn load(path: PathBuf, enabled: bool) -> Self {
        let mut entries = HashMap::new();
        if let Ok(data) = if enabled { std::fs::read(&path) } else { Ok(Vec::new()) }
            && data.len() >= 4
        {
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
        ReportCache {
            entries,
            path,
            hits: std::sync::atomic::AtomicU32::new(0),
            misses: std::sync::atomic::AtomicU32::new(0),
            enabled,
        }
    }

    fn get(&self, hash: u64) -> Option<ReportUnit> {
        if !self.enabled {
            self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        if let Some(data) = self.entries.get(&hash)
            && let Ok(unit) = ReportUnit::decode(data.as_slice())
        {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Some(unit);
        }
        self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        None
    }

    fn save(&self, new_entries: &HashMap<u64, Vec<u8>>) {
        // A disabled cache writes nothing. Writing would leave a sidecar seeded by a
        // run whose key we could not vouch for (`--deduplicate`, or an unidentifiable
        // binary), which the NEXT run would then serve from.
        if !self.enabled {
            return;
        }
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

    /// Hash everything that can change what a cached [`ReportUnit`] would say:
    ///
    ///  1. the unit's target and base .obj bytes;
    ///  2. the RESOLVED effective [`diff::DiffObjConfig`] for this unit, spelled out
    ///     property by property (see [`render_diff_config`]) — this covers `-c`
    ///     args, the project `options` block, the unit `options` block AND the
    ///     report's own `base_diff_config` fallback, all of which layer into it;
    ///  3. the alias map (`map_file`) that supplies ICF symbol equivalences;
    ///  4. the identity of the objdiff-cli binary doing the diffing.
    ///
    /// (3) and (4) are the 2026-08-12 fix. Neither was in the key before, and both
    /// gaps had fired on the same day:
    ///
    ///   * a lane re-ran into one `-o` after changing only `symbol_aliases.json`
    ///     (and thus the rendered map): 2,224 cache hits and a report byte-identical
    ///     to the baseline, for a map carrying 340 more names. A +143-function
    ///     change measured as +0.
    ///   * an A/B of two objdiff builds sharing one output path returned identical
    ///     numbers in all six project x ruler cells. The real delta was +71 complete
    ///     functions.
    ///
    /// The exposure runs in the worst direction: a cached report cannot show a LOST
    /// function, so a guard reading one always says "intact".
    ///
    /// (4) also replaces the hand-maintained `CACHE_LOGIC_VERSION` counter this
    /// function used to carry, which asked an author changing diff semantics
    /// anywhere in objdiff-core to remember to bump a constant in objdiff-cli. It
    /// was bumped three times and missed at least once (4c38c31 / f2424d6 changed
    /// `FunctionRelocDiffs::NameCheck` and never touched this file), which is the
    /// +71 above. The binary hash subsumes it and cannot be forgotten.
    ///
    /// This DOES invalidate every `.cache` file written before the change, costing
    /// one full re-diff each. The property it gives up — "a project that sets no
    /// options keeps its old key" — is exactly the property that let a stale cache
    /// survive a semantic change, so giving it up is the point rather than a cost.
    fn hash_unit(
        object: &ObjectConfig,
        effective_config: &diff::DiffObjConfig,
        global: &GlobalCacheKey,
    ) -> u64 {
        use xxhash_rust::xxh3::xxh3_64;
        let mut combined = Vec::new();
        if let Some(hash) = global.tool_binary_hash {
            combined.extend_from_slice(hash.as_bytes());
        }
        combined.extend_from_slice(&global.map_file_hash.to_le_bytes());
        if let Some(p) = &object.target_path
            && let Ok(data) = std::fs::read(p.as_str())
        {
            combined.extend_from_slice(&data);
        }
        combined.push(0xFF); // separator
        if let Some(p) = &object.base_path
            && let Ok(data) = std::fs::read(p.as_str())
        {
            combined.extend_from_slice(&data);
        }
        // The resolved config, not the arguments that produced it: two spellings that
        // resolve to the same ruler are the same cache entry, and a change to the
        // report's base fallback is a different one.
        for property in render_diff_config(effective_config) {
            combined.push(0xFE);
            combined.extend_from_slice(property.as_bytes());
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
    /// Configuration property (key=value), e.g. -c functionRelocDiffs=name_only.
    /// Overrides the project's and unit's "options" blocks in objdiff.json, which
    /// are the persistent way to set the same properties. Repeatable.
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
    #[argp(switch)]
    /// Diff every unit fresh: do not read the <output>.cache sidecar and do not
    /// write it back. The cache key covers the obj bytes, the resolved diff config,
    /// the alias map and this binary's own hash, so a hit is sound; use this when
    /// you want that belief measured rather than assumed, or when an input objdiff
    /// cannot see (a compiler wrapper, a generated header) may have moved.
    no_cache: bool,
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
    // ── Report base config. These four differ from the schema defaults in
    // objdiff-core/config-schema.json (which are name_address / false / false / true)
    // and they are the de-facto scoring semantics of every project that has ever run
    // `report generate`: dc3-decomp, rb3-xenon, ChimpsAtSea_Reach, decomp-clones/halo,
    // cea-decomp. Their match percentages are tracked over time against THESE values.
    //
    // So this is a FALLBACK, not a policy: `build_unit_diff_config` layers the
    // project's `options` block, then the unit's `options` block, then `-c key=value`
    // on top, and any of the four can be overridden that way. Do not "fix" these to
    // the schema defaults — a project that sets no options must keep scoring exactly
    // as it does today, or every recorded score in every project is silently invalid.
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

    // Load map file for ICF symbol equivalences.
    //
    // Read to memory first and hash the bytes: the map is an INPUT TO THE SCORE
    // (it supplies the symbol equivalences that decide which target symbol a base
    // symbol may pair with), so it belongs in the report-cache key and in the
    // report's provenance. Hashing costs nothing worth measuring — the file has to
    // be read either way, and xxh3 over the ~1-3 MB of map dc3/rb3-xenon carry is
    // dwarfed by the regex parse that follows, let alone by the diff.
    let mut map_file_hash = 0u64;
    let mut map_file_entries = 0u32;
    let mapping_config = if let Some(map_file) = &project.map_file {
        let map_path = project_dir.join(map_file.with_platform_encoding());
        let data = std::fs::read(map_path.as_str())
            .with_context(|| format!("Failed to open map file: {}", map_path))?;
        map_file_hash = xxhash_rust::xxh3::xxh3_64(&data);
        let equivalences = objdiff_core::obj::map_file::parse_msvc_map(std::io::Cursor::new(&data));
        map_file_entries = equivalences.len() as u32;
        info!("Loaded {} ICF equivalence entries from {}", equivalences.len(), map_path);
        diff::MappingConfig { symbol_equivalences: equivalences, ..Default::default() }
    } else {
        diff::MappingConfig::default()
    };

    // Load content-hash based cache for incremental report generation.
    // Cache key = xxHash3 of this binary's hash + the map file's hash + target/base
    // .obj bytes + the resolved effective diff config (see `ReportCache::hash_unit`).
    let cache_path = args
        .output
        .as_ref()
        .map(|o| {
            let mut p = std::path::PathBuf::from(o.as_str());
            p.set_extension("cache");
            p
        })
        .unwrap_or_else(|| std::path::PathBuf::from(".objdiff_report_cache"));
    let tool_binary_hash = tool_binary_hash();
    // Two separate consequences of one failure, and they are not the same warning.
    //
    // The first is about IDENTITY and is unconditional. `tool_binary_hash` is what
    // the proto calls the authoritative identity of the ruler — the one thing that
    // distinguishes builds `tool_version` and `tool_commit` cannot — and a report
    // written without it carries no such key at all, since proto3 JSON omits the
    // empty string. That is a property of the report, permanent, and true whatever
    // the user asked for the cache. `--no-cache` must not silence it: the two-line
    // repro is an executable that is `chmod 111` (exec works, `fs::read` does not),
    // and before this the whole run said nothing.
    if tool_binary_hash.is_none() {
        warn!(
            "Could not hash the objdiff-cli executable, so this report's provenance will \
             carry no tool_binary_hash. That hash is the authoritative identity of the \
             binary that measured this report -- tool_version and tool_commit cannot tell \
             two builds apart -- so this report cannot be compared with another one by \
             instrument."
        );
    }
    // The second is about the CACHE, and only makes sense when the user did not
    // already turn it off. Under `--no-cache` it would blame a failed hash for the
    // user's own flag, and would put a line about a hash failure in front of every
    // consumer that scrapes this stream on a run where nothing went wrong.
    if tool_binary_hash.is_none() && !args.no_cache {
        warn!(
            "Report cache disabled for this run as a result. A cache entry that cannot name \
             the binary that produced it is not safe to serve. Nothing else changes: every \
             unit is diffed fresh."
        );
    }
    // `--deduplicate` makes a unit's emitted functions depend on every unit diffed
    // before it (`existing_functions` suppresses a repeat of a global/weak symbol),
    // and that history is not — and cannot reasonably be — part of a per-unit key.
    // A cache hit under `-d` also skips the bookkeeping, so it corrupts the units
    // that follow as well. Refuse the cache rather than serve an order-dependent
    // answer from it.
    if args.deduplicate && !args.no_cache {
        warn!("--deduplicate makes each unit depend on the ones before it; report cache disabled");
    }
    let cache_enabled =
        report_cache_enabled(args.no_cache, args.deduplicate, tool_binary_hash.is_some());
    let cache = ReportCache::load(cache_path, cache_enabled);
    let global_cache_key = GlobalCacheKey { tool_binary_hash, map_file_hash };
    let new_cache_entries: Mutex<HashMap<u64, Vec<u8>>> = Mutex::new(HashMap::new());

    let start = Instant::now();
    let mut units = vec![];
    let mut existing_functions: HashSet<String> = HashSet::new();
    if args.deduplicate {
        // If deduplicating, we need to run single-threaded
        for (object, unit_idx) in &objects {
            let unit_options = project_units.get(*unit_idx).and_then(ProjectObject::options);
            let diff_config = build_unit_diff_config(
                &base_diff_config,
                project.options.as_ref(),
                unit_options,
                &args.config,
            )?;
            let hash = ReportCache::hash_unit(object, &diff_config, &global_cache_key);
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
                let unit_options = project_units.get(*unit_idx).and_then(ProjectObject::options);
                // Resolve the config BEFORE the cache lookup: it is part of the key
                // now, because the key hashes the resolved ruler rather than the
                // arguments that produced it. Resolving is a clone plus a handful of
                // property writes — nothing next to reading the two objs.
                let diff_config = build_unit_diff_config(
                    &base_diff_config,
                    project.options.as_ref(),
                    unit_options,
                    &args.config,
                )?;
                let hash = ReportCache::hash_unit(object, &diff_config, &global_cache_key);
                if let Some(cached_unit) = cache.get(hash) {
                    return Ok(Some(cached_unit));
                }
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
    // Announce a report in which nothing was recomputed. This is SOUND — the key
    // now covers the objs, the resolved ruler, the alias map and this binary — so
    // it is not an error and the run is not refused: refusing would refuse the
    // correct no-op, which is the case the cache exists for. But "the numbers did
    // not move" and "nothing was measured" look identical downstream, and a caller
    // that expected its edit to be visible here has learned something. The same
    // counts ride along in the report's provenance, so a consumer does not have to
    // scrape this line.
    if hits > 0 && misses == 0 {
        warn!(
            "Every unit in this report came from the cache at {}; nothing was re-diffed. \
             The key covers the objs, the resolved config, the map file and this binary, \
             so this means those are all unchanged. Pass --no-cache to measure instead.",
            cache.path.display()
        );
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

        // Read each obj under the SAME effective config the per-unit pass used —
        // project options, then that unit's options, then `-c` — not the bare base.
        // Reading with a different config than the unit was diffed with would compare
        // byte signatures derived from differently-decoded instructions.
        let unit_objs: Vec<diff::UnitObjs> = objects
            .par_iter()
            .map(|(object, unit_idx)| {
                let gbe_diff_config = build_unit_diff_config(
                    &base_diff_config,
                    project.options.as_ref(),
                    project_units.get(*unit_idx).and_then(ProjectObject::options),
                    &args.config,
                )?;
                let target = object.target_path.as_ref().and_then(|p| {
                    obj::read::read(p.as_ref(), &gbe_diff_config, diff::DiffSide::Target).ok()
                });
                let base = object.base_path.as_ref().and_then(|p| {
                    obj::read::read(p.as_ref(), &gbe_diff_config, diff::DiffSide::Base).ok()
                });
                Ok(diff::UnitObjs { unit_name: object.name.clone(), target, base })
            })
            .collect::<Result<Vec<diff::UnitObjs>>>()?;
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
    // Which ruler produced these numbers. Descriptive only: nothing below reads it,
    // no measure depends on it. `diff_config` is the PROJECT-level effective config
    // — the layering is per-unit, so a unit with its own `options` block can differ,
    // which is what `units_with_option_overrides` discloses.
    let provenance = ReportProvenance {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        tool_binary_hash: tool_binary_hash.unwrap_or_default().to_string(),
        tool_commit: crate::build_id::commit().to_string(),
        diff_config: render_diff_config(&build_unit_diff_config(
            &base_diff_config,
            project.options.as_ref(),
            None,
            &args.config,
        )?),
        config_args: args.config.clone(),
        units_with_option_overrides: project_units
            .iter()
            .filter(|u| ProjectObject::options(u).is_some_and(|o| !o.is_empty()))
            .count() as u32,
        map_file: project.map_file.as_ref().map(|p| p.to_string()).unwrap_or_default(),
        map_file_hash: if project.map_file.is_some() {
            format!("{map_file_hash:016x}")
        } else {
            String::new()
        },
        map_file_entries,
        cache_hits: hits,
        cache_misses: misses,
    };
    let mut report = Report {
        measures: Some(measures),
        units,
        version: REPORT_VERSION,
        categories,
        provenance: Some(provenance),
    };
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

/// Layer diff options onto `base`, lowest precedence first:
/// report base (`base`) → project `options` → unit `options` → `-c key=value`.
///
/// `base` is a fallback that a project overrides by opting in, never a policy. A
/// project with no `options` block and no `-c` gets `base` back verbatim — that is the
/// invariant that keeps every project's tracked match percentage stable.
///
/// Anything appearing here must also appear in [`ReportCache::hash_unit`], or the
/// option gets silently dropped on a cache hit.
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

    // ── Disclosure, part 1 of 2: funclet OVER-SUBSCRIPTION (`pair_funclets_by_bytes`
    // pass 2b) ──
    //
    // NOTE: this is the NARROWER of the two disclosure sources. Part 2 (below, at
    // the per-symbol loop) adds `SymbolDiff::masked_equal_symbol`, i.e. EVERY pair
    // that exists only because the funclet byte-signature fallback matched it.
    // Over-subscription is a strict subset of that, so this set is kept only
    // because it is the one case where we can also name which member of a group is
    // the surplus one.
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
            // ── Disclosure, part 2 of 2: FUNCLET BYTE-SIGNATURE PAIRING ──
            //
            // `masked_equal_symbol` is set by `diff_objs` on every code pair the
            // funclet byte-signature fallback produced (`pair_funclets_by_bytes`,
            // ALL passes — not just the 2b over-subscription counted above). Such a
            // pair was formed by comparing masked bodies: relocation targets are
            // blanked in the signature, so the pairing says "these two bodies have
            // the same shape", NOT "these two symbols are the same function". The
            // credit IS supply-backed — our compiler really emitted a body of that
            // shape — but WHICH target funclet a given base funclet is credited
            // against is arbitrary within a byte-signature group, and the reloc
            // targets that would distinguish them are masked in the signature AND
            // (under the default ruler) in the score.
            //
            // Disclosing only the over-subscription subset understated the class by
            // ~19x on rb3-xenon (1,201 of ~22,549 funclet-paired rows), so the
            // `matched - masked_equal` figure quoted as "honest" still carried the
            // whole byte-signature class inside it. Both sources are unioned here.
            // This changes NO score: `matched_functions`, `matched_code`,
            // `total_*` and `fuzzy_match_percent` are computed above and are not a
            // function of this bit.
            let is_masked_equal = is_oversubscribed || symbol_diff.masked_equal_symbol;
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
                masked_equal: is_masked_equal.then_some(true),
            });
            if match_percent_normalized == 100.0 {
                measures.matched_functions += 1;
                // Disclosure only: a SUBSET of the `matched_functions` just
                // credited, never an addition to it.
                if is_masked_equal {
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
        return parse_report(&data).with_context(|| "Failed to load report from stdin");
    }
    let file = File::open(path).with_context(|| format!("Failed to open {path}"))?;
    let mmap =
        unsafe { memmap2::Mmap::map(&file) }.with_context(|| format!("Failed to map {path}"))?;
    parse_report(mmap.as_ref()).with_context(|| format!("Failed to load report {path}"))
}

/// [`Report::parse`], with a failure a human can act on.
///
/// Every consumer of a report reaches it through `read_report` (`changes`, `summary`,
/// `query`, `function`, `analyze`, `trending`), so all six get the same diagnosis.
fn parse_report(data: &[u8]) -> Result<Report> {
    Report::parse(data).map_err(|e| explain_report_parse_failure(e, data))
}

/// Turn `unknown field 'x', expected one of ...` into the sentence that explains it.
///
/// Report JSON is deserialized with `deny_unknown_fields`, so a report written by a
/// NEWER objdiff-cli than this one fails naming a field the reader has never heard
/// of, and saying nothing about why it is there. The cause is almost always a version
/// skew between the binary that wrote the report and the binary reading it, and the
/// report itself can usually say so: `provenance` records the writer's version and
/// commit. Read that block LENIENTLY (`serde_json::Value`) -- the strict deserializer
/// has just refused this document, and asking it again would fail the same way.
///
/// Decorates a failure and nothing else. By the time this is called,
/// [`Report::parse`] has already tried binary protobuf, strict JSON, and the
/// legacy-JSON fallback; a legacy report reaches `Ok` through `LegacyReport` and
/// never arrives here, even though its strict pass also failed on an unknown field.
fn explain_report_parse_failure(err: anyhow::Error, data: &[u8]) -> anyhow::Error {
    if !err.chain().any(|c| c.to_string().contains("unknown field")) {
        return err;
    }
    // "unknown field" is not enough on its own to conclude version skew, because
    // every JSON document that is not a report at all fails exactly the same way:
    // the strict pass rejects its first key, `LegacyReport` then fails on missing
    // fields, and the strict error is what propagates. `{"foo": 1}` was being told
    // to upgrade objdiff-cli. Require the document to be recognisably a report --
    // at least one key this binary DOES know -- before diagnosing a skew; otherwise
    // let the raw serde error stand, which for a not-a-report is already the more
    // useful message.
    let Ok(document) = serde_json::from_slice::<serde_json::Value>(data) else {
        return err;
    };
    if !looks_like_a_report(&document) {
        return err;
    }
    let hint = format!(
        "this report has a field this objdiff-cli does not know about, so it was probably \
         written by a newer objdiff-cli -- {}; this one is {}. Rebuild/upgrade this \
         objdiff-cli, or regenerate the report with this binary",
        describe_report_writer(&document),
        crate::build_id::version_line("objdiff-cli")
    );
    err.context(hint)
}

/// Top-level keys belonging to objdiff's PROJECT config (`objdiff.json`), which is
/// never a report.
///
/// This is the near-miss that matters: the two files sit side by side in every repo
/// objdiff diffs, they are both JSON, and they share a `units` key whose value is an
/// array in both — so a project config pointed at a report-reading flag looks
/// exactly like a report to any shape check. `units` is therefore NOT in this list.
/// It is the collision, not the tell.
///
/// From `objdiff_core::config::ProjectConfig`, minus `units`. A field added there
/// and not here costs a wrong error message, nothing more.
const PROJECT_CONFIG_ONLY_KEYS: [&str; 12] = [
    "min_version",
    "custom_make",
    "custom_args",
    "target_dir",
    "base_dir",
    "build_base",
    "build_target",
    "watch_patterns",
    "ignore_patterns",
    "progress_categories",
    "options",
    "map_file",
];

/// Whether a JSON document is recognisably an objdiff report, for the purpose of
/// blaming a version skew for its refusal.
///
/// Two questions, in order. Does it carry a key that rules a report OUT — the
/// `objdiff.json` vocabulary above? Then no, whatever else it has. Otherwise, does
/// it carry one DISTINCTIVE report key with a value of the right shape?
///
/// One key is deliberately enough: a report from the future may have renamed or
/// dropped any single one of them, and requiring two would withhold the hint exactly
/// when it is wanted. Four qualify, so any one rename still leaves three.
///
/// `version` is not among them, and that is the point. It is the most common key in
/// any JSON config ever written — `{"version": 3, "services": {…}}` is a
/// docker-compose file, and it was being told to upgrade its objdiff-cli. A document
/// whose only objdiff-shaped evidence is `version` is not evidence.
///
/// Heuristic, and only ever used to pick which error text to print. It never admits
/// or rejects a report — `Report::parse` did that before we were called.
fn looks_like_a_report(document: &serde_json::Value) -> bool {
    if PROJECT_CONFIG_ONLY_KEYS.iter().any(|key| document.get(key).is_some()) {
        return false;
    }
    let has = |key: &str, shaped: fn(&serde_json::Value) -> bool| {
        document.get(key).is_some_and(shaped)
    };
    has("measures", serde_json::Value::is_object)
        || has("provenance", serde_json::Value::is_object)
        || has("units", serde_json::Value::is_array)
        || has("categories", serde_json::Value::is_array)
}

/// Whatever the `provenance` block will admit about the objdiff-cli that wrote a
/// report, read out of JSON this binary cannot fully deserialize.
///
/// Three answers, and they are different: the block names its writer, the block is
/// there but names nobody (a build outside a git checkout writes empty strings, and
/// proto3 JSON then omits the keys), or there is no block at all (the writer
/// predates provenance, or was not objdiff-cli). Saying "no provenance block" for
/// the middle case sends the reader looking for something that is right there.
///
/// Accepts both spellings of each key: objdiff writes proto field names
/// (`preserve_proto_field_names`), but pbjson emits and accepts camelCase too, and a
/// report that has been through another JSON tool may carry either.
fn describe_report_writer(document: &serde_json::Value) -> String {
    let Some(provenance) = document.get("provenance") else {
        return "it carries no provenance block, so it cannot name its writer".to_string();
    };
    let field = |snake: &str, camel: &str| -> Option<&str> {
        provenance
            .get(snake)
            .or_else(|| provenance.get(camel))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    };
    match (field("tool_version", "toolVersion"), field("tool_commit", "toolCommit")) {
        (Some(version), Some(commit)) => {
            format!("the report's provenance says tool_version {version} ({commit})")
        }
        (Some(version), None) => format!("the report's provenance says tool_version {version}"),
        (None, Some(commit)) => format!("the report's provenance says tool_commit {commit}"),
        (None, None) => {
            "its provenance block does not identify its writer (no tool_version, no tool_commit)"
                .to_string()
        }
    }
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
    /// `BTreeMap`, so the serialized key order is the same on every run. A
    /// `HashMap` here published `std::collections::HashMap`'s per-instance
    /// iteration order straight into the JSON.
    by_verdict: BTreeMap<String, usize>,
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

    // Group by unit for efficient loading. `BTreeMap`, not `HashMap`: the loop
    // below appends its results in this map's iteration order, so a `HashMap`
    // reordered every bucket of the output on every run of the same binary --
    // the same leak `diff --batch` had.
    let mut by_unit: BTreeMap<&str, Vec<(&ReportUnit, &ReportItem)>> = BTreeMap::new();
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
    let mut verdict_counts: BTreeMap<String, usize> = BTreeMap::new();

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
        report_data.sort_by_key(|a| a.1);
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
    use objdiff_core::config::ProjectOptionValue;

    use super::*;

    /// The whole truth table, because the `--deduplicate` row is the one that
    /// has already been wrong once in a shipped build and the symptom was a
    /// changed progress number rather than an error.
    #[test]
    fn test_report_cache_enabled() {
        // no_cache, deduplicate, binary_hash_available -> expected
        assert!(report_cache_enabled(false, false, true), "the ordinary run caches");
        assert!(!report_cache_enabled(true, false, true), "--no-cache means no cache");
        assert!(!report_cache_enabled(false, false, false), "an unhashable binary means no cache");
        // Every --deduplicate row is false, whatever else is true. A cached unit
        // is a post-dedup unit under a key that cannot see the units before it,
        // so serving one corrupts BOTH modes through a shared -o.
        assert!(!report_cache_enabled(false, true, true), "-d must not use the cache");
        assert!(!report_cache_enabled(true, true, true), "-d must not use the cache");
        assert!(!report_cache_enabled(false, true, false), "-d must not use the cache");
        assert!(!report_cache_enabled(true, true, false), "-d must not use the cache");
    }

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

    // ── `report generate` diff-option layering.
    //
    // `report_base_diff_config` below is a copy of the literal in `generate`. It has
    // to be, because `generate` takes a `GenerateArgs` and walks a project directory;
    // the point of these tests is the layering, so they exercise
    // `build_unit_diff_config` directly against the same four base values.

    fn report_base_diff_config() -> diff::DiffObjConfig {
        diff::DiffObjConfig {
            function_reloc_diffs: diff::FunctionRelocDiffs::None,
            combine_data_sections: true,
            combine_text_sections: true,
            ppc_calculate_pool_relocations: false,
            ..Default::default()
        }
    }

    fn options(pairs: &[(&str, &str)]) -> ProjectOptions {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), ProjectOptionValue::String(v.to_string())))
            .collect()
    }

    fn bool_options(pairs: &[(&str, bool)]) -> ProjectOptions {
        pairs.iter().map(|(k, v)| (k.to_string(), ProjectOptionValue::Bool(*v))).collect()
    }

    /// `-c key=value` args, as `generate` receives them.
    fn cli_args(args: &[&str]) -> Vec<String> { args.iter().map(|s| s.to_string()).collect() }

    /// A project with no `options` block must score exactly as it always has: the four
    /// report base values survive untouched. Every tracked match percentage in every
    /// project depends on this.
    #[test]
    fn test_report_options_absent_leaves_base_config_untouched() {
        let base = report_base_diff_config();
        let config = build_unit_diff_config(&base, None, None, &[]).unwrap();
        assert_eq!(config.function_reloc_diffs, diff::FunctionRelocDiffs::None);
        assert!(config.combine_data_sections);
        assert!(config.combine_text_sections);
        assert!(!config.ppc_calculate_pool_relocations);
        // And an empty (but present) options block is the same as no options block.
        let empty = ProjectOptions::new();
        let config = build_unit_diff_config(&base, Some(&empty), Some(&empty), &[]).unwrap();
        assert_eq!(config.function_reloc_diffs, diff::FunctionRelocDiffs::None);
        assert!(config.combine_data_sections);
        assert!(config.combine_text_sections);
        assert!(!config.ppc_calculate_pool_relocations);
    }

    /// `{"options": {"functionRelocDiffs": "name_only"}}` reaches the diff config, and
    /// touches nothing else.
    #[test]
    fn test_report_project_options_function_reloc_diffs_name_only() {
        let base = report_base_diff_config();
        let project = options(&[("functionRelocDiffs", "name_only")]);
        let config = build_unit_diff_config(&base, Some(&project), None, &[]).unwrap();
        assert_eq!(config.function_reloc_diffs, diff::FunctionRelocDiffs::NameOnly);
        // Unrelated base values are not disturbed by opting into one option.
        assert!(config.combine_data_sections);
        assert!(config.combine_text_sections);
        assert!(!config.ppc_calculate_pool_relocations);
    }

    /// All four of the report's non-default base values are overridable from the
    /// project file, not just `functionRelocDiffs`.
    #[test]
    fn test_report_project_options_can_override_all_four_base_values() {
        let base = report_base_diff_config();
        let mut project = options(&[("functionRelocDiffs", "all")]);
        project.extend(bool_options(&[
            ("combineDataSections", false),
            ("combineTextSections", false),
            ("ppc.calculatePoolRelocations", true),
        ]));
        let config = build_unit_diff_config(&base, Some(&project), None, &[]).unwrap();
        assert_eq!(config.function_reloc_diffs, diff::FunctionRelocDiffs::All);
        assert!(!config.combine_data_sections);
        assert!(!config.combine_text_sections);
        assert!(config.ppc_calculate_pool_relocations);
    }

    /// Per-unit options win over project options; `-c` wins over both.
    #[test]
    fn test_report_options_layer_unit_over_project_and_cli_over_all() {
        let base = report_base_diff_config();
        let project = options(&[("functionRelocDiffs", "name_address")]);
        let unit = options(&[("functionRelocDiffs", "name_only")]);
        let config = build_unit_diff_config(&base, Some(&project), Some(&unit), &[]).unwrap();
        assert_eq!(config.function_reloc_diffs, diff::FunctionRelocDiffs::NameOnly);
        let cli = cli_args(&["functionRelocDiffs=name_check"]);
        let config = build_unit_diff_config(&base, Some(&project), Some(&unit), &cli).unwrap();
        assert_eq!(config.function_reloc_diffs, diff::FunctionRelocDiffs::NameCheck);
    }

    #[test]
    fn test_report_invalid_project_option_is_an_error() {
        let base = report_base_diff_config();
        let bad_key = options(&[("notAProperty", "name_only")]);
        assert!(build_unit_diff_config(&base, Some(&bad_key), None, &[]).is_err());
        let bad_value = options(&[("functionRelocDiffs", "sideways")]);
        assert!(build_unit_diff_config(&base, Some(&bad_value), None, &[]).is_err());
    }

    // ── Report cache key.
    //
    // Every input that can change what a cached unit says has to be in the key, or a
    // rerun over the same output path answers the previous question. Three classes
    // have actually bitten, in this order:
    //
    //   * the `options` blocks (fixed earlier): adding `options` to objdiff.json was
    //     silently a no-op for as long as the `.cache` file survived;
    //   * the ALIAS MAP (2026-08-12): a lane changed only `symbol_aliases.json`,
    //     re-ran into the same `-o`, and got 2,224 cache hits and a byte-identical
    //     report for a map with 340 more names in it — a +143-function change
    //     measured as +0;
    //   * the BINARY (2026-08-12): two objdiff builds A/B'd through one output path
    //     agreed to the last decimal in all six project x ruler cells. The real
    //     delta was +71 complete functions.
    //
    // The failure is always in the same direction — a cached report reproduces the
    // previous answer, so it cannot show a LOSS, and a guard reading one reports
    // "intact" no matter what happened.

    fn key_config(properties: &[&str]) -> diff::DiffObjConfig {
        let base = report_base_diff_config();
        build_unit_diff_config(&base, None, None, &cli_args(properties)).unwrap()
    }

    fn key_global() -> GlobalCacheKey {
        GlobalCacheKey { tool_binary_hash: Some("0123456789abcdef"), map_file_hash: 0 }
    }

    #[test]
    fn test_hash_unit_key_changes_with_the_effective_ruler() {
        let object = ObjectConfig::default();
        let global = key_global();
        let none = ReportCache::hash_unit(&object, &key_config(&["functionRelocDiffs=none"]), &global);
        let name_check =
            ReportCache::hash_unit(&object, &key_config(&["functionRelocDiffs=name_check"]), &global);
        assert_ne!(none, name_check, "the ruler must be in the cache key");
        // Same resolved config, same key — the key is a function of the config, not
        // of the object identity that carried it.
        assert_eq!(
            none,
            ReportCache::hash_unit(&object, &key_config(&["functionRelocDiffs=none"]), &global)
        );
        // Non-ruler properties count too: anything that reaches `diff_objs` can move
        // a number.
        assert_ne!(
            none,
            ReportCache::hash_unit(
                &object,
                &key_config(&["functionRelocDiffs=none", "combineTextSections=false"]),
                &global
            )
        );
    }

    #[test]
    fn test_hash_unit_key_changes_with_the_alias_map() {
        // The 2026-08-12 map failure. The map supplies ICF symbol equivalences, which
        // decide which symbols may pair, so it moves scores.
        let object = ObjectConfig::default();
        let config = key_config(&[]);
        let a = ReportCache::hash_unit(
            &object,
            &config,
            &GlobalCacheKey { tool_binary_hash: Some("aa"), map_file_hash: 1 },
        );
        let b = ReportCache::hash_unit(
            &object,
            &config,
            &GlobalCacheKey { tool_binary_hash: Some("aa"), map_file_hash: 2 },
        );
        assert_ne!(a, b, "the map file's content must be in the cache key");
    }

    #[test]
    fn test_hash_unit_key_changes_with_the_binary() {
        // The 2026-08-12 cross-build failure, and the reason the hand-maintained
        // CACHE_LOGIC_VERSION counter is gone: the semantic change that this missed
        // was made in objdiff-core, by an author who never opened this file.
        let object = ObjectConfig::default();
        let config = key_config(&[]);
        let a = ReportCache::hash_unit(
            &object,
            &config,
            &GlobalCacheKey { tool_binary_hash: Some("aa"), map_file_hash: 0 },
        );
        let b = ReportCache::hash_unit(
            &object,
            &config,
            &GlobalCacheKey { tool_binary_hash: Some("bb"), map_file_hash: 0 },
        );
        assert_ne!(a, b, "the objdiff binary's identity must be in the cache key");
    }

    #[test]
    fn test_layered_spellings_that_resolve_to_one_ruler_share_a_key() {
        // A deliberate consequence of keying on the RESOLVED config rather than on the
        // inputs that produced it: `-c functionRelocDiffs=name_only` and an
        // `options: {functionRelocDiffs: name_only}` block describe the same diff, so
        // they are the same cache entry. The old key held them apart, which was safe
        // but wrong-headed — it could not have held apart a change to the report's own
        // base fallback, which this does.
        let object = ObjectConfig::default();
        let global = key_global();
        let base = report_base_diff_config();
        let via_cli =
            build_unit_diff_config(&base, None, None, &cli_args(&["functionRelocDiffs=name_only"]))
                .unwrap();
        let via_project = build_unit_diff_config(
            &base,
            Some(&options(&[("functionRelocDiffs", "name_only")])),
            None,
            &[],
        )
        .unwrap();
        let via_unit = build_unit_diff_config(
            &base,
            None,
            Some(&options(&[("functionRelocDiffs", "name_only")])),
            &[],
        )
        .unwrap();
        assert_eq!(
            ReportCache::hash_unit(&object, &via_cli, &global),
            ReportCache::hash_unit(&object, &via_project, &global)
        );
        assert_eq!(
            ReportCache::hash_unit(&object, &via_cli, &global),
            ReportCache::hash_unit(&object, &via_unit, &global)
        );
    }

    #[test]
    fn test_hash_unit_key_distinguishes_bool_option_values() {
        let object = ObjectConfig::default();
        let global = key_global();
        let base = report_base_diff_config();
        let on = build_unit_diff_config(
            &base,
            Some(&bool_options(&[("combineTextSections", true)])),
            None,
            &[],
        )
        .unwrap();
        let off = build_unit_diff_config(
            &base,
            Some(&bool_options(&[("combineTextSections", false)])),
            None,
            &[],
        )
        .unwrap();
        assert_ne!(
            ReportCache::hash_unit(&object, &on, &global),
            ReportCache::hash_unit(&object, &off, &global)
        );
    }

    #[test]
    fn test_render_diff_config_covers_every_property_in_a_stable_order() {
        use objdiff_core::diff::{ConfigEnum, ConfigPropertyId};
        let rendered = render_diff_config(&report_base_diff_config());
        // One line per property objdiff knows about: a property added to the schema is
        // in the cache key and in the report's provenance without anyone remembering.
        assert_eq!(rendered.len(), ConfigPropertyId::variants().len());
        assert!(rendered.iter().all(|line| line.contains('=')));
        // The four report base values, spelled.
        assert!(rendered.contains(&"functionRelocDiffs=none".to_string()));
        assert!(rendered.contains(&"combineDataSections=true".to_string()));
        assert!(rendered.contains(&"combineTextSections=true".to_string()));
        assert!(rendered.contains(&"ppc.calculatePoolRelocations=false".to_string()));
        // Order is the generated variant order, not a hash-map walk: report bytes are
        // compared for equality by several tools, so this must not shuffle run to run.
        assert_eq!(rendered, render_diff_config(&report_base_diff_config()));
    }

    #[test]
    fn test_tool_binary_hash_is_stable_and_hex() {
        // It hashes /proc/self/exe (the test binary here), so it must at least be
        // present and stable within a process.
        let hash = tool_binary_hash().expect("the test binary must be readable");
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(Some(hash), tool_binary_hash());
    }

    // ── Reading a report written by a different objdiff-cli.
    //
    // Three shapes go through `parse_report`, and only the third may be decorated.
    // The other two are the fallback chain inside `Report::parse`, which the
    // diagnosis must not disturb: a legacy report ALSO fails the strict pass with an
    // unknown field, and still has to come back Ok.

    /// A current-shape report, provenance and all.
    fn current_report_json() -> String {
        r#"{
            "measures": {"fuzzy_match_percent": 42.5, "total_code": 100, "matched_code": 40},
            "units": [],
            "version": 2,
            "provenance": {
                "tool_version": "9.9.9",
                "tool_binary_hash": "0123456789abcdef",
                "tool_commit": "cafef00dbaad"
            }
        }"#
        .to_string()
    }

    /// (a) The normal case: this binary's own output reads back.
    #[test]
    fn test_parse_report_accepts_a_current_report() {
        let report = parse_report(current_report_json().as_bytes()).unwrap();
        assert_eq!(report.version, 2);
        let provenance =
            report.provenance.as_ref().expect("provenance must survive the round trip");
        assert_eq!(provenance.tool_version, "9.9.9");
        assert_eq!(provenance.tool_commit, "cafef00dbaad");
        assert_eq!(report.measures.as_ref().unwrap().total_code, 100);
    }

    /// (b) The invariant: pre-v0 JSON still migrates in through `LegacyReport`. Its
    /// strict pass fails on `unknown field 'fuzzy_match_percent'` -- the same class of
    /// error the hint decorates -- so this is the test that catches a diagnosis wired
    /// one layer too early.
    #[test]
    fn test_parse_report_still_accepts_a_legacy_report() {
        let legacy = r#"{
            "fuzzy_match_percent": 50.0,
            "total_code": 200,
            "matched_code": 100,
            "matched_code_percent": 50.0,
            "total_data": 20,
            "matched_data": 10,
            "matched_data_percent": 50.0,
            "total_functions": 4,
            "matched_functions": 2,
            "matched_functions_percent": 50.0,
            "units": []
        }"#;
        let report = parse_report(legacy.as_bytes()).unwrap();
        let measures = report.measures.as_ref().expect("legacy measures are lifted into Measures");
        assert_eq!(measures.total_code, 200);
        assert_eq!(measures.matched_functions, 2);
        // Legacy reports carry no version; `migrate` is what raises it later.
        assert_eq!(report.version, 0);
    }

    /// (c) A field from the future: the error has to name the cause and both binaries.
    #[test]
    fn test_parse_report_from_the_future_explains_the_version_skew() {
        let future = current_report_json().replace(
            "\"version\": 2,",
            "\"version\": 2, \"something_a_later_objdiff_added\": {\"x\": 1},",
        );
        let err = parse_report(future.as_bytes()).unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("newer objdiff-cli"), "{rendered}");
        // The writer, read leniently out of a document the strict deserializer refused.
        assert!(rendered.contains("9.9.9"), "{rendered}");
        assert!(rendered.contains("cafef00dbaad"), "{rendered}");
        // This binary, so the two can be compared without a second command.
        assert!(rendered.contains(env!("CARGO_PKG_VERSION")), "{rendered}");
        assert!(rendered.contains("Rebuild/upgrade"), "{rendered}");
        // And the original serde message survives underneath the hint.
        assert!(rendered.contains("unknown field"), "{rendered}");
    }

    /// A report with no provenance says so rather than inventing a version, and an
    /// error that is not a version skew is passed through untouched.
    #[test]
    fn test_parse_report_hint_is_honest_about_what_it_does_not_know() {
        let future = r#"{"version": 2, "units": [], "something_a_later_objdiff_added": 1}"#;
        let rendered = format!("{:#}", parse_report(future.as_bytes()).unwrap_err());
        assert!(rendered.contains("no provenance block"), "{rendered}");

        // Malformed JSON is a syntax error, not a skew: no hint.
        let rendered = format!("{:#}", parse_report(b"{\"version\":").unwrap_err());
        assert!(!rendered.contains("newer objdiff-cli"), "{rendered}");
    }

    /// A provenance block that names nobody -- what a build outside a git checkout
    /// writes, since proto3 JSON omits the empty strings -- must not be described as
    /// a missing block. It is right there, and it is empty.
    #[test]
    fn test_parse_report_distinguishes_an_anonymous_provenance_from_a_missing_one() {
        let anonymous = r#"{
            "version": 2, "units": [],
            "provenance": {"cache_hits": 3},
            "something_a_later_objdiff_added": 1
        }"#;
        let rendered = format!("{:#}", parse_report(anonymous.as_bytes()).unwrap_err());
        assert!(rendered.contains("does not identify its writer"), "{rendered}");
        assert!(!rendered.contains("no provenance block"), "{rendered}");
    }

    /// JSON that is not a report at all fails identically -- the strict pass rejects
    /// its first key, `LegacyReport` then fails on missing fields, and the strict
    /// "unknown field" error is what propagates. Telling that user to upgrade
    /// objdiff-cli is a wrong answer delivered confidently, so the hint stays out of
    /// it and the raw serde error stands.
    #[test]
    fn test_parse_report_does_not_diagnose_a_skew_for_a_document_that_is_not_a_report() {
        for not_a_report in [
            r#"{"foo": 1}"#,
            // The near-miss, in its REAL shape. objdiff.json sits beside the report
            // in every repo objdiff diffs and its top-level `units` is an ARRAY, so
            // no shape check on `units` alone can tell them apart -- an earlier
            // version of this test used `"units": 3` and passed while the real file
            // failed. `min_version` unknown-fields first, so this is the message a
            // user pointing `report summary` at their project config actually gets.
            r#"{
                "min_version": "2.0.0-beta.5",
                "custom_make": "ninja",
                "build_target": false,
                "watch_patterns": ["*.c", "*.h"],
                "units": [{"name": "main", "target_path": "a.o", "base_path": "b.o"}],
                "progress_categories": [{"id": "dol", "name": "DOL"}],
                "options": {"functionRelocDiffs": "none"}
            }"#,
            // Same class, different vocabulary: `version` is the most common key in
            // any JSON config ever written and is not evidence of anything.
            r#"{"version": 3, "services": {"web": {"image": "nginx"}}}"#,
            r#"{"version": "1.2.3-beta", "dependencies": {}}"#, // package.json
            // A `units` that is not a list: the key name alone must not decide.
            r#"{"name": "some-tool.json", "units": 3}"#,
            // (`{}` is not in this list: every Report field is optional, so an empty
            // object parses as an empty report and never reaches an error at all.)
        ] {
            let err = parse_report(not_a_report.as_bytes()).unwrap_err();
            let rendered = format!("{err:#}");
            assert!(!rendered.contains("newer objdiff-cli"), "{not_a_report} -> {rendered}");
            assert!(!rendered.contains("Rebuild/upgrade"), "{not_a_report} -> {rendered}");
        }
    }

    /// ...but a document carrying any ONE distinctive report key is a report, and
    /// still gets diagnosed. This is the boundary the test above must not overshoot,
    /// and the property that keeps the hint working for a future report that renamed
    /// something: four keys qualify, so any one rename still leaves three.
    #[test]
    fn test_parse_report_diagnoses_a_skew_from_any_one_distinctive_key() {
        for known in ["\"measures\": {}", "\"units\": []", "\"categories\": []", "\"provenance\": {}"]
        {
            let doc = format!("{{{known}, \"something_a_later_objdiff_added\": 1}}");
            let rendered = format!("{:#}", parse_report(doc.as_bytes()).unwrap_err());
            assert!(rendered.contains("newer objdiff-cli"), "{doc} -> {rendered}");
        }
        // `version` is deliberately NOT one of them -- see the docker-compose case
        // above. A document whose only report-shaped key is `version` gets the raw
        // serde error.
        let version_only = r#"{"version": 2, "something_a_later_objdiff_added": 1}"#;
        let rendered = format!("{:#}", parse_report(version_only.as_bytes()).unwrap_err());
        assert!(!rendered.contains("newer objdiff-cli"), "{rendered}");
    }

    /// The veto is scoped to keys that are project-config-ONLY. A real report that
    /// happens to be diagnosed must still be diagnosed, and `units` -- the key both
    /// files share -- must never be treated as a veto.
    #[test]
    fn test_parse_report_veto_does_not_swallow_a_real_report() {
        let rendered =
            format!("{:#}", parse_report(current_report_json().replace(
                "\"version\": 2,",
                "\"version\": 2, \"something_a_later_objdiff_added\": 1,",
            ).as_bytes()).unwrap_err());
        assert!(rendered.contains("newer objdiff-cli"), "{rendered}");
        assert!(!PROJECT_CONFIG_ONLY_KEYS.contains(&"units"), "units is the collision, not the tell");
        assert!(!PROJECT_CONFIG_ONLY_KEYS.contains(&"measures"));
        assert!(!PROJECT_CONFIG_ONLY_KEYS.contains(&"provenance"));
    }
}
