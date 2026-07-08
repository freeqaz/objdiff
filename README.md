# objdiff (MiloHax fork)

## freeqaz fork

This is a fork of [encounter/objdiff](https://github.com/encounter/objdiff), maintained by [freeqaz](https://github.com/freeqaz) for the [milohax](https://github.com/milohax) decomp work (Dance Central 3, Rock Band 3). The canonical push target for this fork's work is [freeqaz/objdiff](https://github.com/freeqaz/objdiff).

Since diverging from upstream, this fork's ~39 commits add:

- **Mismatch analysis engine**: 7 pattern detectors (LinkerMerged, BoolMask, RegisterSwap, ComparisonStyle, ControlFlow, CommutativeOpOrder, OffsetSwap), fixability verdicts (Complete/LikelyFixable/MaybeFixable/AtLimit/NeedsInvestigation), pattern summaries, call-diff analysis, insert/delete cluster detection, and diff-region computation, exposed via new `analysis`/`report` CLI subcommands with structured JSON and markdown output — designed to be consumed by AI agents (e.g. via MCP) as well as humans.
- **MSVC/PowerPC (Xbox 360) diffing fidelity**: deterministic EH funclet pairing by masked byte signature, FP-anchor frame-establisher normalization, masked-equality disclosure with a SignednessMismatch pattern, case-B global byte-equality matching, a `FunctionRelocDiffs::NameOnly` reloc mode (name+section match across COMDAT buckets, ignoring addend), and `??__E`/`??__F` global init/dtor funclet pairing.
- **Reporting/CLI improvements**: a rewritten `match_guidance` + smart unit resolution, per-instruction branch graph in CLI JSON output, structured data-symbol relocation diffs (`--include-data`), `frame_size`/typed instruction args in call-diff analysis, and a normalized-vs-raw match display toggle.
- **Supporting infra**: map file symbol resolution, DWARF2 line info, typed instruction args in JSON output, and routine version bumps / clippy cleanups.

See the "Why this fork?" section immediately below for the original fork rationale and AI/MCP integration context.

> **This is the [MiloHax](https://github.com/milohax) fork of [encounter/objdiff](https://github.com/encounter/objdiff).**
> It adds automated analysis and pattern detection on top of upstream objdiff, designed to be consumed by AI agents working on decompilation at scale.

## Why this fork?

This fork was built for [dc3-decomp](https://github.com/rjkiv/dc3-decomp), the Dance Central 3 decompilation project targeting Xbox 360 (PowerPC). That project has ~47,000 functions to match against the original binary. Manually inspecting every mismatch to figure out what's wrong and whether it's fixable doesn't scale -- so we made objdiff do the diagnosis automatically.

### The problem

Large decompilation projects produce hundreds of functions that _almost_ match but don't quite. Some are genuinely fixable with a one-line change. Others are stuck at 97-99% because the linker merged identical functions (ICF) or the compiler's register allocator made different choices. Telling the difference requires reading raw assembly diffs instruction-by-instruction, which is slow and error-prone for humans and opaque to AI agents.

### The solution: machine-readable analysis

This fork adds an **analysis engine** to objdiff-cli that examines instruction diffs, detects common mismatch patterns, classifies each function with a **fixability verdict**, and outputs everything as structured JSON or human-readable markdown. The key insight is that this output is designed to be consumed by AI agents via MCP (Model Context Protocol), not just read by humans.

In dc3-decomp, an **MCP orchestrator server** wraps objdiff-cli and exposes tools like `run_objdiff` and `run_diff_inspect` to Claude Code agents. An agent working on a function calls `run_objdiff`, gets back a verdict like `LIKELY_FIXABLE` with pattern details ("register swap on r3/r4, 5 occurrences -- try reordering variable declarations"), makes a code change, rebuilds in ~2-4 seconds, and checks the new diff. This tight loop runs autonomously, with 6-10 agents working in parallel on different functions using isolated git worktrees.

The structured output -- verdicts, pattern types, match percentages, call diffs, instruction clusters -- gives agents the context they need to make targeted fixes without staring at raw PowerPC assembly. It also tells them when to stop: if the verdict is `AT_LIMIT` because 80%+ of remaining mismatches are linker-merged calls, there's nothing more to try.

### What it adds

- **7 mismatch pattern detectors**: LinkerMerged, BoolMask, RegisterSwap, ComparisonStyle, ControlFlow, CommutativeOpOrder, OffsetSwap
- **Fixability verdicts**: Complete, LikelyFixable, MaybeFixable, AtLimit, NeedsInvestigation -- so agents (and humans) can prioritize what to work on
- **Pattern summaries**: human-readable explanations of what's wrong and what to try next
- **Call diff analysis**: detects when target and base call different functions or different counts
- **Insert/delete cluster detection**: identifies groups of added/removed instructions and their dominant opcodes
- **Diff region computation**: breaks a function into localized regions with per-region match percentages
- **Markdown diff output**: concise, context, and full-listing rendering modes for CI reports and MCP tool responses
- **`analysis` and `report` CLI subcommands**: batch-analyze entire projects and export structured JSON or readable markdown
- **Map file support**: resolve symbols from linker map files
- **DWARF2 line info**: extract source file and line number from debug info

### How AI agents use it

In the dc3-decomp workflow, the MCP orchestrator exposes these objdiff-powered tools to agents:

| Tool | What it does |
|------|-------------|
| `run_objdiff` | Incremental build + diff a single function. Returns match %, verdict, detected patterns. |
| `run_diff_inspect` | Deep analysis modes: `diagnose` (root cause), `clusters`, `regswaps`, `offsets`, `replaces`, `mismatches` |
| `run_analyze_function` | Combined objdiff + Ghidra analysis with struct field resolution for offset mismatches |

Agents follow a structured workflow: receive pre-computed context (RB3 reference code, Ghidra decompilation, objdiff analysis) -> edit source -> rebuild + diff via `run_objdiff` -> respond to verdict -> iterate or accept limit. The verdict system prevents wasted effort -- agents learn that `AT_LIMIT` means stop, `LIKELY_FIXABLE` means try control flow changes, and `MAYBE_FIXABLE` means try variable reordering.

See the [dc3-decomp docs](https://github.com/rjkiv/dc3-decomp/tree/main/docs) for the full orchestrator setup, master agent prompt, and subagent strategy.

### Upstream compatibility

This fork tracks upstream `encounter/objdiff` and periodically rebases or merges. The core diffing engine, GUI, configuration format, and all existing features are preserved. The analysis features are additive -- they live in the CLI and don't affect the GUI or library API.

---

[![Build Status]][actions]

[Build Status]: https://github.com/encounter/objdiff/actions/workflows/build.yaml/badge.svg
[actions]: https://github.com/encounter/objdiff/actions

A local diffing tool for decompilation projects. Inspired by [decomp.me](https://decomp.me) and [asm-differ](https://github.com/simonlindholm/asm-differ).

Features:

- Compare entire object files: functions and data
- Built-in C++ symbol demangling (GCC, MSVC, CodeWarrior, Itanium)
- Automatic rebuild on source file changes
- Project integration via [configuration file](#configuration)
- Search and filter objects with quick switching
- Click-to-highlight values and registers
- Detailed progress reporting (powers [decomp.dev](https://decomp.dev))
- WebAssembly API, [web interface](https://github.com/encounter/objdiff-web) and [Visual Studio Code extension](https://marketplace.visualstudio.com/items?itemName=decomp-dev.objdiff) (WIP)

Supports:

- ARM (GBA, DS, 3DS)
- ARM64 (Switch)
- MIPS (N64, PS1, PS2, PSP)
- PowerPC (GameCube, Wii, PS3, Xbox 360)
- SuperH (Saturn, Dreamcast)
- x86, x86_64 (PC)

See [Usage](#usage) for more information.

## Downloads

To build from source, see [Building](#building).

### GUI

- [Windows (x86_64)](https://github.com/encounter/objdiff/releases/latest/download/objdiff-windows-x86_64.exe)
- [Linux (x86_64)](https://github.com/encounter/objdiff/releases/latest/download/objdiff-linux-x86_64)
- [macOS (arm64)](https://github.com/encounter/objdiff/releases/latest/download/objdiff-macos-arm64)
- [macOS (x86_64)](https://github.com/encounter/objdiff/releases/latest/download/objdiff-macos-x86_64)

For Linux and macOS, run `chmod +x objdiff-*` to make the binary executable.

### CLI

CLI binaries are available on the [releases page](https://github.com/encounter/objdiff/releases).

## Screenshots

![Symbol Screenshot](assets/screen-symbols.png)
![Diff Screenshot](assets/screen-diff.png)

## Usage

objdiff compares two relocatable object files (`.o`). Here's how it works:

1. **Create an `objdiff.json` configuration file** in your project root (or generate it with your build script).  
  This file lists **all objects in the project** with their target ("expected") and base ("current") paths.

2. **Load the project** in objdiff.

3. **Select an object** from the sidebar to begin diffing.

4. **objdiff automatically:**
   - Executes the build system to compile the base object (from current source code)
   - Compares the two objects and displays the differences
   - Watches for source file changes and rebuilds when detected

The configuration file allows complete flexibility in project structure - your build directories can have any layout as long as the paths are specified correctly.

See [Configuration](#configuration) for setup details.

## Configuration

Projects can add an `objdiff.json` file to configure the tool automatically. The configuration file must be located in
the root project directory.

If your project has a generator script (e.g. `configure.py`), it's highly recommended to generate the objdiff configuration
file as well. You can then add `objdiff.json` to your `.gitignore` to prevent it from being committed.

```json
{
  "$schema": "https://raw.githubusercontent.com/encounter/objdiff/main/config.schema.json",
  "custom_make": "ninja",
  "custom_args": [
    "-d",
    "keeprsp"
  ],
  "build_target": false,
  "build_base": true,
  "watch_patterns": [
    "*.c",
    "*.cc",
    "*.cp",
    "*.cpp",
    "*.cxx",
    "*.c++",
    "*.h",
    "*.hh",
    "*.hp",
    "*.hpp",
    "*.hxx",
    "*.h++",
    "*.pch",
    "*.pch++",
    "*.inc",
    "*.s",
    "*.S",
    "*.asm",
    "*.py",
    "*.yml",
    "*.txt",
    "*.json"
  ],
  "ignore_patterns": [
    "build/**/*"
  ],
  "units": [
    {
      "name": "main/MetroTRK/mslsupp",
      "target_path": "build/asm/MetroTRK/mslsupp.o",
      "base_path": "build/src/MetroTRK/mslsupp.o",
      "metadata": {}
    }
  ]
}
```

### Schema

> [!NOTE]  
> View [config.schema.json](config.schema.json) for all available options. Below is a summary of the most important options.

#### Build Configuration

**`custom_make`** _(optional, default: `"make"`)_  
If the project uses a different build system (e.g. `ninja`), specify it here. The build command will be `[custom_make] [custom_args] path/to/object.o`.

**`custom_args`** _(optional)_  
Additional arguments to pass to the build command prior to the object path.

**`build_target`**  _(default: `false`)_  
If true, objdiff will build the target objects before diffing (e.g. `make path/to/target.o`). Useful if target objects are not built by default or can change based on project configuration. Requires proper build system configuration.

**`build_base`**  _(default: `true`)_  
If true, objdiff will build the base objects before diffing (e.g. `make path/to/base.o`). It's unlikely you'll want to disable this unless using an external tool to rebuild the base object.

#### File Watching

**`watch_patterns`** _(optional, default: listed above)_  
A list of glob patterns to watch for changes ([supported syntax](https://docs.rs/globset/latest/globset/#syntax)). When these files change, objdiff automatically rebuilds and re-compares objects.

**`ignore_patterns`** _(optional, default: listed above)_  
A list of glob patterns to explicitly ignore when watching for changes ([supported syntax](https://docs.rs/globset/latest/globset/#syntax)).

#### Units (Objects)

**`units`** _(optional)_  
If specified, objdiff displays a list of objects in the sidebar for easy navigation. Each unit contains:

- **`name`** _(optional)_ - The display name in the UI. Defaults to the object's `path`.
- **`target_path`** _(optional)_ - Path to the "target" or "expected" object (the **intended result**).
- **`base_path`** _(optional)_ - Path to the "base" or "current" object (built from **current source code**). Omit if there is no source object yet.
- **`metadata.auto_generated`** _(optional)_ - Hides the object from the sidebar but includes it in progress reports.
- **`metadata.complete`** _(optional)_ - Marks the object as "complete" (linked) when `true` or "incomplete" when `false`.

## Building

Install Rust via [rustup](https://rustup.rs).

```shell
git clone https://github.com/freeqaz/objdiff.git
cd objdiff
cargo run --release
```

Or install directly with cargo:

```shell
cargo install --locked --git https://github.com/freeqaz/objdiff.git objdiff-gui objdiff-cli
```

Binaries will be installed to `~/.cargo/bin` as `objdiff` and `objdiff-cli`.

## Contributing

Install `pre-commit` to run linting and formatting automatically:

```shell
rustup toolchain install nightly  # Required for cargo fmt/clippy
cargo install --locked cargo-deny # https://github.com/EmbarkStudios/cargo-deny
uv tool install pre-commit        # https://docs.astral.sh/uv, or use pipx or pip
pre-commit install
```

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
