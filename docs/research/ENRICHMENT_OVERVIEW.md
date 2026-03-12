# Objdiff CLI Enrichment for Agentic Decompilation

## Overview

This document consolidates research findings from multiple investigation threads into a comprehensive overview for enhancing objdiff CLI output to better support AI-assisted decompilation workflows.

**Target Project**: dc3-decomp (Dance Central 3 Xbox 360 decompilation)
**Branch**: `feature/analysis-pattern-detection` (based on 3.6.0)
**Core Problem**: AI agents waste significant effort exploring functions because they lack pre-computed context and actionable guidance.

---

## Current State

### What's Been Implemented (Phase 1-4)

The following changes have been committed to the feature branch (`feature/analysis-pattern-detection`):

#### 1. TypedArg Enum (`diff.rs`)

```rust
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type", content = "value")]
pub enum TypedArg {
    Signed(i64),      // Signed integer values
    Unsigned(u64),    // Unsigned integer values
    Register(String), // Register references (r0-r31, f0-f31, etc.)
    Symbol(String),   // Symbol references from relocations
    BranchDest(u64),  // Branch destination addresses
    Other(String),    // Other opaque values
}
```

**Why this matters**: Previously, instruction arguments were converted to strings and type information was lost. Pattern detection had to use fragile regex on formatted strings. Now the type information is preserved.

#### 2. Extended InstructionInfo

```rust
pub struct InstructionInfo {
    pub address: String,
    pub opcode: String,
    pub args: Option<String>,               // Kept for backward compat
    pub typed_args: Option<Vec<TypedArg>>,  // Typed arguments
    pub branch_dest: Option<u64>,           // Branch destination if branch instruction
    pub line_number: Option<u32>,           // Source line number (from DWARF/COFF)
    pub source_file: Option<String>,        // Source file path (from DWARF/COFF)
}
```

#### 3. Explicit Diff Breakdown

For `diff_arg` instructions, detailed breakdown of what differs:

```rust
#[derive(Serialize, Clone, Debug)]
pub struct ArgumentDiff {
    pub index: usize,        // Which argument position
    pub target: TypedArg,    // Target side value
    pub base: TypedArg,      // Base side value
    pub diff_type: String,   // "register", "immediate", "symbol", "other"
}

// Added to InstructionDiffOutput:
pub diff_breakdown: Option<Vec<ArgumentDiff>>,
```

#### 4. Improved Pattern Detection (`analysis.rs`)

| Pattern | Before | After |
|---------|--------|-------|
| Bool mask | `args.contains(", 24")` - fails on hex (0x18) | Uses `TypedArg::Unsigned(24)` - handles any format |
| Control flow | Hardcoded `BRANCH_OPCODES` list | Uses `branch_dest.is_some()` - architecture-agnostic |

**New Patterns Added (Phase 4)**:

| Pattern | Description | Detection Method |
|---------|-------------|------------------|
| COMMUTATIVE_OP_ORDER | Operand order swap in fadd/fmul/add/and/or/xor | Check if source operands are permuted |
| OFFSET_SWAP | Two offsets swapped between instructions | Find symmetric offset differences |

#### 5. More Specific Suggestions

- Before: "Check branch conditions and if/else structure"
- After: "Check branch at index 12, 45, 67 (+2 more)"
- Register swaps now show: "Register swap r30↔r31 at 4 location(s)"

#### 6. Test Coverage

26 tests passing, including:
- `test_detect_bool_mask_with_typed_args`
- `test_detect_bool_mask_rlwinm_typed_args`
- `test_detect_control_flow_with_branch_dest`
- `test_typed_arg_methods`
- `test_detect_commutative_op_order`
- `test_detect_commutative_op_order_integer`
- `test_detect_offset_swap`
- `test_detect_offset_swap_negative`

---

## Research Findings

### 1. Ghidra Integration Architecture

**Source**: Agent a0ca7e4 (ghidra-integration.md)

**Recommendation**: Keep objdiff and Ghidra separate (Option C)

**Rationale**:
- objdiff is a general-purpose tool used across many decomp projects
- Adding Ghidra dependency would limit portability and increase maintenance
- Current architecture (analyze-function + MCP) already works well
- Each tool should stay focused on its domain

**Proposed Separation of Concerns**:
| Tool | Responsibility |
|------|----------------|
| objdiff | "What instructions differ?" |
| Ghidra | "What do those addresses/offsets mean?" |
| analyze-function | "How do we fix it?" |

**New Ghidra MCP Tools Recommended**:
```python
# Resolve struct field at address+offset
def resolve_struct_field(address: str, offset: int) -> FieldInfo

# Get stack frame variables for a function
def get_stack_frame(function_name: str) -> List[StackVariable]

# Get variable type at instruction
def get_variable_type(function_name: str, address: int) -> TypeInfo

# Get full struct definition
def get_data_type(type_name: str) -> StructDefinition
```

**Files in dc3-decomp**:
- `tools/analyze_function.py` - Orchestrator that merges objdiff + Ghidra
- `tools/pyghidra-mcp-fork/pyghidra_mcp/tools.py` - MCP tool implementations
- `tools/ghidra/direct_client.py` - Direct Python-to-Java bridge

---

### 2. Struct Offset Problem

**Source**: Agent ac95612 (struct-offsets.md)

**The Problem**: When objdiff shows `stw r10, 0x118(r11)` vs `stw r10, 0xf4(r11)`, agents cannot determine:
- Which struct is being accessed
- Which field the offset corresponds to
- What size/padding changes are needed

**Proposed Solutions** (Tiered):

#### Tier 1: Header Parsing (Quick Win)

dc3-decomp already has manually annotated struct definitions:
```cpp
// /home/free/code/milohax/dc3-decomp/src/lazer/game/Game.h
class Game : public Hmx::Object, public SkeletonCallback {
    SongPos mSongPos; // 0x30
    SongDB *mSongDB; // 0x48
    SongInfo *mSongInfo; // 0x4c
    HamMaster *mMaster; // 0x50
    // ...
};
```

**Implementation idea**:
1. Parse header files for offset comments: `(\w+)\s+(\w+);\s*//\s*(0x[0-9a-fA-F]+)`
2. Build lookup table: `(class_name, offset) -> field_name`
3. When objdiff reports offset mismatch, look up both offsets
4. Report: "Offset 0x118 is `Game::unk118`, 0xf4 is `Game::mShuttle`"

**Effort**: Medium
**Accuracy**: High for annotated fields

#### Tier 2: Ghidra Integration (Most Powerful)

Add MCP tools to query Ghidra's type database:
```python
def get_struct_layout(struct_name: str) -> StructLayout
def find_structs_with_offset(offset: int, size: int = 4) -> List[StructMatch]
def get_inferred_type_at_address(address: int, register: str) -> TypeInfo
```

**Effort**: Medium
**Accuracy**: Very high

#### Tier 3: DWARF Extraction (When Available)

Extend existing gimli usage to extract struct layouts from debug info.

**Effort**: Medium-High
**Accuracy**: Very high when DWARF present
**Challenge**: Debug info often stripped or unavailable

---

### 3. Pattern Detection Audit

**Source**: Agent ab501a4 (pattern-detection-audit.md)

#### Working Patterns
| Pattern | Detection Method | Accuracy |
|---------|-----------------|----------|
| BOOL_MASK | `clrlwi`/`rlwinm` with bit positions 24/31 | High |
| LINKER_MERGED | Symbol name contains `merged_` | High |
| REGISTER_SWAP | Consistent register differences (3+ occurrences) | High |
| CONTROL_FLOW | Branch instruction differences | Medium |

#### Fragility Issues Found

1. **Bool mask (FIXED)**: Used `args.contains(", 24")` which failed on hex format. Now uses TypedArg.

2. **Register swap threshold**: Requires `MIN_REGISTER_SWAP_OCCURRENCES = 3`. Small functions with only 2 swap occurrences are missed.
   - **Recommendation**: Scale threshold based on function size

#### Missing Patterns

| Pattern | Description | Difficulty | Status |
|---------|-------------|------------|--------|
| INSTRUCTION_REORDERING | Same instructions in different order | High | Deferred |
| COMMUTATIVE_OP_ORDER | `fmuls f0, f13, f0` vs `fmuls f0, f0, f13` | Medium | ✅ Implemented |
| STRUCT_ACCESS_ORDER | Different order of accessing struct members | Medium | Not started |
| OFFSET_SWAP | Two offsets swapped (e.g., `0x4 <-> 0x8`) | Low | ✅ Implemented |

#### Missing Information for AI Agents

1. **No explicit diff breakdown**: For `diff_arg`, what specifically differs?
   - Register difference? (`r29` vs `r30`)
   - Immediate difference? (`0x118` vs `0xf4`)
   - Symbol difference?

2. **No semantic grouping**: `diff_arg` on a symbol reference vs `diff_arg` on an immediate value need different fixes

3. **No relocation context**: When args differ, is it a different symbol, immediate, or register?

**Recommended Enhancement**:
```json
{
  "diff_breakdown": {
    "register_diff": {"target": "r29", "base": "r30"},
    "immediate_diff": null,
    "symbol_diff": null
  }
}
```

---

### 4. DWARF/Source Line Mapping

**Source**: Agent ae3e409 (dwarf-source-mapping.md)

**Key Finding**: objdiff already has comprehensive DWARF support via gimli crate.

#### What's Already Implemented

| Format | Support |
|--------|---------|
| DWARF 1.1 | `.line` sections |
| DWARF 2+ | gimli crate |
| COFF | Line number records |
| MIPS mdebug | `.mdebug` sections |

Line numbers are stored in `Section.line_info: BTreeMap<u64, u32>` and exposed in:
- GUI display
- Proto/JSON bindings (`line_number` field in `DiffInstruction`)

#### What's Missing: Source File Names

Source file names are NOT currently exposed but are available in gimli:
```rust
row.file()          // -> Option<FileIndex>
program.header().file(file_index)  // -> FileEntry with path_name
```

#### Recommended Implementation (Option C)

Add to proto/JSON bindings only (~50-100 lines):

1. For DWARF objects: Extract file name from line program
2. For COFF/others: Use the unit's `source_path` from config metadata
3. Add field to protobuf: `optional string source_file = 8;`
4. Expose in JSON output

**Files to modify**:
- `objdiff-core/protos/diff.proto` - Add field
- `objdiff-core/src/bindings/diff.rs` - Extract file info
- `objdiff-core/src/obj/dwarf2.rs` - File extraction helper
- `objdiff-cli/src/cmd/diff.rs` - JSON output

**Effort**: Low
**Value**: High - enables correlating assembly to C source lines

---

### 5. Data Diff Analysis

**Source**: Agent aaa82e2 (data-diff.md)

**Recommendation**: Minimal implementation is sufficient

#### Mismatch Types in Practice

| Type | Actionable? | Notes |
|------|-------------|-------|
| Vtable order | Partially | Need class hierarchy knowledge |
| Struct padding | No | Compiler-specific |
| String literals | Yes | Usually typos |
| Global init values | Yes | Check initializers |

#### Recommendation

- **Option A (Size only)**: Just show data section size differences
- **Option B (Size + relocation count)**: Slightly more useful
- **Options C/D (Byte-level)**: Overkill for agent workflows

Full byte-level data diffs are NOT actionable for AI agents without additional context about struct layouts and vtables.

**Priority**: Low

---

### 6. Real Workflow Test Results

**Source**: Agent a5c0df7 (workflow-test.md)

#### Test Case: `Curl_do_more` (98% match)

**Mismatches identified**:
1. `stw r10, 0x118(r11)` vs `stw r10, 0xf4(r11)` - Struct offset wrong
2. `cmplw cr6, r11, r10` vs `cmpw cr6, r11, r10` - Signed vs unsigned comparison
3. `stw r11, 0xf4(r10)` vs `stw r11, 0xd0(r10)` - Struct offset wrong

#### Actionability Assessment

| Issue | Actionable? | Why |
|-------|-------------|-----|
| Signed/unsigned comparison | **Yes** | Agent knew to cast operands to unsigned |
| Struct offset differences | **No** | Cannot determine which field or what padding changes needed |

**Key Quote**:
> "The unsigned comparison issue was actionable - I knew exactly what to try. The struct offset issues were NOT actionable without additional reverse engineering."

#### What Would Have Helped

1. **Source line mapping**: "Instruction at index 20 corresponds to line 5294 of url.c"
2. **Struct layout info**: "Offset 0x118 is field `chunk` in `SingleRequest`"
3. **Type-aware suggestions**: "Target uses unsigned comparison (cmplw), check if operands should be cast to unsigned"

---

## Open Questions

### 1. Where Should Header Parsing Live?

**Options**:
- A) In objdiff-cli as a new flag (`--struct-headers <path>`)
- B) In dc3-decomp as a separate tool that post-processes objdiff output
- C) In analyze-function as part of its orchestration

**Considerations**:
- Header parsing is project-specific (dc3-decomp format)
- objdiff should remain decomp-agnostic
- analyze-function already merges multiple data sources

**Leaning toward**: Option B or C - keep objdiff general, add dc3-decomp tooling

### 2. Should Pattern Detection Be Extensible?

Currently patterns are hardcoded in `analysis.rs`. Should we support:
- User-defined patterns via config?
- Architecture-specific pattern plugins?
- This may be over-engineering for current needs

### 3. How to Handle Architecture-Specific Patterns?

Some patterns are PPC-specific (e.g., `clrlwi` for bool mask). Should we:
- Keep hardcoded arch-specific logic in analysis.rs?
- Move to objdiff-core with arch abstraction?
- Let external tools handle arch-specific interpretation?

---

## Implementation Status

### Completed (Phases 1-4)

| Feature | Phase | Status |
|---------|-------|--------|
| TypedArg enum with typed instruction arguments | 1 | ✅ Complete |
| branch_dest for architecture-agnostic branch detection | 1 | ✅ Complete |
| Source file mapping (line_number, source_file) | 2 | ✅ Complete |
| Explicit diff breakdown (ArgumentDiff, diff_breakdown) | 3 | ✅ Complete |
| COMMUTATIVE_OP_ORDER pattern detection | 4 | ✅ Complete |
| OFFSET_SWAP pattern detection | 4 | ✅ Complete |

### Deferred

| Feature | Reason |
|---------|--------|
| INSTRUCTION_REORDERING pattern | Complex - requires comparing full instruction sequences |

---

## Phase 5: Struct Offset Resolution (dc3-decomp)

**Goal**: Enable AI agents to understand struct offset mismatches like `0x118` vs `0xf4`.

**Location**: This phase is implemented in dc3-decomp repo, not objdiff.

### Phase 5a: Header Parsing Tool

Parse dc3-decomp's annotated header files to build a struct offset database.

**Input**: Header files with offset comments:
```cpp
class Game : public Hmx::Object {
    SongPos mSongPos;    // 0x30
    SongDB *mSongDB;     // 0x48
    HamMaster *mMaster;  // 0x50
};
```

**Output**: Lookup table `(class_name, offset) -> field_name`

**Implementation**:
1. Regex to extract: `(\w+)\s+(\w+);\s*//\s*(0x[0-9a-fA-F]+)`
2. Build hierarchical class database (handle inheritance)
3. CLI tool or library that objdiff/analyze-function can query
4. Integration with `tools/analyze_function.py`

**Files to create/modify in dc3-decomp**:
- `tools/struct_db.py` - Header parser and database
- `tools/analyze_function.py` - Integration to resolve offsets

### Phase 5b: Ghidra MCP Struct Tools

Add MCP tools to query Ghidra's type database for struct resolution.

**New tools for `pyghidra-mcp-fork/pyghidra_mcp/tools.py`**:

```python
def resolve_struct_field(address: str, offset: int) -> FieldInfo:
    """Given an address and offset, return the struct field being accessed."""

def get_stack_frame(function_name: str) -> List[StackVariable]:
    """Get all stack variables for a function."""

def get_data_type(type_name: str) -> StructDefinition:
    """Get full struct definition with fields and offsets."""

def find_structs_with_offset(offset: int, size: int = 4) -> List[StructMatch]:
    """Find all structs that have a field at the given offset."""
```

### Phase 5c: analyze-function Integration

Update `tools/analyze_function.py` to:
1. When objdiff reports offset mismatch, query struct_db or Ghidra
2. Include field names in the diff output
3. Provide actionable suggestions: "Offset 0x118 is `Game::unk118`, expected `Game::mShuttle` at 0xf4"

### Phase 5d: Orchestrator MCP Integration ✅

Added `run_analyze_function` tool to `scripts/orchestrator/mcp_server.py`:

```python
Tool(
    name="run_analyze_function",
    description="Run enriched function analysis with struct offset resolution.",
    inputSchema={
        "properties": {
            "symbol": {"type": "string"},
            "resolve_offsets": {"type": "boolean", "default": true},
            "output_format": {"type": "string", "enum": ["markdown", "json"]},
        },
        "required": ["symbol"],
    },
)
```

This exposes the struct offset resolution to orchestrated agents via MCP.

---

## Phase 6: Advanced Pattern Detection (objdiff - Future)

Lower priority improvements to objdiff pattern detection.

| Pattern | Description | Effort | Value |
|---------|-------------|--------|-------|
| INSTRUCTION_REORDERING | Same instructions in different order | High | Medium |
| STRUCT_ACCESS_ORDER | Different order of struct member access | Medium | Medium |
| Data diff (sizes) | Report data section size differences | Low | Low |
| Register swap scaling | Scale threshold by function size | Low | Low |

---

## File Reference

### objdiff Files Modified (Phases 1-4)

| File | Changes |
|------|---------|
| `objdiff-cli/src/cmd/diff.rs` | TypedArg enum, InstructionInfo extension, ArgumentDiff, diff_breakdown |
| `objdiff-cli/src/cmd/analysis.rs` | 7 pattern detectors, improved suggestions, 30 tests |

### dc3-decomp Files to Create/Modify (Phase 5)

| File | Purpose |
|------|---------|
| `tools/struct_db.py` | Header parser and struct offset database |
| `tools/analyze_function.py` | Integration with struct_db and Ghidra |
| `pyghidra-mcp-fork/pyghidra_mcp/tools.py` | New MCP tools for struct resolution |

### objdiff Files to Modify (Phase 6 - Future)

| File | Purpose |
|------|---------|
| `objdiff-core/protos/diff.proto` | Add source_file field |
| `objdiff-core/src/bindings/diff.rs` | Extract file info from DWARF |
| `objdiff-core/src/obj/dwarf2.rs` | File extraction helper |

### dc3-decomp Files (Reference)

| File | Purpose |
|------|---------|
| `tools/analyze_function.py` | Orchestrator merging objdiff + Ghidra |
| `tools/pyghidra-mcp-fork/pyghidra_mcp/tools.py` | MCP tool implementations |
| `bin/orchestrate` | Multi-agent decompilation pipeline |
| `docs/tools/WORKFLOW.md` | Tool usage documentation |

---

## Research Document Index

All detailed research is available in `docs/research/`:

| Document | Agent | Summary |
|----------|-------|---------|
| `ghidra-integration.md` | a0ca7e4 | Keep Ghidra separate, enhance MCP tools |
| `struct-offsets.md` | ac95612 | Three-tier solution (headers → Ghidra → DWARF) |
| `data-diff.md` | aaa82e2 | Minimal implementation sufficient |
| `dwarf-source-mapping.md` | ae3e409 | Low effort, high value source file mapping |
| `implementation.md` | ae50d2b | TypedArg implementation summary |
| `pattern-detection-audit.md` | ab501a4 | Accuracy assessment and gaps |
| `workflow-test.md` | a5c0df7 | Real test with Curl_do_more at 98% |
