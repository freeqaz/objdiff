# Struct Offset Solutions Research

*Agent ID: ac95612*

---

---

# Research Report: Struct Offset Diff Problem in objdiff

## Executive Summary

When objdiff shows instruction diffs like `stw r10, 0x118, r11` vs `stw r10, 0xf4, r11`, the agent currently lacks the ability to determine which struct is being accessed and which field the offset corresponds to. This research evaluates available solutions ranging from simple heuristics to full-fledged integration with reverse engineering tools.

---

## 1. Current State of objdiff

### Existing Capabilities

**DWARF Support (Limited)**
- Location: `/home/free/code/milohax/objdiff/objdiff-core/src/obj/dwarf2.rs`
- Currently only extracts **line number information** from DWARF debug sections
- Uses `gimli` crate for DWARF parsing
- Does NOT extract type information, struct layouts, or member offsets

**Pattern Detection**
- Location: `/home/free/code/milohax/objdiff/objdiff-cli/src/cmd/analysis.rs`
- Detects patterns like:
  - Linker-merged functions (unfixable)
  - Bool mask patterns
  - Register swaps
  - Comparison style differences
  - Control flow differences
- Does NOT have any struct offset pattern detection

**No Struct Handling**
- objdiff-core has no concept of struct types or member layouts
- No parsing of header files
- No integration with external type databases

---

## 2. Available Solutions

### Solution A: Heuristics-Based Approach (Simplest)

**Concept**: Use offset arithmetic and context clues to infer struct information.

**Implementation Ideas**:
1. **Offset Position Heuristic**
   - "Offset 0x118 (280 bytes) into a struct suggests field is ~70% through the layout"
   - Can estimate struct size from surrounding load/store patterns

2. **Pattern Recognition**
   - Common offset patterns: 0x0 (vtable), 0x4 (first member after vtable)
   - Alignment boundaries: fields at 4/8/16 byte alignments
   - Detect related offsets in same function (e.g., 0x10, 0x14, 0x18 suggest sequential 4-byte fields)

3. **Context from Function Name**
   - If function is `Game::Poll()`, the struct is likely `Game`
   - Parse demangled names to extract class names

**Feasibility**: High - can be implemented entirely within objdiff
**Effort**: Low-Medium
**Accuracy**: Low - cannot definitively identify struct/field names

### Solution B: Header File Parsing (Medium Complexity)

**Concept**: Parse C++ header files to build a struct offset database.

**Evidence from dc3-decomp**:
The decomp project already has manually annotated struct definitions:
```cpp
// /home/free/code/milohax/dc3-decomp/src/lazer/game/Game.h
class Game : public Hmx::Object, public SkeletonCallback {
    SongPos mSongPos; // 0x30
    SongDB *mSongDB; // 0x48
    SongInfo *mSongInfo; // 0x4c
    HamMaster *mMaster; // 0x50
    GameInput *mGameInput; // 0x54
    ...
    ObjPtr<MoveDir> mMoveDir; // 0x7c
    Shuttle *mShuttle; // 0x94
};
```

**Implementation**:
1. Parse header files for struct/class definitions
2. Extract member names and their commented offset annotations
3. Build offset -> (struct, field) lookup table
4. Match instruction offsets against this database

**Feasibility**: High - data already exists
**Effort**: Medium
**Accuracy**: High for annotated fields, none for missing annotations

### Solution C: DWARF Debug Info Extraction (Medium-High Complexity)

**Concept**: Extract struct layouts from DWARF `.debug_info` sections.

**Technical Details**:
- DWARF uses `DW_TAG_structure_type` / `DW_TAG_class_type` for struct definitions
- `DW_TAG_member` entries contain:
  - `DW_AT_name` - field name
  - `DW_AT_data_member_location` - offset from struct base
  - `DW_AT_type` - reference to field type

**Current objdiff gimli Usage**:
```rust
// /home/free/code/milohax/objdiff/objdiff-core/src/obj/dwarf2.rs
let dwarf = gimli::Dwarf::load(...);
// Currently only processes line_program for address->line mapping
```

**Required Extensions**:
1. Iterate over compilation units
2. Find `DW_TAG_structure_type` entries
3. Extract member names and offsets
4. Build struct layout database

**Challenge**: Debug object files may not have DWARF info (stripped for release, or using other formats like CodeView/PDB for MSVC)

**Feasibility**: Medium - depends on whether debug info is available
**Effort**: Medium-High
**Accuracy**: Very High when DWARF is present

### Solution D: Ghidra Integration (High Complexity)

**Concept**: Use Ghidra's analysis capabilities to provide struct information.

**Existing Infrastructure**:
The dc3-decomp project already has `pyghidra-mcp-fork`:
- Location: `/home/free/code/milohax/dc3-decomp/tools/pyghidra-mcp-fork/`
- Provides: Function lookup, decompilation, symbol search, cross-references
- Does NOT currently provide: Struct/type queries

**Ghidra Capabilities**:
1. **Data Type Manager**: Stores all type definitions
2. **Auto-Analysis**: Can infer struct layouts from access patterns
3. **Type Propagation**: Tracks types through code flow
4. **API for Queries**: `getDataTypeManager().getDataType(path)`

**New Tool Needed**:
```python
def get_struct_at_offset(struct_name: str, offset: int) -> FieldInfo:
    """Query Ghidra for what field is at a given offset in a struct."""
    dtm = program.getDataTypeManager()
    struct_type = dtm.getDataType(f"/{struct_name}")
    component = struct_type.getComponentAt(offset)
    return FieldInfo(
        name=component.getFieldName(),
        type=component.getDataType().getName(),
        offset=component.getOffset(),
        size=component.getLength()
    )
```

**Integration Approach**:
1. Add new MCP tool: `get_struct_field_at_offset`
2. objdiff exports offset mismatches
3. Agent queries Ghidra via MCP for struct field info
4. Agent receives "offset 0x118 in Game is field `unk118`"

**Feasibility**: High - Ghidra already loaded with target binary
**Effort**: Medium (new MCP tool) + Low (agent prompt changes)
**Accuracy**: Very High

### Solution E: PDB/CodeView Support (MSVC-specific)

**Current State**: objdiff has no PDB support

**Concept**: For MSVC-compiled binaries, parse PDB files for type information.

**Challenges**:
- PDB format is complex and partially undocumented
- Requires separate tooling (pdb crate, cv2pdb, etc.)
- Only applicable to Windows/MSVC targets

**Feasibility**: Medium
**Effort**: High
**Accuracy**: Very High for MSVC binaries

---

## 3. Feasibility Assessment

| Solution | Effort | Accuracy | Dependencies | Recommended |
|----------|--------|----------|--------------|-------------|
| A. Heuristics | Low | Low | None | Yes (baseline) |
| B. Header Parsing | Medium | High* | Header files | Yes |
| C. DWARF Extraction | Medium-High | Very High* | Debug symbols | Conditional |
| D. Ghidra Integration | Medium | Very High | Ghidra + MCP | **Yes** |
| E. PDB Support | High | Very High* | PDB files | No (scope) |

*\* When data is available*

---

## 4. Recommended Approach

### Tier 1: Implement Header Parsing (Quick Win)

**Why**: The dc3-decomp project already has annotated headers with offset comments.

**Implementation**:
1. Create a parser for C++ headers that extracts offset comments
2. Build a lookup table: `(class_name, offset) -> field_name`
3. When objdiff reports an offset mismatch, look up both offsets
4. Report: "Offset 0x118 is `Game::unk118`, 0xf4 is `Game::unk94`"

**Example Output**:
```
stw r10, 0x118(r11)  vs  stw r10, 0xf4(r11)
        |                        |
        v                        v
   Game::unk118            Game::mShuttle (0x94)
   (unknown field)         (Shuttle*)
   
Suggestion: You may have a missing field or wrong field sizes
between Game::mShuttle (0x94) and this access (0x118).
```

### Tier 2: Add Ghidra MCP Tool (Most Powerful)

**Why**: Ghidra has the complete type database from analysis.

**Implementation**:
1. Add `get_struct_layout` tool to pyghidra-mcp
2. Add `find_struct_by_access_pattern` tool
3. Update agent prompt to use these tools when offset mismatches are detected

**New MCP Tools**:
```python
# Tool 1: Get struct layout
def get_struct_layout(struct_name: str) -> StructLayout:
    """Returns all fields with their offsets."""

# Tool 2: Find struct by offset pattern  
def find_structs_with_offset(offset: int, size: int = 4) -> List[StructMatch]:
    """Find all structs that have a field at the given offset."""

# Tool 3: Infer struct from register
def get_inferred_type_at_address(address: int, register: str) -> TypeInfo:
    """What type does Ghidra think this register holds?"""
```

### Tier 3: DWARF Enhancement (Optional)

**Why**: Provides accurate struct info when debug symbols are present.

**When to Implement**: If decomp builds include DWARF info.

---

## 5. Is Ghidra Necessary?

**Short Answer**: Not strictly necessary, but highly valuable.

**Without Ghidra**:
- Header parsing can provide 80% of the value
- Heuristics can provide contextual hints
- Manual annotation workflow already exists

**With Ghidra**:
- Can query arbitrary struct layouts
- Can infer types from code patterns
- Handles cases where headers are incomplete
- Single source of truth (the analyzed binary)

**Recommendation**: Start with header parsing, add Ghidra integration when the workflow is validated.

---

## 6. Specific Implementation Plan

### Phase 1: Header-Based Struct Database (1-2 days)

1. Create `StructDatabase` module in objdiff-cli
2. Parse header files for offset annotations:
   ```regex
   (\w+)\s+(\w+);\s*//\s*(0x[0-9a-fA-F]+)
   ```
3. Add `--struct-headers` flag to objdiff diff command
4. Enhance analysis output with field name hints

### Phase 2: Pattern Detection Enhancement (1 day)

1. Add `StructOffsetMismatch` pattern to analysis.rs
2. Detect when same opcode differs only in offset
3. Calculate offset difference: `0x118 - 0xf4 = 0x24 (36 bytes)`
4. Report: "36-byte offset shift suggests 9 missing 4-byte fields"

### Phase 3: Ghidra Integration (2-3 days)

1. Add struct query tools to pyghidra-mcp
2. Update CLAUDE.md with struct analysis workflow
3. Test on real decomp cases

---

## 7. Conclusion

The struct offset diff problem is solvable through multiple complementary approaches:

1. **Simplest**: Parse existing header comments (already available in dc3-decomp)
2. **Most Powerful**: Query Ghidra via MCP (infrastructure exists)
3. **Most Portable**: Extend DWARF parsing in gimli (when debug info available)

Ghidra is **valuable but not necessary** for basic struct offset diagnosis. The recommended path is:
1. Start with header parsing (quick, accurate for known structs)
2. Add Ghidra integration (handles unknown cases)
3. Add DWARF support if needed (depends on build configuration)