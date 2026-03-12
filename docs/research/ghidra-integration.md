# Ghidra Integration Research

*Agent ID: a0ca7e4*

---

Now I have a comprehensive understanding of the system. Let me write the recommendation report.

---

# Ghidra Integration Options for objdiff - Recommendation Report

## Executive Summary

After investigating the dc3-decomp codebase, I found a well-established Ghidra integration through pyghidra-mcp that provides decompilation and cross-references. The current architecture uses `analyze-function` as a thin orchestration layer that combines objdiff-cli output with Ghidra MCP queries. This report evaluates three integration approaches and recommends **Option C (keep them separate)** with targeted enhancements to objdiff's analysis capabilities.

---

## 1. Current Integration Architecture

### analyze-function Script (`/home/free/code/milohax/dc3-decomp/tools/analyze_function.py`)

The analyze-function script is a Python-based orchestrator that:

1. **Runs objdiff** via subprocess with incremental build support
2. **Connects to Ghidra MCP** server (HTTP JSON-RPC on port 8000)
3. **Merges results** into unified markdown or JSON output

Key components:
- `MCPClient` class: JSON-RPC 2.0 client for Ghidra MCP server
- `run_objdiff()`: Subprocess wrapper with ninja incremental builds
- `format_markdown()`/`format_json()`: Output formatters

### Ghidra MCP Server (`/home/free/code/milohax/dc3-decomp/tools/pyghidra-mcp-fork/`)

The pyghidra-mcp-fork provides these tools via MCP protocol:

| Tool | Data Provided |
|------|---------------|
| `decompile_function` | Pseudo-C code from Ghidra's decompiler |
| `search_symbols_by_name` | Symbol lookup with address resolution |
| `list_cross_references` | Function callers and callees |
| `search_functions_by_name` | Function discovery |
| `list_exports`/`list_imports` | Binary interface information |

### DirectGhidraClient (`/home/free/code/milohax/dc3-decomp/tools/ghidra/direct_client.py`)

A direct Python-to-Java bridge (no HTTP) used by the orchestrator for faster access:
- Lazy JVM initialization with pyghidra
- Multi-strategy symbol lookup (mangled, demangled, address-based)
- Singleton pattern for instance reuse

### Context Collector (`/home/free/code/milohax/dc3-decomp/scripts/orchestrator/context_collector.py`)

Pre-computes context for AI-driven decompilation:
- Runs objdiff with incremental build
- Queries Ghidra for decompilation + xrefs
- Retrieves previous attempt history from database
- Finds RB3 reference implementations
- Writes cross-reference files to worktree

---

## 2. Available Ghidra Data

Based on analysis of `tools.py` and the MCP client, Ghidra can provide:

### Currently Used
1. **Decompiled pseudocode** - C-like representation of original binary
2. **Cross-references** - Callers (who calls this function) and callees (what this function calls)
3. **Symbol information** - Name, address, type, namespace, reference count

### Potentially Available (Not Yet Exposed)
4. **Data types** - Struct definitions, typedefs, enums from Ghidra's Data Type Manager
5. **Variable information** - Local variables, parameters, their types
6. **Memory references** - Data section references with resolved types
7. **High-level P-code** - Intermediate representation before decompilation
8. **Function signatures** - Return type, calling convention, parameters

---

## 3. Integration Approaches Analysis

### Option A: Enrich objdiff Output by Calling Ghidra MCP After objdiff Runs

**Description**: External Python/Node script that:
1. Runs objdiff-cli to get diff JSON
2. Extracts addresses/offsets from mismatches
3. Queries Ghidra MCP for type information at those addresses
4. Merges Ghidra data into enriched output

**Pros**:
- No changes to objdiff Rust codebase
- Flexible Python implementation
- Can evolve independently
- Easy to prototype

**Cons**:
- Two-pass processing adds latency
- Requires Ghidra MCP server running
- Data correlation is address-based (fragile)
- Duplication with existing analyze-function

**Complexity**: Low (Python scripting, HTTP calls)

### Option B: Add Ghidra Support Directly into objdiff-cli (Rust)

**Description**: Native Rust integration with Ghidra via:
- JNI bindings to Ghidra's Java APIs, or
- Embedded HTTP client for MCP, or
- Ghidra's headless analyzer

**Pros**:
- Single tool invocation
- Native performance
- Tight integration with diff logic
- Could query Ghidra during diff analysis

**Cons**:
- Significant Rust development effort
- JNI bindings are complex and error-prone
- Ghidra is GPL licensed (compatibility concerns)
- Increases objdiff's dependency footprint
- Couples objdiff to specific Ghidra versions
- objdiff is a general tool; Ghidra is decomp-specific

**Complexity**: Very High (Rust FFI, JVM management, GPL considerations)

### Option C: Keep Them Separate, Let analyze-function Merge

**Description**: Maintain current architecture with targeted improvements:
1. Enhance objdiff's JSON output with more structural information
2. Enhance Ghidra MCP tools to expose type/struct data
3. Improve analyze-function to correlate and merge

**Pros**:
- Minimal changes to working system
- Each tool remains focused and maintainable
- objdiff stays portable and decomp-agnostic
- Ghidra integration is optional
- Aligns with Unix philosophy (small tools, pipes)

**Cons**:
- User must run two tools (or use analyze-function)
- Some data correlation happens post-hoc

**Complexity**: Medium (incremental improvements to both tools)

---

## 4. How Ghidra Could Help Specific Problems

### Problem: Struct Offset Diffs (0x118 vs 0xf4)

**Current State**: objdiff shows `lwz r3, 0x118(r4)` vs `lwz r3, 0xf4(r4)` - user must manually determine struct/field.

**Ghidra Solution**: 
- Query Ghidra for data type at register r4's value
- If r4 contains struct pointer, Ghidra can resolve field name at offset
- Expose via new MCP tool: `resolve_struct_field(address, offset)`

**Implementation**:
```python
# New Ghidra tool
def resolve_struct_field(self, address: str, offset: int) -> dict:
    """Resolve struct field at address+offset"""
    dt = self.get_data_type_at(address)
    if dt and hasattr(dt, 'getComponentAt'):
        component = dt.getComponentAt(offset)
        return {"struct": dt.name, "field": component.name, "type": component.dataType.name}
```

### Problem: Signed/Unsigned Comparison Diffs

**Current State**: objdiff detects `cmpwi` vs `cmplwi` differences but cannot explain why.

**Ghidra Solution**:
- Query Ghidra for variable type at comparison operand
- Report: "Variable at r3 is `unsigned int` (Ghidra) but used as `int` in decomp"

**Implementation**: Requires Ghidra's high-level P-code or decompiler variable mapping.

### Problem: Stack Frame Layout Diffs

**Current State**: objdiff shows `stw r3, 0x20(r1)` vs `stw r3, 0x24(r1)` - unclear which local variable.

**Ghidra Solution**:
- Query Ghidra for function's stack frame layout
- Map offsets to local variable names
- Report: "Stack offset 0x20 is `localVar1` (int), 0x24 is `localVar2` (int)"

**Implementation**:
```python
def get_stack_frame(self, function_name: str) -> list:
    """Get stack frame variables for a function"""
    func = self.find_function(function_name)
    frame = func.getStackFrame()
    return [{"offset": var.offset, "name": var.name, "type": var.dataType.name}
            for var in frame.getStackVariables()]
```

---

## 5. Recommendation

### Recommended Approach: Option C with Enhancements

**Rationale**:

1. **objdiff's role**: objdiff is a general-purpose object diff tool used across many decomp projects. Adding Ghidra dependency would limit its portability and increase maintenance burden.

2. **Ghidra's role**: Ghidra integration is decomp-specific and benefits from Python's flexibility for rapid iteration.

3. **Existing infrastructure**: The analyze-function + MCP architecture already works. Enhancements are incremental.

4. **Separation of concerns**:
   - objdiff: "What instructions differ?"
   - Ghidra: "What do those addresses/offsets mean?"
   - analyze-function: "How do we fix it?"

### Proposed Enhancements

#### Phase 1: Enhance objdiff Output (Low Effort)

Already implemented in `/home/free/code/milohax/objdiff/objdiff-cli/src/cmd/analysis.rs`:
- Pattern detection (LINKER_MERGED, BOOL_MASK, REGISTER_SWAP, etc.)
- Verdict classification (AT_LIMIT, LIKELY_FIXABLE, etc.)
- Actionable suggestions

**Additional objdiff enhancements**:
- Include raw offset values in instruction diff (for Ghidra correlation)
- Include relocation symbol names when available
- Add `--include-data-refs` flag to show data section references

#### Phase 2: Enhance Ghidra MCP Tools (Medium Effort)

Add new MCP tools:
1. `resolve_struct_field(address, offset)` - Resolve struct field at offset
2. `get_stack_frame(function_name)` - Get local variable layout
3. `get_variable_type(function_name, address)` - Get variable type at instruction
4. `get_data_type(type_name)` - Get full struct definition

#### Phase 3: Enhance analyze-function Correlation (Medium Effort)

Update analyze-function to:
1. Parse objdiff's offset differences
2. Query Ghidra for struct/field information
3. Annotate diff output with resolved type names
4. Provide "expected struct" vs "actual struct" comparison

### Implementation Complexity

| Component | Effort | Files to Modify |
|-----------|--------|-----------------|
| objdiff: Add offset info | Low | `diff.rs` |
| Ghidra MCP: Add struct tools | Medium | `tools.py`, `models.py` |
| analyze-function: Correlation | Medium | `analyze_function.py` |
| **Total** | **2-3 weeks** | |

---

## 6. Specific File Locations

| Purpose | File Path |
|---------|-----------|
| analyze-function wrapper | `/home/free/code/milohax/dc3-decomp/bin/analyze-function` |
| analyze-function implementation | `/home/free/code/milohax/dc3-decomp/tools/analyze_function.py` |
| Ghidra MCP tools | `/home/free/code/milohax/dc3-decomp/tools/pyghidra-mcp-fork/pyghidra_mcp/tools.py` |
| Direct Ghidra client | `/home/free/code/milohax/dc3-decomp/tools/ghidra/direct_client.py` |
| Context collector | `/home/free/code/milohax/dc3-decomp/scripts/orchestrator/context_collector.py` |
| objdiff diff command | `/home/free/code/milohax/objdiff/objdiff-cli/src/cmd/diff.rs` |
| objdiff analysis | `/home/free/code/milohax/objdiff/objdiff-cli/src/cmd/analysis.rs` |

---

## Conclusion

The current architecture of separate tools (objdiff + Ghidra MCP + analyze-function) is well-designed and should be preserved. The recommendation is to enhance each component within its domain:

1. **objdiff**: Add more structural information to JSON output (offsets, relocations)
2. **Ghidra MCP**: Add type resolution tools (struct fields, stack frames, variable types)
3. **analyze-function**: Improve correlation between objdiff mismatches and Ghidra type data

This approach maintains objdiff's portability, leverages Python's flexibility for Ghidra integration, and provides a clear upgrade path without architectural rewrites.