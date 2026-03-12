# DWARF/Source Line Mapping Research

*Agent ID: ae3e409*

---

I now have all the information needed to write a comprehensive feasibility report. Let me summarize my findings.

---

# Feasibility Report: DWARF/Source Line Mapping for objdiff

## Executive Summary

**objdiff already has comprehensive source line number support built-in.** The infrastructure for parsing and displaying line numbers is complete. Extending this to include source file names is feasible with **low-to-medium complexity**.

---

## 1. Current DWARF Support in objdiff

### 1.1 What's Already Implemented

objdiff-core already parses line number information from multiple debug formats:

| Format | File | Description |
|--------|------|-------------|
| **DWARF 1.1** | `/home/free/code/milohax/objdiff/objdiff-core/src/obj/read.rs:713` | Parses `.line` sections (lines 713-741) |
| **DWARF 2+** | `/home/free/code/milohax/objdiff/objdiff-core/src/obj/dwarf2.rs` | Uses gimli crate (lines 10-51) |
| **COFF** | `/home/free/code/milohax/objdiff/objdiff-core/src/obj/read.rs:744` | Parses COFF line number records (lines 744-867) |
| **MIPS mdebug** | `/home/free/code/milohax/objdiff/objdiff-core/src/obj/mdebug.rs` | Parses `.mdebug` sections for MIPS objects |

### 1.2 How Line Info is Stored

Line information is stored as a `BTreeMap<u64, u32>` in each `Section`:

```rust
// From /home/free/code/milohax/objdiff/objdiff-core/src/obj/mod.rs:83
pub struct Section {
    // ...
    /// Line number info (.line or .debug_line section)
    pub line_info: BTreeMap<u64, u32>,  // address -> line number
    // ...
}
```

### 1.3 Where Line Info is Exposed

1. **GUI Display** (`/home/free/code/milohax/objdiff/objdiff-core/src/diff/display.rs:180`):
   ```rust
   if let Some(line) = resolved.section.line_info.range(..=ins_ref.address).last().map(|(_, &b)| b) {
       cb(DiffTextSegment { text: DiffText::Line(line), color: DiffTextColor::Dim, pad_to: 5 })?;
   }
   ```

2. **Proto/JSON Bindings** (`/home/free/code/milohax/objdiff/objdiff-core/src/bindings/diff.rs:185-199`):
   ```rust
   let line_number = resolved
       .section
       .line_info
       .range(..=resolved.ins_ref.address)
       .last()
       .map(|(_, &line)| line);
   ```

3. **Protobuf Schema** (`/home/free/code/milohax/objdiff/objdiff-core/protos/diff.proto:82`):
   ```protobuf
   message DiffInstruction {
     // ...
     optional uint32 line_number = 7;  // Already present!
   }
   ```

---

## 2. Crates and APIs

### 2.1 Currently Used

- **`gimli`** (git rev 7335f00e7c39) - Already used for DWARF 2+ parsing
- **`object`** (v0.37) - Object file parsing, provides relocation support for DWARF

### 2.2 Available in gimli for Source File Names

The `gimli` crate provides full access to source file information through the line program. In the current code (`dwarf2.rs`), the `row` object (of type `gimli::LineRow`) has access to:

```rust
// Already available but not used:
row.file()          // -> Option<FileIndex>
row.line()          // -> Option<u64> (currently used)
row.column()        // -> Option<u64>

// To get the actual file name:
program.header().file(file_index)  // -> Option<FileEntry>
file_entry.path_name()             // -> AttributeValue (contains filename)
file_entry.directory()             // -> Option<DirectoryIndex>
```

The DWARF line program header contains file and directory tables that map indices to actual paths.

### 2.3 Alternative Crate: addr2line

The `addr2line` crate (built on top of `gimli`) provides a higher-level API:

```rust
use addr2line::Context;

let context = Context::new(object)?;
let location = context.find_location(address)?;
// location.file, location.line, location.column
```

This is simpler but adds another dependency and may have more overhead than the current approach.

---

## 3. Implementation Complexity

### 3.1 Option A: Extend Current line_info to Include File Names

**Complexity: Medium**

Changes needed:
1. Modify `Section.line_info` from `BTreeMap<u64, u32>` to `BTreeMap<u64, LineInfo>` where:
   ```rust
   pub struct LineInfo {
       pub line: u32,
       pub file: Option<String>,  // or interned index
       pub column: Option<u32>,
   }
   ```

2. Update `dwarf2.rs` to extract file names from the line program header
3. Update display code and bindings

**Pros:**
- Clean integration with existing architecture
- No new dependencies

**Cons:**
- Breaking change to Section structure
- Higher memory usage if file paths are stored per-instruction

### 3.2 Option B: Per-Unit Source File Info

**Complexity: Low**

For decompilation projects, each object file typically corresponds to a single source file. Instead of per-instruction file info:

1. Store source file path at the unit/object level (already partially done via `source_path` in config)
2. Use existing `line_number` field as-is
3. Combine with config's `source_path` in CLI output

**Pros:**
- Minimal changes
- Memory efficient
- Works well for typical decomp workflow

**Cons:**
- Doesn't handle inlined functions from other files
- Requires config to be available at diff time

### 3.3 Option C: Add Source File to Proto/JSON Only

**Complexity: Low**

Add source file extraction to the binding layer only:

1. Extract file info when building `DiffInstruction`
2. Add `optional string source_file = 8;` to protobuf
3. Leave internal `line_info` unchanged (still just line numbers)

**Pros:**
- Non-breaking for internal APIs
- Only affects serialization layer
- Can be done incrementally

**Cons:**
- Duplicates some parsing logic
- Not available for GUI until Section changes

---

## 4. Is DWARF Data Available in dc3-decomp?

Based on the file type check, dc3-decomp object files are COFF format (Xbox 360 toolchain). The current COFF line number parsing in objdiff (`parse_line_info_coff`) handles this format. COFF line numbers don't include file names - they're section-relative.

For dc3-decomp specifically:
- The `source_path` is already available in objdiff.json metadata
- Line numbers would come from COFF debug info (if compiled with `/Zi`)
- Source file can be inferred from config rather than parsed from debug info

---

## 5. Recommended Approach

### Short Term (for current iteration)

**Option C: Add to Proto/JSON Bindings Only**

1. For DWARF objects: Extract file name from line program in `DiffInstruction::new()`
2. For COFF/others: Use the unit's `source_path` from config metadata
3. Add field to protobuf: `optional string source_file = 8;`
4. Expose in JSON output

This can be done in ~50-100 lines of new code.

### Medium Term (future iteration)

Consider Option A if there's need for:
- Showing inlined function source files
- Per-instruction file names in GUI
- Better handling of header file line mappings

---

## 6. Summary

| Question | Answer |
|----------|--------|
| Is DWARF parsing available? | **Yes** - gimli already integrated |
| Is line number info exposed? | **Yes** - in GUI, proto, and JSON |
| Is source file info exposed? | **No** - but feasible to add |
| Implementation complexity | **Low** (bindings only) to **Medium** (full integration) |
| Recommended for now? | **Yes** - Option C (bindings extension) |
| Should defer? | **No** - quick win with existing infrastructure |

---

## 7. Code References

Key files to modify for source file support:

1. **Proto schema**: `/home/free/code/milohax/objdiff/objdiff-core/protos/diff.proto`
2. **Binding implementation**: `/home/free/code/milohax/objdiff/objdiff-core/src/bindings/diff.rs`
3. **DWARF parser** (for file extraction): `/home/free/code/milohax/objdiff/objdiff-core/src/obj/dwarf2.rs`
4. **CLI JSON output**: `/home/free/code/milohax/objdiff/objdiff-cli/src/cmd/diff.rs`