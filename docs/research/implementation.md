# TypedArg Implementation Summary

*Agent ID: ae50d2b*

---

## Summary

I have successfully implemented the core objdiff CLI improvements for AI-assisted decompilation workflows. Here is what was implemented:

### What Was Implemented

#### Phase 1: Typed Args in JSON Output (`diff.rs`)

1. **New `TypedArg` enum** with the following variants:
   - `Signed(i64)` - Signed integer values
   - `Unsigned(u64)` - Unsigned integer values  
   - `Register(String)` - Opaque values that look like registers (r0-r31, f0-f31, cr0-cr7, sp, lr, ctr, xer)
   - `Symbol(String)` - Symbol references from relocations
   - `BranchDest(u64)` - Branch destination addresses
   - `Other(String)` - Other opaque values (labels, etc.)

2. **Extended `InstructionInfo` struct** with:
   - `typed_args: Option<Vec<TypedArg>>` - Typed arguments preserving type information
   - `branch_dest: Option<u64>` - Branch destination if this is a branch instruction

3. **Updated `build_instruction_info()`** to:
   - Convert `InstructionArg` from objdiff-core to `TypedArg` for JSON output
   - Use regex-based register detection for opaque values
   - Extract branch destination from instruction args

4. **Backward compatibility maintained**: The existing `args` string field is kept alongside the new typed fields.

#### Phase 2: Improved Pattern Detection (`analysis.rs`)

1. **`detect_bool_mask()` now uses typed args** when available:
   - For `clrlwi`: Checks if the 3rd typed arg is `Unsigned(24)` or `Unsigned(31)`
   - For `rlwinm`: Checks shift=0, mask_begin, mask_end values
   - Falls back to string matching for backward compatibility

2. **`detect_control_flow()` now uses `branch_dest`**:
   - First checks if instruction has `branch_dest.is_some()` (more accurate, architecture-agnostic)
   - Falls back to opcode-based `BRANCH_OPCODES` list for backward compatibility

#### Phase 3: More Specific Suggestions

1. **Control flow suggestions** now include specific instruction indices:
   - "Check branch at index 12, 45, 67 (+2 more)"

2. **Register swap suggestions** now show which registers are swapped:
   - "Register swap r30↔r31 at 4 location(s)"

#### Phase 4: New Pattern Detection & Diff Breakdown

1. **Source file mapping** added to `InstructionInfo`:
   - `line_number: Option<u32>` - Source line from DWARF/COFF
   - `source_file: Option<String>` - Source file path from DWARF/COFF

2. **Explicit diff breakdown** for `diff_arg` instructions:
   - `ArgumentDiff` struct with index, target, base, and diff_type
   - `diff_breakdown` field added to `InstructionDiffOutput`
   - Shows exactly which argument differs and how (register, immediate, symbol)

3. **New pattern detectors**:
   - `COMMUTATIVE_OP_ORDER`: Detects swapped operands in fadd/fmul/add/and/or/xor
   - `OFFSET_SWAP`: Detects symmetric offset swaps between instruction pairs

4. **Updated patterns_checked** list to include all 7 patterns

### Test Results

All 30 tests pass:
- Existing tests continue to work (backward compatibility verified)
- New tests for typed args functionality:
  - `test_detect_bool_mask_with_typed_args`
  - `test_detect_bool_mask_rlwinm_typed_args`
  - `test_detect_control_flow_with_branch_dest`
  - `test_typed_arg_methods`
- New tests for Phase 4 patterns:
  - `test_detect_commutative_op_order`
  - `test_detect_commutative_op_order_integer`
  - `test_detect_commutative_op_order_not_swapped`
  - `test_detect_commutative_op_order_non_commutative`
  - `test_detect_offset_swap`
  - `test_detect_offset_swap_negative`
  - `test_detect_offset_swap_not_symmetric`
  - `test_analyze_instructions_includes_all_patterns`

### Files Modified

1. **`/home/free/code/milohax/objdiff/objdiff-cli/src/cmd/diff.rs`** (+117 lines):
   - Added `TypedArg` enum with helper methods
   - Extended `InstructionInfo` struct
   - Added `convert_to_typed_arg()` function
   - Added `REGISTER_RE` regex for register detection
   - Updated `build_instruction_info()`

2. **`/home/free/code/milohax/objdiff/objdiff-cli/src/cmd/analysis.rs`** (+331/-56 lines):
   - Updated imports
   - Added helper functions: `check_clrlwi_bool_mask()`, `check_rlwinm_bool_mask()`
   - Updated `detect_bool_mask()` to use typed args
   - Added `is_branch_instruction()` helper
   - Updated `detect_control_flow()` to use `branch_dest`
   - Enhanced `compute_verdict()` with specific suggestions
   - Updated test helper functions and added new tests