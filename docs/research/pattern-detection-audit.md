# Pattern Detection Audit

*Agent ID: ab501a4*

---

Now I have gathered all the information needed. Let me write the comprehensive summary report.

---

# Objdiff Pattern Detection Accuracy Audit Report

## Executive Summary

The pattern detection and verdict system in objdiff-cli demonstrates **solid foundational accuracy** but has several areas that need improvement for reliable AI agent usage. Overall, the verdicts are directionally correct but sometimes miss nuances that would help an agent understand what to fix.

---

## Test Results

### Test 1: AT_LIMIT Function (Bool Mask Pattern)
**Function**: `RndMat::GetRefractEnabled`
**Expected**: AT_LIMIT verdict due to bool mask pattern
**Result**: **PASS**

```json
{
  "verdict": {
    "classification": "AT_LIMIT",
    "confidence": "high",
    "explanation": "Bool mask pattern detected - compiler bool return handling cannot be matched."
  }
}
```

**Findings**:
- BOOL_MASK pattern correctly detected with `confidence: "high"`
- Bit position 24 correctly identified
- The `clrlwi r3, r11, 24` instruction at index 33 is marked as "delete" (extra in target)
- The bool mask detection correctly finds the masking instruction that differs

**Instruction Evidence**:
```
Index 30: li r11, 0x1 (target) vs li r3, 0x1 (base) - diff_arg
Index 32: li r11, 0x0 (target) vs li r3, 0x0 (base) - diff_arg  
Index 33: clrlwi r3, r11, 24 (target only) - delete
```

---

### Test 2: COMPLETE Function (100% Match)
**Function**: `operator>>` in `default/system/os/File`
**Expected**: COMPLETE verdict
**Result**: **PASS**

```json
{
  "verdict": {
    "classification": "COMPLETE",
    "confidence": "high",
    "explanation": "Function matches 100%."
  }
}
```

**Findings**:
- Correctly identifies 0 mismatches
- 100% fuzzy_match_percent
- No patterns detected (expected)

---

### Test 3: LIKELY_FIXABLE Function (Control Flow)
**Function**: `PlatformMgr::SetDiskError`
**Expected**: LIKELY_FIXABLE
**Result**: **PASS** (but with concerns)

```json
{
  "verdict": {
    "classification": "LIKELY_FIXABLE",
    "confidence": "medium",
    "explanation": "6 control flow difference(s) detected with low merged ratio (0.0%)."
  }
}
```

**Findings**:
- CONTROL_FLOW pattern detected
- **Issue**: The instruction at index 0 shows `blr` vs `mflr` which appears to be a misalignment issue, not actual control flow difference
- 41.9% mismatch rate is high, but many are diff_arg (symbol name differences), not true semantic differences

---

### Test 4: MAYBE_FIXABLE Function (Register Swap)
**Function**: `UniqueFilename`
**Expected**: MAYBE_FIXABLE with register swap
**Result**: **PASS**

```json
{
  "verdict": {
    "classification": "MAYBE_FIXABLE",
    "confidence": "medium",
    "explanation": "9 register swap(s) detected. May be fixable by reordering variable declarations."
  }
}
```

**Findings**:
- REGISTER_SWAP pattern correctly detected
- Swap identified: `r29 <-> r30` with count 9
- Suggestion is actionable: "Reorder local variable declarations"
- The swap is consistent throughout the function

---

### Test 5: NEEDS_INVESTIGATION Function
**Function**: `Vector2DESmoother::ForceValue`
**Expected**: NEEDS_INVESTIGATION
**Result**: **PASS**

```json
{
  "verdict": {
    "classification": "NEEDS_INVESTIGATION",
    "confidence": "low",
    "explanation": "Mixed patterns detected - manual analysis recommended."
  }
}
```

**Findings**:
- Only 2 mismatched instructions
- No patterns detected (correct - they are reordering differences)
- Looking at the actual diff:
  - Index 7: `stfs f0, 0x8, r3` vs `stfs f13, 0x14, r3`
  - Index 9: `stfs f13, 0x14, r3` vs `stfs f0, 0x8, r3`
- This is an **instruction reordering pattern** that is NOT detected

---

### Test 6: NEEDS_INVESTIGATION (Box::Volume)
**Function**: `Box::Volume`
**Result**: NEEDS_INVESTIGATION

**Findings**:
- 5 diff_arg mismatches with 0 patterns detected
- Looking at the actual diff - these are **struct member access order differences**:
  - Target: loads `0x4, 0x14, 0x18, 0x8` 
  - Base: loads `0x8, 0x18, 0x14, 0x4`
- This represents a **different multiplication order** pattern that could potentially be detected

---

## Pattern Detection Analysis

### Working Well

1. **BOOL_MASK Detection**: Correctly identifies `clrlwi` with bit 24/31 patterns
2. **LINKER_MERGED Detection**: Accurately finds `merged_*` function calls
3. **REGISTER_SWAP Detection**: Properly identifies consistent register allocation differences
4. **CONTROL_FLOW Detection**: Finds branch instruction differences (diff_op/replace)

### Fragility Issues

1. **Bool Mask Detection Fragility**:
   - Uses `args.contains(", 24")` which would fail if:
     - Value is in hex: `", 0x18"` would NOT match
     - Different whitespace: `",24"` (no space) would NOT match
   - **Recommendation**: Use regex to extract numeric value robustly

2. **Register Swap Threshold**:
   - Requires `MIN_REGISTER_SWAP_OCCURRENCES = 3` to be considered significant
   - Small functions with only 2 swap occurrences are missed
   - **Recommendation**: Scale threshold based on function size

### Missing Patterns

1. **INSTRUCTION_REORDERING**: Two instructions swapped in order (Box::Volume, Vector2DESmoother)
2. **STRUCT_ACCESS_ORDER**: Different order of accessing struct members
3. **COMMUTATIVE_OP_ORDER**: `fmuls f0, f13, f0` vs `fmuls f0, f0, f13` (operand order)
4. **OFFSET_SWAP**: When two offsets are swapped (like `0x4 <-> 0x8`)

---

## Missing Information for AI Agent

### What's Present (Good)
- Match type for each instruction (equal, diff_arg, diff_op, etc.)
- Both target and base instruction info
- Pattern names and fixability classification
- Suggestions list

### What's Missing (Problematic)

1. **No Source Location Information**:
   - Cannot correlate instructions to C source lines
   - An AI cannot know which C statement caused the mismatch

2. **No Semantic Grouping**:
   - Diff_arg on a symbol reference vs diff_arg on an immediate value are very different
   - `diff_arg` on `bl SomeFunc` (function call) vs `diff_arg` on `addi r3, r31, 0x50` need different fixes

3. **No Relocation Context**:
   - When args differ, is it:
     - A different symbol reference?
     - A different immediate offset?
     - A different register?
   - This information exists in objdiff-core but isn't exposed in JSON

4. **No Surrounding Context**:
   - What pattern of instructions surrounds a mismatch?
   - Is this mismatch at function entry/exit? Inside a loop?

5. **No Diff Explanation**:
   - For `diff_arg`, what specifically differs?
   - Would help to show: `r29 vs r30` instead of just full args strings

---

## Actionability Assessment

### LIKELY_FIXABLE Suggestions

| Function | Suggestion | Actionable? |
|----------|------------|-------------|
| PlatformMgr::SetDiskError | "Check branch conditions and if/else structure" | **Vague** - doesn't tell which branch or what change to try |
| SkeletonChooser::IsSinglePlayerMode | "Check branch conditions" | **Vague** - same issue |

### MAYBE_FIXABLE Suggestions

| Function | Suggestion | Actionable? |
|----------|------------|-------------|
| UniqueFilename | "Reorder local variable declarations" | **Helpful** - clear action, but doesn't say which variables |
| singlesocket | Same | **Partially helpful** - swap details help (r20 <-> r21) |

### AT_LIMIT Suggestions

| Function | Suggestion | Actionable? |
|----------|------------|-------------|
| RndMat::GetRefractEnabled | None (recommendation: accept current match) | **Correct** - properly indicates no action possible |

---

## Verdict Accuracy Summary

| Classification | Functions Tested | Accurate? | Notes |
|----------------|------------------|-----------|-------|
| COMPLETE | 1 | Yes | Works correctly |
| AT_LIMIT | 1 | Yes | Bool mask properly detected |
| LIKELY_FIXABLE | 2 | Mostly | Sometimes too aggressive |
| MAYBE_FIXABLE | 2 | Yes | Register swap works |
| NEEDS_INVESTIGATION | 2 | Correct but unhelpful | Falls back when no pattern matches |

---

## Specific Bugs Found

1. **False positive control flow detection**: In `PlatformMgr::SetDiskError`, index 0 shows `blr` vs `mflr` which is a diff alignment issue, not a semantic control flow difference.

2. **Register swap under-reporting**: When only 1-2 occurrences exist, swaps are not reported even though they explain the mismatch.

3. **No pattern for reordering**: Common patterns like instruction reordering (same ops, different order) are not detected, leading to NEEDS_INVESTIGATION.

---

## Recommendations

### High Priority

1. **Add explicit diff breakdown** in JSON output:
   ```json
   {
     "diff_breakdown": {
       "register_diff": {"target": "r29", "base": "r30"},
       "immediate_diff": null,
       "symbol_diff": null
     }
   }
   ```

2. **Add INSTRUCTION_REORDERING pattern detection** for when the same instructions appear in different order.

3. **Make bool mask detection robust** using regex to extract numeric values, handling hex and varying whitespace.

### Medium Priority

4. **Add source location hints** if debug info is available.

5. **Lower register swap threshold** for small functions or make it proportional.

6. **Improve suggestions** to be more specific:
   - Instead of "Reorder local variable declarations"
   - Say "Try swapping declarations of the variable using r29 with the one using r30"

### Low Priority

7. **Add COMMUTATIVE_OP pattern** for operations like `fmuls f0, f13, f0` vs `fmuls f0, f0, f13`.

8. **Add confidence scoring** based on how much of the mismatch is explained by patterns.

---

## Conclusion

The pattern detection system is **functional and directionally accurate** but needs enhancements to be truly useful for automated AI-driven fixing:

- **Verdicts are correct** but often lack the specificity needed for automated fixes
- **Pattern detection is good** for major patterns (bool mask, merged functions, register swap)
- **Missing patterns** exist for common reordering/commutative differences
- **Suggestions are too generic** - they describe categories of fixes, not specific changes
- **Missing granular diff information** makes it hard for an AI to know what to change

For an AI agent to effectively use this data, the output needs to provide more structured breakdown of what exactly differs and potentially correlate with source code patterns.

---

## Summary

I have completed a thorough audit of the objdiff pattern detection and verdict system. Here are the key findings:

### Correctness Assessment

**Verdicts are generally accurate:**
- COMPLETE: Works correctly for 100% matches
- AT_LIMIT: Correctly identifies bool mask patterns as unfixable
- LIKELY_FIXABLE: Works but sometimes too aggressive (counts diff_op/replace without verifying semantic significance)
- MAYBE_FIXABLE: Register swap detection works well
- NEEDS_INVESTIGATION: Correct fallback but unhelpful

### Pattern Detection Assessment

**Working Patterns:**
1. **BOOL_MASK**: Correctly detects `clrlwi` with bit positions 24/31
2. **LINKER_MERGED**: Properly finds `merged_*` function calls
3. **REGISTER_SWAP**: Identifies consistent register allocation differences
4. **CONTROL_FLOW**: Finds branch instruction differences

**Fragility Issues Found:**
1. Bool mask uses `args.contains(", 24")` - would fail with hex (0x18) or different whitespace
2. Register swap requires 3+ occurrences - small functions under-detected

### Missing Information for AI Agents

The JSON output lacks:
1. Explicit breakdown of what differs (register vs immediate vs symbol)
2. Source location correlation
3. Semantic categorization of diff_arg (symbol ref vs offset vs register)
4. Context about where in the function the mismatch occurs

### Missing Patterns

1. **INSTRUCTION_REORDERING** - same instructions in different order
2. **COMMUTATIVE_OP_ORDER** - operand order in commutative operations
3. **STRUCT_ACCESS_ORDER** - different member access patterns

### Actionability Issues

Suggestions are too generic:
- "Check branch conditions and if/else structure" - doesn't specify which branch
- "Reorder local variable declarations" - doesn't identify which variables

### Key Files Examined

- `/home/free/code/milohax/objdiff/objdiff-cli/src/cmd/diff.rs` - Main diff command implementation
- `/home/free/code/milohax/objdiff/objdiff-cli/src/cmd/analysis.rs` - Pattern detection and verdict logic