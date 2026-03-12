# Data Diff Analysis Research

*Agent ID: aaa82e2*

---

## Summary

This agent investigated whether data symbol diff output would be valuable for AI-assisted decompilation.

## Key Findings

### 1. objdiff Already Has Data Diffing Infrastructure

The `objdiff-core` library has sophisticated data section comparison:
- Byte-level diffing with relocation awareness
- Data section matching in reports
- `include_data` flag exists but is not fully wired to CLI JSON output

### 2. Data Mismatches in Practice

From examining dc3-decomp:
- Most data mismatches are vtables or struct layout issues
- String literals usually match if source strings match
- Global variable initialization differences are rare

### 3. Actionability Assessment

| Mismatch Type | Actionable? | Notes |
|---------------|-------------|-------|
| Vtable order | Partially | Need class hierarchy knowledge |
| Struct padding | No | Compiler-specific |
| String literals | Yes | Usually typos |
| Global init values | Yes | Check initializers |

### 4. Recommendation

**Minimal implementation is sufficient:**

- Option A (Size only): Just show data section size differences
- Option B (Size + relocation count): Slightly more useful
- Option C/D (Byte-level or relocation diff): Overkill for agent workflows

Full byte-level data diffs are NOT actionable for AI agents without additional
context about struct layouts and vtables, which requires Ghidra integration.

## Status

This research concluded that data diff enhancements are **low priority**.
The existing `--include-data` flag could be wired up to show basic size info,
but full byte-level diffing should be deferred.
