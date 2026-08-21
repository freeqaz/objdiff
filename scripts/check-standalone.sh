#!/usr/bin/env bash
# Build and RUN objdiff-core the way an external consumer gets it: minimal
# features, outside this workspace, with nothing else in the build to unify
# features with.
#
# Why this exists: CI builds everything as `--all-features --workspace`, under
# which objdiff-cli's dependencies quietly supply features objdiff-core needs
# but does not declare. Three defects lived behind that for as long as
# objdiff-cli was the only consumer:
#   * `regex` declared featureless while map_file.rs compiles `\s`/`\d`/`\S`
#     (a RUNTIME panic — a build check alone cannot see it, which is why this
#     script runs the binary instead of only compiling it),
#   * `crate::bindings::report` referenced from `std`-only-gated items,
#   * the `std` feature not propagating to `serde_json`.
#
# Exit non-zero on any of them coming back.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cargo run --manifest-path "$here/standalone-check/Cargo.toml" --quiet

echo "standalone check passed: objdiff-core is usable outside this workspace"
