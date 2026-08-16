#!/usr/bin/env bash
#
# Format (or check) the whole workspace with the toolchain rustfmt.toml requires.
#
# WHY THIS SCRIPT EXISTS
# ----------------------
# rustfmt.toml sets six options that are NIGHTLY-ONLY:
#
#     fn_single_line, where_single_line, imports_granularity,
#     group_imports, reorder_impl_items, overflow_delimited_expr
#
# (only use_small_heuristics and use_field_init_shorthand are stable).
#
# On a stable rustfmt those six are SILENTLY IGNORED -- rustfmt prints
# "Warning: can't set `X`, unstable features are only available in nightly
# channel" to stderr and then formats anyway, with a different style. So a bare
# `cargo fmt` does not merely fail to fix the tree, it actively reformats it
# INTO a shape that `cargo fmt --check` will keep reporting forever, because the
# committed code is nightly-formatted and stable rustfmt disagrees with it.
#
# Measured on this repo: a pristine upstream checkout, which CI proves is
# fmt-clean, is reported as 108 hunks across 29 files by stable rustfmt and 0 by
# nightly. The redness is the toolchain, not the code.
#
# The repo has always said so -- AGENTS.md ("cargo +nightly fmt --all (nightly
# required)"), .pre-commit-config.yaml (entry: cargo +nightly fmt --all),
# README.md, and .github/workflows/build.yaml, whose fmt job pins
# dtolnay/rust-toolchain@nightly with the comment "We use nightly options in
# rustfmt.toml". This script just makes the correct invocation the easy one and
# fails loudly instead of silently formatting to the wrong style.
#
# Deliberately NOT solved with a rust-toolchain.toml: that file applies to every
# cargo invocation, so it would move build/test/clippy onto nightly for everyone,
# and it would be a permanent divergence from upstream (encounter/objdiff), which
# ships the identical rustfmt.toml and no toolchain pin.
#
# USAGE
#   scripts/fmt.sh            # format the workspace in place
#   scripts/fmt.sh --check    # report drift, change nothing (exit 1 if drift)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
  cat >&2 <<'EOF'
error: the nightly toolchain is not installed, and rustfmt.toml needs it.

  rustup toolchain install nightly --component rustfmt

Do NOT fall back to `cargo fmt`: stable rustfmt ignores six of the eight
options in rustfmt.toml and will reformat the tree to the wrong style.
EOF
  exit 127
fi

if ! cargo +nightly fmt --version >/dev/null 2>&1; then
  echo "error: nightly is installed but its rustfmt component is missing." >&2
  echo "  rustup component add rustfmt --toolchain nightly" >&2
  exit 127
fi

# --all covers every workspace member, including objdiff-wasm. AGENTS.md's
# "do NOT use --workspace" caveat is about build/test (the wasm crate needs a
# different target); it explicitly exempts formatting and linting.
exec cargo +nightly fmt --all "$@"
