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
# Running this is not cosmetic. Two consequences of the drift:
#   - The CI fmt job is RED today. It pins nightly and runs
#     `cargo fmt --all --check`, which our main fails at 224 hunks.
#   - Reformatting moves the fork TOWARD upstream, not away: across the 32
#     files we share with upstream/main, `git diff upstream/main` shrinks
#     14,540 -> 13,200 lines (-1,340). It is conflict-reducing.
#
# USAGE
#   scripts/fmt.sh            # format the workspace in place
#   scripts/fmt.sh --check    # report drift, change nothing (exit 1 if drift)

set -euo pipefail

# Resolve symlinks before deriving the repo root. Without this, invoking the
# script through a symlink placed inside ANOTHER cargo workspace would silently
# reformat that workspace -- exactly the "wrong tree, no warning" failure this
# script exists to prevent. `readlink` without -f keeps this working on macOS.
src="${BASH_SOURCE[0]}"
while [ -L "$src" ]; do
  dir="$(cd -P "$(dirname "$src")" && pwd)"
  src="$(readlink "$src")"
  [ "${src#/}" = "$src" ] && src="$dir/$src"
done
REPO_ROOT="$(cd -P "$(dirname "$src")/.." && pwd)"

# Belt and braces: refuse to run anywhere that is not this repo.
if [ ! -f "$REPO_ROOT/rustfmt.toml" ] || [ ! -f "$REPO_ROOT/Cargo.toml" ]; then
  echo "error: $REPO_ROOT does not look like the objdiff workspace" >&2
  echo "  (expected rustfmt.toml and Cargo.toml beside scripts/)" >&2
  exit 2
fi
cd "$REPO_ROOT"

# Four distinct absence modes, each named for its ACTUAL cause. A guard that
# sends you to fix the wrong thing is barely better than no guard.
fatal() {
  echo "error: $1" >&2
  echo "  $2" >&2
  echo >&2
  echo 'Do NOT fall back to `cargo fmt`: stable rustfmt ignores six of the eight' >&2
  echo 'options in rustfmt.toml and will reformat the tree to the wrong style.' >&2
  exit 127
}

if ! command -v rustup >/dev/null 2>&1; then
  fatal "rustup is not on PATH, so the nightly rustfmt that rustfmt.toml needs cannot be selected." \
        "Install rustup (https://rustup.rs), then: rustup toolchain install nightly --component rustfmt"
fi

toolchains="$(rustup toolchain list 2>/dev/null || true)"
# Plain `nightly` lists as nightly-<arch>-...; a pinned one as nightly-YYYY-MM-DD-...
if ! printf '%s\n' "$toolchains" | grep -q '^nightly-'; then
  fatal "no nightly toolchain is installed, and rustfmt.toml needs one." \
        "rustup toolchain install nightly --component rustfmt"
elif ! printf '%s\n' "$toolchains" | grep -q '^nightly-[a-z]'; then
  fatal "only DATE-PINNED nightly toolchains are installed; \`+nightly\` resolves to none of them." \
        "rustup toolchain install nightly --component rustfmt"
fi

if ! cargo +nightly fmt --version >/dev/null 2>&1; then
  fatal "the nightly toolchain is installed but its rustfmt component is missing." \
        "rustup component add rustfmt --toolchain nightly"
fi

# --all covers every workspace member, including objdiff-wasm. AGENTS.md's
# "do NOT use --workspace" caveat is about build/test (the wasm crate needs a
# different target); it explicitly exempts formatting and linting.
exec cargo +nightly fmt --all "$@"
