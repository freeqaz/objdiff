#!/usr/bin/env bash
#
# Point this clone's git hooks at the versioned .githooks/ directory.
#
# `core.hooksPath` is per-clone local config and cannot be committed, so this
# is the one manual step. Everything the hooks then enforce IS versioned.
#
# Run once per clone (and once per worktree that has its own .git dir):
#   scripts/setup-hooks.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

current="$(git config --get core.hooksPath || true)"
if [ "$current" = ".githooks" ]; then
    echo "hooks already installed (core.hooksPath=.githooks)"
else
    git config core.hooksPath .githooks
    echo "installed: core.hooksPath=.githooks${current:+ (was: $current)}"
fi

chmod +x .githooks/* 2>/dev/null || true

# A hook nobody has watched fail is not known to be a hook. Prove this one
# rejects badly-formatted input before claiming it is installed.
#
# This self-test has already earned its keep: the first draft of the hook used
# `rustfmt --check` on stdin, which prints a diff and exits 0 (it only exits
# non-zero for file ARGUMENTS). The hook could not have failed on anything. The
# self-test caught that on its first run, so it detects by COMPARING CONTENT --
# the same way the hook now does, deliberately, so the two cannot drift apart.
if command -v rustup >/dev/null 2>&1 && cargo +nightly fmt --version >/dev/null 2>&1; then
    edition="$(sed -n 's/^edition[[:space:]]*=[[:space:]]*"\([0-9]*\)".*/\1/p' Cargo.toml | head -1)"
    edition="${edition:-2024}"
    mangled='fn  main( ) {let x=1;}'
    formatted="$(printf '%s\n' "$mangled" \
        | rustup run nightly rustfmt --edition "$edition" --emit stdout 2>/dev/null)"

    if [ -z "$formatted" ]; then
        echo "WARNING: self-test INCONCLUSIVE -- rustfmt produced no output." >&2
        echo "         Not treating that as success. Investigate before relying on the hook." >&2
        exit 1
    fi
    if [ "$formatted" = "$(printf '%s\n' "$mangled")" ]; then
        echo "WARNING: self-test FAILED -- rustfmt left deliberately mangled input unchanged." >&2
        echo "         The pre-commit hook cannot catch anything. Investigate before relying on it." >&2
        exit 1
    fi
    echo "self-test passed: mangled input is detectably reformatted, so the hook can fire"
else
    echo "NOTE: no nightly rustfmt found, so the hook could not be self-tested."
    echo "      rustup toolchain install nightly --component rustfmt"
fi
