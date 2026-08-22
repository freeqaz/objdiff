#!/usr/bin/env bash
# Build objdiff-cli at the checkout's HEAD and install an IMMUTABLE,
# version-named copy, then atomically repoint ~/.local/bin/objdiff-cli at it.
#
# Why not symlink ~/.local/bin/objdiff-cli into ./target/release?  Because
# target/ is mutable shared state: any cargo invocation in this checkout —
# including another session's — can silently replace the binary every consumer
# resolves, swapping a scoring comparand under live runs.  An installed copy
# under a version-and-rev name cannot change meaning; a new install is a new
# file and a deliberate relink.
#
# The name is derived from the binary's OWN --version output (which build.rs
# stamps from git, marking dirty builds `-dirty`), so what is installed is what
# is audited.  Refuses a dirty tree: an unauditable rev must not become the
# fleet's comparand.  Builds in a private target dir so this script neither
# perturbs nor is perturbed by ./target.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"

# --check: report whether the installed binary matches this checkout's HEAD.
# Exit 0 = current, 1 = stale/missing (with a one-line diagnosis). No build.
if [ "${1:-}" = "--check" ]; then
    link="$HOME/.local/bin/objdiff-cli"
    head_rev=$(git rev-parse --short=12 HEAD)
    if ! command -v "$link" >/dev/null; then
        echo "STALE: $link missing — run $0"; exit 1
    fi
    inst=$("$link" --version 2>/dev/null || true)
    inst_rev=$(sed -n 's/.*(\([0-9a-f]\{6,\}\)[,)].*/\1/p' <<<"$inst")
    if [ "$inst_rev" = "$head_rev" ]; then
        echo "current: $inst"; exit 0
    fi
    echo "STALE: installed rev ${inst_rev:-<none>} != HEAD $head_rev — run $0"
    exit 1
fi

# Match build.rs dirtiness semantics (--untracked-files=no): untracked files
# cannot reach the build without a tracked edit referencing them.
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "refusing: working tree has uncommitted tracked changes — commit" \
         "first so --version names a real rev" >&2
    exit 1
fi

tdir=${OBJDIFF_INSTALL_TARGET_DIR:-"$HOME/.cache/objdiff-install-target"}
cargo build --release --bin objdiff-cli --target-dir "$tdir"
bin="$tdir/release/objdiff-cli"

ver=$("$bin" --version)   # e.g. "objdiff-cli 4.2.7 (76c8da87e040, xxh3 ...)"
semver=$(awk '{print $2}' <<<"$ver")
rev=$(sed -n 's/.*(\([0-9a-f]\{6,\}\)[,)].*/\1/p' <<<"$ver")
if [ -z "$semver" ] || [ -z "$rev" ]; then
    echo "could not parse --version output: $ver" >&2
    exit 1
fi

dest_dir="$HOME/.local/objdiff/bin"
mkdir -p "$dest_dir"
dest="$dest_dir/objdiff-cli-$semver-$rev"
install -m 0755 "$bin" "$dest"

link="$HOME/.local/bin/objdiff-cli"
tmp="$link.tmp.$$"
ln -sfn "$dest" "$tmp"
mv -Tf "$tmp" "$link"

echo "installed: $dest"
echo "linked:    $link -> $dest"
echo "version:   $ver"
sha256sum "$dest"
