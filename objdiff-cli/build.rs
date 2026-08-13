//! Stamps the build's git identity into the binary, for `--version` and for the
//! `provenance` block of every generated report.
//!
//! Read the caveat before trusting the stamp: cargo only re-runs a build script
//! when one of its declared `rerun-if-changed` inputs changes, and "the working
//! tree became dirty" is not something that can be declared. We declare HEAD,
//! the ref HEAD points at, and the index, which covers commit/checkout/branch
//! changes and `git add`; it does NOT cover an unstaged edit to a tracked file.
//! So `OBJDIFF_GIT_COMMIT` can lag the binary it is compiled into. The
//! authoritative build identity is the hash of the executable itself, computed
//! at runtime (see `ReportProvenance::tool_binary_hash`) -- this stamp exists to
//! make that hash human-readable, not to replace it.
use std::process::Command;

fn main() {
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };

    // Re-run when the checked-out commit changes. `--git-path` resolves correctly
    // from a linked worktree, where `.git` is a file rather than a directory.
    for path in ["HEAD", "index"] {
        if let Some(p) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    if let Some(head_ref) = git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(p) = git(&["rev-parse", "--git-path", &head_ref])
    {
        println!("cargo:rerun-if-changed={p}");
    }

    let commit = match git(&["rev-parse", "--short=12", "HEAD"]) {
        Some(c) if !c.is_empty() => {
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if dirty { format!("{c}-dirty") } else { c }
        }
        // Not a git checkout (a crates.io build, a tarball). Empty, never a guess.
        _ => String::new(),
    };
    println!("cargo:rustc-env=OBJDIFF_GIT_COMMIT={commit}");
}
