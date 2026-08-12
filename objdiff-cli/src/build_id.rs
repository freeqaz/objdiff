//! Who is measuring.
//!
//! A progress report is a measurement, and a measurement that cannot name its
//! instrument cannot be compared with another one. On 2026-08-12 two of them
//! were compared anyway: an A/B of two objdiff builds that agreed to the last
//! decimal in all six project x ruler cells (they shared a report cache keyed on
//! everything except the binary; the real delta was +71 complete functions), and
//! a lane whose objdiff-cli was rebuilt out from under it by a peer at 05:56:47
//! between two verifications. Neither run could have told.
//!
//! Two identities, and they are not equivalent:
//!
//!   * [`binary_hash`] -- xxHash3-64 of the executing binary. Authoritative.
//!     Different bytes, different instrument, whatever either build claims.
//!   * [`commit`] -- the git commit stamped in at build time. Human-readable and
//!     ADVISORY: cargo re-runs `build.rs` only when one of its declared inputs
//!     changes, and "a tracked file was edited but not staged" is not something
//!     it can declare, so the stamp can lag the binary. Never treat a matching
//!     commit as proof that two binaries are the same.

/// xxHash3-64 (hex) of the running executable, computed once per process.
///
/// `None` if the executable cannot be located or read — on which the caller must
/// fail closed rather than substitute a weaker identity (`report generate`
/// disables its unit cache).
///
/// Cost: one read of ~12 MB from page cache plus the hash, ~2 ms.
pub fn binary_hash() -> Option<&'static str> {
    static HASH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        let exe = std::env::current_exe().ok()?;
        let data = std::fs::read(exe).ok()?;
        Some(format!("{:016x}", xxhash_rust::xxh3::xxh3_64(&data)))
    })
    .as_deref()
}

/// The git commit this binary's build script last saw, `"-dirty"`-suffixed if the
/// tree had uncommitted tracked changes then. Empty outside a git checkout.
pub fn commit() -> &'static str { env!("OBJDIFF_GIT_COMMIT") }

/// `objdiff-cli 4.2.3 (9138611 3f940, xxh3 56b672bcdc08a990)` — the line
/// `--version` prints and an installer records.
pub fn version_line(command_name: &str) -> String {
    let mut line = format!("{command_name} {}", env!("CARGO_PKG_VERSION"));
    let commit = commit();
    let hash = binary_hash();
    if !commit.is_empty() || hash.is_some() {
        line.push_str(" (");
        if !commit.is_empty() {
            line.push_str(commit);
            if hash.is_some() {
                line.push_str(", ");
            }
        }
        match hash {
            Some(h) => line.push_str(&format!("xxh3 {h}")),
            // Say so. A silent omission reads as "no hash exists", and this is
            // the state in which `report generate` refuses to use its cache.
            None => line.push_str("xxh3 unavailable"),
        }
        line.push(')');
    }
    line
}
