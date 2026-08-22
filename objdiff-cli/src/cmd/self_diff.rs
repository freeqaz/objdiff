//! Refuse to *score* an object diffed against itself.
//!
//! # The defect
//!
//! `objdiff-cli diff -1 X -2 X <symbol>` puts the same bytes on both sides of
//! the comparison. The diff engine pairs the symbol with itself, every
//! instruction row comes out `equal`, and the result is `100.0%` with
//! `diff_score.score == 0` — **no matter what is actually in X**. Measured on
//! this fork at 4.2.7, dc3-decomp's `?random@@YAJJ@Z`:
//!
//! ```text
//! -1 obj/keygen_xbox.obj -2 src/keygen_xbox.obj  ->  68.96%  score 745/2400
//! -1 obj/keygen_xbox.obj -2 obj/keygen_xbox.obj  -> 100.00%  score   0/2400
//! -1 src/keygen_xbox.obj -2 src/keygen_xbox.obj  -> 100.00%  score   0/2000
//! ```
//!
//! Both self-diffs report a perfect match for a function that is 69% matched.
//! The number is not wrong-in-this-case, it is *structurally guaranteed*: it is
//! incapable of coming out any other way, so a clean result from it carries no
//! information. Two lanes hit this on 2026-08-21 and one concluded a function
//! was byte-perfect on the strength of it.
//!
//! # Why refuse rather than warn
//!
//! `-1 X -2 X` is a *legitimate* invocation — dc3-decomp's docs name it as the
//! way to read the target's own disassembly, because the mirrored two-column
//! listing is more legible than the alternative. So forbidding it outright
//! would break a real workflow, and a stderr warning would be ignored (this
//! fork has a documented history of advisory guards enforcing nothing:
//! `scripts/fmt.sh`'s own header records four of them).
//!
//! The resolution comes from objdiff's own behaviour. `diff -1 X <symbol>`,
//! with `-2` omitted, **already** prints the full listing and **already**
//! reports no percentage at all — every one of `fuzzy_match_percent`,
//! `normalized_match_percent`, `canonical_match_percent`,
//! `raw_match_percent` and `diff_score` is `None`. A scoreless listing is
//! therefore not a new mode being invented here; it is what objdiff does for
//! the single-object case already. The self-diff's only defect is that it
//! manufactures a score where the single-sided form correctly declines to.
//!
//! So: **refuse by default**, and name both remedies in the refusal — drop
//! `-2` (recommended), or pass `--allow-self-diff` to keep the mirrored
//! listing, in which case every match percent and the diff score are omitted
//! and a `self_diff` marker is emitted in their place. The listing survives;
//! the unfalsifiable number does not.
//!
//! # What counts as "the same object"
//!
//! Four ways to reach it, all handled, because a guard that only matches the
//! literal string is a guard you route around by accident:
//!
//! | Kind | Reached by |
//! |------|-----------|
//! | [`SelfDiffKind::SamePath`] | `-1 a.obj -2 a.obj` |
//! | [`SelfDiffKind::SameFileByPath`] | `-1 ./a.obj -2 ../d/a.obj`, `-1 a.obj -2 /abs/a.obj`, or a symlink |
//! | [`SelfDiffKind::HardLink`] | two directory entries, one inode |
//! | [`SelfDiffKind::IdenticalContent`] | two distinct files, same bytes — someone `cp`'d the target into the base dir |
//!
//! `IdenticalContent` is the one the original bug report did not list and the
//! most likely way this recurs: a copied object is not the same file by any
//! filesystem test, and it produces exactly the same guaranteed 100%.
//!
//! Archives (`-1 lib.a:member -2 lib.a:member`) are **not** a case here:
//! this fork's object reader has no archive support whatsoever — `Archive`
//! appears nowhere in `objdiff-core/src` or `objdiff-cli/src`, and a `.a`
//! passed to `-1` is rejected by the object parser. There is no path by which
//! two archive members can be diffed, so there is nothing to guard.

use std::{
    fs,
    io::{BufReader, Read},
    path::Path,
};

/// How the two sides turned out to be the same object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfDiffKind {
    /// `-1` and `-2` are the identical string.
    SamePath,
    /// Different strings, one file: relative vs absolute, `..` traversal, or a
    /// symlink. Detected by canonicalising both sides.
    SameFileByPath,
    /// Two directory entries sharing one inode — a hard link.
    HardLink,
    /// Two genuinely distinct files whose bytes are identical.
    IdenticalContent,
}

impl SelfDiffKind {
    /// Short phrase naming *why* the two sides are the same, for the refusal.
    pub fn reason(self) -> &'static str {
        match self {
            SelfDiffKind::SamePath => "-1 and -2 are the same path",
            SelfDiffKind::SameFileByPath => {
                "-1 and -2 are different paths to the same file (relative path, `..`, or symlink)"
            }
            SelfDiffKind::HardLink => "-1 and -2 are hard links to the same inode",
            SelfDiffKind::IdenticalContent => {
                "-1 and -2 are different files with byte-identical contents (a copy)"
            }
        }
    }

    /// Whether this kind is detectable from filesystem metadata alone, without
    /// reading either file.
    ///
    /// The project-wide sweeps ([`check_object_pairs`]) use only these: a
    /// content comparison over every unit in a project would read the whole
    /// build tree twice on every `report generate`.
    pub fn is_metadata_only(self) -> bool { !matches!(self, SelfDiffKind::IdenticalContent) }
}

/// How much work [`detect`] is permitted to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// Filesystem metadata only — path equality, canonical path, inode. Cheap
    /// enough to run over every unit in a project.
    Metadata,
    /// Also compare file contents when sizes match, catching the `cp` case.
    /// Reads both files; use for a single user-specified pair.
    Contents,
}

/// Determine whether `target` and `base` are the same object.
///
/// Returns `Ok(None)` when they are genuinely different, and **also** when
/// either path cannot be stat'd — a missing file is not this guard's business
/// and must be left to the object reader, which reports it with the real IO
/// error. Swallowing it here would turn "file not found" into "not a
/// self-diff", which is the same class of defect this module exists to remove.
pub fn detect(target: &str, base: &str, depth: Depth) -> std::io::Result<Option<SelfDiffKind>> {
    if target == base {
        return Ok(Some(SelfDiffKind::SamePath));
    }

    let target_path = Path::new(target);
    let base_path = Path::new(base);

    // `canonicalize` resolves `.`, `..` and symlinks in one step. It fails on a
    // nonexistent path, which is why the result is matched rather than `?`.
    if let (Ok(t), Ok(b)) = (target_path.canonicalize(), base_path.canonicalize())
        && t == b
    {
        return Ok(Some(SelfDiffKind::SameFileByPath));
    }

    let (target_meta, base_meta) = match (fs::metadata(target_path), fs::metadata(base_path)) {
        (Ok(t), Ok(b)) => (t, b),
        // Let the object reader produce the real error.
        _ => return Ok(None),
    };

    // Hard links share an inode but not a canonical path. This is a fast path,
    // not the only path: on platforms without `dev`/`ino` a hard link still has
    // identical contents, so `Depth::Contents` catches it below. `Depth::
    // Metadata` on such a platform will miss it, which is stated rather than
    // hidden.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if target_meta.dev() == base_meta.dev() && target_meta.ino() == base_meta.ino() {
            return Ok(Some(SelfDiffKind::HardLink));
        }
    }

    if depth == Depth::Metadata {
        return Ok(None);
    }

    // Differing lengths cannot be byte-identical; skip the read.
    if target_meta.len() != base_meta.len() {
        return Ok(None);
    }
    if files_have_equal_contents(target_path, base_path)? {
        return Ok(Some(SelfDiffKind::IdenticalContent));
    }
    Ok(None)
}

fn files_have_equal_contents(a: &Path, b: &Path) -> std::io::Result<bool> {
    const CHUNK: usize = 64 * 1024;
    let mut ra = BufReader::new(fs::File::open(a)?);
    let mut rb = BufReader::new(fs::File::open(b)?);
    let mut buf_a = vec![0u8; CHUNK];
    let mut buf_b = vec![0u8; CHUNK];
    loop {
        let n = read_full(&mut ra, &mut buf_a)?;
        let m = read_full(&mut rb, &mut buf_b)?;
        if n != m {
            return Ok(false);
        }
        if n == 0 {
            return Ok(true);
        }
        if buf_a[..n] != buf_b[..m] {
            return Ok(false);
        }
    }
}

/// Fill `buf` unless EOF is reached. `Read::read` is permitted to return a
/// short read at any time; comparing two short reads of *different* lengths
/// from equal files would report them unequal.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// The refusal message for an explicit `-1`/`-2` pair.
pub fn refuse_explicit_pair(kind: SelfDiffKind, target: &str, base: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "refusing to score a self-diff: {reason}\n  \
         -1 {target}\n  \
         -2 {base}\n\n\
         Diffing an object against itself is 100% by construction — the same bytes are on\n\
         both sides, so the score cannot come out any other way. It is not a measurement:\n\
         it is incapable of reporting a problem, so a clean result from it means nothing.\n\n\
         To read one object's disassembly (the legitimate reason to do this), drop -2:\n    \
         objdiff-cli diff -1 {target} <symbol> --include-instructions\n  \
         That form already emits no match percent.\n\n\
         To keep the mirrored side-by-side listing, add --allow-self-diff. Every match\n\
         percent and the diff score are omitted in that mode and a `self_diff` marker is\n\
         emitted in their place; -f markdown, json and json-pretty support it.",
        reason = kind.reason(),
        target = target,
        base = base,
    )
}

/// A project unit whose configured target and base objects are the same file.
#[derive(Debug, Clone)]
pub struct SelfDiffUnit {
    pub unit: String,
    pub kind: SelfDiffKind,
    pub target: String,
    pub base: String,
}

/// Sweep a project's `(unit, target, base)` triples for configured self-diffs.
///
/// This is the *configuration* form of the same defect, and it is worse than
/// the command-line form because it is silent and total: an `objdiff.json`
/// whose `target_dir` equals its `base_dir` makes **every** unit a self-diff,
/// so `report generate` produces a 100%-matched project report with no
/// complaint from anything.
///
/// Metadata-depth only — see [`SelfDiffKind::is_metadata_only`].
pub fn check_object_pairs<'a>(
    units: impl IntoIterator<Item = (&'a str, Option<&'a str>, Option<&'a str>)>,
) -> Vec<SelfDiffUnit> {
    let mut found = Vec::new();
    for (unit, target, base) in units {
        let (Some(target), Some(base)) = (target, base) else { continue };
        if let Ok(Some(kind)) = detect(target, base, Depth::Metadata) {
            // `Depth::Metadata` must never have read a file. If this trips, the
            // sweep has started doing O(build tree) IO on every invocation.
            debug_assert!(
                kind.is_metadata_only(),
                "Depth::Metadata returned a content-derived kind: {kind:?}"
            );
            found.push(SelfDiffUnit {
                unit: unit.to_string(),
                kind,
                target: target.to_string(),
                base: base.to_string(),
            });
        }
    }
    found
}

/// The refusal message for a project configuration that pairs objects with
/// themselves.
pub fn refuse_project_config(found: &[SelfDiffUnit], command: &str) -> anyhow::Error {
    let shown: Vec<String> = found
        .iter()
        .take(5)
        .map(|u| {
            format!(
                "  {} — {}\n    target: {}\n    base:   {}",
                u.unit,
                u.kind.reason(),
                u.target,
                u.base
            )
        })
        .collect();
    let trailer = if found.len() > 5 {
        format!("\n  ... and {} more unit(s)", found.len() - 5)
    } else {
        String::new()
    };
    anyhow::anyhow!(
        "refusing to run `{command}`: {n} unit(s) are configured to diff an object against\n\
         itself, which scores 100% by construction and cannot report a problem.\n\n\
         {shown}{trailer}\n\n\
         Check `target_dir` and `base_dir` in the project config — when they are equal,\n\
         every unit self-diffs and the whole report reads as a perfect match.",
        command = command,
        n = found.len(),
        shown = shown.join("\n"),
        trailer = trailer,
    )
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write, os::unix::fs as unix_fs};

    use super::*;

    /// Scratch directory that cleans up after itself.
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "objdiff-selfdiff-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn write(&self, name: &str, bytes: &[u8]) -> std::path::PathBuf {
            let p = self.0.join(name);
            let mut f = fs::File::create(&p).unwrap();
            f.write_all(bytes).unwrap();
            p
        }

        fn path(&self, name: &str) -> std::path::PathBuf { self.0.join(name) }
    }
    impl Drop for Scratch {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    fn s(p: &std::path::Path) -> String { p.to_str().unwrap().to_string() }

    /// Every way of naming one object must be caught — AND the negative
    /// control, two genuinely different files, must NOT be, in the same test.
    ///
    /// The negative control lives inside the test on purpose. A test that only
    /// asserts "the guard fires" passes just as happily if the guard has been
    /// widened into always firing, which is how a carve-out swallows its own
    /// control.
    #[test]
    fn detects_every_aliasing_route_and_only_those() {
        let dir = Scratch::new("routes");
        let a = dir.write("a.obj", b"OBJECT-CONTENTS-AAAA");
        let different = dir.write("different.obj", b"OBJECT-CONTENTS-BBBB");
        let copy = dir.write("copy.obj", b"OBJECT-CONTENTS-AAAA");
        let sym = dir.path("sym.obj");
        unix_fs::symlink(&a, &sym).unwrap();
        let hard = dir.path("hard.obj");
        fs::hard_link(&a, &hard).unwrap();

        // --- positives -------------------------------------------------
        assert_eq!(
            detect(&s(&a), &s(&a), Depth::Contents).unwrap(),
            Some(SelfDiffKind::SamePath),
            "literal same path"
        );

        // Relative vs absolute: same file, different strings.
        let rel = format!("{}/./a.obj", dir.0.display());
        assert_eq!(
            detect(&rel, &s(&a), Depth::Contents).unwrap(),
            Some(SelfDiffKind::SameFileByPath),
            "`.` traversal to the same file"
        );

        // `..` traversal.
        let dotdot = format!(
            "{}/../{}/a.obj",
            dir.0.display(),
            dir.0.file_name().unwrap().to_str().unwrap()
        );
        assert_eq!(
            detect(&dotdot, &s(&a), Depth::Contents).unwrap(),
            Some(SelfDiffKind::SameFileByPath),
            "`..` traversal to the same file"
        );

        assert_eq!(
            detect(&s(&sym), &s(&a), Depth::Contents).unwrap(),
            Some(SelfDiffKind::SameFileByPath),
            "symlink to the same file"
        );

        assert_eq!(
            detect(&s(&hard), &s(&a), Depth::Contents).unwrap(),
            Some(SelfDiffKind::HardLink),
            "hard link to the same inode"
        );

        assert_eq!(
            detect(&s(&copy), &s(&a), Depth::Contents).unwrap(),
            Some(SelfDiffKind::IdenticalContent),
            "byte-identical copy"
        );

        // --- NEGATIVE CONTROL ------------------------------------------
        // Two genuinely different objects. If this ever returns `Some`, the
        // guard has been widened into refusing every diff, and every positive
        // assertion above would still pass. This is the assertion that makes
        // the others mean something.
        assert_eq!(
            detect(&s(&a), &s(&different), Depth::Contents).unwrap(),
            None,
            "NEGATIVE CONTROL: two different objects must not be flagged"
        );

        // Same length, differing bytes — the case a length-only check would
        // wrongly flag. Both files are 20 bytes.
        assert_eq!(fs::metadata(&a).unwrap().len(), fs::metadata(&different).unwrap().len());
    }

    /// `Depth::Metadata` must not read file contents, so a copy is invisible to
    /// it — while every filesystem-level alias remains visible. Asserting both
    /// halves keeps the depth distinction real: a `Metadata` that quietly did
    /// the content read would pass a positives-only test.
    #[test]
    fn metadata_depth_sees_aliases_but_not_copies() {
        let dir = Scratch::new("depth");
        let a = dir.write("a.obj", b"SAME-BYTES");
        let copy = dir.write("copy.obj", b"SAME-BYTES");
        let hard = dir.path("hard.obj");
        fs::hard_link(&a, &hard).unwrap();

        assert_eq!(
            detect(&s(&hard), &s(&a), Depth::Metadata).unwrap(),
            Some(SelfDiffKind::HardLink),
            "Metadata depth still catches filesystem aliases"
        );
        assert_eq!(
            detect(&s(&copy), &s(&a), Depth::Metadata).unwrap(),
            None,
            "Metadata depth must not read contents"
        );
        assert_eq!(
            detect(&s(&copy), &s(&a), Depth::Contents).unwrap(),
            Some(SelfDiffKind::IdenticalContent),
            "...but Contents depth does"
        );
    }

    /// A missing file must NOT be reported as "not a self-diff by coincidence"
    /// — it must fall through so the object reader raises the real IO error.
    /// Verified by checking the sibling case still works: absence must not
    /// disable the guard for the pair that IS aliased.
    #[test]
    fn missing_paths_fall_through_without_disabling_the_guard() {
        let dir = Scratch::new("missing");
        let a = dir.write("a.obj", b"X");
        let ghost = s(&dir.path("nope.obj"));

        assert_eq!(detect(&ghost, &s(&a), Depth::Contents).unwrap(), None);
        assert_eq!(detect(&s(&a), &ghost, Depth::Contents).unwrap(), None);
        // Two identical *nonexistent* paths are still the same path — string
        // equality does not need the file to exist, and refusing here is
        // correct: there is no measurement to be had either way.
        assert_eq!(detect(&ghost, &ghost, Depth::Contents).unwrap(), Some(SelfDiffKind::SamePath));
        // Guard still live for a real alias.
        assert_eq!(detect(&s(&a), &s(&a), Depth::Contents).unwrap(), Some(SelfDiffKind::SamePath));
    }

    /// Empty files are byte-identical but must still be distinguished from the
    /// "different files" case. Zero-length reads are the classic place a
    /// chunked comparator returns a vacuous `true`.
    #[test]
    fn zero_length_and_chunk_boundary_files() {
        let dir = Scratch::new("chunks");
        let e1 = dir.write("e1.obj", b"");
        let e2 = dir.write("e2.obj", b"");
        assert_eq!(
            detect(&s(&e1), &s(&e2), Depth::Contents).unwrap(),
            Some(SelfDiffKind::IdenticalContent),
            "two empty files are identical"
        );

        // Larger than one 64 KiB chunk, differing only in the LAST byte: a
        // comparator that stops after the first chunk would call these equal.
        let big_a: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut big_b = big_a.clone();
        *big_b.last_mut().unwrap() ^= 0xff;
        let p1 = dir.write("big_a.obj", &big_a);
        let p2 = dir.write("big_b.obj", &big_b);
        let p3 = dir.write("big_a2.obj", &big_a);
        assert_eq!(
            detect(&s(&p1), &s(&p2), Depth::Contents).unwrap(),
            None,
            "NEGATIVE CONTROL: a difference in the final byte, past several chunks, must be seen"
        );
        assert_eq!(
            detect(&s(&p1), &s(&p3), Depth::Contents).unwrap(),
            Some(SelfDiffKind::IdenticalContent)
        );
    }

    #[test]
    fn project_sweep_reports_offenders_and_spares_the_rest() {
        let dir = Scratch::new("sweep");
        let t = dir.write("t.obj", b"TTTT");
        let b = dir.write("b.obj", b"BBBB");
        let found = check_object_pairs(vec![
            ("unit/good", Some(t.to_str().unwrap()), Some(b.to_str().unwrap())),
            ("unit/self", Some(t.to_str().unwrap()), Some(t.to_str().unwrap())),
            ("unit/no_base", Some(t.to_str().unwrap()), None),
        ]);
        assert_eq!(found.len(), 1, "only the genuinely self-paired unit: {found:?}");
        assert_eq!(found[0].unit, "unit/self");
        assert_eq!(found[0].kind, SelfDiffKind::SamePath);
    }
}
