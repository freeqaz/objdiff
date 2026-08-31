//! The strict channel: letting objdiff fail a job on what it MEASURED.
//!
//! Before this module, objdiff-cli exited `0` or `1`, and `1` meant only "an
//! I/O, parse or config error happened". There was no way to say "fail the
//! build if the match regressed" or "fail if a detector could not run", so
//! every consumer that wanted one re-implemented threshold logic against parsed
//! JSON. The three sibling decomp repos that share this binary
//! (`dc3-decomp`, `rb3`, `rb3-xenon`) each do, inconsistently.
//!
//! # Design constraints, and where they came from
//!
//! * **Default behaviour is unchanged.** Without `--strict`, nothing here runs
//!   and every exit code is what it was. Three repos and a permuter fleet
//!   depend on the current semantics.
//! * **Zero examined is not success.** A check that ran over nothing and exited
//!   `0` is indistinguishable from a check that passed, and that shape has cost
//!   these repos real measurements — `report generate` used to publish
//!   `matched_code_percent: 100.0` for a project whose unit list was empty
//!   (fixed separately; see the refusal in `report.rs`). So `nonempty` is not
//!   an opt-in rule: **any** `--strict` invocation enforces it, and it has its
//!   own exit code so a vacuous run cannot hide inside a threshold pass.
//! * **Exit codes distinguish causes**, because the consuming repos' guards
//!   already do this and read the code rather than the message.
//! * **It must be demonstrable that it can fail.** `scripts/strict-selftest.sh`
//!   drives a real binary through every code below, including the reds. This
//!   project has a documented case of `rustfmt --check` on stdin *always*
//!   exiting 0, and of a ratchet silently disarmed by deleting its own budget
//!   file — a `--strict` nobody has watched fail is worth nothing.
//!
//! # Exit codes
//!
//! | code | meaning |
//! |------|---------|
//! | 0 | strict rules satisfied, and something was examined |
//! | 1 | error: I/O, parse, config — **unchanged**, not a strict outcome |
//! | 2 | a measurement threshold was violated (an offender was found) |
//! | 3 | a pattern detector could not run (`starved` or `not_applicable`) |
//! | 4 | the check examined zero things |
//! | 5 | the strict configuration is unusable here (unknown rule, unparsable
//!       threshold, or a rule that cannot apply to this invocation) |

use std::fmt;

use anyhow::Result;

/// Strict rules satisfied and something was examined.
#[allow(dead_code)]
pub const EXIT_OK: i32 = 0;
/// I/O, parse or config error. Pre-existing meaning; not a strict outcome.
pub const EXIT_ERROR: i32 = 1;
/// A measurement threshold was violated.
pub const EXIT_THRESHOLD: i32 = 2;
/// A pattern detector could not run, so its silence was not a measurement.
pub const EXIT_DETECTOR: i32 = 3;
/// The check examined zero things. Never folded into `EXIT_OK`.
pub const EXIT_NOTHING_EXAMINED: i32 = 4;
/// The strict configuration cannot be applied to this invocation.
pub const EXIT_UNUSABLE: i32 = 5;

/// A strict-channel outcome, carried through `anyhow` so it can travel the
/// existing `Result` plumbing without every function signature changing.
///
/// `main` downcasts to this to pick an exit code; anything that is not a
/// `StrictFailure` keeps exiting `1` exactly as before.
#[derive(Debug)]
pub struct StrictFailure {
    pub code: i32,
    pub message: String,
}

impl StrictFailure {
    /// Named `raise` rather than `new` because it returns an `anyhow::Error`,
    /// not a `Self` (clippy::new_ret_no_self).
    fn raise(code: i32, message: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(StrictFailure { code, message: message.into() })
    }
}

impl fmt::Display for StrictFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "strict[{}]: {}", self.code, self.message)
    }
}

impl std::error::Error for StrictFailure {}

/// The exit code an error should produce: a strict failure's own code, or the
/// historical `1` for everything else.
///
/// A free function rather than a method so `main` can stay a one-liner and so
/// the "everything else is still 1" rule has a single testable home.
pub fn exit_code_for(err: &anyhow::Error) -> i32 {
    err.downcast_ref::<StrictFailure>().map(|f| f.code).unwrap_or(EXIT_ERROR)
}

/// Which coverage holes the `detectors` rule treats as failures.
///
/// Two scopes because the two states have very different urgency, and a rule
/// with only the maximal reading would be useless in CI. `not_applicable` is
/// the NORMAL state of a perfectly-matched function — no mismatch rows means no
/// detector had anything to read, so `--strict detectors` in its `any` form is
/// red on every 100% symbol. `starved` is the state worth alerting on: the
/// configured ruler is suppressing evidence, so a clean detector report is not
/// evidence of a clean build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorScope {
    /// Any detector whose silence was not a measurement, `starved` or
    /// `not_applicable`. The literal reading of "fail if a detector could not
    /// run"; use it when you mean it.
    Any,
    /// Only detectors starved by the configured relocation ruler. The CI
    /// reading: "my ruler must not be hiding evidence from the detectors".
    Starved,
}

/// One `--strict` rule.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StrictRule {
    /// `min-match=<pct>`: fail if the measured match percent is below `pct`.
    MinMatch(f32),
    /// `detectors` / `detectors=any` / `detectors=starved`: fail if a pattern
    /// detector could not run, in the given scope.
    Detectors(DetectorScope),
    /// `nonempty`: fail if the run examined zero things. Always in effect when
    /// any rule is present; accepted explicitly so a caller can spell it.
    NonEmpty,
}

/// The parsed `--strict` configuration for one invocation.
#[derive(Debug, Clone, Default)]
pub struct StrictConfig {
    rules: Vec<StrictRule>,
}

impl StrictConfig {
    /// Parse repeated `--strict` values.
    ///
    /// Every parse failure is [`EXIT_UNUSABLE`], not [`EXIT_ERROR`]: a
    /// misconfigured guard and a broken build are different problems, and a
    /// consumer that cannot tell them apart will eventually treat one as the
    /// other.
    pub fn parse(values: &[String]) -> Result<Self> {
        let mut rules = Vec::new();
        for raw in values {
            let value = raw.trim();
            let rule = match value.split_once('=') {
                Some(("min-match", pct)) => {
                    let parsed: f32 = pct.trim().parse().map_err(|_| {
                        StrictFailure::raise(
                            EXIT_UNUSABLE,
                            format!(
                                "--strict min-match={pct}: `{pct}` is not a number. \
                                 Expected a percentage, e.g. --strict min-match=99.5"
                            ),
                        )
                    })?;
                    if !parsed.is_finite() || !(0.0..=100.0).contains(&parsed) {
                        return Err(StrictFailure::raise(
                            EXIT_UNUSABLE,
                            format!(
                                "--strict min-match={parsed}: a match percent threshold must \
                                 be between 0 and 100. A threshold outside the range a score \
                                 can take is either always red or never red, and neither is a \
                                 check."
                            ),
                        ));
                    }
                    StrictRule::MinMatch(parsed)
                }
                Some(("detectors", "any")) => StrictRule::Detectors(DetectorScope::Any),
                Some(("detectors", "starved")) => StrictRule::Detectors(DetectorScope::Starved),
                Some(("detectors", other)) => {
                    return Err(StrictFailure::raise(
                        EXIT_UNUSABLE,
                        format!(
                            "--strict detectors={other}: unknown scope. Use `starved` (fail \
                             only when the configured ruler suppresses a detector's \
                             evidence) or `any` (also fail when a detector had no rows to \
                             read, which is the normal state of a 100%-matched symbol). \
                             Bare `detectors` means `any`."
                        ),
                    ));
                }
                Some((other, _)) => {
                    return Err(unknown_rule(other));
                }
                None => match value {
                    "detectors" => StrictRule::Detectors(DetectorScope::Any),
                    "nonempty" => StrictRule::NonEmpty,
                    other => return Err(unknown_rule(other)),
                },
            };
            rules.push(rule);
        }
        Ok(StrictConfig { rules })
    }

    /// Was `--strict` given at all? Everything in this module is inert when
    /// this is false.
    pub fn enabled(&self) -> bool { !self.rules.is_empty() }

    pub fn min_match(&self) -> Option<f32> {
        self.rules.iter().find_map(|r| match r {
            StrictRule::MinMatch(p) => Some(*p),
            _ => None,
        })
    }

    /// The widest detector scope requested, or `None` if the rule was not given.
    pub fn detector_scope(&self) -> Option<DetectorScope> {
        let mut scope = None;
        for rule in &self.rules {
            if let StrictRule::Detectors(s) = rule {
                // `any` subsumes `starved`, so a caller spelling both gets the
                // stricter of the two rather than whichever came last.
                scope = Some(match (scope, s) {
                    (Some(DetectorScope::Any), _) | (_, DetectorScope::Any) => DetectorScope::Any,
                    _ => DetectorScope::Starved,
                });
            }
        }
        scope
    }

    pub fn wants_detectors(&self) -> bool { self.detector_scope().is_some() }

    /// Refuse a rule that cannot mean anything in this invocation.
    ///
    /// Silently ignoring an inapplicable rule is the failure mode this whole
    /// module exists to avoid: the caller believes a check ran.
    pub fn reject_rule(&self, rule_name: &str, why: &str) -> Result<()> {
        Err(StrictFailure::raise(
            EXIT_UNUSABLE,
            format!("--strict {rule_name} cannot be applied here: {why}"),
        ))
    }

    /// The gate every strict invocation passes through first.
    ///
    /// `examined` is the number of things this run actually measured — symbols
    /// for `diff`, functions/bytes for `report`. Zero is [`EXIT_NOTHING_EXAMINED`],
    /// never success, and this is checked BEFORE any threshold so a vacuous run
    /// cannot report itself as a threshold pass.
    pub fn check_examined(&self, examined: usize, what: &str) -> Result<()> {
        if !self.enabled() || examined > 0 {
            return Ok(());
        }
        Err(StrictFailure::raise(
            EXIT_NOTHING_EXAMINED,
            format!(
                "the check examined 0 {what}. A strict run that analysed nothing is not a \
                 pass: an empty result and a clean result are the same output, and only \
                 this exit code distinguishes them."
            ),
        ))
    }

    /// Apply `min-match` to one measured percent.
    ///
    /// `None` — the run produced no match percent at all — is
    /// [`EXIT_NOTHING_EXAMINED`], not a pass. A missing measurement is the
    /// vacuity case wearing a different hat.
    pub fn check_match_percent(&self, percent: Option<f32>, subject: &str) -> Result<()> {
        let Some(threshold) = self.min_match() else { return Ok(()) };
        let Some(percent) = percent else {
            return Err(StrictFailure::raise(
                EXIT_NOTHING_EXAMINED,
                format!(
                    "--strict min-match={threshold} was requested but {subject} produced no \
                     match percent to compare against. An absent measurement is not a \
                     passing one."
                ),
            ));
        };
        if percent < threshold {
            return Err(StrictFailure::raise(
                EXIT_THRESHOLD,
                format!("{subject} measured {percent}%, below the --strict min-match={threshold}"),
            ));
        }
        Ok(())
    }

    /// Apply `detectors` to a coverage table.
    ///
    /// `offenders` are the detectors whose silence was not a measurement, as
    /// `(pattern, status, reason)` where `status` is `"starved"` or
    /// `"not_applicable"`. Filtered here by the requested scope rather than at
    /// the call sites, so `diff` one-shot and `diff --batch` cannot come to
    /// disagree about what the rule means.
    pub fn check_detectors(&self, offenders: &[(&str, &str, String)], subject: &str) -> Result<()> {
        let Some(scope) = self.detector_scope() else { return Ok(()) };
        let relevant: Vec<&(&str, &str, String)> = offenders
            .iter()
            .filter(|(_, status, _)| match scope {
                DetectorScope::Any => true,
                DetectorScope::Starved => *status == "starved",
            })
            .collect();
        if relevant.is_empty() {
            return Ok(());
        }
        let mut detail = String::new();
        for (pattern, status, reason) in relevant.iter().take(8) {
            detail.push_str(&format!("\n  {status:14} {pattern}: {reason}"));
        }
        if relevant.len() > 8 {
            detail.push_str(&format!("\n  ...and {} more", relevant.len() - 8));
        }
        let scope_name = match scope {
            DetectorScope::Any => "any",
            DetectorScope::Starved => "starved",
        };
        Err(StrictFailure::raise(
            EXIT_DETECTOR,
            format!(
                "--strict detectors={scope_name}: {} pattern detector(s) could not run on \
                 {subject}, so their zeroes are not measurements:{detail}",
                relevant.len(),
            ),
        ))
    }
}

fn unknown_rule(name: &str) -> anyhow::Error {
    StrictFailure::raise(
        EXIT_UNUSABLE,
        format!(
            "--strict {name}: unknown rule. Known rules: min-match=<pct>, detectors, \
             nonempty. (`nonempty` is enforced by every --strict invocation whether or not \
             it is spelled.)"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(err: anyhow::Error) -> i32 { exit_code_for(&err) }

    #[test]
    fn no_strict_flag_means_every_gate_is_inert() {
        let cfg = StrictConfig::parse(&[]).unwrap();
        assert!(!cfg.enabled());
        // The default-behaviour-unchanged guarantee, asserted rather than
        // assumed: three repos and a permuter fleet read these exit codes.
        assert!(cfg.check_examined(0, "symbols").is_ok());
        assert!(cfg.check_match_percent(None, "x").is_ok());
        assert!(cfg.check_match_percent(Some(0.0), "x").is_ok());
        assert!(cfg.check_detectors(&[("WRONG_CALLEE", "starved", "because".into())], "x").is_ok());
    }

    #[test]
    fn zero_examined_is_never_a_pass() {
        let cfg = StrictConfig::parse(&["min-match=0".to_string()]).unwrap();
        // min-match=0 is satisfied by any score, so ONLY the vacuity gate can
        // make this red. That is the point: a sweep that analysed nothing must
        // not exit 0 just because its threshold was trivially met.
        assert!(cfg.check_match_percent(Some(0.0), "x").is_ok());
        assert_eq!(code(cfg.check_examined(0, "symbols").unwrap_err()), EXIT_NOTHING_EXAMINED);
        assert!(cfg.check_examined(1, "symbols").is_ok());
    }

    #[test]
    fn a_missing_measurement_is_not_a_passing_one() {
        let cfg = StrictConfig::parse(&["min-match=50".to_string()]).unwrap();
        assert_eq!(
            code(cfg.check_match_percent(None, "the symbol").unwrap_err()),
            EXIT_NOTHING_EXAMINED
        );
    }

    #[test]
    fn threshold_and_detector_failures_have_distinct_codes() {
        let cfg =
            StrictConfig::parse(&["min-match=99.5".to_string(), "detectors".to_string()]).unwrap();
        assert_eq!(code(cfg.check_match_percent(Some(99.4), "f").unwrap_err()), EXIT_THRESHOLD);
        assert!(cfg.check_match_percent(Some(99.5), "f").is_ok(), "boundary is inclusive");
        assert_eq!(
            code(cfg.check_detectors(&[("WRONG_CALLEE", "starved", "r".into())], "f").unwrap_err()),
            EXIT_DETECTOR
        );
        assert!(cfg.check_detectors(&[], "f").is_ok());
    }

    #[test]
    fn detectors_rule_is_opt_in_even_when_detectors_could_not_run() {
        let cfg = StrictConfig::parse(&["min-match=0".to_string()]).unwrap();
        assert!(
            cfg.check_detectors(&[("WRONG_CALLEE", "starved", "r".into())], "f").is_ok(),
            "a coverage hole must not fail a run that never asked about coverage"
        );
    }

    #[test]
    fn detector_scope_separates_a_starved_ruler_from_an_empty_diff() {
        let starved = ("WRONG_CALLEE", "starved", "ruler suppresses it".to_string());
        let na = ("FSEL_TERNARY", "not_applicable", "no replace rows".to_string());

        let any = StrictConfig::parse(&["detectors".to_string()]).unwrap();
        assert_eq!(any.detector_scope(), Some(DetectorScope::Any));
        assert_eq!(
            code(any.check_detectors(std::slice::from_ref(&na), "f").unwrap_err()),
            EXIT_DETECTOR
        );

        let only_starved = StrictConfig::parse(&["detectors=starved".to_string()]).unwrap();
        assert!(
            only_starved.check_detectors(std::slice::from_ref(&na), "f").is_ok(),
            "a 100%-matched symbol has no rows for any detector to read; that is the \
             normal state, not an alert"
        );
        assert_eq!(
            code(only_starved.check_detectors(std::slice::from_ref(&starved), "f").unwrap_err()),
            EXIT_DETECTOR,
            "a ruler suppressing evidence IS the alert"
        );

        // Spelling both takes the stricter, not the last one written.
        let both =
            StrictConfig::parse(&["detectors=starved".to_string(), "detectors=any".to_string()])
                .unwrap();
        assert_eq!(both.detector_scope(), Some(DetectorScope::Any));
        let reversed =
            StrictConfig::parse(&["detectors=any".to_string(), "detectors=starved".to_string()])
                .unwrap();
        assert_eq!(reversed.detector_scope(), Some(DetectorScope::Any));
    }

    #[test]
    fn an_unusable_configuration_is_its_own_code() {
        for bad in
            ["bogus", "min-match=abc", "min-match=101", "min-match=-1", "nope=1", "detectors=all"]
        {
            let err = StrictConfig::parse(&[bad.to_string()]).unwrap_err();
            assert_eq!(code(err), EXIT_UNUSABLE, "{bad}");
        }
        assert_eq!(
            code(StrictConfig::default().reject_rule("detectors", "why").unwrap_err()),
            EXIT_UNUSABLE
        );
    }

    #[test]
    fn a_non_strict_error_still_exits_one() {
        // The regression that would silently re-map every existing failure.
        assert_eq!(exit_code_for(&anyhow::anyhow!("Symbol not found: foo")), EXIT_ERROR);
    }

    #[test]
    fn every_exit_code_is_distinct() {
        let codes = [
            EXIT_OK,
            EXIT_ERROR,
            EXIT_THRESHOLD,
            EXIT_DETECTOR,
            EXIT_NOTHING_EXAMINED,
            EXIT_UNUSABLE,
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "two causes sharing a code cannot be told apart");
    }
}
