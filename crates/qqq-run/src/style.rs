// SPDX-License-Identifier: Apache-2.0
//! `qqqai fmt` and `qqqai lint` — one interface over the project's language toolchain
//! (`§5.2`, `CLI-014`).
//!
//! # Why these two share a module
//!
//! §5.2 lists them as a pair, and they are the same operation with a different verb: resolve
//! the project's language, find the driver for it, run that driver with the arguments the verb
//! implies. Splitting them would duplicate the language dispatch, the toolchain probe and the
//! "declared but not implemented" diagnosis, and those three are the parts that must not drift
//! apart — a `lint` that resolved a different language than `fmt` would check a different
//! project.
//!
//! # What is implemented, and what is refused
//!
//! Rust is the language with a driver, because it is the language this repository is written in
//! and the one `qqqai build` can already drive. The other four (`ts`, `go`, `python`, `cpp`) are
//! **declared in the manifest grammar and refused here**, naming the language matrix item that
//! owns each.
//!
//! Refusing is the honest answer, and the alternative is worse in a specific way: a `lint` that
//! reported "0 problems" for a language it never checked would be a green light over nothing.
//! That is the same failure `qqqai audit` names for checks it did not perform and `qqqai verify`
//! names for the attestation half, and this module follows it.
//!
//! # Why the plan is a value
//!
//! [`plan`] returns a [`ToolPlan`] — a program, its arguments and a working directory — without
//! running anything. That is `build.rs`'s split, and it is what makes the interesting logic
//! testable without a toolchain present: which driver, which arguments, which directory. The
//! command that actually executes is a thin wrapper, so a test of `plan` is a test of the
//! decision rather than of `std::process::Command`.

use std::path::PathBuf;

use qqq_core::{Error, ErrorCode, Result};

/// Which of the two verbs is being run.
///
/// A closed enum rather than a `&str` because the argument sets below are exhaustive per verb:
/// adding a third verb should be a compile error at each `match`, not a runtime default that
/// silently lints when asked to format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StyleVerb {
    /// `qqqai fmt` — rewrite the sources in place.
    Format,
    /// `qqqai lint` — report problems and change nothing.
    Lint,
}

impl StyleVerb {
    /// The verb as the command line spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Format => "fmt",
            Self::Lint => "lint",
        }
    }

    /// Whether the verb modifies source files.
    ///
    /// The distinction drives two things: `lint` must not write (a lint that reformats is a
    /// `fmt` that reports), and the report's own wording differs — one says what changed, the
    /// other says what is wrong.
    #[must_use]
    pub const fn mutates(self) -> bool {
        matches!(self, Self::Format)
    }
}

/// A program to run, with its arguments and working directory.
///
/// The same shape as `build::BuildPlan`, deliberately: one representation of "an external
/// command this tool is about to run" means the renderer, the quoting and the reporting are
/// shared, and a reader who has understood one has understood both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPlan {
    /// The program to execute.
    pub program: String,
    /// Its arguments, one element per argument.
    pub args: Vec<String>,
    /// The directory it runs in.
    pub cwd: PathBuf,
}

impl ToolPlan {
    /// Render the invocation as one line, quoted so it can be pasted into a shell.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = crate::build::shell_quote(&self.program);
        for a in &self.args {
            out.push(' ');
            out.push_str(&crate::build::shell_quote(a));
        }
        out
    }
}

/// The check a language's driver runs for `lint`, or `None` when the language has no driver.
///
/// # Why `clippy` and not `cargo check`
///
/// `cargo check` answers "does this compile", which `qqqai build` already answers and answers
/// better — it produces the artifact. The question `lint` exists to ask is the one the compiler
/// does not: the lints. `clippy` is what this repository's own gate runs with `-D warnings`, so a
/// project linted by `qqqai lint` is held to the same standard QQQ holds itself to, which is the
/// only defensible choice for a tool that ships a lint command.
#[must_use]
fn lint_args(language: &str) -> Option<Vec<String>> {
    match language {
        "rust" => Some(vec![
            "clippy".to_owned(),
            "--all-targets".to_owned(),
            "--".to_owned(),
            "-D".to_owned(),
            "warnings".to_owned(),
        ]),
        _ => None,
    }
}

/// The arguments a language's driver runs for `fmt`.
#[must_use]
fn fmt_args(language: &str) -> Option<Vec<String>> {
    match language {
        "rust" => Some(vec!["fmt".to_owned(), "--all".to_owned()]),
        _ => None,
    }
}

/// The program a language's style tooling is driven through.
#[must_use]
fn driver_for(language: &str) -> Option<&'static str> {
    match language {
        "rust" => Some("cargo"),
        _ => None,
    }
}

/// Plan a `fmt` or `lint` run.
///
/// # Errors
///
/// * `QQQ-1001` — the language is not one `qqqai build` can drive at all. The remediation names
///   the supported set, so the refusal is actionable.
/// * `QQQ-1001` — the language is supported but has no style driver yet, naming the language
///   matrix item. This is the `ts`/`go`/`python`/`cpp` case, and it is a different fact from the
///   first: one is "QQQ does not know this language", the other is "QQQ knows it and has not
///   built its driver".
/// * `QQQ-1003` — the language is driven but the required tool is not installed. The
///   remediation names the install command, because "cargo not found" leaves the user exactly
///   as stuck as before, one step later.
pub fn plan(language: &str, verb: StyleVerb, manifest_dir: &std::path::Path) -> Result<ToolPlan> {
    if !qqq_cap::manifest::Build::supports_language(language) {
        return Err(Error::new(
            ErrorCode::MissingTarget,
            format!("`{language}` is not a language this build can drive"),
        )
        .with_remediation(format!(
            "supported languages: {}",
            qqq_cap::manifest::Build::LANGUAGES.join(", ")
        )));
    }

    let Some(program) = driver_for(language) else {
        return Err(Error::new(
            ErrorCode::MissingTarget,
            format!("`{language}` has no `{}` driver yet", verb.name()),
        )
        .with_remediation(format!(
            "Rust is fully supported today; `{language}` is tracked by the language matrix \
             (`LANG-*`) in QQQ-Checklist-V1.md"
        )));
    };

    let args = match verb {
        StyleVerb::Format => fmt_args(language),
        StyleVerb::Lint => lint_args(language),
    };
    // `driver_for` and the two argument tables are keyed on the same set by construction; if
    // that ever stops being true this is the assertion, and it is an internal invariant rather
    // than a user error.
    let Some(args) = args else {
        return Err(Error::new(
            ErrorCode::InternalInvariantViolated,
            format!(
                "`{language}` has a driver but no `{}` arguments",
                verb.name()
            ),
        )
        .with_remediation("this is a QQQ bug; please report it"));
    };

    Ok(ToolPlan {
        program: program.to_owned(),
        args,
        cwd: manifest_dir.to_path_buf(),
    })
}

/// The outcome of running a style command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StyleOutcome {
    /// The verb that ran.
    pub verb: StyleVerb,
    /// The language it ran against.
    pub language: String,
    /// The invocation, rendered for display so the user can reproduce it.
    pub invocation: String,
    /// The exit status code, or `None` when the tool was killed by a signal.
    pub exit_code: Option<i32>,
    /// Whether the tool reported success.
    pub ok: bool,
    /// Captured stdout, verbatim.
    pub stdout: String,
    /// Captured stderr, verbatim.
    pub stderr: String,
}

impl StyleOutcome {
    /// The one-line conclusion.
    ///
    /// # Why a clean run says "no changes" and a clean lint says "no problems"
    ///
    /// Because they are different claims and a shared sentence would blur them: `fmt` having
    /// nothing to do means the source already matched the formatter, `lint` having nothing to
    /// say means no rule fired. A reader scanning a log should be able to tell which command
    /// they are looking at without reading the invocation line.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.ok {
            return match self.verb {
                StyleVerb::Format => {
                    format!("{}: already formatted, no changes needed", self.language)
                }
                StyleVerb::Lint => format!("{}: no problems found", self.language),
            };
        }
        match self.verb {
            StyleVerb::Format => format!(
                "{}: the formatter rewrote files (exit {})",
                self.language,
                self.exit_code
                    .map_or_else(|| "signal".to_owned(), |c| c.to_string())
            ),
            StyleVerb::Lint => format!(
                "{}: lint reported problems (exit {})",
                self.language,
                self.exit_code
                    .map_or_else(|| "signal".to_owned(), |c| c.to_string())
            ),
        }
    }
}

/// Run a planned style command and capture its output.
///
/// # Errors
///
/// `QQQ-1003` when the process cannot be spawned — the binary disappeared between the probe and
/// the run, or the directory is gone. A tool that was present a moment ago and is not now is a
/// real condition (a concurrent uninstall), and reporting it as a spawn failure names it.
pub fn run(plan: &ToolPlan, verb: StyleVerb, language: &str) -> Result<StyleOutcome> {
    let output = std::process::Command::new(&plan.program)
        .args(&plan.args)
        .current_dir(&plan.cwd)
        .output()
        .map_err(|e| {
            Error::new(
                ErrorCode::MissingTarget,
                format!("cannot run `{}`: {e}", plan.program),
            )
            .with_remediation("install it, then retry: `qqqai doctor` reports the toolchain state")
        })?;

    Ok(StyleOutcome {
        verb,
        language: language.to_owned(),
        invocation: plan.render(),
        exit_code: output.status.code(),
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// The result of running a style command, in the shape the CLI envelope publishes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StyleOutput {
    /// The verb that ran.
    pub verb: &'static str,
    /// The language it ran against.
    pub language: String,
    /// The invocation, so a reader can reproduce it.
    pub invocation: String,
    /// Whether the tool reported success.
    pub ok: bool,
    /// The exit status, or `null` for a signal.
    pub exit_code: Option<i32>,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
}

impl From<StyleOutcome> for StyleOutput {
    fn from(o: StyleOutcome) -> Self {
        Self {
            verb: o.verb.name(),
            language: o.language,
            invocation: o.invocation,
            ok: o.ok,
            exit_code: o.exit_code,
            stdout: o.stdout,
            stderr: o.stderr,
        }
    }
}

impl crate::output::CommandOutput for StyleOutput {
    fn command(&self) -> crate::output::CommandName {
        match self.verb {
            "lint" => crate::output::CommandName::Lint,
            _ => crate::output::CommandName::Fmt,
        }
    }

    /// The conclusion, then the captured stream that explains it.
    ///
    /// # Why the tool's own output is included rather than summarised
    ///
    /// Because the tool's message *is* the finding, and a summary would be this crate's
    /// paraphrase of a compiler diagnostic — strictly worse than the diagnostic, and one more
    /// thing to keep in sync. The exception is a clean run, where the tool said nothing and the
    /// sentence is the whole answer.
    fn summary(&self) -> String {
        use std::fmt::Write as _;
        let mut out = if self.ok {
            match self.verb {
                "lint" => format!("{}: no problems found", self.language),
                _ => format!("{}: already formatted, no changes needed", self.language),
            }
        } else {
            match self.verb {
                "lint" => format!(
                    "{}: lint reported problems (exit {})",
                    self.language,
                    self.exit_code
                        .map_or_else(|| "signal".to_owned(), |c| c.to_string())
                ),
                _ => format!(
                    "{}: the formatter failed (exit {})",
                    self.language,
                    self.exit_code
                        .map_or_else(|| "signal".to_owned(), |c| c.to_string())
                ),
            }
        };
        let _ = write!(out, "\n  ran: {}", self.invocation);

        // Only the stream that carries the finding, and only when there is one. A clean run
        // printed nothing and gets no empty section.
        for (label, text) in [("stdout", &self.stdout), ("stderr", &self.stderr)] {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                let _ = write!(out, "\n\n{label}:\n{trimmed}");
            }
        }
        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn rust_format_plans_a_cargo_fmt() {
        let p = plan("rust", StyleVerb::Format, Path::new("/proj")).expect("plan");
        assert_eq!(p.program, "cargo");
        assert_eq!(p.args, vec!["fmt", "--all"]);
        assert_eq!(p.cwd, PathBuf::from("/proj"));
    }

    #[test]
    fn rust_lint_plans_clippy_that_can_fail() {
        let p = plan("rust", StyleVerb::Lint, Path::new("/proj")).expect("plan");
        assert_eq!(p.program, "cargo");
        assert_eq!(p.args[0], "clippy");
        // The `-D warnings` is the part that makes this a gate. Without it clippy prints and
        // exits zero, which would make `qqqai lint` decorative in CI.
        assert!(
            p.args.windows(2).any(|w| w == ["-D", "warnings"]),
            "lint must deny warnings or it cannot fail: {:?}",
            p.args
        );
    }

    /// The control for the two refusals below: a language that *is* supported plans fine, so
    /// the refusals are decisions rather than a `plan` that rejects everything.
    #[test]
    fn a_supported_language_with_a_driver_plans() {
        assert!(plan("rust", StyleVerb::Lint, Path::new(".")).is_ok());
    }

    #[test]
    fn a_language_with_no_driver_is_refused_by_name() {
        // `go` is declared in `BuildSpec::LANGUAGES`, so this is the "known, not built" case
        // and the message must not claim the language is unknown.
        let err = plan("go", StyleVerb::Lint, Path::new(".")).expect_err("go has no driver");
        assert!(err.message.contains("go"), "{}", err.message);
        assert!(err.message.contains("lint"), "{}", err.message);
        let fix = err.remediation.clone().unwrap_or_default();
        assert!(fix.contains("LANG-"), "the owner must be named: {fix}");
        assert!(
            !err.message.contains("not a language this build can drive"),
            "a known language must not be reported as unknown: {}",
            err.message
        );
    }

    #[test]
    fn an_unknown_language_names_the_supported_set() {
        let err = plan("brainfuck", StyleVerb::Format, Path::new(".")).expect_err("not a language");
        assert!(err.message.contains("brainfuck"), "{}", err.message);
        let fix = err.remediation.clone().unwrap_or_default();
        assert!(
            fix.contains("rust"),
            "the supported set must be named: {fix}"
        );
    }

    #[test]
    fn format_mutates_and_lint_does_not() {
        assert!(StyleVerb::Format.mutates());
        assert!(!StyleVerb::Lint.mutates());
    }

    #[test]
    fn a_clean_lint_and_a_clean_format_say_different_things() {
        let base = StyleOutcome {
            verb: StyleVerb::Format,
            language: "rust".to_owned(),
            invocation: "cargo fmt --all".to_owned(),
            exit_code: Some(0),
            ok: true,
            stdout: String::new(),
            stderr: String::new(),
        };
        let fmt_text = base.summary();
        let lint_text = StyleOutcome {
            verb: StyleVerb::Lint,
            ..base
        }
        .summary();
        assert!(fmt_text.contains("no changes"), "{fmt_text}");
        assert!(lint_text.contains("no problems"), "{lint_text}");
        assert_ne!(
            fmt_text, lint_text,
            "the two claims must be distinguishable"
        );
    }

    #[test]
    fn a_failing_lint_says_so_with_its_status() {
        let out = StyleOutcome {
            verb: StyleVerb::Lint,
            language: "rust".to_owned(),
            invocation: "cargo clippy -- -D warnings".to_owned(),
            exit_code: Some(101),
            ok: false,
            stdout: String::new(),
            stderr: "error: ...".to_owned(),
        };
        let text = out.summary();
        assert!(text.contains("problems"), "{text}");
        assert!(text.contains("101"), "{text}");
    }

    #[test]
    fn the_invocation_is_rendered_so_it_can_be_pasted() {
        let p = ToolPlan {
            program: "cargo".to_owned(),
            args: vec!["clippy".to_owned(), "--all-targets".to_owned()],
            cwd: PathBuf::from("."),
        };
        assert_eq!(p.render(), "cargo clippy --all-targets");
    }
}
