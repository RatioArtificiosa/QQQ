// SPDX-License-Identifier: Apache-2.0

//! The `qqqai` binary.
//!
//! # Why the argument parsing is hand-written
//!
//! QQQ has a hard startup budget (Proposal §5.1: `qqqai --version` in ≤ 15 ms).
//! A derive-based parser pulls in proc-macro output and a parsing layer that,
//! while excellent, costs measurable startup time and a dependency surface that
//! a security-sensitive CLI does not need for twenty-six commands.
//!
//! The trade-off is explicit: hand-written parsing means hand-written `--help`,
//! which means `--help` must be tested. It is — see the tests at the bottom of
//! this file, and `CommandName::all()` drives both the help text and the
//! exhaustiveness check so a new command cannot be forgotten in either.

use std::io::Write;
// Aliased because this file uses **both** traits: `io::Write` for the terminal
// streams in `print_help`, and `fmt::Write` for building output strings. Using
// `write!` on a `String` requires the latter in scope, and importing it
// unaliased would shadow the former.
use std::fmt::Write as _;
use std::process::ExitCode;

use qqq_run::output::{CommandName, Format, Output};

/// Global flags parsed before the command.
///
/// # Why a bitfield rather than five bools
///
/// Five boolean fields is a struct where every combination is representable,
/// including meaningless ones (`json` and `json_lines` together). A
/// bitflag-style `u8` with named accessors keeps the call-site ergonomics while
/// making the representation explicit — and adding a sixth flag no longer grows
/// the struct or trips the "too many bools" heuristic that exists to catch
/// exactly this smell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct GlobalFlags(u16);

impl GlobalFlags {
    /// Emit machine-readable JSON.
    const JSON: u16 = 1 << 0;
    /// Emit JSON Lines.
    const JSON_LINES: u16 = 1 << 1;
    /// Suppress non-essential output.
    const QUIET: u16 = 1 << 2;
    /// Emit additional detail.
    const VERBOSE: u16 = 1 << 3;
    /// Show what would happen without doing it.
    const DRY_RUN: u16 = 1 << 4;
    /// Print the full help rather than the brief one — `DX-013`.
    ///
    /// # Why `--help` has a depth at all
    ///
    /// Because §12.3 commits to `qqqai --help` being **≤40 lines**, and the
    /// measured output was 53. Truncating would lose the `--json` contract line,
    /// which is the most useful thing a script author reads here; so the default
    /// is brief and `--help --all` is complete. See [`render_help`].
    const ALL: u16 = 1 << 5;
    /// Offer to repair what `doctor` found — `DX-016`.
    ///
    /// # Why this is global rather than `doctor`-local
    ///
    /// Because the flag has to survive the single-pass parse. `parse_args`
    /// routes *unknown* flags that appear before the command name to a usage
    /// error and only forwards ones that appear after it, so a `doctor`-local
    /// `--fix` would make `qqqai --fix doctor` fail while `qqqai doctor --fix`
    /// worked. That order-dependence is the exact bug this file already
    /// documents for `--all` and pins with both orders in its test. A global
    /// flag is seen in both positions, and the `Doctor` arm reads it.
    ///
    /// The width of the backing integer is now `u16`: `1 << 6` does not fit in
    /// a `u8` with `ALL` at `1 << 5`.
    const FIX: u16 = 1 << 6;

    /// Set a flag.
    fn set(&mut self, flag: u16) {
        self.0 |= flag;
    }

    /// Test a flag.
    #[must_use]
    const fn has(self, flag: u16) -> bool {
        self.0 & flag != 0
    }

    /// Whether JSON output was requested.
    #[must_use]
    const fn json(self) -> bool {
        self.has(Self::JSON)
    }

    /// Whether JSON Lines output was requested.
    #[must_use]
    const fn json_lines(self) -> bool {
        self.has(Self::JSON_LINES)
    }

    /// Whether this is a rehearsal.
    #[must_use]
    const fn dry_run(self) -> bool {
        self.has(Self::DRY_RUN)
    }

    /// Whether the full help was requested — `DX-013`.
    #[must_use]
    const fn all(self) -> bool {
        self.has(Self::ALL)
    }

    /// Whether `doctor` may repair what it found — `DX-016`.
    #[must_use]
    const fn fix(self) -> bool {
        self.has(Self::FIX)
    }

    /// The output format these flags select.
    #[must_use]
    const fn format(self) -> Format {
        Format::from_flags(self.json(), self.json_lines())
    }
}

/// What the CLI was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Parsed {
    /// The global flags that were seen.
    flags: GlobalFlags,
    /// What to do.
    action: Action,
}

/// The action to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    /// Run a command with its remaining arguments.
    Command {
        /// Which command.
        name: CommandName,
        /// Everything after the command name.
        args: Vec<String>,
    },
    /// Print usage and exit successfully.
    Help,
    /// Print the version and exit successfully.
    Version,
    /// The arguments were not understood.
    UsageError(String),
}

/// The exit codes, matching `sysexits.h` conventions where they apply.
///
/// An agent distinguishes "the command failed" from "you called it wrong" from
/// "the environment is broken" — and each needs a different recovery, so each
/// gets a different code.
mod exit {
    /// The command succeeded.
    pub const OK: u8 = 0;
    /// The command ran but failed — an application error, not a usage mistake.
    ///
    /// Distinct from `USAGE` because an agent's recovery differs: a `FAILURE`
    /// means retrying or fixing the input may help, while `USAGE` means the
    /// invocation itself was wrong.
    pub const FAILURE: u8 = 1;
    /// The arguments were not understood.
    pub const USAGE: u8 = 2;
    /// A required resource was unavailable — a command that does not exist yet.
    pub const UNAVAILABLE: u8 = 69;
    /// An internal error, always a QQQ bug.
    pub const INTERNAL: u8 = 70;
}

/// Parse the process arguments **once**, returning both the flags and the
/// action.
///
/// # Why one pass, not two
///
/// An earlier version parsed the flags inside `parse_args` and then re-scanned
/// `argv` in `main` to recover them — duplicate work with two chances to
/// disagree. Returning both from a single pass makes the flags and the action
/// provably come from the same interpretation of the same input.
///
/// Flags may appear before or after the command, because both conventions are
/// common and forcing one produces avoidable user error.
fn parse_args(argv: &[String]) -> Parsed {
    let mut flags = GlobalFlags::default();
    let mut command: Option<CommandName> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut action: Option<Action> = None;

    for arg in argv {
        match arg.as_str() {
            // These short-circuit: the user is asking what to do, so nothing
            // later on the line changes the answer.
            // These set the action but do NOT stop the loop: `--version --json`
            // puts the flag *after* the short-circuit, and breaking here
            // silently ignored it. That was a real bug found by running the
            // binary (Observations §O-016b).
            "--help" | "-h" => {
                action = Some(Action::Help);
            }
            "--version" | "-V" => {
                // `--help` wins when both are present, regardless of order:
                // someone who typed both wants to know how to use the tool.
                // Encoding that here rather than letting "last one wins" decide
                // makes the behaviour order-independent and testable.
                if action != Some(Action::Help) {
                    action = Some(Action::Version);
                }
            }
            "--json" => flags.set(GlobalFlags::JSON),
            "--jsonl" | "--json-lines" => flags.set(GlobalFlags::JSON_LINES),
            "--quiet" | "-q" => flags.set(GlobalFlags::QUIET),
            "--verbose" | "-v" => flags.set(GlobalFlags::VERBOSE),
            "--dry-run" => flags.set(GlobalFlags::DRY_RUN),
            // `DX-013`: `--all` deepens `--help`. It is accepted *unconditionally*
            // and is inert unless the resolved action is `Help`, for the same
            // reason `--verbose` is: a flag with nothing to modify should not be
            // an error, and this file's own principle is that flag precedence is
            // order-independent.
            //
            // The first version gated on `action == Some(Action::Help)`, which
            // made `--all --help` fail while `--help --all` worked -- an
            // order-dependence introduced by a guard written to prevent a
            // different problem. `all_is_only_accepted_with_help` is what caught
            // it, and it now asserts both orders.
            "--all" => flags.set(GlobalFlags::ALL),
            // `DX-016`: `--fix` lets `doctor` repair what it found.
            //
            // Accepted unconditionally, for the same reason as `--all`: the
            // parse must not make a flag's validity depend on where it sits on
            // the line. It is inert unless the resolved command is `doctor`,
            // and the `Doctor` arm is the only reader.
            "--fix" => flags.set(GlobalFlags::FIX),
            other if other.starts_with('-') && command.is_none() => {
                // An unknown global flag *before* the command is a usage error.
                // After the command it belongs to the command and passes
                // through untouched.
                action = Some(Action::UsageError(format!("unknown flag `{other}`")));
                break;
            }
            other => {
                if command.is_none() {
                    if let Some(c) = CommandName::parse(other) {
                        command = Some(c);
                    } else {
                        action = Some(Action::UsageError(format!("unknown command `{other}`")));
                        break;
                    }
                } else {
                    rest.push(arg.clone());
                }
            }
        }
    }

    let action = action.unwrap_or(match command {
        Some(name) => Action::Command { name, args: rest },
        None => Action::Help,
    });

    Parsed { flags, action }
}

/// The maximum number of lines `qqqai --help` may print — `DX-013`.
///
/// # Where this number comes from
///
/// §12.3's DX-commitments table, in a section titled *"measurable, in CI"*:
///
/// > | `qqqai --help` for any command | **≤ 40 lines, actionable** | Review standard |
///
/// Measured before this constant existed: **53 lines**. The commitment had a
/// number on it and the implementation did not meet it, which is the shape
/// `§O-066` records — a claim that reads as satisfied because nobody counted.
///
/// It is a constant rather than a comment so [`help_fits_the_brevity_standard`]
/// can assert against it, and so a future addition that overflows is a **test
/// failure with the number in it** rather than a slow drift nobody notices.
pub const HELP_MAX_LINES: usize = 40;

/// The command groups, in the order the help presents them.
///
/// # Why this is a constant and not a local
///
/// Because [`render_help`] and the brevity test both need it, and a test that
/// rebuilt the groups independently could disagree with the renderer about what
/// the help contains — the failure mode `§O-103` records for derived fixtures.
const HELP_GROUPS: [(&str, &[CommandName]); 5] = [
    (
        "Project",
        &[
            CommandName::New,
            CommandName::Init,
            CommandName::Add,
            CommandName::Remove,
            CommandName::Install,
            CommandName::Update,
        ],
    ),
    (
        "Build and run",
        &[
            CommandName::Build,
            CommandName::Run,
            CommandName::Dev,
            CommandName::Serve,
            CommandName::Test,
            CommandName::Bench,
            CommandName::Fmt,
            CommandName::Lint,
        ],
    ),
    (
        "Inspect and trust",
        &[
            CommandName::Inspect,
            CommandName::Openapi,
            CommandName::Audit,
            CommandName::Verify,
            CommandName::Caps,
            CommandName::Why,
            CommandName::Trace,
            CommandName::Doctor,
        ],
    ),
    (
        "Agents",
        &[CommandName::Mcp, CommandName::Schema, CommandName::Migrate],
    ),
    ("Other", &[CommandName::Version, CommandName::Help]),
];

/// Render the usage text.
///
/// Built from [`CommandName::all()`] so a new command appears here
/// automatically — the alternative, a hand-maintained help string, is a
/// guaranteed source of drift.
///
/// # Progressive disclosure — `DX-013`
///
/// `verbose` selects the depth:
///
/// * **`qqqai --help`** (default) prints every command with a one-line summary,
///   inside [`HELP_MAX_LINES`]. Option descriptions are short, and the footer is
///   one line instead of two.
/// * **`qqqai --help --all`** prints the same structure with the long option
///   descriptions and the schemas hint, because a reader who asked for everything
///   wants it.
///
/// Truncating to fit the number was the alternative and was rejected: it would
/// lose the `--json` contract line, which is the single most useful thing a
/// script author reads here. Progressive disclosure fits the budget *and* makes
/// the default better, because a reader scanning for a command is not wading
/// through option prose they will read later, if ever.
fn render_help(verbose: bool) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} {} — the QQQ runtime CLI",
        qqq_core::BRAND_NAME,
        qqq_core::VERSION
    );
    let _ = writeln!(
        out,
        "usage: {} [OPTIONS] <COMMAND> [ARGS]",
        qqq_core::BINARY_NAME
    );
    let _ = writeln!(out, "commands:");

    // Group by purpose so the list is scannable rather than alphabetical soup.
    // No blank line before each heading: the indented label already separates
    // them, and four blank lines is four lines of the forty.
    for (title, cmds) in HELP_GROUPS {
        let _ = writeln!(out, "  {title}:");
        for &c in cmds {
            let _ = writeln!(out, "    {:<10} {}", c.as_str(), c.summary());
        }
    }

    let _ = writeln!(out, "options:");
    let _ = writeln!(out, "    --json  --jsonl       machine-readable output");
    let _ = writeln!(out, "    --dry-run             show, do not do");
    if verbose {
        let _ = writeln!(out, "    -q, --quiet           less output");
        let _ = writeln!(out, "    -v, --verbose         more output");
    }
    let _ = writeln!(out, "    -h, --help [--all]    this help");
    let _ = writeln!(out, "    -V, --version         the version");
    if verbose {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Every command supports --json. Schemas: `{} schema --all`",
            qqq_core::BINARY_NAME
        );
    }
    out
}

fn main() -> ExitCode {
    // `args_os` rather than `args` so a non-UTF-8 argument is reported as a
    // usage error instead of panicking.
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    // One pass. The flags and the action come from the same interpretation of
    // the same input, so they cannot disagree.
    let Parsed { flags, action } = parse_args(&argv);

    match action {
        Action::Help => {
            print!("{}", render_help(flags.all()));
            ExitCode::from(exit::OK)
        }
        Action::Version => {
            // `--version` is not part of the machine contract, but an agent
            // probing for a version should not have to parse prose, so --json
            // gives it an object.
            if flags.json() {
                let v = serde_json::json!({
                    "producer": "qqqai",
                    "version": qqq_core::VERSION,
                    "schema_version": qqq_core::SCHEMA_VERSION,
                    "wasi_target": qqq_core::WASI_TARGET_VERSION,
                    "wasmtime_line": qqq_core::WASMTIME_LINE,
                });
                println!("{v}");
            } else {
                println!("{} {}", qqq_core::BINARY_NAME, qqq_core::VERSION);
            }
            ExitCode::from(exit::OK)
        }
        Action::UsageError(message) => {
            let format = flags.format();
            let mut out = Output::new(format, std::io::stdout());
            let err = qqq_core::Error::new(qqq_core::ErrorCode::McpArgumentInvalid, message)
                .with_remediation(format!(
                    "run `{} --help` to see the available commands",
                    qqq_core::BINARY_NAME
                ));
            // A usage error is not a crash, so a write failure must not mask it.
            let _ = out.emit_error_with_exit(CommandName::Help, &err, exit::USAGE);
            ExitCode::from(exit::USAGE)
        }
        Action::Command { name, args } => run_command(name, &args, flags),
    }
}

/// Dispatch a command.
///
/// # Why most arms are not yet implemented
///
/// This function is honest about what exists. An unimplemented command reports
/// the checklist item that tracks it and exits with `UNAVAILABLE`, rather than
/// pretending to work or silently succeeding. A stub that *looks* like it
/// worked is worse than one that says it is missing — especially for an agent,
/// which would otherwise proceed on a false success.
fn run_command(name: CommandName, args: &[String], flags: GlobalFlags) -> ExitCode {
    let format = flags.format();
    let mut out = Output::new(format, std::io::stdout());

    match name {
        CommandName::Schema => dispatch_schema(name, &mut out, args),
        CommandName::Doctor => {
            // `doctor` has one flag of its own, `--fix`, and `--json` is
            // global. Anything else is a mistake worth naming: `--fix` itself
            // was silently ignored while it was unimplemented, so a `doctor`
            // that accepts anything it does not understand is the behaviour
            // this refuses.
            if let Some(code) = refuse_flags(name, args, &["--fix"], &mut out) {
                return code;
            }
            let checks = run_doctor();
            // A failing check must fail the process.
            //
            // This returned `0` unconditionally, which made the command useless
            // in the one place it is most valuable: a CI step or a shell
            // `qqqai doctor || exit 1` would report a broken environment as
            // healthy. A diagnostic that cannot fail is not a diagnostic — it
            // is the same class as a validator with no positive control
            // (`§M-006`), and it manufactures exactly the false confidence
            // `doctor` exists to remove.
            //
            // The exit code is `UNAVAILABLE` rather than `FAILURE`: nothing is
            // broken inside QQQ, the *environment* is not ready. That
            // distinction matters to a caller deciding whether to retry, report
            // or reinstall.
            let fix = apply_fixes(&checks, flags.fix());
            report_with_verdict(&mut out, name, &DoctorOutput { checks, fix }, |d| {
                if d.checks.iter().any(|c| !c.ok) {
                    // Nothing inside QQQ is broken; the *environment* is not
                    // ready. That distinction matters to a caller deciding
                    // whether to retry, report or reinstall.
                    exit::UNAVAILABLE
                } else {
                    exit::OK
                }
            })
        }
        CommandName::Why => {
            // The capability argument is extracted before `out` is borrowed by
            // `with_manifest`, so the missing-argument error does not conflict
            // with the later mutable borrow.
            if let Some(cap) = args.first().cloned() {
                dispatch_why(name, &mut out, args, &cap)
            } else {
                let err = qqq_core::Error::new(
                    qqq_core::ErrorCode::McpArgumentInvalid,
                    "`why` needs a capability to explain",
                )
                .with_remediation("for example: qqqai why crypto.hash");
                let _ = out.emit_error_with_exit(name, &err, exit::USAGE);
                ExitCode::from(exit::USAGE)
            }
        }
        CommandName::Caps => dispatch_caps(name, &mut out, args),
        CommandName::Openapi => dispatch_openapi(name, args, &mut out),
        CommandName::Inspect => dispatch_inspect(name, args, &mut out),
        CommandName::Audit => dispatch_audit(name, args, &mut out),
        CommandName::Verify => dispatch_verify(name, args, &mut out),
        CommandName::Build => dispatch_build(name, args, flags, &mut out),
        CommandName::Run => dispatch_run_with_trap_report(name, args, flags, &mut out),
        CommandName::New => dispatch_new(name, args, &mut out),
        CommandName::Init => dispatch_init(name, args, &mut out),
        CommandName::Dev => dispatch_dev(name, args, &mut out),
        CommandName::Serve => dispatch_serve(name, args, &mut out),
        CommandName::Bench => dispatch_bench(name, args, &mut out),
        CommandName::Add => dispatch_add(name, args, &mut out),
        CommandName::Remove => dispatch_remove(name, args, &mut out),
        CommandName::Install => dispatch_install(name, args, flags, &mut out),
        CommandName::Update => dispatch_update(name, args, flags, &mut out),
        CommandName::Test => dispatch_test(name, args, flags, &mut out),
        _ => {
            let err = qqq_core::Error::new(
                qqq_core::ErrorCode::InternalInvariantViolated,
                format!("`{name}` is not implemented yet"),
            )
            .with_remediation(format!(
                "this command is tracked by the checklist; see QQQ-Checklist-V1.md \
                 for `{name}`"
            ));
            let _ = out.emit_error_with_exit(name, &err, exit::UNAVAILABLE);
            ExitCode::from(exit::UNAVAILABLE)
        }
    }
}

/// Dispatch `qqqai inspect`.
///
/// # Two questions, one command, and why the argument decides
///
/// `qqqai inspect` with no argument answers *"what is this project allowed to
/// do?"* — the manifest's grants. `qqqai inspect <artifact>` answers *"what does
/// this file require?"* — read from the component's imports, with no manifest
/// involved.
///
/// The two must not be confused, and the previous behaviour confused them: the
/// path argument was **ignored** and the manifest's capabilities were reported
/// regardless. A user inspecting an untrusted `.wasm` received a confident
/// answer about their own `qqq.toml`, with nothing to indicate the answer was to
/// a different question. On the surface that exists to make a grant auditable
/// before execution (Proposal §7), a wrong answer is worse than no answer.
///
/// So an argument that is **not** a flag always means "inspect this artifact",
/// and a file that cannot be read or parsed is an error rather than a fallback.
fn dispatch_inspect(
    name: CommandName,
    args: &[String],
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    // `--manifest` and `--diff` take values, so their values must not be
    // mistaken for artifact paths. This is the same reasoning as
    // `build_options`'s `TAKES_VALUE`: a flag's value that is read as a
    // positional silently inspects the wrong file.
    const TAKES_VALUE: [&str; 2] = ["--manifest", "--diff"];
    let mut artifact: Option<String> = None;
    let mut diff_against: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--diff" {
            let Some(v) = args.get(i + 1) else {
                let e = missing_value("--diff");
                let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
                return ExitCode::from(exit::USAGE);
            };
            diff_against = Some(v.clone());
            i += 1;
        } else if let Some(v) = a.strip_prefix("--diff=") {
            diff_against = Some(v.to_owned());
        } else if TAKES_VALUE.contains(&a) {
            i += 1;
        } else if a.starts_with('-') {
            // Unknown flags are ignored here rather than rejected: `inspect`
            // shares the global vocabulary (`--json`) and rejecting a valid
            // global flag would be worse than tolerating one.
        } else if artifact.is_none() {
            artifact = Some(a.to_owned());
        }
        i += 1;
    }

    // `--diff` without an artifact has nothing to compare *from*, and comparing
    // against the manifest would be a category error — the two sides would be a
    // declaration and an import list. Refused with the reason rather than
    // guessed at.
    let Some(path) = artifact else {
        if diff_against.is_some() {
            let e = qqq_core::Error::new(
                qqq_core::ErrorCode::McpArgumentInvalid,
                "`--diff` needs an artifact to compare from",
            )
            .with_remediation(format!(
                "for example: {} inspect new.wasm --diff old.wasm",
                qqq_core::BINARY_NAME
            ));
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
        return with_manifest(name, out, args, qqq_run::commands::inspect);
    };

    let after = match qqq_run::commands::inspect_artifact(std::path::Path::new(&path)) {
        Ok(r) => r,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::FAILURE);
            return ExitCode::from(exit::FAILURE);
        }
    };

    let Some(against) = diff_against else {
        return report(out, name, &after);
    };

    let before = match qqq_run::commands::inspect_artifact(std::path::Path::new(&against)) {
        Ok(r) => r,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::FAILURE);
            return ExitCode::from(exit::FAILURE);
        }
    };

    let diff = qqq_run::commands::diff_artifacts(&before, &after);
    // An escalation exits non-zero so `qqqai inspect --diff` is usable as a CI
    // gate without parsing output: the same reasoning as `doctor` (`§O-036b`).
    // `--fail-on` will make the threshold configurable; today a *gain* of any
    // authority is the only thing that can fail, which is the safe default.
    let code = report(out, name, &diff);
    if diff.escalation && code == ExitCode::from(exit::OK) {
        ExitCode::from(exit::FAILURE)
    } else {
        code
    }
}

/// Dispatch `qqqai build`.
///
/// Split out of [`run_command`] because `build` is the first command with its
/// own flag vocabulary. Keeping it inline would make the dispatcher grow with
/// every command that gains options, and the dispatcher is the one function
/// that must stay readable — it is the map of the whole CLI.
/// Dispatch `qqqai audit` -- `CLI-016`.
///
/// # What §5.2 asks for
///
/// > | `qqqai audit <artifact>` | Full security posture: caps, limits, supply
/// > chain, provenance | `--json`, `--sarif`, `--fail-on <severity>` |
///
/// Four surfaces, all reported; two output modes plus a threshold. The SARIF mode
/// is what earns the command its place: GitHub code scanning reads it, so a
/// capability change appears in the **Security tab of a pull request** beside the
/// `CodeQL` results, with no QQQ-specific integration.
///
/// # Why `--fail-on` defaults to off
///
/// Because an audit that fails by default cannot be *read*. A developer running it
/// locally would get a non-zero exit for findings they may already know about and
/// would learn to append `|| true`, which turns the gate off for everybody. The
/// threshold is opt-in, which is what the flag is for.
///
/// # Why the SARIF branch writes the document itself
///
/// Because `with_manifest` owns the emit, and for SARIF the correct behaviour is
/// **not** to emit an envelope at all: a consumer parsing the output as SARIF must
/// not have to unwrap `data` first — nor skip a trailing human summary line.
/// `Output::write_document` puts the SARIF text on the command's own sink (so a
/// broken pipe is still a `QQQ-6005` rather than a panic, and so a test can
/// capture it) and the returned payload is never printed.
fn dispatch_audit(
    name: CommandName,
    args: &[String],
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let mut sarif = false;
    let mut fail_on: Option<qqq_run::audit::Severity> = None;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--sarif" {
            sarif = true;
        } else if a == "--fail-on" {
            let Some(v) = args.get(i + 1) else {
                let e = missing_value("--fail-on");
                let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
                return ExitCode::from(exit::USAGE);
            };
            match qqq_run::audit::parse_fail_on(v) {
                Ok(sev) => fail_on = Some(sev),
                Err(e) => {
                    let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
                    return ExitCode::from(exit::USAGE);
                }
            }
            i += 1;
        } else if let Some(v) = a.strip_prefix("--fail-on=") {
            match qqq_run::audit::parse_fail_on(v) {
                Ok(sev) => fail_on = Some(sev),
                Err(e) => {
                    let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
                    return ExitCode::from(exit::USAGE);
                }
            }
        }
        i += 1;
    }

    // Printed *before* the threshold is checked, so a failing run still says what
    // failed. A gate that exits before explaining itself is one people work
    // around.
    let mut meets_threshold = false;

    // `with_manifest` is deliberately **not** used here.
    //
    // It always emits the payload's `summary()` line, which is right for a
    // command whose whole output is that line plus its detail — and wrong for
    // `--sarif`, whose stdout must be the SARIF document and nothing else. The
    // first version used `with_manifest` and wrote the document from inside the
    // closure for exactly this reason, and stdout still began with the human
    // sentence: measured, 1438 bytes whose first line was
    // `1 finding(s) over caps, ...` and whose remainder was valid SARIF, so
    // `qqqai audit --sarif | jq` failed. Discovery is three lines; owning the
    // emit is worth them.
    let explicit = flag_value(args, "--manifest").map(std::path::PathBuf::from);
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let loaded = match qqq_run::LoadedManifest::discover(&cwd, explicit.as_deref()) {
        Ok(l) => l,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    let lock = qqq_run::sibling_lockfile(&loaded);
    let report = qqq_run::audit::audit(&loaded, lock.as_ref());

    // The threshold is computed **before** the output branch, so `--sarif
    // --fail-on note` gates like every other mode.
    //
    // Computing it only in the human branch meant the SARIF mode was the one
    // way to run the audit with a threshold and have it silently ignored:
    // measured, `audit --sarif --fail-on note` exited 0 while
    // `audit --fail-on note` exited 1. A CI job that gates on SARIF output —
    // the reason `--sarif` exists — would have been green forever. Found by
    // CodeRabbit reviewing this commit.
    if let Some(threshold) = fail_on {
        meets_threshold = report.fails_at(threshold);
    }
    let mut payload = qqq_run::AuditOutput::from(&report);
    payload.failed = fail_on.map(|_| meets_threshold);

    if sarif {
        // The document *is* the output: no envelope, no summary line.
        if let Err(e) = out.write_document(&report.to_sarif()) {
            let _ = out.emit_error_with_exit(name, &e, exit::INTERNAL);
            return ExitCode::from(exit::INTERNAL);
        }
        return if meets_threshold {
            ExitCode::from(exit::FAILURE)
        } else {
            ExitCode::from(exit::OK)
        };
    }

    // Detail, then the conclusion — and only in `--human`.
    //
    // `render()` is a terminal rendering. Writing it in every format put the
    // human block *in front of* the JSON envelope, so `qqqai --json audit | jq`
    // got six lines of prose with the JSON buried at the end. That is the same
    // defect this commit fixed for `--sarif`, and it survived one round because
    // the exit-code bug above was the one I was looking for. Found by CodeRabbit
    // reviewing this commit, and reproduced before fixing.
    if out.format() == Format::Human {
        if let Err(e) = out.write_document(&report.render()) {
            let _ = out.emit_error_with_exit(name, &e, exit::INTERNAL);
            return ExitCode::from(exit::INTERNAL);
        }
    }
    if let Err(e) = out.emit(&payload) {
        let _ = out.emit_error_with_exit(name, &e, exit::INTERNAL);
        return ExitCode::from(exit::INTERNAL);
    }

    // A manifest that could not be loaded has already reported its own failure,
    // so the threshold is only consulted on a successful audit.
    if meets_threshold {
        return ExitCode::from(exit::FAILURE);
    }
    ExitCode::from(exit::OK)
}

/// Dispatch `qqqai verify <artifact>` (`§5.2`, `SUP-002`).
///
/// # Why the parsing lives here rather than in `verify.rs`
///
/// `qqq_run::verify` takes a [`qqq_run::verify::VerifyOptions`] — a value — and every other
/// command in this file follows the same split: the module owns the meaning, the CLI owns the
/// spelling. Keeping `--key`'s accumulation out of the module is also what lets the module's
/// own tests build an option set directly instead of going through argv.
///
/// # The flag vocabulary, and why `--key` repeats
///
/// | Flag | Meaning |
/// |---|---|
/// | `--key <hex>` | one trusted publisher key; repeatable, because a rotation means two |
/// | `--policy require` | a signature is **required**, not merely verified when present |
///
/// `--policy` takes exactly one value today. An unknown value is refused rather than ignored,
/// because the failure mode of ignoring it is the worst one available: `--policy requiere`
/// would leave the policy opportunistic, and an unsigned artifact would then pass a check the
/// caller believed was mandatory. That is a typo turning into a security decision, so it is a
/// usage error instead.
fn dispatch_verify(
    name: CommandName,
    args: &[String],
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    const TAKES_VALUE: [&str; 2] = ["--key", "--policy"];
    let mut artifact: Option<String> = None;
    let mut keys: Vec<[u8; 32]> = Vec::new();
    let mut require_signature = false;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        // Both flags accept `--flag value` and `--flag=value`. The two forms are handled
        // separately rather than by splitting on '=' up front, because a key may legitimately
        // contain ':' as a separator and pre-splitting would have to decide what else is safe.
        let (flag, inline): (&str, Option<&str>) = match a.split_once('=') {
            Some((f, v)) if TAKES_VALUE.contains(&f) => (f, Some(v)),
            _ => (a, None),
        };
        match flag {
            "--key" | "--policy" => {
                let value = match inline {
                    Some(v) => v.to_owned(),
                    None => {
                        if let Some(v) = args.get(i + 1) {
                            i += 1;
                            v.clone()
                        } else {
                            let e = missing_value(flag);
                            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
                            return ExitCode::from(exit::USAGE);
                        }
                    }
                };
                if flag == "--policy" {
                    if value != "require" {
                        // Built here rather than through `unknown_choice`, whose phrasing is
                        // "`x` is not a known <kind>". The policy flag's job is to say *what
                        // kind of thing* was rejected, and "not a policy" reads as the flag
                        // being wrong rather than the value — which is the distinction the
                        // caller needs when the typo is theirs.
                        let e = qqq_core::Error::new(
                            qqq_core::ErrorCode::McpArgumentInvalid,
                            format!("`{value}` is not a policy"),
                        )
                        .with_remediation(
                            "choose one of: require (a signature is required, not merely \
                             verified when present)",
                        );
                        let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
                        return ExitCode::from(exit::USAGE);
                    }
                    require_signature = true;
                } else {
                    match qqq_run::verify::parse_key(&value) {
                        Ok(k) => keys.push(k),
                        Err(e) => {
                            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
                            return ExitCode::from(exit::USAGE);
                        }
                    }
                }
            }
            // A global flag (`--json`) is tolerated, as in `inspect`: refusing one here would
            // make a valid invocation fail.
            _ if a.starts_with('-') => {}
            _ if artifact.is_none() => artifact = Some(a.to_owned()),
            _ => {
                let e = qqq_core::Error::new(
                    qqq_core::ErrorCode::McpArgumentInvalid,
                    format!("`verify` takes one artifact, but `{a}` is a second"),
                )
                .with_remediation(format!(
                    "for example: {} verify app.wasm --key <hex>",
                    qqq_core::BINARY_NAME
                ));
                let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
                return ExitCode::from(exit::USAGE);
            }
        }
        i += 1;
    }

    let Some(artifact) = artifact else {
        let e = qqq_core::Error::new(
            qqq_core::ErrorCode::McpArgumentInvalid,
            "`verify` needs the artifact to check",
        )
        .with_remediation(format!(
            "for example: {} verify app.wasm --key <hex>",
            qqq_core::BINARY_NAME
        ));
        let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
        return ExitCode::from(exit::USAGE);
    };

    let options = qqq_run::verify::VerifyOptions {
        artifact: std::path::PathBuf::from(artifact),
        keys,
        require_signature,
    };

    // A verification that fails is a *finding*, not a usage error, so it gets `FAILURE`:
    // that is the distinction a CI gate acts on. `QQQ-5002` is the code either way, which is
    // why the exit status is decided here rather than read off the error.
    match qqq_run::verify::verify(&options) {
        Ok(report) => report_with_verdict(out, name, &report, |_| exit::OK),
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::FAILURE);
            ExitCode::from(exit::FAILURE)
        }
    }
}

/// Dispatch `qqqai build`.
fn dispatch_build(
    name: CommandName,
    args: &[String],
    flags: GlobalFlags,
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let opts = match build_options(args) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    with_manifest(name, out, args, |loaded| {
        if flags.dry_run() {
            // A rehearsal plans but does not execute, so it reports the command
            // without touching the toolchain. It still plans *fully* —
            // including probing for missing tools — because discovering a
            // missing compiler is the main reason to rehearse.
            return qqq_run::build::plan(loaded, &opts).map(|p| qqq_run::BuildOutput {
                project: loaded.name().to_owned(),
                language: loaded.manifest.build.language.clone(),
                target: loaded.manifest.build.target.clone(),
                profile: loaded.manifest.build.profile.clone(),
                command: p.render(),
                artifact: None,
                digest: None,
                size_bytes: None,
                kind: None,
                aot_requested: opts.aot(),
                aot_performed: false,
                dry_run: true,
            });
        }
        qqq_run::build::execute(loaded, &opts)
    })
}

/// Dispatch `qqqai run`.
///
/// # Why `run` reports traps with a special exit code
///
/// A guest that traps is not a `qqqai` failure — it is the sandbox working. The
/// exit code an agent should branch on is the guest's outcome, so a trap exits
/// `FAILURE` (1) rather than `INTERNAL` (70). `70` means "QQQ is broken"; a trap
/// means "your program or your limits are wrong", and conflating them would send
/// every trapped guest to a bug tracker that cannot help.
fn dispatch_run(
    name: CommandName,
    args: &[String],
    flags: GlobalFlags,
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let opts = match run_options(args, flags) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    with_manifest(name, out, args, |loaded| {
        if opts.dry_run {
            // A rehearsal performs the whole pre-flight — locating the
            // artifact, compiling it, resolving grants and checking imports —
            // and stops before instantiating. Discovering a missing grant is
            // the entire reason to rehearse, so skipping the check would make
            // the flag worthless.
            let p = qqq_run::run::prepare(loaded, &opts)?;
            let project_dir = loaded
                .path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let artifact = p
                .path
                .strip_prefix(project_dir)
                .unwrap_or(&p.path)
                .to_string_lossy()
                .replace('\\', "/");
            return Ok(qqq_run::RunOutput {
                project: loaded.name().to_owned(),
                artifact,
                digest: p.component.digest().to_owned(),
                imports: p.check.required.clone(),
                granted_imports: p.check.satisfied.clone(),
                ok: p.check.is_satisfied(),
                exit_code: None,
                duration_us: 0,
                fuel_consumed: None,
                deterministic: opts.deterministic,
                dry_run: true,
            });
        }
        qqq_run::run::execute(loaded, &opts)
    })
}

/// Dispatch `qqqai run` with `HOST-009`'s detached trap report.
///
/// # Why this is a separate function from `with_manifest`
///
/// Because resolving a trap's frames needs **the artifact that trapped**, and
/// `with_manifest` is generic over every command — most of which have no artifact
/// at all. Threading an `Option<PathBuf>` through it for one command would put a
/// field that is `None` fourteen times into the shared path.
///
/// # What it does that the generic path cannot
///
/// Before running, it extracts a `SourceMap` from the artifact. On failure, it
/// resolves the trap's frames against that map. This is the whole point: the
/// frames `qqq_host` attaches are already the *offsets*, and the map is what
/// turns them into lines — with no engine, and after the fact.
///
/// Extraction failure is deliberately **not** fatal. A project built without
/// `debug = true` has no DWARF, which is a legitimate configuration and not a
/// reason to refuse to run it; the trap is still reported, with `func+0x…`
/// frames and an explanation naming the missing debug info.
fn dispatch_run_with_trap_report(
    name: CommandName,
    args: &[String],
    flags: GlobalFlags,
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let opts = match run_options(args, flags) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    if opts.dry_run {
        // A rehearsal instantiates nothing, so no trap can occur and there is
        // nothing to resolve. Delegating keeps one definition of what a dry run
        // does rather than two that could drift.
        return dispatch_run(name, args, flags, out);
    }

    let explicit = flag_value(args, "--manifest").map(std::path::PathBuf::from);
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let loaded = match qqq_run::LoadedManifest::discover(&cwd, explicit.as_deref()) {
        Ok(l) => l,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    // Extract the map **before** running, while the artifact is known to exist
    // and before any trap has a chance to confuse the picture. Done here rather
    // than in the error arm because the error arm no longer has the artifact
    // path -- the error is a `qqq_core::Error` and carries no filesystem state.
    let map = qqq_run::run::locate_artifact(&loaded, &opts)
        .ok()
        .map(|path| qqq_run::trap_report::source_map_for_artifact(&path))
        .unwrap_or_default();

    match qqq_run::run::execute(&loaded, &opts) {
        Ok(value) => report(out, name, &value),
        Err(e) => {
            let backtrace = qqq_run::trap_report::resolve_error(&e, &map);
            if backtrace.is_empty() {
                // Not a trap: no frames to resolve, so the ordinary path is used
                // and the output is byte-identical to what it was before this
                // existed.
                let _ = out.emit_error_with_exit(name, &e, exit::FAILURE);
            } else {
                let _ = out.emit_error_with_backtrace(name, &e, &backtrace);
            }
            ExitCode::from(exit::FAILURE)
        }
    }
}

/// Dispatch `qqqai new`.
///
/// # Why this does not go through `with_manifest`
///
/// Because it is the one command whose job is to *create* the manifest. Every
/// other project command reads one; requiring one here would be circular, and
/// the error it produced ("no `qqq.toml` in this directory — run `qqqai new`")
/// would be advice the user is already trying to follow.
fn dispatch_new(name: CommandName, args: &[String], out: &mut Output<std::io::Stdout>) -> ExitCode {
    let opts = match new_options(args) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match qqq_run::scaffold::create(&opts, &cwd) {
        Ok(value) => report(out, name, &value),
        Err(e) => {
            // A refused name is a usage mistake; a refused directory is an
            // environment condition the user must resolve. Distinguishing them
            // lets a script tell "I called it wrong" from "something is in the
            // way".
            //
            // The code is computed **before** the envelope is emitted and then
            // used for both. Emitting with `FAILURE` and returning `USAGE`
            // afterwards is the contradiction §O-208 removed from 48 other
            // sites, and it survived here because the two values happen to agree
            // on every path the tests exercised.
            let code = if e.message.contains("not a usable") || e.message.contains("plain name") {
                exit::USAGE
            } else {
                exit::FAILURE
            };
            let _ = out.emit_error_with_exit(name, &e, code);
            ExitCode::from(code)
        }
    }
}

/// `qqqai openapi [--out <file>]`.
///
/// # Why `--out` writes the **document**, not the envelope
///
/// The file is meant to be read by an `OpenAPI` tool — a client generator, a mock server, an API
/// browser. A tool handed the QQQ envelope would find `{"openapi": ..., "document": {...}}` and
/// no `paths` at the top level, and would reject it. So the file gets the document and stdout
/// gets the envelope, and the two are **different by design**.
///
/// A user who pipes the command gets the envelope, which carries the document under
/// `document`; a user who passes `--out` gets a file their `OpenAPI` tool can open.
fn dispatch_openapi(
    name: qqq_run::CommandName,
    args: &[String],
    out: &mut qqq_run::output::Output<std::io::Stdout>,
) -> ExitCode {
    // `--out <file>` and `--out=<file>`, the two spellings every CLI accepts. A bare `--out`
    // with nothing after it is a usage error rather than a silent write to a file named `--`,
    // which is the mistake this shape prevents.
    let mut target: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if let Some(v) = a.strip_prefix("--out=") {
            target = Some(v.to_owned());
        } else if a == "--out" || a == "-o" {
            // `let ... else`, not a `match` with one meaningful arm: a bare `--out` is a
            // usage error rather than a silent write to a file named `--`, and the shape says
            // so in one line instead of seven.
            let Some(v) = args.get(i + 1) else {
                let err = qqq_core::Error::new(
                    qqq_core::ErrorCode::McpArgumentInvalid,
                    "`--out` needs a file path".to_owned(),
                )
                .with_remediation("write `--out openapi.json`");
                let _ = out.emit_error_with_exit(name, &err, exit::USAGE);
                return ExitCode::from(exit::USAGE);
            };
            target = Some(v.clone());
            i += 1;
        } else {
            let err = qqq_core::Error::new(
                qqq_core::ErrorCode::McpArgumentInvalid,
                format!("unknown argument `{a}` for `openapi`"),
            )
            .with_remediation("`openapi` accepts --out <file> and nothing else");
            let _ = out.emit_error_with_exit(name, &err, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
        i += 1;
    }

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            let err = qqq_core::Error::new(
                qqq_core::ErrorCode::HostResourceExhausted,
                "could not determine the working directory".to_owned(),
            )
            .with_cause(e.to_string());
            let _ = out.emit_error_with_exit(name, &err, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    let loaded = match qqq_run::LoadedManifest::discover(&cwd, None) {
        Ok(l) => l,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::FAILURE);
            return ExitCode::from(exit::FAILURE);
        }
    };

    let mut payload = match qqq_run::commands::openapi(&loaded) {
        Ok(p) => p,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::FAILURE);
            return ExitCode::from(exit::FAILURE);
        }
    };

    if let Some(path) = &target {
        // Rendered from the **document**, not from the envelope -- see this function's
        // documentation for why the two differ.
        //
        // Serialized from `payload.document` rather than by round-tripping back through
        // `Document`: that would need `Deserialize` on a type that is deliberately write-only,
        // and a failed round-trip would have written an **empty** file and reported success.
        let mut rendered = match serde_json::to_string_pretty(&payload.document) {
            Ok(s) => s,
            Err(e) => {
                let err = qqq_core::Error::new(
                    qqq_core::ErrorCode::InternalInvariantViolated,
                    "the OpenAPI document could not be rendered".to_owned(),
                )
                .with_cause(e.to_string());
                let _ = out.emit_error_with_exit(name, &err, exit::INTERNAL);
                return ExitCode::from(exit::INTERNAL);
            }
        };
        rendered.push('\n');
        if let Err(e) = std::fs::write(path, rendered) {
            let err = qqq_core::Error::new(
                qqq_core::ErrorCode::HostResourceExhausted,
                format!("could not write `{path}`"),
            )
            .with_cause(e.to_string());
            let _ = out.emit_error_with_exit(name, &err, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
        payload.out = Some(path.clone());
    }

    // `emit` takes only the value: the command name is derived from `CommandOutput::command`,
    // so the envelope and the payload cannot disagree about which command produced them.
    let _ = out.emit(&payload);
    ExitCode::from(exit::OK)
}

/// Decode `qqqai new`'s own flags.
///
/// # Errors
///
/// A QQQ-7001 usage error for an unrecognised flag, a flag missing its value, or
/// an unknown language or template.
fn new_options(args: &[String]) -> Result<qqq_run::NewOptions, qqq_core::Error> {
    use qqq_run::{Language, Template};

    let mut opts = qqq_run::NewOptions::default();
    let mut i = 0;
    let mut saw_name = false;

    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--lang" | "--language" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                opts.language = Language::parse(v).ok_or_else(|| {
                    unknown_choice("language", v, &Language::ALL.map(Language::as_str))
                })?;
                i += 1;
            }
            "--template" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                opts.template = Template::parse(v).ok_or_else(|| {
                    unknown_choice("template", v, &Template::ALL.map(Template::as_str))
                })?;
                i += 1;
            }
            "--no-git" => opts.no_git = true,
            "--force" => opts.force = true,
            "--yes" | "-y" => opts.yes = true,
            other => {
                if let Some(v) = other.strip_prefix("--lang=") {
                    opts.language = Language::parse(v).ok_or_else(|| {
                        unknown_choice("language", v, &Language::ALL.map(Language::as_str))
                    })?;
                } else if let Some(v) = other.strip_prefix("--template=") {
                    opts.template = Template::parse(v).ok_or_else(|| {
                        unknown_choice("template", v, &Template::ALL.map(Template::as_str))
                    })?;
                } else if other.starts_with('-') {
                    return Err(qqq_core::Error::new(
                        qqq_core::ErrorCode::McpArgumentInvalid,
                        format!("unknown flag `{other}` for `new`"),
                    )
                    .with_remediation(
                        "`new` accepts --lang, --template, --no-git, --force and --yes",
                    ));
                } else if saw_name {
                    // A second positional is a mistake worth naming: it most
                    // often means the user typed a flag as a bare word.
                    return Err(qqq_core::Error::new(
                        qqq_core::ErrorCode::McpArgumentInvalid,
                        format!("unexpected extra argument `{other}`"),
                    )
                    .with_remediation(
                        "`new` takes exactly one project name, e.g. `qqqai new orders-api`",
                    ));
                } else {
                    a.clone_into(&mut opts.name);
                    saw_name = true;
                }
            }
        }
        i += 1;
    }

    if !saw_name {
        return Err(qqq_core::Error::new(
            qqq_core::ErrorCode::McpArgumentInvalid,
            "`new` needs a project name",
        )
        .with_remediation(format!(
            "for example: {} new orders-api --lang rust --template http",
            qqq_core::BINARY_NAME
        )));
    }
    Ok(opts)
}

/// Dispatch `qqqai init`.
///
/// Like `new`, this does not go through `with_manifest`: the manifest is what it
/// creates. It differs from `new` in adopting an existing directory, so the
/// output always reports what was found and what was left alone.
fn dispatch_init(
    name: CommandName,
    args: &[String],
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let opts = match init_options(args) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match qqq_run::scaffold::init(&cwd, &opts) {
        Ok(value) => report(out, name, &value),
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::FAILURE);
            ExitCode::from(exit::FAILURE)
        }
    }
}

/// Decode `qqqai init`'s own flags: `--lang`, `--template`, `--force`.
///
/// # Errors
///
/// A QQQ-7001 usage error for an unrecognised flag or an unknown language.
fn init_options(args: &[String]) -> Result<qqq_run::InitOptions, qqq_core::Error> {
    use qqq_run::{Language, Template};

    let mut opts = qqq_run::InitOptions::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--lang" | "--language" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                opts.language = Some(Language::parse(v).ok_or_else(|| {
                    unknown_choice("language", v, &Language::ALL.map(Language::as_str))
                })?);
                i += 1;
            }
            "--template" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                opts.template = Template::parse(v).ok_or_else(|| {
                    unknown_choice("template", v, &Template::ALL.map(Template::as_str))
                })?;
                i += 1;
            }
            "--force" => opts.force = true,
            other => {
                if let Some(v) = other.strip_prefix("--lang=") {
                    opts.language = Some(Language::parse(v).ok_or_else(|| {
                        unknown_choice("language", v, &Language::ALL.map(Language::as_str))
                    })?);
                } else if let Some(v) = other.strip_prefix("--template=") {
                    opts.template = Template::parse(v).ok_or_else(|| {
                        unknown_choice("template", v, &Template::ALL.map(Template::as_str))
                    })?;
                } else if other.starts_with('-') {
                    return Err(qqq_core::Error::new(
                        qqq_core::ErrorCode::McpArgumentInvalid,
                        format!("unknown flag `{other}` for `init`"),
                    )
                    .with_remediation("`init` accepts --lang, --template and --force"));
                }
                // `init` takes no positional: it always acts on the current
                // directory. A positional is most likely `qqqai init <name>`,
                // which is a `new` habit, so the error says so.
                else {
                    return Err(qqq_core::Error::new(
                        qqq_core::ErrorCode::McpArgumentInvalid,
                        format!("`init` does not take an argument, got `{other}`"),
                    )
                    .with_remediation(format!(
                        "`init` adopts the current directory; to create a new one use \
                         `{} new {other}`",
                        qqq_core::BINARY_NAME
                    )));
                }
            }
        }
        i += 1;
    }
    Ok(opts)
}

/// Dispatch `qqqai dev`.
///
/// `dev` goes through `with_manifest`, because unlike `new` and `init` it needs
/// a manifest to exist — and its error if one is missing is the one place a user
/// should meet `qqqai new`.
/// Dispatch `qqqai test`.
///
/// # Why this needs a manifest but not a built artifact
///
/// Discovery asks the language toolchain what tests exist, which compiles the
/// test harness. It does **not** need the component to have been built: a test
/// that exercises pure logic runs on the host, and requiring `qqqai build` first
/// would make the fast path slow for no reason.
///
/// # Why this does not use `with_manifest`
///
/// Every other command returns a report and exits `0`. `test` has to exit
/// **non-zero** when the report says tests failed — a test command that reports
/// failures and exits `0` is unusable in the one place it matters, which is the
/// defect `qqqai doctor` had (`§O-036b`).
///
/// That does not fit `with_manifest`'s shape, and bending it to fit would mean
/// either a thread-local carrying the outcome out of the closure, or re-running
/// the suite to learn what it said. Both are worse than loading the manifest
/// directly here, which is three lines.
fn dispatch_test(
    name: CommandName,
    args: &[String],
    flags: GlobalFlags,
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let opts = match test_options(args, flags) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    let explicit = flag_value(args, "--manifest").map(std::path::PathBuf::from);
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let loaded = match qqq_run::LoadedManifest::discover(&cwd, explicit.as_deref()) {
        Ok(l) => l,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    let project_dir = loaded
        .path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let language = loaded.manifest.build.language.clone();

    let result = match qqq_run::run_tests(&project_dir, &language, &opts) {
        Ok(mut r) => {
            loaded.name().clone_into(&mut r.project);
            r
        }
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::FAILURE);
            return ExitCode::from(exit::FAILURE);
        }
    };

    report_with_verdict(out, name, &result, |r| {
        // A determinism failure counts as a failure for the exit code. A test
        // that passed 4 of 5 trials is not a passing test, and exiting `0`
        // would let CI accept it — which is the one outcome `--trials` exists
        // to prevent.
        if r.failed + r.nondeterministic > 0 {
            exit::FAILURE
        } else {
            exit::OK
        }
    })
}

/// Decode `qqqai test`'s flags.
///
/// # Why the global flags are taken as a parameter
///
/// `--dry-run` and `--json` are parsed by the **top-level** parser and consumed
/// there, so they never reach this function's argument list. An earlier version
/// looked for them here, found nothing, and silently ran the tests anyway — a
/// rehearsal that rehearses by doing the thing is worse than no rehearsal, and
/// the symptom (a normal summary under `--dry-run`) looked like a formatting bug
/// rather than a wiring one.
///
/// # Errors
///
/// A QQQ-7001 usage error for an unrecognised flag or a non-numeric `--trials`.
fn test_options(
    args: &[String],
    flags: GlobalFlags,
) -> Result<qqq_run::TestOptions, qqq_core::Error> {
    let mut opts = qqq_run::TestOptions {
        dry_run: flags.dry_run(),
        json: flags.format() != Format::Human,
        ..Default::default()
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--filter" | "-f" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                opts.filter = Some(v.clone());
                i += 1;
            }
            "--fail-fast" => opts.fail_fast = true,
            "--dry-run" => opts.dry_run = true,
            "--json" => opts.json = true,
            "--trials" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                opts.trials = Some(
                    v.parse()
                        .map_err(|_| bad_value(a, v, "a whole number of trials"))?,
                );
                i += 1;
            }
            "--manifest" => i += 1,
            other if other.starts_with('-') => {
                return Err(qqq_core::Error::new(
                    qqq_core::ErrorCode::McpArgumentInvalid,
                    format!("unknown flag `{other}` for `test`"),
                )
                .with_remediation(
                    "`test` accepts --filter, --fail-fast, --trials, --dry-run \
                     and --manifest",
                ));
            }
            // A bare argument is treated as a filter, which is what every other
            // test runner does and what a user typing `qqqai test smoke` means.
            other => {
                if opts.filter.is_none() {
                    opts.filter = Some(other.to_owned());
                }
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn dispatch_dev(name: CommandName, args: &[String], out: &mut Output<std::io::Stdout>) -> ExitCode {
    let opts = match dev_options(args) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };
    with_manifest(name, out, args, |loaded| qqq_run::dev::run(loaded, &opts))
}

/// Dispatch `qqqai serve`.
///
/// # Why this function exists at all
///
/// `CommandName::Serve` was parsed and never dispatched, so `serve` fell through to
/// the catch-all arm and answered `QQQ-6004: not implemented yet` while
/// `crates/qqq-run/src/serve.rs` held a complete, tested implementation. The module
/// had no caller from the CLI — the defect shape `QQQ-Observations-and-Memories.md`
/// `§O-130` records four times over, and the reason `CLI-011` was marked complete
/// while the command did not work.
///
/// # Why the options are parsed before the manifest is loaded
///
/// The same ordering `dispatch_dev` uses, for the same reason: `qqqai serve
/// --listenn 0.0.0.0:80` is a typo, and the moment to say so is while the user is
/// looking at the command they typed. Loading the manifest first would move the
/// diagnosis behind a file read and a parse for no benefit.
fn dispatch_serve(
    name: CommandName,
    args: &[String],
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let opts = match qqq_run::serve::options(args) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    // `--config <path>` names an alternate manifest; the loader finds the default
    // (`qqq.toml`) otherwise. Both paths go through the same loader, so a served
    // project is validated exactly as a built one is.
    //
    // This comment was here before the code was: `with_manifest` reads the *global*
    // `--manifest` flag, which `serve::options` rejects as an unknown flag, so `--config`
    // was parsed into `ServeOptions::config` and never read. `qqqai serve --config prod.toml`
    // served `qqq.toml` and said nothing. `with_manifest_at` takes the path explicitly so the
    // flag the command documents is the flag the loader receives (`§O-181`).
    with_manifest_at(
        name,
        out,
        opts.config.as_deref().map(std::path::Path::new),
        |loaded| qqq_run::serve::run_blocking(loaded, &opts),
    )
}

/// Dispatch `qqqai add`.
///
/// # Why the requirement is parsed before anything is written
///
/// `qqqai add foo@1.x.y` is a typo, and the moment to say so is *now* — while
/// the user is looking at the command they just typed. Writing it and failing
/// later at `install` moves the diagnosis to a different command, a different
/// day, and a different mental context (`§O-033a`).
///
/// This is also the only place the real grammar can be checked: `qqq-cap`
/// cannot reach `qqq-pkg::semver::Requirement` because `qqq-pkg` depends on
/// `qqq-cap`, so the manifest layer only shape-checks (`§O-033c`).
/// Dispatch `qqqai bench`.
///
/// # Why this command needs no manifest
///
/// Every other lifecycle command loads `qqq.toml` because it operates *on* a
/// project. `bench` operates on a *running server*: the target is an address, and
/// the ten `§9.1` rows are a property of the runtime rather than of one app's
/// configuration. Requiring a manifest would mean `qqqai bench --listen host:port`
/// failed from a directory without one, which is exactly the case a user measuring
/// a deployed service is in.
///
/// # Why the async runtime is built here rather than reused
///
/// The load generator is async because it holds a stated number of connections in
/// flight, which is `§9.1`'s disclosure requirement. `main` is synchronous, so a
/// runtime is constructed for this command and dropped at the end. It is
/// multi-threaded and sized to the default, because a single-threaded runtime
/// would make the *client* the bottleneck at high concurrency and the reported
/// throughput would be the harness's ceiling rather than the server's.
///
/// # Why a missing target is a usage error and not a guess
///
/// The tempting default is `127.0.0.1:8080`. It was rejected: a benchmark that
/// silently measured whatever happened to be listening would produce a *wrong
/// number* for a *right-looking command*, and `§9.1`'s whole subject is that a
/// benchmark without its methodology is marketing. Naming the target is the
/// least a caller can do to make the result mean something.
fn dispatch_bench(
    name: CommandName,
    args: &[String],
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let opts = match qqq_run::bench::options(args) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    let Some(target) = opts.target else {
        let err = qqq_core::error::Error::new(
            qqq_core::error::ErrorCode::McpArgumentInvalid,
            "`qqqai bench` needs a target to measure",
        )
        .with_remediation(
            "start the app with `qqqai serve --listen 127.0.0.1:8080`, then run \
             `qqqai bench --listen 127.0.0.1:8080`",
        );
        let _ = out.emit_error_with_exit(name, &err, exit::USAGE);
        return ExitCode::from(exit::USAGE);
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            let err = qqq_core::error::Error::new(
                qqq_core::error::ErrorCode::InternalInvariantViolated,
                format!("could not start the async runtime: {e}"),
            )
            .with_remediation("this is a QQQ bug; please report it");
            let _ = out.emit_error_with_exit(name, &err, exit::INTERNAL);
            return ExitCode::from(exit::INTERNAL);
        }
    };

    let outcome = runtime.block_on(qqq_run::bench::run(&opts, target));
    match outcome {
        Ok(document) => {
            let _ = out.emit(&document);
            if qqq_run::bench::should_fail(&document, opts.fail_on_miss) {
                ExitCode::from(exit::FAILURE)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::FAILURE);
            ExitCode::from(exit::FAILURE)
        }
    }
}

fn dispatch_add(name: CommandName, args: &[String], out: &mut Output<std::io::Stdout>) -> ExitCode {
    let parsed = match add_options(args) {
        Ok(p) => p,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    let table = if parsed.dev {
        "dev-dependencies"
    } else {
        "dependencies"
    };

    with_manifest(name, out, args, |loaded| {
        qqq_run::deps::add(&loaded.path, table, &parsed.edit)
    })
}

/// Dispatch `qqqai remove`.
fn dispatch_remove(
    name: CommandName,
    args: &[String],
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let mut dev = false;
    let mut pkg: Option<String> = None;

    for a in args {
        match a.as_str() {
            "--dev" => dev = true,
            "--manifest" => {}
            other if other.starts_with('-') => {
                let e = qqq_core::Error::new(
                    qqq_core::ErrorCode::McpArgumentInvalid,
                    format!("unknown flag `{other}` for `remove`"),
                )
                .with_remediation("`remove` accepts --dev and --manifest");
                let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
                return ExitCode::from(exit::USAGE);
            }
            other if pkg.is_none() => pkg = Some(other.to_owned()),
            _ => {}
        }
    }

    let Some(pkg) = pkg else {
        let e = qqq_core::Error::new(
            qqq_core::ErrorCode::McpArgumentInvalid,
            "`remove` needs the name of a dependency",
        )
        .with_remediation(format!(
            "for example: {} remove qqqai/json",
            qqq_core::BINARY_NAME
        ));
        let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
        return ExitCode::from(exit::USAGE);
    };

    let table = if dev {
        "dev-dependencies"
    } else {
        "dependencies"
    };

    with_manifest(name, out, args, |loaded| {
        qqq_run::deps::remove(&loaded.path, table, &pkg)
    })
}

/// Dispatch `qqqai install`.
///
/// # Why this reports rather than pretends
///
/// There is no registry yet, so nothing can be fetched. The command does the
/// half that is real — reading the lockfile, resolving the manifest against it,
/// and printing the capability diff that Proposal §5.4 exists for — and then
/// **fails**, naming the packages it could not fetch.
///
/// The alternative, writing a lockfile that lists packages never fetched, is the
/// worst available outcome: a lockfile is a promise about bytes, the next
/// command would trust it, and the content-addressed store would be asked for a
/// digest it has never seen. A tool that reports success for work it did not do
/// is worse than one that reports it could not do the work (`§O-033a`).
fn dispatch_install(
    name: CommandName,
    args: &[String],
    flags: GlobalFlags,
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let opts = match install_options(args, flags) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    with_manifest(name, out, args, |loaded| {
        // The manifest's two dependency tables, flattened in a deterministic
        // order so the lockfile and the diff do not depend on map iteration.
        //
        // Each entry carries the dependency's **declared capabilities** as well
        // as its requirement. That third element is what makes `SEC-015`'s
        // capability diff able to observe anything at all: the diff compares the
        // authority *recorded* in the old lockfile against the authority
        // *declared* in the manifest now, and without the declaration there is
        // no second value to compare against (`§O-076`).
        let mut deps: Vec<(String, String, Vec<String>)> = loaded
            .manifest
            .dependencies
            .iter()
            .map(|(n, d)| (n.clone(), d.requirement().to_owned(), d.caps().to_vec()))
            .collect();
        // Dev-dependencies are installed too — a test suite needs them — but
        // they are recorded with the same shape, and the capability diff will
        // show them separately because their `caps` differ.
        deps.extend(
            loaded
                .manifest
                .dev_dependencies
                .iter()
                .map(|(n, d)| (n.clone(), d.requirement().to_owned(), d.caps().to_vec())),
        );
        deps.sort_by(|a, b| a.0.cmp(&b.0));

        let path = qqq_run::lockfile_path(&loaded.path);
        let previous = qqq_run::read_lockfile(&path)?;

        // `--locked`/`--frozen` require a lockfile to exist. Checked before
        // resolving so the error names the missing file rather than the
        // first package that would have been added.
        if opts.mode.requires_current() && previous.is_none() {
            return Err(qqq_run::lockfile_required(&path));
        }

        let resolution = qqq_run::resolve(&deps, previous.as_ref());

        // A `--locked` run must fail if the lockfile would change, and it must
        // fail *before* reporting the diff as though it had been applied.
        if opts.mode.requires_current() {
            if !resolution.unresolved.is_empty() {
                return Err(qqq_run::lockfile_stale(&format!(
                    "`{}` does not resolve {}: the lockfile is out of date",
                    path.display(),
                    resolution.unresolved.join(", ")
                )));
            }
            if !resolution.diff.is_empty() {
                return Err(qqq_run::lockfile_stale(&format!(
                    "`{}` would change ({} package(s)); --locked forbids that",
                    path.display(),
                    resolution.diff.changes.len()
                )));
            }
        }

        // Nothing can be fetched, so anything unresolved is a hard stop. This is
        // checked after the `--locked` path so that CI reports "out of date"
        // rather than "no registry" — the first is actionable, the second is not.
        if let Some(missing) = resolution.unresolved.first() {
            return Err(qqq_run::cannot_fetch(
                missing,
                "it is not in `qqq.lock` and there is no registry to resolve it from",
            ));
        }

        let wrote = if opts.may_write() {
            let mut lock = resolution.lockfile.clone();
            lock.stamp(&format!(
                "{} {}",
                qqq_core::BINARY_NAME,
                qqq_core::SCHEMA_VERSION
            ));
            let text = lock.render()?;
            std::fs::write(&path, text).map_err(|e| {
                qqq_core::Error::new(
                    qqq_core::ErrorCode::LockfileOutOfDate,
                    format!("could not write `{}`", path.display()),
                )
                .with_cause(e.to_string())
            })?;
            true
        } else {
            false
        };

        Ok(qqq_run::InstallOutput {
            manifest: qqq_run::deps::display_manifest(&loaded.path),
            lockfile: qqq_run::deps::display_manifest(&path),
            packages: resolution.lockfile.len(),
            wrote_lockfile: wrote,
            dry_run: opts.dry_run,
            mode: opts.mode.as_str().to_owned(),
            capability_changes: resolution
                .diff
                .capability_changes
                .iter()
                .map(|d| qqq_run::CapabilityChangeReport {
                    package: d.package.clone(),
                    added: d.added.clone(),
                    removed: d.removed.clone(),
                })
                .collect(),
            changes: resolution.diff.changes.len(),
            escalation: resolution.diff.has_escalation(),
        })
    })
}

/// Dispatch `qqqai update`.
///
/// # Why the candidate set is empty
///
/// There is no registry (`PKG-006`), so there are no newer versions to consider.
/// Calling [`qqq_run::decide`] with an empty candidate list is not a stub: it is
/// the honest answer to "what can move?", which today is "nothing, and here is
/// why for each package". The value is the *explanation* — a user running
/// `update --dry-run` learns that `^1.2.3` is blocking `2.0.0`, which is a real
/// answer to a real question even with no registry.
///
/// What this must not do is write a lockfile claiming versions it never saw
/// (`§O-035c`).
fn dispatch_update(
    name: CommandName,
    args: &[String],
    flags: GlobalFlags,
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let opts = match update_options(args, flags) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    with_manifest(name, out, args, |loaded| {
        let path = qqq_run::lockfile_path(&loaded.path);
        let Some(previous) = qqq_run::read_lockfile(&path)? else {
            return Err(qqq_core::Error::new(
                qqq_core::ErrorCode::LockfileOutOfDate,
                format!(
                    "`{}` does not exist, so there is nothing to update",
                    path.display()
                ),
            )
            .with_remediation(format!(
                "run `{} install` first to resolve and write the lockfile",
                qqq_core::BINARY_NAME
            )));
        };

        // `--latest` plus an `exact = true` dependency is a contradiction, and
        // it is refused rather than resolved by precedence: the two state
        // opposite intents, and letting one silently win is how a user gets a
        // major upgrade they did not ask for.
        if opts.latest {
            for (dep_name, dep) in loaded
                .manifest
                .dependencies
                .iter()
                .chain(loaded.manifest.dev_dependencies.iter())
            {
                if matches!(dep, qqq_cap::manifest::Dependency::Full(d) if d.exact) {
                    return Err(qqq_run::contradictory_request(dep_name));
                }
            }
        }

        // The manifest's declared requirements, which is what bounds a move.
        let requirements: std::collections::BTreeMap<String, String> = loaded
            .manifest
            .dependencies
            .iter()
            .chain(loaded.manifest.dev_dependencies.iter())
            .map(|(n, d)| (n.clone(), d.requirement().to_owned()))
            .collect();

        // `NoRegistry` rather than an empty slice: the absence of a registry is
        // a named state, so this line is greppable when `PKG-006` lands and the
        // behaviour is a choice rather than an accident.
        let candidates = qqq_run::plan_update(
            &previous,
            &requirements,
            &qqq_run::NoRegistry,
            opts.strategy(),
        );

        let next = qqq_run::apply(&previous, &candidates);
        let d = qqq_run::diff(&previous, &next);

        let wrote = if opts.may_write() && !d.is_empty() {
            let mut lock = next.clone();
            lock.stamp(&format!(
                "{} {}",
                qqq_core::BINARY_NAME,
                qqq_core::SCHEMA_VERSION
            ));
            let text = lock.render()?;
            qqq_run::deps::write_manifest(&path, &text)?;
            true
        } else {
            false
        };

        let updated = qqq_run::moved_count(&candidates);

        Ok(qqq_run::UpdateOutput {
            lockfile: qqq_run::deps::display_manifest(&path),
            strategy: opts.strategy().as_str().to_owned(),
            dry_run: opts.dry_run,
            wrote_lockfile: wrote,
            updated,
            kept: candidates.len() - updated,
            capability_changes: d
                .capability_changes
                .iter()
                .map(|c| qqq_run::CapabilityChangeReport {
                    package: c.package.clone(),
                    added: c.added.clone(),
                    removed: c.removed.clone(),
                })
                .collect(),
            escalation: d.has_escalation(),
            candidates: qqq_run::report(&candidates, &previous),
        })
    })
}

/// Decode `qqqai update`'s flags.
///
/// # Errors
///
/// A QQQ-7001 usage error for an unrecognised flag.
fn update_options(
    args: &[String],
    flags: GlobalFlags,
) -> Result<qqq_run::UpdateOptions, qqq_core::Error> {
    let mut opts = qqq_run::UpdateOptions {
        // The global `--dry-run` applies here too, and it is the flag this
        // command most needs: an update's whole risk is what it changes, and a
        // rehearsal answers that without committing.
        dry_run: flags.dry_run(),
        ..Default::default()
    };

    for a in args {
        match a.as_str() {
            "--latest" => opts.latest = true,
            "--dry-run" => opts.dry_run = true,
            // Consumed by `with_manifest`.
            "--manifest" => {}
            other if other.starts_with('-') => {
                return Err(qqq_core::Error::new(
                    qqq_core::ErrorCode::McpArgumentInvalid,
                    format!("unknown flag `{other}` for `update`"),
                )
                .with_remediation("`update` accepts --latest, --dry-run and --manifest"));
            }
            // A bare package name is accepted and ignored for now: selecting a
            // subset needs the registry to have candidates at all, and silently
            // updating everything when the user named one package would be
            // worse than saying so.
            _ => {}
        }
    }

    Ok(opts)
}

/// Decode `qqqai install`'s flags.
///
/// # Errors
///
/// A QQQ-7001 usage error for an unrecognised flag.
fn install_options(
    args: &[String],
    flags: GlobalFlags,
) -> Result<qqq_run::InstallOptions, qqq_core::Error> {
    let mut opts = qqq_run::InstallOptions {
        // The global `--dry-run` applies here too: a rehearsal of an install is
        // useful precisely because it shows the capability diff without
        // committing to it.
        dry_run: flags.dry_run(),
        ..Default::default()
    };

    // The strictest flag given wins. `--frozen --offline` is a frozen install,
    // not a contradiction: the two agree on forbidding the network, and frozen
    // adds the lockfile requirement. Taking the strictest value means no
    // combination of flags can weaken the strongest one the user wrote.
    let mut mode = qqq_run::LockMode::Update;
    for a in args {
        match a.as_str() {
            "--locked" => mode = mode.max(qqq_run::LockMode::Locked),
            "--frozen" => mode = mode.max(qqq_run::LockMode::Frozen),
            "--offline" => mode = mode.max(qqq_run::LockMode::Offline),
            "--force" => opts.force = true,
            // Consumed by `with_manifest`, which reads the value itself.
            "--manifest" => {}
            other if other.starts_with('-') => {
                return Err(qqq_core::Error::new(
                    qqq_core::ErrorCode::McpArgumentInvalid,
                    format!("unknown flag `{other}` for `install`"),
                )
                .with_remediation(
                    "`install` accepts --locked, --frozen, --offline, --force, \
                     --dry-run and --manifest",
                ));
            }
            _ => {}
        }
    }
    opts.mode = mode;

    Ok(opts)
}

/// The parsed form of a `qqqai add` invocation.
struct AddRequest {
    edit: qqq_run::DependencyEdit,
    dev: bool,
}

/// Decode `qqqai add`'s own flags and its `name[@version]` argument.
///
/// # Errors
///
/// A QQQ-7001 usage error for a missing argument or an unknown flag, and a
/// QQQ-5004 error when the requirement is not valid semver.
fn add_options(args: &[String]) -> Result<AddRequest, qqq_core::Error> {
    // `--manifest` takes a value that this function does not otherwise use, so
    // it is tracked here only to skip the value rather than read it as the
    // package name.
    const TAKES_VALUE: [&str; 2] = ["--manifest", "--registry"];

    let mut spec: Option<String> = None;
    let mut dev = false;
    let mut exact = false;
    let mut features: Vec<String> = Vec::new();
    let mut source: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--dev" => dev = true,
            "--exact" => exact = true,
            "--feature" | "-F" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                features.push(v.clone());
                i += 1;
            }
            "--registry" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                source = Some(format!("registry+{v}"));
                i += 1;
            }
            other => {
                if TAKES_VALUE.contains(&other) {
                    i += 1;
                } else if other.starts_with('-') {
                    return Err(qqq_core::Error::new(
                        qqq_core::ErrorCode::McpArgumentInvalid,
                        format!("unknown flag `{other}` for `add`"),
                    )
                    .with_remediation(
                        "`add` accepts --dev, --exact, --feature, --registry and --manifest",
                    ));
                } else if spec.is_none() {
                    spec = Some(other.to_owned());
                } else {
                    return Err(qqq_core::Error::new(
                        qqq_core::ErrorCode::McpArgumentInvalid,
                        format!("`add` takes one package, but got a second: `{other}`"),
                    )
                    .with_remediation("run `add` once per package"));
                }
            }
        }
        i += 1;
    }

    let Some(spec) = spec else {
        return Err(qqq_core::Error::new(
            qqq_core::ErrorCode::McpArgumentInvalid,
            "`add` needs a package to add",
        )
        .with_remediation(format!(
            "for example: {} add qqqai/json@1.2",
            qqq_core::BINARY_NAME
        )));
    };

    let (name, requirement) = split_spec(&spec);
    // The default when no version is given. A bare `qqqai add foo` means "the
    // latest compatible release", which is what every other ecosystem does;
    // choosing anything else would surprise on the first command a user runs.
    let requirement = requirement.unwrap_or_else(|| "*".to_owned());

    // Parse with the real grammar. This is the check `qqq-cap` cannot make.
    qqq_pkg::Requirement::parse(&requirement).map_err(|e| {
        qqq_core::Error::new(
            qqq_core::ErrorCode::VersionUnsatisfiable,
            format!("`{requirement}` is not a version requirement: {e}"),
        )
        .with_remediation("write a version like `1.2`, `^1.2.3`, `~1.2.3`, `>=1.0, <2.0` or `*`")
    })?;

    let mut edit = qqq_run::DependencyEdit::new(name.clone(), requirement);
    edit.features = features;
    edit.source = source;
    edit.exact = exact;

    Ok(AddRequest { edit, dev })
}

/// Split `name@version` into its parts.
///
/// `rsplit_once` rather than `split_once`, because a scoped name may contain no
/// `@` today but a future npm-style scope (`@org/pkg@1.0`) has two — and
/// splitting on the first would take `org/pkg@1.0` as the version. The last `@`
/// is unambiguously the separator.
fn split_spec(spec: &str) -> (String, Option<String>) {
    match spec.rsplit_once('@') {
        Some((name, version)) if !name.is_empty() => (name.to_owned(), Some(version.to_owned())),
        // A leading `@` with no name before it is a scope, not a separator.
        _ => (spec.to_owned(), None),
    }
}

/// Decode `qqqai dev`'s own flags.
///
/// # Errors
///
/// A QQQ-7001 usage error for an unrecognised flag or an unparsable value.
fn dev_options(args: &[String]) -> Result<qqq_run::DevOptions, qqq_core::Error> {
    let mut opts = qqq_run::DevOptions::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--port" | "-p" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                opts.port = v
                    .parse()
                    .map_err(|_| bad_value(a, v, "a port number 1-65535"))?;
                i += 1;
            }
            "--host" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                v.clone_into(&mut opts.host);
                i += 1;
            }
            "--watch" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                opts.watch.push(v.clone());
                i += 1;
            }
            "--ignore" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                opts.ignore.push(v.clone());
                i += 1;
            }
            "--inspect" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                opts.inspect = Some(
                    v.parse()
                        .map_err(|_| bad_value(a, v, "a port number 1-65535"))?,
                );
                i += 1;
            }
            "--reload-limit" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value(a))?;
                opts.reload_limit = Some(
                    v.parse()
                        .map_err(|_| bad_value(a, v, "a positive whole number"))?,
                );
                i += 1;
            }
            "--once" => opts.set(qqq_run::DevOptions::ONCE),
            "--open" => opts.set(qqq_run::DevOptions::OPEN),
            "--https" => opts.set(qqq_run::DevOptions::HTTPS),
            "--deterministic" => opts.set(qqq_run::DevOptions::DETERMINISTIC),
            other => {
                if let Some(v) = other.strip_prefix("--port=") {
                    opts.port = v
                        .parse()
                        .map_err(|_| bad_value("--port", v, "a port number"))?;
                } else if let Some(v) = other.strip_prefix("--reload-limit=") {
                    opts.reload_limit = Some(
                        v.parse()
                            .map_err(|_| bad_value("--reload-limit", v, "a positive number"))?,
                    );
                } else if other == "--manifest" {
                    // Owned by `with_manifest`; skip its value.
                    i += 1;
                } else if other.starts_with('-') {
                    return Err(qqq_core::Error::new(
                        qqq_core::ErrorCode::McpArgumentInvalid,
                        format!("unknown flag `{other}` for `dev`"),
                    )
                    .with_remediation(
                        "`dev` accepts --port, --host, --watch, --ignore, --inspect, \
                         --open, --https and --once",
                    ));
                }
            }
        }
        i += 1;
    }
    Ok(opts)
}

/// The error for a flag whose value could not be parsed.
fn bad_value(flag: &str, got: &str, expected: &str) -> qqq_core::Error {
    qqq_core::Error::new(
        qqq_core::ErrorCode::McpArgumentInvalid,
        format!("`{got}` is not valid for `{flag}`"),
    )
    .with_remediation(format!("expected {expected}"))
}

/// The error for an unrecognised choice, listing the valid ones.
fn unknown_choice(kind: &str, got: &str, valid: &[&str]) -> qqq_core::Error {
    qqq_core::Error::new(
        qqq_core::ErrorCode::McpArgumentInvalid,
        format!("`{got}` is not a known {kind}"),
    )
    .with_remediation(format!("choose one of: {}", valid.join(", ")))
}

/// Load the project manifest, run `f`, and emit the result.
///
/// # Why every capability command shares this
///
/// So that manifest discovery, the `--manifest` flag and error reporting are
/// identical across `why`, `caps` and `inspect`. A command that found a
/// different manifest than another would produce a capability report that
/// disagrees with what the runtime enforces — and the disagreement would be
/// invisible until it mattered.
fn with_manifest<T, F>(
    name: CommandName,
    out: &mut Output<std::io::Stdout>,
    args: &[String],
    f: F,
) -> ExitCode
where
    T: qqq_run::output::CommandOutput,
    F: FnOnce(&qqq_run::LoadedManifest) -> qqq_core::Result<T>,
{
    let explicit = flag_value(args, "--manifest").map(std::path::PathBuf::from);
    with_manifest_at(name, out, explicit.as_deref(), f)
}

/// Load a manifest from an explicit path, or discover one, and hand it to `f`.
///
/// # Why the path is a parameter and not a flag name
///
/// Because two commands name the same thing differently: `--manifest` is the global flag,
/// and `serve` documents `--config`. A helper that took the *flag name* would have to know
/// which command was calling it, and the version that guessed — always reading `--manifest` —
/// silently ignored `serve --config`. Taking the resolved path removes the question, and the
/// caller that owns the flag does the reading.
fn with_manifest_at<T, F>(
    name: CommandName,
    out: &mut Output<std::io::Stdout>,
    explicit: Option<&std::path::Path>,
    f: F,
) -> ExitCode
where
    T: qqq_run::output::CommandOutput,
    F: FnOnce(&qqq_run::LoadedManifest) -> qqq_core::Result<T>,
{
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    let loaded = match qqq_run::LoadedManifest::discover(&cwd, explicit) {
        Ok(l) => l,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    match f(&loaded) {
        Ok(value) => report(out, name, &value),
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::FAILURE);
            ExitCode::from(exit::FAILURE)
        }
    }
}

/// As [`with_manifest_at`], but the value decides the exit status.
///
/// # Why this exists
///
/// Some commands answer a question whose *negative* answer is the useful one.
/// `qqqai why <cap>` reporting `DENIED` is exactly what a CI gate wants to see, and
/// it must be distinguishable from a grant by exit status or the gate cannot read
/// it. Measured before this existed: `qqqai why sql.execute` printed the denial and
/// the fix stanza, and exited **0**, so a granted and a denied capability looked
/// identical to a script.
///
/// Discovery is shared with [`with_manifest_at`] rather than re-implemented, because
/// two capability commands that found different manifests would report grants that
/// disagree with what the runtime enforces — and the disagreement would be invisible
/// until it mattered.
fn with_manifest_verdict<T, F, V>(
    name: CommandName,
    out: &mut Output<std::io::Stdout>,
    args: &[String],
    f: F,
    verdict: V,
) -> ExitCode
where
    T: qqq_run::output::CommandOutput,
    F: FnOnce(&qqq_run::LoadedManifest) -> qqq_core::Result<T>,
    V: FnOnce(&T) -> u8,
{
    let explicit = flag_value(args, "--manifest").map(std::path::PathBuf::from);
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    let loaded = match qqq_run::LoadedManifest::discover(&cwd, explicit.as_deref()) {
        Ok(l) => l,
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    };

    match f(&loaded) {
        Ok(value) => report_with_verdict(out, name, &value, verdict),
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::FAILURE);
            ExitCode::from(exit::FAILURE)
        }
    }
}

/// Dispatch `qqqai caps`, with `--explain`.
///
/// # Why an unknown flag is refused
///
/// Measured defect: `qqqai caps --explain` produced **byte-identical output** to
/// `qqqai caps`. The flag was never parsed, so it was neither honoured nor rejected — and
/// a reject would at least have told the user. `§5.2` documents `--explain` and
/// `audit.rs` tells the reader to run it, so the directive was reaching a command that
/// silently ignored it. `--explan` behaved the same way, which is the worse half: a typo
/// that succeeds is undetectable.
///
/// `--manifest` is passed through rather than consumed here, because
/// `with_manifest_verdict` owns it and reads its value.
fn dispatch_caps(
    name: CommandName,
    out: &mut Output<std::io::Stdout>,
    args: &[String],
) -> ExitCode {
    let mut explain = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--explain" => explain = true,
            "--manifest" => i += 1,
            other if other.starts_with('-') => {
                let err = qqq_core::Error::new(
                    qqq_core::ErrorCode::McpArgumentInvalid,
                    format!("unknown flag `{other}` for `caps`"),
                )
                .with_remediation(
                    "`caps` takes `--explain` (show which layer decided each capability) and \
                     the global `--manifest`",
                );
                let _ = out.emit_error_with_exit(name, &err, exit::USAGE);
                return ExitCode::from(exit::USAGE);
            }
            _ => {}
        }
        i += 1;
    }
    with_manifest(name, out, args, |loaded| {
        Ok(qqq_run::commands::caps(loaded, explain))
    })
}

/// `qqqai why <capability>` with a status that reflects the decision.
///
/// # Why a denial is non-zero
///
/// §5.2 defines the command as explaining "why a capability was or was not granted".
/// The second half is the one a CI gate uses — "assert this build cannot reach the
/// network" is `qqqai why http.client` — and a gate needs a status, because parsing
/// prose is not a contract. `exit::FAILURE` rather than a new code: a denial is the
/// command's own negative answer, not a usage mistake and not an internal error, and
/// the human output already names the decision, so the status agrees with the text
/// rather than contradicting it.
fn dispatch_why(
    name: CommandName,
    out: &mut Output<std::io::Stdout>,
    args: &[String],
    cap: &str,
) -> ExitCode {
    with_manifest_verdict(
        name,
        out,
        args,
        |loaded| qqq_run::commands::why(loaded, cap),
        |w| if w.granted { exit::OK } else { exit::FAILURE },
    )
}

/// Read the value following a flag, e.g. `--manifest path/to/qqq.toml`.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let idx = args.iter().position(|a| a == flag)?;
    args.get(idx + 1).cloned()
}

/// Decode `qqqai build`'s own flags.
///
/// # Why an unknown flag is an error here
///
/// The global parser forwards anything after the command name untouched, which
/// is right for commands that define their own options — and wrong for a typo.
/// `qqqai build --relase` would otherwise build a debug artifact and report
/// success, and the user would discover the mistake only by noticing the binary
/// is slow. Rejecting it names the mistake at the point it was made.
///
/// # Errors
///
/// A QQQ-7001 usage error naming the unrecognised flag.
fn build_options(args: &[String]) -> Result<qqq_run::BuildOptions, qqq_core::Error> {
    // Flags that take a value and must not be mistaken for boolean switches.
    const TAKES_VALUE: [&str; 2] = ["--manifest", "--target"];

    let mut bits = 0u8;
    let mut target: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--release" => bits |= qqq_run::BuildOptions::RELEASE,
            "--debug" => bits |= qqq_run::BuildOptions::DEBUG,
            "--aot" | "--emit-cwasm" => bits |= qqq_run::BuildOptions::AOT,
            "--reproducible" => bits |= qqq_run::BuildOptions::REPRODUCIBLE,
            "--target" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value("--target"))?;
                target = Some(v.clone());
                i += 1;
            }
            other => {
                // A value-taking flag this function does not own (e.g.
                // `--manifest`) is consumed with its value so the value is not
                // then rejected as an unknown positional.
                if TAKES_VALUE.contains(&other) {
                    i += 1;
                } else if let Some(stripped) = other.strip_prefix("--target=") {
                    target = Some(stripped.to_owned());
                } else if other.starts_with('-') {
                    return Err(qqq_core::Error::new(
                        qqq_core::ErrorCode::McpArgumentInvalid,
                        format!("unknown flag `{other}` for `build`"),
                    )
                    .with_remediation(
                        "`build` accepts --release, --debug, --target, --aot and --reproducible",
                    ));
                }
                // A bare positional is ignored rather than rejected: `qqqai
                // build .` is a habit from other tools and harms nothing.
            }
        }
        i += 1;
    }
    Ok(qqq_run::BuildOptions::from_flags(bits, target))
}

/// The error for a flag that needs a value and did not get one.
fn missing_value(flag: &str) -> qqq_core::Error {
    qqq_core::Error::new(
        qqq_core::ErrorCode::McpArgumentInvalid,
        format!("`{flag}` needs a value"),
    )
    .with_remediation(format!("for example: {flag} wasm32-wasip2"))
}

/// Decode `qqqai run`'s own flags.
///
/// # Why `--` matters here specifically
///
/// `run` forwards arguments to the component, and a component's own arguments
/// may look exactly like ours — `qqqai run -- --json` must pass `--json` to the
/// guest, not consume it. Without `--` as an explicit separator there is no way
/// to tell the two apart, so anything after `--` is collected verbatim.
///
/// # Errors
///
/// A QQQ-7001 usage error for an unrecognised flag or a flag missing its value.
fn run_options(
    args: &[String],
    flags: GlobalFlags,
) -> Result<qqq_run::RunOptions, qqq_core::Error> {
    // Flags owned by the global parser or `with_manifest`, which take a value.
    const TAKES_VALUE: [&str; 2] = ["--manifest", "--artifact"];

    let mut opts = qqq_run::RunOptions {
        dry_run: flags.dry_run(),
        ..Default::default()
    };
    let mut after_separator = false;
    let mut i = 0;

    while i < args.len() {
        let a = args[i].as_str();
        if after_separator {
            opts.args.push(a.to_owned());
            i += 1;
            continue;
        }
        match a {
            "--" => after_separator = true,
            // `run`'s own `deterministic` is a plain field, unlike `dev`'s
            // bitfield: `run` has only one switch, and a bitfield for one flag
            // would be ceremony.
            "--deterministic" => opts.deterministic = true,
            "--artifact" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value("--artifact"))?;
                opts.artifact = Some(std::path::PathBuf::from(v));
                i += 1;
            }
            "--cap" => {
                let v = args.get(i + 1).ok_or_else(|| missing_value("--cap"))?;
                opts.caps.push(v.clone());
                i += 1;
            }
            other => {
                if let Some(v) = other.strip_prefix("--artifact=") {
                    opts.artifact = Some(std::path::PathBuf::from(v));
                } else if let Some(v) = other.strip_prefix("--cap=") {
                    opts.caps.push(v.to_owned());
                } else if TAKES_VALUE.contains(&other) {
                    // `--manifest` is consumed by `with_manifest`; skip its
                    // value here so it is not mistaken for a positional.
                    i += 1;
                } else if other.starts_with('-') {
                    return Err(qqq_core::Error::new(
                        qqq_core::ErrorCode::McpArgumentInvalid,
                        format!("unknown flag `{other}` for `run`"),
                    )
                    .with_remediation(
                        "`run` accepts --cap, --artifact, --deterministic and -- <args>; \
                         use `--` before arguments meant for the component",
                    ));
                }
                // A bare positional names the artifact, when no `--artifact`
                // was given.
                //
                // It previously went into `opts.args` — passed to the *component*
                // — which meant `qqqai run ./needs-clock.wasm` silently ran the
                // project's built component instead, and reported success. That
                // is the same defect `qqqai inspect` had (`§O-038a`): the
                // argument was accepted and discarded, so the user got a
                // confident answer about something they had not asked for.
                //
                // The remediation text already told users to put component
                // arguments after `--`, so this makes the code match the
                // documented contract rather than inventing one.
                else if opts.artifact.is_none() && !after_separator {
                    opts.artifact = Some(std::path::PathBuf::from(a));
                }
                // Anything after `--` belongs to the component.
                else {
                    opts.args.push(a.to_owned());
                }
            }
        }
        i += 1;
    }
    Ok(opts)
}

/// Emit a successful result and convert it into an exit code.
///
/// A write failure means the *output* could not be delivered, which is a
/// different failure from the command itself failing — hence `INTERNAL` rather
/// than `FAILURE`.
fn report<T: qqq_run::output::CommandOutput>(
    out: &mut Output<std::io::Stdout>,
    name: CommandName,
    value: &T,
) -> ExitCode {
    report_with_verdict(out, name, value, |_| exit::OK)
}

/// Emit a successful result whose exit status depends on what it contains.
///
/// # Why the verdict is a closure
///
/// `qqqai doctor` succeeds and exits non-zero when a check fails, and the
/// envelope must carry the number the process returns. Building the output
/// first and overriding the exit code afterwards is how those two drifted:
/// the struct was constructed before the code was known, so it could only
/// guess. Here the code is computed from the output *before* emission, and the
/// same value is both serialised and returned — one number, two consumers.
fn report_with_verdict<T, F>(
    out: &mut Output<std::io::Stdout>,
    name: CommandName,
    value: &T,
    verdict: F,
) -> ExitCode
where
    T: qqq_run::output::CommandOutput,
    F: FnOnce(&T) -> u8,
{
    let code = verdict(value);
    match out.emit_with_exit(value, code) {
        Ok(()) => ExitCode::from(code),
        Err(e) => {
            let _ = out.emit_error_with_exit(name, &e, exit::INTERNAL);
            ExitCode::from(exit::INTERNAL)
        }
    }
}

/// Dispatch `qqqai schema`, honouring `--all` and `--command <name>`.
///
/// # The two flags, and why neither is a no-op
///
/// Measured before this existed: `qqqai schema --all` and `qqqai schema --command caps`
/// both printed `27 commands, 40 error codes, 24 capabilities` — the same human summary,
/// with the flags parsed as unknown and dropped. §8.3 specifies one JSON document as *the*
/// thing that makes QQQ teachable to a model that has never seen it, and §2.1 NN-1 says an
/// agent "can be given `qqqai schema --all`". It could not be, because the flag did nothing.
///
/// `--all` is therefore the default rather than a modifier with a different default: there
/// is no other sensible reading of the bare command, and `--all` exists so a script that
/// spells its intent gets the same answer as one that does not.
fn dispatch_schema(
    name: CommandName,
    out: &mut Output<std::io::Stdout>,
    args: &[String],
) -> ExitCode {
    let mut only: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            // Accepted and identical to the bare command; see the doc comment.
            "--all" | "--errors" => {}
            "--command" => {
                let Some(v) = args.get(i + 1) else {
                    let err = qqq_core::Error::new(
                        qqq_core::ErrorCode::McpArgumentInvalid,
                        "`--command` needs a command name",
                    )
                    .with_remediation("for example: qqqai schema --command caps");
                    let _ = out.emit_error_with_exit(name, &err, exit::USAGE);
                    return ExitCode::from(exit::USAGE);
                };
                only = Some(v.clone());
                i += 1;
            }
            other => {
                let err = qqq_core::Error::new(
                    qqq_core::ErrorCode::McpArgumentInvalid,
                    format!("unknown flag `{other}` for `schema`"),
                )
                .with_remediation("`schema` takes `--all`, `--errors`, `--command <name>`");
                let _ = out.emit_error_with_exit(name, &err, exit::USAGE);
                return ExitCode::from(exit::USAGE);
            }
        }
        i += 1;
    }

    // An unknown command name is refused rather than answered with an empty map: an empty
    // `commands` reads as "this command has no schema", when the truth is "that command
    // does not exist". §12.6's rule that ambiguity is a defect applies to the machine
    // contract most of all.
    if let Some(want) = &only {
        let known: Vec<&str> = CommandName::all().iter().map(|c| c.as_str()).collect();
        if !known.contains(&want.as_str()) {
            let err = qqq_core::Error::new(
                qqq_core::ErrorCode::McpArgumentInvalid,
                format!("`{want}` is not a command"),
            )
            .with_remediation(format!("known commands: {}", known.join(", ")));
            let _ = out.emit_error_with_exit(name, &err, exit::USAGE);
            return ExitCode::from(exit::USAGE);
        }
    }

    report(out, name, &SchemaDocument { only })
}

/// The `qqqai schema` payload, in the shape §8.3 specifies.
///
/// # Why a struct and not `serde_json::json!`
///
/// Because the field names are the contract. §8.3 writes `schemaVersion` in camelCase and
/// the four existing fields were emitted in `snake_case`, so a consumer generated from the
/// Proposal's example would have found `schema_version`. The rename is applied here, once.
#[derive(Debug, Clone, serde::Serialize)]
struct SchemaDocument {
    /// Narrowed to one command, or every command.
    #[serde(skip_serializing_if = "Option::is_none")]
    only: Option<String>,
}

impl qqq_run::output::CommandOutput for SchemaDocument {
    fn command(&self) -> CommandName {
        CommandName::Schema
    }

    fn summary(&self) -> String {
        // The human format is a *pointer*, not the document: a reader who asked for the
        // machine contract wants the JSON, and printing forty kilobytes of it would bury
        // the fact. The count is followed by how to get it.
        match &self.only {
            Some(c) => {
                format!("schema for `{c}`; run `qqqai schema --all --json` for the full document")
            }
            None => format!(
                "{} commands, {} error codes, {} capabilities; run with `--json` for the \
                 full document",
                qqq_run::output::command_schemas().len(),
                qqq_core::ErrorCode::all().len(),
                qqq_cap::Capability::all().len()
            ),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        let all = qqq_run::output::command_schemas();
        let commands: Vec<_> = match &self.only {
            Some(want) => all.into_iter().filter(|c| c.command == want).collect(),
            None => all,
        };

        let mut doc = serde_json::json!({
            // §8.3: `"qqqai": "1.0.0"` — the CLI's own version, distinct from the schema
            // version, because a CLI can gain a command without the wire format moving.
            "qqqai": qqq_core::VERSION,
            "schemaVersion": qqq_core::SCHEMA_VERSION,
            "commands": commands,
            "errors": error_catalogue(),
            "manifest": manifest_schema(),
            "capabilities": capability_catalogue(),
            "wit": wit_catalogue(),
            "mcp": mcp_catalogue(),
        });

        // A narrowed request carries the name it asked for at the top level, so the caller
        // does not have to search a one-element array to confirm what it got.
        if let Some(c) = &self.only {
            doc["command"] = serde_json::Value::String(c.clone());
        }
        doc
    }
}

/// The `manifest` section of §8.3's document.
///
/// Carries the section names the parser knows, taken from the same table the manifest
/// schema generator uses, so the two cannot disagree about what a manifest may contain.
fn manifest_schema() -> serde_json::Value {
    serde_json::json!({
        "sections": [
            "package", "capabilities", "limits", "server", "dependencies",
            "languages", "build", "covert_channels"
        ],
        "path": "qqq.toml",
        "note": "Each section's full JSON Schema is emitted by `qqqai schema` for the \
                 manifest itself; this lists what the parser accepts.",
    })
}

/// The `wit` section of §8.3's document.
///
/// # Why `complete` is stated rather than omitted
///
/// The proposal asks for "machine-readable interface descriptions". What exists is the WIT
/// package registry, whose documents are the `.wit` files under `wit/` — already
/// machine-readable, and already validated by `check_wit.py`. Reproducing them here would be
/// a second copy of the same text, which is the drift this project removes wherever it finds
/// it. So the section names the packages and says where the definitions live, and says so
/// explicitly rather than leaving a reader to infer it.
fn wit_catalogue() -> serde_json::Value {
    serde_json::json!({
        "interfaces": qqq_run::output::wit_interfaces(),
        "complete": false,
        "note": "the definitions are the `.wit` files under `wit/`, which are themselves \
                 machine-readable; this describes the registry the host dispatches through",
    })
}

/// The `mcp` section of §8.3's document.
fn mcp_catalogue() -> serde_json::Value {
    serde_json::json!({
        "tools": qqq_run::output::mcp_tool_names(),
        "complete": false,
        "note": "tool schemas are emitted by `qqqai mcp --list`. `CLI-022` is open; the \
                 names are listed here so a consumer can see the surface",
    })
}

/// The error catalogue, for `qqqai schema --all`.
fn error_catalogue() -> Vec<serde_json::Value> {
    qqq_core::ErrorCode::all()
        .iter()
        .map(|c| {
            serde_json::json!({
                "code": c.id(),
                "class": c.class().as_str(),
                "retryable": c.is_retryable(),
                "docs_url": c.docs_url(),
            })
        })
        .collect()
}

/// The capability catalogue, for `qqqai schema --all`.
fn capability_catalogue() -> Vec<serde_json::Value> {
    qqq_cap::Capability::all()
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name(),
                "namespace": c.namespace(),
                "kind": c.kind().as_str(),
                "covert_channel": c.is_covert_channel(),
            })
        })
        .collect()
}

/// One environment check.
#[derive(serde::Serialize)]
struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
    fix: Option<String>,
}

/// The target every QQQ guest is compiled to.
///
/// A constant so the check, its remedy and the tests all name the same target.
const WASM_TARGET: &str = "wasm32-wasip2";

/// A repair `doctor` could perform, described before it is performed.
///
/// # Why the command is held as fields rather than as one string
///
/// Because the two claims are different: `what` is what the repair is for, and
/// the command is what runs. Storing them together lets `--fix` print a plan a
/// reader can approve without looking anything up.
///
/// # Why the plan is a value and not a function
///
/// `doctor` must not repair anything it cannot describe. `fix_for` builds a
/// plan, `apply_fixes` prints it, and only then does [`FixPlan::apply`] run it —
/// so the printed plan and the executed command cannot diverge, because they are
/// the same value.
struct FixPlan {
    /// What this repairs, in the reader's terms.
    what: String,
    /// The command a person would type, kept for display.
    command: String,
    /// The program to spawn.
    program: String,
    /// Its arguments.
    argv: Vec<String>,
    /// Whether running this reaches the network.
    ///
    /// # Why this is a field and not a string match
    ///
    /// `apply_fixes` originally decided whether a repair was safe to run
    /// automatically with `plan.command.contains("target add")` — the policy read
    /// out of the display text. That makes the display string load-bearing:
    /// rewording the message, or adding a repair whose command merely mentions
    /// "target add", would silently change what runs. The property is declared
    /// where the plan is built and read from the field, so the policy and the
    /// text are independent.
    reaches_network: bool,
}

impl FixPlan {
    /// Run the repair, returning the program's own output.
    ///
    /// The exit status is **not** an error here: a failing `rustup` produces a
    /// diagnostic message that belongs in the report, and turning it into a
    /// `Result::Err` would replace that message with a summary. Nothing here
    /// claims the repair worked — the caller's re-run of the checks is the only
    /// verdict, and it is the caller that performs it.
    fn apply(&self) -> std::io::Result<String> {
        let output = std::process::Command::new(&self.program)
            .args(&self.argv)
            .output()?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok(text.trim().to_owned())
    }
}

/// Is the wasm target actually installed?
///
/// # Why this is a real probe
///
/// This check used to be `ok: true` with a comment saying that shelling out to
/// `rustup` "would exceed the startup budget and is the build command's job to
/// verify". Both halves of that were wrong. It is the *doctor's* job — that is
/// what a doctor is — and the check could never fail, so it printed
/// `ok wasm-target` while measuring nothing: a green light for an unmeasured
/// thing, the same class as the validator with no positive control the dispatch
/// arm already calls out.
///
/// Three real measurements, in order of cost:
///
/// 1. `QQQ_TEST_WASM_TARGET_PRESENT` is this function's own escape hatch: `0`
///    forces "absent" and any other value forces "present", so the negative
///    case is testable on a machine that has the target. Nothing in the
///    product or in CI sets it — a grep for the name finds this file and its
///    tests only. It is a hook on the probe, not a configuration knob, and the
///    doc comment that described it as one was wrong.
/// 2. The target's own directory under `$RUSTUP_HOME`, or `~/.rustup`, is a
///    file-system read — no subprocess, no budget question.
/// 3. Otherwise ask `rustup` itself.
///
/// A missing `rustup` binary is reported as *not present* rather than as an
/// error: `qqqai build` cannot reach the target without it, so that is the
/// truthful answer to the question the check asks.
fn wasm_target_present() -> bool {
    wasm_target_present_with(&WasmProbeInputs::from_environment())
}

/// The probe's external inputs, passed in rather than read from globals.
///
/// # Why the probe takes parameters
///
/// The first version read `std::env` directly, and its test therefore had to
/// call `set_var`/`remove_var`. In a test binary that is **shared mutable
/// state**: the variables are process-wide, the harness runs tests in parallel
/// threads, and a value set by one test is visible to every other. The test
/// failed on its first run for exactly this reason — it asserted that an *unset*
/// variable reported `false`, which holds only on a machine without the target.
///
/// Injecting the inputs removes the shared state: the test builds a value and
/// passes it, so no test can observe another's setting and none has to mutate the
/// process environment.
#[derive(Debug)]
struct WasmProbeInputs {
    /// `QQQ_TEST_WASM_TARGET_PRESENT`, if set.
    override_present: Option<String>,
    /// `rustc --print sysroot`, if rustc ran successfully.
    sysroot: Option<std::path::PathBuf>,
    /// The rustup home, whose `toolchains/` directory is the fallback.
    rustup_home: Option<std::path::PathBuf>,
    /// Whether a `rustup` binary is available.
    rustup_available: bool,
}

impl WasmProbeInputs {
    /// Gather every input by reading the environment and running the probes.
    fn from_environment() -> Self {
        let sysroot = std::process::Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| std::path::PathBuf::from(String::from_utf8_lossy(&o.stdout).trim().to_owned()))
            .filter(|p| !p.as_os_str().is_empty());

        Self {
            override_present: std::env::var("QQQ_TEST_WASM_TARGET_PRESENT").ok(),
            sysroot,
            rustup_home: std::env::var_os("RUSTUP_HOME")
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    std::env::var_os("USERPROFILE")
                        .or_else(|| std::env::var_os("HOME"))
                        .map(|h| std::path::PathBuf::from(h).join(".rustup"))
                }),
            rustup_available: rustup_on_path(),
        }
    }
}

/// Is `wasm32-wasip2` installed for the toolchain that will actually build?
///
/// # Why the active sysroot and not every toolchain
///
/// The first version scanned `<rustup home>/toolchains/*/lib/rustlib/<target>`
/// and returned true if **any** toolchain had the target. That answers a
/// different question. `rustc` picks one toolchain — this crate's
/// `rust-toolchain.toml` pins it, and a `rustup override` can redirect it — and
/// `qqqai build` uses that one. A machine with `wasm32-wasip2` on a toolchain the
/// project does not use would pass the check and fail the build, which is the
/// false confidence `doctor` exists to remove, reintroduced by another route.
///
/// `rustc --print sysroot` names the active toolchain's sysroot, and the target's
/// directory under it is the one the build will look for. The scan remains as a
/// fallback for when `rustc` cannot run but the directory is plainly there.
fn wasm_target_present_with(inputs: &WasmProbeInputs) -> bool {
    match inputs.override_present.as_deref() {
        Some("0") => return false,
        Some(_) => return true,
        None => {}
    }

    // The active toolchain's own sysroot — the same path the build resolves.
    //
    // When `rustc --print sysroot` succeeded, its answer is **final**: a target
    // installed on some other toolchain is not installed for this build, so
    // falling through to the scan would answer a different question and pass a
    // machine that cannot build. The scan is reached only when there is no
    // sysroot to ask — `rustc` absent or unusable.
    if let Some(sysroot) = &inputs.sysroot {
        return sysroot
            .join("lib")
            .join("rustlib")
            .join(WASM_TARGET)
            .is_dir();
    }

    // Fallback: some mounted toolchain has it. Weaker evidence than the
    // sysroot, which is why it is second.
    if let Some(home) = &inputs.rustup_home {
        if home.join("toolchains").read_dir().is_ok_and(|entries| {
            entries.flatten().any(|e| {
                e.path()
                    .join("lib")
                    .join("rustlib")
                    .join(WASM_TARGET)
                    .is_dir()
            })
        }) {
            return true;
        }
    }

    // Last resort: ask rustup, which is authoritative about what is installed
    // even when the directory layout is unfamiliar.
    inputs.rustup_available
        && std::process::Command::new("rustup")
            .args(["target", "list", "--installed"])
            .output()
            .is_ok_and(|o| {
                o.status.success()
                    && String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .any(|l| l.trim() == WASM_TARGET)
            })
}

/// What `doctor` would do with `--fix`, and what it did.
#[derive(serde::Serialize)]
struct FixOutcome {
    /// Whether repairs were requested.
    requested: bool,
    /// One line per repair plan — always populated when `requested`.
    planned: Vec<String>,
    /// One line per repair actually run.
    applied: Vec<String>,
    /// Repairs that were deliberately not run, and why.
    skipped: Vec<String>,
}

/// Reject any flag the command does not understand.
///
/// # Why a command must do this
///
/// `parse_args` forwards an unrecognised flag that appears *after* the command
/// name, because that is how a command declares its own options. The cost is
/// that a flag the command never learned about is silently swallowed:
/// `qqqai doctor --fix` behaved exactly like `qqqai doctor` while `--fix` was
/// unimplemented, and a mistyped `--jsonn` is accepted by every command in the
/// same way. Silently ignoring an argument is worse than refusing it — the user
/// believes the option took effect, and the *absence* of its effect is then a
/// mystery rather than an error.
///
/// Returns the error rather than emitting it so the caller keeps ownership of
/// its output sink, matching the shape of the other dispatch helpers.
fn reject_unknown_flags(
    name: CommandName,
    args: &[String],
    accepted: &[&str],
) -> Option<qqq_core::Error> {
    let unknown = args
        .iter()
        .filter(|a| a.starts_with('-'))
        .find(|a| !accepted.contains(&a.as_str()))?;
    let mut listing = accepted.join(", ");
    if listing.is_empty() {
        "no flags".clone_into(&mut listing);
    }
    Some(
        qqq_core::Error::new(
            qqq_core::ErrorCode::CliFlagUnknown,
            format!("`{name}` does not accept `{unknown}`"),
        )
        .with_remediation(format!("`{name}` accepts {listing}")),
    )
}

/// Refuse a flag the command does not accept, emitting the error itself.
///
/// Returns the exit code to return, or `None` when every flag is understood.
/// Extracted from the `Doctor` arm so that arm stays inside the crate's
/// 100-line budget: the check is four lines of control flow that belong with
/// [`reject_unknown_flags`] rather than inline at the dispatch site, and
/// silencing the lint would have hidden the growth instead of removing it.
fn refuse_flags(
    name: CommandName,
    args: &[String],
    accepted: &[&str],
    out: &mut Output<std::io::Stdout>,
) -> Option<ExitCode> {
    let err = reject_unknown_flags(name, args, accepted)?;
    let _ = out.emit_error_with_exit(name, &err, exit::USAGE);
    Some(ExitCode::from(exit::USAGE))
}

/// The repair for each failing check, if one exists.
///
/// # Why `wasm-target` has no automatic repair
///
/// `rustup target add` downloads a toolchain component. A diagnostic command
/// that silently fetches from the network is a supply-chain decision made
/// without the user's consent, so it is planned, printed and left to the user.
/// The alternative — running it because `--fix` was passed — would make
/// `qqqai doctor --fix` in a `curl | sh` script a remote-code-install with no
/// prompt. [`FixPlan`] exists precisely because `libloading`-style `dlopen` and
/// `rustup`-style installs are the two things that must be *described* before
/// they happen.
fn fix_for(name: &str, rustup_present: bool) -> Option<FixPlan> {
    if name != "wasm-target" {
        return None;
    }
    if !rustup_present {
        return None;
    }
    Some(FixPlan {
        what: format!("install the {WASM_TARGET} rustup target"),
        command: format!("rustup target add {WASM_TARGET}"),
        program: "rustup".to_owned(),
        argv: vec![
            "target".to_owned(),
            "add".to_owned(),
            WASM_TARGET.to_owned(),
        ],
        // `rustup target add` downloads a toolchain component.
        reaches_network: true,
    })
}

/// Whether a `rustup` binary is on `PATH` — asked once, used by [`fix_for`].
fn rustup_on_path() -> bool {
    std::process::Command::new("rustup")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The `qqqai doctor` checks.
///
/// Ordered so the most likely first-run problem appears first. Each carries a
/// `fix`, because a diagnosis without a remedy is only half the job.
fn run_doctor() -> Vec<Check> {
    let mut checks = Vec::new();

    checks.push(Check {
        name: "binary-name",
        ok: qqq_core::BINARY_NAME == "qqqai",
        detail: format!("running as `{}`", qqq_core::BINARY_NAME),
        fix: (qqq_core::BINARY_NAME != "qqqai").then(|| {
            "the binary must be named `qqqai`; `qqq` is taken on crates.io and npm".to_owned()
        }),
    });

    // The working directory must contain a manifest for project commands.
    let manifest = std::path::Path::new("qqq.toml");
    checks.push(Check {
        name: "manifest",
        ok: manifest.exists(),
        detail: if manifest.exists() {
            "qqq.toml found in the current directory".to_owned()
        } else {
            "no qqq.toml in the current directory".to_owned()
        },
        fix: (!manifest.exists()).then(|| {
            format!(
                "run `{} new <name>` to create a project",
                qqq_core::BINARY_NAME
            )
        }),
    });

    // The wasm target is required to build anything, so it is really probed:
    // see [`wasm_target_present`] for why the old `ok: true` was a defect.
    let target = wasm_target_present();
    checks.push(Check {
        name: "wasm-target",
        ok: target,
        detail: if target {
            format!("the {WASM_TARGET} target is installed")
        } else {
            format!("the {WASM_TARGET} target is not installed")
        },
        fix: (!target).then(|| format!("run `rustup target add {WASM_TARGET}`")),
    });

    checks
}

/// Run `--fix`, returning what was planned, applied and deliberately skipped.
///
/// # The two rules this function exists to enforce
///
/// 1. **A repair that is not planned is not printed, and a repair that is not
///    printed is not run.** Without `--fix` nothing at all is executed, so a
///    bare `qqqai doctor` stays a pure diagnostic — that is the whole point of
///    a doctor.
/// 2. **Network-touching repairs are planned and printed but never run.**
///    `rustup target add` downloads a toolchain component, and a diagnostic
///    command that silently installs software because a flag was present is a
///    supply-chain decision taken on the user's behalf. It is listed under
///    `skipped`, with its exact command, so the user runs it deliberately.
///
/// The verdict on whether a repair worked is the re-run of the check, not the
/// repair's exit status — which is why nothing here claims success.
fn apply_fixes(checks: &[Check], requested: bool) -> FixOutcome {
    let mut outcome = FixOutcome {
        requested,
        planned: Vec::new(),
        applied: Vec::new(),
        skipped: Vec::new(),
    };
    if !requested {
        return outcome;
    }

    let rustup = rustup_on_path();
    for check in checks.iter().filter(|c| !c.ok) {
        let Some(plan) = fix_for(check.name, rustup) else {
            // A failing check with no automatic repair still has a `fix` line
            // for the reader; naming it as skipped is what distinguishes "the
            // doctor has no remedy" from "the doctor has a remedy and chose not
            // to run it".
            outcome.skipped.push(format!(
                "{}: {}",
                check.name,
                check.fix.as_deref().unwrap_or("no automatic repair")
            ));
            continue;
        };
        // Both halves are shown: the shell command is what runs, `what` is
        // what it is for. A plan line with only the command makes the reader
        // look up `rustup target add` to decide whether to approve it.
        outcome
            .planned
            .push(format!("{} — `{}`", plan.what, plan.command));
        // A network fetch is never automatic: see the function comment. The
        // decision reads the plan's own property rather than its display text.
        if plan.reaches_network {
            outcome.skipped.push(format!(
                "{}: `{}` downloads a toolchain component, so it was not run",
                check.name, plan.command
            ));
            // `planned` and `skipped` are both populated for this plan on
            // purpose: the reader sees what was considered *and* what was
            // declined, which is the audit the `--fix` contract promises.
            continue;
        }
        // Allow-listed: only plans whose command was just added to `planned`
        // reach here, and `fix_for` is the single source of those.
        match plan.apply() {
            Ok(text) if text.is_empty() => outcome.applied.push(plan.command),
            Ok(text) => outcome.applied.push(format!("{}: {text}", plan.command)),
            Err(err) => outcome.skipped.push(format!(
                "{}: could not run `{}` ({err})",
                check.name, plan.command
            )),
        }
    }
    outcome
}

/// `qqqai doctor` output.
#[derive(serde::Serialize)]
struct DoctorOutput {
    checks: Vec<Check>,
    /// What `--fix` planned, applied or skipped.
    ///
    /// Serialised rather than kept to the summary because an agent driving
    /// `qqqai doctor --json --fix` needs to know whether a repair happened
    /// without parsing prose.
    fix: FixOutcome,
}

impl qqq_run::output::CommandOutput for DoctorOutput {
    fn command(&self) -> CommandName {
        CommandName::Doctor
    }
    fn summary(&self) -> String {
        // The checks are listed, not just counted. `doctor` exists to diagnose,
        // and "2 of 3 checks need attention" without naming them is a riddle
        // rather than a diagnosis — the failing check's name, its detail and
        // its fix are the entire reason the command was run.
        //
        // Passing checks are shown too, but compactly: their names are what
        // tell the reader the tool actually looked, which is the difference
        // between "all 3 checks passed" and a claim the user cannot audit.
        let failed = self.checks.iter().filter(|c| !c.ok).count();
        let mut out = if failed == 0 {
            format!("all {} checks passed", self.checks.len())
        } else {
            format!("{failed} of {} checks need attention", self.checks.len())
        };

        // Failures first, in full.
        for check in self.checks.iter().filter(|c| !c.ok) {
            let _ = write!(out, "\n\n  FAIL  {}\n        {}", check.name, check.detail);
            if let Some(fix) = &check.fix {
                let _ = write!(out, "\n        fix: {fix}");
            }
        }

        // Then the passes, named but not expounded.
        let passes: Vec<&str> = self
            .checks
            .iter()
            .filter(|c| c.ok)
            .map(|c| c.name)
            .collect();
        if !passes.is_empty() {
            let _ = write!(out, "\n\n  ok    {}", passes.join(", "));
        }

        // `--fix` is reported separately from the checks, because "what I
        // found" and "what I did about it" are different claims and a reader
        // must be able to tell them apart.
        //
        // The header goes on its own line only when it has lines under it. The
        // first version pushed `"\n\n  fix   "` unconditionally and then a
        // newline before each entry, so with a plan present it emitted trailing
        // whitespace after `fix` and nothing else on that line — invisible in a
        // terminal, and enough to break `grep '^  fix'`.
        if self.fix.requested {
            let lines: Vec<String> = self
                .fix
                .planned
                .iter()
                .map(|l| format!("  planned: {l}"))
                .chain(self.fix.applied.iter().map(|l| format!("  applied: {l}")))
                .chain(
                    self.fix
                        .skipped
                        .iter()
                        .map(|l| format!("  left to you: {l}")),
                )
                .collect();
            let _ = write!(out, "\n\n  fix");
            if lines.is_empty() {
                out.push_str("   nothing needed repairing");
            } else {
                for line in &lines {
                    let _ = write!(out, "\n        {line}");
                }
            }
        }

        out
    }
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"checks": self.checks, "fix": self.fix})
    }
}

// Keep `Write` in scope for the output sink.
const _: fn() = || {
    fn assert_write<T: Write>() {}
    assert_write::<std::io::Stdout>();
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The action produced by parsing a bare slice of arguments.
    ///
    /// Takes `&[&str]` so tests read `action_of(&["doctor"])`.
    fn action_of(items: &[&str]) -> Action {
        parse_args(&argv(items)).action
    }

    /// The full parse result, for tests that also assert on the flags.
    fn parsed(items: &[&str]) -> Parsed {
        parse_args(&argv(items))
    }

    /// **The naming invariant.** `qqq` is taken on crates.io and npm, so a
    /// build producing a `qqq` binary is a defect. This test fails the build if
    /// the invariant is ever broken.
    #[test]
    fn the_binary_is_named_qqqai_not_qqq() {
        assert_eq!(qqq_core::BINARY_NAME, "qqqai");
        assert_ne!(
            qqq_core::BINARY_NAME,
            "qqq",
            "`qqq` is taken on crates.io and npm; a `qqq` binary is a defect"
        );
        // The Cargo manifest must agree, or the invariant holds only in prose.
        let manifest = include_str!("../Cargo.toml");
        assert!(
            manifest.contains("name = \"qqqai\""),
            "the [[bin]] name must be qqqai"
        );
        assert!(
            !manifest.contains("name = \"qqq\"\n"),
            "the binary must never be named `qqq`"
        );
    }

    #[test]
    fn parses_a_bare_command() {
        assert_eq!(
            action_of(&["doctor"]),
            Action::Command {
                name: CommandName::Doctor,
                args: vec![]
            }
        );
    }

    #[test]
    fn parses_command_with_arguments() {
        let inv = action_of(&["new", "my-app", "--lang", "rust"]);
        match inv {
            Action::Command { name, args } => {
                assert_eq!(name, CommandName::New);
                assert_eq!(args, vec!["my-app", "--lang", "rust"]);
            }
            other => panic!("expected a command, got {other:?}"),
        }
    }

    /// Global flags are recognised **anywhere** on the command line, including
    /// after the command name. That is the friendlier convention: `qqqai doctor
    /// --json` is what a person actually types, and rejecting it because the
    /// flag came second would be pedantry.
    ///
    /// Commands' *own* flags are passed through untouched, because they are not
    /// in the global set.
    #[test]
    fn global_flags_are_recognised_before_and_after_the_command() {
        // Before the command.
        let before = action_of(&["--json", "doctor"]);
        assert!(
            matches!(
                before,
                Action::Command {
                    name: CommandName::Doctor,
                    ..
                }
            ),
            "--json before the command must still parse: {before:?}"
        );

        // After the command: `--json` is global, so it is consumed rather than
        // forwarded — and the command still parses.
        let after = action_of(&["doctor", "--json"]);
        match after {
            Action::Command { name, args } => {
                assert_eq!(name, CommandName::Doctor);
                assert!(
                    args.is_empty(),
                    "--json is a global flag and must be consumed, not forwarded: {args:?}"
                );
            }
            other => panic!("expected a command, got {other:?}"),
        }
    }

    /// A flag that is **not** global belongs to the command and must reach it
    /// unchanged, so commands can define their own options.
    #[test]
    fn command_specific_flags_are_passed_through() {
        match action_of(&["run", "--cap", "fs.read:/tmp", "--port", "3000"]) {
            Action::Command { name, args } => {
                assert_eq!(name, CommandName::Run);
                assert_eq!(args, vec!["--cap", "fs.read:/tmp", "--port", "3000"]);
            }
            other => panic!("expected a command, got {other:?}"),
        }
    }

    /// `--help` and `--version` short-circuit the *action* but must not stop the
    /// parser from recording flags that appear after them.
    ///
    /// This was a real bug found by running the binary: `qqqai --version --json`
    /// printed the plain text version, because the parser broke out of the loop
    /// on `--version` before seeing `--json`.
    ///
    /// **Precedence is order-independent:** `--help` wins over `--version`
    /// whichever comes first, because someone who typed both wants to know how
    /// to use the tool. "Last one wins" would make the behaviour depend on
    /// argument order for no benefit.
    #[test]
    fn short_circuit_flags_do_not_swallow_later_flags() {
        assert_eq!(action_of(&["--help"]), Action::Help);
        assert_eq!(action_of(&["-h"]), Action::Help);
        assert_eq!(action_of(&["--version"]), Action::Version);
        assert_eq!(action_of(&["-V"]), Action::Version);

        // Help wins, in either order.
        assert_eq!(action_of(&["--version", "--help"]), Action::Help);
        assert_eq!(action_of(&["--help", "--version"]), Action::Help);

        let v = parsed(&["--version", "--json"]);
        assert_eq!(v.action, Action::Version);
        assert!(
            v.flags.json(),
            "a flag after --version must still be recorded"
        );

        let h = parsed(&["--help", "--jsonl"]);
        assert_eq!(h.action, Action::Help);
        assert_eq!(h.flags.format(), Format::JsonLines);
    }

    #[test]
    fn no_arguments_shows_help() {
        assert_eq!(action_of(&[]), Action::Help);
    }

    #[test]
    fn unknown_command_is_a_usage_error() {
        match action_of(&["frobnicate"]) {
            Action::UsageError(m) => assert!(m.contains("frobnicate")),
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_global_flag_is_a_usage_error() {
        match action_of(&["--frobnicate", "doctor"]) {
            Action::UsageError(m) => assert!(m.contains("--frobnicate")),
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    /// The global flags and the action come from **one** parse, so they cannot
    /// disagree about what the command line meant. An earlier two-pass version
    /// scanned `argv` twice; this test pins the single-pass contract.
    #[test]
    fn flags_and_action_come_from_one_parse() {
        let p = parsed(&["--json", "doctor"]);
        assert!(p.flags.json(), "the flag must be recorded");
        assert_eq!(p.flags.format(), Format::Json);
        assert!(matches!(
            p.action,
            Action::Command {
                name: CommandName::Doctor,
                ..
            }
        ));

        let quiet = parsed(&["doctor"]);
        assert!(!quiet.flags.json());
        assert_eq!(quiet.flags.format(), Format::Human);

        // JSON Lines wins when both are present.
        let both = parsed(&["--json", "--jsonl", "doctor"]);
        assert_eq!(both.flags.format(), Format::JsonLines);
    }

    /// Flag bits must be independent: setting one must not disturb another.
    #[test]
    fn flag_bits_are_independent() {
        let mut f = GlobalFlags::default();
        assert!(!f.has(GlobalFlags::QUIET));
        f.set(GlobalFlags::QUIET);
        assert!(f.has(GlobalFlags::QUIET));
        assert!(!f.json(), "setting QUIET must not set JSON");
        assert!(!f.json_lines(), "setting QUIET must not set JSON_LINES");

        f.set(GlobalFlags::JSON);
        assert!(f.json() && f.has(GlobalFlags::QUIET), "both must hold");
    }

    /// A flag appearing *after* the command belongs to that command and must
    /// not be rejected as an unknown global flag.
    #[test]
    fn command_flags_are_passed_through() {
        match action_of(&["run", "--cap", "fs.read:/tmp"]) {
            Action::Command { name, args } => {
                assert_eq!(name, CommandName::Run);
                assert_eq!(args, vec!["--cap", "fs.read:/tmp"]);
            }
            other => panic!("expected a command, got {other:?}"),
        }
    }

    /// The help text is generated from `CommandName::all()`, so every command
    /// must appear in it. A hand-maintained list would drift.
    #[test]
    fn help_lists_every_command() {
        let help = render_help(false);
        for &c in CommandName::all() {
            // `--version` and `--help` are flags, printed in OPTIONS.
            if matches!(c, CommandName::Version | CommandName::Help) {
                continue;
            }
            assert!(
                help.contains(c.as_str()),
                "help text omits the `{c}` command"
            );
            assert!(
                help.contains(c.summary()),
                "help text omits the summary for `{c}`"
            );
        }
    }

    /// **`DX-013`: the default help fits the committed line budget.**
    ///
    /// §12.3's table says `qqqai --help` is **≤40 lines** and calls the whole
    /// table *"measurable, in CI"*. Measured before this test existed: **53
    /// lines**. The commitment had a number on it and nothing counted.
    ///
    /// # Why the assertion names the number and lists the offenders
    ///
    /// Because the actionable failure is *"which command pushed it over?"*, not
    /// *"it is 41"*. A count alone sends the reader to the renderer to count by
    /// hand; naming the budget and the actual value makes the fix obvious.
    #[test]
    fn help_fits_the_brevity_standard() {
        let help = render_help(false);
        let lines = help.lines().count();
        assert!(
            lines <= HELP_MAX_LINES,
            "DX-013: `qqqai --help` prints {lines} lines, over the {HELP_MAX_LINES} \
             line budget from §12.3. Trim a summary, merge a group, or move the \
             detail behind `--help --all`."
        );
        // Not trivially small either: a budget satisfied by printing nothing is
        // the vacuity failure `M-006` records, so the floor is asserted too.
        assert!(
            lines >= 20,
            "the help is suspiciously short at {lines} lines; it must still list \
             every command"
        );
    }

    /// **`--help --all` is the long form and must contain everything the brief
    /// one omits.** Without this, "progressive disclosure" could be implemented
    /// by deleting information rather than by relocating it.
    #[test]
    fn the_full_help_is_a_superset_of_the_brief_one() {
        let brief = render_help(false);
        let full = render_help(true);
        assert!(
            full.lines().count() > brief.lines().count(),
            "`--help --all` must say more than `--help`, or the modifier does \
             nothing"
        );
        for line in brief.lines() {
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            assert!(
                full.contains(trimmed) || full.contains(trimmed.trim()),
                "`--help --all` dropped a line the brief help prints: {trimmed:?}"
            );
        }
        // The two things the brief form deliberately moves behind `--all`.
        assert!(full.contains("--verbose"), "the full help must explain -v");
        assert!(
            full.contains("schema --all"),
            "the full help must point at the schema command"
        );
    }

    /// `--all` is a modifier for `--help`, not a flag on its own.
    #[test]
    fn all_is_a_modifier_accepted_in_either_order() {
        assert!(
            parsed(&["--help", "--all"]).flags.all(),
            "`--help --all` must select the full form"
        );
        assert!(
            parsed(&["--all", "--help"]).flags.all(),
            "order must not matter -- the first version gated on the action \
             already being set, which made this order fail"
        );
        assert!(
            !parsed(&["--help"]).flags.all(),
            "the brief form is the default"
        );
        // **Accepted but inert.** The first version of this test asserted that
        // `--all` alone must NOT set the flag, on the reasoning that a modifier
        // with nothing to modify is a mistake. That is a defensible opinion and
        // not the one this parser implements -- `--verbose` alone behaves the
        // same way -- so the test was the thing that was wrong, not the code.
        //
        // **And the assertion that replaced it was wrong too, in the other
        // direction.** This test asserted `--all` alone does *not* resolve to
        // Help. It does: the parser's default when no command is given is
        // `Action::Help`, so `qqqai --all` prints help exactly as bare `qqqai`
        // does. Two attempts, two wrong expectations, and the code was right both
        // times -- recorded because the pattern is the point: **an assertion about
        // a default is worth checking against the default**, not against an
        // assumption about what the default should be.
        let alone = parsed(&["--all"]);
        assert!(alone.flags.all(), "the flag itself is set");
        assert_eq!(
            alone.action,
            Action::Help,
            "no command defaults to Help, so `--all` alone prints the full help"
        );
    }

    #[test]
    fn help_mentions_the_json_contract() {
        let help = render_help(true);
        assert!(help.contains("--json"));
        assert!(help.contains("--jsonl"));
        assert!(
            help.contains("schema --all"),
            "must point at the schema command"
        );
        assert!(help.contains(qqq_core::BINARY_NAME));
    }

    #[test]
    fn doctor_finds_no_problems_in_a_sane_environment() {
        let checks = run_doctor();
        assert!(!checks.is_empty());
        // The binary-name check must pass, since we are that binary.
        let name_check = checks.iter().find(|c| c.name == "binary-name").unwrap();
        assert!(name_check.ok, "the binary name check must pass");
        assert!(name_check.fix.is_none());
    }

    #[test]
    fn doctor_checks_are_wellformed() {
        for c in run_doctor() {
            assert!(!c.name.is_empty());
            assert!(!c.detail.is_empty(), "{} needs a detail", c.name);
            // A failing check must carry a remedy.
            if !c.ok {
                assert!(
                    c.fix.is_some(),
                    "failing check `{}` must suggest a fix",
                    c.name
                );
            }
        }
    }

    /// `--fix` must be recognised in **both** positions.
    ///
    /// A `doctor`-local `--fix` would have passed only in the second position,
    /// because `parse_args` rejects an unknown flag that precedes the command.
    /// This is the same order-dependence `--all` had, and the reason `FIX` is a
    /// global bit.
    #[test]
    fn fix_is_a_global_flag() {
        for line in [&["doctor", "--fix"][..], &["--fix", "doctor"][..]] {
            let p = parsed(line);
            assert!(p.flags.fix(), "--fix must be recorded in {line:?}");
            assert!(!p.flags.dry_run(), "flag bits must be independent");
            assert_eq!(
                p.flags.format(),
                Format::Human,
                "--fix must not disturb the format"
            );
        }
        assert!(!parsed(&["doctor"]).flags.fix());
    }

    /// A temporary directory that removes itself, without a new dependency.
    ///
    /// # Why not `tempfile`
    ///
    /// `qqq-run` does not depend on it, and adding a crate to the supply chain to
    /// create two directories in a test is not a trade worth making. The name
    /// carries the process id and a counter so parallel tests cannot collide, and
    /// `Drop` removes the tree even when an assertion panics.
    struct TempTree(std::path::PathBuf);

    impl TempTree {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("qqq-doctor-{}-{tag}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).expect("a temp tree");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The probe's inputs, with every external source pinned by the caller.
    ///
    /// # Why the tests build this instead of setting environment variables
    ///
    /// `set_var` mutates **process-wide** state, and the harness runs tests in
    /// parallel threads: a value written by one test is visible to all of them,
    /// including tests that expect the variable to be absent. The first version
    /// of these tests did exactly that and failed on its first run — it asserted
    /// that an unset variable reported `false`, which holds only on a machine
    /// without the target.
    ///
    /// Passing the inputs removes the shared state: nothing here touches the
    /// environment, and no two tests can observe each other.
    fn probe_inputs(
        override_present: Option<&str>,
        sysroot_has_target: bool,
        rustup_home_has_target: bool,
        rustup_available: bool,
    ) -> (WasmProbeInputs, TempTree) {
        let tree = TempTree::new("probe");
        let sysroot = tree.path().join("sysroot");
        let home = tree.path().join("rustup");
        if sysroot_has_target {
            std::fs::create_dir_all(sysroot.join("lib").join("rustlib").join(WASM_TARGET))
                .expect("sysroot tree");
        }
        if rustup_home_has_target {
            std::fs::create_dir_all(
                home.join("toolchains")
                    .join("stable-x86_64")
                    .join("lib")
                    .join("rustlib")
                    .join(WASM_TARGET),
            )
            .expect("toolchain tree");
        }
        (
            WasmProbeInputs {
                override_present: override_present.map(str::to_owned),
                sysroot: Some(sysroot),
                rustup_home: Some(home),
                // `false` means the last-resort `rustup` call is skipped, so the
                // verdict is provably the directory logic and not a subprocess
                // that happens to agree.
                rustup_available,
            },
            tree,
        )
    }

    /// The probe's verdict must follow its inputs, in both directions.
    ///
    /// The previous implementation was `ok: true` with a comment, so it printed
    /// `ok wasm-target` while measuring nothing. Every branch is driven here by
    /// constructing the tree each one looks at.
    #[test]
    fn wasm_target_probe_follows_its_inputs() {
        let (i, _t) = probe_inputs(Some("0"), true, true, true);
        assert!(!wasm_target_present_with(&i), "`0` must force absent");
        let (i, _t) = probe_inputs(Some("1"), false, false, false);
        assert!(
            wasm_target_present_with(&i),
            "any other value forces present"
        );

        let (i, _t) = probe_inputs(None, true, false, false);
        assert!(
            wasm_target_present_with(&i),
            "the target in the active sysroot must be found"
        );
        let (i, _t) = probe_inputs(None, false, false, false);
        assert!(
            !wasm_target_present_with(&i),
            "an empty sysroot and home must report absent with rustup disabled"
        );

        // With the sysroot known, it decides: a target on some *other*
        // toolchain is not installed for this build. The scan is a fallback for
        // when there is no sysroot to ask, which the case below pins.
        let (i, _t) = probe_inputs(None, false, true, false);
        assert!(
            !wasm_target_present_with(&i),
            "a target on another toolchain must not satisfy a known sysroot that \
             lacks it"
        );

        // And the scan is still reachable when there is no sysroot at all:
        // the same inputs with `sysroot` cleared, so only the toolchain tree can
        // answer.
        let (mut no_sysroot, _t) = probe_inputs(None, false, true, false);
        no_sysroot.sysroot = None;
        assert!(
            wasm_target_present_with(&no_sysroot),
            "with no sysroot to ask, the toolchain scan must still find the target"
        );
    }

    /// The verdict and the remedy must both follow the probe, not a constant.
    #[test]
    fn wasm_target_check_follows_the_probe() {
        for (signal, expected_ok) in [("0", false), ("1", true)] {
            let (i, _t) = probe_inputs(Some(signal), true, true, true);
            assert_eq!(
                wasm_target_present_with(&i),
                expected_ok,
                "the probe must honour QQQ_TEST_WASM_TARGET_PRESENT={signal}"
            );
        }

        for (inputs, expected_ok) in [
            (probe_inputs(Some("0"), true, true, true).0, false),
            (probe_inputs(Some("1"), false, false, false).0, true),
        ] {
            let ok = wasm_target_present_with(&inputs);
            assert_eq!(ok, expected_ok);
            let fix = (!ok).then(|| format!("run `rustup target add {WASM_TARGET}`"));
            assert_eq!(
                fix.is_some(),
                !expected_ok,
                "a remedy must appear exactly when the check fails"
            );
        }
    }

    /// Without `--fix`, `doctor` must execute **nothing**.
    #[test]
    fn fix_plan_is_inert_without_the_flag() {
        let checks = run_doctor();
        let outcome = apply_fixes(&checks, false);
        assert!(!outcome.requested);
        assert!(outcome.planned.is_empty());
        assert!(outcome.applied.is_empty());
        assert!(outcome.skipped.is_empty());
    }

    /// With `--fix`, every failing check is accounted for: either it has a
    /// planned repair, or it is named as skipped. Silence is the failure mode
    /// this forbids — a check that fails while `--fix` reports nothing at all
    /// is indistinguishable from a repair that was never considered.
    #[test]
    fn fix_accounts_for_every_failing_check() {
        let checks = run_doctor();
        let failing: Vec<&str> = checks.iter().filter(|c| !c.ok).map(|c| c.name).collect();
        let outcome = apply_fixes(&checks, true);
        assert!(outcome.requested);
        for name in &failing {
            let mentioned = outcome
                .planned
                .iter()
                .chain(outcome.applied.iter())
                .chain(outcome.skipped.iter())
                .any(|line| line.contains(name));
            assert!(mentioned, "`{name}` failed but --fix said nothing about it");
        }
    }

    /// A network fetch is planned and printed, and never run.
    ///
    /// # Why the plan is fetched here rather than probed
    ///
    /// The earlier version called `fix_for("wasm-target", true)` and returned
    /// early when it produced `None` — so on a machine without `rustup` the test
    /// silently passed without exercising anything, which is the "test that
    /// cannot fail" shape this section exists to avoid. The plan is built from
    /// the branch under test and asserted non-`None` first, and the no-rustup
    /// case asserts the *other* branch rather than returning.
    /// A network fetch is planned and printed, and never run.
    ///
    /// # Why the plan is built here rather than probed
    ///
    /// The earlier version called `fix_for("wasm-target", true)` and returned
    /// early when it produced `None` — so on a machine without `rustup` the test
    /// silently passed without exercising anything, which is the "test that
    /// cannot fail" shape this section exists to avoid. The plan is built from
    /// the branch under test and asserted non-`None` first, and the no-rustup
    /// case asserts the *other* branch rather than returning.
    #[test]
    fn target_install_is_planned_but_not_run() {
        let plan = fix_for("wasm-target", true).expect("rustup present must yield a plan");
        assert_eq!(plan.command, "rustup target add wasm32-wasip2");
        assert!(
            plan.reaches_network,
            "installing a toolchain component reaches the network, and that is \
             what makes it non-automatic"
        );

        let checks = vec![Check {
            name: "wasm-target",
            ok: false,
            detail: format!("the {WASM_TARGET} target is not installed"),
            fix: Some(format!("run `rustup target add {WASM_TARGET}`")),
        }];
        let outcome = apply_fixes(&checks, true);
        if rustup_on_path() {
            assert!(
                outcome
                    .planned
                    .iter()
                    .any(|l| l.ends_with(&format!("`{}`", plan.command))),
                "the plan must name the command that would run: {:?}",
                outcome.planned
            );
            assert!(
                !outcome.applied.iter().any(|l| l.contains("target add")),
                "a network fetch must never be applied automatically"
            );
            assert!(
                outcome
                    .skipped
                    .iter()
                    .any(|l| l.contains("toolchain component")),
                "the skip must be explained: {:?}",
                outcome.skipped
            );
        } else {
            assert!(
                outcome.skipped.iter().any(|l| l.contains("wasm-target")),
                "with no rustup the failing check must still be named: {:?}",
                outcome.skipped
            );
        }
    }

    /// A flag `doctor` does not accept must be refused, not ignored.
    ///
    /// This is the invariant that makes `--fix` trustworthy: while `--fix` was
    /// unimplemented, running it behaved exactly like plain `doctor`, so the
    /// user had no way to learn the option did nothing.
    #[test]
    fn doctor_refuses_flags_it_does_not_accept() {
        let err = reject_unknown_flags(CommandName::Doctor, &["--jsonn".to_owned()], &["--fix"])
            .expect("an unrecognised flag must produce an error");
        assert_eq!(err.code, qqq_core::ErrorCode::CliFlagUnknown);
        assert!(err.message.contains("--jsonn"), "{}", err.message);
        let remedy = err.remediation.as_deref().unwrap_or_default();
        assert!(
            remedy.contains("--fix"),
            "the remedy must list the real flags: {remedy}"
        );

        // The accepted flag passes, in either spelling position.
        assert!(
            reject_unknown_flags(CommandName::Doctor, &["--fix".to_owned()], &["--fix"]).is_none()
        );
        // A positional argument is not a flag and must be left to the caller.
        assert!(
            reject_unknown_flags(CommandName::Doctor, &["now".to_owned()], &["--fix"]).is_none()
        );
        // An empty accepted set is reported as "no flags" rather than an empty
        // string, which would render as "accepts ".
        let bare = reject_unknown_flags(CommandName::Doctor, &["-x".to_owned()], &[])
            .expect("must refuse");
        assert_eq!(
            bare.remediation.as_deref(),
            Some("`doctor` accepts no flags")
        );
    }

    /// `doctor`'s JSON must carry the fix outcome, so an agent can tell
    /// "planned" from "applied" from "skipped" without parsing prose.
    #[test]
    fn doctor_json_carries_the_fix_outcome() {
        let checks = run_doctor();
        let out = DoctorOutput {
            checks,
            fix: apply_fixes(&[], true),
        };
        let json = qqq_run::output::CommandOutput::to_json(&out);
        assert!(json["checks"].is_array());
        assert_eq!(json["fix"]["requested"], serde_json::json!(true));
        for key in ["planned", "applied", "skipped"] {
            assert!(
                json["fix"][key].is_array(),
                "`fix.{key}` must be an array, not {key}::missing"
            );
        }
    }

    #[test]
    fn error_catalogue_covers_every_code() {
        let cat = error_catalogue();
        assert_eq!(cat.len(), qqq_core::ErrorCode::all().len());
        for entry in &cat {
            assert!(entry["code"].as_str().unwrap().starts_with("QQQ-"));
            assert!(entry["docs_url"]
                .as_str()
                .unwrap()
                .contains("qqq.codes/errors"));
        }
    }

    #[test]
    fn capability_catalogue_covers_every_capability() {
        let cat = capability_catalogue();
        assert_eq!(cat.len(), qqq_cap::Capability::all().len());
        for entry in &cat {
            assert!(entry["name"].is_string());
            assert!(entry["kind"].is_string());
            assert!(entry["covert_channel"].is_boolean());
        }
    }

    #[test]
    fn exit_codes_are_distinct() {
        let codes = [exit::OK, exit::USAGE, exit::UNAVAILABLE, exit::INTERNAL];
        let unique: std::collections::BTreeSet<u8> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "exit codes must be distinct");
        assert_eq!(exit::OK, 0, "success must be 0");
    }
}
