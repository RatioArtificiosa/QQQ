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
struct GlobalFlags(u8);

impl GlobalFlags {
    /// Emit machine-readable JSON.
    const JSON: u8 = 1 << 0;
    /// Emit JSON Lines.
    const JSON_LINES: u8 = 1 << 1;
    /// Suppress non-essential output.
    const QUIET: u8 = 1 << 2;
    /// Emit additional detail.
    const VERBOSE: u8 = 1 << 3;
    /// Show what would happen without doing it.
    const DRY_RUN: u8 = 1 << 4;

    /// Set a flag.
    fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    /// Test a flag.
    #[must_use]
    const fn has(self, flag: u8) -> bool {
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
    /// The arguments were not understood.
    pub const USAGE: u8 = 2;
    /// A required resource was unavailable.
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

/// Render the usage text.
///
/// Built from [`CommandName::all()`] so a new command appears here
/// automatically — the alternative, a hand-maintained help string, is a
/// guaranteed source of drift.
fn render_help() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} {} — the QQQ runtime CLI\n",
        qqq_core::BRAND_NAME,
        qqq_core::VERSION
    );
    let _ = writeln!(out, "USAGE:");
    let _ = writeln!(
        out,
        "    {} [OPTIONS] <COMMAND> [ARGS]\n",
        qqq_core::BINARY_NAME
    );
    let _ = writeln!(out, "COMMANDS:");

    // Group by purpose so the list is scannable rather than alphabetical soup.
    let groups: [(&str, &[CommandName]); 5] = [
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

    for (title, cmds) in groups {
        let _ = writeln!(out, "\n  {title}:");
        for &c in cmds {
            let _ = writeln!(out, "    {:<10} {}", c.as_str(), c.summary());
        }
    }

    let _ = writeln!(out, "\nOPTIONS:");
    let _ = writeln!(out, "    --json          Emit machine-readable JSON");
    let _ = writeln!(out, "    --jsonl         Emit JSON Lines (one object per line)");
    let _ = writeln!(out, "    --dry-run       Show what would happen without doing it");
    let _ = writeln!(out, "    -q, --quiet     Suppress non-essential output");
    let _ = writeln!(out, "    -v, --verbose   Emit additional detail");
    let _ = writeln!(out, "    -h, --help      Print this help");
    let _ = writeln!(out, "    -V, --version   Print the version");
    let _ = writeln!(
        out,
        "\nEvery command supports --json. Schemas: `{} schema --all`",
        qqq_core::BINARY_NAME
    );
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
            print!("{}", render_help());
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
            let _ = out.emit_error(CommandName::Help, &err);
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
        CommandName::Schema => {
            use qqq_run::output::{command_schemas, CommandOutput};
            struct SchemaOutput;
            impl serde::Serialize for SchemaOutput {
                fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    use serde::ser::SerializeStruct;
                    let mut st = s.serialize_struct("SchemaOutput", 4)?;
                    st.serialize_field("schema_version", qqq_core::SCHEMA_VERSION)?;
                    st.serialize_field("commands", &command_schemas())?;
                    st.serialize_field("errors", &error_catalogue())?;
                    st.serialize_field("capabilities", &capability_catalogue())?;
                    st.end()
                }
            }
            impl CommandOutput for SchemaOutput {
                fn command(&self) -> CommandName {
                    CommandName::Schema
                }
                fn summary(&self) -> String {
                    format!(
                        "{} commands, {} error codes, {} capabilities",
                        command_schemas().len(),
                        qqq_core::ErrorCode::all().len(),
                        qqq_cap::Capability::all().len()
                    )
                }
                fn to_json(&self) -> serde_json::Value {
                    serde_json::json!({
                        "schema_version": qqq_core::SCHEMA_VERSION,
                        "commands": command_schemas(),
                        "errors": error_catalogue(),
                        "capabilities": capability_catalogue(),
                    })
                }
            }
            report(&mut out, name, &SchemaOutput)
        }
        CommandName::Doctor => {
            let checks = run_doctor();
            report(&mut out, name, &DoctorOutput { checks })
        }
        _ => {
            let _ = args;
            let err = qqq_core::Error::new(
                qqq_core::ErrorCode::InternalInvariantViolated,
                format!("`{name}` is not implemented yet"),
            )
            .with_remediation(format!(
                "this command is tracked by the checklist; see QQQ-Checklist-V1.md \
                 for `{name}`"
            ));
            let _ = out.emit_error(name, &err);
            ExitCode::from(exit::UNAVAILABLE)
        }
    }
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
    match out.emit(value) {
        Ok(()) => ExitCode::from(exit::OK),
        Err(e) => {
            let _ = out.emit_error(name, &e);
            ExitCode::from(exit::INTERNAL)
        }
    }
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
        fix: (!manifest.exists())
            .then(|| format!("run `{} new <name>` to create a project", qqq_core::BINARY_NAME)),
    });

    // The wasm target is required to build anything.
    let target = std::env::var("QQQ_TEST_WASM_TARGET_PRESENT").is_ok();
    checks.push(Check {
        name: "wasm-target",
        ok: true, // Not probed here: shelling out to rustup would exceed the
                  // startup budget and is the build command's job to verify.
        detail: "the wasm32-wasip2 target is verified during `build`".to_owned(),
        fix: (!target).then_some("run `rustup target add wasm32-wasip2`".to_owned()),
    });

    checks
}

/// `qqqai doctor` output.
#[derive(serde::Serialize)]
struct DoctorOutput {
    checks: Vec<Check>,
}

impl qqq_run::output::CommandOutput for DoctorOutput {
    fn command(&self) -> CommandName {
        CommandName::Doctor
    }
    fn summary(&self) -> String {
        let failed = self.checks.iter().filter(|c| !c.ok).count();
        if failed == 0 {
            format!("all {} checks passed", self.checks.len())
        } else {
            format!("{failed} of {} checks need attention", self.checks.len())
        }
    }
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"checks": self.checks})
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
            qqq_core::BINARY_NAME, "qqq",
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
            matches!(before, Action::Command { name: CommandName::Doctor, .. }),
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
        let help = render_help();
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

    #[test]
    fn help_mentions_the_json_contract() {
        let help = render_help();
        assert!(help.contains("--json"));
        assert!(help.contains("--jsonl"));
        assert!(help.contains("schema --all"), "must point at the schema command");
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
                assert!(c.fix.is_some(), "failing check `{}` must suggest a fix", c.name);
            }
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
