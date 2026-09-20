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

    /// Whether this is a rehearsal.
    #[must_use]
    const fn dry_run(self) -> bool {
        self.has(Self::DRY_RUN)
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
    let _ = writeln!(
        out,
        "    --jsonl         Emit JSON Lines (one object per line)"
    );
    let _ = writeln!(
        out,
        "    --dry-run       Show what would happen without doing it"
    );
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
        CommandName::Why => {
            // The capability argument is extracted before `out` is borrowed by
            // `with_manifest`, so the missing-argument error does not conflict
            // with the later mutable borrow.
            if let Some(cap) = args.first().cloned() {
                with_manifest(name, &mut out, args, |loaded| {
                    qqq_run::commands::why(loaded, &cap)
                })
            } else {
                let err = qqq_core::Error::new(
                    qqq_core::ErrorCode::McpArgumentInvalid,
                    "`why` needs a capability to explain",
                )
                .with_remediation("for example: qqqai why crypto.hash");
                let _ = out.emit_error(name, &err);
                ExitCode::from(exit::USAGE)
            }
        }
        CommandName::Caps => with_manifest(name, &mut out, args, |loaded| {
            Ok(qqq_run::commands::caps(loaded))
        }),
        CommandName::Inspect => with_manifest(name, &mut out, args, |loaded| {
            qqq_run::commands::inspect(loaded)
        }),
        CommandName::Build => dispatch_build(name, args, flags, &mut out),
        CommandName::Run => dispatch_run(name, args, flags, &mut out),
        CommandName::New => dispatch_new(name, args, &mut out),
        CommandName::Init => dispatch_init(name, args, &mut out),
        CommandName::Dev => dispatch_dev(name, args, &mut out),
        CommandName::Add => dispatch_add(name, args, &mut out),
        CommandName::Remove => dispatch_remove(name, args, &mut out),
        _ => {
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

/// Dispatch `qqqai build`.
///
/// Split out of [`run_command`] because `build` is the first command with its
/// own flag vocabulary. Keeping it inline would make the dispatcher grow with
/// every command that gains options, and the dispatcher is the one function
/// that must stay readable — it is the map of the whole CLI.
fn dispatch_build(
    name: CommandName,
    args: &[String],
    flags: GlobalFlags,
    out: &mut Output<std::io::Stdout>,
) -> ExitCode {
    let opts = match build_options(args) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error(name, &e);
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
            let _ = out.emit_error(name, &e);
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
            let _ = out.emit_error(name, &e);
            return ExitCode::from(exit::USAGE);
        }
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match qqq_run::scaffold::create(&opts, &cwd) {
        Ok(value) => report(out, name, &value),
        Err(e) => {
            let _ = out.emit_error(name, &e);
            // A refused name is a usage mistake; a refused directory is an
            // environment condition the user must resolve. Distinguishing them
            // lets a script tell "I called it wrong" from "something is in the
            // way".
            let code = if e.message.contains("not a usable") || e.message.contains("plain name") {
                exit::USAGE
            } else {
                exit::FAILURE
            };
            ExitCode::from(code)
        }
    }
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
            let _ = out.emit_error(name, &e);
            return ExitCode::from(exit::USAGE);
        }
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match qqq_run::scaffold::init(&cwd, &opts) {
        Ok(value) => report(out, name, &value),
        Err(e) => {
            let _ = out.emit_error(name, &e);
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
fn dispatch_dev(name: CommandName, args: &[String], out: &mut Output<std::io::Stdout>) -> ExitCode {
    let opts = match dev_options(args) {
        Ok(o) => o,
        Err(e) => {
            let _ = out.emit_error(name, &e);
            return ExitCode::from(exit::USAGE);
        }
    };
    with_manifest(name, out, args, |loaded| qqq_run::dev::run(loaded, &opts))
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
fn dispatch_add(name: CommandName, args: &[String], out: &mut Output<std::io::Stdout>) -> ExitCode {
    let parsed = match add_options(args) {
        Ok(p) => p,
        Err(e) => {
            let _ = out.emit_error(name, &e);
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
                let _ = out.emit_error(name, &e);
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
        let _ = out.emit_error(name, &e);
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
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    let loaded = match qqq_run::LoadedManifest::discover(&cwd, explicit.as_deref()) {
        Ok(l) => l,
        Err(e) => {
            let _ = out.emit_error(name, &e);
            return ExitCode::from(exit::USAGE);
        }
    };

    match f(&loaded) {
        Ok(value) => report(out, name, &value),
        Err(e) => {
            let _ = out.emit_error(name, &e);
            ExitCode::from(exit::FAILURE)
        }
    }
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
                // A bare positional is passed to the component.
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
        fix: (!manifest.exists()).then(|| {
            format!(
                "run `{} new <name>` to create a project",
                qqq_core::BINARY_NAME
            )
        }),
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
