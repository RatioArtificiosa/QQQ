// SPDX-License-Identifier: Apache-2.0

//! The shared output layer.
//!
//! Implements `CLI-001` and `CLI-002`: **every command supports `--json`, and
//! a new command cannot ship without a JSON shape.**
//!
//! # Why this is a module and not a convention
//!
//! Non-Negotiable #1 says an AI agent must be able to use QQQ reliably. The
//! failure mode this module prevents is a command added in a hurry that prints
//! prose and forgets `--json`. That command is invisible to every automated
//! consumer, and the omission is discovered by an agent at the worst possible
//! moment.
//!
//! Three mechanisms make the omission impossible:
//!
//! 1. **The renderer is generic over [`CommandOutput`].** A command's return
//!    type must implement the trait, which requires a `to_json` method. There
//!    is no code path that prints a human string without having a JSON form
//!    available.
//! 2. **`Output::emit` is the only way to produce user-visible output.** A
//!    command that wants to print something must go through it.
//! 3. **The schema registry is checked exhaustively.** [`command_schemas`]
//!    returns one entry per [`CommandName`], and a test asserts the mapping is
//!    total — so adding a command without a schema fails the build.
//!
//! # The two audiences, one source
//!
//! Human output is derived *from* the structured value where practical, rather
//! than being written twice. Where a summary must differ (a human wants a table,
//! an agent wants records), the human form is a **rendering** of the same data —
//! so the two can never disagree about what happened.

use std::fmt;
use std::io::Write;

use qqq_core::{Error, ErrorCode, Result};
use serde::Serialize;

/// Every command the CLI exposes.
///
/// Adding a variant is what forces the schema registry and the tests to be
/// updated, because both are exhaustive over this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CommandName {
    /// Scaffold a project.
    New,
    /// Add QQQ to an existing directory.
    Init,
    /// Add a dependency.
    Add,
    /// Remove a dependency.
    Remove,
    /// Resolve and fetch dependencies.
    Install,
    /// Update dependencies within semver.
    Update,
    /// Compile to a component.
    Build,
    /// Execute a component.
    Run,
    /// Dev server with hot reload.
    Dev,
    /// Production server.
    Serve,
    /// Test runner.
    Test,
    /// Benchmark harness.
    Bench,
    /// Format source.
    Fmt,
    /// Lint source.
    Lint,
    /// Static capability report.
    Inspect,
    /// An `OpenAPI` 3.0 description of the app's routes.
    Openapi,
    /// Full security posture.
    Audit,
    /// Verify signature and attestation.
    Verify,
    /// Show effective grants.
    Caps,
    /// Explain a capability decision.
    Why,
    /// Live trace stream.
    Trace,
    /// Environment diagnosis.
    Doctor,
    /// MCP server.
    Mcp,
    /// Emit JSON schemas for every surface.
    Schema,
    /// Convert from another runtime.
    Migrate,
    /// Print the version.
    Version,
    /// Print help.
    Help,
}

impl CommandName {
    /// Every command, for schema generation and exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [CommandName] {
        &[
            Self::New,
            Self::Init,
            Self::Add,
            Self::Remove,
            Self::Install,
            Self::Update,
            Self::Build,
            Self::Run,
            Self::Dev,
            Self::Serve,
            Self::Test,
            Self::Bench,
            Self::Fmt,
            Self::Lint,
            Self::Inspect,
            Self::Openapi,
            Self::Audit,
            Self::Verify,
            Self::Caps,
            Self::Why,
            Self::Trace,
            Self::Doctor,
            Self::Mcp,
            Self::Schema,
            Self::Migrate,
            Self::Version,
            Self::Help,
        ]
    }

    /// The command's CLI spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Init => "init",
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Install => "install",
            Self::Update => "update",
            Self::Build => "build",
            Self::Run => "run",
            Self::Dev => "dev",
            Self::Serve => "serve",
            Self::Test => "test",
            Self::Bench => "bench",
            Self::Fmt => "fmt",
            Self::Lint => "lint",
            Self::Inspect => "inspect",
            Self::Openapi => "openapi",
            Self::Audit => "audit",
            Self::Verify => "verify",
            Self::Caps => "caps",
            Self::Why => "why",
            Self::Trace => "trace",
            Self::Doctor => "doctor",
            Self::Mcp => "mcp",
            Self::Schema => "schema",
            Self::Migrate => "migrate",
            Self::Version => "--version",
            Self::Help => "--help",
        }
    }

    /// One line describing what the command does, for `--help` and the schema.
    ///
    /// Written for a model first, then reviewed by a human — per Proposal §8.2.
    #[must_use]
    pub const fn summary(self) -> &'static str {
        match self {
            Self::New => "Scaffold a new QQQ project with a manifest and a starter source file",
            Self::Init => "Add QQQ to an existing directory without overwriting files",
            Self::Add => "Add a dependency to qqq.toml and resolve it",
            Self::Remove => "Remove a dependency from qqq.toml",
            Self::Install => "Resolve, fetch and verify all dependencies",
            Self::Update => "Update dependencies within their semver ranges",
            Self::Build => "Compile the project to a WebAssembly component",
            Self::Run => "Execute the built component with explicit capabilities",
            Self::Dev => "Run a development server that reloads on source changes",
            Self::Serve => "Run the production server",
            Self::Test => "Run the project's tests",
            Self::Bench => "Run the project's benchmarks",
            Self::Fmt => "Format source using the project's language toolchain",
            Self::Lint => "Lint source using the project's language toolchain",
            Self::Inspect => "Report what a component can do, without running it",
            Self::Audit => "Report the full security posture of a component",
            Self::Verify => "Verify a component's signature and provenance",
            Self::Caps => "Show the effective capability grants",
            Self::Why => "Explain why a capability was granted or denied",
            Self::Trace => "Stream live traces from a running application",
            Self::Doctor => "Diagnose the environment and suggest fixes",
            Self::Mcp => "Run as a Model Context Protocol server for AI agents",
            Self::Openapi => "Emit an OpenAPI 3.0 description of the app's routes",
            Self::Schema => "Emit JSON Schema for every machine-readable surface",
            Self::Migrate => "Analyse a Node, Bun or Deno project and produce a migration plan",
            Self::Version => "Print the version and exit",
            Self::Help => "Print usage and exit",
        }
    }

    /// Whether this command can modify the caller's filesystem or state.
    ///
    /// An agent's first question about any tool is *"will this change
    /// something?"*. Answering it in the schema means the model does not have
    /// to infer it from the name.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        matches!(
            self,
            Self::New
                | Self::Init
                | Self::Add
                | Self::Remove
                | Self::Install
                | Self::Update
                | Self::Build
                | Self::Fmt
                | Self::Lint
                | Self::Migrate
        )
    }

    /// Whether the command supports a `--dry-run` flag.
    ///
    /// Every mutating command should, so an agent can plan before acting.
    /// Non-mutating commands return `false` because a dry run would be
    /// meaningless, not because the flag is missing.
    #[must_use]
    pub const fn supports_dry_run(self) -> bool {
        self.is_mutating()
    }

    /// Parse a command from its CLI spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::all().iter().copied().find(|c| c.as_str() == s)
    }
}

impl fmt::Display for CommandName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The trait every command's output type implements.
///
/// # Why `to_json` returns a `Value` rather than requiring `Serialize`
///
/// Because the schema registry is built from **the same representation the
/// command emits** ([`Output::emit`]). Requiring an explicit `to_json` makes
/// that representation a deliberate, reviewable artifact rather than whatever
/// `serde` happened to derive — which matters, because this representation *is*
/// the machine contract agents depend on.
pub trait CommandOutput: Serialize {
    /// The command this output belongs to.
    fn command(&self) -> CommandName;

    /// A one-line human summary.
    ///
    /// Shown in a terminal and in the `summary` field of JSON output, so a
    /// human and an agent see the same conclusion.
    fn summary(&self) -> String;

    /// The structured form, exactly as it will be emitted.
    fn to_json(&self) -> serde_json::Value;
}

/// How output should be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Human-readable text, for a terminal.
    Human,
    /// Machine-readable JSON, for an agent or a script.
    Json,
    /// JSON Lines: one object per line, for streaming commands.
    JsonLines,
}

impl Format {
    /// Choose a format from the parsed flags.
    #[must_use]
    pub const fn from_flags(json: bool, json_lines: bool) -> Self {
        if json_lines {
            Self::JsonLines
        } else if json {
            Self::Json
        } else {
            Self::Human
        }
    }
}

/// The exit status a successful run returns.
///
/// Mirrored from `crates/qqq-run/src/main.rs`'s `mod exit`. The CLI owns the
/// numbers; this crate names them so the envelope can be built without the two
/// drifting. `check_exit_codes` asserts they agree.
pub const EXIT_OK: u8 = 0;

/// The exit status a command that ran and failed returns.
///
/// Mirrored from `mod exit` in the CLI for the same reason as [`EXIT_OK`].
pub const EXIT_FAILURE: u8 = 1;

/// The envelope every JSON response carries.
///
/// # Why an envelope rather than a bare payload
///
/// Because an agent needs to know three things before it can interpret a
/// response, and none of them can be inferred from the payload alone:
///
/// * **which command produced it** — the payload shape depends on this;
/// * **which schema version it conforms to** — so a client can detect drift;
/// * **whether it succeeded** — probing for the presence of an `error` key is
///   the kind of guessing that produces subtly wrong agent behaviour.
///
/// The envelope makes all three explicit and machine-checkable.
#[derive(Debug, Clone, Serialize)]
pub struct Envelope<T> {
    /// Always `"qqqai"`, so a consumer can tell at a glance what produced this.
    pub producer: &'static str,
    /// The runtime version.
    pub version: &'static str,
    /// The machine-contract version this conforms to.
    pub schema_version: &'static str,
    /// The command that produced this.
    pub command: &'static str,
    /// Whether the command succeeded.
    ///
    /// **`ok` is not the exit status.** It says the command did what it was
    /// asked and produced this payload; it is `true` even when the payload
    /// reports a problem — `doctor` finding a missing manifest is a successful
    /// diagnosis. Read [`Self::exit_code`] for the process's own verdict.
    pub ok: bool,
    /// The exit status the process returns for this run.
    ///
    /// # Why this field exists
    ///
    /// Because `ok` and `$?` disagreed in the shipped binary.
    /// `qqqai doctor --json` printed `"ok":true` and exited **69** while the
    /// human form printed "1 of 3 checks need attention" — an agent that
    /// trusted `ok` and an agent that trusted `$?` reached opposite conclusions
    /// about the same run. Each was reading a real thing; the contract had two
    /// answers to one question.
    ///
    /// Deriving the number here, from the same value the process returns,
    /// makes the disagreement unrepresentable rather than merely documented.
    /// The exit-status constants live in the CLI; this is the protocol's copy
    /// of them, and [`EXIT_OK`] is the only value a success envelope carries.
    pub exit_code: u8,
    /// A one-line human summary of the outcome.
    pub summary: String,
    /// The command's payload, when it succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// The error, when it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
}

/// The machine-readable form of a [`qqq_core::Error`].
///
/// Flattens the fields an agent acts on and keeps `message` clearly separate
/// from `code`, because `message` is documented as unstable and the code is the
/// contract.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorPayload {
    /// The stable code, e.g. `QQQ-4003`.
    pub code: String,
    /// One human sentence. **Do not parse.**
    pub message: String,
    /// The causal chain, outermost first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cause: Vec<String>,
    /// The actionable next step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// The permanent docs URL.
    pub docs_url: String,
    /// Whether retrying the same operation may succeed.
    pub retryable: bool,
    /// Ordered context describing where it happened.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<ErrorContextEntry>,
    /// The guest backtrace, resolved to source lines when a map was available.
    ///
    /// `HOST-009` requires a trap report carry "code, guest backtrace and (if
    /// DWARF present) source line". The `cause` strings carry a *rendered* form
    /// of the frames, which is right for a human and useless to a consumer that
    /// wants the frame list: it would have to parse prose to get `func`,
    /// `offset`, `file` and `line` back out.
    ///
    /// Absent, not empty, when there is no backtrace — so a consumer checking
    /// `error.backtrace` is asking a question with a meaningful answer, and an
    /// error that is not a trap does not carry a misleading empty array.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backtrace: Option<crate::trap_report::ResolvedBacktrace>,
}

/// One context entry, as a name/value pair rather than a tuple.
///
/// A tuple serializes to a JSON array, which is awkward for a consumer and
/// awkward in a schema. An object is self-describing.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorContextEntry {
    /// The key.
    pub name: String,
    /// The value.
    pub value: String,
}

impl From<&Error> for ErrorPayload {
    fn from(e: &Error) -> Self {
        Self {
            code: e.id(),
            message: e.message.clone(),
            cause: e.cause.clone(),
            remediation: e.remediation.clone(),
            docs_url: e.docs_url(),
            retryable: e.is_retryable(),
            context: e
                .context
                .iter()
                .map(|(name, value)| ErrorContextEntry {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect(),
            // `None` here, not an attempt to resolve: this `From` has no source
            // map and no artifact to read one from. Only a caller that knows
            // *which* artifact trapped can resolve, which is `emit_error_with_backtrace`.
            backtrace: None,
        }
    }
}

/// The writer a command uses to produce output.
///
/// Generic over the sink so tests can capture output without a subprocess —
/// which is what makes the output layer itself testable, rather than something
/// only verified by running the binary and eyeballing it.
pub struct Output<W: Write> {
    format: Format,
    sink: W,
}

impl<W: Write> Output<W> {
    /// Construct an output writer.
    pub const fn new(format: Format, sink: W) -> Self {
        Self { format, sink }
    }

    /// The active format.
    #[must_use]
    pub const fn format(&self) -> Format {
        self.format
    }

    /// Emit a successful result.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-6005` if the sink rejects the write. A broken pipe on
    /// stdout is common (`qqqai … | head`) and is reported rather than panicked
    /// on, so a pipeline terminates cleanly instead of printing a panic.
    pub fn emit<T: CommandOutput>(&mut self, value: &T) -> Result<()> {
        self.emit_with_exit(value, EXIT_OK)
    }

    /// Emit a successful result that carries a non-zero exit status.
    ///
    /// # Why the exit status is an argument
    ///
    /// Because one command legitimately succeeds and still exits non-zero:
    /// `qqqai doctor` diagnoses a broken environment correctly and returns
    /// `UNAVAILABLE` so a CI step notices. The old signature forced that arm to
    /// emit `ok: true` alongside exit 69, which is the contradiction this
    /// parameter removes. Every other command keeps [`Self::emit`].
    ///
    /// # Errors
    ///
    /// Returns `QQQ-6005` if the sink rejects the write.
    pub fn emit_with_exit<T: CommandOutput>(&mut self, value: &T, exit_code: u8) -> Result<()> {
        let command = value.command();
        match self.format {
            Format::Human => self.write_line(&value.summary()),
            Format::Json | Format::JsonLines => {
                let text = render_success(command, value, exit_code)?;
                self.write_line(&text)
            }
        }
    }

    /// Emit a failure with the generic failure status.
    ///
    /// The human form is the mandated error block from Proposal §12.2; the JSON
    /// form is the envelope with a populated `error` and `ok: false`.
    ///
    /// A caller that knows its own exit status must use
    /// [`Self::emit_error_with_exit`] — the envelope reports the status, and a
    /// constant here made the two disagree.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-6005` if the sink rejects the write.
    pub fn emit_error(&mut self, command: CommandName, error: &Error) -> Result<()> {
        self.emit_error_with_exit(command, error, EXIT_FAILURE)
    }

    /// Emit a failure whose process exit status is known at the call site.
    ///
    /// # Why the status is an argument
    ///
    /// Because the envelope carries it. `qqqai why --json` printed
    /// `"exit_code":1` while the process returned `2` — the failure path used a
    /// constant, so 38 of the 48 failure envelopes disagreed with their own
    /// process, and an agent reading the envelope and an agent reading `$?`
    /// reached opposite conclusions about the same run. The live probe in
    /// `tools/check_schema_conformance.py` is what caught it, and that probe is
    /// the reason the fix is verified rather than asserted.
    ///
    /// `EXIT_FAILURE` remains the default for [`Self::emit_error`], because a
    /// caller that does not name a status means the generic failure.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-6005` if the sink rejects the write.
    pub fn emit_error_with_exit(
        &mut self,
        command: CommandName,
        error: &Error,
        exit_code: u8,
    ) -> Result<()> {
        match self.format {
            Format::Human => self.write_line(&error.render()),
            Format::Json | Format::JsonLines => {
                let text = render_failure(command, error, exit_code)?;
                self.write_line(&text)
            }
        }
    }

    /// Emit a failure, with a guest backtrace resolved to source lines.
    ///
    /// This is the `HOST-009` path made reachable. `emit_error` cannot do it: a
    /// source map comes from *a specific artifact*, and only the caller that ran
    /// that artifact knows which one. Passing the already-resolved backtrace in
    /// keeps this function from having to guess at a path.
    ///
    /// # Why the human form is more than `error.render()`
    ///
    /// Because the frames are the point. `Error::render()` prints the causes,
    /// which for a trap are `frame 1: spin+0x1a3` — the bytecode offsets a
    /// developer cannot act on. Appending the resolved block is what turns the
    /// same trap into `spin (src/handler.rs:42)`, which is a line they can open.
    /// A resolved frame is *added*, never substituted for the raw causes: the
    /// offset is what identifies the instruction, and dropping it would make a
    /// report less precise than the one that had no debug info at all.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-6005` if the sink rejects the write.
    pub fn emit_error_with_backtrace(
        &mut self,
        command: CommandName,
        error: &Error,
        backtrace: &crate::trap_report::ResolvedBacktrace,
    ) -> Result<()> {
        match self.format {
            Format::Human => self.write_line(&render_error_with_backtrace(error, backtrace)),
            Format::Json | Format::JsonLines => {
                let mut payload = ErrorPayload::from(error);
                // Only attach a backtrace that has frames. An error that is not
                // a trap then serializes exactly as it did before this field
                // existed, so the contract is unchanged for every other command.
                if !backtrace.is_empty() {
                    payload.backtrace = Some(backtrace.clone());
                }
                let text = render_failure_payload(command, error, payload, EXIT_FAILURE)?;
                self.write_line(&text)
            }
        }
    }

    /// Write a bare line, bypassing the envelope.
    ///
    /// Reserved for streaming commands and for `--help`/`--version`, which are
    /// not part of the machine contract.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-6005` if the sink rejects the write.
    pub fn write_line(&mut self, text: &str) -> Result<()> {
        writeln!(self.sink, "{text}").map_err(|e| write_failure(&e))?;
        self.sink.flush().map_err(|e| write_failure(&e))
    }

    /// Write a whole document, bypassing the envelope, and end it with a newline.
    ///
    /// [`Self::write_line`] is for commands whose every line is independent. This
    /// is for a command that emits **one machine-readable document** in a format
    /// of its own — `qqqai audit --sarif` is the case that exists today. Such a
    /// document must be the *entire* stdout stream: appending the human
    /// `summary()` line after the closing brace produced 1440 bytes of which the
    /// first 1356 parsed as SARIF and the rest did not, so
    /// `qqqai audit --sarif | jq` failed with `Extra data: line 2 column 1`.
    /// A `--sarif` flag whose output cannot be piped to a SARIF consumer is not
    /// an interchange format, it is a rendering.
    ///
    /// # Errors
    ///
    /// Returns `QQQ-6005` if the sink rejects the write.
    pub fn write_document(&mut self, text: &str) -> Result<()> {
        self.write_line(text)
    }

    /// Consume the writer and return the sink, for tests.
    pub fn into_inner(self) -> W {
        self.sink
    }
}

/// Serialize a successful envelope.
///
/// Extracted from [`Output::emit`] so the envelope construction is reviewable
/// on its own — this is the machine contract an agent consumes.
fn render_success<T: CommandOutput>(
    command: CommandName,
    value: &T,
    exit_code: u8,
) -> Result<String> {
    let envelope = Envelope {
        producer: "qqqai",
        version: qqq_core::VERSION,
        schema_version: qqq_core::SCHEMA_VERSION,
        command: command.as_str(),
        ok: true,
        exit_code,
        summary: value.summary(),
        data: Some(value.to_json()),
        error: None::<ErrorPayload>,
    };
    serde_json::to_string(&envelope).map_err(|e| serialize_failure(&e))
}

/// Serialize a failure envelope.
fn render_failure(command: CommandName, error: &Error, exit_code: u8) -> Result<String> {
    render_failure_payload(command, error, ErrorPayload::from(error), exit_code)
}

/// Serialize a failure envelope from an already-built payload.
///
/// Split out so a caller that must *augment* the payload — the resolved-backtrace
/// path — reuses the envelope construction rather than duplicating it. Two
/// envelopes that drifted apart would be two machine contracts.
fn render_failure_payload(
    command: CommandName,
    error: &Error,
    payload: ErrorPayload,
    exit_code: u8,
) -> Result<String> {
    let envelope = Envelope::<serde_json::Value> {
        producer: "qqqai",
        version: qqq_core::VERSION,
        schema_version: qqq_core::SCHEMA_VERSION,
        command: command.as_str(),
        ok: false,
        exit_code,
        summary: error.message.clone(),
        data: None,
        error: Some(payload),
    };
    serde_json::to_string(&envelope).map_err(|e| serialize_failure(&e))
}

/// The human error block, with a resolved backtrace appended.
///
/// `Error::render()` first, so nothing that was already printed is lost, then the
/// frames under a heading — mirroring `qqq_host::Trap::render`'s shape so a reader
/// who has seen one trap report recognises the other.
fn render_error_with_backtrace(
    error: &Error,
    backtrace: &crate::trap_report::ResolvedBacktrace,
) -> String {
    let mut out = error.render();
    if backtrace.is_empty() {
        return out;
    }
    out.push_str("  guest backtrace:\n");
    for line in backtrace.render().lines() {
        out.push_str("    ");
        out.push_str(line);
        out.push('\n');
    }
    // The explanation is printed even when everything resolved, because it is
    // the sentence that says *whether* debug info was found. A reader who sees
    // three resolved frames still needs to know the map covered all of them.
    out.push_str("    ");
    out.push_str(&backtrace.explanation);
    out.push('\n');
    out
}

/// Build an error for a failed write.
///
/// A closed pipe is a normal way for a pipeline to end, not a fault, so it gets
/// a different remediation from a genuine I/O error.
fn write_failure(e: &std::io::Error) -> Error {
    let broken_pipe = e.kind() == std::io::ErrorKind::BrokenPipe;
    let err = Error::new(
        ErrorCode::HostResourceExhausted,
        if broken_pipe {
            "the output stream was closed by the reader"
        } else {
            "failed to write command output"
        },
    )
    .with_cause(e.to_string());

    if broken_pipe {
        err.with_remediation(
            "this is normal when piping into a command that exits early (e.g. `| head`)",
        )
    } else {
        err.with_remediation("check that the output destination is writable")
    }
}

fn serialize_failure(e: &serde_json::Error) -> Error {
    Error::new(
        ErrorCode::InternalInvariantViolated,
        "command output could not be serialized",
    )
    .with_cause(e.to_string())
    .with_remediation("this is a QQQ bug; please report it")
}

/// The JSON schema for one command's payload.
#[derive(Debug, Clone, Serialize)]
pub struct CommandSchema {
    /// The command name.
    pub command: &'static str,
    /// What it does.
    pub summary: &'static str,
    /// Whether it modifies state.
    pub mutating: bool,
    /// Whether it accepts `--dry-run`.
    pub supports_dry_run: bool,
    /// The JSON Schema for the `data` field of a successful envelope.
    ///
    /// A minimal, honest schema: it declares the object and the properties the
    /// command actually emits. It is deliberately not a full JSON Schema
    /// document — over-specifying a schema that is not machine-generated from
    /// the type would be a *second* source of truth, and the two would drift.
    pub data_schema: serde_json::Value,
}

/// The payload schema for `qqqai schema`.
///
/// Defined once and cloned, so the `match` above stays a pure dispatch and the
/// schema body is readable on its own.
static SCHEMA_FOR_SCHEMA: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
    serde_json::json!({
        "type": "object",
        "properties": {
            "schema_version": {"type": "string"},
            "commands": {"type": "array", "items": {"type": "object"}},
            "errors": {"type": "array", "items": {"type": "object"}},
            "capabilities": {"type": "array", "items": {"type": "object"}}
        },
        "required": ["schema_version", "commands", "errors", "capabilities"]
    })
});

/// The payload schema for `qqqai doctor`.
static SCHEMA_FOR_DOCTOR: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
    serde_json::json!({
        "type": "object",
        "properties": {
            "checks": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "ok": {"type": "boolean"},
                    "detail": {"type": "string"},
                    "fix": {"type": ["string", "null"]}
                },
                "required": ["name", "ok", "detail"]
            }}
        },
        "required": ["checks"]
    })
});

/// The payload schema for `qqqai openapi`.
///
/// # Why `document` is an object and not a string
///
/// The command can either print the document or write it to a file. When it prints, the
/// document is in `document` as a nested JSON value -- **not** as a string containing JSON.
/// A string would force every consumer to parse twice, and a consumer that forgot would see a
/// quoted blob where it expected an object.
///
/// `out` is `null` when nothing was written, which is a different fact from an empty path.
static SCHEMA_FOR_OPENAPI: std::sync::LazyLock<serde_json::Value> =
    std::sync::LazyLock::new(|| {
        serde_json::json!({
            "type": "object",
            "properties": {
                "openapi": {"type": "string"},
                "title": {"type": "string"},
                "version": {"type": "string"},
                "path_count": {"type": "integer", "minimum": 0},
                "operation_count": {"type": "integer", "minimum": 0},
                "out": {"type": ["string", "null"]},
                "document": {"type": "object"}
            },
            "required": [
                "openapi", "title", "version", "path_count", "operation_count", "document"
            ]
        })
    });

/// Build the schema registry.
///
/// # Exhaustiveness
///
/// This function matches on every [`CommandName`] arm with no wildcard, so
/// adding a command without adding a schema **fails to compile**. That is the
/// mechanism behind `CLI-002`.
#[must_use]
pub fn command_schemas() -> Vec<CommandSchema> {
    // Two functions, keyed by payload family. The single match in each is the
    // exhaustiveness gate: `CommandName` is `#[non_exhaustive]` with no
    // wildcard arm for the commands that have a real schema, so adding a command
    // forces a decision here rather than silently shipping `{"type": "object"}`.
    fn schema_for(c: CommandName) -> serde_json::Value {
        match c {
            // Commands whose payload is deliberately permissive: they have not
            // settled a shape yet, and `{"type": "object"}` is honest about
            // that. A schema that lied would be worse than one admitting
            // ignorance.
            CommandName::New
            | CommandName::Init
            | CommandName::Add
            | CommandName::Remove
            | CommandName::Install
            | CommandName::Update
            | CommandName::Build
            | CommandName::Run
            | CommandName::Dev
            | CommandName::Serve
            | CommandName::Test
            | CommandName::Bench
            | CommandName::Fmt
            | CommandName::Lint
            | CommandName::Inspect
            | CommandName::Audit
            | CommandName::Verify
            | CommandName::Caps
            | CommandName::Why
            | CommandName::Trace
            | CommandName::Mcp
            | CommandName::Migrate
            | CommandName::Version
            | CommandName::Help => serde_json::json!({"type": "object"}),
            CommandName::Schema => SCHEMA_FOR_SCHEMA.clone(),
            CommandName::Doctor => SCHEMA_FOR_DOCTOR.clone(),
            // Described rather than permissive: this command's payload is settled -- the
            // OpenAPI document and where it went -- and a consumer reading the envelope needs
            // both. Joining the permissive group would say "we have not decided" about a shape
            // that is decided.
            CommandName::Openapi => SCHEMA_FOR_OPENAPI.clone(),
        }
    }

    CommandName::all()
        .iter()
        .map(|&c| CommandSchema {
            command: c.as_str(),
            summary: c.summary(),
            mutating: c.is_mutating(),
            supports_dry_run: c.supports_dry_run(),
            data_schema: schema_for(c),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A minimal output type for exercising the renderer.
    #[derive(Serialize)]
    struct Fake {
        value: u32,
    }

    impl CommandOutput for Fake {
        fn command(&self) -> CommandName {
            CommandName::Doctor
        }
        fn summary(&self) -> String {
            format!("value is {}", self.value)
        }
        fn to_json(&self) -> serde_json::Value {
            serde_json::json!({"value": self.value})
        }
    }

    fn emit_to_string<T: CommandOutput>(format: Format, value: &T) -> String {
        let mut out = Output::new(format, Vec::new());
        out.emit(value).expect("emit must succeed");
        String::from_utf8(out.into_inner()).expect("utf-8")
    }

    #[test]
    fn human_format_prints_the_summary() {
        let s = emit_to_string(Format::Human, &Fake { value: 7 });
        assert_eq!(s.trim(), "value is 7");
    }

    #[test]
    fn json_format_produces_a_parseable_envelope() {
        let s = emit_to_string(Format::Json, &Fake { value: 7 });
        let v: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON");
        assert_eq!(v["producer"], "qqqai");
        assert_eq!(v["command"], "doctor");
        assert_eq!(v["ok"], true);
        assert_eq!(v["data"]["value"], 7);
        assert_eq!(v["summary"], "value is 7");
        // Version and schema version must be present: an agent uses them to
        // detect drift.
        assert!(v["version"].is_string());
        assert_eq!(v["schema_version"], qqq_core::SCHEMA_VERSION);
        // No error on a success.
        assert!(v.get("error").is_none());
    }

    #[test]
    fn json_lines_format_also_produces_one_object() {
        let s = emit_to_string(Format::JsonLines, &Fake { value: 1 });
        assert_eq!(s.lines().count(), 1, "must be exactly one line");
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert!(v["ok"].as_bool().unwrap());
    }

    #[test]
    fn error_envelope_is_structured_and_actionable() {
        let e = Error::new(ErrorCode::CapabilityDenied, "sql.query is not granted")
            .with_context("capability", "sql.query")
            .with_cause("no layer grants it")
            .with_remediation("add a [[capabilities.sql]] stanza");
        let mut out = Output::new(Format::Json, Vec::new());
        out.emit_error(CommandName::Why, &e).unwrap();
        let s = String::from_utf8(out.into_inner()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        assert_eq!(v["ok"], false);
        assert_eq!(v["command"], "why");
        assert_eq!(v["error"]["code"], "QQQ-4003");
        assert_eq!(v["error"]["retryable"], false);
        assert!(v["error"]["docs_url"]
            .as_str()
            .unwrap()
            .ends_with("QQQ-4003"));
        assert!(v["error"]["remediation"].is_string());
        // Context must be an array of named objects, not tuples.
        assert_eq!(v["error"]["context"][0]["name"], "capability");
        assert_eq!(v["error"]["context"][0]["value"], "sql.query");
    }

    #[test]
    fn error_human_format_uses_the_mandated_block() {
        let e = Error::new(ErrorCode::FuelExhausted, "guest ran out of fuel")
            .with_remediation("raise limits.fuel");
        let mut out = Output::new(Format::Human, Vec::new());
        out.emit_error(CommandName::Run, &e).unwrap();
        let s = String::from_utf8(out.into_inner()).unwrap();
        assert!(s.contains("error[QQQ-3002]"));
        assert!(s.contains("→ raise limits.fuel"));
        assert!(s.contains("Docs:"));
    }

    /// A broken pipe is a normal pipeline ending, not a fault. It must produce
    /// a distinct, non-alarming error rather than a panic.
    #[test]
    fn broken_pipe_is_reported_as_a_normal_pipeline_end() {
        struct ClosedPipe;
        impl Write for ClosedPipe {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut out = Output::new(Format::Human, ClosedPipe);
        let e = out.write_line("x").unwrap_err();
        assert!(e.message.contains("closed by the reader"));
        assert!(
            e.remediation.as_deref().unwrap_or("").contains("| head"),
            "must explain that this is normal: {:?}",
            e.remediation
        );
    }

    // -- The schema registry ----------------------------------------------

    /// **`CLI-002`.** Every command has a schema entry, and the count matches.
    #[test]
    fn every_command_has_a_schema() {
        let schemas = command_schemas();
        assert_eq!(
            schemas.len(),
            CommandName::all().len(),
            "one schema per command is required"
        );
        let names: BTreeSet<&str> = schemas.iter().map(|s| s.command).collect();
        for &c in CommandName::all() {
            assert!(
                names.contains(c.as_str()),
                "command `{c}` has no schema entry"
            );
        }
    }

    #[test]
    fn schemas_are_wellformed_and_unique() {
        let schemas = command_schemas();
        let mut seen = BTreeSet::new();
        for s in &schemas {
            assert!(seen.insert(s.command), "duplicate schema for {}", s.command);
            assert!(!s.summary.is_empty(), "{} needs a summary", s.command);
            assert!(
                s.data_schema.is_object(),
                "{} schema must be a JSON object",
                s.command
            );
            assert!(
                s.data_schema["type"].is_string(),
                "{} schema must declare a type",
                s.command
            );
        }
    }

    /// An agent's first question about a tool is "will this change something?".
    /// The answer must be present for every command.
    #[test]
    fn mutating_commands_are_precisely_classified() {
        for &c in CommandName::all() {
            let s = command_schemas()
                .into_iter()
                .find(|s| s.command == c.as_str())
                .unwrap();
            assert_eq!(s.mutating, c.is_mutating(), "{c} mutating flag mismatched");
            assert_eq!(
                s.supports_dry_run,
                c.supports_dry_run(),
                "{c} dry-run flag mismatched"
            );
            // Every mutating command must support a dry run, so an agent can
            // plan before acting.
            if c.is_mutating() {
                assert!(s.supports_dry_run, "{c} mutates and must support --dry-run");
            }
        }
    }

    /// Read-only commands must NOT claim to be mutating — a false positive
    /// makes an agent refuse to run something safe.
    #[test]
    fn read_only_commands_are_not_marked_mutating() {
        for c in [
            CommandName::Inspect,
            CommandName::Audit,
            CommandName::Why,
            CommandName::Caps,
            CommandName::Doctor,
            CommandName::Schema,
            CommandName::Trace,
            CommandName::Verify,
            CommandName::Version,
            CommandName::Help,
        ] {
            assert!(!c.is_mutating(), "{c} must be classified read-only");
        }
    }

    #[test]
    fn command_names_round_trip_and_are_unique() {
        let mut seen = BTreeSet::new();
        for &c in CommandName::all() {
            assert!(seen.insert(c.as_str()), "duplicate spelling for {c:?}");
            assert_eq!(CommandName::parse(c.as_str()), Some(c));
        }
    }

    #[test]
    fn unknown_command_does_not_parse() {
        assert_eq!(CommandName::parse("nope"), None);
        assert_eq!(CommandName::parse(""), None);
    }

    #[test]
    fn format_selection_prefers_json_lines() {
        assert_eq!(Format::from_flags(false, false), Format::Human);
        assert_eq!(Format::from_flags(true, false), Format::Json);
        assert_eq!(Format::from_flags(false, true), Format::JsonLines);
        assert_eq!(Format::from_flags(true, true), Format::JsonLines);
    }
}
