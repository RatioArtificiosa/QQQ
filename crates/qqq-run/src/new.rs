//! `qqqai new` — scaffold a project.
//!
//! Implements `CLI-003` and `DX-001`; Proposal §5.2, §12.1.
//!
//! # What this command is really for
//!
//! Proposal §12.1 calls the first ten minutes "a spec, not a wish", and this is
//! where that spec is met or missed. Three properties matter more than the
//! template content:
//!
//! 1. **The generated manifest grants nothing** (`DX-002`). Not a starter set,
//!    not a commented-out example that is easy to uncomment — *nothing*. The
//!    first capability a user adds should be one they had to think about.
//!    Proposal §2.7 operationalises "progressive power, safe defaults" this
//!    way: `qqqai new` produces something secure that runs, and the ladder
//!    upward is signposted rather than pre-climbed.
//!
//! 2. **The generated project builds.** A scaffold that does not compile is
//!    worse than no scaffold, because the user's first experience is debugging
//!    someone else's template. Every template here is a real crate that
//!    `qqqai build` accepts.
//!
//! 3. **Nothing is inferred.** The language defaults to Rust but is always
//!    reported, the template defaults but is always reported, and a directory
//!    that already exists is an error rather than a merge. NN-5 applies to
//!    generators too, and a generator that silently adopted an existing
//!    directory could overwrite work.
//!
//! # Why the templates are `&'static str` and not files on disk
//!
//! A template directory read at runtime means `qqqai new` behaves differently
//! depending on where the binary is installed, and it means a packaging mistake
//! turns into a runtime error for the user. Embedding them makes the scaffold a
//! property of the binary, which is what makes it reproducible.

use std::path::Path;

use qqq_core::{Error, ErrorCode, Result};

use crate::output::{CommandName, CommandOutput};

// ---------------------------------------------------------------------------
// Choices
// ---------------------------------------------------------------------------

/// A project template.
///
/// A closed enum rather than a string, so an unknown template is a parse error
/// naming the valid options instead of a directory that is created and left
/// half-populated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    /// An HTTP server. The most common starting point.
    Http,
    /// A queue worker with no listener.
    Worker,
    /// A command-line tool.
    Cli,
    /// A reusable library: no entrypoint, meant to be composed.
    Lib,
    /// A tool that calls a model.
    AiTool,
}

impl Template {
    /// Every template, in the order the docs list them.
    pub const ALL: [Self; 5] = [Self::Http, Self::Worker, Self::Cli, Self::Lib, Self::AiTool];

    /// The template's name on the command line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Worker => "worker",
            Self::Cli => "cli",
            Self::Lib => "lib",
            Self::AiTool => "ai-tool",
        }
    }

    /// Parse a template name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }

    /// The capabilities this template's generated code would need to run for
    /// real, for the guidance comment in the manifest.
    ///
    /// # Why this is documentation and not code
    ///
    /// The manifest is generated with **zero** capabilities even for `http`,
    /// because generating a grant the code has not yet been shown to need would
    /// violate DX-002. The template's comment names what would be needed, so
    /// the ladder is signposted without being pre-climbed.
    #[must_use]
    pub const fn suggests(self) -> &'static str {
        match self {
            Self::Http => "http.server",
            Self::Worker => "queue.subscribe",
            Self::Cli => "none — a CLI usually needs only stdio",
            Self::Lib => "none — a library inherits its caller's grants",
            Self::AiTool => "ai.infer",
        }
    }
}

/// Which language to scaffold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    /// Rust — the only language with a working `build` driver today.
    Rust,
    /// TypeScript, compiled through a QQQ-managed toolchain.
    TypeScript,
    /// Go via `TinyGo`.
    Go,
    /// Python via `CPython` compiled to WASI.
    Python,
    /// C or C++ via clang.
    Cpp,
}

impl Language {
    /// Every language, in the order the docs list them.
    pub const ALL: [Self; 5] = [
        Self::Rust,
        Self::TypeScript,
        Self::Go,
        Self::Python,
        Self::Cpp,
    ];

    /// The language's name in the manifest and on the command line.
    ///
    /// These strings are exactly `Build::LANGUAGES` from `qqq-cap`, and a test
    /// asserts the two lists agree — a scaffold that writes a manifest its own
    /// parser rejects would be a poor first impression.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::TypeScript => "ts",
            Self::Go => "go",
            Self::Python => "python",
            Self::Cpp => "cpp",
        }
    }

    /// Parse a language name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.as_str() == s)
    }

    /// Whether `qqqai build` can drive this language today.
    ///
    /// Reported honestly in the generated project's guidance: a scaffold that
    /// silently produces a project that cannot build is a trap, and the user
    /// would discover it one command later with no explanation.
    #[must_use]
    pub fn is_buildable(self) -> bool {
        crate::build::toolchain_for(self.as_str(), "wasm32-wasip2").is_some()
    }
}

/// The options `qqqai new` accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOptions {
    /// The project name, which becomes the directory name.
    pub name: String,
    /// The language to scaffold.
    pub language: Language,
    /// The template to scaffold.
    pub template: Template,
    /// Skip `git init`.
    pub no_git: bool,
    /// Do not prompt for anything.
    pub yes: bool,
    /// Overwrite an existing non-empty directory.
    pub force: bool,
}

impl Default for NewOptions {
    fn default() -> Self {
        Self {
            name: String::new(),
            language: Language::Rust,
            template: Template::Http,
            no_git: false,
            yes: false,
            // Overwriting is opt-in, always. A generator that adopted an
            // existing directory by default could destroy uncommitted work.
            force: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// A file the scaffold wrote.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WrittenFile {
    /// Path relative to the project directory.
    pub path: String,
    /// Size in bytes.
    pub bytes: u64,
}

/// The result of `qqqai new`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NewOutput {
    /// The project name.
    pub project: String,
    /// The directory created, relative to the working directory.
    pub directory: String,
    /// The language scaffolded.
    pub language: String,
    /// The template used.
    pub template: String,
    /// The files written, in creation order.
    pub files: Vec<WrittenFile>,
    /// Capabilities granted by the generated manifest — always 0.
    pub capabilities_granted: usize,
    /// What the generated code would need, once it is real.
    pub would_need: String,
    /// Whether `git init` was run.
    pub git_initialised: bool,
    /// The command to run next.
    pub next: String,
    /// A warning when the language cannot be built yet.
    pub warning: Option<String>,
}

impl CommandOutput for NewOutput {
    fn command(&self) -> CommandName {
        CommandName::New
    }

    fn summary(&self) -> String {
        format!(
            "created {} ({}, {} files, {} capabilities granted)",
            self.directory,
            self.template,
            self.files.len(),
            self.capabilities_granted
        )
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Check that a name is usable as a directory and a package name.
///
/// # Errors
///
/// `QQQ-2002` with the specific reason, because "invalid name" without saying
/// which rule was broken leaves the user guessing.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::new(
            ErrorCode::ManifestSchemaViolation,
            "a project name is required",
        )
        .with_remediation(format!(
            "for example: {} new orders-api",
            qqq_core::BINARY_NAME
        )));
    }
    // Reuse the manifest's own identifier rule rather than inventing a second
    // one. If the two disagreed, `new` could produce a name `parse` rejects.
    qqq_core::PackageName::new(name.to_owned()).map_err(|e| {
        Error::new(
            ErrorCode::ManifestSchemaViolation,
            format!("`{name}` is not a usable project name"),
        )
        .with_cause(e.to_string())
        .with_remediation(
            "use lowercase letters, digits and hyphens, starting with a letter \
             — for example `orders-api`",
        )
    })?;
    // A name that is a path separator or traversal would write outside the
    // intended directory. Checking here matters because the directory is joined
    // onto the working directory.
    if name.contains(['/', '\\']) || name == "." || name == ".." {
        return Err(Error::new(
            ErrorCode::ManifestSchemaViolation,
            format!("`{name}` must be a plain name, not a path"),
        )
        .with_remediation(
            "run the command from the parent directory and pass only the project name",
        ));
    }
    Ok(())
}

/// The crate name Cargo will use for a project name.
///
/// Cargo rejects hyphens in lib names, so `orders-api` becomes `orders_api`
/// while the *package* name keeps its hyphen. Getting this wrong produces a
/// `Cargo.toml` that does not build, which is the one outcome a scaffold must
/// never produce.
#[must_use]
pub fn crate_name(project: &str) -> String {
    project.replace('-', "_")
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// The files a scaffold writes, as `(relative path, contents)`.
///
/// Returned as data rather than written directly so it can be asserted on
/// without touching a filesystem — and so `--dry-run` has something to report.
/// The logic that decides *what* a project contains is exactly the logic worth
/// testing, and it should not require a temporary directory to test.
#[must_use]
pub fn files_for(opts: &NewOptions) -> Vec<(String, String)> {
    let crate_name = crate_name(&opts.name);
    let mut files = vec![
        ("qqq.toml".to_owned(), manifest_for(opts)),
        ("README.md".to_owned(), readme_for(opts)),
        (".gitignore".to_owned(), GITIGNORE.to_owned()),
    ];
    files.extend(source_files(opts, &crate_name));
    files
}

/// The generated `qqq.toml`.
///
/// # Why this file is mostly comments
///
/// The manifest is the product (Proposal §5.3), and a new user's first encounter
/// with it should teach the model rather than present an empty file. Every
/// stanza the project might need is shown as a comment with an explanation,
/// while the *active* configuration grants nothing.
#[must_use]
pub fn manifest_for(opts: &NewOptions) -> String {
    format!(
        r#"# ─────────────────────────────────────────────────────────────────────────────
# qqq.toml — the QQQ project manifest
#
# Everything here is explicit. Nothing is discovered implicitly.
# Absent means DENIED: this project currently has 0 capabilities granted.
# ─────────────────────────────────────────────────────────────────────────────

[package]
name        = "{name}"
version     = "0.1.0"
description = ""
license     = "Apache-2.0"

[build]
language     = "{language}"
target       = "wasm32-wasip2"
profile      = "release"
reproducible = false

# ── CAPABILITIES ─────────────────────────────────────────────────────────────
# Nothing is granted yet, which is why your app cannot read a file, open a
# socket or reach the network. That is the default, and it is the point.
#
# When you need something, `{binary} why <capability>` prints the exact stanza
# to paste here, and `{binary} caps` lists what is currently granted.
#
# The code in this template suggests you will eventually want:
#   {suggests}
#
# Examples, commented out because you have not needed them yet:
#
# [capabilities.http]
# server = true
# client = ["api.example.com:443"]
#
# [[capabilities.fs]]
# path = "/var/lib/{name}"
# mode = "read-only"

[limits]
memory            = "128MiB"
fuel              = 50000000
epoch_deadline_ms = 5000
"#,
        name = opts.name,
        language = opts.language.as_str(),
        binary = qqq_core::BINARY_NAME,
        suggests = opts.template.suggests(),
    )
}

/// The generated `README.md`.
#[must_use]
pub fn readme_for(opts: &NewOptions) -> String {
    let build_note = if opts.language.is_buildable() {
        String::new()
    } else {
        format!(
            "\n> **Note:** `qqqai build` does not drive `{}` yet. The project is\n\
             > scaffolded correctly and the manifest is valid; the toolchain\n\
             > driver is tracked by the language matrix in `QQQ-Checklist-V1.md`.\n",
            opts.language.as_str()
        )
    };
    format!(
        r"# {name}

Scaffolded by `{binary}` with the `{template}` template.

{build_note}
## Getting started

```bash
{binary} build   # compile to a WebAssembly component
{binary} run     # execute it under the capability sandbox
{binary} caps    # show what it is allowed to do (currently: nothing)
```

## Capabilities

This project starts with **zero** capabilities. It cannot read a file, open a
socket, or reach the network until you say so in `qqq.toml`.

That is not a limitation to work around — it is the security model. When the
code needs something, ask why it was denied:

```bash
{binary} why http.client
```

The answer includes the exact `qqq.toml` stanza to paste.
",
        name = opts.name,
        binary = qqq_core::BINARY_NAME,
        template = opts.template.as_str(),
        build_note = build_note,
    )
}

/// `.gitignore` shared by every template.
///
/// `target/` holds the build output and the AOT cache; both are derived from
/// committed sources and are machine-specific.
const GITIGNORE: &str = "/target\n";

/// The language-specific source files.
fn source_files(opts: &NewOptions, crate_name: &str) -> Vec<(String, String)> {
    match opts.language {
        Language::Rust => rust_sources(opts, crate_name),
        // The other four languages get a manifest, a README and a source file
        // describing what the project will contain — but not fake code that
        // pretends to work. See `Language::is_buildable`.
        other => vec![(
            source_path_for(other, crate_name),
            placeholder_source(opts, other),
        )],
    }
}

/// Where a language's source lives.
fn source_path_for(language: Language, crate_name: &str) -> String {
    match language {
        Language::Rust => format!("src/{crate_name}.rs"),
        Language::TypeScript => "src/index.ts".to_owned(),
        Language::Go => "main.go".to_owned(),
        Language::Python => "src/app.py".to_owned(),
        Language::Cpp => "src/main.cpp".to_owned(),
    }
}

/// The Rust template sources.
fn rust_sources(opts: &NewOptions, crate_name: &str) -> Vec<(String, String)> {
    vec![
        (
            "Cargo.toml".to_owned(),
            format!(
                r#"[package]
name    = "{name}"
version = "0.1.0"
edition = "2021"

[lib]
# A component is a `cdylib`. Building a binary crate for `wasm32-wasip2`
# produces a core module, which the QQQ runtime will reject.
crate-type = ["cdylib"]
# The file is named after the project rather than `lib.rs`, so `src/` is
# readable at a glance. Cargo requires this `path` key to accept a non-default
# name — without it the manifest fails to parse with "can't find library".
path = "src/{crate_name}.rs"

# An empty `[workspace]` table marks this crate as its own workspace root.
#
# Without it, Cargo walks *up* the directory tree looking for a workspace and
# fails on the first one it finds:
#
#     error: failed searching for potential workspace
#     invalid potential workspace manifest: /home/user/Cargo.toml
#
# That happens whenever a project is created anywhere under a directory that
# happens to contain a `Cargo.toml` — including a stray one left by another
# tool. Declaring the root explicitly makes the scaffold independent of whatever
# is above it, which is what a generated project must be.
[workspace]

[profile.release]
opt-level = "s"
lto       = true
"#,
                name = opts.name
            ),
        ),
        (format!("src/{crate_name}.rs"), rust_lib(opts)),
        (
            "tests/smoke.rs".to_owned(),
            // No `format!`: this template has no placeholders, and a `format!`
            // with no arguments is a lint and a needless allocation.
            r"//! A smoke test that runs on the host, not in the sandbox.
//!
//! It proves the crate compiles and its pure logic behaves. Anything that
//! touches a capability belongs in a component test, where the grant set is
//! explicit.

#[test]
fn the_crate_builds() {
    assert_eq!(1 + 1, 2);
}
"
            .to_owned(),
        ),
    ]
}

/// The generated Rust library body for a template.
///
/// # Why this is a dispatch over named constants
///
/// It was a single `match` whose arms were inline raw strings, at 150 lines.
/// Splitting the bodies into `const`s makes each template independently
/// nameable and reviewable, keeps the dispatch readable, and means adding a
/// sixth template is one constant plus one arm rather than a longer function.
/// The bodies are `const` rather than `fn` because none of them needs the
/// options — they are literal text.
fn rust_lib(opts: &NewOptions) -> String {
    match opts.template {
        Template::Http => HTTP_SOURCE,
        Template::Worker => WORKER_SOURCE,
        Template::Cli => CLI_SOURCE,
        Template::Lib => LIB_SOURCE,
        Template::AiTool => AI_TOOL_SOURCE,
    }
    .to_owned()
}

/// The `http` template body.
const HTTP_SOURCE: &str = r#"//! An HTTP handler.
//!
//! The handler is a pure function of a request. Wiring it to a listener is the
//! runtime's job, which is what keeps the logic testable without a socket.

/// A minimal request, so this module has no dependency on the host ABI.
pub struct Request {
    /// The request path.
    pub path: String,
}

/// A minimal response.
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: String,
}

/// Handle one request.
///
/// # Why this takes a plain struct
///
/// Because a handler written against the host ABI cannot be unit-tested
/// without an instance, a grant set and a store. Keeping the logic pure means
/// the interesting part is testable in milliseconds.
#[must_use]
pub fn handle(request: &Request) -> Response {
    match request.path.as_str() {
        "/" => Response { status: 200, body: "Hello from QQQ".to_owned() },
        "/health" => Response { status: 200, body: "ok".to_owned() },
        _ => Response { status: 404, body: "not found".to_owned() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_route_greets() {
        let r = handle(&Request { path: "/".to_owned() });
        assert_eq!(r.status, 200);
        assert!(r.body.contains("QQQ"));
    }

    #[test]
    fn health_is_available() {
        assert_eq!(handle(&Request { path: "/health".to_owned() }).body, "ok");
    }

    #[test]
    fn an_unknown_route_is_404() {
        assert_eq!(handle(&Request { path: "/nope".to_owned() }).status, 404);
    }
}
"#;

/// The `worker` template body.
const WORKER_SOURCE: &str = r#"//! A queue worker.
//!
//! The message type is defined here so the logic is testable without a broker.

/// One message from the queue.
pub struct Message {
    /// The message body.
    pub body: String,
}

/// What to do with a message.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Handle it.
    Handle(String),
    /// Ignore it — an empty or malformed message.
    Skip,
}

/// Decide what a message means.
#[must_use]
pub fn classify(message: &Message) -> Action {
    let trimmed = message.body.trim();
    if trimmed.is_empty() {
        Action::Skip
    } else {
        Action::Handle(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_message_is_handled() {
        let a = classify(&Message { body: "ping".to_owned() });
        assert_eq!(a, Action::Handle("ping".to_owned()));
    }

    #[test]
    fn an_empty_message_is_skipped() {
        assert_eq!(classify(&Message { body: "   ".to_owned() }), Action::Skip);
    }
}
"#;

/// The `cli` template body.
const CLI_SOURCE: &str = r#"//! A command-line tool.

/// The outcome of running the tool.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Print this, exit 0.
    Ok(String),
    /// Print this to stderr, exit 2.
    Usage(String),
}

/// Run the tool over its arguments.
#[must_use]
pub fn run(args: &[String]) -> Outcome {
    match args.first().map(String::as_str) {
        None | Some("--help" | "-h") => Outcome::Ok("usage: app [name]".to_owned()),
        Some(name) => Outcome::Ok(format!("hello, {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_prints_usage() {
        assert!(matches!(run(&[]), Outcome::Ok(m) if m.contains("usage")));
    }

    #[test]
    fn a_name_is_greeted() {
        assert_eq!(run(&["world".to_owned()]), Outcome::Ok("hello, world".to_owned()));
    }
}
"#;

/// The `lib` template body.
const LIB_SOURCE: &str = r"//! A reusable library.
//!
//! No entrypoint: a library inherits its caller's grants, so it declares no
//! capabilities of its own.

/// Add two numbers.
///
/// # Panics
///
/// Panics on overflow in debug builds, wrapping in release. Replace with
/// `checked_add` if the caller can supply hostile input.
#[must_use]
pub fn add(a: i64, b: i64) -> i64 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addition_works() {
        assert_eq!(add(2, 3), 5);
    }

    #[test]
    fn negative_values_work() {
        assert_eq!(add(-1, 1), 0);
    }
}
";

/// The `ai-tool` template body.
const AI_TOOL_SOURCE: &str = r#"//! A tool that calls a model.
//!
//! The prompt is built here and the model is called by the runtime, so the
//! prompt logic is testable without a model or a grant.

/// Build the prompt for a question.
#[must_use]
pub fn prompt(question: &str) -> String {
    format!("Answer concisely.\n\nQuestion: {}", question.trim())
}

/// Whether a model reply looks usable.
#[must_use]
pub fn is_usable(reply: &str) -> bool {
    !reply.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prompt_carries_the_question() {
        assert!(prompt("why is the sky blue?").contains("why is the sky blue?"));
    }

    #[test]
    fn the_prompt_trims_whitespace() {
        assert!(prompt("  hi  ").ends_with("Question: hi"));
    }

    #[test]
    fn an_empty_reply_is_not_usable() {
        assert!(!is_usable("   "));
    }
}
"#;

/// The placeholder source for a language without a build driver yet.
///
/// # Why this is prose and not code
///
/// Writing plausible-looking TypeScript, Go, Python or C++ that has never been
/// compiled would be a silent stub: the user would believe the scaffold works
/// and discover otherwise at `build`, with no indication that the language is
/// simply not wired up yet. A source file that says exactly what is missing is
/// the honest form, and `Language::is_buildable` drives the same message in the
/// README and in the command's output.
fn placeholder_source(opts: &NewOptions, language: Language) -> String {
    let syntax = match language {
        Language::Rust => "rust",
        Language::TypeScript => "typescript",
        Language::Go => "go",
        Language::Python => "python",
        Language::Cpp => "cpp",
    };
    format!(
        "// {name} — the `{lang}` template.\n\
         //\n\
         // This file is a placeholder, and it is deliberately not code.\n\
         //\n\
         // `{binary} build` does not drive `{lang}` yet: the toolchain driver is\n\
         // tracked by the language matrix (LANG-001..LANG-040) in\n\
         // QQQ-Checklist-V1.md. The manifest this project ships is valid and the\n\
         // capability model applies to `{lang}` exactly as it does to Rust — only\n\
         // the compile step is missing.\n\
         //\n\
         // Scaffolding this project in Rust instead gives a working build today:\n\
         //\n\
         //     {binary} new {name}-rs --lang rust --template {template}\n\
         //\n\
         // A `{syntax}` source file will be emitted here once the driver lands.\n",
        name = opts.name,
        lang = language.as_str(),
        binary = qqq_core::BINARY_NAME,
        template = opts.template.as_str(),
        syntax = syntax,
    )
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// Scaffold a project.
///
/// # Errors
///
/// * `QQQ-2002` — the name is not usable.
/// * `QQQ-6005` — the target directory exists and is not empty, or a file could
///   not be written.
pub fn create(opts: &NewOptions, parent: &Path) -> Result<NewOutput> {
    validate_name(&opts.name)?;

    let dir = parent.join(&opts.name);
    if dir.exists() && !opts.force {
        let empty = std::fs::read_dir(&dir).is_ok_and(|mut d| d.next().is_none());
        if !empty {
            return Err(Error::new(
                ErrorCode::HostResourceExhausted,
                format!("`{}` already exists and is not empty", opts.name),
            )
            // Named as a data-loss risk rather than a nuisance: the alternative
            // behaviour would be to merge into a directory the user may have
            // work in.
            .with_remediation(
                "choose another name, remove the directory, or pass --force to \
                 write into it anyway (existing files with these names are overwritten)",
            ));
        }
    }

    std::fs::create_dir_all(&dir).map_err(|e| {
        Error::new(
            ErrorCode::HostResourceExhausted,
            format!("could not create `{}`", dir.display()),
        )
        .with_cause(e.to_string())
    })?;

    let files = files_for(opts);
    let mut written = Vec::with_capacity(files.len());
    for (rel, contents) in &files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::new(
                    ErrorCode::HostResourceExhausted,
                    format!("could not create `{}`", parent.display()),
                )
                .with_cause(e.to_string())
            })?;
        }
        if path.exists() && !opts.force {
            // The emptiness check above guarded the directory; this guards
            // against a partial previous run leaving files behind with no
            // directory state to detect it.
            return Err(Error::new(
                ErrorCode::HostResourceExhausted,
                format!("`{}` already exists", path.display()),
            )
            .with_remediation("pass --force to overwrite"));
        }
        std::fs::write(&path, contents).map_err(|e| {
            Error::new(
                ErrorCode::HostResourceExhausted,
                format!("could not write `{}`", path.display()),
            )
            .with_cause(e.to_string())
        })?;
        written.push(WrittenFile {
            path: rel.clone(),
            bytes: u64::try_from(contents.len()).unwrap_or(u64::MAX),
        });
    }

    let git_initialised = if opts.no_git { false } else { init_git(&dir) };

    // The generated manifest grants nothing by construction, but reporting the
    // *count* rather than asserting zero means a future template that needs a
    // capability cannot silently break the DX-002 promise — the number in the
    // output would change and a test would catch it.
    let capabilities_granted = qqq_cap::manifest::Manifest::parse(&manifest_for(opts))
        .map_or(0, |m| m.declared_capabilities().len());

    let mut warning = None;
    if !opts.language.is_buildable() {
        warning = Some(format!(
            "`{} build` does not drive `{}` yet; the language matrix \
             (LANG-001..LANG-040) tracks the driver",
            qqq_core::BINARY_NAME,
            opts.language.as_str()
        ));
    }

    Ok(NewOutput {
        project: opts.name.clone(),
        directory: opts.name.clone(),
        language: opts.language.as_str().to_owned(),
        template: opts.template.as_str().to_owned(),
        files: written,
        capabilities_granted,
        would_need: opts.template.suggests().to_owned(),
        git_initialised,
        next: format!("cd {} && {} run", opts.name, qqq_core::BINARY_NAME),
        warning,
    })
}

/// Run `git init` in a new project.
///
/// Best-effort and silent on failure: a machine without git is a perfectly good
/// machine to write software on, and `qqqai new` succeeding without version
/// control is better than failing because of it. The boolean in the output
/// tells the truth about what happened.
fn init_git(dir: &Path) -> bool {
    std::process::Command::new("git")
        .arg("init")
        .arg("--quiet")
        .current_dir(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use qqq_cap::manifest::Build as BuildSpec;

    fn opts(name: &str) -> NewOptions {
        NewOptions {
            name: name.to_owned(),
            ..Default::default()
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-new-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    // -- name validation ---------------------------------------------------

    #[test]
    fn a_good_name_is_accepted() {
        for n in ["app", "orders-api", "a1", "my-service-2"] {
            validate_name(n).unwrap_or_else(|e| panic!("`{n}` should be valid: {e}"));
        }
    }

    #[test]
    fn an_empty_name_is_refused_with_an_example() {
        let e = validate_name("").unwrap_err();
        assert_eq!(e.code, ErrorCode::ManifestSchemaViolation);
        assert!(e.remediation.as_deref().unwrap_or("").contains("new"));
    }

    /// A name containing a separator would write outside the intended
    /// directory. This is the injection case for a generator.
    #[test]
    fn a_path_like_name_is_refused() {
        for n in ["../escape", "a/b", "a\\b", ".", ".."] {
            assert!(
                validate_name(n).is_err(),
                "`{n}` must be refused: it is a path, not a name"
            );
        }
    }

    #[test]
    fn a_name_with_spaces_or_capitals_is_refused() {
        for n in ["My App", "App", "app!", "-app"] {
            assert!(validate_name(n).is_err(), "`{n}` should be refused");
        }
    }

    // -- template and language parsing -------------------------------------

    #[test]
    fn every_template_parses_from_its_own_name() {
        for t in Template::ALL {
            assert_eq!(Template::parse(t.as_str()), Some(t));
        }
        assert_eq!(Template::parse("nonsense"), None);
    }

    #[test]
    fn every_language_parses_from_its_own_name() {
        for l in Language::ALL {
            assert_eq!(Language::parse(l.as_str()), Some(l));
        }
        assert_eq!(Language::parse("cobol"), None);
    }

    /// The scaffold must write a manifest its own parser accepts. These two
    /// lists living in different crates is exactly how they would drift.
    #[test]
    fn the_scaffold_languages_match_the_manifest_languages() {
        for l in Language::ALL {
            assert!(
                BuildSpec::supports_language(l.as_str()),
                "`{}` is scaffoldable but the manifest parser rejects it",
                l.as_str()
            );
        }
        assert_eq!(
            Language::ALL.len(),
            BuildSpec::LANGUAGES.len(),
            "the scaffold and the manifest disagree about how many languages exist"
        );
    }

    /// Rust is the one language that must be buildable, or the scaffold's
    /// primary path is broken.
    #[test]
    fn rust_is_scaffoldable_and_buildable() {
        assert!(Language::Rust.is_buildable());
    }

    // -- generated manifest ------------------------------------------------

    /// **DX-002: a generated project grants nothing.** This is the safe-defaults
    /// promise, and it is checked by parsing the generated manifest rather than
    /// by inspecting the template string — so a template that grew a capability
    /// would fail here regardless of how it was written.
    #[test]
    fn the_generated_manifest_grants_nothing_for_every_template() {
        for t in Template::ALL {
            let o = NewOptions {
                name: "app".to_owned(),
                template: t,
                ..Default::default()
            };
            let text = manifest_for(&o);
            let m = qqq_cap::manifest::Manifest::parse(&text).unwrap_or_else(|e| {
                panic!("the {} template's manifest is invalid: {e}", t.as_str())
            });
            assert_eq!(
                m.declared_capabilities().len(),
                0,
                "the {} template must grant nothing",
                t.as_str()
            );
        }
    }

    /// And for every language, since the language field is interpolated.
    #[test]
    fn the_generated_manifest_is_valid_for_every_language() {
        for l in Language::ALL {
            let o = NewOptions {
                name: "app".to_owned(),
                language: l,
                ..Default::default()
            };
            let text = manifest_for(&o);
            let m = qqq_cap::manifest::Manifest::parse(&text)
                .unwrap_or_else(|e| panic!("the {} manifest is invalid: {e}", l.as_str()));
            assert_eq!(m.build.language, l.as_str());
            assert_eq!(m.package.name, "app");
            assert_eq!(m.declared_capabilities().len(), 0);
        }
    }

    /// The manifest must name the language the user asked for, or `build`
    /// silently compiles the wrong thing.
    #[test]
    fn the_manifest_names_the_requested_language() {
        for l in Language::ALL {
            let o = NewOptions {
                name: "app".to_owned(),
                language: l,
                ..Default::default()
            };
            assert!(manifest_for(&o).contains(&format!("language     = \"{}\"", l.as_str())));
        }
    }

    /// The manifest must signpost the ladder without pre-climbing it: the
    /// suggested capability appears **commented out**.
    #[test]
    fn the_manifest_comments_out_the_suggested_capability() {
        let o = NewOptions {
            name: "app".to_owned(),
            template: Template::Http,
            ..Default::default()
        };
        let text = manifest_for(&o);
        assert!(
            text.contains("http.server"),
            "the ladder must be signposted"
        );
        // Every suggestion must be inside a comment line.
        for line in text.lines() {
            if line.contains("http.server") {
                assert!(
                    line.trim_start().starts_with('#'),
                    "a suggestion must be commented out, not active: {line}"
                );
            }
        }
    }

    // -- generated files ---------------------------------------------------

    #[test]
    fn a_rust_project_gets_working_files() {
        let o = opts("orders-api");
        let files = files_for(&o);
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"qqq.toml"));
        assert!(names.contains(&"Cargo.toml"));
        assert!(names.contains(&"README.md"));
        assert!(names.contains(&".gitignore"));
        assert!(names.contains(&"src/orders_api.rs"), "got {names:?}");
    }

    /// Cargo rejects hyphens in a lib name, so the file must use underscores
    /// while the package keeps its hyphen. Getting this wrong produces a
    /// scaffold that does not build.
    #[test]
    fn a_hyphenated_name_becomes_an_underscored_crate() {
        assert_eq!(crate_name("orders-api"), "orders_api");
        assert_eq!(crate_name("app"), "app");
        let o = opts("orders-api");
        let files = files_for(&o);
        let cargo = files.iter().find(|(n, _)| n == "Cargo.toml").unwrap();
        assert!(
            cargo.1.contains("name    = \"orders-api\""),
            "the package keeps the hyphen"
        );
        assert!(
            cargo.1.contains("crate-type = [\"cdylib\"]"),
            "a component must be a cdylib"
        );
    }

    /// The generated `Cargo.toml` must declare a `cdylib`, because that is what
    /// makes `wasm32-wasip2` emit a component rather than a core module — the
    /// exact failure the build classifier reports.
    #[test]
    fn every_rust_project_declares_a_cdylib() {
        for t in Template::ALL {
            let o = NewOptions {
                name: "app".to_owned(),
                template: t,
                ..Default::default()
            };
            let files = files_for(&o);
            let cargo = files.iter().find(|(n, _)| n == "Cargo.toml").unwrap();
            assert!(
                cargo.1.contains("crate-type = [\"cdylib\"]"),
                "the {} template must declare a cdylib",
                t.as_str()
            );
        }
    }

    /// **The regression test for a bug the string assertions missed.**
    ///
    /// The generator originally wrote `src/<crate>.rs` and declared
    /// `crate-type = ["cdylib"]` without a `path`. Cargo then refused to parse
    /// the manifest at all:
    ///
    /// ```text
    /// can't find library `orders_api`, rename file to `src/lib.rs` or specify lib.path
    /// ```
    ///
    /// So `qqqai new` produced a project that could not build — the single worst
    /// outcome a scaffold can have. Every test above passed throughout, because
    /// they asserted on *strings in generated files* rather than on whether
    /// Cargo would accept them.
    ///
    /// This test checks the invariant directly: whatever `[lib].path` is
    /// declared must be a file the scaffold actually writes. That is the
    /// property Cargo enforces, checked without invoking Cargo.
    #[test]
    fn the_declared_lib_path_is_a_file_that_is_written() {
        // The generated Cargo.toml names its library file explicitly. Whatever
        // it says must exist, or `cargo build` fails before compiling anything.
        for t in Template::ALL {
            let o = NewOptions {
                name: "orders-api".to_owned(),
                template: t,
                ..Default::default()
            };
            let files = files_for(&o);
            let cargo = files
                .iter()
                .find(|(n, _)| n == "Cargo.toml")
                .expect("a Rust project has a Cargo.toml")
                .1
                .clone();

            let declared = cargo
                .lines()
                .find_map(|l| l.trim().strip_prefix("path = "))
                .map(|v| v.trim().trim_matches('"').to_owned())
                .expect("the [lib] table must declare `path` when the file is not lib.rs");

            assert!(
                files.iter().any(|(n, _)| *n == declared),
                "Cargo.toml declares lib.path = `{declared}`, but the scaffold \
                 never writes that file. Files written: {:?}",
                files.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()
            );
        }
    }

    /// And the corollary: a crate declared without `path` must supply
    /// `src/lib.rs`, which is Cargo's default. Either arrangement works; a
    /// silent mixture does not.
    #[test]
    fn a_crate_without_an_explicit_path_writes_lib_rs() {
        let o = NewOptions {
            name: "app".to_owned(),
            ..Default::default()
        };
        let files = files_for(&o);
        let cargo = files
            .iter()
            .find(|(n, _)| n == "Cargo.toml")
            .unwrap()
            .1
            .clone();
        if !cargo.contains("path = ") {
            assert!(
                files.iter().any(|(n, _)| n == "src/lib.rs"),
                "without lib.path, Cargo looks for src/lib.rs — the scaffold must write it"
            );
        }
    }

    /// **The regression test for the second scaffold bug.** Cargo walks *up* the
    /// directory tree looking for a workspace, and refuses to build if it finds
    /// a `Cargo.toml` above that is not a valid workspace root:
    ///
    /// ```text
    /// error: failed searching for potential workspace
    /// invalid potential workspace manifest: /home/user/Cargo.toml
    /// ```
    ///
    /// A user creating a project in their home directory — which is the normal
    /// thing to do — hits this whenever that directory contains a stray
    /// `Cargo.toml`. An empty `[workspace]` table marks the crate as its own
    /// root and makes the scaffold independent of everything above it.
    #[test]
    fn a_generated_crate_is_its_own_workspace_root() {
        for t in Template::ALL {
            let o = NewOptions {
                name: "app".to_owned(),
                template: t,
                ..Default::default()
            };
            let files = files_for(&o);
            let cargo = files
                .iter()
                .find(|(n, _)| n == "Cargo.toml")
                .expect("a Rust project has a Cargo.toml")
                .1
                .clone();
            assert!(
                cargo.lines().any(|l| l.trim() == "[workspace]"),
                "the {} template's Cargo.toml must declare an empty `[workspace]`, \
                 or Cargo searches upward and fails on a stray manifest above",
                t.as_str()
            );
        }
    }

    /// Every template must produce Rust source that is non-empty and testable.
    #[test]
    fn every_template_produces_rust_source_with_tests() {
        for t in Template::ALL {
            let o = NewOptions {
                name: "app".to_owned(),
                template: t,
                ..Default::default()
            };
            let files = files_for(&o);
            let src = files
                .iter()
                .find(|(n, _)| n == "src/app.rs")
                .unwrap_or_else(|| panic!("the {} template produced no source", t.as_str()));
            assert!(!src.1.is_empty());
            assert!(
                src.1.contains("mod tests"),
                "the {} template's source has no tests",
                t.as_str()
            );
            assert!(
                src.1.contains("#[test]"),
                "the {} template's source declares no test functions",
                t.as_str()
            );
        }
    }

    /// The README must state the zero-capability fact. It is the first thing a
    /// user reads, and the security model is the thing they most need to know.
    #[test]
    fn every_readme_explains_the_capability_model() {
        for t in Template::ALL {
            let o = NewOptions {
                name: "app".to_owned(),
                template: t,
                ..Default::default()
            };
            let readme = readme_for(&o);
            assert!(
                readme.contains("zero"),
                "the {} readme must say zero",
                t.as_str()
            );
            assert!(
                readme.contains("capabilit"),
                "the {} readme must explain capabilities",
                t.as_str()
            );
            assert!(
                readme.contains(&format!("{} why", qqq_core::BINARY_NAME)),
                "the readme must teach `why`"
            );
        }
    }

    /// A language without a driver must say so in the README rather than
    /// producing source that looks like it works.
    #[test]
    fn an_unbuildable_language_is_declared_in_the_readme() {
        let o = NewOptions {
            name: "app".to_owned(),
            language: Language::TypeScript,
            ..Default::default()
        };
        if !Language::TypeScript.is_buildable() {
            let readme = readme_for(&o);
            assert!(
                readme.contains("does not drive"),
                "an unbuildable language must be declared: {readme}"
            );
        }
    }

    /// And the placeholder source must not pretend to be working code.
    #[test]
    fn an_unbuildable_language_gets_prose_not_fake_code() {
        for l in Language::ALL {
            if l.is_buildable() {
                continue;
            }
            let o = NewOptions {
                name: "app".to_owned(),
                language: l,
                ..Default::default()
            };
            let files = files_for(&o);
            let (_, src) = files
                .iter()
                .find(|(n, _)| {
                    n.starts_with("src/")
                        || std::path::Path::new(n)
                            .extension()
                            .is_some_and(|e| e.eq_ignore_ascii_case("go"))
                })
                .unwrap_or_else(|| panic!("{} produced no source", l.as_str()));
            assert!(
                src.contains("placeholder"),
                "{} must say it is a placeholder, not fake code",
                l.as_str()
            );
            assert!(
                src.contains("LANG-0"),
                "{} must name the tracking item",
                l.as_str()
            );
        }
    }

    // -- execution ---------------------------------------------------------

    #[test]
    fn creating_a_project_writes_every_file() {
        let parent = temp_dir("create");
        let o = NewOptions {
            name: "myapp".to_owned(),
            no_git: true,
            ..Default::default()
        };
        let out = create(&o, &parent).expect("must create");
        assert_eq!(out.project, "myapp");
        assert_eq!(out.capabilities_granted, 0);
        assert!(!out.git_initialised, "--no-git must be honoured");
        assert!(out.warning.is_none(), "rust is buildable");

        for f in &out.files {
            let p = parent.join("myapp").join(&f.path);
            assert!(p.exists(), "{} was reported but not written", f.path);
            // The reported size must be the real size, or the JSON contract lies.
            let real = std::fs::metadata(&p).unwrap().len();
            assert_eq!(real, f.bytes, "size mismatch for {}", f.path);
        }
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// An existing non-empty directory must be refused, not merged into.
    #[test]
    fn an_existing_directory_is_refused() {
        let parent = temp_dir("exists");
        std::fs::create_dir_all(parent.join("taken")).unwrap();
        std::fs::write(parent.join("taken").join("important.txt"), "work").unwrap();

        let o = NewOptions {
            name: "taken".to_owned(),
            no_git: true,
            ..Default::default()
        };
        let e = create(&o, &parent).unwrap_err();
        assert_eq!(e.code, ErrorCode::HostResourceExhausted);
        assert!(e.remediation.as_deref().unwrap_or("").contains("--force"));
        // And the existing work must be untouched.
        assert!(parent.join("taken").join("important.txt").exists());
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn force_overwrites_an_existing_directory() {
        let parent = temp_dir("force");
        std::fs::create_dir_all(parent.join("taken")).unwrap();
        std::fs::write(parent.join("taken").join("qqq.toml"), "garbage").unwrap();

        let o = NewOptions {
            name: "taken".to_owned(),
            no_git: true,
            force: true,
            ..Default::default()
        };
        let out = create(&o, &parent).expect("--force must proceed");
        assert_eq!(out.capabilities_granted, 0);
        let written = std::fs::read_to_string(parent.join("taken").join("qqq.toml")).unwrap();
        assert!(written.contains("[package]"), "the file must be replaced");
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// The whole point of the scaffold: the project it produces must be one
    /// `qqqai build` can plan. This checks the *plan* rather than compiling,
    /// so it does not depend on the wasm target being installed.
    #[test]
    fn the_created_project_plans_a_build() {
        let parent = temp_dir("plans");
        let o = NewOptions {
            name: "plans".to_owned(),
            no_git: true,
            ..Default::default()
        };
        create(&o, &parent).expect("must create");

        let loaded = crate::LoadedManifest::load(&parent.join("plans").join("qqq.toml"))
            .expect("the generated manifest must load");
        // Either it plans, or it fails only because the toolchain is absent —
        // which is the same contract `build` has.
        match crate::build::plan(&loaded, &crate::BuildOptions::default()) {
            Ok(p) => assert!(p.render().contains("wasm32-wasip2")),
            Err(e) => assert_eq!(
                e.code,
                ErrorCode::MissingTarget,
                "the generated project must fail only for a missing toolchain: {e:?}"
            ),
        }
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn a_bad_name_is_refused_before_touching_the_filesystem() {
        let parent = temp_dir("badname");
        let o = NewOptions {
            name: "../escape".to_owned(),
            no_git: true,
            ..Default::default()
        };
        assert!(create(&o, &parent).is_err());
        // Nothing may have been created outside the parent.
        assert!(!parent.parent().unwrap().join("escape").exists());
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn the_summary_reports_zero_capabilities() {
        let o = opts("app");
        let parent = temp_dir("summary");
        let out = create(&NewOptions { no_git: true, ..o }, &parent).expect("must create");
        let s = out.summary();
        assert!(s.contains("0 capabilities granted"), "got: {s}");
        let j = out.to_json();
        assert_eq!(j["capabilities_granted"], 0);
        assert!(j["next"].as_str().unwrap().contains("run"));
        let _ = std::fs::remove_dir_all(&parent);
    }
}
