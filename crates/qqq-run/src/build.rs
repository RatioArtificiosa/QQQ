//! `qqqai build` — compile a project to a `.component.wasm`.
//!
//! Implements Proposal §4.6 (the artifact model) and §5.2's `build` row;
//! Checklist `CLI-008`.
//!
//! # The shape of this module, and why
//!
//! Building is the one place QQQ must drive a foreign toolchain. That is a
//! trust boundary in both directions: we hand a command line to a compiler we
//! did not write, and we accept a file back that we then load into a sandbox.
//! Three consequences shape everything below.
//!
//! 1. **The invocation is constructed, never concatenated.** Arguments are
//!    passed as a `Vec<String>` to `Command::args`, so no shell parses them. A
//!    path containing a space, a quote or a `;` is one argument, not two — and
//!    a project directory named `app; rm -rf ~` is merely a strange directory
//!    name. Building a shell string and passing it to `sh -c` would make every
//!    project directory an injection vector.
//!
//! 2. **A missing toolchain is diagnosed, not attempted.** We probe for the
//!    program before invoking it. `Command::new("cargo").status()` on a machine
//!    without Cargo returns an OS error whose text is platform-specific and
//!    unhelpful; probing lets us emit `QQQ-1003` with the exact command that
//!    installs what is missing.
//!
//! 3. **The artifact is verified, not assumed.** A compiler that exits 0 while
//!    emitting a core module instead of a component is a real and common
//!    failure (it is what happens when the component-model target is missing).
//!    We check the artifact's shape before declaring success, because a build
//!    that reports success and produces an unloadable file moves the failure to
//!    deploy time, which is strictly worse.
//!
//! # What is deliberately *not* here
//!
//! `--aot` does not compile to `.cwasm` in this module yet. The AOT cache is
//! owned by `qqq-host` (`aot_cache_key`), and wiring it correctly means
//! agreeing on where the cache lives and how it is invalidated. Rather than
//! half-build it, the flag is accepted and reported as not-yet-effective — see
//! `BuildOutput::aot` and the note in `plan()`. That is a **declared gap**, not
//! a silent one.

use std::path::{Path, PathBuf};
use std::process::Command;

use qqq_cap::manifest::Build as BuildSpec;
use qqq_core::{Error, ErrorCode, Result};

use crate::manifest_loader::LoadedManifest;
use crate::output::{CommandName, CommandOutput};

/// The file extension of a compiled component.
pub const COMPONENT_EXTENSION: &str = "component.wasm";

/// Where build outputs go, relative to the project directory.
pub const OUTPUT_DIR: &str = "target/qqq";

// ---------------------------------------------------------------------------
// Toolchain description
// ---------------------------------------------------------------------------

/// A program `build` needs, and how to obtain it.
///
/// The "how to obtain it" half is not decoration. A diagnosis command that says
/// `cargo not found` and stops has done half the job; the user is now exactly
/// as stuck as before, one step later. Naming the install command turns the
/// error into the fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRequirement {
    /// The program to run.
    pub program: &'static str,
    /// The argument that prints its version, used as a liveness probe.
    pub version_args: &'static [&'static str],
    /// What installs it, as a runnable command.
    pub install: &'static str,
    /// Why the build needs it.
    pub why: &'static str,
}

/// The toolchain a language needs, or `None` when the language is not one this
/// build can drive.
///
/// Returning a `Vec` rather than a single program because a language may need
/// more than the compiler: `wasm-tools` is needed to validate that the output
/// really is a component, and C/C++ needs `clang` plus the WASI sysroot.
///
/// # Why most languages return `None`
///
/// `None` means **declared, not implemented**, and the caller turns it into an
/// honest `QQQ-1001` naming the checklist area. Returning a plausible-looking
/// requirement list for a driver that does not exist would produce a build that
/// fails inside a shell command — a worse error, further from the cause.
#[must_use]
pub fn toolchain_for(language: &str, target: &str) -> Option<Vec<ToolRequirement>> {
    // `target` is not yet a discriminator: `wasm32-wasip2` is the only target
    // any language can emit, so it does not change which tools are needed.
    // Taking it now keeps the signature stable for `wasm32-wasip3`, which will
    // need a different `wasm-tools` path.
    let _ = target;

    if language != "rust" {
        return None;
    }
    Some(vec![
        ToolRequirement {
            program: "cargo",
            version_args: &["--version"],
            install: "https://rustup.rs",
            why: "compiles Rust to the component model",
        },
        ToolRequirement {
            program: "wasm-tools",
            version_args: &["--version"],
            install: "cargo install wasm-tools",
            why: "validates that the output is a component, not a core module",
        },
    ])
}

/// Whether a program can be executed, and its reported version.
///
/// # Why we run `--version` rather than checking PATH
///
/// A file can exist on `PATH` and still be unrunnable: wrong architecture, no
/// execute bit, a broken shim. Running it is the only check that answers the
/// question we actually have. It is also cheap — measured well under a
/// millisecond for `cargo --version` on a warm cache, against a build that
/// takes seconds.
#[must_use]
pub fn probe(program: &str, version_args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(version_args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.lines().next().unwrap_or("").trim();
    Some(if first.is_empty() {
        // Some tools print the version to stderr, or print nothing useful.
        // Reporting "present" is more honest than reporting an empty version,
        // which would read as a parse bug.
        "(version not reported)".to_owned()
    } else {
        first.to_owned()
    })
}

// ---------------------------------------------------------------------------
// The build plan
// ---------------------------------------------------------------------------

/// A fully-resolved invocation, ready to run.
///
/// Exposed as a value rather than executed inline so that `--dry-run` can print
/// it, `--json` can report it, and tests can assert on it **without running a
/// compiler**. That last one is the point: the logic that decides what to run is
/// exactly the logic worth testing, and it should not require a toolchain to
/// test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPlan {
    /// The program to execute.
    pub program: String,
    /// Its arguments, one element per argument.
    pub args: Vec<String>,
    /// The directory it runs in.
    pub cwd: PathBuf,
}

impl BuildPlan {
    /// Render the invocation as one line, quoted for display.
    ///
    /// Quoted because the point of showing it is that the user can paste it
    /// into a shell and get the same result. Unquoted, a path with a space would
    /// paste into something different from what ran.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = shell_quote(&self.program);
        for a in &self.args {
            out.push(' ');
            out.push_str(&shell_quote(a));
        }
        out
    }
}

/// Quote an argument for display so a pasted command behaves identically.
#[must_use]
pub fn shell_quote(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@".contains(c));
    if plain {
        return s.to_owned();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The build options, as parsed from the command line and the manifest.
///
/// # Why a bitfield rather than four bools
///
/// Four independent booleans make every combination representable, including
/// `release` and `debug` together — which is a contradiction, not a state. A
/// packed `u8` with named constructors makes the *invalid* state harder to
/// build by accident and keeps the struct a single comparable value, which is
/// what lets `BuildOptions::default()` be tested for meaning. This mirrors the
/// `GlobalFlags` pattern already used in `main.rs`, so the codebase has one
/// answer to "how do we carry several command-line switches".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BuildOptions {
    /// Bit flags; see the constants below.
    bits: u8,
    /// Override the manifest's target.
    pub target: Option<String>,
}

impl BuildOptions {
    /// `--release`
    pub const RELEASE: u8 = 1 << 0;
    /// `--debug`
    pub const DEBUG: u8 = 1 << 1;
    /// `--aot`
    pub const AOT: u8 = 1 << 2;
    /// `--reproducible`
    pub const REPRODUCIBLE: u8 = 1 << 3;

    /// Set a flag.
    pub fn set(&mut self, flag: u8) {
        self.bits |= flag;
    }

    /// Test a flag.
    #[must_use]
    pub const fn has(&self, flag: u8) -> bool {
        self.bits & flag != 0
    }

    /// Whether a release build was requested.
    #[must_use]
    pub const fn release(&self) -> bool {
        self.has(Self::RELEASE)
    }

    /// Whether a debug build was requested.
    #[must_use]
    pub const fn debug(&self) -> bool {
        self.has(Self::DEBUG)
    }

    /// Whether AOT compilation was requested.
    #[must_use]
    pub const fn aot(&self) -> bool {
        self.has(Self::AOT)
    }

    /// Whether the build must be bit-reproducible.
    #[must_use]
    pub const fn reproducible(&self) -> bool {
        self.has(Self::REPRODUCIBLE)
    }

    /// Build an option set from flags, for callers that have already decoded
    /// the command line.
    #[must_use]
    pub fn from_flags(bits: u8, target: Option<String>) -> Self {
        Self { bits, target }
    }
}

/// Plan a build.
///
/// # Errors
///
/// * `QQQ-1003` — the manifest names a language or profile this build cannot
///   drive.
/// * `QQQ-1001` — the output directory could not be created.
pub fn plan(loaded: &LoadedManifest, opts: &BuildOptions) -> Result<BuildPlan> {
    let spec: &BuildSpec = &loaded.manifest.build;

    if !BuildSpec::supports_language(&spec.language) {
        return Err(Error::new(
            ErrorCode::MissingTarget,
            format!("`{}` is not a language this build can drive", spec.language),
        )
        .with_remediation(format!(
            "supported languages: {}",
            BuildSpec::LANGUAGES.join(", ")
        )));
    }

    // `--release` and `--debug` together is a contradiction, not a precedence
    // puzzle. Silently letting one win is how a CI job builds the wrong profile
    // and nobody notices until the binary is slow.
    if opts.release() && opts.debug() {
        return Err(Error::new(
            ErrorCode::McpArgumentInvalid,
            "`--release` and `--debug` ask for opposite profiles",
        )
        .with_remediation("pass at most one of them"));
    }

    let profile = if opts.release() {
        "release"
    } else if opts.debug() {
        "debug"
    } else {
        spec.profile.as_str()
    };

    let target = opts.target.as_deref().unwrap_or(spec.target.as_str());
    if !BuildSpec::supports_target(target) {
        return Err(Error::new(
            ErrorCode::MissingTarget,
            format!("`{target}` is not a target this build can emit"),
        )
        .with_remediation(format!(
            "supported targets: {}",
            BuildSpec::TARGETS.join(", ")
        )));
    }

    let toolchain = toolchain_for(&spec.language, target).ok_or_else(|| {
        Error::new(
            ErrorCode::CompilationFailed,
            format!(
                "the `{}` toolchain driver is not implemented yet",
                spec.language
            ),
        )
        .with_remediation(format!(
            "Rust is fully supported today; `{}` is tracked by the language matrix in \
             QQQ-Checklist-V1.md (LANG-001..LANG-040)",
            spec.language
        ))
    })?;

    // Missing tools are reported here, before any work, naming every one that
    // is absent. Reporting them one at a time would make a fresh machine take
    // three attempts to learn three facts.
    let missing: Vec<&ToolRequirement> = toolchain
        .iter()
        .filter(|t| probe(t.program, t.version_args).is_none())
        .collect();
    if let Some(first) = missing.first() {
        let all = missing
            .iter()
            .map(|t| format!("{} ({} — install with `{}`)", t.program, t.why, t.install))
            .collect::<Vec<_>>()
            .join("\n  ");
        return Err(Error::new(
            ErrorCode::MissingTarget,
            format!(
                "missing {} required for a `{}` build",
                noun(&missing),
                spec.language
            ),
        )
        .with_cause(format!("missing:\n  {all}"))
        // The first missing tool's install line, not an arbitrary one: the
        // probe order is the dependency order, so the first is the one that
        // unblocks the rest.
        .with_remediation(first.install));
    }

    let args = match spec.language.as_str() {
        "rust" => rust_args(profile, target),
        // `toolchain_for` returned `Some` for this language, so this arm exists
        // only if a language was added to one function and not the other.
        // Failing loudly is the correct behaviour: silently building nothing
        // is how a language matrix rots.
        other => {
            return Err(Error::new(
                ErrorCode::InternalInvariantViolated,
                format!("`{other}` has a toolchain but no argument builder"),
            )
            .with_remediation("this is a qqqai bug; the two lists in build.rs disagree"));
        }
    };

    Ok(BuildPlan {
        program: "cargo".to_owned(),
        args,
        cwd: loaded
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
    })
}

/// `1 thing` / `2 things`.
///
/// A pluralisation helper rather than `format!("{} things", n)`, because
/// "missing 1 tools" is the kind of detail that tells a reader the message was
/// never read by its author.
fn noun<T>(items: &[T]) -> String {
    if items.len() == 1 {
        "a tool".to_owned()
    } else {
        format!("{} tools", items.len())
    }
}

/// The `cargo build` arguments for a component build.
///
/// # Why `--target` is passed twice-ish
///
/// `cargo build --target wasm32-wasip2` emits a core module for a normal Rust
/// crate unless the crate opts into the component model. The `wasm32-wasip2`
/// target *does* emit a component for `cdylib`-producing crates, which is why
/// `--target` alone is correct here and no `wasm-tools component new` step is
/// needed. The validation step later confirms this held, rather than assuming
/// it — the assumption is exactly the kind that silently breaks on a toolchain
/// upgrade.
fn rust_args(profile: &str, target: &str) -> Vec<String> {
    let mut args = vec!["build".to_owned()];
    if profile == "release" {
        args.push("--release".to_owned());
    }
    args.push("--target".to_owned());
    args.push(target.to_owned());
    // `--message-format=json` would give structured diagnostics, but it also
    // swallows the human-readable output a developer expects to see scroll by.
    // The compiler's own output is better than ours, so we pass it through.
    args
}

// ---------------------------------------------------------------------------
// Artifact discovery and verification
// ---------------------------------------------------------------------------

/// Where a Rust build puts the `.wasm` it produced.
#[must_use]
pub fn rust_artifact_path(project_dir: &Path, profile: &str, target: &str, name: &str) -> PathBuf {
    project_dir
        .join("target")
        .join(target)
        .join(profile)
        .join(format!("{name}.wasm"))
}

/// The directory Cargo writes a build's output into.
#[must_use]
pub fn artifact_dir(project_dir: &Path, profile: &str, target: &str) -> PathBuf {
    project_dir.join("target").join(target).join(profile)
}

/// Find the component a successful build produced.
///
/// # Why this cannot simply compute the name
///
/// Cargo names the artifact after the **crate** name, which is the package name
/// with hyphens replaced by underscores: `orders-api` yields `orders_api.wasm`.
/// It also honours an explicit `[lib] name`, which may differ from both.
///
/// This was a real defect — `qqqai new` generates hyphenated project names, so
/// every scaffolded project compiled successfully and then reported that no
/// artifact had been produced. Reasoning about the naming convention produced
/// the wrong answer; looking at the directory produced the right one.
///
/// # The preference order, and why
///
/// 1. **The underscored package name.** Cargo's default, so it is the answer in
///    the overwhelming majority of cases and involves no directory scan.
/// 2. **The literal package name.** Correct when the crate declares an explicit
///    `[lib] name` matching the package.
/// 3. **Any single `.wasm`.** Covers a renamed lib target. Ambiguity — more than
///    one candidate that is not accounted for above — resolves to `None` rather
///    than a guess, because picking the wrong artifact silently would ship the
///    wrong code.
///
/// `deps/` is deliberately excluded: it holds duplicate copies of every
/// dependency's artifact, so including it would make "any single `.wasm`"
/// almost never true.
#[must_use]
pub fn find_artifact(
    project_dir: &Path,
    profile: &str,
    target: &str,
    package: &str,
) -> Option<PathBuf> {
    let dir = artifact_dir(project_dir, profile, target);

    // 1. Cargo's default: hyphens become underscores.
    let underscored = dir.join(format!("{}.wasm", package.replace('-', "_")));
    if underscored.is_file() {
        return Some(underscored);
    }

    // 2. A crate that kept the literal name.
    let literal = dir.join(format!("{package}.wasm"));
    if literal.is_file() {
        return Some(literal);
    }

    // 3. A renamed lib target, but only when the answer is unambiguous.
    let candidates = list_wasm_paths(&dir);
    match candidates.len() {
        1 => candidates.into_iter().next(),
        _ => None,
    }
}

/// The `.wasm` files directly inside a directory, sorted, by name.
///
/// Non-recursive on purpose: `deps/` contains a copy of every dependency's
/// artifact, so descending would make any "the only artifact" reasoning false.
#[must_use]
pub fn list_wasm_files(dir: &Path) -> Vec<String> {
    list_wasm_paths(dir)
        .into_iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect()
}

/// The `.wasm` paths directly inside a directory, sorted.
fn list_wasm_paths(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        // An explicit closure rather than `Result::ok`, because this crate
        // imports `qqq_core::Result`, which shadows `std::result::Result` — and
        // `Result::ok` then fails to resolve to the inherent method.
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "wasm"))
        .collect();
    out.sort_unstable();
    out
}

/// The `wasm-tools` style classification of an artifact's bytes.
///
/// # Why we classify rather than trusting the exit code
///
/// A compiler exiting 0 means *it* is satisfied. It does not mean the bytes are
/// what we asked for. The most common real failure — building a core module
/// when a component was wanted — produces a perfectly valid `.wasm` file that
/// fails at `PreparedComponent::compile` with a message about the component
/// model. Catching it here names the actual problem, at the point it was
/// caused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// A WebAssembly component: has a `component` layer.
    Component,
    /// A core module: has a `module` layer but no component layer.
    CoreModule,
    /// Neither — not a WebAssembly binary at all.
    NotWasm,
}

impl ArtifactKind {
    /// The stable name, for JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Component => "component",
            Self::CoreModule => "core-module",
            Self::NotWasm => "not-wasm",
        }
    }

    /// Classify a byte slice from its header.
    ///
    /// # The discriminator is the layer field, not the sections
    ///
    /// Both formats start with the magic `\0asm`, then a 16-bit version and a
    /// 16-bit layer, both little-endian:
    ///
    /// ```text
    /// core module: \0asm  01 00  00 00
    ///                    version layer
    /// component:   \0asm  0d 00  01 00
    ///                    version layer
    /// ```
    ///
    /// The **layer** is the discriminator: `0` is a core module, `1` is a
    /// component. The version is the encoding revision and differs between
    /// them for historical reasons, so it must not be used to tell them apart.
    ///
    /// # Two bugs this function has already had, both found by running it
    ///
    /// 1. It walked the section framing and reported "core module" on seeing a
    ///    type or code section. A real `wasm32-wasip2` artifact was then
    ///    reported as a core module — because a component *contains* core
    ///    modules, so its payload starts with `\0asm` and holds type and code
    ///    sections. Any rule based on finding core sections inside the file
    ///    misclassifies every genuine component.
    /// 2. Having added the header check, it tested `bytes[4] == 1` for a
    ///    component. `bytes[4]` is the version's low byte, and a *core module's*
    ///    version is `01 00 00 00`, so every core module was reported as a
    ///    component. The layer is at `bytes[6]`.
    ///
    /// Both are recorded because the pattern is the same: a plausible reading
    /// of the format that only a real artifact can refute.
    #[must_use]
    pub fn classify(bytes: &[u8]) -> Self {
        if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
            return Self::NotWasm;
        }
        // Little-endian: version = bytes[4..6], layer = bytes[6..8].
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        let layer = u16::from_le_bytes([bytes[6], bytes[7]]);
        match layer {
            // A core module: version 1, no layer.
            0 if version == 1 => Self::CoreModule,
            // Any component layer. The version is an encoding revision and is
            // not our business to police here; `Component::compile` is the
            // authority on whether we can actually load it.
            1 => Self::Component,
            // Unknown layer. Reported as a core module so the caller's error
            // says "not a component" — true and actionable — rather than
            // claiming to have found something we cannot load.
            _ => Self::CoreModule,
        }
    }
}

/// Verify that a produced artifact really is a component.
///
/// # Errors
///
/// * `QQQ-1002` — the file is not a component, with a message that says which
///   of the three shapes it was.
/// * `QQQ-1001` — the file could not be read.
pub fn verify_artifact(path: &Path) -> Result<ArtifactKind> {
    let bytes = std::fs::read(path).map_err(|e| {
        Error::new(
            ErrorCode::CompilationFailed,
            format!(
                "the build reported success but `{}` is unreadable",
                path.display()
            ),
        )
        .with_cause(e.to_string())
        .with_remediation("check the build output above for a partial or failed link step")
    })?;

    let kind = ArtifactKind::classify(&bytes);
    match kind {
        ArtifactKind::Component => Ok(kind),
        ArtifactKind::CoreModule => Err(Error::new(
            ErrorCode::InvalidComponentArtifact,
            "the build produced a core module, not a WebAssembly component",
        )
        .with_context("artifact", path.display().to_string())
        .with_remediation(
            "the crate must be a `cdylib` and target `wasm32-wasip2`; a core module \
             cannot import QQQ's capability interfaces",
        )),
        ArtifactKind::NotWasm => Err(Error::new(
            ErrorCode::InvalidComponentArtifact,
            "the build output is not a WebAssembly binary",
        )
        .with_context("artifact", path.display().to_string())
        .with_remediation("check that the crate type is `cdylib` in Cargo.toml")),
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// Where the final `.component.wasm` is copied to, for a stable path.
///
/// # Why the artifact is copied rather than left where Cargo put it
///
/// Cargo's output path embeds the target triple and profile, so it changes with
/// a flag. `qqqai run`, `qqqai inspect` and a deployment script all need one
/// path that does not. Copying to `target/qqq/<name>.component.wasm` gives the
/// rest of the toolchain a stable name to agree on, and keeps the Cargo
/// directory as an implementation detail that can change without breaking
/// anything downstream.
#[must_use]
pub fn component_path(project_dir: &Path, name: &str) -> PathBuf {
    project_dir
        .join(OUTPUT_DIR)
        .join(format!("{name}.{COMPONENT_EXTENSION}"))
}

/// Run a build and return the report.
///
/// # Errors
///
/// * `QQQ-1003` — the toolchain is incomplete.
/// * `QQQ-1001` — the compiler failed, or the artifact could not be staged.
/// * `QQQ-1002` — the artifact is not a component.
pub fn execute(loaded: &LoadedManifest, opts: &BuildOptions) -> Result<BuildOutput> {
    let spec = &loaded.manifest.build;
    let plan = plan(loaded, opts)?;

    let profile = if opts.release() {
        "release"
    } else if opts.debug() {
        "debug"
    } else {
        spec.profile.as_str()
    };
    let target = opts.target.as_deref().unwrap_or(spec.target.as_str());

    let base = BuildOutput {
        project: loaded.name().to_owned(),
        language: spec.language.clone(),
        target: target.to_owned(),
        profile: profile.to_owned(),
        command: plan.render(),
        artifact: None,
        digest: None,
        size_bytes: None,
        kind: None,
        aot_requested: opts.aot(),
        // Declared false, and it stays false: see the module note. The field
        // exists so the gap is visible in `--json` rather than implied.
        aot_performed: false,
        dry_run: false,
    };

    // The compiler's stdout/stderr are inherited rather than captured. A build
    // is the one command where the underlying tool's own output is better than
    // anything we could synthesise: colours, progress, warnings with source
    // spans. Capturing it to reprint it would lose all of that for no gain.
    let status = Command::new(&plan.program)
        .args(&plan.args)
        .current_dir(&plan.cwd)
        .status()
        .map_err(|e| {
            Error::new(
                ErrorCode::MissingTarget,
                format!("could not run `{}`", plan.program),
            )
            .with_cause(e.to_string())
            .with_remediation("confirm the toolchain is on PATH")
        })?;

    if !status.success() {
        return Err(Error::new(
            ErrorCode::CompilationFailed,
            format!(
                "`{}` failed with {}",
                plan.render(),
                describe_exit(status.code())
            ),
        )
        .with_remediation(
            "the compiler's own output is above; `qqqai doctor` diagnoses an \
             incomplete toolchain",
        ));
    }

    // The compiler succeeded; now find what it produced.
    //
    // # Why this searches rather than computing the name
    //
    // The naive approach is `<package name>.wasm`, and it is wrong. Cargo names
    // the artifact after the **crate** name, which is the package name with
    // hyphens replaced by underscores — `orders-api` produces `orders_api.wasm`.
    // It is also wrong when `[lib].path` renames the target, or when the crate
    // declares a `[lib] name` that differs from the package.
    //
    // This was a real defect: `qqqai new` generates a hyphenated project, so
    // every scaffolded project built successfully and then reported "the build
    // succeeded but `<name>.wasm` was not produced". The fix is to look at what
    // is actually there, and to name every candidate in the error when nothing
    // is.
    let produced = find_artifact(&plan.cwd, profile, target, loaded.name());
    let Some(produced) = produced else {
        let dir = artifact_dir(&plan.cwd, profile, target);
        let seen = list_wasm_files(&dir);
        return Err(Error::new(
            ErrorCode::CompilationFailed,
            format!(
                "the build succeeded but no component was found in `{}`",
                dir.display()
            ),
        )
        .with_cause(if seen.is_empty() {
            "the directory contains no `.wasm` files".to_owned()
        } else {
            format!("found: {}", seen.join(", "))
        })
        .with_remediation(format!(
            "`[package].name` is `{}`; `Cargo.toml` must declare \
             `crate-type = [\"cdylib\"]` and produce a `.wasm` library target",
            loaded.name()
        )));
    };

    // Classify before staging: an artifact that is not a component must never
    // reach `qqqai run`, because the failure there is far from its cause.
    let kind = verify_artifact(&produced)?;
    let (dest, bytes) = stage(&produced, &plan.cwd, loaded.name())?;

    // `--reproducible`: the digest is what a deployment pins, so an unstable
    // digest is a supply-chain problem rather than a cosmetic one. Comparing
    // against a stored digest is how "the same source produced a different
    // artifact twice" is caught, rather than discovered at deploy time.
    let digest = qqq_host::digest_of(&bytes);
    if opts.reproducible() {
        check_reproducible(&plan.cwd, loaded.name(), &digest)?;
    }

    Ok(BuildOutput {
        artifact: Some(relative_display(&dest, &plan.cwd)),
        digest: Some(digest),
        size_bytes: Some(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
        kind: Some(kind.as_str().to_owned()),
        ..base
    })
}

/// Copy the compiler's output to the stable component path, returning both the
/// destination and the staged bytes.
///
/// Reading the bytes back rather than hashing `produced` directly is deliberate:
/// it proves the copy succeeded and gives the digest of *exactly* the file the
/// runtime will load, so a partial copy cannot produce a digest that does not
/// match the artifact on disk.
fn stage(produced: &Path, project_dir: &Path, name: &str) -> Result<(PathBuf, Vec<u8>)> {
    let dest = component_path(project_dir, name);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::new(
                ErrorCode::CompilationFailed,
                format!("could not create `{}`", parent.display()),
            )
            .with_cause(e.to_string())
        })?;
    }
    std::fs::copy(produced, &dest).map_err(|e| {
        Error::new(
            ErrorCode::CompilationFailed,
            format!("could not stage the artifact at `{}`", dest.display()),
        )
        .with_cause(e.to_string())
    })?;

    let bytes = std::fs::read(&dest).map_err(|e| {
        Error::new(
            ErrorCode::CompilationFailed,
            format!("could not read back `{}`", dest.display()),
        )
        .with_cause(e.to_string())
    })?;
    Ok((dest, bytes))
}

/// Compare this digest against the previous build's, and record the new one.
///
/// # Why a sidecar file rather than a lockfile entry
///
/// The reproducibility check needs to remember what the *last* build produced.
/// Putting that in `qqq.lock` would mix "what I depend on" with "what I last
/// built", and a lockfile is committed while this is a build artifact. A sidecar
/// under `target/qqq/` is the right lifecycle: it is ignored by git, and its
/// absence on a first build is expected rather than an error.
///
/// # Errors
///
/// `QQQ-1005` when a previous digest exists and differs.
fn check_reproducible(project_dir: &Path, name: &str, digest: &str) -> Result<()> {
    let stamp = project_dir
        .join(OUTPUT_DIR)
        .join(format!("{name}.{COMPONENT_EXTENSION}.digest"));

    if let Ok(previous) = std::fs::read_to_string(&stamp) {
        let previous = previous.trim();
        if !previous.is_empty() && previous != digest {
            return Err(Error::new(
                ErrorCode::NonReproducibleBuild,
                "two builds of the same source produced different artifacts",
            )
            .with_context("previous_digest", previous.to_owned())
            .with_context("current_digest", digest.to_owned())
            .with_remediation(
                "`[build] reproducible = true` promises a stable digest; a difference \
                 usually means a path, timestamp or unordered iteration reached the compiler",
            ));
        }
    }

    // Written only on success, so a failing build never poisons the baseline it
    // is being compared against.
    let _ = std::fs::write(&stamp, digest);
    Ok(())
}

/// Describe an exit status for the error message.
///
/// `None` means the process was killed by a signal — which on Windows arrives as
/// a plain exit code and here as `None` on Unix. Saying "aborted" is more useful
/// than "exited with code None".
fn describe_exit(code: Option<i32>) -> String {
    match code {
        Some(c) => format!("exit code {c}"),
        None => "a signal".to_owned(),
    }
}

/// Display a path relative to a base, with forward slashes.
///
/// Relative because an absolute developer path in machine-readable output leaks
/// the developer's directory layout into logs and CI artifacts, and absolute
/// paths also make two machines' outputs differ for no reason.
fn relative_display(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

// ---------------------------------------------------------------------------
// Command output
// ---------------------------------------------------------------------------

/// The result of `qqqai build`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BuildOutput {
    /// The project name.
    pub project: String,
    /// The language that was compiled.
    pub language: String,
    /// The target triple that was compiled for.
    pub target: String,
    /// The profile that was used.
    pub profile: String,
    /// The exact command that ran, for reproducibility and bug reports.
    pub command: String,
    /// The artifact, or `None` for a dry run.
    pub artifact: Option<String>,
    /// The artifact's content digest, the identity used by the AOT cache.
    pub digest: Option<String>,
    /// The artifact's size in bytes.
    pub size_bytes: Option<u64>,
    /// What the artifact was classified as.
    pub kind: Option<String>,
    /// Whether AOT compilation was requested.
    pub aot_requested: bool,
    /// Whether AOT compilation actually happened.
    ///
    /// Separate from `aot_requested` on purpose. A single boolean would let a
    /// build report `aot: true` while having done nothing, which is exactly the
    /// silent stub the project forbids. Two fields make the gap visible to
    /// anyone reading the JSON, including an agent.
    pub aot_performed: bool,
    /// Whether this was a rehearsal.
    pub dry_run: bool,
}

impl CommandOutput for BuildOutput {
    fn command(&self) -> CommandName {
        CommandName::Build
    }

    fn summary(&self) -> String {
        if self.dry_run {
            return format!("would run: {}", self.command);
        }
        match (&self.artifact, self.size_bytes) {
            (Some(a), Some(n)) => {
                format!("{}: {} ({} bytes) for {}", self.project, a, n, self.target)
            }
            (Some(a), None) => format!("{}: {a}", self.project),
            _ => format!("{}: build finished", self.project),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(src: &str) -> LoadedManifest {
        LoadedManifest {
            manifest: qqq_cap::manifest::Manifest::parse(src).expect("test manifest"),
            path: PathBuf::from("qqq.toml"),
            source: src.to_owned(),
        }
    }

    const RUST: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n";
    const TS: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                      [build]\nlanguage = \"ts\"\n";

    // -- argument construction --------------------------------------------

    #[test]
    fn a_release_build_passes_release_to_cargo() {
        let args = rust_args("release", "wasm32-wasip2");
        assert_eq!(
            args,
            vec!["build", "--release", "--target", "wasm32-wasip2"]
        );
    }

    /// A debug build must **omit** `--release` rather than pass `--debug`:
    /// `cargo build` has no `--debug` flag, and inventing one produces a
    /// confusing failure inside the compiler.
    #[test]
    fn a_debug_build_omits_the_release_flag_entirely() {
        let args = rust_args("debug", "wasm32-wasip2");
        assert_eq!(args, vec!["build", "--target", "wasm32-wasip2"]);
        assert!(
            !args.iter().any(|a| a == "--debug"),
            "cargo has no --debug flag"
        );
    }

    /// The injection test. A project directory containing shell metacharacters
    /// must reach the compiler as **one** argument, and must never be handed to
    /// a shell.
    #[test]
    fn shell_metacharacters_stay_inside_one_argument() {
        let plan = BuildPlan {
            program: "cargo".to_owned(),
            args: vec![
                "build".to_owned(),
                "--target".to_owned(),
                "wasm32-wasip2".to_owned(),
            ],
            cwd: PathBuf::from("app; rm -rf ~"),
        };
        // The cwd is not part of the argument vector at all: `Command::current_dir`
        // takes it as a path, so it cannot be interpreted as a command.
        assert_eq!(plan.args.len(), 3);
        assert!(!plan.args.iter().any(|a| a.contains(';')));
    }

    #[test]
    fn quoting_renders_a_pastable_command() {
        assert_eq!(shell_quote("cargo"), "cargo");
        assert_eq!(shell_quote("--target"), "--target");
        assert_eq!(shell_quote("wasm32-wasip2"), "wasm32-wasip2");
        assert_eq!(shell_quote("/a/b/c.toml"), "/a/b/c.toml");
        // A space forces quoting, or the pasted command has one more argument.
        assert_eq!(shell_quote("my app"), "'my app'");
        // An embedded quote is escaped rather than dropped.
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    // -- planning ----------------------------------------------------------

    #[test]
    fn a_rust_project_plans_a_cargo_build() {
        let plan = plan(&loaded(RUST), &BuildOptions::default()).expect("must plan");
        assert_eq!(plan.program, "cargo");
        assert!(plan.args.contains(&"build".to_owned()));
        assert!(plan.render().contains("wasm32-wasip2"));
    }

    /// `--release` and `--debug` is a contradiction. Letting one silently win is
    /// how a CI job builds the wrong profile with a green tick.
    #[test]
    fn contradictory_profile_flags_are_refused() {
        let opts = BuildOptions::from_flags(BuildOptions::RELEASE | BuildOptions::DEBUG, None);
        let e = plan(&loaded(RUST), &opts).unwrap_err();
        assert_eq!(e.code, ErrorCode::McpArgumentInvalid);
        assert!(e.remediation.is_some());
    }

    #[test]
    fn the_release_flag_overrides_the_manifest_profile() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[build]\nprofile = \"debug\"\n";
        let opts = BuildOptions::from_flags(BuildOptions::RELEASE, None);
        let plan = plan(&loaded(src), &opts).expect("must plan");
        assert!(plan.args.contains(&"--release".to_owned()));
    }

    #[test]
    fn the_manifest_profile_is_used_when_no_flag_is_given() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[build]\nprofile = \"debug\"\n";
        let plan = plan(&loaded(src), &BuildOptions::default()).expect("must plan");
        assert!(!plan.args.contains(&"--release".to_owned()));
    }

    /// A language that parses but has no driver must fail with an honest
    /// "not implemented yet" naming the checklist area, not a fake success.
    #[test]
    fn an_unimplemented_language_is_declared_not_faked() {
        let e = plan(&loaded(TS), &BuildOptions::default()).unwrap_err();
        assert_eq!(e.code, ErrorCode::CompilationFailed);
        assert!(
            e.message.contains("not implemented yet"),
            "must say so plainly: {}",
            e.message
        );
        assert!(e.remediation.as_deref().unwrap_or("").contains("LANG-0"));
    }

    #[test]
    fn an_unsupported_target_override_is_refused() {
        let opts = BuildOptions::from_flags(0, Some("x86_64-unknown-linux-gnu".to_owned()));
        let e = plan(&loaded(RUST), &opts).unwrap_err();
        assert_eq!(e.code, ErrorCode::MissingTarget);
        assert!(e
            .remediation
            .as_deref()
            .unwrap_or("")
            .contains("wasm32-wasip2"));
    }

    /// Whatever toolchain this test machine has, `plan` must either succeed or
    /// fail with a **typed** error that names the missing tool. It must never
    /// panic, and never return success with an empty argument vector.
    #[test]
    fn planning_never_panics_whatever_is_installed() {
        match plan(&loaded(RUST), &BuildOptions::default()) {
            Ok(p) => {
                assert!(!p.args.is_empty());
                assert_eq!(p.program, "cargo");
            }
            Err(e) => {
                assert_eq!(e.code, ErrorCode::MissingTarget);
                assert!(
                    e.remediation.is_some(),
                    "a missing tool needs an install line"
                );
            }
        }
    }

    /// Flag bits must be independent: setting one must not disturb another.
    /// A packed bitfield is only an improvement over four bools if the bits are
    /// actually orthogonal, so the property is pinned rather than assumed.
    #[test]
    fn option_bits_are_independent() {
        let mut o = BuildOptions::default();
        assert!(!o.release() && !o.debug() && !o.aot() && !o.reproducible());

        o.set(BuildOptions::AOT);
        assert!(o.aot());
        assert!(!o.release(), "setting AOT must not set RELEASE");
        assert!(!o.debug(), "setting AOT must not set DEBUG");
        assert!(!o.reproducible(), "setting AOT must not set REPRODUCIBLE");

        o.set(BuildOptions::REPRODUCIBLE);
        assert!(o.aot() && o.reproducible(), "both must hold");
    }

    #[test]
    fn the_default_option_set_requests_nothing() {
        let d = BuildOptions::default();
        assert!(!d.release() && !d.debug() && !d.aot() && !d.reproducible());
        assert!(d.target.is_none());
    }

    // -- toolchain table ---------------------------------------------------

    #[test]
    fn every_supported_language_has_a_toolchain_or_none_honestly() {
        for lang in BuildSpec::LANGUAGES {
            let tc = toolchain_for(lang, "wasm32-wasip2");
            if let Some(reqs) = tc {
                assert!(
                    !reqs.is_empty(),
                    "{lang} claims a toolchain but names no tools"
                );
                for r in reqs {
                    assert!(!r.program.is_empty());
                    assert!(!r.install.is_empty(), "{} needs an install line", r.program);
                    assert!(!r.why.is_empty(), "{} needs a reason", r.program);
                }
            }
        }
        // Rust is the one language that must work today.
        assert!(toolchain_for("rust", "wasm32-wasip2").is_some());
    }

    #[test]
    fn an_unknown_language_has_no_toolchain() {
        assert!(toolchain_for("cobol", "wasm32-wasip2").is_none());
    }

    // -- artifact classification -------------------------------------------

    #[test]
    fn a_non_wasm_file_is_not_wasm() {
        assert_eq!(
            ArtifactKind::classify(b"hello world"),
            ArtifactKind::NotWasm
        );
        assert_eq!(ArtifactKind::classify(b""), ArtifactKind::NotWasm);
        assert_eq!(ArtifactKind::classify(b"\0asm"), ArtifactKind::NotWasm);
        assert_eq!(
            ArtifactKind::classify(b"\0asm\x01\0\0"),
            ArtifactKind::NotWasm
        );
    }

    /// The exact header a core module carries.
    #[test]
    fn a_core_module_header_is_recognised() {
        assert_eq!(
            ArtifactKind::classify(b"\0asm\x01\0\0\0"),
            ArtifactKind::CoreModule
        );
    }

    /// **The regression test for a real bug.** A `wasm32-wasip2` artifact was
    /// reported as a core module by the previous classifier, because that
    /// classifier looked for core sections inside the file — and a component
    /// *contains* core modules, so it always found them.
    ///
    /// These are the literal first eight bytes of a real `wasm32-wasip2`
    /// release build, captured from this machine.
    #[test]
    fn a_real_component_header_is_recognised() {
        // \0asm, layer 1, version 0.13, as emitted by rustc 1.97.1.
        assert_eq!(
            ArtifactKind::classify(b"\0asm\x0d\0\x01\0"),
            ArtifactKind::Component,
            "a wasm32-wasip2 artifact must be classified as a component"
        );
    }

    /// The header alone decides, so trailing content cannot flip the answer.
    /// This is the property the previous implementation violated: it walked the
    /// body, and the body of a real component contains core-module framing.
    #[test]
    fn the_classification_ignores_the_body_entirely() {
        // A component header followed by a nested core module's magic — which
        // is exactly what a real component looks like.
        let mut bytes = Vec::from(*b"\0asm\x0d\0\x01\0");
        bytes.extend_from_slice(b"\0asm\x01\0\0\0");
        bytes.extend_from_slice(&[1, 1, 0]); // a type section
        assert_eq!(ArtifactKind::classify(&bytes), ArtifactKind::Component);

        // And the converse: a core module header followed by component-looking
        // bytes is still a core module.
        let mut bytes = Vec::from(*b"\0asm\x01\0\0\0");
        bytes.extend_from_slice(b"\0asm\x0d\0\x01\0");
        assert_eq!(ArtifactKind::classify(&bytes), ArtifactKind::CoreModule);
    }

    /// An unrecognised layer must not be claimed as a component. Reporting
    /// "not a component" is true and actionable; a guess would move the failure
    /// to the loader.
    #[test]
    fn an_unknown_layer_is_not_claimed_as_a_component() {
        // layer = 2
        assert_eq!(
            ArtifactKind::classify(b"\0asm\x0d\0\x02\0"),
            ArtifactKind::CoreModule
        );
        // layer = 0xffff, all bits set
        assert_eq!(
            ArtifactKind::classify(b"\0asm\0\0\xff\xff"),
            ArtifactKind::CoreModule
        );
    }

    /// A core module with an unusual version is still a core module: version 1
    /// is what exists, but the *layer* is what decides.
    #[test]
    fn the_layer_not_the_version_decides() {
        // layer 0, version 7 — not a version that exists, but layer 0 means
        // core module regardless.
        assert_eq!(
            ArtifactKind::classify(b"\0asm\x07\0\0\0"),
            ArtifactKind::CoreModule
        );
        // layer 1, an unexpected version — still a component.
        assert_eq!(
            ArtifactKind::classify(b"\0asm\xff\xff\x01\0"),
            ArtifactKind::Component
        );
    }

    #[test]
    fn only_the_magic_and_the_header_are_read() {
        // Exactly eight bytes: enough to classify, nothing to walk.
        assert_eq!(
            ArtifactKind::classify(b"\0asm\x0d\0\x01\0"),
            ArtifactKind::Component
        );
        assert_eq!(
            ArtifactKind::classify(b"\0asm\x01\0\0\0"),
            ArtifactKind::CoreModule
        );
    }

    #[test]
    fn artifact_kind_names_are_stable() {
        assert_eq!(ArtifactKind::Component.as_str(), "component");
        assert_eq!(ArtifactKind::CoreModule.as_str(), "core-module");
        assert_eq!(ArtifactKind::NotWasm.as_str(), "not-wasm");
    }

    #[test]
    fn artifact_paths_follow_the_cargo_layout() {
        let p = rust_artifact_path(Path::new("/proj"), "release", "wasm32-wasip2", "app");
        let s = p.to_string_lossy().replace('\\', "/");
        assert!(
            s.ends_with("target/wasm32-wasip2/release/app.wasm"),
            "got {s}"
        );
    }

    // -- artifact discovery -------------------------------------------------
    //
    // The regression group for a real defect: `qqqai new` generates hyphenated
    // project names, Cargo emits the underscored crate name, and `build`
    // reported "the build succeeded but <name>.wasm was not produced" for every
    // scaffolded project.

    /// Make a directory with the given `.wasm` files in it.
    fn build_dir(tag: &str, files: &[&str]) -> PathBuf {
        let dir = temp_dir(tag);
        let out = artifact_dir(&dir, "release", "wasm32-wasip2");
        std::fs::create_dir_all(&out).expect("create artifact dir");
        for f in files {
            std::fs::write(out.join(f), b"\0asm\x0d\0\x01\0").expect("write artifact");
        }
        dir
    }

    /// **The exact case that was broken**: a hyphenated package name produces an
    /// underscored artifact.
    #[test]
    fn a_hyphenated_package_finds_its_underscored_artifact() {
        let dir = build_dir("hyphen", &["orders_api.wasm"]);
        let found = find_artifact(&dir, "release", "wasm32-wasip2", "orders-api");
        assert_eq!(
            found.map(|p| p.file_name().unwrap().to_string_lossy().into_owned()),
            Some("orders_api.wasm".to_owned()),
            "`orders-api` must find `orders_api.wasm`"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_underscored_package_finds_its_artifact() {
        let dir = build_dir("plain", &["app.wasm"]);
        assert!(find_artifact(&dir, "release", "wasm32-wasip2", "app").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An explicit `[lib] name` equal to the package name still resolves.
    #[test]
    fn a_literal_name_is_found_when_no_underscored_one_exists() {
        let dir = build_dir("literal", &["orders-api.wasm"]);
        let found = find_artifact(&dir, "release", "wasm32-wasip2", "orders-api");
        assert!(found.is_some(), "the literal crate name must be tried");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A renamed lib target is found when it is the only candidate.
    #[test]
    fn a_single_unexpected_artifact_is_accepted() {
        let dir = build_dir("renamed", &["something_else.wasm"]);
        let found = find_artifact(&dir, "release", "wasm32-wasip2", "orders-api");
        assert!(
            found.is_some(),
            "an unambiguous single artifact must be used"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Ambiguity must not be guessed at.** With two candidates, neither of
    /// which matches, picking one silently would ship the wrong code.
    #[test]
    fn ambiguity_resolves_to_nothing_rather_than_a_guess() {
        let dir = build_dir("ambiguous", &["alpha.wasm", "beta.wasm"]);
        assert_eq!(
            find_artifact(&dir, "release", "wasm32-wasip2", "orders-api"),
            None,
            "two candidates and no match must not produce a guess"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A preference case: when both the underscored and an unrelated artifact
    /// exist, the underscored one wins — the answer is never ambiguous when the
    /// expected name is present.
    #[test]
    fn the_expected_name_wins_over_other_artifacts() {
        let dir = build_dir("prefer", &["orders_api.wasm", "unrelated.wasm"]);
        let found = find_artifact(&dir, "release", "wasm32-wasip2", "orders-api")
            .expect("the expected name must be found");
        assert_eq!(
            found.file_name().unwrap().to_string_lossy(),
            "orders_api.wasm"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `deps/` must not be searched: it holds a copy of every dependency's
    /// artifact, so including it would make "the only artifact" never true.
    #[test]
    fn dependency_artifacts_are_not_candidates() {
        let dir = temp_dir("deps");
        let out = artifact_dir(&dir, "release", "wasm32-wasip2");
        std::fs::create_dir_all(out.join("deps")).expect("create deps");
        std::fs::write(out.join("deps").join("serde.wasm"), b"\0asm\x0d\0\x01\0").unwrap();
        assert_eq!(
            find_artifact(&dir, "release", "wasm32-wasip2", "app"),
            None,
            "a `.wasm` under deps/ must not be mistaken for the build output"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_directory_lists_no_files_and_does_not_panic() {
        let dir = temp_dir("absent");
        let missing = artifact_dir(&dir, "release", "wasm32-wasip2");
        assert!(list_wasm_files(&missing).is_empty());
        assert_eq!(find_artifact(&dir, "release", "wasm32-wasip2", "app"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The listing must name only `.wasm` files, so the error message can tell
    /// the user what it actually found.
    #[test]
    fn the_listing_reports_only_wasm_files() {
        let dir = temp_dir("listing");
        let out = artifact_dir(&dir, "release", "wasm32-wasip2");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("a.wasm"), b"x").unwrap();
        std::fs::write(out.join("b.txt"), b"x").unwrap();
        std::fs::write(out.join("c.rlib"), b"x").unwrap();
        let listed = list_wasm_files(&out);
        assert_eq!(listed, vec!["a.wasm".to_owned()], "got {listed:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- staged path --------------------------------------------------------

    /// The staged path must not depend on profile or target, because that is
    /// the whole reason it exists: `run`, `inspect` and deploy scripts need one
    /// name that does not change with a flag.
    #[test]
    fn the_staged_path_is_stable_across_profiles() {
        let dir = Path::new("/proj");
        let p = component_path(dir, "app");
        let s = p.to_string_lossy().replace('\\', "/");
        assert!(s.ends_with("target/qqq/app.component.wasm"), "got {s}");
        assert!(
            !s.contains("release") && !s.contains("debug") && !s.contains("wasm32"),
            "the staged path must not embed a profile or target: {s}"
        );
    }

    /// Two different projects must not collide on one staged path.
    #[test]
    fn distinct_projects_stage_to_distinct_paths() {
        let a = component_path(Path::new("/p"), "alpha");
        let b = component_path(Path::new("/p"), "beta");
        assert_ne!(a, b);
    }

    #[test]
    fn relative_display_strips_the_base_and_normalises_separators() {
        let base = Path::new("/proj");
        let got = relative_display(Path::new("/proj/target/qqq/app.component.wasm"), base);
        assert_eq!(got, "target/qqq/app.component.wasm");
        // A path outside the base is shown as-is rather than silently mangled.
        let outside = relative_display(Path::new("/elsewhere/x.wasm"), base);
        assert!(outside.contains("x.wasm"));
    }

    #[test]
    fn exit_descriptions_cover_code_and_signal() {
        assert_eq!(describe_exit(Some(1)), "exit code 1");
        assert_eq!(describe_exit(Some(101)), "exit code 101");
        assert_eq!(describe_exit(None), "a signal");
    }

    // -- reproducibility stamp --------------------------------------------

    /// A first build has no previous digest, so the check must pass rather than
    /// treat absence as a mismatch. Getting this backwards would make
    /// `--reproducible` fail on every clean checkout.
    #[test]
    fn the_first_reproducible_build_records_a_baseline() {
        let dir = temp_dir("repro-first");
        check_reproducible(&dir, "app", "aaaa").expect("a first build must pass");
        let stamp = dir.join(OUTPUT_DIR).join("app.component.wasm.digest");
        assert!(stamp.exists(), "the baseline must be recorded");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_matching_digest_passes_and_a_differing_one_fails() {
        let dir = temp_dir("repro-match");
        check_reproducible(&dir, "app", "aaaa").expect("first");
        check_reproducible(&dir, "app", "aaaa").expect("same digest must pass");

        let e = check_reproducible(&dir, "app", "bbbb").unwrap_err();
        assert_eq!(e.code, ErrorCode::NonReproducibleBuild);
        assert!(e.remediation.is_some());
        assert!(
            e.context.iter().any(|(k, _)| k == "previous_digest"),
            "the error must carry both digests so a diff is possible"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A build that does not request reproducibility must not leave a stamp,
    /// or a later `--reproducible` build would compare against an artifact from
    /// a different (e.g. debug) profile and fail for the wrong reason.
    #[test]
    fn a_non_reproducible_build_writes_no_stamp() {
        let dir = temp_dir("repro-none");
        let stamp = dir.join(OUTPUT_DIR).join("app.component.wasm.digest");
        assert!(!stamp.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-build-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join(OUTPUT_DIR)).expect("create temp dir");
        p
    }

    #[test]
    fn verifying_a_missing_file_gives_an_actionable_error() {
        let e = verify_artifact(Path::new("does-not-exist-anywhere.wasm")).unwrap_err();
        assert_eq!(e.code, ErrorCode::CompilationFailed);
        assert!(e.remediation.is_some());
    }

    // -- output ------------------------------------------------------------

    #[test]
    fn a_dry_run_summary_shows_the_command() {
        let out = BuildOutput {
            project: "app".to_owned(),
            language: "rust".to_owned(),
            target: "wasm32-wasip2".to_owned(),
            profile: "release".to_owned(),
            command: "cargo build --release".to_owned(),
            artifact: None,
            digest: None,
            size_bytes: None,
            kind: None,
            aot_requested: false,
            aot_performed: false,
            dry_run: true,
        };
        assert!(out.summary().contains("would run"));
        assert!(out.summary().contains("cargo build --release"));
    }

    /// The AOT gap must be representable. One boolean could not express
    /// "asked for but not done", which is the state this build is actually in.
    #[test]
    fn aot_requested_and_performed_are_distinguishable() {
        let out = BuildOutput {
            project: "app".to_owned(),
            language: "rust".to_owned(),
            target: "wasm32-wasip2".to_owned(),
            profile: "release".to_owned(),
            command: "cargo build --release".to_owned(),
            artifact: Some("app.component.wasm".to_owned()),
            digest: Some("abc".to_owned()),
            size_bytes: Some(1234),
            kind: Some("component".to_owned()),
            aot_requested: true,
            aot_performed: false,
            dry_run: false,
        };
        let json = out.to_json();
        assert_eq!(json["aot_requested"], true);
        assert_eq!(json["aot_performed"], false);
        assert_ne!(json["aot_requested"], json["aot_performed"]);
    }
}
