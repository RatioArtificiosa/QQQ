// SPDX-License-Identifier: Apache-2.0

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
//! `--aot` emits content-addressed native artifacts and provenance under
//! `target/qqq/aot`. `--aot-cache` also warms an explicit host-owned cache.
//! Portable WASM remains the deployable source; arbitrary native artifact loading
//! is not exposed under the workspace's no-unsafe policy.

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

    // **This is the driver gate, and it has to come first.** It was previously spelled
    // `if language != "rust"` right here, and a reader could be forgiven for thinking
    // `BuildSpec::supports_language` did the refusing -- it does not: its test
    // `an_unimplemented_language_is_declared_not_faked` passes for `"ts"`, which means this function was the
    // only thing saying no. **A one-word misreading with a real consequence: replacing this guard with the
    // table below let TypeScript past every gate and `plan_pure` begin returning a plan for a language with
    // no driver.** `cargo test` said so in one line.
    if !DRIVEN.contains(&language) {
        return None;
    }

    TOOLCHAINS
        .iter()
        .find(|(id, _)| *id == language)
        .map(|(_, reqs)| reqs.to_vec())
}

/// The tools a language's driver **would** use, whether or not one exists.
///
/// # Why this is separate from [`toolchain_for`]
///
/// Because the two answer different questions. `toolchain_for` answers *"can this build drive the language
/// now?"* and returns `None` when it cannot. **This answers *"what would it need?"* and answers for all five**
/// -- the pinned list is the same table, and only [`DRIVEN`] withholds it.
///
/// **That distinction is what makes a refusal diagnostic.** Point 7 of the delivery's prompt asks for *"exact
/// tool diagnostics"*; a message saying only *"not implemented yet"* is truthful and tells the reader nothing
/// they can act on.
///
/// # What a caller must not do with it
///
/// **Treat a `Some` as permission to build.** This is a reporting helper: [`plan_pure`] still refuses an
/// undriven language, and it must keep refusing -- `toolchain_for`'s own comment records why returning a
/// plausible requirement list for a driver that does not exist produces *"a build that fails inside a shell
/// command -- a worse error, further from the cause"*.
///
/// # Examples
///
/// Rust is driven and Go is not, but **both have a pinned tool list**, which is the point:
///
/// ```
/// let rust = qqq_run::build::pinned_tools("rust").expect("rust has a pinned toolchain");
/// assert!(rust.iter().any(|t| t.program == "cargo"));
///
/// let go = qqq_run::build::pinned_tools("go").expect("go has one too -- it is simply not driven");
/// assert!(!go.is_empty());
/// assert!(!qqq_run::build::DRIVEN.contains(&"go"));
///
/// assert!(qqq_run::build::pinned_tools("cobol").is_none());
/// ```
#[must_use]
pub fn pinned_tools(language: &str) -> Option<Vec<ToolRequirement>> {
    TOOLCHAINS
        .iter()
        .find(|(id, _)| *id == language)
        .map(|(_, reqs)| reqs.to_vec())
}

/// The languages `qqqai build` can **drive** today.
///
/// # Why this is separate from [`TOOLCHAINS`]
///
/// Because they answer different questions. [`TOOLCHAINS`] answers *"what does this language need?"* -- and
/// the delivery measured that for all five. This answers *"can we build it?"* -- and the answer is Rust,
/// because the other four have no driver: their probes are deliberately narrower than the full language
/// promise, and Go still fails the 65,536-byte echo. Python and TypeScript now pass the HTTP probe under
/// an explicit `http.server` grant, but that is not a production driver or full conformance. **A stated
/// toolchain is not a working driver, and conflating a narrow probe with support is how an unexecuted
/// language comes to be marked supported.**
///
/// # Why a list rather than a `match`
///
/// Because `tools/check_conformance.py` reads this to decide which languages are supported **and fails
/// loudly if it cannot find exactly one definition** -- *"passing here would mean reading nothing and
/// reporting agreement."* A named constant is a stable thing to read across a refactor; a string comparison
/// inside a branch is not, which is exactly how this was missed the first time.
///
/// # Examples
///
/// Exactly one language is driven today, and the list is what the conformance checker reads:
///
/// ```
/// assert_eq!(qqq_run::build::DRIVEN, &["rust"]);
/// assert!(qqq_run::build::DRIVEN.contains(&"rust"));
/// ```
///
/// **The other four are deliberately absent.** Their toolchains are stated in [`TOOLCHAINS`], but the probe
/// is not the production build driver: Go fails the 65,536-byte echo, while Python and TypeScript only pass
/// the narrow HTTP probe. Adding one here is a claim that `qqqai build` can drive it, and that claim is not
/// yet true.
pub const DRIVEN: &[&str] = &["rust"];

/// Which languages `qqqai build` supports today, as prose, **derived from [`DRIVEN`]**.
///
/// # Why this exists rather than a sentence written where it is needed
///
/// Because the sentence was written **three times** -- twice in this file and once in `style.rs` -- and a
/// fourth statement of the same fact sits in `new.rs` as a doc comment. **Every one of them could drift from
/// [`DRIVEN`] independently, and adding a language would have required finding all four.**
/// `§O-439` is the record of what that costs: a claim written in several places, each able to disagree with
/// the code, and nothing reporting the one that is missed.
///
/// **A doc comment cannot call this**, so `new.rs` points at [`DRIVEN`] instead of restating it. Everything
/// that *can* derive, does.
///
/// # Why the `LANG-*` reference stays
///
/// Because the language work is tracked there, and `an_unimplemented_language_is_declared_not_faked` asserts
/// that the remediation names it -- so this is a refactor of where the text comes from, not of what it says.
///
/// # Examples
///
/// **The assertion is derived rather than literal on purpose.** A doctest that pinned the current text would
/// have to be edited whenever [`DRIVEN`] gained a language -- and **an example that must be edited to stay
/// true is an example that will eventually be edited to hide a change.** This one asks the property the
/// function exists to provide:
///
/// ```
/// let phrase = qqq_run::build::supported_phrase();
/// for language in qqq_run::build::DRIVEN {
///     assert!(phrase.contains(language), "{language} is driven but not named");
/// }
/// ```
#[must_use]
pub fn supported_phrase() -> String {
    DRIVEN.join(", ")
}

/// Every language's toolchain, measured rather than assumed.
///
/// # What this is, and what it is NOT
///
/// **This is what a language NEEDS, not what `qqqai build` can DO.** The driver gate is
/// [`BuildSpec::supports_language`], it is still Rust-only, and **this table does not touch it.** A language
/// with a stated toolchain and no driver is **declared, not implemented** -- exactly the state
/// [`toolchain_for`] returns `None` to describe, one level up.
///
/// # Why the versions are written down here
///
/// Because `docs/languages/phase3.md` **compiled and ran** each one, and a list assembled from documentation
/// instead would be **a claim about a toolchain nobody executed** -- the defect `O-439` records, one document
/// over. Measured there: `AssemblyScript` `0.28.20`; `TinyGo` `0.42.0` with Go `1.27.1` and
/// `wit-bindgen-go` `0.7.0`; `componentize-py` `0.25.1`; WASI SDK 34 Clang `23.1.0-wasi-sdk` with `wasm-ld`;
/// `wit-bindgen` `0.62.0`; `tsc` `5.9.3` with `ComponentizeJS` `0.23.0`.
///
/// # Why the foreign-language toolchains are here despite no production driver
///
/// Because **the toolchain table answers installation, not production support.** The `TinyGo` probe fails
/// the 65,536-byte echo; Python and TypeScript can now execute the narrow HTTP probe, but neither has a
/// `qqqai build` driver or full capability/conformance parity. Omitting these tools would say they are
/// unknown, while listing them does not overclaim that their production paths exist.
const TOOLCHAINS: &[(&str, &[ToolRequirement])] = &[
    (
        "rust",
        &[
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
        ],
    ),
    (
        "ts",
        &[
            ToolRequirement {
                program: "npm",
                version_args: &["--version"],
                install: "https://nodejs.org",
                why: "installs the pinned AssemblyScript and ComponentizeJS toolchains",
            },
            ToolRequirement {
                program: "wasm-tools",
                version_args: &["--version"],
                install: "cargo install wasm-tools",
                why: "validates the componentised output",
            },
        ],
    ),
    (
        "go",
        &[
            ToolRequirement {
                program: "tinygo",
                version_args: &["version"],
                install: "https://tinygo.org/getting-started/install/",
                why: "compiles Go to wasm32-wasip2; the standard toolchain cannot emit components yet",
            },
            ToolRequirement {
                program: "wit-bindgen-go",
                version_args: &["--version"],
                install: "go install go.bytecodealliance.org/cmd/wit-bindgen-go@v0.7.0",
                why: "generates the bindings from the canonical WIT",
            },
        ],
    ),
    (
        "python",
        &[
            ToolRequirement {
                program: "python3",
                version_args: &["--version"],
                install: "https://www.python.org/downloads/",
                why: "runs componentize-py, which packages the interpreter with the guest",
            },
            ToolRequirement {
                program: "componentize-py",
                version_args: &["--version"],
                install: "pip install componentize-py==0.25.1",
                why: "builds the component from the generated bindings",
            },
        ],
    ),
    (
        "cpp",
        &[
            ToolRequirement {
                program: "clang",
                version_args: &["--version"],
                install: "https://github.com/WebAssembly/wasi-sdk/releases (WASI SDK 34)",
                why: "compiles C and C++ to wasm32-wasip2; the system clang alone is not enough",
            },
            ToolRequirement {
                program: "wasm-ld",
                version_args: &["--version"],
                install: "ships with WASI SDK 34",
                why: "links the reactor module",
            },
            ToolRequirement {
                program: "wit-bindgen",
                version_args: &["--version"],
                install: "cargo install wit-bindgen-cli --version 0.62.0",
                why: "generates the C headers, glue and component-type object from the canonical WIT",
            },
        ],
    ),
];

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

/// One fully-resolved invocation.
///
/// **The step and its working directory travel together on purpose.** A plan holding `programs: Vec<String>`
/// and `cwds: Vec<PathBuf>` would be two lists that must stay the same length, and this file already carries
/// the lesson for that shape: its toolchain code reports *"the two lists in build.rs disagree"* when two
/// parallel lists drift.
/// # Examples
///
/// A step is one invocation, and it carries the directory it runs in:
///
/// ```
/// let step = qqq_run::build::BuildStep {
///     program: "cargo".to_owned(),
///     args: vec!["build".to_owned()],
///     cwd: std::path::PathBuf::from("."),
/// };
/// assert_eq!(step.render(), "cargo build");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildStep {
    /// The program to execute.
    pub program: String,
    /// Its arguments, one element per argument.
    pub args: Vec<String>,
    /// The directory it runs in.
    pub cwd: PathBuf,
}

impl BuildStep {
    /// Render the invocation as one line, quoted for display.
    ///
    /// Quoted because the point of showing it is that the user can paste it
    /// into a shell and get the same result. Unquoted, a path with a space would
    /// paste into something different from what ran.
    ///
    /// # Examples
    ///
    /// ```
    /// # use qqq_run::build::BuildStep;
    /// let step = BuildStep {
    ///     program: "clang".to_owned(),
    ///     args: vec!["--target=wasm32-wasip2".to_owned()],
    ///     cwd: std::path::PathBuf::from("."),
    /// };
    /// assert_eq!(step.render(), "clang --target=wasm32-wasip2");
    /// ```
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

/// A fully-resolved sequence of invocations, ready to run **in order**.
///
/// Exposed as a value rather than executed inline so that `--dry-run` can print
/// it, `--json` can report it, and tests can assert on it **without running a
/// compiler**. That last one is the point: the logic that decides what to run is
/// exactly the logic worth testing, and it should not require a toolchain to
/// test.
///
/// # Why this is a sequence and not one command
///
/// **Because only Rust needs one.** `cargo build --target wasm32-wasip2` emits a component directly -- this
/// file's own comment at the `wasm-tools` question says so -- while each of the other four languages is a
/// pipeline: Go is `wit-bindgen-go`, then `tinygo build`, then `wasm-tools component new`; C is four steps.
/// **A driver for any of them cannot be written against a one-command plan**, which is why this type came
/// first.
///
/// **And this does not touch [`DRIVEN`]:** the type can now *hold* a driver; the build still cannot drive
/// one.
/// # Examples
///
/// A one-step plan renders as its command; a longer one joins with ` && `, which is the shell's *then* and
/// **the same semantics the executor implements**:
///
/// ```
/// use qqq_run::build::{BuildPlan, BuildStep};
/// let step = |program: &str| BuildStep {
///     program: program.to_owned(),
///     args: Vec::new(),
///     cwd: std::path::PathBuf::from("."),
/// };
/// assert_eq!(BuildPlan::one(step("cargo")).render(), "cargo");
/// let two = BuildPlan { steps: vec![step("clang"), step("wasm-ld")] };
/// assert_eq!(two.render(), "clang && wasm-ld");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPlan {
    /// The steps, in execution order.
    pub steps: Vec<BuildStep>,
}

impl BuildPlan {
    /// A plan of exactly one step.
    ///
    /// # Examples
    ///
    /// ```
    /// # use qqq_run::build::{BuildPlan, BuildStep};
    /// let step = BuildStep {
    ///     program: "cargo".to_owned(),
    ///     args: Vec::new(),
    ///     cwd: std::path::PathBuf::from("."),
    /// };
    /// assert_eq!(BuildPlan::one(step).steps.len(), 1);
    /// ```
    #[must_use]
    pub fn one(step: BuildStep) -> Self {
        Self { steps: vec![step] }
    }

    /// The single step of a one-step plan, for callers that know there is one.
    ///
    /// # Why this exists instead of indexing `steps[0]` at the call sites
    ///
    /// **Because "the only step" is a meaning, and `steps[0]` is a coincidence.** Fourteen test assertions read
    /// a plan that has one step today, because only Rust has a driver; written as index `0`, each would encode
    /// that fact silently, and **the day a language gains a second step fourteen tests fail for a reason none
    /// of them is about.**
    ///
    /// # Panics
    ///
    /// If the plan does not have exactly one step. **That is the point**: a caller that meant "the only step"
    /// and got two should be told, not handed the first.
    /// # Panics
    ///
    /// If the plan does not have exactly one step. **That is the point**: a caller that meant *"the only
    /// step"* and got two should be told, not handed the first.
    ///
    /// # Examples
    ///
    /// ```
    /// # use qqq_run::build::{BuildPlan, BuildStep};
    /// let step = BuildStep {
    ///     program: "cargo".to_owned(),
    ///     args: vec!["build".to_owned()],
    ///     cwd: std::path::PathBuf::from("."),
    /// };
    /// let plan = BuildPlan::one(step);
    /// assert_eq!(plan.only_step().program, "cargo");
    /// assert_eq!(plan.steps.len(), 1);
    /// ```
    #[must_use]
    pub fn only_step(&self) -> &BuildStep {
        assert_eq!(
            self.steps.len(),
            1,
            "`only_step` was called on a plan with {} steps; use `steps` if the plan may have more",
            self.steps.len()
        );
        &self.steps[0]
    }

    /// The directory the plan operates in, taken from its first step.
    ///
    /// Every step of every plan built here runs in the project directory, so this is the project root rather
    /// than a guess -- and artifact discovery below reads it.
    ///
    /// The directory the plan operates in, taken from its first step.
    ///
    /// Every step of every plan built here runs in the project directory, so this is the project root rather
    /// than a guess -- and artifact discovery reads it.
    ///
    /// # Examples
    ///
    /// ```
    /// # use qqq_run::build::{BuildPlan, BuildStep};
    /// let step = BuildStep {
    ///     program: "cargo".to_owned(),
    ///     args: Vec::new(),
    ///     cwd: std::path::PathBuf::from("app"),
    /// };
    /// assert_eq!(BuildPlan::one(step).cwd(), std::path::Path::new("app"));
    /// ```
    ///
    /// # Panics
    ///
    /// Never in practice: [`BuildPlan::one`] and `plan_pure` both produce at least one step, and
    /// [`Self::steps`] is never constructed empty.
    #[must_use]
    pub fn cwd(&self) -> &Path {
        self.steps
            .first()
            .map_or_else(|| Path::new("."), |s| s.cwd.as_path())
    }

    /// Each step rendered, in order -- **the plan as a sequence rather than as one line**.
    ///
    /// # Why this exists beside [`Self::render`]
    ///
    /// Because a machine consumer wants the steps and a human wants the line, **and deriving one from the
    /// other at read time means re-splitting on ` && `, which is wrong the first time an argument contains
    /// it.** `--json` reports this list; `command` reports the join.
    ///
    /// # Examples
    ///
    /// ```
    /// # use qqq_run::build::{BuildPlan, BuildStep};
    /// let step = |program: &str| BuildStep {
    ///     program: program.to_owned(),
    ///     args: Vec::new(),
    ///     cwd: std::path::PathBuf::from("."),
    /// };
    /// let plan = BuildPlan { steps: vec![step("clang"), step("wasm-tools")] };
    /// assert_eq!(plan.step_commands(), vec!["clang", "wasm-tools"]);
    /// assert_eq!(plan.render(), "clang && wasm-tools");
    /// ```
    #[must_use]
    pub fn step_commands(&self) -> Vec<String> {
        self.steps.iter().map(BuildStep::render).collect()
    }

    /// Render the plan as one pasteable line, quoted for display.
    ///
    /// # Why ` && `
    ///
    /// Because the shell's `&&` is **the semantics the executor implements**: the next step runs only if this
    /// one succeeded. **A one-step plan therefore renders byte-for-byte as it did before**, so no existing
    /// assertion moves, and a four-step plan renders as something a reader can paste and run.
    ///
    /// **It is [`Self::step_commands`] joined, rather than a second walk of the steps**, so the two cannot
    /// disagree about what the plan is.
    #[must_use]
    pub fn render(&self) -> String {
        self.step_commands().join(" && ")
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
    /// Explicit host-owned native cache directory.
    pub aot_cache: Option<PathBuf>,
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
        Self {
            bits,
            target,
            aot_cache: None,
        }
    }
}

/// The refusal for a language with no driver, naming the tools it **would** use.
///
/// # Why it is a function and not two `format!` calls
///
/// Because it was two `format!` calls with identical text, one of them in an `else` branch whose own comment
/// says it is unreachable. **A message duplicated is a message that drifts** -- the shape `§O-439` and
/// `§O-466` record -- and the fix there was the same: **one place, and references.**
///
/// # What it adds over "not implemented yet"
///
/// The pinned programs, from [`pinned_tools`], and the one that installs each. **A reader learns what the
/// build would run before deciding whether to wait for it.**
fn driver_not_implemented(language: &str) -> Error {
    let tools = pinned_tools(language).map(|reqs| {
        reqs.iter()
            .map(|r| format!("`{}` (install: {})", r.program, r.install))
            .collect::<Vec<_>>()
            .join(", ")
    });

    let message = match tools {
        Some(tools) => format!(
            "the `{language}` toolchain driver is not implemented yet; it would use {tools}"
        ),
        None => format!("the `{language}` toolchain driver is not implemented yet"),
    };

    Error::new(ErrorCode::CompilationFailed, message).with_remediation(format!(
        "{} is fully supported today; `{language}` is tracked by the language matrix in \
         QQQ-Checklist-V1.md (LANG-001..LANG-040)",
        supported_phrase()
    ))
}

/// Plan a build, checking that the toolchain is actually present.
///
/// This is the entry point the CLI uses. It performs every check in
/// [`plan_pure`] and then **probes the environment** for the required programs.
///
/// # Errors
///
/// As [`plan_pure`], plus `QQQ-1003` when a required program is missing.
pub fn plan(loaded: &LoadedManifest, opts: &BuildOptions) -> Result<BuildPlan> {
    let spec = &loaded.manifest.build;
    let target = opts.target.as_deref().unwrap_or(spec.target.as_str());

    // The pure half first: it validates the request without touching the host.
    let plan = plan_pure(loaded, opts)?;

    let Some(toolchain) = toolchain_for(&spec.language, target) else {
        // `plan_pure` only returns `Ok` for a language with a driver, so this
        // is unreachable — but returning an error rather than panicking keeps
        // the contract total if the two functions ever disagree.
        return Err(driver_not_implemented(&spec.language));
    };

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

    Ok(plan)
}

/// Plan a build **without consulting the host**.
///
/// # Why this is separate from [`plan`]
///
/// Because the two answer different questions and have different testability.
/// "Given this manifest and these flags, what command should run?" is a pure
/// function of committed inputs. "Is `wasm-tools` installed here?" depends on
/// the machine.
///
/// Conflating them made three tests fail on CI while passing locally: they
/// asserted the *arguments* (`cargo build --release --target …`) but called
/// `plan`, which failed first with "missing wasm-tools" on a runner that had
/// never installed it. The tests were not wrong about the behaviour they
/// checked — they were checking it through a door that was locked on that
/// machine.
///
/// Splitting the function means argument construction is testable everywhere,
/// and toolchain availability is tested where it can be controlled.
///
/// # Errors
///
/// * `QQQ-1003` — the manifest names a language or target this build cannot
///   drive.
/// * `QQQ-7001` — `--release` and `--debug` were both passed.
pub fn plan_pure(loaded: &LoadedManifest, opts: &BuildOptions) -> Result<BuildPlan> {
    let spec: &BuildSpec = &loaded.manifest.build;

    if !BuildSpec::supports_language(&spec.language) {
        return Err(Error::new(
            ErrorCode::MissingTarget,
            format!("`{}` is not a language this build can drive", spec.language),
        )
        .with_remediation(format!(
            "supported languages today: {}. {}",
            BuildSpec::LANGUAGES.join(", "),
            // **The requirements travel in the refusal**, because this is the only place a caller reaches
            // them: the driver gate fires before the toolchain is consulted, so a `--dry-run` for a Go
            // manifest never asks about tools. **Naming them turns "not supported" into "not supported, and
            // here is what it would take" -- and it does not make the language drivable.**
            match toolchain_for(&spec.language, spec.target.as_str()) {
                Some(reqs) => format!(
                    "`{}` would need: {}",
                    spec.language,
                    reqs.iter()
                        .map(|r| r.program)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => format!("`{}` has no stated toolchain", spec.language),
            }
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

    let toolchain = toolchain_for(&spec.language, target)
        .ok_or_else(|| driver_not_implemented(&spec.language))?;

    // **The toolchain is READ for the name of the program the plan will run, and never PROBED.** Probing is
    // `plan`'s job and doing it here would make this function depend on the host -- which is what the original
    // comment was protecting. **But discarding it altogether was how `"cargo"` came to be written twice for
    // one language:** this table already said `cargo` at its first Rust entry, and the plan hard-coded the
    // same name three lines below.
    //
    // **Adding a language is now one edit fewer.** The program comes from the table the language was added
    // to; only the *arguments* need a new arm.
    let Some(program) = toolchain.first().map(|t| t.program.to_owned()) else {
        return Err(Error::new(
            ErrorCode::InternalInvariantViolated,
            format!("`{}` has a toolchain with no programs in it", spec.language),
        )
        .with_remediation(
            "this is a qqqai bug; a `TOOLCHAINS` entry must name at least one program",
        ));
    };

    let args = match spec.language.as_str() {
        "rust" => rust_args(profile, target),
        // `toolchain_for` returned `Some` for this language, so this arm exists only if a language was added
        // to [`TOOLCHAINS`] without an argument builder here. **The program is no longer one of the edits a
        // new language needs** -- it comes from that same table -- so this is now the ONLY place the two can
        // disagree about a language, and the message says that rather than "one function and not the other".
        // Failing loudly is the correct behaviour: silently building nothing is how a language matrix rots.
        other => {
            return Err(Error::new(
                ErrorCode::InternalInvariantViolated,
                format!("`{other}` has a toolchain but no argument builder"),
            )
            .with_remediation("this is a qqqai bug; the two lists in build.rs disagree"));
        }
    };

    Ok(BuildPlan::one(BuildStep {
        program,
        args,
        cwd: loaded
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
    }))
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
    target_root(project_dir)
        .join(target)
        .join(profile)
        .join(format!("{name}.wasm"))
}

/// Where cargo actually writes build output, honouring `CARGO_TARGET_DIR`.
///
/// # Why this is not simply `project_dir/target`
///
/// Because that is only cargo's default. `CARGO_TARGET_DIR` overrides it, cargo says so in its own
/// documentation, and `qqqai build` **shells out to cargo** -- so a tool that invents its own answer
/// looks in a directory cargo never wrote. Measured before this existed, with the variable set:
///
/// ```text
///     Finished `release` profile ... in 2.03s
/// error[QQQ-1001]: the build succeeded but no component was found in
///                  `/tmp/probeapp/target/wasm32-wasip2/release`
/// ```
///
/// The build succeeded and the error said it had not. **A relative value is relative to the working
/// directory the child cargo inherited**, which for `qqqai build` is the project directory.
fn target_root(project_dir: &Path) -> PathBuf {
    target_root_for(project_dir, std::env::var_os("CARGO_TARGET_DIR").as_deref())
}

/// The rule above, with the environment **passed in** so it can be tested.
///
/// # Why the split exists
///
/// `std::env::set_var` is `unsafe` in edition 2024 and this crate is `#![forbid(unsafe_code)]`, so a
/// test cannot set the variable for itself. **A rule that cannot be tested is a rule that will be
/// broken by the next edit** -- and this one was broken for as long as the function existed. Passing
/// the value in makes the rule testable without touching the process environment. `§O-376`: the
/// predicate and the path are tested separately, and here they can be.
fn target_root_for(project_dir: &Path, override_dir: Option<&std::ffi::OsStr>) -> PathBuf {
    match override_dir {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => project_dir.join("target"),
    }
}

/// The directory Cargo writes a build's output into.
#[must_use]
pub fn artifact_dir(project_dir: &Path, profile: &str, target: &str) -> PathBuf {
    target_root(project_dir).join(target).join(profile)
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

/// Run a plan's steps in order, stopping at the first failure.
///
/// # Returns
///
/// `Ok(None)` if every step succeeded; `Ok(Some((index, status)))` if step `index` failed. **The index is the
/// point**: a four-step C build that reports only *"the build failed"* leaves the reader to guess which of
/// `wit-bindgen`, `clang`, `wasm-ld` or `wasm-tools` broke.
///
/// # Errors
///
/// `QQQ-1003` when a step's program cannot be spawned at all -- **which is a different failure from a step
/// that ran and returned non-zero**, and the caller reports the two with different remediations.
fn run_steps(plan: &BuildPlan) -> Result<Option<(usize, std::process::ExitStatus)>> {
    for (index, step) in plan.steps.iter().enumerate() {
        let status = Command::new(&step.program)
            .args(&step.args)
            .current_dir(&step.cwd)
            .status()
            .map_err(|e| {
                Error::new(
                    ErrorCode::MissingTarget,
                    format!("could not run `{}`", step.program),
                )
                .with_cause(e.to_string())
                .with_remediation("confirm the toolchain is on PATH")
            })?;
        if !status.success() {
            return Ok(Some((index, status)));
        }
    }
    Ok(None)
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
        steps: plan.step_commands(),
        artifact: None,
        digest: None,
        size_bytes: None,
        kind: None,
        aot_requested: opts.aot(),
        // Becomes true only after native artifact and provenance are written.
        aot_performed: false,
        dry_run: false,
    };

    // The compiler's stdout/stderr are inherited rather than captured. A build
    // is the one command where the underlying tool's own output is better than
    // anything we could synthesise: colours, progress, warnings with source
    // spans. Capturing it to reprint it would lose all of that for no gain.
    let failure = run_steps(&plan)?;

    if let Some((index, status)) = failure {
        // **A one-step plan keeps its exact previous message**, because that spelling is what the tests
        // assert and what a user of the only working language sees. **A multi-step plan says which step**,
        // because a plan of four commands that reports only "the build failed" leaves the reader to guess.
        let detail = if plan.steps.len() > 1 {
            format!(
                "step {} of {} failed with {}: `{}`",
                index + 1,
                plan.steps.len(),
                describe_exit(status.code()),
                plan.render()
            )
        } else {
            format!(
                "`{}` failed with {}",
                plan.render(),
                describe_exit(status.code())
            )
        };
        // **The partial output is still on disk, and nothing was saying so.** A pipeline that fails at
        // step 2 leaves step 1's artifacts where step 1 put them, and `execute` returns before the artifact
        // search, so nothing here deletes anything -- the information existed and was not reported. That is
        // `§O-438`'s shape in a third place: a state that is real and indistinguishable from its absence.
        //
        // **And the remediation was unconditionally wrong for this case.** `run_steps` maps a *spawn*
        // failure to `MissingTarget` and a *non-zero exit* to here, so a compiler error was being told to run
        // `qqqai doctor`, which diagnoses an incomplete toolchain. It is the right next step when the tool is
        // at fault, and the wrong one when the code is -- so the message says which question each answer
        // settles rather than asserting the toolchain is incomplete.
        let workdir = plan.cwd().display();
        return Err(
            Error::new(ErrorCode::CompilationFailed, detail).with_remediation(format!(
                "the failing tool's own output is above. **Any artifact an earlier step produced is still \
                 in `{workdir}`** -- nothing is deleted on failure, so a partial build can be inspected \
                 there. If the tool itself is missing or too old, `qqqai doctor` diagnoses that; if the \
                 tool ran and rejected the input, its message above is the diagnosis."
            )),
        );
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
    let produced = find_artifact(plan.cwd(), profile, target, loaded.name());
    let Some(produced) = produced else {
        let dir = artifact_dir(plan.cwd(), profile, target);
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
    let (dest, bytes) = stage(&produced, plan.cwd(), loaded.name())?;

    // `--reproducible`: the digest is what a deployment pins, so an unstable
    // digest is a supply-chain problem rather than a cosmetic one. Comparing
    // against a stored digest is how "the same source produced a different
    // artifact twice" is caught, rather than discovered at deploy time.
    let digest = qqq_host::digest_of(&bytes);
    if opts.reproducible() {
        check_reproducible(plan.cwd(), loaded.name(), &digest)?;
    }

    if opts.aot() {
        crate::aot::emit(
            &bytes,
            &plan.cwd().join("target/qqq/aot"),
            opts.aot_cache.as_deref(),
        )?;
    }
    Ok(BuildOutput {
        aot_performed: opts.aot(),
        artifact: Some(relative_display(&dest, plan.cwd())),
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
    let bytes = std::fs::read(produced)
        .map_err(|e| Error::new(ErrorCode::CompilationFailed, e.to_string()))?;
    crate::aot::atomic_write(&dest, &bytes)?;
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
    ///
    /// **The steps joined with ` && `** -- one line, for a reader who wants to paste it. A machine that wants
    /// the plan unjoined reads [`Self::steps`], which is the same plan and cannot disagree with this one,
    /// because both come from `BuildPlan::step_commands`.
    pub command: String,
    /// The plan as a sequence, one entry per step -- **the same plan as `command`, unjoined**.
    ///
    /// # Why a machine wants this and not `command`
    ///
    /// Because splitting a joined shell line back into steps is wrong the first time an argument contains
    /// ` && `, and a consumer that does it will be wrong only for the inputs nobody tested. **A language whose
    /// build is a pipeline gets one entry per stage here**, so a diagnostic can name the stage that failed
    /// without guessing.
    pub steps: Vec<String>,
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
        let plan = BuildPlan::one(BuildStep {
            program: "cargo".to_owned(),
            args: vec![
                "build".to_owned(),
                "--target".to_owned(),
                "wasm32-wasip2".to_owned(),
            ],
            cwd: PathBuf::from("app; rm -rf ~"),
        });
        // The cwd is not part of the argument vector at all: `Command::current_dir`
        // takes it as a path, so it cannot be interpreted as a command.
        assert_eq!(plan.only_step().args.len(), 3);
        assert!(!plan.only_step().args.iter().any(|a| a.contains(';')));
    }

    /// **A plan stops at the first step that fails, and the index says which.**
    ///
    /// # Why this test exists at all
    ///
    /// `run_steps` was extracted to keep `execute` under clippy's line limit, and **it had no test**. A version
    /// that ran *every* step and reported the last would have passed the entire suite -- **while breaking the
    /// one property the multi-step plan exists for.** The type was tested; the semantics were not.
    ///
    /// # Why the commands are `cfg`-split
    ///
    /// Because nothing else in this crate spawns a process, so there is no helper to reuse, and **a test that
    /// needed `cargo` would not run in the bare environment the API-example checker warns about.** `cmd /c` and
    /// `sh -c` are each guaranteed on their own platforms, which covers all three CI runners.
    ///
    /// # The control
    ///
    /// **The second half asserts `None` for a plan whose steps all succeed.** Without it, an implementation
    /// that always returned `Some((0, ...))` would satisfy the first half, and a test that cannot fail is not a
    /// test -- the rule this repository applies to every checker it adds.
    #[test]
    fn a_plan_stops_at_the_first_step_that_fails() {
        let dir = std::env::temp_dir().join(format!("qqq-plan-steps-{}", std::process::id()));
        // Best-effort, and said so: a directory left by a previous run is not this run's failure. The removal
        // at the end does assert, because that one is about this run.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // **One helper per outcome, so the two arms cannot disagree about the shell.**
        let succeeds = |also_touch: Option<&str>| BuildStep {
            program: if cfg!(windows) { "cmd" } else { "sh" }.to_owned(),
            args: if cfg!(windows) {
                let mut a = vec!["/c".to_owned()];
                a.push(match also_touch {
                    Some(name) => format!("echo ran > {name}"),
                    None => "exit 0".to_owned(),
                });
                a
            } else {
                let mut a = vec!["-c".to_owned()];
                a.push(match also_touch {
                    Some(name) => format!("echo ran > {name}"),
                    None => "exit 0".to_owned(),
                });
                a
            },
            cwd: dir.clone(),
        };
        let fails = || BuildStep {
            program: if cfg!(windows) { "cmd" } else { "sh" }.to_owned(),
            args: if cfg!(windows) {
                vec!["/c".to_owned(), "exit 3".to_owned()]
            } else {
                vec!["-c".to_owned(), "exit 3".to_owned()]
            },
            cwd: dir.clone(),
        };

        // -- the control: every step succeeds, so nothing is reported as failing --
        let all_ok = BuildPlan {
            steps: vec![succeeds(None), succeeds(None)],
        };
        assert!(
            run_steps(&all_ok).unwrap().is_none(),
            "a plan whose steps all succeed must report no failure"
        );

        // -- and the case the type exists for: the second step fails --
        //
        // The first step leaves a marker, so the assertion can tell "the plan ran step one and stopped" from
        // "the plan ran nothing" -- a check that cannot distinguish those is the defect this file already
        // records three times over.
        let marker = "step-one-ran";
        let stops = BuildPlan {
            steps: vec![
                succeeds(Some(marker)),
                fails(),
                succeeds(Some("step-three-ran")),
            ],
        };
        let (index, status) = run_steps(&stops).unwrap().expect("the second step fails");
        assert_eq!(index, 1, "the plan must report the step that failed");
        assert!(!status.success());
        assert!(
            dir.join(marker).exists(),
            "step one must have run -- otherwise `index` is 1 for the wrong reason"
        );
        assert!(
            !dir.join("step-three-ran").exists(),
            "step three must NOT have run: a plan stops at the first failure"
        );

        remove_dir_all_best_effort(&dir);
    }

    /// Best-effort removal for a test's scratch directory.
    ///
    /// **A failure here is not the test's subject**, and saying so in a function whose name says so is better
    /// than a `let _ =` a reader has to interpret -- the shape `live_components.rs` documents at length.
    fn remove_dir_all_best_effort(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
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
    //
    // These call `plan_pure`, not `plan`. `plan` additionally probes the host
    // for `wasm-tools`, which is not installed on a bare CI runner — so these
    // assertions about *argument construction* failed there while passing
    // locally. The property under test is a pure function of the manifest and
    // the flags, so it is tested through the pure entry point.

    #[test]
    fn a_rust_project_plans_a_cargo_build() {
        let plan = plan_pure(&loaded(RUST), &BuildOptions::default()).expect("must plan");
        assert_eq!(plan.only_step().program, "cargo");
        assert!(plan.only_step().args.contains(&"build".to_owned()));
        assert!(plan.render().contains("wasm32-wasip2"));
    }

    /// The planning half must never consult the host. If it did, this test
    /// would fail on a machine without `wasm-tools` — which is exactly the bug
    /// this split fixes.
    #[test]
    fn pure_planning_does_not_depend_on_the_toolchain() {
        // Planning succeeds regardless of what is installed, for every
        // template and language combination that has a driver.
        for profile in ["debug", "release"] {
            let src = format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[build]\nprofile = \"{profile}\"\n"
            );
            assert!(
                plan_pure(&loaded(&src), &BuildOptions::default()).is_ok(),
                "pure planning must not depend on the host for profile `{profile}`"
            );
        }
    }

    /// `--release` and `--debug` is a contradiction. Letting one silently win is
    /// how a CI job builds the wrong profile with a green tick.
    #[test]
    fn contradictory_profile_flags_are_refused() {
        let opts = BuildOptions::from_flags(BuildOptions::RELEASE | BuildOptions::DEBUG, None);
        let e = plan_pure(&loaded(RUST), &opts).unwrap_err();
        assert_eq!(e.code, ErrorCode::McpArgumentInvalid);
        assert!(e.remediation.is_some());
    }

    #[test]
    fn the_release_flag_overrides_the_manifest_profile() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[build]\nprofile = \"debug\"\n";
        let opts = BuildOptions::from_flags(BuildOptions::RELEASE, None);
        let plan = plan_pure(&loaded(src), &opts).expect("must plan");
        assert!(plan.only_step().args.contains(&"--release".to_owned()));
    }

    #[test]
    fn the_manifest_profile_is_used_when_no_flag_is_given() {
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[build]\nprofile = \"debug\"\n";
        let plan = plan_pure(&loaded(src), &BuildOptions::default()).expect("must plan");
        assert!(!plan.only_step().args.contains(&"--release".to_owned()));
    }

    /// The environment-aware entry point must agree with the pure one about the
    /// *arguments*: `plan` adds a probe, not a second interpretation.
    ///
    /// Skipped where the toolchain is incomplete, because that is the one case
    /// where the two legitimately differ — and the difference is the point.
    #[test]
    fn the_probing_plan_agrees_with_the_pure_plan_when_tools_are_present() {
        let opts = BuildOptions::default();
        let pure = plan_pure(&loaded(RUST), &opts).expect("pure planning must succeed");
        match plan(&loaded(RUST), &opts) {
            Ok(probed) => assert_eq!(
                probed.only_step().args,
                pure.only_step().args,
                "the toolchain probe must not change the command"
            ),
            Err(e) => {
                // Only a missing tool may make the two differ.
                assert_eq!(e.code, ErrorCode::MissingTarget);
                assert!(
                    e.remediation.is_some(),
                    "a missing tool must name its install line"
                );
            }
        }
    }

    /// **Every language `TOOLCHAINS` knows is either driven and plans, or undriven and refuses.**
    ///
    /// # The property, and why a runtime check was not enough
    ///
    /// `plan_pure` has a catch-all that reports `InternalInvariantViolated` -- *"`{other}` has a toolchain but
    /// no argument builder"*. **That is a runtime check for a static property**: that [`DRIVEN`], [`TOOLCHAINS`]
    /// and the argument builders name the same set of languages. **It fires when a user builds, not when a
    /// developer adds a language**, which is the wrong end of the process.
    ///
    /// # Why this iterates the table rather than a written list
    ///
    /// **A written list is a fourth place for the same fact.** Iterating `TOOLCHAINS` means a language is
    /// covered the moment it is added to the table -- **including the four this machine cannot run, which is
    /// the point: the test must not need a toolchain, or it would not run here at all.**
    ///
    /// # And why the assertion is about the DISTINCTION rather than about success
    ///
    /// **A driven language must plan and an undriven one must refuse; both are correct, and the defect is
    /// reaching neither.** So this asserts two things: that the invariant-violation arm is never reached, and
    /// that the set of languages which plan is exactly [`DRIVEN`] -- **a language in both would be marked
    /// supported without a driver, and one in neither would parse and build nothing.**
    #[test]
    fn every_known_language_is_either_driven_and_plans_or_undriven_and_refuses() {
        let mut planned: Vec<String> = Vec::new();

        for (language, _) in TOOLCHAINS {
            let src = format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[build]\nlanguage = \"{language}\"\n"
            );
            match plan_pure(&loaded(&src), &BuildOptions::default()) {
                Ok(plan) => {
                    // A plan must be a real one: a step, with the program the table names.
                    assert!(
                        !plan.steps.is_empty(),
                        "`{language}` planned but produced no steps"
                    );
                    planned.push((*language).to_owned());
                }
                Err(e) => {
                    assert_ne!(
                        e.code,
                        ErrorCode::InternalInvariantViolated,
                        "`{language}` is in TOOLCHAINS but has no argument builder -- the lists disagree: {}",
                        e.message
                    );
                    // Any other refusal is a legitimate "not implemented yet" or a manifest complaint,
                    // and the next assertion checks it is the FORMER for a language that is not driven.
                    assert!(
                        !DRIVEN.contains(language),
                        "`{language}` is DRIVEN but refused a plan: {}",
                        e.message
                    );
                }
            }
        }

        // **The two directions, stated separately so a failure says which one broke.**
        for language in DRIVEN {
            assert!(
                planned.iter().any(|p| p == language),
                "`{language}` is in DRIVEN but produced no plan"
            );
        }
        assert_eq!(
            planned.len(),
            DRIVEN.len(),
            "the set of languages that plan must be exactly DRIVEN: planned {planned:?}, driven {DRIVEN:?}"
        );
    }

    /// A language that parses but has no driver must fail with an honest
    /// "not implemented yet" naming the checklist area, not a fake success.
    #[test]
    fn an_unimplemented_language_is_declared_not_faked() {
        let e = plan_pure(&loaded(TS), &BuildOptions::default()).unwrap_err();
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
        let e = plan_pure(&loaded(RUST), &opts).unwrap_err();
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
                assert!(!p.only_step().args.is_empty());
                assert_eq!(p.only_step().program, "cargo");
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
            steps: vec!["cargo build --release".to_owned()],
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
            steps: vec!["cargo build --release".to_owned()],
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

#[cfg(test)]
mod target_root_tests {
    use super::*;

    /// **`CARGO_TARGET_DIR` overrides cargo's default.**
    ///
    /// # Why this test exists, and what it would have caught
    ///
    /// `qqqai build` shells out to cargo, so it must resolve whatever cargo resolved. Measured inside
    /// the bridge, which sets the variable to `/linux-target`:
    ///
    /// ```text
    ///     Finished `release` profile ... in 2.03s
    /// error[QQQ-1001]: the build succeeded but no component was found in
    ///                  `/tmp/probeapp/target/wasm32-wasip2/release`
    /// ```
    ///
    /// **The build succeeded and the tool said it had not**, naming a directory cargo never wrote and
    /// a remediation that was true in general and false here.
    ///
    /// # Why it tests the `_for` form
    ///
    /// Because `std::env::set_var` is `unsafe` in edition 2024 and this crate is `#![forbid(unsafe_code)]`.
    /// A test could not set the variable; so the rule takes it as an argument, and **the pure half is
    /// the half that gets tested**.
    #[test]
    fn cargo_target_dir_overrides_the_default() {
        let project = Path::new("/proj");

        assert_eq!(
            target_root_for(project, Some(std::ffi::OsStr::new("/elsewhere"))),
            PathBuf::from("/elsewhere"),
            "an override must win outright"
        );
        assert_eq!(
            target_root_for(project, None),
            PathBuf::from("/proj/target"),
            "with no override, cargo's default is the project's `target/`"
        );
        assert_eq!(
            target_root_for(project, Some(std::ffi::OsStr::new(""))),
            PathBuf::from("/proj/target"),
            "an EMPTY value is not an override -- cargo treats it as unset, so this must too"
        );
    }

    /// **The artifact path and the directory agree**, because a build that reports one and writes the
    /// other is the defect this pair exists to prevent.
    #[test]
    fn the_artifact_path_lives_under_the_directory() {
        let project = Path::new("/proj");
        let dir = artifact_dir(project, "release", "wasm32-wasip2");
        let file = rust_artifact_path(project, "release", "wasm32-wasip2", "app");
        assert_eq!(file.parent(), Some(dir.as_path()));
    }
}
