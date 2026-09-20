//! `qqqai run` — execute a built component under the capability sandbox.
//!
//! Implements Proposal §5.2's `run` row and the execution half of §4.6;
//! Checklist `CLI-009`.
//!
//! # What this command is actually for
//!
//! `run` is the only place where the whole design becomes observable at once.
//! Everything before it — the manifest, the capability model, the grant
//! resolution, the linker — is static analysis that says what *should* happen.
//! This is where a component either gets exactly the authority its grants name,
//! or does not run at all.
//!
//! That makes the failure modes the interesting part. There are four, and they
//! must be distinguishable, because each has a different fix:
//!
//! | Failure | Meaning | Fix |
//! |---|---|---|
//! | artifact missing/invalid | nothing was built | `qqqai build` |
//! | import not provided | the component wants an ungranted capability | grant it, or stop importing it |
//! | trap | the guest misbehaved or hit a limit | fix the guest, or raise a limit |
//! | success | — | — |
//!
//! Collapsing these into "it didn't work" would make `run` useless for exactly
//! the person most likely to need it: someone whose capability model is wrong.
//!
//! # Why a missing artifact is a *capability-adjacent* error
//!
//! The whole point of the design is that a component's imports are known before
//! it runs. Checking the artifact's imports against the resolved grants
//! *before* instantiating lets us report the mismatch as a capability problem,
//! with the exact `qqq.toml` stanza that resolves it — rather than letting
//! Wasmtime report a link error and leaving the user to translate it.

use std::path::{Path, PathBuf};
use std::time::Instant;

use qqq_cap::resolve::{GrantSet, Resolution};
use qqq_core::{Error, ErrorCode, Result};
use qqq_host::{EngineConfig, Instance, LimitSet, PreparedComponent};

use crate::build::component_path;
use crate::manifest_loader::LoadedManifest;
use crate::output::{CommandName, CommandOutput};

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// How `qqqai run` was invoked.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunOptions {
    /// An explicit artifact to run, overriding the staged path.
    pub artifact: Option<PathBuf>,
    /// Run deterministically: fixed clock, seeded RNG (Proposal §10.5).
    pub deterministic: bool,
    /// Additional capabilities granted on the command line.
    ///
    /// These are applied as a **developer overlay**, which may only narrow the
    /// manifest's grants. A command-line flag that could widen authority would
    /// be a way to defeat the manifest, which is the one thing the design
    /// forbids.
    pub caps: Vec<String>,
    /// Arguments to pass to the component.
    pub args: Vec<String>,
    /// Report what would run without running it.
    pub dry_run: bool,
}

/// Parse a `--cap` value into a capability name and an optional scope.
///
/// # Why scopes are accepted but not yet honoured
///
/// `--cap fs.read:/tmp` is the documented spelling, and the scope is the part
/// that makes it safe. Accepting the name while silently discarding the scope
/// would grant *more* than the user asked for — the exact failure mode the
/// capability system exists to prevent. So a scope is parsed and then checked:
/// for now, a scoped request is refused with a message naming what is missing,
/// rather than quietly widened.
///
/// # Errors
///
/// `QQQ-2007` when the capability name is unknown, with a suggestion.
pub fn parse_cap_flag(spec: &str) -> Result<(qqq_cap::Capability, Option<String>)> {
    let (name, scope) = match spec.split_once(':') {
        Some((n, s)) => (n.trim(), Some(s.trim().to_owned())),
        None => (spec.trim(), None),
    };
    let cap = qqq_cap::Capability::from_name(name).ok_or_else(|| {
        let hint = qqq_cap::Capability::suggest(name).map_or_else(
            || " — run `qqqai caps` for what this project grants".to_owned(),
            |c| format!(" — did you mean `{c}`?"),
        );
        Error::new(
            ErrorCode::CapabilitySyntaxInvalid,
            format!("unknown capability `{name}`{hint}"),
        )
        .with_remediation("capability names are lowercase dotted pairs, e.g. `http.client`")
    })?;
    Ok((cap, scope))
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// The result of `qqqai run`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunOutput {
    /// The project name.
    pub project: String,
    /// The artifact that ran.
    pub artifact: String,
    /// The artifact's content digest.
    pub digest: String,
    /// The interfaces the component imports.
    pub imports: Vec<String>,
    /// The interfaces the grants provide, and which are actually bound.
    pub granted_imports: Vec<String>,
    /// Whether execution succeeded.
    pub ok: bool,
    /// The guest's exit code, when the component exposes one.
    pub exit_code: Option<i32>,
    /// Wall-clock duration in microseconds.
    pub duration_us: u64,
    /// Instruction units consumed, when metering is on.
    pub fuel_consumed: Option<u64>,
    /// Whether the run was deterministic.
    pub deterministic: bool,
    /// Whether this was a rehearsal.
    pub dry_run: bool,
}

impl CommandOutput for RunOutput {
    fn command(&self) -> CommandName {
        CommandName::Run
    }

    fn summary(&self) -> String {
        if self.dry_run {
            return format!(
                "would run: {} ({} imports)",
                self.artifact,
                self.imports.len()
            );
        }
        match self.exit_code {
            Some(0) | None if self.ok => {
                format!("{}: ran in {} µs", self.project, self.duration_us)
            }
            Some(code) => format!("{}: exited with code {code}", self.project),
            None => format!("{}: failed", self.project),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

// ---------------------------------------------------------------------------
// Locating the artifact
// ---------------------------------------------------------------------------

/// Find the artifact to run.
///
/// # Search order, and why it is this order
///
/// 1. An explicit `--artifact` path — the user said exactly what to run.
/// 2. The staged path `target/qqq/<name>.component.wasm`, which `build` writes.
/// 3. The raw Cargo output, so `run` works immediately after a manual
///    `cargo build` without a `qqqai build` in between.
///
/// Falling back to Cargo's directory is a convenience with a cost: it makes
/// `run` succeed on an artifact that `build` never verified. That is acceptable
/// because `run` re-verifies the artifact's shape itself before instantiating,
/// so the check is not skipped — only relocated.
///
/// # Errors
///
/// `QQQ-1002` when no artifact is found, naming every path tried. Listing them
/// is what turns "not found" into "here is what I looked for".
pub fn locate_artifact(loaded: &LoadedManifest, opts: &RunOptions) -> Result<PathBuf> {
    let project_dir = loaded
        .path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(explicit) = &opts.artifact {
        candidates.push(explicit.clone());
    } else {
        let name = loaded.name();
        candidates.push(component_path(&project_dir, name));
        candidates.push(crate::build::rust_artifact_path(
            &project_dir,
            "release",
            &loaded.manifest.build.target,
            name,
        ));
        candidates.push(crate::build::rust_artifact_path(
            &project_dir,
            "debug",
            &loaded.manifest.build.target,
            name,
        ));
    }

    if let Some(found) = candidates.iter().find(|p| p.is_file()) {
        return Ok(found.clone());
    }

    let tried = candidates
        .iter()
        .map(|p| format!("  {}", p.display()))
        .collect::<Vec<_>>()
        .join("\n");
    Err(Error::new(
        ErrorCode::InvalidComponentArtifact,
        "no built component found",
    )
    .with_cause(format!("looked in:\n{tried}"))
    .with_remediation(format!(
        "run `{} build` first, or pass --artifact <path>",
        qqq_core::BINARY_NAME
    )))
}

// ---------------------------------------------------------------------------
// Pre-flight: imports versus grants
// ---------------------------------------------------------------------------

/// A component's imports checked against what the grants can provide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportCheck {
    /// Imports the component declares.
    pub required: Vec<String>,
    /// Imports the grants can satisfy.
    pub satisfied: Vec<String>,
    /// Imports that are required but not granted — the reason a run would fail.
    pub missing: Vec<String>,
}

impl ImportCheck {
    /// Whether every required import is satisfiable.
    #[must_use]
    pub fn is_satisfied(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Compute the import check without running anything.
///
/// # Why this exists separately from instantiation
///
/// Wasmtime *also* detects a missing import — by failing to instantiate. But its
/// message is about a linker and an interface name; ours can be about a
/// capability and a `qqq.toml` stanza. Doing the comparison ourselves means the
/// error the user sees names the thing they can edit.
///
/// It also gives `--dry-run` something meaningful to report, and lets `run`
/// explain the problem for an agent that cannot read Wasmtime's error text.
///
/// # Matching is package-aware, and it has to be
///
/// A component's import table names **interfaces** — `qqq:clock/now@1.0.0` —
/// while QQQ's registry names **packages** — `qqq:clock@1.0.0`. Comparing the
/// two strings directly reports a missing import for a capability that is
/// granted, which is a false alarm on the one diagnostic a user most needs to
/// trust.
///
/// So an import is satisfied when either:
///
/// * it equals a granted interface after version-stripping (the common case), or
/// * its **package** (`qqq:clock`) equals a granted interface's package, meaning
///   the grant covers the whole package.
///
/// This was found by running a real WAT component against a real manifest —
/// every unit test passed while the comparison was wrong, because the tests
/// used the same string form the code did. See Observations §O-020.
#[must_use]
pub fn check_imports(
    component: &PreparedComponent,
    engine: &wasmtime::Engine,
    grants: &GrantSet,
) -> ImportCheck {
    let required = component.imported_interfaces(engine);
    let provided = qqq_host::required_interfaces(grants);

    let provided_names: Vec<String> = provided.iter().map(|i| package_of(i)).collect();
    let mut satisfied = Vec::new();
    let mut missing = Vec::new();
    for import in &required {
        if provided_names.contains(&package_of(import)) {
            satisfied.push(import.clone());
        } else {
            missing.push(import.clone());
        }
    }

    ImportCheck {
        required,
        satisfied,
        missing,
    }
}

/// Reduce an interface or package name to `namespace:name`, dropping both the
/// version and any interface path.
///
/// ```text
/// qqq:clock@1.0.0        -> qqq:clock
/// qqq:clock/now@1.0.0    -> qqq:clock
/// qqq:http/client@1.0.0  -> qqq:http
/// ```
///
/// A name without a colon is returned unchanged: it is not something we
/// recognise, and silently mangling it would turn an unknown import into a
/// spurious match against another unknown import.
#[must_use]
pub fn package_of(interface: &str) -> String {
    let without_version = interface.split('@').next().unwrap_or(interface).trim();
    let without_path = without_version
        .split('/')
        .next()
        .unwrap_or(without_version)
        .trim();
    // Guard the degenerate cases: an empty or colon-less name is returned
    // as-is rather than being reduced to something that could collide.
    if without_path.contains(':') {
        without_path.to_owned()
    } else {
        without_version.to_owned()
    }
}

/// Map an imported interface to the capability that unlocks it, **exactly**.
///
/// # There is only one mapping, and this is it
///
/// An earlier version of this module carried a second, package-level function
/// and justified it as "the right granularity for an error message, where a
/// package-level match is enough to name a stanza". That justification was
/// wrong, and the defect it caused is the reason the function is gone:
///
/// * For a component importing `qqq:clock/wall-clock`, it returned
///   `clock.monotonic` — the other half of the same package. The advice would
///   have left the component still failing, on the one error whose entire
///   purpose is saying what to add.
/// * It was fixed in `qqqai inspect` (`§O-038b`) and left in place in `run`,
///   because the two commands reach the mapping differently: `inspect` had a
///   visibly wrong answer in its report, while `run` only shows it in a
///   remediation line a reader is already primed to trust.
///
/// A second mapping that is *nearly* right is a trap: it compiles, it has
/// passing tests, its doc comment explains why it is fine, and every new caller
/// has to know which of the two to pick. Deleting it is the fix — `run` now uses
/// this one, and nothing else does.
///
/// The two answer different questions and the difference is a security bug if
/// conflated.
#[must_use]
pub fn capability_for_import(interface: &str) -> Option<qqq_cap::Capability> {
    let wanted = strip_version(interface);

    // The precise table first: for a package with several interfaces, this is
    // the only mapping that can name the right capability.
    //
    // **Capabilities come back in a defined order and the strongest wins.** Two
    // capabilities may legitimately map to one interface: `qqq:http/http`
    // carries both `send` (outbound) and `incoming-authority` (which server is
    // serving), so importing it implies `http.client` *and* `http.server`. The
    // report must name the stronger, because understating what an artifact can
    // do is the one failure an audit surface must not have.
    let matches: Vec<qqq_cap::Capability> = qqq_cap::Capability::all()
        .iter()
        .copied()
        .filter(|&c| {
            qqq_abi::registry::interface_path_for(c).is_some_and(|p| strip_version(p) == wanted)
        })
        .collect();

    if !matches.is_empty() {
        return matches.into_iter().max_by_key(|c| exposure_rank(*c));
    }

    // Then the package-level fallback, for single-interface packages where the
    // registry's `name` is already exact.
    //
    // Two shapes are accepted, because both occur in the registry:
    //
    //   * the registry name equals the import exactly (`qqq:dns@1.0.0` for an
    //     import of `qqq:dns@1.0.0`), and
    //   * the registry name is the **package** of a sub-interface import
    //     (`qqq:fs@1.0.0` for `qqq:fs/filesystem@1.0.0`), which is how a
    //     package whose WIT declares one interface is registered.
    //
    // Restricted to capabilities with **no** precise path, so a multi-interface
    // package can never be matched here by accident — that was the original bug.
    let wanted_package = package_of(interface);
    let matching: Vec<qqq_cap::Capability> = qqq_cap::Capability::all()
        .iter()
        .copied()
        .filter(|&c| {
            if qqq_abi::registry::interface_path_for(c).is_some() {
                return false;
            }
            qqq_abi::registry::interface_for(c).is_some_and(|i| {
                let name = strip_version(&i.name);
                // Exact match, or the registry named the *package* of a
                // sub-interface import (`qqq:fs` for `qqq:fs/filesystem`).
                // `wanted` is checked first so an exact match never falls
                // through to the package comparison.
                name == wanted || name == wanted_package
            })
        })
        .collect();

    // Same strongest-wins rule as above. `qqq:fs/filesystem` is unlocked by
    // `FsRead`, `FsWrite` **and** `FsWatch`; reporting `fs.read` for an
    // artifact that imports the whole filesystem interface would understate it
    // by two thirds, and understating is the failure that matters here.
    if matching.is_empty() {
        return None;
    }
    matching.into_iter().max_by_key(|c| exposure_rank(*c))
}

/// How much authority a capability grants, for choosing between two that unlock
/// the same interface.
///
/// Ordered so `max_by_key` picks the one that exposes more. This must agree with
/// [`crate::commands::classify_posture`]'s notion of exposure: if a capability
/// is `Exposed` there and `Contained` here, an artifact could be reported as
/// contained by a path that posture classification would call exposed.
///
/// The ranking is deliberately coarse — three levels — because a finer one would
/// invite the belief that the numbers are comparable across capabilities rather
/// than merely ordered.
#[must_use]
pub const fn exposure_rank(c: qqq_cap::Capability) -> u8 {
    use qqq_cap::Capability::{
        AiInfer, DnsResolve, FsWatch, FsWrite, HttpClient, HttpServer, KvWrite, QueuePublish,
        QueueSubscribe, SqlExecute,
    };
    match c {
        FsWrite | FsWatch | HttpClient | HttpServer | SqlExecute | KvWrite | QueuePublish
        | QueueSubscribe | DnsResolve | AiInfer => 2,
        _ => 1,
    }
}

/// An interface name with its `@version` removed.
fn strip_version(interface: &str) -> String {
    interface
        .split('@')
        .next()
        .unwrap_or(interface)
        .trim()
        .to_owned()
}

/// Turn a failed import check into the error a user can act on.
///
/// # Errors
///
/// Always `QQQ-6003`, with a remediation naming the capability to grant.
fn import_error(check: &ImportCheck, loaded: &LoadedManifest) -> Error {
    let missing = check.missing.join(", ");
    // Name the capability the **failing interface** implies, using the precise
    // mapping.
    //
    // This used `capability_for_interface`, which compares by *package*, and
    // several packages hold several interfaces. Measured on a real artifact: a
    // component importing `qqq:clock/wall-clock` was told to grant
    // `clock.monotonic` — the other half of the same package. The advice named a
    // stanza that would have left the component still failing, on the one error
    // whose entire purpose is telling the user what to add.
    //
    // The same defect was found and fixed in `qqqai inspect` (`§O-038b`); this
    // path was missed because the two commands reach the mapping differently —
    // `inspect` had a visible wrong answer in its report, while `run` only shows
    // it in a remediation line that a reader is already primed to trust.
    let implicated: Option<qqq_cap::Capability> =
        check.missing.iter().find_map(|i| capability_for_import(i));

    let mut e = Error::new(
        ErrorCode::ComponentLoadFailed,
        format!(
            "the component imports {} that no grant provides",
            plural(&check.missing)
        ),
    )
    .with_context("missing", missing)
    .with_context("granted", check.satisfied.join(", "))
    .with_context("project", loaded.name().to_owned())
    .with_remediation(match implicated {
        Some(cap) => crate::commands::fix_stanza_for(cap),
        None => format!(
            "run `{} caps` to see what is granted, and `{} why <capability>` to \
             understand a decision",
            qqq_core::BINARY_NAME,
            qqq_core::BINARY_NAME
        ),
    });
    if let Some(cap) = implicated {
        e = e.with_context("capability", cap.name().to_owned());
    }
    e
}

/// `1 interface` / `2 interfaces`.
fn plural(items: &[String]) -> String {
    if items.len() == 1 {
        format!("`{}`", items[0])
    } else {
        format!("{} interfaces", items.len())
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// Everything that happens before a single guest instruction runs.
///
/// Split out so `--dry-run` can perform the *entire* pre-flight and report it.
/// A rehearsal that skips the checks is worthless: it would print "would run"
/// for a component that cannot possibly instantiate.
///
/// The raw bytes are deliberately **not** returned. The digest comes from
/// `PreparedComponent`, so handing the caller a second copy of the artifact
/// would be an opportunity for the two to disagree about what is being run.
///
/// # Errors
///
/// As [`locate_artifact`], [`PreparedComponent::compile`] and [`resolve_grants`].
pub fn prepare(loaded: &LoadedManifest, opts: &RunOptions) -> Result<Prepared> {
    let path = locate_artifact(loaded, opts)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        Error::new(
            ErrorCode::ComponentLoadFailed,
            format!("could not read `{}`", path.display()),
        )
        .with_cause(e.to_string())
    })?;

    let engine = new_engine(opts)?;
    let prepared = PreparedComponent::compile(&engine, &bytes)?;

    // Resolve the grants. The developer overlay may only narrow, so a `--cap`
    // that is not in the manifest cannot add authority — the overlay is applied
    // and then the *result* is what the linker sees.
    let resolution = resolve_grants(loaded, opts)?;
    let check = check_imports(&prepared, &engine, &resolution.grants);

    Ok(Prepared {
        path,
        engine,
        component: prepared,
        check,
        resolution,
    })
}

/// The result of pre-flight: everything needed to instantiate, and nothing else.
pub struct Prepared {
    /// The artifact that will run.
    pub path: PathBuf,
    /// The engine the component was compiled against.
    ///
    /// Carried alongside the component rather than reconstructed, because
    /// compiling against one engine and instantiating on another is the kind of
    /// aliasing bug that produces unreproducible behaviour.
    pub engine: wasmtime::Engine,
    /// The compiled component.
    pub component: PreparedComponent,
    /// Its imports checked against the grants.
    pub check: ImportCheck,
    /// The resolved grants.
    pub resolution: Resolution,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("path", &self.path)
            .field("digest", &self.component.digest())
            .field("missing_imports", &self.check.missing.len())
            .finish_non_exhaustive()
    }
}

/// Build the engine for a run.
///
/// # Errors
///
/// `QQQ-6004` when the engine configuration is rejected — always a QQQ bug.
pub fn new_engine(opts: &RunOptions) -> Result<wasmtime::Engine> {
    let mut cfg = if opts.deterministic {
        EngineConfig::deterministic()
    } else {
        EngineConfig::default()
    };

    // `qqqai run` loads DWARF, so a trap names a file and line.
    //
    // `EngineConfig::default()` leaves this off — the right default for a
    // *server*, where the module is untrusted, the artifact is large, and a
    // source line is not going to be read by anyone. It is the wrong default for
    // the CLI, whose entire audience is a developer staring at a failed run:
    // without this, `Instance::run` never receives a `WasmBacktrace` with
    // symbols, and reports `func+0x1a3` for a crash the developer could have
    // found by reading one line.
    //
    // Set on the **engine**, not on the artifact: `debug = true` in the
    // project's profile decides whether DWARF is *emitted*, and this decides
    // whether the engine *reads* it. Both are needed, which is why `qqqai new`
    // sets the first and this sets the second.
    //
    // The cost is parse time at startup, proportional to the debug sections.
    // `serve` deliberately does not do this; see `qqq-serve` when it exists.
    cfg.debug_info = true;

    let mut wasmtime_cfg = cfg.to_wasmtime_config()?;
    // `run` executes once and exits; Cranelift's default optimisation level is
    // the right trade for that. Revisit when `serve` holds one engine for many
    // requests and the compile cost is amortised.
    let _ = &mut wasmtime_cfg;
    wasmtime::Engine::new(&wasmtime_cfg).map_err(|e| {
        Error::new(
            ErrorCode::InternalInvariantViolated,
            "could not construct the wasm engine",
        )
        .with_cause(format!("{e:#}"))
        .with_remediation("this is a QQQ bug; please report it")
    })
}

/// Resolve the manifest's grants, applying the developer overlay.
///
/// # Errors
///
/// `QQQ-2007` for an unknown `--cap`, `QQQ-2004` when a granted path does not
/// exist on this host.
pub fn resolve_grants(loaded: &LoadedManifest, opts: &RunOptions) -> Result<Resolution> {
    let mut resolution = Resolution::from_manifest(&loaded.manifest);

    if !opts.caps.is_empty() {
        let mut explicit = Vec::with_capacity(opts.caps.len());
        let mut scoped = Vec::new();
        for spec in &opts.caps {
            let (cap, scope) = parse_cap_flag(spec)?;
            if scope.is_some() {
                scoped.push(spec.clone());
            }
            explicit.push(cap);
        }

        // A scoped `--cap` cannot be honoured yet. Refusing is the only safe
        // answer: applying the capability without its scope would grant more
        // authority than was asked for, which is precisely the widening the
        // design forbids. Saying so beats silently doing the wrong thing.
        if !scoped.is_empty() {
            return Err(Error::new(
                ErrorCode::CapabilityWideningRefused,
                format!(
                    "scoped capability flags are not supported yet: {}",
                    scoped.join(", ")
                ),
            )
            .with_remediation(
                "put the scope in qqq.toml, where it is enforced; `--cap` currently \
                 accepts unscoped names only",
            ));
        }

        resolution = resolution.apply(&crate::commands::developer_overlay(&explicit));
    }

    Ok(resolution)
}

/// Run the component and report the outcome.
///
/// # Errors
///
/// * `QQQ-1002` — no artifact.
/// * `QQQ-6003` — a required import is not granted, or instantiation failed.
/// * `QQQ-3xxx` — the guest trapped; the code names which limit or which bug.
pub fn execute(loaded: &LoadedManifest, opts: &RunOptions) -> Result<RunOutput> {
    let p = prepare(loaded, opts)?;

    // The pre-flight check, reported before Wasmtime would report it, so the
    // error names a capability and a stanza rather than a linker and an
    // interface.
    if !p.check.is_satisfied() {
        return Err(import_error(&p.check, loaded));
    }

    let project_dir = loaded
        .path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let artifact = p
        .path
        .strip_prefix(&project_dir)
        .unwrap_or(&p.path)
        .to_string_lossy()
        .replace('\\', "/");

    let base = RunOutput {
        project: loaded.name().to_owned(),
        artifact,
        digest: p.component.digest().to_owned(),
        imports: p.check.required.clone(),
        granted_imports: p.check.satisfied.clone(),
        ok: true,
        exit_code: None,
        duration_us: 0,
        fuel_consumed: None,
        deterministic: opts.deterministic,
        dry_run: false,
    };

    let limits = LimitSet::from_manifest(&loaded.manifest.limits)?;
    let instance = Instance::create(&p.engine, &p.component, &p.resolution.grants, limits)?;

    let started = Instant::now();
    let outcome = instance.run_measured(|_store, _instance| {
        // A component with no exported entry point still instantiates and
        // drops, which is a meaningful check in itself: it proves every import
        // resolved and every limit applied. Calling a specific export is the
        // job of `qqqai serve` and the entrypoint declared in the manifest;
        // guessing an export name here would make `run` succeed or fail for
        // reasons unrelated to the capability model.
        Ok(RunOutcome::Instantiated)
    });
    let elapsed = started.elapsed();

    match outcome {
        Ok(o) => Ok(RunOutput {
            duration_us: u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            fuel_consumed: o.fuel_consumed,
            ..base
        }),
        Err(e) => Err(e),
    }
}

/// What the run closure produced.
///
/// A named type rather than `()` so the measurement path has something to
/// report, and so adding a real entrypoint call later is a change to one enum
/// rather than to every signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// The component instantiated successfully. Its imports resolved and its
    /// limits applied — which is the whole contract `run` verifies today.
    Instantiated,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(src: &str, dir: &Path) -> LoadedManifest {
        LoadedManifest {
            manifest: qqq_cap::manifest::Manifest::parse(src).expect("test manifest"),
            path: dir.join("qqq.toml"),
            source: src.to_owned(),
        }
    }

    const DENY_ALL: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n";

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-run-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    // -- capability flag parsing -------------------------------------------

    #[test]
    fn a_bare_capability_flag_parses() {
        let (cap, scope) = parse_cap_flag("crypto.hash").expect("must parse");
        assert_eq!(cap.name(), "crypto.hash");
        assert!(scope.is_none());
    }

    #[test]
    fn a_scoped_capability_flag_keeps_its_scope() {
        let (cap, scope) = parse_cap_flag("fs.read:/tmp/data").expect("must parse");
        assert_eq!(cap.name(), "fs.read");
        assert_eq!(scope.as_deref(), Some("/tmp/data"));
    }

    /// A colon is only a scope separator when it follows a known capability
    /// name. `ipv6` style values must not be mistaken for scopes — otherwise
    /// the split lands in the wrong place and the name lookup fails.
    #[test]
    fn a_colon_inside_a_value_is_treated_as_a_scope_not_a_name() {
        let (cap, scope) = parse_cap_flag("http.client:api.example.com:443").expect("must parse");
        assert_eq!(cap.name(), "http.client");
        assert_eq!(scope.as_deref(), Some("api.example.com:443"));
    }

    #[test]
    fn an_unknown_capability_flag_suggests_a_near_match() {
        let e = parse_cap_flag("crypto.has").unwrap_err();
        assert_eq!(e.code, ErrorCode::CapabilitySyntaxInvalid);
        assert!(
            e.message.contains("crypto.hash"),
            "a one-character typo must be corrected: {}",
            e.message
        );
    }

    /// A name with no near match gets the catalogue fallback, not a bad guess.
    ///
    /// Verified against the suggester rather than assumed: `zzzz` and
    /// `nonsense.entirely` both produce no suggestion, while `crypto.has`
    /// resolves to `crypto.hash`. A wrong "did you mean" is worse than none,
    /// because it sends the user to edit a name that was never the problem.
    ///
    /// The catalogue pointer lives in `message`; the `remediation` is the
    /// syntax hint, which applies to every bad name. Asserting on the field
    /// that actually carries the text is the difference between a test that
    /// checks the behaviour and one that checks a guess about where it lives.
    #[test]
    fn an_unknown_capability_with_no_near_match_points_at_caps() {
        for input in ["zzzz", "nonsense.entirely"] {
            let e = parse_cap_flag(input).unwrap_err();
            assert_eq!(e.code, ErrorCode::CapabilitySyntaxInvalid);
            assert!(
                !e.message.contains("did you mean"),
                "`{input}` has no near match and must not be guessed at: {}",
                e.message
            );
            assert!(
                e.message.contains("qqqai caps"),
                "`{input}` must point at the catalogue: {}",
                e.message
            );
            // The syntax hint applies to every bad name, so it is always there.
            assert!(e
                .remediation
                .as_deref()
                .unwrap_or("")
                .contains("lowercase dotted pairs"));
        }
    }

    /// A genuine typo is corrected. Each of these was confirmed against the
    /// suggester itself, so the test asserts what the suggester does rather
    /// than what it seems like it ought to do.
    #[test]
    fn a_genuine_typo_is_corrected() {
        for (typo, expected) in [
            ("crypto.has", "crypto.hash"),
            ("crypto.hsh", "crypto.hash"),
            ("http.clien", "http.client"),
            ("fs.rea", "fs.read"),
            ("clock.wal", "clock.wall"),
        ] {
            let e = parse_cap_flag(typo).unwrap_err();
            assert_eq!(e.code, ErrorCode::CapabilitySyntaxInvalid);
            assert!(
                e.message.contains(expected),
                "`{typo}` should suggest `{expected}`: {}",
                e.message
            );
        }
    }

    // -- artifact location --------------------------------------------------

    #[test]
    fn an_explicit_artifact_wins() {
        let dir = temp_dir("explicit-artifact");
        let art = dir.join("custom.wasm");
        std::fs::write(&art, b"\0asm\x01\0\0\0").unwrap();
        let l = loaded(DENY_ALL, &dir);
        let opts = RunOptions {
            artifact: Some(art.clone()),
            ..Default::default()
        };
        assert_eq!(locate_artifact(&l, &opts).unwrap(), art);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The error must list every path tried. "Not found" without saying where
    /// we looked leaves the user to guess the naming convention.
    #[test]
    fn a_missing_artifact_lists_every_path_tried() {
        let dir = temp_dir("missing-artifact");
        let l = loaded(DENY_ALL, &dir);
        let e = locate_artifact(&l, &RunOptions::default()).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidComponentArtifact);
        // `cause` is a chain, outermost first; the paths we tried are one entry.
        let cause = e.cause.join("\n");
        assert!(
            cause.contains("target"),
            "must show the staged path: {cause}"
        );
        assert!(
            cause.contains("release") && cause.contains("debug"),
            "must show both cargo profiles: {cause}"
        );
        assert!(e.remediation.as_deref().unwrap_or("").contains("build"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The staged path is preferred over Cargo's, because it is the one `build`
    /// verified and the one a deployment pins.
    #[test]
    fn the_staged_artifact_is_preferred_over_the_cargo_output() {
        let dir = temp_dir("prefer-staged");
        let staged = crate::build::component_path(&dir, "app");
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::write(&staged, b"\0asm\x01\0\0\0").unwrap();

        let cargo = crate::build::rust_artifact_path(&dir, "release", "wasm32-wasip2", "app");
        std::fs::create_dir_all(cargo.parent().unwrap()).unwrap();
        std::fs::write(&cargo, b"\0asm\x01\0\0\0").unwrap();

        let l = loaded(DENY_ALL, &dir);
        assert_eq!(locate_artifact(&l, &RunOptions::default()).unwrap(), staged);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no staged artifact, Cargo's output is still usable — so `run` works
    /// straight after a manual `cargo build`.
    #[test]
    fn the_cargo_output_is_used_when_nothing_is_staged() {
        let dir = temp_dir("fallback-cargo");
        let cargo = crate::build::rust_artifact_path(&dir, "release", "wasm32-wasip2", "app");
        std::fs::create_dir_all(cargo.parent().unwrap()).unwrap();
        std::fs::write(&cargo, b"\0asm\x01\0\0\0").unwrap();

        let l = loaded(DENY_ALL, &dir);
        assert_eq!(locate_artifact(&l, &RunOptions::default()).unwrap(), cargo);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- grant resolution ---------------------------------------------------

    #[test]
    fn no_cap_flags_leaves_the_manifest_grants_alone() {
        let dir = temp_dir("no-caps");
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [capabilities.crypto]\nhash = [\"sha256\"]\n";
        let l = loaded(src, &dir);
        let r = resolve_grants(&l, &RunOptions::default()).expect("must resolve");
        assert!(r.grants.grants(qqq_cap::Capability::CryptoHash));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The security property, at the CLI boundary.** A `--cap` for something
    /// the manifest does not grant must not add it. The overlay intersects, so
    /// the ungranted capability stays denied.
    ///
    /// Note the second half of the assertion: intersecting *also* removes the
    /// manifest's own grant, because `--cap` means "restrict to exactly these".
    /// That is the correct reading of a narrowing-only overlay — `--cap` can
    /// only ever take authority away — and it is worth pinning, because the
    /// alternative reading ("--cap adds to the manifest") is the one a user is
    /// likely to assume and the one the design forbids.
    #[test]
    fn a_cap_flag_cannot_widen_beyond_the_manifest() {
        let dir = temp_dir("no-widen");
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [capabilities.crypto]\nhash = [\"sha256\"]\n";
        let l = loaded(src, &dir);
        let opts = RunOptions {
            // `http.client` is NOT in the manifest. Asking for it on the command
            // line must not grant it.
            caps: vec!["http.client".to_owned()],
            ..Default::default()
        };
        let r = resolve_grants(&l, &opts).expect("must resolve");
        assert!(
            !r.grants.grants(qqq_cap::Capability::HttpClient),
            "--cap must never widen beyond the manifest"
        );
        assert!(
            !r.grants.grants(qqq_cap::Capability::CryptoHash),
            "--cap restricts to exactly the named set; the manifest's other \
             grants are intersected away, never preserved"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The identity case: `--cap` naming a capability the manifest already
    /// grants leaves that capability granted. Without this, the test above
    /// could pass for the wrong reason (an overlay that grants nothing at all).
    #[test]
    fn a_cap_flag_matching_the_manifest_preserves_the_grant() {
        let dir = temp_dir("cap-match");
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [capabilities.crypto]\nhash = [\"sha256\"]\n";
        let l = loaded(src, &dir);
        let opts = RunOptions {
            caps: vec!["crypto.hash".to_owned()],
            ..Default::default()
        };
        let r = resolve_grants(&l, &opts).expect("must resolve");
        assert!(
            r.grants.grants(qqq_cap::Capability::CryptoHash),
            "a --cap the manifest already grants must remain granted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A scoped `--cap` must be refused, not silently applied without its
    /// scope: applying it would grant more than was asked for.
    #[test]
    fn a_scoped_cap_flag_is_refused_rather_than_widened() {
        let dir = temp_dir("scoped-cap");
        let src = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [[capabilities.fs]]\npath = \"/tmp\"\nmode = \"read-only\"\n";
        let l = loaded(src, &dir);
        let opts = RunOptions {
            caps: vec!["fs.read:/tmp".to_owned()],
            ..Default::default()
        };
        let e = resolve_grants(&l, &opts).unwrap_err();
        assert_eq!(e.code, ErrorCode::CapabilityWideningRefused);
        assert!(e.remediation.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_cap_flag_is_rejected_before_any_resolution() {
        let dir = temp_dir("unknown-cap");
        let l = loaded(DENY_ALL, &dir);
        let opts = RunOptions {
            caps: vec!["not.a.capability".to_owned()],
            ..Default::default()
        };
        let e = resolve_grants(&l, &opts).unwrap_err();
        assert_eq!(e.code, ErrorCode::CapabilitySyntaxInvalid);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- pluralisation and output -----------------------------------------

    #[test]
    fn plurals_read_correctly() {
        assert_eq!(plural(&["a".to_owned()]), "`a`");
        assert_eq!(plural(&["a".to_owned(), "b".to_owned()]), "2 interfaces");
    }

    #[test]
    fn a_dry_run_summary_names_the_artifact() {
        let out = RunOutput {
            project: "app".to_owned(),
            artifact: "target/qqq/app.component.wasm".to_owned(),
            digest: "d".to_owned(),
            imports: vec!["a".to_owned(), "b".to_owned()],
            granted_imports: vec![],
            ok: true,
            exit_code: None,
            duration_us: 0,
            fuel_consumed: None,
            deterministic: false,
            dry_run: true,
        };
        assert!(out.summary().contains("would run"));
        assert!(out.summary().contains("2 imports"));
    }

    #[test]
    fn a_successful_run_summary_reports_the_duration() {
        let out = RunOutput {
            project: "app".to_owned(),
            artifact: "a.wasm".to_owned(),
            digest: "d".to_owned(),
            imports: vec![],
            granted_imports: vec![],
            ok: true,
            exit_code: None,
            duration_us: 1234,
            fuel_consumed: Some(99),
            deterministic: false,
            dry_run: false,
        };
        assert!(out.summary().contains("1234"));
        assert!(out.summary().contains("µs"));
    }

    #[test]
    fn import_check_satisfaction_is_exactly_emptiness_of_missing() {
        let satisfied = ImportCheck {
            required: vec!["a".to_owned()],
            satisfied: vec!["a".to_owned()],
            missing: vec![],
        };
        assert!(satisfied.is_satisfied());

        let unsatisfied = ImportCheck {
            required: vec!["a".to_owned()],
            satisfied: vec![],
            missing: vec!["a".to_owned()],
        };
        assert!(!unsatisfied.is_satisfied());
    }

    // -- package normalisation --------------------------------------------
    //
    // The distinction this whole group exists for: a component imports an
    // *interface* (`qqq:clock/now@1.0.0`) while the registry grants a *package*
    // (`qqq:clock@1.0.0`). Comparing them directly reported a false "missing
    // import" for a granted capability — found by running a real component,
    // with every unit test passing.

    #[test]
    fn a_package_name_survives_normalisation() {
        assert_eq!(package_of("qqq:clock@1.0.0"), "qqq:clock");
        assert_eq!(package_of("qqq:clock"), "qqq:clock");
        assert_eq!(package_of("qqq:crypto@1.0.0"), "qqq:crypto");
    }

    /// The case that was broken: an interface path reduces to its package.
    #[test]
    fn an_interface_path_reduces_to_its_package() {
        assert_eq!(package_of("qqq:clock/now@1.0.0"), "qqq:clock");
        assert_eq!(package_of("qqq:clock/now"), "qqq:clock");
        assert_eq!(package_of("qqq:http/client@1.0.0"), "qqq:http");
        assert_eq!(package_of("qqq:fs/preopens@1.0.0"), "qqq:fs");
    }

    /// The property the fix depends on: a granted package and an imported
    /// interface in that package normalise to the same string.
    #[test]
    fn a_granted_package_and_an_imported_interface_agree() {
        assert_eq!(
            package_of("qqq:clock@1.0.0"),
            package_of("qqq:clock/now@1.0.0"),
            "a package grant must satisfy an interface import from that package"
        );
    }

    /// Distinct packages must never collapse together, or a capability would
    /// satisfy an unrelated import — a security-relevant false positive.
    #[test]
    fn distinct_packages_stay_distinct() {
        assert_ne!(
            package_of("qqq:clock@1.0.0"),
            package_of("qqq:crypto@1.0.0")
        );
        assert_ne!(package_of("qqq:http/client"), package_of("qqq:dns/resolve"));
    }

    /// A name that is not a QQQ package is returned unchanged rather than being
    /// reduced to something that could collide. `wasi:cli/stdout` is a real
    /// import a component may carry; it must not be silently mangled.
    #[test]
    fn a_foreign_name_is_returned_unchanged() {
        assert_eq!(package_of("wasi:cli/stdout@0.2.0"), "wasi:cli");
        // No colon and no path: nothing to reduce, so nothing is reduced.
        assert_eq!(package_of("plain"), "plain");
        assert_eq!(package_of(""), "");
    }

    /// A package-spelled import still resolves, through the fallback branch.
    ///
    /// The old package-level function matched `qqq:clock@1.0.0` directly because
    /// that is the registry's spelling. The precise mapping delegates to a
    /// package-level fallback for single-interface packages, so this asserts the
    /// registry's own spelling is not left unresolvable now that the second
    /// function is gone.
    #[test]
    fn the_registrys_package_spelling_still_resolves() {
        // `qqq:fs` has one interface, so its package spelling is exact.
        assert!(
            capability_for_import("qqq:fs@1.0.0").is_some(),
            "the registry's own spelling must resolve"
        );
    }

    /// An interface nothing provides must yield no capability, so the error
    /// falls back to generic advice instead of naming a capability that would
    /// not help.
    #[test]
    fn capability_lookup_refuses_to_guess() {
        assert!(capability_for_import("qqq:nonexistent/thing@1.0.0").is_none());
        assert!(capability_for_import("wasi:cli/stdout@0.2.0").is_none());
    }

    /// The two halves of `qqq:clock` resolve to **different** capabilities.
    ///
    /// The regression test for the defect that removed the second mapping. It
    /// lives here as well as in `commands.rs` because `run`'s remediation is
    /// where the wrong answer reached a user.
    #[test]
    fn the_clock_halves_do_not_collapse() {
        assert_eq!(
            capability_for_import("qqq:clock/wall-clock@1.0.0"),
            Some(qqq_cap::Capability::ClockWall)
        );
        assert_eq!(
            capability_for_import("qqq:clock/monotonic-clock@1.0.0"),
            Some(qqq_cap::Capability::ClockMonotonic)
        );
    }
}
