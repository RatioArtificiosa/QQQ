// SPDX-License-Identifier: Apache-2.0

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

use qqq_cap::resolve::{GrantSet, Resolution};
use qqq_core::{Error, ErrorCode, Result};
use qqq_host::{EngineConfig, Instance, LimitSet, PreparedComponent};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::build::component_path;
use crate::manifest_loader::LoadedManifest;
use crate::output::{CommandName, CommandOutput};

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// How `qqqai run` was invoked.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunOptions {
    /// Explicit host-owned native cache directory.
    pub aot_cache: Option<PathBuf>,
    /// An explicit artifact to run, overriding the staged path.
    pub artifact: Option<PathBuf>,
    /// Write a replay file for this run — `DET-007`.
    ///
    /// Requires [`Self::deterministic`]. A log recorded with a real clock records nothing
    /// reproducible, so the pair is checked at parse time rather than left to a runtime refusal the
    /// user would never see.
    pub replay_log: Option<PathBuf>,
    /// Replay a recorded run instead of reading the clock and the RNG — `DET-008`.
    ///
    /// Requires [`Self::deterministic`], for the same reason and by the same check.
    pub replay: Option<PathBuf>,
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
    locate_artifact_with_root(loaded, opts, &crate::build::target_root(&project_dir))
}

/// The lookup above, with the Cargo target root passed in so tests stay hermetic.
///
/// # Why the split exists
///
/// The target root honours `CARGO_TARGET_DIR`, which is correct in production
/// but makes any test that goes through `locate_artifact` depend on the ambient
/// environment. Tests pass their own temp dir here instead.
///
/// # Errors
///
/// `QQQ-1002` when no artifact is found, naming every path tried.
pub fn locate_artifact_with_root(
    loaded: &LoadedManifest,
    opts: &RunOptions,
    target_root: &Path,
) -> Result<PathBuf> {
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
        candidates.push(crate::build::rust_artifact_path_in(
            target_root,
            "release",
            &loaded.manifest.build.target,
            name,
        ));
        candidates.push(crate::build::rust_artifact_path_in(
            target_root,
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
        } else if is_served_03_import(import, grants) {
            // The dual-ABI path (CON-019): a 0.3 import the host serves when
            // granted satisfies pre-flight exactly when the grant is present.
            // Package comparison cannot see it — no `qqq:` package covers a
            // `wasi:` name — so the capability mapping decides, and the grant
            // decides with it.
            satisfied.push(import.clone());
        } else if is_wasi02_baseline(import) {
            // CON-020: served by the retained 0.2 linker with no grant.
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

/// Whether an import is a 0.3 name the host serves **and** the grants cover.
///
/// The two halves are inseparable: the mapping alone would admit an ungranted
/// 0.3 import past pre-flight (and `Instance::create` would refuse it one
/// step later with a link error instead of this diagnostic), while the grant
/// alone would admit nothing — grants name capabilities, not interfaces.
/// Unserved names stay missing here. 0.2 WASI baseline names are admitted
/// separately by [`is_wasi02_baseline`] with no grant involved; routing one
/// through this grant check would demand a grant the runtime never checks.
fn is_served_03_import(interface: &str, grants: &GrantSet) -> bool {
    is_wasi03_revision(interface)
        && capability_for_import(interface).is_some_and(|c| grants.grants(c))
}

/// Whether an import is served by the WASI 0.2 baseline with no grant.
///
/// Exactly the set `qqq_host::host_wasi::register` links via
/// `wasmtime_wasi::p2::add_to_linker_sync`, minus `wasi:http`: HTTP has no
/// baseline registration (no `wasmtime-wasi-http` dependency links those
/// instances) and is mediated through `qqq:http` grants, so a 0.2 HTTP
/// import must stay missing and name itself.
///
/// Everything else 0.2 instantiates against the baseline and fails closed at
/// first use through the grant-derived context — no preopens, no network
/// permission, clocks denied unless granted, stdin closed — which is why
/// pre-flight admits the *name* here rather than demanding a grant the
/// runtime never checks. Sockets resolve at link time and are refused at
/// call time by wasmtime's default-deny network policy, which QQQ never
/// opts out of (no `inherit_network` / `allow_*` call exists in `host_wasi`).
#[must_use]
fn is_wasi02_baseline(interface: &str) -> bool {
    const BASELINE: &[&str] = &[
        "wasi:cli",
        "wasi:clocks",
        "wasi:filesystem",
        "wasi:io",
        "wasi:random",
        "wasi:sockets",
    ];
    let (package, version) = match interface.split_once('@') {
        Some((package, version)) => (package, Some(version)),
        None => (interface, None),
    };
    // A bare package names no instance the linker could serve: only a
    // package/interface path can match a registration.
    let (package, has_interface) = match package.split_once('/') {
        Some((package, _)) => (package, true),
        None => (package, false),
    };
    let version_ok = matches!(version, Some(v) if v.trim().starts_with("0.2."));
    has_interface && version_ok && package.starts_with("wasi:") && BASELINE.contains(&package)
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

    // The 0.3 set beside 0.2 (**ABI-017**): versioned WASI names resolve to
    // the same capabilities, never reinterpreted onto 0.2 implementations.
    // The version gate matters: the table names exact 0.3 revisions, and a
    // 0.2 WASI import (e.g. the `wasi:clocks/monotonic-clock@0.2.9` every
    // `wasm32-wasip2` `std` pulls in) is served by the *unconditional* WASI
    // baseline, not by any grant — resolving it here would demand a grant
    // the runtime never checks and break the reference application's
    // grants-exactly-what-it-imports proof. That proof still holds because
    // the mapping stays `None` for 0.2 (CON-020 admits baseline names at
    // pre-flight without a capability, it does not map them to one). An
    // unserved 0.3 name falls through to `None` below, which the caller
    // reports instead of guessing a capability that would not help.
    let wasi03: Vec<qqq_cap::Capability> = qqq_cap::Capability::all()
        .iter()
        .copied()
        .filter(|&c| {
            qqq_abi::registry::wasi03_interface_for(c)
                .is_some_and(|p| strip_version(p) == wanted && is_wasi03_revision(interface))
        })
        .collect();

    if !wasi03.is_empty() {
        return wasi03.into_iter().max_by_key(|c| exposure_rank(*c));
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

/// Whether an import declares a WASI 0.3 revision.
///
/// The 0.3 table (`wasi03_interface_for`) is compared version-stripped, so
/// without this gate a 0.2 WASI name would match a 0.3 row on the interface
/// path alone — reinterpreting a baseline-served import as a grant-backed
/// one. Only the `major.minor` prefix decides, mirroring
/// `AbiVersion::detect`: patch versions never change the shape.
#[must_use]
fn is_wasi03_revision(interface: &str) -> bool {
    interface
        .rsplit('@')
        .next()
        .is_some_and(|v| v.starts_with("0.3."))
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
    // Destructured rather than subscripted: the single-element shape carries
    // its own check, so no length test and index pair to drift apart.
    match items {
        [only] => format!("`{only}`"),
        _ => format!("{} interfaces", items.len()),
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

    crate::aot::check_grants(
        opts.aot_cache.as_deref(),
        &resolve_grants(loaded, opts)?.grants,
    )?;
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

/// How many nondeterministic reads a `qqqai run` replay log will hold — `DET-007`.
///
/// # Why a bound rather than a growing file
///
/// Because the log is written from the store's own reads, and the store belongs to a guest. **An
/// unbounded log is a guest-controlled allocation**, which is the thing `REPLAY_LOG_CAPACITY`'s
/// counterpart in `crate::audit` exists to prevent for the audit stream. 4096 is generous for a
/// one-shot `run` -- which instantiates and drops -- and small enough that a hostile guest gains
/// nothing by reading in a loop. A log that fills **refuses rather than overwrites**, so the first
/// records -- the ones a reader needs to reproduce the start -- survive, and
/// [`qqq_host::replay::AppendCounters::has_gaps`] says so in the file.
/// ```
/// use qqq_run::run::REPLAY_LOG_CAPACITY;
///
/// assert!(REPLAY_LOG_CAPACITY > 0, "a zero-capacity log records nothing");
/// ```
pub const REPLAY_LOG_CAPACITY: usize = 4096;

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
    crate::aot::configure(&mut wasmtime_cfg, opts.aot_cache.as_deref())?;
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

/// A replay log shared between the store that writes it and the runner that saves it.
///
/// # Why an alias and not the type spelled out
///
/// Because it appears four times in this file's signatures, and **`clippy::type_complexity` is
/// right for a reason a reader feels before a linter states it**: the alias is the thing that says
/// this is *one log seen from two places*, and the stacked generics say only that it is an `Arc` of a
/// `Mutex` of a `ReplayLog`. The name carries the intent the type does not.
type SharedLog = std::sync::Arc<std::sync::Mutex<qqq_host::replay::ReplayLog>>;

/// The identity a replay source must match before any recorded value is consumed.
///
/// The file format verifies its own chain, but chain integrity only proves that the
/// file was not edited after it was written. It does not prove that the file belongs
/// to this artifact or this engine. Keeping construction in one helper prevents the
/// recording and replay paths from silently acquiring different identity rules.
fn replay_header(digest: &str, deterministic: bool) -> qqq_host::replay::ReplayHeader {
    qqq_host::replay::ReplayHeader {
        artifact_digest: digest.to_owned(),
        engine_version: qqq_host::config::ENGINE_VERSION.to_owned(),
        target_triple: qqq_host::config::TARGET_TRIPLE.to_owned(),
        deterministic,
    }
}

/// The replay sink and source a run needs, from its options — `DET-007` and `DET-008`.
///
/// # Why this is a separate function
///
/// Because it is the one part of a run that is about *evidence* rather than execution, and
/// `execute` crossed `clippy`'s line budget when it was inlined. The split is by subject: this
/// builds two optional endpoints and refuses a file it cannot trust, and none of that needs the
/// engine, the grants or the limits.
///
/// # Why the header names the artifact and the engine
///
/// `DET-010` names four inputs that decide whether two recorded runs are comparable: the artifact
/// digest, the engine version, the target triple and the configuration. Three of them are read from
/// the component and the build rather than from the user, because **a header a user could fill in
/// is a header a user could fill in wrongly**, and its whole purpose is to be believed.
///
/// # Errors
///
/// `QQQ-1002` when the replay file cannot be read or does not verify.
/// Read a replay file with the format's own byte limit enforced.
///
/// The file is attacker-supplied by construction, so `read_to_string`
/// on it is an unbounded allocation. Taking one byte past
/// [`qqq_host::replay::REPLAY_FILE_MAX_BYTES`] and refusing past it is
/// deterministic: no check-then-read race, no partial content accepted.
///
/// # Errors
///
/// `QQQ-1002` when the file cannot be opened or read, or exceeds the limit.
fn read_replay_file(path: &Path) -> Result<String> {
    let open_err = |e: std::io::Error| {
        Error::new(
            ErrorCode::InvalidComponentArtifact,
            format!(
                "the replay file `{}` could not be read: {e}",
                path.display()
            ),
        )
        .with_remediation(
            "`--replay` takes the path `--replay-log` wrote; check it exists and is readable",
        )
    };
    let file = std::fs::File::open(path).map_err(open_err)?;
    // Bytes first, text second: a file past the limit that ends mid-char
    // must report "exceeds", not "could not be read" — the truncation is
    // ours (we stopped at limit+1), not corruption in the file.
    let mut bytes = Vec::new();
    file.take(qqq_host::replay::REPLAY_FILE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(open_err)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > qqq_host::replay::REPLAY_FILE_MAX_BYTES {
        return Err(Error::new(
            ErrorCode::InvalidComponentArtifact,
            format!(
                "the replay file `{}` exceeds the {}-byte limit",
                path.display(),
                qqq_host::replay::REPLAY_FILE_MAX_BYTES
            ),
        )
        .with_remediation(
            "re-record it with `--replay-log`; this build never writes larger files",
        ));
    }
    let text = String::from_utf8(bytes).map_err(|e| {
        Error::new(
            ErrorCode::InvalidComponentArtifact,
            format!(
                "the replay file `{}` is not valid UTF-8: {e}",
                path.display()
            ),
        )
        .with_remediation("re-record it with `--replay-log`")
    })?;
    Ok(text)
}

fn replay_endpoints(
    opts: &RunOptions,
    digest: &str,
) -> Result<(Option<SharedLog>, Option<SharedLog>)> {
    //
    // **The log is built here because the header has to name the artifact and the engine**, and this
    // is the last point at which both are in hand. `DET-010` names the four inputs that decide whether
    // two runs are comparable, and three of them -- digest, engine version, target triple -- are read
    // from the component and the build rather than from the user.
    let replay_sink = opts.replay_log.as_ref().map(|_| {
        std::sync::Arc::new(std::sync::Mutex::new(qqq_host::replay::ReplayLog::new(
            replay_header(digest, opts.deterministic),
            REPLAY_LOG_CAPACITY,
        )))
        // A log of a non-deterministic run is not a contradiction to refuse silently: the parser
        // already refused the combination, so reaching here with one is a bug in this function
        // rather than a user error. `AmbientState` refuses the sink in that case, and the file would
        // be an empty header -- which is why the check below is a hard one.
    });
    let replay_source = match &opts.replay {
        None => None,
        Some(path) => {
            let text = read_replay_file(path)?;
            // **A file that does not verify is refused rather than partly used.** The chain is
            // re-derived on load, so an edit, a deletion or a rewritten link is a failure here and
            // not a run that silently reproduces something else.
            let log = qqq_host::replay::ReplayLog::from_text(&text).map_err(|e| {
                qqq_core::Error::new(
                    qqq_core::ErrorCode::InvalidComponentArtifact,
                    format!("the replay file `{}` is not usable: {e}", path.display()),
                )
                .with_remediation(
                    "a replay file this build did not write, or one edited since, is refused; \
                     re-record it with `--replay-log`",
                )
            })?;
            let expected = replay_header(digest, opts.deterministic);
            let mismatches = expected.mismatches(log.header());
            if !mismatches.is_empty() {
                return Err(qqq_core::Error::new(
                    qqq_core::ErrorCode::InvalidComponentArtifact,
                    format!(
                        "the replay file `{}` belongs to different execution conditions",
                        path.display()
                    ),
                )
                .with_context("header_mismatches", mismatches.join(", "))
                .with_context("expected_artifact_digest", expected.artifact_digest)
                .with_context(
                    "recorded_artifact_digest",
                    log.header().artifact_digest.clone(),
                )
                .with_context("expected_engine_version", expected.engine_version)
                .with_context(
                    "recorded_engine_version",
                    log.header().engine_version.clone(),
                )
                .with_context("expected_target_triple", expected.target_triple)
                .with_context("recorded_target_triple", log.header().target_triple.clone())
                .with_context("expected_deterministic", expected.deterministic.to_string())
                .with_context(
                    "recorded_deterministic",
                    log.header().deterministic.to_string(),
                )
                .with_remediation(
                    "re-record the replay with `--replay-log` using this artifact, engine, \
                     target, and deterministic setting",
                ));
            }
            Some(std::sync::Arc::new(std::sync::Mutex::new(log)))
        }
    };

    Ok((replay_sink, replay_source))
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

    // -- The ambient mode, and the replay log that carries it (DET-007, DET-008) ---
    let (replay_sink, replay_source) = replay_endpoints(opts, p.component.digest())?;

    // A literal rather than a `Default` plus an assignment, so the one field that is not optional
    // is set where a reader sees it beside the others.
    let mut inst_opts = qqq_host::InstanceOptions {
        deterministic: opts.deterministic,
        // The manifest's allowlist becomes the connector's policy: without
        // this line every `send` in `qqqai run` would meet the deny-all
        // default. The serve path (`GuestApp`) carries grants only, so its
        // manifest-to-policy threading is scheduled serve-integration work.
        egress: qqq_cap::egress::TenantEgress::from_manifest(&loaded.manifest),
        ..qqq_host::InstanceOptions::default()
    };
    // The manifest's secret references become material: without this line
    // every `secret.use` in `qqqai run` would meet an empty store and fail
    // `unavailable`. Resolution reads the process environment once, here —
    // never per call — and a missing variable fails the run naming it.
    inst_opts.secrets = crate::secrets::resolve_secret_store(&loaded.manifest, &|name| {
        std::env::var_os(name).map(|v| v.as_os_str().as_encoded_bytes().to_vec())
    })?;
    // The manifest's allowlist becomes the guest-visible environment: values
    // resolved once here (unset names stay absent, which the guest observes
    // as `unset`), never per call.
    inst_opts.env = crate::env::resolve_env_map(&loaded.manifest, &|name| {
        std::env::var_os(name).map(|v| v.as_os_str().as_encoded_bytes().to_vec())
    });
    // The manifest's store list becomes the guest-visible kv allowlist,
    // resolved once here; the backend is fresh per run, like the instance.
    inst_opts.kv = crate::kv::view_for_manifest(&loaded.manifest);
    // The manifest's queue list becomes the guest-visible queue allowlist,
    // resolved once here; the backend is fresh per run, like the instance.
    inst_opts.queue = crate::queue::view_for_manifest(&loaded.manifest);
    if let Some(log) = &replay_sink {
        inst_opts.record_to(std::sync::Arc::clone(log));
    }
    if let Some(log) = &replay_source {
        inst_opts.replay_from(std::sync::Arc::clone(log));
    }

    let instance = Instance::create_with(
        &p.engine,
        &p.component,
        &p.resolution.grants,
        limits,
        &inst_opts,
    )?;

    let started = Instant::now();
    let mut guest_logs = Vec::new();
    let outcome = instance.run_measured(|store, _instance| {
        // A component with no exported entry point still instantiates and
        // drops, which is a meaningful check in itself: it proves every import
        // resolved and every limit applied. Calling a specific export is the
        // job of `qqqai serve` and the entrypoint declared in the manifest;
        // guessing an export name here would make `run` succeed or fail for
        // reasons unrelated to the capability model.
        guest_logs = std::mem::take(&mut store.data_mut().logs);
        Ok(RunOutcome::Instantiated)
    });
    // Guest logs go to stderr, never stdout: stdout carries the run's own
    // output and mixing the two would corrupt piped consumers.
    for record in &guest_logs {
        eprintln!("qqq:log {}", qqq_host::host_log::format_record(record));
    }
    let elapsed = started.elapsed();

    // -- Write the log, if one was asked for (DET-007) ------------------
    //
    // Written after the run rather than streamed, because a replay file is only useful if it is
    // complete: a partial file would describe an execution that did not happen, and `from_text`
    // would refuse it at replay time with `Exhausted` -- a failure a reader cannot see coming.
    if let (Some(path), Some(log)) = (&opts.replay_log, &replay_sink) {
        let text = log.lock().map(|l| l.to_text()).map_err(|_| {
            qqq_core::Error::new(
                qqq_core::ErrorCode::InternalInvariantViolated,
                "the replay log's lock was poisoned by a panic elsewhere",
            )
        })?;
        std::fs::write(path, text.as_bytes()).map_err(|e| {
            qqq_core::Error::new(
                qqq_core::ErrorCode::InvalidComponentArtifact,
                format!(
                    "the replay file `{}` could not be written: {e}",
                    path.display()
                ),
            )
            .with_remediation("--replay-log takes a path this process can write")
        })?;
    }

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
            assert!(
                e.remediation
                    .as_deref()
                    .unwrap_or("")
                    .contains("lowercase dotted pairs")
            );
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
        let e = locate_artifact_with_root(&l, &RunOptions::default(), &dir).unwrap_err();
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

        let cargo = crate::build::rust_artifact_path_in(&dir, "release", "wasm32-wasip2", "app");
        std::fs::create_dir_all(cargo.parent().unwrap()).unwrap();
        std::fs::write(&cargo, b"\0asm\x01\0\0\0").unwrap();

        let l = loaded(DENY_ALL, &dir);
        assert_eq!(
            locate_artifact_with_root(&l, &RunOptions::default(), &dir).unwrap(),
            staged
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no staged artifact, Cargo's output is still usable — so `run` works
    /// straight after a manual `cargo build`.
    #[test]
    fn the_cargo_output_is_used_when_nothing_is_staged() {
        let dir = temp_dir("fallback-cargo");
        let cargo = crate::build::rust_artifact_path_in(&dir, "release", "wasm32-wasip2", "app");
        std::fs::create_dir_all(cargo.parent().unwrap()).unwrap();
        std::fs::write(&cargo, b"\0asm\x01\0\0\0").unwrap();

        let l = loaded(DENY_ALL, &dir);
        assert_eq!(
            locate_artifact_with_root(&l, &RunOptions::default(), &dir).unwrap(),
            cargo
        );
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

    /// **ABI-017** — a 0.3 import resolves to the same capability as its 0.2
    /// twin, and an unserved 0.3 name resolves to nothing.
    ///
    /// `wasi:clocks/monotonic-clock@0.3.2` needs `clock.monotonic` — the grant
    /// the 0.3 host path checks — while `wasi:http/incoming-handler@0.3.2`
    /// names an interface no table serves and must stay unmapped so the
    /// caller reports it instead of guessing a capability that would not help.
    #[test]
    fn wasi03_clock_import_resolves_to_the_monotonic_capability() {
        use qqq_cap::Capability;
        assert_eq!(
            capability_for_import("wasi:clocks/monotonic-clock@0.3.2"),
            Some(Capability::ClockMonotonic)
        );
        assert_eq!(
            capability_for_import("wasi:http/incoming-handler@0.3.2"),
            None
        );
    }

    /// **ABI-017, the negative half**: a 0.2 WASI clock must not resolve
    /// through the 0.3 table.
    ///
    /// Regression test for the reinterpretation the first revision shipped:
    /// version-stripped comparison matched `wasi:clocks/monotonic-clock@0.2.9`
    /// (which every `wasm32-wasip2` `std` pulls in, and which the
    /// *unconditional* WASI baseline serves) against the 0.3 row, demanding
    /// a grant the runtime never checks and breaking the reference
    /// application's grants-exactly-what-it-imports proof (`lang005`). The
    /// 0.3 mapping is revision-gated; 0.2 WASI names stay unmapped.
    #[test]
    fn wasi02_clock_does_not_resolve_through_the_03_table() {
        use qqq_cap::Capability;
        assert_eq!(
            capability_for_import("wasi:clocks/monotonic-clock@0.2.9"),
            None
        );
        // Patch releases never change the shape, so any 0.3.x resolves —
        // the same rule `AbiVersion::detect` routes by.
        assert_eq!(
            capability_for_import("wasi:clocks/monotonic-clock@0.3.0"),
            Some(Capability::ClockMonotonic)
        );
    }

    /// A 0.3 guest for pre-flight tests: imports only the served 0.3 clock.
    ///
    /// The same shape the dual-ABI integration suite drives through the real
    /// linker, reduced to the import under test — pre-flight reads imports,
    /// never executes, so the core module is intentionally empty.
    const GUEST_03_CLOCK_WAT: &str = r#"(component
      (import "wasi:clocks/monotonic-clock@0.3.2" (instance $clock
        (export "now" (func (result u64)))))
      (core module $m)
      (core instance $i (instantiate $m))
    )"#;

    /// **CON-019** — pre-flight admits a served 0.3 import when granted.
    ///
    /// Red-first: `check_imports` matches `qqq:` packages only, so the 0.3
    /// clock lands in `missing` and `run` refuses a guest the host would
    /// serve. The fix consults the capability mapping *and* the grant — the
    /// mapping alone would admit ungranted guests past pre-flight (refused
    /// one step later with a link error instead of this diagnostic), while
    /// the grant alone admits nothing.
    #[test]
    fn check_imports_satisfies_a_granted_03_clock() {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&config).expect("engine builds");
        let bytes = wat::parse_str(GUEST_03_CLOCK_WAT).expect("fixture must assemble");
        let prepared = PreparedComponent::compile(&engine, &bytes).expect("fixture must compile");
        let manifest = qqq_cap::manifest::Manifest::parse(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.clock]\nmonotonic = true\n",
        )
        .expect("fixture manifest parses");
        let check = check_imports(&prepared, &engine, &GrantSet::from_manifest(&manifest));
        assert!(
            check.is_satisfied(),
            "a granted 0.3 import must satisfy pre-flight: {check:?}"
        );
        assert!(check.missing.is_empty());
    }

    /// **CON-019** — pre-flight refuses an ungranted 0.3 import by name.
    ///
    /// The fail-closed half at the CLI boundary: the missing list must name
    /// the 0.3 import (so `import_error` can point at `clock.monotonic` and
    /// its stanza), never silently drop it or reinterpret it onto 0.2.
    #[test]
    fn check_imports_reports_an_ungranted_03_clock_as_missing() {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&config).expect("engine builds");
        let bytes = wat::parse_str(GUEST_03_CLOCK_WAT).expect("fixture must assemble");
        let prepared = PreparedComponent::compile(&engine, &bytes).expect("fixture must compile");
        let check = check_imports(&prepared, &engine, &GrantSet::empty());
        assert!(!check.is_satisfied());
        assert!(
            check
                .missing
                .iter()
                .any(|i| i.contains("wasi:clocks/monotonic-clock@0.3.2")),
            "the 0.3 import must be reported missing by name: {:?}",
            check.missing
        );
    }

    /// **CON-020** — pre-flight admits 0.2 WASI baseline names with no grant.
    ///
    /// Supersedes the CON-019 pin that kept them missing: the 0.2 clock is
    /// served by the unconditional baseline with no grant involved, so
    /// demanding a grant (or reporting the name missing) described a refusal
    /// the runtime never performs. The 0.3 gate is untouched — this test uses
    /// an empty grant set to prove no grant is involved at all.
    #[test]
    fn check_imports_satisfies_02_wasi_baseline_names() {
        const GUEST_02_CLOCK_WAT: &str = r#"(component
          (import "wasi:clocks/monotonic-clock@0.2.9" (instance $clock
            (export "now" (func (result u64)))))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&config).expect("engine builds");
        let bytes = wat::parse_str(GUEST_02_CLOCK_WAT).expect("fixture must assemble");
        let prepared = PreparedComponent::compile(&engine, &bytes).expect("fixture must compile");
        let check = check_imports(&prepared, &engine, &GrantSet::empty());
        assert!(
            check.is_satisfied(),
            "the 0.2 baseline needs no grant: {:?}",
            check.missing
        );
    }

    /// **CON-020** — pre-flight admits the 0.2 WASI baseline without a grant.
    ///
    /// Red-first: `check_imports` knows only `qqq:` packages, so a normal
    /// `wasm32-wasip2` guest lands entirely in `missing` and `qqqai run`
    /// refuses with QQQ-6003 before instantiation — even though the retained
    /// 0.2 linker serves every one of these names (§O-782). The fix admits
    /// exactly the baseline set; the grant-derived context still governs
    /// what the names can *do*.
    #[test]
    fn check_imports_satisfies_wasi02_baseline_without_grants() {
        const GUEST_02_BASELINE_WAT: &str = r#"(component
          (import "wasi:clocks/monotonic-clock@0.2.9" (instance $clock
            (export "now" (func (result u64)))))
          (import "wasi:random/random@0.2.9" (instance $random
            (export "get-random-bytes" (func (param "len" u64) (result (list u8))))))
          (import "wasi:cli/environment@0.2.9" (instance $env
            (export "get-environment" (func (result (list (tuple string string)))))))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&config).expect("engine builds");
        let bytes = wat::parse_str(GUEST_02_BASELINE_WAT).expect("fixture must assemble");
        let prepared = PreparedComponent::compile(&engine, &bytes).expect("fixture must compile");
        let check = check_imports(&prepared, &engine, &GrantSet::empty());
        assert!(
            check.is_satisfied(),
            "baseline 0.2 imports need no grant: {:?}",
            check.missing
        );
    }

    /// **CON-020** — `wasi:http` 0.2 names stay missing: HTTP has no baseline
    /// registration (no `wasmtime-wasi-http` dependency links those
    /// instances) and is mediated through `qqq:http` grants. Admitting it
    /// here would promise an instantiation the linker cannot deliver.
    #[test]
    fn check_imports_reports_wasi02_http_as_missing() {
        const GUEST_02_HTTP_WAT: &str = r#"(component
          (import "wasi:http/outgoing-handler@0.2.0" (instance $http
            (export "handle" (func))))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&config).expect("engine builds");
        let bytes = wat::parse_str(GUEST_02_HTTP_WAT).expect("fixture must assemble");
        let prepared = PreparedComponent::compile(&engine, &bytes).expect("fixture must compile");
        let check = check_imports(&prepared, &engine, &GrantSet::empty());
        assert!(
            check
                .missing
                .iter()
                .any(|i| i.contains("wasi:http/outgoing-handler@0.2.0")),
            "unserved 0.2 HTTP must be reported missing by name: {:?}",
            check.missing
        );
    }

    /// **CON-020** — the baseline classifier covers exactly the served set.
    ///
    /// Unit-level pin so a future registration (or removal) forces this table
    /// to move with it: the set must mirror what `host_wasi::register` links
    /// via `wasmtime_wasi::p2::add_to_linker_sync`, nothing more.
    #[test]
    fn baseline_classifier_covers_exactly_the_served_packages() {
        for package in [
            "wasi:cli",
            "wasi:clocks",
            "wasi:filesystem",
            "wasi:io",
            "wasi:random",
            "wasi:sockets",
        ] {
            assert!(
                is_wasi02_baseline(&format!("{package}/x@0.2.9")),
                "{package} is linked by the 0.2 baseline"
            );
        }
        for name in [
            "wasi:http/outgoing-handler@0.2.0",
            "wasi:http/incoming-handler@0.2.0",
            "wasi:keyvalue/store@0.2.0",
            "wasi:config/store@0.2.0",
            "wasi:clocks/monotonic-clock@0.3.2",
            "wasi:cli/stdout@1.0.0",
            "wasi:cli",
            "wasi:cli@0.2.9",
            "qqq:clock@1.0.0",
        ] {
            assert!(
                !is_wasi02_baseline(name),
                "{name} is not baseline and must not be admitted by it"
            );
        }
    }

    /// The two halves of `qqq:clock` resolve to **different** capabilities.
    ///
    /// The regression test for the defect that removed the second mapping. It
    /// lives here as well as in `commands.rs` because `run`'s remediation is
    /// where the wrong answer reached a user.
    /// A run with neither replay flag gets no endpoints at all, so `InstanceOptions::default()` is what
    /// an ordinary `qqqai run` still passes and no evidence file is written unasked.
    #[test]
    fn no_replay_flags_means_no_endpoints() {
        let opts = RunOptions::default();
        let (sink, source) = replay_endpoints(&opts, "sha256:abc").expect("no flags, no failure");
        assert!(sink.is_none(), "a sink is opt-in");
        assert!(source.is_none(), "and so is a source");
    }

    /// **The header names the artifact and the engine rather than the user** — `DET-010`.
    ///
    /// Three of the four comparability inputs come from the component and the build, and this asserts the
    /// two that a caller supplies: the digest it was handed, and the triple compiled in. **A header a user
    /// could fill in is a header a user could fill in wrongly**, and its whole purpose is to be believed.
    #[test]
    fn the_replay_sink_header_names_the_artifact_and_the_engine() {
        let opts = RunOptions {
            deterministic: true,
            replay_log: Some(temp_dir("replay-header").join("one.replay")),
            ..RunOptions::default()
        };
        let (sink, source) = replay_endpoints(&opts, "sha256:9f2c").expect("a sink");
        assert!(source.is_none());
        let log = sink.expect("a sink was asked for");
        let log = log.lock().expect("log");
        assert_eq!(log.header().artifact_digest, "sha256:9f2c");
        assert_eq!(
            log.header().engine_version,
            qqq_host::config::ENGINE_VERSION
        );
        assert_eq!(log.header().target_triple, qqq_host::config::TARGET_TRIPLE);
        assert!(log.header().deterministic);
        // And the triple is a real triple, not a `cfg` approximation: `x86_64-windows` would be missing
        // the vendor and the ABI, which is exactly what makes a `.cwasm` valid or not.
        assert!(
            log.header().target_triple.matches('-').count() >= 2,
            "a triple has at least arch-vendor-os, got `{}`",
            log.header().target_triple
        );
    }

    /// A file this crate wrote is accepted, and the values come back.
    #[test]
    fn a_written_log_replays_through_the_source() {
        let dir = temp_dir("replay-source");
        let path = dir.join("one.replay");
        let opts = RunOptions {
            deterministic: true,
            replay_log: Some(path.clone()),
            ..RunOptions::default()
        };
        let (sink, _) = replay_endpoints(&opts, "sha256:9f2c").expect("a sink");
        // Bound once: `Option::expect` consumes, and calling it twice was the first version's error.
        let sink = sink.expect("a sink");
        sink.lock()
            .expect("log")
            .record("clock.wall", qqq_host::replay::ReplayValue::Clock(7))
            .expect("room");
        let text = sink.lock().expect("log").to_text();
        std::fs::write(&path, text.as_bytes()).expect("write");

        let replay_opts = RunOptions {
            deterministic: true,
            replay: Some(path),
            ..RunOptions::default()
        };
        let (sink, source) = replay_endpoints(&replay_opts, "sha256:9f2c").expect("a source");
        assert!(sink.is_none(), "replaying is not recording");
        let source = source.expect("a source");
        assert_eq!(
            source
                .lock()
                .expect("log")
                .next_record("clock.wall")
                .expect("recorded"),
            qqq_host::replay::ReplayValue::Clock(7)
        );
    }

    /// **A file that does not verify is refused, and the message says why.** The chain is re-derived on
    /// load, so an edit is a failure here rather than a run that silently reproduces something else.
    #[test]
    fn a_tampered_log_is_refused_with_its_cause() {
        let dir = temp_dir("replay-tampered");
        let path = dir.join("one.replay");
        let opts = RunOptions {
            deterministic: true,
            replay_log: Some(path.clone()),
            ..RunOptions::default()
        };
        let (sink, _) = replay_endpoints(&opts, "sha256:9f2c").expect("a sink");
        let log = sink.expect("a sink");
        log.lock()
            .expect("log")
            .record("clock.wall", qqq_host::replay::ReplayValue::Clock(7))
            .expect("room");
        // Edit the value and leave the chain as written.
        let edited = log.lock().expect("log").to_text().replacen(" 7 ", " 8 ", 1);
        assert!(edited.contains(" 8 "), "the edit must have landed");
        std::fs::write(&path, edited.as_bytes()).expect("write");

        let replay_opts = RunOptions {
            deterministic: true,
            replay: Some(path),
            ..RunOptions::default()
        };
        let err = replay_endpoints(&replay_opts, "sha256:9f2c").expect_err("a tampered file");
        let rendered = err.render();
        assert!(
            rendered.contains("chain") || rendered.contains("edited"),
            "the refusal must name the edit, got: {rendered}"
        );
    }

    /// **An oversized replay file is refused without loading it.** The read
    /// takes one byte past the format limit and refuses past it, so a bulk
    /// file costs one bounded read, never an allocation it sized.
    #[test]
    fn an_oversized_replay_file_is_refused_without_loading() {
        let dir = temp_dir("replay-oversized");
        let path = dir.join("big.replay");
        let bulk =
            vec![b'x'; usize::try_from(qqq_host::replay::REPLAY_FILE_MAX_BYTES).expect("fits") + 1];
        std::fs::write(&path, bulk).expect("write");
        let err = read_replay_file(&path).expect_err("bulk must be refused");
        assert!(
            err.to_string().contains("exceeds"),
            "the refusal must name the limit: {err}"
        );
        // A missing file still reports readability, not the limit.
        let missing = dir.join("absent.replay");
        let err = read_replay_file(&missing).expect_err("absent must be refused");
        assert!(
            err.to_string().contains("could not be read"),
            "absent reports readability: {err}"
        );
        // A file past the limit that ends mid-char reports the limit, not
        // a decode failure — the truncation is the reader's own doing.
        let split = dir.join("split.replay");
        let mut bulk =
            vec![b'x'; usize::try_from(qqq_host::replay::REPLAY_FILE_MAX_BYTES).expect("fits")];
        bulk.push(0xC3);
        std::fs::write(&split, bulk).expect("write");
        let err = read_replay_file(&split).expect_err("over-limit must be refused");
        assert!(
            err.to_string().contains("exceeds"),
            "over-limit reports the limit even mid-char: {err}"
        );
        // A small file with bad encoding reports text, not readability.
        let bad = dir.join("bad.replay");
        std::fs::write(&bad, [0xFF]).expect("write");
        let err = read_replay_file(&bad).expect_err("bad encoding must be refused");
        assert!(
            err.to_string().contains("UTF-8"),
            "bad encoding names itself: {err}"
        );
    }

    /// Chain integrity and header identity are separate checks. A header can be
    /// changed without changing the record chain, so each identity field must be
    /// rejected independently before the source is attached to an instance.
    #[test]
    fn a_replay_with_the_wrong_identity_is_refused_before_consumption() {
        let fields = [
            ("artifact_digest", "sha256:other"),
            ("engine_version", "other-engine"),
            ("target_triple", "other-target"),
            ("deterministic", "false"),
        ];

        for (key, replacement) in fields {
            let dir = temp_dir("replay-header-mismatch");
            let path = dir.join("one.replay");
            let opts = RunOptions {
                deterministic: true,
                replay_log: Some(path.clone()),
                ..RunOptions::default()
            };
            let (sink, _) = replay_endpoints(&opts, "sha256:9f2c").expect("a sink");
            let sink = sink.expect("a sink");
            sink.lock()
                .expect("log")
                .record("clock.wall", qqq_host::replay::ReplayValue::Clock(7))
                .expect("room");
            let text = sink.lock().expect("log").to_text();
            let prefix = format!("{key} ");
            let edited = text
                .lines()
                .map(|line| {
                    if line.starts_with(&prefix) {
                        format!("{prefix}{replacement}")
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            std::fs::write(&path, edited).expect("write");

            let replay_opts = RunOptions {
                deterministic: true,
                replay: Some(path),
                ..RunOptions::default()
            };
            let err = replay_endpoints(&replay_opts, "sha256:9f2c")
                .expect_err("a mismatched header must be refused");
            let rendered = err.render();
            assert!(
                rendered.contains("header_mismatches") && rendered.contains(key),
                "the refusal must name {key}, got: {rendered}"
            );
            if key == "deterministic" {
                assert!(
                    rendered.contains("expected_deterministic")
                        && rendered.contains("recorded_deterministic"),
                    "a mode mismatch must carry both sides, got: {rendered}"
                );
            }
        }
    }

    /// The control for the refusal tests above: a log recorded by this build,
    /// unedited, must be accepted as a source.
    ///
    /// Without this, the identity check could refuse everything — including the
    /// replay it was written to admit — and every test above would still pass.
    /// A gate that only refuses is a gate that is always shut.
    #[test]
    fn a_replay_with_matching_identity_is_accepted() {
        let dir = temp_dir("replay-matching-identity");
        let path = dir.join("one.replay");
        let opts = RunOptions {
            deterministic: true,
            replay_log: Some(path.clone()),
            ..RunOptions::default()
        };
        let (sink, _) = replay_endpoints(&opts, "sha256:9f2c").expect("a sink");
        let sink = sink.expect("a sink");
        sink.lock()
            .expect("log")
            .record("clock.wall", qqq_host::replay::ReplayValue::Clock(7))
            .expect("room");
        let text = sink.lock().expect("log").to_text();
        std::fs::write(&path, text.as_bytes()).expect("write");

        let replay_opts = RunOptions {
            deterministic: true,
            replay: Some(path),
            ..RunOptions::default()
        };
        let (_, source) = replay_endpoints(&replay_opts, "sha256:9f2c")
            .expect("a matching replay must be accepted");
        assert!(source.is_some(), "the accepted log must become a source");
    }

    /// A path that cannot be read is a failure, not a silent `None`.
    #[test]
    fn an_unreadable_replay_path_is_refused() {
        let opts = RunOptions {
            deterministic: true,
            replay: Some(temp_dir("replay-missing").join("nothing.replay")),
            ..RunOptions::default()
        };
        assert!(
            replay_endpoints(&opts, "sha256:9f2c").is_err(),
            "a missing file must fail rather than run against the real clock"
        );
    }

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
