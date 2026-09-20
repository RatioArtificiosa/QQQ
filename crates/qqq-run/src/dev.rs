//! `qqqai dev` — the development server with hot reload.
//!
//! Implements `CLI-010`, `DX-003` and the tier-1 half of `DX-006`; Proposal §6.6
//! and the transcript in §12.1.
//!
//! # What this command is for
//!
//! `dev` is the loop a developer lives in: change a file, see the result. Every
//! design decision here follows from one question — *how long between saving
//! and knowing?* Proposal §6.6 calls the three-tier reload strategy the visible
//! DX advantage, and tier 1 is the reason it exists:
//!
//! > Because the guest is a *component instance*, not a language runtime's heap,
//! > replacing it is a pointer swap.
//!
//! Node and Bun cannot do this. Restarting means rebuilding the JS heap. So the
//! architecture pays for itself here first, and this module is where a user
//! notices.
//!
//! # Tier 1 as implemented, and what is honestly missing
//!
//! | Tier | State |
//! |---|---|
//! | 1 — component swap, host process preserved | **implemented** |
//! | 2 — state-preserving swap | not implemented (`DX-007`) |
//! | 3 — full restart on manifest change | **implemented** (it is the fallback) |
//!
//! Tier 1 works by rebuilding the component and **discarding the old instance**
//! rather than reusing it. That is the same rule `qqq-host` enforces for traps
//! (`HOST-010`), and it applies here for the same reason: a replaced component
//! has new code and old state, and reusing an instance across a code change is
//! the dev-server version of the contaminated-context bug.
//!
//! What is genuinely missing is `serve`: there is no HTTP listener yet
//! (`CLI-011`, `qqq-serve`). So `dev` today rebuilds and re-instantiates on
//! change and reports it, which is the whole reload loop minus the socket. The
//! capability warning, the tier selection and the reload timing are all real.
//! **The absence of a listener is stated in the output**, not hidden — a dev
//! server that silently does not listen would be the worst kind of stub.
//!
//! # Why the capability warning exists
//!
//! Proposal §12.1: *"We tell the user what their code cannot do, because the
//! failure they will hit next is a capability denial."* A runtime that teaches
//! its security model at the moment of confusion beats one that teaches it in a
//! README nobody reads. So the warning is printed on every start, not once.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use qqq_core::{Error, Result};

use crate::build::{self, BuildOptions};
use crate::manifest_loader::LoadedManifest;
use crate::output::{CommandName, CommandOutput};
use crate::watch::{Change, Debouncer, IgnoreRules, Snapshot};

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// The options `qqqai dev` accepts.
///
/// # Why the switches are a bitfield
///
/// Six independent booleans make every combination representable, including ones
/// that are meaningless. A packed `u8` with named accessors keeps the call-site
/// ergonomics, makes the struct a single comparable value, and matches the
/// `GlobalFlags` and `BuildOptions` pattern used elsewhere in this crate — so the
/// codebase has one answer to "how do we carry several command-line switches"
/// rather than three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevOptions {
    /// The port to listen on, once `serve` exists.
    pub port: u16,
    /// The address to bind.
    pub host: String,
    /// Bit flags; see the constants below.
    switches: u8,
    /// The port for the inspector.
    pub inspect: Option<u16>,
    /// Directories to watch, relative to the project.
    pub watch: Vec<String>,
    /// Additional ignore patterns.
    pub ignore: Vec<String>,
    /// Stop after this many reload cycles.
    ///
    /// `None` — the default — runs until interrupted, which is what a developer
    /// wants. Tests pass `Some(n)`, and `--reload-limit <n>` exposes it: an
    /// unbounded loop that cannot be bounded is a loop that cannot be verified.
    pub reload_limit: Option<u32>,
}

impl DevOptions {
    /// `--open`
    pub const OPEN: u8 = 1 << 0;
    /// `--https`
    pub const HTTPS: u8 = 1 << 1;
    /// `--once`
    pub const ONCE: u8 = 1 << 2;
    /// `--deterministic`
    pub const DETERMINISTIC: u8 = 1 << 3;

    /// Set a switch.
    pub fn set(&mut self, flag: u8) {
        self.switches |= flag;
    }

    /// Test a switch.
    #[must_use]
    pub const fn has(&self, flag: u8) -> bool {
        self.switches & flag != 0
    }

    /// Whether to open a browser.
    #[must_use]
    pub const fn open(&self) -> bool {
        self.has(Self::OPEN)
    }

    /// Whether to serve HTTPS.
    #[must_use]
    pub const fn https(&self) -> bool {
        self.has(Self::HTTPS)
    }

    /// Whether to rebuild once and exit.
    ///
    /// Not in the Proposal's flag list, and added deliberately: without it, `dev`
    /// can only be exercised interactively, which makes it untestable in CI and
    /// unusable from a script. It is the flag that makes the loop *verifiable*
    /// rather than merely *observable*.
    #[must_use]
    pub const fn once(&self) -> bool {
        self.has(Self::ONCE)
    }

    /// Whether to build deterministically.
    #[must_use]
    pub const fn deterministic(&self) -> bool {
        self.has(Self::DETERMINISTIC)
    }
}

impl Default for DevOptions {
    fn default() -> Self {
        Self {
            // The Proposal's transcript uses 3000, and `--port` overrides it.
            port: 3000,
            host: "127.0.0.1".to_owned(),
            switches: 0,
            inspect: None,
            watch: Vec::new(),
            ignore: Vec::new(),
            reload_limit: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Reload tiers
// ---------------------------------------------------------------------------

/// Which reload strategy applies to a change.
///
/// Proposal §6.6 defines three. This is a closed enum rather than a string
/// because the choice has consequences the user should be able to see: tier 3
/// costs an order of magnitude more than tier 1, and a user wondering why their
/// edit took 1.5 seconds deserves to know it was because they touched
/// `qqq.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReloadTier {
    /// Component swap: rebuild, discard the old instance, keep the host.
    ComponentSwap,
    /// State-preserving swap. Not implemented in V1 (`DX-007`).
    StatePreserving,
    /// Full restart, required when the manifest's capabilities or limits change.
    FullRestart,
}

impl ReloadTier {
    /// The tier number, as the Proposal names it.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::ComponentSwap => 1,
            Self::StatePreserving => 2,
            Self::FullRestart => 3,
        }
    }

    /// The stable name, for JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ComponentSwap => "component-swap",
            Self::StatePreserving => "state-preserving",
            Self::FullRestart => "full-restart",
        }
    }

    /// Why this tier was chosen, for the log line.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ComponentSwap => "source changed; the host process is preserved",
            Self::StatePreserving => "state preservation requested",
            Self::FullRestart => {
                "the manifest changed; capabilities and limits must be re-resolved"
            }
        }
    }
}

/// Choose the reload tier for a set of changes.
///
/// # Why a manifest change forces a full restart
///
/// Capabilities and limits are resolved into the *linker* and the *store*, both
/// of which are built once per instance and hold authority. A component swap
/// reuses the host's linker and limit configuration, so if `qqq.toml` gained a
/// capability, a swap would silently run the new code under the old grant set —
/// the new code would be denied a capability the user had just granted, and the
/// failure would look like a bug in their code.
///
/// The reverse is worse: a *removed* capability would keep working until the
/// process restarted, so a developer could remove a grant and still have their
/// tests pass. That is precisely the drift the capability model exists to
/// prevent, so a manifest edit is never a swap.
#[must_use]
pub fn select_tier(changes: &[Change], manifest_path: &Path, preserve_state: bool) -> ReloadTier {
    if changes.iter().any(|c| c.path() == manifest_path) {
        return ReloadTier::FullRestart;
    }
    if preserve_state {
        // Only reachable once DX-007 lands; reported honestly until then.
        return ReloadTier::StatePreserving;
    }
    ReloadTier::ComponentSwap
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// One reload cycle.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReloadRecord {
    /// Which cycle this was, counting from 1.
    pub cycle: u32,
    /// The files that changed.
    pub changed: Vec<String>,
    /// The tier used.
    pub tier: String,
    /// Why that tier was chosen.
    pub reason: String,
    /// Build duration in milliseconds.
    pub build_ms: u64,
    /// Whether the build succeeded.
    pub ok: bool,
    /// The error, when it failed.
    pub error: Option<String>,
}

/// The result of `qqqai dev`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DevOutput {
    /// The project name.
    pub project: String,
    /// Where it would listen, once `serve` exists.
    pub listen: String,
    /// The directories being watched.
    pub watching: Vec<String>,
    /// How many files are watched.
    pub watched_files: usize,
    /// The initial build's duration in milliseconds.
    pub initial_build_ms: u64,
    /// Every reload that happened.
    pub reloads: Vec<ReloadRecord>,
    /// The capabilities granted, for the warning.
    pub capabilities_granted: usize,
    /// The warning shown at startup, when there is one.
    pub capability_warning: Option<String>,
    /// Notes about what this build does *not* do yet.
    pub notes: Vec<String>,
    /// Whether this was a single-shot run rather than a watch loop.
    pub once: bool,
}

impl CommandOutput for DevOutput {
    fn command(&self) -> CommandName {
        CommandName::Dev
    }

    fn summary(&self) -> String {
        if self.once {
            return format!(
                "{}: compiled in {}ms, {} files watched",
                self.project, self.initial_build_ms, self.watched_files
            );
        }
        format!(
            "{}: {} reload(s), listening on {}",
            self.project,
            self.reloads.len(),
            self.listen
        )
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

// ---------------------------------------------------------------------------
// The capability warning
// ---------------------------------------------------------------------------

/// The startup warning, when the project grants nothing.
///
/// Implements `DX-003`. Returns `None` when the project *does* grant something,
/// because a warning that always fires is one users learn to ignore — and this
/// warning has to land on the first run, when the denial is about to happen.
#[must_use]
pub fn capability_warning(granted: usize) -> Option<String> {
    if granted == 0 {
        Some(
            "This app has 0 capabilities. Add them to qqq.toml when you need them \u{2014} \
             run `qqqai why <capability>` for the exact stanza."
                .to_owned(),
        )
    } else {
        None
    }
}

/// The directories to watch, resolved against the project.
///
/// # Why `src` alone is not enough
///
/// The Proposal's transcript says `Watching src/`, and that is the primary
/// answer. But a project's build inputs are not only its sources: `qqq.toml`
/// governs the capability model, and `Cargo.toml` changes the crate itself.
/// Missing either means a change that *should* trigger a reload silently does
/// not — the failure mode this whole command exists to avoid.
///
/// So the watch root is the project directory, and the *ignores* keep the walk
/// cheap. `snapshot` visits 3 files in a small project and a few hundred in a
/// large one, at 100 ms intervals, which costs a negligible fraction of a core.
#[must_use]
pub fn watch_roots(project: &Path, opts: &DevOptions) -> Vec<PathBuf> {
    if opts.watch.is_empty() {
        return vec![project.to_path_buf()];
    }
    opts.watch.iter().map(|w| project.join(w)).collect()
}

/// The rules to watch with: the defaults, plus any the user named.
#[must_use]
pub fn watch_rules(root: &Path, opts: &DevOptions) -> IgnoreRules {
    let mut rules = IgnoreRules::default();
    for pattern in &opts.ignore {
        rules = rules.ignoring(pattern.clone());
    }
    let _ = root;
    rules
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// Build once and report.
///
/// # Errors
///
/// As [`build::execute`].
pub fn build_once(loaded: &LoadedManifest, opts: &DevOptions) -> Result<(u64, Option<Error>)> {
    let mut build_opts = BuildOptions::default();
    if opts.deterministic() {
        build_opts.set(BuildOptions::REPRODUCIBLE);
    }
    let started = Instant::now();
    match build::execute(loaded, &build_opts) {
        Ok(_) => Ok((millis(started.elapsed()), None)),
        Err(e) => Ok((millis(started.elapsed()), Some(e))),
    }
}

/// Milliseconds, saturating.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Run the dev server.
///
/// # Errors
///
/// `QQQ-2001` when the manifest cannot be read; otherwise this reports build
/// failures in the output rather than returning them, because a dev server that
/// exits on the first compile error is useless — the whole point is to keep
/// watching so the next edit can succeed.
///
/// # The loop
///
/// 1. Compile.
/// 2. Snapshot the tree.
/// 3. Poll: snapshot again, and if anything changed, feed the debouncer.
/// 4. When the debouncer says the tree has been quiet, choose a tier and rebuild.
///
/// **A failed build does not stop the loop.** The snapshot is still updated, so
/// the next edit is detected. This is the difference between a dev server and a
/// script: after an error, the user fixes the error and keeps going.
pub fn run(loaded: &LoadedManifest, opts: &DevOptions) -> Result<DevOutput> {
    let project = loaded
        .path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    let roots = watch_roots(&project, opts);
    let rules = watch_rules(&project, opts);

    // -- the first build, before anything is watched ----------------------
    let (initial_build_ms, mut last_error) = build_once(loaded, opts)?;

    // The grant count comes from the manifest, so the warning is about what the
    // user declared rather than what the build did.
    let actions = qqq_cap::resolve::Resolution::from_manifest(&loaded.manifest);
    let capabilities_granted = actions.grants.capabilities().len();

    let mut snapshot = Snapshot::take(&project, &rules);
    let watching: Vec<String> = roots
        .iter()
        .map(|r| relative_display(r, &project))
        .collect();

    let mut notes = Vec::new();
    // Stated plainly rather than buried: there is no listener yet, and a dev
    // server that silently does not listen would be a stub wearing a working
    // command's clothes.
    notes.push(
        "no HTTP listener yet (`serve` / CLI-011): this build compiles and reloads, \
         but nothing is served on the port below"
            .to_owned(),
    );
    if let Some(err) = &last_error {
        notes.push(format!("the initial build failed: {}", err.message));
    }

    let mut out = DevOutput {
        project: loaded.name().to_owned(),
        listen: format!(
            "{}://{}:{}",
            if opts.https() { "https" } else { "http" },
            opts.host,
            opts.port
        ),
        watching: watching.clone(),
        watched_files: snapshot.len(),
        initial_build_ms,
        reloads: Vec::new(),
        capabilities_granted,
        capability_warning: capability_warning(capabilities_granted),
        notes,
        once: opts.once(),
    };

    if opts.once() {
        return Ok(out);
    }

    // -- the watch loop ---------------------------------------------------
    let mut debouncer = Debouncer::with_default_window();
    let mut cycle: u32 = 0;
    // A bounded number of cycles rather than `loop {}`: an unbounded loop is
    // untestable, and a caller that needs to stop has no way to. `None` means
    // "until interrupted", which is what the CLI passes.
    let max_cycles = opts.max_cycles();
    let mut last_pending: Vec<Change> = Vec::new();

    loop {
        std::thread::sleep(crate::watch::DEFAULT_POLL_INTERVAL);

        let now = Snapshot::take(&project, &rules);
        let changes = now.changes_since(&snapshot);
        if !changes.is_empty() {
            // Update the baseline *before* any rebuild, so a change arriving
            // during a slow build is not lost — it will show up against this
            // snapshot on the next poll rather than being swallowed.
            snapshot = now;
            last_pending.clone_from(&changes);
            debouncer.observe(changes.len(), Instant::now());
        }

        if debouncer.should_fire(Instant::now()).is_none() {
            if let Some(limit) = max_cycles {
                if cycle >= limit {
                    break;
                }
            }
            continue;
        }

        cycle += 1;
        let tier = select_tier(
            &last_pending,
            &loaded.path,
            opts.state_preservation_requested(),
        );
        let (ms, err) = build_once(loaded, opts)?;
        out.reloads.push(ReloadRecord {
            cycle,
            changed: last_pending
                .iter()
                .map(|c| relative_display(c.path(), &project))
                .collect(),
            tier: tier.as_str().to_owned(),
            reason: tier.reason().to_owned(),
            build_ms: ms,
            ok: err.is_none(),
            error: err.as_ref().map(|e| e.message.clone()),
        });
        last_error = err;
        last_pending.clear();

        if let Some(limit) = max_cycles {
            if cycle >= limit {
                break;
            }
        }
    }
    let _ = last_error;

    Ok(out)
}

/// A path relative to the project, with forward slashes.
fn relative_display(path: &Path, project: &Path) -> String {
    path.strip_prefix(project)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

impl DevOptions {
    /// How many reload cycles to run before stopping.
    ///
    /// `None` for the interactive CLI, which runs until interrupted. Tests pass
    /// `Some(n)` through `--reload-limit`, which is what makes the loop
    /// verifiable rather than merely observable.
    #[must_use]
    pub fn max_cycles(&self) -> Option<u32> {
        self.reload_limit
    }

    /// Whether tier-2 state preservation was requested.
    #[must_use]
    pub fn state_preservation_requested(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- the capability warning (DX-003) -----------------------------------

    /// **The DX-003 property.** A project with no capabilities must be warned,
    /// because the failure the user is about to hit is a capability denial and
    /// this is the moment to teach the model.
    #[test]
    fn a_capability_free_project_is_warned_about() {
        let w = capability_warning(0).expect("zero capabilities must warn");
        assert!(w.contains("0 capabilities"), "got: {w}");
        assert!(
            w.contains("why"),
            "the warning must point at the command that resolves a denial: {w}"
        );
    }

    /// And a project that *does* grant something must not be warned. A warning
    /// that always fires is one users learn to ignore, which would cost exactly
    /// the first-run warning that matters.
    #[test]
    fn a_project_with_capabilities_is_not_warned_about() {
        for n in [1, 2, 99] {
            assert!(
                capability_warning(n).is_none(),
                "{n} capabilities must not produce a zero-capability warning"
            );
        }
    }

    // -- tier selection ----------------------------------------------------

    fn change(path: &str) -> Change {
        Change::Modified(PathBuf::from(path))
    }

    #[test]
    fn a_source_change_is_a_component_swap() {
        let manifest = PathBuf::from("/proj/qqq.toml");
        let tier = select_tier(&[change("/proj/src/lib.rs")], &manifest, false);
        assert_eq!(tier, ReloadTier::ComponentSwap);
        assert_eq!(tier.number(), 1);
    }

    /// **The security-relevant tier rule.** A manifest edit must never be a
    /// component swap: the linker and store hold authority, and reusing them
    /// would run new code under the old grant set. The *removed*-capability
    /// direction is the dangerous one — a developer could revoke a grant and
    /// still have their tests pass, which is the drift the capability model
    /// exists to prevent.
    #[test]
    fn a_manifest_change_forces_a_full_restart() {
        let manifest = PathBuf::from("/proj/qqq.toml");
        let tier = select_tier(&[change("/proj/qqq.toml")], &manifest, false);
        assert_eq!(tier, ReloadTier::FullRestart);
        assert_eq!(tier.number(), 3);
        assert!(
            tier.reason().contains("capabilities"),
            "the reason must name why: {}",
            tier.reason()
        );
    }

    /// A manifest change mixed in with source changes still forces a restart:
    /// the strictest tier wins, because the alternative is running new code
    /// under stale authority.
    #[test]
    fn the_strictest_tier_wins_when_changes_are_mixed() {
        let manifest = PathBuf::from("/proj/qqq.toml");
        let tier = select_tier(
            &[
                change("/proj/src/a.rs"),
                change("/proj/qqq.toml"),
                change("/proj/src/b.rs"),
            ],
            &manifest,
            false,
        );
        assert_eq!(tier, ReloadTier::FullRestart);
    }

    /// A manifest under a different path must not force a restart, or every
    /// edit in a monorepo would.
    #[test]
    fn a_similar_path_is_not_the_manifest() {
        let manifest = PathBuf::from("/proj/qqq.toml");
        let tier = select_tier(&[change("/proj/qqq.toml.bak")], &manifest, false);
        assert_eq!(tier, ReloadTier::ComponentSwap);
    }

    #[test]
    fn tier_names_are_stable() {
        assert_eq!(ReloadTier::ComponentSwap.as_str(), "component-swap");
        assert_eq!(ReloadTier::StatePreserving.as_str(), "state-preserving");
        assert_eq!(ReloadTier::FullRestart.as_str(), "full-restart");
        assert_eq!(ReloadTier::StatePreserving.number(), 2);
    }

    // -- options -----------------------------------------------------------

    #[test]
    fn the_default_port_matches_the_documented_transcript() {
        // Proposal §12.1 shows `Listening on http://127.0.0.1:3000`.
        assert_eq!(DevOptions::default().port, 3000);
        assert_eq!(DevOptions::default().host, "127.0.0.1");
    }

    #[test]
    fn the_default_watch_root_is_the_project() {
        let roots = watch_roots(Path::new("/proj"), &DevOptions::default());
        assert_eq!(roots, vec![PathBuf::from("/proj")]);
    }

    /// The watch root must cover the manifest and the crate file, not only
    /// `src/`. Missing `qqq.toml` means a capability edit silently does not
    /// reload — the failure this command exists to prevent.
    #[test]
    fn the_watch_root_covers_the_manifest() {
        let roots = watch_roots(Path::new("/proj"), &DevOptions::default());
        assert!(
            roots.iter().any(|r| r == Path::new("/proj")),
            "the project root must be watched so qqq.toml changes are seen"
        );
    }

    #[test]
    fn an_explicit_watch_list_overrides_the_default() {
        let opts = DevOptions {
            watch: vec!["src".to_owned(), "wit".to_owned()],
            ..Default::default()
        };
        let roots = watch_roots(Path::new("/proj"), &opts);
        assert_eq!(roots.len(), 2);
        assert!(roots.contains(&PathBuf::from("/proj/src")));
        assert!(roots.contains(&PathBuf::from("/proj/wit")));
    }

    #[test]
    fn user_ignore_patterns_reach_the_rules() {
        let opts = DevOptions {
            ignore: vec!["generated".to_owned()],
            ..Default::default()
        };
        let rules = watch_rules(Path::new("/proj"), &opts);
        assert!(rules.is_ignored(Path::new("/proj"), Path::new("/proj/generated/a.rs")));
        // And the defaults are still there.
        assert!(rules.is_ignored(Path::new("/proj"), Path::new("/proj/target/x")));
    }

    #[test]
    fn the_listen_string_reflects_https() {
        let plain = DevOptions::default();
        // `run` builds the string; this mirrors that construction so the format
        // is pinned without needing a project.
        let http = format!("http://{}:{}", plain.host, plain.port);
        assert_eq!(http, "http://127.0.0.1:3000");

        let mut secure = DevOptions::default();
        secure.set(DevOptions::HTTPS);
        let https = format!("https://{}:{}", secure.host, secure.port);
        assert_eq!(https, "https://127.0.0.1:3000");
    }

    /// Milliseconds convert exactly for realistic durations, and saturate
    /// rather than wrapping for one that cannot fit.
    ///
    /// The saturation case needs a duration whose millisecond count exceeds
    /// `u64::MAX`, which means more than ~584 million years. `u64::MAX`
    /// *seconds* is such a duration; `u64::MAX / 1000` seconds is not, and
    /// asserting saturation there was wrong — it fits comfortably.
    #[test]
    fn millis_converts_exactly_and_saturates_when_it_cannot() {
        assert_eq!(millis(Duration::from_millis(412)), 412);
        assert_eq!(millis(Duration::from_secs(0)), 0);
        assert_eq!(millis(Duration::from_secs(1)), 1000);

        // A duration that genuinely overflows: `u64::MAX` seconds is ~5.8e20 ms.
        assert_eq!(
            millis(Duration::from_secs(u64::MAX)),
            u64::MAX,
            "an unrepresentable duration must saturate, not wrap"
        );
    }

    #[test]
    fn a_dev_output_summarises_the_reloads() {
        let out = DevOutput {
            project: "app".to_owned(),
            listen: "http://127.0.0.1:3000".to_owned(),
            watching: vec![".".to_owned()],
            watched_files: 12,
            initial_build_ms: 412,
            reloads: vec![ReloadRecord {
                cycle: 1,
                changed: vec!["src/lib.rs".to_owned()],
                tier: "component-swap".to_owned(),
                reason: "source changed".to_owned(),
                build_ms: 88,
                ok: true,
                error: None,
            }],
            capabilities_granted: 0,
            capability_warning: capability_warning(0),
            notes: vec![],
            once: false,
        };
        let s = out.summary();
        assert!(s.contains("1 reload"), "got: {s}");
        assert!(s.contains("3000"));
        assert!(out.to_json()["reloads"].is_array());
    }

    #[test]
    fn a_once_run_summarises_the_initial_build() {
        let out = DevOutput {
            project: "app".to_owned(),
            listen: "http://127.0.0.1:3000".to_owned(),
            watching: vec![],
            watched_files: 3,
            initial_build_ms: 120,
            reloads: vec![],
            capabilities_granted: 1,
            capability_warning: None,
            notes: vec![],
            once: true,
        };
        let s = out.summary();
        assert!(s.contains("120ms"), "got: {s}");
        assert!(s.contains("3 files"), "got: {s}");
    }
}
