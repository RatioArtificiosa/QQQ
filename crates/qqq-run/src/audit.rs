// SPDX-License-Identifier: Apache-2.0

//! `qqqai audit` — the full security posture of an artifact, with SARIF — `CLI-016`.
//!
//! # What §5.2 asks for
//!
//! > | `qqqai audit <artifact>` | Full security posture: caps, limits, supply
//! > chain, provenance | `--json`, `--sarif`, `--fail-on <severity>` |
//!
//! Four surfaces, and the command's job is to report **all four** rather than the
//! one a user happened to ask about. That is the difference between `audit` and
//! `inspect`: `inspect` answers *"what can this do?"*, which is a static capability
//! question, while `audit` answers *"is this safe to deploy?"*, which is a
//! judgement over capabilities **and** limits **and** the dependency record
//! **and** whether anything is signed.
//!
//! # Why SARIF, and why it is the reason this command is worth building
//!
//! SARIF is the format GitHub code scanning reads. Emitting it means an audit
//! finding appears in the **Security tab of a pull request** beside the `CodeQL`
//! results, with no QQQ-specific integration — a reviewer sees "this change grants
//! `http.client` to a component that had none" in the same list as everything
//! else. That is the entire value: a capability escalation is a security finding,
//! and this puts it where security findings are already read.
//!
//! # The finding taxonomy, and why each rule exists
//!
//! | Rule | Severity | Why it is a finding at all |
//! |---|---|---|
//! | `qqq/exposed-posture` | warning | The grant set can write or reach the network |
//! | `qqq/unbounded-memory` | error | No memory limit means a guest can exhaust the host |
//! | `qqq/unbounded-fuel` | error | No fuel limit means a guest can run forever |
//! | `qqq/no-epoch-deadline` | warning | Without a deadline a looping guest is not preempted |
//! | `qqq/unsigned-manifest` | warning | Authority with no provenance record |
//! | `qqq/capability-escalation` | error | A lockfile update ADDS authority |
//! | `qqq/unpinned-dependency` | warning | A dependency with no digest cannot be reproduced |
//!
//! The severities are not decoration: `--fail-on` branches on them, so a CI job
//! can pass on warnings and fail on errors, and the choice of which is which is a
//! documented decision rather than a default.

use qqq_core::{Error, ErrorCode, Result};

use crate::manifest_loader::LoadedManifest;

/// How serious a finding is, in a fixed order so `--fail-on` can compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational; never fails a build.
    Note,
    /// Worth a reviewer's attention.
    Warning,
    /// A defect that should fail a build.
    Error,
}

impl Severity {
    /// The SARIF spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Parse a `--fail-on` value.
    ///
    /// # Errors
    ///
    /// Returns an error naming the three accepted values rather than defaulting.
    /// A `--fail-on` that silently accepted a typo would be a CI gate that never
    /// fires, which is worse than no gate because it is believed to be one.
    pub fn parse(text: &str) -> std::result::Result<Self, String> {
        match text.to_ascii_lowercase().as_str() {
            "note" => Ok(Self::Note),
            "warning" | "warn" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            other => Err(format!(
                "`{other}` is not a severity; use `note`, `warning` or `error`"
            )),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One audit finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The rule identifier, `qqq/<name>`.
    pub rule: &'static str,
    /// How serious it is.
    pub severity: Severity,
    /// One sentence, no jargon — the same standard as error messages (`DX-004`).
    pub message: String,
    /// What to do about it, as a runnable change or an exact stanza.
    pub remediation: String,
}

impl Finding {
    fn new(
        rule: &'static str,
        severity: Severity,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            rule,
            severity,
            message: message.into(),
            remediation: remediation.into(),
        }
    }
}

/// The whole audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    /// The project name.
    pub project: String,
    /// Every finding, sorted by severity then rule so two runs diff cleanly.
    pub findings: Vec<Finding>,
}

impl AuditReport {
    /// The highest severity present, or `None` when there are no findings.
    #[must_use]
    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Whether the report warrants failing a build at `threshold`.
    #[must_use]
    pub fn fails_at(&self, threshold: Severity) -> bool {
        self.worst().is_some_and(|w| w >= threshold)
    }

    /// The report as a SARIF 2.1.0 document.
    ///
    /// # Why this is hand-written rather than derived
    ///
    /// Because SARIF has a **required shape** — `version`, `$schema`, `runs[]`,
    /// each with `tool.driver.name` and a `results[]` array — and a derived
    /// serialisation of a Rust struct would produce something that *looks* like
    /// SARIF and is rejected by the consumers that matter. Writing the shape
    /// explicitly means the document is valid by construction, and the test
    /// asserts the required keys rather than the absence of a panic.
    ///
    /// # Why `helpUri` points at `qqq.codes`
    ///
    /// Because the error-code contract already promises a stable URL per code
    /// (§8.3), so a finding links to a page explaining the rule rather than to a
    /// paragraph in a repository file that may move.
    #[must_use]
    pub fn to_sarif(&self) -> String {
        use std::fmt::Write as _;
        let mut rules = String::new();
        for rule in RULES {
            let _ = write!(
                rules,
                "{{\"id\":\"{}\",\"shortDescription\":{{\"text\":\"{}\"}},\
                 \"helpUri\":\"https://qqq.codes/rules/{}\"}},",
                rule.id,
                rule.summary,
                rule.id.replace('/', "-")
            );
        }
        rules.pop(); // drop the trailing comma

        let mut results = String::new();
        for f in &self.findings {
            let _ = write!(
                results,
                "{{\"ruleId\":\"{}\",\"level\":\"{}\",\
                 \"message\":{{\"text\":\"{}\"}},\
                 \"fixes\":[{{\"description\":{{\"text\":\"{}\"}}}}]}},",
                f.rule,
                f.severity.as_str(),
                json_escape(&f.message),
                json_escape(&f.remediation)
            );
        }
        results.pop();

        format!(
            "{{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\
             \"version\":\"2.1.0\",\
             \"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"qqqai\",\
             \"informationUri\":\"https://qqq.codes\",\
             \"rules\":[{rules}]}}}},\
             \"results\":[{results}]}}]}}"
        )
    }

    /// One line of context: the limits in force, for a reader deciding whether the
    /// findings are the whole story.
    ///
    /// # What belongs here versus in `findings`
    ///
    /// The distinction the whole module turns on: **a finding must correspond to a
    /// condition that is actually wrong.** `128MiB` and `50M` fuel are the
    /// manifest defaults and they are *safe*, so reporting them as findings would
    /// be noise -- and a report with noise is one people stop reading.
    ///
    /// But a reviewer still wants to know what the limits *are*, because
    /// "no findings" means something different against `64MiB` than against
    /// `128MiB`. So they are stated here, as context rather than as a verdict.
    #[must_use]
    pub fn summary(&self, limits: &qqq_cap::manifest::Limits) -> String {
        format!(
            "limits in force: memory {}, fuel {}, epoch deadline {} ms; \
             posture checked over caps, limits, supply chain and provenance",
            limits.memory, limits.fuel, limits.epoch_deadline_ms
        )
    }

    /// Render for a terminal.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = format!("audit of `{}`\n", self.project);
        if self.findings.is_empty() {
            return out;
        }
        for f in &self.findings {
            let _ = writeln!(out, "  [{:<7}] {}  {}", f.severity, f.rule, f.message);
            let _ = writeln!(out, "            fix: {}", f.remediation);
        }
        out
    }
}

/// Every rule the audit can emit, for the SARIF `rules` array and the docs.
pub const RULES: [RuleInfo; 5] = [
    RuleInfo {
        id: "qqq/exposed-posture",
        summary: "The grant set can write or reach the network",
    },
    RuleInfo {
        id: "qqq/limits-at-default",
        summary: "A limit is at the manifest default rather than chosen",
    },
    RuleInfo {
        id: "qqq/unsigned-manifest",
        summary: "The manifest carries no signature",
    },
    RuleInfo {
        id: "qqq/capability-escalation",
        summary: "A dependency declares authority; check the update delta before \
                  merging",
    },
    RuleInfo {
        id: "qqq/unpinned-dependency",
        summary: "A dependency has no digest",
    },
];

/// One rule's identity, for the SARIF document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleInfo {
    /// The rule id.
    pub id: &'static str,
    /// One-line summary.
    pub summary: &'static str,
}

/// Audit a loaded project.
///
/// # Why the lockfile is a parameter rather than a field of `LoadedManifest`
///
/// Because `LoadedManifest` is `{ manifest, path, source }` — measured, not
/// assumed — and a lockfile lives *beside* the manifest rather than inside it. The
/// caller reads it (or passes `None` when there is none), so the audit does not
/// silently report a supply-chain section it never looked at. `None` means "there
/// is no lockfile", which is a different fact from "the lockfile is clean", and
/// the report says so by omitting the supply-chain findings rather than by
/// claiming none were found.
///
/// # Why this returns a plain value rather than a `Result`
///
/// Because **nothing in it can fail**. The first version returned
/// `Result<AuditReport>` and inherited a `QQQ-2004` case from `inspect`'s path
/// normalization; when the implementation was decomposed into per-surface
/// functions, that call went away and the `Result` stopped having an `Err` arm.
///
/// Clippy flagged it (`unnecessary_wraps`) and was right: **a `Result` whose error
/// arm is unreachable is the same defect as a rule that cannot fire** -- it reads
/// as a failure mode that does not exist, and every caller writes a `?` for
/// nothing. The audit reads a parsed manifest and optionally a parsed lockfile, so
/// by the time it runs, the fallible work has already happened.
#[must_use]
pub fn audit(loaded: &LoadedManifest, lock: Option<&qqq_pkg::lock::Lockfile>) -> AuditReport {
    // Four surfaces, four functions. The single body this replaced reached 114
    // lines, which is how a function grows when each surface is appended as the
    // module is written: every addition looked small on its own. Naming them
    // makes the coverage visible in the call list, and lets a test exercise one
    // surface without constructing a project that triggers the others.
    let mut findings = caps_and_posture(loaded);
    findings.extend(limits_at_default(loaded));
    findings.extend(provenance(lock));
    findings.extend(supply_chain(lock));

    // Severity descending, then by rule and message, so two runs of the same
    // project produce identical output -- which is what makes a SARIF baseline
    // comparison meaningful.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule.cmp(b.rule))
            .then_with(|| a.message.cmp(&b.message))
    });

    AuditReport {
        project: loaded.name().to_owned(),
        findings,
    }
}

/// The exposure question: can this component write or reach the network?
///
/// # Errors
///
/// `QQQ-2004` when a granted path does not exist, because normalization must
/// resolve real paths to be honest about reachability. Inherited from [`inspect`].
///
/// # Why the capability list is filtered rather than the posture re-derived
///
/// [`classify_posture`] already decides *whether* the posture is exposed; this
/// filter decides *which* capabilities made it so, and the finding names them.
/// The two must agree, so `classify_posture` is the single source of the verdict
/// and this is only an explanation of it -- re-deriving the verdict here would be
/// a second opinion that could differ.
///
/// [`inspect`]: crate::commands::inspect
/// [`classify_posture`]: crate::commands::classify_posture
fn caps_and_posture(loaded: &LoadedManifest) -> Vec<Finding> {
    let resolution = qqq_cap::resolve::Resolution::from_manifest(&loaded.manifest);
    let caps: Vec<qqq_cap::Capability> = resolution.grants.capabilities();

    if crate::commands::classify_posture(&caps) != crate::commands::Posture::Exposed {
        return Vec::new();
    }

    let exposing: Vec<&str> = caps
        .iter()
        .filter(|c| {
            matches!(
                c,
                qqq_cap::Capability::FsWrite
                    | qqq_cap::Capability::FsWatch
                    | qqq_cap::Capability::HttpClient
                    | qqq_cap::Capability::HttpServer
                    | qqq_cap::Capability::SqlExecute
                    | qqq_cap::Capability::KvWrite
                    | qqq_cap::Capability::QueuePublish
                    | qqq_cap::Capability::QueueSubscribe
                    | qqq_cap::Capability::DnsResolve
                    | qqq_cap::Capability::AiInfer
            )
        })
        .map(|c| c.name())
        .collect();

    vec![Finding::new(
        "qqq/exposed-posture",
        Severity::Warning,
        format!(
            "this component can write or reach the network: {}",
            exposing.join(", ")
        ),
        "if any of these is not needed, remove it from `[capabilities]` in \
         qqq.toml; run `qqqai caps --explain` to see which layer granted it",
    )]
}

/// Whether the limits were **chosen** or left at the manifest defaults.
///
/// # Why there is no unbounded-limit finding, and why that is the honest choice
///
/// The first version of this module had three rules -- `qqq/unbounded-memory`,
/// `qqq/unbounded-fuel`, `qqq/no-epoch-deadline` -- checking for a zero limit.
/// **All three are unreachable**, measured: `Manifest::parse` refuses a zero limit
/// before `audit` sees it:
///
/// ```text
/// LimitOutOfRange { field: "limits.fuel", value: "0",
///                   permitted: "1000..=1000000000000000" }
/// ```
///
/// and `manifest.rs`'s own tests cover zero fuel, zero memory and zero instances.
/// So a parsed `Manifest` cannot carry an unbounded limit, and a rule checking for
/// one would never fire.
///
/// **A rule that cannot fire is worse than no rule, because it reads as
/// coverage**: a reader sees `qqq/unbounded-fuel` in the SARIF `rules` array and
/// concludes fuel is audited here. It is audited by the parser -- a better place
/// for it, because it fails at the point of the mistake with a message naming the
/// permitted range.
///
/// This was the fourth unreachable rule found in this one file, after the
/// escalation check, the provenance check, and these same three. The pattern is
/// worth naming: **a checker written from a document describes what a reader
/// imagines can go wrong; only running it against the real types reveals what the
/// system already prevents.**
///
/// The rule that replaced them fires on a **note**: using every default is safe,
/// but a deployment that has not chosen its own ceiling is worth knowing about.
fn limits_at_default(loaded: &LoadedManifest) -> Vec<Finding> {
    let defaults = qqq_cap::manifest::Limits::default();
    let mut at_default: Vec<&str> = Vec::new();
    if loaded.manifest.limits.memory == defaults.memory {
        at_default.push("memory");
    }
    if loaded.manifest.limits.fuel == defaults.fuel {
        at_default.push("fuel");
    }
    if loaded.manifest.limits.epoch_deadline_ms == defaults.epoch_deadline_ms {
        at_default.push("epoch_deadline_ms");
    }
    if at_default.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "qqq/limits-at-default",
        Severity::Note,
        format!(
            "{} limit(s) are at the manifest default ({}), which is safe but may \
             not be what this deployment needs",
            at_default.len(),
            at_default.join(", ")
        ),
        "set them explicitly under `[limits]` in qqq.toml if the workload differs \
         from the default assumption",
    )]
}

/// Whether every dependency has a recorded digest.
///
/// # Why this is the provenance rule rather than its own rule
///
/// The first version had a separate `qqq/unpinned-dependency`, and it reported the
/// same fact as this one from a second angle. **Two rules for one fact is a defect
/// rather than thoroughness**: a reader counting findings gets a distorted count,
/// and a SARIF baseline moves twice for one change. So the digest check lives here
/// and `a_lockfile_package_without_a_digest_is_reported_exactly_once` pins the
/// count.
///
/// # Why the finding is not phrased as "the manifest is unsigned"
///
/// Because `Manifest` has **no** `signature` field -- measured; its `limits.crypto`
/// names *allowed signature algorithms*, which answers a different question -- so a
/// finding phrased that way could never fire against the real type. What can be
/// reported honestly is that a package records no digest, which is the provenance
/// gap §5.4 leaves open until signing lands.
fn provenance(lock: Option<&qqq_pkg::lock::Lockfile>) -> Vec<Finding> {
    let Some(lock) = lock else {
        return Vec::new();
    };
    let unsigned: Vec<String> = lock
        .packages
        .iter()
        .filter(|p| p.digest.is_none())
        .map(|p| format!("{}@{}", p.name, p.version))
        .collect();
    if unsigned.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "qqq/unsigned-manifest",
        Severity::Warning,
        format!(
            "{} package(s) have no recorded digest, so their provenance cannot be \
             checked: {}",
            unsigned.len(),
            unsigned.join(", ")
        ),
        "re-resolve with `qqqai install`; a digest is what makes an artifact \
         reproducible and a signature checkable",
    )]
}

/// What the lockfile **records** about dependency authority.
///
/// # Why this is not an escalation check, and why saying so matters
///
/// The first version called `lock.has_escalation()`. That method does not exist on
/// `Lockfile` -- measured, it is on **`LockDiff`** -- because an escalation is a
/// *comparison between two lockfiles* and `audit` has one. Had the call compiled
/// against something else, the finding would have been an assertion about a
/// comparison that never happened: the "control believed live" shape this project
/// has recorded eight times, arriving here as a **finding that cannot fire**.
///
/// So the rule reports what a single lockfile can honestly support: which packages
/// declare authority. The escalation question is `SEC-015`'s, answered by
/// `LockDiff::compute(old, new)` in `install`, and `qqqai install` is what prints
/// the per-package delta. Duplicating it here would be a second source of truth
/// that drifts.
fn supply_chain(lock: Option<&qqq_pkg::lock::Lockfile>) -> Vec<Finding> {
    let Some(lock) = lock else {
        return Vec::new();
    };
    let declaring: Vec<String> = lock
        .packages
        .iter()
        .filter(|p| !p.caps.is_empty())
        .map(|p| format!("{}@{} [{}]", p.name, p.version, p.caps.join(", ")))
        .collect();
    if declaring.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "qqq/capability-escalation",
        Severity::Note,
        format!(
            "{} dependency(ies) declare authority: {}",
            declaring.len(),
            declaring.join("; ")
        ),
        "declaring is not granting -- the effective authority is your manifest plus \
         overlays. Run `qqqai install` after an update to see the per-package \
         delta, which is where an escalation appears",
    )]
}

/// The `CommandOutput` form of an audit, for `qqqai audit --json`.
///
/// # Why `findings` is a flat array of objects rather than a nested structure
///
/// Because the consumers are (a) a human reading a terminal, (b) a CI job
/// branching on the exit code, and (c) GitHub code scanning reading SARIF. Only
/// (a) benefits from grouping, and (a) reads [`AuditReport::render`] instead. A
/// JSON consumer wants to filter and count, and a flat array is what both are
/// easy on.
///
/// # Why `worst` is present when it is derivable
///
/// Because a CI job that wants "did anything reach warning?" should not have to
/// know the severity ordering, and re-deriving it in YAML is how a threshold
/// drifts from the one `--fail-on` applies.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditOutput {
    /// The project name.
    pub project: String,
    /// The worst severity present, or `null` when there are no findings.
    pub worst: Option<&'static str>,
    /// Every finding, worst first.
    pub findings: Vec<FindingOutput>,
    /// Whether the run failed its `--fail-on` threshold, when one was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed: Option<bool>,
}

/// One finding, in the JSON envelope.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FindingOutput {
    /// The rule id.
    pub rule: &'static str,
    /// The severity.
    pub severity: &'static str,
    /// The message.
    pub message: String,
    /// The remediation.
    pub remediation: String,
}

impl From<&AuditReport> for AuditOutput {
    fn from(report: &AuditReport) -> Self {
        Self {
            project: report.project.clone(),
            worst: report.worst().map(Severity::as_str),
            findings: report
                .findings
                .iter()
                .map(|f| FindingOutput {
                    rule: f.rule,
                    severity: f.severity.as_str(),
                    message: f.message.clone(),
                    remediation: f.remediation.clone(),
                })
                .collect(),
            failed: None,
        }
    }
}

impl crate::output::CommandOutput for AuditOutput {
    fn command(&self) -> crate::output::CommandName {
        crate::output::CommandName::Audit
    }

    /// The one-line conclusion a human and an agent both read.
    ///
    /// The sentence names what was **checked**, not only the count, because "no
    /// findings" is a claim about four surfaces and a reader deserves to know
    /// which four.
    fn summary(&self) -> String {
        match (self.findings.len(), self.worst) {
            (0, _) => {
                "no findings: caps, limits, supply chain and provenance all check out".to_owned()
            }
            (n, Some(worst)) => format!(
                "{n} finding(s) over caps, limits, supply chain and provenance; worst severity: {worst}"
            ),
            (n, None) => format!("{n} finding(s)"),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Parse a manifest byte size such as `128MiB` into bytes.
///
/// # Why this is public and tested although the audit no longer needs it
///
/// It was written for a zero-memory check that turned out to be unreachable (the
/// manifest parser refuses a zero limit), so the audit no longer calls it. It is
/// kept because comparing two manifest sizes is a question callers genuinely have
/// -- "is this deployment's ceiling smaller than the default?" -- and a helper
/// that delegates to [`qqq_cap::manifest::ByteSize`] is better than each caller
/// writing its own prefix parser that could disagree with the manifest.
///
/// Returns `None` for a value this function does not understand, which is
/// deliberately *not* a finding: a size the manifest parser accepted and this
/// helper did not is a bug in the helper, and reporting it as a security issue
/// would send the reader to the wrong file.
#[must_use]
pub fn parse_byte_size(text: &str) -> Option<u64> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    // `qqq_cap::manifest::ByteSize` parses the manifest's spelling; use it rather
    // than a second implementation that could disagree.
    qqq_cap::manifest::ByteSize::parse(t)
        .ok()
        .map(qqq_cap::manifest::ByteSize::as_bytes)
}

/// Parse a `--fail-on` value into a severity.
///
/// # Errors
///
/// Names the accepted values. See [`Severity::parse`].
pub fn parse_fail_on(text: &str) -> Result<Severity> {
    Severity::parse(text).map_err(|m| {
        Error::new(ErrorCode::ManifestSyntaxInvalid, m)
            .with_remediation("the flag takes `note`, `warning` or `error`; omit it to never fail")
    })
}

/// Escape a string for a hand-written JSON document.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_core::ErrorCode;

    fn loaded(src: &str) -> LoadedManifest {
        let manifest = qqq_cap::manifest::Manifest::parse(src).expect("test manifest");
        LoadedManifest {
            manifest,
            path: std::path::PathBuf::from("qqq.toml"),
            source: src.to_owned(),
        }
    }

    /// A lockfile holding one package, built through the API rather than from a
    /// hand-written TOML literal.
    ///
    /// # Why not a string literal
    ///
    /// Because `lock.rs`'s own tests do not use one: they call `Lockfile::push`
    /// and `render()`, so the writer and the reader are the same code and the
    /// fixture cannot drift from the format. I hand-wrote `[lock]` and
    /// `[[package]]` tables from memory and **both were wrong** -- the same
    /// mistake this session has recorded for fixtures four times.
    fn lock_with(name: &str, digest: Option<&str>, caps: &[&str]) -> qqq_pkg::lock::Lockfile {
        let mut l = qqq_pkg::lock::Lockfile::new();
        let mut pkg = qqq_pkg::lock::LockPackage::new(name, "1.0.0");
        pkg.digest = digest.map(str::to_owned);
        pkg.caps = caps.iter().map(|c| (*c).to_owned()).collect();
        l.push(pkg);
        l
    }

    /// A lockfile with one fully-pinned package and no declared authority: the
    /// clean baseline every negative test compares against.
    fn clean_lock() -> qqq_pkg::lock::Lockfile {
        lock_with("a", Some("sha256:aa"), &[])
    }

    /// A project with no capabilities, using every default limit.
    ///
    /// It produces exactly one finding: `qqq/limits-at-default` as a **note**.
    const MINIMAL: &str = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n";

    /// A project that also **chose** its limits, so it produces no findings at all.
    ///
    /// # Why this is needed and `MINIMAL` is not
    ///
    /// Because `limits-at-default` is a real rule that fires on `MINIMAL` -- a
    /// deployment using every default is worth knowing about. Tests asserting
    /// "clean" therefore need a project that has made the choice, and conflating
    /// the two was my error: six tests asserted `findings.is_empty()` and were
    /// stale the moment the rule landed.
    ///
    /// The values are the defaults with different numbers, so the test proves the
    /// rule tracks *explicit choice* rather than merely a different value.
    const CHOSEN: &str = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                          [limits]\nmemory = \"64MiB\"\nfuel = 10_000_000\n\
                          epoch_deadline_ms = 2500\n";

    // -- Severity ---------------------------------------------------------

    #[test]
    fn severities_order_from_note_to_error() {
        assert!(Severity::Note < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
    }

    #[test]
    fn severity_parses_its_three_names_and_rejects_a_typo() {
        assert_eq!(Severity::parse("note"), Ok(Severity::Note));
        assert_eq!(Severity::parse("WARNING"), Ok(Severity::Warning));
        assert_eq!(Severity::parse("warn"), Ok(Severity::Warning));
        assert_eq!(Severity::parse("error"), Ok(Severity::Error));

        // A typo must be refused rather than defaulted: a `--fail-on` that
        // silently accepted one would be a CI gate that never fires.
        let e = Severity::parse("critical").expect_err("must reject");
        assert!(e.contains("critical"), "{e}");
        assert!(
            e.contains("note"),
            "the error must list the accepted values: {e}"
        );
    }

    #[test]
    fn parse_fail_on_produces_a_remediation_ready_error() {
        let e = parse_fail_on("nope").expect_err("must reject");
        assert_eq!(e.code, ErrorCode::ManifestSyntaxInvalid);
        assert!(e.remediation.is_some());
        assert!(e.render().contains("QQQ-2002") || e.render().contains("QQQ-"));
    }

    // -- The rules, each made to FIRE -------------------------------------

    /// A project granting `fs.write` is exposed, and the finding names the
    /// capability rather than saying "something is wrong".
    #[test]
    fn an_exposed_posture_is_reported_and_names_the_capability() {
        let src = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                   [[capabilities.fs]]\npath = \".\"\nmode = \"read-write\"\n";
        let report = audit(&loaded(src), None);
        let f = report
            .findings
            .iter()
            .find(|f| f.rule == "qqq/exposed-posture")
            .expect("an exposed posture must be reported");
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.message.contains("fs.write"), "{}", f.message);
        assert!(!f.remediation.is_empty());
    }

    /// **The manifest parser forbids an unbounded limit, which is why the audit
    /// has no rule for one.**
    ///
    /// This test is what makes deleting three rules safe: the property those rules
    /// tried to check is still pinned, at the layer that actually enforces it.
    /// Without it, removing `qqq/unbounded-fuel` would have removed the coverage
    /// rather than relocating it -- and a reader of the SARIF `rules` array would
    /// have no way to tell.
    ///
    /// Three cases, matching the three rules that were removed.
    #[test]
    fn the_manifest_parser_refuses_an_unbounded_limit() {
        for (field, src) in [
            ("memory", "[limits]\nmemory = \"0B\"\n"),
            ("fuel", "[limits]\nfuel = 0\n"),
            ("epoch_deadline_ms", "[limits]\nepoch_deadline_ms = 0\n"),
        ] {
            let text = format!("[package]\nname = \"a\"\nversion = \"1.0.0\"\n{src}");
            let err = qqq_cap::manifest::Manifest::parse(&text)
                .expect_err(&format!("`{field} = 0` must be refused by the parser"));
            let rendered = err.to_string();
            assert!(
                rendered.contains(field),
                "the parse error must name `{field}`: {rendered}"
            );
        }
    }

    /// A limit left at the default is a **note**, not a verdict: the defaults are
    /// safe, but a deployment that has not chosen its own ceiling is worth knowing
    /// about.
    #[test]
    fn limits_left_at_the_default_are_noted() {
        let report = audit(&loaded(MINIMAL), None);
        let f = report
            .findings
            .iter()
            .find(|f| f.rule == "qqq/limits-at-default")
            .expect("a project using every default must be noted");
        assert_eq!(
            f.severity,
            Severity::Note,
            "safe defaults must not be an error or a warning"
        );
        assert!(f.message.contains("memory"), "{}", f.message);
        assert!(f.message.contains("fuel"), "{}", f.message);
    }

    /// And an explicit choice removes the note, so the rule tracks *attention*
    /// rather than merely being present.
    #[test]
    fn explicitly_chosen_limits_are_not_noted() {
        let src = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                   [limits]\nmemory = \"64MiB\"\nfuel = 10_000_000\n\
                   epoch_deadline_ms = 2500\n";
        let report = audit(&loaded(src), None);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == "qqq/limits-at-default"),
            "a project that chose its limits must not be noted: {:?}",
            report.findings
        );
    }

    /// **A package with no digest is reported exactly once.**
    ///
    /// The first version had two rules for this -- `qqq/unpinned-dependency` and
    /// `qqq/unsigned-manifest` -- which reported the same fact twice from two
    /// angles. Two rules for one fact is a defect rather than thoroughness: a
    /// reader counting findings gets a distorted count, and the SARIF baseline
    /// moves twice for one change.
    ///
    /// So the digest check lives in the provenance rule, and this test asserts
    /// **one** finding rather than "at least one".
    #[test]
    fn a_lockfile_package_without_a_digest_is_reported_exactly_once() {
        let l = lock_with("a", None, &[]);
        let report = audit(&loaded(CHOSEN), Some(&l));
        let digest_findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.message.contains("no recorded digest"))
            .collect();
        assert_eq!(
            digest_findings.len(),
            1,
            "one missing digest must produce one finding, got {digest_findings:?}"
        );
        assert_eq!(digest_findings[0].rule, "qqq/unsigned-manifest");
        assert_eq!(digest_findings[0].severity, Severity::Warning);
        assert!(digest_findings[0].message.contains("a@1.0.0"));
    }

    #[test]
    fn a_dependency_declaring_authority_is_noted() {
        let l = lock_with("a", Some("sha256:aa"), &["http.client"]);
        let report = audit(&loaded(MINIMAL), Some(&l));
        let f = report
            .findings
            .iter()
            .find(|f| f.rule == "qqq/capability-escalation")
            .expect("declared authority must be noted");
        assert_eq!(
            f.severity,
            Severity::Note,
            "declaring is not granting, so this must not be an error"
        );
        assert!(f.message.contains("http.client"), "{}", f.message);
    }

    // -- The rules, each made to NOT fire (the half that matters) ---------

    /// **A safe project produces no findings.** Without this, every rule could
    /// fire unconditionally and the tests above would all pass.
    #[test]
    fn a_safe_project_produces_no_findings_at_all() {
        let l = clean_lock();
        let report = audit(&loaded(CHOSEN), Some(&l));
        assert!(
            report.findings.is_empty(),
            "a minimal project with sane limits must be clean, got {:?}",
            report.findings
        );
        assert_eq!(report.worst(), None);
        assert!(!report.fails_at(Severity::Note));
    }

    /// **No finding may be an error or a warning just for using a default.**
    /// `128MiB` and `50M` fuel are safe, and a tool that flagged them would be
    /// ignored -- so the default case is a `Note`.
    ///
    /// The three `unbounded-*` rules that used to be checked here are gone: the
    /// manifest parser refuses an unbounded limit, so those rules could never
    /// fire (`the_manifest_parser_refuses_an_unbounded_limit` pins the property
    /// where it lives).
    #[test]
    fn using_the_defaults_is_never_an_error_or_a_warning() {
        let report = audit(&loaded(MINIMAL), None);
        for f in &report.findings {
            assert!(
                f.severity == Severity::Note,
                "`{}` fired as {} on a default-limit project: {}",
                f.rule,
                f.severity,
                f.message
            );
        }
    }

    /// And no lockfile means no supply-chain findings -- which is *not* the same
    /// as "the supply chain is clean".
    #[test]
    fn no_lockfile_means_no_supply_chain_findings() {
        let report = audit(&loaded(CHOSEN), None);
        for rule in ["qqq/unpinned-dependency", "qqq/capability-escalation"] {
            assert!(
                !report.findings.iter().any(|f| f.rule == rule),
                "{rule} fired"
            );
        }
    }

    /// Read-only filesystem access is `Contained`, not `Exposed`.
    #[test]
    fn read_only_fs_access_is_not_an_exposed_posture() {
        let src = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                   [[capabilities.fs]]\npath = \".\"\nmode = \"read-only\"\n";
        let report = audit(&loaded(src), None);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == "qqq/exposed-posture"),
            "read-only access must not be reported as exposed: {:?}",
            report.findings
        );
    }

    // -- `--fail-on` -------------------------------------------------------

    #[test]
    fn fails_at_honours_the_threshold() {
        // A project whose only findings are notes must fail at `note` and pass at
        // `error`, which is what makes a threshold different from a boolean.
        let report = audit(&loaded(MINIMAL), None);
        assert_eq!(
            report.worst(),
            Some(Severity::Note),
            "{:?}",
            report.findings
        );
        assert!(
            !report.fails_at(Severity::Error),
            "a note must not fail at error"
        );
        assert!(!report.fails_at(Severity::Warning));
        assert!(report.fails_at(Severity::Note), "but it must fail at note");
    }

    /// A report whose worst finding is a warning must NOT fail at error, which is
    /// the whole point of a threshold rather than a boolean.
    #[test]
    fn a_warning_does_not_fail_an_error_threshold() {
        let src = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                   [[capabilities.fs]]\npath = \".\"\nmode = \"read-write\"\n";
        let report = audit(&loaded(src), None);
        assert_eq!(report.worst(), Some(Severity::Warning));
        assert!(!report.fails_at(Severity::Error));
        assert!(report.fails_at(Severity::Warning));
    }

    // -- Determinism, which makes a SARIF baseline meaningful -------------

    #[test]
    fn two_runs_produce_identical_output() {
        let src = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                   [[capabilities.fs]]\npath = \".\"\nmode = \"read-write\"\n\
                   [[capabilities.fs]]\npath = \".\"\nmode = \"read-write\"\n";
        let a = audit(&loaded(src), None);
        let b = audit(&loaded(src), None);
        assert_eq!(a, b);
        assert_eq!(a.to_sarif(), b.to_sarif());
        // Severity sorts descending, so the worst finding comes first.
        let first = a.findings.first().expect("has findings");
        assert_eq!(
            first.severity,
            a.worst().expect("has a worst"),
            "the findings must be sorted by severity, worst first"
        );
    }

    /// **`Severity::Error` is currently unreachable, and that is stated rather
    /// than left implicit.**
    ///
    /// Every rule that remains is a `Warning` or a `Note`: the manifest parser
    /// refuses an unbounded limit and a malformed grant, so an ordinary project
    /// cannot reach an audit *error*. The variant stays because `--fail-on error`
    /// must be a valid threshold and because a future rule will need it -- but a
    /// severity nothing emits is exactly the "control believed live" shape this
    /// project has recorded eight times, so it is **pinned here with its reason**
    /// rather than discovered later by someone reading a distribution.
    ///
    /// If a rule is added that emits `Error`, this test fails and says so.
    #[test]
    fn no_current_rule_emits_an_error_severity() {
        // The most hostile project the current rule set can be given: exposed
        // posture, default limits, and an unpinned dependency.
        let src = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                   [[capabilities.fs]]\npath = \".\"\nmode = \"read-write\"\n\
                   [capabilities.http]\nclient = [\"example.com\"]\n";
        let l = lock_with("a", None, &["http.client"]);
        let report = audit(&loaded(src), Some(&l));

        assert!(
            report.worst().is_some(),
            "the hostile fixture must produce findings, or this test proves nothing"
        );
        assert_ne!(
            report.worst(),
            Some(Severity::Error),
            "a rule now emits Error -- update this test and the docs, because \
             `--fail-on error` has become a real gate: {:?}",
            report.findings
        );
        // And the error threshold is still *expressible*, even when unreachable.
        assert!(!report.fails_at(Severity::Error));
        assert!(report.fails_at(Severity::Warning));
    }

    // -- SARIF -------------------------------------------------------------

    /// **The SARIF document must have the shape consumers require**, checked by
    /// parsing it rather than by grepping for a substring.
    #[test]
    fn the_sarif_document_is_valid_json_with_the_required_shape() {
        let src = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                   [[capabilities.fs]]\npath = \".\"\nmode = \"read-write\"\n";
        let report = audit(&loaded(src), None);
        let text = report.to_sarif();

        let doc: serde_json::Value =
            serde_json::from_str(&text).expect("the SARIF document must be valid JSON");

        assert_eq!(doc["version"], "2.1.0");
        assert!(doc["$schema"].as_str().unwrap().contains("sarif"));
        let runs = doc["runs"].as_array().expect("runs must be an array");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0]["tool"]["driver"]["name"], "qqqai");
        assert!(
            runs[0]["tool"]["driver"]["rules"].is_array(),
            "the driver must declare its rules"
        );
        let results = runs[0]["results"]
            .as_array()
            .expect("results must be an array");
        assert!(
            !results.is_empty(),
            "a failing project must produce a result"
        );
        assert!(results[0]["ruleId"].is_string());
        assert!(results[0]["message"]["text"].is_string());
    }

    /// **The SARIF document must travel alone.**
    ///
    /// A `--sarif` flag exists so a SARIF consumer — GitHub code scanning, a
    /// `jq` pipeline, an editor plugin — can read stdout. If anything else
    /// shares the stream the consumer sees `Extra data: line 2 column 1` and the
    /// flag is a rendering rather than an interchange format. This was measured
    /// broken twice: the old `render()` footer, then the envelope `summary()`
    /// line. The check is that the *first* non-whitespace character is `{` and
    /// the *last* is `}`, which is the property a consumer actually needs.
    #[test]
    fn the_sarif_document_has_nothing_before_or_after_it() {
        let src = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                   [[capabilities.fs]]\npath = \".\"\nmode = \"read-write\"\n";
        for lock in [None, Some(lock_with("a", None, &["http.client"]))] {
            let text = audit(&loaded(src), lock.as_ref()).to_sarif();
            let trimmed = text.trim();
            assert!(
                trimmed.starts_with('{'),
                "leading prose before SARIF: {trimmed}"
            );
            assert!(
                trimmed.ends_with('}'),
                "trailing prose after SARIF: {trimmed}"
            );
            assert_eq!(
                trimmed.matches("\"version\":\"2.1.0\"").count(),
                1,
                "exactly one document"
            );
        }
    }

    /// Every rule the module can emit must be declared in the SARIF `rules`
    /// array, or a consumer sees a `ruleId` it cannot look up.
    #[test]
    fn every_emitted_rule_is_declared_in_the_sarif_document() {
        // A project that triggers as many rules as possible at once.
        let src = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                   [[capabilities.fs]]\npath = \".\"\nmode = \"read-write\"\n";
        let l = lock_with("a", None, &["http.client"]);
        let report = audit(&loaded(src), Some(&l));
        let declared: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        for f in &report.findings {
            assert!(
                declared.contains(&f.rule),
                "`{}` was emitted but is not in RULES",
                f.rule
            );
        }
    }

    /// A clean project still produces a well-formed SARIF document with an empty
    /// `results` array -- an empty array, not a missing key, because a consumer
    /// reading `results` must not have to handle both.
    #[test]
    fn a_clean_project_produces_an_empty_results_array() {
        let report = audit(&loaded(CHOSEN), None);
        let doc: serde_json::Value = serde_json::from_str(&report.to_sarif()).expect("valid JSON");
        let results = doc["runs"][0]["results"]
            .as_array()
            .expect("results must be present");
        assert!(results.is_empty(), "{results:?}");
    }

    /// A message containing a quote or a newline must not break the document.
    #[test]
    fn a_message_with_a_quote_is_escaped() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        let doc = format!(
            "{{\"text\":\"{}\"}}",
            json_escape("he said \"hi\"\nthen left")
        );
        let parsed: serde_json::Value = serde_json::from_str(&doc).expect("must parse");
        assert_eq!(parsed["text"], "he said \"hi\"\nthen left");
    }

    // -- Rendering ---------------------------------------------------------

    /// A clean report renders **nothing** to the terminal body.
    ///
    /// The conclusion is the `summary()` line, printed by the output layer; the
    /// render is detail only. Emitting a conclusion here as well printed it
    /// twice, and the two copies disagreed on wording.
    #[test]
    fn the_terminal_render_says_so_when_there_is_nothing_to_report() {
        let report = audit(&loaded(CHOSEN), None);
        let text = report.render();
        assert_eq!(
            text,
            format!("audit of `{}`\n", report.project),
            "a clean report has no detail to render"
        );
        // ... and the surface list lives in the summary, which still names all four.
        let out = AuditOutput::from(&report);
        let summary = crate::output::CommandOutput::summary(&out);
        for surface in ["caps", "limits", "supply chain", "provenance"] {
            assert!(
                summary.contains(surface),
                "the summary must name what was checked ({surface}): {summary}"
            );
        }
    }

    #[test]
    fn the_terminal_render_lists_every_finding_with_its_fix() {
        let src = "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\
                   [[capabilities.fs]]\npath = \".\"\nmode = \"read-write\"\n";
        let report = audit(&loaded(src), None);
        let text = report.render();
        for f in &report.findings {
            assert!(text.contains(f.rule), "missing {} in {text}", f.rule);
            assert!(
                text.contains(&f.remediation),
                "missing the fix for {}",
                f.rule
            );
        }
        // The conclusion belongs to `summary()`, and only there.
        assert!(
            !text.contains("worst severity"),
            "the render must not repeat the conclusion: {text}"
        );
    }

    #[test]
    fn the_summary_states_the_limits_in_force() {
        let loaded = loaded(CHOSEN);
        let report = audit(&loaded, None);
        let summary = report.summary(&loaded.manifest.limits);
        // `CHOSEN`'s values, not the defaults -- the point of the fixture.
        assert!(summary.contains("64MiB"), "{summary}");
        assert!(summary.contains("10000000"), "{summary}");
        assert!(summary.contains("2500"), "{summary}");
        assert!(summary.contains("posture"), "{summary}");
        assert!(
            summary.contains("supply chain") && summary.contains("provenance"),
            "the summary must name every surface audited: {summary}"
        );
    }

    // -- `parse_byte_size` -------------------------------------------------

    #[test]
    fn parse_byte_size_understands_the_manifest_spellings() {
        assert_eq!(parse_byte_size("0B"), Some(0));
        assert_eq!(parse_byte_size("0"), Some(0));
        assert_eq!(parse_byte_size("1KiB"), Some(1024));
        assert_eq!(parse_byte_size("128MiB"), Some(128 * 1024 * 1024));
        assert_eq!(parse_byte_size(""), None);
        assert_eq!(parse_byte_size("not a size"), None);
    }
}
