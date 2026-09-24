// SPDX-License-Identifier: Apache-2.0

//! The capability-facing commands: `why`, `caps` and `inspect`.
//!
//! These three are what make the capability model *usable*. The engine in
//! `qqq-cap` is proven correct and invisible without them; with them, a
//! developer who hits a denial has a one-command answer, and an agent can
//! enumerate what a component may do without running it.
//!
//! Proposal §6.2 calls `qqqai why` "the killer DX affordance" and §5.2 lists
//! `inspect` among "the surfaces that make QQQ different". Neither claim is
//! worth anything until the commands exist.

// `fmt::Write` for `write!`/`writeln!` into a `String`.
//
// Used instead of `push_str(&format!(..))` because that allocates a second
// string and immediately discards it. Clippy's `format_push_string` flagged
// every site, and it is right in a path that builds output on every command
// invocation — the allocation is pure overhead for a formatting operation.
use std::fmt::Write as _;

use serde::Serialize;

use qqq_abi::registry;
use qqq_cap::capability::Capability;
use qqq_cap::resolve::{Layer, Overlay, Resolution};
use qqq_core::{Error, ErrorCode, Result};

use crate::manifest_loader::LoadedManifest;
use crate::output::{CommandName, CommandOutput};

// ---------------------------------------------------------------------------
// why
// ---------------------------------------------------------------------------

/// The result of `qqqai why <capability>`.
#[derive(Debug, Clone, Serialize)]
pub struct WhyOutput {
    /// The capability being explained.
    pub capability: String,
    /// The final decision.
    pub granted: bool,
    /// The layer that decided, when one is identifiable.
    pub decided_by: Option<String>,
    /// Each step, in order.
    pub steps: Vec<WhyStep>,
    /// A runnable next step when the answer is "denied".
    pub fix: Option<String>,
}

/// One step in a capability's resolution history.
#[derive(Debug, Clone, Serialize)]
pub struct WhyStep {
    /// The layer that made this decision.
    pub layer: String,
    /// The rule that fired.
    pub rule: String,
    /// The state before this step.
    pub before: bool,
    /// The state after this step.
    pub after: bool,
}

impl CommandOutput for WhyOutput {
    fn command(&self) -> CommandName {
        CommandName::Why
    }

    fn summary(&self) -> String {
        // The verdict alone is not the answer to "why". This command is run at
        // the moment a capability has been denied, and the two things the
        // person needs are *which layer decided* and *the exact text that
        // would change it*. Printing only `http.server DENIED` — which is what
        // this did before — answers a question the user already knew the
        // answer to, while the stanza they came for sat unread in `fix`.
        //
        // The human-readable output is the one most users see; if it omits the
        // payload, the command has failed even though the JSON is complete.
        let mut out = if self.granted {
            format!("{} GRANTED", self.capability)
        } else {
            format!("{} DENIED", self.capability)
        };

        if let Some(layer) = &self.decided_by {
            let _ = write!(out, " by {layer}");
        } else if !self.granted {
            // No layer changed anything, which means it was never granted
            // anywhere. Saying so is better than silence: it tells the reader
            // the denial is the default rather than a rule they can go find.
            out.push_str(" (default: not granted by any layer)");
        }

        if let Some(fix) = &self.fix {
            // Printed **verbatim**. `fix_stanza_for` produces the complete,
            // ready-to-read block — its own `add to qqq.toml:` preamble and its
            // own indentation — because it is also emitted in the JSON `fix`
            // field, which has no renderer to add either. An earlier version of
            // this function added a second preamble and re-indented every line,
            // so the terminal showed "add to qqq.toml:" twice and left trailing
            // whitespace inside the stanza.
            //
            // The lesson is the usual one: the string was correct, and the
            // surface re-processed it. Print what the producer produced.
            out.push_str("\n\n");
            out.push_str(fix);
        }

        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Explain a capability's resolution.
///
/// # Errors
///
/// `QQQ-2007` when the capability name is unknown, with a suggestion when one
/// is close — because a typo in a capability name is the most likely reason
/// this command is run at all.
pub fn why(loaded: &LoadedManifest, capability: &str) -> Result<WhyOutput> {
    let cap = Capability::from_name(capability).ok_or_else(|| {
        let hint = Capability::suggest(capability).map_or_else(
            || " — run `qqqai caps` for the capabilities this project declares".to_owned(),
            |c| format!(" — did you mean `{c}`?"),
        );
        Error::new(
            ErrorCode::CapabilitySyntaxInvalid,
            format!("unknown capability `{capability}`{hint}"),
        )
        .with_remediation("capability names are lowercase dotted pairs, e.g. `http.client`")
    })?;

    // Resolve with no overlays: the manifest is the only layer that runs in a
    // plain `qqqai why` invocation. Overlays require policy sources that are a
    // deployment concern, and inventing them here would make the output depend
    // on the developer's machine.
    let resolution = Resolution::from_manifest(&loaded.manifest);

    let steps: Vec<WhyStep> = resolution
        .trace
        .iter()
        .filter(|n| n.capability == Some(cap))
        .map(|n| WhyStep {
            layer: n.layer.as_str().to_owned(),
            rule: n.reason.clone(),
            before: n.granted_before,
            after: n.granted_after,
        })
        .collect();

    let granted = resolution.grants.grants(cap);
    // `.rev().find()` rather than `.last()`: the trace can be long, and the
    // deciding layer is the *final* transition, so searching backwards stops at
    // the first match instead of walking the whole history.
    let decided_by = resolution
        .trace
        .iter()
        .rev()
        .find(|n| n.capability == Some(cap) && n.changed())
        .map(|n| n.layer.as_str().to_owned());

    Ok(WhyOutput {
        capability: cap.name().to_owned(),
        granted,
        decided_by,
        steps,
        fix: (!granted).then(|| fix_stanza_for(cap)),
    })
}

/// The exact `qqq.toml` stanza that would grant a capability.
///
/// # Why this is generated rather than documented
///
/// A developer who hits a denial needs the *exact* text, not a link to a
/// capabilities reference. Generating it from the capability's namespace means
/// the suggestion cannot drift from the parser's expectations.
#[must_use]
pub fn fix_stanza_for(c: Capability) -> String {
    match c.namespace() {
        "http" => "add to qqq.toml:\n\n    [capabilities.http]\n    server = true          # for http.server\n    client = [\"host:443\"]  # for http.client".to_owned(),
        "fs" => "add to qqq.toml:\n\n    [[capabilities.fs]]\n    path = \"/var/lib/app\"\n    mode = \"read-only\"     # or \"append-only\" / \"read-write\"".to_owned(),
        "crypto" => "add to qqq.toml:\n\n    [capabilities.crypto]\n    random = true          # for crypto.random\n    hash = [\"sha256\"]      # for crypto.hash\n    hmac = [\"sha256\"]      # for crypto.hmac\n    aead = [\"aes-256-gcm\"] # for crypto.aead\n    sign = [\"ed25519\"]     # for crypto.sign\n    secrets = [\"env:NAME\"] # for secret.use".to_owned(),
        "clock" => "add to qqq.toml:\n\n    [capabilities.clock]\n    wall = true            # for clock.wall\n    monotonic = true       # for clock.monotonic".to_owned(),
        "env" => "add to qqq.toml:\n\n    [capabilities.env]\n    allow = [\"LOG_LEVEL\"]  # name each variable; wildcards are refused".to_owned(),
        "dns" => "add to qqq.toml:\n\n    [capabilities.dns]\n    resolve = [\"api.example.com\"]".to_owned(),
        "sql" => "add to qqq.toml:\n\n    [[capabilities.sql]]\n    name = \"orders\"\n    driver = \"postgres\"\n    host = \"db.internal:5432\"\n    secret = \"env:ORDERS_DB_URL\"".to_owned(),
        "kv" => "add to qqq.toml:\n\n    [capabilities.kv]\n    stores = [\"sessions\"]".to_owned(),
        "queue" => "add to qqq.toml:\n\n    [[capabilities.queue]]\n    name = \"orders.events\"\n    direction = \"publish\"  # or \"subscribe\"".to_owned(),
        "ai" => "add to qqq.toml:\n\n    [capabilities.ai]\n    providers = [\"local:ggml\"]\n    models = [\"*:<=4B\"]".to_owned(),
        other => format!("add a `[[capabilities.{other}]]` stanza to qqq.toml"),
    }
}

// ---------------------------------------------------------------------------
// caps
// ---------------------------------------------------------------------------

/// The result of `qqqai caps`.
#[derive(Debug, Clone, Serialize)]
pub struct CapsOutput {
    /// The project name.
    pub project: String,
    /// The effective grants, sorted.
    pub grants: Vec<String>,
    /// The stable digest of the grant set, as it appears in the audit stream.
    pub digest: String,
    /// Which layers contributed.
    pub layers: Vec<String>,
    /// Capabilities grouped by namespace, for a readable summary.
    pub by_namespace: Vec<NamespaceGroup>,
    /// Capabilities that are covert channels, called out separately.
    pub covert_channels: Vec<String>,
    /// Whether the project grants nothing at all.
    pub deny_all: bool,
    /// Per-capability reasoning, populated only by `--explain`.
    ///
    /// Absent from the JSON of a plain `caps` rather than present-and-empty, so a
    /// consumer reading the envelope can tell "not asked for" from "no decisions" --
    /// an empty array would conflate the two.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub explained: Vec<ExplainedCapability>,
    /// Non-blocking warnings from resolution, e.g. a developer overlay being active.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Capabilities sharing a namespace.
#[derive(Debug, Clone, Serialize)]
pub struct NamespaceGroup {
    /// The namespace, e.g. `crypto`.
    pub namespace: String,
    /// The capabilities in it.
    pub capabilities: Vec<String>,
}

impl CommandOutput for CapsOutput {
    fn command(&self) -> CommandName {
        CommandName::Caps
    }

    fn summary(&self) -> String {
        // In human format this function *is* the output — the renderer writes
        // nothing else — so a command listing capabilities must list them.
        //
        // It previously printed only `app: 2 capabilities across 2 namespaces`,
        // which is the answer to a question nobody asks: the user ran `caps` to
        // find out *which* capabilities, and the names were sitting unread in
        // the JSON envelope. A count is a useful heading and a useless answer.
        if self.deny_all {
            return format!(
                "{}: no capabilities granted\n\nNothing is granted, which is the default: a \
                 capability\nabsent from qqq.toml is denied. Run `qqqai why <capability>` to\n\
                 get the exact stanza that would grant one.{}",
                self.project,
                self.warning_suffix()
            );
        }

        let mut out = format!(
            "{}: {} capabilities across {} namespace{}\n",
            self.project,
            self.grants.len(),
            self.by_namespace.len(),
            if self.by_namespace.len() == 1 {
                ""
            } else {
                "s"
            }
        );

        // Indexed by name so the loop below stays a lookup rather than a scan: a
        // quadratic walk over a hundred capabilities is small but pointless, and the map
        // is already the shape the JSON uses.
        let reasoning: std::collections::BTreeMap<&str, &ExplainedCapability> = self
            .explained
            .iter()
            .map(|e| (e.capability.as_str(), e))
            .collect();

        for ns in &self.by_namespace {
            let _ = write!(out, "\n  {}\n", ns.namespace);
            for cap in &ns.capabilities {
                if let Some(e) = reasoning.get(cap.as_str()) {
                    let _ = writeln!(out, "    {cap}");
                    // Each step is one line, aligned, with the layer first because the
                    // question `--explain` answers is "which layer?". A step that *removed*
                    // the capability is the interesting one, so it says so rather than
                    // printing a bare `false`.
                    for d in &e.decisions {
                        let _ = writeln!(
                            out,
                            "      {:<12} {} {}",
                            d.layer,
                            if d.granted { "grants:" } else { "revokes:" },
                            d.rule
                        );
                    }
                } else {
                    let _ = writeln!(out, "    {cap}");
                }
            }
        }
        out.pop();

        if self.explained.iter().all(|e| e.decisions.is_empty()) && !self.explained.is_empty() {
            let _ = write!(
                out,
                "\n\nNo layer recorded a decision for these capabilities. That means each was \
                 granted\nby qqq.toml and nothing narrowed it -- which is the normal case."
            );
        }

        if !self.layers.is_empty() {
            let _ = write!(out, "\n\nGranted by: {}", self.layers.join(", "));
        }
        if !self.covert_channels.is_empty() {
            let _ = write!(
                out,
                "\nCovert channels not yet closed: {}",
                self.covert_channels.join(", ")
            );
        }
        let _ = write!(out, "{}", self.warning_suffix());
        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

impl CapsOutput {
    /// The resolution warnings, as a trailing block.
    ///
    /// # Why this is a method and not two copies
    ///
    /// Both `summary` returns need it — the deny-all path and the listing path — and a
    /// developer overlay is *most* likely to have emptied the grant set, which is exactly
    /// the path a copy would have missed.
    fn warning_suffix(&self) -> String {
        if self.warnings.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for w in &self.warnings {
            let _ = write!(out, "\n\nwarning: {w}");
        }
        out
    }
}

/// One capability with the reasoning behind it, for `caps --explain`.
///
/// # Why this is a list of decisions and not a sentence
///
/// A capability can be touched by several layers, and `--explain` exists to show
/// **which** one decided. Rendering it as prose would lose the layer boundary that
/// `audit.rs` sends the reader here to find.
#[derive(Debug, Clone, Serialize)]
pub struct ExplainedCapability {
    /// The capability.
    pub capability: String,
    /// Every step that changed this capability's fate, in order.
    pub decisions: Vec<ExplainedDecision>,
}

/// One layer's decision about one capability.
#[derive(Debug, Clone, Serialize)]
pub struct ExplainedDecision {
    /// The layer that made the decision.
    pub layer: String,
    /// The rule that fired, as the resolver recorded it.
    pub rule: String,
    /// Whether the capability is granted after this step.
    pub granted: bool,
}

/// Show the effective grants for a project.
///
/// # Why `explain` is a parameter and not a second function
///
/// The two renderings share the resolution, the grouping and the digest, and differ only in
/// whether each capability carries its reasoning. A separate function would duplicate the
/// resolution, and the two copies would eventually disagree about what is granted -- which
/// is the one thing this command must not get wrong.
#[must_use]
pub fn caps(loaded: &LoadedManifest, explain: bool) -> CapsOutput {
    let resolution = Resolution::from_manifest(&loaded.manifest);
    let grants: Vec<Capability> = resolution.grants.capabilities();

    let mut by_ns: std::collections::BTreeMap<&'static str, Vec<String>> =
        std::collections::BTreeMap::new();
    for &c in &grants {
        by_ns
            .entry(c.namespace())
            .or_default()
            .push(c.name().to_owned());
    }

    CapsOutput {
        project: loaded.name().to_owned(),
        grants: grants.iter().map(|c| c.name().to_owned()).collect(),
        digest: resolution.grants.digest(),
        layers: resolution
            .grants
            .applied_layers()
            .iter()
            .map(|l| l.as_str().to_owned())
            .collect(),
        by_namespace: by_ns
            .into_iter()
            .map(|(namespace, capabilities)| NamespaceGroup {
                namespace: namespace.to_owned(),
                capabilities,
            })
            .collect(),
        covert_channels: loaded
            .manifest
            .covert_channels()
            .iter()
            .map(|c| c.name().to_owned())
            .collect(),
        deny_all: grants.is_empty(),
        // Built only when asked, so the ordinary listing does not pay for the trace and
        // the JSON of a plain `caps` does not grow a field nobody requested.
        explained: if explain {
            grants
                .iter()
                .map(|&c| ExplainedCapability {
                    capability: c.name().to_owned(),
                    decisions: resolution
                        .trace
                        .iter()
                        .filter(|n| n.capability == Some(c) && n.changed())
                        .map(|n| ExplainedDecision {
                            layer: n.layer.as_str().to_owned(),
                            rule: n.reason.clone(),
                            granted: n.granted_after,
                        })
                        .collect(),
                })
                .collect()
        } else {
            Vec::new()
        },
        warnings: resolution.warnings.clone(),
    }
}

// ---------------------------------------------------------------------------
// openapi
// ---------------------------------------------------------------------------

/// The result of `qqqai openapi`.
///
/// # Why the document is embedded and not just counted
///
/// The JSON envelope is what an agent or a front-end consumes, and the answer to "give me the
/// `OpenAPI` description" is **the description**. A payload of counts and a path would force
/// every consumer to read the file back, and one that could not — a sandboxed agent, a pipe
/// with no filesystem — would have been handed a receipt instead of the thing.
///
/// `document` is the parsed value, not a string of JSON: a string would make each consumer
/// parse twice and the one that forgot would find a quoted blob.
#[derive(Debug, Clone, Serialize)]
pub struct OpenapiOutput {
    /// The spec version emitted.
    pub openapi: String,
    /// The project name.
    pub title: String,
    /// The project version.
    pub version: String,
    /// How many paths the document describes.
    pub path_count: usize,
    /// How many operations it describes.
    pub operation_count: usize,
    /// Where the document was written, or `None` when it was only printed.
    ///
    /// `None` and an empty string are different facts: the first means nothing was written, the
    /// second would mean something tried to write to nowhere.
    pub out: Option<String>,
    /// The document itself.
    pub document: serde_json::Value,
}

impl CommandOutput for OpenapiOutput {
    fn command(&self) -> CommandName {
        CommandName::Openapi
    }

    fn summary(&self) -> String {
        // As with `caps` and `inspect`: in human format this function *is* the output. It
        // therefore carries the **routes**, because a description of an app whose paths the
        // reader cannot see is a receipt, and the user ran the command to see the surface.
        let mut out = format!(
            "{} {}: {} path{}, {} operation{}, OpenAPI {}\n",
            self.title,
            self.version,
            self.path_count,
            if self.path_count == 1 { "" } else { "s" },
            self.operation_count,
            if self.operation_count == 1 { "" } else { "s" },
            self.openapi
        );
        if let Some(paths) = self.document.get("paths").and_then(|p| p.as_object()) {
            for (path, item) in paths {
                let methods: Vec<&str> = [
                    "get", "post", "put", "patch", "delete", "head", "options", "trace",
                ]
                .into_iter()
                .filter(|m| item.get(*m).is_some())
                .collect();
                let _ = writeln!(out, "  {:<7} {}", methods.join(",").to_uppercase(), path);
            }
        }
        match &self.out {
            Some(p) => {
                let _ = write!(out, "\nWritten to {p}\n");
            }
            None => {
                let _ = write!(out, "\nNothing written; pass --out <file> to save it.\n");
            }
        }
        out
    }

    fn to_json(&self) -> serde_json::Value {
        // Serialized from `self`, so the envelope and the struct cannot drift. The schema in
        // `output.rs` describes exactly these fields.
        serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}))
    }
}

/// Generate the `OpenAPI` document for a loaded manifest.
///
/// # Errors
///
/// Propagated from [`crate::openapi::document`] — a route the spec cannot express, or a
/// pattern with a brace. Both are named in the error rather than skipped.
pub fn openapi(loaded: &crate::manifest_loader::LoadedManifest) -> Result<OpenapiOutput> {
    let doc = crate::openapi::document(
        &loaded.manifest.package.name,
        &loaded.manifest.package.version,
        &loaded.manifest.server,
    )?;

    // Counted from the generated document rather than from the manifest, so the numbers and
    // the payload cannot disagree. Counting the manifest's routes would give a different
    // `path_count` whenever two routes share a path -- which is ordinary, and would make the
    // summary wrong in exactly the case a user checks it.
    let path_count = doc.paths.len();
    let operation_count = doc.paths.values().filter(|i| !i.is_empty()).count();
    let document = serde_json::to_value(&doc).map_err(|e| {
        Error::new(
            ErrorCode::InternalInvariantViolated,
            "the OpenAPI document could not be serialized".to_owned(),
        )
        .with_cause(e.to_string())
    })?;

    Ok(OpenapiOutput {
        openapi: crate::openapi::OPENAPI_VERSION.to_owned(),
        title: loaded.manifest.package.name.clone(),
        version: loaded.manifest.package.version.clone(),
        path_count,
        operation_count,
        out: None,
        document,
    })
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

/// The result of `qqqai inspect`.
#[derive(Debug, Clone, Serialize)]
pub struct InspectOutput {
    /// The project name.
    pub project: String,
    /// The capabilities declared.
    pub capabilities: Vec<String>,
    /// The WIT interfaces those capabilities unlock.
    pub interfaces: Vec<InterfaceReport>,
    /// The resource limits that will be enforced.
    pub limits: LimitsReport,
    /// A human-readable security posture.
    pub posture: Posture,
}

/// One interface a component will be able to import.
#[derive(Debug, Clone, Serialize)]
pub struct InterfaceReport {
    /// The versioned WIT name.
    pub name: String,
    /// What it provides.
    pub summary: String,
    /// Whether this build can serve it.
    pub implemented: bool,
}

/// The limits that will be applied.
#[derive(Debug, Clone, Serialize)]
pub struct LimitsReport {
    /// Memory cap as written in the manifest.
    pub memory: String,
    /// Instruction budget.
    pub fuel: u64,
    /// Wall-clock deadline in milliseconds.
    pub epoch_deadline_ms: u64,
    /// The per-tenant request limits, absent when the manifest declares none.
    ///
    /// # Why this is reported at all
    ///
    /// `[server.limits]` bounds what a **client** may send, and it was enforced by the
    /// server while appearing nowhere in `qqqai inspect` — the command whose whole
    /// purpose is to answer "what will this project do?". A limit an operator cannot see
    /// is a limit they will not know to change, and the connection ceiling was in exactly
    /// that state until `SRV-020` was finished. `None` is reported as an absence rather
    /// than as zeroes: the manifest saying "no limits" is a different fact from "limits of
    /// zero", and the runtime treats the two differently.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_limits: Option<RequestLimitsReport>,
}

/// The per-tenant request limits, as declared.
#[derive(Debug, Clone, Serialize)]
pub struct RequestLimitsReport {
    /// The cap for a tenant with no entry, or `None` when the manifest sets none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<TenantLimitReport>,
    /// Per-tenant entries, keyed by the client address they match.
    pub per_tenant: Vec<TenantLimitReport>,
}

/// One tenant's declared limits, flattened for display.
#[derive(Debug, Clone, Serialize)]
pub struct TenantLimitReport {
    /// The tenant this entry applies to, or `"default"` for the fallback.
    pub tenant: String,
    /// The largest request body accepted, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    /// The largest number of requests allowed per window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_requests_per_window: Option<u32>,
    /// The window those requests are counted over.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_seconds: Option<u64>,
    /// The largest number of simultaneous connections the tenant may hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
}

impl TenantLimitReport {
    /// One entry, from the manifest's own type.
    #[must_use]
    fn from_declared(tenant: &str, l: &qqq_cap::manifest::TenantLimit) -> Self {
        Self {
            tenant: tenant.to_owned(),
            max_body_bytes: l.max_body_bytes,
            max_requests_per_window: l.max_requests_per_window,
            window_seconds: l.window_seconds,
            max_connections: l.max_connections,
        }
    }

    /// Whether this entry carries no limit at all.
    #[must_use]
    const fn is_empty(&self) -> bool {
        self.max_body_bytes.is_none()
            && self.max_requests_per_window.is_none()
            && self.max_connections.is_none()
    }
}

impl RequestLimitsReport {
    /// The report for a manifest's table, or `None` when there is no table.
    ///
    /// An entry with no limit set is dropped: a `[server.limits.per_tenant."1.2.3.4"]`
    /// header with nothing under it declares nothing, and listing it would suggest a
    /// policy that does not exist.
    #[must_use]
    fn from_declared(l: &qqq_cap::manifest::RequestLimits) -> Self {
        let default = l
            .default
            .as_ref()
            .map(|d| TenantLimitReport::from_declared("default", d))
            .filter(|d| !d.is_empty());
        let per_tenant = l
            .per_tenant
            .iter()
            .map(|(tenant, limit)| TenantLimitReport::from_declared(tenant, limit))
            .filter(|e| !e.is_empty())
            .collect();
        Self {
            default,
            per_tenant,
        }
    }

    /// Whether the table declares nothing after filtering.
    #[must_use]
    fn is_empty(&self) -> bool {
        self.default.is_none() && self.per_tenant.is_empty()
    }
}

/// The overall security posture, as an enum rather than prose.
///
/// # Why a closed set and not a sentence
///
/// `qqqai audit --fail-on` needs to compare against a severity, and an agent
/// needs to branch on it. Both are impossible against free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Posture {
    /// Grants nothing.
    Minimal,
    /// Grants only ambient or read-only capabilities.
    Contained,
    /// Grants write or egress capabilities.
    Exposed,
}

impl Posture {
    /// The stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Contained => "contained",
            Self::Exposed => "exposed",
        }
    }
}

impl CommandOutput for InspectOutput {
    fn command(&self) -> CommandName {
        CommandName::Inspect
    }

    fn summary(&self) -> String {
        // As with `caps`: in human format this is the whole output, so the
        // counts must be followed by the things counted. The interfaces are
        // what the project actually exposes, and the limits are what bounds it
        // — both were JSON-only.
        let mut out = format!(
            "{}: {} capabilities, {} interfaces, posture: {}",
            self.project,
            self.capabilities.len(),
            self.interfaces.len(),
            self.posture.as_str()
        );

        // A project that cannot run as declared says so on the first line.
        //
        // This is the count a reader needs before anything else: the interfaces below are what
        // the project is *allowed* to import, and one with no host implementation means the
        // artifact will fail at instantiation rather than at the call the author expected. A
        // number buried in a section is the thing people skim past; the first line is not.
        let unimplemented = self.interfaces.iter().filter(|i| !i.implemented).count();
        if unimplemented > 0 {
            let _ = write!(
                out,
                " ({unimplemented} with no host implementation yet, marked below)"
            );
        }

        if !self.interfaces.is_empty() {
            out.push_str("\n\nInterfaces\n");
            for iface in &self.interfaces {
                // The `implemented` flag is rendered, not merely carried.
                //
                // It was in the struct, populated from the registry, and asserted by
                // `inspect_marks_unimplemented_interfaces_honestly` — and the human output printed
                // the bare name anyway. So `qqqai inspect` on a project granting `[[capabilities.fs]]`
                // listed `qqq:fs@1.0.0` as though it were live, and the first hint that it has no
                // host implementation was the `QQQ-6004` at runtime.
                //
                // The JSON carried the field the whole time, which is the trap: a fact that is
                // *available* and not *presented* reads as a fact that does not exist. The
                // annotation is the whole reason `InterfaceReport` has the field.
                if iface.implemented {
                    let _ = writeln!(out, "  {}", iface.name);
                } else {
                    let _ = writeln!(out, "  {}  (no host implementation yet)", iface.name);
                }
            }
            out.pop();
        }

        if !self.capabilities.is_empty() {
            out.push_str("\n\nCapabilities\n");
            for cap in &self.capabilities {
                let _ = writeln!(out, "  {cap}");
            }
            out.pop();
        }

        let limits = &self.limits;
        let _ = write!(
            out,
            "\n\nLimits\n  memory            {}\n  fuel              {}\n  \
             epoch_deadline_ms {}",
            limits.memory, limits.fuel, limits.epoch_deadline_ms
        );

        // The per-tenant request limits, when the manifest declares any. Rendered as a
        // table under its own heading rather than appended to the sandbox limits above:
        // those bound what a **guest** may consume and these bound what a **client** may
        // send, and one list would suggest one policy.
        if let Some(req) = &limits.request_limits {
            let mut rows: Vec<&TenantLimitReport> = Vec::new();
            if let Some(d) = &req.default {
                rows.push(d);
            }
            rows.extend(req.per_tenant.iter());

            let _ = write!(out, "\n\nRequest limits (per tenant)");
            for row in rows {
                let _ = write!(out, "\n  {}", row.tenant);
                if let Some(v) = row.max_body_bytes {
                    let _ = write!(out, "\n      max_body_bytes          {v}");
                }
                if let Some(v) = row.max_requests_per_window {
                    let window = row.window_seconds.unwrap_or(60);
                    let _ = write!(out, "\n      max_requests_per_window {v} per {window}s");
                }
                if let Some(v) = row.max_connections {
                    let _ = write!(out, "\n      max_connections         {v}");
                }
            }
        }

        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// The authority difference between two artifacts.
///
/// # The question this answers
///
/// `qqqai inspect --diff` exists for one scenario: **an artifact changed, and you
/// need to know whether its authority did.** Proposal §5.4 makes the authority
/// delta the central supply-chain signal, because an update that changes no code
/// but gains `http.client` is an event no mainstream tool can currently show.
///
/// Pointed at two builds — the version you ship and the version proposed — this
/// reports exactly which capabilities the second adds and drops.
///
/// # Why the comparison is over capabilities, not interfaces
///
/// The two artifacts may import different interfaces whose capability sets
/// overlap. An artifact that stops importing `qqq:clock/wall-clock` while
/// starting to import `qqq:clock/monotonic-clock` has not gained or lost
/// anything, and an interface-level diff would report two changes that cancel.
/// The question is about authority, so the comparison is over authority.
#[must_use]
pub fn diff_artifacts(before: &ArtifactReport, after: &ArtifactReport) -> ArtifactDiff {
    use std::collections::BTreeSet;

    let before_caps: BTreeSet<&str> = before.required.iter().map(|c| c.name.as_str()).collect();
    let after_caps: BTreeSet<&str> = after.required.iter().map(|c| c.name.as_str()).collect();

    let describe = |name: &str| -> Option<CapabilityChange> {
        // A name that does not resolve cannot happen for a report this crate
        // produced, but returning `None` rather than unwrapping means a future
        // capability rename degrades to a missing line instead of a panic in an
        // audit command.
        Capability::from_name(name).map(|c| CapabilityChange {
            name: c.name().to_owned(),
            kind: c.kind().as_str().to_owned(),
            covert_channel: c.is_covert_channel(),
        })
    };

    let added: Vec<CapabilityChange> = after_caps
        .difference(&before_caps)
        .filter_map(|n| describe(n))
        .collect();
    let removed: Vec<CapabilityChange> = before_caps
        .difference(&after_caps)
        .filter_map(|n| describe(n))
        .collect();
    let mut unchanged: Vec<String> = before_caps
        .intersection(&after_caps)
        .map(|n| (*n).to_owned())
        .collect();
    unchanged.sort();

    // Posture can worsen without any capability being added: an artifact that
    // keeps only the exposed half of a pair is a different risk even when the
    // number of names it imports is unchanged.
    let posture_worsened = posture_rank(after.posture) > posture_rank(before.posture);

    // A gain of a covert channel is an escalation even when the posture band
    // does not move. `clock.wall` and `crypto.random` are `Ambient` and would
    // never lift a component out of `Contained`, but they are exactly the grants
    // §10.5 singles out as information channels the audit stream cannot see.
    let gained_channel = added.iter().any(|c| c.covert_channel);

    ArtifactDiff {
        before: before.artifact.clone(),
        after: after.artifact.clone(),
        before_digest: before.digest.clone(),
        after_digest: after.digest.clone(),
        added,
        removed,
        unchanged,
        escalation: posture_worsened || gained_channel,
        before_posture: before.posture.as_str().to_owned(),
        after_posture: after.posture.as_str().to_owned(),
    }
}

/// The authority difference between two artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactDiff {
    /// The artifact compared from.
    pub before: String,
    /// The artifact compared to.
    pub after: String,
    /// The digest of the first, so a diff is tied to the bytes it describes.
    pub before_digest: String,
    /// The digest of the second.
    pub after_digest: String,
    /// Capabilities the second requires and the first did not.
    pub added: Vec<CapabilityChange>,
    /// Capabilities the first required and the second does not.
    pub removed: Vec<CapabilityChange>,
    /// Capabilities both require.
    pub unchanged: Vec<String>,
    /// Whether the second artifact's authority **grew**.
    ///
    /// Denormalized so CI can branch on it in one comparison. This is the flag
    /// §5.4's whole argument rests on being checkable.
    pub escalation: bool,
    /// The posture before.
    pub before_posture: String,
    /// The posture after.
    pub after_posture: String,
}

/// One capability, with the context a reader needs to judge it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityChange {
    /// The capability name.
    pub name: String,
    /// `ambient`, `resource` or `operation`.
    pub kind: String,
    /// Whether it is a covert channel or exfiltration path.
    pub covert_channel: bool,
}

/// How exposed a posture is, for comparing two.
const fn posture_rank(p: Posture) -> u8 {
    match p {
        Posture::Minimal => 0,
        Posture::Contained => 1,
        Posture::Exposed => 2,
    }
}

impl CommandOutput for ArtifactDiff {
    fn command(&self) -> CommandName {
        CommandName::Inspect
    }

    fn summary(&self) -> String {
        // The escalation leads when there is one, for the same reason
        // `install`'s capability diff does: it is the signal, and burying it
        // after a list of unchanged capabilities invites skimming past it.
        let mut out = if self.escalation {
            format!("AUTHORITY ESCALATION: {} → {}", self.before, self.after)
        } else if self.added.is_empty() && self.removed.is_empty() {
            format!("no authority change: {} → {}", self.before, self.after)
        } else {
            format!("authority changed: {} → {}", self.before, self.after)
        };

        for c in &self.added {
            let mark = if c.covert_channel {
                "  [covert channel]"
            } else {
                ""
            };
            let _ = write!(out, "\n  + {:<20} ({}){mark}", c.name, c.kind);
        }
        for c in &self.removed {
            let _ = write!(out, "\n  - {:<20} ({})", c.name, c.kind);
        }

        let _ = write!(
            out,
            "\n\nPosture: {} → {}",
            self.before_posture, self.after_posture
        );
        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Report what an artifact can do, without running it.
///
/// # This is the security property, not a convenience
///
/// Proposal §5.2 lists `qqqai inspect <artifact>` as *"Static capability report.
/// What can this do, without running it."* §7 states the guarantee it backs:
/// *"Grant is auditable before execution."*
///
/// That guarantee is about an **untrusted artifact**. A user who is handed a
/// `.wasm` file needs to know what it will ask for before they agree to run it —
/// and on this machine, that is the only way to find out, because the artifact
/// carries no manifest.
///
/// The command previously ignored its path argument entirely and reported the
/// *manifest's* capabilities. That is worse than not implementing it: the user
/// asked "what does this file want?", received a confident answer about their
/// own `qqq.toml`, and had no way to tell the answer was to a different
/// question. For an audit surface, a wrong answer is more dangerous than no
/// answer.
///
/// # How the answer is obtained
///
/// The component is compiled — not instantiated — and its **import list** is
/// read from the component type. Imports are what a component declares it needs;
/// under deny-by-default, every one of them is a capability the host must
/// explicitly provide, so the import list *is* the capability surface.
///
/// Compiling does not execute anything: no start function runs, no memory is
/// granted, no host function is reachable. The artifact is parsed and typed.
///
/// # Errors
///
/// * `QQQ-2001` — the artifact could not be read.
/// * `QQQ-6003` — the artifact is not a valid component. Reported rather than
///   falling back to a manifest, because silently answering a different
///   question is the failure this command was fixed for.
pub fn inspect_artifact(path: &std::path::Path) -> Result<ArtifactReport> {
    let bytes = std::fs::read(path).map_err(|e| {
        Error::new(
            ErrorCode::ManifestSyntaxInvalid,
            format!("could not read `{}`", path.display()),
        )
        .with_cause(e.to_string())
    })?;

    // The default engine configuration: inspection is a read-only static
    // analysis, so the deterministic clock and seeded RNG that `RunOptions`
    // can request would change nothing about the answer. Building the default
    // engine keeps the report identical to what a plain `qqqai run` would see.
    let engine = crate::run::new_engine(&crate::run::RunOptions::default())?;
    let component = qqq_host::PreparedComponent::compile(&engine, &bytes).map_err(|e| {
        // Name the file and say what it is not. A user pointing `inspect` at a
        // core module, or at a truncated download, needs to know which.
        Error::new(
            ErrorCode::ComponentLoadFailed,
            format!("`{}` is not a valid WebAssembly component", path.display()),
        )
        .with_cause(e.to_string())
        .with_remediation(
            "check the file is complete, and that it is a component rather \
             than a core module — `qqqai build` produces components",
        )
    })?;

    let imports = component.imported_interfaces(&engine);

    // Map each imported interface to the capability it requires. An import with
    // no matching capability is *not* dropped: it is reported as unmapped,
    // because an interface the host cannot name is exactly the thing an auditor
    // needs to see. Silently omitting it would understate the surface.
    let mut required = Vec::new();
    let mut unmapped = Vec::new();
    for iface in &imports {
        match crate::run::capability_for_import(iface) {
            Some(cap) => required.push(CapabilityReport {
                name: cap.name().to_owned(),
                interface: iface.clone(),
            }),
            None => unmapped.push(iface.clone()),
        }
    }
    required.sort_by(|a, b| (&a.name, &a.interface).cmp(&(&b.name, &b.interface)));
    required.dedup();
    unmapped.sort();
    unmapped.dedup();

    let caps: Vec<Capability> = required
        .iter()
        .filter_map(|r| Capability::from_name(&r.name))
        .collect();

    Ok(ArtifactReport {
        artifact: path.display().to_string().replace('\\', "/"),
        digest: format!("sha256:{}", qqq_pkg::Digest::of(&bytes).hex()),
        size_bytes: bytes.len(),
        kind: crate::build::ArtifactKind::classify(&bytes)
            .as_str()
            .to_owned(),
        required,
        unmapped_interfaces: unmapped,
        posture: classify_posture(&caps),
    })
}

/// What an artifact requires, before it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactReport {
    /// The artifact path, as given.
    pub artifact: String,
    /// The digest of the bytes inspected.
    ///
    /// Recorded because an inspection result is worthless without knowing
    /// *which* bytes produced it — an audit log that says "this artifact is
    /// safe" and does not say which artifact is not an audit log.
    pub digest: String,
    /// The artifact size.
    pub size_bytes: usize,
    /// `component` or `core-module`.
    pub kind: String,
    /// Every capability the artifact requires, with the interface that implies it.
    pub required: Vec<CapabilityReport>,
    /// Interfaces the artifact imports that QQQ has no capability for.
    ///
    /// Reported rather than omitted. An unmapped import means the artifact needs
    /// something this host cannot describe — which is a finding, not a detail to
    /// discard.
    pub unmapped_interfaces: Vec<String>,
    /// The security posture implied by the required capabilities.
    pub posture: Posture,
}

/// One required capability and where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityReport {
    /// The capability name, e.g. `http.client`.
    pub name: String,
    /// The interface whose import implies it.
    pub interface: String,
}

impl CommandOutput for ArtifactReport {
    fn command(&self) -> CommandName {
        CommandName::Inspect
    }

    fn summary(&self) -> String {
        // In human format this is the whole output, so the capabilities are
        // listed. An artifact inspection that reports a count and withholds the
        // names would fail the one question it exists to answer (`§O-036a`).
        let mut out = format!(
            "{}: {} ({} bytes, {}), {} required capabilit{}",
            self.artifact,
            self.kind,
            self.size_bytes,
            &self.digest[..self.digest.len().min(23)],
            self.required.len(),
            if self.required.len() == 1 { "y" } else { "ies" }
        );

        if self.required.is_empty() {
            out.push_str("\n\nThis artifact imports nothing: it can reach no host capability.");
        } else {
            out.push_str("\n\nRequired capabilities");
            for r in &self.required {
                let _ = write!(out, "\n  {:<20} from {}", r.name, r.interface);
            }
        }

        if !self.unmapped_interfaces.is_empty() {
            out.push_str(
                "\n\nUnmapped interfaces — imported, but no QQQ capability describes them:",
            );
            for i in &self.unmapped_interfaces {
                let _ = write!(out, "\n  {i}");
            }
        }

        let _ = write!(out, "\n\nPosture: {}", self.posture.as_str());
        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Report what a project can do, without running it.
///
/// This is the static half of the capability report: it needs the manifest,
/// not a running instance, which is what makes it usable in CI before a
/// deployment exists (NN-5: what a module can do must be discoverable without
/// running it).
///
/// # Errors
///
/// `QQQ-2004` when a granted path does not exist on this host, because
/// normalization must resolve real paths to be honest about what is reachable.
pub fn inspect(loaded: &LoadedManifest) -> Result<InspectOutput> {
    let resolution = Resolution::from_manifest(&loaded.manifest);
    let caps: Vec<Capability> = resolution.grants.capabilities();

    let interfaces: Vec<InterfaceReport> = registry::required_interfaces(&resolution.grants)
        .into_iter()
        .map(|i| InterfaceReport {
            name: i.name,
            summary: i.summary,
            implemented: i.implemented,
        })
        .collect();

    Ok(InspectOutput {
        project: loaded.name().to_owned(),
        capabilities: caps.iter().map(|c| c.name().to_owned()).collect(),
        interfaces,
        limits: LimitsReport {
            memory: loaded.manifest.limits.memory.clone(),
            fuel: loaded.manifest.limits.fuel,
            epoch_deadline_ms: loaded.manifest.limits.epoch_deadline_ms,
            // From the manifest's own table, so the report and the server cannot
            // disagree: both read `RequestLimits`.
            request_limits: loaded
                .manifest
                .server
                .limits
                .as_ref()
                .map(RequestLimitsReport::from_declared)
                .filter(|r| !r.is_empty()),
        },
        posture: classify_posture(&caps),
    })
}

/// Read the `qqq.lock` that sits beside a loaded manifest, if there is one.
///
/// # Why `None` covers both "absent" and "unparseable"
///
/// Because the audit's supply-chain section is *optional context*, and the two
/// cases lead to the same action: run `qqqai install`. A malformed lockfile is
/// reported by `install` with its own error and line number, which is a better
/// diagnostic than an audit finding could produce -- so duplicating it here would
/// be a second, worse report of the same problem.
///
/// The distinction that **does** matter is `None` versus an empty lockfile: no
/// lockfile means the supply-chain surface was never examined, while an empty one
/// means it was examined and found to declare nothing. [`crate::audit::audit`]
/// reports neither as clean, which is the point.
#[must_use]
pub fn sibling_lockfile(loaded: &LoadedManifest) -> Option<qqq_pkg::lock::Lockfile> {
    let dir = loaded.path.parent()?;
    let path = dir.join("qqq.lock");
    let text = std::fs::read_to_string(&path).ok()?;
    qqq_pkg::lock::Lockfile::parse(&text).ok()
}

/// Classify a grant set's security posture.
///
/// The rule is deliberately simple and stated here rather than inferred:
/// anything that can write or reach the network is `Exposed`; anything else
/// that grants at all is `Contained`; nothing at all is `Minimal`.
#[must_use]
pub fn classify_posture(caps: &[Capability]) -> Posture {
    if caps.is_empty() {
        return Posture::Minimal;
    }
    let exposes = caps.iter().any(|c| {
        matches!(
            c,
            Capability::FsWrite
                | Capability::FsWatch
                | Capability::HttpClient
                | Capability::HttpServer
                | Capability::SqlExecute
                | Capability::KvWrite
                | Capability::QueuePublish
                | Capability::QueueSubscribe
                | Capability::DnsResolve
                | Capability::AiInfer
        )
    });
    if exposes {
        Posture::Exposed
    } else {
        Posture::Contained
    }
}

/// Apply an explicit `--cap` overlay from the command line.
///
/// # Why the developer overlay exists and is loud
///
/// Local iteration often needs one more capability than the manifest declares.
/// The alternative — editing `qqq.toml` and remembering to revert — is how a
/// development grant reaches production. An explicit flag that produces a
/// warning and cannot be used in a production environment is the safer shape.
#[must_use]
pub fn developer_overlay(caps: &[Capability]) -> Overlay {
    Overlay::allow_only(
        Layer::Developer,
        caps.iter().copied(),
        "developer --cap override",
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn loaded(src: &str) -> LoadedManifest {
        LoadedManifest {
            manifest: qqq_cap::manifest::Manifest::parse(src).expect("test manifest"),
            path: PathBuf::from("qqq.toml"),
            source: src.to_owned(),
        }
    }

    const DENY_ALL: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n";
    const CRYPTO: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                          [capabilities.crypto]\nhash = [\"sha256\"]\nrandom = true\n";
    const EXPOSED: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                           [capabilities.http]\nclient = [\"api.example.com:443\"]\n";

    // -- why ---------------------------------------------------------------

    #[test]
    fn why_reports_a_granted_capability() {
        let l = loaded(CRYPTO);
        let out = why(&l, "crypto.hash").expect("must explain");
        assert_eq!(out.capability, "crypto.hash");
        assert!(out.granted);
        assert_eq!(out.decided_by.as_deref(), Some("manifest"));
        assert!(out.fix.is_none(), "a granted capability needs no fix");
        assert!(out.summary().contains("GRANTED"));
    }

    #[test]
    fn why_reports_a_denied_capability_with_an_exact_stanza() {
        let l = loaded(DENY_ALL);
        let out = why(&l, "sql.query").expect("must explain");
        assert!(!out.granted);
        assert!(out.steps.is_empty(), "nothing mentioned it");
        // Assert on the summary *before* moving `fix` out of `out`.
        assert!(out.summary().contains("DENIED"));
        let fix = out.fix.expect("a denial must suggest a fix");
        assert!(
            fix.contains("capabilities.sql"),
            "must name the stanza: {fix}"
        );
        assert!(fix.contains("qqq.toml"));
    }

    /// A typo is the most likely reason this command is run, so the error must
    /// suggest the intended name.
    #[test]
    fn why_suggests_a_correction_for_a_typo() {
        let l = loaded(DENY_ALL);
        let e = why(&l, "crypto.hassh").unwrap_err();
        assert_eq!(e.code, ErrorCode::CapabilitySyntaxInvalid);
        assert!(
            e.message.contains("did you mean `crypto.hash`"),
            "got: {}",
            e.message
        );
        assert!(e.remediation.is_some());
    }

    // -- the human-output contract ------------------------------------------
    //
    // In human format `summary()` *is* the output: `Output::emit` writes that
    // string and nothing else. So a command whose payload matters must carry
    // the payload in `summary()`, and a test that only inspects the struct
    // fields cannot detect a summary that drops them.
    //
    // These tests exist because exactly that happened. `qqqai caps` printed
    // "2 capabilities across 2 namespaces" and never named a capability;
    // `qqqai why http.server` printed "DENIED" and omitted the fix stanza the
    // scaffold's own comments promise. The structs were complete and their JSON
    // was correct in both cases — the data was right and the surface dropped it.

    /// `caps` must name the capabilities, not merely count them.
    #[test]
    fn caps_lists_the_capabilities_it_counted() {
        let l = loaded(CRYPTO);
        let out = caps(&l, false);
        let text = out.summary();

        assert!(text.contains("crypto.hash"), "the name must appear: {text}");
        assert!(
            text.contains("crypto.random"),
            "every granted capability must appear: {text}"
        );
        // The count is still a useful heading, so it should survive.
        assert!(text.contains("2 capabilities"), "{text}");
    }

    /// A deny-all project gets an explanation, not a bare count.
    #[test]
    fn caps_explains_a_deny_all_project() {
        let l = loaded(DENY_ALL);
        let text = caps(&l, false).summary();
        assert!(text.contains("no capabilities granted"), "{text}");
        assert!(
            text.contains("denied"),
            "it should say that absence means denial: {text}"
        );
    }

    /// `why` on a denial must print the stanza, not only the verdict.
    ///
    /// This is the command's entire purpose: it is run the moment a capability
    /// is refused, and the person needs the text that would change it.
    #[test]
    fn why_prints_the_fix_stanza_in_human_output() {
        let l = loaded(DENY_ALL);
        let out = why(&l, "sql.query").expect("must explain");
        let text = out.summary();

        assert!(text.contains("DENIED"), "{text}");
        assert!(
            text.contains("capabilities.sql"),
            "the stanza must be in the human output, not only in JSON: {text}"
        );
    }

    /// The stanza is printed verbatim, with no second preamble.
    ///
    /// `fix_stanza_for` already emits `add to qqq.toml:`; an earlier version of
    /// `summary` added its own, so the terminal showed the phrase twice. The
    /// duplication is invisible to any test that only checks the string is
    /// present.
    #[test]
    fn the_fix_stanza_is_not_wrapped_a_second_time() {
        let l = loaded(DENY_ALL);
        let out = why(&l, "fs.read").expect("must explain");
        let text = out.summary();

        assert_eq!(
            text.matches("add to qqq.toml:").count(),
            1,
            "the preamble must appear exactly once: {text}"
        );
    }

    /// No line of the human output has trailing whitespace.
    ///
    /// The first attempt at indenting the stanza added four spaces to a blank
    /// line, which is invisible on screen and shows up in every diff that
    /// quotes the output.
    #[test]
    fn the_human_output_has_no_trailing_whitespace() {
        let l = loaded(DENY_ALL);
        for command in ["fs.read", "crypto.sign", "http.client"] {
            let text = why(&l, command).expect("must explain").summary();
            for (i, line) in text.lines().enumerate() {
                assert_eq!(
                    line,
                    line.trim_end(),
                    "`{command}` line {i} has trailing whitespace: {line:?}"
                );
            }
        }

        let caps_text = caps(&loaded(CRYPTO), false).summary();
        for (i, line) in caps_text.lines().enumerate() {
            assert_eq!(
                line,
                line.trim_end(),
                "caps line {i} has trailing whitespace: {line:?}"
            );
        }
    }

    /// A granted capability names the deciding layer.
    #[test]
    fn why_names_the_layer_that_decided() {
        let l = loaded(CRYPTO);
        let text = why(&l, "crypto.hash").expect("must explain").summary();
        assert!(
            text.contains("GRANTED by manifest"),
            "the deciding layer is the useful part of a grant: {text}"
        );
    }

    /// A denial decided by no layer says so, rather than leaving a blank.
    ///
    /// The distinction matters: "not granted by any layer" tells the reader
    /// this is the deny-by-default state and there is no rule to go find.
    #[test]
    fn a_default_denial_says_it_is_the_default() {
        let l = loaded(DENY_ALL);
        let text = why(&l, "kv.write").expect("must explain").summary();
        assert!(
            text.contains("not granted by any layer"),
            "a default denial must read as the default: {text}"
        );
    }

    #[test]
    fn why_gives_guidance_for_a_wholly_unknown_name() {
        let l = loaded(DENY_ALL);
        let e = why(&l, "notacapability").unwrap_err();
        assert!(e.message.contains("unknown capability"));
        // The remediation points at the naming convention; the *message* is
        // what offers a suggestion when one is close.
        assert!(
            e.remediation
                .as_deref()
                .unwrap_or("")
                .contains("lowercase dotted"),
            "must explain the naming convention: {:?}",
            e.remediation
        );
    }

    /// Every capability's fix must produce a stanza for its own namespace.
    #[test]
    fn every_capability_has_a_useful_fix_stanza() {
        for &c in Capability::all() {
            let fix = fix_stanza_for(c);
            assert!(!fix.is_empty(), "{c} has no fix");
            assert!(
                fix.contains("qqq.toml"),
                "{c}: the fix must name the file: {fix}"
            );
            assert!(
                fix.contains(c.namespace()),
                "{c}: the fix must name its namespace `{}`: {fix}",
                c.namespace()
            );
        }
    }

    // -- caps --------------------------------------------------------------

    #[test]
    fn caps_of_a_deny_all_project_reports_nothing_granted() {
        let out = caps(&loaded(DENY_ALL), false);
        assert!(out.deny_all);
        assert!(out.grants.is_empty());
        assert!(out.by_namespace.is_empty());
        assert!(out.covert_channels.is_empty());
        assert_eq!(
            out.digest.len(),
            64,
            "the audit digest must always be present"
        );
        assert!(out.summary().contains("no capabilities granted"));
    }

    #[test]
    fn caps_groups_by_namespace() {
        let out = caps(&loaded(CRYPTO), false);
        assert!(!out.deny_all);
        assert_eq!(out.by_namespace.len(), 1);
        assert_eq!(out.by_namespace[0].namespace, "crypto");
        assert_eq!(out.by_namespace[0].capabilities.len(), 2);
        // The summary reports counts *and* the things counted.
        //
        // An earlier version of this test asserted only the counts, on the
        // reasoning that "the namespace names live in the structured field,
        // which is what an agent reads". That reasoning was the bug: humans
        // read the human output, and in human format `summary()` is the entire
        // output, so the names were unreachable for the people most likely to
        // run the command.
        assert!(out.summary().contains("2 capabilities"));
        // Singular, because there is one namespace. The plural agreement is
        // asserted here rather than left to chance.
        assert!(
            out.summary().contains("1 namespace"),
            "singular agreement: {}",
            out.summary()
        );
        assert!(!out.summary().contains("1 namespaces"));
        assert!(
            out.summary().contains("crypto.hash"),
            "the names must be in the human output: {}",
            out.summary()
        );
    }

    /// Plural agreement, so the fix above does not overcorrect.
    #[test]
    fn caps_pluralises_namespaces_correctly() {
        let two = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                   [capabilities.crypto]\nhash = [\"sha256\"]\n\
                   [capabilities.clock]\nwall = true\n";
        let text = caps(&loaded(two), false).summary();
        assert!(text.contains("2 namespaces"), "{text}");
        assert!(!text.contains("2 namespace\n"), "{text}");
    }

    /// `crypto.random` is a covert channel and must be called out, because it
    /// is the grant most likely to be added without thought.
    #[test]
    fn caps_surfaces_covert_channels() {
        let out = caps(&loaded(CRYPTO), false);
        assert!(
            out.covert_channels.contains(&"crypto.random".to_owned()),
            "randomness is a covert channel and must be flagged: {:?}",
            out.covert_channels
        );
    }

    #[test]
    fn caps_digest_is_stable_and_content_addressed() {
        let a = caps(&loaded(CRYPTO), false);
        let b = caps(&loaded(CRYPTO), false);
        assert_eq!(a.digest, b.digest);
        assert_ne!(a.digest, caps(&loaded(DENY_ALL), false).digest);
    }

    // -- inspect -----------------------------------------------------------

    #[test]
    fn inspect_of_a_deny_all_project_is_minimal() {
        let out = inspect(&loaded(DENY_ALL)).unwrap();
        assert_eq!(out.posture, Posture::Minimal);
        assert!(out.capabilities.is_empty());
        assert!(
            out.interfaces.is_empty(),
            "no grants must unlock no interfaces"
        );
    }

    /// The interface list is what makes `inspect` a security report rather than
    /// a restatement of the manifest.
    #[test]
    fn inspect_lists_the_interfaces_the_grants_unlock() {
        let out = inspect(&loaded(CRYPTO)).unwrap();
        let names: Vec<&str> = out.interfaces.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"qqq:crypto@1.0.0"), "got {names:?}");
        assert!(!names.contains(&"qqq:sql@1.0.0"), "sql was not granted");
        assert_eq!(
            out.posture,
            Posture::Contained,
            "hashing alone is contained"
        );
    }

    #[test]
    fn inspect_marks_unimplemented_interfaces_honestly() {
        let out = inspect(&loaded(CRYPTO)).unwrap();
        let crypto = out
            .interfaces
            .iter()
            .find(|i| i.name.starts_with("qqq:crypto"))
            .expect("crypto interface");
        assert!(
            !crypto.implemented,
            "crypto is only partially implemented and must say so"
        );
        assert!(!crypto.summary.is_empty());
    }

    /// The gap must reach the **rendered** output, not only the struct.
    ///
    /// # Why this test is separate from the one above
    ///
    /// `inspect_marks_unimplemented_interfaces_honestly` asserts the field, and it passed for as
    /// long as the human renderer printed the bare interface name and dropped the flag. A field
    /// that is populated and not presented reads to a user exactly like a field that does not
    /// exist, so the assertion has to be made against the text a person sees — on the summary
    /// line and beside the interface, because a count inside a section is what people skim past.
    ///
    /// # Why the two annotations are asserted by their own line
    ///
    /// The first version of this test searched the whole document for
    /// `"no host implementation yet"`. The summary line starts with that same phrase, so the
    /// assertion was satisfied by the summary alone and the per-interface annotation was
    /// untested — proved by fault injection, which removed the annotation and watched the test
    /// **pass**. Both places are now pinned by locating the line they belong to, which is what
    /// makes the two independent.
    #[test]
    fn inspect_renders_the_unimplemented_gap_for_a_human() {
        let out = inspect(&loaded(CRYPTO)).unwrap();
        let text = out.summary();
        let lines: Vec<&str> = text.lines().collect();

        // The summary line: the first line, carrying the count.
        let summary_line = lines.first().copied().unwrap_or_default();
        assert!(
            summary_line.contains("1 with no host implementation yet"),
            "the summary line must carry the count:\n{summary_line}"
        );

        // The interface line: the entry *under* the `Interfaces` heading, not the summary above
        // it. Found by walking from the heading rather than by a document-wide search.
        let heading = lines
            .iter()
            .position(|l| l.trim() == "Interfaces")
            .expect("the Interfaces heading must be present");
        let interface_line = lines[heading + 1];
        assert!(
            interface_line.contains("qqq:crypto"),
            "the line after the heading is the interface:\n{interface_line}"
        );
        assert!(
            interface_line.contains("no host implementation yet"),
            "the interface line itself must be annotated:\n{interface_line}"
        );
    }

    /// The control: a fully implemented project must not be annotated.
    ///
    /// Without this, a renderer that marked *everything* as unimplemented would satisfy the test
    /// above while telling every user their working project cannot run.
    #[test]
    fn inspect_does_not_annotate_a_fully_implemented_project() {
        // `qqq:clock` is registered end to end, so this grant set has no gap.
        let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                        [capabilities.clock]\nwall = true\n";
        let out = inspect(&loaded(manifest)).unwrap();
        assert!(
            out.interfaces.iter().all(|i| i.implemented),
            "the fixture must have no gap, or it cannot be a control: {:?}",
            out.interfaces
        );
        let text = out.summary();
        assert!(
            !text.contains("no host implementation yet"),
            "a working project must not be annotated:\n{text}"
        );
    }

    /// A project that reaches the network is `Exposed`, and `inspect` must say
    /// so — this is the report a security reviewer reads before a deployment.
    #[test]
    fn inspect_classifies_a_network_reaching_project_as_exposed() {
        let out = inspect(&loaded(EXPOSED)).unwrap();
        assert_eq!(out.posture, Posture::Exposed);
        assert!(out.capabilities.contains(&"http.client".to_owned()));
        let names: Vec<&str> = out.interfaces.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"qqq:http@1.0.0"), "got {names:?}");
        assert!(out.summary().contains("exposed"));
    }

    #[test]
    fn inspect_carries_the_limits() {
        let out = inspect(&loaded(CRYPTO)).unwrap();
        assert_eq!(out.limits.memory, "128MiB");
        assert_eq!(out.limits.fuel, 50_000_000);
        assert_eq!(out.limits.epoch_deadline_ms, 5_000);
    }

    /// A manifest with no `[server.limits]` reports no request limits.
    ///
    /// The absence must be an absence, not an empty table: "the author declared no
    /// limits" and "the author declared limits of nothing" are different facts, and the
    /// runtime treats them differently (`None` is unlimited; a table is a policy).
    #[test]
    fn inspect_reports_no_request_limits_when_none_are_declared() {
        let out = inspect(&loaded(CRYPTO)).unwrap();
        assert!(
            out.limits.request_limits.is_none(),
            "a manifest declaring no `[server.limits]` must report none"
        );
    }

    /// The declared request limits are carried, including the connection ceiling.
    ///
    /// The ceiling is the field this test exists for: it was a compiled constant until
    /// `SRV-020` was finished, so a report that omitted it would leave the one limit an
    /// operator most needs to change invisible in the command that lists limits.
    #[test]
    fn inspect_carries_the_declared_request_limits() {
        const WITH_LIMITS: &str = r#"
[package]
name = "app"
version = "0.1.0"

[server]
default_auth = "none"

[[server.routes]]
path = "/healthz"
methods = ["GET"]
handler = "health"

[server.limits.default]
max_body_bytes = 1048576
max_requests_per_window = 100
window_seconds = 60

[server.limits.per_tenant."127.0.0.1"]
max_connections = 7
"#;
        let out = inspect(&loaded(WITH_LIMITS)).unwrap();
        let req = out
            .limits
            .request_limits
            .expect("the declared table must be reported");

        let d = req
            .default
            .as_ref()
            .expect("the default entry must survive");
        assert_eq!(d.tenant, "default");
        assert_eq!(d.max_body_bytes, Some(1_048_576));
        assert_eq!(d.max_requests_per_window, Some(100));
        assert_eq!(d.window_seconds, Some(60));

        let entry = req
            .per_tenant
            .iter()
            .find(|e| e.tenant == "127.0.0.1")
            .expect("the per-tenant entry must survive");
        assert_eq!(
            entry.max_connections,
            Some(7),
            "the connection ceiling must be reported, not only enforced"
        );
    }

    /// An entry that declares no limit at all is dropped from the report.
    ///
    /// A `[server.limits.per_tenant."1.2.3.4"]` header with nothing under it declares no
    /// policy, and listing it would show a tenant as limited when nothing bounds it.
    #[test]
    fn inspect_drops_a_per_tenant_entry_that_declares_nothing() {
        const EMPTY_ENTRY: &str = r#"
[package]
name = "app"
version = "0.1.0"

[server]
default_auth = "none"

[[server.routes]]
path = "/healthz"
methods = ["GET"]
handler = "health"

[server.limits.per_tenant."127.0.0.1"]
"#;
        let out = inspect(&loaded(EMPTY_ENTRY)).unwrap();
        assert!(
            out.limits.request_limits.is_none(),
            "an entry with no limits declares nothing, so the report must be absent: {:?}",
            out.limits.request_limits
        );
    }

    // -- posture -----------------------------------------------------------

    #[test]
    fn posture_classification_is_conservative() {
        assert_eq!(classify_posture(&[]), Posture::Minimal);
        // Read-only access is contained.
        assert_eq!(
            classify_posture(&[Capability::FsRead, Capability::CryptoHash]),
            Posture::Contained
        );
        // Anything that writes or reaches out is exposed.
        for c in [
            Capability::FsWrite,
            Capability::HttpClient,
            Capability::HttpServer,
            Capability::SqlExecute,
            Capability::KvWrite,
            Capability::DnsResolve,
            Capability::QueuePublish,
        ] {
            assert_eq!(
                classify_posture(&[c]),
                Posture::Exposed,
                "{c} must be classified as exposed"
            );
        }
    }

    /// The exposure ranking used to pick between capabilities that unlock the
    /// same interface must agree with posture classification.
    ///
    /// This is a real coupling, not a tidiness check. `capability_for_import`
    /// returns the strongest capability implied by an import; `classify_posture`
    /// decides whether that capability makes the artifact `Exposed`. If the two
    /// disagreed, an artifact could be reported as requiring `fs.read` — and
    /// therefore `Contained` — while the interface it actually imports also
    /// carries `fs.write`. The report would be internally consistent and wrong.
    #[test]
    fn the_exposure_ranking_agrees_with_posture_classification() {
        for c in Capability::all() {
            let classified_exposed = classify_posture(&[*c]) == Posture::Exposed;
            let ranked_exposed = crate::run::exposure_rank(*c) == 2;
            assert_eq!(
                classified_exposed, ranked_exposed,
                "`{c}` is {classified_exposed} by posture but {ranked_exposed} by the ranking"
            );
        }
    }

    /// Two capabilities unlocking one interface resolve to the stronger.
    ///
    /// `qqq:fs/filesystem` is unlocked by `FsRead`, `FsWrite` and `FsWatch`.
    /// Reporting `fs.read` for an artifact importing the whole interface would
    /// understate it by two thirds.
    #[test]
    fn an_interface_unlocked_by_several_capabilities_reports_the_strongest() {
        let got = crate::run::capability_for_import("qqq:fs/filesystem@1.0.0")
            .expect("the filesystem interface is mapped");
        assert_eq!(
            got,
            Capability::FsWrite,
            "the strongest of fs.read / fs.write / fs.watch"
        );
    }

    /// The two halves of `qqq:clock` map to two different capabilities.
    ///
    /// This is the regression test for the defect this whole change exists for:
    /// both interfaces sit in one package, so a package-level search reported
    /// whichever the registry listed first — an artifact importing the wall
    /// clock was said to need the monotonic clock.
    #[test]
    fn the_two_clock_interfaces_map_to_different_capabilities() {
        let wall = crate::run::capability_for_import("qqq:clock/wall-clock@1.0.0");
        let mono = crate::run::capability_for_import("qqq:clock/monotonic-clock@1.0.0");

        assert_eq!(wall, Some(Capability::ClockWall));
        assert_eq!(mono, Some(Capability::ClockMonotonic));
        assert_ne!(wall, mono, "one package, two capabilities");
    }

    /// Every sub-interface of a multi-interface package maps distinctly.
    #[test]
    fn the_crypto_interfaces_map_to_distinct_capabilities() {
        let pairs = [
            ("qqq:crypto/random@1.0.0", Capability::CryptoRandom),
            ("qqq:crypto/hashing@1.0.0", Capability::CryptoHash),
            ("qqq:crypto/hmac@1.0.0", Capability::CryptoHmac),
            ("qqq:crypto/aead@1.0.0", Capability::CryptoAead),
            ("qqq:crypto/signing@1.0.0", Capability::CryptoSign),
        ];
        for (iface, expected) in pairs {
            assert_eq!(
                crate::run::capability_for_import(iface),
                Some(expected),
                "{iface} must map to {expected}"
            );
        }
    }

    /// A version on the import does not defeat the mapping.
    #[test]
    fn the_mapping_ignores_the_interface_version() {
        for iface in [
            "qqq:clock/wall-clock@1.0.0",
            "qqq:clock/wall-clock@1.2.3",
            "qqq:clock/wall-clock",
        ] {
            assert_eq!(
                crate::run::capability_for_import(iface),
                Some(Capability::ClockWall),
                "{iface}"
            );
        }
    }

    /// An interface QQQ has no capability for maps to nothing.
    ///
    /// `None` is reported as an unmapped import rather than being papered over
    /// with a plausible neighbour: an interface the host cannot name is a
    /// finding an auditor needs, not a detail to discard.
    #[test]
    fn an_unknown_interface_maps_to_nothing() {
        assert_eq!(
            crate::run::capability_for_import("wasi:filesystem/types@0.2.0"),
            None
        );
        assert_eq!(crate::run::capability_for_import("not-an-interface"), None);
    }

    #[test]
    fn posture_is_a_stable_string() {
        assert_eq!(Posture::Minimal.as_str(), "minimal");
        assert_eq!(Posture::Exposed.as_str(), "exposed");
        assert_eq!(
            serde_json::to_string(&Posture::Contained).unwrap(),
            "\"contained\""
        );
    }

    // -- developer overlay -------------------------------------------------

    #[test]
    fn the_developer_overlay_only_narrows_and_warns() {
        // The warning fires only when the overlay **changes something**, which
        // is the right behaviour: warning about a no-op would train users to
        // ignore the warning. So this uses a manifest that grants something the
        // overlay then narrows.
        let l = loaded(CRYPTO);
        let overlay = developer_overlay(&[Capability::CryptoHash]);
        assert_eq!(overlay.layer, Layer::Developer);

        let r = Resolution::from_manifest(&l.manifest).apply(&overlay);
        // The overlay removed `crypto.random`, which the manifest had granted.
        assert!(r.grants.grants(Capability::CryptoHash));
        assert!(!r.grants.grants(Capability::CryptoRandom));
        assert!(
            r.warnings.iter().any(|w| w.contains("NOT for production")),
            "applying a developer overlay must warn: {:?}",
            r.warnings
        );
    }

    /// A developer overlay applied to a deny-all manifest grants **nothing** —
    /// overlays narrow, they never widen. This is the security property, tested
    /// through the command surface rather than only in `qqq-cap`.
    #[test]
    fn a_developer_overlay_cannot_widen_a_deny_all_manifest() {
        let l = loaded(DENY_ALL);
        let overlay = developer_overlay(&[Capability::CryptoHash, Capability::SqlQuery]);
        let r = Resolution::from_manifest(&l.manifest).apply(&overlay);
        assert!(
            r.grants.is_empty(),
            "`--cap` must not be able to grant authority the manifest did not declare; \
             got {}",
            r.grants
        );
    }

    // -- serialization -----------------------------------------------------

    #[test]
    fn all_outputs_serialize_for_agents() {
        let l = loaded(CRYPTO);
        let why_json = serde_json::to_value(why(&l, "crypto.hash").unwrap()).unwrap();
        assert_eq!(why_json["granted"], true);
        assert!(why_json["steps"].is_array());

        let caps_json = serde_json::to_value(caps(&l, false)).unwrap();
        assert!(caps_json["digest"].is_string());
        assert!(caps_json["by_namespace"].is_array());

        let inspect_json = serde_json::to_value(inspect(&l).unwrap()).unwrap();
        assert_eq!(inspect_json["posture"], "contained");
        assert!(inspect_json["interfaces"].is_array());
        assert_eq!(inspect_json["limits"]["memory"], "128MiB");
    }
}
