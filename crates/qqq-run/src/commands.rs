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

/// The whole `[capabilities.http]` table, covering both directions.
///
/// Shared by the namespace fallback and the run remediation for a component
/// missing both halves: two pasted `[capabilities.http]` tables would be
/// duplicate-table invalid TOML, so the pair case gets one table, not two
/// stanzas.
pub(crate) const HTTP_TABLE_STANZA: &str = "add to qqq.toml:\n\n    [capabilities.http]\n    server = true  # for http.server\n    client = [\"host:443\"]  # for http.client";

/// The exact `qqq.toml` stanza that would grant a capability.
///
/// # Why this is generated rather than documented
///
/// A developer who hits a denial needs the *exact* text, not a link to a
/// capabilities reference. Generating it from the capability's namespace means
/// the suggestion cannot drift from the parser's expectations — and for
/// namespaces the manifest cannot model yet, generating the state instead of
/// guessing a schema means the suggestion cannot be a stanza the parser
/// rejects. Every namespace is modelled now (`sql`/`kv`/`queue`/`ai` in
/// CAP-017/018/019/020, `log`/`trace` in CAP-021/022, `secret` in CAP-023
/// with the legacy `crypto.secrets` spelling still granting;
/// `FsWatch` derivation is tracked as CAP-024) — the wildcard below stays
/// as a safety net for a future fourteenth namespace, never for a known one.
#[must_use]
pub fn fix_stanza_for(c: Capability) -> String {
    // `sql.execute` needs the widening flag the query stanza leaves
    // commented: one namespace, two grants, so the capability — not
    // just the namespace — selects the text. Same for `kv.write`.
    if c == Capability::SqlExecute {
        return "add to qqq.toml:\n\n    [[capabilities.sql]]\n    name = \"orders\"\n    driver = \"postgres\"\n    host = \"db.internal:5432\"\n    execute = true  # for sql.execute".to_owned();
    }
    if c == Capability::KvWrite {
        return "add to qqq.toml:\n\n    [capabilities.kv]\n    stores = [\"sessions\"]\n    write = true  # for kv.write".to_owned();
    }
    if c == Capability::QueueSubscribe {
        return "add to qqq.toml:\n\n    [[capabilities.queue]]\n    name = \"orders.events\"\n    direction = \"subscribe\"  # for queue.subscribe".to_owned();
    }
    // One capability, one grant: suggesting the whole namespace table for a
    // single denial pastes unasked authority. `why http.server` on a deny-all
    // manifest used to suggest `server = true` **and** `client = [...]` — an
    // operator fixing a server denial would grant egress too, and the `crypto`
    // table was worse (five grants including the covert `crypto.random`).
    // Each arm below parses to the capability named in its comment.
    // `fs` modes grant fixed bundles (`read-only` is `read + watch`), so
    // `read` and `watch` name their inherent co-grant rather than hiding it,
    // and only `append-only` is exactly one grant.
    // Pinned by `fix_stanzas_grant_only_the_capability_named`.
    if c == Capability::HttpServer {
        return "add to qqq.toml:\n\n    [capabilities.http]\n    server = true  # for http.server"
            .to_owned();
    }
    if c == Capability::HttpClient {
        return "add to qqq.toml:\n\n    [capabilities.http]\n    client = [\"host:443\"]  # for http.client".to_owned();
    }
    if c == Capability::CryptoRandom {
        return "add to qqq.toml:\n\n    [capabilities.crypto]\n    random = true  # for crypto.random".to_owned();
    }
    if c == Capability::CryptoHash {
        return "add to qqq.toml:\n\n    [capabilities.crypto]\n    hash = [\"sha256\"]  # for crypto.hash".to_owned();
    }
    if c == Capability::CryptoHmac {
        return "add to qqq.toml:\n\n    [capabilities.crypto]\n    hmac = [\"sha256\"]  # for crypto.hmac".to_owned();
    }
    if c == Capability::CryptoAead {
        return "add to qqq.toml:\n\n    [capabilities.crypto]\n    aead = [\"aes-256-gcm\"]  # for crypto.aead".to_owned();
    }
    if c == Capability::CryptoSign {
        return "add to qqq.toml:\n\n    [capabilities.crypto]\n    sign = [\"ed25519\"]  # for crypto.sign".to_owned();
    }
    if c == Capability::ClockWall {
        return "add to qqq.toml:\n\n    [capabilities.clock]\n    wall = true  # for clock.wall"
            .to_owned();
    }
    if c == Capability::ClockMonotonic {
        return "add to qqq.toml:\n\n    [capabilities.clock]\n    monotonic = true  # for clock.monotonic".to_owned();
    }
    // The `fs` modes grant fixed bundles, so the denial selects the mode, not
    // just the table. `read-only` grants `read + watch` — suggesting it for
    // `fs.write` leaves the component still failing, the same defect the
    // per-capability arms above exist to prevent. `append-only` is the one
    // mode that grants exactly `write`; `read` and `watch` have no mode that
    // grants them alone (readable modes imply watch, CAP-024), so their
    // stanzas name the co-grant in the comment instead of hiding it.
    if c == Capability::FsWrite {
        return "add to qqq.toml:\n\n    [[capabilities.fs]]\n    path = \"/var/lib/app\"\n    mode = \"append-only\"  # for fs.write: exactly write, no read, no watch".to_owned();
    }
    if c == Capability::FsRead {
        return "add to qqq.toml:\n\n    [[capabilities.fs]]\n    path = \"/var/lib/app\"\n    mode = \"read-only\"  # for fs.read (also grants fs.watch: readable modes imply watch)".to_owned();
    }
    if c == Capability::FsWatch {
        return "add to qqq.toml:\n\n    [[capabilities.fs]]\n    path = \"/var/lib/app\"\n    mode = \"read-only\"  # for fs.watch (also grants fs.read: watch follows readability)".to_owned();
    }
    match c.namespace() {
        // Whole-table fallbacks, reachable only by future variants of these
        // namespaces: every capability known today returns above with an
        // exact stanza. A future variant has no per-capability pin yet, so
        // the table — with each line annotated — is the honest suggestion
        // until its pin lands.
        "http" => HTTP_TABLE_STANZA.to_owned(),
        // Future-variant fallback: the three known `fs` capabilities return
        // exact modes above.
        "fs" => "add to qqq.toml:\n\n    [[capabilities.fs]]\n    path = \"/var/lib/app\"\n    mode = \"read-only\"     # or \"append-only\" / \"read-write\"".to_owned(),
        "crypto" => "add to qqq.toml:\n\n    [capabilities.crypto]\n    random = true          # for crypto.random\n    hash = [\"sha256\"]      # for crypto.hash\n    hmac = [\"sha256\"]      # for crypto.hmac\n    aead = [\"aes-256-gcm\"] # for crypto.aead\n    sign = [\"ed25519\"]     # for crypto.sign".to_owned(),
        // Future-variant fallback like `http` above: known capabilities
        // return exact stanzas before the match.
        "clock" => "add to qqq.toml:\n\n    [capabilities.clock]\n    wall = true            # for clock.wall\n    monotonic = true       # for clock.monotonic".to_owned(),
        "env" => "add to qqq.toml:\n\n    [capabilities.env]\n    allow = [\"LOG_LEVEL\"]  # name each variable; wildcards are refused".to_owned(),
        "dns" => "add to qqq.toml:\n\n    [capabilities.dns]\n    resolve = [\"api.example.com\"]".to_owned(),
        "kv" => "add to qqq.toml:\n\n    [capabilities.kv]\n    stores = [\"sessions\"]\n    # write = true  # for kv.write; read-only without it".to_owned(),
        "ai" => "add to qqq.toml:\n\n    [capabilities.ai]\n    providers = [\"local:ggml\"]\n    models = [\"*:<=4B\"]".to_owned(),
        "queue" => "add to qqq.toml:\n\n    [[capabilities.queue]]\n    name = \"orders.events\"\n    direction = \"publish\"  # or \"subscribe\"".to_owned(),
        "sql" => "add to qqq.toml:\n\n    [[capabilities.sql]]\n    name = \"orders\"\n    driver = \"postgres\"\n    host = \"db.internal:5432\"\n    # secret = \"env:ORDERS_DB_URL\"\n    # execute = true  # for sql.execute; query-only without it".to_owned(),
        // Markers: presence grants, so the header line is the whole
        // stanza — the trailing comment says so at the paste site,
        // where a `level = "debug"` typo would otherwise land.
        "log" => "add to qqq.toml:\n\n    [capabilities.log]  # presence grants log.write; no fields".to_owned(),
        "trace" => "add to qqq.toml:\n\n    [capabilities.trace]  # presence grants trace.write; no fields".to_owned(),
        // `secret.use` is granted through the dedicated
        // `[capabilities.secret]` table (CAP-023); the legacy nested
        // `crypto.secrets` spelling still grants, pinned below.
        // Operations additionally need their crypto grant (`HOST-028`):
        // naming the key is not using the primitive.
        "secret" => "add to qqq.toml:\n\n    [capabilities.secret]\n    secrets = [\"env:NAME\"]  # for secret.use\n    # plus the primitive's grant: hmac = [\"sha256\"], sign = [\"ed25519\"] or aead = [\"aes-256-gcm\"] in [capabilities.crypto]".to_owned(),
        _ => format!(
            "no qqq.toml spelling grants `{}` yet — this namespace has no modelled table; check the CAP range in QQQ-Checklist-V1.md for the modelling tracker",
            c.name()
        ),
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
        warnings: {
            let mut warnings = resolution.warnings.clone();
            warnings.extend(filesystem_root_warnings(&loaded.manifest));
            warnings
        },
    }
}

/// Warnings for filesystem grants that cover a filesystem root.
///
/// A filesystem-root grant authorizes the entire visible tree, so accepting
/// one silently is how an operator believes a narrow grant is active while
/// every descendant is authorized (CAP-FS-002). The check is lexical on the
/// declared path — no filesystem access — and shares `is_filesystem_root`
/// with the normalization contract, so the two cannot disagree on what
/// counts as a root.
///
/// Shared by `caps` and `inspect`: both surfaces report grants, so both must
/// warn about them. A warning that lives on only one of two grant-reporting
/// commands is one a reviewer reading the other will never see.
fn filesystem_root_warnings(manifest: &qqq_cap::manifest::Manifest) -> Vec<String> {
    manifest
        .capabilities
        .fs
        .iter()
        .filter(|entry| qqq_cap::is_filesystem_root(&entry.path))
        .map(|entry| {
            format!(
                "filesystem grant for `{}` covers a filesystem root — \
                 every descendant is authorized; narrow it to the \
                 smallest directory the guest needs",
                entry.path
            )
        })
        .collect()
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
    let operation_count: usize = doc
        .paths
        .values()
        .map(crate::openapi::PathItem::operation_count)
        .sum();
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
    /// Capabilities that are covert channels, called out separately.
    ///
    /// `caps` has always reported these; `inspect` did not, so a reviewer
    /// reading only the project report missed the grants §10.5 singles out
    /// as information channels the audit stream cannot see.
    pub covert_channels: Vec<String>,
    /// Non-blocking warnings from resolution, e.g. a filesystem-root grant.
    ///
    /// Same sources as `caps`: resolution warnings plus the shared
    /// filesystem-root check. Two grant-reporting commands must not disagree
    /// on what they warn about.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
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
    ///
    /// A window with no capped quantity bounds nothing — it only scopes
    /// `max_requests_per_window` — so a window-only header declares no policy
    /// and is dropped like any other empty header.
    #[must_use]
    const fn is_empty(&self) -> bool {
        self.max_body_bytes.is_none()
            && self.max_requests_per_window.is_none()
            && self.window_seconds.is_none()
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

        // Covert channels and warnings are rendered, not merely carried — the
        // same trap `implemented` fell into: a fact *available* in JSON and not
        // *presented* reads as a fact that does not exist.
        if !self.covert_channels.is_empty() {
            let _ = write!(
                out,
                "\n\nCovert channels not yet closed: {}",
                self.covert_channels.join(", ")
            );
        }
        for w in &self.warnings {
            let _ = write!(out, "\n\nwarning: {w}");
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
                    // The 60 is the manifest's documented default, not an
                    // invention: `qqq_cap::manifest::TenantLimit::window`
                    // applies it when a request cap is set with no window, so
                    // the report and the limiter agree. If that default ever
                    // changes, this line must change with it.
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
    let before_unmapped: BTreeSet<&str> = before
        .unmapped_interfaces
        .iter()
        .map(String::as_str)
        .collect();
    let after_unmapped: BTreeSet<&str> = after
        .unmapped_interfaces
        .iter()
        .map(String::as_str)
        .collect();

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

    // Any added capability is an escalation, which subsumes both rules above:
    // a move between bands and a gained channel both add a name. The two
    // narrower checks stay as documentation of *why* those shapes matter, but
    // the gate branches on the growth itself — otherwise a new write or egress
    // grant inside one band (http.server, then +sql.execute, both `Exposed`)
    // reads as "authority changed" while the CI gate stays green.
    let any_added = !added.is_empty();

    // A gained unmapped import escalates for the opposite reason: nothing
    // known was added, but the artifact reaches an interface the host cannot
    // describe — unauditable authority. (The 0.2 baseline never appears here;
    // `classify_import` filters it before the report is built.)
    let added_unmapped: Vec<String> = after_unmapped
        .difference(&before_unmapped)
        .map(|n| (*n).to_owned())
        .collect();
    let removed_unmapped: Vec<String> = before_unmapped
        .difference(&after_unmapped)
        .map(|n| (*n).to_owned())
        .collect();
    let gained_unmapped = !added_unmapped.is_empty();
    ArtifactDiff {
        before: before.artifact.clone(),
        after: after.artifact.clone(),
        before_digest: before.digest.clone(),
        after_digest: after.digest.clone(),
        added,
        removed,
        unchanged,
        added_unmapped,
        removed_unmapped,
        escalation: posture_worsened || gained_channel || any_added || gained_unmapped,
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
    /// Unmapped imports the second artifact carries and the first did not.
    ///
    /// Unauditable authority: the host cannot describe these interfaces, so a
    /// gain is an escalation even though no known capability was added.
    pub added_unmapped: Vec<String>,
    /// Unmapped imports the first artifact carried and the second does not.
    pub removed_unmapped: Vec<String>,
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
        } else if self.added.is_empty()
            && self.removed.is_empty()
            && self.added_unmapped.is_empty()
            && self.removed_unmapped.is_empty()
        {
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
        for u in &self.added_unmapped {
            let _ = write!(out, "\n  + {u} (unmapped — the host cannot describe it)");
        }
        for u in &self.removed_unmapped {
            let _ = write!(out, "\n  - {u} (unmapped)");
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

/// Sort one imported interface into `required` or `unmapped`.
///
/// The mapping reports the **strongest** capability the import implies, not
/// every one: the host re-checks the grant on every call (`send` demands
/// `http.client`, `incoming-authority` demands `http.server`), so an
/// ungranted half is denied, not silently exercised. Reporting every implied
/// capability would demand grants the artifact may never exercise — for the
/// serve-only reference application it would mandate the inert `http.client`
/// over-grant `LANG-005` exists to forbid. The 0.2 baseline links
/// unconditionally with no grant involved, so its names are neither
/// requirements nor findings.
fn classify_import(iface: &str, required: &mut Vec<CapabilityReport>, unmapped: &mut Vec<String>) {
    if crate::run::is_wasi02_baseline(iface) {
        return;
    }
    match crate::run::capability_for_import(iface) {
        Some(cap) => required.push(CapabilityReport {
            name: cap.name().to_owned(),
            interface: iface.to_owned(),
            implemented: crate::run::interface_implemented(iface),
        }),
        None => unmapped.push(iface.to_owned()),
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
/// * `QQQ-1002` — the artifact could not be read. An unreadable component is
///   a component-domain failure, like `run`'s and `serve`'s reads of the
///   same bytes — not a manifest-syntax failure, which is what `QQQ-2001`
///   names.
/// * `QQQ-6003` — the artifact is not a valid component. Reported rather than
///   falling back to a manifest, because silently answering a different
///   question is the failure this command was fixed for.
pub fn inspect_artifact(path: &std::path::Path) -> Result<ArtifactReport> {
    let bytes = std::fs::read(path).map_err(|e| {
        Error::new(
            ErrorCode::InvalidComponentArtifact,
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

    // Map each imported interface to the capability it requires, strongest
    // match wins. The host re-checks the grant on every call, so an ungranted
    // half is denied rather than exercised — reporting every implied
    // capability would demand grants a serve-only artifact never exercises
    // (`LANG-005`). An import with no matching capability is *not* dropped:
    // it is reported as unmapped, because an interface the host cannot name is
    // exactly the thing an auditor needs to see.
    let mut required = Vec::new();
    let mut unmapped = Vec::new();
    for iface in &imports {
        classify_import(iface, &mut required, &mut unmapped);
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
        // The path as given: normalising separators would break the
        // digest-to-path tie on Windows, where the audit log records the
        // path the operator typed.
        artifact: path.display().to_string(),
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
    /// Whether the host can serve the interface today, regardless of grants.
    ///
    /// The manifest `inspect` marks unimplemented interfaces; the artifact
    /// report did not, so an artifact requiring `http.server` read exactly
    /// like one requiring `crypto.hash`. Servability is not authority — an
    /// ungranted-but-servable interface fails with a remediation, an
    /// unservable one fails no matter what the manifest says.
    pub implemented: bool,
}

impl CommandOutput for ArtifactReport {
    fn command(&self) -> CommandName {
        CommandName::Inspect
    }

    fn summary(&self) -> String {
        // In human format this is the whole output, so the capabilities are
        // listed. An artifact inspection that reports a count and withholds the
        // names would fail the one question it exists to answer (`§O-036a`).
        //
        // The digest preview is `"sha256:"` (7) plus 16 hex characters: long
        // enough to match against the audit log, short enough for one line.
        const DIGEST_PREVIEW_LEN: usize = 23;
        let mut out = format!(
            "{}: {} ({} bytes, {}), {} required capabilit{}",
            self.artifact,
            self.kind,
            self.size_bytes,
            &self.digest[..self.digest.len().min(DIGEST_PREVIEW_LEN)],
            self.required.len(),
            if self.required.len() == 1 { "y" } else { "ies" }
        );

        // A capability the host cannot serve yet fails at instantiation, not
        // at the call the author expected — the same reason the manifest
        // `inspect` annotates unimplemented interfaces rather than listing
        // them bare.
        let unimplemented = self.required.iter().filter(|r| !r.implemented).count();
        if unimplemented > 0 {
            let _ = write!(
                out,
                " ({unimplemented} with no host implementation yet, marked below)"
            );
        }

        if self.required.is_empty() {
            out.push_str("\n\nThis artifact imports nothing: it can reach no host capability.");
        } else {
            out.push_str("\n\nRequired capabilities");
            for r in &self.required {
                if r.implemented {
                    let _ = write!(out, "\n  {:<20} from {}", r.name, r.interface);
                } else {
                    let _ = write!(
                        out,
                        "\n  {:<20} from {}  (no host implementation yet)",
                        r.name, r.interface
                    );
                }
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
        covert_channels: loaded
            .manifest
            .covert_channels()
            .iter()
            .map(|c| c.name().to_owned())
            .collect(),
        warnings: {
            let mut warnings = resolution.warnings.clone();
            warnings.extend(filesystem_root_warnings(&loaded.manifest));
            warnings.extend(dead_window_warnings(&loaded.manifest));
            warnings
        },
    })
}

/// Tenants that declare a window but no capped quantity.
///
/// A window only scopes `max_requests_per_window`; on its own it bounds
/// nothing. The entry is kept in the report (it *is* declared) with this
/// warning, rather than dropped silently — a dropped header would hide an
/// operator's half-written limit, while a bare entry would suggest a policy
/// that does not exist.
fn dead_window_warnings(manifest: &qqq_cap::manifest::Manifest) -> Vec<String> {
    let Some(limits) = manifest.server.limits.as_ref() else {
        return Vec::new();
    };
    limits
        .default
        .iter()
        .map(|d| ("default", d))
        .chain(limits.per_tenant.iter().map(|(t, d)| (t.as_str(), d)))
        .filter(|(_, d)| {
            d.window_seconds.is_some()
                && d.max_body_bytes.is_none()
                && d.max_requests_per_window.is_none()
                && d.max_connections.is_none()
        })
        .map(|(tenant, _)| {
            format!(
                "request limits for tenant `{tenant}` set a window with no capped \
                 quantity — it bounds nothing; add a cap or remove the header"
            )
        })
        .collect()
}

/// Read the `qqq.lock` that sits beside a loaded manifest, if there is one.
///
/// # Why three outcomes instead of two
///
/// Absence and corruption used to collapse into `None`, and the audit's
/// supply-chain section — *optional context* — reported both as silence. But
/// the two cases do not lead to the same action: absence means "never
/// examined", while a present-but-unparseable file means "examined and
/// broken" — a bad merge or tampering, the one shape where staying silent
/// hides exactly what the supply-chain section exists to catch. So absence
/// stays `Ok(None)` and corruption is an error the audit surfaces as a
/// finding (`audit::corrupt_lockfile_finding`); `install` remains the command
/// that reports the parse error with its line number.
///
/// # Errors
///
/// When the lockfile exists but cannot be read, or parses as invalid. The
/// error names the file; absence is `Ok(None)`, never an error.
pub fn sibling_lockfile(loaded: &LoadedManifest) -> Result<Option<qqq_pkg::lock::Lockfile>> {
    let Some(dir) = loaded.path.parent() else {
        return Ok(None);
    };
    let path = dir.join("qqq.lock");
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| {
        Error::new(
            ErrorCode::HostResourceExhausted,
            format!("could not read `{}`", path.display()),
        )
        .with_cause(e.to_string())
    })?;
    qqq_pkg::lock::Lockfile::parse(&text)
        .map(Some)
        .map_err(|e| {
            e.to_error()
                .with_context("lockfile", path.display().to_string())
        })
}

/// Whether one capability exposes the posture on its own.
///
/// The single statement of the rule `classify_posture` and the audit's
/// finding filter both read: a second copy would drift, and drift here
/// names the wrong grants or misses one. `pub(crate)` so the audit uses
/// this rather than restating the list.
#[must_use]
pub(crate) fn exposes_posture(cap: Capability) -> bool {
    matches!(
        cap,
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
    let exposes = caps.iter().any(|c| exposes_posture(*c));
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

// Test indexing (`F-18`): assertions index vectors built inline above.
// One module-level reason, not per-site noise; shipping code above
// carries no such allowance.
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions index inline vectors"
)]
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
    /// `HOST-034` owns the one remaining gap: `qqq:fs` declares `filesystem`
    /// but binds nothing — the WIT has no constructor, so no guest can obtain
    /// a first handle. This fixture names that gap the way the registry's
    /// `partial_implementations_do_not_claim_completeness` does.
    const FS: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                      [[capabilities.fs]]\npath = \"/tmp/in\"\nmode = \"read-only\"\n";

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
    fn why_denial_suggests_a_stanza_that_parses_and_grants() {
        // `log.write` graduated to a stanza in CAP-021 (`trace` in
        // CAP-022; `ai`/`queue`/`kv`/`sql` before them), so a denial
        // now carries a real stanza instead of a named refusal — the
        // inverse of the old unmodelled-denial pin. Ambient or not,
        // an unmentioned capability on DENY_ALL is denied, and the
        // fix is text the parser accepts that grants exactly it.
        use qqq_cap::manifest::Manifest;
        let l = loaded(DENY_ALL);
        let out = why(&l, "log.write").expect("must explain");
        assert!(!out.granted);
        assert!(out.steps.is_empty(), "nothing mentioned it");
        // Assert on the summary *before* moving `fix` out of `out`.
        assert!(out.summary().contains("DENIED"));
        let fix = out.fix.expect("a denial must suggest a fix");
        let body = stanza_body(&fix).expect("a denial carries a stanza now: {fix}");
        let manifest = Manifest::parse(&format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n{body}"
        ))
        .expect("the suggested stanza must parse");
        // Exact set: the marker selects one grant, so `contains`
        // would let a smuggled second grant ride along silently.
        assert_eq!(
            manifest.declared_capabilities(),
            vec![Capability::LogWrite],
            "the suggested stanza must grant exactly log.write: {fix}"
        );
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
    /// `crypto.hash` stands in: its stanza is modelled, so the human output
    /// carries a real one (unmodelled namespaces get the named refusal
    /// pinned above, never a stanza).
    #[test]
    fn why_prints_the_fix_stanza_in_human_output() {
        let l = loaded(DENY_ALL);
        let out = why(&l, "crypto.hash").expect("must explain");
        let text = out.summary();

        assert!(text.contains("DENIED"), "{text}");
        assert!(
            text.contains("capabilities.crypto"),
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

    /// Extract the TOML stanza from a fix suggestion, if it carries
    /// one: the prose header goes, indentation goes, the body stays.
    /// A refusal message has no stanza, so there is nothing to parse.
    fn stanza_body(fix: &str) -> Option<String> {
        let mut lines = fix.lines();
        if !lines.next()?.starts_with("add to qqq.toml:") {
            return None;
        }
        let body: Vec<&str> = lines.map(str::trim_start).collect();
        let body = body.join("\n");
        (!body.trim().is_empty()).then_some(body)
    }

    /// For every namespace, the suggested stanza parses and grants
    /// — or the suggestion is an explicit, named refusal. A stanza
    /// the parser rejects is a lie the tool tells the developer to
    /// paste, and a stanza that parses but grants nothing is the
    /// same lie one step removed; this loop makes both shapes fail
    /// the build for the namespace that introduces them, including
    /// future ones.
    #[test]
    fn every_suggested_stanza_parses() {
        use qqq_cap::capability::Namespace;
        use qqq_cap::manifest::Manifest;
        for ns in Namespace::all() {
            let cap = Capability::all()
                .iter()
                .find(|c| c.namespace() == ns.as_str())
                .expect("every namespace belongs to a capability");
            let fix = fix_stanza_for(*cap);
            let Some(body) = stanza_body(&fix) else {
                // No known namespace takes this branch anymore (pinned
                // by `every_namespace_has_a_modelled_stanza`); it stays
                // for a future fourteenth namespace, whose refusal must
                // still name its state and tracking. "CAP" without a
                // number on purpose: the wildcard names the CAP range,
                // never a phantom `CAP-NNN` the citations checker would
                // fail (procedure §6.5).
                assert!(
                    fix.contains("no qqq.toml spelling") && fix.contains("CAP"),
                    "{ns}: a refusal must name its state and tracking: {fix}"
                );
                continue;
            };
            let manifest = Manifest::parse(&format!(
                "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n{body}"
            ))
            .unwrap_or_else(|e| panic!("{ns}: the suggestion must parse: {e}"));
            assert!(
                manifest.declared_capabilities().contains(cap),
                "{ns}: the parsed stanza must grant {}: {fix}",
                cap.name()
            );
        }
    }

    /// Every namespace has a modelled stanza: `log`/`trace` graduated
    /// in CAP-021/022, leaving no known namespace on the refusal path.
    /// This pin exists because the property loop above would *pass* a
    /// regression that un-models a namespace — a refusal satisfies its
    /// fallback branch — so the "no refusals remain" direction needs
    /// its own assertion. The wildcard arm stays as a safety net for
    /// a future fourteenth namespace only.
    #[test]
    fn every_namespace_has_a_modelled_stanza() {
        use qqq_cap::capability::Namespace;
        for ns in Namespace::all() {
            let cap = Capability::all()
                .iter()
                .find(|c| c.namespace() == ns.as_str())
                .expect("every namespace belongs to a capability");
            let fix = fix_stanza_for(*cap);
            assert!(
                stanza_body(&fix).is_some(),
                "{ns}: must carry a stanza, not a refusal: {fix}"
            );
        }
    }

    /// The property loop picks the first capability per namespace,
    /// which for `sql` is `SqlExecute` in sort order — so the query
    /// stanza gets its own round-trip pin here rather than riding
    /// along unproven.
    #[test]
    fn sql_query_stanza_parses_and_grants_query() {
        use qqq_cap::manifest::Manifest;
        let fix = fix_stanza_for(Capability::SqlQuery);
        let body = stanza_body(&fix).expect("sql.query has a stanza");
        let manifest = Manifest::parse(&format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n{body}"
        ))
        .expect("the query stanza must parse");
        let granted = manifest.declared_capabilities();
        assert!(
            granted.contains(&Capability::SqlQuery),
            "the query stanza grants query"
        );
        assert!(
            !granted.contains(&Capability::SqlExecute),
            "the query stanza must not smuggle execute"
        );
    }

    /// The property loop picks the first capability per namespace,
    /// which for `kv` is `KvRead` in sort order — so the write stanza
    /// gets its own round-trip pin here rather than riding along
    /// unproven. Write implies read: a writer that cannot read its
    /// store is incoherent, so both grants are asserted.
    #[test]
    fn kv_write_stanza_parses_and_grants_write() {
        use qqq_cap::manifest::Manifest;
        let fix = fix_stanza_for(Capability::KvWrite);
        let body = stanza_body(&fix).expect("kv.write has a stanza");
        let manifest = Manifest::parse(&format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n{body}"
        ))
        .expect("the write stanza must parse");
        let granted = manifest.declared_capabilities();
        assert!(
            granted.contains(&Capability::KvWrite),
            "the write stanza grants write"
        );
        assert!(granted.contains(&Capability::KvRead), "write implies read");
    }

    /// The property loop picks the first capability per namespace,
    /// which for `queue` is `QueuePublish` in sort order — so the
    /// subscribe stanza gets its own round-trip pin here rather
    /// than riding along unproven.
    #[test]
    fn queue_subscribe_stanza_parses_and_grants_subscribe() {
        use qqq_cap::manifest::Manifest;
        let fix = fix_stanza_for(Capability::QueueSubscribe);
        let body = stanza_body(&fix).expect("queue.subscribe has a stanza");
        let manifest = Manifest::parse(&format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n{body}"
        ))
        .expect("the subscribe stanza must parse");
        let granted = manifest.declared_capabilities();
        assert!(
            granted.contains(&Capability::QueueSubscribe),
            "the subscribe stanza grants subscribe"
        );
        assert!(
            !granted.contains(&Capability::QueuePublish),
            "the subscribe stanza must not smuggle publish"
        );
    }

    /// The dedicated `[capabilities.secret]` table (CAP-023) is the
    /// stanza `qqqai why` suggests; the legacy nested `crypto.secrets`
    /// spelling still grants, pinned here so backwards compatibility
    /// cannot silently lapse.
    #[test]
    fn secret_stanza_parses_and_grants_use() {
        use qqq_cap::manifest::Manifest;
        let fix = fix_stanza_for(Capability::SecretUse);
        let body = stanza_body(&fix).expect("secret.use has a stanza");
        assert!(
            body.contains("[capabilities.secret]"),
            "the stanza is the dedicated table: {fix}"
        );
        let manifest = Manifest::parse(&format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n{body}"
        ))
        .expect("the secret stanza must parse");
        assert_eq!(
            manifest.declared_capabilities(),
            vec![Capability::SecretUse],
            "exactly one grant, no smuggling"
        );
    }

    /// The legacy spelling keeps granting: manifests written before
    /// CAP-023 used `[capabilities.crypto]` `secrets`, and graduation
    /// must not strand them.
    #[test]
    fn secret_legacy_crypto_spelling_still_grants() {
        use qqq_cap::manifest::Manifest;
        let manifest = Manifest::parse(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\
            [capabilities.crypto]\nsecrets = [\"env:NAME\"]\n",
        )
        .expect("the legacy spelling must parse");
        assert_eq!(
            manifest.declared_capabilities(),
            vec![Capability::SecretUse],
            "legacy grants exactly use"
        );
    }

    /// The `crypto` stanza grants exactly the crypto family: pasting
    /// it for a hash denial must not also grant `secret.use` through
    /// a bundled line. Within the family, each line names its own
    /// capability (`# for crypto.random`), so the reader picks lines
    /// rather than pasting blind — but nothing outside the family
    /// may ride along.
    #[test]
    fn crypto_stanza_grants_only_crypto() {
        use qqq_cap::manifest::Manifest;
        let fix = fix_stanza_for(Capability::CryptoHash);
        let body = stanza_body(&fix).expect("crypto.hash has a stanza");
        let manifest = Manifest::parse(&format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n{body}"
        ))
        .expect("the crypto stanza must parse");
        let granted = manifest.declared_capabilities();
        assert!(
            granted.contains(&Capability::CryptoHash),
            "the stanza grants its own capability"
        );
        assert!(
            !granted.contains(&Capability::SecretUse),
            "the stanza must not smuggle secret.use"
        );
    }

    /// A `fix` stanza grants exactly the capability it names — nothing else
    /// in its namespace.
    ///
    /// `why http.server` used to suggest `server = true` **and**
    /// `client = [...]`, so fixing a server denial granted egress; the
    /// `crypto` suggestion granted five capabilities including the covert
    /// `crypto.random`; and the `fs` suggestion was `read-only` for every
    /// denial, which never grants `write`.
    ///
    /// `fs` modes grant fixed bundles, so `read` and `watch` name their
    /// inherent co-grant (`read-only` is `read + watch`, CAP-024) rather than
    /// hiding it, and only `append-only` is exactly one grant.
    #[test]
    fn fix_stanzas_grant_only_the_capability_named() {
        use qqq_cap::manifest::Manifest;
        for (cap, expected) in [
            (Capability::HttpServer, vec![Capability::HttpServer]),
            (Capability::HttpClient, vec![Capability::HttpClient]),
            (Capability::CryptoRandom, vec![Capability::CryptoRandom]),
            (Capability::CryptoHash, vec![Capability::CryptoHash]),
            (Capability::CryptoHmac, vec![Capability::CryptoHmac]),
            (Capability::CryptoAead, vec![Capability::CryptoAead]),
            (Capability::CryptoSign, vec![Capability::CryptoSign]),
            (Capability::ClockWall, vec![Capability::ClockWall]),
            (Capability::ClockMonotonic, vec![Capability::ClockMonotonic]),
            // `append-only` is exactly `write`: the one fs mode that grants
            // a single capability.
            (Capability::FsWrite, vec![Capability::FsWrite]),
            // Readable modes imply watch (CAP-024): no mode grants `read`
            // or `watch` alone.
            (
                Capability::FsRead,
                vec![Capability::FsRead, Capability::FsWatch],
            ),
            (
                Capability::FsWatch,
                vec![Capability::FsRead, Capability::FsWatch],
            ),
        ] {
            let fix = fix_stanza_for(cap);
            let body = stanza_body(&fix).unwrap_or_else(|| panic!("{cap} has a stanza"));
            let manifest = Manifest::parse(&format!(
                "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n{body}"
            ))
            .unwrap_or_else(|e| panic!("{cap}: the suggestion must parse: {e}"));
            assert_eq!(
                manifest.declared_capabilities(),
                expected,
                "{cap}: the pasted stanza must grant the denied capability and name any co-grant"
            );
        }
    }

    /// The `fs` stanza grants `watch` for the readable modes (CAP-024):
    /// read-only and read-write entries imply `FsWatch`; append-only does
    /// not, or watching would leak reads the mode withholds. A pasted
    /// stanza for a watch denial now grants exactly what was denied — and
    /// the grant set is `Exposed` by posture, which the pin asserts so the
    /// consequence stays visible (a read-only preopen used to be
    /// `Contained`).
    #[test]
    fn fs_stanza_grants_watch_for_read_modes() {
        use qqq_cap::manifest::Manifest;
        let fix = fix_stanza_for(Capability::FsWatch);
        let body = stanza_body(&fix).expect("fs.watch shares the fs stanza");
        let manifest = Manifest::parse(&format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n{body}"
        ))
        .expect("the fs stanza must parse");
        let granted = manifest.declared_capabilities();
        assert_eq!(
            granted,
            vec![Capability::FsRead, Capability::FsWatch],
            "the read-only stanza grants exactly read plus watch"
        );
        assert_eq!(
            classify_posture(&granted),
            Posture::Exposed,
            "watch is exposing: the posture shift is the point, not a surprise"
        );
        // Append-only shares the stanza shape with a different mode and
        // must NOT gain watch.
        let append = Manifest::parse(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\
            [[capabilities.fs]]\npath = \"/var/lib/app\"\nmode = \"append-only\"\n",
        )
        .expect("the append-only stanza must parse");
        assert_eq!(
            append.declared_capabilities(),
            vec![Capability::FsWrite],
            "append-only grants exactly write"
        );
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

    /// **A root grant warns loudly.** A filesystem grant for `/` authorizes
    /// the entire visible tree; accepting it silently is how an operator
    /// believes a narrow grant is active while every descendant is
    /// authorized (CAP-FS-002). The warning names the path and prescribes
    /// narrowing, and a narrow grant must stay silent — a warning that fires
    /// on every grant is decoration, not signal.
    #[test]
    fn caps_warns_on_a_filesystem_root_grant() {
        const ROOT: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                            [[capabilities.fs]]\npath = \"/\"\nmode = \"read-only\"\n";
        const NARROW: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
                              [[capabilities.fs]]\npath = \"/var/lib/app\"\n\
                              mode = \"read-only\"\n";
        let out = caps(&loaded(ROOT), false);
        assert!(
            out.warnings
                .iter()
                .any(|w| w.contains("`/`") && w.contains("narrow")),
            "a `/` grant must warn and prescribe narrowing: {:?}",
            out.warnings
        );
        let quiet = caps(&loaded(NARROW), false);
        assert!(
            !quiet.warnings.iter().any(|w| w.contains("filesystem root")),
            "a narrow grant must not carry the root warning: {:?}",
            quiet.warnings
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
        // `HOST-037` flipped crypto to fully implemented; the inspect layer
        // must report that rather than the stale partial verdict.
        assert!(
            out.interfaces.iter().all(|i| i.implemented),
            "every granted interface here has a host behind it: {names:?}"
        );
        assert_eq!(
            out.posture,
            Posture::Contained,
            "hashing alone is contained"
        );
    }

    /// `qqq:crypto` is fully implemented (`HOST-037`), so the honesty
    /// probe points at the one interface that still has no host behind it:
    /// `qqq:fs` (`HOST-034`, blocked on a WIT constructor).
    #[test]
    fn inspect_marks_unimplemented_interfaces_honestly() {
        let out = inspect(&loaded(FS)).unwrap();
        let fs = out
            .interfaces
            .iter()
            .find(|i| i.name.starts_with("qqq:fs"))
            .expect("fs interface");
        assert!(
            !fs.implemented,
            "fs binds nothing until its WIT gains a constructor and must say so"
        );
        assert!(!fs.summary.is_empty());
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
        let out = inspect(&loaded(FS)).unwrap();
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
            interface_line.contains("qqq:fs"),
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

    /// `inspect` warns about the grants it reports: covert channels and a
    /// filesystem-root grant.
    ///
    /// `caps` has always carried both; `inspect` carried neither, so a
    /// reviewer reading only the project report missed the randomness grant
    /// §10.5 singles out and the root grant that authorizes the whole tree.
    /// The fields and the rendering are pinned separately: a populated field
    /// the human output drops reads exactly like a field that does not exist.
    #[test]
    fn inspect_warns_about_covert_channels_and_root_grants() {
        const RISKY: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
            [capabilities.crypto]\nhash = [\"sha256\"]\nrandom = true\n\
            [[capabilities.fs]]\npath = \"/\"\nmode = \"read-only\"\n";
        let out = inspect(&loaded(RISKY)).unwrap();
        assert!(
            out.covert_channels.contains(&"crypto.random".to_owned()),
            "randomness is a covert channel: {:?}",
            out.covert_channels
        );
        assert!(
            out.warnings.iter().any(|w| w.contains("filesystem root")),
            "the root grant must warn: {:?}",
            out.warnings
        );
        let text = out.summary();
        assert!(
            text.contains("Covert channels not yet closed: crypto.random"),
            "the covert grant must reach the human output:\n{text}"
        );
        assert!(
            text.contains("warning:"),
            "the root warning must reach the human output:\n{text}"
        );
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

    /// A window with no capped quantity bounds nothing: the entry is kept (it
    /// *is* declared) with a warning, rather than dropped like a fully empty
    /// header — dropping it would hide an operator's half-written limit.
    #[test]
    fn inspect_warns_on_a_window_only_entry() {
        const WINDOW_ONLY: &str = r#"
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
window_seconds = 60
"#;
        let out = inspect(&loaded(WINDOW_ONLY)).unwrap();
        let req = out
            .limits
            .request_limits
            .as_ref()
            .expect("a declared window is declared, not dropped");
        assert!(
            req.per_tenant.iter().any(|e| e.tenant == "127.0.0.1"),
            "the window-only tenant must be listed: {req:?}"
        );
        assert!(
            out.warnings.iter().any(|w| w.contains("bounds nothing")),
            "the dead window must warn: {:?}",
            out.warnings
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
            Capability::FsWatch,
            Capability::HttpClient,
            Capability::HttpServer,
            Capability::SqlExecute,
            Capability::KvWrite,
            Capability::DnsResolve,
            Capability::QueuePublish,
            Capability::QueueSubscribe,
            Capability::AiInfer,
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

    /// The remediation path sees every implied capability, not just the strongest.
    ///
    /// `qqq:http/http` is unlocked by both `HttpClient` and `HttpServer`: a
    /// missing-grant error that names only the server half leaves a send-using
    /// component failing after the paste. The singular mapping stays the
    /// reporting answer (per-call enforcement denies ungranted halves, so the
    /// report must not demand unexercised grants); this is the enumeration the
    /// remediation builds on.
    #[test]
    fn an_interface_implying_several_capabilities_reports_all_of_them() {
        let http = crate::run::capabilities_for_import("qqq:http/http@1.0.0");
        assert_eq!(
            http.len(),
            2,
            "http/http implies two capabilities: {http:?}"
        );
        assert!(
            http.contains(&Capability::HttpClient),
            "send-only still implies the client: {http:?}"
        );
        assert!(
            http.contains(&Capability::HttpServer),
            "the authority query still implies the server: {http:?}"
        );

        let fs = crate::run::capabilities_for_import("qqq:fs/filesystem@1.0.0");
        assert_eq!(
            fs.len(),
            3,
            "the whole filesystem interface is three grants: {fs:?}"
        );
        assert_eq!(
            fs[0],
            Capability::FsWrite,
            "strongest first, so the singular gate agrees: {fs:?}"
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

    // -- escalation --------------------------------------------------------

    /// Baseline imports are neither requirements nor findings.
    ///
    /// Every `wasm32-wasip2` `std` pulls in `wasi:cli/stdout` and friends;
    /// listing them as "unmapped" would bury a genuinely unknown import in
    /// noise, while listing them as required would demand a grant the runtime
    /// never checks.
    #[test]
    fn baseline_imports_are_neither_required_nor_unmapped() {
        let mut required = Vec::new();
        let mut unmapped = Vec::new();
        classify_import("wasi:cli/stdout@0.2.0", &mut required, &mut unmapped);
        assert!(required.is_empty() && unmapped.is_empty());
        classify_import(
            "wasi:http/incoming-handler@0.2.0",
            &mut required,
            &mut unmapped,
        );
        assert_eq!(
            unmapped,
            vec!["wasi:http/incoming-handler@0.2.0".to_owned()],
            "no baseline registration: still a finding"
        );
    }

    /// A scratch manifest directory isolated by process id, so parallel test
    /// runners never share it.
    fn temp_project(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("qqq-commands-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn loaded_at(dir: &std::path::Path, src: &str) -> LoadedManifest {
        std::fs::write(dir.join("qqq.toml"), src).unwrap();
        LoadedManifest {
            manifest: qqq_cap::manifest::Manifest::parse(src).expect("test manifest"),
            path: dir.join("qqq.toml"),
            source: src.to_owned(),
        }
    }

    /// Absence stays silence: no lockfile means the supply-chain surface was
    /// never examined.
    #[test]
    fn a_missing_sibling_lockfile_is_not_an_error() {
        let dir = temp_project("no-lock");
        let loaded = loaded_at(&dir, DENY_ALL);
        assert!(sibling_lockfile(&loaded).expect("absent is Ok").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Corruption is an error the audit surfaces — never silent `None`.
    ///
    /// A present-but-unparseable lockfile is what a bad merge or tampering
    /// produces; collapsing it into "absent" made the supply-chain section
    /// report nothing for exactly the file that needed a finding.
    #[test]
    fn a_corrupt_sibling_lockfile_is_an_error() {
        let dir = temp_project("corrupt-lock");
        let loaded = loaded_at(&dir, DENY_ALL);
        std::fs::write(dir.join("qqq.lock"), "this is not TOML [[[").unwrap();
        let err = sibling_lockfile(&loaded).expect_err("corrupt is Err");
        assert!(
            err.to_string().contains("qqq.lock"),
            "the error must name the file: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn artifact_report(required: &[(&str, &str)], posture: Posture) -> ArtifactReport {
        ArtifactReport {
            artifact: "a.wasm".to_owned(),
            digest: "sha256:abc".to_owned(),
            size_bytes: 8,
            kind: "component".to_owned(),
            required: required
                .iter()
                .map(|(n, i)| CapabilityReport {
                    name: (*n).to_owned(),
                    interface: (*i).to_owned(),
                    implemented: crate::run::interface_implemented(i),
                })
                .collect(),
            unmapped_interfaces: Vec::new(),
            posture,
        }
    }

    /// Any gained authority is an escalation, even inside one posture band.
    ///
    /// `before = [http.server]` is `Exposed`; `after = +[sql.execute]` is
    /// still `Exposed`, and `sql.execute` is not a covert channel — so the
    /// old `posture_worsened || gained_channel` rule stayed silent while
    /// authority grew, and the CI gate that promises "a gain of any
    /// authority" fails stayed green on a new write grant.
    #[test]
    fn any_added_authority_is_an_escalation() {
        let before = artifact_report(&[("http.server", "qqq:http/http")], Posture::Exposed);
        let after = artifact_report(
            &[
                ("http.server", "qqq:http/http"),
                ("sql.execute", "qqq:sql/database"),
            ],
            Posture::Exposed,
        );
        let diff = diff_artifacts(&before, &after);
        assert_eq!(diff.added.len(), 1, "one capability was gained");
        assert!(
            diff.escalation,
            "a gained capability is an escalation even when the posture band does not move"
        );
        let narrowed = diff_artifacts(&after, &before);
        assert!(
            !narrowed.escalation,
            "removing authority must not read as an escalation"
        );
        let same = diff_artifacts(&before, &before);
        assert!(!same.escalation, "no change must not read as an escalation");
        // A gained unmapped import escalates: the host cannot describe the
        // interface, so the new reach is unauditable authority.
        let plain = artifact_report(&[], Posture::Minimal);
        let mut weird = artifact_report(&[], Posture::Minimal);
        weird.unmapped_interfaces = vec!["qqq:weird/thing@1.0.0".to_owned()];
        let diff = diff_artifacts(&plain, &weird);
        assert_eq!(diff.added_unmapped.len(), 1);
        assert!(
            diff.escalation,
            "a gained undescribable import is an escalation"
        );
        assert!(
            diff.summary().contains("unmapped"),
            "the new reach must be visible, not just flaggable"
        );
    }

    // -- developer overlay -------------------------------------------------

    /// The envelope counts operations, not non-empty paths.
    ///
    /// One path serving `GET` + `POST` is one path and two operations: the old
    /// filter reported "1 operation" next to a document containing two.
    #[test]
    fn openapi_counts_operations_not_paths() {
        let l = loaded(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\
             [server]\n\
             routes = [{ path = \"/orders\", methods = [\"GET\", \"POST\"], handler = \"orders\" }]\n",
        );
        let out = openapi(&l).expect("the fixture generates");
        assert_eq!(out.path_count, 1);
        assert_eq!(
            out.operation_count, 2,
            "GET + POST on one path is two operations"
        );
    }

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
