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
        if self.granted {
            format!("{} GRANTED", self.capability)
        } else {
            format!("{} DENIED", self.capability)
        }
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
        if self.deny_all {
            return format!("{}: no capabilities granted", self.project);
        }
        format!(
            "{}: {} capabilities across {} namespaces",
            self.project,
            self.grants.len(),
            self.by_namespace.len()
        )
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Show the effective grants for a project.
#[must_use]
pub fn caps(loaded: &LoadedManifest) -> CapsOutput {
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
    }
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
        format!(
            "{}: {} capabilities, {} interfaces, posture: {}",
            self.project,
            self.capabilities.len(),
            self.interfaces.len(),
            self.posture.as_str()
        )
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
        },
        posture: classify_posture(&caps),
    })
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
        let out = caps(&loaded(DENY_ALL));
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
        let out = caps(&loaded(CRYPTO));
        assert!(!out.deny_all);
        assert_eq!(out.by_namespace.len(), 1);
        assert_eq!(out.by_namespace[0].namespace, "crypto");
        assert_eq!(out.by_namespace[0].capabilities.len(), 2);
        // The summary reports counts; the namespace names live in the
        // structured field, which is what an agent reads.
        assert!(out.summary().contains("2 capabilities"));
        assert!(out.summary().contains("1 namespaces"));
    }

    /// `crypto.random` is a covert channel and must be called out, because it
    /// is the grant most likely to be added without thought.
    #[test]
    fn caps_surfaces_covert_channels() {
        let out = caps(&loaded(CRYPTO));
        assert!(
            out.covert_channels.contains(&"crypto.random".to_owned()),
            "randomness is a covert channel and must be flagged: {:?}",
            out.covert_channels
        );
    }

    #[test]
    fn caps_digest_is_stable_and_content_addressed() {
        let a = caps(&loaded(CRYPTO));
        let b = caps(&loaded(CRYPTO));
        assert_eq!(a.digest, b.digest);
        assert_ne!(a.digest, caps(&loaded(DENY_ALL)).digest);
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

        let caps_json = serde_json::to_value(caps(&l)).unwrap();
        assert!(caps_json["digest"].is_string());
        assert!(caps_json["by_namespace"].is_array());

        let inspect_json = serde_json::to_value(inspect(&l).unwrap()).unwrap();
        assert_eq!(inspect_json["posture"], "contained");
        assert!(inspect_json["interfaces"].is_array());
        assert_eq!(inspect_json["limits"]["memory"], "128MiB");
    }
}
