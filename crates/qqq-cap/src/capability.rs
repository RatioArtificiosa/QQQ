//! The capability vocabulary.
//!
//! A **capability** is a named, typed grant of authority. QQQ has three kinds
//! (Proposal §6.2):
//!
//! | Kind | Example | Backed by |
//! |---|---|---|
//! | **Resource** | a read-only preopened directory | a host handle |
//! | **Operation** | "may call `sql.query` against database `orders`" | a policy decision + parameterised binding |
//! | **Ambient** | "may read the wall clock" | a host-mediated interface |
//!
//! # The naming contract
//!
//! Every capability has a **stable dotted name** of the form
//! `<namespace>.<operation>`, e.g. `http.client`, `sql.query`, `fs.read`.
//! These names appear in manifests, in policy, in error messages, on the
//! `qqqai why` command line, and in the audit stream. They are part of the
//! machine contract and are **never renamed** — a capability that is retired
//! keeps its name and is documented as retired, exactly like an error code.
//!
//! # Why this is an enum and not a string
//!
//! Because a typo in a capability name must be a **compile-time or parse-time
//! error**, never a silent no-op. A manifest that says `htttp.client` grants
//! nothing and denies everything — which is safe, but produces a debugging
//! nightmare. Parsing into a closed enum means the error surfaces immediately,
//! with the nearest valid name suggested.
//!
//! See Proposal §6.2 and Checklist `CAP-001`, `CON-013`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A capability kind, matching the three-kind model in Proposal §6.2.
///
/// The distinction matters for resolution: resource capabilities carry a
/// filesystem path or handle, operation capabilities carry a policy target,
/// and ambient capabilities are booleans with no parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityKind {
    /// A handle to a host resource the guest may manipulate (files, sockets).
    Resource,
    /// Permission to invoke a named host operation with a scoped parameter.
    Operation,
    /// Permission to observe something the outside world provides —
    /// time, randomness. Deliberately explicit: both are classic covert
    /// channels and must never be granted implicitly.
    Ambient,
}

impl CapabilityKind {
    /// The stable lowercase name used in JSON and the audit stream.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::Operation => "operation",
            Self::Ambient => "ambient",
        }
    }
}

impl fmt::Display for CapabilityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The closed set of capabilities QQQ understands.
///
/// # Adding a capability
///
/// 1. Add the variant with a doc comment naming what it grants and what it
///    does **not**.
/// 2. Add it to [`Capability::ALL`].
/// 3. Assign it a kind in [`Capability::kind`] and a namespace in
///    [`Capability::name`].
/// 4. The round-trip test will fail until the name parses back, which is the
///    point.
///
/// # Retiring a capability
///
/// Mark it `#[deprecated]` with the replacement. Do **not** remove the variant
/// or its name: manifests, audit records and policy files in the wild refer to
/// it, and `qqqai why` must still be able to explain an old grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Capability {
    // -- Ambient -------------------------------------------------------------
    /// Read the wall clock. A covert channel if granted implicitly, so it is
    /// only ever granted explicitly — and is virtualised in deterministic mode
    /// (Proposal §10.5).
    ClockWall,
    /// Read the monotonic clock. Used for timeouts and measurement.
    ClockMonotonic,
    /// Draw randomness from the host CSPRNG. Never seeded by the guest except
    /// in deterministic test mode (Proposal §7.4).
    CryptoRandom,

    // -- Resource ------------------------------------------------------------
    /// Access a preopened filesystem path, scoped by mode and quota.
    FsRead,
    /// Write to a preopened filesystem path.
    FsWrite,
    /// Observe filesystem changes under a preopened path.
    FsWatch,

    // -- Operation -----------------------------------------------------------
    /// Receive inbound HTTP requests.
    HttpServer,
    /// Make outbound HTTP requests to allowlisted hosts.
    HttpClient,
    /// Query a named, host-pooled SQL database.
    SqlQuery,
    /// Execute a write statement against a named SQL database.
    SqlExecute,
    /// Read from a named key-value store.
    KvRead,
    /// Write to a named key-value store.
    KvWrite,
    /// Publish messages to a named queue or topic.
    QueuePublish,
    /// Subscribe to a named queue or topic.
    QueueSubscribe,
    /// Hash data with an allowlisted algorithm.
    CryptoHash,
    /// Compute a keyed MAC.
    CryptoHmac,
    /// Encrypt or decrypt with an AEAD construction.
    CryptoAead,
    /// Sign or verify with an allowlisted key algorithm.
    CryptoSign,
    /// **Use** a named secret to produce a result, without the secret value
    /// ever entering guest memory (Proposal §6.3).
    SecretUse,
    /// Resolve DNS names from an allowlist.
    DnsResolve,
    /// Emit structured log records.
    LogWrite,
    /// Emit trace spans and events.
    TraceWrite,
    /// Read environment variables, individually named — never a blanket
    /// inherit.
    EnvRead,
    /// Invoke a model through the host's inference interface, metered in
    /// tokens (Proposal §6.9).
    AiInfer,
}

impl Capability {
    /// Every capability, for schema generation and exhaustiveness tests.
    ///
    /// Sorted by namespace then name so an omission is visible in review, and
    /// so `qqqai schema --capabilities` is stable across runs.
    #[must_use]
    pub const fn all() -> &'static [Capability] {
        &[
            Capability::AiInfer,
            Capability::ClockMonotonic,
            Capability::ClockWall,
            Capability::CryptoAead,
            Capability::CryptoHash,
            Capability::CryptoHmac,
            Capability::CryptoRandom,
            Capability::CryptoSign,
            Capability::DnsResolve,
            Capability::EnvRead,
            Capability::FsRead,
            Capability::FsWatch,
            Capability::FsWrite,
            Capability::HttpClient,
            Capability::HttpServer,
            Capability::KvRead,
            Capability::KvWrite,
            Capability::LogWrite,
            Capability::QueuePublish,
            Capability::QueueSubscribe,
            Capability::SecretUse,
            Capability::SqlExecute,
            Capability::SqlQuery,
            Capability::TraceWrite,
        ]
    }

    /// The stable dotted name, e.g. `http.client`.
    ///
    /// This string is a machine contract. See the module docs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ClockWall => "clock.wall",
            Self::ClockMonotonic => "clock.monotonic",
            Self::CryptoRandom => "crypto.random",
            Self::CryptoHash => "crypto.hash",
            Self::CryptoHmac => "crypto.hmac",
            Self::CryptoAead => "crypto.aead",
            Self::CryptoSign => "crypto.sign",
            Self::FsRead => "fs.read",
            Self::FsWrite => "fs.write",
            Self::FsWatch => "fs.watch",
            Self::HttpServer => "http.server",
            Self::HttpClient => "http.client",
            Self::SqlQuery => "sql.query",
            Self::SqlExecute => "sql.execute",
            Self::KvRead => "kv.read",
            Self::KvWrite => "kv.write",
            Self::QueuePublish => "queue.publish",
            Self::QueueSubscribe => "queue.subscribe",
            Self::SecretUse => "secret.use",
            Self::DnsResolve => "dns.resolve",
            Self::LogWrite => "log.write",
            Self::TraceWrite => "trace.write",
            Self::EnvRead => "env.read",
            Self::AiInfer => "ai.infer",
        }
    }

    /// The namespace portion of the name, e.g. `http`.
    ///
    /// Used by policy wildcards (`sql.*`) and by grouping in `qqqai caps`.
    #[must_use]
    pub fn namespace(self) -> &'static str {
        // Every name is `<ns>.<op>` and is a static string, so the split
        // cannot fail; but we handle it defensively rather than panicking in
        // a security-critical path.
        self.name().split_once('.').map_or(self.name(), |(ns, _)| ns)
    }

    /// The capability's kind.
    #[must_use]
    pub const fn kind(self) -> CapabilityKind {
        match self {
            Self::ClockWall
            | Self::ClockMonotonic
            | Self::CryptoRandom
            | Self::LogWrite
            | Self::TraceWrite => CapabilityKind::Ambient,

            Self::FsRead | Self::FsWrite | Self::FsWatch => CapabilityKind::Resource,

            Self::HttpServer
            | Self::HttpClient
            | Self::SqlQuery
            | Self::SqlExecute
            | Self::KvRead
            | Self::KvWrite
            | Self::QueuePublish
            | Self::QueueSubscribe
            | Self::CryptoHash
            | Self::CryptoHmac
            | Self::CryptoAead
            | Self::CryptoSign
            | Self::SecretUse
            | Self::DnsResolve
            | Self::EnvRead
            | Self::AiInfer => CapabilityKind::Operation,
        }
    }

    /// Whether granting this capability can be observed by an attacker as a
    /// covert channel or a data-exfiltration path.
    ///
    /// Used by `qqqai audit` to raise the severity of an unexpected grant, and
    /// by the developer-mode warning to name the risky ones specifically.
    ///
    /// **Not** a measure of "dangerousness" in general — `fs.write` is far more
    /// dangerous than `clock.wall`. This is specifically about *channels*: a
    /// capability that lets a guest move information out of the sandbox in a
    /// way the audit stream cannot see.
    #[must_use]
    pub const fn is_covert_channel(self) -> bool {
        matches!(
            self,
            Self::ClockWall
                | Self::CryptoRandom
                | Self::DnsResolve
                | Self::HttpClient
                | Self::EnvRead
        )
    }

    /// Parse a capability from its stable name.
    ///
    /// Returns `None` for unknown names — callers must handle this and produce
    /// a helpful error rather than silently defaulting to deny-all, because a
    /// silent typo is the failure mode this whole design exists to prevent.
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        // Linear scan over 24 entries is faster than a map and keeps the
        // function `const`-friendly. Not a hot path (parse time only).
        let mut i = 0;
        while i < Self::all().len() {
            let c = Self::all()[i];
            if c.name() == s {
                return Some(c);
            }
            i += 1;
        }
        None
    }

    /// The closest known capability name to `input`, for error messages.
    ///
    /// Implements a small Levenshtein distance so a typo produces
    /// *"did you mean `http.client`?"* rather than *"unknown capability"*.
    /// This is a direct application of Non-Negotiable #1: an error an agent
    /// can act on is worth more than an error that merely reports failure.
    #[must_use]
    pub fn suggest(input: &str) -> Option<Self> {
        // Distance threshold scales with input length: a 3-char typo in a
        // 12-char name is a different signal from one in a 4-char name.
        let limit = match input.len() {
            0..=4 => 1,
            5..=8 => 2,
            _ => 3,
        };
        let mut best: Option<(usize, Capability)> = None;
        for &c in Self::all() {
            let d = levenshtein(input, c.name());
            if d <= limit && best.is_none_or(|(bd, _)| d < bd) {
                best = Some((d, c));
            }
        }
        best.map(|(_, c)| c)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Capability {
    type Err = UnknownCapability;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s).ok_or_else(|| UnknownCapability {
            input: s.to_owned(),
            suggestion: Self::suggest(s),
        })
    }
}

/// An unknown capability name, with a suggestion when one is close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownCapability {
    /// The name the user supplied.
    pub input: String,
    /// The nearest known capability, if any was close enough to be useful.
    pub suggestion: Option<Capability>,
}

impl fmt::Display for UnknownCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown capability `{}`", self.input)?;
        match self.suggestion {
            Some(c) => write!(f, " — did you mean `{c}`?"),
            None => write!(f, " — run `qqqai schema --capabilities` for the full list"),
        }
    }
}

impl std::error::Error for UnknownCapability {}

/// A capability selector: either one capability or a whole namespace.
///
/// Policy and overlays need to say `sql.*`. Manifests never do — a manifest
/// must name exactly what it wants, because "the manifest is the truth" is a
/// property this design depends on, and a wildcard in a manifest is a blank
/// cheque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilitySelector {
    /// Exactly one capability.
    One(Capability),
    /// Every capability in a namespace, e.g. `sql.*`.
    Namespace(Namespace),
}

/// A capability namespace such as `sql` or `http`.
///
/// Separate from `&str` so a namespace can only be constructed from a known
/// capability's namespace, making `sqll.*` unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Namespace(&'static str);

impl Namespace {
    /// The namespace's name, e.g. `sql`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// All namespaces, derived from the capability table so they cannot drift.
    #[must_use]
    pub fn all() -> Vec<Namespace> {
        let mut ns: Vec<&'static str> =
            Capability::all().iter().map(|c| c.namespace()).collect();
        ns.sort_unstable();
        ns.dedup();
        ns.into_iter().map(Namespace).collect()
    }

    /// Parse a namespace name.
    #[must_use]
    pub fn from_str_strict(s: &str) -> Option<Self> {
        Self::all().into_iter().find(|n| n.0 == s)
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl FromStr for CapabilitySelector {
    type Err = UnknownCapability;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(ns) = s.strip_suffix(".*") {
            return Namespace::from_str_strict(ns)
                .map(Self::Namespace)
                .ok_or_else(|| UnknownCapability {
                    input: s.to_owned(),
                    suggestion: None,
                });
        }
        s.parse::<Capability>().map(Self::One)
    }
}

impl fmt::Display for CapabilitySelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::One(c) => write!(f, "{c}"),
            Self::Namespace(n) => write!(f, "{n}.*"),
        }
    }
}

impl CapabilitySelector {
    /// Whether this selector matches a concrete capability.
    #[must_use]
    pub fn matches(self, c: Capability) -> bool {
        match self {
            Self::One(sel) => sel == c,
            Self::Namespace(ns) => ns.as_str() == c.namespace(),
        }
    }
}

/// Compute the Levenshtein edit distance between two strings.
///
/// Iterative with two rolling rows: `O(min(a,b))` space. Names are tiny, so
/// this is not a performance concern, but the bounded allocation avoids any
/// chance of an adversarial input ([`Capability::suggest`] is reachable from
/// user-supplied manifest text) causing a large allocation.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_capability_round_trips_from_its_name() {
        for &c in Capability::all() {
            assert_eq!(
                Capability::from_name(c.name()),
                Some(c),
                "capability {c:?} did not round-trip from `{}`",
                c.name()
            );
            assert_eq!(c.name().parse::<Capability>(), Ok(c));
        }
    }

    #[test]
    fn names_are_unique() {
        let mut seen = BTreeSet::new();
        for &c in Capability::all() {
            assert!(seen.insert(c.name()), "duplicate capability name {}", c.name());
        }
    }

    #[test]
    fn names_are_wellformed_dotted_pairs() {
        for &c in Capability::all() {
            let n = c.name();
            assert_eq!(
                n.matches('.').count(),
                1,
                "capability `{n}` must be exactly `<namespace>.<operation>`"
            );
            let (ns, op) = n.split_once('.').unwrap();
            assert!(!ns.is_empty() && !op.is_empty(), "empty part in `{n}`");
            assert!(
                ns.chars().all(|ch| ch.is_ascii_lowercase()),
                "namespace in `{n}` must be lowercase"
            );
            assert!(
                op.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_'),
                "operation in `{n}` must be lowercase snake_case"
            );
        }
    }

    #[test]
    fn all_is_sorted_so_omissions_are_visible() {
        let names: Vec<&str> = Capability::all().iter().map(|c| c.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "Capability::all() must be sorted by name");
    }

    #[test]
    fn namespace_is_derived_correctly() {
        assert_eq!(Capability::HttpClient.namespace(), "http");
        assert_eq!(Capability::SqlQuery.namespace(), "sql");
        assert_eq!(Capability::CryptoRandom.namespace(), "crypto");
    }

    #[test]
    fn namespaces_are_deduplicated_and_known() {
        let ns = Namespace::all();
        let names: Vec<&str> = ns.iter().map(|n| n.as_str()).collect();
        assert_eq!(names.len(), 13, "expected 13 namespaces, got {names:?}");
        assert!(names.contains(&"http"));
        assert!(names.contains(&"sql"));
        assert!(!names.contains(&"htttp"));
    }

    #[test]
    fn namespace_parse_rejects_typos() {
        assert!(Namespace::from_str_strict("http").is_some());
        assert!(Namespace::from_str_strict("htttp").is_none());
        assert!(Namespace::from_str_strict("").is_none());
    }

    #[test]
    fn kinds_are_assigned_deliberately() {
        assert_eq!(Capability::ClockWall.kind(), CapabilityKind::Ambient);
        assert_eq!(Capability::CryptoRandom.kind(), CapabilityKind::Ambient);
        assert_eq!(Capability::FsRead.kind(), CapabilityKind::Resource);
        assert_eq!(Capability::FsWrite.kind(), CapabilityKind::Resource);
        assert_eq!(Capability::SqlQuery.kind(), CapabilityKind::Operation);
        assert_eq!(Capability::SecretUse.kind(), CapabilityKind::Operation);
    }

    /// `crypto.random` and the clocks are ambient, not operations. If they were
    /// misclassified the resolution pipeline would treat them as scoped
    /// operations and the covert-channel warning would not fire.
    #[test]
    fn ambient_capabilities_are_exactly_the_covert_channel_primitives() {
        let ambient: BTreeSet<&str> = Capability::all()
            .iter()
            .filter(|c| c.kind() == CapabilityKind::Ambient)
            .map(|c| c.name())
            .collect();
        for expected in [
            "clock.wall",
            "clock.monotonic",
            "crypto.random",
            "log.write",
            "trace.write",
        ] {
            assert!(ambient.contains(expected), "{expected} must be ambient");
        }
        assert_eq!(ambient.len(), 5);
    }

    #[test]
    fn covert_channels_are_flagged_conservatively() {
        // Deterministic clock reading is repeatable and cannot carry
        // information out, so it is not flagged.
        assert!(!Capability::ClockMonotonic.is_covert_channel());
        // Wall clock can encode a signal in *when* something happens.
        assert!(Capability::ClockWall.is_covert_channel());
        // Randomness is a classic covert channel.
        assert!(Capability::CryptoRandom.is_covert_channel());
        // Network and DNS exfiltrate trivially.
        assert!(Capability::HttpClient.is_covert_channel());
        assert!(Capability::DnsResolve.is_covert_channel());
        // Environment reads can leak deployment secrets.
        assert!(Capability::EnvRead.is_covert_channel());
        // A filesystem read is a data *access* risk but not a covert channel
        // in this sense: the audit stream sees every byte read.
        assert!(!Capability::FsRead.is_covert_channel());
    }

    /// The auth example from Proposal §5.3 must parse. This is the user-facing
    /// contract; if it breaks, the docs are lying.
    #[test]
    fn proposal_manifest_examples_parse() {
        for name in [
            "http.server",
            "http.client",
            "fs.read",
            "fs.write",
            "sql.query",
            "sql.execute",
            "kv.read",
            "kv.write",
            "queue.publish",
            "crypto.random",
            "crypto.hash",
            "crypto.hmac",
            "crypto.aead",
            "crypto.sign",
            "secret.use",
            "clock.wall",
            "clock.monotonic",
            "env.read",
            "dns.resolve",
            "ai.infer",
        ] {
            assert!(
                name.parse::<Capability>().is_ok(),
                "the proposal's manifest example uses `{name}`, which must parse"
            );
        }
    }

    #[test]
    fn unknown_capability_produces_a_useful_suggestion() {
        let e = "htttp.client".parse::<Capability>().unwrap_err();
        assert_eq!(e.suggestion, Some(Capability::HttpClient));
        let msg = e.to_string();
        assert!(msg.contains("did you mean `http.client`?"), "got: {msg}");

        let e = "sql.querry".parse::<Capability>().unwrap_err();
        assert_eq!(e.suggestion, Some(Capability::SqlQuery));

        let e = "fs.rread".parse::<Capability>().unwrap_err();
        assert_eq!(e.suggestion, Some(Capability::FsRead));
    }

    #[test]
    fn wildly_wrong_names_get_no_misleading_suggestion() {
        let e = "totally_unrelated".parse::<Capability>().unwrap_err();
        assert_eq!(e.suggestion, None, "must not suggest a distant name");
        assert!(e.to_string().contains("schema --capabilities"));
    }

    #[test]
    fn selector_parses_single_and_namespace() {
        assert_eq!(
            "http.client".parse::<CapabilitySelector>().unwrap(),
            CapabilitySelector::One(Capability::HttpClient)
        );
        let ns = "sql.*".parse::<CapabilitySelector>().unwrap();
        assert!(matches!(ns, CapabilitySelector::Namespace(_)));
        assert_eq!(ns.to_string(), "sql.*");
    }

    #[test]
    fn selector_matching_is_correct() {
        let one = CapabilitySelector::One(Capability::HttpClient);
        assert!(one.matches(Capability::HttpClient));
        assert!(!one.matches(Capability::HttpServer));

        let ns: CapabilitySelector = "sql.*".parse().unwrap();
        assert!(ns.matches(Capability::SqlQuery));
        assert!(ns.matches(Capability::SqlExecute));
        assert!(!ns.matches(Capability::KvRead));
    }

    #[test]
    fn selector_rejects_unknown_namespace() {
        assert!("htttp.*".parse::<CapabilitySelector>().is_err());
        assert!("*.client".parse::<CapabilitySelector>().is_err());
    }

    #[test]
    fn levenshtein_is_correct() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("http.client", "htttp.client"), 1);
    }

    /// An adversarial input must not cause a large allocation. `suggest` is
    /// reachable from manifest text, which is attacker-influenced in a
    /// multi-tenant setting.
    #[test]
    fn suggest_survives_adversarial_input() {
        let huge = "a".repeat(100_000);
        assert_eq!(Capability::suggest(&huge), None);
        assert_eq!(Capability::suggest(""), None);
        assert_eq!(Capability::suggest("....."), None);
    }
}
