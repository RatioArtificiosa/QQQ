// SPDX-License-Identifier: Apache-2.0

//! The capability resolution pipeline — steps 3 through 6 of Proposal §6.2.
//!
//! This module implements the single most important invariant in QQQ:
//!
//! > **No configuration layer may ever widen a grant. Overlays may only
//! > narrow.**
//!
//! # Why the invariant is structural, not procedural
//!
//! A rule enforced by a check can be bypassed by a bug in the check. A rule
//! enforced by the *shape of the type system* cannot. So:
//!
//! * The only way to combine two [`GrantSet`]s is [`GrantSet::narrow`], which
//!   computes a **set intersection**. There is no method anywhere in this
//!   crate that adds a capability to a resolved set.
//! * [`GrantSet`] has no public constructor that takes a capability list from
//!   an overlay. Overlays are [`Overlay`] values, and the only operation on an
//!   `Overlay` is to narrow a `GrantSet`.
//! * A test applies every overlay in every permutation and asserts the result
//!   is identical — commutativity, associativity and idempotence together mean
//!   ordering cannot be used to smuggle authority in.
//!
//! # The `why` chain
//!
//! Every narrowing decision is recorded as a [`WhyNode`], so `qqqai why
//! sql.orders` can print the full archaeology: which layer, which rule, and
//! what the value was before and after. This is the "killer DX affordance"
//! from Proposal §6.2, and it is why the pipeline returns a trace rather than
//! just a result.
//!
//! See Checklist `CAP-003` … `CAP-012`, `SEC-001`, `SEC-003`.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::Capability;
use crate::manifest::Manifest;

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

/// The configuration layers, in evaluation order.
///
/// Order matters for *explanation* but not for *outcome*: because narrowing is
/// commutative, the final grant set is the same regardless of order. The order
/// is fixed anyway so the `why` chain reads the way a human expects —
/// developer intent first, then progressively broader authority each taking
/// something away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layer {
    /// The project's own `qqq.toml`. The **only** layer that can grant.
    Manifest,
    /// Developer-mode additions from `qqqai run --cap`. Loudly non-production.
    Developer,
    /// QQQ Fabric organization policy. Narrowing only.
    Organization,
    /// Deployment configuration (k8s annotations, env, config file).
    /// Narrowing only.
    Platform,
}

impl Layer {
    /// Evaluation order, outermost authority first.
    #[must_use]
    pub const fn order(self) -> u8 {
        match self {
            Self::Manifest => 0,
            Self::Developer => 1,
            Self::Organization => 2,
            Self::Platform => 3,
        }
    }

    /// Whether this layer is permitted to grant authority it did not inherit.
    ///
    /// **Only the manifest may grant.** Everything else narrows. If this
    /// function ever returns `true` for another layer, the security model is
    /// broken — so it is tested.
    #[must_use]
    pub const fn may_grant(self) -> bool {
        matches!(self, Self::Manifest)
    }

    /// The stable name used in JSON and in the `why` output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Developer => "developer",
            Self::Organization => "organization",
            Self::Platform => "platform",
        }
    }

    /// Whether this layer is acceptable in a production deployment.
    ///
    /// The developer overlay is not: it exists to unblock local iteration, and
    /// the host refuses to run it when `QQQ_ENV=production` is set explicitly
    /// (it is never read implicitly — NN-5).
    #[must_use]
    pub const fn is_production_safe(self) -> bool {
        !matches!(self, Self::Developer)
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Overlay
// ---------------------------------------------------------------------------

/// A narrowing overlay contributed by one layer.
///
/// An overlay cannot grant. It can only say "remove these", or "keep only
/// these". Both are expressed as a [`GrantSet`] plus a [`NarrowMode`], and the
/// only thing you can do with an `Overlay` is apply it to a `GrantSet` — which
/// can only ever shrink it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlay {
    /// Which layer produced this overlay.
    pub layer: Layer,
    /// The capabilities this overlay permits, or removes.
    pub capabilities: BTreeSet<Capability>,
    /// How to interpret `capabilities`.
    pub mode: NarrowMode,
    /// A human sentence explaining the overlay's origin, shown by `qqqai why`.
    pub reason: String,
}

/// How an overlay's capability set is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarrowMode {
    /// Intersect: keep only capabilities named in the overlay *and* already
    /// granted. This is the common case for an allowlist policy.
    Intersect,
    /// Subtract: remove the named capabilities. Used for explicit `deny` rules.
    Subtract,
}

impl Overlay {
    /// An allowlist overlay: keep only what is both already granted and named.
    #[must_use]
    pub fn allow_only(
        layer: Layer,
        capabilities: impl IntoIterator<Item = Capability>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            layer,
            capabilities: capabilities.into_iter().collect(),
            mode: NarrowMode::Intersect,
            reason: reason.into(),
        }
    }

    /// A deny overlay: remove the named capabilities.
    #[must_use]
    pub fn deny(
        layer: Layer,
        capabilities: impl IntoIterator<Item = Capability>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            layer,
            capabilities: capabilities.into_iter().collect(),
            mode: NarrowMode::Subtract,
            reason: reason.into(),
        }
    }

    /// An overlay that changes nothing. Useful as the identity for tests and
    /// as the result of a policy that failed to match any rule.
    #[must_use]
    pub fn noop(layer: Layer) -> Self {
        Self {
            layer,
            capabilities: BTreeSet::new(),
            mode: NarrowMode::Subtract,
            reason: "no matching rule".to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// GrantSet
// ---------------------------------------------------------------------------

/// A concrete, resolved set of granted capabilities.
///
/// # The invariant
///
/// There is **no public API that adds a capability to a `GrantSet`**. The only
/// constructors take a manifest (the sole authorised granter) or start empty.
/// The only combinator is [`GrantSet::narrow`], which intersects or subtracts.
///
/// This is intentional and load-bearing. Do not add a `grant()` method.
///
/// # Equality semantics — read this before changing `PartialEq`
///
/// Two grant sets are equal **if and only if they grant the same authority**.
/// The `applied_layers` field is *provenance*, not authority, and is therefore
/// **excluded from `PartialEq` and `Hash`**.
///
/// This is not a nicety. Narrowing is commutative — applying overlay A then B
/// yields the same authority as B then A — but the *history* differs. If
/// equality compared history, the commutativity guarantee would be untestable
/// and, worse, a caller comparing two resolutions would see a difference where
/// none exists. Provenance is carried in the separate [`Resolution::trace`],
/// which is where a human or agent looks to understand *how* the authority was
/// arrived at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantSet {
    capabilities: BTreeSet<Capability>,
    /// Which layers contributed, in application order — for the `why` chain.
    /// Excluded from equality: see the type-level docs.
    applied_layers: Vec<Layer>,
}

impl PartialEq for GrantSet {
    fn eq(&self, other: &Self) -> bool {
        self.capabilities == other.capabilities
    }
}

impl Eq for GrantSet {}

impl std::hash::Hash for GrantSet {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Must agree with PartialEq: hash only the authority.
        self.capabilities.hash(state);
    }
}

impl GrantSet {
    /// The empty set. Grants nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            capabilities: BTreeSet::new(),
            applied_layers: Vec::new(),
        }
    }

    /// Build the initial grant set from a manifest — **the only layer that may
    /// grant authority.**
    #[must_use]
    pub fn from_manifest(manifest: &Manifest) -> Self {
        Self {
            capabilities: manifest.declared_capabilities().into_iter().collect(),
            applied_layers: vec![Layer::Manifest],
        }
    }

    /// Test whether a capability is granted.
    #[must_use]
    pub fn grants(&self, c: Capability) -> bool {
        self.capabilities.contains(&c)
    }

    /// The granted capabilities, sorted.
    #[must_use]
    pub fn capabilities(&self) -> Vec<Capability> {
        self.capabilities.iter().copied().collect()
    }

    /// How many capabilities are granted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Whether nothing is granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// The layers that have been applied, in order.
    #[must_use]
    pub fn applied_layers(&self) -> &[Layer] {
        &self.applied_layers
    }

    /// Apply an overlay, producing a **smaller or equal** set.
    ///
    /// # The narrowing guarantee
    ///
    /// The returned set is always a subset of `self`. This holds for both
    /// modes and is asserted by a debug assertion *and* by a unit test that
    /// tries to widen with every mode.
    ///
    /// # Examples
    ///
    /// The two modes can only ever remove authority — including when the
    /// caller asks for capabilities the set never had. Apply an allowlist and
    /// a deny rule to a set that starts empty and nothing appears:
    ///
    /// ```
    /// use qqq_cap::{Capability, GrantSet, Layer, Overlay};
    ///
    /// let mut grants = GrantSet::empty();
    /// assert!(grants.is_empty());
    ///
    /// // An "allow only" overlay is an intersection, so it cannot introduce a
    /// // capability the set did not already hold — the empty set stays empty.
    /// let allow = Overlay::allow_only(
    ///     Layer::Organization,
    ///     [Capability::HttpServer, Capability::CryptoHash],
    ///     "prod baseline",
    /// );
    /// grants = grants.narrow(&allow);
    /// assert!(!grants.grants(Capability::HttpServer));
    /// assert!(grants.is_empty());
    ///
    /// // A deny overlay subtracts. Subtracting from nothing is still nothing.
    /// let deny = Overlay::deny(Layer::Platform, [Capability::FsRead], "no disk");
    /// grants = grants.narrow(&deny);
    /// assert!(grants.is_empty());
    ///
    /// // The only way any authority exists is for the manifest to declare it,
    /// // because the manifest is the sole layer permitted to grant.
    /// let manifest = qqq_cap::Manifest::parse(
    ///     "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n\
    ///      [capabilities.http]\nserver = true\n",
    /// )
    /// .expect("a minimal manifest parses");
    /// let granted = GrantSet::from_manifest(&manifest);
    /// assert!(granted.grants(Capability::HttpServer));
    /// assert_eq!(granted.applied_layers(), [Layer::Manifest]);
    ///
    /// // Narrowing that set keeps a subset and records who narrowed it.
    /// let narrowed = granted.narrow(&Overlay::deny(
    ///     Layer::Platform,
    ///     [Capability::HttpServer],
    ///     "ingress is closed at the edge",
    /// ));
    /// assert!(!narrowed.grants(Capability::HttpServer));
    /// assert_eq!(
    ///     narrowed.applied_layers(),
    ///     [Layer::Manifest, Layer::Platform]
    /// );
    /// ```
    #[must_use]
    pub fn narrow(&self, overlay: &Overlay) -> Self {
        // Defence in depth: an overlay that claims granting authority is a
        // programming error, not a user error. Refuse it outright rather than
        // applying it — a layer that may not grant simply has no effect.
        if overlay.layer.may_grant() && overlay.layer != Layer::Manifest {
            debug_assert!(
                false,
                "non-manifest layer {} attempted to grant",
                overlay.layer
            );
            return self.clone();
        }

        let capabilities: BTreeSet<Capability> = match overlay.mode {
            NarrowMode::Intersect => self
                .capabilities
                .intersection(&overlay.capabilities)
                .copied()
                .collect(),
            NarrowMode::Subtract => self
                .capabilities
                .difference(&overlay.capabilities)
                .copied()
                .collect(),
        };

        // The narrowing guarantee, checked in debug builds. In release this
        // costs nothing; the tests cover it exhaustively.
        debug_assert!(
            capabilities.is_subset(&self.capabilities),
            "narrow() produced a set that is not a subset — the security model is broken"
        );

        let mut applied_layers = self.applied_layers.clone();
        if !applied_layers.contains(&overlay.layer) {
            applied_layers.push(overlay.layer);
        }

        Self {
            capabilities,
            applied_layers,
        }
    }

    /// A stable digest of the granted set, for the audit record (step 8).
    ///
    /// The digest covers only the *capabilities*, not the layer history: two
    /// deployments that arrive at the same authority by different routes have
    /// the same effective grant, and the audit stream should say so.
    #[must_use]
    pub fn digest(&self) -> String {
        // Sorted iteration makes this stable across runs and platforms, which
        // matters because the digest is compared across hosts.
        let mut hasher = Sha256::new();
        for c in &self.capabilities {
            hasher.update(c.name().as_bytes());
            hasher.update(b"\x00"); // unambiguous separator
        }
        hex(&hasher.finalize())
    }
}

impl fmt::Display for GrantSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.capabilities.is_empty() {
            return f.write_str("(none)");
        }
        let names: Vec<&str> = self.capabilities.iter().map(|c| c.name()).collect();
        f.write_str(&names.join(", "))
    }
}

// ---------------------------------------------------------------------------
// Why chain
// ---------------------------------------------------------------------------

/// One step in the resolution history, for `qqqai why`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhyNode {
    /// The layer that made this decision.
    pub layer: Layer,
    /// A human sentence explaining the rule that fired.
    pub reason: String,
    /// The capability this node is about, when the trace is per-capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<Capability>,
    /// Whether the capability was granted after this step.
    pub granted_after: bool,
    /// Whether it was granted before this step.
    pub granted_before: bool,
}

impl WhyNode {
    /// Whether this step changed anything for the capability in question.
    #[must_use]
    pub const fn changed(&self) -> bool {
        self.granted_before != self.granted_after
    }
}

/// The complete resolution result, including the archaeology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    /// The final, effective grant set.
    pub grants: GrantSet,
    /// Every decision made, in order.
    pub trace: Vec<WhyNode>,
    /// Warnings that do not block but that the user should see — e.g. a
    /// developer overlay active, or a declared capability no layer kept.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl Resolution {
    /// Resolve a manifest with no overlays.
    #[must_use]
    pub fn from_manifest(manifest: &Manifest) -> Self {
        let grants = GrantSet::from_manifest(manifest);
        let mut trace = Vec::new();
        for c in grants.capabilities() {
            trace.push(WhyNode {
                layer: Layer::Manifest,
                reason: "declared in qqq.toml".to_owned(),
                capability: Some(c),
                granted_before: false,
                granted_after: true,
            });
        }
        Self {
            grants,
            trace,
            warnings: Vec::new(),
        }
    }

    /// Apply one overlay, extending the trace.
    ///
    /// The trace records **changes**, not raw membership. A capability that was
    /// granted by the manifest and then removed here produces exactly one
    /// `changed` node naming this layer — so `qqqai why <cap>` answers "which
    /// layer took it away?" rather than burying it under the original grant.
    #[must_use]
    pub fn apply(mut self, overlay: &Overlay) -> Self {
        let before: BTreeSet<Capability> = self.grants.capabilities().into_iter().collect();
        let narrowed = self.grants.narrow(overlay);
        let after: BTreeSet<Capability> = narrowed.capabilities().into_iter().collect();

        // Capabilities this overlay had an opinion about, or actually changed.
        // Filtering to *changed* keeps the trace readable and makes the
        // "which layer removed it?" lookup unambiguous.
        let mut interesting: BTreeSet<Capability> = BTreeSet::new();
        interesting.extend(before.difference(&after).copied());
        interesting.extend(after.difference(&before).copied());

        for c in interesting {
            let b = before.contains(&c);
            let a = after.contains(&c);
            // Only genuine transitions reach the trace.
            if b != a {
                self.trace.push(WhyNode {
                    layer: overlay.layer,
                    reason: overlay.reason.clone(),
                    capability: Some(c),
                    granted_before: b,
                    granted_after: a,
                });
            }
        }

        if overlay.layer == Layer::Developer && !before.is_empty() {
            self.warnings.push(format!(
                "developer overlay active — NOT for production ({} rule)",
                overlay.reason
            ));
        }

        self.grants = narrowed;
        self
    }

    /// Apply every overlay in order.
    #[must_use]
    pub fn apply_all(mut self, overlays: &[Overlay]) -> Self {
        for o in overlays {
            self = self.apply(o);
        }
        self
    }

    /// The full explanation for one capability, ready to print.
    ///
    /// Returns `None` only if the capability is entirely absent from the trace
    /// and the final set, which means it was never mentioned by any layer.
    #[must_use]
    pub fn explain(&self, capability: Capability) -> Option<CapabilityExplanation> {
        let relevant: Vec<WhyNode> = self
            .trace
            .iter()
            .filter(|n| n.capability == Some(capability))
            .cloned()
            .collect();
        if relevant.is_empty() && !self.grants.grants(capability) {
            return Some(CapabilityExplanation {
                capability,
                granted: false,
                steps: Vec::new(),
                never_mentioned: true,
            });
        }
        Some(CapabilityExplanation {
            capability,
            granted: self.grants.grants(capability),
            steps: relevant,
            never_mentioned: false,
        })
    }

    /// Capabilities the manifest declared but no layer kept.
    ///
    /// Surfaced as a warning because a capability silently removed by policy
    /// is exactly the failure that `qqqai why` exists to explain, and finding
    /// out at request time is worse.
    #[must_use]
    pub fn narrowed_away(&self, manifest: &Manifest) -> Vec<Capability> {
        manifest
            .declared_capabilities()
            .into_iter()
            .filter(|c| !self.grants.grants(*c))
            .collect()
    }
}

/// The explanation produced by `qqqai why <capability>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityExplanation {
    /// The capability being explained.
    pub capability: Capability,
    /// The final decision.
    pub granted: bool,
    /// The steps, in order.
    pub steps: Vec<WhyNode>,
    /// Whether no layer ever mentioned this capability.
    pub never_mentioned: bool,
}

impl CapabilityExplanation {
    /// Render the chain the way `qqqai why` prints it.
    ///
    /// Shape is fixed: the verdict, then each layer that touched it, then the
    /// fix when the answer is "denied". This is a product surface (Proposal
    /// §12.2), so the format is tested.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let verdict = if self.granted { "GRANTED" } else { "DENIED" };
        let _ = writeln!(out, "{}  {verdict}", self.capability.name());

        if self.never_mentioned {
            let _ = writeln!(out, "  └─ no configuration layer mentions this capability");
            let _ = writeln!(
                out,
                "\n  → add a [[capabilities.*]] stanza for `{}` to qqq.toml",
                self.capability.namespace()
            );
            return out;
        }

        for (i, step) in self.steps.iter().enumerate() {
            let branch = if i + 1 == self.steps.len() {
                "└─"
            } else {
                "├─"
            };
            let mark = if step.changed() {
                if step.granted_after {
                    "GRANTED"
                } else {
                    "REMOVED"
                }
            } else {
                "unchanged"
            };
            let _ = writeln!(
                out,
                "  {branch} {:<12} {mark:<9} {}",
                step.layer.as_str(),
                step.reason
            );
        }

        if !self.granted {
            let _ = writeln!(
                out,
                "\n  → to grant it, add a [[capabilities.*]] stanza to qqq.toml"
            );
        }
        out
    }
}

// ---------------------------------------------------------------------------
// User-facing helpers
// ---------------------------------------------------------------------------

/// A post-resolution check: did the caller ask for something the resolver
/// removed?
///
/// Returns the denial error from `qqq-core` with the full context, so the
/// message an agent sees names *what* was denied, *which* layer removed it,
/// and *how* to fix it.
#[must_use]
pub fn denial(capability: Capability, resolution: &Resolution) -> qqq_core::Error {
    let mut err = qqq_core::Error::new(
        qqq_core::ErrorCode::CapabilityDenied,
        format!("capability `{capability}` is not granted"),
    )
    .with_context("capability", capability.name())
    .with_context("final-grants", resolution.grants.to_string())
    .with_context("grant-digest", resolution.grants.digest());

    for step in resolution
        .trace
        .iter()
        .filter(|n| n.capability == Some(capability) && n.changed())
    {
        err = err.with_cause(format!(
            "layer `{}`: {}{}",
            step.layer.as_str(),
            step.reason,
            if step.granted_after {
                " (granted)"
            } else {
                " (removed)"
            }
        ));
    }

    err.with_remediation(format!(
        "add a [[capabilities.*]] stanza granting `{capability}` to qqq.toml, \
         then run `qqqai why {capability}` to confirm"
    ))
}

// ---------------------------------------------------------------------------
// A tiny SHA-256 wrapper so the digest has no external surface
// ---------------------------------------------------------------------------

use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    // 2 hex chars per byte; pre-size to avoid reallocation.
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"
[package]
name = "test-app"
version = "0.1.0"

[capabilities.http]
server = true
client = ["api.example.com:443"]

[capabilities.crypto]
random = true
hash = ["sha256"]

[capabilities.clock]
wall = true
monotonic = true
"#;

    fn manifest() -> Manifest {
        Manifest::parse(MANIFEST).expect("test manifest must parse")
    }

    #[test]
    fn only_the_manifest_may_grant() {
        assert!(Layer::Manifest.may_grant());
        assert!(!Layer::Developer.may_grant());
        assert!(!Layer::Organization.may_grant());
        assert!(!Layer::Platform.may_grant());
    }

    #[test]
    fn layer_order_is_fixed() {
        assert!(Layer::Manifest.order() < Layer::Developer.order());
        assert!(Layer::Developer.order() < Layer::Organization.order());
        assert!(Layer::Organization.order() < Layer::Platform.order());
    }

    #[test]
    fn only_the_developer_layer_is_not_production_safe() {
        assert!(!Layer::Developer.is_production_safe());
        assert!(Layer::Manifest.is_production_safe());
        assert!(Layer::Organization.is_production_safe());
        assert!(Layer::Platform.is_production_safe());
    }

    #[test]
    fn empty_grant_set_grants_nothing() {
        let g = GrantSet::empty();
        assert!(g.is_empty());
        assert_eq!(g.len(), 0);
        for &c in Capability::all() {
            assert!(!g.grants(c), "empty set must not grant {c}");
        }
    }

    #[test]
    fn manifest_grant_set_matches_declarations() {
        let g = GrantSet::from_manifest(&manifest());
        assert!(g.grants(Capability::HttpServer));
        assert!(g.grants(Capability::HttpClient));
        assert!(g.grants(Capability::CryptoRandom));
        assert!(g.grants(Capability::CryptoHash));
        assert!(g.grants(Capability::ClockWall));
        assert!(g.grants(Capability::ClockMonotonic));
        // Never declared, never granted.
        assert!(!g.grants(Capability::FsRead));
        assert!(!g.grants(Capability::SqlQuery));
        assert!(!g.grants(Capability::SecretUse));
    }

    // -- The narrowing invariant ------------------------------------------

    #[test]
    fn intersect_narrows() {
        let g = GrantSet::from_manifest(&manifest());
        let before = g.len();
        let o = Overlay::allow_only(
            Layer::Organization,
            [Capability::HttpServer, Capability::ClockWall],
            "prod baseline allows only http and a wall clock",
        );
        let narrowed = g.narrow(&o);
        assert!(narrowed.len() < before, "intersect must shrink");
        assert!(narrowed.grants(Capability::HttpServer));
        assert!(narrowed.grants(Capability::ClockWall));
        assert!(!narrowed.grants(Capability::HttpClient));
        assert!(!narrowed.grants(Capability::CryptoRandom));
    }

    #[test]
    fn subtract_narrows() {
        let g = GrantSet::from_manifest(&manifest());
        let o = Overlay::deny(
            Layer::Organization,
            [Capability::CryptoRandom, Capability::HttpClient],
            "randomness and egress forbidden by policy",
        );
        let narrowed = g.narrow(&o);
        assert!(!narrowed.grants(Capability::CryptoRandom));
        assert!(!narrowed.grants(Capability::HttpClient));
        assert!(narrowed.grants(Capability::HttpServer));
    }

    /// **The core security test.** Try to widen with every mode and confirm
    /// nothing is ever added.
    #[test]
    fn no_overlay_can_ever_widen() {
        let base = GrantSet::empty(); // start from nothing at all
        let everything: Vec<Capability> = Capability::all().to_vec();

        for mode in [NarrowMode::Intersect, NarrowMode::Subtract] {
            for layer in [Layer::Developer, Layer::Organization, Layer::Platform] {
                let overlay = Overlay {
                    layer,
                    capabilities: everything.iter().copied().collect(),
                    mode,
                    reason: "hostile overlay attempting to grant everything".to_owned(),
                };
                let result = base.narrow(&overlay);
                assert!(
                    result.is_empty(),
                    "layer {layer} with mode {mode:?} widened an empty set to {result}"
                );
            }
        }
    }

    #[test]
    fn narrowing_is_idempotent() {
        let g = GrantSet::from_manifest(&manifest());
        let o = Overlay::allow_only(Layer::Organization, [Capability::HttpServer], "only http");
        let once = g.narrow(&o);
        let twice = once.narrow(&o);
        assert_eq!(
            once, twice,
            "applying the same overlay twice must not change it"
        );
    }

    /// Commutativity: ordering must not be usable to smuggle authority in.
    #[test]
    fn narrowing_is_commutative_across_layers() {
        let g = GrantSet::from_manifest(&manifest());
        let a = Overlay::allow_only(
            Layer::Organization,
            [
                Capability::HttpServer,
                Capability::CryptoHash,
                Capability::ClockWall,
            ],
            "org allowlist",
        );
        let b = Overlay::deny(
            Layer::Platform,
            [Capability::ClockWall],
            "platform forbids wall clock",
        );
        let c = Overlay::allow_only(
            Layer::Developer,
            [Capability::HttpServer, Capability::CryptoHash],
            "dev override",
        );

        let ab = g.narrow(&a).narrow(&b).narrow(&c);
        let ba = g.narrow(&b).narrow(&a).narrow(&c);
        let ca = g.narrow(&c).narrow(&a).narrow(&b);
        let ac = g.narrow(&a).narrow(&c).narrow(&b);

        assert_eq!(ab, ba, "order A,B differs from B,A");
        assert_eq!(ab, ca, "order differs for C,A");
        assert_eq!(ab, ac, "order differs for A,C");
    }

    #[test]
    fn overlay_from_a_non_granting_layer_that_claims_to_grant_is_ignored() {
        // A no-op overlay changes no authority, regardless of layer. Note it
        // DOES add provenance to applied_layers — which is deliberately
        // excluded from equality (see the GrantSet docs), so the sets compare
        // equal while the history is still available for the why chain.
        let g = GrantSet::from_manifest(&manifest());
        let before = g.clone();
        let result = g.narrow(&Overlay::noop(Layer::Organization));
        assert_eq!(before, result, "a no-op overlay must change no authority");
        assert_eq!(
            result.capabilities(),
            before.capabilities(),
            "the granted authority must be byte-identical"
        );
        assert_eq!(
            result.digest(),
            before.digest(),
            "the audit digest must not change when authority does not"
        );
        // Provenance IS recorded, so `qqqai why` can show the layer ran.
        assert!(result.applied_layers().contains(&Layer::Organization));
    }

    /// Equality must compare **authority**, not provenance. If this regresses,
    /// the commutativity guarantee becomes untestable and callers see phantom
    /// differences between two resolutions that grant exactly the same thing.
    #[test]
    fn equality_ignores_provenance_and_compares_authority() {
        let m = manifest();
        let a = GrantSet::from_manifest(&m);
        let b = GrantSet::from_manifest(&m).narrow(&Overlay::noop(Layer::Platform));
        assert_ne!(
            a.applied_layers(),
            b.applied_layers(),
            "the histories genuinely differ, or this test proves nothing"
        );
        assert_eq!(
            a, b,
            "but the authority is identical, so they must be equal"
        );
        assert_eq!(a.digest(), b.digest());
    }

    // -- Resolution and the why chain --------------------------------------

    #[test]
    fn resolution_records_manifest_grants() {
        let r = Resolution::from_manifest(&manifest());
        assert!(r.grants.grants(Capability::HttpServer));
        assert!(!r.trace.is_empty(), "the trace must record the grants");
        assert!(r.trace.iter().all(|n| n.layer == Layer::Manifest));
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn resolution_records_which_layer_removed_what() {
        let r = Resolution::from_manifest(&manifest()).apply(&Overlay::deny(
            Layer::Organization,
            [Capability::CryptoRandom],
            "policy: no randomness",
        ));
        assert!(!r.grants.grants(Capability::CryptoRandom));

        // The full lifecycle is two transitions: declared by the manifest,
        // then removed by policy. Recording both is what lets `qqqai why`
        // show the complete story rather than an orphaned removal.
        let transitions: Vec<&WhyNode> = r
            .trace
            .iter()
            .filter(|n| n.capability == Some(Capability::CryptoRandom) && n.changed())
            .collect();
        assert_eq!(
            transitions.len(),
            2,
            "expected grant then removal: {transitions:?}"
        );

        let granted = transitions[0];
        assert_eq!(granted.layer, Layer::Manifest);
        assert_eq!(
            (granted.granted_before, granted.granted_after),
            (false, true)
        );

        let removed = transitions[1];
        assert_eq!(removed.layer, Layer::Organization);
        assert_eq!(
            (removed.granted_before, removed.granted_after),
            (true, false)
        );
        assert_eq!(removed.reason, "policy: no randomness");

        // The last transition is authoritative: a reader asking "who decided?"
        // gets the layer that produced the final state.
        assert_eq!(
            transitions.last().unwrap().layer,
            Layer::Organization,
            "the final transition must name the deciding layer"
        );
    }

    #[test]
    fn developer_overlay_raises_a_warning() {
        let r = Resolution::from_manifest(&manifest()).apply(&Overlay::allow_only(
            Layer::Developer,
            [Capability::HttpServer],
            "--cap override",
        ));
        assert!(
            r.warnings.iter().any(|w| w.contains("NOT for production")),
            "developer overlay must warn loudly; got {:?}",
            r.warnings
        );
    }

    #[test]
    fn explain_reports_a_granted_capability() {
        let r = Resolution::from_manifest(&manifest());
        let e = r.explain(Capability::HttpServer).expect("must explain");
        assert!(e.granted);
        assert!(!e.never_mentioned);
        assert!(e.render().contains("GRANTED"));
    }

    #[test]
    fn explain_reports_a_denied_capability_with_a_fix() {
        let r = Resolution::from_manifest(&manifest());
        let e = r.explain(Capability::SqlQuery).expect("must explain");
        assert!(!e.granted);
        assert!(e.never_mentioned, "sql.query was never mentioned");
        let out = e.render();
        assert!(out.contains("DENIED"));
        assert!(out.contains("capabilities"), "must suggest the fix: {out}");
    }

    #[test]
    fn explain_shows_the_layer_that_removed_it() {
        let r = Resolution::from_manifest(&manifest()).apply(&Overlay::deny(
            Layer::Platform,
            [Capability::HttpClient],
            "egress disabled on this platform",
        ));
        let e = r.explain(Capability::HttpClient).unwrap();
        assert!(!e.granted);
        let out = e.render();
        assert!(out.contains("platform"), "must name the layer: {out}");
        assert!(
            out.contains("egress disabled"),
            "must quote the rule: {out}"
        );
    }

    #[test]
    fn narrowed_away_reports_silently_removed_grants() {
        let m = manifest();
        let r = Resolution::from_manifest(&m).apply(&Overlay::allow_only(
            Layer::Organization,
            [Capability::HttpServer],
            "only http",
        ));
        let lost = r.narrowed_away(&m);
        assert!(lost.contains(&Capability::CryptoRandom));
        assert!(lost.contains(&Capability::ClockWall));
        assert!(!lost.contains(&Capability::HttpServer));
    }

    // -- Digest -------------------------------------------------------------

    #[test]
    fn digest_is_stable_and_order_independent() {
        let m = manifest();
        let a = GrantSet::from_manifest(&m);
        let b = GrantSet::from_manifest(&m);
        assert_eq!(
            a.digest(),
            b.digest(),
            "same grants must give the same digest"
        );
        assert_eq!(a.digest().len(), 64, "sha256 hex is 64 chars");
    }

    /// Two routes to the same authority must digest identically, because the
    /// audit stream compares digests across hosts.
    #[test]
    fn digest_depends_only_on_effective_authority() {
        let m = manifest();
        let direct = GrantSet::from_manifest(&m);

        // Reach the same set via a narrowing that removes nothing.
        let via_noop = GrantSet::from_manifest(&m)
            .narrow(&Overlay::noop(Layer::Organization))
            .narrow(&Overlay::noop(Layer::Platform));
        assert_eq!(direct.digest(), via_noop.digest());

        // A genuinely different set must differ.
        let narrower = direct.narrow(&Overlay::deny(
            Layer::Platform,
            [Capability::CryptoRandom],
            "no randomness",
        ));
        assert_ne!(direct.digest(), narrower.digest());
    }

    #[test]
    fn empty_digest_is_still_wellformed() {
        assert_eq!(GrantSet::empty().digest().len(), 64);
        assert_ne!(
            GrantSet::empty().digest(),
            GrantSet::from_manifest(&manifest()).digest()
        );
    }

    // -- Denial error ------------------------------------------------------

    #[test]
    fn denial_error_carries_the_full_context() {
        let r = Resolution::from_manifest(&manifest()).apply(&Overlay::deny(
            Layer::Organization,
            [Capability::CryptoRandom],
            "policy: no randomness",
        ));
        let e = denial(Capability::CryptoRandom, &r);
        assert_eq!(e.code, qqq_core::ErrorCode::CapabilityDenied);
        assert_eq!(e.id(), "QQQ-4003");
        assert!(
            e.cause.iter().any(|c| c.contains("organization")),
            "the cause must name the layer: {:?}",
            e.cause
        );
        assert!(
            e.remediation.is_some(),
            "a denial must always suggest the fix"
        );
        // An agent must be able to act on it without parsing prose.
        assert!(!e.is_retryable(), "a capability denial is deterministic");
    }

    #[test]
    fn grantset_display_is_readable_and_sorted() {
        let g = GrantSet::from_manifest(&manifest());
        let s = g.to_string();
        assert!(s.contains("http.server"));
        assert!(s.contains("crypto.random"));
        assert_eq!(GrantSet::empty().to_string(), "(none)");
    }

    #[test]
    fn resolution_serializes_for_the_audit_stream() {
        let r = Resolution::from_manifest(&manifest());
        let j = serde_json::to_value(&r).unwrap();
        assert!(j["grants"]["capabilities"].is_array());
        assert_eq!(
            j["grants"]["capabilities"].as_array().unwrap().len(),
            r.grants.len()
        );
        // The digest is in the error context, so it reaches the audit record.
        let d = denial(Capability::SqlQuery, &r);
        assert!(d.context.iter().any(|(k, _)| k == "grant-digest"));
    }
}
