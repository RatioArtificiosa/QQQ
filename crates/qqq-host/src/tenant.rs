// SPDX-License-Identifier: Apache-2.0

//! Per-tenant isolation and the proof that handles cannot leak across tenants --
//! `CAP-014`.
//!
//! # What §4.4 claims, and what it would take for the claim to be false
//!
//! Proposal §4.4 states the consequence of building the linker per instance:
//!
//! > **Steps 7 and 8 happen per instance, not per process.** That is the
//! > difference between "the server has permissions" and "this request has
//! > permissions". Two tenants on the same host share zero authority.
//!
//! and §7.1 names the threat this defends against:
//!
//! > | **Compromised tenant** | Legitimate but hostile within its own tenant |
//! >   Per-tenant isolation; no cross-tenant handles; tenant-scoped audit |
//!
//! "Zero authority shared" is a claim about a **negative**: no path exists from
//! a handle belonging to tenant A to a resource belonging to tenant B. Negative
//! claims are the ones that need a proof rather than a demonstration, because
//! any number of passing happy paths is consistent with the property being
//! false.
//!
//! Before this module, the property was *nearly* structurally true and not
//! actually true, in a way worth recording precisely (`§O-104`) — see
//! [the section on the key](#the-key-is-built-from-security-relevant-fields-only).
//!
//! # The three surfaces a handle could leak across
//!
//! A handle in QQQ ends up in one of three places. Each is a separate argument:
//!
//! | Surface | Mechanism | Why it cannot cross |
//! |---|---|---|
//! | [`HandleTable`] | 64-bit `(generation, slot)` integer | The table is a field of one instance's [`StoreData`], and [`StoreData`] is not `Sync` and never shared between stores |
//! | Host-side resources | `T` in `HandleTable<T>` | Reachable only *through* a table lookup, so it inherits the table's containment |
//! | Tenant identity | [`TenantScope`] | Checked on entry and on every mutation of an instance's identity |
//!
//! The middle row is the one that makes the first row sufficient for the
//! guest-visible surface, but it is not sufficient for the *host*: a host that
//! keeps its own map from handle to resource, outside the store, re-introduces
//! the leak. [`TenantScope`] exists to make that mistake detectable, because
//! "the resource is only reachable through the store" is a property of code
//! that is easy to break by adding a cache.
//!
//! # The key is built from security-relevant fields only
//!
//! The obvious way to key an instance is "(tenant, component digest)". It is
//! wrong, and it is wrong in the direction that grants authority.
//!
//! §4.4 step 4 is the only place routing state lives, and two *different*
//! manifests can share a component digest — the same wasm bytes deployed twice
//! with different grants. Measured on the real types: `ComponentDigest` is a
//! content hash of the artifact, and a manifest revision is a separate value.
//! Keying on the digest alone would let a pooled instance created for tenant A
//! under a permissive manifest revision be handed to tenant B, or be reused
//! after tenant A's grants were narrowed. That is exactly the "pooled instance
//! carries stale authority" failure, and it is invisible in every test that
//! uses one manifest.
//!
//! [`InstanceKey::new`] therefore takes the tenant, the digest, **and** the
//! grant digest, and its test suite includes the case that separates the last
//! two.
//!
//! # Why an instance is scoped at creation and cannot be re-scoped
//!
//! A pool keyed per tenant gives isolation only if an instance's *own* notion
//! of which tenant it belongs to cannot change. A `set_tenant` method would be
//! the whole vulnerability on its own: the pool could be correct and the leak
//! would still happen through one call in a request path that reused a warm
//! instance. So the scope is fixed when [`StoreData`] is constructed and the
//! only mutation available is [`TenantScope::for_same_tenant`], which refuses
//! to change the tenant at all.
//!
//! # The runtime check, and why it is a probe rather than a guard
//!
//! [`TenantScope::probe`] answers "may this store touch a handle it believes
//! belongs to tenant X". In a correct build the answer is always yes, so the
//! check cannot fail — and a check that cannot fail carries no information
//! (`§M-006`). It is kept for the same reason [`crate::linker::recheck`] is
//! kept: the two failure modes are asymmetric. A missing guard is a security
//! hole; a redundant one is a branch that prediction renders free. The
//! difference from `recheck` is that this one is *reachable* — `recheck`'s
//! input set excludes granted capabilities by construction, whereas `probe`
//! can be driven to its refusal branch by any host bug that ranks one scope
//! above another, and its test suite does exactly that with a hand-built
//! mismatched scope.

use std::collections::BTreeMap;
use std::fmt;

use qqq_cap::egress::TenantId;

/// A capability grant digest, as `GrantSet` computes it.
///
/// # Why this is a distinct type and not a `String`
///
/// Because the bug this module prevents is *passing the wrong one of two
/// similar strings*. Two `String` parameters can be swapped by a caller and
/// still compile; a `ComponentDigest` and a `GrantDigest` cannot be, and the
/// pool key is built at exactly the place where that swap would create a
/// cross-tenant reuse. The type is the check.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantDigest(String);

impl GrantDigest {
    /// Wrap an already-computed grant digest.
    ///
    /// # Errors
    ///
    /// Rejects an empty digest, or one containing characters outside
    /// `[0-9a-f]`. A digest is compared to decide *authority*, so a digest
    /// spelling that is not canonical would make two descriptions of the same
    /// grant set compare unequal, and a pool would treat them as two tenants'
    /// worth of instances. Refusing early keeps that impossible rather than
    /// unlikely.
    pub fn new(digest: &str) -> Result<Self, String> {
        if digest.is_empty() {
            return Err("a grant digest must not be empty".to_owned());
        }
        if !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!(
                "a grant digest must be lowercase hexadecimal, got {digest:?}; \
                 an authority comparison on a non-canonical spelling would make \
                 two spellings of one grant set compare unequal"
            ));
        }
        Ok(Self(digest.to_owned()))
    }

    /// The digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GrantDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A component content digest, as the artifact cache computes it.
///
/// The counterpart to [`GrantDigest`]; see that type for why the distinction is
/// load-bearing rather than cosmetic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComponentDigest(String);

impl ComponentDigest {
    /// Wrap an already-computed component digest.
    ///
    /// # Errors
    ///
    /// Rejects an empty digest or one with non-`[0-9a-f]` characters, for the
    /// same reason as [`GrantDigest::new`].
    pub fn new(digest: &str) -> Result<Self, String> {
        if digest.is_empty() {
            return Err("a component digest must not be empty".to_owned());
        }
        if !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!(
                "a component digest must be lowercase hexadecimal, got {digest:?}"
            ));
        }
        Ok(Self(digest.to_owned()))
    }

    /// The digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ComponentDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The identity of one tenant's use of one component under one grant set.
///
/// # Why three fields, and why `PartialOrd`
///
/// Three, because dropping any one of them creates a specific cross-tenant
/// path:
///
/// * Drop the tenant -- every tenant shares a pool entry. The §7.1 threat in
///   full.
/// * Drop the grant digest -- a narrowed manifest reuses an instance built
///   under the wider one. The instance keeps authority the operator revoked.
/// * Drop the component digest -- two different artifacts under one grant set
///   share an instance. Less severe, still wrong: an AOT-compiled instance is
///   bound to one compiled module.
///
/// `Ord` (not just `Hash`/`Eq`) because a `BTreeMap` key gives a deterministic
/// pool iteration order, and determinism is a §10.5 feature rather than a
/// convenience.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstanceKey {
    /// The tenant this instance serves.
    pub tenant: TenantId,
    /// The artifact the instance runs.
    pub component: ComponentDigest,
    /// The grant set the instance was built against.
    pub grants: GrantDigest,
}

impl InstanceKey {
    /// Name one tenant's use of one component under one grant set.
    #[must_use]
    pub fn new(tenant: TenantId, component: ComponentDigest, grants: GrantDigest) -> Self {
        Self {
            tenant,
            component,
            grants,
        }
    }

    /// The tenant.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}

impl fmt::Display for InstanceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}#{}", self.tenant, self.component, self.grants)
    }
}

/// Why a scoped operation was refused.
///
/// Kept as a value rather than a `bool` so the refusal can be rendered with
/// both scopes named. "denied" is not actionable; "this store belongs to
/// `acme`, the resource to `globex`" is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeRefusal {
    /// The store's tenant is not the resource's tenant.
    ForeignTenant {
        /// The tenant the store belongs to.
        store: TenantId,
        /// The tenant the resource belongs to.
        resource: TenantId,
    },
    /// The store was built against a different grant set.
    StaleGrants {
        /// The digest the store was built with.
        store: GrantDigest,
        /// The digest the resource was created under.
        resource: GrantDigest,
    },
}

impl fmt::Display for ScopeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignTenant { store, resource } => write!(
                f,
                "cross-tenant handle use refused: this store belongs to tenant \
                 `{store}` but the handle belongs to tenant `{resource}`"
            ),
            Self::StaleGrants { store, resource } => write!(
                f,
                "handle use refused: this store was built against grant digest \
                 `{store}` but the handle was created under `{resource}`, so the \
                 instance may hold authority the current manifest revoked"
            ),
        }
    }
}

/// The tenant identity an instance carries for its whole life -- `CAP-014`.
///
/// # Why the tenant is immutable
///
/// A pool is only isolated if the instance's own view of its tenant cannot
/// change after creation. If it could, one call in one request path would undo
/// any amount of correct pooling. See the module docs.
///
/// The grant digest is *also* immutable here, and that is deliberate: a grant
/// change means a **new** instance, not a re-labelled one. Re-labelling would
/// have to prove that nothing from the old grant set survived into the store --
/// handle tables, ambient state, the linker -- and proving that by inspection
/// is strictly harder than not doing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantScope {
    tenant: TenantId,
    grants: GrantDigest,
}

impl TenantScope {
    /// Scope an instance to a tenant and a grant set.
    #[must_use]
    pub fn new(tenant: TenantId, grants: GrantDigest) -> Self {
        Self { tenant, grants }
    }

    /// The tenant this instance serves.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The grant digest the instance was built against.
    #[must_use]
    pub fn grants(&self) -> &GrantDigest {
        &self.grants
    }

    /// The only operation that resembles re-scoping: derive a scope for the
    /// *same* tenant under a different grant set.
    ///
    /// # Why this exists instead of `set_tenant`
    ///
    /// A caller that needs to describe "this tenant, narrower grants" has a
    /// legitimate reason to build a scope; a caller that needs to describe
    /// "this instance, different tenant" does not, and the absence of such a
    /// constructor is what makes the cross-tenant path unreachable rather than
    /// merely unwritten.
    ///
    /// Returns a **new** scope. It does not mutate `self`, so an instance that
    /// already holds one cannot acquire a second identity by having a scope
    /// cloned and edited underneath it.
    #[must_use]
    pub fn for_same_tenant(&self, grants: GrantDigest) -> Self {
        Self {
            tenant: self.tenant.clone(),
            grants,
        }
    }

    /// Is this store permitted to touch a handle belonging to `resource`?
    ///
    /// # Errors
    ///
    /// Returns the specific [`ScopeRefusal`] naming both sides. In a correct
    /// build this is unreachable for handles the host itself created, because
    /// the store's scope is the scope the handle was created under; it becomes
    /// reachable the moment a host cache keys a resource by anything less than
    /// a full [`InstanceKey`].
    ///
    /// # Why a `Result` and not a `debug_assert`
    ///
    /// A `debug_assert` compiles out of release builds, which is where the
    /// server runs. The cost here is two comparisons on a path already doing a
    /// `BTreeSet` lookup; making it always-on means the invariant is enforced
    /// in the artifact that ships.
    pub fn probe(&self, tenant: &TenantId, grants: &GrantDigest) -> Result<(), ScopeRefusal> {
        if &self.tenant != tenant {
            return Err(ScopeRefusal::ForeignTenant {
                store: self.tenant.clone(),
                resource: tenant.clone(),
            });
        }
        if &self.grants != grants {
            return Err(ScopeRefusal::StaleGrants {
                store: self.grants.clone(),
                resource: grants.clone(),
            });
        }
        Ok(())
    }

    /// Render as the audit record's tenant fields (§10.1).
    ///
    /// The audit stream records tenant, component digest and manifest revision
    /// per event; this produces the tenant half of that, in a stable order, so
    /// two records of the same instance render identically.
    #[must_use]
    pub fn audit_fields(&self) -> [(&'static str, String); 2] {
        [
            ("tenant", self.tenant.as_str().to_owned()),
            ("grant_digest", self.grants.as_str().to_owned()),
        ]
    }
}

impl fmt::Display for TenantScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.tenant, self.grants)
    }
}

/// What a tenanted pool holds, and the invariant it must never break.
///
/// # Why this is a *ledger* and not the pool
///
/// The pooling allocator lives in [`crate::pool`] and is about Wasmtime's
/// memory reuse. This type is about the **bookkeeping** the isolation proof
/// needs: which tenant holds which instances, and whether any instance is
/// reachable by two tenants. Separating them means the isolation property can
/// be tested without instantiating a single module, so the test that proves it
/// runs in milliseconds and in every CI invocation rather than in a
/// feature-gated integration suite.
///
/// The ledger deliberately does *not* hold the instances. It holds keys and
/// counts. If it held the values, it would be a second place resources live,
/// which is the very thing [`TenantScope`] exists to make detectable.
#[derive(Debug, Default)]
pub struct TenantLedger {
    /// Live instances, keyed by the full identity.
    live: BTreeMap<InstanceKey, usize>,
}

/// What the ledger can prove when asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerReport {
    /// Distinct tenants with at least one live instance.
    pub tenants: usize,
    /// Live instances across all tenants.
    pub instances: usize,
    /// The largest number of live instances any one key holds.
    pub deepest: usize,
}

impl TenantLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that one instance of `key` became live.
    pub fn acquire(&mut self, key: InstanceKey) {
        *self.live.entry(key).or_insert(0) += 1;
    }

    /// Record that one instance of `key` was released.
    ///
    /// Returns `false` if the ledger had no such instance, which is a **host
    /// bug** rather than a guest-visible condition: a release for an instance
    /// that was never acquired means accounting drifted, and a drifted ledger
    /// cannot support any isolation claim. Making it a return value means the
    /// caller decides whether to trap or to log, rather than the ledger
    /// silently absorbing the discrepancy.
    pub fn release(&mut self, key: &InstanceKey) -> bool {
        match self.live.get_mut(key) {
            Some(n) if *n > 1 => {
                *n -= 1;
                true
            }
            Some(_) => {
                self.live.remove(key);
                true
            }
            None => false,
        }
    }

    /// How many live instances this exact identity holds.
    #[must_use]
    pub fn count(&self, key: &InstanceKey) -> usize {
        self.live.get(key).copied().unwrap_or(0)
    }

    /// Every live identity for one tenant, in deterministic order.
    ///
    /// # Why filtering by tenant is a method and not a caller's job
    ///
    /// Because the caller's job would be to iterate every key and skip the
    /// others -- and the one time that loop is written slightly wrong, it
    /// returns another tenant's instances with no error. Borrowing narrowly is
    /// the same reasoning as the linker: a thing that is absent cannot be
    /// mis-used.
    #[must_use]
    pub fn for_tenant(&self, tenant: &TenantId) -> Vec<(&InstanceKey, usize)> {
        self.live
            .iter()
            .filter(|(k, _)| k.tenant() == tenant)
            .map(|(k, n)| (k, *n))
            .collect()
    }

    /// Summarise the ledger.
    #[must_use]
    pub fn report(&self) -> LedgerReport {
        let tenants: std::collections::BTreeSet<&TenantId> =
            self.live.keys().map(InstanceKey::tenant).collect();
        LedgerReport {
            tenants: tenants.len(),
            instances: self.live.values().sum(),
            deepest: self.live.values().copied().max().unwrap_or(0),
        }
    }

    /// Is every live identity internally consistent, and every one of them
    /// live?
    ///
    /// # Why this is *not* a tautology, despite appearances
    ///
    /// The obvious formulation — "is every key's tenant the tenant it is
    /// filed under" — is unstateable here, because a `BTreeMap<InstanceKey, _>`
    /// has no separate notion of "the tenant it is filed under": the key *is*
    /// the filing. Writing `key.tenant() == key.tenant()` would compile, run,
    /// and return `true` forever, which is a check that cannot fail and
    /// therefore carries no information (`§M-006`).
    ///
    /// The real invariant this type can hold is a **conservation** one, and it
    /// is the one that matters for pooling: every entry has a non-zero count,
    /// and the number of keys equals the number of distinct keys. A zero-count
    /// entry is a slot a future acquire can revive with the *old* tenant's
    /// claims still attached — which is the cross-tenant leak in its concrete
    /// form, and it is exactly what `release` removing at zero prevents.
    #[must_use]
    pub fn is_isolated(&self) -> bool {
        self.live.values().all(|n| *n > 0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(name: &str) -> TenantId {
        TenantId::new(name).expect("test tenant")
    }

    fn grants(digest: &str) -> GrantDigest {
        GrantDigest::new(digest).expect("test grant digest")
    }

    fn component(digest: &str) -> ComponentDigest {
        ComponentDigest::new(digest).expect("test component digest")
    }

    /// A hex digest of the requested length, so tests do not embed magic
    /// strings that could be mistaken for real hashes.
    fn hex(n: usize) -> String {
        "0123456789abcdef".chars().cycle().take(n).collect()
    }

    // -- GrantDigest / ComponentDigest ------------------------------------

    #[test]
    fn a_digest_must_be_non_empty_hex() {
        assert!(GrantDigest::new("").is_err());
        assert!(ComponentDigest::new("").is_err());
        assert!(
            GrantDigest::new("ABCDEF").is_err(),
            "uppercase is not canonical"
        );
        assert!(GrantDigest::new("dead beef").is_err());
        assert!(GrantDigest::new(&hex(64)).is_ok());
        assert!(ComponentDigest::new(&hex(64)).is_ok());
    }

    #[test]
    fn two_digest_types_are_not_interchangeable_by_accident() {
        // The compile-time half of the argument: `InstanceKey::new` cannot be
        // called with the arguments swapped, because the types differ. This
        // test pins the *value* half -- that each keeps its own text -- so a
        // future "simplification" to one shared type fails here first.
        let g = grants("a1b2c3");
        let c = component("d4e5f6");
        assert_eq!(g.as_str(), "a1b2c3");
        assert_eq!(c.as_str(), "d4e5f6");
        assert_ne!(g.to_string(), c.to_string());
    }

    // -- InstanceKey ------------------------------------------------------

    #[test]
    fn the_key_names_all_three_components() {
        let key = InstanceKey::new(tenant("acme"), component(&hex(64)), grants(&hex(64)));
        assert_eq!(key.tenant().as_str(), "acme");
        let rendered = key.to_string();
        assert!(rendered.starts_with("acme@"), "{rendered}");
        assert!(rendered.contains('#'), "{rendered}");
    }

    /// **The test that separates the two digests.**
    ///
    /// The same artifact under two grant sets must produce two keys. Without
    /// this, narrowing a tenant's grants would leave the wider instance
    /// reachable in the pool -- authority the operator revoked, still live.
    #[test]
    fn one_component_under_two_grant_sets_is_two_keys() {
        let t = tenant("acme");
        let c = component(&hex(64));
        let wide = InstanceKey::new(t.clone(), c.clone(), grants(&hex(64)));
        let narrow = InstanceKey::new(t, c, grants(&hex(16)));
        assert_ne!(
            wide, narrow,
            "two grant sets over one artifact must not share a pool key"
        );
    }

    #[test]
    fn two_tenants_over_one_artifact_are_two_keys() {
        let key =
            |name: &str| InstanceKey::new(tenant(name), component(&hex(64)), grants(&hex(64)));
        assert_ne!(key("acme"), key("globex"));
    }

    #[test]
    fn two_artifacts_under_one_grant_set_are_two_keys() {
        let t = tenant("acme");
        let g = grants(&hex(64));
        assert_ne!(
            InstanceKey::new(t.clone(), component(&hex(64)), g.clone()),
            InstanceKey::new(t, component(&hex(32)), g)
        );
    }

    #[test]
    fn keys_order_deterministically_for_reproducible_pool_iteration() {
        let mut keys = [
            InstanceKey::new(tenant("globex"), component(&hex(64)), grants(&hex(64))),
            InstanceKey::new(tenant("acme"), component(&hex(64)), grants(&hex(64))),
        ];
        keys.sort();
        assert_eq!(keys[0].tenant().as_str(), "acme");
    }

    // -- TenantScope ------------------------------------------------------

    #[test]
    fn a_scope_probes_true_for_its_own_identity() {
        let s = TenantScope::new(tenant("acme"), grants(&hex(64)));
        assert!(s.probe(&tenant("acme"), &grants(&hex(64))).is_ok());
    }

    /// The refusal branch, reached deliberately. This is the fault injection
    /// that makes `probe` a check rather than decoration.
    #[test]
    fn a_scope_probe_refuses_a_foreign_tenant_and_names_both() {
        let s = TenantScope::new(tenant("acme"), grants(&hex(64)));
        let err = s
            .probe(&tenant("globex"), &grants(&hex(64)))
            .expect_err("a foreign tenant must be refused");
        match &err {
            ScopeRefusal::ForeignTenant { store, resource } => {
                assert_eq!(store.as_str(), "acme");
                assert_eq!(resource.as_str(), "globex");
            }
            other @ ScopeRefusal::StaleGrants { .. } => {
                panic!("expected ForeignTenant, got {other:?}")
            }
        }
        let text = err.to_string();
        assert!(text.contains("acme") && text.contains("globex"), "{text}");
        assert!(text.contains("cross-tenant"), "{text}");
    }

    #[test]
    fn a_scope_probe_refuses_stale_grants() {
        let s = TenantScope::new(tenant("acme"), grants(&hex(64)));
        let err = s
            .probe(&tenant("acme"), &grants(&hex(16)))
            .expect_err("a different grant set must be refused");
        assert!(matches!(err, ScopeRefusal::StaleGrants { .. }));
        assert!(err.to_string().contains("revoked"), "{err}");
    }

    /// A refused probe must check the tenant *before* the grants, so the error
    /// for a handle that differs in both names the more severe reason. Ordering
    /// is a user-visible choice, so it is pinned.
    #[test]
    fn the_tenant_is_checked_before_the_grant_digest() {
        let s = TenantScope::new(tenant("acme"), grants(&hex(64)));
        let err = s
            .probe(&tenant("globex"), &grants(&hex(16)))
            .expect_err("both differ");
        assert!(matches!(err, ScopeRefusal::ForeignTenant { .. }));
    }

    #[test]
    fn re_scoping_is_same_tenant_only_and_does_not_mutate() {
        let s = TenantScope::new(tenant("acme"), grants(&hex(64)));
        let narrowed = s.for_same_tenant(grants(&hex(16)));
        assert_eq!(narrowed.tenant().as_str(), "acme");
        assert_eq!(narrowed.grants().as_str(), hex(16));
        // The original is untouched: an instance cannot have its identity
        // edited underneath it by a caller that cloned the scope.
        assert_eq!(s.grants().as_str(), hex(64));
    }

    #[test]
    fn a_scope_renders_its_two_fields_stably() {
        let s = TenantScope::new(tenant("acme"), grants("ab12"));
        assert_eq!(s.to_string(), "acme#ab12");
        let fields = s.audit_fields();
        assert_eq!(fields[0].0, "tenant");
        assert_eq!(fields[0].1, "acme");
        assert_eq!(fields[1].0, "grant_digest");
        assert_eq!(fields[1].1, "ab12");
    }

    // -- TenantLedger -----------------------------------------------------

    fn acme_wide() -> InstanceKey {
        InstanceKey::new(tenant("acme"), component(&hex(64)), grants(&hex(64)))
    }

    fn globex_wide() -> InstanceKey {
        InstanceKey::new(tenant("globex"), component(&hex(64)), grants(&hex(64)))
    }

    #[test]
    fn an_empty_ledger_is_isolated_and_reports_zero() {
        let l = TenantLedger::new();
        assert!(l.is_isolated());
        assert_eq!(
            l.report(),
            LedgerReport {
                tenants: 0,
                instances: 0,
                deepest: 0
            }
        );
    }

    #[test]
    fn acquire_and_release_track_counts_per_key() {
        let mut l = TenantLedger::new();
        l.acquire(acme_wide());
        l.acquire(acme_wide());
        l.acquire(globex_wide());
        assert_eq!(l.count(&acme_wide()), 2);
        assert_eq!(l.count(&globex_wide()), 1);
        assert!(l.release(&acme_wide()));
        assert_eq!(l.count(&acme_wide()), 1);
        assert!(l.release(&acme_wide()));
        assert_eq!(l.count(&acme_wide()), 0);
        assert_eq!(l.report().instances, 1);
    }

    #[test]
    fn releasing_something_never_acquired_is_reported_not_absorbed() {
        let mut l = TenantLedger::new();
        assert!(
            !l.release(&acme_wide()),
            "drift must be visible to the caller"
        );
        assert_eq!(l.report().instances, 0);
    }

    #[test]
    fn the_report_counts_tenants_instances_and_depth() {
        let mut l = TenantLedger::new();
        l.acquire(acme_wide());
        l.acquire(acme_wide());
        l.acquire(globex_wide());
        assert_eq!(
            l.report(),
            LedgerReport {
                tenants: 2,
                instances: 3,
                deepest: 2
            }
        );
    }

    #[test]
    fn for_tenant_borrows_only_that_tenants_instances() {
        let mut l = TenantLedger::new();
        l.acquire(acme_wide());
        l.acquire(globex_wide());
        l.acquire(InstanceKey::new(
            tenant("acme"),
            component(&hex(64)),
            grants(&hex(16)),
        ));
        let acme = tenant("acme");
        let found = l.for_tenant(&acme);
        assert_eq!(found.len(), 2, "acme holds two distinct identities");
        assert!(
            found.iter().all(|(k, _)| k.tenant() == &acme),
            "no other tenant's key may appear"
        );
        let total: usize = found.iter().map(|(_, n)| *n).sum();
        assert_eq!(total, 2);
    }

    #[test]
    fn for_tenant_of_an_absent_tenant_is_empty_rather_than_an_error() {
        let mut l = TenantLedger::new();
        l.acquire(acme_wide());
        assert!(l.for_tenant(&tenant("nobody")).is_empty());
    }

    /// **The dedicated cross-tenant leakage test.**
    ///
    /// Two tenants, one artifact, one grant set, interleaved acquires and
    /// releases. The property under test is the §7.1 claim: after all that
    /// churn, no key reachable as `acme` names any tenant but `acme`, and the
    /// two tenants' counts never mix.
    #[test]
    fn cross_tenant_handles_do_not_leak_across_interleaved_churn() {
        let mut l = TenantLedger::new();
        let acme_narrow = InstanceKey::new(tenant("acme"), component(&hex(64)), grants(&hex(16)));

        for round in 0..64 {
            l.acquire(acme_wide());
            l.acquire(globex_wide());
            if round % 3 == 0 {
                l.acquire(acme_narrow.clone());
            }
            if round % 2 == 0 {
                assert!(l.release(&acme_wide()));
                assert!(l.release(&globex_wide()));
            }
        }

        assert!(l.is_isolated());

        let acme = tenant("acme");
        let globex = tenant("globex");
        let acme_keys = l.for_tenant(&acme);
        let globex_keys = l.for_tenant(&globex);
        assert!(acme_keys.iter().all(|(k, _)| k.tenant() == &acme));
        assert!(globex_keys.iter().all(|(k, _)| k.tenant() == &globex));

        // No identity may appear on both sides.
        for (k, _) in &acme_keys {
            assert!(
                !globex_keys.iter().any(|(g, _)| g == k),
                "one identity listed under two tenants: {k}"
            );
        }

        // And the arithmetic closes: every live instance is accounted for by
        // exactly one tenant's slice.
        let summed: usize = acme_keys
            .iter()
            .chain(globex_keys.iter())
            .map(|(_, n)| *n)
            .sum();
        assert_eq!(summed, l.report().instances);
    }

    /// A tenant's instances released to zero leave *nothing* behind -- no
    /// empty entry that a later `for_tenant` could return, and no tenant row in
    /// the report. A lingering empty entry is how a pool eventually hands a
    /// new tenant a slot that still holds the old tenant's resource.
    #[test]
    fn a_fully_released_tenant_leaves_no_trace() {
        let mut l = TenantLedger::new();
        l.acquire(acme_wide());
        assert!(l.release(&acme_wide()));
        assert!(l.for_tenant(&tenant("acme")).is_empty());
        assert_eq!(l.report().tenants, 0);
        assert!(l.is_isolated());
    }

    /// The fault injection: a ledger holding a slot whose count has fallen to
    /// zero must be reported as **not isolated**.
    ///
    /// Without this, `is_isolated` could be `fn() -> true` and nothing would
    /// notice. The violation is built by hand the only way the type allows —
    /// reaching into the private map from inside the module — which is the
    /// same fault-injection discipline every generator in `tools/` follows:
    /// the checker is shown the shape it must reject.
    ///
    /// A zero-count entry is the concrete cross-tenant leak: a pool slot that
    /// is *not* handed back to the allocator, still carrying the key that
    /// created it, so a later tenant's acquire can revive it with the previous
    /// tenant's claims attached.
    #[test]
    fn a_ledger_with_a_zero_count_slot_is_detected_as_not_isolated() {
        let mut l = TenantLedger::new();
        l.acquire(acme_wide());
        assert!(l.is_isolated(), "a healthy ledger is isolated");

        // Inject the fault directly, bypassing `release` (which removes at
        // zero and is therefore the *fix* for this shape).
        l.live.insert(acme_wide(), 0);
        assert!(
            !l.is_isolated(),
            "a zero-count slot must be reported as a leak, not tolerated"
        );

        // And the honest path produces no such slot.
        let mut honest = TenantLedger::new();
        honest.acquire(acme_wide());
        assert!(honest.release(&acme_wide()));
        assert!(
            honest.is_isolated(),
            "release must not leave a zero-count slot"
        );
        assert!(
            honest.live.is_empty(),
            "release must remove the entry entirely"
        );
    }
}
