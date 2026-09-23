// SPDX-License-Identifier: Apache-2.0

//! Per-route authentication policy: which routes may be served at all.
//!
//! # Why this module exists
//!
//! `qqq.toml` has always been able to say `default_auth = "deny"`, and
//! `qqq-cap::manifest::AuthMode` has always documented `Deny` as *"Refuse every request
//! to this route. The default."* `qqq-run` computed the mode for every declared route
//! (`ServerRoutes::auth`) and then **dropped it on the floor**: nothing in `qqq-serve`
//! had an opinion about authority, so `qqqai serve` served every route on every
//! manifest, including one that had deliberately asked to refuse everything.
//!
//! That is the worst shape a security defect can take here. The manifest is the
//! contract, the contract said *deny*, and the runtime said *allow*. A deployment that
//! read its own configuration and believed it would have been wrong about the most
//! important property it had asked for.
//!
//! # Why the policy lives here and not on `Route`
//!
//! `qqq-cap` is the authority on authority, and in §4.3's order it sits **above**
//! `qqq-serve`, so the router cannot import `AuthMode` — an edge would point upward and
//! `tools/check_topology.py` fails the build. Adding an `auth` field to
//! [`crate::route::Route`] would be the other wrong answer: it would put a capability
//! decision inside the router, whose job is *matching*.
//!
//! So the decisions travel **beside** the table, in this crate's own closed vocabulary,
//! and `qqq-run` — the only crate that can see both — does the translation. The router
//! still only matches; the policy still only decides; the join happens in the crate that
//! is allowed to know about both.
//!
//! # Why every unlisted route refuses
//!
//! A policy that answers "allow" for a route it has no entry for is a policy whose
//! failure mode is *silent permission*. The whole defect this module fixes was a
//! missing entry, so the missing-entry case must be the one that refuses. A route that
//! reaches the policy and is not named in it is a bug in the join, and the safe
//! response to a bug in an authority check is to refuse and say so.

use std::collections::BTreeMap;

use crate::route::Match;

/// What a route's manifest entry asked for.
///
/// A closed two-case vocabulary, deliberately smaller than `qqq-cap`'s five
/// [`AuthMode`]s. Three of those five name an *authenticator* — a bearer JWT, a client
/// certificate, a signed request — and this crate has no implementation of any of them.
/// Modelling them here as cases that could be satisfied would invite a caller to write
/// the check that pretends to satisfy them; modelling them as what they are today
/// (refusals that name themselves) makes the gap visible in the type.
///
/// [`AuthMode`]: https://docs.rs/qqq-cap
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAuth {
    /// Serve the route. The manifest said `auth = "none"`, explicitly.
    Public,
    /// Refuse the route, naming the mode that asked for it.
    ///
    /// `mode` is the manifest's spelling (`deny`, `bearer-jwt`, …) so the refusal can
    /// name what the author wrote rather than what this crate calls it.
    Refused {
        /// The manifest's spelling of the mode that refused.
        mode: &'static str,
    },
}

impl RouteAuth {
    /// Whether this route is served.
    #[must_use]
    pub const fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }
}

/// The decision for one matched request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Serve the request.
    Allow,
    /// Refuse the request with `403`, naming the mode.
    Refuse {
        /// The mode that refused, in the manifest's spelling.
        mode: &'static str,
    },
}

impl Decision {
    /// Whether the request may be served.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// The mode named when a matched route has no entry in the policy.
///
/// Not a mode a manifest can write, and that is the point: it means the join between
/// the route table and the policy is wrong, which is a defect in `qqq-run` rather than a
/// decision anyone made.
pub const UNLISTED: &str = "unlisted";

/// The authentication policy for a route table.
///
/// Keyed by `(pattern, handler)`, the two fields a [`Match`] carries, rather than by
/// `(method, pattern)`. The reason is a real one and not a preference: the router serves
/// `HEAD` from a `GET` route (RFC 9110 §9.3.2), so a key that included the request's
/// method would miss every `HEAD` request and fall through to the fail-closed case,
/// refusing a route the manifest had marked public. Keying on what the *match* returns
/// removes the question.
#[derive(Debug, Clone, Default)]
pub struct AuthPolicy {
    routes: BTreeMap<(String, String), RouteAuth>,
    /// Keys that two manifest rows mapped to **different** modes.
    ///
    /// Kept rather than resolved because there is no correct resolution: the same
    /// pattern and handler under two modes is an ambiguity the manifest does not reject
    /// (it rejects duplicate method+path, which is a different question). Refusing both
    /// is the only answer that cannot serve a route the author meant to protect, and
    /// naming the key makes the ambiguity diagnosable instead of mysterious.
    ambiguous: Vec<(String, String)>,
}

impl AuthPolicy {
    /// An empty policy, which refuses everything it is asked about.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the mode for one route.
    ///
    /// A second entry for the same key with a **different** mode marks the key
    /// ambiguous; the same mode twice is idempotent, because two rows that agree are not
    /// a contradiction.
    pub fn insert(&mut self, pattern: &str, handler: &str, auth: RouteAuth) {
        let key = (pattern.to_owned(), handler.to_owned());
        if let Some(existing) = self.routes.get(&key) {
            if *existing != auth && !self.ambiguous.contains(&key) {
                self.ambiguous.push(key.clone());
            }
            return;
        }
        self.routes.insert(key, auth);
    }

    /// How many routes the policy names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the policy names no routes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// The keys two manifest rows disagreed about.
    #[must_use]
    pub fn ambiguous(&self) -> &[(String, String)] {
        &self.ambiguous
    }

    /// Decide one matched request.
    #[must_use]
    pub fn decide(&self, matched: &Match) -> Decision {
        let key = (matched.pattern.clone(), matched.handler.clone());
        if self.ambiguous.contains(&key) {
            return Decision::Refuse {
                mode: "ambiguous-auth",
            };
        }
        match self.routes.get(&key) {
            Some(RouteAuth::Public) => Decision::Allow,
            Some(RouteAuth::Refused { mode }) => Decision::Refuse { mode },
            None => Decision::Refuse { mode: UNLISTED },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::{Method, Route, RouteTable};

    fn matched(pattern: &str, handler: &str) -> Match {
        let mut table = RouteTable::new();
        table
            .insert(Route::new(Method::Get, pattern, handler).expect("valid route"))
            .expect("inserts");
        table
            .match_route(Method::Get, pattern.replace(':', "x").as_str())
            .expect("the route matches its own pattern")
    }

    #[test]
    fn an_empty_policy_refuses_everything() {
        // The fail-closed direction is the one that matters: a policy that has not been
        // told about a route must not serve it.
        let policy = AuthPolicy::new();
        let d = policy.decide(&matched("/orders", "list"));
        assert_eq!(d, Decision::Refuse { mode: UNLISTED });
        assert!(!d.is_allowed());
    }

    #[test]
    fn an_unlisted_route_refuses_even_when_others_are_public() {
        let mut policy = AuthPolicy::new();
        policy.insert("/healthz", "health", RouteAuth::Public);
        assert!(policy.decide(&matched("/healthz", "health")).is_allowed());
        assert_eq!(
            policy.decide(&matched("/orders", "list")),
            Decision::Refuse { mode: UNLISTED },
            "a route the policy was never told about must not be served"
        );
    }

    #[test]
    fn deny_refuses_and_names_the_manifest_spelling() {
        let mut policy = AuthPolicy::new();
        policy.insert("/orders", "list", RouteAuth::Refused { mode: "deny" });
        assert_eq!(
            policy.decide(&matched("/orders", "list")),
            Decision::Refuse { mode: "deny" },
            "the refusal must name what the author wrote, not a synonym"
        );
    }

    #[test]
    fn an_unimplemented_authenticator_refuses_rather_than_serving() {
        // The load-bearing case: `bearer-jwt` means "only authenticated callers". With no
        // JWT validator, serving the request would be the exact failure this module
        // exists to prevent, so it must refuse and say which mode refused.
        let mut policy = AuthPolicy::new();
        policy.insert("/orders", "list", RouteAuth::Refused { mode: "bearer-jwt" });
        assert_eq!(
            policy.decide(&matched("/orders", "list")),
            Decision::Refuse { mode: "bearer-jwt" }
        );
    }

    #[test]
    fn the_same_mode_twice_is_idempotent_and_not_ambiguous() {
        let mut policy = AuthPolicy::new();
        policy.insert("/a", "h", RouteAuth::Public);
        policy.insert("/a", "h", RouteAuth::Public);
        assert!(policy.ambiguous().is_empty());
        assert!(policy.decide(&matched("/a", "h")).is_allowed());
    }

    #[test]
    fn two_rows_that_disagree_refuse_and_are_named() {
        let mut policy = AuthPolicy::new();
        policy.insert("/a", "h", RouteAuth::Public);
        policy.insert("/a", "h", RouteAuth::Refused { mode: "deny" });
        assert_eq!(policy.ambiguous().len(), 1);
        assert_eq!(
            policy.decide(&matched("/a", "h")),
            Decision::Refuse {
                mode: "ambiguous-auth"
            },
            "an ambiguity must refuse both readings, never pick the permissive one"
        );
    }

    #[test]
    fn a_head_request_finds_the_get_route_and_its_decision() {
        // The router serves HEAD from a GET route, so a decision keyed on the request's
        // method would fall through to `unlisted` and refuse a public route.
        let mut table = RouteTable::new();
        table
            .insert(Route::new(Method::Get, "/orders", "list").expect("valid"))
            .expect("inserts");
        let m = table
            .match_route(Method::Head, "/orders")
            .expect("HEAD is served from the GET route");

        let mut policy = AuthPolicy::new();
        policy.insert("/orders", "list", RouteAuth::Public);
        assert!(
            policy.decide(&m).is_allowed(),
            "a HEAD request must inherit the decision of the GET route it was served from"
        );
    }

    #[test]
    fn a_parameterised_pattern_is_keyed_by_the_declared_pattern() {
        // The key must come from the declaration, not the request path: `/orders/:id`
        // and `/orders/7` are the same route, and keying on the request would make every
        // id a new unlisted route.
        let mut policy = AuthPolicy::new();
        policy.insert("/orders/:id", "order-by-id", RouteAuth::Public);
        assert!(policy
            .decide(&matched("/orders/:id", "order-by-id"))
            .is_allowed());
        assert_eq!(policy.len(), 1, "one declaration, one entry");
    }
}
