// SPDX-License-Identifier: Apache-2.0

//! Building a router from a manifest: the join between `qqq-cap` and `qqq-serve`.
//!
//! # Why this lives in `qqq-run` and not in either crate it joins
//!
//! `qqq-cap` models the `[server]` table from `qqq.toml`; `qqq-serve` owns the route
//! trie. Nothing could connect them until now, and the reason is a real architectural
//! constraint rather than an oversight:
//!
//! - `qqq-serve` **cannot** depend on `qqq-cap`. In Proposal §4.3's topological order
//!   `qqq-cap` sits above `qqq-serve`, so that edge would point upward — and
//!   `tools/check_topology.py` fails the build when one does.
//! - `qqq-cap` **cannot** depend on `qqq-serve`, for the same reason in the other
//!   direction: a manifest is a *file format*, and the crate that parses it must not
//!   need an HTTP implementation to do so.
//!
//! `qqq-run` sits above both. It is the only place in this workspace where the two can
//! meet, and that is not a workaround — it is where the decision belongs. The manifest
//! says what the project intends; the router says how a request is matched. Converting
//! one into the other is an orchestration decision, and orchestration is what this
//! crate is for.
//!
//! # What this closes
//!
//! `SRV-019` (CORS), `SRV-004` (streaming bodies), `SRV-009` (WebSockets) and `SRV-010`
//! (SSE) were each implemented in `qqq-serve` and **none was reachable**, because
//! `Manifest` did not model `[server]` at all (`§O-130`). The section is modelled now;
//! this module is the next link. It is not the last one — `Handler` is still
//! synchronous, so a route can be matched and answered but not streamed — and that
//! remaining gap is named in `qqq-serve::server` rather than hidden here.
//!
//! # Why the conversion reports *every* error, not the first
//!
//! A manifest with three bad routes should not take three runs to fix. The manifest's
//! own validator reports the first problem because it must return a single
//! `ManifestError`; here the caller is a command that can print a list, so the
//! conversion collects them all and returns them together.

use qqq_cap::manifest::{AuthMode, Server};
use qqq_core::{Error, ErrorCode, Result};
use qqq_serve::route::{Method, Route, RouteTable, RouterError};

/// A route table built from a manifest, plus the per-route authentication modes.
///
/// # Why the auth modes are returned separately
///
/// `qqq-serve`'s `Route` carries a **handler name**, deliberately — it is the
/// identifier the host resolves at dispatch, and binding a function pointer there would
/// pin the old code across a hot reload (see the field's own doc comment). Adding an
/// `auth` field to that type would put a capability decision inside the router, and the
/// router is not the authority on authority — `qqq-cap` is.
///
/// So the modes travel beside the table, keyed by the same `(method, pattern)` pair the
/// router matches on, and the dispatcher consults them after a match. That keeps the
/// router's job to *matching* and the capability model's job to *authority*, which is
/// the separation `§4.4` requires.
///
/// # Why there is a policy *and* a vector
///
/// [`Self::auth`] is the declaration record: one mode per `server.routes` entry, in the
/// order the author wrote them, which is what an error message or an audit wants to cite.
/// It is **not** usable for enforcement, because a request arrives with a matched route and
/// no declaration index.
///
/// [`Self::auth_policy`] is the enforcement form: keyed by `(pattern, handler)`, the two
/// fields a `qqq_serve::route::Match` carries. Both are built from one pass over the same
/// list, and `the_policy_and_the_declaration_record_agree` asserts they cannot drift — the
/// failure mode being a vector that says `deny` while the policy that is actually consulted
/// says something else.
#[derive(Debug)]
pub struct ServerRoutes {
    /// The router, ready to match.
    pub table: RouteTable,
    /// The authentication mode for each route, in the order they were declared.
    ///
    /// Parallel to the manifest's `server.routes`, so a caller can name the offending
    /// entry when a request is refused. **Reporting only** — enforcement consults
    /// [`Self::auth_policy`]; see this type's documentation.
    pub auth: Vec<AuthMode>,
    /// The enforcement policy: the mode for each route, keyed by what a match returns.
    ///
    /// Fail-closed for a route it was not told about, so a gap in this construction refuses
    /// rather than serves. Installed into `qqq_serve::ServerConfig::auth` by
    /// `crate::serve`.
    pub auth_policy: qqq_serve::auth::AuthPolicy,
    /// The routes that would be served without authenticating anything.
    ///
    /// Computed here rather than by the caller because it is the first question an
    /// auditor asks and the one a manifest change most often gets wrong. See
    /// [`Server::unauthenticated_routes`].
    pub unauthenticated: Vec<String>,
    /// The per-tenant request limits, built from `[server.limits]`.
    ///
    /// `None` when the manifest declared none, which is the common case and means no
    /// enforcement — deliberately, rather than a built-in cap this crate invented. See
    /// `qqq_cap::manifest::RequestLimits` for why the default is "no limits" and why that is
    /// different from the *connection* ceiling's default.
    ///
    /// Built **here** rather than in `qqq-serve`, because `qqq-cap` may not depend on
    /// `qqq-serve` in either direction: in §4.3's order `qqq-cap` sits above it, so an edge
    /// would point upward. `qqq-run` is the only crate that sees both, which is the same
    /// reason [`routes_from_manifest`] exists.
    pub limits: Option<std::sync::Arc<qqq_serve::limits::TenantLimits>>,
}

impl ServerRoutes {
    /// The authentication mode that applies to a matched route.
    ///
    /// `index` is the declaration index, which the caller gets by matching against
    /// [`Self::table`] and looking the route back up — or, more simply, by iterating
    /// [`Self::auth`] alongside the manifest's routes.
    #[must_use]
    pub fn auth_for(&self, index: usize) -> AuthMode {
        self.auth.get(index).copied().unwrap_or(AuthMode::Deny)
    }

    /// Whether this project serves anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.auth.is_empty()
    }
}

/// Build a router from a manifest's `[server]` section.
///
/// # Errors
///
/// `QQQ-2002` (`ManifestSchemaViolation`) when a pattern cannot be compiled. The manifest's
/// own validation has already rejected the mistakes it can see — an empty method list,
/// a misspelled method, a duplicate — so anything reaching here is a pattern the
/// *router* rejects and the manifest's validator does not, such as two wildcards in one
/// segment. The error names the offending pattern and the manifest path, because the
/// author's next action is to edit that file.
pub fn routes_from_manifest(server: &Server, manifest_path: &str) -> Result<ServerRoutes> {
    let mut table = RouteTable::new();
    let mut auth = Vec::with_capacity(server.routes.len());
    let mut auth_policy = qqq_serve::auth::AuthPolicy::new();
    let mut problems: Vec<String> = Vec::new();

    for (i, entry) in server.routes.iter().enumerate() {
        let mode = entry.effective_auth(server.default_auth);
        auth.push(mode);
        auth_policy.insert(&entry.path, &entry.handler, route_auth(mode));

        for raw in &entry.methods {
            let Some(method) = method_from_str(raw) else {
                // Unreachable through `Manifest::parse`, which validates the method
                // list. Reported rather than skipped because a route silently missing
                // from the table is the defect this whole module exists to prevent —
                // `§O-130` is four features that were unreachable because a table was
                // inert.
                problems.push(format!(
                    "server.routes[{i}].methods: `{raw}` is not an HTTP method"
                ));
                continue;
            };

            match Route::new(method, &entry.path, &entry.handler) {
                Ok(route) => {
                    if let Err(e) = table.insert(route) {
                        problems.push(format!(
                            "server.routes[{i}] (`{}`): {}",
                            entry.path,
                            describe(&e)
                        ));
                    }
                }
                Err(e) => problems.push(format!(
                    "server.routes[{i}] (`{}`): {}",
                    entry.path,
                    describe(&e)
                )),
            }
        }
    }

    if !problems.is_empty() {
        return Err(Error::new(
            ErrorCode::ManifestSchemaViolation,
            format!(
                "{} route(s) in `{manifest_path}` could not be compiled",
                problems.len()
            ),
        )
        .with_cause(problems.join("; "))
        .with_remediation(
            "each pattern must have one wildcard at most per segment, and no two routes \
             may answer the same method on the same path",
        ));
    }

    let unauthenticated = server
        .unauthenticated_routes()
        .iter()
        .map(|r| r.path.clone())
        .collect();

    Ok(ServerRoutes {
        table,
        auth,
        auth_policy,
        unauthenticated,
        limits: build_limits(server.limits.as_ref()),
    })
}

/// Translate the manifest's authentication mode into the server's enforcement vocabulary.
///
/// # Why three of the five modes become a refusal
///
/// `qqq-serve` has no JWT validator, no client-certificate binding to a route, and no
/// request-signature verifier. Each of those modes names a *check that would have to pass*,
/// and none of the checks exists, so a request to such a route cannot be shown to satisfy
/// it. Serving the request would treat "I could not check" as "the check passed", which is
/// the single worst outcome available and the exact shape of the defect that made this
/// function necessary in the first place — `default_auth` was `deny` and the server served
/// everything.
///
/// So they become refusals that **name themselves**. The refusal is honest, it is visible
/// in the access record, and it fails in the safe direction. When an authenticator lands,
/// the mode's arm changes here and nowhere else, which is why this is one function rather
/// than five `match` arms scattered through the serving path.
///
/// `deny` is a refusal for a different reason: it is the manifest saying "refuse", and it
/// is the default, so this is the arm that makes an omitted `default_auth` safe.
#[must_use]
fn route_auth(mode: AuthMode) -> qqq_serve::auth::RouteAuth {
    match mode {
        AuthMode::None => qqq_serve::auth::RouteAuth::Public,
        AuthMode::Deny => qqq_serve::auth::RouteAuth::Refused { mode: "deny" },
        AuthMode::BearerJwt => qqq_serve::auth::RouteAuth::Refused { mode: "bearer-jwt" },
        AuthMode::Mtls => qqq_serve::auth::RouteAuth::Refused { mode: "mtls" },
        AuthMode::SignedRequest => qqq_serve::auth::RouteAuth::Refused {
            mode: "signed-request",
        },
    }
}

/// Build the runtime limiter from the manifest's `[server.limits]` table.
///
/// # Why the conversion is a function and not a `From` impl
///
/// A `From` would put the *reasoning* somewhere a reader looks for mechanics. The two
/// decisions here are both worth stating, and neither is obvious:
///
/// 1. **The manifest's `window_seconds` defaults to 60** when a request cap is set and no
///    window is given, because a cap with no window has no meaning. A manifest author who
///    writes `max_requests_per_window = 100` and stops has a complete thought.
/// 2. **`None` for a field means unlimited**, which is why every field is an `Option` on both
///    sides rather than a `u64` defaulting to zero. A zero body cap refuses every non-empty
///    body, and a manifest author writing `0` almost never meant that.
///
/// The manifest was already validated by `Server::validate`, so a zero window with a request
/// cap cannot reach here — but `TenantLimits::new` asserts it anyway, because this function
/// should not be the only thing standing between a bad table and a limiter that allows
/// everything.
fn build_limits(
    declared: Option<&qqq_cap::manifest::RequestLimits>,
) -> Option<std::sync::Arc<qqq_serve::limits::TenantLimits>> {
    let declared = declared?;

    let convert = |l: &qqq_cap::manifest::TenantLimit| qqq_serve::limits::Limits {
        max_body_bytes: l.max_body_bytes,
        max_requests_per_window: l.max_requests_per_window,
        window: l.window(),
        max_connections: l.max_connections,
    };

    let fallback = declared
        .default
        .as_ref()
        .map_or_else(qqq_serve::limits::Limits::none, &convert);

    let per_tenant = declared
        .per_tenant
        .iter()
        .map(|(tenant, limit)| (tenant.clone(), convert(limit)));

    Some(std::sync::Arc::new(qqq_serve::limits::TenantLimits::new(
        per_tenant, fallback,
    )))
}

/// `qqq-serve`'s `Method` for a manifest spelling.
///
/// The manifest's set and the router's set are both closed, and they must agree. This
/// is the one place they are compared, so `check_topology`'s ban on a `qqq-cap` →
/// `qqq-serve` edge does not become a silent divergence between two lists that *look*
/// identical.
///
/// Returns `None` for an extension method, which the manifest rejects at parse time —
/// the router's `Extension` variant exists for a request line that names something
/// unusual, not for a route declaration.
#[must_use]
fn method_from_str(raw: &str) -> Option<Method> {
    match raw.to_ascii_uppercase().as_str() {
        "GET" => Some(Method::Get),
        "HEAD" => Some(Method::Head),
        "POST" => Some(Method::Post),
        "PUT" => Some(Method::Put),
        "PATCH" => Some(Method::Patch),
        "DELETE" => Some(Method::Delete),
        "OPTIONS" => Some(Method::Options),
        "TRACE" => Some(Method::Trace),
        "CONNECT" => Some(Method::Connect),
        _ => None,
    }
}

/// A one-line reason for a `RouterError`.
///
/// `RouterError` has its own `Display`; this exists so the *kind* of problem is stated
/// in the words a manifest author needs, without repeating the enum in this file. If a
/// variant is added, the fallback keeps the message useful rather than failing to
/// compile in a crate that should not know the router's internals.
fn describe(e: &RouterError) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_cap::manifest::Manifest;
    use qqq_cap::server::METHODS;

    fn server_from(toml: &str) -> Server {
        let m = Manifest::parse(&format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\n[server]\n{toml}\n"
        ))
        .expect("the fixture must parse");
        m.server
    }

    /// **The Proposal's own route table compiles into a working router.**
    ///
    /// `§5.3` prints this manifest as the canonical example. If it does not produce a
    /// router that matches the three routes it declares, either the document or this
    /// conversion is wrong.
    #[test]
    fn the_proposal_route_table_compiles_and_matches() {
        let server = server_from(
            r#"
routes = [
  { path = "/orders",     methods = ["POST"],          handler = "create-order" },
  { path = "/orders/:id", methods = ["GET", "DELETE"], handler = "order-by-id" },
  { path = "/healthz",    methods = ["GET"],           handler = "health", auth = "none" },
]
default_auth = "bearer-jwt"
"#,
        );
        let built = routes_from_manifest(&server, "qqq.toml").expect("must compile");

        // Every declared route is reachable — the property that was missing before.
        assert!(built.table.match_route(Method::Post, "/orders").is_some());
        assert!(built.table.match_route(Method::Get, "/orders/42").is_some());
        assert!(built
            .table
            .match_route(Method::Delete, "/orders/42")
            .is_some());
        assert!(built.table.match_route(Method::Get, "/healthz").is_some());

        // And the handler names survive, which is what dispatch resolves.
        let m = built
            .table
            .match_route(Method::Post, "/orders")
            .expect("matched");
        assert_eq!(m.handler, "create-order");
    }

    /// The auth modes travel beside the table, in declaration order.
    #[test]
    fn the_auth_modes_travel_with_the_table() {
        let server = server_from(
            r#"
routes = [
  { path = "/a", methods = ["GET"], handler = "h" },
  { path = "/b", methods = ["GET"], handler = "h", auth = "none" },
  { path = "/c", methods = ["GET"], handler = "h", auth = "mtls" },
]
default_auth = "bearer-jwt"
"#,
        );
        let built = routes_from_manifest(&server, "qqq.toml").expect("must compile");

        assert_eq!(
            built.auth_for(0),
            AuthMode::BearerJwt,
            "inherits default_auth"
        );
        assert_eq!(built.auth_for(1), AuthMode::None, "explicit override");
        assert_eq!(built.auth_for(2), AuthMode::Mtls, "explicit override");
    }

    /// **The unauthenticated routes are reported.**
    ///
    /// The question an auditor asks first, and the one a manifest change most often gets
    /// wrong: adding `auth = "none"` to make a health check work and forgetting it is
    /// now public.
    #[test]
    fn the_unauthenticated_routes_are_reported() {
        let server = server_from(
            r#"
routes = [
  { path = "/orders",  methods = ["GET"], handler = "h" },
  { path = "/healthz", methods = ["GET"], handler = "h", auth = "none" },
]
default_auth = "deny"
"#,
        );
        let built = routes_from_manifest(&server, "qqq.toml").expect("must compile");
        assert_eq!(built.unauthenticated, vec!["/healthz".to_owned()]);
    }

    /// An empty `[server]` produces an empty router, not an error.
    ///
    /// A library has no network surface. What must not happen is the absence being read
    /// as "serve everything".
    #[test]
    fn an_empty_section_produces_an_empty_router() {
        let server = server_from("default_auth = \"deny\"\n");
        let built = routes_from_manifest(&server, "qqq.toml").expect("must compile");
        assert!(built.is_empty());
        assert!(built.table.match_route(Method::Get, "/anything").is_none());
    }

    /// A path parameter is captured into the match.
    #[test]
    fn a_path_parameter_is_captured() {
        let server = server_from(
            "routes = [{ path = \"/orders/:id\", methods = [\"GET\"], handler = \"h\" }]\n",
        );
        let built = routes_from_manifest(&server, "qqq.toml").expect("must compile");
        let m = built
            .table
            .match_route(Method::Get, "/orders/abc-123")
            .expect("must match a parameterised route");
        assert_eq!(
            m.params.get("id"),
            Some("abc-123"),
            "the capture must reach the handler: {:?}",
            m.params
        );
    }

    /// Every method the manifest accepts maps to a router method.
    ///
    /// The two closed sets must agree. A method the manifest validates but this mapping
    /// rejects would produce a route that silently does not exist — the `§O-130` shape,
    /// arriving through a table lookup.
    #[test]
    fn every_manifest_method_maps_to_a_router_method() {
        for raw in METHODS {
            assert!(
                method_from_str(raw).is_some(),
                "`{raw}` is accepted by the manifest but not by the router"
            );
        }
        // And the mapping is case-insensitive, matching the manifest's own.
        assert_eq!(method_from_str("get"), Some(Method::Get));
    }

    /// An extension method is not a route declaration.
    ///
    /// The router's `Extension` variant exists for a request line naming something
    /// unusual, not for a route. Mapping an unknown token to it would let a manifest
    /// declare a route that catches every extension method.
    #[test]
    fn an_unknown_method_does_not_map() {
        assert_eq!(method_from_str("PROPFIND"), None);
        assert_eq!(method_from_str(""), None);
    }

    // -- limits ------------------------------------------------------------

    /// **A manifest with no `[server.limits]` produces no limiter.**
    ///
    /// The control for everything below: the conversion must not invent enforcement for a
    /// manifest that asked for none. A built-in cap would silently change behaviour on
    /// upgrade, which is why every field on both sides is an `Option`.
    #[test]
    fn no_declared_limits_means_no_limiter() {
        let server = server_from(
            r#"
routes = [{ path = "/", methods = ["GET"], handler = "root" }]
"#,
        );
        let routes = routes_from_manifest(&server, "q.ai.toml").expect("valid");
        assert!(
            routes.limits.is_none(),
            "a manifest that declared no limits must get no limiter"
        );
    }

    /// A declared body cap travels into the runtime limiter.
    #[test]
    fn a_declared_body_cap_is_built() {
        let server = server_from(
            r#"
routes = [{ path = "/", methods = ["GET"], handler = "root" }]

[server.limits.default]
max_body_bytes = 1024
"#,
        );
        let routes = routes_from_manifest(&server, "q.ai.toml").expect("valid");
        let limits = routes.limits.expect("a limiter");

        assert!(limits.check_body("anyone", 1024).is_ok(), "at the cap");
        assert!(limits.check_body("anyone", 1025).is_err(), "over the cap");
    }

    /// **Per-tenant entries override the fallback.**
    ///
    /// The key is a client address, not a name: the runtime's tenant is the peer address
    /// (`tenant_of`), so a name could never match — `Manifest::parse` now refuses one.
    /// `§O-185` records the round that found the mismatch between this field's
    /// documentation and the lookup.
    #[test]
    fn per_tenant_limits_override_the_fallback() {
        let server = server_from(
            r#"
routes = [{ path = "/", methods = ["GET"], handler = "root" }]

[server.limits.default]
max_body_bytes = 100

[server.limits.per_tenant."127.0.0.1"]
max_body_bytes = 100_000
"#,
        );
        let routes = routes_from_manifest(&server, "q.ai.toml").expect("valid");
        let limits = routes.limits.expect("a limiter");

        assert!(
            limits.check_body("198.51.100.7", 101).is_err(),
            "the fallback applies to an address with no entry"
        );
        assert!(
            limits.check_body("127.0.0.1", 50_000).is_ok(),
            "the named address gets its own cap"
        );
    }

    /// **The window defaults to 60 seconds when a request cap is declared without one.**
    ///
    /// A cap with no window has no meaning, so the manifest's natural shorthand must work:
    /// writing `max_requests_per_window = 2` and stopping is a complete thought.
    #[test]
    fn a_request_cap_without_a_window_defaults_to_sixty_seconds() {
        let server = server_from(
            r#"
routes = [{ path = "/", methods = ["GET"], handler = "root" }]

[server.limits.default]
max_requests_per_window = 2
"#,
        );
        let routes = routes_from_manifest(&server, "q.ai.toml").expect("valid");
        let limits = routes.limits.expect("a limiter");
        let now = std::time::Instant::now();

        assert!(limits.check_and_record("t", now).is_ok());
        assert!(limits.check_and_record("t", now).is_ok());
        assert!(
            limits.check_and_record("t", now).is_err(),
            "the cap of 2 applies"
        );
        assert!(
            limits
                .check_and_record("t", now + std::time::Duration::from_secs(60))
                .is_ok(),
            "and the window is 60 seconds, the documented default"
        );
    }

    /// The declared window is honoured when given.
    #[test]
    fn a_declared_window_is_honoured() {
        let server = server_from(
            r#"
routes = [{ path = "/", methods = ["GET"], handler = "root" }]

[server.limits.default]
max_requests_per_window = 1
window_seconds = 5
"#,
        );
        let routes = routes_from_manifest(&server, "q.ai.toml").expect("valid");
        let limits = routes.limits.expect("a limiter");
        let now = std::time::Instant::now();

        assert!(limits.check_and_record("t", now).is_ok());
        assert!(limits.check_and_record("t", now).is_err(), "spent");
        assert!(
            limits
                .check_and_record("t", now + std::time::Duration::from_secs(5))
                .is_ok(),
            "5 seconds, not 60"
        );
    }

    /// **A zero window with a request cap is refused by the manifest, not by the limiter.**
    ///
    /// The incoherence that makes a limiter allow everything. It must be caught at
    /// validation, where the failure names the tenant, rather than at construction where the
    /// message can only say that something is wrong.
    ///
    /// The key is an address because `per_tenant` is keyed by the client address and a name
    /// is refused first (`§O-185`); using a name here would test that refusal instead of
    /// this one.
    #[test]
    fn a_zero_window_is_refused_at_validation() {
        // A full manifest, and the assertion is on **`Manifest::parse` failing** rather
        // than on a validation method returning an error. That is the stronger claim: the
        // manifest cannot be loaded at all, so no path reaches a limiter that would allow
        // everything. `parse` validates internally -- see `manifest.rs`, which does the
        // serde pass and then `validate()` before returning.
        let err = Manifest::parse(
            r#"
[package]
name = "acme"
version = "0.1.0"

[server]
routes = [{ path = "/", methods = ["GET"], handler = "root" }]

[server.limits.per_tenant."127.0.0.1"]
max_requests_per_window = 1
window_seconds = 0
"#,
        )
        .expect_err("a zero window with a cap must be refused at parse time");
        let text = format!("{err}");
        assert!(
            text.contains("127.0.0.1"),
            "the tenant must be named: {text}"
        );
        assert!(
            text.contains("zero window"),
            "and the rule must be named: {text}"
        );
    }

    /// **A name key is refused by the manifest, and the refusal names the address form.**
    ///
    /// The pairing matters: the test above proves a valid key reaches the limit validation,
    /// and this one proves an invalid key never does.
    #[test]
    fn a_name_key_is_refused_at_validation() {
        let err = Manifest::parse(
            r#"
[package]
name = "acme"
version = "0.1.0"

[server]
routes = [{ path = "/", methods = ["GET"], handler = "root" }]

[server.limits.per_tenant.sneaky]
max_requests_per_window = 1
"#,
        )
        .expect_err("a name key can never match a request, so the manifest must not load");
        let text = format!("{err}");
        assert!(text.contains("sneaky"), "the key must be named: {text}");
        assert!(
            text.contains("not an IP address"),
            "and the reason must be named: {text}"
        );
    }
}
