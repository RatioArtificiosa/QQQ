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
#[derive(Debug)]
pub struct ServerRoutes {
    /// The router, ready to match.
    pub table: RouteTable,
    /// The authentication mode for each route, in the order they were declared.
    ///
    /// Parallel to the manifest's `server.routes`, so a caller can name the offending
    /// entry when a request is refused.
    pub auth: Vec<AuthMode>,
    /// The routes that would be served without authenticating anything.
    ///
    /// Computed here rather than by the caller because it is the first question an
    /// auditor asks and the one a manifest change most often gets wrong. See
    /// [`Server::unauthenticated_routes`].
    pub unauthenticated: Vec<String>,
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
    let mut problems: Vec<String> = Vec::new();

    for (i, entry) in server.routes.iter().enumerate() {
        let mode = entry.effective_auth(server.default_auth);
        auth.push(mode);

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
        unauthenticated,
    })
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
}
