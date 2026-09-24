// SPDX-License-Identifier: Apache-2.0

//! The `[server]` section of `qqq.toml`: the network surface a project declares.
//!
//! Implements Proposal §5.3's network surface, which until now had **no
//! representation at all**:
//!
//! ```toml
//! [server]
//! routes = [
//!   { path = "/orders",     methods = ["POST"],          handler = "create-order" },
//!   { path = "/orders/:id", methods = ["GET", "DELETE"], handler = "order-by-id" },
//!   { path = "/healthz",    methods = ["GET"],           handler = "health", auth = "none" },
//! ]
//! default_auth = "bearer-jwt"       # none | bearer-jwt | mtls | signed-request
//!
//! [server.cors]
//! allow_origins = ["https://app.example.com"]
//! ```
//!
//! # Why this module exists, and why its absence was a defect rather than a gap
//!
//! Four checklist items — streaming bodies, `WebSockets`, event streams and CORS — were
//! each "complete" in
//! `qqq-serve` and none was reachable, because `Manifest` modelled `[package]`,
//! `[build]`, `[capabilities]`, `[limits]`, `[dependencies]` and `[dev-dependencies]`
//! and **not** `[server]`. A manifest declaring routes parsed successfully and the
//! whole table was inert. That is the same defect the `[dependencies]` field's own doc
//! comment records, one table over:
//!
//! > Before this field existed, a manifest containing `[dependencies]` parsed
//! > **successfully** and the dependencies were silently dropped [...] A dependency
//! > that silently does not exist is worse than one that fails to resolve, because the
//! > first is discovered at runtime by the person least able to explain it.
//!
//! A *route* that silently does not exist is worse in exactly the same way, and more
//! visible: the server starts, accepts connections, and 404s everything.
//!
//! # Why the HTTP types are not imported
//!
//! This module models the manifest, and the manifest is a **file format**. It does not
//! know about `qqq-serve`'s router, and it must not: `qqq-cap` sits *below* `qqq-serve`
//! in §4.3's topological order, so an edge upward would invert the dependency graph
//! that `tools/check_topology.py` enforces. The conversion from [`Route`] to a router
//! entry belongs in the crate that owns the router.
//!
//! The cost of that discipline is one conversion function. The benefit is that the
//! manifest can be parsed and validated — including the security-relevant parts, like
//! whether `default_auth` is a mode a guest could have supplied — by the CLI, by
//! `qqqai inspect`, and by the capability engine, none of which link a server.
//!
//! # Deny by default, applied to the network surface
//!
//! An absent `[server]` means **no routes**, and therefore no listener. It does not
//! mean "serve everything", and it does not mean "serve the filesystem". The
//! capability model's first rule is that an absent stanza grants nothing, and it
//! applies to the network as much as to the filesystem — a runtime that defaulted to
//! serving whatever it could find would be ambient authority with extra steps.
//!
//! See Proposal §5.3, §6.4 and Checklist `SRV-001`, `SRV-002`, `SRV-019`.

use crate::manifest::{quoted, AuthMode, Cors, ManifestError, Route, Server};

/// The HTTP methods a route may declare, in the spelling `qqq.toml` uses.
///
/// Re-exported rather than imported privately: a caller that converts a manifest's
/// route table into an HTTP router must compare against **the same** closed set, and a
/// caller that cannot see this one would keep its own copy. Two lists that look
/// identical and drift is the defect `§O-130` is about, arriving through a lookup
/// table.
///
/// The list itself is declared in `crate::manifest` beside the types it validates.
pub use crate::manifest::METHODS;

// ---------------------------------------------------------------------------
// The section
// ---------------------------------------------------------------------------

/// Check the `[server.cors]` table.
///
/// # Why a `*` is refused here *and* in `qqq-serve::cors`
///
/// Both do, deliberately, and the duplication is the point rather than an oversight.
/// This one exists so `qqqai inspect`, `qqqai check` and the capability engine — none
/// of which link a server — can report a wildcard policy from the manifest alone. That
/// one exists so a policy built programmatically cannot bypass the rule. A manifest is
/// the file an auditor reads, so the answer must be available without starting a
/// listener.
///
/// The two messages differ in audience: this one names the field path in `qqq.toml`
/// and shows the fix, because the reader is editing a file; that one states the
/// security consequence, because the reader is writing code.
fn validate_cors(cors: &Cors) -> Result<(), ManifestError> {
    if cors.allow_origins.iter().any(|o| o.trim() == "*") {
        return Err(ManifestError::InvalidField {
            field: "server.cors.allow_origins".to_owned(),
            reason: "`*` allows every origin to read every response; name the origins \
                     explicitly, e.g. allow_origins = [\"https://app.example.com\"]"
                .to_owned(),
        });
    }
    if cors
        .allow_origins
        .iter()
        .any(|o| o.contains('*') && o.trim() != "*")
    {
        return Err(ManifestError::InvalidField {
            field: "server.cors.allow_origins".to_owned(),
            reason: "a wildcard host is not supported in V1; list each origin in full, \
                     because a partial matcher is a substring matcher and that is the \
                     classic CORS bypass"
                .to_owned(),
        });
    }
    Ok(())
}

impl Server {
    /// Check the section for the mistakes a manifest author actually makes.
    ///
    /// # Errors
    ///
    /// Returns the first problem found, naming the field, the reason and the fix —
    /// the manifest is the first file a user writes and the first place they get
    /// stuck, so its errors carry their weight.
    ///
    /// # Why the checks are here rather than in `serde`
    ///
    /// `deny_unknown_fields` catches a misspelled *field name*. Everything in this
    /// function is a misspelled *value* or a contradictory combination, and serde
    /// cannot express either. `methods = ["GTE"]` deserializes perfectly and produces
    /// a route nothing can reach.
    pub fn validate(&self) -> Result<(), ManifestError> {
        // The per-route checks are separated from the section-level ones because they
        // are different kinds of mistake — a route literal is wrong, versus the section
        // contradicts itself — and because the loop body was long enough that a reader
        // lost the shape of it.
        let mut seen: Vec<(&str, Vec<&str>)> = Vec::new();
        for (i, route) in self.routes.iter().enumerate() {
            let methods = Self::validate_route(i, route, &seen)?;
            seen.push((route.path.as_str(), methods));
        }

        if let Some(cors) = &self.cors {
            validate_cors(cors)?;
        }

        // `[server.limits]` — `SRV-020`'s per-tenant request caps.
        //
        // Validated here, at the same point as everything else in the section, so a manifest
        // with an incoherent limit is refused by `qqqai check` rather than at startup. The
        // one incoherence is a zero window with a request cap, which makes the limiter allow
        // **everything** — see `qqq_serve::limits::Limits::is_coherent` for why that
        // particular mistake is worth a startup failure rather than a log line.
        if let Some(limits) = &self.limits {
            limits
                .validate()
                .map_err(|reason| ManifestError::InvalidField {
                    field: "server.limits".to_owned(),
                    reason,
                })?;
        }

        Ok(())
    }

    /// Check one route, returning its canonical method list.
    ///
    /// `declared` is what earlier routes in the list already handle, so a duplicate is
    /// caught here rather than in a second pass.
    fn validate_route<'a>(
        i: usize,
        route: &'a Route,
        declared: &[(&str, Vec<&'a str>)],
    ) -> Result<Vec<&'a str>, ManifestError> {
        let where_ = format!("server.routes[{i}]");

        if route.path.is_empty() {
            return Err(ManifestError::InvalidField {
                field: format!("{where_}.path"),
                reason: "the path is empty; a route needs one, e.g. `/orders` or \
                             `/orders/:id`"
                    .to_owned(),
            });
        }
        // A path is a path, not a URL. Accepting an absolute URL would produce a
        // route that can never match.
        if !route.path.starts_with('/') {
            return Err(ManifestError::InvalidField {
                field: format!("{where_}.path"),
                reason: format!(
                    "`{}` does not start with `/`; write it as `/{}`",
                    route.path,
                    route.path.trim_start_matches('/')
                ),
            });
        }
        if route.path.contains(['?', '#']) {
            return Err(ManifestError::InvalidField {
                field: format!("{where_}.path"),
                reason: format!(
                    "`{}` contains a query or fragment; a route matches the path only",
                    route.path
                ),
            });
        }

        if route.handler.is_empty() {
            return Err(ManifestError::InvalidField {
                field: format!("{where_}.handler"),
                reason: "the handler name is empty; name the guest function this \
                             route calls, e.g. \"create-order\""
                    .to_owned(),
            });
        }

        // **An empty method list is an error, not "all methods".** Reading it as
        // "all" is the most dangerous interpretation available: a route the author
        // left incomplete would accept `DELETE`.
        if route.methods.is_empty() {
            return Err(ManifestError::InvalidField {
                field: format!("{where_}.methods"),
                reason: format!(
                    "no methods are listed; an empty list is not \"all methods\", so \
                         name them, e.g. methods = [{}]",
                    quoted(&["GET"])
                ),
            });
        }

        let mut methods: Vec<&str> = Vec::with_capacity(route.methods.len());
        for method in &route.methods {
            let upper = method.to_ascii_uppercase();
            let Some(canonical) = METHODS.iter().find(|m| **m == upper) else {
                return Err(ManifestError::InvalidField {
                    field: format!("{where_}.methods"),
                    reason: format!(
                        "`{method}` is not an HTTP method; expected one of {}",
                        quoted(&METHODS)
                    ),
                });
            };
            methods.push(canonical);
        }

        // A duplicate is an error rather than a last-wins merge: two entries for
        // the same path and method mean the author has two intentions, and picking
        // one silently is how the other is discovered in production.
        for (path, earlier) in declared {
            if *path != route.path {
                continue;
            }
            if let Some(overlap) = methods.iter().find(|m| earlier.contains(m)) {
                return Err(ManifestError::InvalidField {
                    field: format!("{where_}.methods"),
                    reason: format!(
                        "route `{}` already handles `{overlap}`, declared earlier in \
                         this list; remove one entry or give them different methods",
                        route.path
                    ),
                });
            }
        }

        Ok(methods)
    }
}

impl Server {
    /// Whether this project has any network surface at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Whether an untouched `Server` is what this value is, for `skip_serializing_if`.
    ///
    /// Named separately from [`Server::is_empty`] because the two answer different
    /// questions and conflating them loses a decision. `is_empty` asks *"does this
    /// project serve anything?"*; this asks *"can this value be omitted from the file
    /// without losing information?"* — and a `default_auth` other than `deny` is
    /// information, even with no routes, because it is the value every route will
    /// inherit the moment one is added.
    ///
    /// Omission is what keeps `qqqai` able to rewrite a manifest without a spurious
    /// diff, which is why it is worth the extra predicate.
    #[must_use]
    pub fn is_empty_unconfigured(&self) -> bool {
        self.routes.is_empty() && self.default_auth == AuthMode::Deny && self.cors.is_none()
    }

    /// How many routes are declared.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// The routes that would be served **without any authentication**.
    ///
    /// # Why this is a method and not a `filter` at the call site
    ///
    /// It is the first question an auditor asks, the first thing `qqqai inspect` should
    /// print, and the thing a manifest change most often gets wrong — adding
    /// `auth = "none"` to make a health check work and forgetting it is now public.
    /// Returning the routes rather than a count means the caller can name them.
    ///
    /// A route with `auth = "none"` counts; a route inheriting `default_auth = "deny"`
    /// does not, even though it also validates no credential, because it is not
    /// *served*. The distinction is the whole reason `AuthMode` is a closed set with
    /// `deny` in it.
    #[must_use]
    pub fn unauthenticated_routes(&self) -> Vec<&Route> {
        self.routes
            .iter()
            .filter(|r| r.effective_auth(self.default_auth) == AuthMode::None)
            .collect()
    }
}

impl Route {
    /// The authentication mode that applies to this route.
    #[must_use]
    pub const fn effective_auth(&self, default: AuthMode) -> AuthMode {
        match self.auth {
            Some(mode) => mode,
            None => default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{RequestLimits, TenantLimit};

    fn route(path: &str, methods: &[&str]) -> Route {
        Route {
            path: path.to_owned(),
            methods: methods.iter().map(|m| (*m).to_owned()).collect(),
            handler: "handler".to_owned(),
            auth: None,
        }
    }

    fn server(routes: Vec<Route>) -> Server {
        Server {
            routes,
            ..Server::default()
        }
    }

    // -- deny by default ----------------------------------------------------

    /// **Absent `[server]` means no routes, not "serve everything".**
    #[test]
    fn an_absent_server_section_has_no_routes() {
        let s = Server::default();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(s.unauthenticated_routes().is_empty());
    }

    /// **`default_auth` defaults to `deny`, not to `none`.**
    ///
    /// The single most consequential default in the section. A manifest that lists
    /// routes and forgets this line must fail closed; defaulting to `none` would
    /// publish every route because the author omitted one line.
    #[test]
    fn the_default_auth_mode_is_deny() {
        assert_eq!(Server::default().default_auth, AuthMode::Deny);
        // And a route that does not override it is not served without credentials.
        let s = server(vec![route("/orders", &["GET"])]);
        assert!(s.unauthenticated_routes().is_empty(), "deny is not `none`");
    }

    /// `deny` and `none` are different, and only `none` is served unauthenticated.
    #[test]
    fn deny_and_none_differ() {
        assert!(!AuthMode::Deny.validates_a_credential());
        assert!(!AuthMode::None.validates_a_credential());
        assert!(AuthMode::BearerJwt.validates_a_credential());

        let mut r = route("/healthz", &["GET"]);
        r.auth = Some(AuthMode::None);
        let s = server(vec![r]);
        assert_eq!(
            s.unauthenticated_routes().len(),
            1,
            "an explicit `none` is served without credentials and must be reported"
        );
    }

    /// An explicit `auth = "none"` on one route is reported even under `deny`.
    #[test]
    fn a_none_route_is_reported_under_a_deny_default() {
        let mut open = route("/healthz", &["GET"]);
        open.auth = Some(AuthMode::None);
        let s = Server {
            routes: vec![open, route("/orders", &["GET"])],
            default_auth: AuthMode::Deny,
            cors: None,
            limits: None,
        };
        let open_routes = s.unauthenticated_routes();
        assert_eq!(open_routes.len(), 1);
        assert_eq!(open_routes[0].path, "/healthz");
    }

    // -- route validation --------------------------------------------------

    /// A well-formed section validates.
    #[test]
    fn a_valid_section_validates() {
        let s = server(vec![
            route("/orders", &["POST"]),
            route("/orders/:id", &["GET", "DELETE"]),
            route("/healthz", &["GET"]),
        ]);
        assert!(s.validate().is_ok());
        assert_eq!(s.len(), 3);
    }

    /// **An empty `methods` list is an error, not "all methods".**
    ///
    /// Reading it as "all" would make a route the author left incomplete accept
    /// `DELETE`. This is the dangerous interpretation and it is refused by name.
    #[test]
    fn an_empty_method_list_is_refused() {
        let s = server(vec![route("/orders", &[])]);
        let err = s.validate().expect_err("must refuse");
        let text = err.to_string();
        assert!(text.contains("methods"), "{text}");
        assert!(
            text.contains("not \"all methods\""),
            "the message must name the trap it is avoiding: {text}"
        );
    }

    /// A misspelled method is refused, and the message lists the valid ones.
    ///
    /// The list is rendered by `manifest::quoted`, so the assertion checks the
    /// **backtick** convention rather than quotes — a first version of this test looked
    /// for `"GET"` and failed against a correct message. The point of the test is that
    /// the valid set is present, so it asserts on the rendering the module actually
    /// uses, which is shared with every other "expected one of" in the manifest.
    #[test]
    fn an_unknown_method_is_refused_with_the_valid_set() {
        let s = server(vec![route("/orders", &["GTE"])]);
        let err = s.validate().expect_err("must refuse");
        let text = err.to_string();
        assert!(text.contains("GTE"), "{text}");
        assert!(
            text.contains("`GET`") && text.contains("`DELETE`"),
            "the fix must list the valid methods: {text}"
        );
        assert!(
            text.contains("expected one of"),
            "the message must use the shared convention: {text}"
        );
    }

    /// Methods are matched case-insensitively and accepted in lower case.
    #[test]
    fn a_lowercase_method_is_accepted() {
        let s = server(vec![route("/orders", &["get", "post"])]);
        assert!(s.validate().is_ok(), "{:?}", s.validate());
    }

    /// A path must start with `/`, and the message shows the fix.
    #[test]
    fn a_path_without_a_leading_slash_is_refused() {
        let s = server(vec![route("orders", &["GET"])]);
        let err = s.validate().expect_err("must refuse");
        let text = err.to_string();
        assert!(
            text.contains("/orders"),
            "the message must show the fix: {text}"
        );
    }

    /// A path carrying a query or fragment is refused.
    #[test]
    fn a_path_with_a_query_is_refused() {
        for bad in ["/orders?x=1", "/orders#frag"] {
            let s = server(vec![route(bad, &["GET"])]);
            let err = s.validate().expect_err("must refuse");
            assert!(
                err.to_string().contains("query or fragment"),
                "{bad}: {err}"
            );
        }
    }

    /// An empty path is refused.
    #[test]
    fn an_empty_path_is_refused() {
        let s = server(vec![route("", &["GET"])]);
        assert!(s.validate().is_err());
    }

    /// An empty handler name is refused.
    #[test]
    fn an_empty_handler_is_refused() {
        let mut r = route("/orders", &["GET"]);
        r.handler = String::new();
        assert!(server(vec![r]).validate().is_err());
    }

    /// **A duplicate path with an overlapping method is refused, not last-wins.**
    ///
    /// Two entries for the same path and method mean the author has two intentions.
    /// Silently picking one is how the other is discovered in production.
    #[test]
    fn a_duplicate_route_with_an_overlapping_method_is_refused() {
        let s = server(vec![
            route("/orders", &["GET", "POST"]),
            route("/orders", &["POST"]),
        ]);
        let err = s.validate().expect_err("must refuse");
        let text = err.to_string();
        assert!(text.contains("already handles"), "{text}");
        assert!(text.contains("POST"), "{text}");
    }

    /// The same path with **disjoint** methods is fine.
    ///
    /// The control for the test above: a check that refused any repeated path would be
    /// wrong, because splitting one path across two handlers by method is reasonable.
    #[test]
    fn the_same_path_with_disjoint_methods_is_accepted() {
        let s = server(vec![
            route("/orders", &["GET"]),
            route("/orders", &["POST"]),
        ]);
        assert!(s.validate().is_ok(), "{:?}", s.validate());
    }

    /// The error names the offending index, so a long route list is navigable.
    #[test]
    fn the_error_names_the_route_index() {
        let s = server(vec![
            route("/a", &["GET"]),
            route("/b", &["GET"]),
            route("/c", &[]),
        ]);
        let err = s.validate().expect_err("must refuse");
        assert!(err.to_string().contains("routes[2]"), "{err}");
    }

    // -- CORS in the manifest ----------------------------------------------

    /// A `*` origin is refused at parse time, with the reason and the fix.
    #[test]
    fn a_wildcard_origin_is_refused_at_parse_time() {
        let s = Server {
            cors: Some(Cors {
                allow_origins: vec!["*".to_owned()],
                ..Cors::default()
            }),
            ..Server::default()
        };
        let err = s.validate().expect_err("must refuse");
        let text = err.to_string();
        assert!(text.contains("every origin"), "{text}");
        assert!(
            text.contains("explicitly"),
            "the fix must be stated: {text}"
        );
    }

    /// **Credentials with a wildcard is refused, because it does not work.**
    ///
    /// Browsers reject `Access-Control-Allow-Origin: *` when credentials are allowed,
    /// so the combination produces a policy that silently grants nothing. An error is
    /// right rather than a warning: the author would otherwise debug a CORS failure
    /// whose cause is this line.
    #[test]
    fn credentials_with_a_wildcard_is_refused() {
        let s = Server {
            cors: Some(Cors {
                allow_origins: vec!["*".to_owned()],
                allow_credentials: true,
                ..Cors::default()
            }),
            ..Server::default()
        };
        assert!(s.validate().is_err());
    }

    /// A wildcard *host* is refused, distinct from a bare `*`.
    #[test]
    fn a_wildcard_host_is_refused_at_parse_time() {
        for pattern in ["https://*.example.com", "https://example.*"] {
            let s = Server {
                cors: Some(Cors {
                    allow_origins: vec![pattern.to_owned()],
                    ..Cors::default()
                }),
                ..Server::default()
            };
            let err = s.validate().expect_err("must refuse");
            assert!(err.to_string().contains("wildcard"), "{pattern}: {err}");
        }
    }

    /// A named origin validates.
    #[test]
    fn a_named_origin_validates() {
        let s = Server {
            cors: Some(Cors {
                allow_origins: vec!["https://app.example.com".to_owned()],
                allow_credentials: true,
                ..Cors::default()
            }),
            ..Server::default()
        };
        assert!(s.validate().is_ok(), "{:?}", s.validate());
    }

    // -- the file format ---------------------------------------------------

    /// **The Proposal's own example parses.**
    ///
    /// `§5.3` prints a manifest as the canonical illustration of the format. If that
    /// text does not parse, either the document or the parser is wrong — and the
    /// document is the specification, so the parser is.
    #[test]
    fn the_proposal_example_parses() {
        let toml = r#"
routes = [
  { path = "/orders",     methods = ["POST"],          handler = "create-order" },
  { path = "/orders/:id", methods = ["GET", "DELETE"], handler = "order-by-id" },
  { path = "/healthz",    methods = ["GET"],           handler = "health", auth = "none" },
]
default_auth = "bearer-jwt"

[cors]
allow_origins = ["https://app.example.com"]
"#;
        let s: Server = toml::from_str(toml).expect("the Proposal's example must parse");
        assert_eq!(s.routes.len(), 3);
        assert_eq!(s.default_auth, AuthMode::BearerJwt);
        assert_eq!(s.routes[1].path, "/orders/:id");
        assert_eq!(s.routes[1].methods, vec!["GET", "DELETE"]);
        assert_eq!(s.routes[2].auth, Some(AuthMode::None));
        assert_eq!(
            s.cors.as_ref().expect("cors").allow_origins,
            vec!["https://app.example.com"]
        );
        assert!(s.validate().is_ok(), "{:?}", s.validate());
    }

    /// An unknown field inside `[server]` is refused.
    ///
    /// The manifest's strictness rule: a typo like `route = [...]` (singular) must not
    /// parse into a project with no routes and no indication why.
    #[test]
    fn an_unknown_server_field_is_refused() {
        let err = toml::from_str::<Server>("route = []").expect_err("must refuse");
        assert!(err.to_string().contains("route"), "{err}");
    }

    /// An unknown field inside a route is refused.
    #[test]
    fn an_unknown_route_field_is_refused() {
        let toml =
            r#"routes = [{ path = "/a", methods = ["GET"], handler = "h", method = ["POST"] }]"#;
        assert!(toml::from_str::<Server>(toml).is_err());
    }

    /// An unknown auth mode is refused, naming the valid set.
    #[test]
    fn an_unknown_auth_mode_is_refused() {
        let err = toml::from_str::<Server>(r#"default_auth = "jwt""#).expect_err("must refuse");
        let text = err.to_string();
        assert!(
            text.contains("bearer-jwt") || text.contains("unknown variant"),
            "{text}"
        );
    }

    /// The auth modes round-trip through their kebab-case spellings.
    #[test]
    fn auth_modes_round_trip() {
        for mode in [
            AuthMode::Deny,
            AuthMode::None,
            AuthMode::BearerJwt,
            AuthMode::Mtls,
            AuthMode::SignedRequest,
        ] {
            let text = format!("default_auth = \"{}\"", mode.as_str());
            let s: Server = toml::from_str(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(s.default_auth, mode, "{text}");
        }
    }

    /// Serialization is stable, and an absent field is absent rather than empty.
    ///
    /// §10.5 and the manifest's own diffs: `skip_serializing_if` keeps a round-trip
    /// from growing the file, which is what makes `qqqai` able to rewrite a manifest
    /// without a spurious diff.
    #[test]
    fn serialization_omits_empty_fields() {
        let s = Server::default();
        let text = toml::to_string(&s).expect("serializes");
        assert!(!text.contains("routes"), "{text}");
        assert!(!text.contains("cors"), "{text}");
        // And the default auth mode **is** written, because it is a decision the file
        // should state rather than inherit. A reader of the file cannot tell an omitted
        // `default_auth` from a deliberate `deny`.
        assert!(text.contains("default_auth"), "{text}");
    }

    /// A round-trip preserves everything.
    #[test]
    fn a_full_section_round_trips() {
        let s = Server {
            routes: vec![
                route("/orders", &["POST"]),
                Route {
                    path: "/healthz".to_owned(),
                    methods: vec!["GET".to_owned()],
                    handler: "health".to_owned(),
                    auth: Some(AuthMode::None),
                },
            ],
            default_auth: AuthMode::BearerJwt,
            cors: Some(Cors {
                allow_origins: vec!["https://app.example.com".to_owned()],
                allow_credentials: true,
                allow_methods: vec!["GET".to_owned(), "POST".to_owned()],
                allow_headers: vec!["content-type".to_owned()],
                expose_headers: vec!["x-request-id".to_owned()],
                max_age: Some(600),
            }),
            // Populated rather than `None`, because the point of a round-trip test is that
            // every field survives. A `None` here would let a serialization bug in the limits
            // shape pass unnoticed.
            limits: Some(RequestLimits {
                default: Some(TenantLimit {
                    max_body_bytes: Some(1_048_576),
                    max_requests_per_window: Some(1_000),
                    window_seconds: Some(60),
                    max_connections: Some(64),
                }),
                // A canonical client address, not a name: `validate_tenant_key` refuses a
                // name because it can never match a request's tenant. This fixture builds
                // the struct directly and so bypasses that check, which is why the old
                // `"big"` key survived here while the same key is refused by `parse`.
                per_tenant: std::collections::BTreeMap::from([(
                    "127.0.0.1".to_owned(),
                    TenantLimit {
                        max_body_bytes: Some(16_777_216),
                        max_requests_per_window: None,
                        window_seconds: None,
                        max_connections: Some(8),
                    },
                )]),
            }),
        };
        let text = toml::to_string(&s).expect("serializes");
        let back: Server = toml::from_str(&text).expect("parses");
        assert_eq!(back, s, "round-trip changed the value:\n{text}");
    }
}
