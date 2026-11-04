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

use crate::manifest::{AuthMode, Cors, ManifestError, Route, Server, quoted};

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

/// Check a `[server.tls]` table (`SRV-021`).
///
/// Paths are checked for shape only — empty, whitespace-only, or NUL-bearing
/// — never for existence: the files live where the server runs, and `qqqai
/// check` must accept a manifest whose certificate is not on the author's
/// machine. Existence and parse errors surface at serve time, naming the
/// file, through `CertificateSource::resolve`.
fn validate_tls(tls: &crate::manifest::ServerTls) -> Result<(), ManifestError> {
    for (field, value) in [
        ("server.tls.cert_file", tls.cert_file.as_str()),
        ("server.tls.key_file", tls.key_file.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(ManifestError::InvalidPath {
                path: value.to_owned(),
                reason: format!(
                    "{field} must name a file; an empty path would fail at serve \
                     time with a read error, far from the line that is wrong"
                ),
            });
        }
        if value.contains('\0') {
            return Err(ManifestError::InvalidPath {
                path: value.to_owned(),
                reason: format!("{field} must not contain a NUL byte"),
            });
        }
    }
    // The client CA is optional; when present it follows the same shape
    // rules — existence stays serve-time, like the identity files.
    if let Some(ca) = tls.client_ca_file.as_deref() {
        if ca.trim().is_empty() {
            return Err(ManifestError::InvalidPath {
                path: ca.to_owned(),
                reason: "server.tls.client_ca_file must name a file; an empty path would fail at serve time with a read error, far from the line that is wrong".to_owned(),
            });
        }
        if ca.contains('\0') {
            return Err(ManifestError::InvalidPath {
                path: ca.to_owned(),
                reason: "server.tls.client_ca_file must not contain a NUL byte".to_owned(),
            });
        }
    }
    Ok(())
}

/// Check a `[server.tenants]` table: no dead keys, no empty labels.
///
/// A key the matcher can never produce is dead configuration reading as
/// policy: empty, non-lowercase, carrying a `:port` (stripped from requests
/// before lookup), a trailing dot (requests arrive undotted), whitespace,
/// or brackets. An empty hosts map is the same mistake at the table level —
/// a `[server.tenants]` section that maps nothing behaves as absent, so it
/// is refused rather than silently switching the feature off — unless
/// components are mapped: an mTLS-only deployment resolves tenants from
/// client certificates and needs no `Host` mapping at all.
/// Check one `[server.tenants]` host entry: a key the matcher can never
/// produce, or a label no renderer can show honestly, is dead configuration
/// reading as policy.
///
/// Extracted from `validate_tenants` (which clippy's line budget asked
/// for), because one entry's rule must read in one place: a caller that
/// inlined the arms would duplicate the "which forms can match" answer,
/// and the two copies would disagree the next time it changes.
fn validate_host_entry(host: &str, label: &str) -> Result<(), ManifestError> {
    if host.trim().is_empty() {
        return Err(ManifestError::InvalidField {
            field: "server.tenants.hosts".to_owned(),
            reason: "a host key must not be empty; an empty key never matches".to_owned(),
        });
    }
    // Matching lowercases the request's host, so a mixed-case key would
    // never match: reject it here with the spelling to use, the way
    // non-canonical per-tenant addresses are refused, rather than
    // letting a deployment silently serve every host as unmapped.
    // Escaped, not Debug-formatted: a hostile key is echoed into a startup
    // error on the operator's terminal, and `{:?}` leaves U+2800 raw — a
    // raw blank would reorder the message meant to warn about it.
    if host != host.to_ascii_lowercase() {
        return Err(ManifestError::InvalidField {
            field: "server.tenants.hosts".to_owned(),
            reason: format!(
                "host keys must be lowercase; `{}` never matches because \
                 requests are compared lowercased — write `{}`",
                crate::text::escape_for_error(host),
                host.to_ascii_lowercase()
            ),
        });
    }
    // The request side strips a numeric `:port` before lookup
    // (`ws::host_name`: a non-numeric or empty port is not a port at all,
    // so the whole value compares instead) — so a key that still carries
    // one, or a trailing dot, whitespace, or stray brackets, can never
    // equal a normalized request host. The two must agree on what a port
    // is: if `host_name` ever strips non-numeric ports, this gate must
    // follow, or dead keys become live without review. Controls,
    // layout-forgers, and invisible format characters cannot arrive in a
    // real `Host` header either, so a key carrying one is dead the same
    // way — and would render invisibly in every log line that names it.
    // Over-long keys are dead too: no DNS name exceeds 253 bytes.
    // A bare or bracketed IP literal is looked up verbatim:
    // `ws::host_name` preserves brackets when stripping a numeric port
    // and leaves addresses without brackets or port untouched, so
    // `[::1]:8080` normalizes to `[::1]`, `::1` to `::1`, and a zoned
    // `[fe80::1%eth0]` keeps its zone. Refusing any of them would lie
    // about a mapping that works. Anything else bracketed stays dead.
    // Zones follow RFC 6874 (`unreserved`); an empty or exotic zone is
    // refused, not guessed.
    let literal = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let (addr, zone) = match literal.split_once('%') {
        Some((a, z)) => (a, Some(z)),
        None => (literal, None),
    };
    let ip_literal = addr.parse::<std::net::IpAddr>().is_ok()
        && zone.is_none_or(|z| {
            !z.is_empty()
                && z.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
        });
    if host.len() > 253 {
        return Err(ManifestError::InvalidField {
            field: "server.tenants.hosts".to_owned(),
            reason: format!(
                "host key `{}` exceeds the 253-byte DNS maximum and can never arrive",
                crate::text::escape_for_error(host)
            ),
        });
    }
    if (host.contains(':') && !ip_literal)
        || host.ends_with('.')
        || host.chars().any(char::is_whitespace)
        || ((host.contains('[') || host.contains(']')) && !ip_literal)
        || host.chars().any(|c| {
            c.is_control()
                || crate::text::is_layout_forgery(c)
                || crate::text::is_invisible_format(c)
        })
    {
        return Err(ManifestError::InvalidField {
            field: "server.tenants.hosts".to_owned(),
            reason: format!(
                "host key `{}` can never match: write the bare \
                 lowercased host without port, trailing dot, whitespace, \
                 stray brackets, or invisible characters, as it arrives after normalization",
                crate::text::escape_for_error(host)
            ),
        });
    }
    if label.trim().is_empty() {
        return Err(ManifestError::InvalidField {
            field: "server.tenants.hosts".to_owned(),
            reason: format!(
                "the tenant for host `{}` must not be empty",
                crate::text::escape_for_error(host)
            ),
        });
    }
    // Labels render into access records, metrics, and audit rows: an
    // invisible character (a zero-width space, an NBSP, a bidi
    // override) would be a tenant no reader can tell apart from its
    // visible twin. `TenantId` refuses the whole class, so the table
    // routes through it rather than growing a parallel list — a label
    // the policy layer would refuse must not be issued here.
    if let Err(reason) = crate::egress::TenantId::new(label) {
        return Err(ManifestError::InvalidField {
            field: "server.tenants.hosts".to_owned(),
            reason: format!(
                "the tenant for host `{}` is not a valid tenant id: {reason}",
                crate::text::escape_for_error(host)
            ),
        });
    }
    Ok(())
}

fn validate_tenants(tenants: &crate::manifest::TenantHosts) -> Result<(), ManifestError> {
    if tenants.hosts.is_empty() && tenants.components.is_empty() {
        return Err(ManifestError::InvalidField {
            field: "server.tenants.hosts".to_owned(),
            reason: "the hosts table is empty and behaves as absent; remove \
                     `[server.tenants]` or map at least one host"
                .to_owned(),
        });
    }
    for (host, label) in &tenants.hosts {
        validate_host_entry(host, label)?;
    }
    for (label, artifact) in &tenants.components {
        if label.trim().is_empty() || artifact.trim().is_empty() {
            return Err(ManifestError::InvalidField {
                field: "server.tenants.components".to_owned(),
                reason: "component keys and artifact names must not be empty; an empty entry routes no tenant to no component".to_owned(),
            });
        }
        // Keys match resolved tenant labels verbatim, so anything that
        // cannot name a tenant is dead configuration reading as policy:
        // it never equals the label a request resolves to. Servable
        // labels are ASCII (certificate common names, host names, peer
        // addresses); a CN that is not a printable string decodes with
        // replacement characters and must not map either — it falls
        // through to the default component. Surrounding whitespace,
        // control characters, and non-ASCII lookalikes (NBSP,
        // zero-width spaces) are therefore refused. Interior ASCII
        // spaces stay allowed — a `John Doe` common name matches its
        // key exactly. Quotes and backslashes are refused too: resolved
        // labels route through `TenantId`, which refuses both, so a
        // quoted key could never equal a resolved label. Over-long keys
        // are refused for the same reason (`TenantId` bounds 256 bytes).
        if label != label.trim()
            || label
                .chars()
                .any(|c| c.is_control() || (c.is_whitespace() && c != ' ') || !c.is_ascii())
            || label.contains('"')
            || label.contains('\\')
            || label.len() > 256
        {
            return Err(ManifestError::InvalidField {
                field: "server.tenants.components".to_owned(),
                reason: format!(
                    "component key `{}` never matches; write the label exactly as resolved",
                    crate::text::escape_for_error(label)
                ),
            });
        }
        // Artifacts are bare Cargo package names, resolved by `find_artifact`
        // as `{package}.wasm` under the build directory. Anything that is
        // not a valid package name — a control character, whitespace, a path
        // separator, parent navigation, a file suffix, an uppercase letter,
        // a leading digit, a trailing separator, or more than 64 characters —
        // is refused here instead of failing at serve time far from the line
        // that is wrong. `PackageName` is the same gate `[package] name`
        // passes at parse, so an artifact the toolchain itself built always
        // passes; a hand-placed file with another spelling must be renamed
        // to the package name rather than relied on through the single-file
        // fallback, which breaks the moment a second file lands beside it.
        if let Err(reason) = qqq_core::PackageName::new(artifact.clone()) {
            return Err(ManifestError::InvalidField {
                field: "server.tenants.components".to_owned(),
                reason: format!(
                    "component artifact `{}` is not a valid package name ({reason}); write the bare package name",
                    crate::text::escape_for_error(artifact)
                ),
            });
        }
    }
    Ok(())
}

/// Check a `[server.websocket]` table (`F-14`).
///
/// Origins admit the literal `"*"` (the explicit any-origin opt-in, which
/// `[server.cors]` refuses) and otherwise must be `scheme://host[:port]`
/// shapes — the runtime parses them strictly, so a value that cannot parse
/// would be dead configuration. A zero cap refuses everything, like a zero
/// connection ceiling, and is refused for the same reason. Absolute ceilings
/// are enforced where the numbers live (`qqq-serve`), not here.
fn validate_websocket(ws: &crate::manifest::WebsocketPolicy) -> Result<(), ManifestError> {
    for origin in &ws.allowed_origins {
        let value = origin.trim();
        if value == "*" {
            continue;
        }
        if value.contains('*') {
            return Err(ManifestError::InvalidField {
                field: "server.websocket.allowed_origins".to_owned(),
                reason: format!(
                    "`{value}` is a wildcard host, which V1 refuses; list each origin \
                     in full, because a partial matcher is a substring matcher and \
                     that is the classic WebSocket bypass"
                ),
            });
        }
        if value.eq_ignore_ascii_case("null") {
            return Err(ManifestError::InvalidField {
                field: "server.websocket.allowed_origins".to_owned(),
                reason: "`null` is sent by sandboxed iframes and `file://` pages: \
                         admitting it grants exactly the callers least able to be trusted"
                    .to_owned(),
            });
        }
        let Some((scheme, rest)) = value.split_once("://") else {
            return Err(ManifestError::InvalidField {
                field: "server.websocket.allowed_origins".to_owned(),
                reason: format!(
                    "`{value}` is not `scheme://host[:port]`; the upgrade check \
                     compares origins exactly, so this entry could never match"
                ),
            });
        };
        if scheme.is_empty() || rest.is_empty() {
            return Err(ManifestError::InvalidField {
                field: "server.websocket.allowed_origins".to_owned(),
                reason: format!("`{value}` has no scheme or no host"),
            });
        }
        if rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err(ManifestError::InvalidField {
                field: "server.websocket.allowed_origins".to_owned(),
                reason: format!(
                    "`{value}` carries a path, query or fragment; an origin is not a URL"
                ),
            });
        }
    }
    for host in &ws.allowed_hosts {
        // Bare-host discipline, mirroring `validate_tenants` keys: the
        // upgrade check compares `Host` headers case-insensitively without a
        // port, so a value that cannot match there is dead configuration.
        let value = host.trim();
        if value.is_empty() {
            return Err(ManifestError::InvalidField {
                field: "server.websocket.allowed_hosts".to_owned(),
                reason: "an empty host admits nothing and documents nothing; remove it".to_owned(),
            });
        }
        if value != value.to_ascii_lowercase() {
            return Err(ManifestError::InvalidField {
                field: "server.websocket.allowed_hosts".to_owned(),
                reason: format!("`{value}` must be lowercase; hosts compare case-insensitively"),
            });
        }
        for bad in [':', '/', '?', '#', '[', ']', ' ', '\t'] {
            if value.contains(bad) {
                return Err(ManifestError::InvalidField {
                    field: "server.websocket.allowed_hosts".to_owned(),
                    reason: format!(
                        "`{value}` must be a bare host, without a port, path, \
                         brackets, or whitespace"
                    ),
                });
            }
        }
        if value == "*" || value.starts_with('.') || value.ends_with('.') || value.contains("..") {
            return Err(ManifestError::InvalidField {
                field: "server.websocket.allowed_hosts".to_owned(),
                reason: format!(
                    "`{value}` is not a bare host: no wildcard, no leading or \
                     trailing dot, no empty label"
                ),
            });
        }
    }
    for (name, cap) in [
        ("max_frame_bytes", ws.max_frame_bytes),
        ("max_message_bytes", ws.max_message_bytes),
        ("max_total_buffer_bytes", ws.max_total_buffer_bytes),
    ] {
        if cap == Some(0) {
            return Err(ManifestError::InvalidField {
                field: format!("server.websocket.{name}"),
                reason: "a zero cap refuses every WebSocket payload: every message \
                         would close with 1009 and nothing would say why"
                    .to_owned(),
            });
        }
    }
    validate_websocket_timeout(ws.handler_timeout_ms)
}

/// A zero handler timeout closes every message before the guest runs, so it
/// is refused the same way a zero byte cap is — but with its own reason: a
/// 1011 on every message reads as a broken guest rather than a cap, and the
/// operator must be told which of the two to fix.
fn validate_websocket_timeout(handler_timeout_ms: Option<u64>) -> Result<(), ManifestError> {
    if handler_timeout_ms == Some(0) {
        return Err(ManifestError::InvalidField {
            field: "server.websocket.handler_timeout_ms".to_owned(),
            reason: "a zero handler timeout closes every message with 1011 before \
                 the guest runs: a bound that refuses rather than bounds"
                .to_owned(),
        });
    }
    Ok(())
}

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
/// The two messages differ in audience: the manifest error names the field path in
/// `qqq.toml` and shows the fix, because the reader is editing a file; the runtime
/// error states the security consequence, because the reader is writing code.
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
    // Same shape discipline as `[server.websocket]`: an origin is
    // `scheme://host[:port]`, never `null` and never carrying a path, query,
    // or fragment. A value that cannot match is dead configuration reading
    // as policy.
    for origin in &cors.allow_origins {
        let value = origin.trim();
        if value.eq_ignore_ascii_case("null") {
            return Err(ManifestError::InvalidField {
                field: "server.cors.allow_origins".to_owned(),
                reason: "`null` is sent by sandboxed iframes and `file://` pages: \
                         admitting it grants exactly the callers least able to be trusted"
                    .to_owned(),
            });
        }
        let Some((scheme, rest)) = value.split_once("://") else {
            return Err(ManifestError::InvalidField {
                field: "server.cors.allow_origins".to_owned(),
                reason: format!(
                    "`{value}` is not `scheme://host[:port]`; origins compare \
                     exactly, so this entry could never match"
                ),
            });
        };
        if scheme.is_empty() || rest.is_empty() {
            return Err(ManifestError::InvalidField {
                field: "server.cors.allow_origins".to_owned(),
                reason: format!("`{value}` has no scheme or no host"),
            });
        }
        if rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err(ManifestError::InvalidField {
                field: "server.cors.allow_origins".to_owned(),
                reason: format!(
                    "`{value}` carries a path, query or fragment; an origin is not a URL"
                ),
            });
        }
    }
    Ok(())
}

impl Server {
    /// Check the section for the mistakes a manifest author actually makes.    ///
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

        if let Some(ws) = &self.websocket {
            validate_websocket(ws)?;
        }

        // `[server.tls]` — `SRV-021`'s TLS identity. Shape only (see
        // `validate_tls`): the files are read where the server runs.
        if let Some(tls) = &self.tls {
            validate_tls(tls)?;
        }

        // `[server.tenants]` — host-to-tenant attribution. Dead keys and
        // empty labels or maps are refused here rather than becoming dead
        // configuration that reads as policy.
        if let Some(tenants) = &self.tenants {
            validate_tenants(tenants)?;
        }

        Ok(())
    }
}

/// Whether two route paths can match the same request.
///
/// Normalizes a trailing `/` (except the root) and treats `:param` and `*`
/// segments as matching any one segment. Exact equality is the common case;
/// the segment rule catches `/orders/:id` vs `/orders/*`, which would
/// otherwise route the same request to two handlers.
fn paths_overlap(a: &str, b: &str) -> bool {
    fn normalized(p: &str) -> &str {
        if p.len() > 1 {
            p.strip_suffix('/').unwrap_or(p)
        } else {
            p
        }
    }
    let (a, b) = (normalized(a), normalized(b));
    if a == b {
        return true;
    }
    let (mut ai, mut bi) = (a.split('/'), b.split('/'));
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) => {
                let wild = |s: &str| s == "*" || s.starts_with(':');
                if x != y && !wild(x) && !wild(y) {
                    return false;
                }
            }
            (None, Some(_)) | (Some(_), None) => return false,
        }
    }
}

impl Server {
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

        // A method listed twice on one route is the same defect as two entries
        // for one path and method: the author wrote one intention twice, and
        // the table would carry a duplicate no reader can distinguish from a
        // merge. Refused here rather than in `RouteTable`, which should never
        // see ambiguity the manifest could have named.
        {
            let mut seen = std::collections::BTreeSet::new();
            for m in &methods {
                if !seen.insert(*m) {
                    return Err(ManifestError::InvalidField {
                        field: format!("{where_}.methods"),
                        reason: format!(
                            "`{m}` is listed twice on one route; list each method once"
                        ),
                    });
                }
            }
        }

        // A duplicate is an error rather than a last-wins merge: two entries for
        // the same path and method mean the author has two intentions, and picking
        // one silently is how the other is discovered in production. Paths
        // compare normalized (a trailing `/` is not a different route) and
        // segment-wise (`:id` and `*` both match any one segment, so
        // `/orders/:id` overlaps `/orders/*` and `/orders/:name`).
        for (path, earlier) in declared {
            if !paths_overlap(path, &route.path) {
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

        // A `ws` route upgrades from `GET`: the handshake is a `GET` with
        // `Upgrade: websocket`, so a `ws` route without `GET` is a route no
        // handshake can reach — and any non-`GET` method on a `ws` route is
        // dead for the same reason (no upgrade ever arrives as `POST`).
        // Refused here rather than as a runtime `400`, where the author
        // would debug the client instead of the manifest.
        validate_stateful_methods(route, &methods, &where_)?;

        Ok(methods)
    }
}

/// Refuse dead methods on stateful (`ws`/`sse`) routes.
///
/// Extracted from `validate_route`: the two kind rules together pushed it
/// past the line budget, and the method policy reads better beside itself
/// than between the path checks. `sse` mirrors `ws` — an event poll replays
/// the head with no body, so a stream declared for another method would run
/// blind, the same shape as a handshake that never arrives.
fn validate_stateful_methods(
    route: &Route,
    methods: &[&str],
    where_: &str,
) -> Result<(), ManifestError> {
    if route.kind == crate::manifest::RouteKind::Ws {
        if !methods.contains(&"GET") {
            return Err(ManifestError::InvalidField {
                field: format!("{where_}.methods"),
                reason: "a `ws` route must list `GET`: the WebSocket handshake \
                         is a `GET` with `Upgrade: websocket`, so without it \
                         no client can ever upgrade"
                    .to_owned(),
            });
        }
        if methods.iter().any(|m| *m != "GET") {
            return Err(ManifestError::InvalidField {
                field: format!("{where_}.methods"),
                reason: "a `ws` route must list only `GET`: the handshake \
                         never arrives as another method, so any other \
                         entry is dead configuration"
                    .to_owned(),
            });
        }
    }

    if route.kind == crate::manifest::RouteKind::Sse && !methods.contains(&"GET") {
        return Err(ManifestError::InvalidField {
            field: format!("{where_}.methods"),
            reason: "an `sse` route must list `GET`: without it no event \
                     poll can ever arrive"
                .to_owned(),
        });
    }
    if route.kind == crate::manifest::RouteKind::Sse && methods.iter().any(|m| *m != "GET") {
        return Err(ManifestError::InvalidField {
            field: format!("{where_}.methods"),
            reason: "an `sse` route must list only `GET`: event polls \
                     replay the head with no body, so a stream declared \
                     for another method would run blind"
                .to_owned(),
        });
    }
    Ok(())
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
        self.routes.is_empty()
            && self.default_auth == AuthMode::Deny
            && self.cors.is_none()
            && self.websocket.is_none()
            && self.limits.is_none()
            && self.tls.is_none()
            && self.tenants.is_none()
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
    use crate::manifest::{RequestLimits, RouteKind, ServerTls, TenantLimit};

    fn route(path: &str, methods: &[&str]) -> Route {
        Route {
            path: path.to_owned(),
            methods: methods.iter().map(|m| (*m).to_owned()).collect(),
            handler: "handler".to_owned(),
            auth: None,
            kind: RouteKind::Http,
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

    /// Ultra-review r1 C6: `is_empty_unconfigured` must account for every
    /// optional table — otherwise `[server.limits]`, `[server.tls]`, or
    /// `[server.tenants]` round-trips away via `skip_serializing_if`.
    #[test]
    fn empty_unconfigured_accounts_for_limits_tls_and_tenants() {
        assert!(Server::default().is_empty_unconfigured());
        for s in [
            Server {
                limits: Some(RequestLimits {
                    default: None,
                    per_tenant: std::collections::BTreeMap::new(),
                }),
                ..Server::default()
            },
            Server {
                tls: Some(ServerTls {
                    cert_file: "c".to_owned(),
                    key_file: "k".to_owned(),
                    client_ca_file: None,
                }),
                ..Server::default()
            },
            Server {
                tenants: Some(crate::manifest::TenantHosts::default()),
                ..Server::default()
            },
        ] {
            assert!(
                !s.is_empty_unconfigured(),
                "an optional table must defeat the empty-unconfigured predicate"
            );
        }
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
            websocket: None,
            tls: None,
            tenants: None,
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

    /// Ultra-review r1: trailing-slash and parameter-segment duplicates are
    /// refused too — `/orders/` is `/orders`, and `:id` overlaps `*`.
    #[test]
    fn trailing_slash_and_parameter_duplicates_are_refused() {
        let s = server(vec![
            route("/orders", &["GET"]),
            route("/orders/", &["GET"]),
        ]);
        assert!(
            s.validate().is_err(),
            "trailing slash is not a different route"
        );
        let s = server(vec![
            route("/orders/:id", &["GET"]),
            route("/orders/*", &["GET"]),
        ]);
        assert!(s.validate().is_err(), ":id overlaps *");
        // Different segment counts do not overlap.
        let s = server(vec![route("/a", &["GET"]), route("/a/b", &["GET"])]);
        assert!(
            s.validate().is_ok(),
            "different depths are different routes"
        );
    }

    /// Ultra-review r1: a `ws` route must list only `GET` — any other method
    /// is dead configuration (no upgrade ever arrives as `POST`).
    #[test]
    fn a_ws_route_with_a_non_get_method_is_refused() {
        let mut r = route("/socket", &["GET", "POST"]);
        r.kind = crate::manifest::RouteKind::Ws;
        assert!(server(vec![r]).validate().is_err());
        let mut r = route("/socket", &["GET"]);
        r.kind = crate::manifest::RouteKind::Ws;
        assert!(server(vec![r]).validate().is_ok());
    }

    /// An `sse` route must list only `GET`: event polls replay the head with
    /// no body, so any other method would run with a body the guest never sees.
    #[test]
    fn an_sse_route_with_a_non_get_method_is_refused() {
        for methods in [&["GET", "POST"][..], &["POST"][..]] {
            let mut r = route("/events", methods);
            r.kind = crate::manifest::RouteKind::Sse;
            let err = server(vec![r]).validate().expect_err("must refuse");
            let text = err.to_string();
            assert!(text.contains("methods"), "{text}");
        }
        // Each arm fires on its own shape: missing-`GET` versus extra methods.
        let mut missing = route("/events", &["POST"]);
        missing.kind = crate::manifest::RouteKind::Sse;
        let err = server(vec![missing]).validate().expect_err("must refuse");
        assert!(
            err.to_string().contains("must list `GET`"),
            "missing GET names the missing method: {err}"
        );
        let mut extra = route("/events", &["GET", "POST"]);
        extra.kind = crate::manifest::RouteKind::Sse;
        let err = server(vec![extra]).validate().expect_err("must refuse");
        assert!(
            err.to_string().contains("only `GET`"),
            "extra methods name the restriction: {err}"
        );
        let mut ok = route("/events", &["GET"]);
        ok.kind = crate::manifest::RouteKind::Sse;
        assert!(server(vec![ok]).validate().is_ok());
    }

    /// A method listed twice on one route is refused: the table would carry
    /// a duplicate no reader can distinguish from a merge.
    #[test]
    fn a_duplicate_method_on_one_route_is_refused() {
        let s = server(vec![route("/orders", &["GET", "GET"])]);
        let err = s.validate().expect_err("must refuse");
        assert!(err.to_string().contains("twice"), "{err}");
    }

    /// Ultra-review r1: CORS origins follow the websocket shape discipline —
    /// `null` and path/query/fragment entries are dead configuration.
    #[test]
    fn cors_origins_with_null_or_paths_are_refused() {
        for bad in [
            "null",
            "NULL",
            "https://app.example.com/path",
            "https://a.com?q=1",
        ] {
            let s = Server {
                cors: Some(Cors {
                    allow_origins: vec![bad.to_owned()],
                    ..Cors::default()
                }),
                ..Server::default()
            };
            assert!(s.validate().is_err(), "{bad} must be refused");
        }
        let s = Server {
            cors: Some(Cors {
                allow_origins: vec!["https://app.example.com".to_owned()],
                ..Cors::default()
            }),
            ..Server::default()
        };
        assert!(s.validate().is_ok());
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

    /// A `ws` route without `GET` is refused: the handshake is a `GET`
    /// with `Upgrade: websocket`, so without it no client can upgrade.
    #[test]
    fn a_ws_route_without_get_is_refused() {
        let mut r = route("/ws", &["POST"]);
        r.kind = RouteKind::Ws;
        let s = server(vec![r]);
        let err = s.validate().expect_err("must refuse");
        assert!(err.to_string().contains("GET"), "{err}");
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
                    kind: RouteKind::Http,
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
            websocket: None,
            // Populated for the same reason as `limits` above: a `None` here
            // would let a serialization bug in the TLS shape pass unnoticed.
            tls: Some(ServerTls {
                cert_file: "certs/server.pem".to_owned(),
                key_file: "certs/server.key".to_owned(),
                client_ca_file: None,
            }),
            // Populated for the same reason: the tenants table must survive
            // a round trip, or a deployment would lose its host mapping on
            // rewrite.
            tenants: Some(crate::manifest::TenantHosts {
                hosts: std::collections::BTreeMap::from([(
                    "shop.example.com".to_owned(),
                    "shop".to_owned(),
                )]),
                components: std::collections::BTreeMap::from([(
                    "shop".to_owned(),
                    "shop-app".to_owned(),
                )]),
            }),
        };
        let text = toml::to_string(&s).expect("serializes");
        let back: Server = toml::from_str(&text).expect("parses");
        assert_eq!(back, s, "round-trip changed the value:\n{text}");
    }

    // -- [server.tls] ------------------------------------------------------

    /// A TLS section naming files validates: existence is serve-time.
    #[test]
    fn a_tls_section_naming_files_validates() {
        let mut s = server(vec![route("/orders", &["POST"])]);
        s.tls = Some(ServerTls {
            cert_file: "certs/server.pem".to_owned(),
            key_file: "certs/server.key".to_owned(),
            client_ca_file: None,
        });
        assert!(s.validate().is_ok());
        assert!(s.tls.is_some(), "absent TLS must stay absent, not default");
    }

    /// **An empty `cert_file` is refused, not defaulted.**
    #[test]
    fn an_empty_tls_cert_file_is_refused() {
        let mut s = server(vec![route("/orders", &["POST"])]);
        s.tls = Some(ServerTls {
            cert_file: String::new(),
            key_file: "certs/server.key".to_owned(),
            client_ca_file: None,
        });
        let err = s
            .validate()
            .expect_err("an empty cert path must be refused");
        let text = err.to_string();
        assert!(
            text.contains("server.tls.cert_file"),
            "the refusal must name the field: {text}"
        );
    }

    /// **A whitespace-only `key_file` is refused like an empty one.**
    #[test]
    fn a_whitespace_tls_key_file_is_refused() {
        let mut s = server(vec![route("/orders", &["POST"])]);
        s.tls = Some(ServerTls {
            cert_file: "certs/server.pem".to_owned(),
            key_file: "   ".to_owned(),
            client_ca_file: None,
        });
        let err = s.validate().expect_err("a blank key path must be refused");
        let text = err.to_string();
        assert!(
            text.contains("server.tls.key_file"),
            "the refusal must name the field: {text}"
        );
    }

    /// **An empty `client_ca_file` is refused like an empty `cert_file`.**
    #[test]
    fn an_empty_tls_client_ca_file_is_refused() {
        let mut s = server(vec![route("/orders", &["POST"])]);
        s.tls = Some(ServerTls {
            cert_file: "certs/server.pem".to_owned(),
            key_file: "certs/server.key".to_owned(),
            client_ca_file: Some("   ".to_owned()),
        });
        let err = s
            .validate()
            .expect_err("an empty client CA path must be refused");
        assert!(
            err.to_string().contains("server.tls.client_ca_file"),
            "the refusal must name the field: {err}"
        );
    }

    /// **A NUL byte in a TLS path is refused.**
    #[test]
    fn a_nul_byte_in_a_tls_path_is_refused() {
        let mut s = server(vec![route("/orders", &["POST"])]);
        s.tls = Some(ServerTls {
            cert_file: "certs/serv\0er.pem".to_owned(),
            key_file: "certs/server.key".to_owned(),
            client_ca_file: None,
        });
        let err = s.validate().expect_err("a NUL path must be refused");
        assert!(
            err.to_string().contains("NUL"),
            "the refusal must name the reason: {err}"
        );
    }
}
