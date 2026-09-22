// SPDX-License-Identifier: Apache-2.0

//! `qqqai openapi` — an OpenAPI 3.0 description of a running app (`SRV-017`).
//!
//! Proposal §5.2 lists the command as:
//!
//! > | `qqqai openapi` | Emit an OpenAPI description of a running app | `--out <file>` |
//!
//! # Why this is generated from the manifest and not from a running server
//!
//! §5.2 says "of a running app", and the tempting reading is to start the server and
//! introspect it. That would be wrong for the reason the rest of this project keeps
//! rediscovering: **the manifest is the authority on what the app exposes.** A description
//! generated from a live server would describe whatever that process happened to be serving —
//! a half-written manifest, a route behind a flag, a build from an hour ago — and would be
//! silently wrong the moment the two diverged. Generating from the same route table the
//! server binds makes the document and the serving **the same fact**, and it works in CI with
//! no port, no build and no network.
//!
//! "Running app" is satisfied by the document being *about* the app the manifest defines,
//! which is what `qqqai serve` will bind.
//!
//! # What the manifest cannot say, and what this does about it
//!
//! A QQQ route declares a path, a method set and a handler name. It does **not** declare
//! request or response schemas — the handler is a guest, and its interface is a WIT world
//! rather than a per-route type. So every method is emitted with **no request body schema**
//! and a **generic response**, and each operation carries `x-qqq-handler` naming the handler
//! that serves it.
//!
//! That is stated rather than papered over. An OpenAPI document that invented schemas would
//! be more useful to a code generator and **wrong** — and a client generated from it would
//! fail at runtime in a way nobody could trace back to this file. The `x-` extension is the
//! spec's own mechanism for vendor data, so the document stays valid.
//!
//! # Why 3.0 and not 3.1
//!
//! 3.1 aligns with JSON Schema 2020-12 and is the better spec. 3.0 is what the tooling
//! ecosystem actually consumes today — including the generators a user of `qqqai openapi`
//! most likely wants. The version is a **constant in one place** so the choice is visible and
//! reversible rather than scattered.

use serde::Serialize;

use qqq_cap::manifest::Server;
use qqq_core::{Error, ErrorCode, Result};

/// The `OpenAPI` version this emits.
///
/// See the module documentation for why 3.0 rather than 3.1.
pub const OPENAPI_VERSION: &str = "3.0.3";

/// An `OpenAPI` document.
///
/// Serialized with `serde_json`, and the field order here is the order a reader sees: `openapi`
/// and `info` first because that is what the spec requires and what every tool looks for.
#[derive(Debug, Clone, Serialize)]
pub struct Document {
    /// The spec version.
    pub openapi: String,
    /// Who wrote this and what it is.
    pub info: Info,
    /// The paths, keyed by the manifest's route patterns.
    pub paths: std::collections::BTreeMap<String, PathItem>,
}

/// The `info` object.
#[derive(Debug, Clone, Serialize)]
pub struct Info {
    /// The project name, from `[package]`.
    pub title: String,
    /// The project version, from `[package]`.
    pub version: String,
    /// What generated this, so a reader knows not to hand-edit it.
    pub description: String,
}

/// One path and the operations on it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PathItem {
    /// `GET`, lowercased as the spec requires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get: Option<Operation>,
    /// `POST`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post: Option<Operation>,
    /// `PUT`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub put: Option<Operation>,
    /// `PATCH`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<Operation>,
    /// `DELETE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<Operation>,
    /// `HEAD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<Operation>,
    /// `OPTIONS`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Operation>,
    /// `TRACE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<Operation>,
}

impl PathItem {
    /// Whether any operation is present.
    ///
    /// Used by a test to assert that a manifest method the spec cannot express is **not
    /// silently dropped**: a path with no operations is a path the document claims exists and
    /// describes nothing about, and that is worth knowing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.get.is_none()
            && self.post.is_none()
            && self.put.is_none()
            && self.patch.is_none()
            && self.delete.is_none()
            && self.head.is_none()
            && self.options.is_none()
            && self.trace.is_none()
    }

    /// Set the operation for a method, or `None` if the method has no place in the spec.
    fn set(&mut self, method: &str, op: Operation) -> bool {
        let slot = match method {
            "GET" => &mut self.get,
            "POST" => &mut self.post,
            "PUT" => &mut self.put,
            "PATCH" => &mut self.patch,
            "DELETE" => &mut self.delete,
            "HEAD" => &mut self.head,
            "OPTIONS" => &mut self.options,
            "TRACE" => &mut self.trace,
            _ => return false,
        };
        *slot = Some(op);
        true
    }
}

/// One operation.
#[derive(Debug, Clone, Serialize)]
pub struct Operation {
    /// The operation id, derived from the handler name.
    ///
    /// Derived rather than declared because the manifest has no place to declare one, and a
    /// code generator needs *something* — an operation with no id cannot be turned into a
    /// method. Made unique by appending the method when two routes share a handler, which is
    /// legal in the manifest and would otherwise produce a document whose generated client has
    /// two methods with one name.
    #[serde(rename = "operationId")]
    pub operation_id: String,
    /// The handler that serves this, as a vendor extension.
    ///
    /// `x-` is the spec's own mechanism for data it does not model, so the document stays
    /// valid while carrying the one fact a QQQ reader actually needs: which guest function
    /// answers this route.
    #[serde(rename = "x-qqq-handler")]
    pub handler: String,
    /// The responses.
    pub responses: std::collections::BTreeMap<String, Response>,
    /// The path parameters, extracted from the route pattern.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<Parameter>,
}

/// One response.
#[derive(Debug, Clone, Serialize)]
pub struct Response {
    /// What the status means.
    pub description: String,
}

/// A path parameter.
#[derive(Debug, Clone, Serialize)]
pub struct Parameter {
    /// The parameter name, as it appears in the pattern.
    pub name: String,
    /// Always `path` — QQQ has no other kind yet.
    pub r#in: String,
    /// Whether it must be supplied. Always `true` for a path parameter.
    pub required: bool,
    /// The parameter's type.
    pub schema: Schema,
}

/// A JSON Schema fragment, as small as this generator needs.
#[derive(Debug, Clone, Serialize)]
pub struct Schema {
    /// The type.
    pub r#type: String,
}

/// Build a document from a manifest's server section.
///
/// # Errors
///
/// `QQQ-7001` when a route's path cannot be expressed as an `OpenAPI` path. See
/// [`path_template`] for what that means and why it is an error rather than a silent skip.
pub fn document(title: &str, version: &str, server: &Server) -> Result<Document> {
    let mut paths: std::collections::BTreeMap<String, PathItem> = std::collections::BTreeMap::new();
    // Handlers seen so far, so a second route sharing one gets a distinct operation id.
    let mut handler_uses: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();

    for route in &server.routes {
        let openapi_path = path_template(&route.path)?;
        let item = paths.entry(openapi_path).or_default();

        for method in &route.methods {
            let upper = method.to_ascii_uppercase();
            let uses = handler_uses.entry(route.handler.clone()).or_insert(0);
            *uses += 1;
            // Unique by construction: the first use keeps the bare name, later ones are
            // suffixed. Derived from the handler because the manifest declares no id, and a
            // generator needs one to emit a method.
            let operation_id = if *uses == 1 {
                route.handler.clone()
            } else {
                format!("{}_{}", route.handler, upper.to_lowercase())
            };

            let operation = Operation {
                operation_id,
                handler: route.handler.clone(),
                // One response per operation, and its description says what the manifest
                // knows -- which is nothing about the body. Stated rather than invented.
                responses: std::collections::BTreeMap::from([(
                    "200".to_owned(),
                    Response {
                        description: "Served by the QQQ guest handler. The response body is \
                                      not described because the manifest does not declare one."
                            .to_owned(),
                    },
                )]),
                parameters: parameters_of(&route.path),
            };

            if !item.set(&upper, operation) {
                // A method the OpenAPI spec has no slot for. `CONNECT` is the only manifest
                // method in that position, and it is refused rather than dropped: a document
                // that silently omits an exposed method is a document that understates the
                // surface, which is the failure mode this project treats as worse than an
                // error.
                return Err(Error::new(
                    ErrorCode::McpArgumentInvalid,
                    format!(
                        "route `{}` exposes `{upper}`, which OpenAPI 3.0 has no operation for",
                        route.path
                    ),
                )
                .with_remediation(
                    "remove the method from the route, or describe it outside OpenAPI",
                ));
            }
        }
    }

    Ok(Document {
        openapi: OPENAPI_VERSION.to_owned(),
        info: Info {
            title: title.to_owned(),
            version: version.to_owned(),
            description:
                "Generated by `qqqai openapi` from the manifest's route table. The manifest \
                 is the authority on what this app exposes, so this document and the running \
                 server describe the same routes by construction. Handlers are named with \
                 `x-qqq-handler`; request and response bodies are not described because a QQQ \
                 route declares no schema for them."
                    .to_owned(),
        },
        paths,
    })
}

/// Render a QQQ route pattern as an `OpenAPI` path template.
///
/// # The conversion
///
/// QQQ writes a parameter as `:name`; `OpenAPI` writes it as `{name}`. That is the whole
/// difference for a well-formed pattern.
///
/// # Errors
///
/// A pattern this cannot express, named in the message. In practice that is a pattern with a
/// **brace**, which QQQ's own router rejects at parse time as a literal character — so this is
/// unreachable through a validated manifest and exists because the function is public and a
/// caller could hand it anything. Refusing beats emitting a path the spec reads as a malformed
/// template.
pub fn path_template(pattern: &str) -> Result<String> {
    // A **brace** in the source pattern cannot be passed through: the spec would read it as a
    // template, so `/a{b}` would become a path with an undeclared parameter. QQQ's router
    // rejects a brace at parse time, so this is unreachable through a validated manifest --
    // checked anyway because refusing beats emitting a malformed template.
    if pattern.contains('{') || pattern.contains('}') {
        return Err(Error::new(
            ErrorCode::McpArgumentInvalid,
            format!("route `{pattern}` contains a brace, which OpenAPI would read as a template"),
        )
        .with_remediation("a literal brace is not expressible as an OpenAPI path"));
    }

    // Split, transform each segment, rejoin. A first version assembled the string
    // incrementally and pushed a separator for the empty leading segment **and** for the
    // prefix check, so `/orders` came out as `//orders` -- and every test that looked up a
    // path by its manifest spelling failed with a key that looked almost right. Transforming
    // segments and rejoining cannot produce that class of error, because there is no
    // accumulator to get wrong.
    let mut out = String::with_capacity(pattern.len() + 8);
    for (i, segment) in pattern.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        match segment.strip_prefix(':') {
            Some(name) => {
                if name.is_empty() {
                    return Err(Error::new(
                        ErrorCode::McpArgumentInvalid,
                        format!("route `{pattern}` has an empty parameter name"),
                    )
                    .with_remediation("write the parameter as `:name`"));
                }
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
            None => out.push_str(segment),
        }
    }
    Ok(out)
}

/// The path parameters a pattern declares.
///
/// Every one is a `string`, because that is all the manifest knows: it declares no types for
/// its parameters, and inventing `integer` for a segment that happens to look numeric would be
/// wrong for the segment that does not. The spec requires a path parameter to be declared, so
/// the declaration is the honest minimum.
#[must_use]
pub fn parameters_of(pattern: &str) -> Vec<Parameter> {
    pattern
        .split('/')
        .filter_map(|s| s.strip_prefix(':'))
        .filter(|n| !n.is_empty())
        .map(|name| Parameter {
            name: name.to_owned(),
            r#in: "path".to_owned(),
            required: true,
            schema: Schema {
                r#type: "string".to_owned(),
            },
        })
        .collect()
}

/// Render a document as pretty JSON, with a trailing newline.
///
/// Pretty rather than compact, and a newline rather than none: this is a file a human reads and
/// a `git diff` shows. A compact document diffs as one changed line, and a file with no
/// trailing newline is the thing every POSIX tool complains about.
#[must_use]
pub fn to_json(doc: &Document) -> String {
    let mut s = serde_json::to_string_pretty(doc).unwrap_or_else(|_| "{}".to_owned());
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server section from a TOML body, as the other modules in this crate do it.
    fn server(body: &str) -> Server {
        let m = qqq_cap::manifest::Manifest::parse(&format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n\n[server]\n{body}\n"
        ))
        .expect("the fixture must parse");
        m.server
    }

    fn doc(body: &str) -> Document {
        document("probe", "0.1.0", &server(body)).expect("generates")
    }

    // -- the shape the spec requires ---------------------------------------

    /// **The document declares the version, the info, and the paths.**
    ///
    /// The three things every `OpenAPI` tool looks for first. A document missing any is not
    /// merely incomplete — most tools refuse it outright.
    #[test]
    fn the_document_has_the_required_top_level_keys() {
        let d = doc("routes = [{ path = \"/orders\", methods = [\"GET\"], handler = \"list\" }]");

        assert_eq!(d.openapi, OPENAPI_VERSION);
        assert_eq!(d.info.title, "probe");
        assert_eq!(d.info.version, "0.1.0");
        assert!(d.info.description.contains("qqqai openapi"));
        assert!(d.paths.contains_key("/orders"));
    }

    /// **A `:param` becomes an `OpenAPI` `{param}`.**
    ///
    /// The one syntactic difference between the two notations. Getting it wrong produces a
    /// path the spec reads as a literal, so a client generated from it would request the
    /// string `:id` rather than a value.
    #[test]
    fn a_parameter_becomes_a_template() {
        assert_eq!(path_template("/orders/:id").expect("valid"), "/orders/{id}");
        assert_eq!(path_template("/").expect("valid"), "/");
        assert_eq!(path_template("/orders").expect("valid"), "/orders");
        assert_eq!(path_template("/a/:b/c/:d").expect("valid"), "/a/{b}/c/{d}");
    }

    /// **The declared parameters are emitted, because the spec requires them.**
    ///
    /// A path template with an undeclared parameter is an **invalid** document, and the
    /// failure appears in the consumer's tool rather than here — which is exactly the kind of
    /// distance this project keeps finding expensive.
    #[test]
    fn path_parameters_are_declared() {
        let d =
            doc("routes = [{ path = \"/orders/:id\", methods = [\"GET\"], handler = \"get\" }]");
        let item = d.paths.get("/orders/{id}").expect("the templated path");
        let op = item.get.as_ref().expect("a GET");

        assert_eq!(op.parameters.len(), 1);
        let p = &op.parameters[0];
        assert_eq!(p.name, "id");
        assert_eq!(p.r#in, "path");
        assert!(
            p.required,
            "a path parameter must be required, or the document is invalid"
        );
        assert_eq!(p.schema.r#type, "string");
    }

    /// A route with no parameters declares none.
    #[test]
    fn a_route_without_parameters_declares_none() {
        let d = doc("routes = [{ path = \"/orders\", methods = [\"GET\"], handler = \"list\" }]");
        let op = d.paths["/orders"].get.as_ref().expect("a GET");
        assert!(op.parameters.is_empty());
    }

    // -- methods -----------------------------------------------------------

    /// Every method the spec has a slot for is emitted in that slot.
    #[test]
    fn every_expressed_method_lands_in_its_slot() {
        let d = doc(r#"routes = [
                { path = "/a", methods = ["GET"], handler = "h1" },
                { path = "/b", methods = ["POST"], handler = "h2" },
                { path = "/c", methods = ["PUT"], handler = "h3" },
                { path = "/d", methods = ["PATCH"], handler = "h4" },
                { path = "/e", methods = ["DELETE"], handler = "h5" },
                { path = "/f", methods = ["HEAD"], handler = "h6" },
                { path = "/g", methods = ["OPTIONS"], handler = "h7" },
                { path = "/h", methods = ["TRACE"], handler = "h8" },
            ]"#);

        assert!(d.paths["/a"].get.is_some());
        assert!(d.paths["/b"].post.is_some());
        assert!(d.paths["/c"].put.is_some());
        assert!(d.paths["/d"].patch.is_some());
        assert!(d.paths["/e"].delete.is_some());
        assert!(d.paths["/f"].head.is_some());
        assert!(d.paths["/g"].options.is_some());
        assert!(d.paths["/h"].trace.is_some());
    }

    /// **A method the spec cannot express is refused, not silently dropped.**
    ///
    /// `CONNECT` is exposed by the manifest's method set and has no `OpenAPI` operation. A
    /// document that omitted it would **understate the surface** — the app answers `CONNECT`
    /// on that path and the document says nothing — and understating an exposed surface is the
    /// failure mode this project treats as worse than an error. So it is an error.
    #[test]
    fn an_inexpressible_method_is_refused() {
        let s =
            server("routes = [{ path = \"/tunnel\", methods = [\"CONNECT\"], handler = \"h\" }]");
        let err = document("probe", "0.1.0", &s).expect_err("CONNECT is not expressible");
        let text = format!("{err}");
        assert!(text.contains("CONNECT"), "the method must be named: {text}");
        assert!(
            text.contains("/tunnel"),
            "and the route, so an operator can find it: {text}"
        );
    }

    /// Two methods on one path share a `PathItem`.
    #[test]
    fn two_methods_share_a_path_item() {
        let d = doc(
            "routes = [{ path = \"/orders\", methods = [\"GET\", \"POST\"], handler = \"orders\" }]",
        );
        assert_eq!(d.paths.len(), 1);
        let item = &d.paths["/orders"];
        assert!(item.get.is_some(), "GET");
        assert!(item.post.is_some(), "POST");
    }

    // -- operation ids -----------------------------------------------------

    /// **Two routes sharing a handler get distinct operation ids.**
    ///
    /// A manifest may route several paths to one handler — that is ordinary — and a code
    /// generator needs an id per operation. Duplicated ids produce a client with two methods
    /// of one name, which either fails to compile or silently overwrites one.
    #[test]
    fn operations_sharing_a_handler_get_distinct_ids() {
        let d = doc(r#"routes = [
                { path = "/orders", methods = ["GET"], handler = "orders" },
                { path = "/orders/:id", methods = ["GET"], handler = "orders" },
            ]"#);
        let a = d.paths["/orders"].get.as_ref().expect("GET");
        let b = d.paths["/orders/{id}"].get.as_ref().expect("GET");

        assert_ne!(
            a.operation_id, b.operation_id,
            "two operations must not share an id"
        );
        assert_eq!(a.operation_id, "orders", "the first keeps the bare name");
        assert_eq!(b.operation_id, "orders_get");
    }

    /// The operation id is a usable identifier.
    ///
    /// A code generator turns it into a method name, so it must not contain a path separator or
    /// a brace. Checked on every operation of a document with an awkward handler name, because
    /// the derivation is string arithmetic and string arithmetic is where this goes wrong.
    #[test]
    fn operation_ids_are_plain_identifiers() {
        let d = doc(r#"routes = [
                { path = "/a/:id", methods = ["GET"], handler = "list" },
                { path = "/b/:id", methods = ["POST"], handler = "list" },
            ]"#);
        for (path, item) in &d.paths {
            let op = item
                .get
                .as_ref()
                .or(item.post.as_ref())
                .expect("an operation");
            assert!(
                !op.operation_id.contains('/'),
                "{path}: an id must not contain a separator: {}",
                op.operation_id
            );
            assert!(
                !op.operation_id.contains('{') && !op.operation_id.contains('}'),
                "{path}: an id must not contain a brace: {}",
                op.operation_id
            );
            assert!(
                !op.operation_id.is_empty(),
                "{path}: an id must not be empty"
            );
        }
    }

    // -- honesty about what is not described --------------------------------

    /// **Every operation names its handler, and none invents a schema.**
    ///
    /// The document must be *honest*: the manifest declares no request or response schema, so
    /// the document must not contain one. An invented schema would generate a client that
    /// fails at runtime in a way nobody can trace back to this file.
    #[test]
    fn the_document_invents_no_schemas() {
        let d = doc("routes = [{ path = \"/orders\", methods = [\"GET\"], handler = \"list\" }]");
        let op = d.paths["/orders"].get.as_ref().expect("a GET");

        assert_eq!(op.handler, "list", "the handler is named");
        assert!(
            op.parameters.is_empty(),
            "no parameters, because the manifest declares none"
        );
        let json = to_json(&d);
        assert!(
            !json.contains("requestBody"),
            "the manifest declares no request body, so none may be emitted:\n{json}"
        );
        assert!(
            json.contains("x-qqq-handler"),
            "the handler must be carried as a vendor extension:\n{json}"
        );
        assert!(
            json.contains("does not declare one"),
            "the response description must say what the manifest knows, which is nothing"
        );
    }

    /// The rendering is valid JSON with a trailing newline.
    #[test]
    fn the_rendering_is_json_with_a_final_newline() {
        let d = doc("routes = [{ path = \"/orders\", methods = [\"GET\"], handler = \"list\" }]");
        let json = to_json(&d);

        assert!(
            json.ends_with('\n'),
            "a file a human edits ends with a newline"
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must parse");
        assert_eq!(parsed["openapi"], OPENAPI_VERSION);
        assert_eq!(parsed["info"]["title"], "probe");
        assert!(parsed["paths"]["/orders"]["get"].is_object());
    }

    /// An empty server section produces a document with no paths.
    ///
    /// The format requires a `paths` object even when it is empty, so the key must be present
    /// and empty rather than absent.
    #[test]
    fn an_empty_section_has_an_empty_paths_object() {
        let d = doc("routes = []");
        assert!(d.paths.is_empty());
        let json = to_json(&d);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must parse");
        assert!(
            parsed["paths"].is_object(),
            "`paths` must be present even when empty:\n{json}"
        );
    }

    // -- determinism -------------------------------------------------------

    /// The same manifest produces byte-identical output. §10.5.
    #[test]
    fn generation_is_deterministic() {
        let body = r#"routes = [
            { path = "/z", methods = ["GET"], handler = "z" },
            { path = "/a", methods = ["POST"], handler = "a" },
            { path = "/m/:id", methods = ["GET", "DELETE"], handler = "m" },
        ]"#;
        let first = to_json(&doc(body));
        for _ in 0..20 {
            assert_eq!(to_json(&doc(body)), first);
        }
        // And the paths are **sorted**, because a `BTreeMap` is what makes that true. A
        // manifest order that leaked into the output would make two equivalent manifests
        // produce different files, and a diff of them would show nothing meaningful.
        let a = first.find("\"/a\"").expect("/a present");
        let m = first.find("\"/m/{id}\"").expect("/m present");
        let z = first.find("\"/z\"").expect("/z present");
        assert!(
            a < m && m < z,
            "paths must be sorted, not in manifest order"
        );
    }

    /// The module's version constant is the one the document carries.
    #[test]
    fn the_version_constant_is_used() {
        assert_eq!(OPENAPI_VERSION, "3.0.3");
        assert_eq!(doc("routes = []").openapi, OPENAPI_VERSION);
    }
}
