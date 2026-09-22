// SPDX-License-Identifier: Apache-2.0

//! The orders reference application — `SRV-018`.
//!
//! # What this app is for
//!
//! `SRV-018` calls it "the reference application used by all benchmarks". It is
//! the single artifact every claim in `§9.1` and every number in `§9.2` is
//! measured against, so it has three jobs and they pull in different directions:
//!
//! 1. **Be a real application.** If it is a toy, the benchmark measures the toy.
//!    So it parses a body, validates it, keeps order state across requests, and
//!    returns a `Location` header, real status codes and real error shapes.
//! 2. **Exercise each §9.1 row honestly.** The ten benchmarks are not ten
//!    different servers; they are ten workloads driven through *this* app. Each
//!    route below is the work that row names, with nothing padded and nothing
//!    elided — a `db` benchmark that does not do I/O-shaped work would make the
//!    budget in §9.2 meaningless.
//! 3. **Stay legible.** This file is documentation-of-record for how a QQQ app is
//!    written. A reader should be able to copy its shape.
//!
//! # Why nothing here comes from crates.io
//!
//! JSON, SHA-256 and the prime sieve are implemented in-tree (`json`, `hash`,
//! `compute`). That is a deliberate and slightly uncomfortable choice, because
//! hand-writing a SHA-256 is normally the wrong call.
//!
//! The reason is that this app is the **measurement instrument**. `§9.1` claims
//! QQQ is "far ahead" on `crypto` and `cpu`; if the guest's arithmetic came from a
//! dependency, the benchmark would be measuring that dependency's optimisation
//! budget, not QQQ's ABI and codegen. Pinning the work in-tree means a change in
//! the numbers is a change in *QQQ*, which is the only property that makes the
//! suite worth publishing. `§9.1` also requires the suite be "harder to game than
//! the ones we are compared against" — a reference app with a dependency tree has
//! an unbounded answer to "what was actually measured".
//!
//! The cost is honest and stated: these are correct-but-unoptimised
//! implementations. That is the right bias for a *baseline* — the first published
//! number should be the floor, not the ceiling.
//!
//! # Why state lives in a `static` and not in a host capability
//!
//! The `db` workload needs order state that survives across requests. The
//! Proposal's answer is `capabilities.sql`, and this app will use it once the host
//! side lands — but `SRV-018` cannot wait for it, and a benchmark that measures a
//! *missing* host feature measures nothing.
//!
//! So the store is in-guest. This is stated rather than hidden because it changes
//! what `db` measures: it currently measures *the ABI cost of a stateful
//! read-modify-write*, not the cost of a Postgres round trip. That distinction is
//! recorded in the route table below and must travel with any published number.

wit_bindgen::generate!({
    world: "app",
    path: "wit",
    // The export references `qqq:http/http`'s `request`/`response` types, so the
    // macro must bind that interface too. Without it the refusal is
    // "missing `with` mapping for the key `qqq:http/http@1.0.0`", and that message
    // names `generate_all` as one of its three accepted answers (`§O-147`).
    generate_all,
});

mod compute;
mod hash;
mod json;
mod orders;
mod router;

use exports::qqq::http::incoming_handler::{Guest, HttpError, Request, Response};

/// The **exported** interface's module, re-exported for the sibling modules.
///
/// # Why these aliases exist, and how the paths were found
///
/// `wit_bindgen::generate!` emits its bindings into **this** module, the crate root
/// where the macro is invoked. A sibling module cannot write `exports::qqq::…` with
/// no leading `crate::`, because a path's first segment resolves against that
/// module's own items — the error is `cannot find module or crate 'exports' in this
/// scope`, and it appears at every use site rather than once.
///
/// The generated layout is **not** uniform, and this is the part that cost several
/// build cycles to learn. `generate_all` emits two things:
///
/// * `exports::qqq::http::incoming_handler` — the world's *export*. This re-exports
///   exactly what the WIT's `use http.{request, response, http-error}` names, so it
///   holds `Guest`, `Request`, `Response` and `HttpError` and **nothing else**.
/// * `qqq::http::http` — the `qqq:http/http` interface itself, at the **crate
///   root**, because the world's export references its types and so the interface is
///   generated as a non-exported module as well. `Header` and `Method` live here.
///
/// Guessing at this shape is not worth the cycles: the layout is discoverable with
/// `cargo check` and a one-line type alias per candidate (see
/// `QQQ-Observations-and-Memories.md §O-153`). Note also that **there is no
/// `HttpErrorKind`** — WIT's `http-error` is a `variant`, so wit-bindgen emits one
/// Rust enum named `HttpError` whose variants are the cases.
///
/// These aliases give every module one stable spelling, and keep the generated
/// paths in a single place so a change to the world's package name is a one-line
/// edit rather than a search across five files.
pub mod exports_ih {
    pub use crate::exports::qqq::http::incoming_handler;
}

/// The `qqq:http` interface's own types, which live at the crate root.
pub mod root_http {
    pub use crate::qqq::http::http::{Header, Method, Request, Response};
}

/// The `qqq:http` request type, as the exported handler receives it.
pub use exports_ih::incoming_handler::Request as GuestRequest;
/// The `qqq:http` response type, as the exported handler returns it.
pub use exports_ih::incoming_handler::Response as GuestResponse;
/// The `qqq:http` error type. A `variant` in WIT, so one Rust enum of cases.
pub use exports_ih::incoming_handler::HttpError as GuestHttpError;

/// The application component.
///
/// `router::route` is the only place that decides what a path means; everything
/// below it is a workload implementation. Keeping the dispatch in one function is
/// what lets the route table and the benchmark list stay verifiably the same set —
/// see `router`'s docs, and its test that reads §9.1.

struct Component;

impl Guest for Component {
    fn handle(req: Request) -> Result<Response, HttpError> {
        Ok(router::route(&req))
    }
}

export!(Component);

#[cfg(test)]
mod tests {
    use super::*;

    /// The world's export is what `qqq-host::invoke` resolves, and the strings
    /// live in `qqq-host` as constants. This test cannot import them — this crate
    /// is a *guest* and does not depend on the host — so it asserts the shape the
    /// constants encode: an interface with a `handle` function returning a
    /// result. If this ever changes, the host's two-step lookup breaks, and the
    /// single-step failure mode is `None`, which a careless caller serves as an
    /// empty response (`§O-148`).
    #[test]
    fn the_component_implements_the_exported_handler() {
        let r = Component::handle(Request {
            method: crate::root_http::Method::Get,
            url: "https://orders.test/healthz".to_owned(),
            headers: vec![],
            body: None,
        });
        assert!(r.is_ok(), "the handler must answer a routable request");
    }
}
