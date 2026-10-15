// SPDX-License-Identifier: Apache-2.0

//! The `qqq:http` host implementation — the interface's **import** side.
//!
//! # Why this module is the last link in the guest chain
//!
//! A QQQ guest imports `qqq:http/http@1.0.0` and exports
//! `qqq:http/incoming-handler@1.0.0`. The export is what the host calls
//! ([`crate::invoke`] resolves it). The **import** is what this module supplies, and
//! it is required even by a guest that never calls it:
//!
//! ```text
//! $ wasm-tools print target/qqq/orders-api.component.wasm
//!   (import "qqq:http/http@1.0.0" (instance $qqq:http/http@1.0.0 (type ...)))
//!   (alias export $qqq:http/http@1.0.0 "request"    (type $request))
//!   (alias export $qqq:http/http@1.0.0 "response"   (type $response))
//!   (alias export $qqq:http/http@1.0.0 "http-error" (type $http-error))
//!   (alias export $qqq:http/http@1.0.0 "method"     (type $method))
//!   (alias export $qqq:http/http@1.0.0 "header"     (type $header))
//! ```
//!
//! The guest aliases those types because its own **export** mentions them, and the
//! component model has no way to say "I need your type names but not your functions".
//! So the import instance must exist at instantiation regardless of whether `send` is
//! ever called. Without it:
//!
//! ```text
//! error[QQQ-6004]: capability `http.server` is granted but `qqq:http@1.0.0`
//!                  has no host implementation
//! ```
//!
//! # Why `bindgen!` and not `func_wrap`
//!
//! `qqq:http/http`'s functions take and return **records** (`request`, `response`) and
//! a **variant** (`http-error`). `Linker::func_wrap` binds only functions whose
//! parameters are primitives, because a record needs the canonical ABI's lifting and
//! lowering. The other host modules (`host_clock`, `host_crypto`) use `func_wrap`
//! legitimately — their interfaces are flat. This one cannot, which is why it is the
//! only host module with generated bindings.
//!
//! # The binding invocation, and how its shape was established
//!
//! `wit/qqq-http.wit` declares `package qqq:http@1.0.0` with two **interfaces** and
//! **no world**, so `bindgen!`'s `world:` option cannot be used — there is no world to
//! name. The macro's `interfaces:` option synthesizes one:
//!
//! ```text
//! package wasmtime:component-macro-synthesized;
//! world interfaces { <the interfaces string> }
//! ```
//!
//! so the value must be **WIT items**, each terminated by `;`. Every part of that was
//! probed rather than guessed; `§O-154` records the wrong attempts it took, including
//! two where the probe was measuring its own mistake instead of the macro's behaviour.
//!
//! # The security argument
//!
//! `send` is the outbound HTTP capability, so it is the one host function in QQQ that
//! could make the runtime contact an arbitrary destination. Two independent checks
//! govern it, in the order an attacker would have to defeat them:
//!
//! 1. **Registration is conditional.** [`register`] adds the interface only when
//!    `http.server` or `http.client` is granted, so an ungranted guest's import is
//!    *absent* rather than *denied* — the property `linker.rs` documents for every
//!    other interface, and the whole reason the linker is built from grants alone.
//! 2. **The call re-checks.** Every body consults the store's grant set again, because
//!    a mis-built linker is a security hole while a mis-placed check is only an
//!    annoyance. `linker::recheck`'s documentation gives that asymmetry.
//!
//! `send` itself is **wired** (`I-01`, Phase 2): grant re-check, then
//! `SEC-009` budget charge, then the connector (`vet` → open →
//! `exchange` → audit) over the store's egress policy, with one audit
//! row per call. The loud refusal stays for every path that is not
//! fully wired: no grant, no budget, an unmappable method, and a
//! deny-all policy all refuse without a socket opening.

use qqq_cap::capability::Capability;
use qqq_cap::resolve::GrantSet;
use qqq_core::{Error, ErrorCode};
use wasmtime::component::{HasSelf, Linker};

use crate::linker::StoreData;

/// The interface name, as the component model spells it.
///
/// A constant rather than a literal at each site so `qqqai inspect`, the linker and
/// this module cannot disagree about the string a guest imports. The value was read
/// from `wasm-tools component wit` on a real guest, not chosen.
pub const INTERFACE: &str = "qqq:http/http@1.0.0";

/// The generated bindings.
///
/// # Why the path reaches up two levels
///
/// `bindgen!` resolves `path:` relative to **`CARGO_MANIFEST_DIR`** (the crate root),
/// not to this file, so from `crates/qqq-host/` the repository's WIT is
/// `../../wit/qqq-http.wit`.
///
/// The **file**, not the directory: `wit/` holds sixteen standalone `.wit` files,
/// each declaring its own package, and WIT reads a directory of `.wit` files as
/// **one** package spread across them. Pointing at the directory therefore fails with
/// *"package identifier `qqq:ai@1.0.0` does not match previous package name of
/// `qqq:agent@1.0.0`"*. This is the same rule `§O-147` records from the guest side,
/// where a world and its dependencies cannot share a directory either.
///
/// `qqq-http.wit` needs no `deps/`: it declares `package qqq:http@1.0.0` and imports
/// nothing. The guest's `wit/app/app.wit` *does* need `deps/qqq-http/`, because it
/// imports this package -- so the two directories differ for a reason, not by
/// accident.
///
/// `qqq-abi` embeds the same file with `include_str!("../../../wit/qqq-http.wit")`,
/// because `include_str!` *does* resolve relative to the source file, so
/// both crates read **one** source of truth. A second copy under `qqq-host/wit/` would
/// be a second answer to "what is `qqq:http`", and the two would drift — the failure
/// `qqq-abi`'s module docs record for the interface registry.
///
/// # Why the invocation is terminated with `;`
///
/// `bindgen!` expands to items, so in statement position it needs a terminator when
/// anything follows it. Measured in both directions: without the `;` and with items
/// following, the error is *"macros that expand to items must be delimited with braces
/// or followed by a semicolon"*; with the `;` and nothing following, it is *"expected
/// item, found `;`"*.
mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit/qqq-http.wit",
        // WIT items, not a bare interface name: the substitution is verbatim into a
        // synthesized world, so omitting the `;` yields a WIT parse error.
        interfaces: "import qqq:http/http@1.0.0;",
    });
}

// Only what this crate actually names. `Header` and `Method` are part of the
// interface's public type surface, but nothing here consumes them -- a caller building a
// `Request` gets them from the generated module directly, and `qqqai inspect` reads the
// WIT rather than this crate. Re-exporting a type nobody uses is speculative API, so
// they are not re-exported; the tests import them explicitly.
pub use bindings::qqq::http::http::{HttpError, Request, Response};

/// The authority reported to a guest that was not granted a server.
///
/// A visible sentinel rather than an empty string, so a guest's own logs show why the
/// value is unusable. Empty would be indistinguishable from a server bound on an empty
/// host, and the two are very different facts.
pub const UNGRANTED_AUTHORITY: &str = "<qqq:http.server not granted>";

/// The host implementation of `qqq:http/http`.
///
/// # Why the methods take `&mut self`
///
/// `bindgen!`'s host trait uses `&mut self` — verified from the compiler, which
/// reported `expected signature fn(&mut St, Request) -> Result<Response, HttpError>` —
/// **not** the `StoreContextMut` that `host_clock` and `host_crypto` use. That
/// difference is a property of the generated trait rather than a choice: a `func_wrap`
/// closure receives a store context, while a `bindgen!` host trait is implemented on
/// the store's data type directly.
///
/// The consequence is that the call-time grant re-check reads `self`, which is the same
/// data the linker was built from. So the two checks are independent in mechanism but
/// not in source, and that is stated rather than glossed: a guest cannot reach `send`
/// at all unless the interface was registered, which already required the grant.
impl bindings::qqq::http::http::Host for StoreData {
    /// `send` — the outbound HTTP capability, wired end to end.
    ///
    /// Grant re-check, then `SEC-009` budget charge, then the
    /// connector over `StoreData::egress`: `vet` → open → `exchange`
    /// → audit, with exactly one audit row per call in
    /// `egress_audit`. The sync/async bridge (scoped thread, fresh
    /// current-thread runtime) assumes no ambient runtime, so the
    /// call works from sync tests, the blocking pool, and async
    /// callers alike. Unwired paths stay loud: no grant, no budget,
    /// an unmappable method, and deny-all policy all refuse without
    /// a socket opening.
    ///
    /// # The order of the two refusals, and why it matters
    ///
    /// The **budget is charged before the destination is considered**, so a guest cannot
    /// learn whether a host is allowlisted by exhausting its budget and observing which
    /// error it gets. Charging first also means a refusal still spends budget, which is
    /// the correct reading of `SEC-009`: the budget bounds *attempts*, not successes.
    ///
    /// # Why the URL is not echoed into the error
    ///
    /// The refusal could name what was attempted, and that would be useful. It is not
    /// done because a URL routinely carries a credential — a presigned query string, or
    /// userinfo in the authority — and this value reaches an access log. Only the **host**
    /// portion would be safe, since that is what an allowlist matches on, and extracting
    /// it here without a parser would be exactly the "trusting the authority section"
    /// hazard `qqq-http.wit` warns about.
    fn send(&mut self, req: Request) -> std::result::Result<Response, HttpError> {
        // The call-time re-check, before anything reads `req`.
        if !self.grants.grants(Capability::HttpClient) {
            return Err(HttpError::HostNotAllowed);
        }

        // `SEC-009`'s budget. A store assembled by `Default` or `new` has a budget of
        // **zero**, and zero means "no outbound effects declared" rather than
        // "unlimited" — the reading `StoreData`'s own documentation insists on, and the
        // one that makes an undeclared app unable to phone home.
        if self.subrequests.charge().is_refused() {
            return Err(HttpError::SubrequestLimitExceeded);
        }

        // The bridge to the async connector. `send` is sync (the `bindgen!`
        // host trait says so) while `egress::request` is async, and the
        // guest may be driven from any runtime context — sync tests, the
        // blocking pool `dispatch_off_thread` uses, or an async caller.
        // A scoped thread running a fresh current-thread runtime makes
        // no ambient assumptions: it works under every one, at the cost
        // of a thread spawn per call (microseconds against network
        // milliseconds — remeasure before "optimising" this into a
        // shared pool, which would be ambient state). Timeouts live
        // inside the future (`Limits`), so a stuck peer cannot hang
        // the join beyond them.
        //
        // The runtime is shut down explicitly with a zero timeout
        // rather than dropped: dropping it would join the blocking
        // pool, where a stalled system DNS lookup (`spawn_blocking`
        // `getaddrinfo`, uncancellable) can outlive every connector
        // timeout and hang the join with it. `shutdown_background`
        // detaches instead — the call still fails closed at
        // `total_timeout`, and the leaked lookup dies with the OS
        // resolver timeout, bounded by the subrequest budget's rate
        // limit. Panics resume rather than mapping to
        // `connection-failed`: the F-01 abort guard kills a panicking
        // host call anyway, and under test unwind a masked panic
        // would turn a host bug into a green-looking refusal.
        let transport = crate::egress::SystemTransport;
        let resolver = crate::egress::SystemResolver;
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return Err(HttpError::ConnectionFailed);
                };
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    runtime.block_on(self.send_via(req, &transport, &resolver))
                }));
                runtime.shutdown_background();
                match outcome {
                    Ok(result) => result,
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            });
            // A scoped-thread panic outside the guarded future is a host
            // bug, not a network failure: resume it loud rather than
            // mapping to `connection-failed` like the old fallback did.
            match handle.join() {
                Ok(result) => result,
                Err(payload) => std::panic::resume_unwind(payload),
            }
        })
    }

    /// `incoming-authority` — the host and port this request arrived on.
    ///
    /// # Why this cannot fail, and why the WIT is right about that
    ///
    /// The WIT gives this function no error type, which looks like an omission until one
    /// notices what it reports: the authority the **server bound**, which is
    /// configuration rather than a runtime condition. `qqq-http.wit` explains why a guest
    /// wants it — to adapt to virtual hosts without parsing a `Host` header that is
    /// client-controlled — and `GuestApp`'s module docs make the same point from the
    /// other side.
    ///
    /// The only refusal available is for a caller that was never granted a server, and
    /// that is a **programming error** rather than a condition: a guest calling this
    /// without `http.server` has violated its manifest. It gets [`UNGRANTED_AUTHORITY`],
    /// a sentinel rather than a panic, because a panic inside a host call unwinds through
    /// Wasmtime's frames toward the F-01 abort guard — the failure
    /// `guard.rs` exists to contain.
    fn incoming_authority(&mut self) -> (String, u16) {
        if !self.grants.grants(Capability::HttpServer) {
            return (UNGRANTED_AUTHORITY.to_owned(), 0);
        }

        let authority = self.incoming_authority.clone();
        // Split at the **last** colon: IPv6 authorities are written `[::1]:8080`, and a
        // first-colon split would cut inside the address and report host `[`.
        match authority.rsplit_once(':') {
            Some((host, port)) => match port.parse::<u16>() {
                Ok(p) => (host.to_owned(), p),
                // A bound authority whose port does not parse is a QQQ bug rather than a
                // guest error -- `ListenAddr::parse` validated it before the server
                // started. Keeping the whole string and reporting 0 leaves the value
                // diagnosable instead of panicking.
                Err(_) => (authority, 0),
            },
            // No colon at all: a default port was implied. 0 says "not stated" rather
            // than inventing 80 or 443.
            None => (authority, 0),
        }
    }
}

impl StoreData {
    /// `send` through vetting: grant and budget are the caller's job
    /// (checked in `send` before this runs); everything from the URL
    /// down is the connector's. Async so tests drive it directly
    /// against fake transports and resolvers over duplex — the sync
    /// `send` adds only the bridge.
    ///
    /// Exactly one audit row lands in `egress_audit` per call: the
    /// connector audits every path (refusal, timeout, success,
    /// failure), and rows are moved here rather than borrowed so no
    /// borrow of `self` outlives the call.
    pub(crate) async fn send_via(
        &mut self,
        req: Request,
        transport: &impl crate::egress::Transport,
        resolver: &impl crate::egress::Resolver,
    ) -> std::result::Result<Response, HttpError> {
        let egress_req = map_request(req)?;
        let mut rows = Vec::new();
        let result = crate::egress::request(
            &self.egress,
            &egress_req,
            resolver,
            &crate::egress::Limits::default(),
            transport,
            &mut |row| rows.push(row),
        )
        .await;
        self.egress_audit.extend(rows);
        result
            .map(map_response)
            .map_err(|failure| map_failure(&failure))
    }
}

/// Map the guest's request onto the connector's: method, headers,
/// body. Anything the connector cannot express is refused here,
/// before any socket opens — and before any audit row, because
/// nothing reached the connector to audit.
fn map_request(req: Request) -> std::result::Result<crate::egress::Request, HttpError> {
    use crate::egress::Method as EgressMethod;
    use bindings::qqq::http::http::Method as GuestMethod;
    let method = match req.method {
        GuestMethod::Get => EgressMethod::Get,
        GuestMethod::Head => EgressMethod::Head,
        GuestMethod::Post => EgressMethod::Post,
        // The connector speaks three methods; the WIT names nine.
        // Refusing as `invalid-url` is the least-wrong case in a
        // taxonomy with no not-implemented: the request as addressed
        // cannot be performed, and the URL is the address. Loud and
        // documented beats guessing an equivalent.
        _ => return Err(HttpError::InvalidUrl),
    };
    let mut headers = Vec::with_capacity(req.headers.len());
    for header in req.headers {
        let value = String::from_utf8(header.value).map_err(|_| HttpError::RequestTooLarge)?;
        headers.push((header.name, value));
    }
    Ok(crate::egress::Request {
        method,
        url: req.url,
        headers,
        body: req.body.unwrap_or_default(),
    })
}

/// Map the connector's response back onto the guest's types.
fn map_response(response: crate::egress::Response) -> Response {
    Response {
        status: response.status,
        headers: response
            .headers
            .into_iter()
            .map(|(name, value)| bindings::qqq::http::http::Header {
                name,
                value: value.into_bytes(),
            })
            .collect(),
        body: response.body,
    }
}

/// Map connector failures onto the guest-visible taxonomy.
///
/// Policy refusals stay `host-not-allowed` (a guest that cannot tell
/// denial from outage retries the denial forever — the WIT's own
/// warning); everything the network did wrong is
/// `connection-failed`; cap breaches keep their direction
/// (request vs. response).
fn map_failure(failure: &crate::egress::Failure) -> HttpError {
    use crate::egress::{CallError, Failure};
    match failure {
        Failure::Refused(_) | Failure::Failed(CallError::Redirect) => HttpError::HostNotAllowed,
        Failure::Failed(CallError::RequestTooLarge) => HttpError::RequestTooLarge,
        Failure::Failed(CallError::ResponseHeadTooLarge | CallError::BodyTooLarge { .. }) => {
            HttpError::ResponseTooLarge
        }
        Failure::Failed(
            CallError::Timeout | CallError::Tls | CallError::Protocol | CallError::Transport,
        ) => HttpError::ConnectionFailed,
    }
}

/// The error for a component that imports `qqq:http` without a grant.
///
/// Mirrors `linker::describe_gap` so the two read the same way in a terminal.
#[must_use]
pub fn describe_ungranted() -> Error {
    Error::new(
        ErrorCode::CapabilityDenied,
        format!(
            "`{INTERFACE}` was requested but neither `http.server` nor `http.client` is granted"
        ),
    )
    .with_context("interface", INTERFACE)
    .with_remediation(
        "add `[capabilities.http] server = true` (or `client = [...]`) to qqq.toml, \
         then run `qqqai caps` to confirm",
    )
}

/// Register `qqq:http/http`, if the grants justify it.
///
/// # Why conditional registration is the whole security argument
///
/// The linker is built from the grant set alone, so an ungranted interface is *absent*
/// rather than *denied*. That distinction is what makes "no ambient authority"
/// structural rather than a policy: a guest cannot reach a capability the manifest did
/// not name, because the code implementing it was never linked in.
///
/// # Why both `server` and `client` register it
///
/// Because the guest's **import** exists either way — a guest that only exports a
/// handler still imports `qqq:http/http` to alias its types. Registering on
/// `http.server` alone would leave a client-only app unable to instantiate, and
/// registering on neither would leave every app unable to.
///
/// # Errors
///
/// Wasmtime's own error when a definition is rejected, which indicates a QQQ bug.
pub fn register(linker: &mut Linker<StoreData>, grants: &GrantSet) -> wasmtime::Result<bool> {
    let has_server = grants.grants(Capability::HttpServer);
    let has_client = grants.grants(Capability::HttpClient);
    if !has_server && !has_client {
        return Ok(false);
    }

    // The second type parameter is Wasmtime's `HasData` wrapper, **not** the store's
    // own type. A `bindgen!` host trait is implemented on `StoreData` directly, and
    // `HasSelf<T>` is the convenience implementation Wasmtime ships for that case:
    //
    //     impl<T: ?Sized + 'static> HasData for HasSelf<T> {
    //         type Data<'a> = &'a mut T;
    //     }
    //
    // so the closure is the identity. `add_to_linker::<StoreData, StoreData>` does not
    // compile -- `StoreData` implements no `HasData`, and it should not have to, since a
    // bespoke impl would only restate what `HasSelf` already provides.
    bindings::qqq::http::http::add_to_linker::<StoreData, HasSelf<StoreData>>(linker, |s| s)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bindings::qqq::http::http::{Header, Host as _, Method};
    use qqq_cap::manifest::Manifest;

    fn engine() -> wasmtime::Engine {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        wasmtime::Engine::new(&config).expect("engine")
    }

    fn linker() -> Linker<StoreData> {
        Linker::new(&engine())
    }

    fn grants_from(toml: &str) -> GrantSet {
        GrantSet::from_manifest(&Manifest::parse(toml).expect("test manifest"))
    }

    const BASE: &str = "[package]\nname = \"acme\"\nversion = \"1.0.0\"\n";
    const SERVER: &str = "[package]\nname = \"acme\"\nversion = \"1.0.0\"\n\
                          [capabilities.http]\nserver = true\n";
    const CLIENT: &str = "[package]\nname = \"acme\"\nversion = \"1.0.0\"\n\
                          [capabilities.http]\nclient = [\"api.example.com:443\"]\n";

    /// A store with a client grant and a budget of `budget`.
    fn client_store(budget: u32) -> StoreData {
        let mut d = StoreData::new(grants_from(CLIENT));
        d.subrequests = crate::quota::SubrequestBudget::new(budget);
        d
    }

    /// The discriminant of a generated `HttpError`.
    ///
    /// `bindgen!` does not derive `PartialEq` on the types it generates, so an error
    /// value cannot be compared directly. Rendering its case is both compilable and
    /// **more informative**: a failing assertion names the case it received rather than
    /// showing two opaque values.
    fn case(e: HttpError) -> &'static str {
        // By value: the generated enum is one byte, so a reference is a pessimisation.
        match e {
            HttpError::HostNotAllowed => "host-not-allowed",
            HttpError::ConnectionFailed => "connection-failed",
            HttpError::RequestTooLarge => "request-too-large",
            HttpError::ResponseTooLarge => "response-too-large",
            HttpError::InvalidUrl => "invalid-url",
            HttpError::SubrequestLimitExceeded => "subrequest-limit-exceeded",
        }
    }

    /// The case of a `send` outcome, or `"ok"`.
    fn outcome(r: &std::result::Result<Response, HttpError>) -> &'static str {
        match r {
            Ok(_) => "ok",
            // `e` is `&HttpError` (destructured through a reference) and the enum is
            // `Copy`, so this is free.
            Err(e) => case(*e),
        }
    }

    fn get(url: &str) -> Request {
        Request {
            method: Method::Get,
            url: url.to_owned(),
            headers: vec![],
            body: None,
        }
    }

    #[test]
    fn the_interface_name_is_the_one_a_guest_imports() {
        // The string was read from `wasm-tools component wit` on a real guest, not
        // chosen. If it drifted, registration would bind nothing and instantiation would
        // fail with Wasmtime's generic "unknown import".
        assert_eq!(INTERFACE, "qqq:http/http@1.0.0");
    }

    #[test]
    fn nothing_is_registered_without_a_grant() {
        // The core security property, asserted first: no grant means the interface is
        // absent from the linker, not merely denied at call time.
        let mut l = linker();
        assert!(
            !register(&mut l, &GrantSet::empty()).expect("registration"),
            "an ungranted guest must not have `qqq:http` linked in at all"
        );
    }

    #[test]
    fn a_server_grant_registers_the_interface() {
        let mut l = linker();
        assert!(
            register(&mut l, &grants_from(SERVER)).expect("registration"),
            "http.server must register the interface"
        );
    }

    #[test]
    fn a_client_grant_registers_the_interface() {
        // The measured reason this branch exists: a guest exporting only a handler still
        // imports `qqq:http/http` for its types, so a client-only manifest has the same
        // import and must also instantiate.
        let mut l = linker();
        assert!(
            register(&mut l, &grants_from(CLIENT)).expect("registration"),
            "http.client must register the interface"
        );
    }

    #[test]
    fn an_unrelated_grant_does_not_register_the_interface() {
        // The control: if registration were unconditional, the assertions above would
        // pass while proving nothing. This pins that a *different* capability does not
        // bring `qqq:http` in.
        let mut l = linker();
        let crypto = grants_from(&format!(
            "{BASE}[capabilities.crypto]\nhash = [\"sha256\"]\n"
        ));
        assert!(
            !register(&mut l, &crypto).expect("registration"),
            "crypto.hash must not register `qqq:http`"
        );
    }

    #[test]
    fn the_ungranted_diagnostic_names_the_interface_and_the_fix() {
        let e = describe_ungranted();
        assert!(
            e.message.contains(INTERFACE),
            "the message must name the interface"
        );
        let remediation = e.remediation.as_deref().unwrap_or_default();
        assert!(
            remediation.contains("[capabilities.http]"),
            "the remediation must name the stanza to add; got `{remediation}`"
        );
    }

    #[test]
    fn the_wit_types_bind_with_the_shapes_a_guest_aliases() {
        // The interface's records are what a guest aliases. Asserting their shape here
        // means a WIT change that altered a field fails at this test rather than as a
        // canonical-ABI mismatch deep inside a guest call.
        let r = Request {
            method: Method::Post,
            url: "https://example.test/orders".to_owned(),
            headers: vec![Header {
                name: "content-type".to_owned(),
                value: b"application/json".to_vec(),
            }],
            body: Some(b"{}".to_vec()),
        };
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.headers.len(), 1);

        let resp = Response {
            status: 201,
            headers: vec![],
            body: b"created".to_vec(),
        };
        assert_eq!(resp.status, 201);

        // `http-error` is a variant, so its cases are values. The WIT documents why
        // `host-not-allowed` is distinct from a connection failure: a guest that cannot
        // tell a policy denial from an outage retries the denial forever.
        assert_ne!(
            case(HttpError::HostNotAllowed),
            case(HttpError::ConnectionFailed),
            "a policy denial and a connection failure must be distinguishable"
        );
    }

    #[test]
    fn the_method_enum_has_the_nine_cases_the_wit_declares() {
        // A WIT `enum` lowers to a **case index**, so declaration order *is* the wire
        // encoding: a reordered variant renumbers every method with nothing in the type
        // system to notice. `qqq-host::abi` records the same trap for the ABI copy of
        // this enum; this pins the bindgen-generated one, which is the type the linker
        // actually marshals.
        let order = [
            Method::Get,
            Method::Head,
            Method::Post,
            Method::Put,
            Method::Delete,
            Method::Connect,
            Method::Options,
            Method::Trace,
            Method::Patch,
        ];
        assert_eq!(order.len(), 9, "the WIT declares nine methods");
        for (i, a) in order.iter().enumerate() {
            for (j, b) in order.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "variants {i} and {j} must differ");
                }
            }
        }
    }

    #[test]
    fn send_refuses_with_a_grant_and_no_allowlist_wired() {
        // The current behaviour, asserted rather than described: granted, budget
        // available, and still refused because no egress allowlist is connected. If this
        // ever returns `Ok`, `send` has started performing network I/O and this test must
        // be replaced by a real one.
        let mut data = client_store(8);
        let r = data.send(get("https://api.example.com/thing"));
        assert_eq!(
            outcome(&r),
            "host-not-allowed",
            "`send` must refuse while no egress allowlist is wired"
        );
    }

    #[test]
    fn send_refuses_without_the_grant() {
        // The defence-in-depth check, isolated. Registration already gates the
        // interface, so this covers the case a mis-built linker would create -- and the
        // two failure modes differ in severity, which is why both checks exist.
        let mut data = StoreData::default();
        data.subrequests = crate::quota::SubrequestBudget::new(8);
        let r = data.send(get("https://api.example.com/thing"));
        assert_eq!(outcome(&r), "host-not-allowed");
    }

    #[test]
    fn send_refuses_when_the_subrequest_budget_is_exhausted() {
        // `SEC-009`'s budget, in the only place it can currently be observed. A store
        // assembled by `Default` or `new` has a budget of **zero**, and zero must mean
        // "no outbound effects" rather than "unlimited".
        let mut data = StoreData::new(grants_from(CLIENT));
        let r = data.send(get("https://api.example.com/thing"));
        assert_eq!(
            outcome(&r),
            "subrequest-limit-exceeded",
            "an exhausted budget must be reported as such, not as a policy denial"
        );
    }

    #[test]
    fn send_charges_the_budget_on_a_refusal() {
        // The property that makes the budget bound *attempts* rather than successes: a
        // refusal still spends. This is also what stops a guest learning the allowlist by
        // probing -- it runs out of budget either way.
        let mut data = client_store(2);
        for i in 0..2 {
            let r = data.send(get("https://api.example.com/thing"));
            assert_eq!(outcome(&r), "host-not-allowed", "attempt {i}");
        }
        let r = data.send(get("https://api.example.com/thing"));
        assert_eq!(
            outcome(&r),
            "subrequest-limit-exceeded",
            "two refusals must exhaust a budget of two"
        );
    }

    // -- Phase 2 wiring: `send` through vetting (`send_via`) --------------
    //
    // Red-first: `StoreData::egress`, `send_via`, `take_egress_audit`,
    // and the fake transport/resolver below do not exist until the
    // wiring lands, so these fail to compile first — then prove the
    // composition (grant → budget → vet → open → exchange → audit)
    // rather than its pieces.

    use crate::egress::{Limits, Outcome, Resolver, Transport, Vetted};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// The tenant policy the `CLIENT` manifest implies: `api.example.com`
    /// on 443, nothing else, no cleartext, no literals.
    fn allowing_store() -> StoreData {
        let mut data = client_store(8);
        data.egress = qqq_cap::egress::TenantEgress::allowing_hosts(&["api.example.com"])
            .expect("fixture policy parses");
        data
    }

    /// A resolver answering one canned address per host, counting calls
    /// so tests prove resolve-once.
    #[derive(Default)]
    struct CannedResolver {
        hosts: HashMap<String, Vec<std::net::IpAddr>>,
        calls: Mutex<Vec<String>>,
    }

    impl CannedResolver {
        fn answering(host: &str, addr: &str) -> Self {
            let mut hosts = HashMap::new();
            hosts.insert(
                host.to_owned(),
                vec![addr.parse().expect("fixture addr parses")],
            );
            Self {
                hosts,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Resolver for CannedResolver {
        // Synchronous body behind the async trait: a fake has no I/O to
        // await, and manufacturing a timer just to satisfy the lint would
        // be theater — the `async` is the trait's contract, not this impl's.
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "canned answers involve no I/O; async satisfies the Resolver contract"
        )]
        async fn resolve(&self, host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
            self.calls
                .lock()
                .expect("test mutex held")
                .push(host.to_owned());
            Ok(self.hosts.get(host).cloned().unwrap_or_default())
        }
    }

    /// A transport serving an echo over duplex: it parses the request
    /// head the connector wrote and answers with `METHOD TARGET` plus
    /// the value of the `x-probe` header (or `-`). Mapping (method,
    /// target, headers) is proven by what comes back — the response
    /// is observed after the server wrote it, so the echo carries a
    /// causal edge no shared slot can provide.
    struct CannedTransport;

    impl Transport for CannedTransport {
        type Stream = tokio::io::DuplexStream;

        // No `.await` in this impl: the duplex pair and the spawn are
        // synchronous setup; the I/O happens in the spawned task. The
        // `async` is the trait's contract, not this impl's.
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "duplex setup involves no I/O to await; async satisfies the Transport contract"
        )]
        async fn open(
            &self,
            _vetted: &Vetted,
            _limits: &Limits,
        ) -> Result<Self::Stream, crate::egress::CallError> {
            let (client, mut server) = tokio::io::duplex(65536);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut head = Vec::new();
                loop {
                    let mut byte = [0u8; 1];
                    if server.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    if head.len() > 8192 {
                        return;
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let mut lines = text.split("\r\n");
                let request_line = lines.next().unwrap_or("");
                let mut parts = request_line.split(' ');
                let method = parts.next().unwrap_or("");
                let target = parts.next().unwrap_or("");
                let mut probe = "-";
                let mut content_length = 0usize;
                for line in lines {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("x-probe") {
                            probe = value.trim();
                        }
                        if name.trim().eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().unwrap_or(0);
                        }
                    }
                }
                // The body the connector wrote, so its mapping is proven
                // by what comes back too — not just head mapping.
                let mut sent = vec![0u8; content_length.min(65536)];
                let mut read = 0usize;
                while read < sent.len() {
                    // `get_mut` with the loop invariant (`read` only
                    // advances by bytes just read) rather than slicing:
                    // an out-of-range here would be a fake bug, not a
                    // product one, and it must fail loudly either way.
                    let slot = sent
                        .get_mut(read..)
                        .expect("read cursor stays inside the body buffer");
                    match server.read(slot).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => read += n,
                    }
                }
                let body = format!(
                    "{method} {target} {probe} {}",
                    String::from_utf8_lossy(
                        sent.get(..read)
                            .expect("read cursor stays inside the body buffer")
                    )
                );
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = server.write_all(reply.as_bytes()).await;
                let _ = server.write_all(body.as_bytes()).await;
                let _ = server.flush().await;
            });
            Ok(client)
        }
    }

    /// Drive the async wiring from a sync test: each test owns a tiny
    /// current-thread runtime, so no ambient runtime is assumed.
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds")
            .block_on(future)
    }

    /// A granted host travels vet → open → exchange → audit: the
    /// response comes back mapped, the echo proves the connector
    /// wrote the guest's method, target, header, and body on the
    /// wire, and exactly one `Success` audit row names the host,
    /// port, and byte counts.
    #[test]
    fn send_routes_a_granted_host_through_vet_open_exchange_and_audit() {
        let mut data = allowing_store();
        let transport = CannedTransport;
        let resolver = CannedResolver::answering("api.example.com", "93.184.216.34");
        let request = Request {
            method: Method::Post,
            url: "https://api.example.com/thing".to_owned(),
            headers: vec![Header {
                name: "x-probe".to_owned(),
                value: b"seven".to_vec(),
            }],
            body: Some(b"payload".to_vec()),
        };
        let response =
            block_on(data.send_via(request, &transport, &resolver)).expect("granted host succeeds");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"POST /thing seven payload");
        let rows = data.take_egress_audit();
        assert_eq!(rows.len(), 1, "one call emits exactly one row");
        let row = rows.first().expect("one row recorded");
        assert_eq!(row.host, "api.example.com");
        assert_eq!(row.port, 443);
        assert!(matches!(row.outcome, Outcome::Success { status: 200 }));
        assert!(row.request_bytes > 0 && row.response_bytes > 0);
        assert_eq!(
            resolver.calls.lock().expect("test mutex held").len(),
            1,
            "the connector resolves once per call"
        );
    }

    /// A method the connector does not speak is refused before any
    /// socket opens: `egress` moves GET, HEAD, and POST only, so the
    /// WIT's wider enum meets `invalid-url` with the reason stated.
    /// No audit row: rows start when the connector runs (vet refusal
    /// and later), exactly like grant and budget refusals emit none —
    /// a mapping refusal is a client-shape error, and the budget
    /// charge is its accounting.
    #[test]
    fn send_refuses_methods_the_connector_does_not_speak() {
        let mut data = allowing_store();
        let transport = CannedTransport;
        let resolver = CannedResolver::answering("api.example.com", "93.184.216.34");
        let request = Request {
            method: Method::Put,
            url: "https://api.example.com/thing".to_owned(),
            headers: vec![],
            body: None,
        };
        let result = block_on(data.send_via(request, &transport, &resolver));
        assert_eq!(outcome(&result), "invalid-url");
        assert_eq!(
            data.take_egress_audit().len(),
            0,
            "mapping refusals predate the connector, like grant and budget refusals"
        );
    }

    /// An unwired store refuses through `send()` itself — grant checked,
    /// budget charged, vet refusal recorded — without ever dialling.
    /// No-dial is proven observably, not structurally: a dial would
    /// reach the real network (hanging to timeout or failing as
    /// `connection-failed`), while vetting refuses fast as
    /// `host-not-allowed` before `open` is ever reached — the order
    /// `egress::request` owns and its own tests pin.
    #[test]
    fn send_stores_a_vet_refusal_row_without_dialling() {
        let mut data = client_store(8);
        let result = data.send(get("https://api.example.com/thing"));
        assert_eq!(outcome(&result), "host-not-allowed");
        let rows = data.take_egress_audit();
        assert_eq!(rows.len(), 1, "the refusal is recorded, not silent");
        assert!(matches!(
            rows.first().expect("one row recorded").outcome,
            Outcome::Refused { .. }
        ));
        // Budget charged before the destination was considered: the
        // order that keeps allowlist probing from being free.
        let again = data.send(get("https://api.example.com/thing"));
        assert_eq!(outcome(&again), "host-not-allowed");
    }

    /// The manifest is the policy's single source: a store built
    /// from the `CLIENT` manifest enforces its allowlist without
    /// anyone setting the field by hand. Budget comes from the
    /// manifest's `[limits]` here too (zero in the fixture, so the
    /// test sets what the manifest path would carry in production).
    #[test]
    fn send_enforces_the_manifest_derived_policy() {
        let manifest = Manifest::parse(CLIENT).expect("test manifest");
        let mut data = StoreData::from_manifest_with_env(&manifest, &[]);
        data.subrequests = crate::quota::SubrequestBudget::new(8);
        let transport = CannedTransport;
        let resolver = CannedResolver::answering("api.example.com", "93.184.216.34");
        let allowed =
            block_on(data.send_via(get("https://api.example.com/thing"), &transport, &resolver));
        assert_eq!(outcome(&allowed), "ok", "manifest-allowed host succeeds");
        let denied = block_on(data.send_via(
            get("https://other.example.com/thing"),
            &transport,
            &resolver,
        ));
        assert_eq!(outcome(&denied), "host-not-allowed");
        let rows = data.take_egress_audit();
        assert_eq!(rows.len(), 2, "both calls emit rows");
    }

    /// Connector failures map to `connection-failed` with a `Failed`
    /// audit row: the guest can tell a dead peer from a denied policy.
    #[test]
    fn send_maps_connector_failures_to_connection_failed() {
        struct RefusedTransport;
        impl Transport for RefusedTransport {
            type Stream = tokio::io::DuplexStream;
            // No `.await`: refusing needs no I/O. The `async` is the
            // trait's contract, not this impl's.
            #[expect(
                clippy::unused_async_trait_impl,
                reason = "refusal involves no I/O; async satisfies the Transport contract"
            )]
            async fn open(
                &self,
                _: &Vetted,
                _: &Limits,
            ) -> Result<Self::Stream, crate::egress::CallError> {
                Err(crate::egress::CallError::Transport)
            }
        }
        let mut data = allowing_store();
        let resolver = CannedResolver::answering("api.example.com", "93.184.216.34");
        let result = block_on(data.send_via(
            get("https://api.example.com/thing"),
            &RefusedTransport,
            &resolver,
        ));
        assert_eq!(outcome(&result), "connection-failed");
        let rows = data.take_egress_audit();
        assert_eq!(rows.len(), 1);
        assert!(matches!(
            rows.first().expect("one row recorded").outcome,
            Outcome::Failed { .. }
        ));
    }

    #[test]
    fn incoming_authority_reports_the_bound_host_and_port() {
        let mut data = StoreData::new(grants_from(SERVER));
        data.incoming_authority = "127.0.0.1:8080".to_owned();
        assert_eq!(data.incoming_authority(), ("127.0.0.1".to_owned(), 8080));
    }

    #[test]
    fn incoming_authority_splits_an_ipv6_authority_at_the_last_colon() {
        // The case a first-colon split gets wrong: `[::1]:8080` would become host `[`
        // and port `:1]:8080`. `rsplit_once` is what makes the bracketed form correct,
        // and this is the test that pins it.
        let mut data = StoreData::new(grants_from(SERVER));

        data.incoming_authority = "[::1]:8080".to_owned();
        assert_eq!(data.incoming_authority(), ("[::1]".to_owned(), 8080));

        data.incoming_authority = "[2001:db8::1]:443".to_owned();
        assert_eq!(data.incoming_authority(), ("[2001:db8::1]".to_owned(), 443));
    }

    #[test]
    fn incoming_authority_reports_port_zero_when_none_is_stated_or_parsable() {
        // Both must return something diagnosable rather than panicking: a panic inside a
        // host call unwinds through Wasmtime's frames.
        let mut data = StoreData::new(grants_from(SERVER));

        data.incoming_authority = "example.test".to_owned();
        assert_eq!(data.incoming_authority(), ("example.test".to_owned(), 0));

        data.incoming_authority = "example.test:notaport".to_owned();
        assert_eq!(
            data.incoming_authority(),
            ("example.test:notaport".to_owned(), 0),
            "an unparsable port must keep the authority diagnosable"
        );

        data.incoming_authority = String::new();
        assert_eq!(data.incoming_authority(), (String::new(), 0));
    }

    #[test]
    fn incoming_authority_reports_the_sentinel_without_a_server_grant() {
        // The refusal is a visible sentinel, not an empty string: a guest's own logs
        // then show why the value is unusable. Empty would be indistinguishable from a
        // server bound on an empty host, and the two are different facts.
        let mut data = StoreData::new(grants_from(CLIENT));
        data.incoming_authority = "127.0.0.1:8080".to_owned();
        let (host, port) = data.incoming_authority();
        assert_eq!(host, UNGRANTED_AUTHORITY);
        assert_eq!(port, 0);
        assert!(
            !host.is_empty(),
            "the sentinel must be visible, not an empty string"
        );
    }
}
