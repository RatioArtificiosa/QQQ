// SPDX-License-Identifier: Apache-2.0

//! Routing: the one place that maps a request to a workload.
//!
//! # Why the route table is a `const` and not a `match`
//!
//! Every `§9.1` benchmark drives *this* app, so there has to be one artifact that
//! can answer all ten. If the paths were spelled inline in a `match`, the set of
//! routes and the set of benchmarks would be two lists that agree only by
//! maintenance, and `PERF-002` ("implement the ten benchmarks listed in §9.1")
//! would have nothing to check against.
//!
//! Instead [`ROUTES`] is data, each row names the `§9.1` benchmark it serves, and
//! a test walks it. The test asserts the property that actually matters: **every
//! one of the ten §9.1 rows is reachable from this table.** A benchmark whose
//! route is missing would otherwise fail as a 404 and be reported as a slow
//! runtime.
//!
//! # Routing here versus `qqq-serve`'s router
//!
//! `qqq-serve` has a real `RouteTable` with path params, and the manifest's
//! `[server] routes` feed it. **That router is not what this function is.** The
//! host matches the manifest's patterns and *then* calls the guest; by the time
//! `handle` runs, the guest has been handed a complete URL and is responsible for
//! its own dispatch.
//!
//! This is the boundary being honest about itself: `qqq:http`'s `request` carries
//! `url` — the full one, host included — and no route match. A guest that needs
//! the matched params must parse them from the path. That is a deliberate
//! consequence of the world importing nothing (`wit/app/app.wit`): the host cannot
//! pass a struct the world does not declare.
//!
//! So this module does the guest-side dispatch with the same rules — exact
//! segments win, then a single-segment `:id` param — implemented small and tested
//! directly.

use crate::exports_ih::incoming_handler::{HttpError, Request, Response};
use crate::root_http::Header;

use crate::{compute, hash, json, orders};

/// One §9.1 workload and the method/path that reaches it.
pub struct Route {
    /// The `§9.1` benchmark name, spelled exactly as the Proposal's table spells it.
    pub benchmark: &'static str,
    pub method: &'static str,
    /// The path. A `:name` segment matches exactly one segment.
    pub path: &'static str,
}

/// Every `§9.1` workload, as routes.
///
/// The `benchmark` field is the Proposal's own name for the row, so
/// [`tests::every_9_1_benchmark_is_reachable`] can compare this table against the
/// ten names rather than against a second copy of this list.
pub const ROUTES: &[Route] = &[
    Route {
        benchmark: "hello",
        method: "GET",
        path: "/healthz",
    },
    Route {
        benchmark: "json",
        method: "GET",
        path: "/orders/:id",
    },
    Route {
        benchmark: "route",
        method: "GET",
        path: "/r/:slug",
    },
    Route {
        benchmark: "db",
        method: "GET",
        path: "/orders/:id/items",
    },
    Route {
        benchmark: "crypto",
        method: "POST",
        path: "/crypto/:rounds",
    },
    Route {
        benchmark: "template",
        method: "GET",
        path: "/orders",
    },
    Route {
        benchmark: "template",
        method: "POST",
        path: "/orders",
    },
    Route {
        benchmark: "template",
        method: "DELETE",
        path: "/orders/:id",
    },
    Route {
        benchmark: "cpu",
        method: "GET",
        path: "/compute/:n",
    },
    Route {
        benchmark: "multi",
        method: "GET",
        path: "/multi",
    },
    Route {
        benchmark: "tailp99",
        method: "GET",
        path: "/orders/:id/status",
    },
    Route {
        benchmark: "cold",
        method: "GET",
        path: "/cold",
    },
];

/// The ten `§9.1` benchmark names, in the Proposal's order.
///
/// Duplicated from the Proposal **on purpose** and compared against [`ROUTES`] by
/// test. The comparison is the check; a table that derived this list from itself
/// would verify nothing (`§O-149`: a test that checks a hand-maintained mirror
/// checks the mirror).
///
/// Public rather than `#[cfg(test)]` because the guest is measured by an external
/// harness (`PERF-002`) that needs to know which workloads exist without
/// re-deriving them from the route table.
#[allow(dead_code)]
pub const BENCHMARKS: [&str; 10] = [
    "hello",
    "json",
    "route",
    "db",
    "crypto",
    "template",
    "cpu",
    "multi",
    "tailp99",
    "cold",
];

/// Dispatch one request.
///
/// Order matters and is stated so a test can pin it: exact literal segments are
/// tried before a `:param`, so `/orders/items` would beat `/orders/:id` if both
/// existed. They do not, but the rule is what makes the table safe to extend.
#[must_use]
pub fn route(req: &Request) -> Response {
    let (path, query) = split_target(&req.url);
    let method = method_name(req);

    // A HEAD is answered as the GET it names, minus the body. That is the HTTP
    // rule and it keeps the `hello` benchmark's HEAD variant from needing its own
    // route row.
    let lookup = if method == "HEAD" { "GET" } else { method };

    // Match literal paths first, then the `:param` shapes. Doing it in that order
    // rather than trusting the table's order is what makes the precedence a
    // property of the matcher instead of a property of how someone sorted a
    // literal.
    for r in ROUTES {
        if r.method == lookup && !r.path.contains(':') && r.path == path {
            return dispatch(r.benchmark, req, &[], query, method);
        }
    }
    for r in ROUTES {
        if r.method != lookup || !r.path.contains(':') {
            continue;
        }
        if let Some(params) = match_pattern(r.path, path) {
            return dispatch(r.benchmark, req, &params, query, method);
        }
    }

    // 405 before 404 when the path exists under another method: "that path is not
    // a POST" is a materially different fact from "there is no such path", and
    // collapsing them costs a caller a debugging cycle.
    let path_exists = ROUTES
        .iter()
        .any(|r| match_pattern(r.path, path).is_some() || r.path == path);

    if path_exists {
        let mut resp = crate::orders::text(405, "method not allowed");
        resp.headers.push(header("Allow", &allowed_for(path)));
        resp
    } else {
        not_found(path)
    }
}

/// Call the workload the route names.
///
/// Kept as a separate function so the route loop stays a loop and the error
/// mapping is in one place: a workload returning a `Result` becomes an HTTP status
/// **here**, and nowhere else.
fn dispatch(
    benchmark: &str,
    req: &Request,
    params: &[&str],
    query: &str,
    method: &str,
) -> Response {
    let first = params.first().copied().unwrap_or("");

    // # Why the guest does **not** strip the body for a HEAD
    //
    // It used to, and that was a defect measured end to end: clearing the body destroyed
    // the representation's length, so the server computed `Content-Length: 0` for
    // `/healthz` while its `GET` reports `2`. `RFC 9110` §9.3.2 requires a HEAD to send the
    // same header fields as a GET.
    //
    // The server owns the stripping because it must own it anyway -- a handler that forgot
    // would emit a body on a HEAD and desynchronise the stream. So this returns the
    // representation a GET would return, and `qqq_serve::write_response` writes the true
    // length and withholds the bytes.
    let mut response = match benchmark {
        "hello" => orders::health(),
        "json" => orders::by_id(first),
        "route" => orders::route_echo(first),
        "db" => orders::items(first),
        "crypto" => crypto_workload(req, first),
        // §5.3 declares `/orders` POST as `create-order` and `/orders/:id` DELETE as
        // `order-by-id`. Both are the *template* route's path with a different
        // method, so they are reached by the `template` row and dispatched by
        // method — the route table matches on path+method, and the workload then
        // branches. Keeping them off the §9.1 table is deliberate: they are part of
        // §5.3's manifest contract, not one of §9.1's ten measurements.
        "template" => match method {
            "POST" => orders::create(req.body.as_deref().unwrap_or(b"")),
            "DELETE" => orders::delete(first),
            _ => orders::table(query),
        },
        "cpu" => cpu_workload(first, query),
        "multi" => orders::multi(query),
        "tailp99" => orders::status(first),
        "cold" => orders::cold(),
        other => unreachable_response(other),
    };

    response
}

/// `crypto` — 1 KB SHA-256, repeated.
///
/// The round count comes from the path so `PERF-002` can dial it without a rebuild.
fn crypto_workload(req: &Request, rounds: &str) -> Response {
    let rounds: u32 = match rounds.parse() {
        Ok(n) => n,
        Err(_) => return bad_request("rounds must be a positive integer"),
    };
    // A round count is caller-supplied, so it is bounded. Unbounded, this route is
    // a denial-of-service primitive that any unauthenticated client can drive —
    // the same reason a limit is not optional in `PERF-*`'s own budgets.
    if rounds == 0 || rounds > 1_000_000 {
        return bad_request("rounds must be between 1 and 1000000");
    }

    let seed: &[u8] = req.body.as_deref().unwrap_or(b"");
    let digest = hash::sha256_repeated(seed, rounds);

    let mut resp = json::object(&[
        ("rounds", json::number(u64::from(rounds))),
        ("digest", json::string(&hash::hex(&digest))),
    ]);
    resp.status = 200;
    resp
}

/// `cpu` — pure compute, sized from the path.
fn cpu_workload(n: &str, query: &str) -> Response {
    let n: u32 = match n.parse() {
        Ok(n) => n,
        Err(_) => return bad_request("n must be a positive integer"),
    };
    if n == 0 || n > 50_000_000 {
        return bad_request("n must be between 1 and 50000000");
    }

    // `?mode=sieve|matmul` selects the workload. Defaulting to the sieve keeps the
    // benchmark's happy path free of a query string.
    let matmul = query.split('&').any(|kv| kv == "mode=matmul");

    let mut resp = if matmul {
        json::object(&[
            ("mode", json::string("matmul")),
            ("result", json::number(compute::matmul_trace(n))),
        ])
    } else {
        json::object(&[
            ("mode", json::string("sieve")),
            ("primes", json::number(u64::from(compute::count_primes(n)))),
        ])
    };
    resp.status = 200;
    resp
}

/// The body of a 404, naming the path.
///
/// The path is echoed because a benchmark harness that mistypes a route should see
/// *which* path missed, not a bare 404 that looks like a runtime failure.
fn not_found(path: &str) -> Response {
    crate::orders::text(404, format!("no workload is routed at `{path}`"))
}

/// A refusal for a malformed request.
fn bad_request(reason: &str) -> Response {
    crate::orders::text(400, reason)
}

/// Reached only if [`ROUTES`] gains a row whose `benchmark` is not handled in
/// [`dispatch`].
///
/// A 500 rather than a panic, and a distinct message, because the two failure
/// modes are different: this is a **defect in this file**, and the route comment
/// names it so a harness report is actionable rather than mysterious.
fn unreachable_response(benchmark: &str) -> Response {
    let mut resp = crate::orders::text(
        500,
        format!("the route table names `{benchmark}` but no workload implements it"),
    );
    resp.headers.push(header("X-QQQ-Defect", "unimplemented-route"));
    resp
}

/// The `Allow` header value for a path — every method any route uses for it.
///
/// Sorted and comma-space joined so the output is byte-stable: `§10.5` requires a
/// deterministic run to produce identical output, and header order is observable.
fn allowed_for(path: &str) -> String {
    let mut methods: Vec<&str> = ROUTES
        .iter()
        .filter(|r| match_pattern(r.path, path).is_some() || r.path == path)
        .map(|r| r.method)
        .collect();
    methods.sort_unstable();
    methods.dedup();
    methods.join(", ")
}

/// Split a full URL into its path and query.
///
/// # Why this does not use a URL parser
///
/// `qqq:http`'s `request.url` is a **full URL** that the *host* parsed and
/// validated before handing it over (`qqq-http.wit` says so: "The host parses it;
/// a guest cannot smuggle a different host past the allowlist"). Re-parsing here
/// would add a second, weaker parser on the trusted side of that boundary.
///
/// So this splits on the first `?` and takes the path that follows the authority.
/// A URL with no authority — a bare `*` from `OPTIONS` — yields `*`, and the
/// caller's table lookup then simply misses, which is the correct answer.
///
/// # The authority-form case, and the bug it caused
///
/// A `CONNECT` request carries an **authority-form** target — `orders.test:443` —
/// with no scheme and no path at all. The first version computed
/// `after_scheme.find('/').unwrap_or(after_scheme.len())` and then sliced
/// `&after_scheme[path_start..]`, which for a target with no `/` indexes to the
/// *end* and yields an empty string. The whole authority vanished, so a CONNECT
/// would have been reported as a request for `""`.
///
/// An authority-form target has no path; the target **is** its own path component.
/// Returning it whole is the correct answer, and the route table then misses it —
/// which is what should happen for a method no route serves.
fn split_target(url: &str) -> (&str, &str) {
    // Where does the authority begin? After `scheme://`, or at the start when there
    // is no scheme (authority-form and asterisk-form targets).
    let after_scheme = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };

    // Where does the path begin? At the first `/` *after* the authority. When there
    // is none the target has no path, and the target itself is what the caller must
    // match against.
    let target = match after_scheme.find('/') {
        Some(i) => &after_scheme[i..],
        None => after_scheme,
    };

    match target.find('?') {
        Some(i) => (&target[..i], &target[i + 1..]),
        None => (target, ""),
    }
}

/// The request's method as an uppercase name.
#[must_use]
pub fn method_name(req: &Request) -> &'static str {
    use crate::root_http::Method;
    match req.method {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Connect => "CONNECT",
        Method::Options => "OPTIONS",
        Method::Trace => "TRACE",
        Method::Patch => "PATCH",
    }
}

/// Match a `:param` pattern, returning the captured segments.
///
/// A `:name` matches exactly one non-empty segment. It does not match across `/`,
/// which is the property a naive `starts_with` would get wrong and the reason
/// `/orders/:id` must not swallow `/orders/1/items`.
#[must_use]
pub fn match_pattern<'p>(pattern: &str, path: &'p str) -> Option<Vec<&'p str>> {
    let mut pat = pattern.split('/');
    let mut got = path.split('/');
    let mut params = Vec::new();

    loop {
        match (pat.next(), got.next()) {
            (None, None) => return Some(params),
            (Some(p), Some(g)) => {
                if let Some(name) = p.strip_prefix(':') {
                    // A parameter with an empty value is not a match: `/orders/`
                    // is not `/orders/:id`.
                    if name.is_empty() || g.is_empty() {
                        return None;
                    }
                    params.push(g);
                } else if p != g {
                    return None;
                }
            }
            // Different segment counts.
            _ => return None,
        }
    }
}

/// Build a header. The guest's value is bytes, per `qqq:http`.
fn header(name: &str, value: &str) -> Header {
    Header {
        name: name.to_owned(),
        value: value.as_bytes().to_vec(),
    }
}

/// The error kind for a routing failure that is the *host's* problem.
///
/// Unused at present — [`route`] answers with a status instead of failing — but
/// named so the mapping is documented rather than discovered: a guest that returns
/// `Err` gives the host an error kind and **no status**, and the host then chooses
/// one. A workload that can express its failure as a status should do so.
#[allow(dead_code)]
fn internal_error() -> HttpError {
    // `http-error` is a WIT `variant`, so wit-bindgen emits one Rust enum whose six
    // cases are **unit** variants — there is no payload to carry a reason. A guest
    // that needs to explain itself must therefore do so in the response body, not
    // on the error; that is a property of the interface, not of this app.
    HttpError::ConnectionFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root_http::Method;

    /// Render a response's headers as `name: value` pairs, for comparison.
    ///
    /// The generated `Header` record has no `PartialEq`, and comparing an owned
    /// `Vec<Header>` would also be a weaker statement than comparing what the
    /// client receives.
    fn render_headers(r: &Response) -> Vec<String> {
        r.headers
            .iter()
            .map(|h| format!("{}: {}", h.name, String::from_utf8_lossy(&h.value)))
            .collect()
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
    fn every_9_1_benchmark_is_reachable() {
        // The property that matters: all ten names in §9.1 appear in ROUTES. A
        // missing one would 404 and be reported as a slow runtime rather than a
        // missing route.
        for name in BENCHMARKS {
            assert!(
                ROUTES.iter().any(|r| r.benchmark == name),
                "§9.1 names the `{name}` benchmark but no route serves it"
            );
        }

        // Every route row must name a §9.1 benchmark. A row naming something else
        // would be a route that is not a measurement, and it would drift the table
        // away from §9.1 without anything noticing.
        let named: Vec<&str> = ROUTES.iter().map(|r| r.benchmark).collect();
        for name in &named {
            assert!(
                BENCHMARKS.contains(name),
                "route table row `{name}` is not one of §9.1's ten benchmarks"
            );
        }

        // Each benchmark must be reachable, and no benchmark may be missing a
        // route. This is the assertion the count check used to make — expressed as
        // a set comparison so it stays true when a benchmark legitimately has more
        // than one row (as `template` does, via §5.3's POST and DELETE).
        for name in BENCHMARKS {
            assert!(
                named.contains(&name),
                "§9.1's `{name}` benchmark has rows in the table that do not name it"
            );
        }
    }

    #[test]
    fn the_route_passwords_match_the_manifest_in_the_proposal() {
        // §5.3's `[server] routes` table is a contract with users, so the two
        // paths it names and the two this app serves must be the same strings.
        // §5.3: `{ path = "/orders", methods = ["POST"], handler = "create-order" }`
        //       `{ path = "/orders/:id", methods = ["GET","DELETE"], handler = "order-by-id" }`
        //       `{ path = "/healthz", methods = ["GET"], handler = "health" }`
        assert!(
            ROUTES.iter().any(|r| r.path == "/orders" && r.method == "GET"),
            "§5.3 declares an `/orders` route; the template workload must serve it"
        );
        assert!(
            ROUTES
                .iter()
                .any(|r| r.path == "/orders/:id" && r.method == "GET"),
            "§5.3 declares `/orders/:id` GET; the json workload must serve it"
        );
        assert!(
            ROUTES
                .iter()
                .any(|r| r.path == "/healthz" && r.method == "GET"),
            "§5.3 declares `/healthz`; the hello workload must serve it"
        );
    }

    #[test]
    fn a_param_matches_exactly_one_segment() {
        assert_eq!(match_pattern("/orders/:id", "/orders/42"), Some(vec!["42"]));
        assert_eq!(
            match_pattern("/orders/:id", "/orders/42/items"),
            None,
            "a param must not swallow a following segment; `/orders/:id` and \
             `/orders/:id/items` are different routes"
        );
        assert_eq!(
            match_pattern("/orders/:id", "/orders/"),
            None,
            "an empty segment is not a parameter value"
        );
        assert_eq!(match_pattern("/a/:b/:c", "/a/1/2"), Some(vec!["1", "2"]));
        assert_eq!(match_pattern("/a/b", "/a/b"), Some(vec![]));
        assert_eq!(match_pattern("/a/b", "/a/c"), None);
    }

    #[test]
    fn a_head_produces_the_same_representation_as_a_get() {
        // # What this asserts, and what it deliberately does not
        //
        // The guest's job is to produce the **representation**; withholding the bytes is
        // `qqq_serve::write_response`'s job, and it needs the real body to compute a
        // truthful `Content-Length` (`RFC 9110` §9.3.2).
        //
        // So this test asserts identity: HEAD and GET return the same status, the same
        // headers and the same body, and the *server* strips. The previous version
        // asserted the guest stripped the body -- which was the defect, because it left the
        // server unable to report the length. It measured `Content-Length: 0` for a
        // resource whose GET reports `2`.
        let mut head = get("https://x.test/healthz");
        head.method = Method::Head;
        let by_head = route(&head);
        let by_get = route(&get("https://x.test/healthz"));

        assert_eq!(by_head.status, by_get.status);
        assert_eq!(
            render_headers(&by_head),
            render_headers(&by_get),
            "a HEAD must carry every header the GET would"
        );
        assert_eq!(
            by_head.body, by_get.body,
            "the guest returns the same representation; the server withholds the bytes"
        );
        // The control: the body is non-empty, so the equality above is a real statement
        // rather than two empty vectors matching.
        assert!(!by_get.body.is_empty(), "control: the GET has a body");
    }

    #[test]
    fn a_url_with_a_query_string_routes_on_its_path() {
        let r = route(&get("https://x.test/compute/1000?mode=matmul"));
        assert_eq!(r.status, 200);
        assert!(
            String::from_utf8_lossy(&r.body).contains("matmul"),
            "the query must reach the workload, not the path matcher"
        );
    }

    #[test]
    fn an_unknown_path_is_a_404_and_a_known_path_wrong_method_is_a_405() {
        assert_eq!(route(&get("https://x.test/nope")).status, 404);

        let mut post = get("https://x.test/healthz");
        post.method = Method::Post;
        let r = route(&post);
        assert_eq!(
            r.status, 405,
            "'this path is not a POST' is a different fact from 'no such path'"
        );
        let allow = r
            .headers
            .iter()
            .find(|h| h.name == "Allow")
            .expect("a 405 must say what is allowed");
        assert_eq!(allow.value, b"GET");
    }

    #[test]
    fn the_allow_header_is_sorted_so_output_is_deterministic() {
        // §10.5 requires identical output for identical input, and header order is
        // observable, so this must not depend on table order.
        let sorted = allowed_for("/healthz");
        assert_eq!(sorted, "GET");

        // A path with two methods, whichever they are, must come out sorted.
        let mut methods: Vec<&str> = ROUTES
            .iter()
            .filter(|r| r.path == "/orders/:id")
            .map(|r| r.method)
            .collect();
        methods.sort_unstable();
        methods.dedup();
        let expected = methods.join(", ");
        assert_eq!(allowed_for("/orders/7"), expected);
        assert_eq!(
            expected,
            expected.split(", ").collect::<Vec<_>>().join(", "),
            "sanity: the join round-trips"
        );
    }

    #[test]
    fn the_url_split_handles_the_shapes_that_occur() {
        assert_eq!(
            split_target("https://orders.test/orders/42"),
            ("/orders/42", "")
        );
        assert_eq!(
            split_target("https://orders.test/orders/42?x=1"),
            ("/orders/42", "x=1")
        );
        assert_eq!(split_target("http://h/a?b?c"), ("/a", "b?c"));
        // No path at all: the target is the authority, because there is nothing
        // after it to be a path. The first version of this test expected ("", "")
        // and the code was right -- a target with no `/` has no path component, so
        // the whole target is what the caller must match against.
        assert_eq!(split_target("https://orders.test"), ("orders.test", ""));
        // Authority-form, sent by CONNECT. Not a route, and must not panic.
        assert_eq!(split_target("orders.test:443"), ("orders.test:443", ""));
        // A bare `*`, sent by OPTIONS. Must not panic.
        assert_eq!(split_target("*"), ("*", ""));
    }


    #[test]
    fn every_route_in_the_table_actually_dispatches() {
        // A row whose `benchmark` has no `dispatch` arm returns the defect 500.
        // This walks the table so a new row cannot be half-added — a route that
        // matched but had no workload would otherwise look like a 500 from the
        // runtime.
        for r in ROUTES {
            let url = format!(
                "https://x.test{}",
                r.path
                    .replace(":id", "1")
                    .replace(":slug", "s")
                    .replace(":rounds", "10")
                    .replace(":n", "100")
            );
            let mut req = get(&url);
            req.method = match r.method {
                // `get()` already sets GET, so this arm is the default path and
                // its absence was a harness defect: the walk panicked on the first
                // GET row and never tested any route at all.
                "GET" => Method::Get,
                "POST" => Method::Post,
                "DELETE" => Method::Delete,
                other => panic!("the table names an unhandled method `{other}`"),
            };
            // §5.3's POST route reads a form body; without one it answers 400,
            // which is a correct dispatch and not a missing arm.
            if r.method == "POST" {
                req.body = Some(b"id=walk&quantity=1&unit_cents=1".to_vec());
            }

            let resp = route(&req);

            // The property this test's name claims is *reachability*: the row
            // reached a workload. A specific status cannot express that, because a
            // matched row may legitimately answer 404 -- `orders::delete` on an
            // unknown id does exactly that, and asserting `!= 404` here was wrong
            // for that reason.
            //
            // The two failure modes are distinguishable, so they are distinguished:
            // the defect marker is set by `unreachable_response`, and the router's
            // no-such-path 404 echoes the path in its body.
            let defect = resp
                .headers
                .iter()
                .any(|h| h.name == "X-QQQ-Defect" && h.value == b"unimplemented-route");
            assert!(
                !defect,
                "the `{}` route has a table row but no dispatch arm",
                r.benchmark
            );

            let body = String::from_utf8_lossy(&resp.body);
            assert!(
                !body.contains("no workload is routed at"),
                "the `{}` route at `{}` did not match its own table row (status {})",
                r.benchmark,
                r.path,
                resp.status
            );
            assert_ne!(
                resp.status, 405,
                "the `{}` route at `{}` is reachable only under another method",
                r.benchmark, r.path
            );
        }
    }

    #[test]
    fn the_manifest_contract_routes_from_5_3_are_served() {
        // §5.3 declares three routes. Each must be reachable, with the status its
        // handler implies. This is the item's real end-to-end claim, expressed as
        // HTTP rather than as a table lookup.
        crate::orders::reset();

        // `{ path = "/healthz", methods = ["GET"], handler = "health", auth = "none" }`
        assert_eq!(route(&get("https://x.test/healthz")).status, 200);

        // `{ path = "/orders", methods = ["POST"], handler = "create-order" }`
        let mut create = get("https://x.test/orders");
        create.method = Method::Post;
        create.body = Some(b"id=api-1&quantity=2&unit_cents=500".to_vec());
        let created = route(&create);
        assert_eq!(created.status, 201, "§5.3's create-order must create");

        // `{ path = "/orders/:id", methods = ["GET","DELETE"], handler = "order-by-id" }`
        let fetched = route(&get("https://x.test/orders/api-1"));
        assert_eq!(fetched.status, 200, "§5.3's order-by-id GET must find it");
        assert_eq!(
            route(&get("https://x.test/orders/api-1")).body,
            fetched.body,
            "a GET must be repeatable"
        );

        let mut del = get("https://x.test/orders/api-1");
        del.method = Method::Delete;
        assert_eq!(route(&del).status, 204, "§5.3's DELETE must remove it");
        let mut del2 = get("https://x.test/orders/api-1");
        del2.method = Method::Delete;
        assert_eq!(route(&del2).status, 404, "and then report it gone");
    }
}
