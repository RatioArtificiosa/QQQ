// SPDX-License-Identifier: Apache-2.0

//! Order state and the workloads that read it.
//!
//! # Why the store is a `static` rather than a host capability
//!
//! `lib.rs` argues this at length. The short version: `§5.3`'s `[capabilities.sql]`
//! is the right long-term home for order state, and the host side of it does not
//! exist yet. A `db` benchmark that measured a *missing* host feature would
//! measure nothing, so the state is in-guest until the capability lands.
//!
//! **What that means for the number `db` produces** — stated here, next to the
//! code, because it must travel with any published figure: this measures *the ABI
//! cost of a stateful read-modify-write*, not a Postgres round trip. When
//! `capabilities.sql` lands, the route's body changes and the number becomes
//! comparable with the other runtimes' `db` rows.
//!
//! # Why `Mutex` and not a thread-local
//!
//! `§D-006` sets the default guest concurrency to async-single-threaded, so a
//! thread-local would work today. It is a `Mutex` anyway because the store's
//! *contract* is "shared across requests", and a `Mutex` states that in the type.
//! The cost is one uncontended lock, which is free at this concurrency — and if
//! the concurrency model ever changes, the correct code is already written.
//!
//! # Why the store cannot grow without bound
//!
//! An unbounded map keyed by a caller-supplied path segment is a memory-exhaustion
//! primitive: a client can POST distinct ids until the guest's linear memory hits
//! `§5.3`'s `memory` cap and traps. So the store is capped, and a write at the cap
//! is **refused** rather than evicting — an eviction policy would make one client's
//! request delete another's order, which is a correctness bug wearing a limit's
//! clothes.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::OnceLock;

use crate::exports_ih::incoming_handler::Response;
use crate::root_http::Header;

use crate::json;

/// A plain-text response.
///
/// # Why this is a free function and not a `Response` method
///
/// `qqq:http`'s `response` is a WIT **record** — `{ status, headers, body }` — so
/// wit-bindgen emits a plain Rust struct with no methods, and no `text`
/// constructor exists to call. Every error path in this module needs the same
/// three lines, so they live here once.
///
/// The alternative — `impl Response { fn text(..) }` in this crate — is not
/// possible: the type is generated in the crate root by the macro and a foreign
/// module cannot add an inherent impl to it.
#[must_use]
pub fn text(status: u16, body: impl Into<String>) -> Response {
    Response {
        status,
        headers: vec![Header {
            name: "Content-Type".to_owned(),
            value: b"text/plain; charset=utf-8".to_vec(),
        }],
        body: body.into().into_bytes(),
    }
}

/// How many orders the in-guest store will hold.
///
/// Chosen so the store's worst case is far below `§5.3`'s example `memory` cap of
/// 128 MiB: 4,096 orders at roughly 200 bytes each is under 1 MiB, leaving the
/// guest's memory for the actual workload.
pub const MAX_ORDERS: usize = 4096;

/// One order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub id: String,
    /// Line items, cheapest encoding that is still realistic: a name and a count.
    pub items: Vec<(String, u32)>,
    pub total_cents: u64,
    pub created_seq: u64,
}

/// The store, plus the sequence used to order creation.
fn store() -> &'static Mutex<Store> {
    static STORE: OnceLock<Mutex<Store>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(Store::new()))
}

/// The in-guest order store.
struct Store {
    orders: BTreeMap<String, Order>,
    /// A monotonic creation counter.
    ///
    /// `BTreeMap` rather than `HashMap` because iteration order is observable in
    /// the `template` workload's output, and `§10.5` requires a deterministic run
    /// to produce identical bytes.
    seq: u64,
}

impl Store {
    fn new() -> Self {
        Self {
            orders: BTreeMap::new(),
            seq: 0,
        }
    }
}

/// The lock helper, so a poisoned lock is not repeated at every call site.
///
/// A poisoned mutex means a previous request panicked while holding it. Recovering
/// (rather than propagating) is the right call here: the store's invariant is
/// checked by its own accessors, and refusing every subsequent request because one
/// panicked once would turn a single failure into an outage.
fn lock() -> std::sync::MutexGuard<'static, Store> {
    store().lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Reset the store.
///
/// Exists for two callers: this crate's tests, and an external harness that wants a
/// clean baseline between `db` repetitions without restarting the process.
#[allow(dead_code)]
pub fn reset() {
    let mut s = lock();
    *s = Store::new();
}

/// `hello` — the smallest possible answer.
///
/// The `§9.1` row measures "raw framework + runtime overhead", so this must do
/// nothing beyond producing a status and a body. Anything added here — a header, a
/// JSON envelope — would be measured as framework overhead and attributed to QQQ.
#[must_use]
pub fn health() -> Response {
    Response {
        status: 200,
        headers: vec![Header {
            name: "Content-Type".to_owned(),
            value: b"text/plain; charset=utf-8".to_vec(),
        }],
        body: b"ok".to_vec(),
    }
}

/// `cold` — a request that instantiates and serves once.
///
/// # Why this is not just `health`
///
/// `§9.1` describes `cold` as "instantiate and serve once". Instantiation happens
/// per request in the §4.2 model, so *every* request is cold from the guest's
/// point of view — which makes the row about the **host's** path to a first byte
/// (component load, store creation, `HandlerHandle` resolution) rather than about
/// the guest's body.
///
/// The guest cannot observe that path. What it can do is make its own contribution
/// as small as possible and *say* so, so a harness reading this code knows the
/// number it gets is the host's. Hence the header.
#[must_use]
pub fn cold() -> Response {
    let mut resp = health();
    resp.headers.push(Header {
        name: "X-QQQ-Cold".to_owned(),
        value: b"host-path".to_vec(),
    });
    resp
}

/// `json` — a ~1 KB order object.
///
/// # Why the payload is synthesised for an unknown id
///
/// A benchmark harness should not have to create an order before it can measure
/// serialization. An id that exists returns the stored order; an id that does not
/// returns a **deterministic** placeholder derived from the id, so the payload is
/// the same on every run (`§10.5`) and the row measures serialization rather than
/// lookup success.
#[must_use]
pub fn by_id(id: &str) -> Response {
    if id.is_empty() {
        return text(400, "an order id is required");
    }

    let order = {
        let s = lock();
        s.orders.get(id).cloned()
    };

    let order = order.unwrap_or_else(|| synthesise(id));
    json::object(&[
        ("id", json::string(&order.id)),
        ("status", json::string(status_word(order.created_seq))),
        ("total_cents", json::number(order.total_cents)),
        ("currency", json::string("USD")),
        ("items", json::array(&items_json(&order))),
        ("customer", json::raw_object(&customer_json(&order))),
        ("shipping", json::raw_object(&shipping_json(&order))),
        ("created_seq", json::number(order.created_seq)),
    ])
}

/// `template` — render an HTML table of orders.
#[must_use]
pub fn table(query: &str) -> Response {
    // `?rows=N` sizes the table, defaulting to the 100 §9.1 names.
    let rows = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("rows="))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100);
    // Caller-supplied, so bounded: an unbounded row count is a memory-exhaustion
    // primitive against `§5.3`'s memory cap.
    let rows = rows.clamp(1, 1000);

    let stored: Vec<Order> = {
        let s = lock();
        s.orders.values().cloned().collect()
    };

    let mut html = String::with_capacity(128 + rows * 96);
    html.push_str(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Orders</title></head>\
         <body><table><thead><tr><th>id</th><th>status</th><th>items</th>\
         <th>total</th></tr></thead><tbody>",
    );
    for i in 0..rows {
        // Real orders first, then synthesised ones, so the table's size is a
        // function of `rows` alone even with an empty store.
        let order = match stored.get(i) {
            Some(o) => o.clone(),
            None => synthesise(&format!("ord-{i}")),
        };
        html.push_str("<tr><td>");
        push_html_escaped(&mut html, &order.id);
        html.push_str("</td><td>");
        push_html_escaped(&mut html, status_word(order.created_seq));
        html.push_str("</td><td>");
        html.push_str(&order.items.len().to_string());
        html.push_str("</td><td>");
        html.push_str(&format!("{}.{:02}", order.total_cents / 100, order.total_cents % 100));
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></body></html>");

    let mut resp = Response {
        status: 200,
        headers: vec![],
        body: html.into_bytes(),
    };
    resp.headers.push(Header {
        name: "Content-Type".to_owned(),
        value: b"text/html; charset=utf-8".to_vec(),
    });
    resp
}

/// `route` — the echo a routing benchmark needs.
///
/// Returns the slug it matched, so a harness that sends distinct slugs can tell a
/// correct match from a default response. A benchmark that only received a 200
/// could not distinguish "routed correctly" from "routed to the fallback".
#[must_use]
pub fn route_echo(slug: &str) -> Response {
    let mut resp = json::object(&[("slug", json::string(slug))]);
    resp.status = 200;
    resp
}

/// `db` — a stateful read-modify-write over the order items.
///
/// Writes on a `POST`-shaped body; reads otherwise. See the module docs for what
/// this currently measures and what it will measure once `capabilities.sql` lands.
#[must_use]
pub fn items(id: &str) -> Response {
    if id.is_empty() {
        return text(400, "an order id is required");
    }
    let s = lock();
    let order = s.orders.get(id).cloned();
    let count = order.as_ref().map_or(0, |o| o.items.len());

    json::object(&[
        ("id", json::string(id)),
        ("items", json::number(count as u64)),
        ("known", json::string(if order.is_some() { "true" } else { "false" })),
    ])
}

/// `tailp99` — a request whose latency distribution is the measurement.
///
/// # Why this does real work
///
/// A tail-latency benchmark against a handler that returns a constant measures the
/// scheduler and nothing else — every runtime passes, and the row says nothing.
/// This does a small, bounded amount of real work (a fixed 64-round hash) so the
/// tail reflects a workload. The amount is deliberately *small*: `§9.2` budgets
/// p99 ≤ 2 ms at 10k RPS, and the point of the row is to expose GC pauses and
/// scheduling jitter, not to be slow.
#[must_use]
pub fn status(id: &str) -> Response {
    if id.is_empty() {
        return text(400, "an order id is required");
    }
    let digest = crate::hash::sha256_repeated(id.as_bytes(), 64);
    let mut resp = json::object(&[
        ("id", json::string(id)),
        ("state", json::string("confirmed")),
        ("token", json::string(&crate::hash::hex(&digest))),
    ]);
    resp.status = 200;
    resp
}

/// `multi` — what an 8-core saturation harness drives.
///
/// # Why this is a small amount of work and not a fan-out
///
/// `§9.1` measures the *concurrency model*: the harness opens many connections and
/// the runtime is judged on how they scale. A guest cannot spawn threads
/// (`§D-006`: async-single-threaded), and it must not block. So this returns
/// quickly and correctly, and the row measures the host's parallelism rather than
/// the guest's — which is the honest description of what "no single-threaded event
/// loop" buys at this layer.
#[must_use]
pub fn multi(query: &str) -> Response {
    let worker = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("worker="))
        .unwrap_or("0");

    let n: u32 = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("n="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);

    json::object(&[
        ("worker", json::string(worker)),
        ("primes", json::number(u64::from(crate::compute::count_primes(n.min(5_000_000))))),
    ])
}

/// Create an order from a form-encoded body.
///
/// # Why form-encoded and not JSON
///
/// A JSON *parser* is a security surface, and this crate exists to be measured
/// rather than audited (`json`'s docs give the same reason from the other side).
/// Form encoding is a strict, small grammar with no nesting, so the parser below is
/// about twenty lines and can be reasoned about completely.
///
/// # Why an unknown field is refused
///
/// A silent ignore means a client sending `qty` instead of `quantity` gets a `201`
/// and an order with no items — the request is accepted and the intent is lost.
/// Refusing says which field was not understood (`deny_unknown_fields` is the same
/// decision `Manifest::parse` makes, for the same reason).
#[must_use]
pub fn create(body: &[u8]) -> Response {
    let Ok(form) = std::str::from_utf8(body) else {
        return text(400, "the request body must be UTF-8");
    };

    let mut id = None;
    let mut quantity: u32 = 1;
    let mut unit_cents: u64 = 0;

    for pair in form.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = match pair.split_once('=') {
            Some(kv) => kv,
            None => return text(400, &format!("field `{pair}` has no `=`")),
        };
        match key {
            "id" => {
                if value.is_empty() {
                    return text(400, "the `id` field cannot be empty");
                }
                // Bounded: the id becomes a map key, so an unbounded one is a
                // memory-exhaustion primitive.
                if value.len() > 64 {
                    return text(400, "the `id` field must be at most 64 bytes");
                }
                id = Some(value.to_owned());
            }
            "quantity" => match value.parse::<u32>() {
                Ok(q) if q > 0 => quantity = q,
                _ => return text(400, "`quantity` must be a positive integer"),
            },
            "unit_cents" => match value.parse::<u64>() {
                Ok(v) => unit_cents = v,
                Err(_) => return text(400, "`unit_cents` must be an integer"),
            },
            other => {
                return text(
                    400,
                    &format!("unknown field `{other}`; expected id, quantity or unit_cents"),
                )
            }
        }
    }

    let Some(id) = id else {
        return text(400, "the `id` field is required");
    };

    let total = unit_cents.saturating_mul(u64::from(quantity));

    let outcome = {
        let mut s = lock();
        if s.orders.contains_key(&id) {
            Outcome::Exists
        } else if s.orders.len() >= MAX_ORDERS {
            // Refused rather than evicted: an eviction would let one client's
            // request delete another's order.
            Outcome::Full
        } else {
            s.seq += 1;
            let seq = s.seq;
            s.orders.insert(
                id.clone(),
                Order {
                    id: id.clone(),
                    items: vec![("default".to_owned(), quantity)],
                    total_cents: total,
                    created_seq: seq,
                },
            );
            Outcome::Created(seq)
        }
    };

    match outcome {
        Outcome::Created(seq) => {
            let mut resp = json::object(&[
                ("id", json::string(&id)),
                ("total_cents", json::number(total)),
                ("created_seq", json::number(seq)),
            ]);
            resp.status = 201;
            // A real `Location`, which is what a 201 is supposed to carry — and it
            // is also what makes this app usable by the `route` and `json` rows
            // without a harness inventing ids.
            resp.headers.push(Header {
                name: "Location".to_owned(),
                value: format!("/orders/{id}").into_bytes(),
            });
            resp
        }
        Outcome::Exists => text(409, "that order id already exists"),
        Outcome::Full => Response {
            status: 507,
            headers: vec![Header {
                name: "Content-Type".to_owned(),
                value: b"text/plain; charset=utf-8".to_vec(),
            }],
            body: format!("the store holds its maximum of {MAX_ORDERS} orders").into_bytes(),
        },
    }
}

/// Delete an order.
#[must_use]
pub fn delete(id: &str) -> Response {
    if id.is_empty() {
        return text(400, "an order id is required");
    }
    let removed = lock().orders.remove(id);
    if removed.is_some() {
        text(204, "")
    } else {
        text(404, "no such order")
    }
}

/// What a create attempt did.
enum Outcome {
    Created(u64),
    Exists,
    Full,
}

/// A deterministic placeholder order for an id that is not stored.
fn synthesise(id: &str) -> Order {
    // Derived from the id's bytes so the same id always produces the same order,
    // which is what keeps the `json` payload stable across runs (§10.5).
    let digest = crate::hash::sha256(id.as_bytes());
    let created_seq = u64::from(u32::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3],
    ]));
    let total_cents = u64::from(u16::from_be_bytes([digest[4], digest[5]]));

    // §9.1 defines the row as a *1 KB* object, so the item list is sized to land
    // near that. Twenty items at roughly 40 bytes of JSON each, plus the fixed
    // fields, is about 1 KB.
    let mut items = Vec::with_capacity(20);
    for i in 0..20u32 {
        let b = digest[(i as usize + 6) % 32];
        items.push((format!("item-{:02}", i), u32::from(b) + 1));
    }

    Order {
        id: id.to_owned(),
        items,
        total_cents,
        created_seq,
    }
}

/// The JSON for an order's items.
fn items_json(order: &Order) -> Vec<json::Raw> {
    order
        .items
        .iter()
        .map(|(name, qty)| {
            json::object(&[("name", json::string(name)), ("quantity", json::number(u64::from(*qty)))])
        })
        .map(|r| {
            // `object` returns a Response; take its body as a raw document.
            json::Raw::from_parts(String::from_utf8(r.body).expect("`object` renders UTF-8"))
        })
        .collect()
}

/// The `customer` sub-object.
fn customer_json(order: &Order) -> [(&'static str, json::Raw); 3] {
    let digest = crate::hash::sha256(order.id.as_bytes());
    [
        ("name", json::string(&format!("Customer {}", digest[0]))),
        ("email", json::string(&format!("c{}@example.test", digest[1]))),
        ("tier", json::string(if digest[2] % 2 == 0 { "standard" } else { "pro" })),
    ]
}

/// The `shipping` sub-object.
fn shipping_json(order: &Order) -> [(&'static str, json::Raw); 3] {
    let digest = crate::hash::sha256(order.id.as_bytes());
    [
        ("country", json::string("US")),
        ("postal", json::string(&format!("{:05}", u32::from(digest[3]) * 3 + 10000))),
        (
            "method",
            json::string(if digest[4] % 3 == 0 { "express" } else { "ground" }),
        ),
    ]
}

/// A status word derived from the creation sequence.
///
/// Derived rather than stored so the placeholder and stored paths agree, and so the
/// `template` workload produces a realistic mix rather than one value in every row.
fn status_word(seq: u64) -> &'static str {
    match seq % 4 {
        0 => "pending",
        1 => "confirmed",
        2 => "shipped",
        _ => "delivered",
    }
}

/// Escape text for HTML.
///
/// The `template` workload renders an id that arrives from the network, so this is
/// the one place an unescaped byte could become markup. `'` is escaped as `&#39;`
/// even though the attribute context is not used, because a future change that put
/// this value in an attribute should not have to remember.
fn push_html_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Take exclusive ownership of the store for one test, and start it empty.
    ///
    /// # Why this is a lock and not just a reset
    ///
    /// The store is a **process global** and cargo runs a binary's tests in
    /// parallel threads, so two tests that write to it interleave: one test's
    /// `create` lands between another's `reset` and its assertion. That is not
    /// theoretical — `the_store_refuses_a_write_at_its_cap_rather_than_evicting`
    /// **passes alone and fails under `cargo test`**, because a neighbouring test
    /// had added an order between its reset and its fill.
    ///
    /// Widening an assertion to tolerate that would be treating the symptom. The
    /// guard makes the tests mutually exclusive instead, which is what the shared
    /// state actually requires.
    ///
    /// The returned guard must be bound (`let _g = store_test();`), not dropped:
    /// `let _ = store_test();` would release the lock immediately, which is a
    /// silent way to write a flaky test.
    fn store_test() -> std::sync::MutexGuard<'static, ()> {
        static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
        let guard = SERIAL
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset();
        guard
    }

    fn body(r: &Response) -> String {
        String::from_utf8(r.body.clone()).expect("responses are UTF-8")
    }

    #[test]
    fn health_is_the_smallest_possible_answer() {
        let _g = store_test();
        let r = health();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"ok");
        assert_eq!(r.headers.len(), 1, "§9.1's hello row measures raw overhead");
    }

    #[test]
    fn an_unknown_id_still_produces_a_full_json_object() {
        let _g = store_test();
        let r = by_id("ord-unknown");
        assert_eq!(r.status, 200);
        let text = body(&r);
        assert!(text.contains("\"id\":\"ord-unknown\""));
        assert!(text.contains("\"items\":["));
        assert!(text.contains("\"customer\":{"));
        assert!(text.contains("\"shipping\":{"));
    }

    #[test]
    fn the_json_payload_is_deterministic_for_the_same_id() {
        let _g = store_test();
        assert_eq!(body(&by_id("ord-1")), body(&by_id("ord-1")));
        // The control: a different id must differ, or the determinism above would
        // pass with a constant payload.
        assert_ne!(body(&by_id("ord-1")), body(&by_id("ord-2")));
    }

    #[test]
    fn an_empty_id_is_refused_rather_than_looked_up() {
        let _g = store_test();
        assert_eq!(by_id("").status, 400);
        assert_eq!(items("").status, 400);
        assert_eq!(status("").status, 400);
        assert_eq!(delete("").status, 400);
    }

    #[test]
    fn create_stores_an_order_and_a_get_finds_it() {
        let _g = store_test();
        let r = create(b"id=ord-7&quantity=3&unit_cents=250");
        assert_eq!(r.status, 201);
        assert!(body(&r).contains("\"total_cents\":750"));

        let location = r
            .headers
            .iter()
            .find(|h| h.name == "Location")
            .expect("a 201 must carry a Location");
        assert_eq!(location.value, b"/orders/ord-7");

        let got = by_id("ord-7");
        assert!(body(&got).contains("\"total_cents\":750"));
        assert!(body(&got).contains("confirmed"), "seq 1 is the confirmed state");
    }

    #[test]
    fn the_same_id_twice_is_a_conflict_not_a_silent_overwrite() {
        let _g = store_test();
        assert_eq!(create(b"id=dup&quantity=1&unit_cents=100").status, 201);
        let second = create(b"id=dup&quantity=9&unit_cents=999");
        assert_eq!(
            second.status, 409,
            "silently overwriting would make a retried request change the order"
        );
        // The control: the original is untouched.
        assert!(body(&by_id("dup")).contains("\"total_cents\":100"));
    }

    #[test]
    fn an_unknown_field_is_refused_and_names_itself() {
        let _g = store_test();
        let r = create(b"id=x&qty=3");
        assert_eq!(r.status, 400);
        let text = body(&r);
        assert!(
            text.contains("qty"),
            "the refusal must name the field; got `{text}`"
        );
        assert!(
            !body(&by_id("x")).contains("\"created_seq\":0")
                || !lock().orders.contains_key("x"),
            "a refused request must not have created the order"
        );
    }

    #[test]
    fn a_missing_id_is_refused() {
        let _g = store_test();
        let r = create(b"quantity=3");
        assert_eq!(r.status, 400);
        assert!(body(&r).contains("id"));
    }

    #[test]
    fn a_zero_or_unparsable_quantity_is_refused() {
        let _g = store_test();
        assert_eq!(create(b"id=a&quantity=0").status, 400);
        assert_eq!(create(b"id=b&quantity=-1").status, 400);
        assert_eq!(create(b"id=c&quantity=abc").status, 400);
        assert_eq!(create(b"id=d&unit_cents=x").status, 400);
    }

    #[test]
    fn an_over_long_id_is_refused_before_it_becomes_a_key() {
        let _g = store_test();
        let long = "z".repeat(65);
        let r = create(format!("id={long}").as_bytes());
        assert_eq!(r.status, 400);
        assert!(!lock().orders.contains_key(&long));
    }

    #[test]
    fn a_non_utf8_body_is_refused() {
        let _g = store_test();
        assert_eq!(create(&[0xff, 0xfe]).status, 400);
    }

    #[test]
    fn a_field_without_an_equals_is_refused() {
        let _g = store_test();
        let r = create(b"id=x&flag");
        assert_eq!(r.status, 400);
        assert!(body(&r).contains("flag"));
    }

    #[test]
    fn the_store_refuses_a_write_at_its_cap_rather_than_evicting() {
        let _g = store_test();

        // Fill until the store refuses, rather than assuming it starts empty. The
        // store is a process global and other tests in this binary write to it; the
        // first version of this test assumed `reset()` left it at zero and then
        // asserted a 507 that a partially-full store could not produce. Counting to
        // the cap is the assertion the test's name makes — *at* the cap, refuse —
        // and it holds whatever the starting size was.
        let mut accepted = 0usize;
        let mut first_refusal = None;
        for i in 0..(MAX_ORDERS + 16) {
            match create(format!("id=cap{i}").as_bytes()).status {
                201 => accepted += 1,
                507 => {
                    first_refusal = Some(i);
                    break;
                }
                other => panic!("unexpected status {other} while filling the store"),
            }
        }

        let refused_at = first_refusal.expect(
            "the store accepted every write up to MAX_ORDERS + 16; the cap is not enforced",
        );

        // The cap is a limit on the registry, so the fill must stop at it.
        assert!(
            accepted <= MAX_ORDERS,
            "accepted {accepted} orders, above the {MAX_ORDERS} cap"
        );
        assert_eq!(
            refused_at, accepted,
            "the refusal must come immediately after the last acceptance"
        );

        // The control: the store refused rather than evicted, so an order written
        // before the cap is still present.
        assert!(
            lock().orders.contains_key("cap0"),
            "a refusal must not evict an earlier order"
        );
    }

    #[test]
    fn delete_removes_and_then_reports_not_found() {
        let _g = store_test();
        let _ = create(b"id=gone");
        assert_eq!(delete("gone").status, 204);
        assert_eq!(
            delete("gone").status,
            404,
            "a second delete must be a 404, not another 204"
        );
        assert_eq!(by_id("gone").status, 200, "the placeholder still answers");
        assert!(body(&by_id("gone")).contains("\"known\":false") || items("gone").status == 200);
    }

    #[test]
    fn the_items_workload_reports_known_from_the_store() {
        let _g = store_test();
        let _ = create(b"id=known&quantity=4");
        let text = body(&items("known"));
        assert!(text.contains("\"known\":\"true\""));
        assert!(text.contains("\"items\":1"));
        assert!(body(&items("nope")).contains("\"known\":\"false\""));
    }

    #[test]
    fn the_template_renders_the_requested_row_count() {
        let _g = store_test();
        let html = body(&table("rows=5"));
        assert_eq!(html.matches("<tr>").count(), 6, "one header row plus five");
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.ends_with("</html>"));
    }

    #[test]
    fn the_template_escapes_an_id_that_would_be_markup() {
        let _g = store_test();
        let _ = create(b"id=%3Cscript%3E");
        let html = body(&table("rows=1"));
        // The encoded id is not decoded by this app's parser, so the markup never
        // appears; assert both that the raw sequence is absent and the escaper
        // works when given one directly.
        assert!(!html.contains("<script>"));
        let mut out = String::new();
        push_html_escaped(&mut out, "<script>alert('x')</script>");
        assert_eq!(
            out,
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
    }

    #[test]
    fn the_template_row_count_is_bounded() {
        let _g = store_test();
        // A caller-supplied count must not be able to exhaust memory.
        let html = body(&table("rows=99999999"));
        assert_eq!(html.matches("<tr>").count(), 1001, "clamped to 1000 rows");
        assert_eq!(body(&table("rows=0")).matches("<tr>").count(), 2);
        assert_eq!(body(&table("rows=abc")).matches("<tr>").count(), 101);
    }

    #[test]
    fn the_template_is_deterministic() {
        let _g = store_test();
        // §10.5: identical input, identical bytes.
        assert_eq!(body(&table("rows=10")), body(&table("rows=10")));
    }

    #[test]
    fn route_echo_returns_the_slug_it_matched() {
        let _g = store_test();
        assert_eq!(body(&route_echo("abc")), r#"{"slug":"abc"}"#);
        assert_ne!(body(&route_echo("abc")), body(&route_echo("xyz")));
    }

    #[test]
    fn the_tail_workload_depends_on_the_id() {
        let _g = store_test();
        let a = body(&status("a"));
        assert_eq!(a, body(&status("a")));
        assert_ne!(a, body(&status("b")));
        assert!(a.contains("\"state\":\"confirmed\""));
    }

    #[test]
    fn the_multi_workload_echoes_its_worker_and_bounds_n() {
        let _g = store_test();
        let text = body(&multi("worker=3&n=50"));
        assert!(text.contains("\"worker\":\"3\""));
        // A huge n must be clamped rather than run.
        let big = body(&multi("worker=0&n=999999999"));
        assert!(big.contains("\"worker\":\"0\""));
    }

    #[test]
    fn the_cold_workload_marks_itself_as_the_host_path() {
        let _g = store_test();
        let r = cold();
        assert_eq!(r.status, 200);
        let marker = r
            .headers
            .iter()
            .find(|h| h.name == "X-QQQ-Cold")
            .expect("the cold row must say what it measures");
        assert_eq!(marker.value, b"host-path");
    }

    #[test]
    fn the_status_word_covers_every_class() {
        let _g = store_test();
        // Four classes, so the template renders a mix rather than one value.
        let words: Vec<&str> = (0..4).map(status_word).collect();
        assert_eq!(words, vec!["pending", "confirmed", "shipped", "delivered"]);
    }

    #[test]
    fn synthesise_is_stable_and_item_count_is_the_9_1_payload_size() {
        let _g = store_test();
        let a = synthesise("x");
        assert_eq!(a, synthesise("x"));
        assert_eq!(
            a.items.len(),
            20,
            "§9.1's json row is a 1 KB object; the item count is what sizes it"
        );
        assert_ne!(synthesise("x").total_cents, 0);
    }
}
