// SPDX-License-Identifier: Apache-2.0

//! Guest-backed Server-Sent Events: one guest answer, framed as an event stream.
//!
//! An SSE route is an ordinary HTTP route whose response the server delivers
//! as `text/event-stream`. The bridge calls the guest exactly once through
//! the body-aware dispatch (hot-swap generation tracking, budgets, audit —
//! the same path as every write route), requires the guest to answer with
//! the event-stream content type, and adds the framing headers the protocol's
//! deployment needs.
//!
//! # Why the guest must declare the content type
//!
//! The manifest marks the route `sse`, but the route's bytes come from the
//! guest. If the guest answers anything else, serving it as an event stream
//! anyway would reinterpret the payload — and an EventSource client told
//! `text/html` would render events as a document instead of dispatching
//! them. A 502 naming the requirement fails closed at the only point the
//! mismatch is visible.
//!
//! # Why the host adds framing headers
//!
//! `Cache-Control: no-store` and `X-Accel-Buffering: no` are not content;
//! they are delivery requirements a guest cannot know about, and omitting
//! them is the most common reason an SSE endpoint works locally and dies
//! behind a load balancer. See `qqq_serve::sse` for the full rationale.
//!
//! # What this is not
//!
//! It is not a multi-shot push channel: one request produces one guest
//! answer, delivered as one body. A stream that stays open across guest
//! calls needs the `incoming-streaming` WIT interface, which does not exist
//! yet — that is the follow-up, and this bridge is the shape it must keep
//! working through, not a substitute for it.

use std::sync::Arc;

/// Build a body-aware handler that serves one guest answer as an event stream.
///
/// ```
/// # use std::sync::Arc;
/// # use qqq_run::guest_sse::sse_handler;
/// let guest: qqq_serve::BodyHandler = Arc::new(|_, _, _| {
///     let mut response = qqq_serve::Response::text(200, "data: hi\n\n");
///     response.set_header("Content-Type", "text/event-stream");
///     response
/// });
/// let handler = sse_handler(&guest, "/events");
/// let head = qqq_serve::http1::RequestHead {
///     method: qqq_serve::route::Method::Get,
///     target: "/events".to_owned(),
///     version: qqq_serve::http1::Version::Http11,
///     headers: Vec::new(),
///     content_length: None,
///     chunked: false,
/// };
/// let response = handler(&head, &qqq_serve::BodyBytes::Absent, "tenant-a");
/// assert_eq!(response.status, 200);
/// assert_eq!(response.header("Cache-Control"), Some("no-store"));
/// ```
#[must_use]
pub fn sse_handler(dispatch: &qqq_serve::BodyHandler, path: &str) -> qqq_serve::BodyHandler {
    let dispatch = Arc::clone(dispatch);
    let path = path.to_owned();
    Arc::new(
        move |head: &qqq_serve::RequestHead, body: &qqq_serve::BodyBytes, tenant: &str| {
            let response = dispatch(head, body, tenant);
            if is_event_stream(response.header("Content-Type")) {
                let mut framed = response;
                framed.set_header("Cache-Control", "no-store");
                framed.set_header("X-Accel-Buffering", "no");
                framed
            } else {
                let mut refused = qqq_serve::Response::text(
                    502,
                    format!(
                        "route {path} is declared `sse` but the guest answered \
                         content-type `{}`; an event stream requires \
                         `Content-Type: text/event-stream`",
                        response.header("Content-Type").unwrap_or("(absent)")
                    ),
                );
                refused.set_header("X-QQQ-Error", "sse-content-type");
                refused
            }
        },
    )
}

/// Whether a `Content-Type` value declares an event stream.
///
/// Compared as a media type, not a string: `text/event-stream;
/// charset=utf-8` is the same stream with an explicit charset (which
/// `qqq-serve/src/sse.rs` permits), and the type itself is
/// case-insensitive per RFC 9110 §5.6.5. Only `utf-8` is accepted as a
/// parameter — any other parameter would change the bytes' meaning.
///
/// ```
/// # use qqq_run::guest_sse::sse_handler;
/// # use std::sync::Arc;
/// let guest: qqq_serve::BodyHandler = Arc::new(|_, _, _| {
///     qqq_serve::Response::text(200, "x")
/// });
/// let handler = sse_handler(&guest, "/events");
/// # let head = qqq_serve::http1::RequestHead {
/// #     method: qqq_serve::route::Method::Get,
/// #     target: "/events".to_owned(),
/// #     version: qqq_serve::http1::Version::Http11,
/// #     headers: Vec::new(),
/// #     content_length: None,
/// #     chunked: false,
/// # };
/// # let response = handler(&head, &qqq_serve::BodyBytes::Absent, "t");
/// assert_eq!(response.status, 502);
/// ```
fn is_event_stream(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let mut parts = value.split(';');
    let Some(top) = parts.next() else {
        return false;
    };
    if !top.trim().eq_ignore_ascii_case("text/event-stream") {
        return false;
    }
    for param in parts {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        if !param.eq_ignore_ascii_case("charset=utf-8") {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use qqq_serve::http1::{RequestHead, Version};
    use qqq_serve::response::Response;
    use qqq_serve::route::Method;

    fn head() -> RequestHead {
        RequestHead {
            method: Method::Get,
            target: "/events".to_owned(),
            version: Version::Http11,
            headers: Vec::new(),
            content_length: None,
            chunked: false,
        }
    }

    fn body() -> qqq_serve::BodyBytes {
        qqq_serve::BodyBytes::Absent
    }

    fn guest(content_type: Option<&str>, text: &str) -> qqq_serve::BodyHandler {
        let text = text.to_owned();
        let content_type = content_type.map(str::to_owned);
        Arc::new(
            move |_head: &RequestHead, _body: &qqq_serve::BodyBytes, _tenant: &str| {
                let mut response = Response::text(200, text.clone());
                // A guest that does not declare an event stream must not be
                // reinterpreted as one: remove the default text/plain so the
                // bridge sees exactly what the guest said.
                response
                    .headers
                    .retain(|(name, _)| !name.eq_ignore_ascii_case("content-type"));
                if let Some(ct) = &content_type {
                    response.set_header("Content-Type", ct);
                }
                response
            },
        )
    }

    /// An event-stream answer keeps its body and gains the framing headers.
    #[test]
    fn an_event_stream_answer_is_framed_not_reinterpreted() {
        let handler = sse_handler(&guest(Some("text/event-stream"), "data: hi\n\n"), "/events");
        let response = handler(&head(), &body(), "tenant-a");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.header("Content-Type"),
            Some("text/event-stream"),
            "the guest's declaration must survive"
        );
        assert_eq!(response.header("Cache-Control"), Some("no-store"));
        assert_eq!(response.header("X-Accel-Buffering"), Some("no"));
        assert_eq!(
            String::from_utf8(response.body).expect("utf8"),
            "data: hi\n\n",
            "the payload passes through untouched"
        );
    }

    /// Anything else the guest answers is refused with the requirement named.
    #[test]
    fn a_non_event_stream_answer_is_refused_by_name() {
        for content_type in [None, Some("text/html")] {
            let handler = sse_handler(&guest(content_type, "<h1>hi</h1>"), "/events");
            let response = handler(&head(), &body(), "tenant-a");
            assert_eq!(
                response.status, 502,
                "a non-event answer must fail closed: {content_type:?}"
            );
            assert!(
                String::from_utf8(response.body)
                    .expect("utf8")
                    .contains("text/event-stream"),
                "the refusal must name the required content type"
            );
        }
    }

    /// The media type compares as a type, not a string: an explicit
    /// `charset=utf-8` is the same stream, and the type is
    /// case-insensitive. Any other parameter changes the meaning and is
    /// refused rather than reinterpreted.
    #[test]
    fn event_stream_media_type_allows_charset_nothing_else() {
        for content_type in [
            "text/event-stream",
            "text/event-stream; charset=utf-8",
            "Text/Event-Stream; Charset=UTF-8",
            "text/event-stream ; charset=utf-8 ",
        ] {
            let handler = sse_handler(&guest(Some(content_type), "data: hi\n\n"), "/events");
            let response = handler(&head(), &body(), "tenant-a");
            assert_eq!(
                response.status, 200,
                "an event-stream declaration must survive: {content_type:?}"
            );
        }
        for content_type in [
            "text/event-stream; charset=latin-1",
            "text/html; charset=utf-8",
        ] {
            let handler = sse_handler(&guest(Some(content_type), "data: hi\n\n"), "/events");
            let response = handler(&head(), &body(), "tenant-a");
            assert_eq!(
                response.status, 502,
                "a different media type must fail closed: {content_type:?}"
            );
        }
    }

    /// A live SSE route through `serve` refuses a guest that does not
    /// declare an event stream — fail closed at the only point the
    /// mismatch is visible, through the dispatched path the manifest
    /// `sse` kind registers, not the handler in isolation.
    #[tokio::test]
    async fn a_live_sse_route_refuses_a_non_event_answer_by_name() {
        use std::net::SocketAddr;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let source = include_str!("../tests/fixtures/echo-http.wat");
        let manifest = qqq_cap::Manifest::parse(
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n\
             [capabilities.http]\nserver = true\n",
        )
        .expect("a minimal manifest parses");
        let engine = wasmtime::Engine::new(
            &qqq_host::config::EngineConfig::default()
                .to_wasmtime_config()
                .expect("engine config"),
        )
        .expect("engine");
        let app = std::sync::Arc::new(
            crate::guest_handler::GuestApp::with_capacity(
                engine,
                source.as_bytes(),
                qqq_cap::resolve::GrantSet::from_manifest(&manifest),
                qqq_host::LimitSet {
                    memory_bytes: 64 * 1024 * 1024,
                    fuel: 1_000_000_000,
                    epoch_deadline_ms: 10_000,
                    max_open_handles: 64,
                    max_subrequests: 16,
                },
                "127.0.0.1:8080",
                1,
            )
            .expect("the echo fixture must build"),
        );
        // The echo guest answers with no `Content-Type`: the bridge must
        // refuse rather than reinterpret the bytes as an event stream.
        let handler = sse_handler(&app.dispatch_with_body(), "/events");

        let mut table = qqq_serve::route::RouteTable::new();
        table
            .insert(
                qqq_serve::route::Route::new(qqq_serve::route::Method::Get, "/events", "feed")
                    .expect("valid route"),
            )
            .expect("distinct route");
        let dispatch = qqq_serve::server::Dispatch::flat(std::sync::Arc::new(
            |_head: &qqq_serve::RequestHead, _m: &qqq_serve::RouteMatch| {
                qqq_serve::Response::text(500, "flat must not answer an sse route")
            },
        ))
        .with_body("feed", handler);

        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr: SocketAddr = probe.local_addr().expect("addr");
        drop(probe);
        let listen = qqq_io::listener::ListenAddr::parse(&addr.to_string()).expect("parses");
        let shutdown = qqq_io::listener::Shutdown::new();
        let local = shutdown.clone();
        let server_task = tokio::spawn(async move {
            let _ = qqq_serve::server::serve(
                qqq_serve::server::ServerConfig::for_addr(listen),
                table,
                dispatch,
                local,
                qqq_serve::access_log::Logger::new(
                    qqq_serve::access_log::Format::Json,
                    qqq_serve::access_log::Level::Error,
                ),
            )
            .await;
        });
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        client.flush().await.expect("flush");
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut raw),
        )
        .await;
        let text = String::from_utf8_lossy(&raw).into_owned();
        assert!(
            text.contains("502"),
            "a non-event answer must fail closed on the wire: {text}"
        );
        assert!(
            text.contains("text/event-stream"),
            "the refusal must name the required content type: {text}"
        );
        // The refused request still ran through the guest, so its audit row
        // exists and carries the loopback tenant the peer resolved to.
        let (records, _) = app.audit_snapshot();
        assert!(
            records
                .iter()
                .any(|r| r.tenant.as_ref().is_some_and(|t| t.as_str() == "127.0.0.1")),
            "the guest call must be attributed to the calling tenant"
        );
        shutdown.signal();
        let _ = server_task.await;
    }

    /// The one-shot bridge is load-bearing on the guest HTTP ABI having no
    /// multi-shot export: the day another interface (e.g. a planned
    /// `incoming-streaming`) lands in the `qqq:http` package, this test
    /// goes red and forces `SRV-024`'s remaining half — a real multi-shot
    /// bridge — to be built instead of silently extending the one-shot
    /// adaptation. Scoped to the HTTP package on purpose: other
    /// capabilities (e.g. `qqq:queue/messaging`) are guest-to-host calls,
    /// not host-to-guest pushes, so they must not trip this wire.
    #[test]
    fn no_multishot_http_guest_export_exists_yet() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../wit");
        let mut names = std::collections::BTreeSet::new();
        for relative in ["qqq-http.wit", "app/deps/qqq-http/qqq-http.wit"] {
            let path = root.join(relative);
            let text = std::fs::read_to_string(&path).expect("http wit must read");
            for line in text.lines().map(str::trim) {
                let line = line.split("//").next().unwrap_or("").trim();
                if let Some(name) = line
                    .strip_prefix("interface ")
                    .and_then(|rest| rest.split_whitespace().next())
                {
                    names.insert(format!(
                        "{}:{}",
                        relative,
                        name.trim_end_matches('{').trim()
                    ));
                }
            }
        }
        let expected: std::collections::BTreeSet<String> = [
            "qqq-http.wit:http",
            "qqq-http.wit:incoming-handler",
            "app/deps/qqq-http/qqq-http.wit:http",
            "app/deps/qqq-http/qqq-http.wit:incoming-handler",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(
            names, expected,
            "the qqq:http package gained an interface — build the multi-shot \
             bridge (SRV-024) instead of extending the one-shot adaptation"
        );
    }
}
