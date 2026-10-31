// SPDX-License-Identifier: Apache-2.0

//! Guest-backed Server-Sent Events: guest answers, framed as an event stream.
//!
//! An SSE route is an ordinary HTTP route whose response the server delivers
//! as `text/event-stream`. The bridge has two halves sharing one contract:
//! `sse_handler` answers the gate — one guest call whose answer must declare
//! the event-stream content type (anything else is a 502 naming the
//! requirement) — and `StreamBridge` polls the guest once per event after
//! the head commits, until the guest answers empty or the client leaves.
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
//! # Why polling, not holding the socket
//!
//! A guest export that holds a socket open across writes does not exist in
//! the `qqq:http` ABI (`incoming-streaming` is planned, not defined —
//! `no_multishot_http_guest_export_exists_yet` pins that). Polling is the
//! compatibility shape: one guest call per event over the existing
//! one-shot `handle`, paced so an always-answering guest cannot spin the
//! executor, and bounded by the guest itself — an empty answer ends the
//! stream. A guest that always answers streams until the client
//! disconnects, which is the normal end of an event stream, not an error.

use std::sync::Arc;
use std::time::Duration;

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

/// How long the poll loop waits between guest calls.
///
/// An always-answering guest polled without pause would burn an executor
/// thread and guest fuel at full speed for a stream whose client reads at
/// human pace. Fifty milliseconds bounds a hot guest to twenty calls per
/// second — prompt for live updates, cheap for idle ones — while keeping
/// the multi-event test's three events well inside its timeout.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Consecutive pool-saturation refusals a stream waits out before failing.
///
/// A burst is transient; a pool saturated for ~30 s straight is not — the
/// stream would hold its connection open indefinitely while flat routes
/// starve for the same slots. The cap turns a wedged stream into a failed
/// record the client can reconnect from. The interval stays fixed, with no
/// jitter: this path also serves deterministic mode, and jitter would be
/// hidden randomness there. Lockstep polling across streams is unlikely
/// anyway — each stream's guest-call duration already desynchronizes its
/// polls — so a fixed step plus a cap is the whole mechanism.
const MAX_CONSECUTIVE_RETRIES: u32 = 600;

/// How long to wait before re-polling after `consecutive` saturation
/// refusals, or `None` when the burst has outlasted the stream's patience.
fn retry_delay(consecutive: u32) -> Option<Duration> {
    if consecutive >= MAX_CONSECUTIVE_RETRIES {
        None
    } else {
        Some(POLL_INTERVAL)
    }
}

/// A guest-backed multi-shot event stream: one guest call per event.
///
/// Built per route at dispatch time (`for_route`), then bound per request
/// through [`factory`]: the serve path runs the [`sse_handler`] gate
/// first — its answer is event one — and the poll loop below starts at
/// event two, so the guest is never executed twice for the same event.
/// Every poll goes through the same body-aware dispatch as every write
/// route (generation tracking, budgets, audit), so each event is a real
/// guest execution the audit can attribute, not a replay.
///
/// The loop ends when the guest answers empty (done), answers
/// non-event or non-200 (truncated stream: the only honest signal left
/// after the head committed), or the client disconnects (the normal end
/// of an event stream). There is no event-count cap: a guest that always
/// answers streams until the client leaves, which is what an event
/// stream is.
pub struct StreamBridge {
    guest: qqq_serve::BodyHandler,
    path: String,
}

impl StreamBridge {
    /// Bind the bridge to one `sse` route's guest dispatch and path.
    #[must_use]
    pub fn for_route(dispatch: &qqq_serve::BodyHandler, path: &str) -> Self {
        Self {
            guest: Arc::clone(dispatch),
            path: path.to_owned(),
        }
    }

    /// Build the per-request poll loop, bound to that request's tenant.
    ///
    /// A factory rather than a handler because the loop needs the tenant
    /// the serve path resolved, and registration has no request to read
    /// it from. Threading the tenant through the shared streaming-handler
    /// type instead would touch every streaming caller for one route
    /// kind's benefit.
    #[must_use]
    pub fn factory(&self) -> qqq_serve::server::SseStreamFactory {
        use std::pin::Pin;
        let guest = Arc::clone(&self.guest);
        let path = self.path.clone();
        Arc::new(move |tenant: &str| {
            let guest = Arc::clone(&guest);
            let path = path.clone();
            let tenant = tenant.to_owned();
            Arc::new(
                move |head: &qqq_serve::http1::RequestHead,
                      _matched: &qqq_serve::server::RouteMatch,
                      writer: &mut qqq_serve::stream::StreamWriter<'_>|
                      -> Pin<
                    Box<
                        dyn std::future::Future<Output = Result<(), qqq_serve::stream::StreamError>>
                            + Send
                            + '_,
                    >,
                > {
                    let guest = Arc::clone(&guest);
                    let path = path.clone();
                    // Cloned per call: the handler is `Fn` and may run more
                    // than once, so nothing may move out of its captures.
                    let tenant = tenant.clone();
                    let head = head.clone();
                    Box::pin(async move { Self::run(&head, writer, &guest, &path, &tenant).await })
                },
            )
        })
    }

    /// Poll the guest until it says done, fails, or the client leaves.
    ///
    /// The head is replayed verbatim: the request the client sent is the
    /// request every event answers. (The route matched before the gate
    /// ran; re-matching per poll would let a concurrent table change move
    /// a stream mid-flight, so the match is deliberately not consulted.)
    async fn run(
        head: &qqq_serve::http1::RequestHead,
        writer: &mut qqq_serve::stream::StreamWriter<'_>,
        guest: &qqq_serve::BodyHandler,
        path: &str,
        tenant: &str,
    ) -> Result<(), qqq_serve::stream::StreamError> {
        use qqq_serve::stream::StreamError;
        let guest_call =
            |head: qqq_serve::http1::RequestHead, tenant: String, guest: qqq_serve::BodyHandler| {
                tokio::task::spawn_blocking(move || {
                    guest(&head, &qqq_serve::BodyBytes::Absent, &tenant)
                })
            };
        let mut consecutive_retries: u32 = 0;
        loop {
            let response = guest_call(head.clone(), tenant.to_owned(), Arc::clone(guest))
                .await
                .map_err(|e| {
                    let cancelled = e.is_cancelled();
                    let detail = match e.try_into_panic() {
                        Ok(payload) => format!(
                            "panicked: {:?}",
                            payload.downcast_ref::<String>().map_or(
                                payload
                                    .downcast_ref::<&str>()
                                    .map_or("<non-string panic>", |s| s),
                                String::as_str
                            )
                        ),
                        Err(_) => format!("join failed, cancelled={cancelled}"),
                    };
                    StreamError::Handler(format!("guest poll failed: {detail}"))
                })?;
            match classify_poll(&response, path) {
                PollOutcome::Retry => {
                    // Transient saturation: the pool shed this poll, not the
                    // guest. Wait out the burst and poll again rather than
                    // truncating a stream a momentary overlap would end —
                    // under `workers 1` any concurrent guest execution can
                    // collide with a poll, and a 50 ms wait is invisible
                    // next to event-stream lifetimes. Past the cap the burst
                    // is the steady state, so fail rather than hold the
                    // connection (and the pool pressure) open forever.
                    consecutive_retries += 1;
                    match retry_delay(consecutive_retries) {
                        Some(wait) => tokio::time::sleep(wait).await,
                        None => {
                            return Err(StreamError::Handler(format!(
                                "route {path} is declared `sse` but the pool stayed \
                                 saturated for {consecutive_retries} consecutive polls"
                            )));
                        }
                    }
                }
                PollOutcome::Failed(detail) => return Err(StreamError::Handler(detail)),
                PollOutcome::Done => {
                    // The guest says done: an orderly end, not a truncation.
                    return Ok(());
                }
                PollOutcome::Event(body) => {
                    consecutive_retries = 0;
                    writer
                        .write_now(&body)
                        .await
                        .map_err(|_| StreamError::Transport("client disconnected".to_owned()))?;
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
        }
    }
}

/// What one guest poll means for the stream.
///
/// A poll is a load-bearing decision: the same response shape must mean
/// the same thing every time, or the stream's end becomes a judgment
/// call. `Retry` is deliberately narrow — only the pool-saturation the
/// error taxonomy marks retryable (`QQQ-6001`) waits out a burst. Any
/// other failure ends the stream as `HandlerFailed`, including a
/// saturated buffer or a failed audit persist: those are host faults to
/// surface, not contention to outlast.
#[derive(Debug, PartialEq, Eq)]
enum PollOutcome {
    /// An event to write, verbatim.
    Event(Vec<u8>),
    /// The guest said done: close the stream completed.
    Done,
    /// Transient saturation: wait and poll again.
    Retry,
    /// Anything else, with the message for the failed stream record.
    Failed(String),
}

/// Classify one poll answer into what the stream does next.
///
/// `200` + `text/event-stream` + a body is an event; an empty body with
/// that declaration ends the stream (a guest with nothing to say closes
/// rather than idling forever); a saturated pool (`QQQ-6001`, which the
/// error taxonomy marks retryable) waits out the burst; everything else
/// — guest errors, traps, wrong content type — fails the stream, because
/// a truncated event stream that reads as delivered is worse than one
/// that reports handler failure.
fn classify_poll(response: &qqq_serve::Response, path: &str) -> PollOutcome {
    // Pool saturation arrives as the dispatcher's fail-closed refusal
    // (502 carrying the `InstancePoolExhausted` code name), not as a guest
    // answer: the guest never ran, so there is nothing to fail closed on,
    // and the error taxonomy marks exactly this code retryable.
    if response.status == 502 && response.header("X-QQQ-Error") == Some("InstancePoolExhausted") {
        return PollOutcome::Retry;
    }
    if response.status != 200 || !is_event_stream(response.header("Content-Type")) {
        // The record names the cause, not just the shape: a bare status
        // sends the operator hunting through guest logs for which failure
        // truncated the stream.
        let error = response.header("X-QQQ-Error").unwrap_or("none");
        let snippet: String = String::from_utf8_lossy(&response.body)
            .chars()
            .take(120)
            .collect();
        return PollOutcome::Failed(format!(
            "route {path} is declared `sse` but the guest stopped \
             answering events (status {}, error {error}, body {snippet:?})",
            response.status
        ));
    }
    if response.body.is_empty() {
        return PollOutcome::Done;
    }
    PollOutcome::Event(response.body.clone())
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

    /// Retries wait out a burst, not a steady state: early refusals wait
    /// the fixed step, while a pool saturated past the cap fails the
    /// stream so the client can reconnect instead of holding a wedged
    /// connection open.
    #[test]
    fn retries_wait_then_fail_past_the_cap() {
        assert_eq!(
            retry_delay(1),
            Some(POLL_INTERVAL),
            "the first saturation waits the fixed step"
        );
        assert_eq!(
            retry_delay(MAX_CONSECUTIVE_RETRIES - 1),
            Some(POLL_INTERVAL),
            "the last refusal inside the cap still waits"
        );
        assert_eq!(
            retry_delay(MAX_CONSECUTIVE_RETRIES),
            None,
            "saturation past the cap fails the stream"
        );
        assert_eq!(
            retry_delay(MAX_CONSECUTIVE_RETRIES + 1),
            None,
            "the cap stays failed, it never recovers silently"
        );
    }

    /// A saturated pool waits out the burst instead of truncating: the
    /// guest never ran, so there is nothing to fail closed on, and the
    /// error taxonomy marks exactly this code retryable.
    #[test]
    fn a_saturated_pool_is_a_retry_not_a_truncation() {
        let mut refused = Response::text(502, "the application failed: saturated");
        refused.set_header("X-QQQ-Error", "InstancePoolExhausted");
        assert_eq!(
            classify_poll(&refused, "/events"),
            PollOutcome::Retry,
            "pool saturation must wait, not truncate",
        );
    }

    /// Every other failure ends the stream: a guest 500, a non-event
    /// answer, a wrong content type — each names itself in the failure.
    #[test]
    fn guest_failures_end_the_stream_with_their_reason() {
        let failed = Response::text(500, "boom");
        match classify_poll(&failed, "/events") {
            PollOutcome::Failed(detail) => assert!(
                detail.contains("500"),
                "the failure must name the status: {detail}"
            ),
            other => panic!("a guest 500 must fail the stream, got {other:?}"),
        }
        let html_guest: qqq_serve::BodyHandler =
            Arc::new(|_, _, _| Response::text(200, "<h1>x</h1>"));
        let html = sse_handler(&html_guest, "/events")(&head(), &body(), "t");
        // The gate already refused it with 502; the classifier sees a
        // 502 without the pool-saturation marker, so it stays failed.
        assert_eq!(html.status, 502, "the gate must refuse html: {html:?}");
        assert!(
            matches!(classify_poll(&html, "/events"), PollOutcome::Failed(_)),
            "a gated refusal must fail, not stream"
        );
        // And a bare non-event 200 (a gate that did not run) fails too,
        // naming the status, the error marker, and the body it stopped on.
        let bare = Response::text(200, "<h1>x</h1>");
        assert_eq!(
            classify_poll(&bare, "/events"),
            PollOutcome::Failed(
                "route /events is declared `sse` but the guest stopped \
                 answering events (status 200, error none, body \"<h1>x</h1>\")"
                    .to_owned()
            ),
            "a non-event 200 must fail, not stream html",
        );
    }

    /// An event-stream answer with a body is an event; without one the
    /// guest is done, and an orderly end is not a truncation.
    #[test]
    fn event_and_done_follow_the_body() {
        let event = guest(Some("text/event-stream"), "data: hi\n\n");
        let head = head();
        let response = event(&head, &body(), "t");
        assert_eq!(
            classify_poll(&response, "/events"),
            PollOutcome::Event(b"data: hi\n\n".to_vec()),
            "an event must pass through byte-identical",
        );
        let empty = guest(Some("text/event-stream"), "");
        assert_eq!(
            classify_poll(&empty(&head, &body(), "t"), "/events"),
            PollOutcome::Done,
            "an empty event body ends the stream completed",
        );
    }

    /// Boot a live in-house server for one `/events` sse route backed by
    /// the given guest bytes, and wait until it accepts. Shared by the live
    /// refusal and multi-event tests so neither duplicates the harness:
    /// the registration is exactly production's (gate plus poll loop), so
    /// a registration that drops either half fails here.
    async fn serve_sse_fixture(
        source: &[u8],
    ) -> (
        std::net::SocketAddr,
        std::sync::Arc<crate::guest_handler::GuestApp>,
        tokio::task::JoinHandle<()>,
        qqq_io::listener::Shutdown,
    ) {
        let manifest = qqq_cap::manifest::Manifest::parse(
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\
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
                source,
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
            .expect("the fixture guest must build"),
        );
        let dispatch = qqq_serve::server::Dispatch::flat(std::sync::Arc::new(
            |_head: &qqq_serve::RequestHead, _m: &qqq_serve::server::RouteMatch| {
                qqq_serve::Response::text(500, "flat must not answer an sse route")
            },
        ))
        .with_sse(
            "feed",
            sse_handler(&app.dispatch_with_body(), "/events"),
            StreamBridge::for_route(&app.dispatch_with_body(), "/events").factory(),
        );

        let mut table = qqq_serve::route::RouteTable::new();
        table
            .insert(
                qqq_serve::route::Route::new(qqq_serve::route::Method::Get, "/events", "feed")
                    .expect("valid route"),
            )
            .expect("distinct route");
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr: std::net::SocketAddr = probe.local_addr().expect("addr");
        drop(probe);
        let listen = qqq_io::listener::ListenAddr::parse(&addr.to_string()).expect("parses");
        let shutdown = qqq_io::listener::Shutdown::new();
        let local = shutdown.clone();
        let server_task = tokio::spawn(async move {
            let _ = qqq_serve::server::serve(
                qqq_serve::server::ServerConfig::for_addr(listen),
                table,
                qqq_serve::server::TenantDispatch::new(dispatch),
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
        (addr, app, server_task, shutdown)
    }

    /// A live SSE route through `serve` refuses a guest that does not
    /// declare an event stream — fail closed at the only point the
    /// mismatch is visible, through the dispatched path the manifest
    /// `sse` kind registers, not the handler in isolation.
    #[tokio::test]
    async fn a_live_sse_route_refuses_a_non_event_answer_by_name() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (addr, app, server_task, shutdown) =
            serve_sse_fixture(include_bytes!("../tests/fixtures/echo-http.wat")).await;

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

    /// One stream, many guest executions: the static event guest answers
    /// every poll, so three events arrive on one open stream — and the
    /// audit shows at least three guest executions for that one stream,
    /// which is what makes this multi-shot rather than a replay. The
    /// stream ends when the client disconnects (the normal end), not
    /// when the guest runs out of answers.
    #[tokio::test]
    async fn a_live_sse_stream_carries_many_guest_events() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (addr, app, server_task, shutdown) =
            serve_sse_fixture(include_bytes!("../tests/fixtures/sse-event.wat")).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client
            .write_all(b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        client.flush().await.expect("flush");
        // Read until three events arrive on the one open stream: a
        // one-shot bridge would have closed after the first.
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let mut chunk = [0u8; 4096];
                match client.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => match chunk.get(..n) {
                        Some(bytes) => raw.extend_from_slice(bytes),
                        None => break,
                    },
                }
                if raw.windows(5).filter(|w| *w == b"data:").count() >= 3 {
                    break;
                }
            }
        })
        .await;
        let text = String::from_utf8_lossy(&raw).into_owned();
        assert!(text.starts_with("HTTP/1.1 200"), "the stream must open 200");
        assert!(
            text.matches("data:").count() >= 3,
            "one stream must carry three guest events, not one-and-close: {text:?}"
        );
        drop(client);
        // Every event went through the guest: at least three executions
        // for the one stream. A replay would show one.
        let (records, _) = app.audit_snapshot();
        assert!(
            records.len() >= 3,
            "three events must mean three guest executions, found {}",
            records.len()
        );
        shutdown.signal();
        let _ = server_task.await;
    }

    /// An empty event body ends the stream orderly on the wire: the head
    /// commits 200 with the event-stream declaration, then the stream
    /// closes with no `data:` lines — `Done`, not a truncation and not
    /// an idle hold. The unit pin covers the classifier; this covers the
    /// dispatched path the manifest `sse` kind registers.
    #[tokio::test]
    async fn a_live_sse_stream_ends_when_the_guest_is_done() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (addr, _app, server_task, shutdown) =
            serve_sse_fixture(include_bytes!("../tests/fixtures/sse-empty.wat")).await;

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
            text.starts_with("HTTP/1.1 200"),
            "an empty event answer still opens 200: {text:?}"
        );
        assert!(
            text.contains("text/event-stream"),
            "the declaration the gate checked must be on the wire: {text:?}"
        );
        assert!(
            !text.contains("data:"),
            "a guest with nothing to say sends no events: {text:?}"
        );
        shutdown.signal();
        let _ = server_task.await;
    }

    /// The one-shot bridge is load-bearing on the guest HTTP ABI having no
    /// multi-shot export: the day another interface (e.g. a planned
    /// `incoming-streaming`) lands in the `qqq:http` package, this test
    /// goes red and forces a revisit of the polling bridge — a native
    /// guest-driven push would replace polling per event, not extend it.
    /// Scoped to the HTTP package on purpose: other
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

    /// Twenty sequential guest calls all serve: the pool slot is released
    /// on every exit path, so a stream's polls never starve each other and
    /// a burst of streams cannot wedge the pool. A leak here would shrink
    /// the capacity monotonically — the server would get slower the more
    /// it serves, and multi-event streams would be the first to notice.
    #[test]
    fn sequential_guest_calls_release_their_pool_slots() {
        let source = include_str!("../tests/fixtures/sse-event.wat");
        let manifest = qqq_cap::manifest::Manifest::parse(
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\
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
            .expect("the event fixture must build"),
        );
        let guest = app.dispatch_with_body();
        let head = qqq_serve::http1::RequestHead {
            method: qqq_serve::route::Method::Get,
            target: "/events".to_owned(),
            version: qqq_serve::http1::Version::Http11,
            headers: Vec::new(),
            content_length: None,
            chunked: false,
        };
        for _ in 1..=20 {
            let response = guest(&head, &qqq_serve::BodyBytes::Absent, "shop");
            assert_eq!(
                response.status, 200,
                "twenty sequential guest calls must all serve: {response:?}"
            );
        }
    }
}
