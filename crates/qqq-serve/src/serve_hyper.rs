// SPDX-License-Identifier: Apache-2.0

//! Hyper-backed HTTP/1.1 serving for flat routes (`F-16` Option A).
//!
//! One connection in, the QQQ pipeline around it: the request head is
//! mapped from hyper's parse to the same [`RequestHead`] the in-house
//! path produces, the same pre-reading gates run in the same order
//! (loopback `Host`, process budget, tenant limits, auth), the body is
//! collected through the same [`BodyReader`], dispatch reuses
//! [`dispatch_off_thread`], and rendering validates through
//! [`validate_outbound`] before hyper frames it. Policy lives in exactly
//! one place; this module is the second transport that calls it.
//!
//! # What this serves, stated plainly
//!
//! Flat routes, the metrics path, and CORS preflights — as ordinary
//! responses through hyper's HTTP/1.1 driver. WebSocket and streaming
//! routes answer `501` here, loudly: the upgrade and stream loops still
//! belong to the in-house path until the parity commit wires them to
//! hyper's upgrade and streaming bodies. A silent 404 for those routes
//! would be a fork; the 501 names the transport gap instead.
//!
//! # Where the behaviours differ from the in-house path, and why
//!
//! * Hyper parses the head itself, so malformed heads hyper rejects
//!   (bad header syntax, obs-fold, over-count/size lines) close the
//!   connection instead of answering `400`/`431`. Anything hyper *does*
//!   parse gets the in-house refusal taxonomy byte-for-byte, because the
//!   refusal is built by the same constructors from the same
//!   [`ParseError`]. The direction is safe: nothing hyper accepts is
//!   refused in-house, and the differential suite pins every row.
//! * Header names arrive lowercased (hyper normalises); the in-house
//!   path preserves case. Routing, CORS, and limits all match
//!   case-insensitively, so the difference is representation, not
//!   policy — except for a handler that reflects header names, which
//!   the differential echo test pins.
//! * The idle bound wraps the whole connection rather than tracking
//!   activity: hyper offers no idle callback, so an activity clock
//!   would need an IO wrapper. A 75 s connection ceiling is the
//!   conservative approximation; the drain commit refines it.
//! * A request past the per-connection ceiling is answered `503` and
//!   closed, where the in-house path closes bare. The connection is
//!   still reclaimed; the status tells the client why.
//! * A `1xx` handler response becomes `500`: a flat response is final,
//!   and `1xx` has no final meaning. Handlers never emit one; the
//!   branch exists so a future one cannot desynchronise the stream.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use futures_core::Stream as _;
use http_body_util::{BodyExt as _, BodyStream};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::TcpStream;

use crate::body::{BodyChunk, BodyReader};
use crate::body_bytes::BodyBytes;
use crate::http1::{MAX_REQUEST_BYTES, MAX_TARGET_BYTES, ParseError, RequestHead, Version};
use crate::response::{self, Response, validate_outbound};
use crate::route::{Method, RouteTable};
use crate::server::{
    ConnectionContext, Dispatch, Served, apply_cors, config_max_request_bytes, dispatch_off_thread,
    emit_record, emit_span, is_head, micros_since, record_metrics, split_target,
};
use crate::transport::HyperLimits;
use crate::ws::loopback_host_allowed;

/// Serve one TCP connection through hyper's HTTP/1.1 driver.
///
/// The accept loop calls this exactly where it calls the in-house
/// `serve_connection`: after ledger admission, with the same context.
/// Ledger release, metrics, and the accept bound stay the caller's job,
/// because they describe the accept, not the transport.
pub async fn serve_hyper_h1(
    stream: TcpStream,
    table: &RouteTable,
    dispatch: &Dispatch,
    limits: &HyperLimits,
    ctx: &ConnectionContext<'_>,
) -> Served {
    let mut builder = hyper::server::conn::http1::Builder::new();
    crate::transport::apply_http1(&mut builder, limits);
    let served = AtomicU64::new(0);
    let state = State {
        table,
        dispatch,
        limits,
        ctx,
        served: &served,
    };
    let service = service_fn(|request: hyper::Request<Incoming>| answer(request, &state));
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => {
            // The connection ended. Per-request outcomes already went to
            // the access log; this is the connection's. A hyper-side
            // header timeout is its own outcome; anything else is the
            // client going away.
            match result {
                Ok(()) => Served::ClientClosed,
                Err(error) if error.is_timeout() => Served::HeaderTimeout,
                Err(_error) => Served::ClientClosed,
            }
        }
        () = ctx.shutdown.wait() => {
            // Hyper's own graceful path: stop keep-alive, finish
            // in-flight within the drain bound, then report drained.
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(limits.drain_timeout, &mut connection).await;
            Served::Drained
        }
        () = tokio::time::sleep(limits.idle_timeout) => Served::IdleTimeout,
    }
}

/// Everything one request borrows, shared across the connection's requests.
#[derive(Clone, Copy)]
struct State<'a> {
    table: &'a RouteTable,
    dispatch: &'a Dispatch,
    limits: &'a HyperLimits,
    ctx: &'a ConnectionContext<'a>,
    served: &'a AtomicU64,
}

/// The pre-reading gates, in `refuse_before_reading` order.
///
/// Returns the refusal — rendered and recorded — when a gate fires, so
/// `answer` stays a pipeline rather than growing past the line budget.
/// Same order, same shapes, same records as the in-house path: loopback
/// `Host`, process budget, tenant limits, auth.
fn refuse_early(
    state: &State<'_>,
    head: &RequestHead,
    path: &str,
    span: u64,
    started: Instant,
) -> Option<hyper::Response<http_body_util::Full<Bytes>>> {
    let ctx = state.ctx;
    let tenant_key = ctx.id.tenant;
    let tenant: &str = &ctx.id.tenant_label;
    if ctx.loopback_only {
        let host = head.header("host").unwrap_or("");
        if !loopback_host_allowed(host, &ctx.ws.extra_hosts) {
            let response = Response::text(421, "misdirected request");
            return Some(close_after(render_recorded(
                state,
                Some((head, path)),
                &response,
                0,
                started,
            )));
        }
    }
    if let Some(budget) = ctx.global_requests
        && !budget.admit(Instant::now())
    {
        if let Some(metrics) = ctx.metrics {
            metrics.record_global_request_refusal();
        }
        let mut response = Response::text(
            503,
            "the server is at its process-wide admission budget; retry shortly",
        );
        response.set_header("retry-after", "1");
        return Some(close_after(render_recorded(
            state,
            Some((head, path)),
            &response,
            0,
            started,
        )));
    }
    if let Some(limits) = ctx.limits {
        if let Some(declared) = head.content_length
            && limits.check_body(tenant_key, declared).is_err()
        {
            if let Some(metrics) = ctx.metrics {
                let label = ctx.tenant_labels.label(tenant);
                metrics.record_body_limit(label.as_str());
            }
            let response = Response::text(413, "this tenant's request body exceeded its limit");
            return Some(close_after(render_recorded(
                state,
                Some((head, path)),
                &response,
                0,
                started,
            )));
        }
        let limit_started = Instant::now();
        let over = limits.check_and_record(tenant_key, Instant::now()).is_err();
        emit_span(ctx, tenant, 8, span, micros_since(limit_started), over);
        if over {
            let response = Response::text(429, "this tenant has exceeded its request limit");
            return Some(close_after(render_recorded(
                state,
                Some((head, path)),
                &response,
                0,
                started,
            )));
        }
    }
    if let Some(policy) = ctx.auth
        && let Some(matched) = state.table.match_route(head.method, path)
    {
        let policy_started = Instant::now();
        let decision = policy.decide(&matched);
        let refused = matches!(decision, crate::auth::Decision::Refuse { .. });
        emit_span(ctx, tenant, 5, span, micros_since(policy_started), refused);
        if let crate::auth::Decision::Refuse { mode } = decision {
            let body = format!(
                "this route is not served: its manifest entry requires `auth = \"{mode}\"`"
            );
            let mut response = Response::text(403, body);
            response.set_header("X-QQQ-Error", "unauthenticated");
            response.set_header("X-QQQ-Auth-Mode", mode);
            return Some(close_after(render_recorded(
                state,
                Some((head, path)),
                &response,
                0,
                started,
            )));
        }
    }
    None
}

/// Metrics path, preflight, and the upgrade/stream gap.
///
/// Returns the response — rendered and recorded — when the request is
/// not an ordinary flat one. Order mirrors `serve_special_route`:
/// server-owned metrics path first, preflight before routing, then the
/// loud 501 for routes whose loop lives elsewhere.
fn serve_special(
    state: &State<'_>,
    head: &RequestHead,
    path: &str,
    started: Instant,
) -> Option<hyper::Response<http_body_util::Full<Bytes>>> {
    let ctx = state.ctx;
    if let Some(metrics_path) = ctx.metrics_path
        && path == metrics_path
        && let Some(metrics) = ctx.metrics
    {
        let mut response = Response::text(200, metrics.render_prometheus());
        response.set_header("content-type", "text/plain; version=0.0.4; charset=utf-8");
        return Some(close_after(render_recorded(
            state,
            Some((head, path)),
            &response,
            0,
            started,
        )));
    }
    if head.method == Method::Options
        && let Some(requested) = head.header("access-control-request-method")
        && let Some(cors) = ctx.cors
    {
        if head.chunked || head.content_length.is_some_and(|n| n > 0) {
            let response = response::from_error(&response::parse_error_response(
                "special routes do not accept an HTTP request body; send the body to an ordinary route",
            ));
            return Some(close_after(render_recorded(
                state,
                Some((head, path)),
                &response,
                0,
                started,
            )));
        }
        let decision = cors.preflight(
            head.header("origin"),
            Some(requested),
            head.header("access-control-request-headers"),
        );
        let mut response = Response::status(if decision.is_granted() { 204 } else { 403 });
        for (name, value) in decision.headers() {
            response.set_header(name, value);
        }
        return Some(close_after(render_recorded(
            state,
            Some((head, path)),
            &response,
            0,
            started,
        )));
    }
    if let Some(matched) = state.table.match_route(head.method, path)
        && (state.dispatch.websocket_for(&matched.handler).is_some()
            || state.dispatch.streaming_for(&matched.handler).is_some())
    {
        let mut response = Response::text(
            501,
            "this route needs the WebSocket or streaming loop, which the hyper path does not serve yet",
        );
        response.set_header("X-QQQ-Error", "hyper-transport-gap");
        return Some(close_after(render_recorded(
            state,
            Some((head, path)),
            &response,
            0,
            started,
        )));
    }
    None
}

/// The per-connection ceiling decision for one request start.
///
/// `served` is the count before this request (the `fetch_add` return),
/// mirroring `Connection`'s `RequestLimit`: serve while under, warn on
/// the response that reaches the ceiling, refuse past it. The refuse
/// arm is unreachable over sequential HTTP/1 — hyper closes after the
/// warned response before reading another — and exists for multiplexed
/// HTTP/2, where a second stream can start past the ceiling mid-flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ceiling {
    /// Serve normally.
    Serve,
    /// Serve, but this response must say the connection ends here.
    Warn,
    /// Do not serve: answer `503` and close.
    Refuse,
}

fn ceiling_for(served: u64, max: u32) -> Ceiling {
    if served >= u64::from(max) {
        Ceiling::Refuse
    } else if u64::from(max) == served + 1 {
        Ceiling::Warn
    } else {
        Ceiling::Serve
    }
}
///
/// Recording (access log, metrics, spans) happens inside, at the same
/// points the in-house path records, because a hyper request invisible
/// in the log is a request the operator cannot see refused. The result
/// never errors: every failure below has a response, so the connection
/// always gets an answer rather than an abort.
async fn answer(
    request: hyper::Request<Incoming>,
    state: &State<'_>,
) -> Result<hyper::Response<http_body_util::Full<Bytes>>, hyper::Error> {
    let ctx = state.ctx;
    let tenant: &str = &ctx.id.tenant_label;
    let request_started = Instant::now();

    // The per-connection ceiling first, mirroring `Connection`'s
    // `RequestLimit`: the in-house path checks before reading, so a
    // request past the ceiling is never served. Here it is answered
    // `503` rather than closed bare, so the client learns why — the
    // connection is still reclaimed either way, and there is no head
    // to log, mirroring the in-house silence.
    let served = state.served.fetch_add(1, Ordering::SeqCst);
    let ceiling = ceiling_for(served, state.limits.max_requests_per_connection);
    if ceiling == Ceiling::Refuse {
        let response = Response::text(503, "this connection served its request ceiling");
        return Ok(close_after(render_validated(
            &response,
            false,
            state.limits,
        )));
    }

    // --- The head, mapped to the in-house taxonomy ----------------------
    //
    // No access record on this path, mirroring `reject_parse_error`: an
    // unreadable head has no method or path worth logging.
    let head = match map_head(&request) {
        Ok(head) => head,
        Err(error) => {
            let response =
                response::from_error(&response::parse_error_response(&error.to_string()));
            return Ok(close_after(render_validated(
                &response,
                false,
                state.limits,
            )));
        }
    };
    let (path, _query) = split_target(&head.target);
    let span = state.served.load(Ordering::SeqCst);

    // --- The gates that must run before anything is read -----------------
    //
    // Same order as `refuse_before_reading`: loopback `Host`, process
    // budget, tenant limits, auth. Same shapes, same records.
    if let Some(refusal) = refuse_early(state, &head, path, span, request_started) {
        return Ok(refusal);
    }

    // --- Metrics path, preflight, upgrades: off the flat path ------------
    if let Some(special) = serve_special(state, &head, path, request_started) {
        return Ok(special);
    }

    // --- The body, through the shared reader ------------------------------
    //
    // `request` is consumed here; every head fact needed below was
    // extracted above the move.
    let Some((body, body_bytes)) = collect_body(request.into_body(), &head).await else {
        if let Some(metrics) = ctx.metrics {
            let label = ctx.tenant_labels.label(tenant);
            metrics.record_body_limit(label.as_str());
        }
        let response = response::from_error(&response::error_response(
            &qqq_core::Error::new(
                qqq_core::ErrorCode::RequestBodyTooLarge,
                "the request body exceeded max_request_bytes while arriving",
            ),
            false,
        ));
        eprintln!(
            "HYPERDBG reject_body shape: status={} headers={:?}",
            response.status, response.headers
        );
        return Ok(close_after(render_recorded(
            state,
            Some((&head, path)),
            &response,
            0,
            request_started,
        )));
    };

    // --- Dispatch, CORS, record, render ------------------------------------
    let route_started = Instant::now();
    let response =
        dispatch_off_thread(state.table, state.dispatch, &head, path, &body, tenant).await;
    emit_span(ctx, tenant, 3, span, micros_since(route_started), false);
    let response = apply_cors(response, &head, ctx.cors);
    let rendered = render_recorded(
        state,
        Some((&head, path)),
        &response,
        body_bytes,
        request_started,
    );
    // The ceiling warning, mirroring `Connection`: the response that
    // reaches the ceiling says the connection ends here.
    if ceiling == Ceiling::Warn {
        return Ok(close_after(rendered));
    }
    Ok(rendered)
}

/// Render a QQQ response for a recorded request: validate, map to hyper,
/// emit the access record and the metric — the same facts from the same
/// inputs, so the log and the counters cannot drift.
fn render_recorded(
    state: &State<'_>,
    known: Option<(&RequestHead, &str)>,
    response: &Response,
    body_bytes: u64,
    started: Instant,
) -> hyper::Response<http_body_util::Full<Bytes>> {
    let ctx = state.ctx;
    let tenant: &str = &ctx.id.tenant_label;
    if let Some((head, path)) = known {
        let span = state.served.load(Ordering::SeqCst);
        emit_record(
            ctx.logger,
            crate::server::access_record(head, path, response, tenant, ctx.id.trace, span),
        );
        if let Some(metrics) = ctx.metrics {
            record_metrics(
                metrics,
                ctx.tenant_labels,
                head,
                response,
                started,
                tenant,
                body_bytes,
            );
        }
        render_validated(response, is_head(head), state.limits)
    } else {
        render_validated(response, false, state.limits)
    }
}

/// Mark a rendered response to close the connection after it.
///
/// The in-house path closes the socket for every one of these cases
/// (unread body, untrustworthy framing, one-shot routes); hyper closes
/// on the header instead.
fn close_after(
    mut response: hyper::Response<http_body_util::Full<Bytes>>,
) -> hyper::Response<http_body_util::Full<Bytes>> {
    response.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
    response
}

/// Validate a response and map it to hyper's framing.
///
/// `validate_outbound` is the F-02 gate: a bad handler response becomes
/// `500`, never a split stream. Framing headers stay hyper's, exactly as
/// the in-house writer owns them: a caller cannot contradict the
/// framing. `head_request` strips the body but keeps the real length,
/// mirroring `response_body_for_wire`.
fn render_validated(
    response: &Response,
    head_request: bool,
    limits: &HyperLimits,
) -> hyper::Response<http_body_util::Full<Bytes>> {
    let replacement: Response;
    let validated = match validate_outbound(response, limits.max_response_body_bytes) {
        Ok(()) => response,
        Err(refusal) => {
            replacement = refusal.replacement();
            &replacement
        }
    };
    // A flat response is final; `1xx` has no final meaning. Handlers
    // never emit one — this branch exists so a future one cannot
    // desynchronise the stream.
    if validated.status < 200 {
        let fallback = Response::text(500, "response failed validation: no final meaning");
        return render_inner(&fallback, head_request);
    }
    render_inner(validated, head_request)
}

/// Map a validated response onto hyper types.
///
/// Unreachable-by-construction fallbacks (`500`) cover the mapping
/// errors validation already excluded: returning hyper's error type
/// would abort the connection with no response at all, which answers
/// less than a loud 500.
fn render_inner(
    response: &Response,
    head_request: bool,
) -> hyper::Response<http_body_util::Full<Bytes>> {
    let status = hyper::StatusCode::from_u16(response.status)
        .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = hyper::Response::builder().status(status);
    for (name, value) in &response.headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        let Ok(header_name) = name.parse::<hyper::header::HeaderName>() else {
            return render_inner(
                &Response::text(500, "response failed validation: bad header"),
                head_request,
            );
        };
        let Ok(header_value) = value.parse::<hyper::header::HeaderValue>() else {
            return render_inner(
                &Response::text(500, "response failed validation: bad header"),
                head_request,
            );
        };
        builder = builder.header(header_name, header_value);
    }
    let real_len = response.body.len();
    let body = if crate::response::forbids_body(response.status) || head_request {
        Bytes::new()
    } else {
        Bytes::copy_from_slice(&response.body)
    };
    // `Content-Length` always describes the real body, even when the
    // bytes are omitted — mirroring the in-house writer, so a HEAD
    // response does not claim the representation is empty.
    builder = builder.header(hyper::header::CONTENT_LENGTH, real_len.to_string());
    builder
        .body(http_body_util::Full::new(body))
        .unwrap_or_else(|_| {
            hyper::Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(http_body_util::Full::new(Bytes::new()))
                .unwrap_or_else(|_| hyper::Response::new(http_body_util::Full::new(Bytes::new())))
        })
}

/// Map hyper's parsed head to the in-house taxonomy.
///
/// Every refusal reuses [`ParseError`], so the status and the body come
/// from the same constructors the in-house path uses — identical by
/// construction, not by parallel code. The rules mirror `parse_head`'s
/// header phase exactly: duplicate/single `Content-Length`,
/// `Transfer-Encoding: chunked`-only, duplicate `Host`, both framings,
/// declared cap, target length and shape, ASCII-only target.
fn map_head<B>(request: &hyper::Request<B>) -> Result<RequestHead, ParseError> {
    let method =
        Method::parse(request.method().as_str()).ok_or_else(|| ParseError::UnknownMethod {
            method: truncate_head(request.method().as_str(), 32),
        })?;
    let version = match request.version() {
        hyper::Version::HTTP_11 => Version::Http11,
        hyper::Version::HTTP_10 => Version::Http10,
        other => {
            return Err(ParseError::UnsupportedVersion {
                version: truncate_head(&format!("{other:?}"), 16),
            });
        }
    };
    // Origin-form carries path and query; asterisk-form is the `OPTIONS *`
    // exception; anything else (absolute- or authority-form) is not a
    // target this server routes, mirroring `TargetNotAbsolute`. The
    // scheme check comes first because hyper normalises absolute-form
    // to origin-form below — without it, a proxy-style request would
    // route as the path it names.
    let target = if request.uri().scheme().is_some() {
        return Err(ParseError::TargetNotAbsolute {
            target: truncate_head(&request.uri().to_string(), 64),
        });
    } else if method == Method::Options && request.uri().path() == "*" {
        "*".to_owned()
    } else if let Some(path_query) = request.uri().path_and_query() {
        path_query.as_str().to_owned()
    } else {
        return Err(ParseError::TargetNotAbsolute {
            target: truncate_head(&request.uri().to_string(), 64),
        });
    };
    if target.len() > MAX_TARGET_BYTES {
        return Err(ParseError::TargetTooLong {
            bytes: target.len(),
            limit: MAX_TARGET_BYTES,
        });
    }
    if !target.is_ascii() {
        return Err(ParseError::BadRequestLine {
            detail: "non-ASCII byte in the request line".to_owned(),
        });
    }
    let is_asterisk = target == "*" && method == Method::Options;
    if !is_asterisk && !target.starts_with('/') {
        return Err(ParseError::TargetNotAbsolute {
            target: truncate_head(&target, 64),
        });
    }

    let mut headers = Vec::new();
    let mut content_length = None;
    let mut chunked = false;
    let mut seen_transfer_encoding = false;
    let mut seen_host = false;
    // `HeaderMap::iter` yields multi-valued keys once per value, so a
    // doubled header is seen twice here exactly as the parser sees two
    // lines. Names arrive lowercased — hyper normalises — where the
    // in-house path preserves case; routing, CORS, and limits all match
    // case-insensitively, so the difference is representation.
    for (name, value) in request.headers() {
        let name = name.as_str();
        let value = value.to_str().map_err(|_| ParseError::InvalidUtf8)?.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ParseError::DuplicateContentLength);
            }
            let n: u64 = value
                .parse()
                .map_err(|_| ParseError::InvalidContentLength {
                    value: truncate_head(value, 64),
                })?;
            if n > MAX_REQUEST_BYTES {
                return Err(ParseError::BodyTooLarge {
                    declared: n,
                    limit: MAX_REQUEST_BYTES,
                });
            }
            content_length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if seen_transfer_encoding {
                return Err(ParseError::DuplicateTransferEncoding);
            }
            seen_transfer_encoding = true;
            if value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else {
                return Err(ParseError::UnsupportedTransferEncoding {
                    value: truncate_head(value, 64),
                });
            }
        } else if name.eq_ignore_ascii_case("host") {
            if seen_host {
                return Err(ParseError::DuplicateHost);
            }
            seen_host = true;
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    if chunked && content_length.is_some() {
        return Err(ParseError::ConflictingFraming);
    }
    Ok(RequestHead {
        method,
        target,
        version,
        headers,
        content_length,
        chunked,
    })
}

/// Truncate for an error detail without splitting UTF-8, mirroring the
/// private `http1::truncate`: an unbounded method or target must not
/// become an unbounded log line.
fn truncate_head(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}…", &s[..end])
}

/// Collect a hyper body with the shared caps.
///
/// Two framings, two readers — deliberately, because hyper delivers
/// them differently. A `Content-Length` body arrives as raw bytes, so
/// it goes through the shared [`BodyReader`] (same streaming counts,
/// same refusals as the in-house path). A chunked body arrives
/// *decoded* — hyper strips the chunk framing — so feeding it to the
/// reader would decode twice; instead the frames are counted directly
/// against the same [`config_max_request_bytes`] cap. Returns the body
/// with the byte count, so the metric cannot drift from what arrived.
async fn collect_body(incoming: Incoming, head: &RequestHead) -> Option<(BodyBytes, u64)> {
    if !head.chunked && head.content_length.is_none_or(|n| n == 0) {
        let body = if head.content_length == Some(0) {
            BodyBytes::Buffered(Vec::new())
        } else {
            BodyBytes::Absent
        };
        return Some((body, 0));
    }
    if head.chunked {
        return collect_chunked(incoming).await;
    }
    let Ok(mut reader) = BodyReader::from_head(head, config_max_request_bytes()) else {
        return None;
    };
    let mut transport = IncomingReader::new(incoming);
    let mut body = Vec::new();
    loop {
        match reader.poll_chunk(&mut transport, 8 * 1024).await {
            Ok(BodyChunk::Data(chunk)) => body.extend_from_slice(&chunk),
            Ok(BodyChunk::End) => {
                let received = reader.bytes_read();
                return Some((BodyBytes::Buffered(body), received));
            }
            Err(_) => return None,
        }
    }
}

/// Collect a hyper-decoded chunked body, counting against the shared cap.
///
/// Hyper guarantees the framing (it decoded it); QQQ guarantees the
/// bound. A body past the cap, a transport error, or a truncation all
/// refuse the same way the shared reader refuses: no partial body ever
/// reaches a handler.
async fn collect_chunked(incoming: Incoming) -> Option<(BodyBytes, u64)> {
    let cap = config_max_request_bytes();
    let mut stream = BodyStream::new(incoming);
    let mut body = Vec::new();
    loop {
        let Some(next) = stream.frame().await else {
            let received = body.len() as u64;
            return Some((BodyBytes::Buffered(body), received));
        };
        let Ok(frame) = next else {
            return None;
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let received = body.len() as u64 + data.len() as u64;
        if received > cap {
            return None;
        }
        body.extend_from_slice(&data);
    }
}

/// Adapt hyper's body stream to the [`AsyncRead`] the shared
/// [`BodyReader`] polls.
///
/// Data frames become read bytes; trailer and informational frames are
/// skipped (the flat path has no trailer contract, matching the
/// in-house reader, which never sees them); transport end becomes EOF,
/// which the reader interprets — truncated bodies fail there, not here.
///
/// Soundness of the manual `Unpin`: the struct owns its pinned body
/// through a `Box`, so moving the adapter moves the pointer, never the
/// body. The leftover bytes move freely.
struct IncomingReader {
    body: Pin<Box<BodyStream<Incoming>>>,
    leftover: Option<Bytes>,
}

impl Unpin for IncomingReader {}

impl IncomingReader {
    fn new(incoming: Incoming) -> Self {
        Self {
            body: Box::pin(BodyStream::new(incoming)),
            leftover: None,
        }
    }
}

impl AsyncRead for IncomingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if let Some(rest) = this.leftover.take() {
            let n = rest.len().min(buf.remaining());
            let take = rest.slice(..n);
            buf.put_slice(&take);
            if n < rest.len() {
                this.leftover = Some(rest.slice(n..));
            }
            return Poll::Ready(Ok(()));
        }
        match this.body.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    this.leftover = Some(data);
                }
                // Through the leftover path for data, or back to the
                // transport for trailers: one place fills the buffer.
                self.poll_read(cx, buf)
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(std::io::Error::other(format!(
                "hyper body failed: {error}"
            )))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head<B>(request: &hyper::Request<B>) -> Result<RequestHead, ParseError> {
        map_head(request)
    }

    fn get(target: &str, headers: &[(&str, &str)]) -> hyper::Request<()> {
        let mut builder = hyper::Request::builder().method("GET").uri(target);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap_or_else(|_| hyper::Request::new(()))
    }

    /// The smuggling rows refuse with the in-house taxonomy, not a guess.
    #[test]
    fn conflicting_and_doubled_framing_refuse() {
        let both = hyper::Request::builder()
            .method("POST")
            .uri("/a")
            .header("content-length", "5")
            .header("transfer-encoding", "chunked")
            .body(())
            .unwrap_or_else(|_| hyper::Request::new(()));
        assert!(matches!(head(&both), Err(ParseError::ConflictingFraming)));
        let dup = hyper::Request::builder()
            .method("POST")
            .uri("/a")
            .header("content-length", "5")
            .header("content-length", "6")
            .body(())
            .unwrap_or_else(|_| hyper::Request::new(()));
        assert!(matches!(
            head(&dup),
            Err(ParseError::DuplicateContentLength)
        ));
        let dup_host = get("/a", &[("host", "x"), ("host", "y")]);
        assert!(matches!(head(&dup_host), Err(ParseError::DuplicateHost)));
    }

    /// Absolute-form is not routable: a scheme means a proxy wrote this.
    #[test]
    fn absolute_form_refuses() {
        let absolute = hyper::Request::builder()
            .method("GET")
            .uri("http://x/b")
            .body(())
            .unwrap_or_else(|_| hyper::Request::new(()));
        assert!(matches!(
            head(&absolute),
            Err(ParseError::TargetNotAbsolute { .. })
        ));
    }

    /// Unknown methods refuse; known ones map, case-insensitively like the parser.
    #[test]
    fn methods_map_like_the_parser() {
        let known = get("/a", &[]);
        assert_eq!(head(&known).expect("GET maps").method, Method::Get);
        let unknown = hyper::Request::builder()
            .method("FROBNICATE")
            .uri("/a")
            .body(())
            .unwrap_or_else(|_| hyper::Request::new(()));
        assert!(matches!(
            head(&unknown),
            Err(ParseError::UnknownMethod { .. })
        ));
    }

    /// The ceiling decides serve, warn, and refuse on the count before
    /// the request — mirroring `Connection`'s `RequestLimit`, including
    /// the zero-ceiling edge that refuses everything.
    #[test]
    fn ceiling_decides_serve_warn_and_refuse() {
        assert_eq!(ceiling_for(0, 2), Ceiling::Serve);
        assert_eq!(ceiling_for(1, 2), Ceiling::Warn);
        assert_eq!(ceiling_for(2, 2), Ceiling::Refuse);
        assert_eq!(ceiling_for(9, 2), Ceiling::Refuse);
        assert_eq!(ceiling_for(0, 0), Ceiling::Refuse);
        assert_eq!(ceiling_for(0, 1), Ceiling::Warn);
    }
}
