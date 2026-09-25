// SPDX-License-Identifier: Apache-2.0

//! Server-Sent Events: the `text/event-stream` framing, per the WHATWG HTML
//! specification's [Server-Sent Events][spec] section.
//!
//! Implements Checklist `SRV-010` — *"Implement Server-Sent Events"* — which Proposal
//! §6.4 scopes in V1:
//!
//! > **Scope in V1:** HTTP/1.1 (complete), HTTP/2 (complete), WebSockets over both,
//! > **Server-Sent Events**, gRPC via `wasi:http` + `qqq:grpc` (beta), HTTP/3/QUIC
//! > behind a flag (beta).
//!
//! [spec]: https://html.spec.whatwg.org/multipage/server-sent-events.html
//!
//! # Why the framing is a type and not a `format!` at the call site
//!
//! SSE's wire format looks trivial — `data: hello\n\n` — and the places it goes wrong
//! are all invisible in that example:
//!
//! - **A newline inside the payload must become a second `data:` field**, not a raw
//!   newline. `data: a\nb\n\n` is not one event carrying `"a\nb"`; it is one event
//!   carrying `"a"` and the browser discards `b` as a field with no colon. Getting
//!   this wrong silently truncates every multi-line message, which is the common case
//!   for a JSON payload written with pretty-printing.
//! - **A `\r`, `\r\n` or `\n` terminates a line**, all three, so a payload containing
//!   any of them needs the same treatment.
//! - **A leading space after the colon is stripped**, exactly one. `data: x` and
//!   `data:x` both carry `x`; `data:  x` carries ` x`. A producer that emits
//!   `data: {json}` is correct and one that emits `data:  {json}` has a leading space
//!   in its payload.
//! - **A NUL or a lone `\r` in the payload** is not forbidden by the grammar but
//!   breaks parsers; the spec's own field rules exclude `\r` from the payload
//!   entirely.
//!
//! Each of those is a rule about a string, so each belongs in a function that a test
//! can call — not in the string-building code of whatever handler happens to emit an
//! event.
//!
//! # What this module does not do
//!
//! It does not own a connection, a stream or a scheduler. [`Event::encode`] returns
//! bytes and the caller writes them. That is deliberate and it is what §6.4's body
//! rule demands:
//!
//! > Bodies are `stream<u8>` end-to-end. Backpressure propagates from the client
//! > socket through the host to the guest's stream and back. There is no point at
//! > which a request body is fully buffered unless the manifest asked for it.
//!
//! An SSE module that buffered events into a `Vec<Event>` and flushed at the end
//! would look simpler and would be wrong twice over: it would break the streaming
//! promise, and it would make an event stream's latency a function of when the
//! handler finishes — which for a stream that is meant to stay open is never.

use std::fmt::Write as _;

/// The media type an SSE response must carry.
///
/// `text/event-stream` exactly. A response labelled anything else — including
/// `text/event-stream; charset=utf-8`, which is valid HTTP — is **not** treated as an
/// event stream by browsers: the specification requires the type to match
/// `text/event-stream` and permits `charset=utf-8` only as an explicit parameter that
/// is ignored. Since the encoding is always UTF-8 by definition, emitting the bare
/// type is both correct and the least ambiguous thing to say.
pub const CONTENT_TYPE: &str = "text/event-stream";

/// The headers every SSE response needs, as `(name, value)` pairs.
///
/// # Why this is a function and not three `set_header` calls at each call site
///
/// All three are load-bearing and all three are easy to omit:
///
/// - **`Content-Type: text/event-stream`** — without it the client never enters the
///   event-stream parsing mode and the bytes are just a body.
/// - **`Cache-Control: no-store`** — an event stream is live data. A cache that stored
///   it would serve a stale stream, and an intermediary that buffered it would hold
///   events until the response ended, which for an SSE stream is *never*. `no-store`
///   rather than `no-cache`: `no-cache` permits storing and requires revalidation, and
///   revalidating a stream is meaningless.
/// - **`X-Accel-Buffering: no`** — the de-facto control for nginx and several other
///   reverse proxies, which otherwise buffer a proxied response until it completes.
///   It is not a standard header and it is not in the specification; it is here
///   because omitting it is the single most common reason an SSE endpoint "works
///   locally and not behind the load balancer", and a runtime that leaves that trap
///   in place has not really implemented the feature.
///
/// Returning them as a slice rather than mutating a [`crate::Response`] keeps this
/// module independent of the response type, so the framing can be tested — and reused
/// — without constructing one.
#[must_use]
pub fn headers() -> &'static [(&'static str, &'static str)] {
    &[
        ("Content-Type", CONTENT_TYPE),
        ("Cache-Control", "no-store"),
        ("X-Accel-Buffering", "no"),
    ]
}

/// One server-sent event.
///
/// A field set to `None` is omitted from the wire entirely, which is required: the
/// specification's parser treats `event:` with an empty value as *setting the event
/// type to the empty string*, so an "absent" field and an "empty" field are different
/// things and only absence is neutral.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Event {
    /// The event's type, for `addEventListener`. Absent means `message`.
    pub event: Option<String>,
    /// The payload. May contain newlines; each becomes its own `data:` field.
    pub data: String,
    /// The last-event-ID to send, for reconnection. Absent means "do not update".
    pub id: Option<String>,
    /// A reconnection delay hint, in milliseconds.
    pub retry: Option<u64>,
    /// A comment, emitted as a `:` line.
    ///
    /// Not decoration: a comment is the **keep-alive mechanism**. A proxy or client
    /// with an idle timeout will drop a quiet stream, and the way to hold it open is
    /// to send a comment periodically, which the client receives and discards. Exposing
    /// it on the event type rather than as a separate call means a keep-alive is
    /// expressible in the same way as any other event.
    pub comment: Option<String>,
}

impl Event {
    /// An event with a payload and nothing else.
    #[must_use]
    pub fn data(data: impl Into<String>) -> Self {
        Self {
            data: data.into(),
            ..Self::default()
        }
    }

    /// A named event, for `addEventListener("name", ...)`.
    #[must_use]
    pub fn named(event: impl Into<String>, data: impl Into<String>) -> Self {
        Self {
            event: Some(event.into()),
            data: data.into(),
            ..Self::default()
        }
    }

    /// A keep-alive comment.
    ///
    /// The payload is echoed back to the client **nowhere** — a comment is discarded
    /// by the parser — so this exists to produce bytes on an otherwise idle
    /// connection. Passing something identifying (a timestamp, a server name) is
    /// useful in a packet capture and harmless on the wire.
    #[must_use]
    pub fn keep_alive(text: impl Into<String>) -> Self {
        Self {
            comment: Some(text.into()),
            ..Self::default()
        }
    }

    /// Set the event type.
    #[must_use]
    pub fn with_event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    /// Set the last-event-ID.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the reconnection delay.
    #[must_use]
    pub fn with_retry(mut self, millis: u64) -> Self {
        self.retry = Some(millis);
        self
    }

    /// Encode this event as the bytes of one `text/event-stream` message.
    ///
    /// # The order of the fields
    ///
    /// `comment`, `event`, `id`, `retry`, then `data`, then the blank line that
    /// dispatches. The specification's parser accepts the fields in any order and the
    /// dispatch happens at the blank line, so the order is a choice — and this one
    /// puts `data` last because it is the field that varies in length and the one a
    /// reader scanning a capture wants adjacent to the terminating blank line.
    ///
    /// An `id` containing a NUL is **omitted** rather than emitted. The specification
    /// says a client must ignore an `id` field whose value contains U+0000, so
    /// emitting it would produce a stream that works until a reconnect and then
    /// silently loses its position. Dropping it here makes the loss visible in the
    /// producer's tests instead of in production.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::with_capacity(self.data.len() + 64);

        if let Some(comment) = &self.comment {
            // A comment is `:` followed by optional text. Its own newlines are folded
            // to spaces: a comment containing a line break would end the comment and
            // start a *second* field on the next line, which changes the message.
            let _ = writeln!(out, ":{}", fold_newlines(comment));
        }

        if let Some(event) = &self.event {
            let _ = writeln!(out, "event:{}", fold_newlines(event));
        }

        if let Some(id) = &self.id {
            if !id.contains('\u{0}') {
                let _ = writeln!(out, "id:{}", fold_newlines(id));
            }
        }

        if let Some(retry) = self.retry {
            let _ = writeln!(out, "retry:{retry}");
        }

        // The payload, one `data:` line per line of input. This is the rule that
        // makes multi-line payloads work, and splitting on all three terminators is
        // what the specification's "split a string on line breaks" step does.
        //
        // A **leading space in the payload needs a second space on the wire.** The
        // parser strips exactly one space after the colon, so `data: x` and `data:x`
        // both yield `x`, while `data:  x` yields ` x`. Writing the payload directly
        // after the colon therefore eats a significant leading space, which is how a
        // payload that legitimately begins with one arrives mangled. The specification
        // names this exact case and its remedy.
        //
        // A payload that is empty *and* has no other field emits one `data:` line: an
        // event with an `event:` type and no data is legal and a client dispatches it.
        // But a **comment-only** event emits no `data:` line at all, and that
        // distinction is the difference between a keep-alive and a message: a
        // keep-alive carrying `data:` would be dispatched by the client as an empty
        // message, waking every listener on an idle connection — the opposite of what
        // it is for.
        let comment_only = self.comment.is_some()
            && self.event.is_none()
            && self.id.is_none()
            && self.retry.is_none()
            && self.data.is_empty();

        if !comment_only {
            // One `data:` line per line of the payload — **empty lines included** — and one
            // extra empty `data:` line when the payload ends with a line break.
            //
            // # Why the extra line
            //
            // The client's assembler joins the `data:` lines with `"\n"` and then removes
            // **one** trailing break, as the specification requires. A payload has to
            // survive that trim, so the wire form must carry one break more than the
            // payload does: `data("a\n")` is three `data:` lines, which join to `"a\n\n"`
            // and trim to `"a\n"`.
            //
            // The previous version dropped empty lines and then supplied a single `data:`
            // line if none remained. That handled the concern it was written for — a
            // newline-only payload must not emit a bare blank line, which an earlier
            // version did — but it also threw away the line structure, so **every payload
            // ending in a line break lost it**: `data("a\n")` dispatched `"a"`. Its comment
            // argued the loss was required, claiming `data("")`, `data("\n")` and
            // `data("\n\n")` "must" encode identically. They must not: identical bytes
            // cannot carry three different payloads (`§O-278`).
            //
            // A **comment-only** event still emits no `data:` line at all, and that
            // distinction is what separates a keep-alive from a message: a keep-alive
            // carrying `data:` would be dispatched by the client as an empty message,
            // waking every listener on an idle connection — the opposite of what it is
            // for.
            for line in split_lines(&self.data) {
                let _ = writeln!(out, "data:{}", escape_leading_space(line));
            }
            if self.data.ends_with(['\n', '\r']) {
                out.push_str("data:\n");
            }
            // No "at least one line" fallback is needed: `split_lines` never returns an
            // empty sequence, so `data("")` writes `data:\n` above rather than a bare
            // blank line.
        }

        // The blank line dispatches the event. Without it the fields accumulate and
        // the client sees nothing — the failure mode is a stream that connects
        // successfully and delivers no events, which reads as a client bug.
        out.push('\n');
        out.into_bytes()
    }
}

/// Fold every line break to a space, for a field that must stay on one line.
fn fold_newlines(s: &str) -> String {
    if !s.contains(['\n', '\r']) {
        return s.to_owned();
    }
    s.chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect()
}

/// Split on `\r\n`, `\n` or a lone `\r`, as the specification requires, **keeping every
/// empty field**.
///
/// A single `\r` terminates a line in SSE, which is not true of most text formats and is the
/// reason this is a named function. `str::lines` splits on `\n` and strips a trailing `\r`, so
/// it would treat a lone `\r` as ordinary data and produce an event whose payload contains a
/// raw `\r` — which the *client* then splits on, arriving at a different payload than the
/// server encoded. Splitting on both terminators in one pass, as an earlier version did, also
/// turns `"a\r\nb"` into three fields with a spurious empty one between; the loop below
/// consumes `\r\n` as a single break.
///
/// # Why empty fields are kept
///
/// The client joins the data lines with `"\n"` and removes the trailing one, so an empty field
/// is not information *by itself* — but the **number** of fields is information, and it is how
/// a trailing line break is carried. The earlier version filtered them out
/// (`s.split(['\n', '\r']).filter(|l| !l.is_empty())`), which looked harmless and silently
/// dropped the trailing empty line a payload ending in a line break produces: `data("a\n")`
/// encoded as one `data:` line, and the client's mandatory trim of one trailing break left
/// `"a"`. Dropping empty fields collapses `data("a")`, `data("a\n")` and `data("a\n\n")` onto
/// the same wire form, so at most one of the three could survive the round trip.
///
/// The filter existed to stop a newline-only payload emitting a bare **blank line** — a real
/// defect, produced by an earlier version still. The encoder's "at least one `data:` line" rule
/// handles that, so the two concerns were never a trade-off; they were a pair only because the
/// first fix chose the wrong lever (`§O-278`).
fn split_lines(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' || bytes[i] == b'\r' {
            out.push(&s[start..i]);
            i += if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                2
            } else {
                1
            };
            start = i;
        } else {
            i += 1;
        }
    }
    // The text after the final break, which is `""` when the payload ends with one. This
    // unconditional push is why the sequence is never empty.
    out.push(&s[start..]);
    out
}

/// Add the second space a payload with a leading space needs.
///
/// The specification's parser strips **exactly one** space after the field's colon:
/// `data: x` and `data:x` both carry `x`, and `data:  x` carries ` x`. So a payload
/// whose first character is a space must be written with two spaces or the client
/// sees a different string than the server encoded — a silent one-character
/// corruption, and one that survives every round-trip test that uses no leading
/// whitespace.
fn escape_leading_space(line: &str) -> String {
    if line.starts_with(' ') {
        format!(" {line}")
    } else {
        line.to_owned()
    }
}

/// The `Last-Event-ID` a client sent, for resuming a stream.
///
/// Returned as `Some` only when the header is present **and** non-empty. A client
/// reconnecting without having seen an event sends no header; a client that has seen
/// events sends the last id. Treating an empty value as an id would make a resume
/// start from the empty string, which is a valid id and therefore ambiguous with
/// "no id" — so the empty case maps to `None` and the caller's "no resume" branch is
/// the one that runs.
///
/// The value is returned verbatim. This is a guest-visible string, and the caller is
/// responsible for looking it up rather than building a path or a query from it.
#[must_use]
pub fn last_event_id(headers: &[(String, String)]) -> Option<&str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Last-Event-ID"))
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(event: &Event) -> String {
        String::from_utf8(event.encode()).expect("SSE output is UTF-8 by construction")
    }

    // -- the headers -------------------------------------------------------

    /// The three headers that make a response a working SSE stream.
    #[test]
    fn the_required_headers_are_present() {
        let h: std::collections::BTreeMap<&str, &str> = headers().iter().copied().collect();
        assert_eq!(h.get("Content-Type"), Some(&"text/event-stream"));
        assert_eq!(
            h.get("Cache-Control"),
            Some(&"no-store"),
            "a cacheable event stream serves stale events"
        );
        assert_eq!(
            h.get("X-Accel-Buffering"),
            Some(&"no"),
            "without this a reverse proxy buffers the stream and nothing arrives"
        );
    }

    /// The media type carries no parameters.
    ///
    /// A response labelled `text/event-stream; charset=utf-8` is valid HTTP and is
    /// **not** an event stream to a browser: the specification requires the type to
    /// match exactly, with `charset=utf-8` permitted only as an ignored parameter. A
    /// producer that helpfully appends a charset produces a stream that never fires
    /// `onmessage`.
    #[test]
    fn the_content_type_has_no_parameters() {
        assert_eq!(CONTENT_TYPE, "text/event-stream");
        assert!(!CONTENT_TYPE.contains(';'), "{CONTENT_TYPE}");
        assert!(!CONTENT_TYPE.contains("charset"), "{CONTENT_TYPE}");
    }

    // -- framing -----------------------------------------------------------

    /// The simplest event, exactly as the specification writes it.
    #[test]
    fn a_simple_event_is_data_then_a_blank_line() {
        assert_eq!(encoded(&Event::data("hello")), "data:hello\n\n");
    }

    /// **A newline in the payload becomes a second `data:` field.**
    ///
    /// This is the rule that makes multi-line payloads work, and the one a naive
    /// implementation gets wrong in the most damaging way: `data: a\nb\n\n` is not one
    /// event carrying `"a\nb"` — the client parses `a` as the data, sees `b` as a field
    /// name with no colon and ignores it, and dispatches `"a"`. The payload is
    /// silently truncated, and the common case that hits it is pretty-printed JSON.
    #[test]
    fn a_newline_in_the_payload_becomes_several_data_fields() {
        assert_eq!(
            encoded(&Event::data("a\nb")),
            "data:a\ndata:b\n\n",
            "each line needs its own `data:` prefix or the client drops the rest"
        );
        assert_eq!(
            encoded(&Event::data("a\nb\nc")),
            "data:a\ndata:b\ndata:c\n\n"
        );
    }

    /// **A lone `\r` also terminates a line.**
    ///
    /// `str::lines` would treat a bare `\r` as ordinary data and emit it inside a
    /// `data:` field, and the *client* would then split on it — so the server and the
    /// client would disagree about the payload. The specification's line-break set is
    /// `\r\n`, `\n` and `\r`, and all three are tested here.
    #[test]
    fn all_three_line_break_forms_split_the_payload() {
        assert_eq!(encoded(&Event::data("a\r\nb")), "data:a\ndata:b\n\n");
        assert_eq!(encoded(&Event::data("a\nb")), "data:a\ndata:b\n\n");
        assert_eq!(encoded(&Event::data("a\rb")), "data:a\ndata:b\n\n");
    }

    /// A line break never survives into a `data:` line.
    ///
    /// The invariant behind the three cases above, stated directly: if any `data:`
    /// line contained a raw break, the client would parse a different payload than the
    /// server encoded.
    #[test]
    fn no_data_line_contains_a_line_break() {
        for payload in [
            "a\nb",
            "a\rb",
            "a\r\nb",
            "\nleading",
            "trailing\n",
            "\n\n\n",
            "mixed\r\n\n\rend",
        ] {
            let out = encoded(&Event::data(payload));
            for line in out.split('\n') {
                assert!(
                    !line.contains('\r'),
                    "payload {payload:?} left a CR inside a field: {out:?}"
                );
            }
        }
    }

    /// The blank line is what dispatches the event, and it is always there.
    ///
    /// Without it the fields accumulate and the client receives nothing — a stream
    /// that connects cleanly and delivers no events, which reads as a client bug.
    #[test]
    fn every_event_ends_with_a_blank_line() {
        let events = [
            Event::data("x"),
            Event::named("tick", "x"),
            Event::data("x").with_id("1"),
            Event::data("x").with_retry(1000),
            Event::keep_alive("ping"),
            Event::data(""),
            Event::default(),
        ];
        for event in events {
            let out = encoded(&event);
            assert!(
                out.ends_with("\n\n"),
                "event {event:?} did not end with a blank line: {out:?}"
            );
        }
    }

    /// Every field the event carries appears, in the documented order.
    #[test]
    fn a_full_event_carries_every_field() {
        let event = Event::data("payload")
            .with_event("update")
            .with_id("42")
            .with_retry(3000);
        assert_eq!(
            encoded(&event),
            "event:update\nid:42\nretry:3000\ndata:payload\n\n"
        );
    }

    /// A comment is a `:` line, and it is the keep-alive.
    #[test]
    fn a_comment_is_a_colon_line() {
        assert_eq!(encoded(&Event::keep_alive("ping")), ":ping\n\n");
        // No text at all is still a valid comment and still produces bytes, which is
        // the whole point of a keep-alive.
        assert_eq!(encoded(&Event::keep_alive("")), ":\n\n");
    }

    /// A comment's own line breaks are folded, so it stays one field.
    ///
    /// A comment containing a newline would end the comment and begin a second field
    /// on the next line — changing the message rather than merely formatting it.
    #[test]
    fn a_comment_with_a_line_break_stays_one_field() {
        let out = encoded(&Event::keep_alive("a\nb"));
        assert_eq!(out, ":a b\n\n");
        assert_eq!(
            out.lines().filter(|l| l.starts_with(':')).count(),
            1,
            "{out:?}"
        );
    }

    /// **An `id` containing NUL is omitted, not emitted.**
    ///
    /// The specification says a client must ignore an `id` field whose value contains
    /// U+0000. Emitting it would produce a stream that works until the first reconnect
    /// and then silently loses its position — a defect that only appears under network
    /// conditions, which is the worst place to find one.
    #[test]
    fn an_id_containing_nul_is_omitted() {
        let out = encoded(&Event::data("x").with_id("a\u{0}b"));
        assert_eq!(out, "data:x\n\n", "the id must be dropped entirely");
        assert!(!out.contains("id:"), "{out:?}");

        // A normal id is unaffected, so the rule above is not just "ids never work".
        assert_eq!(
            encoded(&Event::data("x").with_id("a-b")),
            "id:a-b\ndata:x\n\n"
        );
    }

    /// An absent field is absent — never an empty field.
    ///
    /// The parser treats `event:` with an empty value as setting the event type to the
    /// empty string, which is different from leaving it unset. Emitting an empty field
    /// for an absent value would change how the client dispatches.
    #[test]
    fn an_absent_field_is_not_emitted() {
        let out = encoded(&Event::data("x"));
        assert!(!out.contains("event:"), "{out:?}");
        assert!(!out.contains("id:"), "{out:?}");
        assert!(!out.contains("retry:"), "{out:?}");
        assert_eq!(out, "data:x\n\n");
    }

    /// An empty payload still emits one `data:` field.
    ///
    /// An event with a type and no data is legal and distinct from no event at all; a
    /// client dispatches it. Omitting the `data:` line entirely would produce a
    /// message that sets the event type and dispatches nothing.
    #[test]
    fn an_empty_payload_still_emits_a_data_field() {
        assert_eq!(encoded(&Event::data("")), "data:\n\n");
        assert_eq!(encoded(&Event::named("ping", "")), "event:ping\ndata:\n\n");
    }

    // -- the encoding is a function, not a format string ----------------

    /// The output is valid UTF-8 for any input.
    ///
    /// `encode` returns `Vec<u8>` but builds a `String`, so this is guaranteed by
    /// construction — and asserted because a future "optimisation" that wrote bytes
    /// directly could break it silently, and SSE is defined in terms of UTF-8.
    #[test]
    fn the_output_is_utf8_for_awkward_input() {
        for payload in ["日本語", "emoji 🎉", "\u{feff}bom", "a\u{0}b", "  spaces  "] {
            let bytes = Event::data(payload).encode();
            let text = std::str::from_utf8(&bytes).expect("must be UTF-8");
            assert!(text.starts_with("data:"), "{text:?}");
        }
    }

    /// A payload with a leading space keeps it.
    ///
    /// The parser strips **exactly one** space after the colon. `data:x` and
    /// `data: x` both yield `x`; `data:  x` yields ` x`. So a payload that genuinely
    /// begins with a space must be emitted as `data:  x` — two spaces — and the
    /// encoder must not "tidy" it.
    #[test]
    fn a_leading_space_in_the_payload_survives() {
        assert_eq!(encoded(&Event::data(" x")), "data:  x\n\n");
        // And with no leading space, exactly one space is what a reader expects.
        assert_eq!(encoded(&Event::data("x")), "data:x\n\n");
    }

    /// Encoding is deterministic: the same event produces the same bytes.
    ///
    /// §10.5 requires a deterministic run to produce identical output, and log or
    /// stream bytes are output. A `HashMap` in this path, or an iteration order that
    /// depended on allocation, would break that.
    #[test]
    fn encoding_is_deterministic() {
        let event = Event::data("a\nb").with_event("e").with_id("1");
        let first = event.encode();
        for _ in 0..50 {
            assert_eq!(
                event.encode(),
                first,
                "encoding must not vary between calls"
            );
        }
    }

    // -- Last-Event-ID -----------------------------------------------------

    /// A present, non-empty `Last-Event-ID` is returned.
    #[test]
    fn a_present_last_event_id_is_returned() {
        let h = vec![("Last-Event-ID".to_owned(), "17".to_owned())];
        assert_eq!(last_event_id(&h), Some("17"));
    }

    /// The header is matched case-insensitively, as HTTP requires.
    #[test]
    fn the_last_event_id_header_is_case_insensitive() {
        for name in ["last-event-id", "LAST-EVENT-ID", "Last-Event-Id"] {
            let h = vec![(name.to_owned(), "9".to_owned())];
            assert_eq!(last_event_id(&h), Some("9"), "{name}");
        }
    }

    /// **An empty `Last-Event-ID` is `None`, not `Some("")`.**
    ///
    /// The empty string is a *valid* event id, so returning it would make "the client
    /// sent no id" and "the client's last id was empty" indistinguishable — and the
    /// caller's resume branch would run with an id it cannot look up. Mapping the
    /// empty case to `None` keeps the two apart.
    #[test]
    fn an_empty_last_event_id_is_none() {
        let h = vec![("Last-Event-ID".to_owned(), String::new())];
        assert_eq!(last_event_id(&h), None);
    }

    /// No header at all is `None`.
    #[test]
    fn an_absent_last_event_id_is_none() {
        assert_eq!(last_event_id(&[]), None);
        let h = vec![("Host".to_owned(), "example".to_owned())];
        assert_eq!(last_event_id(&h), None);
    }

    /// The value is returned verbatim, including characters a caller must not trust.
    ///
    /// This is guest-visible input. The module returns it unchanged and documents that
    /// the caller must look it up rather than build a path or query from it — a
    /// `../` in an event id is exactly the sort of value that becomes a path
    /// traversal one layer up.
    #[test]
    fn the_value_is_returned_verbatim_for_the_caller_to_validate() {
        let h = vec![("Last-Event-ID".to_owned(), "../../etc/passwd".to_owned())];
        assert_eq!(last_event_id(&h), Some("../../etc/passwd"));
    }

    // -- line splitting, directly -----------------------------------------

    /// The splitter handles every form, and **keeps every empty field**.
    ///
    /// The empty cases are the point. `""` yields one empty field and `"\n"` yields two,
    /// because that is how a trailing line break is carried to the client.
    ///
    /// This doc used to read *"Empty fields are dropped, including for `""` itself"* — the
    /// opposite of what the expectations three lines below assert — and was left behind when
    /// the filter that caused `data("a\n")` to arrive as `"a"` was removed (`§O-278`). **A
    /// comment that contradicts the assertions beside it is worse than no comment**: it is
    /// exactly what would stop a reader noticing the bug the assertions were supposed to catch.
    #[test]
    fn the_line_splitter_handles_every_form() {
        let cases: [(&str, Vec<&str>); 8] = [
            ("", vec![""]),
            ("a", vec!["a"]),
            ("a\nb", vec!["a", "b"]),
            ("a\r\nb", vec!["a", "b"]),
            ("a\rb", vec!["a", "b"]),
            ("\n", vec!["", ""]),
            ("a\n", vec!["a", ""]),
            ("\n\n", vec!["", "", ""]),
        ];
        for (input, want) in cases {
            let got: Vec<&str> = split_lines(input);
            assert_eq!(got, want, "splitting {input:?}");
        }
    }

    /// A payload of only line breaks is the same event as an empty payload.
    ///
    /// The consequence of the splitter rule above, asserted at the encoder so the
    /// equivalence is a stated property rather than an inference from two other tests.
    /// It matters because the client cannot tell them apart either: its assembler
    /// joins the data lines and drops the trailing one, so every one of these
    /// dispatches `""`.
    /// A payload's line structure survives the encoder, including a trailing line break.
    ///
    /// # This test used to assert the opposite
    ///
    /// It was `a_newline_payload_is_the_same_event_as_an_empty_one`, and it required
    /// `data("")`, `data("\n")`, `data("\n\n")`, `data("\r")` and `data("\r\n")` to encode
    /// to **identical bytes**, on the argument that the client's assembler trims one
    /// trailing break and so all of them dispatch `""`. The argument is self-defeating:
    /// identical bytes cannot carry five different payloads, so the claim amounts to saying
    /// a trailing line break is not transmittable. It is — by emitting one `data:` line
    /// more than the payload has lines — and asserting otherwise is what kept the encoder
    /// wrong while its tests stayed green (`§O-278`).
    #[test]
    fn a_trailing_line_break_survives_the_encoder() {
        let empty = encoded(&Event::data(""));
        let one = encoded(&Event::data("\n"));
        let two = encoded(&Event::data("\n\n"));
        assert_ne!(empty, one, "`data(\"\")` and `data(\"\\n\")` must differ");
        assert_ne!(
            one, two,
            "`data(\"\\n\")` and `data(\"\\n\\n\")` must differ"
        );

        // The specification's assembler rule — join the `data:` lines with `"\n"`, then
        // drop **one** trailing break — applied to the encoder's own output. This is the
        // property the encoder has to satisfy, and it is checked here rather than only
        // in an integration test because a sender's contract is about the bytes it writes.
        for payload in ["", "\n", "\n\n", "a", "a\n", "a\nb", "a\n\nb", "a\n\n"] {
            let wire = encoded(&Event::data(payload));
            let mut joined = wire
                .split('\n')
                .filter_map(|line| line.strip_prefix("data:"))
                .collect::<Vec<_>>()
                .join("\n");
            if joined.ends_with('\n') {
                joined.pop();
            }
            assert_eq!(
                joined, payload,
                "payload {payload:?} did not survive the encoder"
            );
        }
    }
}
