// SPDX-License-Identifier: Apache-2.0

//! `qqq:trace/tracing` — spans and events with W3C Trace Context.
//!
//! Sampling decisions are made by the host, never the guest: a guest that
//! could influence sampling could hide its own activity, which is the one
//! thing an observability system must not permit.
//!
//! Spans live in a per-instance resource table; dropping a span closes it,
//! and a child outliving its parent fails the call that would have used it
//! with `span-closed` — the guarantee the WIT documents, enforced at call
//! time rather than by the type system (which cannot express it).
//!
//! Operator visibility in V1 is the log channel: every event and error is
//! mirrored there as a structured record carrying the trace context, so a
//! trace is readable in the terminal today (`OBS-018`) and OTLP export
//! (`OBS-012`) has a defined source to drain later rather than a format to
//! invent.
//!
//! V1 samples everything: `current-traceparent` always carries the `-01`
//! flag. Per-span sampling decisions stay host-owned by construction (the
//! guest has no API that influences them), and a future selective sampler
//! would change this one constant, not the call surface.
//!
//! The mirror is best-effort operator visibility, not a second store: when
//! the log buffer is full the event is dropped rather than failing the
//! trace call, because a full log buffer must not take down tracing with
//! it. The trace state itself is unaffected — only its terminal rendering
//! is lost, and the buffer's own backpressure error tells the guest the
//! log path is saturated.
//!
//! ```
//! let mut state = qqq_host::host_trace::TraceState::new();
//! assert!(state.spans.is_empty());
//! state.minted += 1;
//! assert_eq!(state.minted, 1);
//! ```
//!
//! ```
//! let state = qqq_host::host_trace::TraceState::default();
//! assert_eq!(state.next, 0);
//! assert!(state.active.is_none());
//! ```
//!
//! ```
//! let span = qqq_host::host_trace::SpanState {
//!     name: "child".to_owned(),
//!     trace_id: [3u8; 16],
//!     span_id: [4u8; 8],
//!     parent: Some(0),
//!     failed: true,
//!     attributes: std::collections::BTreeMap::new(),
//! };
//! assert_eq!(span.parent, Some(0));
//! assert!(span.failed);
//! ```
//!
//! ```
//! let manifest = qqq_cap::manifest::Manifest::parse(
//!     "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.trace]\n",
//! )
//! .expect("manifest parses");
//! let grants = qqq_cap::resolve::GrantSet::from_manifest(&manifest);
//! let engine = wasmtime::Engine::default();
//! let mut linker = wasmtime::component::Linker::<qqq_host::linker::StoreData>::new(&engine);
//! qqq_host::host_trace::register(&mut linker, &grants)
//!     .expect("granted trace registers");
//! ```

use std::collections::BTreeMap;

use qqq_cap::capability::Capability::TraceWrite;
use wasmtime::component::{Linker, Resource};

use crate::host_log::AttributeValue as LogAttributeValue;

/// The WIT package this module implements.
///
/// ```
/// assert_eq!(qqq_host::host_trace::INTERFACE, "qqq:trace@1.0.0");
/// ```
pub const INTERFACE: &str = "qqq:trace@1.0.0";

mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit/qqq-trace.wit",
        interfaces: "import qqq:trace/tracing@1.0.0;",
    });
}

/// The WIT `trace-error`, re-exported rather than re-declared: the WIT
/// variant is the definition. (Same rule as `host_test` and `host_secrets`.)
pub use bindings::qqq::trace::tracing::TraceError as WitTraceError;

/// A span the guest holds: parentage, trace identity, and limits.
///
/// ```
/// let span = qqq_host::host_trace::SpanState {
///     name: "root".to_owned(),
///     trace_id: [1u8; 16],
///     span_id: [2u8; 8],
///     parent: None,
///     failed: false,
///     attributes: std::collections::BTreeMap::new(),
/// };
/// assert_eq!(span.name, "root");
/// assert!(!span.failed);
/// ```
#[derive(Debug, Clone)]
pub struct SpanState {
    /// The span's name, as created. Kept for operator diagnostics.
    pub name: String,
    /// The W3C trace id, shared by the whole tree from its root.
    pub trace_id: [u8; 16],
    /// This span's id, unique within the trace.
    pub span_id: [u8; 8],
    /// The parent's table index, if any. Checked on every child call: a
    /// parent dropped from the table makes the child call fail `span-closed`
    /// rather than recording into a severed tree.
    pub parent: Option<u32>,
    /// Whether the span recorded a failure.
    pub failed: bool,
    /// Bounded attributes; the WIT's `span-too-large` caps growth.
    pub attributes: BTreeMap<String, LogAttributeValue>,
}

/// The tracing state for one instance.
///
/// ```
/// let state = qqq_host::host_trace::TraceState::new();
/// assert!(state.spans.is_empty());
/// assert!(state.active.is_none());
/// ```
///
/// The default is the same empty state:
///
/// ```
/// let state = qqq_host::host_trace::TraceState::default();
/// assert_eq!(state.next, 0);
/// assert_eq!(state.minted, 0);
/// ```
pub struct TraceState {
    /// Span states by host-assigned index. A plain map rather than wasmtime's
    /// `ResourceTable`: the generated bindings hand the host `Resource<Span>`
    /// handles, and the host's own counter assigns the indices — so every key
    /// here is one this instance minted, never one it reinterpreted.
    pub spans: BTreeMap<u32, SpanState>,
    /// The next index to assign. Monotonic: an index is never reused while an
    /// older span might still be referenced, so a stale handle cannot resolve
    /// to a newer span.
    pub next: u32,
    /// The current trace: the most recently started root span. `None` means
    /// no span is open, so `current-traceparent` answers none rather than a
    /// stale header from a finished trace.
    pub active: Option<([u8; 16], u32)>,
    /// Trace ids minted, bounding nothing but naming the sequence for tests.
    pub minted: u64,
}

impl TraceState {
    /// Empty: no spans, no active trace.
    #[must_use]
    pub fn new() -> Self {
        Self {
            spans: BTreeMap::new(),
            next: 0,
            active: None,
            minted: 0,
        }
    }
}

impl Default for TraceState {
    fn default() -> Self {
        Self::new()
    }
}

/// Register the tracing interface for the granted capability.
///
/// Links `qqq:trace/tracing` only when `trace.write` is granted; every
/// method re-checks at call time.
///
/// ```
/// let engine = wasmtime::Engine::default();
/// let mut linker = wasmtime::component::Linker::<qqq_host::linker::StoreData>::new(&engine);
/// qqq_host::host_trace::register(&mut linker, &qqq_cap::resolve::GrantSet::empty())
///     .expect("empty grants register nothing");
/// ```
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects an interface.
pub fn register(
    linker: &mut Linker<crate::linker::StoreData>,
    grants: &qqq_cap::resolve::GrantSet,
) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    if !grants.grants(TraceWrite) {
        return Ok(());
    }
    bindings::qqq::trace::tracing::add_to_linker::<
        crate::linker::StoreData,
        HasSelf<crate::linker::StoreData>,
    >(linker, |s| s)?;
    Ok(())
}

use bindings::qqq::trace::tracing::{
    Attribute as WitAttribute, AttributeValue as WitTraceAttribute, Host as TraceHost, HostSpan,
    Span,
};

/// The most spans one instance may hold. Past this `start-span` fails
/// `span-too-large` rather than growing without bound — an unbounded table is
/// a memory-exhaustion primitive any guest can drive.
///
/// Crate-visible: the bound is enforced inside this module and read nowhere
/// else; it is an implementation limit rather than a cross-crate contract.
pub(crate) const MAX_TRACE_SPANS: usize = 256;

/// The most attributes one span may hold.
pub(crate) const MAX_TRACE_ATTRIBUTES: usize = 64;

/// The largest single attribute value, in bytes.
pub(crate) const MAX_TRACE_VALUE_BYTES: usize = 64 * 1024;

/// The host implementation of `qqq:trace/tracing`.
///
/// # Why spans live in the store's own resource table
///
/// The generated `Host` trait hands the implementation `Resource<Span>`
/// handles; resolving them needs the table that minted them, and the store
/// is the only per-instance scope that outlives a single call. A parent that
/// the guest dropped is absent from the table, which is exactly how a child
/// call detects the severed tree and fails `span-closed`.
impl TraceHost for crate::linker::StoreData {
    fn start_span(&mut self, name: String) -> std::result::Result<Resource<Span>, WitTraceError> {
        // No `guard::guard` wrapper: these methods return the WIT `result`
        // directly (the generated `Host` trait's shape, as in `host_http`),
        // and a WIT `trace-error` has no case for a host fault. Panics are
        // contained by the same combination as `host_http`: the crate forbids
        // `unwrap`/`expect`/indexing, and a residual host defect traps in
        // Wasmtime rather than unwinding through the engine.
        start_span_impl(self, &name, None)
    }

    fn current_traceparent(&mut self) -> Option<String> {
        if !self.grants.grants(TraceWrite) {
            return None;
        }
        self.trace.active.and_then(|(trace_id, root)| {
            self.trace
                .spans
                .get(&root)
                .map(|span| format_traceparent(&trace_id, span.span_id))
        })
    }
}

impl HostSpan for crate::linker::StoreData {
    fn child(
        &mut self,
        parent: Resource<Span>,
        name: String,
    ) -> std::result::Result<Resource<Span>, WitTraceError> {
        let parent_id = rep_index(&parent);
        match self.trace.spans.get(&parent_id) {
            Some(_) => start_span_impl(self, &name, Some(parent_id)),
            None => Err(WitTraceError::SpanClosed),
        }
    }

    fn event(
        &mut self,
        handle: Resource<Span>,
        name: String,
        attributes: Vec<WitAttribute>,
    ) -> std::result::Result<(), WitTraceError> {
        // Bounded up front: the mirror drops oversize messages silently
        // (best-effort visibility), so an unbounded name that passed here
        // would return `Ok` for an event nobody can read. The bound
        // accounts for the `"event "` prefix the mirror adds, so a name
        // that passes here always survives the mirror's own length check.
        if name.len() > crate::host_log::MAX_LOG_FIELD_BYTES - "event ".len() {
            return Err(WitTraceError::SpanTooLarge);
        }
        let id = with_span(self, &handle, |span| (span.trace_id, span.span_id))?;
        let attrs = check_attributes(&attributes)?;
        mirror_to_log(self, id, "event", &name, attrs, false);
        Ok(())
    }

    fn set_attributes(
        &mut self,
        handle: Resource<Span>,
        attributes: Vec<WitAttribute>,
    ) -> std::result::Result<(), WitTraceError> {
        // Grant first, like every sibling: an ungranted call fails before
        // its handle is judged (`ARCH-012`).
        if !self.grants.grants(TraceWrite) {
            return Err(WitTraceError::NotGranted);
        }
        let checked = check_attributes(&attributes)?;
        // Through `with_span`, like `event` and `set-error`: a child whose
        // parent was dropped is severed, and writing to it must fail
        // `span-closed` exactly as reading from it does.
        with_span(
            self,
            &handle,
            |span| -> std::result::Result<(), WitTraceError> {
                for (key, value) in checked {
                    if span.attributes.len() >= MAX_TRACE_ATTRIBUTES
                        && !span.attributes.contains_key(&key)
                    {
                        return Err(WitTraceError::SpanTooLarge);
                    }
                    span.attributes.insert(key, value);
                }
                Ok(())
            },
        )??;
        Ok(())
    }

    fn set_error(
        &mut self,
        handle: Resource<Span>,
        message: String,
    ) -> std::result::Result<(), WitTraceError> {
        let id = with_span(self, &handle, |span| {
            span.failed = true;
            (span.trace_id, span.span_id)
        })?;
        // Prefix-aware like `event`: the mirror renders `"error {message}"`,
        // so the boundary bound leaves room for the prefix.
        if message.len() > crate::host_log::MAX_LOG_FIELD_BYTES - "error ".len() {
            return Err(WitTraceError::SpanTooLarge);
        }
        mirror_to_log(self, id, "error", &message, Vec::new(), true);
        Ok(())
    }

    fn drop(&mut self, rep: Resource<Span>) -> std::result::Result<(), wasmtime::Error> {
        // Read-then-delete in two steps: the lookup borrows, the removal
        // needs `&mut`, and holding both would not compile — which is the
        // borrow checker enforcing that a use-after-delete cannot happen here
        // either.
        let ended = self
            .trace
            .spans
            .get(&rep_index(&rep))
            .map(|span| (span.parent.is_none(), span.trace_id));
        // A dropped root clears the active trace so a later
        // `current-traceparent` does not report a finished trace.
        if self.trace.spans.remove(&rep_index(&rep)).is_some()
            && let Some((true, trace_id)) = ended
            && matches!(self.trace.active, Some((id, _)) if id == trace_id)
        {
            self.trace.active = None;
        }
        Ok(())
    }
}

/// Start a span, root or child, enforcing the table bound.
fn start_span_impl(
    data: &mut crate::linker::StoreData,
    name: &str,
    parent: Option<u32>,
) -> std::result::Result<Resource<Span>, WitTraceError> {
    if !data.grants.grants(TraceWrite) {
        return Err(WitTraceError::NotGranted);
    }
    if name.len() > crate::host_log::MAX_LOG_FIELD_BYTES {
        return Err(WitTraceError::SpanTooLarge);
    }
    if data.trace.spans.len() >= MAX_TRACE_SPANS {
        return Err(WitTraceError::SpanTooLarge);
    }
    data.trace.minted = data.trace.minted.wrapping_add(1);
    let salt = data.trace.minted;
    let trace_id: [u8; 16] = if parent.is_none() {
        random_id(&data.ambient, salt)
    } else {
        // A child shares its root's trace: find the root by walking parents.
        let mut cursor = parent;
        loop {
            match cursor {
                None => break [0u8; 16],
                Some(index) => match data.trace.spans.get(&index) {
                    Some(span) => {
                        if span.parent.is_none() {
                            break span.trace_id;
                        }
                        cursor = span.parent;
                    }
                    None => return Err(WitTraceError::SpanClosed),
                },
            }
        }
    };
    let span_id: [u8; 8] = random_id(&data.ambient, salt ^ 0x9E37_79B9_7F4A_7C15);
    let index = data.trace.next;
    data.trace.next = data
        .trace
        .next
        .checked_add(1)
        .ok_or(WitTraceError::SpanTooLarge)?;
    data.trace.spans.insert(
        index,
        SpanState {
            name: name.to_owned(),
            trace_id,
            span_id,
            parent,
            failed: false,
            attributes: BTreeMap::new(),
        },
    );
    let rep = rep_from_index(index);
    if parent.is_none() {
        data.trace.active = Some((trace_id, index));
    }
    Ok(rep)
}

/// N random bytes from the ambient RNG (seeded in deterministic mode), with
/// a per-instance counter mixed in.
///
/// On entropy failure the counter alone still guarantees uniqueness *within
/// this instance* — which is all a trace/span id promises (correlation, not
/// secrecy). Hiding the failure would be wrong for key material; for
/// correlation ids the alternative — refusing the span — would make an
/// entropy outage take down observability exactly when it is needed most.
fn random_id<const N: usize>(ambient: &crate::ambient::AmbientState, salt: u64) -> [u8; N] {
    let mut out = [0u8; N];
    if let Ok(bytes) = ambient.read_random(64) {
        for (slot, source) in out.iter_mut().zip(bytes.iter()) {
            *slot = *source;
        }
    }
    for (slot, mixer) in out.iter_mut().zip(salt.to_le_bytes().iter().cycle()) {
        *slot ^= mixer;
    }
    out
}

/// The table index behind a resource handle.
fn rep_index(rep: &Resource<Span>) -> u32 {
    rep.rep()
}

/// A resource handle for a table index. Used only to re-key lookups from a
/// stored index — never fabricated across stores.
fn rep_from_index(index: u32) -> Resource<Span> {
    Resource::new_own(index)
}

/// Run a closure against a live span, failing `span-closed` when the guest
/// dropped it — or any ancestor up to the root. A child whose parent was
/// dropped is severed even though the child itself is still present, which is
/// exactly the case the parentage check exists for.
fn with_span<T>(
    data: &mut crate::linker::StoreData,
    handle: &Resource<Span>,
    f: impl FnOnce(&mut SpanState) -> T,
) -> std::result::Result<T, WitTraceError> {
    if !data.grants.grants(TraceWrite) {
        return Err(WitTraceError::NotGranted);
    }
    let mut cursor = Some(rep_index(handle));
    while let Some(index) = cursor {
        match data.trace.spans.get(&index) {
            None => return Err(WitTraceError::SpanClosed),
            Some(span) => cursor = span.parent,
        }
    }
    let span = data
        .trace
        .spans
        .get_mut(&rep_index(handle))
        .ok_or(WitTraceError::SpanClosed)?;
    Ok(f(span))
}

/// Validate one attribute list: count and per-value size.
fn check_attributes(
    attributes: &[WitAttribute],
) -> std::result::Result<Vec<(String, LogAttributeValue)>, WitTraceError> {
    if attributes.len() > MAX_TRACE_ATTRIBUTES {
        return Err(WitTraceError::SpanTooLarge);
    }
    let mut out = Vec::with_capacity(attributes.len());
    for attribute in attributes {
        // Same rule as the log boundary: names are guest-controlled heap
        // and rendered structure, so they are bounded and shaped alike.
        if !crate::host_log::valid_name(&attribute.name)
            || attribute.name.len() > MAX_TRACE_VALUE_BYTES
        {
            return Err(WitTraceError::SpanTooLarge);
        }
        match &attribute.value {
            WitTraceAttribute::Text(text) if text.len() > MAX_TRACE_VALUE_BYTES => {
                return Err(WitTraceError::SpanTooLarge);
            }
            _ => {}
        }
        out.push((
            attribute.name.clone(),
            match attribute.value.clone() {
                WitTraceAttribute::Text(text) => LogAttributeValue::Text(text),
                WitTraceAttribute::Integer(number) => LogAttributeValue::Integer(number),
                WitTraceAttribute::Float(float) => LogAttributeValue::Float(float),
                WitTraceAttribute::Boolean(boolean) => LogAttributeValue::Boolean(boolean),
            },
        ));
    }
    Ok(out)
}

/// Format a W3C `traceparent` header value: version `00`, sampled flag set.
fn format_traceparent(trace_id: &[u8; 16], span_id: [u8; 8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(55);
    let _ = write!(out, "00-");
    for b in trace_id {
        let _ = write!(out, "{b:02x}");
    }
    let _ = write!(out, "-");
    for b in span_id {
        let _ = write!(out, "{b:02x}");
    }
    let _ = write!(out, "-01");
    out
}

/// Mirror an event or error into the instance's log buffer, tagged with the
/// span's trace context. This is the operator-visible half of tracing until
/// OTLP export lands (`OBS-012`): without it a trace would be write-only.
///
/// Best-effort by design: when the buffer is full or over its byte bound the
/// mirror drops the event rather than failing the trace call. A saturated
/// log buffer must not take down tracing with it, and the buffer's own
/// backpressure error already tells the guest the log path is saturated.
///
/// Secret values are redacted exactly as in `host_log`: an event name or
/// text attribute that equals a resolved secret value is stored as
/// `[redacted:secret]` with the flag set, because the mirror lands in the
/// same buffer — and the same stderr — as every other log record.
#[allow(clippy::too_many_arguments)]
fn mirror_to_log(
    data: &mut crate::linker::StoreData,
    id: ([u8; 16], [u8; 8]),
    kind: &str,
    name: &str,
    attributes: Vec<(String, LogAttributeValue)>,
    is_error: bool,
) {
    use crate::host_log::{LogRecord, MAX_LOG_FIELD_BYTES, MAX_LOG_RECORDS, MAX_LOG_TOTAL_BYTES};
    if data.logs.len() >= MAX_LOG_RECORDS {
        return;
    }
    // Redact the name before prefixing it: the formatted message carries a
    // `"{kind} "` prefix, so an exact-match check on the whole message
    // could never fire for a bare secret value. The whole-message check
    // stays as well, for the degenerate case of a secret that already
    // carries the prefix.
    let (name, mut redacted) = redact_text(data, name.to_owned());
    let (message, message_secret) = redact_text(data, format!("{kind} {name}"));
    redacted |= message_secret;
    if message.len() > MAX_LOG_FIELD_BYTES {
        return;
    }
    let tenant = data
        .tenant
        .as_ref()
        .map_or("unscoped".to_owned(), ToString::to_string);
    let (trace_id, span_id) = id;
    let mut kept: Vec<(String, LogAttributeValue)> = Vec::with_capacity(attributes.len() + 1);
    for (key, value) in attributes {
        let (value, was_secret) = match value {
            LogAttributeValue::Text(text) => {
                let (text, was_secret) = redact_text(data, text);
                (LogAttributeValue::Text(text), was_secret)
            }
            value => (value, false),
        };
        redacted |= was_secret;
        kept.push((key, value));
    }
    // The `span_id` tag is host-added, so the guest's full house of
    // `MAX_TRACE_ATTRIBUTES` attributes plus this tag would store a
    // 65-attribute record the log boundary itself refuses. Best-effort
    // again: drop the mirror rather than the guest's data or the bound.
    if kept.len() >= crate::host_log::MAX_LOG_ATTRIBUTES {
        return;
    }
    kept.push((
        "span_id".to_owned(),
        LogAttributeValue::Text(
            span_id
                .iter()
                .fold(String::with_capacity(16), |mut acc, b| {
                    use std::fmt::Write as _;
                    let _ = write!(acc, "{b:02x}");
                    acc
                }),
        ),
    ));
    if crate::host_log::buffered_bytes(&data.logs) + crate::host_log::record_bytes(&message, &kept)
        > MAX_LOG_TOTAL_BYTES
    {
        return;
    }
    data.logs.push(LogRecord {
        tenant,
        trace_id: Some(trace_id),
        level: if is_error { 4 } else { 2 },
        message,
        attributes: kept,
        redacted,
    });
}

/// Redact one text exactly as the log boundary does: an exact match of a
/// resolved secret value becomes `[redacted:secret]`.
fn redact_text(data: &crate::linker::StoreData, text: String) -> (String, bool) {
    if !text.is_empty() && data.secrets.is_secret_value(text.as_bytes()) {
        ("[redacted:secret]".to_owned(), true)
    } else {
        (text, false)
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
    use crate::linker::StoreData;
    use qqq_cap::manifest::Manifest;
    use qqq_cap::resolve::GrantSet;

    fn granted_store() -> StoreData {
        let m =
            Manifest::parse("[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.trace]\n")
                .expect("manifest parses");
        StoreData::new(GrantSet::from_manifest(&m))
    }

    fn ungranted_store() -> StoreData {
        StoreData::new(GrantSet::empty())
    }

    /// Start/child/event/attributes/traceparent round-trip through one trace.
    #[test]
    fn span_lifecycle_orders_and_propagates() {
        let mut data = granted_store();
        let root = start_span_impl(&mut data, "root", None).expect("root starts");
        let tp = TraceHost::current_traceparent(&mut data).expect("traceparent present");
        assert!(tp.starts_with("00-"), "W3C version prefix: {tp}");
        assert_eq!(
            tp.len(),
            55,
            "version(2)+trace(32)+sep+span(16)+sep+flag(2): {tp}"
        );
        assert!(tp.ends_with("-01"), "sampled flag set: {tp}");
        let kid = start_span_impl(&mut data, "kid", Some(rep_index(&root))).expect("child starts");
        with_span(&mut data, &kid, |s| {
            s.attributes.insert("k".to_owned(), host_log_attr("v"));
            s.failed = true;
        })
        .expect("attributes set");
        // A child shares the root's trace: no forked traceparent.
        let tp2 = TraceHost::current_traceparent(&mut data).expect("traceparent still root");
        assert_eq!(tp, tp2, "children do not fork the trace");
        // Dropping the root clears the trace; the live child fails closed.
        // `Resource` moves into `drop`, so the post-drop checks go through
        // the indices captured beforehand.
        let root_id = rep_index(&root);
        let kid_id = rep_index(&kid);
        <StoreData as HostSpan>::drop(&mut data, root).expect("drop runs");
        assert!(
            TraceHost::current_traceparent(&mut data).is_none(),
            "no traceparent after the root dropped"
        );
        assert!(
            !data.trace.spans.contains_key(&root_id),
            "the dropped span is gone"
        );
        let err =
            with_span(&mut data, &rep_from_index(kid_id), |_| ()).expect_err("severed child fails");
        assert!(matches!(err, WitTraceError::SpanClosed));
    }

    /// Ungranted guests get `not-granted`, never a span.
    #[test]
    fn start_span_without_grant_is_not_granted() {
        let mut data = ungranted_store();
        let err = start_span_impl(&mut data, "x", None).expect_err("no grant");
        assert!(matches!(err, WitTraceError::NotGranted));
        assert!(data.trace.spans.is_empty(), "nothing is stored");
    }

    /// The register links only when granted.
    #[test]
    fn register_links_only_when_granted() {
        const EMPTY: &str = r#"(component
          (import "qqq:trace/tracing@1.0.0" (instance $t))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        const NAMED: &str = r#"(component
          (import "qqq:trace/tracing@1.0.0" (instance $t
            (export "start-span" (func (param "a" string)))))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        fn link(grants: &GrantSet, wat: &str) -> wasmtime::Result<()> {
            let mut config = wasmtime::Config::new();
            config.wasm_component_model(true);
            let engine = wasmtime::Engine::new(&config).expect("engine builds");
            let mut linker = wasmtime::component::Linker::new(&engine);
            register(&mut linker, grants)?;
            let bytes = wat::parse_str(wat).expect("fixture assembles");
            let component =
                wasmtime::component::Component::new(&engine, &bytes).expect("fixture compiles");
            let mut store = wasmtime::Store::new(&engine, StoreData::new(grants.clone()));
            linker.instantiate(&mut store, &component).map(|_| ())
        }
        let m =
            Manifest::parse("[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.trace]\n")
                .expect("manifest parses");
        link(&GrantSet::from_manifest(&m), EMPTY).expect("a granted import links");
        let err = link(&GrantSet::empty(), NAMED).expect_err("no grant means no instance");
        assert!(
            format!("{err:#}").contains("qqq:trace/tracing"),
            "the refusal must name the import: {err:#}"
        );
    }

    /// `set-attributes` re-checks the grant like every sibling: an
    /// ungranted call fails before its handle is judged.
    #[test]
    fn set_attributes_without_grant_is_not_granted() {
        // Index 0 in a store that never minted a span: the grant check
        // fires before the handle is looked at, so any handle proves it.
        let mut data = ungranted_store();
        let err = <StoreData as HostSpan>::set_attributes(
            &mut data,
            rep_from_index(0),
            vec![WitAttribute {
                name: "k".to_owned(),
                value: WitTraceAttribute::Text("v".to_owned()),
            }],
        )
        .expect_err("no grant");
        assert!(matches!(err, WitTraceError::NotGranted));
    }

    /// `set-attributes` on a severed child fails like `event` does: the
    /// parent walk, not just the handle, decides liveness.
    #[test]
    fn set_attributes_on_severed_child_is_closed() {
        let mut data = granted_store();
        let root = start_span_impl(&mut data, "root", None).expect("root starts");
        let kid = start_span_impl(&mut data, "kid", Some(rep_index(&root))).expect("child starts");
        let kid_id = rep_index(&kid);
        <StoreData as HostSpan>::drop(&mut data, root).expect("parent drops");
        let err = <StoreData as HostSpan>::set_attributes(
            &mut data,
            rep_from_index(kid_id),
            vec![WitAttribute {
                name: "k".to_owned(),
                value: WitTraceAttribute::Text("v".to_owned()),
            }],
        )
        .expect_err("severed child fails");
        assert!(matches!(err, WitTraceError::SpanClosed));
    }

    /// Oversize event names fail instead of returning `Ok` for an event the
    /// mirror silently drops.
    #[test]
    fn oversize_event_names_fail_closed() {
        let mut data = granted_store();
        let root = start_span_impl(&mut data, "root", None).expect("root starts");
        let big = "e".repeat(crate::host_log::MAX_LOG_FIELD_BYTES + 1);
        let before = data.logs.len();
        let err = <StoreData as HostSpan>::event(&mut data, root, big, vec![])
            .expect_err("name too long");
        assert!(matches!(err, WitTraceError::SpanTooLarge));
        assert_eq!(data.logs.len(), before, "no silent mirror drop");
    }

    /// The event-name bound leaves room for the mirror's `"event "` prefix:
    /// the longest fitting name is stored, one byte more fails at the
    /// boundary rather than vanishing in the mirror.
    #[test]
    fn event_name_boundary_accounts_for_prefix() {
        let mut data = granted_store();
        let root = start_span_impl(&mut data, "root", None).expect("root starts");
        let max = crate::host_log::MAX_LOG_FIELD_BYTES - "event ".len();
        let fitting = "e".repeat(max);
        <StoreData as HostSpan>::event(
            &mut data,
            rep_from_index(rep_index(&root)),
            fitting,
            vec![],
        )
        .expect("the boundary name fits its rendering");
        assert_eq!(data.logs.len(), 1);
        let overflow = "e".repeat(max + 1);
        let err = <StoreData as HostSpan>::event(
            &mut data,
            rep_from_index(rep_index(&root)),
            overflow,
            vec![],
        )
        .expect_err("one byte over fails");
        assert!(matches!(err, WitTraceError::SpanTooLarge));
        assert_eq!(data.logs.len(), 1, "the refused event mirrors nothing");
    }

    /// Hostile attribute names are refused at the trace boundary too.
    #[test]
    fn hostile_attribute_names_are_refused() {
        let mut data = granted_store();
        let root = start_span_impl(&mut data, "root", None).expect("root starts");
        for hostile in ["", "a b", "a=b", "a\"b", "a\nb"] {
            let err = <StoreData as HostSpan>::event(
                &mut data,
                rep_from_index(rep_index(&root)),
                "ev".to_owned(),
                vec![WitAttribute {
                    name: hostile.to_owned(),
                    value: WitTraceAttribute::Boolean(true),
                }],
            )
            .expect_err("hostile name refused");
            assert!(
                matches!(err, WitTraceError::SpanTooLarge),
                "{hostile:?} must fail closed"
            );
        }
    }

    /// A secret value in an event or error is mirrored redacted: the mirror
    /// lands in the same buffer — and stderr — as every other log record.
    #[test]
    fn mirrored_events_redact_secrets() {
        use crate::host_secrets::{PermittedOp, SecretMaterial, SecretStore};
        let mut data = granted_store();
        data.secrets = SecretStore::with_grants(
            vec!["K".to_owned()],
            vec![SecretMaterial::new(
                "K",
                b"trace-secret".to_vec(),
                PermittedOp::all().to_vec(),
            )],
        );
        let root = start_span_impl(&mut data, "root", None).expect("root starts");
        <StoreData as HostSpan>::event(
            &mut data,
            rep_from_index(rep_index(&root)),
            "trace-secret".to_owned(),
            vec![WitAttribute {
                name: "k".to_owned(),
                value: WitTraceAttribute::Text("trace-secret".to_owned()),
            }],
        )
        .expect("event records");
        assert_eq!(data.logs.len(), 1);
        let record = &data.logs[0];
        assert_eq!(record.message, "event [redacted:secret]");
        assert!(
            matches!(&record.attributes[0].1, LogAttributeValue::Text(value) if value == "[redacted:secret]"),
            "the mirrored attribute redacts too"
        );
        assert!(record.redacted, "the flag travels with the mirror");
    }

    /// The mirror's `span_id` tag never pushes a record past the log
    /// boundary's own attribute cap: a 64-attribute event returns `Ok` (the
    /// trace call succeeded) but mirrors nothing, rather than storing a
    /// 65-attribute record the log boundary refuses.
    #[test]
    fn full_attribute_mirror_drops_best_effort() {
        let mut data = granted_store();
        let root = start_span_impl(&mut data, "root", None).expect("root starts");
        let attrs: Vec<WitAttribute> = (0..crate::host_log::MAX_LOG_ATTRIBUTES)
            .map(|i| WitAttribute {
                name: format!("k{i}"),
                value: WitTraceAttribute::Boolean(true),
            })
            .collect();
        <StoreData as HostSpan>::event(
            &mut data,
            rep_from_index(rep_index(&root)),
            "ev".to_owned(),
            attrs,
        )
        .expect("the trace call succeeds");
        assert!(
            data.logs.is_empty(),
            "best-effort: no 65-attribute row is stored"
        );
    }

    /// `with_span` on a dropped span is `span-closed`, never a missing entry.
    #[test]
    fn dropped_span_reads_closed() {
        let mut data = granted_store();
        let root = start_span_impl(&mut data, "root", None).expect("root starts");
        let root_id = rep_index(&root);
        <StoreData as HostSpan>::drop(&mut data, root).expect("drop runs");
        let err = with_span(&mut data, &rep_from_index(root_id), |_| ()).expect_err("dropped");
        assert!(matches!(err, WitTraceError::SpanClosed));
        // And the active trace cleared with its root.
        assert!(
            TraceHost::current_traceparent(&mut data).is_none(),
            "no traceparent after the root dropped"
        );
    }

    fn host_log_attr(s: &str) -> crate::host_log::AttributeValue {
        crate::host_log::AttributeValue::Text(s.to_owned())
    }
}
