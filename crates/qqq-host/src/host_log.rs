// SPDX-License-Identifier: Apache-2.0

//! `qqq:log/logging` — structured logging with host-side redaction.
//!
//! Logs carry tenant and trace attribution applied by the **host**, not the
//! guest — so a guest cannot forge another tenant's identity in a log line,
//! and redaction of secret values is enforced outside the guest's reach
//! (Proposal §10.3).
//!
//! A record whose attribute **value** exactly equals a resolved secret value
//! is stored redacted. Exact-match only: substring redaction would mangle
//! legitimate output that happens to contain a short secret name, and an
//! attacker who splits a value across attributes is outside what an equality
//! check can catch — which is stated here rather than oversold.
//!
//! ```
//! let record = qqq_host::host_log::LogRecord {
//!     tenant: "t".to_owned(),
//!     trace_id: None,
//!     level: 1,
//!     message: "m".to_owned(),
//!     attributes: vec![(
//!         "n".to_owned(),
//!         qqq_host::host_log::AttributeValue::Integer(7),
//!     )],
//!     redacted: false,
//! };
//! assert_eq!(record.attributes.len(), 1);
//! ```
//!
//! ```
//! let record = qqq_host::host_log::LogRecord {
//!     tenant: "t".to_owned(),
//!     trace_id: None,
//!     level: 3,
//!     message: "w".to_owned(),
//!     attributes: vec![(
//!         "f".to_owned(),
//!         qqq_host::host_log::AttributeValue::Float(0.5),
//!     )],
//!     redacted: false,
//! };
//! assert!(!record.redacted);
//! ```
//!
//! ```
//! let record = qqq_host::host_log::LogRecord {
//!     tenant: "t".to_owned(),
//!     trace_id: None,
//!     level: 0,
//!     message: "x".to_owned(),
//!     attributes: vec![(
//!         "b".to_owned(),
//!         qqq_host::host_log::AttributeValue::Boolean(true),
//!     )],
//!     redacted: false,
//! };
//! assert_eq!(record.level, 0);
//! ```
//!
//! ```
//! let line = qqq_host::host_log::format_record(&qqq_host::host_log::LogRecord {
//!     tenant: "acme".to_owned(),
//!     trace_id: None,
//!     level: 1,
//!     message: "hi".to_owned(),
//!     attributes: Vec::new(),
//!     redacted: false,
//! });
//! assert!(line.contains("level=debug"));
//! ```

use qqq_cap::capability::Capability::LogWrite;

/// The WIT package this module implements.
///
/// ```
/// assert_eq!(qqq_host::host_log::INTERFACE, "qqq:log@1.0.0");
/// ```
pub const INTERFACE: &str = "qqq:log@1.0.0";

/// The generated bindings carry no doc comments of their own, and re-exporting
/// them would fail `missing_docs` on the WIT's definition rather than on any
/// prose this crate wrote. The allow is scoped to the generated module so
/// hand-written items keep the lint.
#[allow(missing_docs)]
mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit/qqq-log.wit",
        interfaces: "import qqq:log/logging@1.0.0;",
    });
}

/// The WIT `log-error`, re-exported rather than re-declared: the WIT variant
/// is the definition. (Same rule as `host_test` and `host_secrets`.)
pub use bindings::qqq::log::logging::LogError as WitLogError;
/// A WIT log attribute, re-exported for conversion at the boundary.
pub use bindings::qqq::log::logging::{Attribute, AttributeValue};

/// The largest single message or attribute value the host accepts, in bytes.
///
/// Crate-visible: the trace mirror enforces the same bound, and the value is
/// an implementation limit rather than a cross-crate contract.
pub(crate) const MAX_LOG_FIELD_BYTES: usize = 64 * 1024;

/// The most attributes one record may carry.
pub(crate) const MAX_LOG_ATTRIBUTES: usize = 64;

/// The most records one instance may hold. Past this the call fails
/// `record-too-large` rather than dropping history silently — a log that
/// silently loses records is worse than a guest that must slow down, and the
/// WIT error is the backpressure signal.
pub(crate) const MAX_LOG_RECORDS: usize = 4096;

/// The most bytes of stored log data one instance may buffer.
///
/// The per-record bound alone does not bound the buffer: 4096 records at
/// 64 KiB each would be hundreds of megabytes of host heap no budget is
/// charged for. Four mebibytes is a quarter of the smallest instance memory
/// (16 MiB), so a guest that fills it has spent a visible share of its
/// budget getting there — and the failure is `record-too-large`, the same
/// backpressure signal as every other bound here.
pub(crate) const MAX_LOG_TOTAL_BYTES: usize = 4 * 1024 * 1024;

/// One guest log record, host-attributed.
///
/// ```
/// let record = qqq_host::host_log::LogRecord {
///     tenant: "t".to_owned(),
///     trace_id: None,
///     level: 2,
///     message: "hello".to_owned(),
///     attributes: Vec::new(),
///     redacted: false,
/// };
/// assert_eq!(record.message, "hello");
/// ```
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// The tenant that emitted it, applied by the host.
    pub tenant: String,
    /// The W3C trace id active when it was emitted, if any.
    pub trace_id: Option<[u8; 16]>,
    /// Severity, in WIT declaration order (trace..=error as 0..=4).
    pub level: u8,
    /// The message, redacted if it matched a secret value.
    pub message: String,
    /// Attribute names to values, in call order.
    pub attributes: Vec<(String, AttributeValue)>,
    /// Whether redaction replaced a value.
    pub redacted: bool,
}

/// Register the logging interface for the granted capability.
///
/// Links `qqq:log/logging` only when `log.write` is granted; every function
/// re-checks at call time.
///
/// ```
/// let engine = wasmtime::Engine::default();
/// let mut linker = wasmtime::component::Linker::<qqq_host::linker::StoreData>::new(&engine);
/// qqq_host::host_log::register(&mut linker, &qqq_cap::resolve::GrantSet::empty())
///     .expect("empty grants register nothing");
/// ```
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects an interface.
///
/// # Errors
///
/// A `wasmtime::Error` if the linker rejects a signature.
pub fn register(
    linker: &mut wasmtime::component::Linker<crate::linker::StoreData>,
    grants: &qqq_cap::resolve::GrantSet,
) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    if !grants.grants(LogWrite) {
        return Ok(());
    }
    bindings::qqq::log::logging::add_to_linker::<
        crate::linker::StoreData,
        HasSelf<crate::linker::StoreData>,
    >(linker, |s| s)?;
    Ok(())
}

/// The host implementation of `qqq:log/logging`.
///
/// # Why the tenant comes from the store, not the call
///
/// A guest that could name its own tenant in a log line could forge another
/// tenant's identity in the operator's records. The store knows which tenant
/// it serves; the guest does not get a vote.
///
/// # Why no `guard::guard` wrapper here
///
/// `guard` returns `wasmtime::Result`; these methods return the WIT `result`
/// directly (the generated `Host` trait's shape, as in `host_http`), and a
/// WIT `log-error` has no case for a host fault. Panics are contained by the
/// same combination as `host_http`: the crate forbids `unwrap`/`expect`/
/// indexing, and a residual host defect traps in Wasmtime rather than
/// unwinding through the engine.
impl LogHost for crate::linker::StoreData {
    fn emit(
        &mut self,
        level: Level,
        message: String,
        attributes: Vec<Attribute>,
    ) -> std::result::Result<(), WitLogError> {
        emit_record(self, level_index(level), &message, &attributes)
    }

    fn emit_many(
        &mut self,
        records: Vec<(Level, String, Vec<Attribute>)>,
    ) -> std::result::Result<(), WitLogError> {
        // Atomic: every record validates before any is stored, so a batch
        // that fails on its last record leaves no prefix behind. A caller
        // that retries the batch would otherwise duplicate the prefix, and
        // an operator reading the buffer could not tell which records came
        // from a batch that reported failure. The seam records the batch
        // as one consultation (`log_emit_many`, not per-record rows), so a
        // large batch is one audit row rather than thousands.
        crate::ambient::require(self, LogWrite, "log_emit_many")
            .map_err(|_| WitLogError::NotGranted)?;
        if !self.grants.grants(LogWrite) {
            return Err(WitLogError::NotGranted);
        }
        // Cap before allocate: the host-side `validated`/`levels` vectors
        // would otherwise pre-allocate for an arbitrarily large batch before
        // the first record is even judged. A batch that cannot fit the table
        // (`MAX_LOG_RECORDS` total) can never succeed, so refusing it here
        // changes nothing observable — it only fails before the allocation
        // instead of after it.
        if records.len() > MAX_LOG_RECORDS {
            return Err(WitLogError::RecordTooLarge);
        }
        // Quota before validation: the loop below clones and redacts every
        // record (host CPU per guest byte), so an over-quota batch would
        // burn that work before being refused. The count is known up front
        // and needs no validation — a batch that cannot fit is refused the
        // same way either way, only earlier.
        let open = u32::try_from(self.logs.len()).unwrap_or(u32::MAX);
        let more = u32::try_from(records.len()).unwrap_or(u32::MAX);
        self.handles
            .try_open_batch(open, more)
            .map_err(|_| WitLogError::RecordTooLarge)?;
        let mut validated = Vec::with_capacity(records.len());
        let mut levels = Vec::with_capacity(records.len());
        // Accumulate the byte total as each record validates, failing fast:
        // a batch that overflows on its first record must not pay to
        // validate the remaining thousands. The batch stays atomic — a
        // failure stores nothing — it just fails earlier.
        let base_bytes = buffered_bytes(&self.logs);
        let mut additional: usize = 0;
        for (level, message, attributes) in &records {
            levels.push(level_index(*level));
            let v = validate_record(self, message, attributes)?;
            additional = additional.saturating_add(v.size);
            if self.logs.len() + validated.len() + 1 > MAX_LOG_RECORDS
                || base_bytes.saturating_add(additional) > MAX_LOG_TOTAL_BYTES
            {
                return Err(WitLogError::RecordTooLarge);
            }
            validated.push(v);
        }
        // The batch is atomic and the quota binds on the would-be total, so a
        // batch that overflows is refused whole rather than half-applied.
        // (Checked incrementally above; this re-check pins the invariant for
        // readers that skip the loop.)
        if self.logs.len() + validated.len() > MAX_LOG_RECORDS
            || buffered_bytes(&self.logs) + additional > MAX_LOG_TOTAL_BYTES
        {
            return Err(WitLogError::RecordTooLarge);
        }
        let tenant = self
            .tenant
            .as_ref()
            .map_or("unscoped".to_owned(), ToString::to_string);
        let trace_id = self.trace.active.map(|(id, _)| id);
        for (validated, level) in validated.into_iter().zip(levels) {
            self.logs.push(crate::host_log::LogRecord {
                tenant: tenant.clone(),
                trace_id,
                level,
                message: validated.message,
                attributes: validated.attributes,
                redacted: validated.redacted,
            });
        }
        Ok(())
    }

    fn enabled(&mut self, _level: Level) -> bool {
        // No level filter is configured in V1 (the marker stanza carries no
        // fields), so every level records. Returning false would silence a
        // guest that has no way to learn why, and a filter that exists
        // nowhere is not a filter. The probe is still a consultation of the
        // grant, so it is recorded -- mirroring `kv::stores` -- while the
        // answer stays a pure function of the grant set.
        let granted = self.grants.grants(LogWrite);
        let _ = crate::ambient::require(self, LogWrite, "log_enabled");
        granted
    }
}

/// The log level names in WIT declaration order, for diagnostics.
const LEVEL_NAMES: [&str; 5] = ["trace", "debug", "info", "warn", "error"];
use bindings::qqq::log::logging::{Host as LogHost, Level};

/// Render one record as a single operator-readable line.
///
/// Pure so the format is testable without a store: the run and serve paths
/// print exactly this. Fields are space-separated `k=v`; values with spaces
/// are quoted. The trace id renders as 32 hex chars when present.
/// Structured export (OTLP/JSON with `span_id`, `component`, `manifest_rev`
/// and `code`) is `OBS-012` future work; this is the terminal rendering
/// (`OBS-018`), not the export format.
///
/// Keys are quoted too, and control characters are escaped: attribute names
/// are guest-controlled, and a raw newline in a key or message would forge
/// a second operator line starting with attacker-chosen text. The boundary
/// already refuses whitespace-bearing names; the quoting is defense in depth
/// for records built inside the crate (the trace mirror) rather than a
/// second check on the same path.
///
/// ```
/// let record = qqq_host::host_log::LogRecord {
///     tenant: "acme".to_owned(),
///     trace_id: None,
///     level: 2,
///     message: "hello".to_owned(),
///     attributes: Vec::new(),
///     redacted: false,
/// };
/// let line = qqq_host::host_log::format_record(&record);
/// assert!(line.contains("tenant=acme"));
/// assert!(line.contains("msg=hello"));
/// ```
///
/// Redaction travels with the record, and values with spaces are quoted:
///
/// ```
/// let record = qqq_host::host_log::LogRecord {
///     tenant: "acme".to_owned(),
///     trace_id: Some([1u8; 16]),
///     level: 4,
///     message: "[redacted:secret]".to_owned(),
///     attributes: vec![(
///         "note".to_owned(),
///         qqq_host::host_log::AttributeValue::Text("hello world".to_owned()),
///     )],
///     redacted: true,
/// };
/// let line = qqq_host::host_log::format_record(&record);
/// assert!(line.contains("redacted=true"));
/// assert!(line.contains("\"hello world\""));
/// assert!(line.contains("trace="));
/// ```
///
/// Control characters never produce a raw line break:
///
/// ```
/// let record = qqq_host::host_log::LogRecord {
///     tenant: "t".to_owned(),
///     trace_id: None,
///     level: 2,
///     message: "a\nb".to_owned(),
///     attributes: vec![(
///         "k".to_owned(),
///         qqq_host::host_log::AttributeValue::Boolean(true),
///     )],
///     redacted: false,
/// };
/// let line = qqq_host::host_log::format_record(&record);
/// assert!(!line.contains('\n'), "one record is one line: {line}");
/// assert!(line.contains("msg=\"a\\nb\""), "{line}");
/// ```
#[must_use]
pub fn format_record(record: &LogRecord) -> String {
    use std::fmt::Write as _;
    let level = LEVEL_NAMES
        .get(record.level as usize % LEVEL_NAMES.len())
        .copied()
        .unwrap_or("unknown");
    let mut out = format!(
        "tenant={} level={level} msg={}",
        quote(&record.tenant),
        quote(&record.message)
    );
    for (k, v) in &record.attributes {
        let rendered = match v {
            AttributeValue::Text(s) => quote(s),
            AttributeValue::Integer(n) => n.to_string(),
            AttributeValue::Float(f) => format!("{f:?}"),
            AttributeValue::Boolean(b) => b.to_string(),
        };
        let _ = write!(out, " {}={rendered}", quote(k));
    }
    if let Some(id) = record.trace_id {
        let _ = write!(out, " trace={}", hex_bytes(&id));
    }
    if record.redacted {
        out.push_str(" redacted=true");
    }
    out
}

fn quote(s: &str) -> String {
    use std::fmt::Write as _;
    // Byte checks cannot see multibyte characters: U+0085 rides two bytes past
    // the ASCII-control test. The trigger is therefore char-level, and the
    // shared layout-forgery predicate covers the separators and bidi controls
    // that are not controls at all.
    if s.chars().any(|c| {
        c.is_control()
            || c.is_whitespace()
            || c == '"'
            || c == '\\'
            || crate::boundary::is_layout_forgery(c)
    }) {
        let mut escaped = String::with_capacity(s.len() + 2);
        escaped.push('"');
        for c in s.chars() {
            match c {
                '\\' => escaped.push_str("\\\\"),
                '"' => escaped.push_str("\\\""),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                c if c.is_control() || crate::boundary::is_layout_forgery(c) => {
                    let _ = write!(escaped, "\\u{:04x}", c as u32);
                }
                c => escaped.push(c),
            }
        }
        escaped.push('"');
        escaped
    } else {
        s.to_owned()
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// The severity index in WIT declaration order. Matched, not cast: the
/// generated enum carries no representation promise.
fn level_index(level: Level) -> u8 {
    match level {
        Level::Trace => 0,
        Level::Debug => 1,
        Level::Info => 2,
        Level::Warn => 3,
        Level::Error => 4,
    }
}
/// Approximate stored bytes of one record: message plus names plus text
/// values. Integers, floats and booleans render to a few bytes; counting
/// eight each keeps the estimate above the stored content without
/// pretending it is exact — the bound is backpressure, not accounting.
///
/// Two things are deliberately outside the estimate. The per-record
/// framing the renderer adds (`tenant=`, `level=`, `trace=`, key quotes
/// and escapes) is a bounded constant: tenant names and trace ids are
/// fixed-size, and escape expansion happens at render time, which streams
/// rather than buffers. The headroom between any plausible sum of records
/// and `MAX_LOG_TOTAL_BYTES` absorbs the framing; the scan-vs-counter
/// reasoning below says why no running total tracks it.
///
/// The constant below prices that framing into the estimate anyway, so the
/// bound holds even when the buffer fills with maximally-framed records.
pub(crate) const RECORD_FRAMING_BYTES: usize = 64;

pub(crate) fn record_bytes(message: &str, attributes: &[(String, AttributeValue)]) -> usize {
    let mut total = RECORD_FRAMING_BYTES + message.len();
    for (name, value) in attributes {
        total += name.len();
        // Worst-case rendered widths, not averages: `i64::MIN` is 20
        // characters and the longest shortest-repr `f64` 24. Counting the
        // typical small number instead would let a buffer of extremes
        // overshoot the 4 MiB bound by megabytes per thousand records —
        // the estimate must stay above the rendering it bounds.
        total += match value {
            AttributeValue::Text(text) => text.len(),
            AttributeValue::Integer(_) => 20,
            AttributeValue::Float(_) => 24,
            AttributeValue::Boolean(_) => 5,
        };
    }
    total
}

/// Currently buffered stored bytes across the instance's records.
///
/// A full scan on every call, deliberately: the scan is bounded by
/// `MAX_LOG_RECORDS` (4096) — a few thousand integer adds, negligible next
/// to the per-record validation the caller already does — while a running
/// counter would have to stay in sync across every mutation path (`emit`,
/// `emit_many`, the trace mirror) with no enforcement that it does. A stale
/// counter fails open or closed depending on the direction of the drift; a
/// scan cannot drift.
pub(crate) fn buffered_bytes(logs: &[LogRecord]) -> usize {
    logs.iter()
        .map(|record| record_bytes(&record.message, &record.attributes))
        .sum()
}

/// Whether an attribute name is safe to store and render.
///
/// Empty names render as `=value`, and whitespace, quotes or `=` in a name
/// would forge structure in the rendered line. Control bytes (including NUL
/// and DEL, which whitespace matching misses) are refused for the same
/// reason: the renderer escapes them as defense in depth, but the boundary
/// refuses rather than repairs — a guest that meant a different name must
/// learn it failed. The check is char-level, not byte-level: Unicode
/// whitespace, C1 controls, and invisible layout-forgers would otherwise
/// ride multibyte UTF-8 past an ASCII scan.
///
/// Crate-visible: the trace mirror enforces the same rule on span
/// attributes, so both `qqq:` surfaces refuse the same names.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || c == '"'
                || c == '='
                || c == '\\'
                || crate::boundary::is_layout_forgery(c)
        })
}

/// A record that passed every bound, with redaction applied.
struct ValidatedRecord {
    message: String,
    attributes: Vec<(String, AttributeValue)>,
    redacted: bool,
    size: usize,
}

/// Check every bound on one record without storing anything.
///
/// Grant first (an ungranted call fails before its size is judged), then the
/// per-field bounds, then names and redaction. Callers check the buffer
/// bounds themselves so `emit_many` can validate the whole batch before
/// storing any of it.
fn validate_record(
    data: &crate::linker::StoreData,
    message: &str,
    attributes: &[Attribute],
) -> std::result::Result<ValidatedRecord, WitLogError> {
    if !data.grants.grants(LogWrite) {
        return Err(WitLogError::NotGranted);
    }
    if message.len() > MAX_LOG_FIELD_BYTES {
        return Err(WitLogError::RecordTooLarge);
    }
    if attributes.len() > MAX_LOG_ATTRIBUTES {
        return Err(WitLogError::RecordTooLarge);
    }
    let mut redacted = false;
    let mut kept: Vec<(String, AttributeValue)> = Vec::with_capacity(attributes.len());
    for attribute in attributes {
        if !valid_name(&attribute.name) || attribute.name.len() > MAX_LOG_FIELD_BYTES {
            return Err(WitLogError::RecordTooLarge);
        }
        let bytes: &[u8] = match &attribute.value {
            AttributeValue::Text(text) => text.as_bytes(),
            _ => &[],
        };
        let value = if !bytes.is_empty() && data.secrets.is_secret_value(bytes) {
            redacted = true;
            AttributeValue::Text("[redacted:secret]".to_owned())
        } else {
            attribute.value.clone()
        };
        if let AttributeValue::Text(text) = &value
            && text.len() > MAX_LOG_FIELD_BYTES
        {
            return Err(WitLogError::RecordTooLarge);
        }
        kept.push((attribute.name.clone(), value));
    }
    let (message, redacted) =
        if !message.is_empty() && data.secrets.is_secret_value(message.as_bytes()) {
            (("[redacted:secret]".to_owned()), true)
        } else {
            (message.to_owned(), redacted)
        };
    let size = record_bytes(&message, &kept);
    Ok(ValidatedRecord {
        message,
        attributes: kept,
        redacted,
        size,
    })
}

/// Append one record to this instance's log buffer, redacting secret values.
fn emit_record(
    data: &mut crate::linker::StoreData,
    level: u8,
    message: &str,
    attributes: &[Attribute],
) -> std::result::Result<(), WitLogError> {
    // Grant first, like every sibling: an ungranted call fails for the
    // missing grant before its size or quota is judged — otherwise the
    // error tells an ungranted guest how big a record may be. (`validate_record`
    // repeats the check; the second one always passes here and stays as
    // defense in depth.) The seam records the consultation, so the audit
    // stream sees log use like every other capability family.
    crate::ambient::require(data, LogWrite, "log_emit").map_err(|_| WitLogError::NotGranted)?;
    if !data.grants.grants(LogWrite) {
        return Err(WitLogError::NotGranted);
    }
    // The manifest quota binds before the absolute caps — and before
    // validation: one record against the current buffer length, judged
    // before the host clones and redacts anything. Both report
    // `RecordTooLarge` — the WIT type has no quota case — while the quota's
    // counter records the exhaustion.
    let open = u32::try_from(data.logs.len()).unwrap_or(u32::MAX);
    data.handles
        .try_open(open)
        .map_err(|_| WitLogError::RecordTooLarge)?;
    let validated = validate_record(data, message, attributes)?;
    if data.logs.len() >= MAX_LOG_RECORDS
        || buffered_bytes(&data.logs) + validated.size > MAX_LOG_TOTAL_BYTES
    {
        return Err(WitLogError::RecordTooLarge);
    }
    let tenant = data
        .tenant
        .as_ref()
        .map_or("unscoped".to_owned(), ToString::to_string);
    let trace_id = data.trace.active.map(|(id, _)| id);
    data.logs.push(crate::host_log::LogRecord {
        tenant,
        trace_id,
        level,
        message: validated.message,
        attributes: validated.attributes,
        redacted: validated.redacted,
    });
    Ok(())
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

    fn data_with_log(granted: bool) -> crate::linker::StoreData {
        use qqq_cap::resolve::GrantSet;
        let grants = if granted {
            let m = qqq_cap::manifest::Manifest::parse(
                "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.log]\n",
            )
            .expect("manifest parses");
            GrantSet::from_manifest(&m)
        } else {
            GrantSet::empty()
        };
        let mut data = crate::linker::StoreData::new(grants);
        // Test room, not policy: every stored record goes through the quota,
        // so tests that fill the buffer declare headroom up front.
        data.handles = crate::quota::HandleQuota::new(10_000);
        data
    }

    fn attr(name: &str, value: AttributeValue) -> Attribute {
        Attribute {
            name: name.to_owned(),
            value,
        }
    }

    /// Emitted records land in the instance buffer with tenant attribution.
    #[test]
    fn emit_records_with_tenant() {
        let mut data = data_with_log(true);
        emit_record(
            &mut data,
            2,
            "hello",
            &[attr("k", AttributeValue::Text("v".to_owned()))],
        )
        .expect("emits");
        assert_eq!(data.logs.len(), 1);
        let r = &data.logs[0];
        assert_eq!(r.message, "hello");
        assert!(!r.redacted);
        assert_eq!(r.attributes.len(), 1);
    }

    /// Ungranted guests get `not-granted`, never silence or storage.
    #[test]
    fn emit_without_grant_is_not_granted() {
        let mut data = data_with_log(false);
        let err = emit_record(&mut data, 2, "hello", &[]).expect_err("no grant");
        assert!(matches!(err, WitLogError::NotGranted));
        assert!(data.logs.is_empty(), "a refused record is not stored");
    }

    /// Every log body records through the audit seam: a direct grant check
    /// would answer identically while leaving the caller looking
    /// capability-clean to `assert-caps-only`. Counted, not `contains`.
    #[test]
    fn every_log_body_records_through_the_audit_seam() {
        let production = include_str!("host_log.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        let seams = production.matches("ambient::require(").count();
        assert_eq!(
            seams, 3,
            "every log body (emit, emit_many, enabled) must consult \
             the audit seam; found {seams} seam call(s)"
        );
    }

    /// Attach a record stream to a store, so the seam tests can assert on
    /// the rows rather than on the return value alone.
    fn attach_audit(
        data: &mut crate::linker::StoreData,
    ) -> std::sync::Arc<std::sync::Mutex<crate::audit::AuditStream>> {
        let stream = std::sync::Arc::new(std::sync::Mutex::new(
            crate::audit::AuditStream::with_default_capacity(),
        ));
        let digest = data.grants.digest();
        data.audit = Some(crate::audit::AuditHandle::new(
            std::sync::Arc::clone(&stream),
            crate::tenant::ComponentDigest::new("0011223344556677").expect("digest"),
            crate::tenant::GrantDigest::new(&digest).expect("digest"),
            None,
        ));
        stream
    }

    /// A granted emit records a `Granted` row naming the capability and the
    /// host function -- the row an auditor aggregates, not a constant.
    #[test]
    fn a_granted_emit_records_a_granted_row() {
        let mut data = data_with_log(true);
        let stream = attach_audit(&mut data);
        emit_record(&mut data, 2, "hello", &[]).expect("emits");
        let committed = data.audit.as_ref().expect("handle").commit();
        assert_eq!(committed.len(), 1, "one consultation, one row");
        let stream = stream.lock().expect("lock");
        let records = stream.records();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].capability,
            qqq_cap::capability::Capability::LogWrite
        );
        assert_eq!(records[0].function, "log_emit");
        assert_eq!(records[0].outcome, crate::audit::Outcome::Granted);
    }

    /// A refused batch records a `Denied` row even though nothing is
    /// stored -- a refusal is the row an auditor most wants. One row for
    /// the batch, not one per record.
    #[test]
    fn a_denied_emit_many_records_a_denied_row() {
        let mut data = data_with_log(false);
        let stream = attach_audit(&mut data);
        let err = LogHost::emit_many(&mut data, vec![(Level::Info, "one".to_owned(), vec![])])
            .expect_err("no grant");
        assert!(matches!(err, WitLogError::NotGranted));
        let committed = data.audit.as_ref().expect("handle").commit();
        assert_eq!(committed.len(), 1, "the denial must be recorded");
        let stream = stream.lock().expect("lock");
        let records = stream.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].function, "log_emit_many");
        assert_eq!(records[0].outcome, crate::audit::Outcome::Denied);
    }

    /// Even the grant probe records: `enabled` answers from the grant set,
    /// and the consultation is visible like `kv::stores`.
    #[test]
    fn an_enabled_probe_records_its_consultation() {
        let mut data = data_with_log(false);
        let stream = attach_audit(&mut data);
        assert!(!LogHost::enabled(&mut data, Level::Info));
        let committed = data.audit.as_ref().expect("handle").commit();
        assert_eq!(committed.len(), 1, "the probe must be recorded");
        let stream = stream.lock().expect("lock");
        let records = stream.records();
        assert_eq!(records[0].function, "log_enabled");
        assert_eq!(records[0].outcome, crate::audit::Outcome::Denied);
    }

    /// An exact secret value is stored redacted; near-matches are verbatim.
    #[test]
    fn secret_values_are_redacted_exact_matches_only() {
        use crate::host_secrets::{PermittedOp, SecretMaterial, SecretStore};
        let mut data = data_with_log(true);
        data.secrets = SecretStore::with_grants(
            vec!["K".to_owned()],
            vec![SecretMaterial::new(
                "K",
                b"super-secret".to_vec(),
                PermittedOp::all().to_vec(),
            )],
        );
        emit_record(&mut data, 2, "super-secret", &[]).expect("emits");
        let r = &data.logs[0];
        assert_eq!(r.message, "[redacted:secret]");
        assert!(r.redacted);
        emit_record(
            &mut data,
            2,
            "not the secret",
            &[attr("k", AttributeValue::Text("super-secret".to_owned()))],
        )
        .expect("emits");
        let r = &data.logs[1];
        assert_eq!(
            r.message, "not the secret",
            "messages are not substring-matched"
        );
        assert!(matches!(&r.attributes[0].1, AttributeValue::Text(v) if v == "[redacted:secret]"));
        assert!(r.redacted);
        emit_record(&mut data, 2, "prefix-super-secret", &[]).expect("emits");
        assert!(!data.logs[2].redacted, "no substring redaction");
    }

    /// Oversize messages and attribute lists fail before any write.
    #[test]
    fn oversize_records_fail_closed() {
        let mut data = data_with_log(true);
        let big = "x".repeat(MAX_LOG_FIELD_BYTES + 1);
        let err = emit_record(&mut data, 2, &big, &[]).expect_err("too big");
        assert!(matches!(err, WitLogError::RecordTooLarge));
        let many: Vec<Attribute> = (0..=MAX_LOG_ATTRIBUTES)
            .map(|i| attr(&format!("k{i}"), AttributeValue::Boolean(true)))
            .collect();
        let err = emit_record(&mut data, 2, "ok", &many).expect_err("too many");
        assert!(matches!(err, WitLogError::RecordTooLarge));
        assert!(
            data.logs.is_empty(),
            "a refused record is not partially stored"
        );
    }

    /// A full buffer refuses rather than dropping history silently.
    #[test]
    fn full_buffer_is_backpressure_not_loss() {
        let mut data = data_with_log(true);
        for _ in 0..MAX_LOG_RECORDS {
            emit_record(&mut data, 2, "x", &[]).expect("fits");
        }
        let err = emit_record(&mut data, 2, "one more", &[]).expect_err("full");
        assert!(matches!(err, WitLogError::RecordTooLarge));
        assert_eq!(data.logs.len(), MAX_LOG_RECORDS);
    }

    /// The manifest quota binds before the absolute buffer caps: with room
    /// for 4096 records but a quota of 1, the second record is refused and
    /// counted — not stored past the policy.
    #[test]
    fn quota_exhaustion_refuses_before_the_buffer_caps() {
        let mut data = data_with_log(true);
        data.handles = crate::quota::HandleQuota::new(1);
        emit_record(&mut data, 2, "first", &[]).expect("one record fits");
        let err = emit_record(&mut data, 2, "second", &[]).expect_err("quota exhausted");
        assert!(matches!(err, WitLogError::RecordTooLarge));
        assert_eq!(data.logs.len(), 1, "the refused record is not stored");
        assert_eq!(data.handles.exhaustion_attempts(), 1);
    }

    /// A batch that would overflow the quota is refused whole: no prefix
    /// persists, matching the byte-cap atomicity below.
    #[test]
    fn an_over_quota_batch_stores_nothing() {
        let mut data = data_with_log(true);
        data.handles = crate::quota::HandleQuota::new(1);
        let err = LogHost::emit_many(
            &mut data,
            vec![
                (Level::Info, "one".to_owned(), vec![]),
                (Level::Info, "two".to_owned(), vec![]),
            ],
        )
        .expect_err("two records against a quota of one must refuse");
        assert!(matches!(err, WitLogError::RecordTooLarge));
        assert!(
            data.logs.is_empty(),
            "no prefix of a failed batch may persist"
        );
    }

    /// A batch larger than the table can ever hold is refused before the
    /// host-side vectors allocate: the refusal must precede the
    /// `with_capacity`, or a giant batch of invalid records still triggers
    /// a giant allocation.
    #[test]
    fn an_oversize_batch_is_refused_before_allocating() {
        let mut data = data_with_log(true);
        let batch: Vec<(Level, String, Vec<Attribute>)> = (0..=MAX_LOG_RECORDS)
            .map(|i| (Level::Info, format!("r{i}"), vec![]))
            .collect();
        let err =
            LogHost::emit_many(&mut data, batch).expect_err("a batch that cannot fit must refuse");
        assert!(matches!(err, WitLogError::RecordTooLarge));
        assert!(data.logs.is_empty(), "a refused batch stores nothing");
    }

    /// Attribute names are bounded: an unbounded name is guest-controlled
    /// heap no budget is charged for.
    #[test]
    fn attribute_names_are_bounded() {
        let mut data = data_with_log(true);
        let big = "k".repeat(MAX_LOG_FIELD_BYTES + 1);
        let err = emit_record(
            &mut data,
            2,
            "ok",
            &[attr(&big, AttributeValue::Boolean(true))],
        )
        .expect_err("name too long");
        assert!(matches!(err, WitLogError::RecordTooLarge));
        assert!(data.logs.is_empty(), "a refused record is not stored");
    }

    /// Names that would forge structure in the rendered line are refused at
    /// the boundary rather than repaired: the renderer quotes as defense in
    /// depth, but a guest that meant a different name must learn it failed.
    #[test]
    fn hostile_attribute_names_are_refused() {
        let mut data = data_with_log(true);
        for hostile in ["", "a b", "a=b", "a\"b", "a\\b", "a\nb", "a\0b", "a\x7fb"] {
            let err = emit_record(
                &mut data,
                2,
                "ok",
                &[attr(hostile, AttributeValue::Boolean(true))],
            )
            .expect_err("hostile name refused");
            assert!(
                matches!(err, WitLogError::RecordTooLarge),
                "{hostile:?} must fail closed"
            );
        }
        // Unicode whitespace, C1 controls, and invisible layout-forgers ride
        // multibyte UTF-8 past a byte scan; the char-level check refuses them.
        for hostile in [
            "a\u{a0}b",
            "a\u{85}b",
            "a\u{2028}b",
            "a\u{2029}b",
            "a\u{202e}b",
            "a\u{feff}b",
        ] {
            let err = emit_record(
                &mut data,
                2,
                "ok",
                &[attr(hostile, AttributeValue::Boolean(true))],
            )
            .expect_err("hostile unicode name refused");
            assert!(
                matches!(err, WitLogError::RecordTooLarge),
                "{hostile:?} must fail closed"
            );
        }
        assert!(data.logs.is_empty(), "no hostile name is stored");
    }

    /// `emit-many` is atomic: a batch that fails on its last record stores
    /// nothing, so a retry cannot duplicate a prefix the caller was told
    /// failed.
    #[test]
    fn emit_many_is_atomic() {
        let mut data = data_with_log(true);
        let big = "x".repeat(MAX_LOG_FIELD_BYTES + 1);
        let err = LogHost::emit_many(
            &mut data,
            vec![
                (Level::Info, "first".to_owned(), vec![]),
                (Level::Info, big, vec![]),
            ],
        )
        .expect_err("second record too big");
        assert!(matches!(err, WitLogError::RecordTooLarge));
        assert!(
            data.logs.is_empty(),
            "no prefix of a failed batch may persist"
        );
    }

    /// Stored bytes are bounded, not just stored records: 64 KiB messages
    /// backpressure long before the 4096-record count does.
    #[test]
    fn total_buffered_bytes_are_bounded() {
        let mut data = data_with_log(true);
        let message = "x".repeat(MAX_LOG_FIELD_BYTES);
        let mut count = 0;
        loop {
            match LogHost::emit(&mut data, Level::Info, message.clone(), vec![]) {
                Ok(()) => count += 1,
                Err(WitLogError::RecordTooLarge) => break,
                Err(other) => panic!("unexpected failure: {other:?}"),
            }
            assert!(count < 10_000, "the buffer must backpressure");
        }
        assert!(
            data.logs.len() < MAX_LOG_RECORDS,
            "the byte bound fires first: {} records",
            data.logs.len()
        );
        assert!(
            buffered_bytes(&data.logs) <= MAX_LOG_TOTAL_BYTES,
            "the buffer never exceeds its byte bound"
        );
    }

    /// The byte estimate counts worst-case renderings, not averages: an
    /// `i64::MIN` renders 20 characters and the longest shortest-repr
    /// `f64` 24, so the estimate for scalar-heavy records must clear both.
    #[test]
    fn record_bytes_counts_worst_case_scalar_widths() {
        let attrs = vec![
            ("i".to_owned(), AttributeValue::Integer(i64::MIN)),
            ("f".to_owned(), AttributeValue::Float(f64::MAX)),
            ("b".to_owned(), AttributeValue::Boolean(true)),
        ];
        assert_eq!(
            record_bytes("msg", &attrs),
            RECORD_FRAMING_BYTES + 3 + (1 + 20) + (1 + 24) + (1 + 5),
            "message plus per-attribute name and worst-case value widths, plus framing"
        );
    }

    /// One record renders as one line even when the guest sends control
    /// characters: the renderer escapes them.
    /// Other controls use conventional four-digit escapes, so a log
    /// consumer never sees a bare byte it cannot parse.
    #[test]
    fn other_controls_use_four_digit_escapes() {
        let record = LogRecord {
            tenant: "t".to_owned(),
            trace_id: None,
            level: 2,
            message: "a\u{1}b".to_owned(),
            attributes: vec![],
            redacted: false,
        };
        let line = format_record(&record);
        assert!(
            line.contains("\\u0001"),
            "control escapes are four-digit: {line}"
        );
    }

    /// Separators and lone non-ASCII controls trigger quoting and escape:
    /// a value holding only U+2028 must not pass through bare.
    #[test]
    fn quote_covers_separators_and_lone_controls() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote("a b"), "\"a b\"");
        assert!(
            quote("x\u{2028}y").contains("\\u2028"),
            "U+2028 must escape"
        );
        assert!(
            quote("x\u{2029}y").contains("\\u2029"),
            "U+2029 must escape"
        );
        assert!(quote("x\u{85}y").contains("\\u0085"), "U+0085 must escape");
        assert!(
            quote("x\u{202e}y").contains("\\u202e"),
            "bidi overrides must escape"
        );
        assert!(quote("t").chars().all(|c| !c.is_control()));
    }

    #[test]
    fn format_keeps_one_record_on_one_line() {
        let record = LogRecord {
            tenant: "t".to_owned(),
            trace_id: None,
            level: 2,
            message: "a\nb".to_owned(),
            attributes: vec![("k".to_owned(), AttributeValue::Text("x\ty".to_owned()))],
            redacted: false,
        };
        let line = format_record(&record);
        assert!(!line.contains('\n'), "one record is one line: {line}");
        assert!(!line.contains('\t'), "tabs are escaped: {line}");
    }

    /// Separators and tenant text are neutralised too: U+2028/U+2029 break
    /// lines without being controls, and the tenant rides unquoted unless it
    /// needs quoting.
    #[test]
    fn format_neutralises_separators_and_tenant_text() {
        let record = LogRecord {
            tenant: "acme".to_owned(),
            trace_id: None,
            level: 2,
            message: "a\u{2028}b".to_owned(),
            attributes: vec![("k".to_owned(), AttributeValue::Text("x\u{85}y".to_owned()))],
            redacted: false,
        };
        let line = format_record(&record);
        assert!(
            !line
                .chars()
                .any(|c| c == '\u{2028}' || c == '\u{2029}' || c == '\u{85}'),
            "no separator survives raw: {line}"
        );
        assert!(line.contains("\\u2028"), "separators escape: {line}");
        assert!(line.contains("\\u0085"), "NEL escapes: {line}");
        // A tenant needing no quoting renders bare, exactly as before.
        assert!(line.starts_with("tenant=acme "), "{line}");
    }

    /// The register links only when granted.
    #[test]
    fn register_links_only_when_granted() {
        use qqq_cap::resolve::GrantSet;
        const EMPTY: &str = r#"(component
          (import "qqq:log/logging@1.0.0" (instance $l))
          (core module $m)
          (core instance $i (instantiate $m))
        )"#;
        const NAMED: &str = r#"(component
          (import "qqq:log/logging@1.0.0" (instance $l
            (export "emit" (func (param "a" string)))))
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
            let mut store =
                wasmtime::Store::new(&engine, crate::linker::StoreData::new(grants.clone()));
            linker.instantiate(&mut store, &component).map(|_| ())
        }
        let m = qqq_cap::manifest::Manifest::parse(
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n[capabilities.log]\n",
        )
        .expect("manifest parses");
        link(&GrantSet::from_manifest(&m), EMPTY).expect("a granted import links");
        let err = link(&GrantSet::empty(), NAMED).expect_err("no grant means no instance");
        assert!(
            format!("{err:#}").contains("qqq:log/logging"),
            "the refusal must name the import: {err:#}"
        );
    }

    /// The rendered line carries tenant, level, message, attributes, trace.
    #[test]
    fn format_covers_every_field() {
        let r = LogRecord {
            tenant: "t".to_owned(),
            trace_id: Some([1u8; 16]),
            level: 3,
            message: "m".to_owned(),
            attributes: vec![("k".to_owned(), AttributeValue::Integer(7))],
            redacted: false,
        };
        let text = format_record(&r);
        assert!(text.contains("tenant=t"), "{text}");
        assert!(text.contains("level=warn"), "{text}");
        assert!(text.contains("msg=m"), "{text}");
        assert!(text.contains("k=7"), "{text}");
        assert!(
            text.contains("trace=01010101010101010101010101010101"),
            "{text}"
        );
    }
}
