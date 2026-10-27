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
        emit_record(self, level_index(level), message, attributes)
    }

    fn emit_many(
        &mut self,
        records: Vec<(Level, String, Vec<Attribute>)>,
    ) -> std::result::Result<(), WitLogError> {
        for (level, message, attributes) in records {
            emit_record(self, level_index(level), message, attributes)?;
        }
        Ok(())
    }

    fn enabled(&mut self, _level: Level) -> bool {
        // No level filter is configured in V1 (the marker stanza carries no
        // fields), so every level records. Returning false would silence a
        // guest that has no way to learn why, and a filter that exists
        // nowhere is not a filter.
        self.grants.grants(LogWrite)
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
#[must_use]
pub fn format_record(record: &LogRecord) -> String {
    use std::fmt::Write as _;
    let level = LEVEL_NAMES
        .get(record.level as usize % LEVEL_NAMES.len())
        .copied()
        .unwrap_or("unknown");
    let mut out = format!(
        "tenant={} level={level} msg={}",
        record.tenant,
        quote(&record.message)
    );
    for (k, v) in &record.attributes {
        let rendered = match v {
            AttributeValue::Text(s) => quote(s),
            AttributeValue::Integer(n) => n.to_string(),
            AttributeValue::Float(f) => format!("{f:?}"),
            AttributeValue::Boolean(b) => b.to_string(),
        };
        let _ = write!(out, " {k}={rendered}");
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
    if s.bytes().any(|b| b.is_ascii_whitespace() || b == b'"') {
        format!("\"{}\"", s.replace('"', "\\\""))
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
/// Append one record to this instance's log buffer, redacting secret values.
fn emit_record(
    data: &mut crate::linker::StoreData,
    level: u8,
    message: String,
    attributes: Vec<Attribute>,
) -> std::result::Result<(), WitLogError> {
    if !data.grants.grants(LogWrite) {
        return Err(WitLogError::NotGranted);
    }
    if message.len() > MAX_LOG_FIELD_BYTES {
        return Err(WitLogError::RecordTooLarge);
    }
    if attributes.len() > MAX_LOG_ATTRIBUTES {
        return Err(WitLogError::RecordTooLarge);
    }
    if data.logs.len() >= MAX_LOG_RECORDS {
        return Err(WitLogError::RecordTooLarge);
    }
    let mut redacted = false;
    let mut attrs: Vec<(String, AttributeValue)> = Vec::with_capacity(attributes.len());
    for a in attributes {
        let bytes: &[u8] = match &a.value {
            AttributeValue::Text(s) => s.as_bytes(),
            _ => &[],
        };
        let value = if !bytes.is_empty() && data.secrets.is_secret_value(bytes) {
            redacted = true;
            AttributeValue::Text("[redacted:secret]".to_owned())
        } else {
            a.value
        };
        if let AttributeValue::Text(s) = &value
            && s.len() > MAX_LOG_FIELD_BYTES
        {
            return Err(WitLogError::RecordTooLarge);
        }
        attrs.push((a.name, value));
    }
    let message = if !message.is_empty() && data.secrets.is_secret_value(message.as_bytes()) {
        redacted = true;
        "[redacted:secret]".to_owned()
    } else {
        message
    };
    let tenant = data
        .tenant
        .as_ref()
        .map_or("unscoped".to_owned(), ToString::to_string);
    let trace_id = data.trace.active.map(|(id, _)| id);
    data.logs.push(crate::host_log::LogRecord {
        tenant,
        trace_id,
        level,
        message,
        attributes: attrs,
        redacted,
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
        crate::linker::StoreData::new(grants)
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
            "hello".to_owned(),
            vec![attr("k", AttributeValue::Text("v".to_owned()))],
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
        let err = emit_record(&mut data, 2, "hello".to_owned(), vec![]).expect_err("no grant");
        assert!(matches!(err, WitLogError::NotGranted));
        assert!(data.logs.is_empty(), "a refused record is not stored");
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
        emit_record(&mut data, 2, "super-secret".to_owned(), vec![]).expect("emits");
        let r = &data.logs[0];
        assert_eq!(r.message, "[redacted:secret]");
        assert!(r.redacted);
        emit_record(
            &mut data,
            2,
            "not the secret".to_owned(),
            vec![attr("k", AttributeValue::Text("super-secret".to_owned()))],
        )
        .expect("emits");
        let r = &data.logs[1];
        assert_eq!(
            r.message, "not the secret",
            "messages are not substring-matched"
        );
        assert!(matches!(&r.attributes[0].1, AttributeValue::Text(v) if v == "[redacted:secret]"));
        assert!(r.redacted);
        emit_record(&mut data, 2, "prefix-super-secret".to_owned(), vec![]).expect("emits");
        assert!(!data.logs[2].redacted, "no substring redaction");
    }

    /// Oversize messages and attribute lists fail before any write.
    #[test]
    fn oversize_records_fail_closed() {
        let mut data = data_with_log(true);
        let big = "x".repeat(MAX_LOG_FIELD_BYTES + 1);
        let err = emit_record(&mut data, 2, big, vec![]).expect_err("too big");
        assert!(matches!(err, WitLogError::RecordTooLarge));
        let many: Vec<Attribute> = (0..=MAX_LOG_ATTRIBUTES)
            .map(|i| attr(&format!("k{i}"), AttributeValue::Boolean(true)))
            .collect();
        let err = emit_record(&mut data, 2, "ok".to_owned(), many).expect_err("too many");
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
            emit_record(&mut data, 2, "x".to_owned(), vec![]).expect("fits");
        }
        let err = emit_record(&mut data, 2, "one more".to_owned(), vec![]).expect_err("full");
        assert!(matches!(err, WitLogError::RecordTooLarge));
        assert_eq!(data.logs.len(), MAX_LOG_RECORDS);
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
