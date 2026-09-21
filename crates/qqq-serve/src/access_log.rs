// SPDX-License-Identifier: Apache-2.0

//! Structured access logging: one JSON object per request, with redaction applied
//! **here** rather than in the guest.
//!
//! Implements Checklist `SRV-013` — *"Implement structured access logging with
//! tenant and trace correlation"* — and Proposal §10.3:
//!
//! > Structured JSON by default; human-readable in a TTY. Every line carries
//! > `trace_id`, `span_id`, `tenant`, `component`, `manifest_rev`, `level`, `msg`,
//! > `code?`. Redaction is applied by the **host**, not the guest, using
//! > manifest-declared secret names — so a guest cannot leak a secret it was never
//! > given (§6.3).
//!
//! # Why the field list is a type and not a convention
//!
//! "Every line carries these fields" is the kind of requirement that decays: a new
//! call site writes the four fields it has to hand, a reader learns that `tenant`
//! is sometimes absent, and a query that groups by tenant silently drops rows. The
//! defense is to make the fields **unrepresentable as anything else** — [`Record`]
//! has them all, they are not `Option`, and there is no constructor that omits one.
//! `code` is the only optional field, because §10.3 writes it as `code?` and a
//! successful request genuinely has no code.
//!
//! # Why redaction lives in the host
//!
//! §10.3's second sentence is a capability argument, not a formatting one. A guest
//! holding a secret can leak it; a guest that only ever sees a *name* cannot,
//! because it never had the value. Redaction at the host boundary is what makes
//! "a guest cannot leak a secret it was never given" true, which is why this module
//! owns it rather than delegating to whatever the guest decides to log.
//!
//! The mechanism is deliberately blunt: any substring matching a declared secret
//! value is replaced. A cleverer scheme — hashing, structured field allow-lists —
//! would still have to handle the case where a secret appears inside a longer
//! string, and a value-substring match is the only approach that catches
//! `Authorization: Bearer <secret>` and a secret logged in a URL with the same
//! rule.
//!
//! # What "human-readable in a TTY" means here
//!
//! [`Record::render_human`] prints the same fields in a fixed order, one line, with
//! the level first so `grep ERROR` works. It is **not** a different data model: the
//! same record, two encodings. A human format that could carry a field the JSON
//! form cannot is a second source of truth for what a log line is.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The severity of a log record, in the order the Proposal's §12.2 catalogue uses.
///
/// `Ord` is derived so a level filter is a comparison rather than a match, and so
/// `Error > Warn > Info > Debug > Trace` is stated once instead of at each call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Finest-grained, for development.
    Trace,
    /// Diagnostic detail.
    Debug,
    /// Normal operation.
    Info,
    /// Something is wrong but the request succeeded.
    Warn,
    /// The request failed.
    Error,
}

impl Level {
    /// The level's name, as it appears on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    /// Parse a level name.
    ///
    /// # Errors
    ///
    /// Returns `None` for anything else. A caller setting a filter from a config
    /// file needs to reject a typo rather than silently defaulting to a level the
    /// operator did not ask for — `log_level = "warnng"` defaulting to `Info` is
    /// how an operator loses the `warn` lines they were trying to see.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }

    /// The uppercase form, for the human rendering.
    #[must_use]
    pub const fn as_upper(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

/// The identifier of a request, as it travels.
///
/// # Why this is not a `String`
///
/// Trace and span ids have to satisfy two properties that a `String` cannot state:
/// they are **hex**, and they are **one of exactly two lengths** (OWASP's W3C
/// `traceparent` shape: 16 bytes for a trace, 8 for a span). A server that accepted
/// any string would forward a client-supplied `traceparent` straight into logs,
/// where a newline in it forges a log line. Validating at construction is what makes
/// `render_human`'s one-line guarantee true rather than hopeful.
///
/// # Errors
///
/// [`TraceIdError`] when the value is not hex of the required length.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceId(String);

/// Why a trace or span id was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceIdError {
    /// The value was empty.
    Empty,
    /// The value had the wrong number of characters.
    WrongLength {
        /// How many characters it had.
        got: usize,
        /// How many it needed.
        want: usize,
    },
    /// The value contained a character that is not a hex digit.
    NotHex {
        /// The offending character.
        ch: char,
    },
}

impl std::fmt::Display for TraceIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "a trace id must not be empty"),
            Self::WrongLength { got, want } => {
                write!(f, "a trace id must be {want} hex characters, got {got}")
            }
            Self::NotHex { ch } => write!(
                f,
                "a trace id must be hex, found {ch:?} -- a non-hex character could carry a \
                 newline and forge a log line"
            ),
        }
    }
}

impl std::error::Error for TraceIdError {}

impl TraceId {
    /// The character count of a trace id (W3C `traceparent`: 16 bytes).
    pub const TRACE_LEN: usize = 32;
    /// The character count of a span id (W3C `traceparent`: 8 bytes).
    pub const SPAN_LEN: usize = 16;

    /// A validated trace id.
    ///
    /// # Errors
    ///
    /// [`TraceIdError`] as described on the type.
    pub fn trace(value: &str) -> Result<Self, TraceIdError> {
        Self::check(value, Self::TRACE_LEN)
    }

    /// A validated span id.
    ///
    /// # Errors
    ///
    /// [`TraceIdError`] as described on the type.
    pub fn span(value: &str) -> Result<Self, TraceIdError> {
        Self::check(value, Self::SPAN_LEN)
    }

    fn check(value: &str, want: usize) -> Result<Self, TraceIdError> {
        if value.is_empty() {
            return Err(TraceIdError::Empty);
        }
        if value.len() != want {
            return Err(TraceIdError::WrongLength {
                got: value.len(),
                want,
            });
        }
        if let Some(ch) = value.chars().find(|c| !c.is_ascii_hexdigit()) {
            return Err(TraceIdError::NotHex { ch });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// The id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A deterministic id derived from a counter, for callers with no tracer.
    ///
    /// Hex, fixed width, and distinct per counter value — which is what a log
    /// correlation needs. **Not** random: a value that changes between two runs of
    /// the same input would break the determinism `§10.5` promises, and this is the
    /// id a deterministic-mode run would otherwise have to special-case.
    #[must_use]
    pub fn from_counter(n: u64) -> Self {
        Self(format!("{n:032x}"))
    }
}

/// One log record, with every field §10.3 names.
///
/// Construct with [`Record::new`] and refine with the builder methods. `BTreeMap`
/// for the extras rather than a `HashMap`: iteration order is observable in the
/// rendered line, and §10.5 bans unordered map iteration from anything a guest can
/// observe — including, for reproducibility, the logs a run produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    trace_id: TraceId,
    span_id: TraceId,
    tenant: String,
    component: String,
    manifest_rev: String,
    level: Level,
    msg: String,
    code: Option<String>,
    /// Additional fields, in a stable order.
    extra: BTreeMap<String, String>,
}

impl Record {
    /// A record with the eight mandatory fields.
    ///
    /// Every one is required by §10.3 except `code`, which is added by
    /// [`Self::with_code`]. There is deliberately no constructor that omits one:
    /// see the module documentation for why the field list is a type.
    #[must_use]
    pub fn new(
        level: Level,
        trace_id: TraceId,
        span_id: TraceId,
        tenant: impl Into<String>,
        component: impl Into<String>,
        manifest_rev: impl Into<String>,
        msg: impl Into<String>,
    ) -> Self {
        Self {
            trace_id,
            span_id,
            tenant: tenant.into(),
            component: component.into(),
            manifest_rev: manifest_rev.into(),
            level,
            msg: msg.into(),
            code: None,
            extra: BTreeMap::new(),
        }
    }

    /// Add the error code, for a record about a failure.
    #[must_use]
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    /// Add an extra field.
    ///
    /// The name is **not** validated here and must not be empty: an empty name
    /// renders as `"":value`, which is valid JSON and useless to a query. Callers
    /// pass a literal in every case in this crate; the debug assertion catches a
    /// computed empty name in tests without adding a runtime branch to a hot path.
    #[must_use]
    pub fn with_field(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        debug_assert!(!name.is_empty(), "a log field name must not be empty");
        self.extra.insert(name, value.into());
        self
    }

    /// The level.
    #[must_use]
    pub const fn level(&self) -> Level {
        self.level
    }

    /// The trace id.
    #[must_use]
    pub const fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// The span id.
    #[must_use]
    pub const fn span_id(&self) -> &TraceId {
        &self.span_id
    }

    /// The tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The component that emitted the record.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// The manifest revision the emitting component was built from.
    #[must_use]
    pub fn manifest_rev(&self) -> &str {
        &self.manifest_rev
    }

    /// The message.
    #[must_use]
    pub fn msg(&self) -> &str {
        &self.msg
    }

    /// The error code, when the record carries one.
    ///
    /// `code` is §10.3's only optional field: a successful request genuinely has no
    /// code, and a caller must be able to tell "no code" from "the empty code".
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    /// The caller-supplied fields, in the order they are rendered.
    ///
    /// No `#[must_use]`: `impl Iterator` is already `#[must_use]`, and the redundant
    /// attribute is what `clippy::double_must_use` rejects.
    pub fn fields(&self) -> impl Iterator<Item = (&str, &str)> {
        self.extra.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Apply a redactor to every string the record carries.
    ///
    /// Returns how many substitutions were made, so a caller can assert that a
    /// fixture actually contained a secret rather than trusting that it did — the
    /// difference between a test that proves redaction and one that passes because
    /// there was nothing to redact.
    pub fn redact(&mut self, redactor: &Redactor) -> usize {
        let mut hits = 0;
        hits += redactor.apply(&mut self.msg);
        hits += redactor.apply(&mut self.tenant);
        hits += redactor.apply(&mut self.component);
        hits += redactor.apply(&mut self.manifest_rev);
        if let Some(code) = &mut self.code {
            hits += redactor.apply(code);
        }
        for value in self.extra.values_mut() {
            hits += redactor.apply(value);
        }
        hits
    }

    /// Serialize as one JSON object, without a trailing newline.
    ///
    /// Hand-written rather than derived: `serde`'s derive would need a mirror
    /// struct with `rename_all`, which is a second place to keep the field names
    /// right. The names here are the ones §10.3 lists, in its order.
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');
        let _ = write!(out, "\"level\":{}", json_string(self.level.as_str()));
        let _ = write!(out, ",\"trace_id\":{}", json_string(self.trace_id.as_str()));
        let _ = write!(out, ",\"span_id\":{}", json_string(self.span_id.as_str()));
        let _ = write!(out, ",\"tenant\":{}", json_string(&self.tenant));
        let _ = write!(out, ",\"component\":{}", json_string(&self.component));
        let _ = write!(out, ",\"manifest_rev\":{}", json_string(&self.manifest_rev));
        let _ = write!(out, ",\"msg\":{}", json_string(&self.msg));
        if let Some(code) = &self.code {
            let _ = write!(out, ",\"code\":{}", json_string(code));
        }
        for (k, v) in &self.extra {
            let _ = write!(out, ",{}:{}", json_string(k), json_string(v));
        }
        out.push('}');
        out
    }

    /// Render for a terminal: the same fields, one line, level first.
    ///
    /// # Why `manifest_rev` is here, and why its absence was a defect
    ///
    /// §10.3 lists `manifest_rev` among the fields on **every** line, and a caller
    /// debugging "which build served this request?" reads the human form far more
    /// often than the JSON one. A first version of this function omitted the field
    /// while `render_json` wrote it, so the two encodings disagreed about the record
    /// — exactly the "second source of truth" this module's docs warn against, in
    /// the one place where writing the warning did not prevent it. The field now
    /// follows `component`, and `the_two_encodings_carry_the_same_fields` compares
    /// the two renderings field-by-field so the next omission fails a test instead of
    /// shipping.
    ///
    /// # Every variable string goes through [`one_line`]
    ///
    /// The fixed-width columns are formatted from values this module validates
    /// (`trace_id`, `span_id`, the level) and are safe by construction. Everything
    /// else — `tenant`, `component`, `manifest_rev`, `msg`, `code` and both halves of
    /// every extra field — is data from outside this layer, and is sanitized so the
    /// one-line guarantee holds no matter what a guest puts in a request. See
    /// [`one_line`] for the measurement that made this necessary.
    #[must_use]
    pub fn render_human(&self) -> String {
        let mut out = String::with_capacity(160);
        let _ = write!(
            out,
            "{:<5} {:<32} {:<16} {:<12} {} {} ",
            self.level.as_upper(),
            self.trace_id.as_str(),
            self.span_id.as_str(),
            one_line(&truncate(&self.tenant, 12)),
            one_line(&self.component),
            one_line(&self.manifest_rev)
        );
        let _ = write!(out, "{}", one_line(&self.msg));
        if let Some(code) = &self.code {
            let _ = write!(out, " ({})", one_line(code));
        }
        for (k, v) in &self.extra {
            let _ = write!(out, " {}={}", one_line(k), one_line(v));
        }
        out
    }
}

/// Replace every occurrence of a declared secret with a placeholder.
///
/// # Why a value-substring match
///
/// The declared names are the *keys*; the values come from the environment at
/// resolve time. Matching on the value is what catches a secret wherever it
/// appears — inside a header, a URL query, a JSON body — with one rule. A scheme
/// that tried to understand each field would miss the next format someone invents.
///
/// # Why the replacement is a fixed marker plus an index
///
/// `[redacted:3]` rather than `***`, so two different secrets are distinguishable in
/// a log without revealing either. An operator debugging an auth failure needs to
/// know *which* credential was used; a marker that collapses them all makes that
/// question unanswerable.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    /// Values to replace, longest first.
    ///
    /// Longest first because a short secret that is a substring of a longer one
    /// would otherwise consume part of it and leave the remainder in the clear.
    values: Vec<String>,
}

impl Redactor {
    /// A redactor with nothing to redact.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from declared secret values.
    ///
    /// Empty values are ignored: replacing the empty string would insert a marker
    /// between every character. This is not a hypothetical — an unset environment
    /// variable resolves to an empty string, and a redactor that treated it as a
    /// secret would corrupt every log line it touched. It is also why the guard is
    /// here rather than at the call site: a caller cannot be relied on to check.
    ///
    /// # Why duplicates are removed *before* the length sort
    ///
    /// `sort_by_key(Reverse(len)); dedup();` looks right and is not. `sort_by_key` is
    /// **stable**, so equal-length values keep their input order, and `dedup` only
    /// removes *adjacent* equal elements. Measured: `from_values(["abcd", "zzzz",
    /// "abcd"])` kept all **3** — the two `abcd` entries were separated by `zzzz`
    /// after the sort, so neither sat next to its twin.
    ///
    /// The consequence is not cosmetic. The marker is numbered by position (`i + 1`
    /// in `apply`), so one secret could be reported as both `[redacted:1]` and
    /// `[redacted:3]` — two identifiers for one secret, which breaks the correlation
    /// the marker exists to provide.
    ///
    /// So: sort by **value** first (a total order, which puts equal elements adjacent
    /// regardless of length) and `dedup`, then sort by length for the matching order.
    /// Two passes over a list that is small and fixed at startup.
    #[must_use]
    pub fn from_values<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut values: Vec<String> = values
            .into_iter()
            .map(Into::into)
            .filter(|v| !v.is_empty())
            .collect();

        // Pass 1: distinct. Sorting by value makes equal elements adjacent; sorting by
        // length does not, which was the defect.
        values.sort_unstable();
        values.dedup();

        // Pass 2: longest first, which is what the matching depends on — a short
        // secret that prefixes a longer one must not match first. `sort_by_key` is
        // stable and the values are now distinct, so equal lengths keep the value
        // order from pass 1 and the marker numbering is deterministic.
        values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        Self { values }
    }

    /// How many distinct values are redacted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether there is nothing to redact.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Replace secrets in one string, returning how many were replaced.
    fn apply(&self, text: &mut String) -> usize {
        let mut hits = 0;
        for (i, secret) in self.values.iter().enumerate() {
            if !text.contains(secret.as_str()) {
                continue;
            }
            let marker = format!("[redacted:{}]", i + 1);
            hits += text.matches(secret.as_str()).count();
            *text = text.replace(secret.as_str(), &marker);
        }
        hits
    }
}

/// The destination for records.
///
/// # Why an enum and not a `dyn Write`
///
/// The choice is between two encodings, not between two sinks, and making it a
/// type keeps `render_human`'s one-line guarantee checkable. A `dyn Write` would
/// also accept a sink that splits lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One JSON object per line.
    Json,
    /// One aligned line, for a terminal.
    Human,
}

/// A logger: a format, a level filter, and a redactor.
///
/// Holds no file handle. `qqq-serve` writes to stdout or to a caller-supplied sink;
/// keeping the handle out means the decision is the server's, and the filter and
/// redaction logic is testable without one.
#[derive(Debug, Clone)]
pub struct Logger {
    format: Format,
    level: Level,
    redactor: Redactor,
}

impl Logger {
    /// A logger at a format and a minimum level, with nothing redacted.
    #[must_use]
    pub fn new(format: Format, level: Level) -> Self {
        Self {
            format,
            level,
            redactor: Redactor::new(),
        }
    }

    /// A logger that redacts the given declared secret values.
    #[must_use]
    pub fn with_redactor(mut self, redactor: Redactor) -> Self {
        self.redactor = redactor;
        self
    }

    /// The minimum level that will be emitted.
    #[must_use]
    pub const fn level(&self) -> Level {
        self.level
    }

    /// The active format.
    #[must_use]
    pub const fn format(&self) -> Format {
        self.format
    }

    /// Whether a record at this level would be emitted.
    #[must_use]
    pub const fn enabled(&self, level: Level) -> bool {
        level as u8 >= self.level as u8
    }

    /// Redact and render a record, or `None` when the level filters it out.
    ///
    /// Redaction runs **before** the format branch, so the two encodings can never
    /// disagree about whether a secret was replaced. Redacting inside
    /// `render_human` and again inside `render_json` is how one of them ends up
    /// forgotten.
    #[must_use]
    pub fn emit(&self, mut record: Record) -> Option<String> {
        if !self.enabled(record.level) {
            return None;
        }
        record.redact(&self.redactor);
        Some(match self.format {
            Format::Json => record.render_json(),
            Format::Human => record.render_human(),
        })
    }
}

/// Truncate to `max` characters, on a character boundary, with an ellipsis.
///
/// `chars().take` rather than a byte slice: a tenant id containing a multi-byte
/// character would panic a byte-indexed cut, and a logger that panics on an
/// operator-supplied name takes the server down with it.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Replace every character that could break the human format's one-line guarantee.
///
/// # Why the human renderer needs this and the JSON renderer does not
///
/// `json_string` escapes `\n`, `\r` and every other control character, so a JSON line
/// can never be split or coloured by its own content — the module docs call log
/// injection *"exactly the property §10.3's host-side redaction exists to protect."*
///
/// The human renderer had **no such guard**, and that was a security defect, not a
/// cosmetic one. Measured before the fix: a `msg` of
/// `"GET /x 200\nINFO  fake  fake  fake  false  FORGED LINE"` rendered as **2 lines**,
/// and a `msg` carrying `ESC[31m` put a raw ANSI escape into an operator's terminal.
/// Both are guest-controlled: `msg` comes from the request, so a guest could forge a
/// log line that a `grep`-based alerting rule would read as genuine, or emit terminal
/// control sequences into whatever reads the log.
///
/// # Why the whole record is passed through it, not just `msg`
///
/// Every string on the record is guest-influenced — `msg` from the request line,
/// `code` from a body, `extra` values from whatever the call site logs, and even
/// `tenant` from a peer address or, later, a header. Sanitizing only `msg` would leave
/// the same forgery available one field over, which is the "looks handled" failure this
/// file's redaction docs already warn about.
///
/// The replacement is `U+FFFD` rather than a deletion or an escape: a line with a
/// visibly broken character tells a reader that something was there, while silently
/// dropping the byte could make two different forged messages render identically.
#[must_use]
fn one_line(s: &str) -> String {
    if s.chars().all(|c| !c.is_control()) {
        // The common case: no allocation and no copy.
        return s.to_owned();
    }
    s.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

/// Encode a string as a JSON string literal, with every character JSON requires
/// escaped.
///
/// Hand-written so this module has no serialization dependency, and so the control
/// characters are handled explicitly: a log message containing a newline is the
/// classic log-injection vector, and an encoder that passed `\n` through would let
/// a guest forge a second log line — which is exactly the property §10.3's
/// host-side redaction exists to protect.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            // Every other control character, so no raw control byte reaches the
            // stream. JSON requires these escaped; a reader that tolerated them
            // would be the only thing standing between a log and a forged line.
            c if c < '\u{20}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (TraceId, TraceId) {
        (
            TraceId::trace("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
            TraceId::span("00f067aa0ba902b7").unwrap(),
        )
    }

    fn record() -> Record {
        let (t, s) = ids();
        Record::new(
            Level::Info,
            t,
            s,
            "acme",
            "orders-api",
            "rev-7",
            "request completed",
        )
    }

    // -- levels -------------------------------------------------------------

    /// The ordering is the filter. A reversed `Ord` would silently invert it.
    #[test]
    fn levels_order_from_trace_to_error() {
        assert!(Level::Trace < Level::Debug);
        assert!(Level::Debug < Level::Info);
        assert!(Level::Info < Level::Warn);
        assert!(Level::Warn < Level::Error);
    }

    /// A typo must not silently become a default.
    #[test]
    fn level_parsing_rejects_a_typo() {
        assert_eq!(Level::parse("warn"), Some(Level::Warn));
        assert_eq!(Level::parse("WARNING"), Some(Level::Warn));
        assert_eq!(Level::parse("ERROR"), Some(Level::Error));
        assert_eq!(Level::parse("warnng"), None);
        assert_eq!(Level::parse(""), None);
    }

    // -- trace ids ----------------------------------------------------------

    /// A validated id is hex of one of exactly two lengths.
    #[test]
    fn trace_ids_are_validated() {
        assert!(TraceId::trace("4bf92f3577b34da6a3ce929d0e0e4736").is_ok());
        assert!(TraceId::span("00f067aa0ba902b7").is_ok());

        // Too short.
        assert!(matches!(
            TraceId::trace("abc"),
            Err(TraceIdError::WrongLength { got: 3, want: 32 })
        ));
        // Upper case is accepted and normalized.
        assert_eq!(
            TraceId::trace("4BF92F3577B34DA6A3CE929D0E0E4736")
                .unwrap()
                .as_str(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
    }

    /// **A newline must not be accepted**, because it forges a log line.
    ///
    /// This is the reason trace ids are validated rather than passed through: a
    /// client-supplied `traceparent` reaches the logs, and a 32-character string
    /// containing a newline and a fake `ERROR` line is a log-injection vector that
    /// nothing downstream would question.
    #[test]
    fn a_trace_id_with_a_newline_is_refused() {
        let forged = "4bf92f3577b34da6a3ce929d0e0e473\nERROR forged";
        let e = TraceId::trace(forged).expect_err("a newline must be refused");
        assert!(
            matches!(
                e,
                TraceIdError::NotHex { .. } | TraceIdError::WrongLength { .. }
            ),
            "{e}"
        );

        // And the right length with one bad character is still refused.
        let e = TraceId::trace("4bf92f3577b34da6a3ce929d0e0e473g")
            .expect_err("a non-hex character must be refused");
        assert!(matches!(e, TraceIdError::NotHex { ch: 'g' }), "{e}");
    }

    /// An id from a counter is deterministic, which §10.5 requires.
    #[test]
    fn counter_ids_are_deterministic_and_distinct() {
        assert_eq!(TraceId::from_counter(1), TraceId::from_counter(1));
        assert_ne!(TraceId::from_counter(1), TraceId::from_counter(2));
        // Same length as a real trace id, so a log reader sees one shape.
        assert_eq!(TraceId::from_counter(1).as_str().len(), TraceId::TRACE_LEN);
    }

    // -- the field contract -------------------------------------------------

    /// **Every mandatory §10.3 field is present, in JSON.**
    #[test]
    fn the_json_record_carries_every_mandatory_field() {
        let json = record().render_json();
        for field in [
            "level",
            "trace_id",
            "span_id",
            "tenant",
            "component",
            "manifest_rev",
            "msg",
        ] {
            assert!(
                json.contains(&format!("\"{field}\":")),
                "the record must carry `{field}`: {json}"
            );
        }
        assert!(
            !json.contains("\"code\""),
            "`code` is optional and must be absent when there is none: {json}"
        );
    }

    /// `code` appears only when set, per §10.3's `code?`.
    #[test]
    fn the_code_field_appears_only_for_a_failure() {
        let json = record().with_code("QQQ-6006").render_json();
        assert!(json.contains("\"code\":\"QQQ-6006\""), "{json}");
    }

    /// The JSON must actually parse, checked by parsing it.
    #[test]
    fn the_json_record_parses() {
        let json = record()
            .with_code("QQQ-6001")
            .with_field("status", "500")
            .render_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("the record must be JSON");
        assert_eq!(v["tenant"], "acme");
        assert_eq!(v["level"], "info");
        assert_eq!(v["status"], "500");
        assert_eq!(v["code"], "QQQ-6001");
    }

    /// **A message containing a newline must not produce two lines.**
    #[test]
    fn a_message_with_a_newline_stays_on_one_line() {
        let mut r = record();
        r.msg = "first\nERROR forged by a newline".to_owned();
        let json = r.render_json();
        assert_eq!(
            json.matches('\n').count(),
            0,
            "a raw newline in the JSON would forge a line: {json:?}"
        );
        assert!(json.contains("\\n"), "{json}");
        // And it still parses, with the newline intact inside the value.
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["msg"], "first\nERROR forged by a newline");
    }

    /// Quotes, backslashes and control characters are all escaped.
    #[test]
    fn awkward_characters_are_escaped() {
        let mut r = record();
        r.msg = "quote \" backslash \\ tab \t bell \u{07}".to_owned();
        let json = r.render_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["msg"], "quote \" backslash \\ tab \t bell \u{07}");
    }

    /// The human rendering is one line and names the level first.
    #[test]
    fn the_human_record_is_one_line_with_the_level_first() {
        let line = record().render_human();
        assert!(!line.contains('\n'), "the human line must not wrap: {line}");
        assert!(line.starts_with("INFO"), "{line}");
        assert!(line.contains("acme"), "{line}");
        assert!(line.contains("request completed"), "{line}");
    }

    /// **The two encodings carry the same fields.**
    ///
    /// # Why this test exists
    ///
    /// `render_human` shipped without `manifest_rev` while `render_json` wrote it:
    /// §10.3 lists the field as mandatory on every line, and the human form is what
    /// an operator reads when asking "which build served this?". The module docs warn
    /// that "a human format that could carry a field the JSON form cannot is a second
    /// source of truth" — and writing the warning did not prevent the defect, because
    /// nothing compared the two.
    ///
    /// So this compares them. Every mandatory field and every optional one is pulled
    /// out of the JSON keys and looked for in the human line, which means dropping a
    /// field from **either** renderer fails here rather than in an integration test
    /// three layers away.
    #[test]
    fn the_two_encodings_carry_the_same_fields() {
        let r = record()
            .with_code("QQQ-2001")
            .with_field("status", "200")
            .with_field("method", "GET");

        // The values, keyed as they appear in JSON. Read through the record's own
        // accessors, so renaming a field has to be changed here deliberately rather
        // than being papered over by a literal that happens to match.
        let values = [
            ("level", r.level().as_str().to_owned()),
            ("trace_id", r.trace_id().as_str().to_owned()),
            ("span_id", r.span_id().as_str().to_owned()),
            ("tenant", r.tenant().to_owned()),
            ("component", r.component().to_owned()),
            ("manifest_rev", r.manifest_rev().to_owned()),
            ("msg", r.msg().to_owned()),
            ("code", r.code().unwrap_or_default().to_owned()),
            ("status", "200".to_owned()),
            ("method", "GET".to_owned()),
        ];

        let json = r.render_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let human = r.render_human();

        for (key, value) in &values {
            assert!(
                v.get(key).is_some(),
                "render_json omitted `{key}` from §10.3's field set: {json}"
            );
            assert_eq!(
                v[key].as_str(),
                Some(value.as_str()),
                "render_json's `{key}` must be the value the record holds"
            );

            // `level` is the one field the two encodings deliberately case
            // differently: JSON carries the lower-case wire name (so a query can
            // compare it to a config value) and the human line carries `INFO` (so
            // `grep ERROR` reads as a word). Every other field must appear verbatim.
            let found = if *key == "level" {
                human
                    .to_ascii_uppercase()
                    .contains(&value.to_ascii_uppercase())
            } else {
                human.contains(value.as_str())
            };
            assert!(
                found,
                "render_human omitted `{key}` (value `{value}`): {human}"
            );
        }

        // The JSON key set is exactly these fields — compared as a **set**, because
        // `serde_json::Value` sorts keys alphabetically while `render_json` writes
        // them in §10.3's order. What matters here is that no field exists in one
        // list and not the other, so a field added to `render_json` without being
        // added to this comparison fails rather than passing unnoticed.
        let mut keys: Vec<&str> = v
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected: Vec<&str> = values.iter().map(|(k, _)| *k).collect();
        keys.sort_unstable();
        expected.sort_unstable();
        assert_eq!(
            keys, expected,
            "the JSON field set changed; update the comparison above deliberately"
        );
    }

    /// A long tenant is truncated without panicking on a multi-byte boundary.
    ///
    /// A byte-indexed cut would panic here, and a logger that panics on an
    /// operator-supplied name takes the server down with it.
    #[test]
    fn a_multibyte_tenant_is_truncated_safely() {
        let (t, s) = ids();
        let r = Record::new(
            Level::Info,
            t,
            s,
            "テナント名がとても長い場合",
            "svc",
            "rev",
            "msg",
        );
        let line = r.render_human();
        assert!(line.contains('…'), "{line}");
        assert!(!line.contains('\n'), "{line}");
    }

    // -- redaction ----------------------------------------------------------

    /// **The host replaces a declared secret value wherever it appears.**
    #[test]
    fn a_declared_secret_is_replaced() {
        let redactor = Redactor::from_values(["super-secret-token"]);
        let mut r = record();
        r.msg = "sending Authorization: Bearer super-secret-token".to_owned();

        let hits = r.redact(&redactor);
        assert_eq!(hits, 1, "the fixture must actually contain the secret");
        assert!(
            !r.msg.contains("super-secret-token"),
            "the value must be gone: {}",
            r.msg
        );
        assert!(r.msg.contains("[redacted:1]"), "{}", r.msg);
    }

    /// A secret in an extra field is redacted too, not only in `msg`.
    ///
    /// A redactor that walked only the message would leave the same secret in the
    /// clear one field over, which is worse than no redaction: it looks handled.
    #[test]
    fn a_secret_in_any_field_is_replaced() {
        let redactor = Redactor::from_values(["hunter2"]);
        let mut r = record()
            .with_field("query_string", "token=hunter2&x=1")
            .with_field("note", "hunter2");
        r.msg = "hunter2".to_owned();

        let hits = r.redact(&redactor);
        assert_eq!(hits, 3, "one per field: {hits}");
        let json = r.render_json();
        assert!(
            !json.contains("hunter2"),
            "no field may retain the secret: {json}"
        );
    }

    /// **An empty secret must not be treated as one.**
    ///
    /// An unset environment variable resolves to an empty string. A redactor that
    /// accepted it would insert a marker between every character of every log line
    /// — a total corruption of the output, caused by the safety mechanism.
    #[test]
    fn an_empty_secret_is_ignored() {
        let redactor = Redactor::from_values(["", "real-secret"]);
        assert_eq!(redactor.len(), 1, "the empty value must be dropped");

        let mut r = record();
        r.msg = "harmless".to_owned();
        let hits = r.redact(&redactor);
        assert_eq!(hits, 0);
        assert_eq!(r.msg, "harmless", "the message must be untouched");
    }

    /// Two secrets are distinguishable in the output.
    ///
    /// An operator debugging an auth failure needs to know *which* credential was
    /// used; a single `***` marker makes that unanswerable.
    #[test]
    fn two_secrets_get_distinct_markers() {
        let redactor = Redactor::from_values(["aaaa", "bbbb"]);
        let mut r = record();
        r.msg = "first aaaa then bbbb".to_owned();
        r.redact(&redactor);
        assert!(r.msg.contains("[redacted:1]"), "{}", r.msg);
        assert!(r.msg.contains("[redacted:2]"), "{}", r.msg);
        assert!(
            !r.msg.contains("aaaa") && !r.msg.contains("bbbb"),
            "{}",
            r.msg
        );
    }

    /// **A repeated secret collapses to one value, so it gets one marker.**
    ///
    /// # The defect, measured
    ///
    /// `from_values` sorted by **length** and then called `dedup`. `sort_by_key` is
    /// stable, so equal-length values keep their input order, and `dedup` removes only
    /// *adjacent* equal elements. Measured:
    /// `from_values(["abcd", "zzzz", "abcd"])` kept all **3** — the two `abcd` entries
    /// were separated by `zzzz`, so neither sat beside its twin.
    ///
    /// `apply` numbers its markers by position, so the same secret was reported as both
    /// `[redacted:1]` and `[redacted:3]`. That breaks the one thing the marker is for:
    /// an operator counting occurrences of one secret across lines would see two
    /// different identifiers and conclude two secrets were leaking.
    ///
    /// Two cases are covered, because they fail for the same reason but reach the sort
    /// differently: equal-length duplicates (interleaved with another equal-length
    /// value) and different-length duplicates.
    #[test]
    fn a_repeated_secret_collapses_to_one_value() {
        // Equal lengths: the case that was broken. `zzzz` sits between the twins.
        let interleaved = Redactor::from_values(["abcd", "zzzz", "abcd"]);
        assert_eq!(interleaved.len(), 2, "the duplicate must collapse");

        // Different lengths: the duplicate is separated by length ordering.
        let mixed = Redactor::from_values(["abc", "ab", "abc"]);
        assert_eq!(mixed.len(), 2, "the duplicate must collapse");

        // And the marker numbering follows: one secret, one marker, whichever of the
        // two distinct values it is.
        let mut r = record();
        r.msg = "here abcd and abcd twice".to_owned();
        let hits = r.redact(&interleaved);
        assert_eq!(hits, 2, "both occurrences are replaced");
        assert!(r.msg.contains("[redacted:1]"), "{}", r.msg);
        assert!(
            !r.msg.contains("[redacted:2]"),
            "one secret must not produce a second marker: {}",
            r.msg
        );
        assert!(!r.msg.contains("abcd"), "{}", r.msg);
    }

    /// Deduplication must not disturb the longest-first *matching* order `apply` needs.
    ///
    /// The control for the test above: adding a value sort before the length sort could
    /// plausibly have broken the ordering that stops a short secret from matching first.
    #[test]
    fn dedup_preserves_longest_first_matching() {
        let redactor = Redactor::from_values(["secret", "secret", "secret-extended-value"]);
        assert_eq!(
            redactor.len(),
            2,
            "the repeated short value must collapse, leaving two distinct"
        );

        let mut r = record();
        r.msg = "value=secret-extended-value".to_owned();
        r.redact(&redactor);
        assert!(
            !r.msg.contains("extended-value") && !r.msg.contains("secret"),
            "the longer value must still match first: {}",
            r.msg
        );
    }

    /// A longer secret consumes a shorter one nested inside it.
    ///
    /// Longest-first ordering: with the short value applied first, the remainder of
    /// the long one would be left in the clear.
    #[test]
    fn a_nested_short_secret_does_not_reveal_the_long_one() {
        let redactor = Redactor::from_values(["secret", "secret-extended-value"]);
        let mut r = record();
        r.msg = "value=secret-extended-value".to_owned();
        r.redact(&redactor);
        assert!(
            !r.msg.contains("extended-value"),
            "the tail of the long secret must not survive: {}",
            r.msg
        );
    }

    // -- the logger ---------------------------------------------------------

    /// The filter suppresses a record below the configured level.
    #[test]
    fn the_level_filter_suppresses_lower_levels() {
        let logger = Logger::new(Format::Json, Level::Warn);
        assert!(logger.enabled(Level::Error));
        assert!(logger.enabled(Level::Warn));
        assert!(!logger.enabled(Level::Info));
        assert!(logger.emit(record()).is_none(), "Info is below Warn");

        let (t, s) = ids();
        let warn = Record::new(Level::Warn, t, s, "acme", "svc", "rev", "careful");
        assert!(logger.emit(warn).is_some(), "Warn must pass");
    }

    /// **Redaction runs for both formats.**
    ///
    /// Redacting inside only one rendering is how the other one leaks, and the
    /// leak appears in whichever format the deployment does not use in testing.
    #[test]
    fn redaction_applies_in_both_formats() {
        for format in [Format::Json, Format::Human] {
            let logger =
                Logger::new(format, Level::Trace).with_redactor(Redactor::from_values(["s3cret"]));
            let mut r = record();
            r.msg = "token s3cret".to_owned();
            let line = logger.emit(r).expect("Trace passes the filter");
            assert!(
                !line.contains("s3cret"),
                "{format:?} leaked the secret: {line}"
            );
        }
    }

    /// The same record renders the same way twice.
    #[test]
    fn rendering_is_deterministic() {
        let logger =
            Logger::new(Format::Json, Level::Trace).with_redactor(Redactor::from_values(["x"]));
        let a = logger.emit(record()).unwrap();
        let b = logger.emit(record()).unwrap();
        assert_eq!(a, b);
    }

    /// Extra fields render in a stable order, not in hash order.
    #[test]
    fn extra_fields_have_a_stable_order() {
        let r = record()
            .with_field("zulu", "1")
            .with_field("alpha", "2")
            .with_field("mike", "3");
        let json = r.render_json();
        let a = json.find("\"alpha\"").unwrap();
        let m = json.find("\"mike\"").unwrap();
        let z = json.find("\"zulu\"").unwrap();
        assert!(a < m && m < z, "fields must be ordered: {json}");
    }
}
