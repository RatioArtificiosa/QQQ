// SPDX-License-Identifier: Apache-2.0

//! W3C Trace Context — the `traceparent` header, Proposal §10.4's `OBS-010`.
//!
//! > *"Trace context propagates through `wasi:http` headers and through the `qqq:trace` interface.
//! > Sampling is host-controlled (head-based with tail sampling option) and **never**
//! > guest-controlled."*
//!
//! # The two halves of that sentence, and why they are in different places
//!
//! **Propagation is correlation**: an inbound `traceparent` says *"this request is part of a trace that
//! started upstream"*, and honouring it is what makes one trace out of many services.
//!
//! **Sampling is a decision**, and §10.4 forbids the guest a hand in it. The header carries a `sampled`
//! bit, and a conventional implementation **inherits** it — which would let a caller choose whether its
//! own traffic is recorded.
//!
//! So this module **parses** and **carries** the flag, and [`Flags`] documents it as a *correlation
//! hint*. The decision lives in [`crate::span::Sampler`], whose only input is a host-allocated
//! [`TraceId`], and `OBS-014` is the item that proves a guest cannot reach it. **`§O-321`'s guard
//! enforces the separation at the source level**: `span.rs` and every `emit_span` call must name no
//! request field, so the decision cannot read this module's output.
//!
//! # Where it is wired, and what is not wired yet
//!
//! [`crate::server`]'s `access_record` parses the header and records **`upstream_trace`** and
//! **`upstream_sampled`** on the access line. That is the **inbound** half.
//!
//! **The outbound half is not wired**, and it is not an oversight: continuing a trace *downstream*
//! needs an outbound `wasi:http` request, which this server does not make. [`TraceContext::to_header`]
//! exists for the path that will call it, and its doctest is the caller until then — which is stated
//! rather than implied.
//!
//! # Why the parser is strict
//!
//! Because a permissive one is worse than none. A `traceparent` that half-parses produces a trace id
//! that **looks** valid in a log and joins nothing — and the failure is invisible, because a trace that
//! does not join is indistinguishable from a trace with one service in it.
//!
//! # Example
//!
//! ```
//! use qqq_serve::trace_context::TraceContext;
//!
//! // A malformed header is REFUSED rather than half-parsed, and the refusal names the field.
//! let err = TraceContext::parse("00-4bf92f35-00f067aa0ba902b7-01").unwrap_err();
//! assert!(err.to_string().contains("trace-id"), "{err}");
//! ```

use std::fmt::Write as _;

use crate::access_log::{TraceId, TraceIdError};

/// The characters in a `traceparent`: `version` + `-` + trace + `-` + parent + `-` + flags.
const FIELDS: usize = 4;

/// The version this implementation emits.
///
/// W3C says a receiver **must** accept an unknown *higher* version by parsing the fields it knows and
/// ignoring the rest — which is why [`TraceContext::parse`] accepts `ff` rather than pinning to this.
const VERSION: &str = "00";

/// Why a `traceparent` was refused.
///
/// # Example
///
/// ```
/// use qqq_serve::trace_context::{TraceContext, TraceContextError};
///
/// // A short trace id names the field, so a reader is not sent looking at four at once.
/// assert_eq!(
///     TraceContext::parse("00-4bf92f35-00f067aa0ba902b7-01"),
///     Err(TraceContextError::WrongLength {
///         field: "trace-id",
///         got: 8,
///         want: 32
///     })
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceContextError {
    /// The header was empty.
    Empty,
    /// The wrong number of dash-separated fields.
    FieldCount {
        /// How many were found.
        got: usize,
    },
    /// A field was not the length W3C requires.
    WrongLength {
        /// Which field, by its W3C name.
        field: &'static str,
        /// The length found.
        got: usize,
        /// The length required.
        want: usize,
    },
    /// A field was not hexadecimal.
    NotHex {
        /// Which field, by its W3C name.
        field: &'static str,
    },
    /// A field that W3C requires to be non-zero was all zeros.
    AllZero {
        /// Which field, by its W3C name.
        field: &'static str,
    },
}

impl std::fmt::Display for TraceContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "the `traceparent` header is empty"),
            Self::FieldCount { got } => write!(
                f,
                "a `traceparent` has {FIELDS} dash-separated fields and this has {got}"
            ),
            Self::WrongLength { field, got, want } => {
                write!(f, "`{field}` is {got} character(s) and W3C requires {want}")
            }
            Self::NotHex { field } => write!(f, "`{field}` is not hexadecimal"),
            Self::AllZero { field } => write!(
                f,
                "`{field}` is all zeros, which W3C defines as invalid rather than as an id"
            ),
        }
    }
}

impl std::error::Error for TraceContextError {}

/// The `trace-flags` byte, **as a correlation hint**.
///
/// # This is not a sampling decision
///
/// §10.4: *"Sampling is host-controlled … and **never** guest-controlled."* The `sampled` bit here is
/// what an **upstream** service decided, and it is carried so a trace can be described coherently.
/// **It is never consulted when this server decides whether to record**, which is
/// [`crate::span::Sampler`]'s job and takes a host-allocated [`TraceId`] and nothing else.
///
/// The type exists rather than a `u8` so that the one place a reader might mistake it for a decision
/// carries the correction with it.
///
/// # Example
///
/// ```
/// use qqq_serve::trace_context::TraceContext;
///
/// let ctx = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
///     .expect("parses");
/// assert!(ctx.flags().upstream_sampled(), "upstream sampled it");
/// assert_eq!(ctx.flags().bits(), 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(u8);

impl Flags {
    /// The bit W3C defines as `sampled`.
    const SAMPLED: u8 = 0x01;

    /// The flags byte, unmodified.
    ///
    /// # Example
    ///
    /// ```
    /// use qqq_serve::trace_context::TraceContext;
    ///
    /// let ctx = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    ///     .expect("parses");
    /// assert_eq!(ctx.flags().bits(), 0x01, "the byte is reported as it arrived");
    /// ```
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// What the **upstream** service said about sampling.
    ///
    /// # Read this before using it
    ///
    /// **This is not this server's decision and must not become one.** It is exposed so a trace can be
    /// *described* — *"upstream sampled this, we did not"* is a useful thing to know — and using it to
    /// choose whether to record is exactly what §10.4 forbids. `OBS-014` is the item that proves a guest
    /// cannot reach the decision.
    ///
    /// # Example
    ///
    /// ```
    /// use qqq_serve::trace_context::TraceContext;
    ///
    /// // `sampled=1` upstream, and `sampled=0` not -- and BOTH are only reported.
    /// let yes = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    ///     .expect("parses");
    /// let no = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
    ///     .expect("parses");
    /// assert!(yes.flags().upstream_sampled());
    /// assert!(!no.flags().upstream_sampled());
    /// ```
    #[must_use]
    pub const fn upstream_sampled(self) -> bool {
        self.0 & Self::SAMPLED != 0
    }
}

/// A parsed `traceparent` — Proposal §10.4's propagation half.
///
/// # Example
///
/// ```
/// use qqq_serve::trace_context::TraceContext;
///
/// // A well-formed header: version, 32-hex trace, 16-hex parent, flags.
/// let header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
/// let ctx = TraceContext::parse(header).expect("a well-formed traceparent parses");
///
/// assert_eq!(ctx.trace().as_str(), "4bf92f3577b34da6a3ce929d0e0e4736");
/// assert_eq!(ctx.parent().as_str(), "00f067aa0ba902b7");
///
/// // The flag is what UPSTREAM decided, and it is carried rather than obeyed.
/// assert!(ctx.flags().upstream_sampled());
///
/// // And a malformed header is refused rather than half-parsed: a trace id that looks valid and joins
/// // nothing is invisible, because a trace that does not join looks like a trace of one.
/// assert!(TraceContext::parse("00-not-hex-00f067aa0ba902b7-01").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    trace: TraceId,
    parent: TraceId,
    flags: Flags,
}

impl TraceContext {
    /// Parse a `traceparent` header.
    ///
    /// # Errors
    ///
    /// [`TraceContextError`] naming the field that was wrong, because *"invalid traceparent"* sends a
    /// reader looking at four fields at once.
    ///
    /// # Why the all-zero ids are refused
    ///
    /// Because W3C defines them as **invalid rather than as ids**: an all-zero trace id is what a
    /// producer sends when it has not decided one, and accepting it would join every such request into
    /// one trace — the opposite of what propagation is for.
    ///
    /// # Example
    ///
    /// ```
    /// use qqq_serve::trace_context::TraceContext;
    ///
    /// assert!(TraceContext::parse("").is_err(), "empty is refused");
    /// assert!(
    ///     TraceContext::parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01").is_err(),
    ///     "an all-zero trace id is invalid rather than an id"
    /// );
    /// // A higher version is READ, not refused: a receiver that rejected `ff` would break every
    /// // future producer, and W3C says so explicitly.
    /// assert!(TraceContext::parse("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_ok());
    /// ```
    pub fn parse(header: &str) -> Result<Self, TraceContextError> {
        let header = header.trim();
        if header.is_empty() {
            return Err(TraceContextError::Empty);
        }
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != FIELDS {
            return Err(TraceContextError::FieldCount { got: parts.len() });
        }
        let (version, trace, parent, flags) = (parts[0], parts[1], parts[2], parts[3]);

        check(version, 2, "version")?;
        check(trace, TraceId::TRACE_LEN, "trace-id")?;
        check(parent, TraceId::SPAN_LEN, "parent-id")?;
        check(flags, 2, "trace-flags")?;

        // W3C: an all-zero trace id or parent id is invalid. The version and the flags are allowed to
        // be zero -- `00` is the version and `00` is "not sampled".
        if trace.bytes().all(|b| b == b'0') {
            return Err(TraceContextError::AllZero { field: "trace-id" });
        }
        if parent.bytes().all(|b| b == b'0') {
            return Err(TraceContextError::AllZero { field: "parent-id" });
        }

        let trace = TraceId::trace(trace).map_err(|e| from_id(e, "trace-id"))?;
        let parent = TraceId::span(parent).map_err(|e| from_id(e, "parent-id"))?;
        let flags = u8::from_str_radix(flags, 16).map_err(|_| TraceContextError::NotHex {
            field: "trace-flags",
        })?;

        // An unknown HIGHER version is accepted, per W3C, by reading the fields this implementation
        // knows. `VERSION` is the version this emits, and naming it here is what a future change to
        // the field meanings would have to look at.
        let _ = VERSION;
        Ok(Self {
            trace,
            parent,
            flags: Flags(flags),
        })
    }

    /// The trace this request belongs to.
    ///
    /// # Example
    ///
    /// ```
    /// use qqq_serve::trace_context::TraceContext;
    ///
    /// let ctx = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    ///     .expect("parses");
    /// assert_eq!(ctx.trace().as_str(), "4bf92f3577b34da6a3ce929d0e0e4736");
    /// ```
    #[must_use]
    pub const fn trace(&self) -> &TraceId {
        &self.trace
    }

    /// The caller's own span — this request's **parent**, not its own id.
    ///
    /// # Example
    ///
    /// ```
    /// use qqq_serve::trace_context::TraceContext;
    ///
    /// let ctx = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    ///     .expect("parses");
    /// assert_eq!(ctx.parent().as_str(), "00f067aa0ba902b7");
    /// ```
    #[must_use]
    pub const fn parent(&self) -> &TraceId {
        &self.parent
    }

    /// What the upstream service said about sampling. **See [`Flags::upstream_sampled`].**
    ///
    /// # Example
    ///
    /// ```
    /// use qqq_serve::trace_context::TraceContext;
    ///
    /// let ctx = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
    ///     .expect("parses");
    /// assert!(!ctx.flags().upstream_sampled(), "upstream did not sample it");
    /// ```
    #[must_use]
    pub const fn flags(&self) -> Flags {
        self.flags
    }

    /// The header this context would emit, for a downstream hop.
    ///
    /// # Why the span id is a parameter
    ///
    /// Because this server's own span id is allocated by the **host**, per request, and this type is
    /// the *inbound* half. Emitting is where propagation continues, and the caller owns the id it
    /// emits — the same separation that keeps the decision host-made.
    ///
    /// # Not wired yet, and that is stated rather than implied
    ///
    /// Continuing a trace **downstream** needs an outbound `wasi:http` request, which this server does
    /// not make. This method exists for the path that will call it, and **its doctest is the caller
    /// until then.**
    ///
    /// # Example
    ///
    /// ```
    /// use qqq_serve::access_log::TraceId;
    /// use qqq_serve::trace_context::TraceContext;
    ///
    /// let ctx = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    ///     .expect("parses");
    /// let own = TraceId::span("0123456789abcdef").expect("a span id");
    ///
    /// let header = ctx.to_header(&own);
    /// assert_eq!(header, "00-4bf92f3577b34da6a3ce929d0e0e4736-0123456789abcdef-01");
    ///
    /// // And what we emit, we accept: the next hop reads the same trace, with this server as parent.
    /// let next = TraceContext::parse(&header).expect("round-trips");
    /// assert_eq!(next.parent().as_str(), own.as_str());
    /// ```
    #[must_use]
    pub fn to_header(&self, own_span: &TraceId) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            "{VERSION}-{}-{}-{:02x}",
            self.trace.as_str(),
            own_span.as_str(),
            self.flags.bits()
        );
        out
    }
}

/// Length and hexadecimal checks, shared by the four fields.
fn check(value: &str, want: usize, field: &'static str) -> Result<(), TraceContextError> {
    if value.len() != want {
        return Err(TraceContextError::WrongLength {
            field,
            got: value.len(),
            want,
        });
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(TraceContextError::NotHex { field });
    }
    Ok(())
}

/// [`TraceId`]'s own error, translated so the message names the W3C field.
///
/// [`TraceId`] validates the same characters, so this is a translation rather than a second check — and
/// it exists so the caller reads `trace-id` rather than `trace`.
fn from_id(error: TraceIdError, field: &'static str) -> TraceContextError {
    match error {
        TraceIdError::Empty => TraceContextError::Empty,
        TraceIdError::WrongLength { got, want } => {
            TraceContextError::WrongLength { field, got, want }
        }
        TraceIdError::NotHex { .. } => TraceContextError::NotHex { field },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example header from the W3C specification.
    const WELL_FORMED: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn a_well_formed_header_parses_into_its_three_parts() {
        let ctx = TraceContext::parse(WELL_FORMED).expect("the specification's own example parses");
        assert_eq!(ctx.trace().as_str(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.parent().as_str(), "00f067aa0ba902b7");
        assert_eq!(ctx.flags().bits(), 0x01);
    }

    /// **The `sampled` bit is carried, and carrying it is all that happens here.**
    ///
    /// §10.4: *"Sampling is host-controlled … and never guest-controlled."* This test asserts the two
    /// halves are **separate values**: the header says one thing and the host's sampler says another,
    /// and nothing in this module consults the sampler or is consulted by it.
    #[test]
    fn the_flag_is_carried_and_never_obeyed() {
        let sampled = TraceContext::parse(WELL_FORMED).expect("parses");
        assert!(
            sampled.flags().upstream_sampled(),
            "the upstream bit is reported"
        );

        let not_sampled =
            TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
                .expect("parses");
        assert!(!not_sampled.flags().upstream_sampled());

        // And the host's decision is taken from a HOST-allocated id, with the header nowhere in sight.
        // The sampler is constructed `off` and stays `off` whatever the header says -- and this test
        // has to hand it a host id, because **there is no way to hand it the header**: the signature
        // admits a `TraceId` and nothing else. That is the property, stated as an API rather than as a
        // check, and `OBS-014` proves it from the other side.
        let host = crate::span::Sampler::from_rate("off", false).expect("`off` parses");
        let host_trace = TraceId::from_counter(7);
        assert!(
            !host.decide(&host_trace).is_record(),
            "an inbound `sampled=1` must not turn a host `off` into an `on`"
        );
    }

    /// **An all-zero trace id is refused, because W3C defines it as invalid rather than as an id.**
    ///
    /// Accepting it would join every request that has not decided its trace into **one** trace — the
    /// opposite of what propagation is for.
    #[test]
    fn an_all_zero_id_is_refused() {
        assert_eq!(
            TraceContext::parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
            Err(TraceContextError::AllZero { field: "trace-id" })
        );
        assert_eq!(
            TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"),
            Err(TraceContextError::AllZero { field: "parent-id" })
        );
        // The VERSION and the FLAGS are allowed to be zero: `00` is the version, and `00` is "not
        // sampled". Only the two ids are refused.
        assert!(
            TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00").is_ok()
        );
    }

    /// **A malformed header is refused rather than half-parsed.**
    #[test]
    fn a_malformed_header_is_refused_by_field() {
        assert_eq!(TraceContext::parse(""), Err(TraceContextError::Empty));
        assert_eq!(TraceContext::parse("   "), Err(TraceContextError::Empty));
        assert_eq!(
            TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-01"),
            Err(TraceContextError::FieldCount { got: 3 })
        );
        assert_eq!(
            TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra"),
            Err(TraceContextError::FieldCount { got: 5 })
        );
        assert_eq!(
            TraceContext::parse("00-4bf92f35-00f067aa0ba902b7-01"),
            Err(TraceContextError::WrongLength {
                field: "trace-id",
                got: 8,
                want: 32
            })
        );
        assert!(matches!(
            TraceContext::parse("00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01"),
            Err(TraceContextError::NotHex { field: "trace-id" })
        ));
        assert!(matches!(
            TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz"),
            Err(TraceContextError::NotHex {
                field: "trace-flags"
            })
        ));
    }

    /// **An unknown HIGHER version is accepted**, per W3C, by reading the fields this knows.
    #[test]
    fn a_higher_version_is_accepted() {
        let ctx = TraceContext::parse("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .expect("a higher version is read, not refused");
        assert_eq!(ctx.trace().as_str(), "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    /// **What is parsed can be emitted**, so a downstream hop continues the trace.
    #[test]
    fn a_context_emits_a_header_for_the_next_hop() {
        let ctx = TraceContext::parse(WELL_FORMED).expect("parses");
        let own = TraceId::span("0123456789abcdef").expect("a span id");
        let header = ctx.to_header(&own);
        assert_eq!(
            header,
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0123456789abcdef-01"
        );
        let next = TraceContext::parse(&header).expect("what we emit, we accept");
        assert_eq!(next.trace().as_str(), ctx.trace().as_str());
        assert_eq!(next.parent().as_str(), own.as_str());
    }

    /// **The header is trimmed**, because a proxy may pad it and a padded id is not a different trace.
    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let ctx = TraceContext::parse(&format!("  {WELL_FORMED}  ")).expect("padded, still parses");
        assert_eq!(ctx.trace().as_str(), "4bf92f3577b34da6a3ce929d0e0e4736");
    }
}
