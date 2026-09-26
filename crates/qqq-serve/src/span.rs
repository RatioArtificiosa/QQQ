// SPDX-License-Identifier: Apache-2.0

//! Automatic spans and host-controlled sampling — Proposal §10.4, `OBS-009` and `OBS-011`.
//!
//! > *"Automatic spans for: inbound request, routing, instance acquire, guest entry, each host
//! > capability call, outbound HTTP, DB queries, and instance release. Trace context propagates
//! > through `wasi:http` headers and through the `qqq:trace` interface. **Sampling is
//! > host-controlled (head-based with tail sampling option) and *never* guest-controlled.**"*
//!
//! # Why the span and the sampler are one module
//!
//! `OBS-009` (spans), `OBS-010` (propagation), `OBS-011` (sampling) and `OBS-014` (proving a guest
//! cannot influence sampling) are four items with **no shared foundation**: `span_seq` in `server.rs`
//! counts stages per connection and nothing emitted one, so there was nothing to propagate, nothing
//! to sample, and nothing for a guest to try to influence.
//!
//! **A sampler built before the thing it samples is the eighth instance of *"written, tested, never
//! called"*** — the pattern this goal keeps finding. So the span is here, and the sampler decides
//! whether it is emitted.
//!
//! # Where a span goes, and why it goes through the logger
//!
//! Through [`crate::access_log::Logger`] — the only sink until `OBS-012`'s OTLP exporter exists.
//! That is a deliberate choice and not a shortcut:
//!
//! * a span inherits the **level filter**, so `--log-level warn` quiets spans as it quiets records;
//! * it inherits the **format**, so a JSON deployment gets JSON spans;
//! * and it inherits **§10.3's redaction**, so a span cannot become a path around it. **A span that
//!   bypassed redaction would be a hole in the one control `OBS-008` exists to provide.**
//!
//! # The security property, and why it is a *signature* rather than a check
//!
//! §10.4 says sampling is *never* guest-controlled. The way to make that true is not to inspect a
//! guest-supplied value and reject it — it is to make the decision a function of state the guest
//! cannot reach. [`Sampler::decide`] takes a [`TraceId`], and **every `TraceId` in this server is
//! allocated by the host** (`TraceId::from_counter`, once per connection). There is no parameter a
//! guest can populate, so there is no check to forget.
//!
//! **An inbound `traceparent` is the one place a guest *could* reach a sampling decision**, and the
//! decision here does not read it: the W3C `sampled` flag is a *correlation* hint, and honouring it
//! would let a caller choose whether its own traffic is recorded. `OBS-014` is the item that proves
//! this, and the proof is only meaningful because the input is host-owned.
//!
//! # Example
//!
//! The whole public surface is one constructor, because the **decision** belongs to the server,
//! which owns the trace id:
//!
//! ```
//! use qqq_serve::span::Sampler;
//!
//! // `on` records every trace and `off` records none.
//! let all = Sampler::from_rate("on", false).expect("`on` parses");
//! let none = Sampler::from_rate("off", false).expect("`off` parses");
//!
//! // A rate is a real rate, and the tail option is chosen rather than assumed.
//! let quarter = Sampler::from_rate("0.25", true).expect("a rate parses");
//!
//! // A typo is refused, not defaulted: a server that ignored `0.5x` would sample at some other rate
//! // and look configured.
//! assert!(Sampler::from_rate("0.5x", false).is_err());
//! # let _ = (all, none, quarter);
//! ```

use std::fmt::Write as _;

use crate::access_log::TraceId;

/// Whether a span is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Emit the span.
    Record,
    /// Drop it.
    Drop,
}

impl Decision {
    /// Whether the span is recorded.
    #[must_use]
    pub(crate) const fn is_record(self) -> bool {
        matches!(self, Self::Record)
    }
}

/// The head-based policy.
///
/// # Why a ratio is deterministic on the trace id and not a coin flip
///
/// Because a trace has many spans — one per §4.4 step — and a decision made per span would record
/// **part** of a trace: the inbound request kept, the guest entry dropped, and a trace nobody can
/// read. Choosing from the trace id makes every span of one trace agree, which is what "head-based"
/// means and what makes the sampled output coherent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Policy {
    /// Record every span.
    AlwaysOn,
    /// Record none.
    AlwaysOff,
    /// Record `numerator / denominator` of traces, chosen from the trace id, in lowest terms.
    Ratio {
        /// How many of `denominator` are kept.
        numerator: u32,
        /// The bucket count.
        denominator: u32,
    },
}

impl Policy {
    /// Parse a policy from its CLI spelling.
    ///
    /// `1`, `1.0` and `on` are all; `0`, `0.0` and `off` are none; anything else is a ratio.
    ///
    /// # Errors
    ///
    /// A sentence naming what was wrong, so a typo is answered rather than defaulted — a server that
    /// silently ignored `--trace-sample 0.5x` would sample at some other rate and look configured.
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "on" => return Ok(Self::AlwaysOn),
            "off" => return Ok(Self::AlwaysOff),
            _ => {}
        }
        let (num, den) = match s.split_once('.') {
            // A decimal is a fraction of its own length, so `0.25` is 25/100 **without a float**: a
            // float would make the bucket comparison inexact at the boundary, and a sampling rate
            // that is off by one bucket is a rate nobody can reason about.
            Some((whole, frac)) if !frac.is_empty() => {
                let scale = 10u32.pow(u32::try_from(frac.len()).unwrap_or(9));
                let whole: u32 = whole.parse().map_err(|_| format!("`{s}` is not a rate"))?;
                let frac: u32 = frac.parse().map_err(|_| format!("`{s}` is not a rate"))?;
                (whole.saturating_mul(scale).saturating_add(frac), scale)
            }
            _ => {
                let n: u32 = s.parse().map_err(|_| {
                    format!(
                        "`{s}` is not a sampling rate; use `on`, `off`, or a number like `0.25`"
                    )
                })?;
                (n, 1)
            }
        };
        if den == 0 {
            return Err(format!("`{s}` has a zero denominator"));
        }
        if num == 0 {
            return Ok(Self::AlwaysOff);
        }
        if num >= den {
            return Ok(Self::AlwaysOn);
        }
        // **Reduced to lowest terms**, because `0.25` (25/100) and `0.250` (250/1000) are the same
        // rate and must sample identically. Without this they bucket in different spaces and the same
        // rate behaves differently depending on how it was *written*.
        let g = Self::gcd(num, den);
        Ok(Self::Ratio {
            numerator: num / g,
            denominator: den / g,
        })
    }

    /// Greatest common divisor, for reducing a ratio to lowest terms.
    const fn gcd(a: u32, b: u32) -> u32 {
        let (mut a, mut b) = (a, b);
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        if a == 0 {
            1
        } else {
            a
        }
    }

    /// The bucket a trace falls in, in `0..denominator`.
    ///
    /// A FNV-1a fold over the trace id's characters. **Not** a cryptographic hash and deliberately
    /// so: this chooses a bucket, and a keyed hash would make the rate unpredictable across restarts
    /// for the same trace — the opposite of what a *sampling rate* is for.
    #[must_use]
    fn bucket(trace: &TraceId, denominator: u32) -> u32 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in trace.as_str().bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        u32::try_from(h % u64::from(denominator)).unwrap_or(0)
    }
}

/// The sampling decision, head and tail — `OBS-011`.
///
/// # Example
///
/// ```
/// use qqq_serve::span::Sampler;
///
/// // `on` records everything and `off` records nothing.
/// assert!(Sampler::from_rate("on", false).is_ok());
/// assert!(Sampler::from_rate("off", false).is_ok());
///
/// // A rate is a real rate: `0.25` is one trace in four, and `0.250` is the same rate written
/// // differently -- both are accepted and both reduce to the same fraction.
/// assert!(Sampler::from_rate("0.25", false).is_ok());
/// assert!(Sampler::from_rate("0.250", false).is_ok());
///
/// // And the tail option is chosen, not assumed.
/// assert!(Sampler::from_rate("0.1", true).is_ok());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sampler {
    head: Policy,
    /// Tail sampling: keep a trace the head dropped when it turned out to be interesting.
    ///
    /// §10.4 asks for *"head-based with tail sampling option"*, and this is the option. Head sampling
    /// is the only kind that can be decided before the work happens, and the traces worth keeping are
    /// disproportionately the ones that **failed** — knowable only afterwards.
    ///
    /// **It is off unless asked for**, and that is a correction rather than a default. Measured: with
    /// it on, `--trace-sample 0.25` sampled **24 of 24** requests against a project whose responses
    /// were all 503 — because a failure is read from the status, and an option that keeps failures
    /// keeps *everything* when everything fails. **The rate was not the rate.**
    keep_failures: bool,
}

impl Sampler {
    /// Build a sampler from a `--trace-sample` value and the tail option.
    ///
    /// # Why this is the whole public surface
    ///
    /// Because `qqq-run`'s job is to *construct* a sampler from a command line and hand it over; the
    /// **decision** belongs to the server, which owns the trace id. Exposing `decide`, the policy
    /// enum or the outcome flag would publish arithmetic nobody outside calls — and `§O-311` is the
    /// entry about what a public item with no caller costs.
    ///
    /// # Errors
    ///
    /// The parse error's sentence, so a typo is answered rather than defaulted.
    ///
    /// # Example
    ///
    /// ```
    /// use qqq_serve::span::Sampler;
    ///
    /// assert!(Sampler::from_rate("on", false).is_ok());
    /// assert!(Sampler::from_rate("0.1", true).is_ok());
    ///
    /// // A typo is refused rather than defaulted: a server that ignored `0.5x` would sample at some
    /// // other rate and look configured.
    /// let err = Sampler::from_rate("0.5x", false).expect_err("a typo is refused");
    /// assert!(err.contains("is not a rate"), "{err}");
    /// ```
    pub fn from_rate(rate: &str, keep_failures: bool) -> Result<Self, String> {
        Ok(Self::new(Policy::parse(rate)?, keep_failures))
    }

    /// A sampler with a head policy and the tail option.
    #[must_use]
    const fn new(head: Policy, keep_failures: bool) -> Self {
        Self {
            head,
            keep_failures,
        }
    }

    /// The head decision, from the trace id alone.
    ///
    /// # The security property
    ///
    /// **The only input is a host-allocated [`TraceId`].** There is no guest-supplied parameter, so
    /// §10.4's *"never guest-controlled"* is a property of the signature rather than of a check
    /// someone could forget — and `OBS-014` is the item that proves it.
    #[must_use]
    pub(crate) fn decide(&self, trace: &TraceId) -> Decision {
        match self.head {
            Policy::AlwaysOn => Decision::Record,
            Policy::AlwaysOff => Decision::Drop,
            Policy::Ratio {
                numerator,
                denominator,
            } => {
                if Policy::bucket(trace, denominator) < numerator {
                    Decision::Record
                } else {
                    Decision::Drop
                }
            }
        }
    }

    /// The decision after the outcome is known — head, then the tail override.
    ///
    /// `failed` is a property of **the host's own observation of the request**, never of anything the
    /// guest said. A guest that could claim to have failed would be able to force recording, which is
    /// the same influence §10.4 forbids in the other direction.
    #[must_use]
    pub(crate) fn decide_with_outcome(&self, trace: &TraceId, failed: bool) -> Decision {
        if self.decide(trace).is_record() {
            return Decision::Record;
        }
        if failed && self.keep_failures {
            return Decision::Record;
        }
        Decision::Drop
    }
}

/// One automatic span — `OBS-009`.
///
/// # Why the step is a number *and* a name
///
/// Because the number is what §4.4 orders and what a reader correlates against the lifecycle table,
/// and the name is what makes a line readable without opening the Proposal. `lifecycle` owns the
/// names, so a span **cannot invent one**: [`Span::for_step`] is the only constructor and it looks
/// the name up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Span {
    /// The trace this span belongs to.
    trace: TraceId,
    /// This span's own id, derived from the connection's span ordinal.
    id: TraceId,
    /// The §4.4 step number, 1-based.
    step: u8,
    /// The step's name, from [`crate::lifecycle`].
    name: &'static str,
    /// How long the step took, in microseconds.
    micros: u64,
}

impl Span {
    /// A span for a §4.4 step, or `None` for a number the table does not define.
    #[must_use]
    pub(crate) fn for_step(trace: TraceId, id: TraceId, step: u8, micros: u64) -> Option<Self> {
        let name = crate::lifecycle::step_name(step)?;
        Some(Self {
            trace,
            id,
            step,
            name,
            micros,
        })
    }

    /// The id this span reports as its own.
    #[must_use]
    pub(crate) const fn id(&self) -> &TraceId {
        &self.id
    }

    /// The §4.4 step number.
    #[must_use]
    pub(crate) const fn step(&self) -> u8 {
        self.step
    }

    /// The line the logger carries.
    ///
    /// One line, in the access log's own key=value shape so a reader does not learn two formats.
    #[must_use]
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            "span step={} name={} trace={} span={} micros={}",
            self.step,
            self.name,
            self.trace.as_str(),
            self.id.as_str(),
            self.micros
        );
        out
    }
}
